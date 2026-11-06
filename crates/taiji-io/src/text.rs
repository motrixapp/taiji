//! Single source for untrusted-codepoint decisions in file names.
//!
//! # Placement (dependency direction)
//!
//! Three consumers — taiji-bt `filetree.rs` (parse face, refuse to load),
//! taiji-http `naming.rs` (sanitization face, replace with `_`), and
//! taiji-core `session::actor` (admission face, reject) — each used to
//! keep a hand-copied copy of the set that had to move in lockstep on
//! every extension. A single source must be reachable from all three:
//! taiji-domain depends on taiji-bt (bt depending on domain would be a
//! cycle — not viable), and taiji-http depends only on this crate within
//! the workspace (bt/store/domain are unreachable from it), so the lowest
//! common reachable layer is this crate (the transport carrier; pure
//! character classification with no transport-semantic coupling,
//! std-only).
//!
//! # Set contents (18 code points)
//!
//! - **Bidirectional overrides, 12 Cf code points**: U+061C (ALM),
//! U+200E/U+200F (LRM/RLM), U+202A-202E (LRE/RLE/PDF/LRO/RLO),
//! U+2066-2069 (LRI/RLI/FSI/PDI) — these can reorder the displayed
//! name (the `photo\u{202E}gpj.exe` rendering as `photo.exe` display
//! spoof).
//! - **Zero-width, 3**: U+200B (ZWSP), U+200C (ZWNJ), U+FEFF (BOM) —
//! zero rendering width, so `evil\u{200B}.exe` is visually identical
//! to `evil.exe` (name borrowing / directory-twin surface).
//! - **Line/paragraph separators, 2**: U+2028 (Zl) / U+2029 (Zp) —
//! separator semantics are a residual log-line injection surface;
//! neither `is_ascii_control` (C0+DEL) nor `char::is_control` (Cc)
//! covers them.
//! - **DEL U+007F**: overlaps the consumers' control-character checks
//! (`char::is_control` covers C0+DEL+C1), but this function still
//! carries DEL itself so a future consumer relying only on this
//! function cannot let DEL through by skipping the control check.
//!
//! # Deliberately excluded (passthrough; the trade-off is fixed)
//!
//! U+200D ZWJ (a legal component of emoji ZWJ sequences), U+00AD SHY,
//! variation selectors (U+FE00-U+FE0F etc.) — no display-reordering or
//! visual-identity surface. C0/C1 control characters are handled
//! uniformly by the consumers' `char::is_control` (Cc = U+0000-001F,
//! U+007F-009F; the same scope on all three channels) and are not carried
//! here again.

/// File-name display-spoofing / hidden-injection code point classification
/// (single source; set contents and placement rationale in the module
/// docs). Consumers: bt `filetree` (refuse to load), http `naming`
/// (replace with `_`), core `session::actor::sanitize_out_option`
/// (reject).
#[inline]
pub fn is_spoofing_char(c: char) -> bool {
    matches!(
        c,
        '\u{7f}'            // DEL
            | '\u{61c}'     // ALM
            | '\u{200b}'    // ZWSP
            | '\u{200c}'    // ZWNJ
            | '\u{200e}'    // LRM
            | '\u{200f}'    // RLM
            | '\u{2028}'    // LINE SEPARATOR (Zl)
            | '\u{2029}'    // PARAGRAPH SEPARATOR (Zp)
            | '\u{202a}'..='\u{202e}' // LRE/RLE/PDF/LRO/RLO
            | '\u{2066}'..='\u{2069}' // LRI/RLI/FSI/PDI
            | '\u{feff}'    // BOM
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Explicit set table (18 code points, an enumeration independent of
    /// the implementation — the expected values for the full-scalar
    /// scan): DEL 1 + bidi overrides 12 + zero-width 3 + line/paragraph
    /// separators 2 (grouping matches the `matches!` branch order at the
    /// implementation).
    const SPOOFING_SET: [char; 18] = [
        '\u{7f}', '\u{61c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}',
        '\u{202d}', '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', '\u{200b}',
        '\u{200c}', '\u{feff}', '\u{2028}', '\u{2029}',
    ];

    /// Full-scalar table drive: the implementation and the explicit set
    /// table must agree pointwise over the entire Unicode scalar range
    /// (surrogates U+D800-DFFF are not scalar values and are skipped) —
    /// any drift (missed merge, wrong merge, wrong range) surfaces here,
    /// not after the fact at a consumer.
    #[test]
    fn full_scalar_range_matches_the_explicit_set() {
        for cp in 0u32..=0x10FFFF {
            if let Some(c) = char::from_u32(cp) {
                assert_eq!(
                    is_spoofing_char(c),
                    SPOOFING_SET.contains(&c),
                    "U+{cp:04X} verdict disagrees with the set table"
                );
            }
        }
    }

    /// Each listed code point is spoofing (a positive anchor independent
    /// of the full-scalar scan).
    #[test]
    fn every_listed_code_point_is_spoofing() {
        for c in SPOOFING_SET {
            assert!(
                is_spoofing_char(c),
                "U+{:04X} must be classified spoofing",
                c as u32
            );
        }
    }

    /// Passthrough anchors: the deliberately excluded set — ZWJ (emoji
    /// sequence component), SHY, variation selectors, adjacent unselected
    /// code points (U+2027, U+2065, U+206A-206F, U+0085 C1), and healthy
    /// name components (ASCII/CJK/emoji).
    #[test]
    fn passthrough_anchors_stay_out_of_the_set() {
        for c in [
            '\u{200d}', // ZWJ
            '\u{ad}',   // SHY
            '\u{fe00}', // VS1
            '\u{fe0f}', // VS16
            '\u{2027}', // HYPHENATION POINT (adjacent to U+2028)
            '\u{2065}', // unassigned (adjacent to U+2066)
            '\u{206a}', // reversed SSE (deprecated control, not bidi/zero-width)
            '\u{206f}', // end of that same range
            '\u{85}',   // C1 NEL (control face belongs to is_control, not this set)
            'a',
            'Z',
            '.',
            '文',
            '\u{1f600}',
        ] {
            assert!(!is_spoofing_char(c), "U+{:04X} must pass through", c as u32);
        }
    }
}
