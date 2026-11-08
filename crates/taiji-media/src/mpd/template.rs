//! MPD URL-template expansion (ISO/IEC 23009-1 §5.3.9.4.4
//! subset: the identifier vocabulary — `$$`,
//! `$RepresentationID$`, `$Bandwidth$`, `$Number$`, `$Time$` and the
//! width format tags).
//!
//! Grammar (of record, the spec's Table 15 subset):
//!
//! ```text
//! template = 1*( char | "$$" | identifier )
//! identifier = "$" name [ "%" format ] "$"
//! name = "RepresentationID" | "Bandwidth" | "Number" | "Time"
//! format = 1*DIGIT ( "d" | "x" | "X" )
//! ```
//!
//! Rules:
//! * `$$` is the literal `$` (the only escape);
//! * `$RepresentationID$`/`$Bandwidth$` substitute always;
//!   `$Number$`/`$Time$` substitute the segment's number/time and are
//!   an error when the addressing form does not provide the value
//!   (a `$Number$` template under timeline addressing without a
//!   startNumber, a `$Time$` under `@duration` addressing is served
//!   by the computed segment time — [`super::expand`]'s ruled
//!   mapping);
//! * a bare unpaired `$` or an unknown identifier is a parse-class
//!   error (`manifest_parse`) — the spec's "invalid MPD" clause;
//! * `$RepresentationID$` does not take a format tag (its value is a
//!   string); the format tag zero-pads to the width with the given
//!   conversion (`d` decimal, `x`/`X` hex).
//!
//! Output bounds (the amplification guard — a ≤16MiB input must not
//! drive unbounded allocation): a format-tag **width over
//! [`MAX_FORMAT_WIDTH`** is a parse-class refusal (ISO 23009-1
//! widths are zero-padding digits; a 9-digit width is padding abuse,
//! not a template), and an **expansion output over
//! [`MAX_EXPANDED_URL_BYTES`** is `manifest_too_large` — checked
//! upfront on the template length and re-checked at every growth, so
//! a hostile `$…$`-dense or long-literal template refuses at ~zero
//! allocation, never after building the string.

use crate::error::MediaError;

/// Format-tag width bound: widths beyond this are padding abuse
/// (each width unit becomes a literal `0` per expanded URL — the
/// review-block PoC drove ~95MiB URIs from a 246-byte MPD with
/// `$Number%100000000d$`). Parse-class refusal.
pub const MAX_FORMAT_WIDTH: usize = 64;

/// One expanded URL's byte bound (the template-expansion output
/// guard). A real-world media URL is ~0.1–2KiB; 64KiB is the
/// bound-with-headroom. Over = `manifest_too_large`.
pub const MAX_EXPANDED_URL_BYTES: usize = 64 * 1024;

/// The substitution values one expansion carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemplateValues<'a> {
    /// `@id` of the representation.
    pub representation_id: &'a str,
    /// `@bandwidth` of the representation.
    pub bandwidth: u64,
    /// The segment's number (`$Number$`; `None` = not derivable).
    pub number: Option<u64>,
    /// The segment's presentation time in ticks (`$Time$`; `None` =
    /// not derivable).
    pub time: Option<u64>,
}

fn bad(text: String) -> MediaError {
    MediaError::ManifestParse(format!("URL template: {text}"))
}

/// Expand one URL template (`@media`/`@initialization` value) under
/// the given values. Pure; every failure is a `manifest_parse`
/// error naming the offending token, except the output-budget
/// refusal (`manifest_too_large`, [`MAX_EXPANDED_URL_BYTES`] — the
/// guard is checked upfront on the template length and at every
/// growth, so a hostile template refuses before the string is
/// built).
pub fn expand_url_template(
    template: &str,
    values: &TemplateValues<'_>,
) -> Result<String, MediaError> {
    if template.len() > MAX_EXPANDED_URL_BYTES {
        return Err(MediaError::ManifestTooLarge(format!(
            "URL template {} bytes over the {} byte expansion bound",
            template.len(),
            MAX_EXPANDED_URL_BYTES
        )));
    }
    let over_budget = || {
        MediaError::ManifestTooLarge(format!(
            "URL template expands over the {} byte bound",
            MAX_EXPANDED_URL_BYTES
        ))
    };
    let bytes = template.as_bytes();
    let mut out = String::with_capacity(template.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'$' {
            // Template values are attribute-unescaped before arriving
            // here; push the byte as a char boundary (values come from
            // the parser as &str, so multi-byte UTF-8 rides whole).
            let ch_len = utf8_len(bytes[i]);
            let chunk = template
                .get(i..i + ch_len)
                .ok_or_else(|| bad("multibyte truncation".to_string()))?;
            out.push_str(chunk);
            if out.len() > MAX_EXPANDED_URL_BYTES {
                return Err(over_budget());
            }
            i += ch_len;
            continue;
        }
        // "$$" escape.
        if bytes.get(i + 1) == Some(&b'$') {
            out.push('$');
            if out.len() > MAX_EXPANDED_URL_BYTES {
                return Err(over_budget());
            }
            i += 2;
            continue;
        }
        // identifier: "$" name ["%" format] "$"
        let Some(close_rel) = bytes[i + 1..].iter().position(|b| *b == b'$') else {
            return Err(bad(format!("unpaired '$' at byte {i} in {template:?}")));
        };
        let token = &template[i + 1..i + 1 + close_rel];
        let (name, format) = match token.split_once('%') {
            Some((n, f)) => (n, Some(f)),
            None => (token, None),
        };
        match name {
            "RepresentationID" => {
                if format.is_some() {
                    return Err(bad(
                        "$RepresentationID$ does not take a format tag".to_string()
                    ));
                }
                out.push_str(values.representation_id);
                if out.len() > MAX_EXPANDED_URL_BYTES {
                    return Err(over_budget());
                }
            }
            "Bandwidth" => {
                let width = parse_format(format, "$Bandwidth$")?;
                out.push_str(&render_u64(values.bandwidth, width));
                if out.len() > MAX_EXPANDED_URL_BYTES {
                    return Err(over_budget());
                }
            }
            "Number" => {
                let Some(number) = values.number else {
                    return Err(bad(
                        "$Number$ in a template whose addressing provides no segment \
                         number"
                            .to_string(),
                    ));
                };
                let width = parse_format(format, "$Number$")?;
                out.push_str(&render_u64(number, width));
                if out.len() > MAX_EXPANDED_URL_BYTES {
                    return Err(over_budget());
                }
            }
            "Time" => {
                let Some(time) = values.time else {
                    return Err(bad(
                        "$Time$ in a template whose addressing provides no segment \
                         time"
                            .to_string(),
                    ));
                };
                let width = parse_format(format, "$Time$")?;
                out.push_str(&render_u64(time, width));
                if out.len() > MAX_EXPANDED_URL_BYTES {
                    return Err(over_budget());
                }
            }
            other => {
                return Err(bad(format!(
                    "unknown identifier ${other}$ (known: RepresentationID, \
                     Bandwidth, Number, Time)"
                )));
            }
        }
        i = i + 1 + close_rel + 1;
    }
    Ok(out)
}

/// One format tag's parsed form: minimal width + conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatTag {
    /// Minimum field width (0 = none).
    pub width: usize,
    /// Conversion: `d` decimal, `x` lower-hex, `X` upper-hex.
    pub conversion: Conversion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conversion {
    Decimal,
    LowerHex,
    UpperHex,
}

fn parse_format(format: Option<&str>, owner: &str) -> Result<FormatTag, MediaError> {
    let Some(f) = format else {
        return Ok(FormatTag {
            width: 0,
            conversion: Conversion::Decimal,
        });
    };
    let conversion = match f.as_bytes().last() {
        Some(b'd') => Conversion::Decimal,
        Some(b'x') => Conversion::LowerHex,
        Some(b'X') => Conversion::UpperHex,
        _ => {
            return Err(bad(format!(
                "{owner} format tag {f:?}: conversion must be d, x or X"
            )));
        }
    };
    let digits = &f[..f.len() - 1];
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad(format!(
            "{owner} format tag {f:?}: width must be decimal digits"
        )));
    }
    let width = digits
        .parse::<usize>()
        .map_err(|e| bad(format!("{owner} format tag {f:?}: width: {e}")))?;
    if width > MAX_FORMAT_WIDTH {
        return Err(bad(format!(
            "{owner} format tag {f:?}: width {width} over the {MAX_FORMAT_WIDTH} cap (padding              abuse, not a template)"
        )));
    }
    Ok(FormatTag { width, conversion })
}

fn render_u64(value: u64, format: FormatTag) -> String {
    let mut text = match format.conversion {
        Conversion::Decimal => value.to_string(),
        Conversion::LowerHex => format!("{value:x}"),
        Conversion::UpperHex => format!("{value:X}"),
    };
    if format.width > text.len() {
        let pad = format.width - text.len();
        text.insert_str(0, &"0".repeat(pad));
    }
    text
}

/// Length in bytes of the UTF-8 sequence starting with `first`
/// (ASCII fast path; invalid leads are clamped to 1 and the caller's
/// slice check turns them into an error — the parser hands out
/// well-formed `&str`, so this is defense in depth).
fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vals(number: Option<u64>, time: Option<u64>) -> TemplateValues<'static> {
        TemplateValues {
            representation_id: "v720",
            bandwidth: 750_000,
            number,
            time,
        }
    }

    #[test]
    fn identifier_substitution() {
        let v = vals(Some(4), Some(1800));
        assert_eq!(
            expand_url_template("seg-$RepresentationID$-$Bandwidth$.m4s", &v)
                .unwrap_or_else(|e| panic!("{e}")),
            "seg-v720-750000.m4s"
        );
        assert_eq!(
            expand_url_template("$Number$.m4s", &v).unwrap_or_else(|e| panic!("{e}")),
            "4.m4s"
        );
        assert_eq!(
            expand_url_template("t/$Time$.m4s", &v).unwrap_or_else(|e| panic!("{e}")),
            "t/1800.m4s"
        );
        // $$ escape, and the $-free fast path.
        assert_eq!(
            expand_url_template("a$$b-$Number$", &v).unwrap_or_else(|e| panic!("{e}")),
            "a$b-4"
        );
        assert_eq!(
            expand_url_template("plain.m4s", &v).unwrap_or_else(|e| panic!("{e}")),
            "plain.m4s"
        );
    }

    #[test]
    fn format_tags() {
        let v = vals(Some(42), Some(255));
        assert_eq!(
            expand_url_template("$Number%05d$.m4s", &v).unwrap_or_else(|e| panic!("{e}")),
            "00042.m4s"
        );
        assert_eq!(
            expand_url_template("$Time%04x$.m4s", &v).unwrap_or_else(|e| panic!("{e}")),
            "00ff.m4s"
        );
        assert_eq!(
            expand_url_template("$Time%04X$.m4s", &v).unwrap_or_else(|e| panic!("{e}")),
            "00FF.m4s"
        );
        // Width below the natural width is a no-op (no truncation).
        assert_eq!(
            expand_url_template("$Number%2d$", &v).unwrap_or_else(|e| panic!("{e}")),
            "42"
        );
    }

    #[test]
    fn format_width_cap_refuses_padding_abuse() {
        let v = vals(Some(1), Some(1));
        // The review-block PoC shape: a 9-digit width pads every
        // expanded URL toward 100MB — refused at parse, zero alloc.
        for tag in ["$Number%100000000d$", "$Time%65d$", "$Bandwidth%99999999x$"] {
            let err = expand_url_template(tag, &v)
                .err()
                .unwrap_or_else(|| panic!("expected a refusal for {tag}"));
            assert_eq!(err.code(), "taiji.media.manifest_parse", "{tag}: {err}");
            assert!(err.to_string().contains("over the 64 cap"), "{err}");
        }
        // The cap itself is legal (64 = the boundary width).
        let out = expand_url_template("$Number%064d$", &v).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(out.len(), 64, "width 64 pads to exactly 64 chars");
        assert!(out.ends_with('1'));
    }

    #[test]
    fn expansion_output_bound_refuses_at_zero_alloc() {
        let v = vals(Some(1), Some(1));
        // A literal template over the bound: refused upfront on the
        // template length, before any string is built.
        let long = format!("{}.m4s", "a".repeat(MAX_EXPANDED_URL_BYTES));
        let err = expand_url_template(&long, &v)
            .err()
            .unwrap_or_else(|| panic!("expected a refusal"));
        assert_eq!(err.code(), "taiji.media.manifest_too_large", "{err}");
        // A short template whose substitutions cross the bound (the
        // growth-check path): ~500 x $RepresentationID$ at 200 chars.
        let mut dense = String::new();
        for _ in 0..500 {
            dense.push_str("$RepresentationID$");
        }
        let wide = TemplateValues {
            representation_id: &"r".repeat(200),
            ..v
        };
        let err = expand_url_template(&dense, &wide)
            .err()
            .unwrap_or_else(|| panic!("expected a refusal"));
        assert_eq!(err.code(), "taiji.media.manifest_too_large", "{err}");
        // Under the bound: fine.
        let ok = expand_url_template("$RepresentationID$-$Number%05d$.m4s", &v)
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(ok.len() < MAX_EXPANDED_URL_BYTES);
    }

    #[test]
    fn errors() {
        let v = vals(Some(1), Some(1));
        // Unknown identifier.
        assert!(expand_url_template("$Unknown$", &v).is_err());
        // Unpaired $.
        assert!(expand_url_template("a$Number", &v).is_err());
        // Bad conversion / width.
        assert!(expand_url_template("$Number%5s$", &v).is_err());
        assert!(expand_url_template("$Number%d$", &v).is_err());
        // $RepresentationID$ with a format tag.
        assert!(expand_url_template("$RepresentationID%03d$", &v).is_err());
        // $Number$/$Time$ without a value.
        let bare = vals(None, None);
        assert!(expand_url_template("$Number$.m4s", &bare).is_err());
        assert!(expand_url_template("$Time$.m4s", &bare).is_err());
    }
}
