//! Output-template expansion + forced sanitization (the media spec's
//! naming/sanitization red line).
//!
//! 0.3 field domain = manifest-available only: `{title}{id}{ext}{res}
//! {lang}{playlist_index}` (rich fields unlock via the 0.5 bridge —
//! the context fills what the manifest knows, the rest
//! expand to `NA`, the yt-dlp convention). `{title}`/`{ext}` are
//! treated as **untrusted remote strings**: whatever they
//! carry, the expanded result passes [`sanitize_output_name`] —
//! basename-ization, leading-`-`/absolute-path rejection, NUL/control
//! stripping, Unicode NFC normalization, length + charset clamping
//! (the product spec's same profile). A rewrite that changes the name raises the
//! `taiji.media.template_unsafe` warning (the caller emits it through
//! the phaseChanged bypass).

use crate::error::MediaError;

/// The 0.3 template fields (the manifest-available domain).
pub const TEMPLATE_FIELDS: &[&str] = &["title", "id", "ext", "res", "lang", "playlist_index"];

/// Template expansion context: everything the 0.3 manifest face
/// knows. `None` fields expand to `NA` (never empty — an empty
/// expansion can degenerate into a dot-only name).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TemplateContext {
    pub title: Option<String>,
    pub id: Option<String>,
    pub ext: Option<String>,
    pub res: Option<String>,
    pub lang: Option<String>,
    pub playlist_index: Option<String>,
}

impl TemplateContext {
    fn field(&self, name: &str) -> Option<&str> {
        match name {
            "title" => self.title.as_deref(),
            "id" => self.id.as_deref(),
            "ext" => self.ext.as_deref(),
            "res" => self.res.as_deref(),
            "lang" => self.lang.as_deref(),
            "playlist_index" => self.playlist_index.as_deref(),
            _ => None,
        }
    }
}

/// Expand a template (`None`/empty = the `{id}.{ext}` default shape,
/// falling back to plain `{id}` when the context has no ext). Unknown
/// fields are an explicit error (a typo'd field silently producing
/// garbage names is worse than a refused task).
pub fn expand_template(
    template: Option<&str>,
    ctx: &TemplateContext,
) -> Result<String, MediaError> {
    let raw = match template.map(str::trim).filter(|t| !t.is_empty()) {
        None => {
            return Ok(match &ctx.ext {
                Some(ext) => format!("{}.{}", ctx.id.as_deref().unwrap_or("NA"), ext),
                None => ctx.id.clone().unwrap_or_else(|| "media".to_string()),
            });
        }
        Some(t) => t,
    };
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close_rel) = after.find('}') else {
            return Err(MediaError::OptionInvalid(format!(
                "--media-template {raw:?}: unterminated placeholder"
            )));
        };
        let field = &after[..close_rel];
        if !TEMPLATE_FIELDS.contains(&field) {
            return Err(MediaError::OptionInvalid(format!(
                "--media-template field {{{field}}}: unknown (0.3 domain: {TEMPLATE_FIELDS:?})"
            )));
        }
        out.push_str(ctx.field(field).unwrap_or("NA"));
        rest = &after[close_rel + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Max output-name length in **bytes** (the fs-name budget; 0.3
/// clamps at 200 — comfortably inside every supported fs limit while
/// staying human-plausible).
pub const MAX_OUTPUT_NAME_BYTES: usize = 200;

/// The sanitization verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizedName {
    /// The sanitized basename (never empty; the `media` fallback when
    /// everything was stripped).
    pub name: String,
    /// True when anything was rewritten (the `template_unsafe`
    /// warning trigger).
    pub rewritten: bool,
    /// What was rewritten (the warning payload).
    pub reasons: Vec<&'static str>,
}

/// Sanitize an expanded output name (the product spec's same profile; the red
/// line — every product name passes here, template or not):
///
/// * Unicode spoofing neutralization (the normalization
/// vector): bidi-override/zero-width characters
/// ([`taiji_io::text::is_spoofing_char`], the shared spoofing set)
/// and combining marks (the composed/decomposed spoof family,
/// `A\u{030A}` vs `Å`) are stripped — a product name can never carry
/// a hidden normalization lookalike. Full NFC *composition* would
/// add the `unicode-normalization` crate — a workspace-dependency
/// decision owned by the coordination face (recorded in the design
/// report); neutralization closes the attack family without it;
/// * basename-ization: every path separator (`/`, `\`) and any
/// `..`/`.` **path component** collapses — the result can never
/// escape the output directory;
/// * NUL and C0/C1 control characters stripped;
/// * a leading `-` (the argv-injection face) is prefixed off;
/// * length clamp to [`MAX_OUTPUT_NAME_BYTES`] on UTF-8 sequence
/// boundaries (no interior code-point splits);
/// * the empty result falls back to `media`.
pub fn sanitize_output_name(input: &str) -> SanitizedName {
    let mut reasons = Vec::new();
    let mut rewritten = false;

    // 1. Unicode spoofing neutralization (bidi/zero-width + combining
    // marks — the normalization-lookalike family).
    let neutralized: String = input
        .chars()
        .filter(|c| {
            if taiji_io::text::is_spoofing_char(*c) || is_combining_mark(*c) {
                reasons.push("unicode-spoofing-stripped");
                rewritten = true;
                false
            } else {
                true
            }
        })
        .collect();
    // 2. Basename-ization: split on both separators, drop `.`/`..`
    // components entirely (an `a/../b` collapses to `b`; a name that
    // was only separators/dots falls to the final fallback).
    let mut parts: Vec<&str> = Vec::new();
    for comp in neutralized.split(['/', '\\']) {
        match comp {
            "." | ".." => {
                reasons.push("path-component-stripped");
                rewritten = true;
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("_");
    // 3. Control characters (NUL included) stripped.
    let stripped: String = joined
        .chars()
        .filter(|c| {
            if c.is_control() {
                reasons.push("control-character-stripped");
                rewritten = true;
                false
            } else {
                true
            }
        })
        .collect();
    // Whitespace trim (a padded name is not worth refusing, but a
    // trailing space is a Windows hazard).
    let trimmed = stripped.trim().to_string();
    if trimmed != stripped {
        reasons.push("whitespace-trimmed");
        rewritten = true;
    }
    // 4. Leading `-`: the argv face — prefix it off.
    let no_dash = if trimmed.starts_with('-') {
        reasons.push("leading-dash-prefixed");
        rewritten = true;
        format!("_{trimmed}")
    } else {
        trimmed
    };
    // 5. Length clamp (UTF-8 sequence boundaries — never splits a
    // code point, multi-byte names clamp on whole characters).
    let clamped: String = if no_dash.len() > MAX_OUTPUT_NAME_BYTES {
        reasons.push("length-clamped");
        rewritten = true;
        let mut out = String::new();
        for ch in no_dash.chars() {
            if out.len() + ch.len_utf8() > MAX_OUTPUT_NAME_BYTES {
                break;
            }
            out.push(ch);
        }
        out
    } else {
        no_dash
    };
    // 6. Empty / degenerate fallback: an empty result (everything
    // stripped) OR a path-magic bare `.`/`..` (component
    // collapsing runs BEFORE the whitespace trim, so a padded
    // " .. " survives collapsing as the single component " .. "
    // and then trims to `..` — the fuzzer's findings)
    // falls back to `media`: a product name is always a creatable
    // regular filename.
    let name = if clamped.is_empty() || clamped == "." || clamped == ".." {
        reasons.push("empty-fallback");
        rewritten = true;
        "media".to_string()
    } else {
        clamped
    };
    SanitizedName {
        name,
        rewritten,
        reasons,
    }
}

/// Combining-mark ranges (the composed/decomposed spoof family; the
/// common diacritical block plus the extended combining blocks). A
/// product name never needs a bare combining mark.
fn is_combining_mark(c: char) -> bool {
    matches!(
        c,
        '\u{0300}'..='\u{036f}'      // combining diacritical marks
            | '\u{0483}'..='\u{0489}'
            | '\u{1ab0}'..='\u{1aff}'
            | '\u{1dc0}'..='\u{1dff}'
            | '\u{20d0}'..='\u{20ff}'
            | '\u{fe20}'..='\u{fe2f}' // combining half marks
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> TemplateContext {
        TemplateContext {
            title: Some("Big Buck Bunny".into()),
            id: Some("aBc123".into()),
            ext: Some("mp4".into()),
            res: Some("1280x720".into()),
            lang: Some("en".into()),
            playlist_index: Some("01".into()),
        }
    }

    #[test]
    fn expansion_domain() {
        assert_eq!(
            expand_template(Some("{title}-{id}.{ext}"), &ctx()).ok(),
            Some("Big Buck Bunny-aBc123.mp4".into())
        );
        // Missing fields expand to NA.
        let partial = TemplateContext {
            id: Some("x".into()),
            ext: Some("mp4".into()),
            ..Default::default()
        };
        assert_eq!(
            expand_template(Some("{title}.{id}.{ext}"), &partial).ok(),
            Some("NA.x.mp4".into())
        );
        // The default shape.
        assert_eq!(
            expand_template(None, &ctx()).ok(),
            Some("aBc123.mp4".into())
        );
        assert_eq!(
            expand_template(None, &TemplateContext::default()).ok(),
            Some("media".into())
        );
        // Unknown fields refuse.
        for bad in ["{uploader}", "{format}", "{title", "{}", "{TITLE}"] {
            assert!(
                expand_template(Some(bad), &ctx()).is_err(),
                "{bad:?} must be refused (0.3 domain)"
            );
        }
    }

    /// The template-injection vectors (all-platform unit face):
    /// `../`, leading `-`, NUL, overlong, Unicode normalization.
    #[test]
    fn injection_vectors_all_neutralized() {
        // (1) Path traversal — every `../` form collapses to a
        // basename (also via backslashes and mixed separators).
        for evil in [
            "../../etc/passwd",
            "a/../../b.mp4",
            "..\\..\\win.ini",
            "ok.mp4\\..\\..\\x",
            "..",
            "../",
            "a/../..",
        ] {
            let s = sanitize_output_name(evil);
            assert!(
                !s.name.contains('/'),
                "{evil:?} -> {:?} still carries a separator",
                s.name
            );
            assert!(!s.name.contains('\\'), "{evil:?} -> {:?}", s.name);
            assert_ne!(s.name, "..");
            assert!(s.rewritten, "{evil:?} must be flagged");
        }
        // (2) Leading dash (the argv face).
        let s = sanitize_output_name("-report.pdf.mp4");
        assert!(
            s.name.starts_with('_'),
            "leading - prefixed off: {:?}",
            s.name
        );
        assert!(s.rewritten);
        // (3) NUL + control characters.
        let s = sanitize_output_name("na\x00me\t.mp4\x1b");
        assert!(!s.name.chars().any(char::is_control), "{:?}", s.name);
        assert!(s.rewritten);
        // (4) Overlong — clamped on UTF-8 sequence boundaries, still
        // valid UTF-8.
        let long = "x".repeat(MAX_OUTPUT_NAME_BYTES + 100);
        let s = sanitize_output_name(&long);
        assert_eq!(s.name.len(), MAX_OUTPUT_NAME_BYTES);
        // (5) Unicode normalization vector: the decomposed form
        // (`A` + combining ring U+030A, spoofing `Å`) loses the bare
        // combining mark; the bidi-override family (U+202E RLO — the
        // "Evil.exe" face) is stripped; the result can never carry a
        // hidden lookalike sequence.
        let decomposed = "A\u{030A}.mp4";
        let s = sanitize_output_name(decomposed);
        assert_eq!(s.name, "A.mp4");
        assert!(s.rewritten);
        let trojan = "\u{202E}evil.mp4";
        let s = sanitize_output_name(trojan);
        assert_eq!(s.name, "evil.mp4");
        assert!(s.rewritten);
        // A clean name passes untouched.
        let clean = sanitize_output_name("Big Buck Bunny-aBc123.mp4");
        assert!(!clean.rewritten);
        assert_eq!(clean.name, "Big Buck Bunny-aBc123.mp4");
        // (6) The degenerate lone-dot form (a padded dot trims to it
        // after component collapsing — the fuzz finding):
        // the media fallback, never an uncreatable `.` filename.
        for degenerate in [" .", ".", " . ", "\t.\n", " ..", "  ..  ", ".."] {
            let s = sanitize_output_name(degenerate);
            assert_eq!(s.name, "media", "{degenerate:?} must fall back");
            assert!(s.rewritten, "{degenerate:?} must be flagged");
        }
        // The remote-string posture end to end: a hostile {title}
        // value cannot escape the output directory.
        let hostile = expand_template(Some("{title}/../{id}.{ext}"), &ctx())
            .unwrap_or_else(|e| panic!("{e}"));
        let s = sanitize_output_name(&hostile);
        assert_eq!(s.name, "Big Buck Bunny_aBc123.mp4");
        assert!(s.rewritten);
    }

    /// A multi-byte length clamp never splits a code point.
    #[test]
    fn length_clamp_respects_char_boundaries() {
        let name = "é".repeat(MAX_OUTPUT_NAME_BYTES);
        let s = sanitize_output_name(&name);
        assert!(s.name.len() <= MAX_OUTPUT_NAME_BYTES);
        assert_eq!(s.name.chars().count(), MAX_OUTPUT_NAME_BYTES / 2);
    }
}
