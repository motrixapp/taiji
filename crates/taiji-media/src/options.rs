//! Media download option faces: typed values + strict
//! parsing/validation for the flags wired here. Registration on
//! the unified option surface (`RPC_METHOD_INFO`/options table) is
//! a later step — the parse faces here are the single source
//! the registration will mount, same posture as the
//! `--media-variant-policy` flag face, which
//! follows the require_equals discipline first; unified
//! registration comes with the unified option surface.
//!
//! require_equals note: these values are parsed strictly —
//! an empty or out-of-domain value is an explicit error, never a
//! silent default; the CLI layer's `--flag=value` discipline applies
//! at registration time.

use std::path::PathBuf;

use crate::error::MediaError;

/// `--media-segment-concurrency` default (per-task
/// segment concurrency, default 8).
pub const DEFAULT_SEGMENT_CONCURRENCY: u32 = 8;

/// `--media-segment-concurrency` domain lower bound (inclusive).
pub const MIN_SEGMENT_CONCURRENCY: u32 = 1;

/// `--media-segment-concurrency` domain upper bound (inclusive,
/// the declared domain 1..64).
pub const MAX_SEGMENT_CONCURRENCY: u32 = 64;

/// `--media-staging-quota-gib` default (default quota
/// 50GiB, built-in constant).
pub const DEFAULT_STAGING_QUOTA_GIB: u64 = 50;

/// Parse `--media-segment-concurrency` (integer, domain
/// 1..=64; out-of-domain is an explicit error — no truncation, the
/// options fail honestly).
pub fn parse_segment_concurrency(input: &str) -> Result<u32, MediaError> {
    let value = input
        .trim()
        .parse::<u32>()
        .map_err(|_| option_invalid("--media-segment-concurrency", input, "an integer"))?;
    if !(MIN_SEGMENT_CONCURRENCY..=MAX_SEGMENT_CONCURRENCY).contains(&value) {
        return Err(option_invalid(
            "--media-segment-concurrency",
            input,
            "in 1..=64",
        ));
    }
    Ok(value)
}

/// Parse `--media-subtitles` (`sidecar|none`; default `sidecar` —
/// the sidecar product face itself is the synthesis line; this
/// module downloads sidecar tracks into staging only).
pub fn parse_subtitles(input: &str) -> Result<SubtitleMode, MediaError> {
    match input.trim() {
        "sidecar" => Ok(SubtitleMode::Sidecar),
        "none" => Ok(SubtitleMode::None),
        other => Err(option_invalid("--media-subtitles", other, "sidecar|none")),
    }
}

/// `--media-subtitles` value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SubtitleMode {
    /// `sidecar` (default): subtitle renditions download into
    /// staging; the VTT-concat product face is the synthesis line.
    #[default]
    Sidecar,
    /// `none`: no subtitle tracks.
    None,
}

/// Parse `--media-audio-lang` (RFC 5646 tag; empty = policy chain
/// unchanged — the language tier is simply absent, DEFAULT→en→order
/// still applies). Validation is the RFC 5646 "well-formed prefix"
/// shape: ASCII letters/digits/hyphen segments, at least one segment
/// (the full grammar validation belongs to the matcher, which does
/// case-insensitive prefix matching).
pub fn parse_audio_lang(input: &str) -> Result<Option<String>, MediaError> {
    let t = input.trim();
    if t.is_empty() {
        return Ok(None);
    }
    let mut segments = 0usize;
    for seg in t.split('-') {
        if seg.is_empty() || !seg.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(option_invalid(
                "--media-audio-lang",
                input,
                "an RFC 5646 language tag",
            ));
        }
        segments += 1;
    }
    if segments == 0 {
        return Err(option_invalid(
            "--media-audio-lang",
            input,
            "an RFC 5646 language tag",
        ));
    }
    Ok(Some(t.to_ascii_lowercase()))
}

/// Parse `--media-staging-quota-gib` (integer GiB, >= 1; 0 makes the
/// staging face unusable, an explicit domain error).
pub fn parse_staging_quota_gib(input: &str) -> Result<u64, MediaError> {
    let value = input
        .trim()
        .parse::<u64>()
        .map_err(|_| option_invalid("--media-staging-quota-gib", input, "an integer"))?;
    if value == 0 {
        return Err(option_invalid(
            "--media-staging-quota-gib",
            input,
            ">= 1 (GiB)",
        ));
    }
    Ok(value)
}

/// `--media-staging-dir` (a directory path; `None` = same-volume
/// default `<dir>/.taiji-b`).
pub fn parse_staging_dir(input: &str) -> Result<PathBuf, MediaError> {
    let t = input.trim();
    if t.is_empty() {
        return Err(option_invalid(
            "--media-staging-dir",
            input,
            "a directory path",
        ));
    }
    Ok(PathBuf::from(t))
}

/// Parse `--media-allow-private-key-url` (`true|false`, default false;
/// per the product spec). Scope note: the flag governs **both**
/// SSRF-line
/// faces — key URIs *and* media-segment/init-section URLs
/// (the media line widens the key-only rule; one threat model, one
/// escape hatch; the widened
/// scope of the original key-only name is recorded for the unified
/// registration / difference declaration).
pub fn parse_allow_private_key_url(input: &str) -> Result<bool, MediaError> {
    match input.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(option_invalid(
            "--media-allow-private-key-url",
            other,
            "true|false",
        )),
    }
}

/// Parse `--media-archive` (`true|false`, default false): per-task
/// download-archive recording + the duplicate
/// checkpoints. The session-global face sets the default; the
/// addMedia per-task key wins (the family's merge rule).
pub fn parse_media_archive(input: &str) -> Result<bool, MediaError> {
    match input.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(option_invalid("--media-archive", other, "true|false")),
    }
}

/// Parse `--media-info-json` (`true|false`, default false): the
/// whitelisted+redacted info.json sidecar export at the
/// Done close-out. Orthogonal to `--no-meta` (the embed face is
/// `--no-meta`'s; the export face is this flag's alone).
pub fn parse_media_info_json(input: &str) -> Result<bool, MediaError> {
    match input.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(option_invalid("--media-info-json", other, "true|false")),
    }
}

/// Parse `--media-archive-clear` (`true|false`; the one-shot CLI
/// pre-clear face — the `taiji.clearMediaArchive` RPC's CLI
/// counterpart). Not a task option; accepted here so every face
/// shares one value domain.
pub fn parse_media_archive_clear(input: &str) -> Result<bool, MediaError> {
    match input.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(option_invalid("--media-archive-clear", other, "true|false")),
    }
}

/// `--media-ffmpeg-path` value (the fallback channel's
/// discovery input; the `--media-ffmpeg-path=auto` face —
/// `auto` (default) runs the discovery precedence chain; a directory
/// is the precedence-1 explicit parameter; the `path:` prefix
/// declares an explicit-PATH opt-in (that PATH posture is carried
/// for the unified registration; the discovery applies it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FfmpegPathSpec {
    /// `auto` — the discovery precedence chain.
    Auto,
    /// An explicit directory (precedence 1).
    Explicit(PathBuf),
    /// `path:<dir>` — explicit PATH opt-in (host-injection escape
    /// hatch posture; discovery + the start precheck honor it).
    PathOptIn(PathBuf),
}

/// Parse `--media-ffmpeg-path` (`auto | <dir> | path:<dir>`).
pub fn parse_ffmpeg_path(input: &str) -> Result<FfmpegPathSpec, MediaError> {
    let t = input.trim();
    if t.is_empty() {
        return Err(option_invalid(
            "--media-ffmpeg-path",
            input,
            "auto|<dir>|path:<dir>",
        ));
    }
    if t == "auto" {
        return Ok(FfmpegPathSpec::Auto);
    }
    if let Some(rest) = t.strip_prefix("path:") {
        if rest.trim().is_empty() {
            return Err(option_invalid(
                "--media-ffmpeg-path",
                input,
                "path:<dir> needs a directory",
            ));
        }
        return Ok(FfmpegPathSpec::PathOptIn(PathBuf::from(rest.trim())));
    }
    Ok(FfmpegPathSpec::Explicit(PathBuf::from(t)))
}

/// `--media-output-format` value (media group:
/// `mp4|mkv`, default mp4 — mkv routes through the
/// ffmpeg fallback).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OutputFormat {
    /// `mp4` (default).
    #[default]
    Mp4,
    /// `mkv` — fallback channel territory.
    Mkv,
}

/// Parse `--media-output-format` (`mp4|mkv`).
pub fn parse_output_format(input: &str) -> Result<OutputFormat, MediaError> {
    match input.trim() {
        "mp4" => Ok(OutputFormat::Mp4),
        "mkv" => Ok(OutputFormat::Mkv),
        other => Err(option_invalid("--media-output-format", other, "mp4|mkv")),
    }
}

/// `--media-muxer` value (the user-explicit fallback trigger
/// face; `native|ffmpeg|auto`, default
/// auto — native primary with the fallback net).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MuxerSpec {
    /// `auto` — native first, fallback as the safety net.
    #[default]
    Auto,
    /// `native` — the fallback never runs.
    Native,
    /// `ffmpeg` — user-explicit fallback (native never runs).
    Ffmpeg,
}

/// Parse `--media-muxer` (`native|ffmpeg|auto`).
pub fn parse_muxer(input: &str) -> Result<MuxerSpec, MediaError> {
    match input.trim() {
        "auto" => Ok(MuxerSpec::Auto),
        "native" => Ok(MuxerSpec::Native),
        "ffmpeg" => Ok(MuxerSpec::Ffmpeg),
        other => Err(option_invalid("--media-muxer", other, "native|ffmpeg|auto")),
    }
}

fn option_invalid(flag: &str, value: &str, expected: &str) -> MediaError {
    MediaError::OptionInvalid(format!("{flag} {value:?}: expected {expected}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_concurrency_domain() {
        assert_eq!(
            parse_segment_concurrency("8").ok(),
            Some(DEFAULT_SEGMENT_CONCURRENCY)
        );
        assert_eq!(parse_segment_concurrency("1").ok(), Some(1));
        assert_eq!(parse_segment_concurrency("64").ok(), Some(64));
        for bad in ["0", "65", "-1", "abc", "", " 8x"] {
            assert!(
                parse_segment_concurrency(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn subtitles_domain() {
        assert_eq!(parse_subtitles("sidecar").ok(), Some(SubtitleMode::Sidecar));
        assert_eq!(parse_subtitles("none").ok(), Some(SubtitleMode::None));
        for bad in ["both", "", "SIDEcar"] {
            assert!(parse_subtitles(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn audio_lang_shape() {
        assert_eq!(parse_audio_lang(""), Ok(None));
        assert_eq!(
            parse_audio_lang("EN").ok().flatten(),
            Some("en".to_string()),
            "normalized lowercase"
        );
        assert_eq!(
            parse_audio_lang("zh-Hans-CN").ok().flatten(),
            Some("zh-hans-cn".to_string())
        );
        for bad in ["-", "en-", "-en", "en us", "en_US"] {
            assert!(parse_audio_lang(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn quota_domain() {
        assert_eq!(parse_staging_quota_gib("50").ok(), Some(50));
        assert_eq!(
            parse_staging_quota_gib("50").ok(),
            Some(DEFAULT_STAGING_QUOTA_GIB)
        );
        for bad in ["0", "-1", "x", ""] {
            assert!(parse_staging_quota_gib(bad).is_err(), "{bad:?} rejected");
        }
    }

    #[test]
    fn staging_dir_shape() {
        assert!(parse_staging_dir("").is_err());
        assert_eq!(
            parse_staging_dir("/tmp/s").ok(),
            Some(PathBuf::from("/tmp/s"))
        );
    }

    #[test]
    fn allow_private_key_url_domain() {
        assert!(!parse_allow_private_key_url("false").unwrap_or(true));
        assert!(parse_allow_private_key_url("true").unwrap_or(false));
        for bad in ["", "yes", "1", "TRUE", "True"] {
            assert!(
                parse_allow_private_key_url(bad).is_err(),
                "{bad:?} must be rejected (require_equals discipline)"
            );
        }
    }

    #[test]
    fn ffmpeg_path_domain() {
        assert_eq!(parse_ffmpeg_path("auto").ok(), Some(FfmpegPathSpec::Auto));
        assert_eq!(
            parse_ffmpeg_path("/opt/ffmpeg").ok(),
            Some(FfmpegPathSpec::Explicit(PathBuf::from("/opt/ffmpeg")))
        );
        assert_eq!(
            parse_ffmpeg_path("path:/usr/local/bin").ok(),
            Some(FfmpegPathSpec::PathOptIn(PathBuf::from("/usr/local/bin")))
        );
        for bad in ["", "  ", "path:"] {
            assert!(parse_ffmpeg_path(bad).is_err(), "{bad:?} rejected");
        }
    }

    #[test]
    fn output_format_domain() {
        assert_eq!(parse_output_format("mp4").ok(), Some(OutputFormat::Mp4));
        assert_eq!(parse_output_format("mkv").ok(), Some(OutputFormat::Mkv));
        for bad in ["", "MP4", "mov", "webm"] {
            assert!(parse_output_format(bad).is_err(), "{bad:?} rejected");
        }
    }

    #[test]
    fn muxer_domain() {
        assert_eq!(parse_muxer("auto").ok(), Some(MuxerSpec::Auto));
        assert_eq!(parse_muxer("native").ok(), Some(MuxerSpec::Native));
        assert_eq!(parse_muxer("ffmpeg").ok(), Some(MuxerSpec::Ffmpeg));
        for bad in ["", "FFMPEG", "both"] {
            assert!(parse_muxer(bad).is_err(), "{bad:?} rejected");
        }
        // Trim tolerance follows the other option faces.
        assert_eq!(
            parse_muxer("auto ").ok(),
            Some(MuxerSpec::Auto),
            "trim tolerance (the established parse face)"
        );
    }
}
