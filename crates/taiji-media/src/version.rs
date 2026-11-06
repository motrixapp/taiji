//! `ffmpeg/ffprobe -version` parsing + the LGPL configuration-string
//! assertion (the product spec's version/packaging sections).
//!
//! Parsed shape (both binaries, identical grammar):
//!
//! ```text
//! ffmpeg version 9.0.2 Copyright (c) 2000-2026 the FFmpeg developers
//! built with Apple clang version 21.0.0 (clang-210.0.3.34.2)
//! configuration: --prefix=... --enable-shared --enable-gpl ...
//! libavutil 61. 1.102 / 61. 1.102
//! ```
//!
//! The license assertion is token-exact over the space-separated
//! configuration flags: `--disable-gpl` and friends never false-positive.
//! `--enable-gpl` / `--enable-nonfree` must both be absent — the LGPL
//! face of the 0.3.0 packaging plan (prebuilt allowlist +
//! configuration-string assertion; GPL/nonfree builds are rejected).
//!
//! Strictness tiers: `Gate` (assertion failure = error; default) and
//! `Info` (warning only — diagnostics on a dev machine with a distro
//! GPL build).

use crate::error::MediaError;

/// Parsed `-version` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionInfo {
    /// Program token from the first line (`ffmpeg`/`ffprobe`).
    pub program: String,
    /// Version token (`9.0.2`, or an `N-12345-gabcdef0` git build).
    pub version: String,
    /// Raw configuration flags (text after `configuration:`, one line).
    pub configuration: String,
}

impl VersionInfo {
    /// Parse a `-version` stdout block. Tolerant of banner noise before
    /// the version line (a leading `\n` appears on some builds); the
    /// version line and the configuration line are both mandatory — a
    /// block missing either is a `Parse` error (the caller feeds a child
    /// process's captured stdout, never attacker bytes, so strictness is
    /// safe here; the fuzz face is on progress/ffprobe where inputs are
    /// hostile).
    pub fn parse(stdout: &str) -> Result<Self, MediaError> {
        let mut program = String::new();
        let mut version = String::new();
        let mut configuration: Option<String> = None;
        for line in stdout.lines() {
            let line = line.trim();
            if program.is_empty() {
                // "ffmpeg version X ..." / "ffprobe version X ..."
                let mut it = line.split_whitespace();
                match (it.next(), it.next(), it.next()) {
                    (Some(p), Some("version"), Some(v)) => {
                        program = p.to_string();
                        version = v.to_string();
                    }
                    _ => continue,
                }
            } else if let Some(rest) = line.strip_prefix("configuration:") {
                configuration = Some(rest.trim().to_string());
            }
        }
        if program.is_empty() {
            return Err(MediaError::Parse(
                "no `<program> version <x>` line in -version output".to_string(),
            ));
        }
        let configuration = configuration.ok_or_else(|| {
            MediaError::Parse("no `configuration:` line in -version output".to_string())
        })?;
        Ok(Self {
            program,
            version,
            configuration,
        })
    }

    /// argv for the `-version` probe (the single query face used by
    /// doctor and the pairing check).
    pub fn version_args() -> &'static [&'static str] {
        &["-hide_banner", "-version"]
    }
}

/// License audit of one configuration string (`true` = flag present =
/// red).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct LicenseAudit {
    /// `--enable-gpl` present.
    pub gpl: bool,
    /// `--enable-nonfree` present.
    pub nonfree: bool,
}

impl LicenseAudit {
    /// Token-exact audit of a configuration flag string.
    pub fn audit(configuration: &str) -> Self {
        Self {
            gpl: configuration
                .split_whitespace()
                .any(|tok| tok == "--enable-gpl"),
            nonfree: configuration
                .split_whitespace()
                .any(|tok| tok == "--enable-nonfree"),
        }
    }

    /// Green iff neither flag is present (the LGPL-2.1+ packaging face).
    pub fn is_clean(&self) -> bool {
        !self.gpl && !self.nonfree
    }

    /// Human-readable flag list for report lines.
    pub fn offending_flags(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.gpl {
            v.push("--enable-gpl");
        }
        if self.nonfree {
            v.push("--enable-nonfree");
        }
        v
    }
}

/// Strictness tier of the license assertion (gate/info, default
/// gate).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LicenseStrictness {
    /// Assertion failure = error (default; the shipping posture).
    #[default]
    Gate,
    /// Assertion failure = warning (diagnostics on dev machines).
    Info,
}

/// Version-token agreement between the ffmpeg and ffprobe `-version`
/// payloads (the second half of the same-origin pairing contract: same
/// directory at discovery, same version string here). A disagreement is
/// a mixed installation and is refused.
pub fn versions_agree(a: &VersionInfo, b: &VersionInfo) -> bool {
    a.version == b.version
}

/// Apply the strictness tier to an audit result. `Gate` maps a dirty
/// audit to `Err(LicenseGate)`; `Info` logs and passes.
pub fn license_verdict(
    audit: LicenseAudit,
    strictness: LicenseStrictness,
    context: &str,
) -> Result<LicenseAudit, MediaError> {
    if audit.is_clean() {
        return Ok(audit);
    }
    let flags = audit.offending_flags().join(", ");
    match strictness {
        LicenseStrictness::Gate => Err(MediaError::LicenseGate(format!(
            "{context}: configuration carries {flags} (LGPL-2.1+ face)"
        ))),
        LicenseStrictness::Info => {
            tracing::warn!(
                target: "taiji::media",
                "{context}: configuration carries {flags} (info tier — gate would refuse)"
            );
            Ok(audit)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLEAN: &str = "\
ffmpeg version 9.0.2 Copyright (c) 2000-2026 the FFmpeg developers
built with Apple clang version 21.0.0 (clang-210.0.3.34.2)
configuration: --prefix=/opt/ffmpeg --enable-shared --enable-pthreads
libavutil      61.  1.102 / 61.  1.102
";

    #[test]
    fn parses_version_and_configuration() {
        let v = match VersionInfo::parse(CLEAN) {
            Ok(v) => v,
            Err(e) => panic!("parse failed: {e}"),
        };
        assert_eq!(v.program, "ffmpeg");
        assert_eq!(v.version, "9.0.2");
        assert!(v.configuration.contains("--enable-shared"));
    }

    #[test]
    fn rejects_output_without_configuration_line() {
        match VersionInfo::parse("ffmpeg version 9.0.2\n") {
            Err(e) => assert_eq!(e.code(), "taiji.media.ffmpeg_parse"),
            Ok(v) => panic!("unexpected success: {v:?}"),
        }
    }

    #[test]
    fn license_audit_is_token_exact() {
        // A false-positive guard: substring `--enable-gpl` inside another
        // flag must not trip the audit.
        let audit = LicenseAudit::audit("--enable-gplish --enable-nonfree2");
        assert!(audit.is_clean());
        let red = LicenseAudit::audit("--enable-shared --enable-gpl");
        assert_eq!(red.offending_flags(), vec!["--enable-gpl"]);
        assert!(!red.is_clean());
    }
}
