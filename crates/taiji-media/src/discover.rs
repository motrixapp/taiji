//! ffmpeg/ffprobe discovery (the product spec's
//! `--media-ffmpeg-path=auto` face).
//!
//! Resolution order, highest precedence first:
//!
//! 1. explicit caller parameter (library face; the unified option panel will
//!    project `--media-ffmpeg-path` onto it — no CLI option is added in
//!    the initial release, frozen-seam note);
//! 2. `TAIJI_FFMPEG_PATH` environment variable — a *directory* holding
//!    both binaries (ffprobe is derived from the same directory);
//! 3. the packaged-path constant (`TAIJI_FFMPEG_DIR` build-time env; the
//!    packaging pipeline owns setting it — absent in dev builds);
//! 4. `PATH` search.
//!
//! Pairing contract: ffmpeg and ffprobe must resolve from the same
//! origin directory. A PATH search that finds the two binaries in
//! different directories is a hard `OriginMismatch` — never a silent
//! mixed pair (a version-skewed pair produces undiagnosable remux
//! failures). Version-token agreement between the two `-version` outputs
//! is checked at the version layer, not here.

use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::error::MediaError;

/// Environment variable consulted at precedence 2 (directory form).
pub const ENV_FFMPEG_DIR: &str = "TAIJI_FFMPEG_PATH";

/// Build-time packaged-directory constant (precedence 3). Set by the
/// packaging pipeline (`TAIJI_FFMPEG_DIR=/Applications/Motrix.app/
/// Contents/MacOS` or the per-platform equivalent); `None` in dev
/// builds, which falls through to the PATH search.
const PACKAGED_DIR: Option<&str> = option_env!("TAIJI_FFMPEG_DIR");

/// Where a resolved pair came from (doctor reports it verbatim).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoverySource {
    /// Caller-supplied directory (library parameter).
    Explicit(PathBuf),
    /// `TAIJI_FFMPEG_PATH` directory.
    Env(PathBuf),
    /// Build-time packaged constant.
    Packaged(PathBuf),
    /// `PATH` search hit.
    Path(PathBuf),
}

impl DiscoverySource {
    /// Lowercase name for stable JSON rendering.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Explicit(_) => "explicit",
            Self::Env(_) => "env",
            Self::Packaged(_) => "packaged",
            Self::Path(_) => "path",
        }
    }
}

/// A resolved same-origin ffmpeg/ffprobe pair (both paths absolute;
/// `ffmpeg`/`ffprobe` names are fixed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FfmpegPair {
    /// Absolute ffmpeg path.
    pub ffmpeg: PathBuf,
    /// Absolute ffprobe path (same parent directory, verified).
    pub ffprobe: PathBuf,
    /// Winning precedence tier.
    pub source: DiscoverySource,
}

impl FfmpegPair {
    /// Parent directory (the shared origin).
    pub fn dir(&self) -> &Path {
        self.ffmpeg.parent().unwrap_or_else(|| Path::new("/"))
    }
}

/// Executable suffix (empty on unix, `.exe` on Windows).
#[cfg(windows)]
const EXE_SUFFIX: &str = ".exe";
#[cfg(unix)]
const EXE_SUFFIX: &str = "";

/// Candidate enumeration outcome used by both the discovery walk and the
/// unit tests (pure — no filesystem interaction beyond `is_file`).
struct DirCandidate {
    ffmpeg: PathBuf,
    ffprobe: PathBuf,
}

/// Probe one directory for a complete pair (both names present as
/// files; execute bits are the PATH-search caller's concern).
fn dir_candidate(dir: &Path) -> Option<DirCandidate> {
    let ffmpeg = dir.join(binary_name("ffmpeg"));
    let ffprobe = dir.join(binary_name("ffprobe"));
    if ffmpeg.is_file() && ffprobe.is_file() {
        Some(DirCandidate { ffmpeg, ffprobe })
    } else {
        None
    }
}

/// Fixed binary name with the platform suffix folded in.
fn binary_name(base: &str) -> String {
    if cfg!(windows) {
        format!("{base}{EXE_SUFFIX}")
    } else {
        base.to_string()
    }
}

/// Discovery request. `explicit_dir` is precedence 1 (None = skip the
/// tier); the environment/build-time tiers are read from the process
/// environment, which makes them a caller-visible seam — tests pass a
/// scrubbed env through [`discover_with_env`].
#[derive(Debug, Clone, Default)]
pub struct DiscoveryRequest {
    /// Precedence-1 directory (caller parameter; `--media-ffmpeg-path`
    /// projects here in M1).
    pub explicit_dir: Option<PathBuf>,
}

/// Discover the pair against the live process environment.
pub fn discover(request: &DiscoveryRequest) -> Result<FfmpegPair, MediaError> {
    let env_dir = env::var_os(ENV_FFMPEG_DIR).map(PathBuf::from);
    discover_with_env(request, env_dir.as_deref(), PACKAGED_DIR)
}

/// Discovery with the environment/packaged tiers injected (pure seam:
/// the precedence order and pairing rules are testable without process
/// environment mutation).
///
/// A tier's directory candidate participates only when *both* binaries
/// are present in it — an `TAIJI_FFMPEG_PATH` directory holding ffmpeg
/// but not ffprobe is a hard error (not a silent fallthrough to PATH:
/// the operator asked for that directory explicitly), while an absent
/// tier falls through.
pub fn discover_with_env(
    request: &DiscoveryRequest,
    env_dir: Option<&Path>,
    packaged_dir: Option<&str>,
) -> Result<FfmpegPair, MediaError> {
    if let Some(dir) = request.explicit_dir.as_deref() {
        return pair_from_dir(dir, DiscoverySource::Explicit(dir.to_path_buf()));
    }
    if let Some(dir) = env_dir {
        return pair_from_dir(dir, DiscoverySource::Env(dir.to_path_buf()));
    }
    if let Some(dir) = packaged_dir {
        return pair_from_dir(
            Path::new(dir),
            DiscoverySource::Packaged(PathBuf::from(dir)),
        );
    }
    search_path()
}

/// Resolve one mandatory tier directory into a pair (both binaries
/// required; any miss = `ffmpeg_missing` naming the tier).
fn pair_from_dir(dir: &Path, source: DiscoverySource) -> Result<FfmpegPair, MediaError> {
    match dir_candidate(dir) {
        Some(c) => Ok(FfmpegPair {
            ffmpeg: c.ffmpeg,
            ffprobe: c.ffprobe,
            source,
        }),
        None => Err(MediaError::Missing(format!(
            "tier {} -> directory {} does not hold both ffmpeg and ffprobe",
            source.as_str(),
            dir.display()
        ))),
    }
}

/// Precedence-4 PATH search (live process PATH). ffmpeg is located
/// first; ffprobe is then required in the *same* directory (same-origin
/// pairing — a hit in a different directory is `OriginMismatch`, never
/// a mixed pair).
fn search_path() -> Result<FfmpegPair, MediaError> {
    let path_value = env::var_os("PATH").unwrap_or_default();
    search_path_in(&path_value)
}

/// PATH search against an explicit PATH value (test seam — process-env
/// mutation is off-limits under edition 2024 without unsafe).
pub fn search_path_in(path_value: &OsStr) -> Result<FfmpegPair, MediaError> {
    let ffmpeg = find_in_path("ffmpeg", path_value)
        .ok_or_else(|| MediaError::Missing("PATH holds no executable ffmpeg".to_string()))?;
    let dir = ffmpeg.parent().map(Path::to_path_buf).ok_or_else(|| {
        MediaError::Missing(format!("ffmpeg path {} has no parent", ffmpeg.display()))
    })?;
    let ffprobe = dir.join(binary_name("ffprobe"));
    if !ffprobe.is_file() {
        return Err(MediaError::OriginMismatch(format!(
            "ffmpeg found at {} but ffprobe is not in the same directory (PATH pairing rule)",
            ffmpeg.display()
        )));
    }
    Ok(FfmpegPair {
        ffmpeg,
        ffprobe,
        source: DiscoverySource::Path(dir),
    })
}

/// Walk the PATH components for an executable file (first hit wins;
/// execute-bit check is unix-only, existence is the windows bar).
fn find_in_path(base: &str, path_value: &OsStr) -> Option<PathBuf> {
    let name = binary_name(base);
    for dir in env::split_paths(path_value) {
        let candidate = dir.join(&name);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// File + executable-bit predicate (unix) / file predicate (windows).
fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = path.metadata() else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(windows)]
    {
        true
    }
}

/// Convenience for callers holding an already-resolved ffmpeg path:
/// derive the mandatory same-directory ffprobe (pairing rule applied).
pub fn pair_for_ffmpeg(ffmpeg: &Path) -> Result<FfmpegPair, MediaError> {
    let dir = ffmpeg.parent().ok_or_else(|| {
        MediaError::Missing(format!("ffmpeg path {} has no parent", ffmpeg.display()))
    })?;
    pair_from_dir(dir, DiscoverySource::Explicit(dir.to_path_buf()))
}

/// Test seam: the fixed binary name (platform suffix included).
#[allow(dead_code)] // exercised via integration tests on all platforms
pub(crate) fn fixed_binary_name(base: &str) -> String {
    binary_name(base)
}

/// OsStr helper for callers building argv from discovery output.
#[allow(dead_code)]
pub(crate) fn as_os_str(p: &Path) -> &OsStr {
    p.as_os_str()
}
