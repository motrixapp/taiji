//! Windows long-path verbatim conversion layer (aligned with the aria2
//! fork `4c169633` / issue #2183; cf. Rust std `get_long_path` and Go
//! `os.fixLongPath`).
//!
//! Rust std does not add the `\\?\` prefix automatically and the binary
//! carries no longPathAware manifest, so without the admin-gated
//! `LongPathsEnabled` policy, targets over 260 chars fail with
//! ERROR_PATH_NOT_FOUND. Conversion happens at the last moment before an
//! OS API call (the Go fixLongPath shape: inside the syscall boundary,
//! invisible to callers):
//!
//! - Non-Windows: identity ([`to_fs_path`] compiles away under
//!   `cfg(not(windows))` to a zero-cost borrow — call sites carry no cfg,
//!   no macros);
//! - Windows: already-verbatim `\\?\` / `\??\` (incl. `\\?\UNC\`) and
//!   `\\.\` device paths pass through; absolute paths shorter than
//!   [`LONG_PATH_THRESHOLD`] UTF-16 units return unchanged (regular paths
//!   keep their bytes); otherwise normalize with `std::path::absolute`
//!   (GetFullPathNameW semantics: cwd, relative segments, forward slashes,
//!   `.`/`..`); if the result still reaches the threshold, prefix it —
//!   drive paths `\\?\C:\...`, UNC `\\server\share\...` ->
//!   `\\?\UNC\server\share\...`; `absolute()` failure returns the
//!   input unchanged (fail-open, as in the fork).
//!
//! Length is measured in UTF-16 code units, not chars: the Win32 path
//! surface (`GetFullPathNameW`/`CreateFileW`) counts UTF-16 units, and
//! astral-plane characters are 1 char but 2 units, so `chars().count()`
//! undercounts. Threshold 248 (convert at >= 248): the Win32 documented
//! cap for normalized directory paths; exactly 247 stays, exactly 248
//! converts. Verbatim paths disable normalization, so `absolute()` must
//! run BEFORE prefixing (feeding `\\?\..\foo` to CreateFileW is literal);
//! short paths stay non-verbatim so the OS keeps its usual normalization
//! ("short paths keep their bytes").
//!
//! The conversion is only for the OS call (`std::fs::*`, `OpenOptions`,
//! `File::open`, sqlite open strings); RPC echoes, logs, error messages,
//! and task-row storage always carry the original path. Returns [`Cow`] —
//! short and already-verbatim paths allocate nothing.
//!
//! Structure: pure-function decisions ([`plan_for`] / [`prefix_kind_for`],
//! no IO; input `(UTF-16 encoding, PathKind)` supplied by the caller)
//! run and test on all platforms; the Windows-only `absolute()`
//! integration surface is covered by `#[cfg(windows)]` tests. std only.
//!
use std::borrow::Cow;
use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;

/// Verbatim conversion threshold (UTF-16 units): convert at >= 248.
/// Rationale in the module doc (Win32 248 directory-path cap; same value
/// as fork #2183 and Go fixLongPath).
pub const LONG_PATH_THRESHOLD: usize = 248;

/// Decision plan (pure-function core of [`to_fs_path`]; no IO, no platform API).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsPathPlan {
    /// Pass through unchanged (already verbatim/device, or absolute and
    /// < 248 UTF-16 units) — the [`Cow::Borrowed`] case, zero allocation.
    Keep,
    /// Normalize with `std::path::absolute` first (relative / over-long /
    /// un-normalized shapes), then pick a prefix via [`prefix_kind_for`].
    Absolutize,
}

/// Verbatim/device prefix shape test (pure function, UTF-16 code-unit
/// prefix match): `\\?\` (incl. `\\?\UNC\`), `\??\` (NT object prefix),
/// `\\.\` (device paths).
pub fn is_verbatim_or_device(wide: &[u16]) -> bool {
    const VERBATIM: [u16; 4] = ['\\' as u16, '\\' as u16, '?' as u16, '\\' as u16];
    const NT: [u16; 4] = ['\\' as u16, '?' as u16, '?' as u16, '\\' as u16];
    const DEVICE: [u16; 4] = ['\\' as u16, '\\' as u16, '.' as u16, '\\' as u16];
    wide.starts_with(&VERBATIM) || wide.starts_with(&NT) || wide.starts_with(&DEVICE)
}

/// Whether the caller's wide path is absolute (the std
/// `Path::is_absolute` reading of the source path; a pure fact supplied
/// by the caller, this module does no IO to re-derive it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathKind {
    /// Absolute (drive / UNC / rooted) — short ones keep as-is.
    Absolute,
    /// Relative to the process working directory — absolutize first.
    Relative,
}

/// Pre-normalization decision (pure function): verbatim/device -> keep;
/// absolute and short -> keep; everything else (relative / absolute but
/// long) -> absolutize first.
pub fn plan_for(wide: &[u16], kind: PathKind) -> FsPathPlan {
    if is_verbatim_or_device(wide)
        || (kind == PathKind::Absolute && wide.len() < LONG_PATH_THRESHOLD)
    {
        FsPathPlan::Keep
    } else {
        FsPathPlan::Absolutize
    }
}

/// Prefix shape for an `absolute()`-normalized result (pure function; the
/// second decision stage of [`to_fs_path`]'s Windows side).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrefixKind {
    /// Still < 248: no prefix (stay non-verbatim, OS normalizes as usual).
    None,
    /// Drive path (`C:\...`) -> `\\?\C:\...`.
    VerbatimDrive,
    /// UNC (`\\server\share\...`) -> `\\?\UNC\server\share\...`.
    VerbatimUnc,
}

/// Prefix decision for a normalized result (pure function): at >= 248,
/// dispatch by shape — UNC (leading `\\`; GetFullPathNameW output keeps
/// the `\\server\share` form) is rewritten to `\\?\UNC\`, everything else
/// (drive paths) gets `\\?\`.
pub fn prefix_kind_for(abs_wide: &[u16]) -> PrefixKind {
    const UNC_LEAD: [u16; 2] = ['\\' as u16, '\\' as u16];
    if abs_wide.len() < LONG_PATH_THRESHOLD {
        PrefixKind::None
    } else if abs_wide.starts_with(&UNC_LEAD) {
        PrefixKind::VerbatimUnc
    } else {
        PrefixKind::VerbatimDrive
    }
}

/// Path conversion right before an OS API call (the single public entry;
/// every fs choke point wraps through here).
///
/// - Non-Windows: identity borrow (compiled away; zero cost, no cfg);
/// - Windows: semantics in the module doc; `absolute()` failure returns
///   the input unchanged (fail-open).
///
/// Short and already-verbatim paths allocate nothing (`Cow::Borrowed`).
#[cfg(not(windows))]
#[inline(always)]
pub fn to_fs_path(path: &Path) -> Cow<'_, Path> {
    Cow::Borrowed(path)
}

#[cfg(windows)]
pub fn to_fs_path(path: &Path) -> Cow<'_, Path> {
    use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};

    let wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    match plan_for(
        &wide,
        if path.is_absolute() {
            PathKind::Absolute
        } else {
            PathKind::Relative
        },
    ) {
        FsPathPlan::Keep => Cow::Borrowed(path),
        FsPathPlan::Absolutize => match std::path::absolute(path) {
            Ok(abs) => {
                let abs_wide: Vec<u16> = abs.as_os_str().encode_wide().collect();
                match prefix_kind_for(&abs_wide) {
                    PrefixKind::None => Cow::Owned(abs),
                    PrefixKind::VerbatimDrive => {
                        // `\\?\` + `C:\...` (joined as wide bytes, not via
                        // lossy display — paths need not be UTF-8).
                        let mut out: Vec<u16> = Vec::with_capacity(4 + abs_wide.len());
                        out.extend_from_slice(&['\\' as u16, '\\' as u16, '?' as u16, '\\' as u16]);
                        out.extend_from_slice(&abs_wide);
                        Cow::Owned(PathBuf::from(std::ffi::OsString::from_wide(&out)))
                    }
                    PrefixKind::VerbatimUnc => {
                        // `\\server\share\...` -> `\\?\UNC\server\share\...`
                        // (strip the leading `\\`, prepend `\\?\UNC\`).
                        let mut out: Vec<u16> = Vec::with_capacity(8 + abs_wide.len() - 2);
                        out.extend_from_slice(&[
                            '\\' as u16,
                            '\\' as u16,
                            '?' as u16,
                            '\\' as u16,
                            'U' as u16,
                            'N' as u16,
                            'C' as u16,
                            '\\' as u16,
                        ]);
                        out.extend_from_slice(&abs_wide[2..]);
                        Cow::Owned(PathBuf::from(std::ffi::OsString::from_wide(&out)))
                    }
                }
            }
            // fail-open: on normalization failure (empty path / illegal
            // shape) return the input unchanged and let the OS call report
            // the error — this layer invents no new error surface (same as
            // the fork).
            Err(_) => Cow::Borrowed(path),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: string -> UTF-16 encoding (pure-function test vehicle).
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    /// UTF-16 unit count (test convention: test inputs are always valid
    /// UTF-8, so `encode_utf16` matches the Windows-side `encode_wide`).
    fn utf16_units(s: &str) -> usize {
        s.encode_utf16().count()
    }

    /// Astral-plane counting pin: 1 char = 2 UTF-16 units (surrogate pair) —
    /// `chars().count()` necessarily undercounts here (see the module doc's
    /// length section).
    #[test]
    fn utf16_units_count_surrogate_pairs_not_chars() {
        // U+1F600: 1 char, 2 UTF-16 units.
        assert_eq!("😀".chars().count(), 1);
        assert_eq!(utf16_units("😀"), 2);
        // 124 emoji = 124 chars = 248 UTF-16 units (threshold exactly hit).
        let emoji_str: String = "😀".repeat(124);
        assert_eq!(emoji_str.chars().count(), 124);
        assert_eq!(utf16_units(&emoji_str), 248);
    }

    // ------------------------------------------------------------------
    // plan_for: pre-normalization decision matrix (pure functions, runs on
    // all platforms).
    // ------------------------------------------------------------------

    /// Short absolute paths keep — the regular-paths-keep-their-bytes decision.
    #[test]
    fn plan_short_absolute_keeps() {
        assert_eq!(
            plan_for(&wide(r"C:\down\f.bin"), PathKind::Absolute),
            FsPathPlan::Keep
        );
        // 247 UTF-16 units (threshold - 1): unchanged.
        let p247 = format!(r"C:\{}f", "a".repeat(247 - 4));
        assert_eq!(utf16_units(&p247), 247);
        assert_eq!(plan_for(&wide(&p247), PathKind::Absolute), FsPathPlan::Keep);
    }

    /// Boundary at exactly 248/249 UTF-16 units: >= 248 converts (Absolutize).
    #[test]
    fn plan_boundary_247_248_249() {
        let mk = |n: usize| format!(r"C:\{}f", "a".repeat(n - 4));
        assert_eq!(
            utf16_units(&mk(247)),
            247,
            "pins the construction semantics"
        );
        assert_eq!(
            plan_for(&wide(&mk(247)), PathKind::Absolute),
            FsPathPlan::Keep
        );
        assert_eq!(
            plan_for(&wide(&mk(248)), PathKind::Absolute),
            FsPathPlan::Absolutize
        );
        assert_eq!(
            plan_for(&wide(&mk(249)), PathKind::Absolute),
            FsPathPlan::Absolutize
        );
        // Non-BMP boundary: `C:\` (3 units) + 121/122 emoji (242/244 units)
        // + `ff` (2) = 247/249. The UTF-16 and char counts diverge here (a
        // 122-emoji path counts 127 via chars().count() — always a
        // misjudgment).
        let mk_emoji = |emojis: usize| {
            let mut p = String::from(r"C:\");
            for _ in 0..emojis {
                p.push('😀');
            }
            p.push_str("ff");
            p
        };
        // 3 + 121x2 + 2 = 247: unchanged.
        let p247 = mk_emoji(121);
        assert_eq!(utf16_units(&p247), 247);
        assert_eq!(plan_for(&wide(&p247), PathKind::Absolute), FsPathPlan::Keep);
        // 3 + 122x2 + 2 = 249: convert.
        let p249 = mk_emoji(122);
        assert_eq!(utf16_units(&p249), 249);
        assert_eq!(
            plan_for(&wide(&p249), PathKind::Absolute),
            FsPathPlan::Absolutize
        );
    }

    /// Relative paths (any length) absolutize first — length is judged after normalization.
    #[test]
    fn plan_relative_absolutizes() {
        assert_eq!(
            plan_for(&wide("f.bin"), PathKind::Relative),
            FsPathPlan::Absolutize
        );
        assert_eq!(
            plan_for(&wide("a/f.bin"), PathKind::Relative),
            FsPathPlan::Absolutize
        );
        // Absolute but long: also absolutizes (`.`/`..`/forward slashes resolved there).
        let long = format!(r"C:\down\{}f", "a".repeat(300));
        assert_eq!(
            plan_for(&wide(&long), PathKind::Absolute),
            FsPathPlan::Absolutize
        );
    }

    /// Already verbatim / NT prefix / device paths keep — the idempotence surface.
    #[test]
    fn plan_verbatim_and_device_passthrough() {
        assert_eq!(
            plan_for(&wide(r"\\?\C:\down\f.bin"), PathKind::Absolute),
            FsPathPlan::Keep,
            "already verbatim passes through"
        );
        assert_eq!(
            plan_for(&wide(r"\\?\UNC\server\share\f.bin"), PathKind::Absolute),
            FsPathPlan::Keep,
            "already verbatim UNC passes through"
        );
        assert_eq!(
            plan_for(&wide(r"\??\C:\down\f.bin"), PathKind::Absolute),
            FsPathPlan::Keep,
            "NT object prefix passes through"
        );
        assert_eq!(
            plan_for(&wide(r"\\.\COM1"), PathKind::Absolute),
            FsPathPlan::Keep,
            "device path passes through"
        );
        assert_eq!(
            plan_for(&wide(r"\\.\PhysicalDrive0"), PathKind::Absolute),
            FsPathPlan::Keep
        );
        // Even long verbatim paths get no rework (idempotent: call sites may wrap repeatedly).
        let long_verbatim = format!(r"\\?\C:\{}f", "a".repeat(300));
        assert_eq!(
            plan_for(&wide(&long_verbatim), PathKind::Absolute),
            FsPathPlan::Keep
        );
    }

    // ------------------------------------------------------------------
    // prefix_kind_for: normalized-result prefix decision matrix (pure
    // functions, runs on all platforms).
    // ------------------------------------------------------------------

    /// Still < 248 after normalization: no prefix (short relative path absolutized).
    #[test]
    fn prefix_none_below_threshold() {
        assert_eq!(prefix_kind_for(&wide(r"C:\down\f.bin")), PrefixKind::None);
        let p247 = format!(r"C:\{}f", "a".repeat(247 - 4));
        assert_eq!(prefix_kind_for(&wide(&p247)), PrefixKind::None);
    }

    /// >= 248 after normalization: drive -> VerbatimDrive; UNC -> VerbatimUnc.
    #[test]
    fn prefix_drive_and_unc_above_threshold() {
        let drive = format!(r"C:\{}f", "a".repeat(300));
        assert_eq!(prefix_kind_for(&wide(&drive)), PrefixKind::VerbatimDrive);
        let unc = format!(r"\\server\share\{}f", "a".repeat(300));
        assert_eq!(prefix_kind_for(&wide(&unc)), PrefixKind::VerbatimUnc);
        // Boundary: exactly 248 converts.
        let p248 = format!(r"C:\{}f", "a".repeat(248 - 4));
        assert_eq!(prefix_kind_for(&wide(&p248)), PrefixKind::VerbatimDrive);
        // Non-BMP exactly 248: `C:\` (3 units) + 122 emoji (244) + `f` (1).
        let mut p = String::from(r"C:\");
        for _ in 0..122 {
            p.push('😀');
        }
        p.push('f');
        assert_eq!(utf16_units(&p), 248);
        assert_eq!(prefix_kind_for(&wide(&p)), PrefixKind::VerbatimDrive);
    }

    // ------------------------------------------------------------------
    // to_fs_path: platform surface. Non-Windows is identity (zero-alloc
    // borrow); the Windows absolute() integration is covered by
    // cfg(windows) tests (cannot run on this macOS host).
    // ------------------------------------------------------------------

    /// Non-Windows: identity (zero-alloc borrow — short/long/verbatim all unchanged).
    #[cfg(not(windows))]
    #[test]
    fn to_fs_path_identity_on_non_windows() {
        let cases = [
            r"C:\down\f.bin",
            r"\\?\C:\down\f.bin",
            r"\\server\share\f.bin",
            "/tmp/f.bin",
            "f.bin",
        ];
        for c in cases {
            let p = Path::new(c);
            let out = to_fs_path(p);
            assert!(
                matches!(out, Cow::Borrowed(_)),
                "identity must be borrowed: {c}"
            );
            assert_eq!(&*out, p, "bytes unchanged on non-Windows");
        }
    }

    /// Windows integration 1: short absolute path unchanged byte-for-byte (zero-alloc borrow).
    #[cfg(windows)]
    #[test]
    fn to_fs_path_short_absolute_unchanged() {
        let p = Path::new(r"C:\nonexistent-taiji-winpath\f.bin");
        let out = to_fs_path(p);
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(&*out, p);
    }

    /// Windows integration 2: relative paths are length-judged after
    /// absolutizing — matches `std::path::absolute` (GetFullPathNameW: cwd
    /// prefix + normalization).
    #[cfg(windows)]
    #[test]
    fn to_fs_path_relative_matches_absolute() {
        let p = Path::new("rel-dir-taiji-winpath/f.bin");
        let out = to_fs_path(p);
        let expect = std::path::absolute(p).unwrap_or_else(|e| panic!("absolute: {e}"));
        assert_eq!(&*out, expect);
        // A short relative path stays below the threshold after
        // normalization: no verbatim prefix (non-verbatim shape returned to
        // the OS for its usual normalization — short paths stay byte-stable).
        assert!(
            !out.to_string_lossy().starts_with(r"\\?\"),
            "< 248 after normalization must not gain a prefix: {}",
            out.display()
        );
    }

    /// Windows integration 3: forward-slash/`.`/`..` segments resolved by
    /// normalization (trigger = long paths; short paths keep forward slashes
    /// — the OS normalizes them itself).
    #[cfg(windows)]
    #[test]
    fn to_fs_path_normalizes_slashes_and_dot_segments_when_long() {
        let long = "a".repeat(300);
        // Long relative path with forward slashes + `..` segments: normalized
        // to backslashes, `..` resolved.
        let p = PathBuf::from(format!(r"C:/down/./x/../{long}/f.bin"));
        let p = p.as_path();
        let out = to_fs_path(p);
        let s = out.to_string_lossy();
        assert!(
            s.starts_with(r"\\?\C:\"),
            "over-long drive path gains verbatim: {s}"
        );
        assert!(
            !s.contains('/'),
            "forward slashes normalized by absolute: {s}"
        );
        assert!(!s.contains(r"\.\\"), "'.' segments resolved: {s}");
        assert!(!s.contains(r"\..\"), "'..' segments resolved: {s}");
    }

    /// Windows integration 4: long drive -> `\\?\C:\...`; long UNC ->
    /// `\\?\UNC\server\share\...`; already verbatim passes through
    /// (idempotent).
    #[cfg(windows)]
    #[test]
    fn to_fs_path_long_drive_unc_and_verbatim() {
        let long = "a".repeat(300);
        let drive = PathBuf::from(format!(r"C:\down\{long}\f.bin"));
        assert_eq!(
            &*to_fs_path(&drive),
            Path::new(&format!(r"\\?\C:\down\{long}\f.bin"))
        );
        // Long UNC: `\\server\share\...` -> `\\?\UNC\server\share\...`.
        let unc = PathBuf::from(format!(r"\\server\share\{long}\f.bin"));
        assert_eq!(
            &*to_fs_path(&unc),
            Path::new(&format!(r"\\?\UNC\server\share\{long}\f.bin"))
        );
        // Already verbatim passes through (bytes unchanged).
        let verbatim = PathBuf::from(format!(r"\\?\C:\down\{long}\f.bin"));
        let out = to_fs_path(&verbatim);
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(&*out, verbatim);
    }

    /// Windows integration 5: fail-open — absolute() failure (empty path) returns the input.
    #[cfg(windows)]
    #[test]
    fn to_fs_path_fail_open_on_absolute_error() {
        let p = Path::new("");
        let out = to_fs_path(p);
        assert_eq!(
            &*out, p,
            "normalization failure returns the input as-is (no invented error surface)"
        );
    }
}
