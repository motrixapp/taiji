//! Disk naming, creation-time path conflict checks, and platform file
//! name sanitization.
//!
//! URL/Content-Disposition derived names are the main dirty-data
//! source (attack surface; fully server-controlled), and pure rejection
//! would cost a meaningful failure rate. Sanitization happens at the
//! engine layer: **the sanitized name is the task's final name** —
//! after creation-time path resolution ([`plan_output`]) the
//! `final_path` is reported back to the query face/persisted row, so
//! upper layers always know the actual on-disk name.
//!
//! Full channel ([`sanitize_generated_name`], URL/CD derived names):
//! illegal characters `< > : " | ? *`, control codes
//! (`char::is_control`), display-spoofing/hidden-injection codepoints
//! (single source `taiji_io::text::is_spoofing_char`: 12 bidi + 3
//! zero-width + 2 line/paragraph separators + DEL), and path
//! separators `/` `\` all map to `_` (replacing separators is a
//! security requirement: the product must stay a single path component
//! so a caller's `dir.join(name)` cannot escape the directory);
//! trailing dots/spaces stripped (Win32 parsing strips them — the
//! name-borrowing confusion face); Windows reserved names
//! (CON/PRN/AUX/NUL/COM1-9/LPT1-9, extension forms included — stem
//! compared before the first dot, case-insensitive) get `_` appended
//! to the stem, keeping the extension (`CON.txt` -> `CON_.txt`);
//! 254-byte UTF-8 truncation keeping the extension, with the budget
//! sized so `<final name><auto-rename marker><incomplete suffix>`
//! stays within `NAME_MAX` (the final-name budget shrinks via
//! [`engine_name_budget`]); empty-name fallback `download`.
//!
//! Light channel ([`sanitize_user_name`], user-explicit `out=`):
//! strip path components (`/` `\` take the last segment; an `X:` drive
//! prefix strips with its component — Windows `Path::join` replaces
//! the base directory for prefixed arguments, a cross-directory write
//! face, not a character rewrite) + 254-byte truncation keeping the
//! extension + reserved-name suffix; **no character replacement**
//! (touch user names minimally; hand illegal characters to the OS
//! error). The acceptance layer (addUri/CLI `-o`
//! `sanitize_out_option`) already rejects separators/colons/reserved
//! names/trailing dots and spaces/spoofing codepoints at task creation
//! with a 255-byte cap — the light channel enforces the engine budget
//! beneath it (254 - suffix - marker) and pre-arms engine semantics
//! for any future acceptance loosening.
//!
//! # Incomplete suffix
//!
//! Incomplete data lands at `<out><--http-incomplete-suffix>` (default
//! `.part`) and is atomically renamed to `<out>` on completion via
//! [`crate::finalize`]. The suffix is this engine's `taiji.*` extension
//! option, therefore:
//!
//! - Strict validation `^\.[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`: a single
//!   tail token; separators/NUL/overlong/out-of-domain characters are
//!   rejected, collapsing the path-injection surface to the naming
//!   domain itself ([`IncompleteSuffix::parse`], out-of-domain is
//!   always `taiji.option.invalid`);
//! - Persisted at creation: the suffix is written into
//!   `http_task.config_json` ([`CONFIG_KEY_INCOMPLETE_SUFFIX`]); on
//!   restore the task's persisted value wins over the session default
//!   — a default change never breaks in-flight tasks
//!   ([`IncompleteSuffix::restore_from_config`]);
//! - Path conflict checks and auto-file-renaming both run with the
//!   configured suffix.
//!
//! # Creation-time path conflict check (`taiji.http.path_conflict`)
//!
//! At task creation (before the download starts): if the target output
//! exists, `--auto-file-renaming` renames per the aria2 candidate
//! algorithm ([`renamed_candidate`]; direct translation reference:
//! upstream aria2 `RequestGroup.cc`), otherwise the task is rejected.
//! One listed aria2 difference: aria2's candidate check also probes
//! for an `.aria2` control file — this engine keeps control state in
//! sqlite (the DB is the journal; no sidecar control file), so
//! candidates check only the target name itself.
//!
//! `.part` reuse: length != probed length -> full re-download (the
//! caller clears the bitmap); only matching lengths resume. Degraded
//! tasks without a bitmap (no-range / no REST) always restore from
//! zero — see [`decide_part_reuse`].
//!
//! # Blocking discipline
//!
//! This module touches the filesystem directly (metadata/existence
//! probes): async-context callers must go through `spawn_blocking`.
//! [`next_free_candidate`], [`split_name_ext`],
//! [`sanitize_generated_name`]/[`sanitize_user_name`] are pure-function
//! injection seams (the existence predicate is injectable) for unit
//! tests and for reuse above the engine in non-blocking contexts.
//!
//! Upstream anchor mapping: docs/design/http.md

use std::path::{Path, PathBuf};

use taiji_io::text::is_spoofing_char;

use crate::error::HttpError;

/// Incomplete suffix default (`.part`).
pub const DEFAULT_INCOMPLETE_SUFFIX: &str = ".part";

/// Persistence key inside `http_task.config_json` (written at
/// creation; the store does not interpret the structure — this
/// constant is the key contract).
pub const CONFIG_KEY_INCOMPLETE_SUFFIX: &str = "http_incomplete_suffix";

/// auto-file-renaming candidate ordinal cap (cross-checked against
/// aria2 `RequestGroup.cc` `for (int i = 1; i < 10000; ++i)`).
pub const AUTO_RENAME_MAX_TRIES: u32 = 10000;

/// A validated incomplete suffix (built by [`IncompleteSuffix::parse`];
/// the type is the proof: naming domain
/// `^\.[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`, no separators/NUL — safe to
/// append to a path tail and to embed in JSON verbatim).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncompleteSuffix(String);

impl IncompleteSuffix {
    /// Validates strictly and constructs. Out-of-domain is always
    /// `taiji.option.invalid` (no truncation, no default fallback).
    pub fn parse(value: &str) -> Result<Self, HttpError> {
        if is_valid_suffix(value) {
            Ok(IncompleteSuffix(value.to_string()))
        } else {
            Err(HttpError::OptionInvalid {
                option: "--http-incomplete-suffix",
                value: format!("{value:?} (must match ^\\.[A-Za-z0-9][A-Za-z0-9._-]{{0,31}}$)"),
            })
        }
    }

    /// Suffix text (including the leading dot, e.g. `.part`).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Creation-time persistence fragment:
    /// `{"http_incomplete_suffix":"<suffix>"}`.
    ///
    /// The suffix naming domain `[A-Za-z0-9._-]` contains no JSON
    /// structural characters and no control characters, so no escaping
    /// is needed (that property is carried by the
    /// [`IncompleteSuffix::parse`] type invariant, locked by tests).
    /// The producer merges this into the task `config_json`.
    pub fn config_json_fragment(&self) -> String {
        format!("{{\"{CONFIG_KEY_INCOMPLETE_SUFFIX}\":\"{}\"}}", self.0)
    }

    /// Restore-time resolution (a default change never breaks in-flight
    /// tasks): the task's persisted value wins — if present, resume
    /// with the creation-time suffix (validation failure = the
    /// persistence layer was corrupted externally; defensive reject);
    /// missing (old tasks / the creation face never wrote) -> the
    /// session current default.
    pub fn restore_from_config(
        persisted: Option<&str>,
        session_default: &IncompleteSuffix,
    ) -> Result<Self, HttpError> {
        match persisted {
            Some(value) => IncompleteSuffix::parse(value),
            None => Ok(session_default.clone()),
        }
    }
}

impl Default for IncompleteSuffix {
    fn default() -> Self {
        IncompleteSuffix(DEFAULT_INCOMPLETE_SUFFIX.to_string())
    }
}

/// Strict naming domain: `^\.[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`.
///
/// Hand-written character checks (regex is not in this crate's
/// dependency set): leading dot + first char ASCII alphanumeric +
/// 0..=31 further `[A-Za-z0-9._-]` (total length 2..=33).
fn is_valid_suffix(value: &str) -> bool {
    let mut chars = value.chars();
    if chars.next() != Some('.') {
        return false;
    }
    let rest: Vec<char> = chars.collect();
    if rest.is_empty() || rest.len() > 32 {
        return false;
    }
    rest[0].is_ascii_alphanumeric()
        && rest[1..]
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

// ---- Platform file name sanitization (rule set and trade-offs in the module doc) ----

/// Final-name byte budget: the cap for the full
/// `<final name><auto-rename marker><incomplete suffix>` form (same
/// value as Firefox `kDefaultMaxFileNameLength`, 254 = the 255-byte
/// `NAME_MAX` minus margin). The **final-name** budget shrinks from
/// this value via [`engine_name_budget`] by the suffix and marker
/// bytes — empirically, taking 254 directly for the final name makes
/// `<name>.part` = 259 bytes, over `NAME_MAX` (macOS error 63).
pub const MAX_NAME_BYTES: usize = 254;

/// Minimal auto-rename marker `.N` in bytes (the budget reserve — the
/// first candidate `<name>.1<suffix>` always fits
/// [`MAX_NAME_BYTES`]; multi-digit ordinals can exceed 255 on extreme
/// names, the same league as competitors — noted in the diff
/// declaration).
pub const CONFLICT_SUFFIX_RESERVE: usize = 2;

/// Engine-side final-name byte budget: [`MAX_NAME_BYTES`] minus the
/// incomplete suffix length and the minimal candidate marker (default
/// `.part` -> 247). A task-level suffix can reach 33 bytes (naming
/// domain), so the budget shrinks with the persisted suffix — in-flight
/// tasks are immune to default changes.
pub fn engine_name_budget(suffix: &IncompleteSuffix) -> usize {
    MAX_NAME_BYTES
        .saturating_sub(suffix.as_str().len())
        .saturating_sub(CONFLICT_SUFFIX_RESERVE)
}

/// Extension retention cap: beyond this, treat the extension as
/// payload (truncate whole, do not keep it; same value 24 as Motrix
/// sanitize.rs `MAX_EXTENSION_BYTES`).
const MAX_EXTENSION_BYTES: usize = 24;

/// Sanitization-exhausted fallback name (all characters stripped /
/// empty input; same value as Chromium `kFinalFallbackName`).
pub const FALLBACK_NAME: &str = "download";

/// Replacement character (the uniform mapping for illegal characters/control codes/separators).
const REPLACEMENT: char = '_';

/// Full-channel sanitization (URL/CD derived names; channel semantics
/// and competitor comparison in the module doc).
///
/// Idempotent: running the output through again changes nothing. Pure
/// function, no disk access. Rule order: character replacement ->
/// trailing dot/space strip -> reserved-name suffix -> byte truncation
/// keeping the extension (default budget [`MAX_NAME_BYTES`]; the
/// engine side shrinks via [`engine_name_budget`] and goes through
/// [`sanitize_generated_name_with_budget`]) -> empty-name fallback.
pub fn sanitize_generated_name(raw: &str) -> String {
    sanitize_generated_name_with_budget(raw, MAX_NAME_BYTES)
}

/// Full-channel sanitization (explicit byte budget; budget semantics at [`MAX_NAME_BYTES`]).
pub fn sanitize_generated_name_with_budget(raw: &str, max_bytes: usize) -> String {
    // 1. Illegal characters + control codes + path separators -> '_'
    // (separators included for security: the product must stay a
    // single path component — `dir.join` must not escape the
    // directory).
    let replaced: String = raw
        .chars()
        .map(|c| {
            if is_replaced_character(c) {
                REPLACEMENT
            } else {
                c
            }
        })
        .collect();
    // 2. Trailing dot/space strip (Win32 parsing strips them -> the
    // name-borrowing confusion face; interleaved tails like `file. .`
    // strip clean in one pass).
    let trimmed = replaced.trim_end_matches(['.', ' ']);
    // 3. Reserved-stem suffix (keeping the extension) + 4. byte
    // truncation keeping the extension. Truncation cannot reconstruct
    // a reserved stem (reserved words are <= 4 bytes): in the
    // keep-extension branch with extension <= 24, the stem budget is
    // >= budget-25 bytes, so the cut cannot land on a reserved-word
    // boundary; the whole-truncation branch never moves the first dot
    // (a first dot beyond the budget yields a dotless product, the
    // stem being the full length). The invariant is locked by
    // `windows_component_contract_holds_after_full_sanitize`.
    let clamped = clamp_name(&dereserve_name(trimmed), max_bytes);
    if clamped.is_empty() {
        FALLBACK_NAME.to_string()
    } else {
        clamped
    }
}

/// Light-channel sanitization (user-explicit `out=`; **no character
/// replacement** — competitor consensus, trade-offs in the module
/// doc).
///
/// Idempotent. Pure function, no disk access. Rule order: strip path
/// components (`/` `\` last segment + `X:` drive prefix) ->
/// reserved-name suffix -> byte truncation keeping the extension
/// (default [`MAX_NAME_BYTES`]; engine-side shrink via
/// [`sanitize_user_name_with_budget`]) -> empty/dot-shape fallback.
pub fn sanitize_user_name(raw: &str) -> String {
    sanitize_user_name_with_budget(raw, MAX_NAME_BYTES)
}

/// Light-channel sanitization (explicit byte budget; budget semantics at [`MAX_NAME_BYTES`]).
pub fn sanitize_user_name_with_budget(raw: &str, max_bytes: usize) -> String {
    let trimmed = raw.trim();
    // 1. Strip path components: `a/b.txt` -> `b.txt`,
    // `C:\d\f.bin` -> `f.bin`, `C:evil` -> `evil` (a drive prefix is
    // the cross-directory write face of Windows join replacing the
    // base directory; stripped with the component, not per character).
    let component = last_path_component(trimmed);
    if component.is_empty() || component == "." || component == ".." {
        return FALLBACK_NAME.to_string();
    }
    // 2. Reserved-name suffix + 3. byte truncation keeping the
    // extension (truncation cannot reconstruct a reserved stem; the
    // boundary argument sits at the same spot in the full channel). No
    // character replacement, no trailing dot/space strip (user content
    // goes to the OS as-is; the acceptance face already rejected those
    // shapes).
    let clamped = clamp_name(&dereserve_name(component), max_bytes);
    if clamped.is_empty() {
        FALLBACK_NAME.to_string()
    } else {
        clamped
    }
}

/// Full-channel replacement predicate: control codes
/// (`char::is_control`, Cc class = C0 `0x00-0x1F` + DEL `0x7F` + C1
/// `0x80-0x9F`), the display-spoofing/hidden-injection codepoint set
/// (single source [`taiji_io::text::is_spoofing_char`]: 12 bidi + 3
/// zero-width + 2 line/paragraph separators + DEL), `< > : " | ? *`,
/// and path separators `/` `\`.
fn is_replaced_character(c: char) -> bool {
    c.is_control()
        || is_spoofing_char(c)
        || matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*' | '/' | '\\')
}

/// Strips path components: the last non-empty component across `/`
/// `\`, then a leading drive prefix (a single ASCII letter + `:`).
fn last_path_component(name: &str) -> &str {
    let last = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let bytes = last.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        &last[2..]
    } else {
        last
    }
}

/// Reserved-stem suffix: if the stem (before the first dot) hits a
/// Windows reserved device name, `CON.txt` -> `CON_.txt` (stem gets
/// `_`, extension kept); otherwise unchanged.
fn dereserve_name(name: &str) -> String {
    let stem_end = name.find('.').unwrap_or(name.len());
    let (stem, rest) = name.split_at(stem_end);
    if stem_is_reserved_str(stem) {
        format!("{stem}_{rest}")
    } else {
        name.to_string()
    }
}

/// Reserved device name stem check (CON/PRN/AUX/NUL/COM1-9/LPT1-9,
/// ASCII case-insensitive; does NOT include CONIN$/CONOUT$ or the
/// superscript digit shapes — a rule-set difference from Motrix
/// sanitize.rs).
fn stem_is_reserved_str(stem: &str) -> bool {
    let upper = stem.to_ascii_uppercase();
    if matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL") {
        return true;
    }
    let Some(digits) = upper
        .strip_prefix("COM")
        .or_else(|| upper.strip_prefix("LPT"))
    else {
        return false;
    };
    matches!(digits, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
}

/// Byte truncation keeping the extension: split the extension at the
/// last dot, kept only if <= [`MAX_EXTENSION_BYTES`] (the stem
/// truncates UTF-8 safely to the byte budget, with truncation-exposed
/// trailing dots/spaces stripped); an overlong "extension" is treated
/// as payload (truncate whole).
fn clamp_name(name: &str, max_bytes: usize) -> String {
    if name.len() <= max_bytes {
        return name.to_string();
    }
    if let Some(dot) = name.rfind('.')
        && dot > 0
    {
        let extension_bytes = name.len() - dot - 1;
        if extension_bytes > 0 && extension_bytes <= MAX_EXTENSION_BYTES {
            let stem_budget = max_bytes - extension_bytes - 1;
            let stem = truncate_utf8(&name[..dot], stem_budget).trim_end_matches(['.', ' ']);
            let extension = &name[dot + 1..];
            return format!("{stem}.{extension}");
        }
    }
    truncate_utf8(name, max_bytes)
        .trim_end_matches(['.', ' '])
        .to_string()
}

/// UTF-8 safe byte truncation (falls back to a character boundary).
fn truncate_utf8(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

/// Creation-time output path resolution result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputPaths {
    /// Completed-state target path (the candidate name when auto-file-renaming fired).
    pub final_path: PathBuf,
    /// Incomplete data path: `<final_path><suffix>`.
    pub part_path: PathBuf,
    /// Whether auto-file-renaming already renamed at creation.
    pub renamed: bool,
}

/// Creation-time policy (aria2 same-named option semantics).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CreationPolicy {
    /// `--auto-file-renaming` (default false): when the target exists,
    /// rename per the aria2 candidate algorithm instead of rejecting.
    pub auto_file_renaming: bool,
}

/// Creation-time path conflict check (engine-side, at task creation;
/// `taiji.http.path_conflict`).
///
/// - Target output exists (on disk, or held by another task in the
///   in-process final-path registry — the window where an in-flight
///   task has a decided name but no file yet carries the same weight
///   as disk presence) -> rename if `auto_file_renaming` is on
///   (returns the candidate name), otherwise reject;
/// - the incomplete path `<final><suffix>` occupied by a directory ->
///   same-code rejection (an existing file-shaped `.part` is NOT a
///   conflict — that is the resume input face, decided by
///   [`decide_part_reuse`]);
/// - on success the final path is claimed in the registry (`holder` =
///   the task gid; idempotent on the same key — a reactivation rerun
///   does not self-reject); release points are the rename landing
///   ([`crate::finalize`] closure) or task removal (the claim spans
///   the task lifetime).
///
/// This check is a creation-time snapshot; the authoritative
/// arbitration for the `.part` open face is the per-path claim in
/// [`crate::partfile::PartFile::open`] (the TOCTOU between check and
/// open is not closed by this function).
///
/// Blocking face: the caller owns `spawn_blocking` (module doc).
pub fn plan_output(
    final_path: PathBuf,
    suffix: &IncompleteSuffix,
    policy: CreationPolicy,
    holder: &str,
) -> Result<OutputPaths, HttpError> {
    // Final-path occupancy = disk presence OR held by another task in
    // the in-process registry (equal-weight conflict face; auto-rename
    // candidates use the same predicate — a candidate name must not
    // land on a path an in-flight task has already decided).
    let taken = |p: &Path| path_exists(p) || crate::partfile::final_path_held_by_other(p, holder);
    let (final_path, renamed) = if taken(&final_path) {
        if !policy.auto_file_renaming {
            return Err(HttpError::PathConflict);
        }
        match next_free_candidate(&final_path, taken) {
            Some(candidate) => (candidate, true),
            None => return Err(HttpError::PathConflict),
        }
    } else {
        (final_path, false)
    };
    let part_path = part_path_for(&final_path, suffix);
    // Probe-face OS calls go through the winpath conversion (identity off Windows).
    match std::fs::metadata(taiji_io::winpath::to_fs_path(&part_path)) {
        Ok(meta) if meta.is_dir() => return Err(HttpError::PathConflict),
        Ok(_) => {}
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(HttpError::Disk(format!(
                "stat {}: {e}",
                part_path.display()
            )));
        }
        Err(_) => {}
    }
    // Final-path claim (late, atomic): races with other registry keys
    // are decided inside the lock; early exits (existence/directory
    // conflicts above) do not claim. Release points = the rename
    // landing (`crate::finalize` closure) or task removal.
    crate::partfile::claim_final_path(&final_path, holder)?;
    Ok(OutputPaths {
        final_path,
        part_path,
        renamed,
    })
}

/// `<final><suffix>` concatenation (the suffix is appended directly,
/// no separator inserted — the suffix naming domain guarantees no path
/// separators).
pub fn part_path_for(final_path: &Path, suffix: &IncompleteSuffix) -> PathBuf {
    let mut s = final_path.as_os_str().to_os_string();
    s.push(suffix.as_str());
    PathBuf::from(s)
}

/// Existence probe (any entry type; probe errors count as "absent" —
/// real IO failures surface at the later open; the creation-time check
/// must not reject a task over a probe hiccup).
fn path_exists(path: &Path) -> bool {
    // metadata rather than exists(): exists() folds probe errors into
    // false too — same semantics, but the explicit match keeps this on
    // the same probe face as the part directory check. OS calls go
    // through the winpath conversion (no false negatives for Windows
    // long-path probes).
    !matches!(
        std::fs::metadata(taiji_io::winpath::to_fs_path(path)).map_err(|e| e.kind()),
        Err(std::io::ErrorKind::NotFound)
    )
}

/// aria2 candidate name generation (direct translation of
/// `RequestGroup.cc` `fmt("%s.%d%s", fn, i, ext)`): `file.tar.gz` ->
/// `file.tar.1.gz`.
pub fn renamed_candidate(final_path: &Path, i: u32) -> PathBuf {
    let (base, ext) = split_name_ext(final_path);
    let mut s = base.into_os_string();
    s.push(format!(".{i}"));
    s.push(ext);
    PathBuf::from(s)
}

/// Extension split (direct translation of aria2 `RequestGroup.cc`):
/// the extension is everything after the last `.`, except three shapes
/// — the dot is at position 0 (`.file`), there is no dot beyond the
/// path component (a purely dotted leading name), or `*/.*` shapes
/// (the dot immediately follows a directory separator, the leading dot
/// of a directory name). Returns `(stem, extension with dot)`; an
/// empty extension when there is none.
pub fn split_name_ext(path: &Path) -> (PathBuf, String) {
    let s = path.to_string_lossy();
    let idx = s.rfind('.');
    let slash = s.rfind(['/', '\\']);
    let ext_at = idx.filter(|&i| i != 0 && slash.is_none_or(|sl| sl < i - 1));
    match ext_at {
        Some(i) => (PathBuf::from(&s[..i]), s[i..].to_string()),
        None => (PathBuf::from(s.as_ref()), String::new()),
    }
}

/// The first non-existent candidate (ordinals
/// 1..[`AUTO_RENAME_MAX_TRIES`], cross-checked against the aria2 cap);
/// `None` when exhausted (the caller rejects with
/// `taiji.http.path_conflict`). The `exists` predicate is injected:
/// the algorithm stays a pure function (unit test / upper-layer reuse
/// face).
pub fn next_free_candidate<F>(final_path: &Path, mut exists: F) -> Option<PathBuf>
where
    F: FnMut(&Path) -> bool,
{
    (1..AUTO_RENAME_MAX_TRIES)
        .map(|i| renamed_candidate(final_path, i))
        .find(|c| !exists(c))
}

/// `.part` reuse decision.
///
/// - Degraded tasks (no bitmap: no-range / no REST / non-identity
///   encoding) -> restore always from zero (`Restart`);
/// - no probed total length -> no resume criterion, from zero;
/// - `.part` missing -> from zero;
/// - matching length -> resume (`Resume`; the bitmap-trust second
///   line of defense still runs as usual); mismatching length -> full
///   re-download (`Restart`; **the caller clears the bitmap** —
///   bitmap persistence lives in the store, this module only produces
///   the decision).
///
/// Illegal shapes such as a directory occupying the `.part` path are
/// rejected earlier by [`plan_output`] at creation.
///
/// Blocking face: the caller owns `spawn_blocking` (module doc).
pub fn decide_part_reuse(
    part_path: &Path,
    probed_total: Option<u64>,
    degraded: bool,
) -> Result<PartReuse, HttpError> {
    if degraded || probed_total.is_none() {
        return Ok(PartReuse::Restart);
    }
    let total = probed_total.unwrap_or_default();
    // OS calls go through the winpath conversion (identity off Windows).
    match std::fs::metadata(taiji_io::winpath::to_fs_path(part_path)) {
        Ok(meta) if meta.is_file() && meta.len() == total => Ok(PartReuse::Resume),
        Ok(_) => Ok(PartReuse::Restart),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(PartReuse::Restart),
        Err(e) => Err(HttpError::Disk(format!(
            "stat {}: {e}",
            part_path.display()
        ))),
    }
}

/// `.part` reuse decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartReuse {
    /// Matching length: keep the existing bytes and resume (positioned writes advance).
    Resume,
    /// Truncate and start over (degraded / length mismatch / missing
    /// file); **the caller clears the bitmap**.
    Restart,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Full-channel sanitization matrix (aligned with competitor rule
    /// tables: surge `sanitizeFilename` replacement set / Chromium
    /// reserved names + tail handling / Firefox 254 truncation keeping
    /// the extension / Motrix sanitize.rs same-shape cases; differences
    /// noted per assertion group).
    #[test]
    fn full_channel_sanitizes_the_competitor_matrix() {
        let cases: &[(&str, &str)] = &[
            // Passthrough: healthy names (Unicode/emoji included —
            // multi-byte is not an illegal face).
            ("normal.zip", "normal.zip"),
            ("资料.tar.gz", "资料.tar.gz"),
            ("movie🎬.mp4", "movie🎬.mp4"),
            ("my.file name-v2.bin", "my.file name-v2.bin"),
            // Illegal chars `< > : " | ? *` -> '_' (surge's set, plus
            // control codes replaced rather than deleted — surge
            // deletes, Chromium/Motrix replace; we follow the latter).
            ("file<name>.mp4", "file_name_.mp4"),
            ("a:b.txt", "a_b.txt"),
            ("say \"hi\"?", "say _hi__"),
            ("star*|dot>", "star__dot_"),
            // Control codes (C0 + DEL) -> '_'.
            ("control\tchar\n", "control_char_"),
            ("console\u{7f}.log", "console_.log"),
            // Path separators -> '_' (security: the product stays a
            // single component; Chromium/Motrix do the same — the
            // competitor table lists aria2 as %XX escaping, we take the
            // GUI-product mainstream `_`).
            ("path/injection.txt", "path_injection.txt"),
            ("win\\dows.txt", "win_dows.txt"),
            // Windows reserved names (extension forms included, stem
            // compare case-insensitive): stem gets `_` appended,
            // keeping the extension (Motrix same shape; Chromium uses a
            // `_` prefix).
            ("CON", "CON_"),
            ("con.txt", "con_.txt"),
            ("Com5", "Com5_"),
            ("LPT9.tar.gz", "LPT9_.tar.gz"),
            ("aux", "aux_"),
            ("nul.image.iso", "nul_.image.iso"),
            ("COM7.exe", "COM7_.exe"),
            // Reserved-set boundary (rule set differs from Motrix):
            // superscript digits `¹²³` and CONIN$/CONOUT$ are not in
            // this set — passthrough.
            ("COM¹.log", "COM¹.log"),
            ("conin$.txt", "conin$.txt"),
            ("COM0.bin", "COM0.bin"),
            ("LPT0.bin", "LPT0.bin"),
            // Trailing dot/space strip (interleaved tails strip clean in one pass).
            ("trailing. ", "trailing"),
            ("trailing...   ", "trailing"),
            ("trailing.", "trailing"),
            ("spaces   .txt", "spaces   .txt"),
            // Empty/pure-stripped shapes -> fallback `download` (Chromium same value).
            (".", "download"),
            ("..", "download"),
            ("", "download"),
            ("   ", "download"),
            ("???", "___"),
            (".hidden", ".hidden"),
            // Replacement precedes the tail strip: a control code after
            // the trailing dot -> replaced with `_`, so no trailing dot
            // is exposed (`evil._` is a legal Windows name — no
            // trailing dot/space means safe).
            ("evil.\u{1}", "evil._"),
        ];
        for (input, expected) in cases {
            assert_eq!(sanitize_generated_name(input), *expected, "input {input:?}");
        }
    }

    /// Full-channel replacement folds in the Unicode bidi-override
    /// codepoint set via the single source
    /// `taiji_io::text::is_spoofing_char` (the bt parse face / core
    /// acceptance face reference the same source — one source instead
    /// of three hand copies): 12 Cf codepoints (U+061C, U+200E/U+200F,
    /// U+202A-202E, U+2066-2069) -> `_` — URL derived names like
    /// `photo\u{202E}gpj.exe` used to land verbatim (display spoofing:
    /// Explorer/Finder render it as `photo.exe`). Contrast: U+200D ZWJ
    /// (a legal emoji-sequence component, not in the set) passes
    /// through; the replacement product is idempotent. Zero-width /
    /// line-separator / C1 extensions in
    /// [`full_channel_replaces_zero_width_and_separator_codepoints`].
    #[test]
    fn full_channel_replaces_bidi_override_codepoints() {
        const BIDI: [char; 12] = [
            '\u{061C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}',
            '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
        ];
        for c in BIDI {
            assert_eq!(
                sanitize_generated_name(&format!("photo{c}gpj.exe")),
                "photo_gpj.exe",
                "U+{:04X} must be replaced with '_'",
                c as u32
            );
        }
        // Multiple occurrences replaced one by one.
        assert_eq!(sanitize_generated_name("a\u{202E}b\u{2066}c"), "a_b_c");
        // ZWJ emoji name (U+200D is a legal component; the set does
        // not grow to all Cf) passes through.
        let zwj = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}.png";
        assert_eq!(sanitize_generated_name(zwj), zwj);
        // Idempotent: re-sanitizing the replacement product changes nothing.
        let once = sanitize_generated_name("a\u{202E}b");
        assert_eq!(sanitize_generated_name(&once), once);
    }

    /// Zero-width / line-separator / C1 closure (full channel):
    /// U+200B ZWSP, U+200C ZWNJ, U+FEFF BOM (`evil\u{200B}.exe` is
    /// visually identical to `evil.exe` before sanitization — the
    /// name-borrowing face of URL derived names), U+2028/U+2029 (Zl/Zp
    /// line/paragraph separators — residual log-line injection) -> `_`;
    /// C1 (U+0080-009F, unified to `char::is_control` semantics) ->
    /// `_`. Contrast: U+200D ZWJ (a legal emoji-sequence component) /
    /// U+00AD SHY / VS15 pass through (trade-offs unchanged).
    #[test]
    fn full_channel_replaces_zero_width_and_separator_codepoints() {
        const INVISIBLE: [char; 5] = ['\u{200B}', '\u{200C}', '\u{FEFF}', '\u{2028}', '\u{2029}'];
        for c in INVISIBLE {
            assert_eq!(
                sanitize_generated_name(&format!("evil{c}.exe")),
                "evil_.exe",
                "U+{:04X} must be replaced with '_'",
                c as u32
            );
        }
        // C1 control characters (the same face the acceptance layer's `is_control` rejects) -> '_'.
        for c in ['\u{85}', '\u{9F}'] {
            assert_eq!(
                sanitize_generated_name(&format!("evil{c}.exe")),
                "evil_.exe",
                "C1 U+{:04X} must be replaced with '_'",
                c as u32
            );
        }
        // Contrast anchors: deliberate passthrough — ZWJ emoji
        // sequences, SHY, VS15 (no display reordering / visual-identity
        // face) stay as-is.
        let passthrough = "\u{1F468}\u{200D}\u{1F469}.png";
        assert_eq!(sanitize_generated_name(passthrough), passthrough);
        assert_eq!(sanitize_generated_name("a\u{AD}b"), "a\u{AD}b");
        assert_eq!(sanitize_generated_name("a\u{FE0E}b"), "a\u{FE0E}b");
        // Multiple occurrences replaced one by one + idempotent.
        assert_eq!(sanitize_generated_name("a\u{200B}b\u{2028}c"), "a_b_c");
        let once = sanitize_generated_name("a\u{FEFF}b");
        assert_eq!(sanitize_generated_name(&once), once);
    }

    /// Full-channel truncation (254 bytes keeping the extension, with
    /// conflict-suffix margin; Firefox same value): ASCII overlong, CJK
    /// cut at character boundaries, extension kept, overlong "extension"
    /// treated as payload, truncation-exposed trailing dots stripped.
    #[test]
    fn full_channel_clamps_to_254_bytes_keeping_extension() {
        // ASCII stem overlong: full length exactly 254.
        let clamped = sanitize_generated_name(&"a".repeat(300));
        assert_eq!(clamped.len(), MAX_NAME_BYTES);
        assert!(clamped.chars().all(|c| c == 'a'));

        // CJK + extension: cut at a character boundary, `.zip` kept.
        let named = format!("{}.zip", "字".repeat(100));
        let clamped = sanitize_generated_name(&named);
        assert!(clamped.ends_with(".zip"), "{clamped}");
        // 83 x 3-byte chars (249 bytes) + ".zip" = 253 <= 254; the 84th exceeds.
        assert_eq!(clamped, format!("{}.zip", "字".repeat(83)));

        // Overlong "extension" (> 24 bytes) as payload: truncate whole, extension not kept.
        let giant_extension = format!("{}.{}", "d".repeat(300), "x".repeat(200));
        let clamped = sanitize_generated_name(&giant_extension);
        assert_eq!(clamped.len(), MAX_NAME_BYTES);

        // The truncation point exposes a trailing dot -> stripped (no trailing-dot ending).
        let dotted = format!("{}.", "b".repeat(300));
        let clamped = sanitize_generated_name(&dotted);
        assert_eq!(clamped.len(), MAX_NAME_BYTES);
        assert!(!clamped.ends_with('.'));

        // Reserved name + overlong stem: suffixing precedes truncation;
        // the stem stays non-reserved after the cut.
        let reserved_long = format!("CON{}.txt", "x".repeat(300));
        let clamped = sanitize_generated_name(&reserved_long);
        assert!(clamped.ends_with(".txt"), "{clamped}");
        assert_eq!(clamped.len(), MAX_NAME_BYTES);
        assert_ne!(clamped.split('.').next(), Some("CON"));
    }

    /// Full-channel idempotence: re-sanitizing the product changes
    /// nothing (the auto-rename conflict namespace builds on sanitized
    /// names — a second entry must not deform).
    #[test]
    fn full_channel_is_idempotent() {
        for input in [
            "CON",
            "file.",
            "a/b\\c:d",
            "spaces . ",
            "name<?>.txt",
            "",
            &"a".repeat(300),
            &format!("{}.zip", "字".repeat(100)),
        ] {
            let once = sanitize_generated_name(input);
            assert_eq!(sanitize_generated_name(&once), once, "input {input:?}");
        }
    }

    /// Full-channel invariant (the Windows component contract):
    /// non-empty, no trailing dot/space, no illegal characters,
    /// non-reserved stem, <= 254 bytes — locked item by item over an
    /// adversarial input set (truncation-boundary shapes included; the
    /// test face of the `clamp_name` boundary proof).
    #[test]
    fn windows_component_contract_holds_after_full_sanitize() {
        let adversarial: Vec<String> = [
            "CON".to_string(),
            "con.tar.gz".to_string(),
            "com1".to_string(),
            "x".repeat(300),
            format!("{}.{}", "CON", "y".repeat(300)),
            format!("CON.{}", "x".repeat(250)),
            "a:b".to_string(),
            "tail. ".to_string(),
            "a/b\\c|d?e*f<g>h\"i".to_string(),
            "\u{1}\u{7f}\t".to_string(),
            format!("{}.", "z".repeat(300)),
        ]
        .into();
        for input in &adversarial {
            let sanitized = sanitize_generated_name(input);
            assert!(!sanitized.is_empty(), "{input:?} → {sanitized:?}");
            assert!(
                !sanitized.ends_with([' ', '.']),
                "{input:?} → {sanitized:?}"
            );
            assert!(
                !sanitized.chars().any(is_replaced_character),
                "{input:?} → {sanitized:?}"
            );
            let stem = sanitized.split('.').next().unwrap_or_default();
            assert!(!stem_is_reserved_str(stem), "{input:?} → {sanitized:?}");
            assert!(
                sanitized.len() <= MAX_NAME_BYTES,
                "{input:?} → {sanitized:?}"
            );
        }
    }

    /// Light-channel matrix (user-explicit names: strip path components +
    /// length + reserved names, **no character replacement** — surge
    /// `ResolveDestination` consensus).
    #[test]
    fn light_channel_strips_components_keeps_characters() {
        let cases: &[(&str, &str)] = &[
            // Passthrough: healthy names as-is (any character shape the acceptance face allows).
            ("f.bin", "f.bin"),
            ("my.file name-v2.bin", "my.file name-v2.bin"),
            // Strip path components: `/` `\` take the last segment
            // (cross-directory write face collapsed).
            ("a/b.txt", "b.txt"),
            ("a\\b.txt", "b.txt"),
            ("C:\\Users\\x\\f.bin", "f.bin"),
            ("/abs/path.bin", "path.bin"),
            ("..\\..\\evil", "evil"),
            ("nested/deep/name.zip", "name.zip"),
            // Drive prefixes stripped with the component (the
            // cross-directory face of Windows join replacing the base
            // directory; `C:\evil` is already handled by separator
            // stripping, `C:evil` is the drive-relative form).
            ("C:evil", "evil"),
            ("d:data.tar", "data.tar"),
            // No character replacement: illegal characters go to the OS
            // as-is (the acceptance face already rejected them; here we
            // verify the engine-level invariant — the character set is
            // not sanitized).
            ("a<b>c.txt", "a<b>c.txt"),
            ("q?.zip", "q?.zip"),
            // Trailing dots/spaces not stripped (user content as-is;
            // the acceptance face already rejected; POSIX-legal).
            ("evil.", "evil."),
            ("name .txt", "name .txt"),
            // Reserved-name suffix (same rule as the full channel: stem gets `_`, extension kept).
            ("CON", "CON_"),
            ("con.txt", "con_.txt"),
            ("LPT9.tar.gz", "LPT9_.tar.gz"),
            ("aux", "aux_"),
            // Empty/dot shapes/pure drive -> fallback.
            ("", "download"),
            ("   ", "download"),
            (".", "download"),
            ("..", "download"),
            ("C:", "download"),
            ("/", "download"),
            ("a/b/", "download"),
        ];
        for (input, expected) in cases {
            assert_eq!(sanitize_user_name(input), *expected, "input {input:?}");
        }
    }

    /// Light-channel length truncation (the acceptance face
    /// `sanitize_out_option` already caps at 255 bytes; names of
    /// 248-255 bytes within that cap still shrink to the engine budget
    /// here): 254 bytes keeping the final extension (`.tar` counts as
    /// stem and truncates by budget); idempotent.
    #[test]
    fn light_channel_clamps_length_and_stays_idempotent() {
        let long_user = format!("{}{}", "u".repeat(300), ".tar.gz");
        let clamped = sanitize_user_name(&long_user);
        assert_eq!(clamped.len(), MAX_NAME_BYTES, "{clamped}");
        assert!(clamped.ends_with(".gz"), "{clamped}");
        assert!(clamped.starts_with('u'));
        assert!(clamped.chars().take(251).all(|c| c == 'u'));
        // Idempotent (running the truncated product through the light
        // channel again changes nothing).
        assert_eq!(sanitize_user_name(&clamped), clamped);
        for input in ["C:evil", "CON", "a/b.txt", "..", "x".repeat(300).as_str()] {
            let once = sanitize_user_name(input);
            assert_eq!(sanitize_user_name(&once), once, "input {input:?}");
        }
    }

    /// Light-channel invariants: non-empty, single component (no `/`
    /// `\`, no drive prefix), <= 254 bytes, non-reserved stem. The
    /// character set is NOT sanitized (the difference vs the
    /// full-channel contract).
    #[test]
    fn light_channel_holds_component_invariants_only() {
        for input in [
            "C:evil",
            "a/b\\c",
            "CON",
            "",
            "..",
            "x".repeat(300).as_str(),
            "nul.bin",
            "COM9",
        ] {
            let sanitized = sanitize_user_name(input);
            assert!(!sanitized.is_empty(), "{input:?} → {sanitized:?}");
            assert!(
                !sanitized.contains('/') && !sanitized.contains('\\'),
                "{input:?} → {sanitized:?}"
            );
            let bytes = sanitized.as_bytes();
            assert!(
                !(bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'),
                "drive-letter prefix must be stripped: {input:?} → {sanitized:?}"
            );
            let stem = sanitized.split('.').next().unwrap_or_default();
            assert!(!stem_is_reserved_str(stem), "{input:?} → {sanitized:?}");
            assert!(
                sanitized.len() <= MAX_NAME_BYTES,
                "{input:?} → {sanitized:?}"
            );
        }
    }

    /// Engine-side budget: default `.part` -> 247 (`<name>.1.part` <=
    /// 254); task-level suffix shrink (the 33-byte extreme -> 219);
    /// budget-face sanitization of long names + idempotence. The e2e
    /// tests are the on-disk proof (a final name taken directly at 254
    /// makes `<name>.part` = 259 bytes, over `NAME_MAX` — macOS error
    /// 63; this budget is the fix).
    #[test]
    fn engine_name_budget_scales_with_task_suffix() {
        let default_suffix = IncompleteSuffix::default();
        assert_eq!(engine_name_budget(&default_suffix), 247);
        let custom =
            IncompleteSuffix::parse(".crdownload").unwrap_or_else(|e| panic!("parse: {e}"));
        assert_eq!(
            engine_name_budget(&custom),
            254 - 11 - CONFLICT_SUFFIX_RESERVE
        );
        let extreme = IncompleteSuffix::parse(concat!(".", "a", "0123456789012345678901234567890"))
            .unwrap_or_else(|e| panic!("parse extreme: {e}"));
        assert_eq!(engine_name_budget(&extreme), 219);

        // Budget face: an overlong name truncates to the budget
        // (extension kept) and the `.1` candidate + suffix stay <= 254.
        let budget = engine_name_budget(&default_suffix);
        let name = sanitize_generated_name_with_budget(&format!("{}.bin", "L".repeat(300)), budget);
        assert_eq!(name.len(), budget);
        let candidate = renamed_candidate(Path::new(&name), 1);
        let candidate_part = part_path_for(&candidate, &default_suffix);
        assert!(
            candidate_part.to_string_lossy().len() <= MAX_NAME_BYTES,
            "the first candidate's .part component must be <= {}: {}",
            MAX_NAME_BYTES,
            candidate_part.display()
        );
        // Idempotent (budget face).
        assert_eq!(
            sanitize_generated_name_with_budget(&name, budget),
            name,
            "budget-face sanitization is idempotent"
        );
    }

    /// Suffix strict-validation matrix: legal (`.part`/`.crdownload`/
    /// `.9`/`.a1.b2-c3_d4`/the 33-byte full length) and illegal (no
    /// dot, dot with no body, separators, NUL, non-ASCII, first char
    /// not alphanumeric, 34-byte overlong, empty) — out-of-domain is
    /// always `taiji.option.invalid`.
    #[test]
    fn suffix_validation_matrix() {
        let valid = [
            ".part",
            ".crdownload",
            ".9",
            ".z",
            ".A0._-",
            ".a1.b2-c3_d4",
            concat!(".", "a", "0123456789012345678901234567890"), // 1+32 = full length 33
        ];
        for v in valid {
            let s = IncompleteSuffix::parse(v).unwrap_or_else(|e| panic!("`{v}` must parse: {e}"));
            assert_eq!(s.as_str(), v);
        }

        let invalid = [
            "",                                                    // empty
            "part",                                                // no leading dot
            ".",                                                   // dot with no body
            "..",                                                  // first char not alphanumeric
            ".-part",                                              // first char not alphanumeric
            "._part",                                              // first char not alphanumeric
            ".par/t",                                              // separator
            ".part\\",                                             // separator
            ".pa rt",                                              // space out of domain
            ".pa:rt",                                              // structural char out of domain
            ".中文",                                               // non-ASCII
            concat!(".", "a", "01234567890123456789012345678901"), // body 33 = overlong
        ];
        for v in invalid {
            let err = IncompleteSuffix::parse(v)
                .err()
                .unwrap_or_else(|| panic!("`{v}` must be rejected"));
            match err {
                HttpError::OptionInvalid { option, .. } => {
                    assert_eq!(option, "--http-incomplete-suffix");
                    assert_eq!(err.code(), "taiji.option.invalid");
                }
                other => panic!("unexpected error for `{v}`: {other:?}"),
            }
        }
        // Carrier text for the 32-byte cap (the diagnostic does not truncate the original value).
        let err = IncompleteSuffix::parse(concat!(".", "a", "01234567890123456789012345678901"))
            .err()
            .unwrap_or_else(|| panic!("overlong must be rejected"));
        assert!(
            err.to_string().contains("0,31}"),
            "rejection payload names the naming domain: {err}"
        );
    }

    /// Creation-time persistence + restore semantics (a default change
    /// never breaks in-flight tasks): the task's persisted value wins
    /// over the session default; missing falls back to the default; a
    /// corrupted persisted value is defensively rejected; the
    /// config_json fragment is stable single-key JSON (parsed with
    /// serde_json as a cross-check).
    #[test]
    fn suffix_persistence_survives_default_change() {
        // The fragment written into config_json at creation (stable shape).
        let custom =
            IncompleteSuffix::parse(".crdownload").unwrap_or_else(|e| panic!("parse: {e}"));
        let fragment = custom.config_json_fragment();
        assert_eq!(
            fragment, r#"{"http_incomplete_suffix":".crdownload"}"#,
            "stable single-key shape (key order / no whitespace)"
        );
        // The fragment is legal JSON and the value round-trips
        // verbatim (the naming domain guarantees no escaping).
        let parsed: serde_json::Value =
            serde_json::from_str(&fragment).unwrap_or_else(|e| panic!("json: {e}"));
        assert_eq!(
            parsed
                .get(CONFIG_KEY_INCOMPLETE_SUFFIX)
                .and_then(|v| v.as_str()),
            Some(".crdownload")
        );

        // In-flight task restore: the persisted value wins — the
        // session default flipping back to `.part` does not break the
        // resume.
        let session_default = IncompleteSuffix::default();
        let restored = IncompleteSuffix::restore_from_config(Some(".crdownload"), &session_default)
            .unwrap_or_else(|e| panic!("restore: {e}"));
        assert_eq!(restored, custom);
        // The join face uses the restored value.
        assert_eq!(
            part_path_for(Path::new("/data/file.bin"), &restored),
            PathBuf::from("/data/file.bin.crdownload")
        );

        // No persisted value (old task) -> the session current default.
        assert_eq!(
            IncompleteSuffix::restore_from_config(None, &session_default)
                .unwrap_or_else(|e| panic!("restore default: {e}")),
            session_default
        );
        // Persisted value corrupted externally -> defensive reject (no silent default fallback).
        assert!(IncompleteSuffix::restore_from_config(Some("bad"), &session_default).is_err());
    }

    /// auto-file-renaming candidate algorithm (cross-checked against
    /// aria2 `RequestGroup.cc`): extension split matrix + `fn.i.ext`
    /// shape + first free candidate + 10000 exhaustion.
    #[test]
    fn auto_rename_candidates_follow_aria2_scheme() {
        // Split matrix: regular / multi-dot / leading-dot name /
        // directory leading dot / no dot (reference comment, case by case).
        let cases = [
            ("/d/file.tar.gz", ("/d/file.tar", ".gz")),
            ("/d/file", ("/d/file", "")),
            ("/d/.file", ("/d/.file", "")), // leading-dot name: no extension
            ("/d/.hidden.x", ("/d/.hidden", ".x")),
            (".file", (".file", "")),
            ("file.v2.tar", ("file.v2", ".tar")),
        ];
        for (input, (base, ext)) in cases {
            let (b, e) = split_name_ext(Path::new(input));
            assert_eq!(
                (b.as_os_str().to_string_lossy().as_ref(), e.as_str()),
                (base, ext),
                "split {input}"
            );
        }

        // Candidate shape (reference `fmt("%s.%d%s", fn, i, ext)`):
        // file.tar.gz -> file.tar.1.gz / file.bin -> file.7.bin.
        assert_eq!(
            renamed_candidate(Path::new("/d/file.tar.gz"), 1),
            PathBuf::from("/d/file.tar.1.gz")
        );
        assert_eq!(
            renamed_candidate(Path::new("/d/file.bin"), 7),
            PathBuf::from("/d/file.7.bin")
        );

        // First free candidate: occupied ordinals skipped (aria2
        // semantics — if a candidate itself exists, keep going; this
        // engine has no `.aria2` sidecar, only the candidate name is
        // checked).
        let mut taken = BTreeSet::new();
        taken.insert("/d/file.1.bin".to_string());
        taken.insert("/d/file.2.bin".to_string());
        let free = next_free_candidate(Path::new("/d/file.bin"), |p| {
            taken.contains(p.to_string_lossy().as_ref())
        })
        .unwrap_or_else(|| panic!("free candidate"));
        assert_eq!(free, PathBuf::from("/d/file.3.bin"));

        // All occupied -> exhausted None (cross-checked against the
        // aria2 FILE_RENAMING_FAILED face).
        let exhausted = next_free_candidate(Path::new("/d/x"), |_| true);
        assert!(exhausted.is_none(), "10000 ordinals exhausted -> reject");
    }

    /// Conflict-check negative cases: the target exists without
    /// auto-rename -> `taiji.http.path_conflict`; a directory occupying
    /// the `.part` slot -> same code; probe hiccups do not reject the
    /// task.
    #[test]
    fn creation_conflict_negative_cases() {
        let dir = tempdir();
        // Target exists: auto-rename off -> reject.
        let out = dir.path.join("a.bin");
        std::fs::write(&out, b"existing").unwrap_or_else(|e| panic!("seed: {e}"));
        let suffix = IncompleteSuffix::default();
        let err = plan_output(out.clone(), &suffix, CreationPolicy::default(), "t-pl-c1")
            .err()
            .unwrap_or_else(|| panic!("conflict must be refused"));
        assert_eq!(err.code(), "taiji.http.path_conflict");

        // Auto-rename on -> candidate name + suffix joined with the configured suffix.
        let plan = plan_output(
            out.clone(),
            &suffix,
            CreationPolicy {
                auto_file_renaming: true,
            },
            "t-pl-c1",
        )
        .unwrap_or_else(|e| panic!("auto rename: {e}"));
        assert_eq!(plan.final_path, dir.path.join("a.1.bin"));
        assert_eq!(plan.part_path, dir.path.join("a.1.bin.part"));
        assert!(
            plan.renamed,
            "an effective auto-rename must be flagged in the result"
        );

        // A directory occupies the `.part` slot -> conflict (the target itself does not exist).
        let out2 = dir.path.join("b.bin");
        std::fs::create_dir(dir.path.join("b.bin.part"))
            .unwrap_or_else(|e| panic!("seed dir: {e}"));
        let err = plan_output(out2, &suffix, CreationPolicy::default(), "t-pl-c1")
            .err()
            .unwrap_or_else(|| panic!("part dir must conflict"));
        assert_eq!(err.code(), "taiji.http.path_conflict");

        // Clean path -> the original name passes through, renamed = false.
        let plan = plan_output(
            dir.path.join("c.bin"),
            &suffix,
            CreationPolicy::default(),
            "t-pl-c1",
        )
        .unwrap_or_else(|e| panic!("clean: {e}"));
        assert_eq!(plan.final_path, dir.path.join("c.bin"));
        assert_eq!(plan.part_path, dir.path.join("c.bin.part"));
        assert!(!plan.renamed);

        dir.wipe();
    }

    /// `.part` reuse decision: matching length resumes / mismatching
    /// length re-downloads fully / missing starts from zero / degraded
    /// always starts from zero (even with matching lengths).
    #[test]
    fn part_reuse_decision() {
        let dir = tempdir();
        let part = dir.path.join("f.bin.part");
        std::fs::write(&part, [0u8; 128]).unwrap_or_else(|e| panic!("seed: {e}"));

        // Matching length -> resume.
        assert_eq!(
            decide_part_reuse(&part, Some(128), false).unwrap_or_else(|e| panic!("reuse: {e}")),
            PartReuse::Resume
        );
        // Mismatch -> full re-download (the caller clears the bitmap).
        assert_eq!(
            decide_part_reuse(&part, Some(256), false).unwrap_or_else(|e| panic!("mismatch: {e}")),
            PartReuse::Restart
        );
        // Missing -> from zero.
        assert_eq!(
            decide_part_reuse(&dir.path.join("absent.part"), Some(128), false)
                .unwrap_or_else(|e| panic!("absent: {e}")),
            PartReuse::Restart
        );
        // Degraded (no bitmap): from zero even with matching lengths.
        assert_eq!(
            decide_part_reuse(&part, Some(128), true).unwrap_or_else(|e| panic!("degraded: {e}")),
            PartReuse::Restart
        );
        // No total length: no criterion, from zero.
        assert_eq!(
            decide_part_reuse(&part, None, false).unwrap_or_else(|e| panic!("no len: {e}")),
            PartReuse::Restart
        );

        dir.wipe();
    }

    /// (a) Final-path mutual exclusion (red then green): two tasks on
    /// the same dir/out with different incomplete suffixes, created in
    /// sequence — the second must be rejected with
    /// `taiji.http.path_conflict`. Before the fix, the claim hung only
    /// off the `.part` path: the two part paths differ -> both pass and
    /// download concurrently, and finalize's atomic posix rename lets
    /// the later finisher silently swallow the earlier task's final
    /// file. After the first task releases (terminal/removed), the path
    /// is reusable (the anti-overblock anchor).
    #[test]
    fn final_path_registry_rejects_second_task_with_different_suffix() {
        let dir = tempdir();
        let out = dir.path.join("race.bin");
        let sfx_a = IncompleteSuffix::parse(".a").unwrap_or_else(|e| panic!("sfx a: {e}"));
        let sfx_b = IncompleteSuffix::parse(".b").unwrap_or_else(|e| panic!("sfx b: {e}"));
        let (gid_a, gid_b) = ("80000000000000a1", "80000000000000a2");

        let first = plan_output(out.clone(), &sfx_a, CreationPolicy::default(), gid_a)
            .unwrap_or_else(|e| panic!("first plan: {e}"));
        assert_eq!(
            first.part_path,
            dir.path.join("race.bin.a"),
            "suffixes are appended independently \
             (the part paths are irrelevant to each other — \
             the final path is the shared domain)"
        );

        match plan_output(out.clone(), &sfx_b, CreationPolicy::default(), gid_b) {
            Err(e) => assert_eq!(e.code(), "taiji.http.path_conflict", "{e}"),
            Ok(_) => panic!(
                "must not admit a second task while the final path is held \
                 by an in-flight task (different suffixes are not an isolation domain)"
            ),
        }

        // First task released (rename landed / removed) -> the path
        // is reusable (the anti-overblock anchor).
        crate::partfile::release_final_path(&first.final_path, gid_a);
        let second = plan_output(out, &sfx_b, CreationPolicy::default(), gid_b)
            .unwrap_or_else(|e| panic!("plan after release: {e}"));
        assert_eq!(second.final_path, dir.path.join("race.bin"));

        dir.wipe();
    }

    // ---- Test scaffolding: temp dirs (no tempfile dependency; process-unique names) ----

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("taiji-http-{}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap_or_else(|e| panic!("tempdir: {e}"));
            TempDir { path }
        }

        fn wipe(&self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn tempdir() -> TempDir {
        TempDir::new()
    }
}
