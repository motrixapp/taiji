//! v2 file tree parsing + path sanitization + `piece layers` load-time
//! validation (SPEC §4.2, BEP-52).
//!
//! `parse` walks the `file tree` in key (DFS) order, sanitizes each path
//! component (reject, never rewrite), then joins and re-validates the
//! top-level `piece layers` per file. Missing layer entries degrade to
//! `FileEntry::layer_missing` (recoverable via hash recovery); present but
//! invalid layers, missing pieces roots and path rule violations are hard
//! rejects. Upstream rule anchors: docs/design/piece-verification.md.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use bytes::Bytes;
use taiji_io::text::is_spoofing_char;
use taiji_store::merkle;
use thiserror::Error;

use crate::bencode::Value;

const INFO_KEY: &[u8] = b"info";
const FILE_TREE_KEY: &[u8] = b"file tree";
const META_VERSION_KEY: &[u8] = b"meta version";
const PIECE_LENGTH_KEY: &[u8] = b"piece length";

/// Engineering piece length cap: 16 MiB (rationale in the `parse` body).
pub(crate) const MAX_PIECE_LENGTH: u32 = 16 * 1024 * 1024;
const PIECE_LAYERS_KEY: &[u8] = b"piece layers";
const LENGTH_KEY: &[u8] = b"length";
const PIECES_ROOT_KEY: &[u8] = b"pieces root";
const ATTR_KEY: &[u8] = b"attr";

/// BEP-47 `attr` flags. Rarely present in a v2 file tree; parsed per byte,
/// unknown flags ignored (undefined by BEP-47; libtorrent does the same).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileAttr {
    /// 'p': padding file (BEP-47; never written to disk or requested, SPEC §4.5.3).
    pub padding: bool,
    /// 'h': hidden file.
    pub hidden: bool,
    /// 'x': executable.
    pub executable: bool,
    /// 'l': symbolic link (target in the BEP-47 `symlink path` key; not parsed here).
    pub symlink: bool,
}

fn parse_attr(bytes: &[u8]) -> FileAttr {
    let mut attr = FileAttr::default();
    for &b in bytes {
        match b {
            b'p' => attr.padding = true,
            b'h' => attr.hidden = true,
            b'x' => attr.executable = true,
            b'l' => attr.symlink = true,
            _ => {}
        }
    }
    attr
}

/// One file in the file tree (SPEC §4.2 `FileEntry`).
#[derive(Debug, Clone)]
pub struct FileEntry {
    /// Sanitized relative path (DFS order). Rejects '.', '..', '/', '\', ':',
    /// control chars (C0/DEL/C1), display-spoofing code points (single source
    /// [`taiji_io::text::is_spoofing_char`]), >255-byte components, NUL,
    /// invalid UTF-8, reserved names, trailing dot/space — details in
    /// [`sanitize_component`].
    pub path: PathBuf,
    pub length: u64,
    pub attr: FileAttr,
    /// Required for non-empty v2 files; None for empty files (BEP-52).
    pub pieces_root: Option<[u8; 32]>,
    /// Top-level `piece layers[root]`, re-validated at load; None for files
    /// of <= 1 piece.
    pub piece_layer: Option<Bytes>,
    /// `piece layers` entry missing (length > piece length, root intact) —
    /// load proceeds (SPEC §4.2 missing-layer degradation; libtorrent
    /// `torrent.cpp` does the same with `valid = false; continue`) and the
    /// file enters hash recovery via its pieces root. An entry that is
    /// present but fails validation is still a hard reject (libtorrent
    /// `torrent_invalid_piece_layer`).
    pub layer_missing: bool,
    /// Global v1 piece-aligned offset for the hybrid/v1 view (pad
    /// placeholders included); filled by the layout mapping, always None
    /// during file tree parsing (SPEC §4.2).
    pub v1_offset: Option<u64>,
}

/// Output of [`parse`]: global piece length + file list in DFS order (SPEC §4.2).
#[derive(Debug, Clone)]
pub struct TorrentFiles {
    /// Global piece length. v2/hybrid face: power of two and >= 16 KiB
    /// (BEP-52; validated). v1-only face (produced by [`parse_v1_files`]):
    /// any positive integer (BEP-3 has no power-of-two/minimum rule —
    /// constraints are per face, see the `parse_v1_files` comments).
    pub piece_length: u32,
    pub files: Vec<FileEntry>,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FileTreeError {
    #[error("metainfo is not a dict")]
    NotADict,
    #[error("`info` is not a dict")]
    InfoNotADict,
    #[error("v1 file entry has no valid `path`/`length`")]
    V1FileMissingPath,
    #[error("`file tree` key missing: not a v2/hybrid torrent")]
    NoFileTree,
    #[error("`file tree` is not a dict")]
    FileTreeNotADict,
    #[error("`meta version` missing while `file tree` present (BEP52 requires the field)")]
    MissingMetaVersion,
    #[error("`meta version` is not an integer")]
    InvalidMetaVersion,
    #[error("unsupported `meta version` {0}: only 2 (BEP52 current revision) is accepted")]
    UnsupportedMetaVersion(i64),
    #[error("`piece length` missing")]
    MissingPieceLength,
    #[error("`piece length` {0} is not a positive integer in u32 range")]
    PieceLengthOutOfRange(i64),
    #[error("invalid `piece length`: {0}")]
    InvalidPieceLength(#[source] merkle::MerkleError),
    #[error("file tree root must not be a file (BEP52)")]
    RootIsFile,
    #[error("path traversal attempt via component {component:?}")]
    PathTraversal { component: String },
    #[error("path component {component:?} contains '/', breaking the one-element-per-key model")]
    PathSeparator { component: String },
    #[error("path component {component:?} contains NUL")]
    NulInPath { component: String },
    #[error(
        "path component {component:?} contains a control character other than NUL (C0 0x01-0x1F, DEL 0x7F, or C1 0x80-0x9F)"
    )]
    ControlCharInPath { component: String },
    #[error(
        "path component {component:?} contains a display-spoofing code point (bidi overrides U+061C/U+200E/U+200F/U+202A-202E/U+2066-2069, zero-width U+200B/U+200C/U+FEFF, or line/paragraph separators U+2028/U+2029)"
    )]
    SpoofingCharInPath { component: String },
    #[error(
        "path component is {len} bytes long, exceeding the 255-byte component cap (NAME_MAX/ENAMETOOLONG)"
    )]
    ComponentTooLong { component: String, len: usize },
    #[error("path component is not valid UTF-8 (lossy: {0:?})")]
    InvalidUtf8Path(String),
    #[error("path component {component:?} is a reserved device name")]
    ReservedName { component: String },
    #[error(
        "path component {component:?} contains '\\' (Windows path separator / UNC prefix; a file tree key must be a single path element on every platform)"
    )]
    BackslashInPath { component: String },
    #[error(
        "path component {component:?} contains ':' (drive designator or NTFS alternate data stream form)"
    )]
    ColonInPath { component: String },
    #[error(
        "path component {component:?} ends with '.' or ' ' (Win32 strips trailing dots/spaces, so the name would silently resolve to a different path or device)"
    )]
    TrailingDotOrSpace { component: String },
    #[error("file marker at {path:?} must not have sibling entries (BEP52)")]
    FileMarkerWithSiblings { path: PathBuf },
    #[error(
        "duplicate file path {path:?} in v1 `files` list: two entries would open the same on-disk file and rewrite each other's verified bytes"
    )]
    DuplicateFilePath { path: PathBuf },
    #[error("file node at {path:?} is not a dict")]
    ChildNotADict { path: PathBuf },
    #[error("file properties at {path:?} is not a dict")]
    FilePropsNotADict { path: PathBuf },
    #[error("file at {path:?} has no `length` key")]
    MissingLength { path: PathBuf },
    #[error("file at {path:?} has a non-integer or negative `length`")]
    InvalidLength { path: PathBuf },
    #[error("empty file at {path:?} must not carry `pieces root` (BEP52)")]
    EmptyFileWithPiecesRoot { path: PathBuf },
    #[error("non-empty file at {path:?} must carry `pieces root` (SPEC §4.2)")]
    MissingPiecesRoot { path: PathBuf },
    #[error("`pieces root` at {path:?} is {len} bytes, expected 32")]
    PiecesRootLength { path: PathBuf, len: usize },
    #[error("`piece layers` is not a dict")]
    PieceLayersNotADict,
    #[error("`piece layers` keys must be 32-byte merkle roots")]
    InvalidPieceLayerKey,
    #[error("`piece layers` value for {path:?} is not a byte string")]
    PieceLayerNotBytes { path: PathBuf },
    #[error("`piece layers` validation failed for {path:?}")]
    PieceLayerMismatch {
        path: PathBuf,
        #[source]
        source: merkle::MerkleError,
    },
}

/// Parse `file tree` + `piece layers` of a v2/hybrid metainfo.
///
/// Input is the metadata **top-level** dict (output of `bencode::decode`).
/// BEP-52 layout: `file tree`/`meta version`/`piece length` live inside
/// `info`, `piece layers` at the top level (outside `info`). Dict entries
/// are stored in byte-sorted key order (enforced by strict decode), so DFS
/// order is file order. Any validation failure returns an explicit error —
/// the torrent is rejected (invalid per BEP-52), never silently repaired.
pub fn parse(meta: &Value) -> Result<TorrentFiles, FileTreeError> {
    if !matches!(meta, Value::Dict(_)) {
        return Err(FileTreeError::NotADict);
    }
    // v1 torrents have no file tree; a missing `info` also maps to
    // NoFileTree so the caller falls back to the v1 path.
    let info = match meta.get(INFO_KEY) {
        Some(v @ Value::Dict(_)) => v,
        Some(_) => return Err(FileTreeError::InfoNotADict),
        None => return Err(FileTreeError::NoFileTree),
    };
    let file_tree = info.get(FILE_TREE_KEY);
    // BEP-52: "Implementations must check this field first" — the version
    // gate precedes all other structural validation.
    match info.get(META_VERSION_KEY) {
        Some(Value::Int(2)) => {}
        Some(Value::Int(v)) => return Err(FileTreeError::UnsupportedMetaVersion(*v)),
        Some(_) => return Err(FileTreeError::InvalidMetaVersion),
        None => match file_tree {
            None => return Err(FileTreeError::NoFileTree),
            Some(_) => return Err(FileTreeError::MissingMetaVersion),
        },
    }
    let file_tree = file_tree.ok_or(FileTreeError::NoFileTree)?;
    let pairs = match file_tree {
        Value::Dict(pairs) => pairs,
        _ => return Err(FileTreeError::FileTreeNotADict),
    };
    if file_tree.get(b"").is_some() {
        // "" at the root level means the root is a file (explicitly
        // forbidden by BEP-52; walk never sees an empty key below the root).
        return Err(FileTreeError::RootIsFile);
    }

    let piece_length = match info.get(PIECE_LENGTH_KEY) {
        // Engineering cap MAX_PIECE_LENGTH (16 MiB): BEP-3/BEP-52 set no
        // upper bound, but piece length is the common multiplier of webseed
        // whole-piece fetch buffers, in-flight verify (workers x queue x
        // piece length) and the fixed-size write cache (2 x peers x piece
        // length); a legal-in-u32 4 GiB piece would mean GiB-scale RSS per
        // task. qBittorrent's creator caps at 16 MiB, libtorrent is the
        // same order; existing torrents above 16 MiB are practically
        // nonexistent.
        Some(Value::Int(n)) if *n > 0 && *n <= MAX_PIECE_LENGTH as i64 => *n as u32,
        Some(Value::Int(n)) => return Err(FileTreeError::PieceLengthOutOfRange(*n)),
        Some(_) => return Err(FileTreeError::PieceLengthOutOfRange(0)),
        None => return Err(FileTreeError::MissingPieceLength),
    };
    merkle::validate_piece_len(piece_length).map_err(FileTreeError::InvalidPieceLength)?;

    let mut files = Vec::new();
    walk(pairs, Path::new(""), &mut files)?;

    join_piece_layers(meta, piece_length, &mut files)?;

    Ok(TorrentFiles {
        piece_length,
        files,
    })
}

/// DFS pre-order walk: pairs are already byte-sorted by key (strict decode),
/// which is file order.
fn walk(
    dir: &[(Vec<u8>, Value)],
    dir_path: &Path,
    out: &mut Vec<FileEntry>,
) -> Result<(), FileTreeError> {
    for (name, child) in dir {
        let component = sanitize_component(name)?;
        let file_path = dir_path.join(&component);
        let members = match child {
            Value::Dict(members) => members,
            _ => return Err(FileTreeError::ChildNotADict { path: file_path }),
        };
        match members.iter().find(|(k, _)| k.is_empty()) {
            Some((_, marker)) => {
                if members.len() != 1 {
                    // BEP-52: "Presence of this field [length] indicates
                    // that the dictionary describes a file ... it must not
                    // have any sibling entries".
                    return Err(FileTreeError::FileMarkerWithSiblings { path: file_path });
                }
                out.push(parse_file_props(marker, &file_path)?);
            }
            None => {
                // Directory (empty dirs produce no entry; not forbidden by
                // the BEP, libtorrent also preserves them).
                walk(members, &file_path, out)?;
            }
        }
    }
    Ok(())
}

fn parse_file_props(marker: &Value, path: &Path) -> Result<FileEntry, FileTreeError> {
    let props = match marker {
        Value::Dict(_) => marker,
        _ => {
            return Err(FileTreeError::FilePropsNotADict {
                path: path.to_path_buf(),
            });
        }
    };
    let length = match props.get(LENGTH_KEY) {
        Some(Value::Int(n)) if *n >= 0 => *n as u64,
        Some(_) => {
            return Err(FileTreeError::InvalidLength {
                path: path.to_path_buf(),
            });
        }
        None => {
            return Err(FileTreeError::MissingLength {
                path: path.to_path_buf(),
            });
        }
    };
    let pieces_root = match props.get(PIECES_ROOT_KEY) {
        None => None,
        Some(Value::Bytes(b)) if b.len() == 32 => {
            let mut root = [0u8; 32];
            root.copy_from_slice(b);
            Some(root)
        }
        Some(Value::Bytes(b)) => {
            return Err(FileTreeError::PiecesRootLength {
                path: path.to_path_buf(),
                len: b.len(),
            });
        }
        Some(_) => {
            return Err(FileTreeError::PiecesRootLength {
                path: path.to_path_buf(),
                len: 0,
            });
        }
    };
    match (length, pieces_root) {
        (0, Some(_)) => {
            return Err(FileTreeError::EmptyFileWithPiecesRoot {
                path: path.to_path_buf(),
            });
        }
        // An empty file without a root is spec behavior (BEP-52 "For
        // non-empty files ..."; the official creator writes only `length`
        // for length==0).
        (0, None) => {}
        // SPEC §4.2: a v2 non-empty file must carry a pieces root.
        (_, None) => {
            return Err(FileTreeError::MissingPiecesRoot {
                path: path.to_path_buf(),
            });
        }
        (_, Some(_)) => {}
    }
    let attr = props
        .get(ATTR_KEY)
        .and_then(Value::as_bytes)
        .map(parse_attr)
        .unwrap_or_default();
    Ok(FileEntry {
        path: path.to_path_buf(),
        length,
        attr,
        pieces_root,
        piece_layer: None,
        layer_missing: false,
        v1_offset: None,
    })
}

/// Sanitize `info.name` / `info.name.utf-8` (BEP-3 "name" section; the root
/// directory name for multi-file torrents, the file name for single-file).
/// Returns `Err` for an invalid name (reject the torrent, same rules as
/// component sanitization).
pub fn sanitize_info_name(name: &[u8]) -> Result<String, FileTreeError> {
    sanitize_component(name)
}

/// Path sanitization (BEP-52 file tree section + SPEC §4.2; details in the
/// module docs).
fn sanitize_component(name: &[u8]) -> Result<String, FileTreeError> {
    if name.is_empty() {
        // Defensive branch: "" at the root is checked explicitly by parse()
        // (RootIsFile); below the root "" is only consumed as a file marker by
        // walk and never reaches here as a name.
        return Err(FileTreeError::RootIsFile);
    }
    // 255-byte component cap: the strictest cross-platform NAME_MAX (Linux
    // 255 B, macOS APFS 255 UTF-8 bytes, Windows without long paths 255
    // UTF-16 units). A longer component hits ENAMETOOLONG on strict
    // filesystems, so the first file create would fail and reject the whole
    // task. Unlike naming.rs's 254-byte truncation, this face rejects
    // rather than silently rewriting names declared in the user's torrent;
    // the cap is 255 (reject only when over; exactly at the cap is legal).
    if name.len() > MAX_COMPONENT_BYTES {
        return Err(FileTreeError::ComponentTooLong {
            component: String::from_utf8_lossy(name).into_owned(),
            len: name.len(),
        });
    }
    let s = String::from_utf8(name.to_vec())
        .map_err(|_| FileTreeError::InvalidUtf8Path(String::from_utf8_lossy(name).into_owned()))?;
    // "path components exactly matching '.' and '..' must be sanitized
    // since they could lead to directory traversal attacks" (BEP-52).
    if s == "." || s == ".." {
        return Err(FileTreeError::PathTraversal { component: s });
    }
    if s.contains('\0') {
        return Err(FileTreeError::NulInPath { component: s });
    }
    // Remaining C0 (0x01-0x1F), DEL (0x7F) and C1 (0x80-0x9F): control
    // characters in file names are a log/alert injection surface
    // (`\n`/`\r` fake lines) and are illegal names on Windows
    // (0x01-0x1F), letting a remote peer reject the whole task. NUL was
    // handled by the previous branch, so only other C0/DEL/C1 can reach
    // here. `char::is_control` (Cc category = U+0000-001F, U+007F-009F) is
    // the single rule shared by all intake faces; MS Naming Conventions
    // reserves the whole 0x00-0x1F range.
    if s.chars().any(|c| c.is_control()) {
        return Err(FileTreeError::ControlCharInPath { component: s });
    }
    // Display-spoofing / hidden-injection code points (single source):
    // `a\u{202E}b.exe` bidi display spoofing, `evil\u{200B}.exe` zero-width
    // visual twin, U+2028/U+2029 line/paragraph separator injection. The
    // set lives in [`taiji_io::text::is_spoofing_char`] (shared by
    // bt/http/core).
    if s.chars().any(is_spoofing_char) {
        return Err(FileTreeError::SpoofingCharInPath { component: s });
    }
    if s.contains('/') {
        // A '/' embedded in one key expands into multiple directories in a
        // POSIX path, breaking the "dictionary keys represent path elements"
        // model.
        return Err(FileTreeError::PathSeparator { component: s });
    }
    // ---- Windows component rules (three) ----
    // Torrents are cross-platform artifacts: a key accepted on a POSIX host
    // may later be written to a Windows volume, so these rules apply
    // unconditionally on all platforms, like the existing reserved-name
    // check.
    //
    // Rule 1: '\' (UNC prefix and embedded backslash) -> reject.
    // - libtorrent `torrent_info.cpp` `filter_path_character` filters `/`
    // and `\` unconditionally on every platform ("forward- and backslash
    // are filtered unconditionally and separately from this function") —
    // but that is write-side stripping; this parser rejects instead of
    // rewriting.
    // - MS "Naming Files, Paths, and Namespaces", Naming Conventions: "You
    // cannot use a backslash in the name for the actual file or directory";
    // UNC names "always start with two backslash characters" — `\\` is path
    // prefix (namespace) syntax, never a name component.
    if s.contains('\\') {
        return Err(FileTreeError::BackslashInPath { component: s });
    }
    // Rule 2: ':' (drive designator `X:` and any colon) -> reject.
    // - libtorrent `torrent_info.cpp` `valid_path_character` (Windows
    // invalid set `?<>\"|\b*:` includes ':') and aria2 `util.cc`
    // `escapePath` (MinGW `WIN_INVALID_PATH_CHARS` includes ':') both treat
    // ':' as unusable in a name.
    // - MS Naming Conventions: ':' is reserved; "Fully Qualified vs.
    // Relative Paths": `C:tmp.txt` resolves drive-relative ("tmp.txt in the
    // current directory of drive C") — the same bytes would land with
    // ambiguous path semantics. A colon also opens an NTFS alternate data
    // stream (`file:stream`), so any ':' is rejected, not just the `X:`
    // form.
    if s.contains(':') {
        return Err(FileTreeError::ColonInPath { component: s });
    }
    // Rule 3: trailing dot or space -> reject at parse time.
    // - MS Naming Conventions: "Do not end a file or directory name with a
    // space or a period. Although the underlying file system may support
    // such names, the Windows shell and user interface does not." Win32
    // namespace normalization strips trailing '.'/' ', so names silently
    // drift on disk (`...` -> `..`, `nul.` -> `nul` device), creating
    // ambiguity and evading this sanitization.
    // - libtorrent `torrent_info.cpp` (TORRENT_WINDOWS branch strips
    // trailing spaces and dots, "These aren't allowed in filenames on
    // windows") — that is write-side stripping; this repo forbids silently
    // rewriting file names on write, so it rejects at parse time instead.
    // aria2 has no rule here (`detectDirTraversal`/`escapePath` ignore
    // trailing dots/spaces).
    if s.ends_with('.') || s.ends_with(' ') {
        return Err(FileTreeError::TrailingDotOrSpace { component: s });
    }
    if is_windows_reserved(&s) {
        return Err(FileTreeError::ReservedName { component: s });
    }
    Ok(s)
}

/// Windows reserved device names, including extension forms like `nul.txt`:
/// only the stem before the first '.' is checked (MS Naming Conventions:
/// "avoid these names followed immediately by an extension; for example,
/// NUL.txt and NUL.tar.gz are both equivalent to NUL"). UNC prefixes /
/// drive designators / trailing dot-space are handled in
/// [`sanitize_component`]; this predicate stays as is.
fn is_windows_reserved(component: &str) -> bool {
    let stem = match component.split_once('.') {
        Some((stem, _)) => stem,
        None => component,
    };
    const RESERVED: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    RESERVED.iter().any(|r| stem.eq_ignore_ascii_case(r))
}

/// Per-component byte cap: the strictest cross-platform NAME_MAX (Linux
/// ext4 255 B, macOS APFS 255 UTF-8 bytes; Windows without `\\?\` long
/// paths is the same order). Only `>` rejects (at the cap is legal). The
/// core `session::actor` `--out` intake face uses the same cap.
const MAX_COMPONENT_BYTES: usize = 255;

/// Join the top-level `piece layers` per file and re-validate (BEP-52
/// infohash + `piece layers` sections; math in
/// [`merkle::validate_piece_layer`]).
///
/// Missing vs corrupt split (SPEC §4.2 missing-layer degradation):
/// - entry **missing** (length > piece length, root intact) -> flag
/// `layer_missing` and keep loading (recoverable via hash recovery;
/// libtorrent `torrent.cpp` does the same with `valid = false; continue`).
/// The root inside `info` is the trust anchor, so SHA-256 convergence
/// guarantees a recovered layer is verifiable;
/// - entry **present but invalid** (count or root mismatch) -> hard reject
/// (corrupt metadata, not missing; libtorrent
/// `torrent_invalid_piece_layer`);
/// - root missing was already rejected in [`parse_file_props`]
/// (`MissingPiecesRoot`) — no trust anchor, mathematically unrecoverable,
/// never enters recovery;
/// - a file <= piece size with no entry is spec behavior (BEP-52 piece
/// layers section).
fn join_piece_layers(
    meta: &Value,
    piece_length: u32,
    files: &mut [FileEntry],
) -> Result<(), FileTreeError> {
    let piece_layers = match meta.get(PIECE_LAYERS_KEY) {
        None => None,
        Some(v @ Value::Dict(pairs)) => {
            for (k, _) in pairs {
                if k.len() != 32 {
                    return Err(FileTreeError::InvalidPieceLayerKey);
                }
            }
            Some(v)
        }
        Some(_) => return Err(FileTreeError::PieceLayersNotADict),
    };
    for entry in files.iter_mut() {
        let Some(root) = entry.pieces_root else {
            continue;
        };
        match piece_layers.and_then(|layers| layers.get(root.as_slice())) {
            Some(Value::Bytes(bytes)) => {
                merkle::validate_piece_layer(&root, bytes, entry.length, piece_length).map_err(
                    |source| FileTreeError::PieceLayerMismatch {
                        path: entry.path.clone(),
                        source,
                    },
                )?;
                entry.piece_layer = Some(Bytes::copy_from_slice(bytes));
            }
            Some(_) => {
                return Err(FileTreeError::PieceLayerNotBytes {
                    path: entry.path.clone(),
                });
            }
            None => {
                if entry.length > u64::from(piece_length) {
                    // Missing entry: degrade to the flag and keep loading
                    // (SPEC §4.2 missing-layer degradation). Root integrity is
                    // guaranteed by parse_file_props (non-empty files always
                    // have a root) — the trust anchor is present, so the gap is
                    // recoverable.
                    entry.layer_missing = true;
                }
                // A file <= piece size with no entry is spec behavior
                // (BEP-52 piece layers section).
            }
        }
    }
    // Extra entries matching no file: not forbidden by the BEP, ignored
    // (forward compatibility).
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bencode::Value;

    /// Build a dict with keys sorted by bytes (the strict-decode shape;
    /// [`Value::get`] binary search relies on this order).
    fn d(mut pairs: Vec<(Vec<u8>, Value)>) -> Value {
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        Value::Dict(pairs)
    }

    /// File leaf `{"": {length, "pieces root"?, attr?}}` (the outer `""` is
    /// the file marker).
    fn file_leaf(length: i64, pieces_root: Option<&[u8]>, attr: Option<&[u8]>) -> Value {
        let mut props: Vec<(Vec<u8>, Value)> = Vec::new();
        if let Some(a) = attr {
            props.push((ATTR_KEY.to_vec(), Value::Bytes(a.to_vec())));
        }
        props.push((LENGTH_KEY.to_vec(), Value::Int(length)));
        if let Some(r) = pieces_root {
            props.push((PIECES_ROOT_KEY.to_vec(), Value::Bytes(r.to_vec())));
        }
        // key byte order: "attr" < "length" < "pieces root".
        Value::Dict(vec![(Vec::new(), Value::Dict(props))])
    }

    fn marker() -> [u8; 32] {
        [0xaa; 32]
    }

    /// Top-level metainfo: `{info: {file tree, meta version, piece length},
    /// piece layers?}` (BEP-52 layout: piece layers outside info).
    fn metainfo(
        file_tree: Value,
        piece_layers: Option<Value>,
        meta_version: Option<i64>,
        piece_length: i64,
    ) -> Value {
        let info = d(vec![
            (FILE_TREE_KEY.to_vec(), file_tree),
            (
                META_VERSION_KEY.to_vec(),
                Value::Int(meta_version.unwrap_or(2)),
            ),
            (PIECE_LENGTH_KEY.to_vec(), Value::Int(piece_length)),
        ]);
        let mut pairs = vec![(INFO_KEY.to_vec(), info)];
        if let Some(layers) = piece_layers {
            pairs.push((PIECE_LAYERS_KEY.to_vec(), layers));
        }
        d(pairs)
    }

    fn pattern(len: usize) -> Vec<u8> {
        const P: &[u8] = b"blackhole-merkle-reference-";
        P.iter().cycle().take(len).copied().collect()
    }

    fn expect_err<T>(r: Result<T, FileTreeError>, what: &str) -> FileTreeError {
        match r {
            Err(e) => e,
            Ok(_) => panic!("expected error: {what}"),
        }
    }

    /// Negative-case table: (case name, constructed metainfo/file tree,
    /// expected-error predicate).
    type Case = (&'static str, Value, fn(&FileTreeError) -> bool);

    fn ok<T, E: std::fmt::Debug>(r: Result<T, E>, what: &str) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("{what}: {e:?}"),
        }
    }

    #[test]
    fn single_small_file_no_layer_needed() {
        let meta = metainfo(
            d(vec![(
                b"a.bin".to_vec(),
                file_leaf(90, Some(marker().as_slice()), None),
            )]),
            None,
            None,
            16384,
        );
        let files = ok(parse(&meta), "small file parses");
        assert_eq!(files.piece_length, 16384);
        assert_eq!(files.files.len(), 1);
        let f = &files.files[0];
        assert_eq!(f.path, Path::new("a.bin"));
        assert_eq!(f.length, 90);
        assert_eq!(f.pieces_root, Some(marker()));
        // files of <= 1 piece have no layer entry (BEP-52 piece layers section).
        assert!(f.piece_layer.is_none());
        // v1_offset is filled by the layout mapping; always None at parse
        // time (SPEC §4.2).
        assert!(f.v1_offset.is_none());
        assert_eq!(f.attr, FileAttr::default());
    }

    #[test]
    fn dfs_order_matches_bencode_key_order() {
        let leaf = |len| file_leaf(len, Some(marker().as_slice()), None);
        let tree = d(vec![
            (
                b"a_dir".to_vec(),
                d(vec![(b"inner.txt".to_vec(), leaf(10))]),
            ),
            (b"z.txt".to_vec(), leaf(20)),
        ]);
        let files = ok(parse(&metainfo(tree, None, None, 16384)), "tree parses");
        let paths: Vec<String> = files
            .files
            .iter()
            .map(|f| f.path.display().to_string())
            .collect();
        assert_eq!(paths, ["a_dir/inner.txt", "z.txt"]);
    }

    /// v2 allows the same basename in different directories: the file tree
    /// is addressed by key (path element), so duplicate basenames across
    /// directories are legal — v1-side dedup must not affect the v2 view
    /// (v2 uniqueness is guaranteed by dict keys: strict decode rejects
    /// duplicate keys).
    #[test]
    fn v2_same_name_different_dirs_accepted() {
        let leaf = |len| file_leaf(len, Some(marker().as_slice()), None);
        let tree = d(vec![
            (b"dir1".to_vec(), d(vec![(b"a.bin".to_vec(), leaf(90))])),
            (b"dir2".to_vec(), d(vec![(b"a.bin".to_vec(), leaf(90))])),
        ]);
        let files = ok(
            parse(&metainfo(tree, None, None, 16384)),
            "same basename in different dirs",
        );
        let paths: Vec<String> = files
            .files
            .iter()
            .map(|f| f.path.display().to_string())
            .collect();
        assert_eq!(paths, ["dir1/a.bin", "dir2/a.bin"]);
    }

    #[test]
    fn empty_dir_produces_no_entry() {
        let tree = d(vec![(b"dir".to_vec(), Value::Dict(Vec::new()))]);
        let files = ok(
            parse(&metainfo(tree, None, None, 16384)),
            "empty dir parses",
        );
        assert!(files.files.is_empty());
    }

    #[test]
    fn empty_file_without_root_is_valid() {
        let tree = d(vec![(b"empty".to_vec(), file_leaf(0, None, None))]);
        let files = ok(
            parse(&metainfo(tree, None, None, 16384)),
            "empty file parses",
        );
        assert_eq!(files.files[0].length, 0);
        assert!(files.files[0].pieces_root.is_none());
    }

    #[test]
    fn attr_flags_parsed() {
        let tree = d(vec![(
            b"f".to_vec(),
            file_leaf(10, Some(marker().as_slice()), Some(b"hx")),
        )]);
        let files = ok(parse(&metainfo(tree, None, None, 16384)), "attr parses");
        let attr = files.files[0].attr;
        assert!(attr.hidden && attr.executable);
        assert!(!attr.padding && !attr.symlink);
    }

    /// `piece layers` join + re-validation for a multi-piece file (layer
    /// built with store::merkle; both crates share the same hash math).
    #[test]
    fn piece_layers_join_and_validate() {
        let content = pattern(40000); // 3 blocks / 3 pieces (16 KiB piece)
        let blocks: Vec<[u8; 32]> = content
            .chunks(merkle::BLOCK_SIZE as usize)
            .map(merkle::block_hash)
            .collect();
        let root = ok(merkle::file_root(&blocks, 16384), "reference root");
        // bpp == 1: piece root == block hash, layer = concatenation in order.
        let layer: Vec<u8> = blocks.iter().flat_map(|h| h.iter()).copied().collect();
        let tree = d(vec![(
            b"f.bin".to_vec(),
            file_leaf(40000, Some(root.as_slice()), None),
        )]);
        let layers = d(vec![(root.to_vec(), Value::Bytes(layer))]);
        let files = ok(
            parse(&metainfo(tree, Some(layers), None, 16384)),
            "join parses",
        );
        assert_eq!(
            files.files[0].piece_layer.as_ref().map(Bytes::len),
            Some(96)
        );
    }

    /// A file <= piece size carrying a (legal) redundant layer: validation
    /// must pass.
    #[test]
    fn redundant_layer_for_small_file_accepted() {
        let content = pattern(90);
        let blocks: Vec<[u8; 32]> = content
            .chunks(merkle::BLOCK_SIZE as usize)
            .map(merkle::block_hash)
            .collect();
        let root = ok(merkle::file_root(&blocks, 16384), "reference root");
        let tree = d(vec![(
            b"tiny".to_vec(),
            file_leaf(90, Some(root.as_slice()), None),
        )]);
        let layers = d(vec![(root.to_vec(), Value::Bytes(root.to_vec()))]);
        let files = ok(
            parse(&metainfo(tree, Some(layers), None, 16384)),
            "redundant layer",
        );
        assert!(files.files[0].piece_layer.is_some());
    }

    #[test]
    fn sanitization_rejections() {
        let leaf = |len| file_leaf(len, Some(marker().as_slice()), None);
        let cases: Vec<Case> = vec![
            (
                "dot",
                d(vec![(b"dir".to_vec(), d(vec![(b".".to_vec(), leaf(1))]))]),
                |e| matches!(e, FileTreeError::PathTraversal { component } if component == "."),
            ),
            (
                "dotdot",
                d(vec![(b"..".to_vec(), leaf(1))]),
                |e| matches!(e, FileTreeError::PathTraversal { component } if component == ".."),
            ),
            (
                "separator",
                d(vec![(b"a/b".to_vec(), leaf(1))]),
                |e| matches!(e, FileTreeError::PathSeparator { component } if component == "a/b"),
            ),
            (
                "nul",
                d(vec![(b"a\0b".to_vec(), leaf(1))]),
                |e| matches!(e, FileTreeError::NulInPath { component } if component == "a\0b"),
            ),
            (
                "reserved_upper",
                d(vec![(b"CON".to_vec(), leaf(1))]),
                |e| matches!(e, FileTreeError::ReservedName { component } if component == "CON"),
            ),
            (
                "reserved_with_ext",
                d(vec![(b"nul.txt".to_vec(), leaf(1))]),
                |e| matches!(e, FileTreeError::ReservedName { component } if component == "nul.txt"),
            ),
            (
                "invalid_utf8",
                d(vec![(b"\xff\xfe".to_vec(), leaf(1))]),
                |e| matches!(e, FileTreeError::InvalidUtf8Path(_)),
            ),
            (
                "root_is_file",
                d(vec![(b"".to_vec(), d(vec![(b"".to_vec(), leaf(1))]))]),
                |e| matches!(e, FileTreeError::RootIsFile),
            ),
            (
                "marker_with_siblings",
                d(vec![(
                    b"f".to_vec(),
                    d(vec![
                        (b"".to_vec(), leaf(1)),
                        (b"sub".to_vec(), Value::Dict(Vec::new())),
                    ]),
                )]),
                |e| matches!(e, FileTreeError::FileMarkerWithSiblings { .. }),
            ),
        ];
        for (name, tree, check) in cases {
            let err = expect_err(parse(&metainfo(tree, None, None, 16384)), name);
            assert!(check(&err), "{name}: unexpected error {err}");
        }
    }

    /// Windows-rule negative table: [`sanitization_rejections`] unchanged;
    /// this table adds `\`/drive-letter/trailing dot-space vectors plus
    /// combined forms. Rules are documented in [`sanitize_component`].
    #[test]
    fn windows_component_rules_rejections() {
        let leaf = |len| file_leaf(len, Some(marker().as_slice()), None);
        let cases: Vec<Case> = vec![
            // Rule 1: embedded '\' (Windows separator; a single key on
            // POSIX too, rejected as well).
            (
                "backslash_embedded",
                d(vec![(b"a\\b".to_vec(), leaf(1))]),
                |e| {
                    matches!(e, FileTreeError::BackslashInPath { component }
                        if component == "a\\b")
                },
            ),
            // Rule 1: UNC prefix form ("\\server\share" is path syntax, not
            // a name).
            (
                "unc_prefix",
                d(vec![(b"\\\\srv\\share".to_vec(), leaf(1))]),
                |e| matches!(e, FileTreeError::BackslashInPath { .. }),
            ),
            // Rule 2: drive designator `X:`.
            ("drive_letter", d(vec![(b"C:".to_vec(), leaf(1))]), |e| {
                matches!(e, FileTreeError::ColonInPath { component }
                        if component == "C:")
            }),
            // Rule 2: drive-relative form (`C:tmp.txt` = current directory
            // on drive C, per MS docs).
            (
                "drive_letter_relative",
                d(vec![(b"C:tmp.txt".to_vec(), leaf(1))]),
                |e| matches!(e, FileTreeError::ColonInPath { .. }),
            ),
            // Rule 2: ADS stream form (any ':' rejects, not just the `X:`
            // prefix).
            (
                "ads_stream",
                d(vec![(b"file:ads".to_vec(), leaf(1))]),
                |e| matches!(e, FileTreeError::ColonInPath { .. }),
            ),
            // Combined: drive designator + '\' — the backslash check fires
            // first (matching the implementation's check order).
            (
                "combo_drive_backslash",
                d(vec![(b"C:\\path".to_vec(), leaf(1))]),
                |e| {
                    matches!(e, FileTreeError::BackslashInPath { component }
                        if component == "C:\\path")
                },
            ),
            // Rule 3: trailing dot (Win32 normalization strips it -> silent
            // drift).
            ("trailing_dot", d(vec![(b"a.".to_vec(), leaf(1))]), |e| {
                matches!(e, FileTreeError::TrailingDotOrSpace { component }
                        if component == "a.")
            }),
            // Rule 3: trailing space.
            ("trailing_space", d(vec![(b"a ".to_vec(), leaf(1))]), |e| {
                matches!(e, FileTreeError::TrailingDotOrSpace { component }
                        if component == "a ")
            }),
            // Rule 3: trailing dot + trailing space combined.
            (
                "trailing_dot_space",
                d(vec![(b"a. ".to_vec(), leaf(1))]),
                |e| matches!(e, FileTreeError::TrailingDotOrSpace { .. }),
            ),
            // Rule 3: all dots — after Win32 strips trailing dots this
            // becomes ".." (parent reference), must reject.
            ("all_dots", d(vec![(b"...".to_vec(), leaf(1))]), |e| {
                matches!(e, FileTreeError::TrailingDotOrSpace { .. })
            }),
            // Rule 3: space-only name — empty after stripping, also
            // rejected.
            ("space_only", d(vec![(b" ".to_vec(), leaf(1))]), |e| {
                matches!(e, FileTreeError::TrailingDotOrSpace { .. })
            }),
            // Combined: directory components are covered too (walk
            // sanitizes every level's key).
            (
                "dir_component_trailing_dot",
                d(vec![(b"dir.".to_vec(), d(vec![(b"f".to_vec(), leaf(1))]))]),
                |e| {
                    matches!(e, FileTreeError::TrailingDotOrSpace { component }
                        if component == "dir.")
                },
            ),
            // Reserved-name check is not regressed: stem-before-extension
            // rule holds.
            (
                "reserved_with_ext_not_regressed",
                d(vec![(b"aux.txt".to_vec(), leaf(1))]),
                |e| {
                    matches!(e, FileTreeError::ReservedName { component }
                        if component == "aux.txt")
                },
            ),
        ];
        for (name, tree, check) in cases {
            let err = expect_err(parse(&metainfo(tree, None, None, 16384)), name);
            assert!(check(&err), "{name}: unexpected error {err}");
        }
    }

    /// POSIX-face no-regression lock: the new rules only harden Windows
    /// dangerous forms; legal names (leading dot / multi-dot extensions /
    /// inner spaces / non-ASCII) still pass with path fidelity preserved.
    #[test]
    fn windows_rules_keep_plain_names() {
        for name in [".temp", "a.b.c", "file_v2.tar.gz", "a b", "日本語", ".pad"] {
            let tree = d(vec![(
                name.as_bytes().to_vec(),
                file_leaf(1, Some(marker().as_slice()), None),
            )]);
            let files = ok(parse(&metainfo(tree, None, None, 16384)), name);
            assert_eq!(files.files[0].path, Path::new(name), "vector {name:?}");
        }
    }

    /// Control-char/bidi/length negative table (zero-width/line-separator/C1
    /// extensions in [`component_zero_width_separator_c1_rejections`]): the
    /// previous face only rejected NUL — other C0 (`\n`/`\r`/ESC/Tab: fake
    /// log/alert lines; Windows 0x01-0x1F illegal names = a remote peer can
    /// kill the whole task), DEL, the 12 bidi overrides (display spoofing
    /// `a\u{202E}b.exe`) and >255-byte components (ENAMETOOLONG on strict
    /// filesystems / Windows without long paths) were all previously
    /// accepted.
    #[test]
    fn component_control_bidi_length_rejections() {
        let leaf = |len| file_leaf(len, Some(marker().as_slice()), None);
        let key = |s: &str| (s.as_bytes().to_vec(), leaf(1));
        let cases: Vec<Case> = vec![
            // C0: newline (fake log/alert lines).
            ("newline", d(vec![key("a\nb.txt")]), |e| {
                matches!(e, FileTreeError::ControlCharInPath { component }
                        if component == "a\nb.txt")
            }),
            // C0: carriage return (same surface).
            ("carriage_return", d(vec![key("a\rb")]), |e| {
                matches!(e, FileTreeError::ControlCharInPath { .. })
            }),
            // C0: ESC (terminal control sequence injection).
            ("escape", d(vec![key("a\u{1b}b")]), |e| {
                matches!(e, FileTreeError::ControlCharInPath { .. })
            }),
            // C0: Tab (fake alignment / parse ambiguity).
            ("tab", d(vec![key("a\tb")]), |e| {
                matches!(e, FileTreeError::ControlCharInPath { .. })
            }),
            // DEL 0x7F (same surface as C0, missed by the old set).
            ("del", d(vec![key("a\u{7f}b")]), |e| {
                matches!(e, FileTreeError::ControlCharInPath { .. })
            }),
            // Bidi override: RLO (classic photo<RLO>gpj.exe display
            // spoofing).
            ("bidi_rlo", d(vec![key("a\u{202E}b.exe")]), |e| {
                matches!(e, FileTreeError::SpoofingCharInPath { component }
                        if component == "a\u{202E}b.exe")
            }),
            // Bidi override: ALM (U+061C).
            ("bidi_alm", d(vec![key("a\u{061C}b")]), |e| {
                matches!(e, FileTreeError::SpoofingCharInPath { .. })
            }),
            // Bidi override: LRM/RLM (U+200E/U+200F).
            ("bidi_lrm_rlm", d(vec![key("a\u{200E}\u{200F}b")]), |e| {
                matches!(e, FileTreeError::SpoofingCharInPath { .. })
            }),
            // Bidi override: LRE..PDF (full U+202A-202E range).
            (
                "bidi_202a_range",
                d(vec![key("a\u{202A}\u{202B}\u{202C}\u{202D}b")]),
                |e| matches!(e, FileTreeError::SpoofingCharInPath { .. }),
            ),
            // Bidi override: isolates (full U+2066-2069 range).
            (
                "bidi_isolates",
                d(vec![key("a\u{2066}\u{2067}\u{2068}\u{2069}b")]),
                |e| matches!(e, FileTreeError::SpoofingCharInPath { .. }),
            ),
            // Length cap: 300-byte component (ENAMETOOLONG on strict
            // filesystems).
            (
                "too_long_300b",
                d(vec![("x".repeat(300).into_bytes(), leaf(1))]),
                |e| matches!(e, FileTreeError::ComponentTooLong { len: 300, .. }),
            ),
            // Length cap boundary: 256 bytes (over 255 rejects).
            (
                "too_long_256b",
                d(vec![("x".repeat(256).into_bytes(), leaf(1))]),
                |e| matches!(e, FileTreeError::ComponentTooLong { len: 256, .. }),
            ),
        ];
        for (name, tree, check) in cases {
            let err = expect_err(parse(&metainfo(tree, None, None, 16384)), name);
            assert!(check(&err), "{name}: unexpected error {err}");
        }
    }

    /// Zero-width/line-separator/C1 negative table: U+200B ZWSP, U+200C
    /// ZWNJ, U+FEFF BOM (`evil\u{200B}.exe` looks identical to `evil.exe` —
    /// name borrowing / directory twins), U+2028/U+2029 (Zl/Zp
    /// line/paragraph separators — residual log-line injection, covered by
    /// neither `is_ascii_control` nor `is_control`) were all previously
    /// accepted; C1 (U+0080-009F) joins the control-character rejection
    /// (one rule via `char::is_control`, consistent with the existing
    /// C0/DEL rejection).
    #[test]
    fn component_zero_width_separator_c1_rejections() {
        let leaf = |len| file_leaf(len, Some(marker().as_slice()), None);
        let key = |s: &str| (s.as_bytes().to_vec(), leaf(1));
        let cases: Vec<Case> = vec![
            // Zero-width: ZWSP (classic visually-identical name borrowing).
            ("zwsp", d(vec![key("evil\u{200B}.exe")]), |e| {
                matches!(e, FileTreeError::SpoofingCharInPath { component }
                    if component == "evil\u{200B}.exe")
            }),
            // Zero-width: ZWNJ.
            ("zwnj", d(vec![key("a\u{200C}b")]), |e| {
                matches!(e, FileTreeError::SpoofingCharInPath { .. })
            }),
            // Zero-width: BOM (equally invisible at the start or middle of
            // a name).
            ("bom", d(vec![key("a\u{FEFF}b")]), |e| {
                matches!(e, FileTreeError::SpoofingCharInPath { .. })
            }),
            // Line separator U+2028 (residual log-line injection).
            ("line_separator", d(vec![key("evil\u{2028}.exe")]), |e| {
                matches!(e, FileTreeError::SpoofingCharInPath { .. })
            }),
            // Paragraph separator U+2029.
            ("paragraph_separator", d(vec![key("a\u{2029}b")]), |e| {
                matches!(e, FileTreeError::SpoofingCharInPath { .. })
            }),
            // C1: NEL U+0085 (control char with line-separator semantics).
            ("c1_nel", d(vec![key("a\u{85}b")]), |e| {
                matches!(e, FileTreeError::ControlCharInPath { .. })
            }),
            // C1 range tail U+009F.
            ("c1_tail", d(vec![key("a\u{9F}b")]), |e| {
                matches!(e, FileTreeError::ControlCharInPath { .. })
            }),
        ];
        for (name, tree, check) in cases {
            let err = expect_err(parse(&metainfo(tree, None, None, 16384)), name);
            assert!(check(&err), "{name}: unexpected error {err}");
        }
    }

    /// Control (no over-rejection): an exactly-255-byte component passes; a
    /// ZWJ emoji name (U+200D is a legitimate emoji name component — the
    /// reason the bidi set is not widened to all of Cf) passes through.
    #[test]
    fn cap_boundary_and_zwj_emoji_names_pass() {
        let at_cap = "y".repeat(255);
        let tree = d(vec![(
            at_cap.as_bytes().to_vec(),
            file_leaf(1, Some(marker().as_slice()), None),
        )]);
        let files = ok(
            parse(&metainfo(tree, None, None, 16384)),
            "255-byte component",
        );
        assert_eq!(files.files[0].path, PathBuf::from(&at_cap));

        let zwj = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}.png";
        let tree = d(vec![(
            zwj.as_bytes().to_vec(),
            file_leaf(1, Some(marker().as_slice()), None),
        )]);
        let files = ok(parse(&metainfo(tree, None, None, 16384)), "ZWJ emoji name");
        assert_eq!(files.files[0].path, Path::new(zwj));
    }

    #[test]
    fn file_props_rejections() {
        let cases: Vec<Case> = vec![
            (
                "empty_with_root",
                d(vec![(
                    b"f".to_vec(),
                    file_leaf(0, Some(marker().as_slice()), None),
                )]),
                |e| matches!(e, FileTreeError::EmptyFileWithPiecesRoot { .. }),
            ),
            (
                "nonempty_missing_root",
                d(vec![(b"f".to_vec(), file_leaf(100, None, None))]),
                |e| matches!(e, FileTreeError::MissingPiecesRoot { .. }),
            ),
            (
                "root_wrong_length",
                d(vec![(
                    b"f".to_vec(),
                    file_leaf(100, Some(&[0xaa; 31][..]), None),
                )]),
                |e| matches!(e, FileTreeError::PiecesRootLength { len: 31, .. }),
            ),
            (
                "negative_length",
                d(vec![(b"f".to_vec(), file_leaf(-5, None, None))]),
                |e| matches!(e, FileTreeError::InvalidLength { .. }),
            ),
            (
                "missing_length",
                // {"f": {"": {}}}: file marker present but empty props.
                d(vec![(
                    b"f".to_vec(),
                    Value::Dict(vec![(Vec::new(), Value::Dict(Vec::new()))]),
                )]),
                |e| matches!(e, FileTreeError::MissingLength { .. }),
            ),
        ];
        for (name, tree, check) in cases {
            let err = expect_err(parse(&metainfo(tree, None, None, 16384)), name);
            assert!(check(&err), "{name}: unexpected error {err}");
        }
    }

    #[test]
    fn piece_layers_rejections() {
        let content = pattern(40000);
        let blocks: Vec<[u8; 32]> = content
            .chunks(merkle::BLOCK_SIZE as usize)
            .map(merkle::block_hash)
            .collect();
        let root = ok(merkle::file_root(&blocks, 16384), "reference root");
        let good_layer: Vec<u8> = blocks.iter().flat_map(|h| h.iter()).copied().collect();
        let leaf_root = |r: &[u8]| file_leaf(40000, Some(r), None);

        let tree = d(vec![(b"f.bin".to_vec(), leaf_root(&root))]);

        // Corrupt hash -> RootMismatch (present but invalid = corrupt
        // metadata, hard reject; libtorrent torrent.cpp
        // `torrent_invalid_piece_layer` — strictly separate from the
        // missing-entry degradation).
        let mut corrupt = good_layer.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0xff;
        let layers = d(vec![(root.to_vec(), Value::Bytes(corrupt))]);
        let err = expect_err(
            parse(&metainfo(tree.clone(), Some(layers), None, 16384)),
            "corrupt",
        );
        assert!(
            matches!(err, FileTreeError::PieceLayerMismatch { ref source, .. }
                if matches!(source, merkle::MerkleError::RootMismatch { .. })),
            "got {err}"
        );

        // Wrong layer count (one extra) -> LayerCountMismatch (as above,
        // hard reject).
        let mut extra = good_layer;
        extra.extend_from_slice(&[0u8; 32]);
        let layers = d(vec![(root.to_vec(), Value::Bytes(extra))]);
        let err = expect_err(
            parse(&metainfo(tree, Some(layers), None, 16384)),
            "extra hash",
        );
        assert!(
            matches!(err, FileTreeError::PieceLayerMismatch { ref source, .. }
                if matches!(source, merkle::MerkleError::LayerCountMismatch { expected: 3, got: 4 })),
            "got {err}"
        );
    }

    /// Missing/corrupt boundary, table-driven (SPEC §4.2 missing-layer
    /// degradation; the two libtorrent torrent.cpp
    /// `initialize_merkle_trees` boundaries):
    /// - multi-piece file with the whole entry missing -> load proceeds
    /// with the `layer_missing` flag (libtorrent `valid = false; continue`);
    /// - some files missing their layer -> only those are flagged, fully
    /// equipped files keep their layers;
    /// - file <= piece size with no entry -> spec behavior, no flag;
    /// - entry present but corrupt -> hard reject (see
    /// [`piece_layers_rejections`]);
    /// - root missing -> hard reject (`MissingPiecesRoot` — no trust
    /// anchor, never enters recovery).
    #[test]
    fn missing_layer_degrades_to_marker() {
        let content = pattern(40000); // 3 pieces (16 KiB piece)
        let blocks: Vec<[u8; 32]> = content
            .chunks(merkle::BLOCK_SIZE as usize)
            .map(merkle::block_hash)
            .collect();
        let root_a = ok(merkle::file_root(&blocks, 16384), "reference root a");
        let leaf_root = |r: &[u8]| file_leaf(40000, Some(r), None);
        let marker_root = marker();

        // Row 1: whole layer missing (no `piece layers` key) -> keep
        // loading + flag.
        let tree = d(vec![(b"a.bin".to_vec(), leaf_root(&root_a))]);
        let files = ok(
            parse(&metainfo(tree, None, None, 16384)),
            "absent entry degrades",
        );
        assert!(
            files.files[0].layer_missing,
            "a multi-piece file missing its layer must be flagged"
        );
        assert!(files.files[0].piece_layer.is_none());
        assert_eq!(
            files.files[0].pieces_root,
            Some(root_a),
            "the root is the trust anchor"
        );

        // Row 2: some files missing layers -> flagged; equipped files
        // unchanged.
        let content_b = pattern(20000); // 2 pieces
        let blocks_b: Vec<[u8; 32]> = content_b
            .chunks(merkle::BLOCK_SIZE as usize)
            .map(merkle::block_hash)
            .collect();
        let root_b = ok(merkle::file_root(&blocks_b, 16384), "reference root b");
        let layer_a: Vec<u8> = blocks.iter().flat_map(|h| h.iter()).copied().collect();
        let tree = d(vec![
            (b"a.bin".to_vec(), leaf_root(&root_a)),
            (b"b.bin".to_vec(), file_leaf(20000, Some(&root_b), None)),
        ]);
        let layers = d(vec![(root_a.to_vec(), Value::Bytes(layer_a))]);
        let files = ok(parse(&metainfo(tree, Some(layers), None, 16384)), "partial");
        assert!(
            !files.files[0].layer_missing,
            "equipped files are not flagged"
        );
        assert!(files.files[0].piece_layer.is_some());
        assert!(
            files.files[1].layer_missing,
            "files missing a layer are flagged"
        );

        // Row 3: file <= piece size with no entry -> spec behavior, never
        // flagged (recovery is never triggered).
        let tree = d(vec![(
            b"tiny".to_vec(),
            file_leaf(90, Some(marker_root.as_slice()), None),
        )]);
        let files = ok(
            parse(&metainfo(tree, None, None, 16384)),
            "single piece file",
        );
        assert!(
            !files.files[0].layer_missing,
            "a single-piece file with no entry is spec behavior"
        );

        // Row 4: root missing (corrupt file tree shape) -> still a hard
        // reject — no trust anchor, mathematically unrecoverable, never
        // enters recovery.
        let tree = d(vec![(b"a.bin".to_vec(), file_leaf(40000, None, None))]);
        let err = expect_err(parse(&metainfo(tree, None, None, 16384)), "no root");
        assert!(
            matches!(err, FileTreeError::MissingPiecesRoot { .. }),
            "got {err}"
        );
    }

    #[test]
    fn metainfo_level_rejections() {
        let tree = d(vec![(
            b"f".to_vec(),
            file_leaf(10, Some(marker().as_slice()), None),
        )]);
        assert!(matches!(
            parse(&Value::Int(1)),
            Err(FileTreeError::NotADict)
        ));
        assert!(matches!(
            parse(&d(vec![(
                b"announce".to_vec(),
                Value::Bytes(b"x".to_vec())
            )])),
            Err(FileTreeError::NoFileTree)
        ));
        assert!(matches!(
            parse(&metainfo(tree.clone(), None, Some(3), 16384)),
            Err(FileTreeError::UnsupportedMetaVersion(3))
        ));
        // `file tree` present without `meta version` -> MissingMetaVersion.
        let info_no_version = d(vec![
            (FILE_TREE_KEY.to_vec(), tree.clone()),
            (PIECE_LENGTH_KEY.to_vec(), Value::Int(16384)),
        ]);
        assert!(matches!(
            parse(&d(vec![(INFO_KEY.to_vec(), info_no_version)])),
            Err(FileTreeError::MissingMetaVersion)
        ));
        // `info` not a dict -> InfoNotADict.
        assert!(matches!(
            parse(&d(vec![(INFO_KEY.to_vec(), Value::Int(0))])),
            Err(FileTreeError::InfoNotADict)
        ));
        assert!(matches!(
            parse(&metainfo(tree.clone(), None, None, 8192)),
            Err(FileTreeError::InvalidPieceLength(
                merkle::MerkleError::InvalidPieceLength { piece_len: 8192 }
            ))
        ));
        assert!(matches!(
            parse(&metainfo(tree.clone(), None, None, 24576)),
            Err(FileTreeError::InvalidPieceLength(_))
        ));
        // Regression anchor: the v2-face constraint is unchanged — 20000
        // (not a power of two; accepted on the relaxed v1-only face) is
        // still rejected by v2 parsing (BEP-52 "power of two and at least
        // 16KiB" relaxes only the v1-only face, never v2).
        assert!(matches!(
            parse(&metainfo(tree.clone(), None, None, 20000)),
            Err(FileTreeError::InvalidPieceLength(_))
        ));
        // `piece layers` not a dict.
        assert!(matches!(
            parse(&metainfo(tree.clone(), Some(Value::Int(0)), None, 16384)),
            Err(FileTreeError::PieceLayersNotADict)
        ));
        // layer key not 32 bytes.
        let layers = d(vec![(b"short".to_vec(), Value::Bytes(vec![0; 32]))]);
        assert!(matches!(
            parse(&metainfo(tree, Some(layers), None, 16384)),
            Err(FileTreeError::InvalidPieceLayerKey)
        ));
    }
}

/// Swarm kind (SPEC §4.2 `TorrentMeta.kind`; detected on the bt side,
/// reused by core).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwarmKind {
    /// v1 only (`pieces`/`files`, no `file tree`).
    V1Only,
    /// v2 only (`file tree` + `piece layers`, no v1 keys).
    V2Only,
    /// Hybrid (both present; one set of bytes, two swarms, SPEC §4.2/§6.2).
    Hybrid,
}

/// Detect the swarm kind by structural keys; `meta version` validation
/// happens inside [`parse`]/[`parse_v1_files`] (BEP-52 "check this field
/// first").
pub fn detect_swarm_kind(meta: &Value) -> Result<SwarmKind, FileTreeError> {
    if !matches!(meta, Value::Dict(_)) {
        return Err(FileTreeError::NotADict);
    }
    let info = match meta.get(INFO_KEY) {
        Some(v @ Value::Dict(_)) => v,
        Some(_) => return Err(FileTreeError::InfoNotADict),
        None => return Err(FileTreeError::NoFileTree),
    };
    let v2_side = info.get(FILE_TREE_KEY).is_some();
    // v1 keys: multi-file `files` or single-file `length` (BEP-3).
    let v1_side = info.get(b"files").is_some() || info.get(b"length").is_some();
    match (v2_side, v1_side) {
        (true, true) => Ok(SwarmKind::Hybrid),
        (true, false) => Ok(SwarmKind::V2Only),
        (false, true) => Ok(SwarmKind::V1Only),
        (false, false) => Err(FileTreeError::NoFileTree),
    }
}

/// Parse the v1 `files` list (or single-file `length`) into a file view
/// with padding flags and v1 offsets (SPEC §4.2 v1 layout; BEP-47).
///
/// - `.pad` entries (attr 'p') are never written to disk or requested per
/// BEP-47, but they still advance the offset accumulation;
/// - `v1_offset` = accumulated byte offset in list order (pads included;
/// BEP-47: pads align the following file to a piece boundary);
/// - non-pad entries must have unique sanitized full paths: a duplicate
/// means two layout ranges point at the same physical file and the later
/// entry would rewrite the earlier one's verified bytes (data corruption +
/// spreading bad blocks to the swarm) -> `DuplicateFilePath` reject. Pad
/// entries are exempt: BEP-47 recommends `[".pad", "<length>"]` paths, so
/// equal-length pads legally share a path, and pads are never written to
/// disk (TorrentWriter/Layout::find skips them), so there is no overwrite
/// surface. The v2 file tree is unique by key (strict decode rejects
/// duplicate dict keys) and needs no such check;
/// - v2 roots/layers are not part of this view (hybrid v2 validation
/// combines the file tree view with this view's offsets);
/// - piece length constraints are per face (BEP-3 vs BEP-52): v1-only
/// takes any positive integer; a hybrid (`file tree` present) still
/// follows the BEP-52 power-of-two >= 16 KiB rule — rationale and decision
/// point in the function body comments.
pub fn parse_v1_files(meta: &Value) -> Result<TorrentFiles, FileTreeError> {
    if !matches!(meta, Value::Dict(_)) {
        return Err(FileTreeError::NotADict);
    }
    let info = match meta.get(INFO_KEY) {
        Some(v @ Value::Dict(_)) => v,
        Some(_) => return Err(FileTreeError::InfoNotADict),
        None => return Err(FileTreeError::NoFileTree),
    };
    // v1-face check: at least one of `files`/`length` (BEP-3). A hybrid
    // has both file tree and v1 keys — this view is the hybrid's v1 face;
    // calling here on a pure v2 (file tree only) is a programming error,
    // rejected explicitly.
    if info.get(b"files").is_none() && info.get(b"length").is_none() {
        return Err(FileTreeError::V1FileMissingPath);
    }
    let piece_length = match info.get(PIECE_LENGTH_KEY) {
        // Engineering cap (v1-only arm; the v2/hybrid arm has the same
        // gate in `parse`): MAX_PIECE_LENGTH = 16 MiB — piece length is
        // the common multiplier of webseed whole-piece fetches, in-flight
        // verify and the fixed-size write cache; a legal-in-u32 4 GiB
        // piece would mean GiB-scale RSS per task (qBittorrent's creator
        // caps at the same 16 MiB; existing torrents above 16 MiB are
        // practically nonexistent).
        Some(Value::Int(n)) if *n > 0 && *n <= MAX_PIECE_LENGTH as i64 => *n as u32,
        Some(Value::Int(n)) => return Err(FileTreeError::PieceLengthOutOfRange(*n)),
        Some(_) => return Err(FileTreeError::PieceLengthOutOfRange(0)),
        None => return Err(FileTreeError::MissingPieceLength),
    };
    // Piece length constraints per face (BEP-3 vs BEP-52 wording): BEP-3
    // only asks "number of bytes in each piece" for the v1 face (a
    // positive integer; the range check above is the whole constraint).
    // "It must be a power of two and at least 16KiB" (BEP-52 `piece
    // length` section) constrains the v2 file tree merkle block-leaf math.
    // v1-only (no `file tree`) must not inherit BEP-52 — legacy torrents
    // with 20000, 8192 etc. are legal. A hybrid (`file tree` present)
    // shares the same `piece length` key and that key feeds the v2 face,
    // so the BEP-52 constraint applies; the decision lives in this
    // function (by key presence), with no ordering assumption about the
    // caller running v2 parsing first.
    if info.get(FILE_TREE_KEY).is_some() {
        merkle::validate_piece_len(piece_length).map_err(FileTreeError::InvalidPieceLength)?;
    }

    let mut files = Vec::new();
    match info.get(b"files") {
        Some(Value::List(list)) => {
            let mut offset = 0u64;
            // Uniqueness ledger for non-pad sanitized full paths (pad
            // exemption rationale in the function docs).
            let mut seen_paths: HashSet<PathBuf> = HashSet::new();
            for entry in list {
                let path = match entry.get(b"path") {
                    Some(Value::List(components)) => components,
                    _ => return Err(FileTreeError::V1FileMissingPath),
                };
                // v1 `path: []`: an empty list would produce a `FileEntry`
                // with an empty `PathBuf` and fail at the allocate stage
                // when opening the directory — rejected here under the
                // existing "no valid `path`" semantics (BEP-3: a legal
                // file entry has at least one path component).
                if path.is_empty() {
                    return Err(FileTreeError::V1FileMissingPath);
                }
                let length = match entry.get(b"length") {
                    Some(Value::Int(n)) if *n >= 0 => *n as u64,
                    _ => {
                        return Err(FileTreeError::InvalidLength {
                            path: PathBuf::new(),
                        });
                    }
                };
                // Sanitize each path component with the same rules as the
                // file tree (BEP-47: pads have a path too, recommended
                // [".pad", "N"]).
                let mut built = PathBuf::new();
                for comp in path {
                    let bytes = match comp {
                        Value::Bytes(b) => b,
                        _ => return Err(FileTreeError::V1FileMissingPath),
                    };
                    let s = sanitize_component(bytes)?;
                    built.push(&s);
                }
                let attr = entry
                    .get(ATTR_KEY)
                    .and_then(Value::as_bytes)
                    .map(parse_attr)
                    .unwrap_or_default();
                if !attr.padding && !seen_paths.insert(built.clone()) {
                    return Err(FileTreeError::DuplicateFilePath { path: built });
                }
                files.push(FileEntry {
                    v1_offset: Some(offset),
                    path: built,
                    length,
                    attr,
                    pieces_root: None,
                    piece_layer: None,
                    layer_missing: false,
                });
                offset += length;
            }
        }
        Some(_) => return Err(FileTreeError::V1FileMissingPath),
        None => {
            // Single file: info.length + info.name (BEP-3).
            let length = match info.get(b"length") {
                Some(Value::Int(n)) if *n >= 0 => *n as u64,
                _ => {
                    return Err(FileTreeError::InvalidLength {
                        path: PathBuf::new(),
                    });
                }
            };
            let name = match info.get(b"name") {
                Some(Value::Bytes(b)) => sanitize_component(b)?,
                _ => return Err(FileTreeError::V1FileMissingPath),
            };
            files.push(FileEntry {
                v1_offset: Some(0),
                path: PathBuf::from(name),
                length,
                attr: FileAttr::default(),
                pieces_root: None,
                piece_layer: None,
                layer_missing: false,
            });
        }
    }
    Ok(TorrentFiles {
        piece_length,
        files,
    })
}

#[cfg(test)]
mod v1_tests {
    use super::*;
    use crate::bencode;

    /// Hybrid fixture: v1 files view (a.bin + .pad/11920 + b.bin); offset
    /// accumulation and the pad flag follow BEP-47 (official creator
    /// output).
    #[test]
    fn parse_v1_files_hybrid_fixture() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/hybrid_16k.torrent");
        let torrent = std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture: {e}"));
        let top = bencode::decode(&torrent).unwrap_or_else(|e| panic!("decode: {e:?}"));

        assert_eq!(
            detect_swarm_kind(&top).unwrap_or_else(|e| panic!("{e}")),
            SwarmKind::Hybrid
        );
        let files = parse_v1_files(&top).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(files.piece_length, 16384);
        assert_eq!(files.files.len(), 3);
        let (a, pad, b) = (&files.files[0], &files.files[1], &files.files[2]);
        assert_eq!(a.path, std::path::Path::new("a.bin"));
        assert_eq!(a.length, 70000);
        assert_eq!(a.v1_offset, Some(0));
        assert!(!a.attr.padding);
        assert_eq!(pad.path, std::path::Path::new(".pad/11920"));
        assert_eq!(
            pad.length, 11920,
            "BEP47: pad length = the slack up to the next piece boundary"
        );
        assert_eq!(pad.v1_offset, Some(70000));
        assert!(pad.attr.padding, "attr 'p' → padding");
        assert!(pad.pieces_root.is_none());
        assert_eq!(b.path, std::path::Path::new("b.bin"));
        assert_eq!(b.length, 30000);
        assert_eq!(
            b.v1_offset,
            Some(81920),
            "the file after a pad starts at a piece boundary"
        );
    }

    /// v1 `path: []` empty list -> reject: it would produce a `FileEntry`
    /// with an empty `PathBuf` and crash the task's on-disk face at the
    /// allocate stage; the parser rejects explicitly (`V1FileMissingPath`,
    /// the existing "no valid `path`" semantics).
    #[test]
    fn v1_empty_path_list_rejected() {
        let d = |pairs: Vec<(&str, bencode::Value)>| {
            let mut v: Vec<(Vec<u8>, bencode::Value)> = pairs
                .into_iter()
                .map(|(k, x)| (k.as_bytes().to_vec(), x))
                .collect();
            v.sort_by(|a, b| a.0.cmp(&b.0));
            bencode::Value::Dict(v)
        };
        let files = bencode::Value::List(vec![d(vec![
            ("length", bencode::Value::Int(1)),
            ("path", bencode::Value::List(Vec::new())),
        ])]);
        let info = d(vec![
            ("files", files),
            ("piece length", bencode::Value::Int(16384)),
        ]);
        let top = d(vec![("info", info)]);
        let err = match parse_v1_files(&top) {
            Err(e) => e,
            Ok(v) => panic!("path:[] must be rejected, produced {:?}", v.files),
        };
        assert!(matches!(err, FileTreeError::V1FileMissingPath), "got {err}");
    }

    /// Swarm kind: the three states.
    #[test]
    fn detect_swarm_kind_three_states() {
        let d = |pairs: Vec<(&str, bencode::Value)>| {
            let mut v: Vec<(Vec<u8>, bencode::Value)> = pairs
                .into_iter()
                .map(|(k, x)| (k.as_bytes().to_vec(), x))
                .collect();
            v.sort_by(|a, b| a.0.cmp(&b.0));
            bencode::Value::Dict(v)
        };
        let v1 = d(vec![(
            "info",
            d(vec![
                ("length", bencode::Value::Int(5)),
                ("name", bencode::Value::Bytes(b"x".to_vec())),
            ]),
        )]);
        assert_eq!(
            detect_swarm_kind(&v1).unwrap_or_else(|e| panic!("{e}")),
            SwarmKind::V1Only
        );
        let v2 = d(vec![("info", d(vec![("file tree", d(vec![]))]))]);
        assert_eq!(
            detect_swarm_kind(&v2).unwrap_or_else(|e| panic!("{e}")),
            SwarmKind::V2Only
        );
        let hybrid = d(vec![(
            "info",
            d(vec![
                ("file tree", d(vec![])),
                ("length", bencode::Value::Int(5)),
            ]),
        )]);
        assert_eq!(
            detect_swarm_kind(&hybrid).unwrap_or_else(|e| panic!("{e}")),
            SwarmKind::Hybrid
        );
    }

    /// v1 files list helper (keys byte-sorted; piece length parameterizable).
    fn v1_files_top_with_len(entries: Vec<bencode::Value>, piece_len: i64) -> bencode::Value {
        let d = |pairs: Vec<(&str, bencode::Value)>| {
            let mut v: Vec<(Vec<u8>, bencode::Value)> = pairs
                .into_iter()
                .map(|(k, x)| (k.as_bytes().to_vec(), x))
                .collect();
            v.sort_by(|a, b| a.0.cmp(&b.0));
            bencode::Value::Dict(v)
        };
        d(vec![(
            "info",
            d(vec![
                ("files", bencode::Value::List(entries)),
                ("piece length", bencode::Value::Int(piece_len)),
            ]),
        )])
    }

    /// v1 files list helper (keys byte-sorted).
    fn v1_files_top(entries: Vec<bencode::Value>) -> bencode::Value {
        v1_files_top_with_len(entries, 16384)
    }

    fn v1_entry(path: &[&str], len: i64, attr: Option<&[u8]>) -> bencode::Value {
        let d = |pairs: Vec<(&str, bencode::Value)>| {
            let mut v: Vec<(Vec<u8>, bencode::Value)> = pairs
                .into_iter()
                .map(|(k, x)| (k.as_bytes().to_vec(), x))
                .collect();
            v.sort_by(|a, b| a.0.cmp(&b.0));
            bencode::Value::Dict(v)
        };
        let mut pairs: Vec<(&str, bencode::Value)> = Vec::new();
        if let Some(a) = attr {
            pairs.push(("attr", bencode::Value::Bytes(a.to_vec())));
        }
        pairs.push(("length", bencode::Value::Int(len)));
        pairs.push((
            "path",
            bencode::Value::List(
                path.iter()
                    .map(|c| bencode::Value::Bytes(c.as_bytes().to_vec()))
                    .collect(),
            ),
        ));
        d(pairs)
    }

    /// Duplicate paths are rejected: two same-named entries -> two layout
    /// ranges -> TorrentWriter opens the same physical file via the
    /// relative path and entry 2 rewrites from offset 0, overwriting entry
    /// 1's verified bytes (data corruption + spreading bad blocks to the
    /// swarm). The parser dedups sanitized full paths; a duplicate ->
    /// `DuplicateFilePath` reject.
    #[test]
    fn v1_duplicate_file_path_rejected() {
        let top = v1_files_top(vec![
            v1_entry(&["a.bin"], 100, None),
            v1_entry(&["b.bin"], 100, None),
            v1_entry(&["a.bin"], 100, None),
        ]);
        let err = match parse_v1_files(&top) {
            Err(e) => e,
            Ok(v) => panic!("duplicate paths must be rejected, produced {:?}", v.files),
        };
        assert!(
            matches!(err, FileTreeError::DuplicateFilePath { ref path }
                if path == std::path::Path::new("a.bin")),
            "got {err}"
        );

        // Nested paths are deduped too (the sanitized full PathBuf is the
        // key).
        let top = v1_files_top(vec![
            v1_entry(&["dir", "f.bin"], 1, None),
            v1_entry(&["dir", "f.bin"], 1, None),
        ]);
        assert!(
            matches!(
                parse_v1_files(&top),
                Err(FileTreeError::DuplicateFilePath { .. })
            ),
            "nested duplicate paths must be rejected"
        );

        // Control: a multi-file list with distinct paths is not regressed.
        let top = v1_files_top(vec![
            v1_entry(&["a.bin"], 100, None),
            v1_entry(&["b.bin"], 100, None),
            v1_entry(&["dir", "a.bin"], 100, None),
        ]);
        let files = parse_v1_files(&top).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            files.files.len(),
            3,
            "distinct paths (including same name in different dirs) not wrongly rejected"
        );
    }

    /// Pad entries are exempt from dedup: BEP-47 recommends pad paths
    /// `[".pad", "<length>"]` — length naming makes two equal-length pads
    /// legally share a path; pads are never written to disk
    /// (TorrentWriter/Layout::find skips them), so a shared path cannot
    /// overwrite anything.
    #[test]
    fn v1_duplicate_pad_path_accepted() {
        let top = v1_files_top(vec![
            v1_entry(&["a.bin"], 100, None),
            v1_entry(&[".pad", "100"], 100, Some(b"p")),
            v1_entry(&["b.bin"], 100, None),
            v1_entry(&[".pad", "100"], 100, Some(b"p")),
            v1_entry(&["c.bin"], 100, None),
        ]);
        let files = parse_v1_files(&top).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            files.files.len(),
            5,
            "equal-length pads sharing a path (BEP47 recommended naming) are accepted"
        );
        assert!(files.files[1].attr.padding && files.files[3].attr.padding);
    }

    /// v1-only face piece length relaxation (BEP-3 vs BEP-52 wording).
    ///
    /// BEP-3 only describes `piece length` as "number of bytes in each
    /// piece", with no power-of-two/minimum rule; "It must be a power of
    /// two and at least 16KiB" is the BEP-52 `piece length` section
    /// constraining the v2 file tree (merkle block-leaf math: 16 KiB
    /// blocks x power-of-two pieces). Legacy v1 torrents (early
    /// clients/small tools, 20000/8192 forms) fall outside the BEP-52
    /// domain — the v1-only face only requires a positive integer (the
    /// existing `PieceLengthOutOfRange` face).
    #[test]
    fn v1_only_piece_length_relaxed_to_positive() {
        // Non-power-of-two (20000) multi-piece v1-only torrent: loads.
        let top = v1_files_top_with_len(
            vec![
                v1_entry(&["a.bin"], 30000, None),
                v1_entry(&["b.bin"], 30000, None),
            ],
            20000,
        );
        let files =
            parse_v1_files(&top).unwrap_or_else(|e| panic!("v1-only 20000 must be accepted: {e}"));
        assert_eq!(files.piece_length, 20000);
        assert_eq!(files.files.len(), 2);

        // Below 16 KiB (8192): also accepted.
        let top = v1_files_top_with_len(vec![v1_entry(&["a.bin"], 20000, None)], 8192);
        let files =
            parse_v1_files(&top).unwrap_or_else(|e| panic!("v1-only 8192 must be accepted: {e}"));
        assert_eq!(files.piece_length, 8192);

        // The relaxed lower bound is "positive integer": 0/negative still
        // rejected (existing face unchanged).
        for bad in [0, -1] {
            let top = v1_files_top_with_len(vec![v1_entry(&["a.bin"], 1, None)], bad);
            assert!(
                matches!(
                    parse_v1_files(&top),
                    Err(FileTreeError::PieceLengthOutOfRange(_))
                ),
                "piece length {bad} still rejected"
            );
        }
    }

    /// Anchor: the hybrid face (`file tree` present) does not slip through
    /// the v1-face relaxation. A hybrid's v1 tree and v2 tree share the
    /// same `piece length` key, which feeds the v2 merkle math (16 KiB
    /// block leaves, the BEP-52 domain) — non-power-of-two/<16KiB is
    /// rejected within this view, with no ordering assumption about the
    /// caller running v2 parsing (`parse`) first.
    #[test]
    fn hybrid_v1_face_piece_length_still_bep52() {
        let d = |pairs: Vec<(&str, bencode::Value)>| {
            let mut v: Vec<(Vec<u8>, bencode::Value)> = pairs
                .into_iter()
                .map(|(k, x)| (k.as_bytes().to_vec(), x))
                .collect();
            v.sort_by(|a, b| a.0.cmp(&b.0));
            bencode::Value::Dict(v)
        };
        for bad_len in [20000, 8192] {
            let info = d(vec![
                (
                    "files",
                    bencode::Value::List(vec![v1_entry(&["a.bin"], 30000, None)]),
                ),
                ("file tree", d(vec![])),
                ("piece length", bencode::Value::Int(bad_len)),
            ]);
            let top = d(vec![("info", info)]);
            assert!(
                matches!(
                    parse_v1_files(&top),
                    Err(FileTreeError::InvalidPieceLength(_))
                ),
                "hybrid piece length {bad_len} must still be rejected (BEP52 face constraint unchanged)"
            );
        }
    }
}

#[cfg(test)]
mod bt_piece_len_cap {
    use super::*;
    use crate::bencode;

    /// The 16 MiB engineering cap on piece length is one source across
    /// faces: the v1-only arm (`parse_v1_files`, the most common/easiest to
    /// construct form) is fed 16 MiB+1 (reject) and exactly 16 MiB (pass);
    /// the v2/hybrid arm has the same gate in `parse`. Guards against a
    /// legal-in-u32 4 GiB piece becoming a GiB-scale common multiplier of
    /// webseed whole-piece fetches and in-flight verify.
    #[test]
    fn max_piece_length_gates_v1_face() {
        assert_eq!(
            MAX_PIECE_LENGTH,
            16 * 1024 * 1024,
            "cap value anchored (changing it warrants a dedicated review)"
        );
        assert!(
            MAX_PIECE_LENGTH.is_power_of_two(),
            "legal within the v2 domain (power of two)"
        );
        let d = |pairs: Vec<(&str, bencode::Value)>| {
            let mut v: Vec<(Vec<u8>, bencode::Value)> = pairs
                .into_iter()
                .map(|(k, x)| (k.as_bytes().to_vec(), x))
                .collect();
            v.sort_by(|a, b| a.0.cmp(&b.0));
            bencode::Value::Dict(v)
        };
        let v1_info = |plen: i64| {
            d(vec![
                (
                    "files",
                    bencode::Value::List(vec![d(vec![
                        ("length", bencode::Value::Int(1)),
                        (
                            "path",
                            bencode::Value::List(vec![bencode::Value::Bytes(b"a".to_vec())]),
                        ),
                    ])]),
                ),
                ("piece length", bencode::Value::Int(plen)),
            ])
        };
        let over = d(vec![("info", v1_info(MAX_PIECE_LENGTH as i64 + 1))]);
        assert!(
            matches!(
                parse_v1_files(&over),
                Err(FileTreeError::PieceLengthOutOfRange(_))
            ),
            "v1-only 16MiB+1 must be rejected"
        );
        let ok = d(vec![("info", v1_info(MAX_PIECE_LENGTH as i64))]);
        assert!(
            parse_v1_files(&ok).is_ok(),
            "16MiB exactly passes (legal within the v1 domain)"
        );
    }
}
