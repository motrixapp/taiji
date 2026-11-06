//! .torrent creator: v1/v2/hybrid generation.
//!
//! The write-side mirror of [`crate::filetree`]: everything generated here
//! must pass the parse side losslessly ([`filetree::parse`] +
//! [`filetree::parse_v1_files`] + piece layers re-validation). Hash
//! primitives reuse the [`taiji_store::merkle`] public API (bt -> store,
//! one way); both sides share the same BEP-52 tree shape (16KiB leaves,
//! zero-leaf padding to a power of two, balanced piece-root layer).
//!
//! Flow: validate + pad planning ([`Plan::new`]) -> one streaming hash pass
//! ([`hash_pass`], blocking context only; async callers use [`create`]) ->
//! info/top-level assembly + dual infohashes computed over the raw info
//! byte slice. BEP rules, upstream anchors and deliberate divergences:
//! docs/design/piece-verification.md.
//!
//! Input model: the caller provides an ordered file list + source paths +
//! piece length + target form. Pads are planned automatically here
//! (multi-file + v1 side only); input entries carrying attr 'p' are
//! rejected, as are symlinks without `symlink path` support.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::ops::Range;
use std::path::{Component, Path, PathBuf};

use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use thiserror::Error;
use tokio::task::spawn_blocking;

use taiji_store::layout::{Layout, LayoutError, PlanEntry};
use taiji_store::merkle;

use crate::bencode::{self, Value};
use crate::filetree::{self, FileAttr, SwarmKind};

/// v2 leaf granularity = [`merkle::BLOCK_SIZE`] (16KiB, fixed by BEP-52).
const BLOCK: usize = merkle::BLOCK_SIZE as usize;

/// SHA-1 digest length (BEP-3 v1 pieces / v1 infohash).
const SHA1_LEN: usize = 20;

/// Target swarm form. Dual of the parse-side [`SwarmKind`] detection:
/// whatever form is written, `detect_swarm_kind` must detect.
pub use crate::filetree::SwarmKind as TorrentForm;

/// One file in a create request.
#[derive(Debug, Clone)]
pub struct CreateFile {
    /// In-torrent relative path (**without** the `name` prefix; used
    /// directly as both the v1 `files.path` and the v2 file tree key —
    /// libtorrent `create_torrent.cpp` likewise "deliberately skip[s] the
    /// first path element"). Components are validated by the same
    /// sanitizer rules as the parse side ('.'/'..'/NUL/invalid UTF-8/
    /// Windows reserved names/'\'/':'/trailing dot-space).
    pub path: PathBuf,
    /// On-disk source file (read by the hash pass; must be >= `length`
    /// bytes, extra ignored).
    pub source: PathBuf,
    /// Declared length (written to `length` and bounds the hash read; a
    /// shorter source is an explicit error).
    pub length: u64,
    /// File attributes. 'p' (pad) and 'l' (symlink) are not accepted in
    /// create input (see module docs).
    pub attr: FileAttr,
}

/// Create request (input model: file list + piece length + target form +
/// passthrough fields).
#[derive(Debug, Clone)]
pub struct CreateRequest {
    /// Torrent name (BEP-3 `name`; the file name when single-file, the
    /// root directory name when multi-file). Validated via
    /// [`filetree::sanitize_info_name`] (same rules as the parse side).
    pub name: String,
    /// Ordered file list (>= 1 entry; order = v1 layout order = cumulative
    /// on-disk offset order).
    pub files: Vec<CreateFile>,
    /// Piece length: power of two >= 16KiB (BEP-52; validated by
    /// [`merkle::validate_piece_len`]).
    pub piece_length: u32,
    /// Target form (v1-only / v2-only / hybrid).
    pub form: TorrentForm,
    /// BEP-27 private torrent: writes `private: 1` inside info.
    pub private: bool,
    /// Top-level `announce` (optional).
    pub announce: Option<String>,
    /// Top-level `announce-list` (reserved; each inner list = one tier,
    /// BEP-12 shape).
    pub announce_list: Option<Vec<Vec<String>>>,
    /// Top-level `comment` (optional).
    pub comment: Option<String>,
    /// Top-level `creation date` (unix seconds; None omits the key — same
    /// as libtorrent `create_torrent.cpp`, written only when
    /// `m_creation_date != 0`).
    pub creation_date: Option<i64>,
}

/// Create output.
#[derive(Debug, Clone)]
pub struct CreatedTorrent {
    /// Full .torrent bytes (canonical bencode, keys strictly ascending).
    pub bytes: Vec<u8>,
    /// Raw byte range of the info section within [`CreatedTorrent::bytes`]
    /// (both infohashes are computed over `&bytes[info_span]`).
    pub info_span: Range<usize>,
    /// v1 infohash = SHA-1 of the raw info slice (BEP-3/BEP-52).
    pub info_hash_v1: [u8; SHA1_LEN],
    /// v2 infohash = SHA-256 of the raw info slice (BEP-52; the 20-byte
    /// transport identity is truncated via
    /// [`crate::info_hash::truncated_v2`]).
    pub info_hash_v2: [u8; 32],
    /// Actual form (= requested form; callers can self-verify via
    /// `detect_swarm_kind`).
    pub kind: SwarmKind,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CreatorError {
    #[error("file list is empty")]
    EmptyFileList,
    #[error(
        "all files are empty: total length is zero (libtorrent torrent_missing_file_tree, create_torrent.cpp)"
    )]
    AllFilesEmpty,
    #[error("invalid piece length")]
    InvalidPieceLength(#[source] merkle::MerkleError),
    #[error("torrent name is invalid")]
    InvalidName(#[source] filetree::FileTreeError),
    #[error(
        "file {path:?} carries attr 'p' (padding): pad files are planned by the creator itself (BEP47) and must not appear in the input"
    )]
    PadFileInInput { path: PathBuf },
    #[error(
        "file {path:?} carries attr 'l' (symlink): `symlink path` is not supported by the creator"
    )]
    SymlinkUnsupported { path: PathBuf },
    #[error("file path {path:?} has an invalid component (absolute/dot segment)")]
    BadPathComponent { path: PathBuf },
    #[error("file path {path:?} contains a component that is not valid UTF-8")]
    InvalidPathUtf8 { path: PathBuf },
    #[error("file path {path:?} component is rejected by the sanitizer")]
    BadPathComponentName {
        path: PathBuf,
        #[source]
        source: filetree::FileTreeError,
    },
    #[error("file path is empty")]
    EmptyPath,
    #[error(
        "single-file torrent requires files[0].path == name: expected {expected:?}, got {got:?}"
    )]
    SingleFilePathMismatch { expected: String, got: PathBuf },
    #[error("path conflict: {path:?} collides with an existing file or directory in the torrent")]
    PathConflict { path: PathBuf },
    #[error("source file {path:?} is shorter than the declared length {expected}")]
    SourceTooShort { path: PathBuf, expected: u64 },
    #[error("io error on {path:?}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("pad layout planning failed (creator pads are exact piece remainders, BEP47 L85)")]
    PadPlan(#[source] LayoutError),
    #[error("v2-only compact layout planning failed (length sum not representable)")]
    CompactPlan(#[source] LayoutError),
    #[error("v1 piece count mismatch after hashing (creator bug)")]
    PieceCountMismatch,
    #[error("internal entry/state inconsistency during creation (creator bug)")]
    SelfCheck,
    #[error("hash task panicked or was cancelled")]
    HashTaskJoin,
}

/// In-memory file tree node (BTreeMap => key byte order = bencode
/// ascending).
enum TreeNode {
    /// File leaf: `{"": {attr?, length, "pieces root"?}}` (a constructed
    /// Value).
    Leaf(Value),
    Dir(BTreeMap<Vec<u8>, TreeNode>),
}

/// Plan output: validated input + pad layout (layout planning first).
struct Plan {
    piece_length: u32,
    form: TorrentForm,
    private: bool,
    /// Entry metadata aligned 1:1 with [`Plan::layout`] `files()` (pad
    /// entries have `source` = None).
    entries: Vec<EntrySpec>,
    layout: Layout,
    /// Single-file form (decides the v1 `length`@info and how the v2 tree
    /// wraps).
    single: bool,
}

/// Layout entry metadata (index-aligned with [`Layout::files`]).
struct EntrySpec {
    /// Sanitized path components (the sole source for written `files.path`
    /// / tree keys).
    components: Vec<String>,
    source: Option<PathBuf>,
    length: u64,
    attr: FileAttr,
}

impl Plan {
    fn new(req: &CreateRequest) -> Result<Plan, CreatorError> {
        // ---- scalar validation ----
        filetree::sanitize_info_name(req.name.as_bytes()).map_err(CreatorError::InvalidName)?;
        merkle::validate_piece_len(req.piece_length).map_err(CreatorError::InvalidPieceLength)?;
        if req.files.is_empty() {
            return Err(CreatorError::EmptyFileList);
        }
        let total: u64 = req.files.iter().map(|f| f.length).sum();
        if total == 0 {
            return Err(CreatorError::AllFilesEmpty);
        }
        let single = req.files.len() == 1;

        // ---- path sanitization + input attr gate + prefix-conflict
        // detection ----
        let mut entries: Vec<EntrySpec> = Vec::with_capacity(req.files.len());
        let mut seen: BTreeSet<Vec<String>> = BTreeSet::new();
        for f in &req.files {
            if f.attr.padding {
                return Err(CreatorError::PadFileInInput {
                    path: f.path.clone(),
                });
            }
            if f.attr.symlink {
                return Err(CreatorError::SymlinkUnsupported {
                    path: f.path.clone(),
                });
            }
            let components = sanitize_path(&f.path)?;
            // Component-level prefix conflicts: a file path must not be a
            // prefix of another — the v2 file tree cannot represent "file
            // and directory with the same name" (same as libtorrent
            // create_torrent.cpp torrent_inconsistent_files). Exact
            // duplicates are rejected here too (zero-difference prefix).
            // Prefix pairs are adjacent in sorted order (a standard
            // property of sorted prefixes), so both neighbors are
            // checked.
            let conflicting = {
                let backward = seen
                    .range(..=components.clone())
                    .next_back()
                    .is_some_and(|prev| {
                        prev.len() <= components.len() && components.starts_with(prev.as_slice())
                    });
                let forward = seen.range(components.clone()..).next().is_some_and(|next| {
                    next.len() >= components.len() && next.starts_with(components.as_slice())
                });
                backward || forward
            };
            if conflicting {
                return Err(CreatorError::PathConflict {
                    path: f.path.clone(),
                });
            }
            seen.insert(components.clone());
            entries.push(EntrySpec {
                components,
                source: Some(f.source.clone()),
                length: f.length,
                attr: f.attr,
            });
        }

        // Single file: the logical name = `name` (BEP-3 single-file form
        // has no path; the v2 tree wraps under name).
        if single && entries[0].components != [req.name.clone()] {
            return Err(CreatorError::SingleFilePathMismatch {
                expected: req.name.clone(),
                got: req.files[0].path.clone(),
            });
        }

        // ---- pad planning (BEP-47): v1 side + multi-file only; the
        // following file starts at a piece boundary; pad length = the
        // boundary remainder. None before the first file (offset 0 is
        // aligned) or after the last (no "following file"; no trailing pad
        // either — see module docs).
        let has_v1 = matches!(req.form, SwarmKind::V1Only | SwarmKind::Hybrid);
        let mut plan_entries: Vec<PlanEntry> = Vec::with_capacity(entries.len() * 2);
        let mut specs: Vec<EntrySpec> = Vec::with_capacity(entries.len() * 2);
        let mut offset = 0u64;
        for (i, e) in entries.into_iter().enumerate() {
            if has_v1
                && i > 0
                && e.length > 0
                && !offset.is_multiple_of(u64::from(req.piece_length))
            {
                let pad_len = u64::from(req.piece_length) - offset % u64::from(req.piece_length);
                plan_entries.push(PlanEntry {
                    path: pad_path(pad_len),
                    length: pad_len,
                    padding: true,
                });
                specs.push(EntrySpec {
                    components: pad_components(pad_len),
                    source: None,
                    length: pad_len,
                    attr: FileAttr {
                        padding: true,
                        ..FileAttr::default()
                    },
                });
                offset += pad_len;
            }
            plan_entries.push(PlanEntry {
                path: e.components.iter().collect(),
                length: e.length,
                padding: false,
            });
            offset += e.length;
            specs.push(e);
        }

        let layout = if has_v1 {
            // store::layout cross-checks the pad plan: pads computed here
            // must satisfy BEP-47 (following-file alignment + exact
            // remainder); a violation is a creator bug.
            Layout::plan_v1_padded(&plan_entries, req.piece_length)
                .map_err(CreatorError::PadPlan)?
        } else {
            // v2-only: compact contiguous, no pads (SPEC §4.2).
            Layout::plan_v2_compact(&plan_entries, req.piece_length)
                .map_err(CreatorError::CompactPlan)?
        };

        Ok(Plan {
            piece_length: req.piece_length,
            form: req.form,
            private: req.private,
            entries: specs,
            layout,
            single,
        })
    }
}

/// `.pad/<N>` layout path (the BEP-47 recommended form).
fn pad_path(pad_len: u64) -> PathBuf {
    PathBuf::from(".pad").join(pad_len.to_string())
}

fn pad_components(pad_len: u64) -> Vec<String> {
    vec![".pad".to_string(), pad_len.to_string()]
}

/// Path -> sanitized component list (same rules as the parse side; the
/// write-side mirror).
///
/// Component-level decisions are fully delegated to
/// [`filetree::sanitize_info_name`] — a single definition point keeps both
/// sanitizers in sync. Equivalent domain = Normal components from
/// `components` ('/' is a legal separator on the `PathBuf` side but
/// illegal in a file tree key, so it is outside the domain; per the std
/// docs, components do "no other normalization" and keep component text
/// verbatim). On Windows the OS parser pre-splits on '\', so '\' forms
/// never reach this function as single components — but the invariant "no
/// emitted key contains '\'" holds on both platforms (POSIX by rule 1
/// rejection, Windows by pre-splitting).
fn sanitize_path(path: &Path) -> Result<Vec<String>, CreatorError> {
    let mut out = Vec::new();
    for comp in path.components() {
        let raw = match comp {
            Component::Normal(s) => s,
            // Absolute/parent/current-dir components are rejected; "." is
            // swallowed by components() normalization (an equivalent
            // relative path, harmless), while ".." stays as ParentDir and
            // is rejected here.
            _ => {
                return Err(CreatorError::BadPathComponent {
                    path: path.to_path_buf(),
                });
            }
        };
        let s = match raw.to_str() {
            Some(s) => s,
            None => {
                return Err(CreatorError::InvalidPathUtf8 {
                    path: path.to_path_buf(),
                });
            }
        };
        filetree::sanitize_info_name(s.as_bytes()).map_err(|source| {
            CreatorError::BadPathComponentName {
                path: path.to_path_buf(),
                source,
            }
        })?;
        out.push(s.to_string());
    }
    if out.is_empty() {
        return Err(CreatorError::EmptyPath);
    }
    Ok(out)
}

/// Hash pass output: one item per layout entry (pad / empty file /
/// non-v2 forms have root/layer = None).
#[derive(Debug, Default, Clone)]
struct EntryHashes {
    root: Option<[u8; 32]>,
    layer: Option<Vec<u8>>,
}

#[derive(Debug)]
struct HashOutcome {
    entries: Vec<EntryHashes>,
    /// v1 global pieces (SHA-1s concatenated in order; pad zero spans are
    /// hashed). None for non-v1 forms.
    v1_pieces: Option<Vec<u8>>,
}

/// Synchronous hash kernel: one streaming read pass, v1/v2 pipelines fed
/// from the same reads. Only callable in a blocking context
/// ([`spawn_blocking`] or sync callers); async callers use [`create`].
fn hash_pass(plan: &Plan) -> Result<HashOutcome, CreatorError> {
    let has_v1 = matches!(plan.form, SwarmKind::V1Only | SwarmKind::Hybrid);
    let has_v2 = matches!(plan.form, SwarmKind::V2Only | SwarmKind::Hybrid);
    let piece_len = plan.piece_length;
    let bpp = merkle::blocks_per_piece(piece_len) as usize;

    let mut v1 = V1PieceHasher::new(has_v1, piece_len);
    let mut out: Vec<EntryHashes> = Vec::with_capacity(plan.entries.len());

    for (entry, spec) in plan.layout.files().iter().zip(&plan.entries) {
        if entry.padding {
            // BEP-47: pad content counts as all zeros in the v1 piece
            // hashes; pads never enter the v2 face.
            v1.feed_zeros(entry.length);
            out.push(EntryHashes::default());
            continue;
        }
        if entry.length == 0 {
            // Empty file: zero bytes do not disturb the v1 stream; v2 has
            // no root (BEP-52 "For non-empty files this is ...").
            out.push(EntryHashes::default());
            continue;
        }
        let source = spec.source.as_deref().ok_or(CreatorError::SelfCheck)?;
        let mut file = File::open(source).map_err(|e| CreatorError::Io {
            path: source.to_path_buf(),
            source: e,
        })?;
        let mut block = [0u8; BLOCK];
        let mut remaining = entry.length;
        let mut blocks: Vec<[u8; 32]> = Vec::new();
        while remaining > 0 {
            let want = remaining.min(BLOCK as u64) as usize;
            read_full(&mut file, &mut block[..want]).map_err(|e| {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    CreatorError::SourceTooShort {
                        path: source.to_path_buf(),
                        expected: entry.length,
                    }
                } else {
                    CreatorError::Io {
                        path: source.to_path_buf(),
                        source: e,
                    }
                }
            })?;
            if has_v2 {
                // a 16KiB read is exactly one leaf block; a short final
                // read = last block (BEP-52).
                blocks.push(merkle::block_hash(&block[..want]));
            }
            if has_v1 {
                v1.feed(&block[..want]);
            }
            remaining -= want as u64;
        }
        let hashes = if has_v2 {
            // File root: the BEP-52 tree shape (<=1 piece pads the block
            // count to a power of two; >1 piece folds per-piece groups) —
            // same source as the parse side's merkle::file_root.
            let root =
                merkle::file_root(&blocks, piece_len).map_err(CreatorError::InvalidPieceLength)?;
            // layer = piece roots concatenated in order; none for <= 1
            // piece (BEP-52 piece layers section; libtorrent
            // create_torrent.cpp `size() < 2` same rule).
            let layer = if blocks.len() > bpp {
                Some(
                    blocks
                        .chunks(bpp)
                        .flat_map(|c| merkle::piece_root_from_block_hashes(c, bpp))
                        .collect::<Vec<u8>>(),
                )
            } else {
                None
            };
            EntryHashes {
                root: Some(root),
                layer,
            }
        } else {
            EntryHashes::default()
        };
        out.push(hashes);
    }
    let v1_pieces = v1.finish(plan.layout.total(), plan.layout.piece_len())?;
    Ok(HashOutcome {
        entries: out,
        v1_pieces,
    })
}

/// Fill `buf` completely; early EOF = source shorter than declared (mapped
/// to [`CreatorError::SourceTooShort`]).
fn read_full(file: &mut File, buf: &mut [u8]) -> std::io::Result<()> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "source file shorter than declared length",
                ));
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// v1 global piece SHA-1 pipeline: accumulates across files (piece
/// boundaries can fall inside files); pad zero spans are hashed (BEP-47
/// "the content of padding file is all zeros").
struct V1PieceHasher {
    active: bool,
    piece_len: usize,
    hasher: Sha1,
    fill: usize,
    pieces: Vec<u8>,
}

impl V1PieceHasher {
    fn new(active: bool, piece_len: u32) -> V1PieceHasher {
        V1PieceHasher {
            active,
            piece_len: piece_len as usize,
            hasher: Sha1::new(),
            fill: 0,
            pieces: Vec::new(),
        }
    }

    fn feed(&mut self, data: &[u8]) {
        if !self.active {
            return;
        }
        let mut rest = data;
        while !rest.is_empty() {
            let take = (self.piece_len - self.fill).min(rest.len());
            self.hasher.update(&rest[..take]);
            self.fill += take;
            rest = &rest[take..];
            if self.fill == self.piece_len {
                self.seal_piece();
            }
        }
    }

    /// Pad zero span: feed zeros in blocks instead of allocating the whole
    /// span (pad < piece_len, but piece_len can reach 16MiB).
    fn feed_zeros(&mut self, mut len: u64) {
        const ZERO: [u8; BLOCK] = [0u8; BLOCK];
        while len > 0 {
            let take = len.min(ZERO.len() as u64) as usize;
            self.feed(&ZERO[..take]);
            len -= take as u64;
        }
    }

    fn seal_piece(&mut self) {
        self.pieces.extend_from_slice(&self.hasher.finalize_reset());
        self.fill = 0;
    }

    fn finish(mut self, total: u64, piece_len: u32) -> Result<Option<Vec<u8>>, CreatorError> {
        if !self.active {
            return Ok(None);
        }
        if self.fill > 0 {
            // last piece = the real remaining bytes (v1 short final pieces
            // are not zero-padded, BEP-3 pieces semantics).
            self.pieces.extend_from_slice(&self.hasher.finalize_reset());
        }
        let expected = total.div_ceil(u64::from(piece_len));
        let got = self.pieces.len() / SHA1_LEN;
        if usize::try_from(expected) != Ok(got) {
            return Err(CreatorError::PieceCountMismatch);
        }
        Ok(Some(self.pieces))
    }
}

/// Create a torrent (synchronous kernel).
///
/// Flow: validate + pad planning ([`Plan::new`]) -> one streaming hash pass
/// ([`hash_pass`]; never call directly from async context) -> info/
/// top-level assembly + dual infohashes. Async callers must use [`create`]
/// (wrapped in spawn_blocking).
pub fn create_blocking(req: CreateRequest) -> Result<CreatedTorrent, CreatorError> {
    let plan = Plan::new(&req)?;
    let outcome = hash_pass(&plan)?;
    assemble(&req, &plan, &outcome)
}

/// Create a torrent (async entry): the disk-read hashing runs inside
/// [`spawn_blocking`].
pub async fn create(req: CreateRequest) -> Result<CreatedTorrent, CreatorError> {
    spawn_blocking(move || create_blocking(req))
        .await
        .map_err(|_| CreatorError::HashTaskJoin)?
}

/// info/top-level assembly + dual infohashes (computed over the raw info
/// byte slice).
fn assemble(
    req: &CreateRequest,
    plan: &Plan,
    outcome: &HashOutcome,
) -> Result<CreatedTorrent, CreatorError> {
    let has_v1 = matches!(plan.form, SwarmKind::V1Only | SwarmKind::Hybrid);
    let has_v2 = matches!(plan.form, SwarmKind::V2Only | SwarmKind::Hybrid);

    // ---- info dict (sorted after insertion; encode enforces strict
    // ascending) ----
    let mut info: Vec<(Vec<u8>, Value)> = Vec::new();
    info.push((b"name".to_vec(), Value::Bytes(req.name.as_bytes().to_vec())));
    info.push((
        b"piece length".to_vec(),
        Value::Int(i64::from(plan.piece_length)),
    ));
    if plan.private {
        info.push((b"private".to_vec(), Value::Int(1)));
    }

    if has_v1 {
        let pieces = outcome
            .v1_pieces
            .as_ref()
            .ok_or(CreatorError::PieceCountMismatch)?;
        info.push((b"pieces".to_vec(), Value::Bytes(pieces.clone())));
        if plan.single {
            // Single file: length + attr at the info top level (BEP-3;
            // libtorrent create_torrent.cpp same shape). Single-file
            // torrents have no pads, so entries[0] is the only real file.
            info.push((
                b"length".to_vec(),
                Value::Int(len_int(plan.entries[0].length)),
            ));
            if let Some(attr) = attr_bytes(plan.entries[0].attr) {
                info.push((b"attr".to_vec(), Value::Bytes(attr)));
            }
        } else {
            info.push((b"files".to_vec(), Value::List(files_list(plan))));
        }
    }

    if has_v2 {
        info.push((b"meta version".to_vec(), Value::Int(2)));
        info.push((b"file tree".to_vec(), file_tree(plan, outcome)?));
    }
    sort_dict(&mut info);
    let info_value = Value::Dict(info);

    // ---- top-level dict: piece layers goes outside info (BEP-52) ----
    let mut top: Vec<(Vec<u8>, Value)> = Vec::new();
    if let Some(a) = &req.announce {
        top.push((b"announce".to_vec(), Value::Bytes(a.as_bytes().to_vec())));
    }
    if let Some(tiers) = &req.announce_list {
        let tiers = tiers
            .iter()
            .map(|tier| {
                Value::List(
                    tier.iter()
                        .map(|u| Value::Bytes(u.as_bytes().to_vec()))
                        .collect(),
                )
            })
            .collect();
        top.push((b"announce-list".to_vec(), Value::List(tiers)));
    }
    if let Some(c) = &req.comment {
        top.push((b"comment".to_vec(), Value::Bytes(c.as_bytes().to_vec())));
    }
    if let Some(d) = req.creation_date {
        top.push((b"creation date".to_vec(), Value::Int(d)));
    }
    top.push((b"info".to_vec(), info_value));
    if has_v2 && let Some(layers) = piece_layers(plan, outcome)? {
        top.push((b"piece layers".to_vec(), layers));
    }
    sort_dict(&mut top);

    let bytes = bencode::encode(&Value::Dict(top)).map_err(|_| CreatorError::SelfCheck)?;

    // Self-check: our own bytes must strictly decode through the
    // authoritative parser and locate the raw info slice (encode is
    // deterministic, so failure = an internal bencode bug; better an
    // explicit error than emitting suspect bytes). The dual infohashes are
    // then computed directly over that slice — no re-encode round trip.
    let (_, info_span) =
        bencode::decode_with_info_span(&bytes).map_err(|_| CreatorError::SelfCheck)?;

    // dual infohashes: over the raw info byte slice (BEP-52; no re-encode
    // round trip).
    let raw = &bytes[info_span.clone()];
    let info_hash_v1: [u8; SHA1_LEN] = Sha1::digest(raw).into();
    let info_hash_v2: [u8; 32] = Sha256::digest(raw).into();

    Ok(CreatedTorrent {
        bytes,
        info_span,
        info_hash_v1,
        info_hash_v2,
        kind: plan.form,
    })
}

fn len_int(length: u64) -> i64 {
    i64::try_from(length).unwrap_or(i64::MAX)
}

/// attr string: order h,x (p/l are rejected at the input face; libtorrent
/// add_file_attrs order p,h,x,l minus the unreachable bits).
fn attr_bytes(attr: FileAttr) -> Option<Vec<u8>> {
    let mut s = Vec::new();
    if attr.hidden {
        s.push(b'h');
    }
    if attr.executable {
        s.push(b'x');
    }
    if s.is_empty() { None } else { Some(s) }
}

/// The v1 `files` list (layout order, pad entries interleaved between real
/// files; BEP-47).
fn files_list(plan: &Plan) -> Vec<Value> {
    plan.entries
        .iter()
        .zip(plan.layout.files())
        .map(|(spec, layout_file)| {
            let mut pairs: Vec<(Vec<u8>, Value)> = Vec::new();
            let attr = if layout_file.padding {
                Some(b"p".to_vec())
            } else {
                attr_bytes(spec.attr)
            };
            if let Some(a) = attr {
                pairs.push((b"attr".to_vec(), Value::Bytes(a)));
            }
            pairs.push((b"length".to_vec(), Value::Int(len_int(spec.length))));
            pairs.push((
                b"path".to_vec(),
                Value::List(
                    spec.components
                        .iter()
                        .map(|c| Value::Bytes(c.as_bytes().to_vec()))
                        .collect(),
                ),
            ));
            sort_dict(&mut pairs);
            Value::Dict(pairs)
        })
        .collect()
}

/// v2 file tree: descend per path component, leaves
/// `{"": {attr?, length, "pieces root"?}}`. Empty files carry only
/// `length` (BEP-52); directory nodes are in key byte order (BTreeMap).
fn file_tree(plan: &Plan, outcome: &HashOutcome) -> Result<Value, CreatorError> {
    let mut root = BTreeMap::new();
    for ((spec, layout_file), hashes) in plan
        .entries
        .iter()
        .zip(plan.layout.files())
        .zip(&outcome.entries)
    {
        if layout_file.padding {
            continue; // pads never enter the file tree (BEP-47; mirrors the parse side having no pad form)
        }
        let mut props: Vec<(Vec<u8>, Value)> = Vec::new();
        if let Some(attr) = attr_bytes(spec.attr) {
            props.push((b"attr".to_vec(), Value::Bytes(attr)));
        }
        props.push((b"length".to_vec(), Value::Int(len_int(spec.length))));
        if let Some(root_hash) = &hashes.root {
            props.push((b"pieces root".to_vec(), Value::Bytes(root_hash.to_vec())));
        }
        sort_dict(&mut props);
        let leaf = TreeNode::Leaf(Value::Dict(vec![(Vec::new(), Value::Dict(props))]));

        // Descend: intermediate components must be directories; endpoint
        // conflicts (file/dir same name, duplicate paths) were already
        // rejected by prefix at the Plan stage — this is a defensive
        // backstop.
        let mut cursor = &mut root;
        let last = spec.components.len() - 1;
        for (depth, comp) in spec.components.iter().enumerate() {
            let key = comp.as_bytes().to_vec();
            if depth == last {
                if cursor.contains_key(&key) {
                    return Err(CreatorError::PathConflict {
                        path: PathBuf::from(spec.components.join("/")),
                    });
                }
                cursor.insert(key, leaf);
                break;
            }
            match cursor
                .entry(key)
                .or_insert_with(|| TreeNode::Dir(BTreeMap::new()))
            {
                TreeNode::Dir(children) => cursor = children,
                TreeNode::Leaf(_) => {
                    return Err(CreatorError::PathConflict {
                        path: PathBuf::from(spec.components.join("/")),
                    });
                }
            }
        }
    }
    Ok(node_to_value(&TreeNode::Dir(root)))
}

fn node_to_value(node: &TreeNode) -> Value {
    match node {
        TreeNode::Leaf(v) => v.clone(),
        TreeNode::Dir(children) => Value::Dict(
            children
                .iter()
                .map(|(k, v)| (k.clone(), node_to_value(v)))
                .collect(),
        ),
    }
}

/// Top-level `piece layers` (outside info): key = 32B raw merkle root,
/// value = concatenated piece-root layer; the whole field is omitted when
/// there are no entries (BEP-52: only files > piece size need one).
///
/// Same-root dedup collapse: BEP-52 pieces root section, "Note that
/// identical files always result in the same root hash" — identical files
/// share a root, and the dict is keyed by root (bencode dict keys are
/// unique; duplicate keys cannot be canonically encoded); libtorrent
/// `create_torrent.cpp` `file_pieces[m_fileroots[fi].to_string()]` writes
/// by key and overwrites, so same roots naturally collapse to one entry.
/// The layer is a pure function of (content, piece length), so collapsing
/// is lossless; same root with a different layer is unreachable by
/// construction (SHA-256 collision resistance) and is treated
/// conservatively as internal inconsistency.
fn piece_layers(plan: &Plan, outcome: &HashOutcome) -> Result<Option<Value>, CreatorError> {
    let mut pairs: Vec<(Vec<u8>, Value)> = Vec::new();
    for ((_, layout_file), hashes) in plan
        .entries
        .iter()
        .zip(plan.layout.files())
        .zip(&outcome.entries)
    {
        if layout_file.padding {
            continue;
        }
        if let (Some(root), Some(layer)) = (&hashes.root, &hashes.layer) {
            match pairs.iter_mut().find(|(k, _)| k == root) {
                Some((_, Value::Bytes(prev))) if prev == layer => continue,
                Some(_) => return Err(CreatorError::SelfCheck),
                None => pairs.push((root.to_vec(), Value::Bytes(layer.clone()))),
            }
        }
    }
    if pairs.is_empty() {
        return Ok(None);
    }
    sort_dict(&mut pairs);
    Ok(Some(Value::Dict(pairs)))
}

/// Build dicts: keys strictly ascending by bytes (the precondition of
/// bencode::encode).
fn sort_dict(pairs: &mut [(Vec<u8>, Value)]) {
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(hidden: bool, executable: bool) -> FileAttr {
        FileAttr {
            padding: false,
            hidden,
            executable,
            symlink: false,
        }
    }

    fn file(path: &str, length: u64) -> CreateFile {
        CreateFile {
            path: PathBuf::from(path),
            source: PathBuf::from("/nonexistent"),
            length,
            attr: FileAttr::default(),
        }
    }

    fn req(files: Vec<CreateFile>, form: TorrentForm) -> CreateRequest {
        CreateRequest {
            name: "test".to_string(),
            files,
            piece_length: 16 * 1024,
            form,
            private: false,
            announce: None,
            announce_list: None,
            comment: None,
            creation_date: None,
        }
    }

    // ===== pad planning (BEP-47; store::layout::plan_v1_padded as
    // reference) =====

    /// 70000 + 30000 @16KiB: a 11920 pad is inserted between (same shape
    /// as the hybrid fixture); the file after the pad starts at a piece
    /// boundary.
    #[test]
    fn pad_inserted_between_unaligned_files() {
        let plan = Plan::new(&req(
            vec![file("a.bin", 70000), file("b.bin", 30000)],
            SwarmKind::Hybrid,
        ))
        .unwrap_or_else(|e| panic!("{e}"));
        let files = plan.layout.files();
        assert_eq!(files.len(), 3);
        assert_eq!(
            (files[1].path.clone(), files[1].length, files[1].padding),
            (PathBuf::from(".pad/11920"), 11920, true)
        );
        assert_eq!(
            files[2].offset, 81920,
            "file after pad starts on a piece boundary"
        );
        assert_eq!(plan.layout.total(), 111920);
        assert_eq!(
            plan.entries[1].components,
            vec![".pad".to_string(), "11920".to_string()],
            "pad path = BEP47 L89 recommended [\".pad\", \"N\"]"
        );
    }

    /// Aligned / single-file / pure v2 / empty file on an aligned path: no
    /// pad.
    #[test]
    fn pad_omitted_when_aligned_or_single_or_v2() {
        // aligned: b follows at 16384, no pad.
        let p = Plan::new(&req(
            vec![file("a", 16384), file("b", 10)],
            SwarmKind::Hybrid,
        ))
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(p.layout.files().len(), 2);
        // single-file (even unaligned): libtorrent file_storage.cpp —
        // single-file torrents are never padded (otherwise single-file
        // hybrids could not exist).
        let mut r = req(vec![file("a", 70000)], SwarmKind::Hybrid);
        r.name = "a".to_string();
        let p = Plan::new(&r).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(p.layout.files().len(), 1);
        // pure v2: no v1 layout concept, no pad.
        let p = Plan::new(&req(
            vec![file("a", 70000), file("b", 10)],
            SwarmKind::V2Only,
        ))
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(p.layout.files().len(), 2);
        assert_eq!(p.layout.kind(), taiji_store::layout::LayoutKind::V2Compact);
        // an empty file landing on an aligned path: no pad triggered.
        let p = Plan::new(&req(
            vec![file("a", 16384), file("e", 0), file("b", 10)],
            SwarmKind::Hybrid,
        ))
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(p.layout.files().len(), 3);
    }

    /// Empty file on an unaligned path: the pad goes before the next
    /// non-empty file.
    #[test]
    fn pad_before_next_nonempty_after_empty_file() {
        let p = Plan::new(&req(
            vec![file("a", 70000), file("e", 0), file("b", 30000)],
            SwarmKind::Hybrid,
        ))
        .unwrap_or_else(|e| panic!("{e}"));
        let files = p.layout.files();
        assert_eq!(files.len(), 4);
        assert_eq!(files[1].length, 0);
        assert!(
            files[2].padding,
            "pad inserted between the empty file and b.bin"
        );
        assert_eq!(files[3].offset, 81920);
    }

    // ===== error faces (explicit rejection) =====

    fn expect_err(r: Result<Plan, CreatorError>, what: &str) -> CreatorError {
        match r {
            Err(e) => e,
            Ok(_) => panic!("expected error: {what}"),
        }
    }

    #[test]
    fn error_faces_rejected() {
        // non-power-of-two / too-small piece length (BEP-52: power of two
        // and at least 16KiB).
        for bad in [8 * 1024u32, 24 * 1024, 0] {
            let mut r = req(vec![file("a", 10)], SwarmKind::V1Only);
            r.piece_length = bad;
            assert!(
                matches!(
                    expect_err(Plan::new(&r), "piece length"),
                    CreatorError::InvalidPieceLength(_)
                ),
                "piece_length = {bad}"
            );
        }
        // empty file list.
        assert!(matches!(
            expect_err(Plan::new(&req(vec![], SwarmKind::V1Only)), "empty"),
            CreatorError::EmptyFileList
        ));
        // all files empty (total length 0): same verdict as libtorrent
        // torrent_missing_file_tree.
        assert!(matches!(
            expect_err(
                Plan::new(&req(vec![file("a", 0), file("b", 0)], SwarmKind::V1Only)),
                "all empty"
            ),
            CreatorError::AllFilesEmpty
        ));
        // input carrying pad attr conflicts with the creator's automatic
        // pad planning (BEP-47: pads are a v1 layout concept the creator
        // plans itself).
        let mut f = file("a", 10);
        f.attr.padding = true;
        assert!(matches!(
            expect_err(
                Plan::new(&req(vec![f, file("b", 10)], SwarmKind::V1Only)),
                "pad input"
            ),
            CreatorError::PadFileInInput { .. }
        ));
        // rejected for hybrid/v2 too (pads never belong to create input).
        let mut f = file("a", 10);
        f.attr.padding = true;
        assert!(matches!(
            expect_err(
                Plan::new(&req(vec![f, file("b", 10)], SwarmKind::V2Only)),
                "pad input (v2)"
            ),
            CreatorError::PadFileInInput { .. }
        ));
        // symlink attr: no `symlink path` support, explicit reject.
        let mut f = file("a", 10);
        f.attr.symlink = true;
        assert!(matches!(
            expect_err(Plan::new(&req(vec![f], SwarmKind::V1Only)), "symlink"),
            CreatorError::SymlinkUnsupported { .. }
        ));
        // path conflicts: file-vs-directory prefix / duplicates (order
        // independent).
        assert!(matches!(
            expect_err(
                Plan::new(&req(vec![file("a", 1), file("a/b", 1)], SwarmKind::V1Only)),
                "prefix conflict"
            ),
            CreatorError::PathConflict { .. }
        ));
        assert!(matches!(
            expect_err(
                Plan::new(&req(vec![file("a/b", 1), file("a", 1)], SwarmKind::V1Only)),
                "prefix conflict (reversed)"
            ),
            CreatorError::PathConflict { .. }
        ));
        assert!(matches!(
            expect_err(
                Plan::new(&req(vec![file("a", 1), file("a", 1)], SwarmKind::V1Only)),
                "duplicate"
            ),
            CreatorError::PathConflict { .. }
        ));
        // single file: path must equal name.
        assert!(matches!(
            expect_err(
                Plan::new(&req(vec![file("other", 1)], SwarmKind::V1Only)),
                "single path"
            ),
            CreatorError::SingleFilePathMismatch { .. }
        ));
        // invalid name / path components (same sanitizer rules as the
        // parse side, BEP-52 sanitize).
        let mut r = req(vec![file("a", 1)], SwarmKind::V1Only);
        r.name = "../evil".to_string();
        assert!(matches!(
            expect_err(Plan::new(&r), "bad name"),
            CreatorError::InvalidName(_)
        ));
        assert!(matches!(
            expect_err(
                Plan::new(&req(vec![file("CON", 1)], SwarmKind::V1Only)),
                "reserved"
            ),
            CreatorError::BadPathComponentName { .. }
        ));
        assert!(matches!(
            expect_err(
                Plan::new(&req(vec![file("..", 1)], SwarmKind::V1Only)),
                "parent dir"
            ),
            CreatorError::BadPathComponent { .. }
        ));
        assert!(matches!(
            expect_err(
                Plan::new(&req(vec![file("/abs", 1)], SwarmKind::V1Only)),
                "absolute"
            ),
            CreatorError::BadPathComponent { .. }
        ));
        assert!(matches!(
            expect_err(
                Plan::new(&req(
                    vec![CreateFile {
                        path: PathBuf::new(),
                        source: PathBuf::from("/x"),
                        length: 1,
                        attr: FileAttr::default(),
                    }],
                    SwarmKind::V1Only
                )),
                "empty path"
            ),
            CreatorError::EmptyPath
        ));
    }

    /// The two sanitizers agree: same input, same verdict at the component
    /// level. Equivalent domain = a single Normal path component ('/' is a
    /// legal separator on the PathBuf side but illegal in a file tree key,
    /// so it is outside the domain); single components containing '\'
    /// only exist on POSIX (Windows pre-splits on '\'), covered by the
    /// cfg gate below.
    #[test]
    fn sanitize_path_matches_filetree_sanitizer() {
        let vectors: &[&str] = &[
            // legal: accepted by both parse and create faces.
            "a.bin",
            ".pad",
            "11920",
            "a b",
            "a.b.c",
            "日本語",
            // illegal: rejected by both faces ('.'/'..'/reserved names/NUL
            // pre-existing; ':'/trailing dot-space added later).
            ".",
            "..",
            "",
            "CON",
            "nul.txt",
            "C:",
            "C:tmp",
            "file:ads",
            "a.",
            "a ",
            "a. ",
            "...",
            " ",
        ];
        for v in vectors {
            let via_parse = filetree::sanitize_info_name(v.as_bytes());
            let via_create = sanitize_path(Path::new(v));
            assert_eq!(
                via_parse.is_ok(),
                via_create.is_ok(),
                "vector {v:?}: parse={via_parse:?} create={via_create:?}"
            );
        }
        // UNC forms (forward-slash spelling judged the same on both
        // platforms: a component containing '/' -> parse face rejects /
        // RootDir component -> create face rejects).
        let via_parse = filetree::sanitize_info_name(b"//srv/share");
        let via_create = sanitize_path(Path::new("//srv/share"));
        assert!(via_parse.is_err() && via_create.is_err());
    }

    /// '\' single-component forms (UNC prefixes / embedded backslashes)
    /// reach the sanitizer directly on POSIX and both faces reject; on
    /// Windows `Path::components()` pre-splits on '\', so the shapes
    /// differ while the "no emitted key contains '\'" invariant holds
    /// (see [`sanitize_path`] docs).
    #[cfg(not(windows))]
    #[test]
    fn sanitize_path_backslash_forms_posix() {
        for v in ["a\\b", "\\\\srv\\share", "C:\\path"] {
            let via_parse = filetree::sanitize_info_name(v.as_bytes());
            let via_create = sanitize_path(Path::new(v));
            assert!(via_parse.is_err(), "parse face must reject {v:?}");
            assert!(via_create.is_err(), "creator face must reject {v:?}");
        }
    }

    /// The newer rules are rejected end-to-end through the create entry
    /// (vectors chosen to agree on both platforms; "C:" is a Prefix
    /// component on Windows -> BadPathComponent, BadPathComponentName on
    /// POSIX — only the rejection itself is asserted). The name takes the
    /// same vector to satisfy the single-file path==name precondition and
    /// avoid tripping SingleFilePathMismatch.
    #[test]
    fn windows_component_rules_rejected_via_plan() {
        for v in ["C:", "C:tmp", "a.", "a ", "file:ads"] {
            let mut r = req(vec![file("placeholder", 1)], SwarmKind::V1Only);
            r.files[0].path = PathBuf::from(v);
            r.name = v.to_string();
            assert!(Plan::new(&r).is_err(), "vector {v:?} must be rejected");
        }
    }

    // ===== tree building (write-side shape = mirror of filetree::parse)
    // =====

    /// Multi-file tree: per-component descent + key byte order + leaves
    /// `{"": props}`; strict decode accepting = canonical ascending (the
    /// write side mirrors the parse-side invariant).
    #[test]
    fn tree_shape_and_ordering() {
        let r = req(
            vec![
                file("z.txt", 1),
                file("a_dir/inner.txt", 2),
                file("a.bin", 3),
            ],
            SwarmKind::V2Only,
        );
        let plan = Plan::new(&r).unwrap_or_else(|e| panic!("{e}"));
        let outcome = HashOutcome {
            entries: vec![EntryHashes::default(); plan.entries.len()],
            v1_pieces: None,
        };
        // with zero-hash placeholders root is None => leaves carry only
        // length (shape test needs no real hashes).
        let tree = file_tree(&plan, &outcome).unwrap_or_else(|e| panic!("{e}"));
        let Value::Dict(top_pairs) = &tree else {
            panic!("tree must be a dict");
        };
        let keys: Vec<&[u8]> = top_pairs.iter().map(|(k, _)| k.as_slice()).collect();
        assert_eq!(
            keys,
            [
                b"a.bin".as_slice(),
                b"a_dir".as_slice(),
                b"z.txt".as_slice()
            ]
        );
        // a_dir is a directory node (containing inner.txt), not a file
        // leaf.
        match &top_pairs[1].1 {
            Value::Dict(inner) => assert!(inner.iter().any(|(k, _)| k == b"inner.txt")),
            other => panic!("a_dir must be a dir dict, got {other:?}"),
        }
        // strict decode accepting = canonical ascending.
        let bytes = bencode::encode(&tree).unwrap_or_else(|e| panic!("{e}"));
        assert!(bencode::decode(&bytes).is_ok());
    }

    /// Single-file v2: the tree wraps under the name key (BEP-52 root must
    /// not be a file; libtorrent v2_only.torrent same shape); the leaf
    /// carries length and pieces root.
    #[test]
    fn single_file_tree_wraps_under_name() {
        let mut r = req(vec![file("test1MB", 5)], SwarmKind::V2Only);
        r.name = "test1MB".to_string();
        let plan = Plan::new(&r).unwrap_or_else(|e| panic!("{e}"));
        assert!(plan.single);
        let root_hash = [0xaa; 32];
        let outcome = HashOutcome {
            entries: vec![EntryHashes {
                root: Some(root_hash),
                layer: None,
            }],
            v1_pieces: None,
        };
        let tree = file_tree(&plan, &outcome).unwrap_or_else(|e| panic!("{e}"));
        let Value::Dict(top_pairs) = &tree else {
            panic!("tree must be a dict");
        };
        assert_eq!(top_pairs.len(), 1);
        assert_eq!(top_pairs[0].0, b"test1MB".to_vec());
        let Value::Dict(marker) = &top_pairs[0].1 else {
            panic!("leaf must be {{\"\": props}}");
        };
        assert_eq!(marker.len(), 1);
        assert_eq!(
            marker[0].0,
            Vec::<u8>::new(),
            "file marker = zero-length key"
        );
        let Value::Dict(props) = &marker[0].1 else {
            panic!("props must be a dict");
        };
        let get = |k: &[u8]| props.iter().find(|(key, _)| key == k).map(|(_, v)| v);
        assert_eq!(get(b"length"), Some(&Value::Int(5)));
        assert_eq!(get(b"pieces root"), Some(&Value::Bytes(root_hash.to_vec())));
        // no zero-length key at the root (BEP-52 "root dictionary itself
        // must not be a file").
        assert!(!top_pairs.iter().any(|(k, _)| k.is_empty()));
    }

    /// attr string: h,x order (libtorrent add_file_attrs order); empty
    /// attr writes no key.
    #[test]
    fn attr_bytes_order_and_omission() {
        assert_eq!(attr_bytes(attr(false, false)), None);
        assert_eq!(attr_bytes(attr(true, false)), Some(b"h".to_vec()));
        assert_eq!(attr_bytes(attr(false, true)), Some(b"x".to_vec()));
        assert_eq!(attr_bytes(attr(true, true)), Some(b"hx".to_vec()));
    }
}
