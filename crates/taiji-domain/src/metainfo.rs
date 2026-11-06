//! .torrent metainfo parsing into the unified metadata model.
//!
//! # Model
//!
//! - [`TorrentIdentity`]: dual infohash (v1 = SHA-1, v2 = SHA-256), both
//! computed over the **raw info byte slice** (BEP52);
//! - [`TorrentMeta`]: kind + piece_length + [`MetaFile`] list + layout
//! planning (dispatched by kind);
//! - hybrid dual-representation join: the v2 file tree (DFS order) is the
//! primary view; the v1 `files` list joins by sanitized relative path
//! with `v1_offset`. The two views must agree on file order and lengths,
//! otherwise the torrent is rejected (both views come from the same
//! bytes, so agreement is inherent — a mismatch means corrupted
//! metadata).
//!
//! # Engine-side assembly (host side)
//!
//! Assembles the download engine's swarm faces by kind (assembly functions
//! live on the engine side; this module never references engine types):
//! v1-only -> single v1 face; v2-only -> single v2 face (PerFile addressing
//! plus a compact-layout goff table); hybrid -> v1 + v2 dual faces. The
//! BEP52 alignment mapping keeps the two face piece spaces identical
//! (v1 stream piece k <-> v2 wire piece k); each face runs dual hash
//! checks (BEP52: "must verify that pieces match both piece hash
//! formats").
//!
//! # Scope (honesty)
//!
//! - The parse and data faces of all three swarm kinds are fully
//! supported; hash-exchange requesting (lazy base-layer fetch plus
//! block-level verification) is part 2 — v2 verification granularity
//! here is the whole piece.
//! - announce: the top-level `announce` or the first usable URL of
//! `announce-list` (compatibility surface), plus the full tier table
//! [`Metainfo::announce_tiers`] (BEP12 "a list of tiers of announces";
//! order preserved within a tier, entry-level tolerance — only a fully
//! broken table is Malformed). With no announce at all the parse face
//! accepts an empty string (structure parsing and intake policy are
//! separate — the parse layer does not know the DHT switch); the stall
//! hint is conditional in the intake gate [`Metainfo::check_intake`]
//! (no tracker and DHT off = accept + WARN guidance).
//! - BEP19 webseed: the top-level `url-list` is parsed in both shapes
//! (single string / list; http(s) only, entries leniently skipped) into
//! [`Metainfo::url_list`], projected onto the engine config's webseeds
//! field (the `--enable-http-seeding` / `enable-http-seeding` switch
//! clears it on the assembly/activation chain; this layer always
//! projects the original values).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use bytes::Bytes;
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use thiserror::Error;

use taiji_bt::bencode::{self, BencodeError, Value};
use taiji_bt::filetree::{self, FileTreeError, SwarmKind, TorrentFiles};
use taiji_store::layout::{Layout, LayoutError, PlanEntry};

/// Metainfo parsing/assembly error.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MetainfoError {
    #[error("bencode decode failed: {0}")]
    Decode(#[from] BencodeError),
    #[error("metainfo structure invalid: {0}")]
    Structure(#[from] FileTreeError),
    #[error("hybrid dual-view mismatch: {0}")]
    HybridMismatch(#[from] HybridMismatch),
    // The former `NoAnnounce` rejection variant is gone with the intake
    // gate flip: no tracker plus DHT off is accepted + WARN (guidance in
    // the WARN text; see `Metainfo::check_intake`).
    #[error("`announce-list` entry is not a list of byte strings")]
    MalformedAnnounceList,
    #[error("`url-list` is neither a byte string nor a list of byte strings")]
    MalformedUrlList,
    #[error("announce URL is not valid UTF-8")]
    InvalidAnnounceEncoding,
    #[error("v1 pieces hash unavailable (v2-only torrent has no v1 face)")]
    NoV1Pieces,
    #[error("v2 identity unavailable (v1-only torrent has no v2 face)")]
    NoV2Identity,
    #[error("v1 pieces count mismatch: got {got} hashes, layout needs {expected}")]
    PiecesCountMismatch { got: usize, expected: usize },
    #[error("`pieces` length {0} is not a multiple of 20 (SHA-1)")]
    PiecesNotMultipleOfSha1(usize),
    #[error("layout planning failed: {0}")]
    Layout(#[from] LayoutError),
    #[error(
        "v1 piece {index} maps into a padding file region (hybrid layout misalignment: BEP52 requires piece-aligned files)"
    )]
    MisalignedHybridLayout { index: u64 },
    #[error("file {path:?} not found in disk layout (metadata/layout inconsistent)")]
    FileNotInLayout { path: PathBuf },
    #[error("v2 file {path:?}: piece layer missing or malformed for {pieces} pieces")]
    BadPieceLayer { path: PathBuf, pieces: usize },
    #[error(
        "hybrid face piece count mismatch: v1 {v1} != v2 {v2} (BEP52 alignment invariant broken)"
    )]
    FacePieceCountMismatch { v1: usize, v2: usize },
    #[error(
        "piece budget exceeded: torrent declares {pieces} pieces, max {max} (piece-vector allocation cap)"
    )]
    PieceBudgetExceeded { pieces: u64, max: u64 },
}

/// Hybrid dual-representation mismatch (reject on load).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HybridMismatch {
    #[error("v1 file {path:?} not found in v2 file tree view")]
    V1FileMissingFromTree { path: PathBuf },
    #[error("length mismatch for {path:?}: v1 {v1} != v2 {v2}")]
    LengthMismatch { path: PathBuf, v1: u64, v2: u64 },
    #[error("v1 first file must start at offset 0, got {0}")]
    FirstOffsetNotZero(u64),
    #[error("v1 offset {offset} goes backwards at {path:?} (previous end {prev})")]
    OffsetRegression {
        path: PathBuf,
        offset: u64,
        prev: u64,
    },
}

/// Dual infohash (both over the raw info slice; a side absent from the
/// factual face is None).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TorrentIdentity {
    /// SHA-1(info slice): used by v1/hybrid handshake and announce (BEP3).
    pub v1: Option<[u8; 20]>,
    /// SHA-256(info slice): v2/hybrid identity (BEP52; the wire uses the
    /// truncated 20 bytes).
    pub v2: Option<[u8; 32]>,
}

/// Unified file entry (hybrid dual-view join).
#[derive(Debug, Clone)]
pub struct MetaFile {
    /// Sanitized relative path (same sanitization rule in both views).
    pub path: PathBuf,
    pub length: u64,
    /// BEP47 padding (`true` only appears in v1-only lists; the hybrid/v2
    /// primary view has no pad entries — hybrid pads are derived from
    /// `v1_offset` deltas, see [`TorrentMeta::plan_entries`]).
    pub padding: bool,
    /// Required for non-empty v2 files (BEP52); None for v1 files.
    pub pieces_root: Option<[u8; 32]>,
    /// Piece layer carried by the metadata (trusted; None for files with
    /// <= 1 piece).
    pub piece_layer: Option<Bytes>,
    /// v1/hybrid: global offset in the v1 layout (pad placeholders
    /// included).
    pub v1_offset: Option<u64>,
}

impl MetaFile {
    /// Marker for a missing `piece layers` entry (the runtime projection of
    /// bt::filetree's `FileEntry::layer_missing`). The parse face sets it
    /// only for "multiple pieces + root present + entry missing"; all three
    /// facts derive from the same source, so no extra storage is needed. A
    /// layer that is **present but fails verification** is hard-rejected at
    /// parse time and never reaches this struct.
    pub fn layer_missing(&self, piece_len: u32) -> bool {
        self.pieces_root.is_some()
            && self.piece_layer.is_none()
            && self.length > u64::from(piece_len)
    }
}

/// Unified metadata (kind + dual infohash + joined file view + layout
/// planning).
#[derive(Debug, Clone)]
pub struct TorrentMeta {
    pub identity: TorrentIdentity,
    pub kind: SwarmKind,
    /// Globally uniform piece length. v2/hybrid faces: power of two and >=
    /// 16 KiB (BEP52, checked by `filetree::parse`); v1-only: any
    /// positive integer (BEP3 has no power-of-two/minimum constraint;
    /// `parse_v1_files` dispatches per face).
    pub piece_length: u32,
    /// File list: v2-only/hybrid = DFS order (no pad entries); v1-only =
    /// v1 list order (pad entries included).
    pub files: Vec<MetaFile>,
}

impl TorrentMeta {
    /// Layout total (sum of primary-view file lengths; v1-only includes
    /// pad entry lengths).
    pub fn total_len(&self) -> u64 {
        self.files.iter().map(|f| f.length).sum()
    }

    /// Layout planning input (dispatched by kind):
    /// - v1-only: the list as-is (pad entries are pads);
    /// - hybrid: DFS files placed at their `v1_offset`, inter-file pads
    /// derived from offset deltas (BEP47 path `[".pad", "N"]`);
    /// alignment legality is checked by `Layout::plan_v1_padded`;
    /// - v2-only: compact contiguous (no pads).
    pub fn plan_entries(&self) -> Result<Vec<PlanEntry>, MetainfoError> {
        match self.kind {
            SwarmKind::V1Only => Ok(self
                .files
                .iter()
                .map(|f| PlanEntry {
                    path: f.path.clone(),
                    length: f.length,
                    padding: f.padding,
                })
                .collect()),
            SwarmKind::Hybrid => {
                let mut entries: Vec<PlanEntry> = Vec::new();
                let mut prev_end: Option<u64> = None;
                for f in &self.files {
                    let off = f.v1_offset.ok_or(HybridMismatch::V1FileMissingFromTree {
                        path: f.path.clone(),
                    })?;
                    match prev_end {
                        None => {
                            if off != 0 {
                                return Err(MetainfoError::HybridMismatch(
                                    HybridMismatch::FirstOffsetNotZero(off),
                                ));
                            }
                        }
                        Some(prev) => {
                            if off < prev {
                                return Err(MetainfoError::HybridMismatch(
                                    HybridMismatch::OffsetRegression {
                                        path: f.path.clone(),
                                        offset: off,
                                        prev,
                                    },
                                ));
                            }
                            if off > prev {
                                // Pad placeholder: length = slack up to the
                                // next file's start (alignment checked by
                                // plan_v1_padded).
                                entries.push(PlanEntry {
                                    path: PathBuf::from(format!(".pad/{}", off - prev)),
                                    length: off - prev,
                                    padding: true,
                                });
                            }
                        }
                    }
                    entries.push(PlanEntry {
                        path: f.path.clone(),
                        length: f.length,
                        padding: false,
                    });
                    prev_end = Some(off + f.length);
                }
                Ok(entries)
            }
            SwarmKind::V2Only => Ok(self
                .files
                .iter()
                .map(|f| PlanEntry {
                    path: f.path.clone(),
                    length: f.length,
                    padding: false,
                })
                .collect()),
        }
    }

    /// Layout planning (kind dispatch: v1/hybrid -> v1 layout, v2-only ->
    /// compact).
    ///
    /// The path view is the metadata (wire) view: **no** `info.name`
    /// directory prefix — consumers of this method's path matching
    /// (`Layout::find` <-> `MetaFile.path`, the hash service's file-face
    /// offset backfill) rely on both views having the same shape. The disk
    /// view applies the prefix in [`Metainfo::disk_layout`].
    pub fn layout(&self) -> Result<Layout, MetainfoError> {
        let entries = self.plan_entries()?;
        let layout = match self.kind {
            SwarmKind::V2Only => Layout::plan_v2_compact(&entries, self.piece_length)?,
            SwarmKind::V1Only | SwarmKind::Hybrid => {
                Layout::plan_v1_padded(&entries, self.piece_length)?
            }
        };
        Ok(layout)
    }
}

/// Parsed metainfo (unified model + announce + v1 piece hashes + raw info
/// bytes).
impl Metainfo {
    /// In-memory residency estimate (the metering source for the
    /// queued-metadata budget; a rough upper bound suffices —
    /// overestimating only trips the cap earlier, never wrongly passes):
    /// v1 hash string 20B/piece + announce/webseed strings + file rows
    /// (path + v2 layer hash) + structural slack.
    pub fn resident_estimate_bytes(&self) -> usize {
        let mut n = 64 + self.announce.len() + self.v1_pieces.len() * 20;
        for tier in &self.announce_tiers {
            n += 16 + tier.iter().map(|u| u.len() + 16).sum::<usize>();
        }
        for u in &self.url_list {
            n += u.len() + 16;
        }
        for f in &self.meta.files {
            n += 96
                + f.path.as_os_str().len()
                + f.pieces_root.map_or(0, |_| 32)
                + f.piece_layer.as_ref().map_or(0, |b| b.len());
        }
        n
    }
}

#[derive(Debug, Clone)]
pub struct Metainfo {
    pub meta: TorrentMeta,
    /// announce URL (`announce` first, falling back to the first usable
    /// `announce-list` entry). **Empty string = no tracker** (when both
    /// keys are missing the parse face accepts an empty string; whether to
    /// reject is decided by the intake gate based on the DHT switch — no
    /// URL is fabricated).
    pub announce: String,
    /// Full BEP12 tier table: with the `announce` key present -> single
    /// tier `[announce]`; otherwise collected tier by tier from
    /// `announce-list` (order preserved within a tier; non-list tiers /
    /// non-Bytes / non-UTF-8 entries skipped one by one, empty tiers
    /// dropped). Only a table with no usable URL yields
    /// [`MetainfoError::MalformedAnnounceList`] (reject only on total
    /// corruption; error layering follows [`Self::announce`] extraction).
    /// Both keys missing -> empty table (pure-DHT intake form). BEP12
    /// "a list of tiers of announces": a tier is a failover group (any
    /// usable URL makes the group usable); intake must not collapse it to
    /// the first URL. The empty announce string sentinel also maps to an
    /// empty table (no tracker, no fabricated tier).
    pub announce_tiers: Vec<Vec<String>>,
    /// BEP19 webseed URL set (top-level `url-list`; both shapes accepted —
    /// single string (Bytes) and string list (List), BEP19 "url-list ...
    /// can be either a string containing a single URL or a list of
    /// strings"). http/https only (non-http schemes and non-string /
    /// non-UTF-8 entries in the list are leniently skipped — nothing
    /// outside the HTTP semantic face consumes them). A field present but
    /// wholly mis-shaped (Int/Dict) -> [`MetainfoError::MalformedUrlList`]
    /// (same precedent as `MalformedAnnounceList`: metadata defects are
    /// switch-independent, both arms reject). Empty = no webseed. The
    /// engine projection is the engine config's webseeds field (cleared on
    /// the assembly/activation chain when `--enable-http-seeding` is off —
    /// this table keeps the original values, so toggling is lossless).
    pub url_list: Vec<String>,
    /// v1 whole-piece SHA-1 string (`info.pieces`, 20B x piece count;
    /// empty for v2-only).
    pub v1_pieces: Vec<[u8; 20]>,
    /// BEP27 private flag (`info.private` = 1; true -> the DHT-side gate
    /// disabling DHT/PEX/LSD). Missing / non-1 = public.
    pub private: bool,
    /// `info.name` (sanitized; `name.utf-8` preferred, falling back to
    /// `name`, same rule as reference `bittorrent_helper.cc`). None = not
    /// provided by the metadata (no name is fabricated — aria2's
    /// "<infohash>.file" fallback belongs to its orchestration face; not
    /// done here).
    ///
    /// BEP3 "name" semantics: single file = the file name (already the
    /// path itself); multi-file = the root directory name, `files[].path`
    /// relative to it — on disk `<dir>/<name>/...` (aria2's
    /// `bittorrent_helper.cc` splices the name as the first path element;
    /// rqbit/libtorrent share the convention). Dropping the name layer for
    /// multi-file (flat layout) was a real defect, corrected in
    /// [`Metainfo::disk_layout`].
    pub name: Option<String>,
    /// Multi-file form (BEP3: the v1 `files` list present = multi-file;
    /// v2-only decided by file-tree output count > 1 — a single-file file
    /// tree's root key is the `name`, the path already contains it).
    pub multi_file: bool,
    /// Raw info dict bytes (the BEP9 ut_metadata serving-face carrier;
    /// magnet-rebuilt .torrents carry it too, shared by disk and serving).
    pub info_bytes: Bytes,
}

impl Metainfo {
    /// Parses .torrent bytes (all three swarm kinds supported).
    pub fn parse(bytes: &[u8]) -> Result<Metainfo, MetainfoError> {
        let (top, info_span) = bencode::decode_with_info_span(bytes)?;
        let info_bytes = Bytes::copy_from_slice(&bytes[info_span]);
        // Both infohashes over the raw info slice (BEP52; never
        // decode->re-encode).
        let v1_hash: [u8; 20] = Sha1::digest(info_bytes.as_ref()).into();
        let v2_hash: [u8; 32] = Sha256::digest(info_bytes.as_ref()).into();
        let raw_identity = TorrentIdentity {
            v1: Some(v1_hash),
            v2: Some(v2_hash),
        };

        let kind = filetree::detect_swarm_kind(&top)?;
        let (announce, announce_tiers) = extract_announce_tables(&top)?;
        let url_list = extract_url_list(&top)?;
        let parsed = parse_files(&top, kind)?;
        // BEP27 private: integer 1 inside the info dict (any other value /
        // missing = public).
        let private = top
            .get(b"info")
            .and_then(|info| info.get(b"private"))
            .is_some_and(|v| matches!(v, bencode::Value::Int(1)));
        // `info.name`: `name.utf-8` preferred, falling back to `name`
        // (BEP3; same rule as reference `bittorrent_helper.cc`), sanitized
        // with the file-tree component's rule. None = not provided (no
        // fabricated name; multi-file disk layout falls back to flat).
        let info = top
            .get(b"info")
            .ok_or(FileTreeError::NoFileTree)
            .map_err(MetainfoError::Structure)?;
        let name = match info
            .get(b"name.utf-8")
            .or_else(|| info.get(b"name"))
            .and_then(bencode::Value::as_bytes)
        {
            Some(raw) => Some(filetree::sanitize_info_name(raw).map_err(MetainfoError::Structure)?),
            None => None,
        };
        // Multi-file decision (BEP3): the v1 `files` list present =
        // multi-file (single file = `length` scalar); v2-only has no v1
        // key, decided by file-tree output count > 1 (a single-file tree's
        // root key is the `name`, the path already contains it).
        let multi_file = match kind {
            SwarmKind::V1Only | SwarmKind::Hybrid => info.get(b"files").is_some(),
            SwarmKind::V2Only => parsed.files.len() > 1,
        };

        Ok(Metainfo {
            meta: TorrentMeta {
                identity: kind_identity(kind, raw_identity),
                kind,
                piece_length: parsed.piece_length,
                files: parsed.files,
            },
            name,
            multi_file,
            announce,
            announce_tiers,
            url_list,
            v1_pieces: parsed.v1_pieces,
            private,
            info_bytes,
        })
    }

    /// Intake gate: a missing discovery source no longer rejects — accept
    /// plus WARN guidance (the stalled-state recovery paths are complete).
    ///
    /// Returns `Some(warn)` = no tracker (empty `announce`) and DHT off —
    /// the task is accepted but currently has no discovery source and will
    /// stall; `None` = normal acceptance (has a tracker, or no tracker but
    /// DHT on = pure-DHT discovery face — the BEP5 announce/lookup
    /// pipeline is proven on the magnet path).
    ///
    /// The WARN text gives actionable guidance, revive-without-restart
    /// paths first: hot-enable DHT (`changeGlobalOption("enable-dht",
    /// "true")`; per-task override `bt-disable-dht=false`), add trackers
    /// (`taiji.addTracker` / `changeGlobalOption("bt-tracker", ...)`), or
    /// restart the session with DHT on.
    ///
    /// Upstream alignment: aria2 (`RequestGroup.cc`) never rejects DHT-off
    /// plus no tracker (only NOTICE — accepts and then stalls for lack of
    /// discovery sources); libtorrent never rejects at intake
    /// (`should_announce_dht` with DHT off merely silences the announce
    /// face). Accept + WARN matches both references and keeps hot-enable
    /// revival reachable (a rejected task would not exist to operate on).
    ///
    /// Why the gate sits at the consumption point rather than
    /// parameterizing parse: `Metainfo::parse` is a pure structure face
    /// (30+ call sites: tests, seeding re-reads, imports, restart
    /// rebuilds) and holds no DHT switch; parameterizing it would change
    /// every signature and couple structure validation to session options.
    /// Intake is a policy decision belonging to consumers that hold
    /// `enable_dht` (the CLI download entry and session addTorrent/URL
    /// fetch); both entries share this method and stay consistent.
    /// Restart-rebuild/import paths skip the gate (previously accepted
    /// tasks are not re-rejected by a new session's DHT switch; aria2
    /// likewise does not re-run intake validation at startup).
    ///
    /// The BEP27 interaction gate is not here: disabling DHT for private
    /// plus DHT-on is held by the engine interaction face (the engine
    /// config's private field -> DHT announce/lookup gate plus a runtime
    /// enable hard gate); this method only produces the intake hint.
    pub fn check_intake(&self, dht_enabled: bool) -> Option<String> {
        if self.announce.is_empty() && !dht_enabled {
            return Some(
                "no announce URL (announce / announce-list both missing) and DHT is \
                 disabled: task accepted but has no discovery source and will stall. \
                 To revive without restarting the session: changeGlobalOption \
                 \"enable-dht\"=\"true\" (per-task override: changeOption \
                 \"bt-disable-dht\"=\"false\"), or add trackers (taiji.addTracker / \
                 changeGlobalOption \"bt-tracker\"), or restart with --enable-dht=true"
                    .to_string(),
            );
        }
        None
    }

    /// Disk (on-disk) view layout: when multi-file and `name` is present,
    /// every file path is prefixed with `<name>/` (BEP3 files[].path is
    /// relative to the name directory; reference `bittorrent_helper.cc`
    /// splices the name as the first path element; a single file is the
    /// name itself, no prefix). Pad placeholder entries get the prefix too
    /// (never written to disk, BEP47; keeps the views consistent).
    /// Single file / unnamed = same shape as the wire view. Offsets and
    /// totals are identical to [`TorrentMeta::layout`] (the prefix only
    /// changes paths).
    pub fn disk_layout(&self) -> Result<Layout, MetainfoError> {
        let layout = self.meta.layout()?;
        match (&self.name, self.multi_file) {
            (Some(dir), true) => {
                let entries: Vec<PlanEntry> = layout
                    .files()
                    .iter()
                    .map(|f| PlanEntry {
                        path: Path::new(dir).join(&f.path),
                        length: f.length,
                        padding: f.padding,
                    })
                    .collect();
                Ok(match self.meta.kind {
                    SwarmKind::V2Only => Layout::plan_v2_compact(&entries, self.meta.piece_length)?,
                    SwarmKind::V1Only | SwarmKind::Hybrid => {
                        Layout::plan_v1_padded(&entries, self.meta.piece_length)?
                    }
                })
            }
            _ => Ok(layout),
        }
    }
}

/// Trims the identity by kind (a side absent from the factual face is
/// None; no leftover computed hash is kept).
fn kind_identity(kind: SwarmKind, id: TorrentIdentity) -> TorrentIdentity {
    match kind {
        SwarmKind::V1Only => TorrentIdentity {
            v1: id.v1,
            v2: None,
        },
        SwarmKind::V2Only => TorrentIdentity {
            v1: None,
            v2: id.v2,
        },
        SwarmKind::Hybrid => id,
    }
}

/// File-view parse product (piece_length + joined file list + v1 piece
/// hashes).
struct ParsedFiles {
    piece_length: u32,
    files: Vec<MetaFile>,
    v1_pieces: Vec<[u8; 20]>,
}

/// Parses the file view by kind (v1 list / v2 DFS / hybrid join).
fn parse_files(top: &Value, kind: SwarmKind) -> Result<ParsedFiles, MetainfoError> {
    let info = top
        .get(b"info")
        .ok_or(FileTreeError::NoFileTree)
        .map_err(MetainfoError::Structure)?;
    // v1 piece hashes (v1-only/hybrid); v2-only has no such face.
    let v1_pieces: Vec<[u8; 20]> = match info.get(b"pieces").and_then(Value::as_bytes) {
        None if kind == SwarmKind::V2Only => Vec::new(),
        None => return Err(MetainfoError::NoV1Pieces),
        Some(raw) => {
            if raw.len() % 20 != 0 {
                return Err(MetainfoError::PiecesNotMultipleOfSha1(raw.len()));
            }
            let mut out = Vec::with_capacity(raw.len() / 20);
            for c in raw.chunks_exact(20) {
                // chunks_exact(20) guarantees the length; map_err just
                // avoids a panic-based conversion.
                let arr: [u8; 20] = c
                    .try_into()
                    .map_err(|_| MetainfoError::PiecesNotMultipleOfSha1(raw.len()))?;
                out.push(arr);
            }
            out
        }
    };

    let parsed = match kind {
        SwarmKind::V1Only => {
            let TorrentFiles {
                piece_length,
                files: v1_files,
            } = filetree::parse_v1_files(top)?;
            ParsedFiles {
                piece_length,
                files: v1_files
                    .into_iter()
                    .map(|f| MetaFile {
                        path: f.path,
                        length: f.length,
                        padding: f.attr.padding,
                        pieces_root: None,
                        piece_layer: None,
                        v1_offset: f.v1_offset,
                    })
                    .collect(),
                v1_pieces,
            }
        }
        SwarmKind::V2Only => {
            let TorrentFiles {
                piece_length,
                files: v2_files,
            } = filetree::parse(top)?;
            ParsedFiles {
                piece_length,
                files: v2_files
                    .into_iter()
                    .map(|f| MetaFile {
                        path: f.path,
                        length: f.length,
                        padding: false,
                        pieces_root: f.pieces_root,
                        piece_layer: f.piece_layer,
                        v1_offset: None,
                    })
                    .collect(),
                v1_pieces,
            }
        }
        SwarmKind::Hybrid => {
            // The v2 view is primary (DFS order + root/layer); the v1 view
            // joins v1_offset. Order/length agreement between the views is
            // inherent to the same bytes' dual representation (mismatch
            // rejects).
            let v2_view = filetree::parse(top)?;
            let v1_view = filetree::parse_v1_files(top)?;
            if v2_view.piece_length != v1_view.piece_length {
                // Same key of the same info dict; defensive rejection.
                return Err(MetainfoError::HybridMismatch(
                    HybridMismatch::LengthMismatch {
                        path: PathBuf::from("<piece_length>"),
                        v1: u64::from(v1_view.piece_length),
                        v2: u64::from(v2_view.piece_length),
                    },
                ));
            }
            let v1_by_path: BTreeMap<PathBuf, &filetree::FileEntry> = v1_view
                .files
                .iter()
                .filter(|f| !f.attr.padding)
                .map(|f| (f.path.clone(), f))
                .collect();
            if v1_by_path.len() != v2_view.files.len() {
                // Reverse consistency: a v1 file with no file-tree
                // counterpart = corrupted metadata.
                if let Some((path, _)) = v1_by_path
                    .iter()
                    .find(|(p, _)| !v2_view.files.iter().any(|f| &f.path == *p))
                {
                    return Err(MetainfoError::HybridMismatch(
                        HybridMismatch::V1FileMissingFromTree { path: path.clone() },
                    ));
                }
            }
            let mut joined = Vec::with_capacity(v2_view.files.len());
            for f in &v2_view.files {
                let v1f = v1_by_path
                    .get(&f.path)
                    .ok_or(HybridMismatch::V1FileMissingFromTree {
                        path: f.path.clone(),
                    })?;
                if v1f.length != f.length {
                    return Err(MetainfoError::HybridMismatch(
                        HybridMismatch::LengthMismatch {
                            path: f.path.clone(),
                            v1: v1f.length,
                            v2: f.length,
                        },
                    ));
                }
                joined.push(MetaFile {
                    path: f.path.clone(),
                    length: f.length,
                    padding: false,
                    pieces_root: f.pieces_root,
                    piece_layer: f.piece_layer.clone(),
                    v1_offset: v1f.v1_offset,
                });
            }
            ParsedFiles {
                piece_length: v2_view.piece_length,
                files: joined,
                v1_pieces,
            }
        }
    };
    Ok(parsed)
}

/// Extracts the announce face: `(single-URL surface, full tier table)`,
/// both products from one pass, always consistent.
///
/// - `announce` key present and Bytes -> `([announce], [[announce]])`
/// (BEP3 single-tracker semantics); non-UTF-8 ->
/// [`MetainfoError::InvalidAnnounceEncoding`] (an encoding defect of
/// the announce key itself = hard reject, DHT-switch independent);
/// empty-string sentinel (key present but empty bytes) -> both products
/// empty (no tracker, no fabricated tier; no fallback to announce-list
/// — announce-key priority preserved).
/// - Otherwise `announce-list` (BEP12 "a list of tiers of announces"):
/// whole field not a List -> [`MetainfoError::MalformedAnnounceList`];
/// per tier, Bytes and UTF-8 entries are collected (order preserved
/// within a tier; non-list tiers, non-Bytes / non-UTF-8 entries skipped
/// one by one, empty tiers dropped — matching AnnounceList reconfigure
/// skipping empty groups); no usable URL in the whole table ->
/// `MalformedAnnounceList` (reject only on total corruption). The
/// single-URL surface = the first URL of the first usable tier (legacy
/// `announce` first-URL fallback).
/// - Both keys missing -> `("", [])` (empty string = no-tracker sentinel;
/// the parse face makes no intake policy decision, the DHT switch is
/// not this layer).
fn extract_announce_tables(top: &Value) -> Result<(String, Vec<Vec<String>>), MetainfoError> {
    if let Some(Value::Bytes(url)) = top.get(b"announce") {
        let announce =
            String::from_utf8(url.clone()).map_err(|_| MetainfoError::InvalidAnnounceEncoding)?;
        if announce.is_empty() {
            return Ok((String::new(), Vec::new()));
        }
        return Ok((announce.clone(), vec![vec![announce]]));
    }
    let Some(list) = top.get(b"announce-list") else {
        return Ok((String::new(), Vec::new()));
    };
    let Value::List(tiers) = list else {
        return Err(MetainfoError::MalformedAnnounceList);
    };
    let mut collected: Vec<Vec<String>> = Vec::new();
    for tier in tiers {
        let Value::List(urls) = tier else {
            continue;
        };
        let urls: Vec<String> = urls
            .iter()
            .filter_map(Value::as_bytes)
            .filter_map(|b| String::from_utf8(b.to_vec()).ok())
            .collect();
        if !urls.is_empty() {
            collected.push(urls);
        }
    }
    if collected.is_empty() {
        return Err(MetainfoError::MalformedAnnounceList);
    }
    let announce = collected
        .first()
        .and_then(|tier| tier.first())
        .cloned()
        .unwrap_or_default();
    Ok((announce, collected))
}

/// Extracts the BEP19 webseed set: the top-level `url-list` in both
/// shapes — `Bytes` (single string) and `List` (string list) both
/// accepted (BEP19 allows both encodings).
///
/// Lenient face (entry-level skips, no rejection): non-Bytes / non-UTF-8
/// entries in the list, URLs with non-http(s) schemes — nothing outside
/// the HTTP semantic face (webseeds are always HTTP(S) GET Range)
/// consumes them, so skip per entry (aria2 likewise only mounts HTTP
/// download faces for url-list entries). Field missing = `Ok(vec![])`
/// (no webseed; sentinel semantics like the empty announce string —
/// presence of discovery sources is proven by the swarm face, not decided
/// here).
///
/// Hard-reject face (whole-field shape): field present but neither Bytes
/// nor List (Int/Dict) -> [`MetainfoError::MalformedUrlList`] — metadata
/// defects are switch-independent (same precedent as
/// `MalformedAnnounceList`: structural corruption is not excused by
/// discovery-source redundancy).
fn extract_url_list(top: &Value) -> Result<Vec<String>, MetainfoError> {
    let Some(field) = top.get(b"url-list") else {
        return Ok(Vec::new());
    };
    /// http/https scheme check (case-insensitive — RFC 3986 §3.1 scheme
    /// syntax is case-equivalent; BEP19 webseeds are always HTTP
    /// semantics).
    fn is_http_url(s: &str) -> bool {
        s.split_once("://").is_some_and(|(scheme, _)| {
            scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
        })
    }
    match field {
        // Single-string form (BEP19): equivalent to a [url] list;
        // non-http(s) skipped (empty set).
        Value::Bytes(b) => Ok(String::from_utf8(b.clone())
            .ok()
            .filter(|s| is_http_url(s))
            .map(|s| vec![s])
            .unwrap_or_default()),
        Value::List(entries) => Ok(entries
            .iter()
            .filter_map(|e| e.as_bytes())
            .filter_map(|b| String::from_utf8(b.to_vec()).ok())
            .filter(|s| is_http_url(s))
            .collect()),
        _ => Err(MetainfoError::MalformedUrlList),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use taiji_bt::bencode;

    /// Single-file contrast: the v1 single file (name = file name) disk
    /// view has no prefix; v2-only single file (file tree root key is the
    /// name) the same; unnamed metadata gets no fabricated prefix.
    #[test]
    fn disk_layout_single_file_stays_flat() {
        let info = dict(vec![
            (b"name", Value::Bytes(b"blob.bin".to_vec())),
            (b"length", Value::Int(16384)),
            (b"piece length", Value::Int(16384)),
            (b"pieces", Value::Bytes(vec![0xAA; 20])),
        ]);
        let top = dict(vec![
            (b"announce", Value::Bytes(b"http://t.invalid".to_vec())),
            (b"info", info),
        ]);
        let raw = bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"));
        let m = Metainfo::parse(&raw).unwrap_or_else(|e| panic!("parse: {e}"));
        assert!(!m.multi_file);
        let disk = m.disk_layout().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(disk.files()[0].path, std::path::Path::new("blob.bin"));
    }

    /// Hybrid dual-view mismatch (the v1 list has a file absent from the
    /// file tree) -> reject.
    #[test]
    fn hybrid_view_mismatch_rejected() {
        let tree = Value::Dict(vec![(
            b"a.bin".to_vec(),
            Value::Dict(vec![(
                b"".to_vec(),
                Value::Dict(vec![
                    (b"length".to_vec(), Value::Int(16384)),
                    (b"pieces root".to_vec(), Value::Bytes(vec![0xaa; 32])),
                ]),
            )]),
        )]);
        let info = dict(vec![
            (
                b"files",
                Value::List(vec![
                    dict(vec![
                        (b"length", Value::Int(16384)),
                        (b"path", Value::List(vec![Value::Bytes(b"a.bin".to_vec())])),
                    ]),
                    dict(vec![
                        (b"length", Value::Int(1)),
                        (
                            b"path",
                            Value::List(vec![Value::Bytes(b"ghost.bin".to_vec())]),
                        ),
                    ]),
                ]),
            ),
            (b"file tree", tree),
            (b"meta version", Value::Int(2)),
            (b"piece length", Value::Int(16384)),
            (b"pieces", Value::Bytes(vec![0u8; 20])),
        ]);
        let top = dict(vec![
            (b"announce", Value::Bytes(b"http://t.invalid".to_vec())),
            (b"info", info),
        ]);
        let raw = bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(
            Metainfo::parse(&raw),
            Err(MetainfoError::HybridMismatch(
                HybridMismatch::V1FileMissingFromTree { .. }
            ))
        ));
    }

    /// announce-list present but structurally broken (no URL entries)
    /// still rejects — metadata defects are DHT-switch independent (gate
    /// conditioning does not relax structure validation).
    #[test]
    fn malformed_announce_list_still_rejected() {
        let info = dict(vec![
            (b"length", Value::Int(1)),
            (b"name", Value::Bytes(b"x".to_vec())),
            (b"piece length", Value::Int(16384)),
            (b"pieces", Value::Bytes(vec![0u8; 20])),
        ]);
        let top = dict(vec![
            (b"announce-list", Value::List(vec![])),
            (b"info", info),
        ]);
        let raw = bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(
            Metainfo::parse(&raw),
            Err(MetainfoError::MalformedAnnounceList)
        ));
    }

    /// Minimal valid info (v1 single file; shared by announce-face tests).
    fn announce_test_info() -> Value {
        dict(vec![
            (b"length", Value::Int(1)),
            (b"name", Value::Bytes(b"x".to_vec())),
            (b"piece length", Value::Int(16384)),
            (b"pieces", Value::Bytes(vec![0u8; 20])),
        ])
    }

    /// BEP12 full tier extraction — announce-list=[[u1,u2],[u3]] -> tiers
    /// length 2, order preserved within a tier (BEP12 "a list of tiers of
    /// announces"; a tier = failover group: any usable URL makes the group
    /// usable). The legacy `announce` surface is unchanged (first-URL
    /// fallback).
    #[test]
    fn announce_tiers_collects_full_bep12_tiers() {
        let top = dict(vec![
            (
                b"announce-list",
                Value::List(vec![
                    Value::List(vec![
                        Value::Bytes(b"http://u1.invalid/announce".to_vec()),
                        Value::Bytes(b"http://u2.invalid/announce".to_vec()),
                    ]),
                    Value::List(vec![Value::Bytes(b"http://u3.invalid/announce".to_vec())]),
                ]),
            ),
            (b"info", announce_test_info()),
        ]);
        let raw = bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"));
        let m = Metainfo::parse(&raw).unwrap_or_else(|e| panic!("parse: {e}"));
        assert_eq!(
            m.announce_tiers.len(),
            2,
            "two tiers, not a single one-tier URL"
        );
        assert_eq!(
            m.announce_tiers,
            vec![
                vec![
                    "http://u1.invalid/announce".to_string(),
                    "http://u2.invalid/announce".to_string()
                ],
                vec!["http://u3.invalid/announce".to_string()],
            ],
            "order preserved within a tier (BEP12 tier sequence semantics)"
        );
        assert_eq!(
            m.announce, "http://u1.invalid/announce",
            "legacy semantics unchanged"
        );
    }

    /// Companion: top-level announce present -> single tier [announce]
    /// (BEP3 single-tracker semantics; matches the legacy announce-first
    /// branch); both keys missing -> empty tiers (pure-DHT intake form).
    #[test]
    fn announce_tiers_single_announce_and_missing_forms() {
        let top = dict(vec![
            (
                b"announce",
                Value::Bytes(b"http://top.invalid/announce".to_vec()),
            ),
            (
                b"announce-list",
                Value::List(vec![Value::List(vec![Value::Bytes(
                    b"http://list.invalid/announce".to_vec(),
                )])]),
            ),
            (b"info", announce_test_info()),
        ]);
        let raw = bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"));
        let m = Metainfo::parse(&raw).unwrap_or_else(|e| panic!("parse: {e}"));
        assert_eq!(
            m.announce_tiers,
            vec![vec!["http://top.invalid/announce".to_string()]],
            "announce key present -> single tier [announce]"
        );

        let top = dict(vec![(b"info", announce_test_info())]);
        let raw = bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"));
        let m = Metainfo::parse(&raw).unwrap_or_else(|e| panic!("parse: {e}"));
        assert!(
            m.announce_tiers.is_empty(),
            "both keys missing -> empty tiers"
        );
    }

    /// Companion: announce-list entry-level tolerance — non-list tiers,
    /// non-Bytes entries, non-UTF-8 entries skipped one by one (empty
    /// tiers dropped); Malformed only when the whole table has no usable
    /// URL (error layering consistent with the legacy extract_announce).
    #[test]
    fn announce_tiers_entry_level_tolerance() {
        let top = dict(vec![
            (
                b"announce-list",
                Value::List(vec![
                    // Non-list tier: skipped.
                    Value::Bytes(b"http://not-a-tier.invalid/announce".to_vec()),
                    // Mixed-entry tier: Int skipped, non-UTF-8 skipped,
                    // URL collected.
                    Value::List(vec![
                        Value::Int(7),
                        Value::Bytes(vec![0xff, 0xfe]),
                        Value::Bytes(b"http://u1.invalid/announce".to_vec()),
                    ]),
                    // All-bad tier: dropped (no empty tier kept).
                    Value::List(vec![Value::Int(1)]),
                    Value::List(vec![Value::Bytes(b"http://u2.invalid/announce".to_vec())]),
                ]),
            ),
            (b"info", announce_test_info()),
        ]);
        let raw = bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"));
        let m = Metainfo::parse(&raw).unwrap_or_else(|e| panic!("parse: {e}"));
        assert_eq!(
            m.announce_tiers,
            vec![
                vec!["http://u1.invalid/announce".to_string()],
                vec!["http://u2.invalid/announce".to_string()],
            ],
            "bad entries skipped, empty tiers dropped"
        );
    }

    /// v1-only face relaxed piece length (BEP3 vs BEP52 text difference).
    ///
    /// BEP3 puts no power-of-two/minimum constraint on `piece length`
    /// ("number of bytes in each piece"); "power of two and at least
    /// 16KiB" (BEP52) only constrains the v2 file tree's merkle leaf
    /// math. Legacy v1 torrents (20000/8192 shapes) load successfully;
    /// hybrid with the same value still rejects (the same key feeds the
    /// v2 face, constraint unchanged).
    #[test]
    fn v1_only_relaxed_piece_length_loads() {
        // 20000 (not a power of two), multi-piece multi-file v1-only:
        // total 60000 -> 3 pieces.
        let info = dict(vec![
            (
                b"files",
                Value::List(vec![
                    dict(vec![
                        (b"length", Value::Int(30000)),
                        (b"path", Value::List(vec![Value::Bytes(b"a.bin".to_vec())])),
                    ]),
                    dict(vec![
                        (b"length", Value::Int(30000)),
                        (b"path", Value::List(vec![Value::Bytes(b"b.bin".to_vec())])),
                    ]),
                ]),
            ),
            (b"name", Value::Bytes(b"relaxed".to_vec())),
            (b"piece length", Value::Int(20000)),
            (b"pieces", Value::Bytes(vec![0x11; 60])),
        ]);
        let top = dict(vec![
            (b"announce", Value::Bytes(b"http://t.invalid".to_vec())),
            (b"info", info),
        ]);
        let raw = bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"));
        let m =
            Metainfo::parse(&raw).unwrap_or_else(|e| panic!("v1-only 20000 must be accepted: {e}"));
        assert_eq!(m.meta.kind, SwarmKind::V1Only);
        assert_eq!(m.meta.piece_length, 20000);

        // 8192 (<16KiB) single file multi-piece: 20000 bytes -> 3 pieces
        // (8192+8192+3616).
        let info = dict(vec![
            (b"length", Value::Int(20000)),
            (b"name", Value::Bytes(b"small.bin".to_vec())),
            (b"piece length", Value::Int(8192)),
            (b"pieces", Value::Bytes(vec![0x22; 60])),
        ]);
        let top = dict(vec![(b"info", info)]);
        let raw = bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"));
        let m =
            Metainfo::parse(&raw).unwrap_or_else(|e| panic!("v1-only 8192 must be accepted: {e}"));
        assert_eq!(m.meta.piece_length, 8192);
        assert_eq!(m.meta.total_len(), 20000);
    }

    /// Anchor: hybrid and v2-only face constraints unchanged — with
    /// `file tree` present, the same `piece length` key enters the BEP52
    /// domain (16KiB merkle leaf math); 20000 still rejects. A hybrid's
    /// v1 tree piece length shares the key with the v2 piece length, so
    /// "v1 tree piece length != v2 piece length" rejection here is "the
    /// shared value fails BEP52" (parse_files additionally carries the
    /// dual-view equality defense).
    #[test]
    fn hybrid_and_v2_piece_length_still_bep52() {
        let tree = Value::Dict(vec![(
            b"a.bin".to_vec(),
            Value::Dict(vec![(
                b"".to_vec(),
                Value::Dict(vec![
                    (b"length".to_vec(), Value::Int(30000)),
                    (b"pieces root".to_vec(), Value::Bytes(vec![0xaa; 32])),
                ]),
            )]),
        )]);
        // Hybrid: files + file tree + meta version 2, piece length 20000.
        let info = dict(vec![
            (
                b"files",
                Value::List(vec![dict(vec![
                    (b"length", Value::Int(30000)),
                    (b"path", Value::List(vec![Value::Bytes(b"a.bin".to_vec())])),
                ])]),
            ),
            (b"file tree", tree.clone()),
            (b"meta version", Value::Int(2)),
            (b"piece length", Value::Int(20000)),
            (b"pieces", Value::Bytes(vec![0u8; 40])),
        ]);
        let top = dict(vec![(b"info", info)]);
        let raw = bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            matches!(
                Metainfo::parse(&raw),
                Err(MetainfoError::Structure(FileTreeError::InvalidPieceLength(
                    _
                )))
            ),
            "hybrid piece length 20000 must still be rejected"
        );

        // v2-only: same value, same rejection.
        let info = dict(vec![
            (b"file tree", tree),
            (b"meta version", Value::Int(2)),
            (b"piece length", Value::Int(20000)),
        ]);
        let top = dict(vec![(b"info", info)]);
        let raw = bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            matches!(
                Metainfo::parse(&raw),
                Err(MetainfoError::Structure(FileTreeError::InvalidPieceLength(
                    _
                )))
            ),
            "v2-only piece length 20000 must still be rejected"
        );
    }

    fn dict(pairs: Vec<(&[u8], Value)>) -> Value {
        let mut v: Vec<(Vec<u8>, Value)> =
            pairs.into_iter().map(|(k, x)| (k.to_vec(), x)).collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        Value::Dict(v)
    }
}
