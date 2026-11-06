//! Scheduler strategy layer: piece selection extracted into the pluggable
//! trait [`PieceSelectionStrategy`]. The active strategy object is swapped
//! atomically at runtime via `EngineCommand::SetSchedulerPolicy` inside the
//! engine single-writer loop (lock-free: the object lives in
//! [`super::run::state::EngineLoop`]; each `select!` arm holds `&mut`, so
//! nothing is shared across tasks).
//!
//! Implementations: [`RarestFirstStrategy`] = the existing rarest-first
//! semantics ported line for line (two-phase: spread round
//! [`select_advertised_piece_spread`] → fallback [`select_advertised_piece`];
//! default, zero behavior change), [`StreamingStrategy`] (stream-while-
//! downloading), [`SequentialStrategy`] (layered order: priority descending,
//! file order within a group; all three report `is_supported() == true`).
//!
//! Extension policy: enhancements land as dispatch-side constants, never as
//! trait changes — method signatures are frozen; [`SelectionCtx`] grows only
//! by adding fields (source-compatible for all implementors); the RPC
//! parameter surface is a policy-name string or `{"policy": name, ...}`,
//! with parameter keys added over time without changing the method shape.
//!
//! Upstream anchor mapping: docs/design/engine.md

use std::sync::Arc;

use taiji_bt::piece_stat::PieceStatMan;
use taiji_store::layout::Layout;

use crate::bitmap::PieceBitmap;
use crate::dispatch::{
    ClaimedSet, select_advertised_piece, select_advertised_piece_spread,
    select_rarest_two_phase_one_pass,
};

// ---- Policy configuration surface (cross-crate: session mirror, RPC, config_json) ----

/// rarest-first parameter struct. Smart enhancements (adaptive endgame,
/// bandwidth-aware dispatch, reciprocity tie-break) land as constant notes on
/// the dispatch gate (the empty [`StreamingParams`] is the precedent shape:
/// enhancement semantics are on by default, with no tunable constants); this
/// struct stays empty as a future tuning extension point (stable serde form).
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RarestFirstParams {}

/// Sequential-download parameter struct; stays empty (sequential semantics
/// have no tunable constants). Stable serde extension point.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SequentialParams {}

/// Stream-while-downloading parameter struct. The playhead is runtime command
/// state (repeated `taiji.setStreamingPlayhead` calls advance it), not policy
/// config: it is not persisted and not carried in config_json — the caller
/// replays it after restart. This struct stays empty as a future
/// window-tuning extension point (stable serde form).
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StreamingParams {}

/// Scheduler policy config. Adjacent-tag JSON form
/// `{"policy":"rarest_first","params":{}}` is carried in config_json.
/// Default = [`SchedulerPolicy::RarestFirst`] (zero change for existing
/// tasks).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "policy", content = "params", rename_all = "snake_case")]
pub enum SchedulerPolicy {
    /// rarest-first (default).
    RarestFirst(RarestFirstParams),
    /// Sequential download ([`SequentialStrategy`]): priority descending,
    /// file order within a group.
    Sequential(SequentialParams),
    /// Stream-while-downloading ([`StreamingStrategy`]).
    Streaming(StreamingParams),
}

impl Default for SchedulerPolicy {
    fn default() -> SchedulerPolicy {
        SchedulerPolicy::RarestFirst(RarestFirstParams::default())
    }
}

impl SchedulerPolicy {
    /// All strategy names — the registry behind the `scheduler.available`
    /// capability list; same value domain as the [`FromStr`] parse (locked
    /// by a capabilities roundtrip test). Additive only; the trait/decision
    /// surfaces stay untouched.
    pub const NAMES: &'static [&'static str] = &["rarest_first", "sequential", "streaming"];

    /// Strategy name (RPC echo / logs; same as the serde snake_case form).
    pub fn name(&self) -> &'static str {
        match self {
            SchedulerPolicy::RarestFirst(_) => "rarest_first",
            SchedulerPolicy::Sequential(_) => "sequential",
            SchedulerPolicy::Streaming(_) => "streaming",
        }
    }

    /// Named constructor for the sequential policy (`Sequential` with
    /// default params). The panic-free consume face for cross-crate
    /// callers: `parse("sequential")` is a string lookup whose `Err` arm
    /// is unreachable in practice, but a rename on the engine side would
    /// turn every `unwrap_or_else(panic!)` consumer into a remote panic on
    /// the single-writer session actor — this constructor keeps the
    /// name↔variant binding inside this crate (compile-checked; see the
    /// `name()` roundtrip test).
    pub fn sequential() -> SchedulerPolicy {
        SchedulerPolicy::Sequential(SequentialParams::default())
    }

    /// Strategies implemented (configurable) in this module. Unsupported
    /// values are rejected explicitly by the `set` validation rather than
    /// silently mapped to the default.
    pub fn is_supported(&self) -> bool {
        matches!(
            self,
            SchedulerPolicy::RarestFirst(_)
                | SchedulerPolicy::Streaming(_)
                | SchedulerPolicy::Sequential(_)
        )
    }
}

/// Unknown scheduler-policy name (the [`FromStr`] error face; carries the
/// rejected input verbatim so callers can echo it in diagnostics).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown scheduler policy: `{0}`")]
pub struct UnknownPolicyName(pub String);

/// Strategy name -> default parameter config (RPC `set` parsing; callers
/// extend the parameter object on their side). Unknown names = `Err`
/// carrying the rejected name (the caller raises an explicit error).
impl std::str::FromStr for SchedulerPolicy {
    type Err = UnknownPolicyName;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "rarest_first" => Ok(SchedulerPolicy::RarestFirst(RarestFirstParams::default())),
            "sequential" => Ok(SchedulerPolicy::Sequential(SequentialParams::default())),
            "streaming" => Ok(SchedulerPolicy::Streaming(StreamingParams::default())),
            _ => Err(UnknownPolicyName(s.to_string())),
        }
    }
}

// ---- Piece-selection trait surface (engine-internal, not cross-crate) ----

// ---- Streaming data surface: playhead-driven piece priority map ----

/// Head/tail first-window size (2 MiB each side of a file; fixed by design).
/// A general approximation of the MP4 moov-at-head-or-tail convention (same
/// shape as WebTorrent/peerflix head+tail fetching and qBittorrent's
/// "download first and last pieces first"). No MP4/container parsing is
/// introduced (explicitly out of scope): containers that do not place moov
/// at head/tail only waste bounded extra fetching (≤ 4 MiB).
pub(super) const STREAM_HEAD_TAIL_BYTES: u64 = 2 * 1024 * 1024;
/// Forward buffer window in seconds: window = `N × bytes_per_sec` bytes
/// starting at the playhead. Local policy value (no BEP/libtorrent constant
/// counterpart; conceptual precedent = libtorrent `piece_picker.cpp`
/// `m_priority_boundaries`, a bounded priority region ahead of the cursor).
pub(super) const STREAM_WINDOW_SECS: u64 = 30;
/// Default playback bitrate tier when `bytes_per_sec` is unconfigured:
/// 1 MiB/s (≈ an 8 Mbps stream). Local policy value.
pub(super) const DEFAULT_PLAYBACK_BYTES_PER_SEC: u64 = 1024 * 1024;
/// Window byte cap: bounds the priority-map entry count (≤ cap/stride +
/// 2×(head-tail window/stride) + 1, about 4.4k entries at 16 KiB pieces) —
/// the enforcement of the "no unbounded priority map" rule. Larger
/// `bytes_per_sec` configs are clamped to this cap (the window grows to
/// 64 MiB at most).
pub(super) const STREAM_WINDOW_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Playhead (runtime state): the file being played (client file index =
/// non-pad entry order, same anchor as BEP-53) and the byte position within
/// it; `bytes_per_sec` = the playback bitrate of this stream (None = the
/// [`DEFAULT_PLAYBACK_BYTES_PER_SEC`] tier). Delivered via
/// `EngineCommand::SetStreamingPlayhead` and replaced inside the engine
/// single-writer loop (same domain as the strategy object, lock-free);
/// advancing = repeated calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Playhead {
    pub(super) file: u32,
    pub(super) position: u64,
    pub(super) bytes_per_sec: Option<u64>,
}

/// Static streaming geometry (built once from the layout at assembly; shared
/// by all faces). Contains only real files (non-pad entry order = client file
/// order, the same projection anchor as [`super::selection_mask`]). Each
/// file's flat-piece mapping follows the wire-true addressing rule (see
/// [`Self::from_layout`]): the earlier "each file starts at a piece boundary"
/// assumption does not hold for v1-only no-pad layouts (the playhead file's
/// true first piece would never enter the priority map).
pub(super) struct StreamGeo {
    piece_len: u32,
    /// Flat-piece geometry per real file (client order).
    files: Vec<FileGeo>,
}

/// Mapping of one real file into flat piece space.
#[derive(Debug, Clone, Copy)]
struct FileGeo {
    /// File length in bytes (zero-length files cover 0 pieces).
    len: u64,
    /// Number of flat pieces covered (unaligned files share first/last pieces with neighbors).
    pieces: u64,
    /// First flat piece (the piece containing file byte 0).
    base: u64,
    /// Offset of the file start within its first piece (0 for aligned files).
    rem: u64,
}

impl StreamGeo {
    /// Layout → stream geometry: skips pad entries (BEP-47 — pads are
    /// transport filler, not files; client file order = non-pad entry order).
    /// The flat piece space follows the wire-true mapping for the layout kind
    /// (isomorphic to [`taiji_bt::piece_id::Addressing`]):
    ///
    /// - v1 face (`V1Padded`: v1-only and hybrid): flat piece k covers
    /// layout-stream bytes `[k·stride, (k+1)·stride)` (`Addressing::Flat`
    /// identity mapping) — file i maps to the pieces covering its byte
    /// range `[offset_i, offset_i+len_i)` (pads count toward offsets).
    /// Unaligned files (v1-only injects no pads; metainfo `plan_entries`
    /// keeps the V1Only list verbatim) share first/last pieces with
    /// neighbors. When pads are present the following file is always
    /// aligned (BEP-47 check), and the mapping degenerates to exact
    /// per-file piece counts.
    /// - v2 face (`V2Compact`: v2-only): flat piece space is a per-file
    /// aligned synthetic view (`Addressing::PerFile` base model) — file i's
    /// base = the sum of preceding files' piece counts; in-file piece p
    /// covers file bytes `[p·stride, (p+1)·stride)`. Compact disk layout
    /// does not affect piece addressing.
    ///
    /// For aligned files (v2/hybrid/v1-padded) the two formulas coincide and
    /// the behavior matches the original implementation byte for byte; this
    /// function only corrects the mapping for unaligned v1 files.
    pub(super) fn from_layout(layout: &Layout, piece_len: u32) -> StreamGeo {
        let stride = u64::from(piece_len);
        let files = match layout.kind() {
            taiji_store::layout::LayoutKind::V2Compact => {
                let mut base = 0u64;
                layout
                    .files()
                    .iter()
                    .map(|f| {
                        let pieces = f.length.div_ceil(stride);
                        let g = FileGeo {
                            len: f.length,
                            pieces,
                            base,
                            rem: 0,
                        };
                        base += pieces;
                        g
                    })
                    .collect()
            }
            taiji_store::layout::LayoutKind::V1Padded => layout
                .files()
                .iter()
                .filter(|f| !f.padding)
                .map(|f| {
                    let base = f.offset / stride;
                    // zero-length files cover 0 pieces (div_ceil over-counts 1 when unaligned).
                    let pieces = if f.length == 0 {
                        0
                    } else {
                        (f.offset + f.length).div_ceil(stride) - base
                    };
                    FileGeo {
                        len: f.length,
                        pieces,
                        base,
                        rem: f.offset % stride,
                    }
                })
                .collect(),
            // Forward-compat (LayoutKind is #[non_exhaustive]): an unknown
            // future layout kind yields an empty geo - playhead validation
            // then fails explicitly ("out of range (0 files)"), never a
            // silent projection onto a known face.
            _ => Vec::new(),
        };
        StreamGeo { piece_len, files }
    }

    /// Playhead argument validation (explicit failure arm of the engine
    /// command; out of range = Err, never a silent clamp — the same BEP-53
    /// out-of-range semantics as [`super::selection_mask`]).
    pub(super) fn validate(&self, file: u32, position: u64) -> Result<(), String> {
        let Some(&len) = self.files.get(file as usize).map(|f| &f.len) else {
            return Err(format!(
                "playhead file index {file} out of range ({} files)",
                self.files.len()
            ));
        };
        if position > len {
            return Err(format!(
                "playhead position {position} beyond end of file {file} ({len} bytes)"
            ));
        }
        Ok(())
    }
}

/// Resolved view from playhead to window piece set (built once per face per
/// dispatch round; pure computation, no allocation beyond the priority map).
/// The set = head/tail pieces (class 0, highest priority) ∪ forward window
/// (class 1, EDF). Ranges resolve through the [`StreamGeo::from_layout`]
/// wire-true mapping into flat piece ranges: the piece containing in-file
/// byte b is `base + (rem + b)/stride` (floor) — for aligned files
/// (v2/hybrid/v1-padded) rem = 0 and this degenerates to the file-aligned
/// "in-file piece p covers `[p·stride, (p+1)·stride)`" form; unaligned v1
/// files sharing first/last pieces resolve through the same formula.
pub(super) struct StreamView {
    /// Head 2 MiB pieces (flat range).
    head: std::ops::Range<u64>,
    /// Tail 2 MiB pieces (flat range).
    tail: std::ops::Range<u64>,
    /// Forward window: from the piece containing the playhead (inclusive)
    /// through `window_bytes/stride` more pieces.
    window: std::ops::Range<u64>,
    /// Playhead byte position within its file (EDF distance basis).
    pos: u64,
    /// Piece stride = piece_len (in-file piece p starts at byte p·stride).
    stride: u64,
}

impl StreamView {
    /// Playhead + geometry → window view. An out-of-range playhead file or a
    /// zero-piece file = None (the strategy falls back to the rarity layer;
    /// the command side already validated, this defends against silent
    /// mismatch instead of panicking).
    pub(super) fn build(playhead: &Playhead, geo: &StreamGeo) -> Option<StreamView> {
        let fi = playhead.file as usize;
        let &f = geo.files.get(fi)?;
        if f.pieces == 0 {
            return None;
        }
        let stride = u64::from(geo.piece_len);
        let pos = playhead.position.min(f.len);
        // In-file byte b → relative piece (the piece containing b) =
        // (rem + b)/stride (floor); b = len (EOF) → relative piece = pieces
        // (one past the last piece).
        let rel = |b: u64| (f.rem + b) / stride;
        // Head window: pieces covering file bytes [0, min(2 MiB, len)) (the
        // first piece contains file byte 0).
        let head_n = (f.rem + f.len.min(STREAM_HEAD_TAIL_BYTES))
            .div_ceil(stride)
            .min(f.pieces);
        // Tail window: pieces covering file bytes [len - min(2 MiB, len),
        // len) — the start piece is the one containing byte (len − T); when
        // evenly divisible that piece starts exactly at the boundary and
        // still belongs to the tail window.
        let t = f.len.min(STREAM_HEAD_TAIL_BYTES);
        let tail_start = rel(f.len - t);
        // Forward window: at least one piece of window bytes (the playhead's
        // own piece included); bps default = the default tier.
        let window_bytes = playhead
            .bytes_per_sec
            .unwrap_or(DEFAULT_PLAYBACK_BYTES_PER_SEC)
            .saturating_mul(STREAM_WINDOW_SECS)
            .min(STREAM_WINDOW_MAX_BYTES)
            .max(stride);
        // EOF playhead (pos = len): relative piece = pieces → empty forward
        // window (matches the aligned-form semantics: no bytes after the
        // playhead).
        let p0 = if pos >= f.len { f.pieces } else { rel(pos) };
        let p1 = rel((pos + window_bytes).min(f.len - 1));
        Some(StreamView {
            head: f.base..f.base + head_n,
            tail: f.base + tail_start..f.base + f.pieces,
            window: f.base + p0..f.base + p1 + 1,
            pos,
            stride,
        })
    }

    /// Priority map (bounded): flat piece → (class, dist). Class 0 = head/tail
    /// pieces (highest priority), class 1 = forward-window pieces; dist = byte
    /// distance from the playhead (|piece start − pos|, an EDF approximation —
    /// the playhead reaches a piece at a time ∝ distance/bitrate). Sort key =
    /// (class, dist, flat) ascending; pieces under both head/tail and window
    /// keep the higher-priority class. Entry count is bounded (see
    /// [`STREAM_WINDOW_MAX_BYTES`]).
    pub(super) fn priority_ctx(&self) -> StreamCtx {
        let mut map: std::collections::BTreeMap<u64, (u8, u64)> = std::collections::BTreeMap::new();
        let dist = |p: u64| (p * self.stride).abs_diff(self.pos);
        // Head/tail pieces enter first (class 0); window pieces use
        // or_insert so they never overwrite them.
        for p in self.head.clone().chain(self.tail.clone()) {
            map.insert(p, (0, dist(p)));
        }
        for p in self.window.clone() {
            map.entry(p).or_insert_with(|| (1, dist(p)));
        }
        let mut priority: Vec<(u8, u64, u64)> = map
            .into_iter()
            .map(|(flat, (class, d))| (class, d, flat))
            .collect();
        priority.sort_unstable();
        StreamCtx { priority }
    }
}

/// Streaming selection context shared across a dispatch round (built once per
/// face per round, reused by every peer; `priority` = the bounded priority
/// map, (class, dist, flat) ascending).
pub(super) struct StreamCtx {
    priority: Vec<(u8, u64, u64)>,
}

/// Playhead + geometry + face piece count → dispatch-round context
/// (dispatch-side assembly point; defensive: when the face piece count
/// mismatches the geometry, ranges are clamped into the face, so malformed
/// input degrades to a smaller window instead of panicking).
pub(super) fn stream_ctx_for(
    playhead: &Playhead,
    geo: &StreamGeo,
    piece_count: u64,
) -> Option<StreamCtx> {
    let mut view = StreamView::build(playhead, geo)?;
    let cap = piece_count.max(1);
    for r in [&mut view.head, &mut view.tail, &mut view.window] {
        r.end = r.end.min(cap);
        r.start = r.start.min(r.end);
    }
    Some(view.priority_ctx())
}

/// Per-round dispatch payload for playhead + static geometry (EngineLoop →
/// dispatch; a lightweight Copy + Arc clone of the [`Playhead`] runtime state
/// and the shared [`StreamGeo`] snapshot, lock-free).
pub(super) struct StreamPlan {
    pub(super) playhead: Playhead,
    pub(super) geo: Arc<StreamGeo>,
}

/// Piece-selection input context (trait surface frozen; extension = adding
/// fields, source-compatible for implementors). Fields are per-peer per-round
/// decision input snapshots:
/// - `advertised`: the peer's advertised bitmap (None = no bitmap evidence;
/// BEP-3 treats this as have_none, so regular policies request nothing);
/// - `done`: the local incomplete mask (already includes the BEP-53
/// select-file projection — only selected pieces are dispatched);
/// - `stats`: rarity statistics (rarest-first counts, driven live by
/// Have/bitfield);
/// - `claimed`: pieces claimed in the spread round (in flight at other
/// peers, refetch window not yet expired); a dense [`ClaimedSet`] bitmap
/// with the same semantics as `HashSet<u64>` (see that type's docs);
/// - `preferred`: the partials table for the partial hard-gate round
/// (libtorrent `piece_picker.cpp` `prioritize_partials`); always empty
/// outside gate rounds — an empty table means zero selection change;
/// - `stream`: the streaming context (playhead priority map; None = no
/// playhead);
/// - `priority`: per-piece multi-level file priorities (None = an all-zero
/// default face, zero selection change). Consumption is per strategy:
/// rarest_first uses it as the primary key ahead of rarity
/// (higher-priority files download first); streaming consumes it only in
/// the outside-window rarity layer (the playhead window always outranks
/// file priority, so higher-priority files accelerate outside the window).
///
/// `advertised` is a compacted bitmap: an out-of-range `get` returns false,
/// matching the old slice's `unwrap_or(false)` verdict.
pub(super) struct SelectionCtx<'a> {
    pub(super) advertised: Option<&'a PieceBitmap>,
    pub(super) done: &'a [bool],
    pub(super) stats: &'a PieceStatMan,
    pub(super) claimed: &'a ClaimedSet,
    pub(super) preferred: &'a [u64],
    pub(super) stream: Option<&'a StreamCtx>,
    pub(super) priority: Option<&'a [i8]>,
}

/// Piece-selection strategy (the trait extraction): which pieces to request
/// from one peer in one round. `Some(wire piece)` = request that piece from
/// this peer (block-level windowing, in-flight dedup and lazy-fetch gating
/// remain dispatch-loop decisions; strategies do not overreach); `None` = no
/// request to this peer this round.
///
/// Implementations are swapped as whole objects atomically via
/// `EngineCommand::SetSchedulerPolicy` in the engine single-writer loop
/// (lock-free). A swap affects only subsequent selection decisions:
/// in-flight requests, refetch queues and claim bookkeeping are
/// strategy-independent and are not cleared on swap (see the
/// `scheduler_policy_swap` engine test).
pub(super) trait PieceSelectionStrategy: Send {
    /// Strategy name (swap logging; same form as [`SchedulerPolicy::name`]).
    fn name(&self) -> &'static str;
    /// One peer, one round selection decision ([`SelectionCtx`] input → piece request plan).
    fn select_piece(&self, ctx: &SelectionCtx<'_>) -> Option<u64>;
}

impl SchedulerPolicy {
    /// Config → strategy object (factory for the engine's SetSchedulerPolicy
    /// arm; strategy bodies are stateless — round inputs all arrive via
    /// [`SelectionCtx`], so whole-object replacement is the entire switch
    /// surface).
    pub(super) fn into_strategy(self) -> Box<dyn PieceSelectionStrategy> {
        match self {
            SchedulerPolicy::RarestFirst(_) => Box::new(RarestFirstStrategy),
            SchedulerPolicy::Sequential(_) => Box::new(SequentialStrategy),
            SchedulerPolicy::Streaming(_) => Box::new(StreamingStrategy),
        }
    }
}

/// Rarest-first two-phase (spread round → original fallback; the reuse point
/// for streaming's fallback layer).
///
/// The RarestFirst main path now goes through
/// [`select_rarest_two_phase_one_pass`] (single-pass two-record scan, same
/// verdict); this function remains as the two-phase reference, and
/// streaming's fallback layer consumes the same pair of primitives.
fn rarity_two_phase(ctx: &SelectionCtx<'_>) -> Option<u64> {
    select_advertised_piece_spread(
        ctx.advertised,
        ctx.done,
        ctx.stats,
        ctx.claimed,
        ctx.priority,
    )
    .or_else(|| select_advertised_piece(ctx.advertised, ctx.done, ctx.stats, ctx.priority))
}

/// Rarest-first strategy (a line-for-line port of the existing behavior, zero
/// new semantics): two-phase selection — first the spread round (skip pieces
/// in flight at other peers so each peer claims a different piece; the aria2
/// `getMissingPiece` `isPieceUsed` exclusion), then fall back to the original
/// selection when everything is claimed (few pieces, many peers / endgame
/// keeps peers busy). See the free-function docs for provenance.
///
/// Enhancements (adaptive endgame, bandwidth-aware dispatch, reciprocity
/// tie-break) are not implemented in this object: the selection decision
/// surface keeps the unchanged two-phase form. Endgame semantics land in the
/// dispatch loop (emptying the `claimed` input makes the spread round pick
/// the globally rarest missing piece, i.e. request every missing piece from
/// every peer that has it, plus the ×2 duplicate gate and dispatch order —
/// see the dispatch module docs). Method signatures stay frozen and
/// `select_piece` is unaware of endgame (the trait surface never changes
/// shape). Outside the endgame segment this strategy matches the original
/// behavior byte for byte.
pub(super) struct RarestFirstStrategy;

impl PieceSelectionStrategy for RarestFirstStrategy {
    fn name(&self) -> &'static str {
        "rarest_first"
    }
    fn select_piece(&self, ctx: &SelectionCtx<'_>) -> Option<u64> {
        // Single-pass two-record scan: mathematically the same verdict as the
        // two-phase form (each min replaces only on strict less-than),
        // compressing the fallback shape to 1xO(N) instead of 2xO(N) per peer
        // per round outside endgame; endgame does not go through this arm
        // (the dispatch loop cursor picks pieces). The scan reads buckets
        // (same verdict; see the select_two_phase equivalence doc).
        // `ctx.preferred` carries the partial hard-gate table (always empty
        // outside gate rounds = zero behavior change).
        select_rarest_two_phase_one_pass(
            ctx.advertised,
            ctx.done,
            ctx.stats,
            ctx.claimed,
            ctx.preferred,
            // Multi-level file priority as the primary key ahead of rarity
            // (None = the all-zero default face, same verdict).
            ctx.priority,
        )
    }
}

/// Sequential-download strategy (aria2 `--bt-sequential-download` /
/// libtorrent `torrent_flags::sequential_download` capability parity).
///
/// # Decision (one peer, one round)
///
/// Piece order = flat coordinate natural order (v1: global piece order =
/// byte-grid order; v2: in-file piece order concatenated in file order —
/// the `SelectFilter::sequential` "the two are isomorphic" anchor). The
/// overlay is layered ordering: priority descending, file order within a
/// group (a higher-priority file forms an entire layer ahead of lower ones;
/// no rarity reordering within a group). Candidates are always filtered by
/// advertised awareness and the `done` mask (BEP-53 unselected pieces are
/// invisible through the mask — select-file cooperation).
///
/// Single pass with two records per level (the spread/fallback shape of the
/// rarest two-phase, organized by level): each level records the first
/// eligible piece (fallback record) and the first unclaimed eligible piece
/// (spread record); the decision is the spread record of the highest level
/// with a candidate, or that level's fallback record when all its pieces are
/// claimed (the same "few pieces, many peers / keep peers busy" rule;
/// duplicate in-flight requests are blocked by the dispatch loop's InFlight
/// filter). A `None` priority face is a single all-zero layer (pure file
/// order).
pub(super) struct SequentialStrategy;

impl PieceSelectionStrategy for SequentialStrategy {
    fn name(&self) -> &'static str {
        "sequential"
    }
    fn select_piece(&self, ctx: &SelectionCtx<'_>) -> Option<u64> {
        // Missing evidence → zero requests (falls through; no blind picks —
        // the same rule as the other strategies).
        ctx.advertised?;
        let eligible = |k: u64| {
            ctx.advertised.is_some_and(|a| a.get(k as usize))
                && !ctx.done.get(k as usize).copied().unwrap_or(true)
        };
        let level = |i: u64| {
            ctx.priority
                .and_then(|p| p.get(i as usize).copied())
                .unwrap_or(0)
        };
        let n = ctx.done.len() as u64;
        // Two records per level: first = first eligible (fallback);
        // unclaimed = first unclaimed eligible (spread).
        let mut first = [None::<u64>; 8];
        let mut unclaimed = [None::<u64>; 8];
        for i in 0..n {
            if !eligible(i) {
                continue;
            }
            let q = level(i).clamp(0, 7) as usize;
            if first[q].is_none() {
                first[q] = Some(i);
            }
            if unclaimed[q].is_none() && !ctx.claimed.contains(i) {
                unclaimed[q] = Some(i);
            }
        }
        (0..8usize).rev().find_map(|q| unclaimed[q].or(first[q]))
    }
}

/// Stream-while-downloading strategy: a playhead-driven piece priority map
/// with layered ordering.
///
/// # Four-layer decision (one peer, one round)
///
/// Candidates are always filtered by advertised awareness (chosen only from
/// this peer's advertised bitmap) and the `done` mask (locally complete
/// pieces + BEP-53 select-file unselected pieces — pieces outside the
/// selection are never chosen, cooperating with `SetFileSelection`/`so=`):
///
/// 1. In-window spread round: in priority-map order (head/tail pieces class
/// 0 first, then forward-window class 1 by ascending byte distance from
/// the playhead = an EDF approximation), take the first unclaimed piece
/// (skips pieces in flight at other peers — the spread semantics);
/// 2. Outside-window rarity mix: when every in-window piece is claimed, fall
/// through to the global rarest-first spread round (the same verdict as
/// [`RarestFirstStrategy`]'s first phase) — the key difference from pure
/// sequential: during playback the peer keeps contributing rare-piece
/// collection to the swarm, so reciprocity is not harmed (see the
/// `streaming_reciprocity_not_harmed` test);
/// 3. In-window duplicate fallback: when the outside window also has no
/// unclaimed piece, duplicates in flight are allowed within the window
/// (the "few pieces, many peers / keep peers busy" fallback; duplicate
/// blocks are caught by the dispatch loop's InFlight filter and refetch
/// window);
/// 4. Global fallback: the rarest-first original selection (the second phase
/// of the two-phase form).
///
/// # Degenerate cases and bounds
///
/// - No playhead (`ctx.stream = None`) → exactly the rarest-first two-phase:
/// no pure-sequential guessing without playback information (a pure
/// sequential full download is explicitly disallowed);
/// - Priority-map entries are bounded (see [`STREAM_WINDOW_MAX_BYTES`]);
/// - The head/tail 2 MiB first-window is the generic moov dual-position
/// approximation, with no container parser (see
/// [`STREAM_HEAD_TAIL_BYTES`]).
pub(super) struct StreamingStrategy;

impl PieceSelectionStrategy for StreamingStrategy {
    fn name(&self) -> &'static str {
        "streaming"
    }
    fn select_piece(&self, ctx: &SelectionCtx<'_>) -> Option<u64> {
        // Missing bitmap evidence → zero requests (falls through every layer).
        ctx.advertised?;
        let Some(stream) = ctx.stream else {
            return rarity_two_phase(ctx);
        };
        let eligible = |k: u64| {
            ctx.advertised.is_some_and(|a| a.get(k as usize))
                && !ctx.done.get(k as usize).copied().unwrap_or(true)
        };
        // Layer 1: in-window (head/tail first, EDF ascending) ∩ unclaimed (spread).
        stream
            .priority
            .iter()
            .copied()
            .find(|&(_, _, k)| eligible(k) && !ctx.claimed.contains(k))
            .map(|(_, _, k)| k)
            // Layer 2: outside-window rarity mix (same verdict as the spread
            // round); file priorities are consumed in this layer only
            // (layers 1/3 ignore ctx.priority — the playhead window always
            // outranks file priority, so higher-priority files accelerate
            // outside the window).
            .or_else(|| {
                select_advertised_piece_spread(
                    ctx.advertised,
                    ctx.done,
                    ctx.stats,
                    ctx.claimed,
                    ctx.priority,
                )
            })
            // Layer 3: in-window duplicate fallback (in-flight duplicates
            // allowed; block-level dedup lives in the dispatch loop).
            .or_else(|| {
                stream
                    .priority
                    .iter()
                    .copied()
                    .find(|&(_, _, k)| eligible(k))
                    .map(|(_, _, k)| k)
            })
            // Layer 4: global fallback (the rarest-first original selection).
            .or_else(|| select_advertised_piece(ctx.advertised, ctx.done, ctx.stats, ctx.priority))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Strategy name ↔ config parsing roundtrip (the RPC set parsing rules).
    #[test]
    fn policy_name_parse_roundtrip() {
        for name in ["rarest_first", "sequential", "streaming"] {
            let p: SchedulerPolicy = name.parse().unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(p.name(), name);
            assert_eq!(
                p.name().parse::<SchedulerPolicy>(),
                Ok(p),
                "{name} roundtrip"
            );
        }
        // Unknown names = Err carrying the name verbatim (the RPC layer
        // raises an explicit error; no silent default).
        assert_eq!(
            "bogus".parse::<SchedulerPolicy>(),
            Err(UnknownPolicyName("bogus".to_string()))
        );
        assert_eq!(
            "".parse::<SchedulerPolicy>(),
            Err(UnknownPolicyName(String::new()))
        );
        assert_eq!(
            "RAREST_FIRST".parse::<SchedulerPolicy>(),
            Err(UnknownPolicyName("RAREST_FIRST".to_string())),
            "the name literal is case-sensitive"
        );
        // Default = rarest_first (zero change for existing tasks).
        assert_eq!(SchedulerPolicy::default().name(), "rarest_first");
    }

    /// Support gate: all three strategies pass.
    #[test]
    fn policy_support_gate() {
        assert!(SchedulerPolicy::default().is_supported());
        for name in ["rarest_first", "streaming", "sequential"] {
            let p: SchedulerPolicy = name.parse().unwrap_or_else(|e| panic!("{e}"));
            assert!(p.is_supported(), "{name} must be configurable");
        }
    }

    /// config_json payload form: stable adjacent-tag JSON serialization; the
    /// default writing no extra bytes is guaranteed by the caller side
    /// (PersistedTaskConfig skip_serializing_if) — this locks the enum's
    /// serde shape (adding parameters does not change the form).
    #[test]
    fn policy_serde_form_is_stable() {
        let p = SchedulerPolicy::default();
        let json = serde_json::to_string(&p).unwrap_or_default();
        assert_eq!(json, r#"{"policy":"rarest_first","params":{}}"#);
        let back: SchedulerPolicy =
            serde_json::from_str(&json).unwrap_or_else(|_| panic!("parse {json}"));
        assert_eq!(back, p);
        // Non-default variants are equally stable (forward-compatible payload).
        let seq: SchedulerPolicy = "sequential".parse().unwrap_or_else(|e| panic!("{e}"));
        let json = serde_json::to_string(&seq).unwrap_or_default();
        assert_eq!(json, r#"{"policy":"sequential","params":{}}"#);
        let back: SchedulerPolicy =
            serde_json::from_str(&json).unwrap_or_else(|_| panic!("parse {json}"));
        assert_eq!(back, seq);
    }

    /// Default behavior zero-change (trait extraction): `RarestFirstStrategy`
    /// selection through [`SelectionCtx`] matches the existing free-function
    /// direct calls case by case — locking both the (advertised ∩
    /// incomplete) and the (spread/fallback) decision tables. The single-pass
    /// two-record path ([`select_rarest_two_phase_one_pass`]) is also locked
    /// as verdict-equivalent to the two-phase direct form (spread `.or_else`
    /// fallback).
    #[test]
    fn rarest_first_strategy_matches_direct_calls() {
        fn claims(n: usize, pieces: impl IntoIterator<Item = u64>) -> ClaimedSet {
            let mut c = ClaimedSet::with_len(n);
            for p in pieces {
                c.mark_claimed(p);
            }
            c
        }
        fn ctx<'a>(
            advertised: Option<&'a PieceBitmap>,
            done: &'a [bool],
            stats: &'a PieceStatMan,
            claimed: &'a ClaimedSet,
        ) -> SelectionCtx<'a> {
            SelectionCtx {
                advertised,
                done,
                stats,
                claimed,
                preferred: &[],
                stream: None,
                priority: None,
            }
        }
        let stat = PieceStatMan::new(4, &mut |n| n / 2);
        let full = Some(PieceBitmap::ones(4));
        let none_done = vec![false; 4];
        let claimed = claims(4, std::iter::empty());
        let strategy = RarestFirstStrategy;

        // Missing evidence (None advertised) → None (BEP-3 have_none through the trait).
        assert_eq!(
            strategy.select_piece(&ctx(None, &none_done, &stat, &claimed)),
            None
        );

        // Spread round: empty claimed matches the direct call; a claim skips
        // to the next best; all claimed falls back to the original choice.
        let first = strategy.select_piece(&ctx(full.as_ref(), &none_done, &stat, &claimed));
        assert_eq!(
            first,
            select_advertised_piece_spread(full.as_ref(), &none_done, &stat, &claimed, None)
                .or_else(|| select_advertised_piece(full.as_ref(), &none_done, &stat, None)),
            "empty claimed = same verdict as the direct call"
        );
        let Some(first) = first else {
            panic!("a non-empty full-advertised face must yield a selection");
        };
        let claimed = claims(4, [first]);
        let second = strategy.select_piece(&ctx(full.as_ref(), &none_done, &stat, &claimed));
        assert_eq!(
            second,
            select_advertised_piece_spread(full.as_ref(), &none_done, &stat, &claimed, None)
                .or_else(|| select_advertised_piece(full.as_ref(), &none_done, &stat, None))
        );
        assert_ne!(
            second,
            Some(first),
            "another peer's in-flight piece is skipped"
        );
        let claimed = claims(4, 0..4u64);
        // All claimed: spread round None → fallback to the original selection
        // (duplicate in-flight is blocked by the dispatch loop's InFlight
        // filter).
        assert_eq!(
            strategy.select_piece(&ctx(full.as_ref(), &none_done, &stat, &claimed)),
            Some(first),
            "all claimed -> fall back to the original choice (two-phase semantics penetrate the trait surface)"
        );
    }

    // ---- StreamingStrategy (stream-while-downloading) tests ----

    /// Stream geometry fixture: piece_len = 1 MiB (head/tail 2 MiB windows
    /// are exactly table-drivable at small piece counts); `lens` = real file
    /// lengths (written as whole MiB). Built through a real `Layout` via
    /// [`StreamGeo::from_layout`] (for aligned fixtures the two mappings
    /// coincide, so existing assertions are unchanged).
    const MIB: u64 = 1024 * 1024;
    fn geo_mib(lens_mib: &[u64]) -> StreamGeo {
        let entries: Vec<taiji_store::layout::PlanEntry> = lens_mib
            .iter()
            .enumerate()
            .map(|(i, &m)| taiji_store::layout::PlanEntry {
                path: std::path::PathBuf::from(format!("f{i}.bin")),
                length: m * MIB,
                padding: false,
            })
            .collect();
        let layout =
            Layout::plan_v2_compact(&entries, MIB as u32).unwrap_or_else(|e| panic!("{e}"));
        StreamGeo::from_layout(&layout, MIB as u32)
    }
    fn ph(file: u32, position_mib: u64, bps: Option<u64>) -> Playhead {
        Playhead {
            file,
            position: position_mib * MIB,
            bytes_per_sec: bps,
        }
    }
    /// Bitrate tier for a 3 MiB window (bps × STREAM_WINDOW_SECS = 3 MiB; at
    /// stride 1 MiB the window = the playhead piece + the next 2 pieces).
    const BPS_3MIB: u64 = (3 * MIB) / STREAM_WINDOW_SECS + 1;

    fn stream_of(playhead: &Playhead, g: &StreamGeo, piece_count: u64) -> StreamCtx {
        stream_ctx_for(playhead, g, piece_count).unwrap_or_else(|| panic!("stream ctx"))
    }
    #[allow(clippy::too_many_arguments)]
    fn sctx<'a>(
        advertised: Option<&'a PieceBitmap>,
        done: &'a [bool],
        stats: &'a PieceStatMan,
        claimed: &'a ClaimedSet,
        stream: Option<&'a StreamCtx>,
    ) -> SelectionCtx<'a> {
        sctx_prio(advertised, done, stats, claimed, stream, None)
    }

    /// Constructor with priority injection (decision-table specific).
    #[allow(clippy::too_many_arguments)]
    fn sctx_prio<'a>(
        advertised: Option<&'a PieceBitmap>,
        done: &'a [bool],
        stats: &'a PieceStatMan,
        claimed: &'a ClaimedSet,
        stream: Option<&'a StreamCtx>,
        priority: Option<&'a [i8]>,
    ) -> SelectionCtx<'a> {
        SelectionCtx {
            advertised,
            done,
            stats,
            claimed,
            preferred: &[],
            stream,
            priority,
        }
    }
    /// Claimed-set test constructor (bitmap form).
    fn claims(n: usize, pieces: impl IntoIterator<Item = u64>) -> ClaimedSet {
        let mut c = ClaimedSet::with_len(n);
        for p in pieces {
            c.mark_claimed(p);
        }
        c
    }
    fn full(n: u64) -> PieceBitmap {
        PieceBitmap::ones(n as usize)
    }

    /// Window-range resolution table ([`StreamView::build`]): flat piece
    /// boundaries of the head/tail/forward ranges. Row 2 covers an EOF
    /// playhead (empty window → the strategy falls to the rarity layer);
    /// row 3 covers multiple files (file 1's base offset).
    #[test]
    fn stream_view_ranges_table() {
        let g = geo_mib(&[5]);
        // Row 1: pos = 2 MiB + 10 B, window 3 MiB → head 0..2, tail (5-2)..5, window 2..=4.
        let v = StreamView::build(&ph(0, 2, Some(BPS_3MIB)), &g).unwrap_or_else(|| panic!("v1"));
        assert_eq!(
            v.head,
            0..2,
            "row 1 head window = ceil(2MiB/1MiB) = 2 pieces"
        );
        assert_eq!(v.tail, 3..5, "row 1 tail window start = (5-2)/1 pieces");
        assert_eq!(
            v.window,
            2..5,
            "row 1 forward window = playhead piece 2 through EOF"
        );
        // Row 2: pos = len (EOF) → empty forward window (no window-layer candidates).
        let v = StreamView::build(&ph(0, 5, Some(BPS_3MIB)), &g).unwrap_or_else(|| panic!("v2"));
        assert!(
            v.window.is_empty(),
            "row 2 EOF playhead has no forward window"
        );
        // Row 3: two files (3 MiB + 5 MiB); playhead at 1 MiB in file 1 →
        // flat base +3; file 1 tail window = 3 + (5-2)..3+5.
        let g2 = geo_mib(&[3, 5]);
        let v = StreamView::build(&ph(1, 1, Some(BPS_3MIB)), &g2).unwrap_or_else(|| panic!("v3"));
        assert_eq!(v.head, 3..5, "row 3 head window = file 1 base 3, 2 pieces");
        assert_eq!(v.tail, 6..8, "row 3 tail window = base + (5-2)..5");
        assert_eq!(
            v.window,
            4..8,
            "row 3 forward window = playhead piece (base+1) for 3MiB — a partially \
             covered boundary piece qualifies"
        );
        // Row 4: out-of-range file = None (defense behind command-side validation).
        assert!(StreamView::build(&ph(2, 0, None), &g2).is_none());
        // Row 5: a zero-length file covers 0 pieces = None.
        let g0 = geo_mib(&[0, 5]);
        assert!(StreamView::build(&ph(0, 0, None), &g0).is_none());
    }

    // ---- v1-only multi-file (unaligned) flat true-mapping regression ----
    //
    // The old "each file starts at a piece boundary" assumption in
    // `StreamGeo` does not hold for v1-only no-pad layouts (metainfo
    // `plan_entries` keeps the V1Only list verbatim): flat piece k covers
    // layout-stream bytes [k·stride, (k+1)·stride) (`Addressing::Flat`), and
    // an unaligned file starts mid-piece. Under the old mapping the playhead
    // file's true first piece never entered class 0/1 (it degraded to the
    // rarity layer, delaying playback start).

    /// v1-only layout fixture (`plan_v1_padded` with no pad entries = offsets
    /// accumulated verbatim; built from a real `Layout`, not the aligned
    /// `geo_mib` helper).
    fn geo_v1(lens: &[u64]) -> StreamGeo {
        let entries: Vec<taiji_store::layout::PlanEntry> = lens
            .iter()
            .enumerate()
            .map(|(i, &l)| taiji_store::layout::PlanEntry {
                path: std::path::PathBuf::from(format!("v1f{i}.bin")),
                length: l,
                padding: false,
            })
            .collect();
        let layout = Layout::plan_v1_padded(&entries, MIB as u32)
            .unwrap_or_else(|e| panic!("v1 layout: {e}"));
        StreamGeo::from_layout(&layout, MIB as u32)
    }

    /// Config A (3.5 MiB + 5 MiB at 1 MiB pieces): playhead = file 1 byte 0.
    /// True mapping: file 1 flat range [3,9) (start 3.5 MiB → first piece 3);
    /// head = [3, 3+ceil((0.5 MiB+2 MiB)/1 MiB)) = [3,6), so first piece 3 is
    /// in class 0; under the old mapping (base = Σceil = 4) piece 3 is absent
    /// and the tail window overruns.
    #[test]
    fn v1_unaligned_playhead_first_piece_in_head_class() {
        let geo = geo_v1(&[35 * MIB / 10, 5 * MIB]);
        // True first piece = layout offset 3.5 MiB / 1 MiB = 3 (floor).
        let stream = stream_of(&ph(1, 0, Some(BPS_3MIB)), &geo, 9);
        let first = stream
            .priority
            .iter()
            .find(|&&(_, _, k)| k == 3)
            .copied()
            .unwrap_or_else(|| panic!("first piece 3 must enter the priority graph"));
        assert_eq!(
            first.0, 0,
            "the playhead file's true first piece is in class 0 (head window first)"
        );
        // Range resolution (rem = 0.5 MiB lifts the boundaries): head [3,6),
        // forward window from the playhead piece 3, tail [6,9). The 5 MiB
        // file's head+tail 2 MiB covers all 6 covered pieces → class 0 = the
        // whole file [3,9).
        let view =
            StreamView::build(&ph(1, 0, Some(BPS_3MIB)), &geo).unwrap_or_else(|| panic!("view"));
        assert_eq!(
            view.head,
            3..6,
            "head window [3,6): the 2MiB head segment crosses an unaligned boundary = 3 pieces"
        );
        assert_eq!(
            view.window,
            3..7,
            "forward window starts at the playhead piece 3"
        );
        assert_eq!(
            view.tail,
            6..9,
            "tail window = the file's last 2MiB covering pieces [6,9)"
        );
        let class0: Vec<u64> = stream
            .priority
            .iter()
            .filter(|&&(c, _, _)| c == 0)
            .map(|&(_, _, k)| k)
            .collect();
        assert_eq!(
            class0,
            vec![3, 4, 5, 6, 7, 8],
            "class 0 = all covered pieces of the file"
        );
        // The map never exceeds the true piece count (config A truly has 9;
        // the old mapping's tail window clamped at 9 landed misaligned).
        assert!(
            stream.priority.iter().all(|&(_, _, k)| k < 9),
            "the priority graph never exceeds the true total: {:?}",
            stream.priority.last()
        );
    }

    /// Config B (3.5 MiB + 4.5 MiB, both files spanning fractional pieces):
    /// the old mapping totals 9 pieces > the true 8, and the overrunning tail
    /// window index clamped by `stream_ctx_for` landed in a misaligned range.
    /// True mapping: file 1 = [3, 8) (span = ceil(8.5)−3 = 5); tail window
    /// [5,8) covers the true last piece 7; the map stays ≤ 8 without
    /// clamping.
    #[test]
    fn v1_unaligned_tail_stays_within_true_piece_count() {
        let geo = geo_v1(&[35 * MIB / 10, 45 * MIB / 10]);
        let stream = stream_of(&ph(1, 0, Some(BPS_3MIB)), &geo, 8);
        assert!(
            stream.priority.iter().all(|&(_, _, k)| k < 8),
            "config B: the whole graph stays within the true total 8: {:?}",
            stream.priority.last()
        );
        assert!(
            stream.priority.iter().any(|&(_, _, k)| k == 3),
            "the true first piece 3 is in the graph"
        );
        assert!(
            stream.priority.iter().any(|&(_, _, k)| k == 7),
            "the true last piece 7 (tail window) is in the graph"
        );
        // Per-piece coverage: all 5 covered pieces of file 1 (3..8) reach the priority layer.
        for k in 3..8u64 {
            assert!(
                stream.priority.iter().any(|&(_, _, p)| p == k),
                "covered piece {k} of file 1 should be in the priority graph"
            );
        }
    }

    /// v1 with pads (BEP-47 alignment), single-file v1, and v2 compact do not
    /// regress: aligned-file mapping matches the original byte for byte
    /// (base = the exact piece-count sum, rem = 0).
    #[test]
    fn aligned_layouts_mapping_unchanged() {
        // Row 1: v1 with pads — a 0.5 MiB pad aligns after the 3.5 MiB file,
        // so file 1 starts at 4 MiB → base 4, rem 0 (same values as the old
        // Σceil model).
        let entries = vec![
            taiji_store::layout::PlanEntry {
                path: std::path::PathBuf::from("a.bin"),
                length: 35 * MIB / 10,
                padding: false,
            },
            taiji_store::layout::PlanEntry {
                path: std::path::PathBuf::from(".pad/524288"),
                length: MIB / 2,
                padding: true,
            },
            taiji_store::layout::PlanEntry {
                path: std::path::PathBuf::from("b.bin"),
                length: 5 * MIB,
                padding: false,
            },
        ];
        let layout = Layout::plan_v1_padded(&entries, MIB as u32)
            .unwrap_or_else(|e| panic!("padded layout: {e}"));
        let geo = StreamGeo::from_layout(&layout, MIB as u32);
        let v = StreamView::build(&ph(1, 1, Some(BPS_3MIB)), &geo)
            .unwrap_or_else(|| panic!("padded v"));
        assert_eq!(
            v.head,
            4..6,
            "aligned-file head window = base 4, 2 pieces (same values)"
        );
        assert_eq!(v.tail, 7..9, "aligned-file tail window = base + (5-2)..5");
        assert_eq!(
            v.window,
            5..9,
            "aligned-file forward window, same shape as row 3"
        );
        // Row 2: single-file v1 (3.5 MiB; a lone file always starts at
        // offset 0 = aligned) — head 0..2, map ≤ ceil(3.5) = 4.
        let single = geo_v1(&[35 * MIB / 10]);
        let v = StreamView::build(&ph(0, 0, Some(BPS_3MIB)), &single)
            .unwrap_or_else(|| panic!("single v"));
        assert_eq!(
            v.head,
            0..2,
            "single-file head window = the first 2MiB as two pieces"
        );
        assert!(
            v.tail.end <= 4 && v.window.end <= 4,
            "the whole graph stays within the true 4 pieces"
        );
        // Row 3: v2 compact multi-file (unaligned file lengths) — flat =
        // per-file aligned synthesis (`Addressing::PerFile`), same mapping as
        // geo_mib.
        let v2g = geo_mib(&[3, 5]);
        let v =
            StreamView::build(&ph(1, 1, Some(BPS_3MIB)), &v2g).unwrap_or_else(|| panic!("v2 v"));
        assert_eq!(v.head, 3..5, "v2 file 1 base 3 (same value as row 3)");
    }

    /// Playhead validation (explicit engine-command failure arm):
    /// out-of-range file/position = Err; an EOF position (pos == len) is
    /// legal.
    #[test]
    fn playhead_validation_rows() {
        let g = geo_mib(&[3, 5]);
        assert_eq!(g.validate(0, 3 * MIB), Ok(()), "pos == len is legal (EOF)");
        assert!(
            g.validate(2, 0).is_err(),
            "out-of-range file explicitly rejected"
        );
        assert!(
            g.validate(0, 3 * MIB + 1).is_err(),
            "out-of-range position explicitly rejected"
        );
    }

    /// Head/tail pieces first, then in-window EDF order (strategy-layer
    /// table): playhead at 3 MiB of an 8 MiB file, window 3 MiB — pick order
    /// = head/tail pieces (class 0, ascending distance from the playhead) →
    /// window pieces (class 1, EDF ascending) → outside-window rarity.
    /// Expected order (dist in MiB): head {1(2), 0(3)}, tail {6(3), 7(4)} →
    /// window {3(0), 4(1), 5(2)}; class-0 dist ties (0 and 6 both 3) break by
    /// flat ascending.
    #[test]
    fn streaming_head_tail_then_edf_sequence() {
        let g = geo_mib(&[8]);
        let stat = PieceStatMan::new(8, &mut |n| n / 2);
        let avail = full(8);
        let none_done = vec![false; 8];
        let stream = stream_of(&ph(0, 3, Some(BPS_3MIB)), &g, 8);
        let mut claimed = claims(8, std::iter::empty());
        let strategy = StreamingStrategy;
        let mut done = none_done.clone();
        let mut picked = Vec::new();
        for _ in 0..8 {
            let Some(k) =
                strategy.select_piece(&sctx(Some(&avail), &done, &stat, &claimed, Some(&stream)))
            else {
                break;
            };
            claimed.mark_claimed(k);
            done[k as usize] = true;
            picked.push(k);
        }
        assert_eq!(
            picked,
            vec![1, 0, 6, 7, 3, 4, 5, 2],
            "head/tail first -> in-window EDF -> outside-window"
        );
    }

    /// Outside-window rarity mix + layer-3 duplicate fallback + layer-4
    /// global fallback: with all in-window pieces done, the pick is the
    /// global rarest (same verdict as the direct spread call); with all
    /// in-window and outside-window pieces claimed, the in-window duplicate
    /// fallback applies (layer 3, in-flight duplicates allowed — the
    /// dispatch loop's block-level dedup backstops); with all pieces claimed
    /// and window pieces done, layer 4 = the rarest-first original selection
    /// (claims ignored).
    #[test]
    fn streaming_outside_window_rarity_and_fallbacks() {
        let g = geo_mib(&[6]);
        // Playhead 0, window 3 MiB: priority map = head {0,1} + window
        // {0,1,2} + tail {4,5}; with head/tail done, only piece 2 remains
        // in-window.
        let mut stat = PieceStatMan::new(6, &mut |n| n / 2);
        stat.add_bitfield(|i| i == 3, 6); // piece 3, count 1 (the rarest pickable)
        let avail = full(6);
        let mut done = vec![false; 6];
        for p in [0usize, 1, 4, 5] {
            done[p] = true;
        }
        let stream = stream_of(&ph(0, 0, Some(BPS_3MIB)), &g, 6);
        let strategy = StreamingStrategy;

        // Row 1: window piece (2) done → layer 2 rarity mix picks piece 3
        // (count 1, the only pickable).
        let mut done1 = done.clone();
        done1[2] = true;
        let empty = claims(6, std::iter::empty());
        assert_eq!(
            strategy.select_piece(&sctx(Some(&avail), &done1, &stat, &empty, Some(&stream))),
            select_advertised_piece_spread(Some(&avail), &done1, &stat, &empty, None),
            "row 1: window exhausted -> global rarest (reciprocity mix)"
        );
        assert_eq!(
            strategy.select_piece(&sctx(Some(&avail), &done1, &stat, &empty, Some(&stream))),
            Some(3),
            "row 1: the rarest piece 3 selected"
        );

        // Row 2: window piece 2 and outside piece 3 all claimed → layers 1/2
        // None → layer 3 in-window duplicate (returns piece 2; the dispatch
        // loop's dedup/refetch window backstops).
        let claimed = claims(6, [2u64, 3]);
        assert_eq!(
            strategy.select_piece(&sctx(Some(&avail), &done, &stat, &claimed, Some(&stream))),
            Some(2),
            "row 2: all claimed -> in-window duplicate fallback (shape)"
        );

        // Row 3: window done + all claimed → layer 4 = the rarest-first
        // original selection (claims ignored; keep-peers-busy semantics as in
        // RarestFirst's fallback).
        let claimed_all = claims(6, 0..6u64);
        assert_eq!(
            strategy.select_piece(&sctx(
                Some(&avail),
                &done1,
                &stat,
                &claimed_all,
                Some(&stream)
            )),
            select_advertised_piece(Some(&avail), &done1, &stat, None),
            "row 3: layer 4 = the original selection"
        );
    }

    /// No-playhead degeneration guard: with `ctx.stream = None`,
    /// StreamingStrategy matches RarestFirstStrategy case by case (no
    /// pure-sequential guessing — reciprocity maximized). Sequential strategy
    /// decision table: file order (flat natural order) + layered overlay
    /// (priority descending, file order within a group) + spread/fallback
    /// records + mask cooperation (done folds unselected pieces away).
    #[test]
    fn sequential_strategy_ordering_table() {
        // Fixed 8-piece counts (the sequential strategy ignores rarity; any counts work).
        let stat = {
            let mut s = PieceStatMan::new(8, &mut |n| n / 2);
            for i in 0..8u64 {
                s.add_piece(i);
            }
            s
        };
        let strategy = SequentialStrategy;
        let adv = Some(PieceBitmap::ones(8));
        let none_done = vec![false; 8];
        let no_claims = claims(8, std::iter::empty());

        // Row 1 (pure file order): first eligible = piece 0.
        assert_eq!(
            strategy.select_piece(&sctx_prio(
                adv.as_ref(),
                &none_done,
                &stat,
                &no_claims,
                None,
                None
            )),
            Some(0)
        );

        // Row 2 (mask cooperation): pieces 0..3 done (select-file folded) → piece 4.
        let mut done = vec![false; 8];
        for d in done.iter_mut().take(4) {
            *d = true;
        }
        assert_eq!(
            strategy.select_piece(&sctx_prio(
                adv.as_ref(),
                &done,
                &stat,
                &no_claims,
                None,
                None
            )),
            Some(4)
        );

        // Row 3 (spread round): piece 0 in flight (claimed) → piece 1
        // (sequential advance, no layer skip).
        let claimed0 = claims(8, [0u64]);
        assert_eq!(
            strategy.select_piece(&sctx_prio(
                adv.as_ref(),
                &none_done,
                &stat,
                &claimed0,
                None,
                None
            )),
            Some(1)
        );

        // Row 4 (fallback): all claimed → the first piece is allowed as an
        // in-flight duplicate (the dispatch layer's InFlight filter
        // backstops).
        let all_claimed = claims(8, 0..8u64);
        assert_eq!(
            strategy.select_piece(&sctx_prio(
                adv.as_ref(),
                &none_done,
                &stat,
                &all_claimed,
                None,
                None
            )),
            Some(0)
        );

        // Row 5 (layered overlay): piece 5 raised to level 7 → the
        // high-priority layer precedes the file-order head; within the layer
        // file order still applies (piece 6 shares level 7 → 5 wins first).
        let prio = [0i8, 0, 0, 0, 0, 7, 7, 0];
        assert_eq!(
            strategy.select_piece(&sctx_prio(
                adv.as_ref(),
                &none_done,
                &stat,
                &no_claims,
                None,
                Some(&prio)
            )),
            Some(5),
            "a higher-priority layer precedes lower layers' file order"
        );
        // In-layer file order: piece 5 done → the same layer takes 6 (not lower-layer piece 0).
        let mut done = vec![false; 8];
        done[5] = true;
        assert_eq!(
            strategy.select_piece(&sctx_prio(
                adv.as_ref(),
                &done,
                &stat,
                &no_claims,
                None,
                Some(&prio)
            )),
            Some(6)
        );

        // Row 6 (missing evidence = None).
        assert_eq!(
            strategy.select_piece(&sctx_prio(None, &none_done, &stat, &no_claims, None, None)),
            None
        );
    }

    /// Multi-level file priority decision table (rarest_first consumption):
    /// level precedence — a higher-level piece outranks a rarer lower-level
    /// one; same level = the existing rarest verdict (min count, then
    /// shuffled order); the None face = zero change.
    #[test]
    fn rarest_first_priority_face_decision_table() {
        fn ctx<'a>(
            adv: Option<&'a PieceBitmap>,
            done: &'a [bool],
            stats: &'a PieceStatMan,
            claimed: &'a ClaimedSet,
            prio: Option<&'a [i8]>,
        ) -> SelectionCtx<'a> {
            sctx_prio(adv, done, stats, claimed, None, prio)
        }
        // 8 pieces, shuffle |n|/2; peer counts: pieces 0..3 have count 3,
        // pieces 4..7 have count 1 (4..7 are rarer — the None face must pick
        // the shuffle-first of 4..7).
        let mut stat = PieceStatMan::new(8, &mut |n| n / 2);
        for i in 0..4u64 {
            for _ in 0..3 {
                stat.add_piece(i);
            }
        }
        for i in 4..8u64 {
            stat.add_piece(i);
        }
        let adv = Some(PieceBitmap::ones(8));
        let none_done = vec![false; 8];
        let claimed = claims(8, std::iter::empty());
        let strategy = RarestFirstStrategy;

        // Row 1 (None baseline): the rarest order (shuffle-first of 4..7) —
        // bit-identical to the existing verdict (zero-drift lock).
        let baseline = strategy.select_piece(&ctx(adv.as_ref(), &none_done, &stat, &claimed, None));
        assert_eq!(
            baseline,
            select_advertised_piece_spread(adv.as_ref(), &none_done, &stat, &claimed, None)
        );

        // Row 2 (level precedence): low-band piece 2 raised to 7 → picked
        // first even though its count is 3 (pieces 4..7 with count 1 are
        // rarer).
        let prio = [0i8, 0, 7, 0, 0, 0, 0, 0];
        assert_eq!(
            strategy.select_piece(&ctx(adv.as_ref(), &none_done, &stat, &claimed, Some(&prio))),
            Some(2),
            "a high-priority piece outranks a rarer lower-priority one"
        );

        // Row 3 (same level = rarest): two pieces at level 5 → the rarer one wins (the 4..7 band).
        let prio = [0i8, 0, 0, 0, 5, 0, 5, 0];
        let got =
            strategy.select_piece(&ctx(adv.as_ref(), &none_done, &stat, &claimed, Some(&prio)));
        assert!(
            got == Some(4) || got == Some(6),
            "same-level pieces pick from the rarer band: {got:?}"
        );

        // Row 4 (spread respects priority): the high-level piece is claimed →
        // the next level (rarest within level); with all claimed the fallback
        // still applies level precedence.
        let prio = [0i8, 0, 7, 0, 0, 0, 0, 0];
        let claimed2 = claims(8, [2u64]);
        assert!(
            strategy
                .select_piece(&ctx(
                    adv.as_ref(),
                    &none_done,
                    &stat,
                    &claimed2,
                    Some(&prio)
                ))
                .is_some(),
            "high-priority piece in flight -> the fallback face still yields a selection"
        );

        // Row 5 (high-level piece done → unselected): after the done fold
        // only the low-level face remains = baseline behavior.
        let mut done = vec![false; 8];
        done[2] = true;
        assert_eq!(
            strategy.select_piece(&ctx(adv.as_ref(), &done, &stat, &claimed, Some(&prio))),
            baseline,
            "after the high-priority piece is done, back to the baseline order"
        );
    }

    #[test]
    fn streaming_without_playhead_matches_rarest_first() {
        let stat = PieceStatMan::new(4, &mut |n| n / 2);
        let avail = full(4);
        let none_done = vec![false; 4];
        let mut claimed = claims(4, std::iter::empty());
        let rf = RarestFirstStrategy;
        let st = StreamingStrategy;
        for round in 0..3 {
            let a = rf.select_piece(&sctx(Some(&avail), &none_done, &stat, &claimed, None));
            let b = st.select_piece(&sctx(Some(&avail), &none_done, &stat, &claimed, None));
            assert_eq!(a, b, "round {round}: no playhead = rarest-first");
            if let Some(k) = b {
                claimed.mark_claimed(k);
            }
        }
        // Missing bitmap evidence passes through: None advertised → None.
        assert_eq!(
            st.select_piece(&sctx(None, &none_done, &stat, &claimed, None)),
            None
        );
    }

    /// Advertised awareness + BEP-53 selection overlay (constraint inputs are
    /// never relaxed per strategy): a silent peer = zero requests; a piece
    /// outside the selection (the done-mask projection) is never chosen even
    /// in-window — pieces outside `so=`/select-file are unreachable.
    #[test]
    fn streaming_respects_ads_and_selection_overlay() {
        let g = geo_mib(&[8]);
        let stat = PieceStatMan::new(8, &mut |n| n / 2);
        let stream = stream_of(&ph(0, 3, Some(BPS_3MIB)), &g, 8);
        let empty = claims(8, std::iter::empty());
        // Row 1: silent peer (None) → zero requests.
        let none_done = [false; 8];
        assert_eq!(
            StreamingStrategy.select_piece(&sctx(None, &none_done, &stat, &empty, Some(&stream))),
            None
        );
        // Row 2: piece 2 unselected (so= projected into done) → the whole
        // sequence skips it; class-0 head/tail first, remaining window pieces
        // by EDF (3,4,5).
        let avail = full(8);
        let mut done = vec![false; 8];
        done[2] = true;
        let mut picked = Vec::new();
        let mut claimed = claims(8, std::iter::empty());
        for _ in 0..7 {
            let Some(k) = StreamingStrategy.select_piece(&sctx(
                Some(&avail),
                &done,
                &stat,
                &claimed,
                Some(&stream),
            )) else {
                break;
            };
            claimed.mark_claimed(k);
            picked.push(k);
        }
        assert_eq!(
            picked,
            vec![1, 0, 6, 7, 3, 4, 5],
            "the out-of-selection window piece (2) is never picked; head/tail \
             first + remaining window EDF"
        );
    }

    /// Pure-sequential baseline (a test-only comparison strategy, not
    /// production; represents the disallowed pure-sequential form).
    struct SeqBaseline;
    impl PieceSelectionStrategy for SeqBaseline {
        fn name(&self) -> &'static str {
            "test_seq_baseline"
        }
        fn select_piece(&self, ctx: &SelectionCtx<'_>) -> Option<u64> {
            let avail = ctx.advertised?;
            (0..avail.len() as u64).find(|&k| {
                avail.get(k as usize)
                    && !ctx.done.get(k as usize).copied().unwrap_or(true)
                    && !ctx.claimed.contains(k)
            })
        }
    }

    /// Reciprocity-not-harmed statistical assertion: 3 parallel peers pick
    /// per round, settled at round end — upload potential U(t) = Σ over
    /// acquired pieces of demand(p), demand(p) = 6 − count(p) (rarer pieces
    /// are more needed by the swarm; window pieces held by all peers have
    /// demand 0). Fixture: 48 MiB single file, 8 MiB window (~17%, close to a
    /// real streaming window share). Asserts: (1) the streaming AUC strictly
    /// beats the pure-sequential baseline (the outside-window mix — the key
    /// difference from pure sequential); (2) the streaming AUC is at least
    /// 70% of rarest-first (the window-period concession is bounded: window
    /// pieces have demand 0 and outside the window the verdict matches
    /// rarest-first, so the loss comes only from window-period ordering).
    /// Deterministic simulation (fixed shuffle order); the numbers are locked
    /// to the fixture.
    #[test]
    fn streaming_reciprocity_not_harmed() {
        const N: u64 = 48;
        // Rarity: window region 0..9 held by all peers (demand 0); outside
        // 9..24 count 2 (demand 4), 24..48 count 1 (demand 5, rarer further
        // out).
        let mut stat = PieceStatMan::new(N, &mut |n| n / 2);
        for _ in 0..6u64 {
            stat.add_bitfield(|i| i < 9, N); // window pieces: all 6 peers have them
        }
        stat.add_bitfield(|i| (9..24).contains(&i), N); // count 2
        // 24..48 stay at count 1
        let demand = |p: u64| 6u64.saturating_sub(u64::from(stat.count(p)));
        let g = geo_mib(&[N]);
        // Playhead 0, window 8 MiB (bps = 8 MiB / 30 s): head {0,1} ∪
        // window {0..8} ∪ tail {22,23}.
        let stream = stream_of(&ph(0, 0, Some((8 * MIB) / STREAM_WINDOW_SECS + 1)), &g, N);
        let avail = full(N);
        let rf = RarestFirstStrategy;
        let st = StreamingStrategy;

        // 3-parallel-peer simulation: one pick each per round (in-round
        // claims make the spread visible); at round end everything settles
        // (done + claims cleared). Returns the pick order flattened by round.
        fn simulate(
            strategy: &dyn PieceSelectionStrategy,
            stream: Option<&StreamCtx>,
            stat: &PieceStatMan,
            avail: &PieceBitmap,
            n: u64,
        ) -> Vec<u64> {
            let mut done = vec![false; n as usize];
            let mut claimed = crate::dispatch::ClaimedSet::with_len(n as usize);
            let mut picks = Vec::new();
            while done.iter().filter(|&&d| d).count() < n as usize {
                let mut round: Vec<u64> = Vec::new();
                for _ in 0..3u64 {
                    if let Some(k) = strategy.select_piece(&SelectionCtx {
                        advertised: Some(avail),
                        done: &done,
                        stats: stat,
                        claimed: &claimed,
                        preferred: &[],
                        stream,
                        priority: None,
                    }) {
                        if !round.contains(&k) {
                            round.push(k);
                        }
                    }
                }
                if round.is_empty() {
                    break;
                }
                for k in &round {
                    done[*k as usize] = true;
                    picks.push(*k);
                }
                for k in round {
                    claimed.remove(k);
                }
            }
            picks
        }

        let auc = |picks: &[u64]| -> u64 {
            let mut have = 0u64;
            let mut acc = 0u64;
            for &p in picks {
                have += demand(p);
                acc += have;
            }
            acc
        };
        let seq_stat = PieceStatMan::new(N, &mut |n| n / 2);
        let picks_st = simulate(&st, Some(&stream), &stat, &avail, N);
        let picks_rf = simulate(&rf, None, &stat, &avail, N);
        let picks_seq = simulate(&SeqBaseline, None, &seq_stat, &avail, N);
        let (a_st, a_rf, a_seq) = (auc(&picks_st), auc(&picks_rf), auc(&picks_seq));
        assert_eq!(
            picks_st.len(),
            N as usize,
            "all pieces eventually acquired (completeness sanity)"
        );
        assert!(
            a_st > a_seq,
            "the outside-window mix must beat pure sequential (st {a_st} vs seq {a_seq})"
        );
        assert!(
            a_st * 10 >= a_rf * 7,
            "streaming upload potential stays >= 70% of rarest-first (st {a_st} vs rf {a_rf})"
        );
    }
}
