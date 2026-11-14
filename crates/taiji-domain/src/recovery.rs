//! Engine recovery surface: recovery event relay payloads plus
//! recovery-layer row assembly.
//!
//! Ownership: the payloads are produced by the engine (the HookRunner
//! recovery-notify slot plus the runtime admission arm); the types and pure
//! functions here are the neutral engine-to-session event vocabulary and
//! belong in the shared vocabulary layer. Neither side defines its own
//! copies: the engine subtree and the session side (events bus payloads /
//! persist assembly) re-export from here, so existing public paths do not
//! move.

use taiji_store::persist::RecoveredLayerRow;

use crate::hash_fetch::RecoveredPieceLayer;

/// `taiji.*` extension event kinds.
///
/// Namespace policy: every new event uses `taiji.*`. The aria2.* name table
/// stays frozen (the six aria2 names and `system.listNotifications` are
/// untouched); extension event names are declared through the
/// `taiji.getCapabilities` notifications list. If the product is renamed,
/// the extension surface renames with it — no dual-naming window.
///
/// Carrier relationship to the six frozen events: their payload is
/// `[{gid}]` and cannot be extended, while these payloads carry a file set.
/// They therefore run on a parallel bus with the same topology (capacity,
/// backpressure, and disconnect policy identical to the six-event bus; see
/// the session events module docs). The shared `SessionEvent` struct stays
/// frozen; extension payloads are separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecoveryEventKind {
    /// A missing-layer task activated and recovery fetching began. The
    /// engine emits on every activation (including re-activation after
    /// pause/resume); the session dedupes by gid, so the session sees it
    /// exactly once per task per session lifetime. Rebuilding the session
    /// resets the dedup bookkeeping and re-emits (making the task visible
    /// again after an admin reconnect).
    Started,
    /// Every activated missing layer has been promoted to ready; emitted
    /// exactly once per convergence wave, when the engine's remaining set
    /// empties. Failure has no dedicated event by design: the completed
    /// payload carries a status field instead. The recovery state machine
    /// has no failure terminal state (budget exhaustion stays in
    /// `recovering`, waiting for new peers), so a failure event would have
    /// no emission point; a stalled activation is observable as started
    /// without completed. The status key is a reserved slot for a future
    /// terminal-state field.
    Completed,
}

impl RecoveryEventKind {
    /// The full set (shared by iteration and consistency tests to prevent
    /// name-surface drift).
    pub const ALL: [RecoveryEventKind; 2] =
        [RecoveryEventKind::Started, RecoveryEventKind::Completed];

    /// WS notification method name (`taiji.*` extension namespace). Same
    /// source of truth as the `taiji.getCapabilities` notifications
    /// declaration: the actor injects `CapabilitiesView::notifications`
    /// from this, and a consistency test locks the two together.
    pub fn notification_method(self) -> &'static str {
        match self {
            RecoveryEventKind::Started => "taiji.recoveryStarted",
            RecoveryEventKind::Completed => "taiji.recoveryCompleted",
        }
    }
}

/// Per-file hash-recovery projection state (the getFiles missing-layer
/// face: engine snapshot -> session file entry). A kernel enum with no
/// wire strings — the RPC adapter owns the rendered words (the
/// `recoveryStatus` key and the completed event's `status` slot).
///
/// There is no failure terminal: an exhausted fetch budget stays
/// [`RecoveryStatus::Recovering`], waiting for a new peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecoveryStatus {
    /// The layer is missing and no hashes are in flight or staged yet
    /// (waiting for hash recovery; also the stuck edge where the
    /// bookkeeping is gone but the gate is still closed).
    LayerMissing,
    /// A hash fetch is in progress (requested / received / delivered).
    Recovering,
    /// The recovered layer was admitted and the gate promoted.
    Ready,
}

impl RecoveryStatus {
    /// The full set (shared by iteration and the adapter's frozen
    /// word-table test).
    pub const ALL: [RecoveryStatus; 3] = [
        RecoveryStatus::LayerMissing,
        RecoveryStatus::Recovering,
        RecoveryStatus::Ready,
    ];
}

/// Engine-to-session relay payload for recovery events (HookRunner recovery
/// notify slot). The engine side has no gid (`EngineConfig` carries none —
/// CLI/test direct runs have no session ownership); the session-side relay
/// closure stamps the gid per task before publishing to the bus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryNotice {
    pub kind: RecoveryEventKind,
    /// Client file order, **1-based** (same anchor as getFiles `index`:
    /// position in meta.files plus 1). Padding entries keep their positions
    /// so indices align with getFiles but never appear here: missing-layer
    /// bookkeeping registers only real files.
    pub files: Vec<u32>,
}

/// Runtime-admitted recovery layer to derived row assembly for persistence
/// (key = gid + file_index).
pub fn recovered_layer_row(
    gid_hex: &str,
    file_index: usize,
    rec: &RecoveredPieceLayer,
) -> RecoveredLayerRow {
    RecoveredLayerRow {
        gid: gid_hex.to_string(),
        file_index: file_index as i64,
        piece_length: i64::from(rec.piece_len),
        file_length: rec.file_len.min(i64::MAX as u64) as i64,
        pieces_root: rec.root.to_vec(),
        layer: rec
            .layer
            .iter()
            .flat_map(|h| h.iter())
            .copied()
            .collect::<Vec<u8>>(),
    }
}
