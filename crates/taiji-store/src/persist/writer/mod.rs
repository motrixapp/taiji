//! PersistWriter: the sole writer of `taiji.sqlite3` (the single
//! PersistWriter row; digest dedup follows the upstream
//! fork's `lastDigest_` trick).
//!
//! Shape: a dedicated `spawn_blocking` thread owns the `Connection`
//! (`Connection` is not `Sync`, so ownership is the single-writer proof);
//! the async side submits [`PersistJob`] over a bounded mpsc and receives
//! results via oneshot; once every handle is dropped the thread finishes
//! the queue and exits.
//!
//! Business-row semantics (dedup rules, remove semantics, the recovery
//! read face, and the in-flight bitmap divergence from aria2):
//! docs/design/store.md.
//!
//! # Module layout
//!
//! - `job`: the [`PersistJob`] single-writer command set + [`PersistOutcome`]
//!   write results;
//! - `rows`: business-row payload types (the persistence tables field by
//!   field);
//! - `handle`: the [`PersistHandle`] async API face (bounded mpsc submit +
//!   oneshot reply);
//! - `runner`: the [`PersistWriter`] entry (open + migrate via
//!   `spawn_blocking`) and the dedicated blocking thread's main loop
//!   (dispatching each job to its `write_*` row face);
//! - `write_progress`/`write_tracker`/`write_ipguard`/`write_dht`/
//!   `write_torrent`/`write_kv`/`write_recovery`: per-table row write
//!   faces (digest dedup / row-comparison skip-write semantics preserved
//!   as-is; recovery = the recovery-layer derived table);
//!   `write_cookie` = the unified task_cookie faces (paired
//!   delete + terminal clear + the startup GC);
//! - `tests`: the former inline `#[cfg(test)]` code, moved over byte for
//!   byte.

#[cfg(test)]
use crate::error::StoreError;
#[cfg(test)]
use rusqlite::{Connection, OptionalExtension, params};
#[cfg(test)]
use std::path::PathBuf;

#[cfg(test)]
use self::write_tracker::TrackerRowCmp;

pub use handle::PersistHandle;
pub use job::{MediaTrackSet, PersistJob, PersistOutcome};
pub use observer::{PersistObserve, SharedPersistObserve};
pub use rows::{
    DhtStateRow, HttpTaskRow, HttpTaskSnapshot, IpfilterRow, MediaArchiveRow, MediaFormatRow,
    MediaKeyRow, MediaSegmentRow, MediaTaskRow, MediaTrackRow, PeerBanRow, RecoveredLayerRow,
    TASK_KIND_HTTP, TASK_KIND_MEDIA, TaskCookieRow, TorrentFileRow, TorrentProgressRow, TorrentRow,
    TorrentSnapshot, TrackerRow,
};
pub use runner::PersistWriter;
// The unified task-phase vocabulary over the three persisted `state`
// columns (torrent/http/media) — the enum + parse/coarse faces and the
// derived word sets ([`TaskPhase::active_words`] and kin) that the
// write/read faces consume; see the task_phase module doc for the
// landing rationale.
pub use task_phase::{TaskFamily, TaskPhase, TaskPhaseError};
// The unified task_cookie faces: the sweep report
// types ride the public face (the bootstrap alert/log consumers).
pub use write_cookie::{TaskCookieSweepEntry, TaskCookieSweepReport};

mod handle;
mod job;
mod observer;
mod rows;
mod runner;
mod task_phase;
mod write_cookie;
mod write_dht;
mod write_http;
mod write_ipguard;
mod write_kv;
mod write_media;
mod write_progress;
mod write_recovery;
mod write_torrent;
mod write_tracker;

/// Write-point state validation shared by the three task-row upsert
/// faces (torrent/http/media): parse the payload's `state` string
/// against the unified v1 vocabulary
/// ([`TaskPhase::parse_v1`]) and require the family's declared value
/// domain ([`TaskPhase::applies_to`]).
///
/// A writer-side defense under row serialization: the producers are
/// typed upstream (the store's row payloads carry `state: String`, so a
/// hand-built or imported row can smuggle any string), and the DDL
/// carries no CHECK on these columns (schema frozen until the v4
/// tightening). The refusal is explicit — an unknown string (case
/// drift, a projection word) and a cross-family word (a torrent
/// `metadata` presented as an http row) never silently land; the error
/// carries the offending value verbatim. The parsed phase rides back so
/// the caller's guards ([`TaskPhase::is_terminal`] /
/// [`TaskPhase::is_guarded`]) classify the payload by variant instead
/// of a second string lookup.
pub(super) fn validate_task_state(
    state: &str,
    family: TaskFamily,
    table: &str,
) -> Result<TaskPhase, crate::error::StoreError> {
    match TaskPhase::parse_v1(state) {
        Ok(phase) if phase.applies_to(family) => Ok(phase),
        Ok(phase) => Err(crate::error::StoreError::Internal(format!(
            "{table} row state {state:?} ({phase:?}) is outside the {table} family's declared \
             value domain"
        ))),
        Err(e) => Err(crate::error::StoreError::Internal(format!(
            "{table} row state {e}"
        ))),
    }
}

#[cfg(test)]
mod tests;
