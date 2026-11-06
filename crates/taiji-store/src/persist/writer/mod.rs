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
//! write results;
//! - `rows`: business-row payload types (the persistence tables field by
//! field, including [`TORRENT_ACTIVE_STATES`]);
//! - `handle`: the [`PersistHandle`] async API face (bounded mpsc submit +
//! oneshot reply);
//! - `runner`: the [`PersistWriter`] entry (open + migrate via
//! `spawn_blocking`) and the dedicated blocking thread's main loop
//! (dispatching each job to its `write_*` row face);
//! - `write_progress`/`write_tracker`/`write_ipguard`/`write_dht`/
//! `write_torrent`/`write_kv`/`write_recovery`: per-table row write
//! faces (digest dedup / row-comparison skip-write semantics preserved
//! as-is; recovery = the recovery-layer derived table);
//! `write_cookie` = the unified task_cookie faces (paired
//! delete + terminal clear + the startup GC);
//! - `tests`: the former inline `#[cfg(test)]` code, moved over byte for
//! byte.

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
    DhtStateRow, HTTP_TASK_ACTIVE_STATES, HttpTaskRow, HttpTaskSnapshot, IpfilterRow,
    MediaArchiveRow, MediaFormatRow, MediaKeyRow, MediaSegmentRow, MediaTaskRow, MediaTrackRow,
    PeerBanRow, RecoveredLayerRow, TASK_KIND_HTTP, TASK_KIND_MEDIA, TORRENT_ACTIVE_STATES,
    TaskCookieRow, TorrentFileRow, TorrentProgressRow, TorrentRow, TorrentSnapshot, TrackerRow,
};
pub use runner::PersistWriter;
// The media active-state domain (the startup recovery read face's
// declaration — re-exported for the schema comment-consistency pin).
pub use write_media::MEDIA_TASK_ACTIVE_STATES;
// The unified task_cookie faces: the sweep report
// types ride the public face (the bootstrap alert/log consumers).
pub use write_cookie::{TaskCookieSweepEntry, TaskCookieSweepReport};

mod handle;
mod job;
mod observer;
mod rows;
mod runner;
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

#[cfg(test)]
mod tests;
