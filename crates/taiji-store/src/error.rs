//! Unified store-layer errors (thiserror per crate; normalized across
//! crates in core).
//!
//! Establishes the error-convention base; the disk-error classification
//! (`NoSpace`/`FileIo`) expands within this enum as follow-up tasks land —
//! the single source for RPC error mapping remains taiji-rpc.

/// Store-layer errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// sqlite operation failure (open/migrate/execute).
    #[error("store: sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// The database file is corrupt or not a valid sqlite db (normalized to
    /// this variant when the PRAGMA probe on the open path fails, so
    /// callers get a clear error instead of a panic).
    #[error("store: corrupt database at {path}: {source}")]
    CorruptDatabase {
        path: String,
        source: rusqlite::Error,
    },

    /// Migration version rollback (db newer than the code) — refuse to
    /// write to an unknown schema.
    #[error("store: database user_version {db} is newer than supported {supported}")]
    MigrationVersionMismatch { db: i64, supported: i64 },

    /// Fork sqlite schema probe failure (importer: the `--from-aria2-db`
    /// db's user_version ≠ 1 or its task/task_progress tables are missing —
    /// including the case of mistakenly pointing at taiji.sqlite3; an
    /// explicit rejection under SPEC §10 / read-only discipline).
    #[error("store: not an legacy aria2-fork v1 database at {path} (user_version {version})")]
    ForkSchema { path: String, version: i64 },

    /// The fork db is write-locked (first Phase B precheck): the read-only
    /// open/read probe hits SQLITE_BUSY — a strong signal that an old
    /// aria2-fork/Motrix process is still running; the importer refuses and
    /// asks for the old version to be exited rather than forcing through
    /// the lock.
    #[error(
        "store: fork database is locked at {path} (SQLITE_BUSY): the old \
         Motrix (legacy aria2-fork) process may still be running; exit it and retry"
    )]
    ForkLocked { path: String },

    /// The PersistWriter has exited (a command submitted after all handles
    /// were dropped).
    #[error("store: persist writer closed")]
    WriterClosed,

    /// The target db is still in concurrent use (the enforced "target db
    /// offline" point before an import actually writes): `-wal`/`-shm`
    /// sidecars on disk = a local taiji session is alive or the last exit
    /// was unclean (checkpoint-busy as the fallback test) — prechecks
    /// refuse to force a snapshot out from under an active session.
    #[error(
        "store: target database is in use at {path}: stop the local taiji \
         session before import"
    )]
    TargetInUse { path: String },

    /// Disk full (cross-validation: aria2 `isDiskFullError`, ENOSPC ->
    /// NOT_ENOUGH_DISK_SPACE).
    #[error("store: no space left on device at {path}: {source}")]
    NoSpace {
        path: String,
        source: std::io::Error,
    },

    /// General file IO failure (open/read/write/fsync etc., other than
    /// ENOSPC).
    #[error("store: file io at {path}: {source}")]
    FileIo {
        path: String,
        source: std::io::Error,
    },

    /// A DiskWriter used before open/create (a programming error, not an IO
    /// fault).
    #[error("store: disk writer has no open file")]
    FileNotOpen,

    /// Platform/feature explicitly unsupported (Windows stubs, F_NOCACHE
    /// etc. — never pretend to work; real implementations fail their tasks
    /// here).
    #[error("store: unsupported feature: {0}")]
    Unsupported(String),

    /// A duplicate block pushed for an already-complete piece (a late
    /// response from another peer for the same block). Benign: the caller
    /// (the write pipeline) drops the late block; not a fault.
    #[error("store: piece {index} already complete: duplicate block")]
    PieceAlreadyComplete { index: u64 },

    /// Hybrid cross-check failure: the same piece disagrees between the
    /// v1/v2 hash forms (BEP-52 "inconsistency detected") -> torrent-level
    /// failure; the piece data is not written to disk.
    #[error("store: hybrid cross-check failed at piece {piece}: v1/v2 hashes inconsistent")]
    CrossCheckFailed { piece: u64 },

    /// Piece/block range errors from the hash pool (in-piece bounds,
    /// block alignment, duplicate-completion bookkeeping). Carried with
    /// its source chain intact (callers `?` it) instead of being
    /// flattened into `Internal(String)`; matchability preserved
    /// (`RangeError::PieceAlreadyComplete` still maps to the dedicated
    /// [`StoreError::PieceAlreadyComplete`] at its site).
    #[error("store: piece range: {0}")]
    Range(#[from] crate::hashpool::RangeError),

    /// Hash-tree cache errors (v2 verify-input paths). Carried with its
    /// source chain intact instead of being flattened into
    /// `Internal(String)`; the benign fallback arms
    /// (`LeafLayerNotCached`/`UnknownRoot`) are matched before this.
    #[error("store: hash tree: {0}")]
    Tree(#[from] crate::hashtree::TreeError),

    /// Layout resolution errors (goff -> file mapping). Carried with its
    /// source chain intact instead of being flattened into
    /// `Internal(String)`.
    #[error("store: layout: {0}")]
    Layout(#[from] crate::layout::LayoutError),

    /// Internal error (serialization / task panic and other paths that
    /// should not normally happen).
    #[error("store: internal: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corrupt_database_message_contains_path() {
        let e = StoreError::CorruptDatabase {
            path: "/tmp/taiji.sqlite3".into(),
            source: rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(11), // SQLITE_CORRUPT
                Some("file is not a database".into()),
            ),
        };
        let msg = e.to_string();
        assert!(msg.contains("/tmp/taiji.sqlite3"), "{msg}");
        assert!(msg.contains("corrupt"), "{msg}");
    }
}
