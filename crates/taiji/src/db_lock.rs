//! Cross-process mutex for the session database (a single-session guard;
//! lockfile beside the DB).
//!
//! Why: the `.part` occupancy table (taiji-http `partfile`) is an
//! in-process `OnceLock<Mutex<HashSet>>` — two `taiji http` processes
//! started with the same arguments (or a CLI and a daemon sharing the
//! default database) would each bootstrap-resume the same in-flight task
//! and co-write one `.part` across processes (truncate-restart vs
//! bitmap-resume trampling each other). The session model is "one
//! database, one writer": in-process PersistWriter serialization is only
//! a necessary condition; the cross-process face is closed off here —
//! the second process fails fast with an explicit error, it never
//! co-writes.
//!
//! Mechanism (a sqlite write lock as a kernel-arbitrated lockfile):
//! `<db>.lock` is a minimal sqlite database; the session opens a
//! separate connection, runs `BEGIN EXCLUSIVE`, writes a holder record,
//! and holds the whole transaction until the session ends. The semantics
//! match `flock` (kernel file lock, released on process death) with no
//! new dependency and no unsafe — within this repo's MSRV (1.85) std has
//! no `File::try_lock` (stable since 1.89), while rusqlite/bundled is
//! already in the dependency set. Hard invariants:
//!
//! - The lock lives as long as the session: the lock is held while the
//!   connection is alive; on process death (including kill -9) the
//!   kernel releases the POSIX file lock and the next opener
//!   automatically recovers the lock database's hot journal — no
//!   stale-lock deadlock (an `O_EXCL` create-file scheme would deadlock
//!   after kill -9, hence not adopted);
//! - the lock file is never deleted: release + unlink races with a
//!   concurrent opener and can swap file identity (two "holders" each
//!   locking a different inode); an empty lock database lingering is
//!   harmless;
//! - no waiting: after a short `busy_timeout` window an occupied lock
//!   fails (`SQLITE_BUSY`) — a concurrent second process means "fail
//!   with an explicit error", not queueing (queued resume = implicit
//!   serialized sessions, beyond what a user expects);
//! - zero interference with the main database: the lock lives on a
//!   separate file, so this process's PersistWriter writes to the main
//!   database are unaffected;
//! - the daemon (the RPC-resident form) will join the same lock: a
//!   planned integration; today only the `taiji http` CLI holds it.
//!
//! Upstream anchor mapping: docs/design/cli.md

use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::Connection;

/// Holder wait window: the fast-fail ceiling for a second process (not a
/// queueing slot — past this the lock is judged occupied).
const LOCK_BUSY_TIMEOUT: Duration = Duration::from_millis(300);

/// Lock failure face (callers branch on it for exit codes and messaging).
#[derive(Debug)]
pub enum LockError {
    /// Already held by another session (`SQLITE_BUSY` — the expected
    /// failure of a concurrent second process).
    Held { path: PathBuf },
    /// System-level failure creating or locking the lock database.
    Io {
        path: PathBuf,
        error: rusqlite::Error,
    },
}

/// Session database lock handle: held for the session's lifetime; drop
/// (connection closed) = lock released.
#[derive(Debug)]
pub struct SessionDbLock {
    /// Lock-holding connection: the open `BEGIN EXCLUSIVE` transaction
    /// lives as long as the connection. "Held = locked" — this field has
    /// no readers; dropping it (closing the connection) releases the
    /// lock.
    #[expect(
        dead_code,
        reason = "held-for-drop only: no readers; drop (connection close) releases the lock"
    )]
    conn: Connection,
    // Live via `path()` (the diagnostic face — logs/tests carry the
    // path): dead_code never fires here, so the old #[allow(dead_code)]
    // was a stale no-op — removed, not converted to #[expect] (an
    // expectation on a lint that does not fire warns unfulfilled).
    path: PathBuf,
}

impl SessionDbLock {
    /// Take the exclusive inter-session lock on `<db>.lock`
    /// ([`LockError::Held`] if occupied; never queues). Blocking
    /// (creating the database / locking = disk IO) — callers must run it
    /// inside `spawn_blocking`.
    pub fn acquire(db_path: &Path) -> Result<Self, LockError> {
        let mut name = std::ffi::OsString::from(db_path.as_os_str());
        name.push(".lock");
        let path = PathBuf::from(name);
        // The sqlite open point converts the path the same way (the C
        // library consumes the same string semantics; identity borrow off
        // Windows. The lock/diagnostic faces keep the original path).
        let conn = Connection::open(taiji_io::winpath::to_fs_path(&path)).map_err(|error| {
            LockError::Io {
                path: path.clone(),
                error,
            }
        })?;
        conn.busy_timeout(LOCK_BUSY_TIMEOUT)
            .map_err(|error| LockError::Io {
                path: path.clone(),
                error,
            })?;
        // Exclusive write transaction + holder record (once the write
        // lands, the EXCLUSIVE lock is truly held; in rollback-journal
        // mode it blocks all reads and writes by other connections).
        conn.execute_batch(
            "BEGIN EXCLUSIVE;
             CREATE TABLE IF NOT EXISTS session_lock (holder TEXT NOT NULL);
             INSERT OR REPLACE INTO session_lock (holder) VALUES ('session');",
        )
        .map_err(|error| match error {
            rusqlite::Error::SqliteFailure(_, Some(msg))
                if msg.contains("locked") || msg.contains("busy") =>
            {
                LockError::Held { path: path.clone() }
            }
            other => LockError::Io {
                path: path.clone(),
                error: other,
            },
        })?;
        Ok(SessionDbLock { conn, path })
    }

    /// Lock database path (diagnostic face).
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(tag: &str) -> PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("tj-dblock-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap_or_else(|e| panic!("tempdir: {e}"));
        path
    }

    /// Two connections in one process are mutually exclusive (file locks
    /// are arbitrated per connection, so a second lock in the same
    /// process is also Held); re-acquiring after release works.
    #[test]
    fn second_acquire_held_then_released() {
        let dir = tempdir("held");
        let db = dir.join("taiji.sqlite3");
        let first = SessionDbLock::acquire(&db).unwrap_or_else(|e| panic!("first: {e:?}"));
        assert!(
            dir.join("taiji.sqlite3.lock").is_file(),
            "lock file sits next to the DB"
        );

        match SessionDbLock::acquire(&db) {
            Err(LockError::Held { path }) => {
                assert_eq!(path, dir.join("taiji.sqlite3.lock"))
            }
            Err(e) => panic!("second must be Held, got {e:?}"),
            Ok(_) => panic!("second acquire must not succeed while held"),
        }

        drop(first);
        let third = SessionDbLock::acquire(&db).unwrap_or_else(|e| panic!("after drop: {e:?}"));
        drop(third);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Different database paths do not interfere; the lock file is
    /// created beside the DB (`<db>.lock`).
    #[test]
    fn distinct_paths_independent_and_siblings() {
        let dir = tempdir("indep");
        let a =
            SessionDbLock::acquire(&dir.join("a.sqlite3")).unwrap_or_else(|e| panic!("a: {e:?}"));
        let b =
            SessionDbLock::acquire(&dir.join("b.sqlite3")).unwrap_or_else(|e| panic!("b: {e:?}"));
        assert_eq!(
            dir.join("a.sqlite3.lock")
                .file_name()
                .and_then(|s| s.to_str()),
            Some("a.sqlite3.lock")
        );
        assert!(dir.join("a.sqlite3.lock").is_file());
        assert!(dir.join("b.sqlite3.lock").is_file());
        drop(a);
        drop(b);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Relative path form (the default `taiji.sqlite3`) puts the lock
    /// file in the sibling relative spot.
    #[test]
    fn relative_db_path_lock_sibling() {
        let lock = SessionDbLock::acquire(Path::new("tj-dblock-rel.sqlite3"))
            .unwrap_or_else(|e| panic!("rel: {e:?}"));
        assert!(Path::new("tj-dblock-rel.sqlite3.lock").is_file());
        drop(lock);
        let _ = std::fs::remove_file("tj-dblock-rel.sqlite3.lock");
    }
}
