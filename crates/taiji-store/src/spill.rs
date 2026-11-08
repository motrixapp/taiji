//! Unverified spill area: sidecar staging when the write cache is full.
//!
//! Under verify-before-write ([`crate::verified`]) write-cache eviction
//! means destroy-and-refetch (`cache.rs` `update_min_loss`, an
//! intentional divergence from aria2's largest-first flush); even at a
//! fixed capacity, extreme shapes (endgame trickles over deep
//! connections) still evict pieces mid-assembly. On cache overflow this
//! module does not destroy: the victim piece's cells spill to a sidecar
//! file and are read back when the piece assembles — the main data files
//! keep the verified-bytes-only invariant while refetch traffic
//! disappears.
//!
//! Upstream anchor mapping: docs/design/store.md
//!
//! Hard invariants:
//! - The sidecar is a pure optimization: any IO failure degrades to
//!   "this data was never received" (store failure = today's
//!   destroy-refetch; read-back failure = piece reset-refetch); never
//!   fatal, and unverified bytes never enter the main data files. Spill
//!   files carry no fsync — losing pages to a crash means the same as
//!   "never received" (disposability is a design premise, not a defect).
//! - Same-dest exclusion: opening takes the face lock ([`FaceLock`]);
//!   busy = a definite `None` refusal (the caller degrades to no spill
//!   face), and another task's directory is never cleaned. Crash residue
//!   cleanup runs only after the lock is held.
//! - Disk budget: the cap is caller-given (pipeline default = the write
//!   cache capacity, `BH_SPILL_BYTES` overrides). An oversized single
//!   entry is not absorbed (falls back to destroy-refetch); an
//!   over-budget total displaces already-spilled entries FIFO, and
//!   displaced entries are destroyed by the caller's existing per-source
//!   teardown (pool reset + upstream bookkeeping invalidation).
//! - Spill writes stay per-cell `write_at` and do not join
//!   `BH_WRITE_COALESCE`: spill is piece-file-granular and a small share
//!   of the main-file write face, so the coalescing gain is ~0 while it
//!   would couple sidecar layout to the append cursor (`file_len`). The
//!   main-file write face (completed-piece batch writes) is the
//!   coalescing lever; see [`crate::verified`].

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::cache::DataCell;
use crate::disk::DiskWriter;
use crate::disk::FileDiskWriter;

/// Spill task directory name: first 16 hex of SHA-256 over the full dest
/// path (content-addressed — deterministic, stable across sessions, no
/// gid dependency; dest maps 1:1 to the task, collision domain 2^-64).
/// The equivalent of the spec's `.taiji-spill/<gid>`: the engine-side gid
/// is only injected with persistence (`TrackerWireConfig::persist`; None
/// for bare CLI runs/tests), so the dest hash carries the same
/// per-task-directory semantics without widening the public config
/// surface for naming.
pub fn spill_task_name(dest: &Path) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(dest.to_string_lossy().as_bytes());
    digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// Spill root: `.taiji-spill` beside the dest (single-file dest = its
/// parent; multi-file dest = the content root, taking its parent — the
/// sidecar stays out of the content directory to keep torrent file
/// listings/sync domains unpolluted).
pub fn spill_root_for_dest(dest: &Path) -> PathBuf {
    dest.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".taiji-spill")
}

/// On-disk placement of one spilled cell (ascending in-piece goff;
/// `off` = byte offset within the piece file).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SpillCell {
    goff: u64,
    len: u32,
    off: u64,
}

/// Index of one spilled piece (cells + byte count + piece-file write
/// cursor + arrival stamp). Repeated spills of the same piece (partial
/// spill, then eviction) merge in place — cells are block-granular and
/// disjoint across the cache/spill domains, and insertion keeps goff
/// ascending (read-back and coverage checks consume in the same order).
#[derive(Debug, Clone)]
struct SpillEntry {
    cells: Vec<SpillCell>,
    bytes: usize,
    /// Piece-file write cursor (append offset; = current file length).
    file_len: u64,
    stamp: u64,
}

/// Face-lock holder: a `BEGIN EXCLUSIVE` transaction on the minimal
/// sqlite database at `<task_dir>/face<N>.lock`, held for the life of
/// the connection and released on drop (connection close).
///
/// Mechanism and trade-offs mirror the taiji crate's `db_lock.rs` (the
/// existing session-db cross-process lock discipline): a
/// kernel-arbitrated lockfile — process death (including kill -9)
/// releases through the kernel, so there is no stale-lock deadlock (an
/// `O_EXCL` lockfile would deadlock after kill -9, hence not used); std
/// has no cross-platform `flock` at MSRV 1.85 (< `File::try_lock`'s
/// 1.89), while rusqlite/bundled is already in the dependency set. The
/// lock file itself is never deleted: release + unlink races a
/// concurrent opener and swaps file identity (two "holders" each locking
/// one inode).
#[derive(Debug)]
struct FaceLock {
    /// Lock-holding connection: the open `BEGIN EXCLUSIVE` lives with
    /// the connection — holding IS locking. No readers; drop releases.
    // The field is never read: its whole purpose is being held open
    // (drop = unlock), so the dead-code face is intentional.
    #[expect(dead_code, reason = "held-open connection is the lock itself")]
    conn: rusqlite::Connection,
}

/// Face-lock wait window: the fast-fail cap for a second open (not a
/// queuing slot — a busy spill face means "degrade to no spill";
/// queuing would block disk IO behind open).
const FACE_LOCK_BUSY_TIMEOUT: Duration = Duration::from_millis(300);

/// Face-lock file path: `<task_dir>/face<N>.lock` beside the face
/// directory — the face directory itself is wiped on open cleanup and
/// teardown, so the lock file cannot live inside it. Sibling faces of
/// the same task (hybrid dual-face coexistence) each hold their own lock
/// file and do not exclude each other.
fn face_lock_path(face_dir: &Path) -> PathBuf {
    let name = face_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "face".to_string());
    face_dir.with_file_name(format!("{name}.lock"))
}

/// Take the face lock: busy (`SQLITE_BUSY`/locked) or lock-surface IO
/// failure → `Err` (the caller degrades to no spill face; not fatal —
/// spill is a pure optimization).
fn acquire_face_lock(lock_path: &Path) -> Result<FaceLock, rusqlite::Error> {
    // Same conversion as the sqlite open point (the C library consumes
    // the same string semantics; an identity borrow off Windows).
    let conn = rusqlite::Connection::open(taiji_io::winpath::to_fs_path(lock_path))?;
    conn.busy_timeout(FACE_LOCK_BUSY_TIMEOUT)?;
    // Exclusive write transaction + holder record (the committed write =
    // the EXCLUSIVE lock actually held).
    conn.execute_batch(
        "BEGIN EXCLUSIVE;
         CREATE TABLE IF NOT EXISTS face_lock (holder TEXT NOT NULL);
         INSERT OR REPLACE INTO face_lock (holder) VALUES ('spill');",
    )?;
    Ok(FaceLock { conn })
}

/// Result of [`SpillStore::store`].
#[derive(Debug)]
pub struct SpillStoreOutcome {
    /// true = the piece spilled (the caller must not destroy/reset/
    /// notify — the bytes remain retrievable); false = not absorbed
    /// (single entry over budget or the write failed), cells dropped in
    /// place, the caller follows the existing destroy path.
    pub stored: bool,
    /// Pieces `(piece, bytes)` displaced by the spill area to free
    /// budget (destroy semantics; the caller follows its existing
    /// per-source teardown: pool reset + precomputed entry clearing +
    /// upstream bookkeeping invalidation; bytes = spilled bytes destroyed
    /// with the eviction, the authoritative accounting figure).
    pub displaced: Vec<(u64, usize)>,
    /// Bytes successfully written this call (observation surface; 0 when
    /// not absorbed).
    pub written: usize,
}

/// Unverified spill area (one per face; held by
/// [`crate::verified::VerifiedWriter`]).
///
/// IO discipline: synchronous positioned reads/writes
/// ([`FileDiskWriter`]), invoked only on the store pipeline's
/// `spawn_blocking` batch-buffer surface (the same thread discipline as
/// cell placement/verification).
#[derive(Debug)]
pub struct SpillStore {
    /// Spill root (`.taiji-spill`).
    root: PathBuf,
    /// Task directory (`<root>/<task name>`).
    task_dir: PathBuf,
    /// Face directory (`<task_dir>/face<N>`; parent of the cell files).
    face_dir: PathBuf,
    /// Disk budget (bytes).
    limit: usize,
    /// Spilled bytes outstanding (decremented on eviction/read-back).
    used: usize,
    /// Piece index → entry.
    entries: HashMap<u64, SpillEntry>,
    /// Arrival clock (FIFO eviction order — deliberately not isomorphic
    /// to the write cache's min-loss: spilling destroys a piece, so the
    /// cache-side "minimum loss" is unrecoverable here; oldest = most
    /// likely past its hot window).
    stamp_clock: u64,
    /// Whether the directories exist (lazy — an untriggered face leaves
    /// zero on-disk footprint, except the face-lock file, which lands at
    /// open as the occupancy claim).
    dirs_created: bool,
    /// Face lock: `Some` = this store is the face's sole holder; drop
    /// releases (connection close). `None` appears only briefly on the
    /// degraded construction path (the end state is `Some` or the store
    /// itself is `None`).
    face_lock: Option<FaceLock>,
    /// Observation surface: total spilled bytes / read-back bytes /
    /// read-back piece count (the read-back hit-rate denominator =
    /// read-back pieces + destroy-refetch pieces, the latter being the
    /// existing `evicted_unverified`).
    write_bytes_total: u64,
    read_bytes_total: u64,
    readback_pieces_total: u64,
}

impl SpillStore {
    /// Open (dest-wired): root = [`spill_root_for_dest`], task name =
    /// [`spill_task_name`], face directory = `face<N>`.
    ///
    /// Same-dest exclusion: take the face lock ([`FaceLock`]) first;
    /// busy (a live same-dest task / stale process / import residue) or
    /// lock-surface IO failure → a definite `None` refusal (the caller
    /// degrades to no spill face); another task's directory is never
    /// cleaned. Crash-residue cleanup runs after the lock is held — at
    /// that point no one else can hold the face, so only this task's own
    /// residue can be cleaned.
    pub fn open_for_dest(dest: &Path, face: usize, limit: usize) -> Option<SpillStore> {
        let root = spill_root_for_dest(dest);
        let task_dir = root.join(spill_task_name(dest));
        let face_dir = task_dir.join(format!("face{face}"));
        Self::open_locked(&root, &task_dir, &face_dir, limit)
    }

    /// Test/assembly seam: explicit-directory form (the same
    /// initialization as [`Self::open_for_dest`], directories given by
    /// the caller — not derived from dest). Still takes the face lock —
    /// the sole-holder invariant does not depend on the seam.
    pub fn open_at(face_dir: PathBuf, limit: usize) -> Option<SpillStore> {
        let task_dir = face_dir
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let root = task_dir
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        Self::open_locked(&root, &task_dir, &face_dir, limit)
    }

    /// Locked open (shared by both constructors): task directory first
    /// (the lock file needs it) → take the face lock → clean crash
    /// residue under the lock. Any failure = `None` (spill is a pure
    /// optimization; open degradation is not fatal).
    fn open_locked(
        root: &Path,
        task_dir: &Path,
        face_dir: &Path,
        limit: usize,
    ) -> Option<SpillStore> {
        std::fs::create_dir_all(taiji_io::winpath::to_fs_path(task_dir)).ok()?;
        let lock_path = face_lock_path(face_dir);
        let face_lock = match acquire_face_lock(&lock_path) {
            Ok(lock) => Some(lock),
            Err(e) => {
                tracing::warn!(target: "taiji::store::spill",
                    lock = %lock_path.display(), error = %e,
                    "spill: face lock unavailable (same-dest task alive or stale holder \
                     io error); spill disabled for this face (destroy-and-refetch)");
                return None;
            }
        };
        // Crash-residue cleanup (best effort; a missing directory on the
        // first run reaches the same ready state).
        let _ = std::fs::remove_dir_all(taiji_io::winpath::to_fs_path(face_dir));
        Some(SpillStore {
            root: root.to_path_buf(),
            task_dir: task_dir.to_path_buf(),
            face_dir: face_dir.to_path_buf(),
            limit,
            used: 0,
            entries: HashMap::new(),
            stamp_clock: 0,
            dirs_created: false,
            write_bytes_total: 0,
            read_bytes_total: 0,
            readback_pieces_total: 0,
            face_lock,
        })
    }

    /// Piece file path (`<face_dir>/<piece>`; decimal piece index —
    /// unambiguous, nothing to escape).
    fn piece_path(&self, piece: u64) -> PathBuf {
        self.face_dir.join(piece.to_string())
    }

    fn ensure_dirs(&mut self) -> io::Result<()> {
        if self.dirs_created {
            return Ok(());
        }
        std::fs::create_dir_all(taiji_io::winpath::to_fs_path(&self.face_dir))?;
        self.dirs_created = true;
        Ok(())
    }

    /// Absorb all cells of one piece (whole-entry spill — the write
    /// cache evicts whole entries, `ensure_limit_min_loss` hands over
    /// `Evicted { key, cells, bytes }`). An existing entry for the piece
    /// merges in place (append to the piece file; cell insertion keeps
    /// goff ascending — the shape of later evictions after a partial
    /// spill).
    ///
    /// Budget freeing: victim candidates exclude this piece (merge
    /// semantics — never evict yourself); when the candidates cannot
    /// cover the need, nothing is displaced (zero unnecessary loss); new
    /// data is written first (on failure the displaced candidates stay
    /// intact — files not unlinked, index untouched); unlink and
    /// accounting commit only after success.
    pub fn store(&mut self, piece: u64, cells: Vec<DataCell>) -> SpillStoreOutcome {
        let not_stored = || SpillStoreOutcome {
            stored: false,
            displaced: Vec::new(),
            written: 0,
        };
        let total: usize = cells.iter().map(DataCell::len).sum();
        if total == 0 {
            return not_stored();
        }
        if total > self.limit {
            // Single entry over budget: not absorbed (falls back to
            // destroy-refetch); no displacement attempted (evicting
            // sibling entries cannot save one entry).
            return not_stored();
        }
        if let Err(e) = self.ensure_dirs() {
            tracing::debug!(target: "taiji::store::spill", piece, error = %e,
                "spill: mkdir failed, piece falls back to destroy");
            return not_stored();
        }
        // Displacement candidates (FIFO ascending; this piece excluded —
        // merge semantics): nothing deleted — the set is computed first
        // and committed only after the write succeeds. If the candidates
        // cannot cover the need: zero unnecessary loss.
        let mut victims: Vec<u64> = Vec::new();
        let mut victims_bytes = 0usize;
        if self.used + total > self.limit {
            let mut by_stamp: Vec<(u64, u64)> = self
                .entries
                .iter()
                .filter(|(k, _)| **k != piece)
                .map(|(k, e)| (e.stamp, *k))
                .collect();
            by_stamp.sort_unstable();
            for (_, k) in by_stamp {
                if self.used + total <= self.limit + victims_bytes {
                    break;
                }
                let bytes = self.entries.get(&k).map(|e| e.bytes).unwrap_or(0);
                victims.push(k);
                victims_bytes += bytes;
            }
            if self.used + total > self.limit + victims_bytes {
                return not_stored();
            }
        }
        // Write to disk first (open the existing piece file to append, or
        // create — O_NOFOLLOW hardening comes with FileDiskWriter's
        // open/create surface; a same-piece merge appends after the write
        // cursor).
        let path = self.piece_path(piece);
        let base_off = self.entries.get(&piece).map(|e| e.file_len).unwrap_or(0);
        let mut writer: Box<dyn DiskWriter> = Box::new(FileDiskWriter::new());
        let write_result = (|| -> io::Result<usize> {
            writer.open(&path, false).map_err(io::Error::other)?;
            let mut off = base_off;
            for cell in &cells {
                writer
                    .write_at(off, cell.data())
                    .map_err(io::Error::other)?;
                off += cell.len() as u64;
            }
            Ok(total)
        })();
        let written = match write_result {
            Ok(n) => n,
            Err(e) => {
                // Write failed: a new piece falls back to destroy-refetch;
                // displaced candidates stay intact (file not unlinked,
                // index untouched — zero unnecessary loss).
                if base_off == 0 {
                    let _ = std::fs::remove_file(taiji_io::winpath::to_fs_path(&path));
                }
                tracing::debug!(target: "taiji::store::spill", piece, error = %e,
                    "spill: write failed, piece falls back to destroy");
                return not_stored();
            }
        };
        // Commit: unlink displaced entries + settle index/accounting
        // (cells are block-granular and disjoint from existing entries;
        // insertion keeps ascending order).
        let mut displaced: Vec<(u64, usize)> = Vec::with_capacity(victims.len());
        for v in &victims {
            let _ = std::fs::remove_file(taiji_io::winpath::to_fs_path(&self.piece_path(*v)));
            if let Some(e) = self.entries.remove(v) {
                self.used = self.used.saturating_sub(e.bytes);
                displaced.push((*v, e.bytes));
            }
        }
        self.stamp_clock += 1;
        let stamp = self.stamp_clock;
        let spill_cells: Vec<SpillCell> = {
            let mut off = base_off;
            cells
                .iter()
                .map(|c| {
                    let sc = SpillCell {
                        goff: c.goff(),
                        len: c.len() as u32,
                        off,
                    };
                    off += c.len() as u64;
                    sc
                })
                .collect()
        };
        self.used += written;
        self.write_bytes_total = self.write_bytes_total.saturating_add(written as u64);
        match self.entries.get_mut(&piece) {
            Some(entry) => {
                // Merge: insertion keeps goff ascending (covers/read_back
                // consume in the same order).
                for sc in spill_cells {
                    let pos = entry
                        .cells
                        .partition_point(|existing| existing.goff < sc.goff);
                    entry.cells.insert(pos, sc);
                }
                entry.bytes += written;
                entry.file_len = base_off + written as u64;
                entry.stamp = stamp;
            }
            None => {
                self.entries.insert(
                    piece,
                    SpillEntry {
                        cells: spill_cells,
                        bytes: written,
                        file_len: base_off + written as u64,
                        stamp,
                    },
                );
            }
        }
        SpillStoreOutcome {
            stored: true,
            displaced,
            written,
        }
    }

    /// Whether the spill area holds this piece (the union surface for
    /// duplicate-delivery coverage checks).
    pub fn holds(&self, piece: u64) -> bool {
        self.entries.contains_key(&piece)
    }

    /// Whether `[goff, goff+len)` is fully covered by this piece's
    /// spilled cells.
    ///
    /// Deliverable input = single blocks (≤16KiB, block-aligned), cells =
    /// whole-block union — coverage is naturally block-granular; the
    /// cursor walk mirrors [`crate::cache::CacheEntry::covers`] (guarding
    /// against silent misjudgment if the delivery granularity ever
    /// changes).
    pub fn covers(&self, piece: u64, goff: u64, len: usize) -> bool {
        if len == 0 {
            return true;
        }
        let Some(entry) = self.entries.get(&piece) else {
            return false;
        };
        let end = goff + len as u64;
        let mut cursor = goff;
        for cell in &entry.cells {
            let cell_end = cell.goff + cell.len as u64;
            if cell_end <= cursor {
                continue;
            }
            if cell.goff > cursor {
                return false;
            }
            cursor = cell_end;
            if cursor >= end {
                return true;
            }
        }
        false
    }

    /// Read back at assembly: the piece-file bytes are restored to
    /// [`DataCell`]s by cell coordinates (goff ascending; capacity = cell
    /// len — read-back cells are never appended to); the piece file is
    /// then deleted and index/accounting settle.
    ///
    /// IO failure = the piece's data is lost (semantically "never
    /// received"): the index still settles and the error propagates; the
    /// caller reset-refetches the piece — never a half read-back (no
    /// residual index left when returning Err).
    pub fn read_back(&mut self, piece: u64) -> io::Result<Vec<DataCell>> {
        let Some(entry) = self.entries.remove(&piece) else {
            return Ok(Vec::new());
        };
        self.used = self.used.saturating_sub(entry.bytes);
        let path = self.piece_path(piece);
        let result = (|| -> io::Result<Vec<DataCell>> {
            let mut reader: Box<dyn DiskWriter> = Box::new(FileDiskWriter::new());
            reader
                .open_existing(&path, true)
                .map_err(io::Error::other)?;
            let mut cells = Vec::with_capacity(entry.cells.len());
            for sc in &entry.cells {
                let mut buf = vec![0u8; sc.len as usize];
                let n = reader.read_at(sc.off, &mut buf).map_err(io::Error::other)?;
                if n != sc.len as usize {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("spill read short at piece {piece} goff {}", sc.goff),
                    ));
                }
                cells.push(DataCell::with_data(sc.goff, buf, sc.len as usize));
            }
            Ok(cells)
        })();
        // Either way: delete the piece file (consumed by read-back or
        // invalidated into refetch — not needed on either path).
        let _ = std::fs::remove_file(taiji_io::winpath::to_fs_path(&path));
        match result {
            Ok(cells) => {
                self.read_bytes_total = self.read_bytes_total.saturating_add(entry.bytes as u64);
                self.readback_pieces_total = self.readback_pieces_total.saturating_add(1);
                Ok(cells)
            }
            Err(e) => Err(e),
        }
    }

    /// Discard a piece's spilled data without reading back: when the
    /// write cache destroys/resets the piece, its spilled bytes must be
    /// invalidated too — otherwise re-delivered blocks get swallowed as
    /// benign duplicates by the coverage check while the pool counter is
    /// already reset, and the piece can never complete (stalled
    /// progress).
    pub fn drop_piece(&mut self, piece: u64) {
        if let Some(entry) = self.entries.remove(&piece) {
            self.used = self.used.saturating_sub(entry.bytes);
            let _ = std::fs::remove_file(taiji_io::winpath::to_fs_path(&self.piece_path(piece)));
        }
    }

    /// Currently outstanding bytes (observation surface).
    pub fn used_bytes(&self) -> usize {
        self.used
    }

    /// Number of pieces outstanding (observation surface).
    pub fn live_pieces(&self) -> usize {
        self.entries.len()
    }

    /// Total spilled bytes (observation surface).
    pub fn write_bytes_total(&self) -> u64 {
        self.write_bytes_total
    }

    /// Total read-back bytes (observation surface).
    pub fn read_bytes_total(&self) -> u64 {
        self.read_bytes_total
    }

    /// Read-back piece count (observation surface; the hit-rate
    /// numerator, denominator = this value + destroy-refetch pieces —
    /// the residual `evicted_unverified` count).
    pub fn readback_pieces_total(&self) -> u64 {
        self.readback_pieces_total
    }
}

impl Drop for SpillStore {
    fn drop(&mut self) {
        // Index cleanup (cell files go with the face-directory wipe).
        self.entries.clear();
        self.used = 0;
        // Release the face lock first (connection close = the kernel
        // releases the EXCLUSIVE lock; afterwards wiping our own face
        // directory cannot race anyone). The lock file itself stays (see
        // [`FaceLock`]: release+unlink races and swaps inode identity) →
        // task/root rmdir best-effort failing on the leftover lock file
        // is expected (the next task on the same face reuses the same
        // lock file; footprint bounded: one per dest×face).
        self.face_lock = None;
        // Wipe the face directory; rmdir task/root when empty (best
        // effort: non-empty = sibling faces/lock file still in use,
        // silently kept).
        let _ = std::fs::remove_dir_all(taiji_io::winpath::to_fs_path(&self.face_dir));
        let _ = std::fs::remove_dir(taiji_io::winpath::to_fs_path(&self.task_dir));
        let _ = std::fs::remove_dir(taiji_io::winpath::to_fs_path(&self.root));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "taiji-spill-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos())
                    .unwrap_or(0)
            ));
            TempDir(dir)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn cell(goff: u64, data: &[u8]) -> DataCell {
        DataCell::with_data(goff, data.to_vec(), data.len())
    }

    /// open_at test-seam adapter (lock failure = broken test environment;
    /// panic to localize).
    fn open(face_dir: PathBuf, limit: usize) -> SpillStore {
        SpillStore::open_at(face_dir.clone(), limit)
            .unwrap_or_else(|| panic!("open_at face lock unavailable: {face_dir:?}"))
    }

    /// Name derivation: deterministic + 16 hex + dest change → name
    /// change.
    #[test]
    fn task_name_is_deterministic_hex16() {
        let a = Path::new("/downloads/big torrent/file.bin");
        let n1 = spill_task_name(a);
        let n2 = spill_task_name(a);
        assert_eq!(n1, n2, "same-name derivation is stable");
        assert_eq!(n1.len(), 16);
        assert!(n1.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(spill_task_name(Path::new("/downloads/other.bin")), n1);
        // Root: single-file and multi-file dests both take the parent;
        // the sidecar stays out of the content directory.
        assert_eq!(
            spill_root_for_dest(Path::new("/dl/torrent-dir")),
            Path::new("/dl").join(".taiji-spill")
        );
        assert_eq!(
            spill_root_for_dest(Path::new("/dl/file.bin")),
            Path::new("/dl").join(".taiji-spill")
        );
    }

    /// Spill → read-back byte-exact restoration; accounting (used/live/
    /// read-back counters) settles with consumption.
    #[test]
    fn store_and_read_back_roundtrip_bytes() {
        let tmp = TempDir::new("roundtrip");
        let mut s = open(tmp.0.join("task/face0"), 1 << 20);
        let cells = vec![cell(0, b"hello "), cell(6, b"spill!")];
        let out = s.store(7, cells);
        assert!(out.stored);
        assert!(out.displaced.is_empty());
        assert_eq!(out.written, 12);
        assert_eq!(s.used_bytes(), 12);
        assert!(s.holds(7));
        assert!(s.covers(7, 0, 6));
        assert!(s.covers(7, 6, 6));
        assert!(s.covers(7, 0, 12), "full span covered across cells");
        assert!(
            !s.covers(7, 3, 12),
            "partial coverage past block granularity is not overreported (cursor walk)"
        );
        assert!(!s.covers(7, 12, 1));
        let back = s.read_back(7).unwrap_or_else(|e| panic!("read_back: {e}"));
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].data(), b"hello ");
        assert_eq!(back[1].data(), b"spill!");
        assert_eq!(back[0].goff(), 0);
        assert_eq!(back[1].goff(), 6);
        assert_eq!(s.used_bytes(), 0, "accounting settles on read-back");
        assert_eq!(s.live_pieces(), 0);
        assert_eq!(s.read_bytes_total(), 12);
        assert_eq!(s.readback_pieces_total(), 1);
        // The file was deleted on read-back.
        assert!(!tmp.0.join("task/face0/7").exists());
    }

    /// Budget displacement: FIFO evicts the oldest; a write failure means
    /// zero unnecessary loss (this test covers the success path;
    /// failure-path semantics are covered by the fallback assertions in
    /// verified.rs's in-domain tests).
    #[test]
    fn budget_displaces_oldest_entry_fifo() {
        let tmp = TempDir::new("displace");
        let mut s = open(tmp.0.join("task/face0"), 24);
        assert!(s.store(1, vec![cell(0, b"aaaaaaaaaaaa")]).stored); // 12B
        assert!(s.store(2, vec![cell(0, b"bbbbbbbbbbbb")]).stored); // 12B → full
        let out = s.store(3, vec![cell(0, b"cccccccccccc")]); // needs 12B freed
        assert!(out.stored);
        assert_eq!(
            out.displaced,
            vec![(1, 12)],
            "FIFO evicts the oldest (bytes leave with the accounting)"
        );
        assert!(!s.holds(1));
        assert!(s.holds(2));
        assert!(s.holds(3));
        assert_eq!(s.used_bytes(), 24);
        // The displaced file is gone; other read-backs are unaffected.
        assert!(!tmp.0.join("task/face0/1").exists());
        assert_eq!(
            s.read_back(2)
                .unwrap_or_else(|e| panic!("{e}"))
                .remove(0)
                .data(),
            b"bbbbbbbbbbbb"
        );
        assert_eq!(
            s.read_back(3)
                .unwrap_or_else(|e| panic!("{e}"))
                .remove(0)
                .data(),
            b"cccccccccccc"
        );
    }

    /// Single entry over budget → not absorbed (no displacement); an
    /// empty cell set is not absorbed.
    #[test]
    fn oversized_entry_rejected_without_displacement() {
        let tmp = TempDir::new("oversize");
        let mut s = open(tmp.0.join("task/face0"), 8);
        assert!(!s.store(9, vec![cell(0, b"0123456789abcdef")]).stored);
        assert_eq!(s.used_bytes(), 0);
        assert!(
            !s.store(9, Vec::new()).stored,
            "an empty cell set is not absorbed"
        );
    }

    /// Repeated spills of one piece (partial spill, then eviction) merge
    /// in place: append to the piece file, cell insertion keeps goff
    /// ascending, read-back restores in order; accounting (used/bytes)
    /// accumulates with merges.
    #[test]
    fn repeated_store_merges_entry_and_reads_back_sorted() {
        let tmp = TempDir::new("merge");
        let mut s = open(tmp.0.join("task/face0"), 1 << 20);
        assert!(s.store(4, vec![cell(0, b"aaaa"), cell(8, b"cccc")]).stored);
        assert!(s.store(4, vec![cell(16, b"dddd")]).stored);
        assert!(
            s.store(4, vec![cell(4, b"eeee")]).stored,
            "mid-span insertion"
        );
        assert_eq!(s.used_bytes(), 4 + 4 + 4 + 4);
        assert!(s.holds(4));
        // After the mid-span insertion contiguous coverage holds; the
        // [12,16) hole is not overreported.
        assert!(
            s.covers(4, 0, 12),
            "the contiguous span [0,12) is fully covered"
        );
        assert!(s.covers(4, 16, 4));
        assert!(!s.covers(4, 0, 20), "the holed span is not overreported");
        let back = s.read_back(4).unwrap_or_else(|e| panic!("{e}"));
        let goffs: Vec<u64> = back.iter().map(|c| c.goff()).collect();
        assert_eq!(
            goffs,
            vec![0, 4, 8, 16],
            "read-back in goff-ascending order"
        );
        let joined: Vec<u8> = back.iter().flat_map(|c| c.data().to_vec()).collect();
        assert_eq!(&joined[..], b"aaaaeeeeccccdddd");
        assert_eq!(s.used_bytes(), 0);
    }

    /// Drop cleanup: the face directory goes with Drop; the task/root
    /// directories stay because the face-lock file persists (the lock
    /// file is never deleted — release+unlink inode-identity race, see
    /// [`FaceLock`]; footprint bounded = one lock file per dest×face).
    #[test]
    fn drop_removes_face_dir_keeps_lock_file() {
        let tmp = TempDir::new("cleanup");
        let face = tmp.0.join(".taiji-spill/task/face0");
        {
            let mut s = open(face.clone(), 1 << 20);
            assert!(s.store(1, vec![cell(0, b"payload")]).stored);
            assert!(face.exists());
        }
        assert!(!face.exists(), "the face directory is removed with Drop");
        // The lock file persists (task/root stay with it — the non-empty
        // arm of best-effort rmdir).
        assert!(
            tmp.0.join(".taiji-spill/task/face0.lock").is_file(),
            "the face lock file persists (reused by the next task on the same face)"
        );
        assert!(tmp.0.join(".taiji-spill/task").exists());
        assert!(tmp.0.join(".taiji-spill").exists());
    }

    /// Same dest, same face: a second `open_for_dest` must be refused
    /// (`None`) and the first task's in-flight spilled pieces must
    /// survive; after release (Drop) a reopen takes over.
    #[test]
    fn same_dest_second_open_rejected_and_first_intact() {
        let tmp = TempDir::new("sec27-excl");
        let dest = tmp.0.join("file.bin");
        let mut first = SpillStore::open_for_dest(&dest, 0, 1 << 20)
            .unwrap_or_else(|| panic!("first open must succeed"));
        assert!(first.store(1, vec![cell(0, b"live-spill-bytes")]).stored);
        // A second task on the same dest (different infohash, same
        // on-disk path) opening the same face → refused.
        assert!(
            SpillStore::open_for_dest(&dest, 0, 1 << 20).is_none(),
            "second open on same dest+face must be rejected"
        );
        // The first task's in-flight spilled piece still reads back (not
        // wiped by the second open).
        assert_eq!(
            first
                .read_back(1)
                .unwrap_or_else(|e| panic!("read_back: {e}"))
                .remove(0)
                .data(),
            b"live-spill-bytes"
        );
        drop(first);
        // After release a reopen succeeds (the next task on the same dest
        // takes over; residue cleanup resumes).
        let mut second = SpillStore::open_for_dest(&dest, 0, 1 << 20)
            .unwrap_or_else(|| panic!("reopen after release must succeed"));
        assert!(!second.holds(1), "the taker starts from a zero ledger");
        assert!(second.store(2, vec![cell(0, b"fresh")]).stored);
    }

    /// Same dest, sibling faces (the hybrid dual-face coexistence shape)
    /// do not exclude each other — the face lock is keyed by `face<N>`,
    /// not a whole-task-directory lock.
    #[test]
    fn same_dest_sibling_face_coexists() {
        let tmp = TempDir::new("sec27-sibling");
        let dest = tmp.0.join("content-dir");
        let _face0 = SpillStore::open_for_dest(&dest, 0, 1 << 20)
            .unwrap_or_else(|| panic!("face0 open must succeed"));
        let mut face1 = SpillStore::open_for_dest(&dest, 1, 1 << 20)
            .unwrap_or_else(|| panic!("sibling face must coexist with face0"));
        assert!(face1.store(3, vec![cell(0, b"v2-face")]).stored);
        assert_eq!(
            face1
                .read_back(3)
                .unwrap_or_else(|e| panic!("read_back: {e}"))
                .remove(0)
                .data(),
            b"v2-face"
        );
    }

    /// Reopen (the crash-restart shape): the stale face directory is
    /// cleaned first and accounting starts at zero.
    #[test]
    fn reopen_clears_stale_face_dir() {
        let tmp = TempDir::new("reopen");
        let face = tmp.0.join("task/face0");
        {
            let mut s = open(face.clone(), 1 << 20);
            assert!(s.store(5, vec![cell(0, b"stale-bytes")]).stored);
        }
        {
            let mut s = open(face.clone(), 1 << 20);
            assert_eq!(s.used_bytes(), 0, "residue cleared to zero");
            assert!(!s.holds(5));
            assert!(s.store(6, vec![cell(0, b"fresh")]).stored);
            assert_eq!(
                s.read_back(6)
                    .unwrap_or_else(|e| panic!("{e}"))
                    .remove(0)
                    .data(),
                b"fresh"
            );
        }
    }
}
