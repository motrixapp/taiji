//! TorrentWriter: layout-aware multi-file write entry point (SPEC §5.1).
//!
//! Implements [`DiskWriter`]: global-offset reads/writes are split across
//! the layout's files, pad ranges are skipped on write and served as
//! zeros (BEP47 L87), so the [`crate::verified`] pipeline serves
//! multi-file torrents without changes.
//!
//! Write de-serialization: the write path is `write_at(&self)` with
//! per-file handles handed out as cloned `Arc` values from a pool (see
//! [`WriteHandles`]) — multiple workers write non-overlapping goff spans
//! concurrently; non-write operations (open/allocate/flush) stay
//! serialized by the upper layer's
//! [`crate::verified::SharedDiskWriter`] exclusive domain.
//!
//! Upstream anchor mapping: docs/design/store.md

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::disk::DiskWriter;
use crate::disk_policy::{AllocationMode, IoGate};
use crate::error::StoreError;
use crate::handle_pool::HandlePool;
use crate::layout::Layout;
use crate::lock;

/// Read-side handle pool capacity, the same value as the write side
/// (the `crate::engine::pipeline` constructs
/// `TorrentWriter::new(_, _, 100)`): aria2 caps globally open files at
/// 100 by default (`OptionHandlerFactory.cc` `--bt-max-open-files`). The
/// read pool mirrors libtorrent's read-only file tables
/// (`file_view_pool` / `file_pool_impl<FileEntry>`, mmap/pread twin
/// instances in `file_view_pool.cpp`): the read path holds handles
/// independently of the write pool, so `open` drops from O(requests) to
/// O(active files).
pub const READER_MAX_OPEN_HANDLES: usize = 100;

/// Read-side shared handle pool: layout-relative path → read-only
/// [`crate::disk::FileDiskWriter`]. `Arc` values mean acquiring a handle
/// is a clone and pread runs outside the pool lock (concurrent reads are
/// not serialized; `File::read_at` is pread, safe on a shared fd).
type SharedHandles = Arc<Mutex<HandlePool<PathBuf, Arc<crate::disk::FileDiskWriter>>>>;

/// Request span of the batched read primitive (goff = layout global
/// offset; len = requested bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadSpec {
    pub goff: u64,
    pub len: usize,
}

/// Coalesced adjacent-read result: one sequential large-read span plus a
/// map of the absorbed read spans `(spec index, offset within the merged
/// span)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergedRead {
    pub goff: u64,
    pub len: usize,
    parts: Vec<(usize, u32)>,
}

impl MergedRead {
    /// Absorbed read spans (spec indices in caller submission order).
    pub fn parts(&self) -> &[(usize, u32)] {
        &self.parts
    }
}

/// Coalesce adjacent reads (pure function; the sequential large-read
/// surface behind libtorrent's "coalesce the small bittorrent requests",
/// `docs/manual.rst`):
/// - `max_bytes` caps a merged span's bytes; `max_ranges` caps the
/// absorbed spans per merged span; either 0 → no merging (1:1 identity
/// mapping; the default throughput profile is unchanged).
/// - Only adjacent spans merge (`prev.goff + prev.len == next.goff`);
/// gaps split spans; overlapping spans are tolerated (the merged span
/// is the union and each span reads back its own bytes).
/// - Input order is arbitrary (sorted stably by goff internally; parts
/// records the original indices).
pub fn coalesce_reads(specs: &[ReadSpec], max_bytes: usize, max_ranges: usize) -> Vec<MergedRead> {
    if specs.is_empty() {
        return Vec::new();
    }
    if max_bytes == 0 || max_ranges == 0 {
        return specs
            .iter()
            .enumerate()
            .map(|(i, s)| MergedRead {
                goff: s.goff,
                len: s.len,
                parts: vec![(i, 0)],
            })
            .collect();
    }
    let mut order: Vec<usize> = (0..specs.len()).collect();
    order.sort_by_key(|&i| specs[i].goff);
    let mut out: Vec<MergedRead> = Vec::new();
    let mut group: Option<MergedRead> = None;
    for &si in &order {
        let s = specs[si];
        let spec_end = s.goff + s.len as u64;
        let absorb = match &group {
            Some(g) => {
                let group_end = g.goff + g.len as u64;
                s.goff <= group_end
                    && spec_end - g.goff <= max_bytes as u64
                    && g.parts.len() < max_ranges
            }
            None => false,
        };
        match (&mut group, absorb) {
            (Some(g), true) => {
                g.len = (spec_end - g.goff).max(g.len as u64) as usize;
                g.parts.push((si, (s.goff - g.goff) as u32));
            }
            (Some(g), false) => {
                out.push(std::mem::replace(
                    g,
                    MergedRead {
                        goff: 0,
                        len: 0,
                        parts: Vec::new(),
                    },
                ));
                group = Some(MergedRead {
                    goff: s.goff,
                    len: s.len,
                    parts: vec![(si, 0)],
                });
            }
            (None, _) => {
                group = Some(MergedRead {
                    goff: s.goff,
                    len: s.len,
                    parts: vec![(si, 0)],
                });
            }
        }
    }
    if let Some(g) = group {
        out.push(g);
    }
    out
}

/// Read-only view: cross-file reads plus pad zero-fill. Shared by the
/// seeding data source (core via adapter) and TorrentWriter's read path.
///
/// Handle policy:
/// - [`TorrentReader::new`] = no pool; handles open/close temporarily per
/// file span (existing behavior — short-lived callers such as recheck
/// and TorrentWriter delegated reads keep it);
/// - [`TorrentReader::with_handle_pool`] = a shared LRU handle pool (the
/// caller holds it for the data source's lifetime); `open` drops from
/// O(requests) to O(active files) (see [`READER_MAX_OPEN_HANDLES`]).
pub struct TorrentReader {
    layout: Layout,
    root: PathBuf,
    handles: Option<SharedHandles>,
}

/// Read-handle shape: pooled (clone an [`Arc`], pread outside the lock)
/// or temporary (open/close per span, existing behavior).
enum ReadHandle {
    Pooled(Arc<crate::disk::FileDiskWriter>),
    Temp(Box<crate::disk::FileDiskWriter>),
}

impl ReadHandle {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, StoreError> {
        let w: &dyn DiskWriter = match self {
            ReadHandle::Pooled(w) => w.as_ref(),
            ReadHandle::Temp(w) => w.as_ref(),
        };
        w.read_at(offset, buf)
    }
}

impl std::fmt::Debug for TorrentReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redacted: the read-handle pool is behind a Mutex and Debug must
        // not take that lock (formatting from another thread would block
        // on in-flight reads) — only its presence is reported.
        f.debug_struct("TorrentReader")
            .field("layout", &self.layout)
            .field("root", &self.root)
            .field("pooled", &self.handles.is_some())
            .finish()
    }
}

impl TorrentReader {
    pub fn new(layout: Layout, root: PathBuf) -> TorrentReader {
        TorrentReader {
            layout,
            root,
            handles: None,
        }
    }

    /// Pooled constructor: `max_open` is the LRU handle cap
    /// ([`READER_MAX_OPEN_HANDLES`]; counting semantics from aria2
    /// `OpenedFileCounter.cc`, LRU close being the improvement noted in
    /// SPEC §5.1 — the write-side [`HandlePool`] matches).
    pub fn with_handle_pool(layout: Layout, root: PathBuf, max_open: usize) -> TorrentReader {
        TorrentReader {
            layout,
            root,
            handles: Some(Arc::new(Mutex::new(HandlePool::new(max_open)))),
        }
    }

    /// Handles currently open in the pool (0 without a pool);
    /// observation surface for tests and benchmarks.
    pub fn open_handles(&self) -> usize {
        self.handles
            .as_ref()
            .map(|p| lock(p).open_count())
            .unwrap_or(0)
    }

    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// Acquire a read handle for one file span: pooled = open/LRU
    /// bookkeeping under the pool lock (a synchronous primitive; callers
    /// run in blocking context — no await under the lock), then pread
    /// outside the lock; unpooled = temporary open (existing behavior;
    /// missing files surface as errors).
    fn acquire_read_handle(&self, rel: &Path) -> Result<ReadHandle, StoreError> {
        match &self.handles {
            None => {
                let full = self.root.join(rel);
                let mut w = Box::new(crate::disk::FileDiskWriter::new());
                w.open_existing(&full, true)?;
                Ok(ReadHandle::Temp(w))
            }
            Some(pool) => {
                let mut g = lock(pool);
                let handle = g
                    .get_or_open_with(
                        &rel.to_path_buf(),
                        |key| {
                            // Pool key = layout-relative path; the opener
                            // closure joins the captured root into the full
                            // path (same shape as the write-side open).
                            // Missing/unopenable files propagate as errors.
                            let full = self.root.join(key);
                            let mut w = crate::disk::FileDiskWriter::new();
                            w.open_existing(&full, true)?;
                            Ok::<_, StoreError>(Arc::new(w))
                        },
                        |_, handle| drop(handle),
                    )?
                    .clone();
                drop(g);
                Ok(ReadHandle::Pooled(handle))
            }
        }
    }

    /// Batched read primitive: merge adjacent read spans into sequential
    /// large reads, then scatter the bytes back into each span's buffer.
    /// Each merged span opens each involved file exactly once and reads
    /// it exactly once (versus an open+read per 16KiB span with per-span
    /// `read_at` — the main HDD seek win); `gate` is the IO quota bucket
    /// shared with write flush (1 op per merged span; `None` = unlimited,
    /// existing behavior).
    ///
    /// Semantics are identical to per-span `read_at`: pad ranges served
    /// as zeros (BEP47 L87), EOF short-read remainder treated as sparse
    /// zeros, missing/unopenable files propagate as errors. Returns are
    /// aligned with `specs` order.
    ///
    /// Merge limits come from the caller-side
    /// [`crate::disk_policy::DiskPolicy`] read-coalescing parameters
    /// (0 = no merging; the throughput profile is unchanged).
    pub fn read_coalesced(
        &self,
        specs: &[ReadSpec],
        max_bytes: usize,
        max_ranges: usize,
        gate: Option<&IoGate>,
    ) -> Result<Vec<Vec<u8>>, StoreError> {
        let mut out: Vec<Vec<u8>> = specs.iter().map(|s| vec![0u8; s.len]).collect();
        let mut outs: Vec<&mut [u8]> = out.iter_mut().map(|v| v.as_mut_slice()).collect();
        self.read_coalesced_bufs(specs, &mut outs, max_bytes, max_ranges, gate)?;
        Ok(out)
    }

    /// Caller-buffered form of [`TorrentReader::read_coalesced`]: output
    /// buffers are caller-owned (pooled read blocks fill in place,
    /// removing per-request allocation; the minimal read-side pool is
    /// bt::peer::ReadPool). Constraints: `outs[i].len() >= specs[i].len`;
    /// the `specs[i].len` prefix of each buffer is fully defined (pad
    /// spans, EOF remainders, and beyond-total tails are explicitly
    /// zeroed — pooled buffers hold stale bytes and must not rely on zero
    /// initialization). Returns the actually filled length per spec
    /// (same semantics as per-span [`TorrentReader::read_at`]: covered
    /// length within the layout total; the EOF short-read remainder still
    /// counts as filled, matching read_at's `filled += take`). IO errors
    /// (missing files) fail the whole batch — callers reject per request
    /// accordingly.
    pub fn read_coalesced_bufs(
        &self,
        specs: &[ReadSpec],
        outs: &mut [&mut [u8]],
        max_bytes: usize,
        max_ranges: usize,
        gate: Option<&IoGate>,
    ) -> Result<Vec<usize>, StoreError> {
        if specs.len() != outs.len() {
            return Err(StoreError::Internal(
                "read_coalesced_bufs: specs/outs length mismatch".into(),
            ));
        }
        for (s, o) in specs.iter().zip(outs.iter()) {
            if o.len() < s.len {
                return Err(StoreError::Internal(
                    "read_coalesced_bufs: out buffer shorter than spec".into(),
                ));
            }
        }
        let merged = coalesce_reads(specs, max_bytes, max_ranges);
        for m in &merged {
            if let Some(g) = gate {
                // Synchronous primitive (callers run in blocking context —
                // see read_coalesced docs).
                g.acquire_blocking(1);
            }
            // Scratch for the merged span (one allocation per span,
            // span-granular rather than block-granular; block reuse for
            // the serve surface lives in bt::peer::ReadPool).
            let mut scratch = vec![0u8; m.len];
            self.read_merged_range_into(m, &mut scratch)?;
            for (si, rel) in m.parts() {
                let s = specs[*si];
                let rel = *rel as usize;
                outs[*si][..s.len].copy_from_slice(&scratch[rel..rel + s.len]);
            }
        }
        // filled matches per-span read_at: covered length within the
        // layout total (pad spans and EOF short-read remainders both
        // count as filled).
        Ok(specs
            .iter()
            .map(|s| self.layout.total().saturating_sub(s.goff).min(s.len as u64) as usize)
            .collect())
    }

    /// Sequential read of one merged span into the caller's buffer (pad
    /// zero-fill + EOF short-read zeros + beyond-total tail zeros +
    /// missing files propagate — same semantics as
    /// [`TorrentReader::read_at`] but with one handle open and one read
    /// per file). Every byte of the buffer is explicitly defined (pooled
    /// reused buffers hold stale bytes; zero initialization is not
    /// assumed).
    fn read_merged_range_into(&self, m: &MergedRead, buf: &mut [u8]) -> Result<(), StoreError> {
        let end = m.goff + m.len as u64;
        let mut pos = m.goff;
        let mut filled = 0usize;
        while pos < end {
            // Beyond the layout total = sparse zeros (same as read_at's
            // EOF short-read remainder).
            if pos >= self.layout.total() {
                break;
            }
            let (idx, in_file) = self.layout.locate(pos)?;
            let (f_path, f_length, f_padding) = {
                let f = &self.layout.files()[idx];
                (f.path.clone(), f.length, f.padding)
            };
            let file_room = (f_length - in_file) as usize;
            let take = file_room.min((end - pos) as usize);
            if take == 0 {
                break;
            }
            let base = (pos - m.goff) as usize;
            if !f_padding {
                // Missing/unopenable files propagate as errors (silently
                // keeping a zero buffer with Ok would serve sparse zeros
                // for pieces the bitmap claims complete → swarm hash-fail
                // storms + this end gets banned; upstream anchor: aria2
                // surfaces read failures and refuses unservable requests
                // rather than returning zeros). EOF short-read remainders
                // stay sparse zeros (download-time semantics unchanged);
                // real IO errors propagate as-is.
                let handle = self.acquire_read_handle(&f_path)?;
                let n = handle.read_at(in_file, &mut buf[base..base + take])?;
                buf[base + n..base + take].fill(0);
            } else {
                // Pad ranges zero-fill (BEP47 L87 serving duty; explicit
                // clear — pooled buffers hold stale bytes).
                buf[base..base + take].fill(0);
            }
            filled += take;
            pos += take as u64;
        }
        // Tail beyond the layout total = sparse zeros (explicitly
        // cleared, as above).
        buf[filled..m.len].fill(0);
        Ok(())
    }

    /// Global-offset read: file ranges read from disk (EOF short-read
    /// remainder treated as sparse zeros; missing/unopenable files
    /// propagate as errors, so piece/hash serving paths reject instead
    /// of serving zero bytes), pad ranges zero-filled (BEP47 L87 serving
    /// duty). Returns the actually filled byte count.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, StoreError> {
        let mut goff = offset;
        let mut filled = 0usize;
        while filled < buf.len() {
            if goff >= self.layout.total() {
                break;
            }
            let (idx, in_file) = self.layout.locate(goff)?;
            let (f_path, f_length, f_padding) = {
                let f = &self.layout.files()[idx];
                (f.path.clone(), f.length, f.padding)
            };
            let file_room = (f_length - in_file) as usize;
            let take = file_room.min(buf.len() - filled);
            if take == 0 {
                break;
            }
            if f_padding {
                buf[filled..filled + take].fill(0);
            } else {
                // Missing/unopenable files propagate as errors (a silent
                // `Err(_) => 0` zero-fill would stream garbage for a
                // missing file → swarm hash-fail storms + this end gets
                // banned; upstream anchor: aria2 surfaces read failures
                // and refuses the piece request instead of silently
                // returning zeros). EOF short-read remainders of existing
                // but not-yet-full files stay sparse zeros (download-time
                // semantics unchanged). Handle policy follows the
                // constructor: pooled = LRU reuse (open drops from
                // O(requests) to O(active files)); unpooled = temporary
                // open (existing behavior).
                let handle = self.acquire_read_handle(&f_path)?;
                let n = handle.read_at(in_file, &mut buf[filled..filled + take])?;
                buf[filled + n..filled + take].fill(0);
            }
            filled += take;
            goff += take as u64;
        }
        Ok(filled)
    }
}

/// Write-side shared handle pool: layout-relative path → open write-only
/// handle. `Arc` values mean acquiring a handle is a clone and pwrite
/// runs outside the pool lock (the lock guards only a microsecond-scale
/// open/LRU bookkeeping critical section; write syscalls run unlocked;
/// same shape as the read-side `SharedHandles` above). unix: concurrent
/// pwrite at different offsets on one fd is safe (POSIX pread/pwrite
/// atomicity; `File::write_all_at`); Windows: `seek_write` is not
/// thread-safe — the concurrency surface is guaranteed by the upper
/// layer's [`crate::verified::SharedDiskWriter`] write-exclusive domain
/// (platform split), while the pool bookkeeping itself is thread-safe
/// and identical on both platforms.
type WriteHandles = Mutex<HandlePool<PathBuf, Arc<crate::disk::FileDiskWriter>>>;

/// Layout-aware write entry point, one per torrent.
pub struct TorrentWriter {
    layout: Layout,
    root: PathBuf,
    pool: WriteHandles,
}

impl std::fmt::Debug for TorrentWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redacted: the write-handle pool is behind a Mutex and Debug
        // must not take that lock (formatting from another thread would
        // block on in-flight writes) — only the identity fields are
        // reported.
        f.debug_struct("TorrentWriter")
            .field("layout", &self.layout)
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl TorrentWriter {
    pub fn new(layout: Layout, root: PathBuf, max_open: usize) -> TorrentWriter {
        TorrentWriter {
            layout,
            root,
            pool: Mutex::new(HandlePool::new(max_open)),
        }
    }

    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    pub fn open_handles(&self) -> usize {
        lock(&self.pool).open_count()
    }

    fn file_path(&self, path: &Path) -> PathBuf {
        self.root.join(path)
    }

    /// Acquire a write handle: open/LRU bookkeeping under the pool lock
    /// (a synchronous primitive; callers run in blocking context — no
    /// await under the lock and the only syscall under it is the open),
    /// then pwrite outside the lock (same shape as the read-side
    /// `acquire_read_handle`). LRU eviction closing a handle cannot race
    /// an in-flight pwrite — `Arc` holders keep the `File` alive until
    /// the write completes.
    fn write_handle(&self, path: &Path) -> Result<Arc<crate::disk::FileDiskWriter>, StoreError> {
        let full = self.file_path(path);
        let mut g = lock(&self.pool);
        let handle = g
            .get_or_open_with(
                &path.to_path_buf(),
                |_key| {
                    // Pool key = layout-relative path; the opener closure
                    // opens the captured full path.
                    let mut w = crate::disk::FileDiskWriter::new();
                    w.open_existing(&full, false)?;
                    Ok::<_, StoreError>(Arc::new(w))
                },
                |_, handle| drop(handle),
            )?
            .clone();
        Ok(handle)
    }

    /// Allocate (trunc semantics): create + truncate each non-pad file to
    /// its layout length; zero-length files are created too (aria2
    /// MultiDiskAdaptor.cc); pads are never created. Handles close right
    /// after creation (allocation is a side operation and does not
    /// consume the steady-open budget).
    pub fn allocate(&mut self) -> Result<(), StoreError> {
        self.allocate_with(AllocationMode::Trunc)
    }

    /// Allocate per mode, each non-pad file in turn (pads never created):
    ///
    /// - Already on disk → open only, no allocation, no truncation
    /// (truncating first would destroy preloaded payloads in the
    /// "re-seed existing payload" scenario; the upstream anchor is
    /// aria2 `AbstractDiskWriter::openFile`: try `openExistingFile`
    /// (O_RDWR without O_TRUNC) first and only create via
    /// `initAndOpenFile` → `createFile` on ENOENT; `MultiDiskAdaptor.cc`
    /// applies the same policy per file). Trade-off: aria2 refuses the
    /// task by default when files already exist on disk without a
    /// control file (`RequestGroup.cc` FILE_ALREADY_EXISTS; only
    /// `--check-integrity`/`--allow-overwrite`/`--bt-seed-unverified`
    /// let it through); the add path here has no startup recheck flow
    /// yet, so it takes the `--allow-overwrite` open semantics —
    /// existing bytes are preserved and the bitmap downloads from
    /// zero. falloc/prealloc run only for newly created files (the
    /// allocation contract is only ever valid for new empty files, see
    /// [`DiskWriter::allocate`]).
    /// - Missing → create + allocate to the layout length per mode;
    /// zero-length files are created too (aria2 MultiDiskAdaptor.cc);
    /// handles close right after creation (allocation is a side
    /// operation and does not consume the steady-open budget).
    pub fn allocate_with(&mut self, mode: AllocationMode) -> Result<(), StoreError> {
        for f in self.layout.files() {
            if f.padding {
                continue;
            }
            let path = f.path.clone();
            let length = f.length;
            let full = self.file_path(&path);
            let mut w: Box<dyn DiskWriter> = Box::new(crate::disk::FileDiskWriter::new());
            if full.exists() {
                // Existing file: open semantics — data preserved (no
                // truncation, no zero-fill; logged as not allocated).
                w.open_existing(&full, false)?;
                tracing::info!(target: "taiji::store::torrent_writer",
                    path = %full.display(),
                    "file exists: opened without allocation (existing data preserved)");
                drop(w);
                continue;
            }
            w.create(&full)?;
            let effect = w.allocate(length, mode)?;
            match effect {
                crate::disk::AllocationEffect::Truncated { fallback: true } => {
                    tracing::warn!(target: "taiji::store::torrent_writer",
                        path = %full.display(), len = length,
                        "allocation fell back to trunc (sparse): falloc fast path unavailable");
                }
                other => {
                    tracing::info!(target: "taiji::store::torrent_writer",
                        path = %full.display(), len = length, effect = ?other,
                        "file allocation done");
                }
            }
            drop(w);
        }
        Ok(())
    }
}

impl DiskWriter for TorrentWriter {
    fn open(&mut self, _path: &Path, _read_only: bool) -> Result<(), StoreError> {
        // Torrent level has no single path; handles open lazily on demand
        // (open_existing).
        Ok(())
    }

    fn open_existing(&mut self, _path: &Path, _read_only: bool) -> Result<(), StoreError> {
        Ok(())
    }

    fn create(&mut self, _path: &Path) -> Result<(), StoreError> {
        self.allocate()
    }

    fn truncate(&mut self, _len: u64) -> Result<(), StoreError> {
        // Torrent-level length is determined by the layout; allocation
        // goes through create/allocate.
        Ok(())
    }

    /// Torrent-level allocate by mode: lengths are given per file by the
    /// layout (the trait's `len` parameter is meaningless for a torrent
    /// layout, same note as `truncate`).
    fn allocate(
        &mut self,
        _len: u64,
        mode: AllocationMode,
    ) -> Result<crate::disk::AllocationEffect, StoreError> {
        self.allocate_with(mode)?;
        Ok(match mode {
            AllocationMode::Prealloc => crate::disk::AllocationEffect::ZeroFilled,
            AllocationMode::Falloc | AllocationMode::Trunc => {
                // Per-file real effects are logged inside allocate_with
                // (fallback warn); the torrent-level summary reports
                // trunc (platform-stubbed falloc also falls back to
                // trunc — see the disk.rs allocate docs).
                crate::disk::AllocationEffect::Truncated { fallback: false }
            }
        })
    }

    /// Global-offset write: split across files, pad ranges skipped
    /// (never written to disk, BEP47 L87).
    ///
    /// `&self` concurrency surface — each span's handle is cloned out of
    /// the pool lock via [`Self::write_handle`] and written outside it,
    /// so multiple callers (verify-pool workers / inline completion
    /// paths) are concurrency-safe; piece goff spans never overlap (the
    /// [`crate::verified`] pipeline invariant), interleaving happens only
    /// at piece boundaries.
    fn write_at(&self, offset: u64, data: &[u8]) -> Result<(), StoreError> {
        let mut goff = offset;
        let mut done = 0usize;
        while done < data.len() {
            let (idx, in_file) = self.layout.locate(goff)?;
            let (f_path, f_length, f_padding) = {
                let f = &self.layout.files()[idx];
                (f.path.clone(), f.length, f.padding)
            };
            let file_room = (f_length - in_file) as usize;
            let take = file_room.min(data.len() - done);
            if take == 0 {
                // locate landed on the end boundary (room 0) with no data
                // left to advance: guard against an infinite loop.
                return Err(StoreError::Internal("write made no progress".into()));
            }
            if !f_padding {
                let handle = self.write_handle(&f_path)?;
                handle.write_at(in_file, &data[done..done + take])?;
            }
            done += take;
            goff += take as u64;
        }
        Ok(())
    }

    /// Global-offset vectored write: when a merged span lies **entirely
    /// within one non-pad file**, one handle and a single
    /// `write_vectored_at` (unix = one pwritev — the main win: adjacent
    /// piece merges in single-file torrents always land in one file);
    /// cross-file/pad spans fall back to per-span [`Self::write_at`]
    /// (the existing split logic, pad skipping unchanged). The byte
    /// semantics contract is in [`DiskWriter::write_vectored_at`].
    fn write_vectored_at(&self, offset: u64, bufs: &[&[u8]]) -> Result<(), StoreError> {
        let total: usize = bufs.iter().map(|b| b.len()).sum();
        if total == 0 {
            return Ok(());
        }
        let located = self.layout.locate(offset).ok();
        if let Some((idx, in_file)) = located {
            let (f_path, f_length, f_padding) = {
                let f = &self.layout.files()[idx];
                (f.path.clone(), f.length, f.padding)
            };
            let file_room = (f_length - in_file) as usize;
            if !f_padding && file_room >= total {
                let handle = self.write_handle(&f_path)?;
                return handle.write_vectored_at(in_file, bufs);
            }
        }
        crate::disk::write_vectored_sequential(self, offset, bufs)
    }

    /// Global-offset read: delegates to [`TorrentReader`] (temporary
    /// handles, no pool; `&self`).
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, StoreError> {
        TorrentReader::new(self.layout.clone(), self.root.clone()).read_at(offset, buf)
    }

    fn flush_os_buffers(&self) -> Result<(), StoreError> {
        // Peek handles (not through the LRU pool) fsync file by file (the
        // read path is not bound by the LRU pool; see the read_at notes).
        // Cross-platform invariant: fsync requires the handle open for
        // read-write — Windows FlushFileBuffers needs write access and a
        // read-only handle returns ACCESS_DENIED, which the periodic
        // flush arm escalates to Fatal; unix allows fsync on O_RDONLY, so
        // read-only opens never exposed the difference.
        for f in self.layout.files() {
            if f.padding {
                continue;
            }
            let full = self.file_path(&f.path);
            let mut w: Box<dyn DiskWriter> = Box::new(crate::disk::FileDiskWriter::new());
            if w.open_existing(&full, false).is_ok() {
                w.flush_os_buffers()?;
            }
        }
        Ok(())
    }

    fn size(&self) -> Result<u64, StoreError> {
        Ok(self.layout.total())
    }

    fn set_bypass_page_cache(&self) -> Result<(), StoreError> {
        // Best effort: set per file, ignore failures (same semantics as
        // aria2's `AbstractDiskWriter::openFileWithFlags` F_NOCACHE
        // branch). Handles open read-write, same as flush_os_buffers:
        // the Windows surface needs write access.
        for f in self.layout.files() {
            if f.padding {
                continue;
            }
            let full = self.file_path(&f.path);
            let mut w: Box<dyn DiskWriter> = Box::new(crate::disk::FileDiskWriter::new());
            if w.open_existing(&full, false).is_ok() {
                let _ = w.set_bypass_page_cache();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::{Layout, PlanEntry};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "taiji-tw-{}-{}-{}",
                tag,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos())
                    .unwrap_or(0)
            ));
            std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir: {e}"));
            TempDir(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const PIECE_LEN: u32 = 16384;

    /// Hybrid-fixture-shaped layout: a.bin 70000 → pad 11920 → b.bin 30000.
    fn setup(tag: &str, max_open: usize) -> (TempDir, TorrentWriter) {
        let tmp = TempDir::new(tag);
        let entries = vec![
            PlanEntry {
                path: PathBuf::from("a.bin"),
                length: 70000,
                padding: false,
            },
            PlanEntry {
                path: PathBuf::from(".pad/11920"),
                length: 11920,
                padding: true,
            },
            PlanEntry {
                path: PathBuf::from("b.bin"),
                length: 30000,
                padding: false,
            },
        ];
        let layout = Layout::plan_v1_padded(&entries, PIECE_LEN).unwrap_or_else(|e| panic!("{e}"));
        let writer = TorrentWriter::new(layout, tmp.0.clone(), max_open);
        (tmp, writer)
    }

    fn file_exists(dir: &std::path::Path, rel: &str) -> bool {
        dir.join(rel).exists()
    }

    /// Cross-file + cross-pad write: [69000, 89000) covers a's tail
    /// (1000B), the whole pad (11920B, skipped), and b's head (7080B);
    /// the pad never lands on disk.
    #[test]
    fn write_splits_across_files_and_skips_pad() {
        let (_tmp, mut w) = setup("split", 8);
        w.allocate().unwrap_or_else(|e| panic!("{e}"));
        // Global write [69000, 89000): the stream covers a's tail 1000B +
        // the pad 11920B (zero span) + b's head 7080B — piece data
        // includes the pad zero span (BEP47 L85 hashes pads as all-zero).
        let mut data = Vec::new();
        data.extend((0..1000u32).map(|i| (i % 251) as u8));
        data.extend(std::iter::repeat_n(0u8, 11920));
        data.extend((0..7080u32).map(|i| (i % 253) as u8));
        w.write_at(69000, &data).unwrap_or_else(|e| panic!("{e}"));

        // a's tail, 1000B.
        let mut buf = vec![0u8; 1000];
        let n = w.read_at(69000, &mut buf).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(n, 1000);
        assert_eq!(buf, data[..1000]);
        // Pad range reads back all zeros (BEP47 L87 serving duty; the pad
        // file is not on disk).
        let mut padbuf = vec![1u8; 11920];
        let n = w
            .read_at(70000, &mut padbuf)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(n, 11920);
        assert!(padbuf.iter().all(|&b| b == 0), "pad reads must zero-fill");
        assert!(
            !file_exists(&_tmp.0, ".pad/11920"),
            "the pad file never hits disk (BEP47 L87)"
        );
        // b's head, 7080B = the segment after the pad in the data stream.
        let mut bbuf = vec![0u8; 7080];
        w.read_at(81920, &mut bbuf)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(bbuf, &data[12920..]);
        // One whole-span read (with pad zero-fill) matches the stream.
        let mut whole = vec![0u8; 20000];
        let n = w
            .read_at(69000, &mut whole)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(n, 20000);
        assert_eq!(whole, data);
    }

    /// Writing fully inside a pad range is a no-op (legal: piece data
    /// contains the pad zero span; the write path skips it).
    #[test]
    fn write_fully_inside_pad_is_noop() {
        let (_tmp, mut w) = setup("padonly", 8);
        w.allocate().unwrap_or_else(|e| panic!("{e}"));
        w.write_at(70000, &[0xAA; 100])
            .unwrap_or_else(|e| panic!("{e}"));
        let mut buf = vec![1u8; 100];
        w.read_at(70000, &mut buf).unwrap_or_else(|e| panic!("{e}"));
        assert!(buf.iter().all(|&b| b == 0));
    }

    /// allocate: non-pad files created at layout length (trunc); pads not
    /// created; zero-length files created too (aria2
    /// MultiDiskAdaptor.cc).
    #[test]
    fn allocate_creates_files_except_pads() {
        let (tmp, mut w) = setup("alloc", 8);
        w.allocate().unwrap_or_else(|e| panic!("{e}"));
        assert!(tmp.0.join("a.bin").exists());
        assert!(tmp.0.join("b.bin").exists());
        assert!(!tmp.0.join(".pad/11920").exists(), "pads are never created");
        assert_eq!(
            w.size().unwrap_or_else(|e| panic!("{e}")),
            111920,
            "size = the layout total"
        );
    }

    /// Handle cap: cross-file writes stay correct with max_open=1 (LRU
    /// churn).
    #[test]
    fn works_with_handle_cap_one() {
        let (_tmp, mut w) = setup("cap1", 1);
        w.allocate().unwrap_or_else(|e| panic!("{e}"));
        let data = vec![7u8; 20000];
        w.write_at(69000, &data).unwrap_or_else(|e| panic!("{e}"));
        let mut buf = vec![0u8; 1000];
        w.read_at(69000, &mut buf).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(buf, vec![7u8; 1000]);
        assert!(
            w.open_handles() <= 1,
            "the read path uses a temp handle; the write pool obeys the handle cap"
        );
    }

    // -------------------------------------------------------------------
    // Read-coalescing primitives (the coalesce_reads pure function and
    // TorrentReader::read_coalesced) and per-mode allocation.
    // -------------------------------------------------------------------

    fn spec(goff: u64, len: usize) -> ReadSpec {
        ReadSpec { goff, len }
    }

    /// Adjacent merging: contiguous spans join one range; gaps split;
    /// zero caps = identity.
    #[test]
    fn coalesce_adjacent_merges_and_gaps_split() {
        let specs = vec![spec(0, 16), spec(16, 16), spec(64, 16)];
        // Two adjacent spans merge; a gap splits.
        let m = coalesce_reads(&specs, 1 << 20, 64);
        assert_eq!(m.len(), 2, "gaps must split: {m:?}");
        assert_eq!(m[0].goff, 0);
        assert_eq!(m[0].len, 32);
        assert_eq!(m[0].parts(), &[(0, 0), (1, 16)]);
        assert_eq!(m[1].goff, 64);
        assert_eq!(m[1].parts(), &[(2, 0)]);
        // Cap 0 = identity mapping (throughput default profile unchanged).
        let id = coalesce_reads(&specs, 0, 0);
        assert_eq!(id.len(), 3);
        for (i, r) in id.iter().enumerate() {
            assert_eq!(r.parts(), &[(i, 0)]);
            assert_eq!(r.len, specs[i].len);
        }
    }

    /// Caps: a byte cap forces a split; a range cap forces a split;
    /// unsorted input converges by goff.
    #[test]
    fn coalesce_caps_and_unsorted_input() {
        // Byte cap: 3×16B spans with cap 32 → two ranges.
        let specs = vec![spec(0, 16), spec(16, 16), spec(32, 16)];
        let m = coalesce_reads(&specs, 32, 64);
        assert_eq!(m.len(), 2, "the byte cap must split: {m:?}");
        assert_eq!(m[0].len, 32);
        assert_eq!(m[1].goff, 32);
        // Range cap: 2 spans per range → 3 spans split across two.
        let m2 = coalesce_reads(&specs, 1 << 20, 2);
        assert_eq!(m2.len(), 2, "the range cap must split: {m2:?}");
        assert_eq!(m2[0].parts().len(), 2);
        assert_eq!(m2[1].parts().len(), 1);
        // Unsorted input: the result converges by goff; parts keeps the
        // original indices.
        let unsorted = vec![spec(32, 16), spec(0, 16), spec(16, 16)];
        let m3 = coalesce_reads(&unsorted, 1 << 20, 64);
        assert_eq!(m3.len(), 1);
        assert_eq!(m3[0].goff, 0);
        assert_eq!(m3[0].len, 48);
        assert_eq!(m3[0].parts(), &[(1, 0), (2, 16), (0, 32)]);
        // Empty input = empty.
        assert!(coalesce_reads(&[], 1 << 20, 8).is_empty());
    }

    /// read_coalesced end-to-end: adjacent-read merging across files and
    /// pads, semantics identical to per-span read_at (pad zero-fill
    /// BEP47 L87, EOF sparse zeros); gate = Some exercises the shared
    /// quota bucket path (an unlimited bucket passes through).
    #[test]
    fn read_coalesced_matches_per_read_semantics() {
        let tmp = TempDir::new("coalesce");
        let entries = vec![
            PlanEntry {
                path: PathBuf::from("a.bin"),
                length: 70000,
                padding: false,
            },
            PlanEntry {
                path: PathBuf::from(".pad/11920"),
                length: 11920,
                padding: true,
            },
            PlanEntry {
                path: PathBuf::from("b.bin"),
                length: 30000,
                padding: false,
            },
        ];
        let layout = Layout::plan_v1_padded(&entries, PIECE_LEN).unwrap_or_else(|e| panic!("{e}"));
        let mut w = TorrentWriter::new(layout.clone(), tmp.0.clone(), 8);
        // Preallocation goes through the mode surface (prealloc really
        // allocates — also covers allocate_with).
        w.allocate_with(AllocationMode::Prealloc)
            .unwrap_or_else(|e| panic!("{e}"));
        // Write recognizable content: a in full + b in full (the pad is
        // not on disk).
        let mut stream = Vec::new();
        stream.extend((0..70000u32).map(|i| (i % 251) as u8));
        stream.extend(std::iter::repeat_n(0u8, 11920));
        stream.extend((0..30000u32).map(|i| (i % 253) as u8));
        w.write_at(0, &stream).unwrap_or_else(|e| panic!("{e}"));

        let reader = TorrentReader::new(layout, tmp.0.clone());
        // specs: two adjacent spans inside a + two adjacent spans across
        // a tail → pad → b head + a b-tail overread past EOF (sparse
        // zeros).
        let specs = vec![
            spec(0, 16384),
            spec(16384, 16384),
            spec(65536, 16384), // a tail + the whole pad + b head
            spec(81920, 16384), // inside b
            spec(110000, 4096), // past total 111920 → EOF short read
        ];
        let gate = IoGate::unlimited();
        let got = reader
            .read_coalesced(&specs, 1 << 20, 64, Some(&gate))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(got.len(), specs.len());
        for (i, s) in specs.iter().enumerate() {
            let mut expect = vec![0u8; s.len];
            reader
                .read_at(s.goff, &mut expect)
                .unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(
                got[i], expect,
                "spec {i} @{} disagrees with the per-span read",
                s.goff
            );
        }
        // Pad spans read as zeros (BEP47 L87).
        let pad_in_merged = &got[2][70000 - 65536..70000 - 65536 + 11920];
        assert!(
            pad_in_merged.iter().all(|&b| b == 0),
            "the pad span zero-fills"
        );
        // Merging took effect: 5 spans → 3 ranges (0-16384/16384-32768
        // adjacent merge; 65536-81920/81920-98304 adjacent merge; the EOF
        // span has a gap and stands alone).
        let merged = coalesce_reads(&specs, 1 << 20, 64);
        assert_eq!(merged.len(), 3, "5 specs → 3 merged ranges: {merged:?}");
        // No-merge caps (0) and merge caps give byte-identical results
        // (semantic invariance).
        let plain = reader
            .read_coalesced(&specs, 0, 0, None)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(plain, got);
    }

    /// allocate_with mode surface: prealloc fully allocates (files exist +
    /// non-sparse + write/read-back intact); allocate()'s default trunc
    /// behavior unchanged (existence covered by
    /// allocate_creates_files_except_pads).
    #[test]
    fn allocate_with_prealloc_creates_real_files() {
        let (tmp, mut w) = setup("alloc-prealloc", 8);
        w.allocate_with(AllocationMode::Prealloc)
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(tmp.0.join("a.bin").exists());
        assert!(!tmp.0.join(".pad/11920").exists(), "pads are never created");
        // Non-sparse (st_blocks covers the full length) — unix-side
        // assertion.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            for rel in ["a.bin", "b.bin"] {
                let m = match std::fs::metadata(tmp.0.join(rel)) {
                    Ok(m) => m,
                    Err(e) => panic!("stat {rel}: {e}"),
                };
                assert!(
                    m.blocks() * 512 + 4096 >= m.len(),
                    "{rel} must be really allocated: blocks={} len={}",
                    m.blocks(),
                    m.len()
                );
            }
        }
        // After allocation, write/read-back is intact (pipeline
        // compatibility; a span inside one file — cross-pad zero
        // semantics covered by write_splits_across_files_and_skips_pad).
        let data = vec![9u8; 1000];
        w.write_at(69000, &data).unwrap_or_else(|e| panic!("{e}"));
        let mut buf = vec![0u8; 1000];
        w.read_at(69000, &mut buf).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(buf, data);
    }

    // -------------------------------------------------------------------
    // Regression tests: allocation must not destroy existing data;
    // missing files must error instead of silently returning zeros.
    // -------------------------------------------------------------------

    /// Regression (preloaded data → add → allocation must not destroy
    /// it): when files with the same layout already exist on disk,
    /// allocate_with (identical across trunc/falloc/prealloc) only opens
    /// without allocating — bytes preserved; missing files are still
    /// created to layout length. reference = aria2
    /// `AbstractDiskWriter::openFile` (openExistingFile first) +
    /// `MultiDiskAdaptor.cc`.
    #[test]
    fn allocate_preserves_existing_file_bytes() {
        for mode in [
            AllocationMode::Trunc,
            AllocationMode::Falloc,
            AllocationMode::Prealloc,
        ] {
            let tag = format!("reseed-{mode:?}");
            let (tmp, mut w) = setup(&tag, 8);
            // Preload a.bin (recognizable content, length = layout length
            // 70000); b.bin absent (must still be created).
            let preset: Vec<u8> = (0..70000u32).map(|i| (i % 251) as u8).collect();
            std::fs::write(tmp.0.join("a.bin"), &preset).unwrap_or_else(|e| panic!("{e}"));
            w.allocate_with(mode).unwrap_or_else(|e| panic!("{e}"));
            let got = std::fs::read(tmp.0.join("a.bin")).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(
                got, preset,
                "{mode:?}: existing file bytes must be preserved"
            );
            assert!(
                tmp.0.join("b.bin").exists(),
                "{mode:?}: missing files must be created"
            );
        }
    }

    /// Regression (bitmap full + file missing on disk → serving zeros →
    /// peers hash-fail and ban this end): reading a missing file must
    /// error (callers reject on the piece/hash serving path), never
    /// return Ok with a zero buffer. EOF short-read remainders of
    /// existing but incomplete files stay sparse zeros (download-time
    /// semantics unchanged); the pad zero-fill duty is unchanged
    /// (BEP47 L87).
    #[test]
    fn read_missing_file_errors_while_eof_stays_sparse_zero() {
        let tmp = TempDir::new("def3");
        let entries = vec![
            PlanEntry {
                path: PathBuf::from("a.bin"),
                length: 70000,
                padding: false,
            },
            PlanEntry {
                path: PathBuf::from(".pad/11920"),
                length: 11920,
                padding: true,
            },
            PlanEntry {
                path: PathBuf::from("b.bin"),
                length: 30000,
                padding: false,
            },
        ];
        let layout = Layout::plan_v1_padded(&entries, PIECE_LEN).unwrap_or_else(|e| panic!("{e}"));
        let reader = TorrentReader::new(layout, tmp.0.clone());
        // (1) Missing file (a.bin absent) → Err.
        let mut buf = vec![0u8; 1000];
        match reader.read_at(0, &mut buf) {
            Err(_) => {}
            other => panic!("reading a missing file must error, got {other:?}"),
        }
        // (2) File exists but short (written to 1000B) → EOF remainder
        // sparse zeros + Ok.
        std::fs::write(tmp.0.join("a.bin"), vec![7u8; 1000]).unwrap_or_else(|e| panic!("{e}"));
        let mut buf = vec![0xABu8; 2000];
        let n = reader
            .read_at(0, &mut buf)
            .unwrap_or_else(|e| panic!("an EOF short read must be Ok: {e}"));
        assert_eq!(n, 2000);
        assert_eq!(&buf[..1000], &vec![7u8; 1000][..]);
        assert!(
            buf[1000..].iter().all(|&b| b == 0),
            "the EOF remainder stays sparse zero"
        );
        // (3) Pad zero-fill unchanged: a.bin exists; reading the pad
        // range (70000..81920) → all zeros, Ok.
        let mut padbuf = vec![1u8; 11920];
        reader
            .read_at(70000, &mut padbuf)
            .unwrap_or_else(|e| panic!("a pad read must be Ok: {e}"));
        assert!(
            padbuf.iter().all(|&b| b == 0),
            "the pad span zero-fills (BEP47 L87)"
        );
        // (4) read_coalesced same semantics: a merged range covering the
        // still-missing b.bin ([81920, 111920)) → Err.
        let specs = vec![ReadSpec {
            goff: 90000,
            len: 32,
        }];
        let gate = IoGate::unlimited();
        match reader.read_coalesced(&specs, 1 << 20, 64, Some(&gate)) {
            Err(_) => {}
            other => panic!("read_coalesced on a missing file must error, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // Read-side handle pool: open drops from O(requests) to O(active
    // files), byte-identical semantics to unpooled read_at.
    // -------------------------------------------------------------------

    /// Pooled reader: after 50 cross-file block reads the pool holds as
    /// many handles as active files (2), and the data is byte-identical
    /// to the unpooled reader (missing-file / pad / EOF semantics are
    /// unchanged by pooling — read_at is a single implementation, only
    /// handle acquisition forks).
    #[test]
    fn pooled_reader_keeps_open_count_at_active_files() {
        let tmp = TempDir::new("pooled");
        let entries = vec![
            PlanEntry {
                path: PathBuf::from("a.bin"),
                length: 70000,
                padding: false,
            },
            PlanEntry {
                path: PathBuf::from(".pad/11920"),
                length: 11920,
                padding: true,
            },
            PlanEntry {
                path: PathBuf::from("b.bin"),
                length: 30000,
                padding: false,
            },
        ];
        let layout = Layout::plan_v1_padded(&entries, PIECE_LEN).unwrap_or_else(|e| panic!("{e}"));
        let mut w = TorrentWriter::new(layout.clone(), tmp.0.clone(), 8);
        w.allocate().unwrap_or_else(|e| panic!("{e}"));
        let mut stream = Vec::new();
        stream.extend((0..70000u32).map(|i| (i % 251) as u8));
        stream.extend(std::iter::repeat_n(0u8, 11920));
        stream.extend((0..30000u32).map(|i| (i % 253) as u8));
        w.write_at(0, &stream).unwrap_or_else(|e| panic!("{e}"));

        let pooled = TorrentReader::with_handle_pool(layout.clone(), tmp.0.clone(), 8);
        let plain = TorrentReader::new(layout, tmp.0.clone());
        // 16KiB block reads ×50 across a.bin / pad / b.bin (covers both
        // files + the pad range).
        for k in 0..50u64 {
            let goff = k * 16384 % 111_000;
            let mut got_pooled = vec![0u8; 16384];
            let mut got_plain = vec![0u8; 16384];
            let np = pooled
                .read_at(goff, &mut got_pooled)
                .unwrap_or_else(|e| panic!("pooled @{goff}: {e}"));
            let nl = plain
                .read_at(goff, &mut got_plain)
                .unwrap_or_else(|e| panic!("plain @{goff}: {e}"));
            assert_eq!(np, nl, "filled @{goff}");
            assert_eq!(got_pooled, got_plain, "bytes identical @{goff}");
        }
        assert_eq!(
            pooled.open_handles(),
            2,
            "after 50 reads the pool holds = the active file count (O(requests) -> O(files))"
        );
        assert_eq!(
            plain.open_handles(),
            0,
            "the unpooled reader keeps no handles resident"
        );
    }

    /// Pool capacity 1: cross-file reads stay correct under LRU churn
    /// (same shape as the write-side works_with_handle_cap_one — the
    /// read pool obeys the same HandlePool semantics).
    #[test]
    fn pooled_reader_cap_one_churn_is_correct() {
        let tmp = TempDir::new("pooled-cap1");
        let entries = vec![
            PlanEntry {
                path: PathBuf::from("a.bin"),
                length: 70000,
                padding: false,
            },
            PlanEntry {
                path: PathBuf::from(".pad/11920"),
                length: 11920,
                padding: true,
            },
            PlanEntry {
                path: PathBuf::from("b.bin"),
                length: 30000,
                padding: false,
            },
        ];
        let layout = Layout::plan_v1_padded(&entries, PIECE_LEN).unwrap_or_else(|e| panic!("{e}"));
        let mut w = TorrentWriter::new(layout.clone(), tmp.0.clone(), 8);
        w.allocate().unwrap_or_else(|e| panic!("{e}"));
        let data = vec![9u8; 70000];
        w.write_at(0, &data).unwrap_or_else(|e| panic!("{e}"));
        let pooled = TorrentReader::with_handle_pool(layout, tmp.0.clone(), 1);
        for (goff, len) in [(0u64, 1000usize), (69999, 1), (0, 1000)] {
            let mut buf = vec![0u8; len];
            pooled
                .read_at(goff, &mut buf)
                .unwrap_or_else(|e| panic!("@{goff}: {e}"));
            assert_eq!(&buf[..], &data[goff as usize..goff as usize + len]);
        }
        assert!(pooled.open_handles() <= 1, "the handle count obeys the cap");
    }

    /// The pooled reader does not regress on missing files: reads error
    /// (the pool opener's open_existing error path).
    #[test]
    fn pooled_reader_missing_file_errors() {
        let tmp = TempDir::new("pooled-def3");
        let entries = vec![PlanEntry {
            path: PathBuf::from("a.bin"),
            length: 70000,
            padding: false,
        }];
        let layout = Layout::plan_v1_padded(&entries, PIECE_LEN).unwrap_or_else(|e| panic!("{e}"));
        let pooled = TorrentReader::with_handle_pool(layout, tmp.0.clone(), 8);
        let mut buf = vec![0u8; 1000];
        match pooled.read_at(0, &mut buf) {
            Err(_) => {}
            other => panic!("the pooled reader must error on a missing file, got {other:?}"),
        }
        // After creating the file the same reader reads successfully (the
        // opener retries the open inside the pool).
        std::fs::write(tmp.0.join("a.bin"), vec![7u8; 70000]).unwrap_or_else(|e| panic!("{e}"));
        pooled
            .read_at(0, &mut buf)
            .unwrap_or_else(|e| panic!("reading after the file is created must be Ok: {e}"));
        assert!(buf.iter().all(|&b| b == 7));
    }

    /// read_coalesced_bufs (caller-buffered form): byte-identical to
    /// read_coalesced; per-spec filled matches read_at semantics; stale
    /// pooled-buffer bytes are explicitly overwritten (pad/EOF/beyond-
    /// total tails leave no residue).
    #[test]
    fn read_coalesced_bufs_matches_read_coalesced_and_defines_all_bytes() {
        let tmp = TempDir::new("coalesce-bufs");
        let entries = vec![
            PlanEntry {
                path: PathBuf::from("a.bin"),
                length: 70000,
                padding: false,
            },
            PlanEntry {
                path: PathBuf::from(".pad/11920"),
                length: 11920,
                padding: true,
            },
            PlanEntry {
                path: PathBuf::from("b.bin"),
                length: 30000,
                padding: false,
            },
        ];
        let layout = Layout::plan_v1_padded(&entries, PIECE_LEN).unwrap_or_else(|e| panic!("{e}"));
        let mut w = TorrentWriter::new(layout.clone(), tmp.0.clone(), 8);
        w.allocate().unwrap_or_else(|e| panic!("{e}"));
        let mut stream = Vec::new();
        stream.extend((0..70000u32).map(|i| (i % 251) as u8));
        stream.extend(std::iter::repeat_n(0u8, 11920));
        stream.extend((0..30000u32).map(|i| (i % 253) as u8));
        w.write_at(0, &stream).unwrap_or_else(|e| panic!("{e}"));
        let pooled = TorrentReader::with_handle_pool(layout.clone(), tmp.0.clone(), 8);
        let plain = TorrentReader::new(layout, tmp.0.clone());

        let specs = vec![
            ReadSpec {
                goff: 65536,
                len: 16384,
            }, // a tail + the whole pad + b head
            ReadSpec {
                goff: 81920,
                len: 16384,
            }, // inside b
            ReadSpec {
                goff: 110000,
                len: 4096,
            }, // past the total → EOF short read
        ];
        // Pre-fill stale bytes (0xAA): pad/EOF/tail spans must not retain
        // them.
        let mut bufs: Vec<Vec<u8>> = specs.iter().map(|s| vec![0xAAu8; s.len]).collect();
        let mut outs: Vec<&mut [u8]> = bufs.iter_mut().map(|v| v.as_mut_slice()).collect();
        let filled = pooled
            .read_coalesced_bufs(&specs, &mut outs, 1 << 20, 64, None)
            .unwrap_or_else(|e| panic!("{e}"));

        let expect = plain
            .read_coalesced(&specs, 1 << 20, 64, None)
            .unwrap_or_else(|e| panic!("{e}"));
        for (i, s) in specs.iter().enumerate() {
            assert_eq!(
                &bufs[i][..s.len],
                &expect[i][..],
                "spec {i} bytes identical"
            );
        }
        // filled: the first two spans are fully covered inside the
        // layout; the EOF span = total 111920 - 110000 = 1920.
        assert_eq!(
            filled,
            vec![16384, 16384, 1920],
            "filled matches read_at semantics"
        );
        // The beyond-total tail ([1920..]) is explicitly zeroed;
        // [..1920] = b.bin's real bytes (already asserted byte-identical
        // to read_coalesced above).
        assert!(
            bufs[2][1920..].iter().all(|&b| b == 0),
            "the beyond-total tail is explicitly zeroed"
        );
        assert!(
            bufs[0][70000 - 65536..81920 - 65536]
                .iter()
                .all(|&b| b == 0),
            "the pad span is explicitly zeroed (the stale 0xAA bytes leave no residue)"
        );
        // Length mismatch: defensive Err.
        let mut short_outs: Vec<&mut [u8]> = Vec::new();
        match pooled.read_coalesced_bufs(&specs, &mut short_outs, 1 << 20, 64, None) {
            Err(_) => {}
            other => panic!("a specs/outs mismatch must be Err, got {other:?}"),
        }
    }

    /// Concurrency (multi-file layout): 4 threads write disjoint piece
    /// spans through one `Arc<TorrentWriter>` `write_at(&self)` (across
    /// the a/pad/b file boundaries, threads emit in reverse = out of
    /// order); reading back the full stream is byte-identical; the LRU
    /// handle count holds under concurrency (`Arc`-valued handles:
    /// in-flight writes keep the `File` alive; eviction close cannot
    /// race).
    #[test]
    fn concurrent_write_at_multifile_layout_is_correct() {
        const THREADS: usize = 4;
        let tmp = TempDir::new("conc-tw");
        let entries = vec![
            PlanEntry {
                path: PathBuf::from("a.bin"),
                length: 70000,
                padding: false,
            },
            PlanEntry {
                path: PathBuf::from(".pad/11920"),
                length: 11920,
                padding: true,
            },
            PlanEntry {
                path: PathBuf::from("b.bin"),
                length: 30000,
                padding: false,
            },
        ];
        let layout = Layout::plan_v1_padded(&entries, PIECE_LEN).unwrap_or_else(|e| panic!("{e}"));
        let mut w = TorrentWriter::new(layout.clone(), tmp.0.clone(), 8);
        w.allocate().unwrap_or_else(|e| panic!("{e}"));
        let w = Arc::new(w);
        // Full-stream content (including the pad zero span) written
        // concurrently per 16KiB piece (boundary-crossing pieces are
        // present).
        let mut stream = Vec::new();
        stream.extend((0..70000u32).map(|i| (i % 251) as u8));
        stream.extend(std::iter::repeat_n(0u8, 11920));
        stream.extend((0..30000u32).map(|i| (i % 253) as u8));
        let stream = Arc::new(stream);
        let pieces = stream.len().div_ceil(PIECE_LEN as usize);
        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let w = Arc::clone(&w);
                let stream = Arc::clone(&stream);
                std::thread::spawn(move || {
                    for p in (0..pieces).filter(|p| p % THREADS == t).rev() {
                        let start = p * PIECE_LEN as usize;
                        let end = (start + PIECE_LEN as usize).min(stream.len());
                        w.write_at(start as u64, &stream[start..end])
                            .unwrap_or_else(|e| panic!("t{t} piece {p}: {e}"));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join()
                .unwrap_or_else(|e| panic!("writer thread panicked: {e:?}"));
        }
        // Read back the full stream (unpooled reader) byte-identical;
        // pad spans served as zeros (BEP47 L87).
        let reader = TorrentReader::new(layout, tmp.0.clone());
        let mut got = vec![0u8; stream.len()];
        let n = reader
            .read_at(0, &mut got)
            .unwrap_or_else(|e| panic!("readback: {e}"));
        assert_eq!(n, stream.len());
        assert_eq!(
            got, *stream,
            "after concurrent writes the full-stream read-back must be byte-identical"
        );
        assert!(
            w.open_handles() <= 8,
            "under concurrency the LRU handle count must hold (cap 8)"
        );
    }
}
