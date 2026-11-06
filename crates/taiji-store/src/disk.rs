//! Single-file DiskWriter: positioned writes + trunc allocation
//! (SPEC §5.1).
//!
//! Mechanism: positioned `write_at`/`read_at` on one open file;
//! allocation in three modes (sparse trunc, zero-fill prealloc, falloc
//! fast path with a design-specified trunc fallback where unsafe libc is
//! banned); fsync via `sync_all`; `ENOSPC` classified to
//! [`StoreError::NoSpace`]. Symlink defense on the final path component
//! (`O_NOFOLLOW` / `FILE_FLAG_OPEN_REPARSE_POINT`) covers every open
//! face.
//!
//! Concurrency discipline: `DiskWriter` is a synchronous object (direct
//! syscalls); async callers must run its operations inside
//! `spawn_blocking`. This module never spawns.
//!
//! Scope: single-file layout only; multi-file layout and `.pad`
//! semantics are out of scope here. Upstream anchor mapping and the
//! unix/Windows platform matrix: docs/design/store.md

use std::io;
use std::path::{Path, PathBuf};

use crate::disk_policy::AllocationMode;
use crate::error::StoreError;

/// Result of [`DiskWriter::allocate`] (honest reporting: what actually
/// happened is reported as-is and callers log it — no fake "fast path
/// succeeded").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AllocationEffect {
    /// Platform fast path completed (Linux fallocate / macOS
    /// F_PREALLOCATE). Currently unreachable: the fast path needs unsafe
    /// libc, forbidden by the workspace's `unsafe_code = forbid` (see
    /// [`crate::disk_policy`] module docs); the arm stays as the honest
    /// reporting slot for when a safe wrapper lands.
    Fallocated,
    /// Real allocation done by segment-wise zero fill (aria2
    /// `SingleFileAllocationIterator` semantics; identical on all
    /// platforms, not sparse — st_blocks reflects actual usage).
    ZeroFilled,
    /// Sparse ftruncate. `fallback = true` marks the design-specified
    /// fallback taken when the falloc fast path is unavailable (callers
    /// log a warning).
    Truncated { fallback: bool },
}

/// Single-file disk write abstraction (SPEC §5.1: positioned writes, no
/// lseek+write).
///
/// All methods block (disk IO); async callers must go through
/// `spawn_blocking`. `Sync` is deliberate: positioned writes are the
/// shared write face ([`crate::verified::SharedDiskWriter`] runs
/// multiple workers on the write hot path — concurrent unix pwrite at
/// different offsets is safe; on Windows each [`FileDiskWriter`] write
/// serializes its non-atomic `seek_write` pair behind a per-instance
/// `write_gate` mutex, which is what makes concurrent `&self` writes
/// sound). Implementation state must be self-synchronizing (inline
/// mutex/atomics, like [`TorrentWriter`]'s handle-pool `Mutex`).
pub trait DiskWriter: Send + Sync {
    /// Open a file for download writes: open directly when present;
    /// create when missing (mirrors `AbstractDiskWriter::openFile`'s
    /// `ENOENT -> create` fallback).
    ///
    /// # Errors
    ///
    /// [`StoreError::NoSpace`]/[`StoreError::FileIo`] from the open
    /// syscall (`classify_io`); a `NotFound` from `open_existing` falls
    /// through to [`Self::create`] (its errors surface as-is).
    fn open(&mut self, path: &Path, read_only: bool) -> Result<(), StoreError>;

    /// Open only an existing file; error if missing (mirrors `openExistingFile`, no O_CREAT).
    ///
    /// # Errors
    ///
    /// [`StoreError::FileIo`] with `io::ErrorKind::NotFound` when the
    /// file does not exist; other open errors classified via
    /// `classify_io`.
    fn open_existing(&mut self, path: &Path, read_only: bool) -> Result<(), StoreError>;

    /// Create a new file (recursive parent creation + truncate; mirrors `createFile`).
    ///
    /// # Errors
    ///
    /// [`StoreError::FileIo`] from parent-directory creation, the open
    /// itself, the symlink/reparse-point rejection or the `set_len(0)`
    /// truncation.
    fn create(&mut self, path: &Path) -> Result<(), StoreError>;

    /// Truncate allocation: `ftruncate` semantics (sparse extension or
    /// shrink to `len`).
    ///
    /// # Errors
    ///
    /// [`StoreError::FileNotOpen`] without an open file;
    /// [`StoreError::FileIo`] from the resize syscall.
    fn truncate(&mut self, len: u64) -> Result<(), StoreError>;

    /// Preallocate to `len` bytes (mirrors aria2's three-state
    /// `--file-allocation`; semantics in [`crate::disk_policy`]). Returns
    /// the [`AllocationEffect`] actually in effect (fallback/zero-fill/
    /// fast path — no pretending).
    ///
    /// Default implementation = sparse trunc — lets writers without real
    /// preallocation (test stubs/loopback hooks) inherit unchanged;
    /// [`FileDiskWriter`] overrides with the full zero-fill/fallback
    /// paths. Valid only on a newly created empty file (allocation before
    /// writing); zero-fill on a file with data would overwrite it — the
    /// caller contract is
    /// [`crate::torrent_writer::TorrentWriter::allocate_with`].
    ///
    /// # Errors
    ///
    /// Per-mode: `Trunc` = [`Self::truncate`]'s errors; `Falloc` = the
    /// same (documented fallback on platforms without a safe fast path);
    /// `Prealloc` = the zero-fill write errors (see [`Self::write_at`])
    /// plus the final truncate.
    fn allocate(&mut self, len: u64, mode: AllocationMode) -> Result<AllocationEffect, StoreError> {
        let _ = mode;
        self.truncate(len)
            .map(|()| AllocationEffect::Truncated { fallback: false })
    }

    /// Positioned write of the full buffer: short writes looped
    /// internally (mirrors `writeDataInternal`).
    ///
    /// `&self` = positioned writes may be called concurrently through a
    /// shared reference: unix `write_all_at` is a `pwrite` loop — no
    /// shared file cursor, concurrent use of the same fd at different
    /// offsets is safe (POSIX pread/pwrite atomicity clause). Windows
    /// `seek_write` has cursor side effects and concurrent calls are not
    /// thread-safe — the [`FileDiskWriter`] Windows arm serializes each
    /// write behind its per-instance `write_gate` mutex (the `Sync`
    /// promise is enforced there, not left to caller discipline).
    /// Open/create/truncate/allocate and other out-of-write operations
    /// stay `&mut` (outer exclusive domain).
    ///
    /// # Errors
    ///
    /// [`StoreError::NoSpace`] (ENOSPC, classified per aria2
    /// `isDiskFullError`), [`StoreError::FileIo`] for other IO faults;
    /// [`StoreError::FileNotOpen`] without an open file.
    fn write_at(&self, offset: u64, data: &[u8]) -> Result<(), StoreError>;

    /// Positioned vectored write (iovec merging; as much as possible in
    /// one syscall — the syscall-granularity face of write batching,
    /// mirroring libtorrent's merge of adjacent blocks into a single
    /// `pwritev`).
    ///
    /// Byte-semantics contract: exactly equal to sequential
    /// [`Self::write_at`] calls (concatenate in order, fill
    /// `[offset, offset+Σlen)`, short writes looped to the end); callers
    /// guarantee segments are goff-contiguous (the merge face constructs
    /// them by adjacency).
    ///
    /// Default implementation = a per-segment `write_at` loop (the
    /// conservative, semantics-equivalent base):
    /// - Windows keeps per-segment writes: `WriteFileGather` needs
    /// page-aligned buffers + Win32 FFI (blocked by the workspace's
    /// `unsafe_code = forbid`; a safe wrapper crate would be a new
    /// dependency) — stubbed for the same reason as the
    /// [`FileDiskWriter`] falloc fast path, no fake vectorization;
    /// - test-stub writers inherit unchanged.
    ///
    /// The unix [`FileDiskWriter`] overrides this with a `pwritev`
    /// short-write loop (true vectorization).
    ///
    /// # Errors
    ///
    /// Same family as [`Self::write_at`] ([`StoreError::NoSpace`] /
    /// [`StoreError::FileIo`] / [`StoreError::FileNotOpen`]); the
    /// default implementation surfaces the failing segment's error.
    fn write_vectored_at(&self, offset: u64, bufs: &[&[u8]]) -> Result<(), StoreError> {
        write_vectored_sequential(self, offset, bufs)
    }

    /// Positioned read: returns the bytes actually read (short reads are legal at EOF).
    ///
    /// # Errors
    ///
    /// [`StoreError::FileIo`] from the read syscall;
    /// [`StoreError::FileNotOpen`] without an open file. A legal 0-byte
    /// read at EOF is `Ok(0)`, not an error.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, StoreError>;

    /// fsync to disk (mirrors `flushOSBuffers`).
    ///
    /// # Errors
    ///
    /// [`StoreError::FileIo`] from the fsync/`FlushFileBuffers` call.
    fn flush_os_buffers(&self) -> Result<(), StoreError>;

    /// Current file size (fstat st_size).
    ///
    /// # Errors
    ///
    /// [`StoreError::FileIo`] from the metadata call;
    /// [`StoreError::FileNotOpen`] without an open file.
    fn size(&self) -> Result<u64, StoreError>;

    /// Best-effort page-cache bypass (mirrors `openFileWithFlags`'s
    /// `__APPLE__` `F_NOCACHE` branch — aria2 ignores its failure;
    /// functionality is unaffected).
    ///
    /// # Errors
    ///
    /// [`StoreError::Unsupported`] on macOS (no safe fcntl wrapper; the
    /// caller logs and continues — aria2 parity). `Ok` no-op elsewhere.
    fn set_bypass_page_cache(&self) -> Result<(), StoreError>;
}

/// Sequential per-segment base for [`DiskWriter::write_vectored_at`]:
/// [`DiskWriter::write_at`] for each segment in order (short-write loops
/// live inside write_at) — byte-identical semantics to a vectored
/// implementation (the conservative path shared by the default
/// implementation, the Windows domain, and test stubs). `W: ?Sized` so
/// both the trait default's `&Self` (`?Sized`) and `&dyn DiskWriter`
/// (the TorrentWriter cross-file fallback face) call it.
pub(crate) fn write_vectored_sequential<W: DiskWriter + ?Sized>(
    writer: &W,
    mut offset: u64,
    bufs: &[&[u8]],
) -> Result<(), StoreError> {
    for buf in bufs {
        writer.write_at(offset, buf)?;
        offset += buf.len() as u64;
    }
    Ok(())
}

/// Iovec count cap for one vectored syscall = 512.
///
/// Source: `IOV_MAX = 1024` (darwin `sys/syslimits.h` / Linux
/// `limits.h`; pwritev beyond it returns `EINVAL`). Half the value for
/// headroom: callers' structural segment bounds (pipeline batches of 32
/// blocks, or the disk-policy merge window 4MiB/16KiB = 256 segments on
/// the hdd-sequential tier) are far below this cap — the chunking is
/// trait-face defense against arbitrary callers, not the hot path's
/// normal shape.
const WRITEV_IOVEC_CHUNK: usize = 512;

#[cfg(unix)]
pub use unix_impl::FileDiskWriter;

#[cfg(unix)]
mod unix_impl {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::os::unix::fs::{FileExt, OpenOptionsExt};

    /// `O_NOFOLLOW` platform constants (each platform's fcntl.h value;
    /// std does not export it and a new dependency just for this is
    /// avoided; `OpenOptionsExt::custom_flags` is a safe API, no unsafe).
    /// Security hardening: a symlink pre-planted in the download
    /// directory made `create`'s bare `O_CREAT|O_TRUNC` open punch
    /// through and write an arbitrary target — with the flag set, open
    /// fails with `ELOOP` when the final component is a symlink (the
    /// error lands in [`StoreError::FileIo`] as-is).
    /// Platform gap: only darwin/linux/android port the constant; other
    /// unix (freebsd etc.) does not set this flag (constant not ported —
    /// the placeholder is 0, which sets no flag). The Linux raw value
    /// must not leak to other unix: there it aliases O_DIRECTORY, which
    /// would fail every regular-file open with ENOTDIR and break the
    /// whole disk layer; see the platform notes.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const O_NOFOLLOW: i32 = 0x0100; // Darwin sys/fcntl.h
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const O_NOFOLLOW: i32 = 0o400000; // Linux/Android asm-generic/fcntl.h
    #[cfg(all(
        unix,
        not(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "linux",
            target_os = "android"
        ))
    ))]
    const O_NOFOLLOW: i32 = 0; // other unix: constant not ported — flag not set

    /// Unix implementation of [`DiskWriter`].
    #[derive(Debug)]
    pub struct FileDiskWriter {
        file: Option<File>,
        path: PathBuf,
        read_only: bool,
    }

    impl FileDiskWriter {
        pub fn new() -> Self {
            FileDiskWriter {
                file: None,
                path: PathBuf::new(),
                read_only: false,
            }
        }
    }

    impl Default for FileDiskWriter {
        fn default() -> Self {
            Self::new()
        }
    }

    impl DiskWriter for FileDiskWriter {
        fn open(&mut self, path: &Path, read_only: bool) -> Result<(), StoreError> {
            match self.open_existing(path, read_only) {
                Ok(()) => Ok(()),
                // Mirrors openFile: only ENOENT falls back to create; other errors propagate as-is.
                Err(StoreError::FileIo { source, .. })
                    if source.kind() == io::ErrorKind::NotFound =>
                {
                    self.create(path)
                }
                Err(e) => Err(e),
            }
        }

        fn open_existing(&mut self, path: &Path, read_only: bool) -> Result<(), StoreError> {
            // Open-face OS calls go through winpath conversion (an
            // identity borrow on non-Windows; error classification and
            // logging keep the original path). Resume/read/flush opens
            // set O_NOFOLLOW like create — a symlink pre-planted in the
            // download directory must not punch through the "open
            // existing" face (ELOOP propagates, no fallback).
            let file = OpenOptions::new()
                .read(true)
                .write(!read_only)
                .custom_flags(O_NOFOLLOW)
                .open(taiji_io::winpath::to_fs_path(path))
                .map_err(|e| classify_io(path, e))?;
            self.file = Some(file);
            self.path = path.to_path_buf();
            self.read_only = read_only;
            Ok(())
        }

        fn create(&mut self, path: &Path) -> Result<(), StoreError> {
            // Mirrors createFile: create parent directories first
            // (util::mkdirs), then O_CREAT|O_RDWR|O_TRUNC.
            // Security hardening: open adds `O_NOFOLLOW` (`custom_flags`;
            // platform constants in the module comment) — a symlink
            // pre-planted in the download directory must not be punched
            // through to an arbitrary target; ELOOP propagates as FileIo,
            // no fallback to a bare open. mkdirs goes through winpath
            // like the open face.
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(taiji_io::winpath::to_fs_path(parent))
                    .map_err(|e| classify_io(path, e))?;
            }
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .custom_flags(O_NOFOLLOW)
                .open(taiji_io::winpath::to_fs_path(path))
                .map_err(|e| classify_io(path, e))?;
            self.file = Some(file);
            self.path = path.to_path_buf();
            self.read_only = false;
            Ok(())
        }

        fn truncate(&mut self, len: u64) -> Result<(), StoreError> {
            let file = self.opened()?;
            file.set_len(len).map_err(|e| classify_io(&self.path, e))
        }

        /// Preallocation (mirrors aria2 `AbstractDiskWriter::allocate`'s
        /// three platform branches):
        /// - Trunc: sparse ftruncate;
        /// - Falloc: the fast path (macOS fcntl F_PREALLOCATE / Linux
        /// fallocate(2)) is stubbed to a trunc fallback — the libc
        /// calls are unsafe, forbidden workspace-wide, and a safe
        /// wrapper crate would be a new dependency (same reason as
        /// F_NOCACHE). The fallback is logged by the caller; success is
        /// never faked;
        /// - Prealloc: segment-wise zero fill (direct translation of
        /// aria2 `SingleFileAllocationIterator.cc`, 256KiB buffer) —
        /// real allocation on every platform (not sparse), protects
        /// HDDs from fragmentation.
        fn allocate(
            &mut self,
            len: u64,
            mode: AllocationMode,
        ) -> Result<AllocationEffect, StoreError> {
            match mode {
                AllocationMode::Trunc => self
                    .truncate(len)
                    .map(|()| AllocationEffect::Truncated { fallback: false }),
                AllocationMode::Falloc => {
                    tracing::warn!(
                        target: "taiji::store::disk",
                        path = %self.path.display(),
                        "falloc fast path unavailable on this platform/build \
                         (fcntl/fallocate need unsafe libc; safe wrapper + ADR \
                         pending, PLAN M1): falling back to trunc (sparse)"
                    );
                    self.truncate(len)
                        .map(|()| AllocationEffect::Truncated { fallback: true })
                }
                AllocationMode::Prealloc => self
                    .prealloc_zero_fill(len)
                    .map(|()| AllocationEffect::ZeroFilled),
            }
        }

        fn write_at(&self, offset: u64, data: &[u8]) -> Result<(), StoreError> {
            let file = self.opened()?;
            // std write_all_at: short writes/EINTR looped internally to
            // completion (pwrite, no shared cursor — concurrency note in
            // the trait docs).
            file.write_all_at(data, offset)
                .map_err(|e| classify_io(&self.path, e))
        }

        /// True vectorization face: `pwritev` (unix; mirrors libtorrent
        /// merging adjacent blocks into a single pwritev). Syscall face =
        /// `rustix::io::pwritev` (safe API — hand-rolled iovec/libc calls
        /// are unsafe, forbidden workspace-wide, and std
        /// `FileExt::write_vectored_at` is still unstable).
        /// `pwritev` may write short (returns bytes written) — the inner
        /// loop advances the segment window by bytes until everything is
        /// written (`IoSlice::advance_slices`; zero progress is an error
        /// to prevent spinning, same rule as the Windows `write_all_at`).
        fn write_vectored_at(&self, offset: u64, bufs: &[&[u8]]) -> Result<(), StoreError> {
            use std::io::IoSlice;
            let file = self.opened()?;
            // Chunk: iovecs per pwritev <= WRITEV_IOVEC_CHUNK (half of
            // IOV_MAX=1024; source in the constant note).
            let mut off = offset;
            for chunk in bufs.chunks(WRITEV_IOVEC_CHUNK) {
                let mut slices: Vec<IoSlice> = chunk.iter().map(|b| IoSlice::new(b)).collect();
                let mut pending: &mut [IoSlice] = &mut slices;
                while !pending.is_empty() {
                    let n = rustix::io::pwritev(file, pending, off)
                        .map_err(|e| classify_io(&self.path, e.into()))?;
                    if n == 0 {
                        return Err(StoreError::FileIo {
                            path: self.path.display().to_string(),
                            source: io::Error::other("vectored write made no progress"),
                        });
                    }
                    off += n as u64;
                    IoSlice::advance_slices(&mut pending, n);
                }
            }
            Ok(())
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, StoreError> {
            let file = self.opened()?;
            file.read_at(buf, offset)
                .map_err(|e| classify_io(&self.path, e))
        }

        fn flush_os_buffers(&self) -> Result<(), StoreError> {
            let file = self.opened()?;
            file.sync_all().map_err(|e| classify_io(&self.path, e))
        }

        fn size(&self) -> Result<u64, StoreError> {
            let file = self.opened()?;
            file.metadata()
                .map(|m| m.len())
                .map_err(|e| classify_io(&self.path, e))
        }

        fn set_bypass_page_cache(&self) -> Result<(), StoreError> {
            // Non-Apple unix: aria2 also does nothing here (same behavior
            // -> Ok). macOS F_NOCACHE needs a platform fcntl: neither
            // rustix nor nix exposes safe bindings and libc fcntl is
            // unsafe (workspace forbid) — a safe wrapper is a platform
            // API requiring an ADR. This side explicitly does not support
            // it and does not fake success.
            if cfg!(target_os = "macos") {
                Err(StoreError::Unsupported(
                    "F_NOCACHE (macOS; PLAN M1, needs safe fcntl wrapper + ADR)".into(),
                ))
            } else {
                Ok(())
            }
        }
    }

    impl FileDiskWriter {
        fn opened(&self) -> Result<&File, StoreError> {
            self.file.as_ref().ok_or(StoreError::FileNotOpen)
        }

        /// Full zero-fill prealloc (direct translation of aria2
        /// `SingleFileAllocationIterator.cc`): a 256KiB all-zero buffer
        /// written segment by segment at position, then a final
        /// `truncate` to land exactly on the target length. Start =
        /// current file length (call contract = newly created empty file,
        /// always 0; a non-zero start is also safe — only [size, len) is
        /// filled, existing data untouched).
        fn prealloc_zero_fill(&mut self, len: u64) -> Result<(), StoreError> {
            let file = self.opened()?;
            let start = file
                .metadata()
                .map(|m| m.len())
                .map_err(|e| classify_io(&self.path, e))?;
            if len > start {
                // SingleFileAllocationIterator.cc BUFSIZE = 256 KiB.
                const BUFSIZE: usize = 256 * 1024;
                let zeros = vec![0u8; BUFSIZE];
                let mut off = start;
                while off < len {
                    let n = ((len - off) as usize).min(BUFSIZE);
                    file.write_all_at(&zeros[..n], off)
                        .map_err(|e| classify_io(&self.path, e))?;
                    off += n as u64;
                }
            }
            self.truncate(len)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Regression (platform matrix): the Linux raw value `0o400000`
        /// must stay cfg-bound to linux/android — on other unix it
        /// aliases O_DIRECTORY (e.g. freebsd), which would fail every
        /// regular-file open with ENOTDIR and break the whole disk
        /// layer. Locks each arm: the ported arms hold their canonical
        /// fcntl.h values; the unported arm holds 0 (= no flag set, the
        /// documented platform gap).
        #[test]
        fn o_nofollow_constant_matches_platform_fcntl_h() {
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            assert_eq!(O_NOFOLLOW, 0x0100, "darwin sys/fcntl.h O_NOFOLLOW");
            #[cfg(any(target_os = "linux", target_os = "android"))]
            assert_eq!(O_NOFOLLOW, 0o400000, "asm-generic/fcntl.h O_NOFOLLOW");
            #[cfg(all(
                unix,
                not(any(
                    target_os = "macos",
                    target_os = "ios",
                    target_os = "linux",
                    target_os = "android"
                ))
            ))]
            assert_eq!(O_NOFOLLOW, 0, "unported unix must not set the flag");
        }
    }
}

#[cfg(windows)]
pub use windows_impl::FileDiskWriter;

/// Windows implementation of [`DiskWriter`].
///
/// Pure std safe-API face: the workspace's `unsafe_code = forbid` rules
/// out raw Win32 FFI (OVERLAPPED WriteFile / SetFileValidData calls),
/// and a Win32 binding crate (windows-rs etc.) would be a new
/// dependency, so this module does not add one.
///
/// # Positioned-write tradeoff
///
/// `FileExt::seek_write` with a short-write loop: std's safe wrapper for
/// OVERLAPPED `WriteFile` positioned writes, shape-matching libtorrent
/// `file.cpp` `pwrite_all` (a segment-wise OVERLAPPED WriteFile loop).
/// Raw OVERLAPPED `WriteFile` is rejected: it needs unsafe FFI
/// (forbidden) or a new dependency crate. std documents that
/// `seek_write` short writes are not errors and the cursor moves after
/// writing — the cursor side effect is data-irrelevant (all IO is
/// positioned, never cursor-based) but IS a concurrency hazard: std's
/// seek+write pair is not atomic, so concurrent `seek_write` calls can
/// interleave and land bytes at the wrong absolute position. The
/// per-instance [`FileDiskWriter`]'s `write_gate` mutex serializes the
/// seek+write pairs (see `write_at`), which is what makes the trait's
/// `Sync` promise hold on this platform. The short-write loop equals
/// unix `write_all_at`.
///
/// # Open/handle semantics
///
/// One [`FileDiskWriter`] holds one `File` handle: the pool's opener
/// calls `open`/`open_existing`, the closer drops the handle (LRU close
/// = handle close); open failures propagate as-is and fields land only
/// on success (same policy as unix). Share mode is std's default
/// `FILE_SHARE_READ|WRITE|DELETE`, matching libtorrent `CreateFileW`
/// (`file.cpp`); handles are non-inheritable
/// (lpSecurityAttributes=NULL).
#[cfg(windows)]
mod windows_impl {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::os::windows::fs::{FileExt, OpenOptionsExt};
    use std::sync::Mutex;

    /// `FILE_FLAG_OPEN_REPARSE_POINT` (winbase.h `0x00200000`; std does
    /// not export it and a new dependency just for this is avoided;
    /// `OpenOptionsExt::custom_flags` is a safe API, no unsafe).
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    /// `seek_write` to completion (short-write loop): the Windows
    /// equivalent of unix `write_all_at` (mirrors libtorrent
    /// `pwrite_all`, `file.cpp`: a segment-wise OVERLAPPED `WriteFile`
    /// loop; zero byte progress is an error — same rule here, prevents
    /// spinning).
    fn write_all_at(
        file: &File,
        path: &Path,
        mut data: &[u8],
        mut offset: u64,
    ) -> Result<(), StoreError> {
        while !data.is_empty() {
            let n = file
                .seek_write(data, offset)
                .map_err(|e| classify_io(path, e))?;
            if n == 0 {
                return Err(StoreError::FileIo {
                    path: path.display().to_string(),
                    source: io::Error::other("positioned write made no progress"),
                });
            }
            data = &data[n..];
            offset += n as u64;
        }
        Ok(())
    }

    /// Windows implementation of [`DiskWriter`].
    ///
    /// `write_gate` serializes the non-atomic `seek_write` (seek+write
    /// pair) of concurrent `&self` writes — this is what upholds the
    /// [`DiskWriter`] `Sync` promise on Windows (the unix arm needs no
    /// gate: `pwrite` has no shared cursor). Deriving `Debug` is safe:
    /// `Mutex`'s own `Debug` probes with `try_lock` (never blocks), no
    /// bulk data lives behind it.
    #[derive(Debug)]
    pub struct FileDiskWriter {
        file: Option<File>,
        path: PathBuf,
        read_only: bool,
        write_gate: Mutex<()>,
    }

    impl FileDiskWriter {
        pub fn new() -> Self {
            FileDiskWriter {
                file: None,
                path: PathBuf::new(),
                read_only: false,
                write_gate: Mutex::new(()),
            }
        }
    }

    impl Default for FileDiskWriter {
        fn default() -> Self {
            Self::new()
        }
    }

    impl DiskWriter for FileDiskWriter {
        fn open(&mut self, path: &Path, read_only: bool) -> Result<(), StoreError> {
            match self.open_existing(path, read_only) {
                Ok(()) => Ok(()),
                // Mirrors openFile: only NotFound falls back to create;
                // other errors propagate as-is (std maps
                // ERROR_FILE_NOT_FOUND/ERROR_PATH_NOT_FOUND to
                // `io::ErrorKind::NotFound`).
                Err(StoreError::FileIo { source, .. })
                    if source.kind() == io::ErrorKind::NotFound =>
                {
                    self.create(path)
                }
                Err(e) => Err(e),
            }
        }

        fn open_existing(&mut self, path: &Path, read_only: bool) -> Result<(), StoreError> {
            // OPEN_EXISTING (std default, no create flags): read_only =
            // GENERIC_READ only; otherwise GENERIC_READ|GENERIC_WRITE.
            // Open-face OS calls go through winpath conversion (Windows
            // long paths get the `\\?\` prefix; error classification and
            // logging keep the original path).
            let file = OpenOptions::new()
                .read(true)
                .write(!read_only)
                .open(taiji_io::winpath::to_fs_path(path))
                .map_err(|e| classify_io(path, e))?;
            self.file = Some(file);
            self.path = path.to_path_buf();
            self.read_only = read_only;
            Ok(())
        }

        fn create(&mut self, path: &Path) -> Result<(), StoreError> {
            // Mirrors createFile (aria2 AbstractDiskWriter.cc): create
            // parent directories first (util::mkdirs), then
            // O_CREAT|O_RDWR|O_TRUNC semantics.
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(taiji_io::winpath::to_fs_path(parent))
                        .map_err(|e| classify_io(path, e))?;
                }
            }
            // Security hardening (parity with unix `O_NOFOLLOW`): with
            // FILE_FLAG_OPEN_REPARSE_POINT set, open does not follow a
            // symlink/mount point in the final component but returns the
            // reparse point handle; the explicit `is_symlink()` check
            // then rejects it (the ELOOP equivalent). After the check
            // passes, `set_len(0)` performs the O_TRUNC.
            // std's `create(true).truncate(true)` (CREATE_ALWAYS) is not
            // used: combined with OPEN_REPARSE_POINT its "replace"
            // semantics for an existing reparse point are ambiguous and
            // could destroy the target before the check.
            // Only the final path component is protected (parent
            // components follow normally — same scope as O_NOFOLLOW).
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true) // OPEN_ALWAYS; trunc done by set_len(0) after the check
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(taiji_io::winpath::to_fs_path(path))
                .map_err(|e| classify_io(path, e))?;
            let is_reparse = file
                .metadata()
                .map(|m| m.file_type().is_symlink())
                .map_err(|e| classify_io(path, e))?;
            if is_reparse {
                return Err(StoreError::FileIo {
                    path: path.display().to_string(),
                    source: io::Error::other(
                        "refusing to create through symlink/reparse point (O_NOFOLLOW parity)",
                    ),
                });
            }
            file.set_len(0).map_err(|e| classify_io(path, e))?;
            self.file = Some(file);
            self.path = path.to_path_buf();
            self.read_only = false;
            Ok(())
        }

        fn truncate(&mut self, len: u64) -> Result<(), StoreError> {
            // SetEndOfFile semantics: sparse extension/shrink on NTFS,
            // same shape as unix ftruncate.
            let file = self.opened()?;
            file.set_len(len).map_err(|e| classify_io(&self.path, e))
        }

        /// Preallocation (Windows terms; same three-tier structure):
        /// - Trunc: sparse set_len (same as unix);
        /// - Falloc: falls back to trunc, reported accurately (no fake
        /// fast path). The real Windows fast path = `SetFileValidData`
        /// (libtorrent `file.cpp` privileged call_once:
        /// SetFilePointerEx+SetEndOfFile+SetFileValidData), which needs
        /// `SE_MANAGE_VOLUME_NAME` privilege and Win32 FFI — beyond
        /// std's safe face (forbidden); a safe wrapper would be a new
        /// dependency and is not added. The fallback is logged by the
        /// caller (same tier as the unix falloc fallback);
        /// - Prealloc: segment-wise zero fill (direct translation of
        /// aria2 `SingleFileAllocationIterator.cc`, 256KiB buffer) —
        /// real allocation (not sparse), same algorithm as unix,
        /// identical on all platforms.
        fn allocate(
            &mut self,
            len: u64,
            mode: AllocationMode,
        ) -> Result<AllocationEffect, StoreError> {
            match mode {
                AllocationMode::Trunc => self
                    .truncate(len)
                    .map(|()| AllocationEffect::Truncated { fallback: false }),
                AllocationMode::Falloc => {
                    tracing::warn!(
                        target: "taiji::store::disk",
                        path = %self.path.display(),
                        "falloc fast path unavailable on windows \
                         (SetFileValidData needs SE_MANAGE_VOLUME_NAME privilege + \
                         Win32 FFI; unsafe forbidden / safe wrapper + ADR pending): \
                         falling back to trunc (sparse)"
                    );
                    self.truncate(len)
                        .map(|()| AllocationEffect::Truncated { fallback: true })
                }
                AllocationMode::Prealloc => self
                    .prealloc_zero_fill(len)
                    .map(|()| AllocationEffect::ZeroFilled),
            }
        }

        fn write_at(&self, offset: u64, data: &[u8]) -> Result<(), StoreError> {
            let file = self.opened()?;
            // seek_write's seek+write pair is not atomic: concurrent
            // &self writes could interleave the pair and land bytes at
            // the wrong absolute position. The per-instance gate
            // serializes whole writes, which is what makes this
            // writer's `Sync` honest on Windows (the old prose-only
            // discipline relied on the SharedDiskWriter write-exclusive
            // routing; the gate enforces it at the writer itself).
            // Poisoning = fatal per the crate lock policy ([`crate::lock`]).
            let _gate = crate::lock(&self.write_gate);
            write_all_at(file, &self.path, data, offset)
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, StoreError> {
            let file = self.opened()?;
            // Single positioned read: a legal 0-byte read at EOF (std:
            // "Reading beyond the end of the file will always return with
            // a length of 0") = unix `read_at` semantics (returns bytes
            // actually read).
            file.seek_read(buf, offset)
                .map_err(|e| classify_io(&self.path, e))
        }

        fn flush_os_buffers(&self) -> Result<(), StoreError> {
            // FlushFileBuffers equivalent (the Windows face of aria2
            // flushOSBuffers).
            let file = self.opened()?;
            file.sync_all().map_err(|e| classify_io(&self.path, e))
        }

        fn size(&self) -> Result<u64, StoreError> {
            let file = self.opened()?;
            file.metadata()
                .map(|m| m.len())
                .map_err(|e| classify_io(&self.path, e))
        }

        fn set_bypass_page_cache(&self) -> Result<(), StoreError> {
            // Windows: aria2's F_NOCACHE branch is `__APPLE__` only (same
            // behavior -> Ok no-op, same as non-Apple unix). A real
            // bypass = open-time FILE_FLAG_WRITE_THROUGH / NO_BUFFERING
            // (libtorrent file.cpp) — an open-time performance seam, out
            // of scope for this module; success is never faked after the
            // fact.
            Ok(())
        }
    }

    impl FileDiskWriter {
        fn opened(&self) -> Result<&File, StoreError> {
            self.file.as_ref().ok_or(StoreError::FileNotOpen)
        }

        /// Full zero-fill prealloc (direct translation of aria2
        /// `SingleFileAllocationIterator.cc`, same algorithm as the unix
        /// module): a 256KiB all-zero buffer written segment by segment
        /// at position, then a final `truncate` to the target length.
        /// Start = current file length (call contract = newly created
        /// empty file, always 0; a non-zero start is also safe — only
        /// [size, len) is filled).
        fn prealloc_zero_fill(&mut self, len: u64) -> Result<(), StoreError> {
            let file = self.opened()?;
            let start = file
                .metadata()
                .map(|m| m.len())
                .map_err(|e| classify_io(&self.path, e))?;
            if len > start {
                // SingleFileAllocationIterator.cc BUFSIZE = 256 KiB.
                const BUFSIZE: usize = 256 * 1024;
                let zeros = vec![0u8; BUFSIZE];
                let mut off = start;
                while off < len {
                    let n = ((len - off) as usize).min(BUFSIZE);
                    write_all_at(file, &self.path, &zeros[..n], off)?;
                    off += n as u64;
                }
            }
            self.truncate(len)
        }
    }
}

/// io::Error -> store error classification (mirrors `isDiskFullError`:
/// disk full -> NoSpace).
///
/// Disk-full detection uses each platform's *native* codes, never mixed
/// across platforms:
/// - unix: `ENOSPC` = 28 (same value on linux/macOS);
/// - Windows (winerror.h): `ERROR_DISK_FULL` = 112,
/// `ERROR_HANDLE_DISK_FULL` = 39 (Win16 legacy alias, still possible
/// from filter-driver stacks); raw 28 on Windows is
/// `ERROR_NOT_A_REPARSE_POINT`, unrelated to disk full.
pub(crate) fn classify_io(path: &Path, e: io::Error) -> StoreError {
    #[cfg(windows)]
    let disk_full = matches!(e.raw_os_error(), Some(112) | Some(39));
    #[cfg(not(windows))]
    let disk_full = {
        const ENOSPC: i32 = 28; // same value on linux/macOS
        e.raw_os_error() == Some(ENOSPC)
    };
    if disk_full {
        StoreError::NoSpace {
            path: path.display().to_string(),
            source: e,
        }
    } else {
        StoreError::FileIo {
            path: path.display().to_string(),
            source: e,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "taiji-disk-{}-{}-{}",
                tag,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos())
                    .unwrap_or(0)
            ));
            TempDir(dir)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Test Result unwrap (lints forbid unwrap/expect).
    fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("{what}: {e}"),
        }
    }

    /// xorshift64 deterministic PRNG (no rand dependency; reproducible tests).
    fn xorshift(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }

    #[test]
    fn error_classification_enospc_vs_other_io() {
        // Error classification coverage. Disk-full codes are each
        // platform's native code (see the classify_io docs: unix
        // ENOSPC=28; Windows ERROR_DISK_FULL=112), never mixed across
        // platforms.
        let path = Path::new("/tmp/x");
        #[cfg(windows)]
        let enospc = io::Error::from_raw_os_error(112);
        #[cfg(not(windows))]
        let enospc = io::Error::from_raw_os_error(28);
        match classify_io(path, enospc) {
            StoreError::NoSpace { path: p, .. } => assert!(p.contains("/tmp/x")),
            other => panic!("disk-full must map to NoSpace, got {other:?}"),
        }
        let eacces = io::Error::from_raw_os_error(13);
        match classify_io(path, eacces) {
            StoreError::FileIo { path: p, .. } => assert!(p.contains("/tmp/x")),
            other => panic!("EACCES must map to FileIo, got {other:?}"),
        }
    }

    /// Windows disk-full classification: ERROR_DISK_FULL(112) and the
    /// legacy alias ERROR_HANDLE_DISK_FULL(39) -> NoSpace;
    /// ERROR_ACCESS_DENIED(5) -> FileIo; unix ENOSPC raw 28 is an
    /// unrelated code on Windows (NOT_A_REPARSE_POINT) -> not mapped
    /// (guards against cross-platform mixing).
    #[cfg(windows)]
    #[test]
    fn windows_disk_full_codes_map_to_nospace() {
        let path = Path::new(r"C:\tmp\x");
        for code in [112, 39] {
            match classify_io(path, io::Error::from_raw_os_error(code)) {
                StoreError::NoSpace { path: p, .. } => assert!(p.contains(r"C:\tmp\x")),
                other => panic!("ERROR {code} must map to NoSpace, got {other:?}"),
            }
        }
        match classify_io(path, io::Error::from_raw_os_error(5)) {
            StoreError::FileIo { .. } => {}
            other => panic!("ERROR_ACCESS_DENIED must map to FileIo, got {other:?}"),
        }
        match classify_io(path, io::Error::from_raw_os_error(28)) {
            StoreError::FileIo { .. } => {}
            other => panic!("raw 28 on windows must NOT map to NoSpace, got {other:?}"),
        }
    }

    /// Positioned writes are cursor-independent: out-of-order offset
    /// writes + read back. Windows `seek_write` has cursor side effects
    /// (std: the cursor moves after writing) — this object never does
    /// cursor IO, and out-of-order positioned writes must not interfere
    /// (unix `write_all_at` guarantees the same; tested on both
    /// platforms).
    #[test]
    fn positioned_writes_are_cursor_independent() {
        let tmp = TempDir::new("cursor");
        let path = tmp.path("c.bin");
        let mut w = FileDiskWriter::new();
        ok(w.create(&path), "create");
        ok(w.write_at(4, b"BBBB"), "write at 4");
        ok(w.write_at(0, b"AA"), "write at 0 (descending order)");
        ok(w.write_at(8, b"CC"), "write past previous end");
        let mut buf = [0u8; 10];
        let n = ok(w.read_at(0, &mut buf), "read back");
        assert_eq!(n, 10);
        // [0,2)=AA, [2,4)=zero gap, [4,8)=BBBB, [8,10)=CC.
        assert_eq!(&buf, b"AA\0\0BBBBCC");
    }

    #[test]
    fn write_read_roundtrip_across_page_boundary() {
        let tmp = TempDir::new("roundtrip");
        let path = tmp.path("a.bin");
        let mut w = FileDiskWriter::new();
        ok(w.create(&path), "create");

        // offset+len crosses a 4KiB page boundary (short-write edge).
        let offset: u64 = 8 * 1024 - 3;
        let data: Vec<u8> = (0..20u32).map(|i| (i * 7) as u8).collect();
        ok(w.write_at(offset, &data), "write cross-page");

        let mut buf = vec![0u8; data.len()];
        let n = ok(w.read_at(offset, &mut buf), "read cross-page");
        assert_eq!(n, data.len());
        assert_eq!(buf, data);
        // size grows with positioned writes.
        assert_eq!(ok(w.size(), "size"), offset + data.len() as u64);

        // trunc shrink and sparse growth.
        ok(w.truncate(4 * 1024), "truncate down");
        assert_eq!(ok(w.size(), "size after shrink"), 4 * 1024);
        ok(w.truncate(1 << 20), "truncate up (sparse)");
        assert_eq!(ok(w.size(), "size after grow"), 1 << 20);
        ok(w.flush_os_buffers(), "fsync");
    }

    /// Vectored write: the unix `pwritev` face (trait override) and the
    /// sequential default face are byte-identical — multi-segment
    /// concatenated write + byte-for-byte read-back (segment boundaries
    /// across a 4KiB page boundary, empty-segment skip, contiguous span
    /// after out-of-order writes).
    #[test]
    fn write_vectored_at_matches_sequential_semantics() {
        let tmp = TempDir::new("writev");
        let path = tmp.path("v.bin");
        let mut w = FileDiskWriter::new();
        ok(w.create(&path), "create");

        // Segment boundary crosses a page boundary: offset starts 3 bytes
        // into a page; segment lengths 4090/10 (crossing).
        let offset: u64 = 8 * 1024 - 3;
        let a: Vec<u8> = (0..4090u32).map(|i| (i % 251) as u8).collect();
        let b: Vec<u8> = (0..10u32).map(|i| (i % 13) as u8).collect();
        let c: Vec<u8> = (0..100u32).map(|i| (i % 7) as u8).collect();
        ok(w.write_vectored_at(offset, &[&a, &b, &c]), "writev 3 segs");
        ok(
            w.write_vectored_at(offset, &[&a, &[], &b, &c]),
            "writev empty segment rewrites equivalently",
        );

        let mut want = a;
        want.extend_from_slice(&b);
        want.extend_from_slice(&c);
        let mut got = vec![0u8; want.len()];
        let n = ok(w.read_at(offset, &mut got), "read back");
        assert_eq!(n, want.len());
        assert_eq!(
            got, want,
            "the vectored-write read-back must match the concatenated segments"
        );
        assert_eq!(ok(w.size(), "size"), offset + want.len() as u64);
    }

    /// Vectored write past the per-syscall iovec cap (WRITEV_IOVEC_CHUNK
    /// = 512, the IOV_MAX half-value defense) chunks into multiple
    /// syscalls — 1024 segments x 64B all written, read back identical.
    #[test]
    fn write_vectored_at_chunks_past_iovec_limit() {
        let tmp = TempDir::new("writev-chunk");
        let path = tmp.path("vc.bin");
        let mut w = FileDiskWriter::new();
        ok(w.create(&path), "create");

        let segs: Vec<Vec<u8>> = (0..1024u32).map(|i| vec![i as u8; 64]).collect();
        let refs: Vec<&[u8]> = segs.iter().map(|v| v.as_slice()).collect();
        ok(w.write_vectored_at(0, &refs), "writev 1024 segs");

        let mut got = vec![0u8; 1024 * 64];
        let n = ok(w.read_at(0, &mut got), "read back");
        assert_eq!(n, got.len());
        for (i, seg) in got.chunks(64).enumerate() {
            assert!(seg.iter().all(|&b| b == i as u8), "segment {i} content");
        }
    }

    /// Default implementation (per-segment write_at base): validated
    /// directly via `write_vectored_sequential` on FileDiskWriter —
    /// locking the path semantics that the Windows domain and test stubs
    /// inherit.
    #[test]
    fn write_vectored_sequential_fallback_semantics() {
        let tmp = TempDir::new("writev-seq");
        let path = tmp.path("vs.bin");
        let mut w = FileDiskWriter::new();
        ok(w.create(&path), "create");
        let a = b"hello ";
        let b = b"vectored";
        ok(
            write_vectored_sequential(&w, 2, &[a.as_slice(), b.as_slice()]),
            "sequential fallback",
        );
        let mut got = [0u8; 14];
        let n = ok(w.read_at(2, &mut got), "read back");
        assert_eq!(n, 14);
        assert_eq!(&got, b"hello vectored");
    }

    #[test]
    fn create_makes_parent_directories() {
        let tmp = TempDir::new("mkdirs");
        let path = tmp.path("deep/nested/dir/file.bin");
        let mut w = FileDiskWriter::new();
        ok(w.create(&path), "create with mkdirs");
        assert!(
            path.exists(),
            "parent dirs must be created (reference createFile mkdirs)"
        );
    }

    /// Security regression: a symlink pre-planted in the download
    /// directory must not be punched through by `create` into an
    /// arbitrary target — `O_NOFOLLOW` makes open fail with `ELOOP` and
    /// the target file stays untouched (macOS/Linux; the other-unix gap
    /// is noted in the module docs).
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "android"))]
    #[test]
    fn create_refuses_pre_planted_symlink() {
        use std::fs;

        let tmp = TempDir::new("nofollow");
        // TempDir only provides the path, no directory — create the base directory first.
        ok(fs::create_dir_all(&tmp.0), "mkdir tmp base");
        // "Victim": an existing file outside the download directory.
        let victim = tmp.path("victim.txt");
        ok(fs::write(&victim, b"DO-NOT-TOUCH"), "seed victim");
        // A pre-planted symlink inside the download directory points at the victim.
        let planted_dir = tmp.path("sub");
        let planted = planted_dir.join("download.bin");
        ok(fs::create_dir_all(&planted_dir), "mkdir planted parent");
        ok(
            std::os::unix::fs::symlink(&victim, &planted),
            "plant symlink",
        );

        let mut w = FileDiskWriter::new();
        match w.create(&planted) {
            Err(StoreError::FileIo { .. }) => {}
            other => panic!("create on symlink must fail with FileIo (ELOOP), got {other:?}"),
        }
        // Victim content was not punched through.
        let content = ok(fs::read(&victim), "read victim");
        assert_eq!(
            content, b"DO-NOT-TOUCH",
            "the symlink target must not be written"
        );
        // create on a real file path is unaffected (the guard does not break normal paths).
        let real = tmp.path("real.bin");
        let mut w2 = FileDiskWriter::new();
        ok(w2.create(&real), "create real path after guard");
        ok(w2.write_at(0, b"hello"), "write real path");
    }

    /// Security regression — Windows face: an NTFS file symlink is a
    /// reparse point; `create` sets `FILE_FLAG_OPEN_REPARSE_POINT`, gets
    /// the reparse point handle, and must reject it via `is_symlink()`
    /// (the equivalent of unix O_NOFOLLOW's ELOOP); the target content
    /// stays untouched.
    ///
    /// Environment note: creating NTFS symlinks needs the
    /// SeCreateSymbolicLink privilege (CI grants it via Developer Mode);
    /// without the privilege the behavior cannot be constructed, so the
    /// test silently skips (missing environment capability, not a
    /// failure of the behavior under test).
    #[cfg(windows)]
    #[test]
    fn create_refuses_pre_planted_symlink() {
        use std::fs;
        use std::os::windows::fs::symlink_file;

        let tmp = TempDir::new("nofollow");
        ok(fs::create_dir_all(&tmp.0), "mkdir tmp base");
        // "Victim": an existing file outside the download directory.
        let victim = tmp.path("victim.txt");
        ok(fs::write(&victim, b"DO-NOT-TOUCH"), "seed victim");
        // A pre-planted symlink inside the download directory points at the victim.
        let planted_dir = tmp.path("sub");
        let planted = planted_dir.join("download.bin");
        ok(fs::create_dir_all(&planted_dir), "mkdir planted parent");
        if symlink_file(&victim, &planted).is_err() {
            return; // No SeCreateSymbolicLink privilege: cannot construct, skip (see above).
        }

        let mut w = FileDiskWriter::new();
        match w.create(&planted) {
            Err(StoreError::FileIo { .. }) => {}
            other => panic!("create on symlink must fail with FileIo, got {other:?}"),
        }
        // Victim content was not punched through.
        let content = ok(fs::read(&victim), "read victim");
        assert_eq!(
            content, b"DO-NOT-TOUCH",
            "the symlink target must not be written"
        );
        // create on a real file path is unaffected (the guard does not break normal paths).
        let real = tmp.path("real.bin");
        let mut w2 = FileDiskWriter::new();
        ok(w2.create(&real), "create real path after guard");
        ok(w2.write_at(0, b"hello"), "write real path");
    }

    #[test]
    fn open_falls_back_to_create_on_enoent() {
        // Mirrors aria2 openFile: ENOENT -> create fallback.
        let tmp = TempDir::new("fallback");
        let path = tmp.path("fresh.bin");
        let mut w = FileDiskWriter::new();
        ok(w.open(&path, false), "open fallback");
        assert!(path.exists());
        ok(w.write_at(0, b"hello"), "write after fallback");

        // Existing file: open directly, no truncation (openExistingFile semantics).
        let mut w2 = FileDiskWriter::new();
        ok(w2.open(&path, false), "open existing");
        assert_eq!(ok(w2.size(), "size"), 5);
    }

    #[test]
    fn read_only_open_rejects_write_allows_read() {
        let tmp = TempDir::new("readonly");
        let path = tmp.path("ro.bin");
        {
            let mut w = FileDiskWriter::new();
            ok(w.create(&path), "create");
            ok(w.write_at(0, b"abcdef"), "seed");
        }
        let mut ro = FileDiskWriter::new();
        ok(ro.open_existing(&path, true), "open read-only");
        let mut buf = [0u8; 6];
        let n = ok(ro.read_at(0, &mut buf), "read");
        assert_eq!((&buf[..n], n), (&b"abcdef"[..], 6usize));
        match ro.write_at(0, b"xyz") {
            Err(StoreError::FileIo { source, .. }) => {
                assert_ne!(
                    source.kind(),
                    io::ErrorKind::Other,
                    "must be an EBADF-class error"
                );
            }
            other => panic!("write on read-only handle must fail, got {other:?}"),
        }
    }

    #[test]
    fn bypass_page_cache_explicit_policy() {
        let tmp = TempDir::new("nocache");
        let path = tmp.path("nc.bin");
        let mut w = FileDiskWriter::new();
        ok(w.create(&path), "create");
        match w.set_bypass_page_cache() {
            // macOS: explicit Unsupported (needs a safe fcntl wrapper; see the impl comment).
            #[cfg(target_os = "macos")]
            Err(StoreError::Unsupported(msg)) => assert!(msg.contains("F_NOCACHE")),
            // Other unix: same behavior as aria2 (do nothing -> Ok).
            #[cfg(not(target_os = "macos"))]
            Ok(()) => {}
            other => panic!("unexpected bypass_page_cache result: {other:?}"),
        }
    }

    #[test]
    fn sparse_1gib_random_write_readback() {
        // 1GiB sparse-file random-write read-back (truncate creates sparse, no disk usage).
        let tmp = TempDir::new("sparse1g");
        let path = tmp.path("sparse.bin");
        let mut w = FileDiskWriter::new();
        ok(w.create(&path), "create");
        let gib: u64 = 1024 * 1024 * 1024;
        ok(w.truncate(gib), "ftruncate 1GiB");
        assert_eq!(ok(w.size(), "size"), gib);

        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        let block: u64 = 4 * 1024;
        for i in 0..64u32 {
            let offset = (xorshift(&mut seed) % (gib - block)) & !3; // 4-byte aligned
            let data: Vec<u8> = (0..block as u32)
                .map(|b| ((i as u64 * 31 + b as u64 * 17 + offset) & 0xFF) as u8)
                .collect();
            ok(w.write_at(offset, &data), "write block {i}");
            let mut buf = vec![0u8; block as usize];
            let n = ok(w.read_at(offset, &mut buf), "read block {i}");
            assert_eq!(n, block as usize);
            assert_eq!(buf, data, "readback mismatch at offset {offset}");
        }
    }

    // -------------------------------------------------------------------
    // Preallocation closed loop (trunc / falloc / prealloc: effect assertions + fallback path).
    // -------------------------------------------------------------------

    /// st_blocks (512B-unit disk blocks; unix MetadataExt). Windows has
    /// no stable equivalent reading (`file_size_on_disk` is still
    /// unstable, windows_file_size_on_disk #63010; GetCompressedFileSize
    /// needs FFI) — the Windows preallocation assertion is the
    /// functional-equivalence test below.
    #[cfg(unix)]
    fn allocated_blocks(path: &Path) -> u64 {
        use std::os::unix::fs::MetadataExt;
        let m = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => panic!("stat {path:?}: {e}"),
        };
        m.blocks()
    }

    /// prealloc effect assertion: (1) the effect reports ZeroFilled
    /// accurately; (2) allocated blocks ~= the full file length (a
    /// same-length sparse trunc file is far smaller than a real
    /// allocation); (3) the allocated region reads as zeros and data
    /// written at head/tail survives (file readability + preallocation
    /// does not break later writes). The block-count comparison is a unix
    /// reading (st_blocks) — the Windows functional-equivalent assertion
    /// is in `prealloc_zero_fill_functional_on_windows`.
    #[cfg(unix)]
    #[test]
    fn prealloc_yields_real_allocation_and_readable_file() {
        let tmp = TempDir::new("prealloc");
        let path = tmp.path("pre.bin");
        let mut w = FileDiskWriter::new();
        ok(w.create(&path), "create");
        let len: u64 = 2 * 1024 * 1024;
        let effect = ok(w.allocate(len, AllocationMode::Prealloc), "prealloc");
        assert_eq!(
            effect,
            AllocationEffect::ZeroFilled,
            "prealloc = a real zero-filled allocation"
        );
        // Write real data at the head/tail of the allocated region; the middle stays zero.
        ok(w.write_at(0, b"head-data"), "write head");
        ok(w.write_at(len - 4096, b"tail-data"), "write tail");
        let mut buf = [0u8; 9];
        ok(w.read_at(0, &mut buf), "read head");
        assert_eq!(&buf, b"head-data");
        ok(w.read_at(len - 4096, &mut buf), "read tail");
        assert_eq!(&buf, b"tail-data");
        let mut mid = vec![1u8; 4096];
        ok(w.read_at(len / 2, &mut mid), "read middle");
        assert!(
            mid.iter().all(|&b| b == 0),
            "the unwritten allocated region reads as zeros"
        );

        // Non-sparse comparison: a same-length sparse trunc file must use
        // far fewer disk blocks than prealloc (sparse ~= 0; zero-fill ~=
        // full length/512).
        let sparse_path = tmp.path("sparse.bin");
        let mut sw = FileDiskWriter::new();
        ok(sw.create(&sparse_path), "create sparse");
        let sparse_effect = ok(sw.allocate(len, AllocationMode::Trunc), "trunc");
        assert_eq!(
            sparse_effect,
            AllocationEffect::Truncated { fallback: false }
        );
        let pre_blocks = allocated_blocks(&path);
        let sparse_blocks = allocated_blocks(&sparse_path);
        assert!(
            sparse_blocks * 8 < pre_blocks,
            "trunc must be far sparser than prealloc: sparse={sparse_blocks} pre={pre_blocks}"
        );
        assert!(
            pre_blocks * 512 + 4096 >= len,
            "prealloc disk usage must cover the full length: {pre_blocks} blocks for {len}B"
        );
    }

    /// prealloc functional-equivalence assertion — Windows: no stable
    /// disk-cluster reading API (see the `allocated_blocks` note), so the
    /// zero-fill algorithm contract itself is asserted: (1) the effect
    /// reports ZeroFilled accurately; (2) the segment-wise zero fill runs
    /// in full (the middle of the allocated region reads zero, head/tail
    /// data survives, size = target length) — on NTFS, writing [0,len)
    /// via WriteFile physically allocates (not sparse); the st_blocks-
    /// level comparison stays locked by the unix test.
    #[cfg(windows)]
    #[test]
    fn prealloc_zero_fill_functional_on_windows() {
        let tmp = TempDir::new("prealloc-win");
        let path = tmp.path("pre.bin");
        let mut w = FileDiskWriter::new();
        ok(w.create(&path), "create");
        let len: u64 = 2 * 1024 * 1024;
        let effect = ok(w.allocate(len, AllocationMode::Prealloc), "prealloc");
        assert_eq!(
            effect,
            AllocationEffect::ZeroFilled,
            "zero fill = reported as a real allocation"
        );
        assert_eq!(ok(w.size(), "size"), len);
        ok(w.write_at(0, b"head-data"), "write head");
        ok(w.write_at(len - 4096, b"tail-data"), "write tail");
        let mut buf = [0u8; 9];
        ok(w.read_at(0, &mut buf), "read head");
        assert_eq!(&buf, b"head-data");
        ok(w.read_at(len - 4096, &mut buf), "read tail");
        assert_eq!(&buf, b"tail-data");
        let mut mid = vec![1u8; 4096];
        ok(w.read_at(len / 2, &mut mid), "read middle");
        assert!(
            mid.iter().all(|&b| b == 0),
            "the unwritten allocated region reads as zeros"
        );
    }

    /// falloc fast-path status (stubbed accurately; see the disk_policy
    /// module docs for the platform capability matrix — fcntl/fallocate
    /// need unsafe libc, forbidden workspace-wide; a safe wrapper would
    /// be a new dependency): design-specified fallback to trunc +
    /// accurately reported fallback=true effect + a functionally sound
    /// file. (Once a safe fcntl wrapper lands, this assertion updates to
    /// the Fallocated branch per the platform matrix — same dispatch
    /// style as bypass_page_cache_explicit_policy.)
    #[test]
    fn falloc_unavailable_falls_back_to_trunc_with_honest_effect() {
        let tmp = TempDir::new("falloc");
        let path = tmp.path("f.bin");
        let mut w = FileDiskWriter::new();
        ok(w.create(&path), "create");
        let effect = ok(w.allocate(1 << 20, AllocationMode::Falloc), "falloc");
        assert_eq!(
            effect,
            AllocationEffect::Truncated { fallback: true },
            "the stub-period fallback must be reported accurately (no masquerading as success)"
        );
        assert_eq!(ok(w.size(), "size"), 1 << 20);
        // The fallback path file is readable (sparse reads return zeros).
        let mut buf = [1u8; 16];
        let n = ok(w.read_at(0, &mut buf), "read");
        assert_eq!(n, 16);
        assert!(
            buf.iter().all(|&b| b == 0),
            "the trunc sparse read returns zeros"
        );
    }

    /// prealloc only fills [current length, target length) — existing
    /// data untouched (defensive contract: allocation semantics belong to
    /// newly created empty files, and a non-zero start is safe too).
    #[test]
    fn prealloc_zero_fill_starts_at_current_size() {
        let tmp = TempDir::new("prealloc-keep");
        let path = tmp.path("keep.bin");
        let mut w = FileDiskWriter::new();
        ok(w.create(&path), "create");
        ok(w.write_at(0, b"PRESERVED"), "seed head");
        let effect = ok(w.allocate(64 * 1024, AllocationMode::Prealloc), "prealloc");
        assert_eq!(effect, AllocationEffect::ZeroFilled);
        let mut buf = [0u8; 9];
        ok(w.read_at(0, &mut buf), "read head");
        assert_eq!(
            &buf, b"PRESERVED",
            "existing bytes must not be overwritten by the zero fill"
        );
        let mut rest = vec![1u8; 64 * 1024 - 9];
        ok(w.read_at(9, &mut rest), "read rest");
        assert!(rest.iter().all(|&b| b == 0));
    }
}
