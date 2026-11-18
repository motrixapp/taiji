//! Null disk backend: writes are discarded, reads return
//! deterministic filler (the no-IO baseline for benchmarking and
//! testing).
//!
//! Upstream anchor: libtorrent's `disabled_disk_io_constructor`
//! (`include/libtorrent/session_params.hpp`, self-described as
//! "Throws away all data and reads garbage. Useful for testing and
//! benchmarking"). The taiji form slots behind the same
//! [`DiskWriter`](crate::disk::DiskWriter) abstraction as the real
//! file backend, so throughput runs and e2e smokes can execute the
//! whole network/download path with the disk decoupled: whatever the
//! numbers then show is the network+pipeline cost, not the disk's.
//!
//! Semantics per face:
//! - `write_at` / `write_vectored_at` succeed without storing;
//! - `read_at` / `read_at_volatile` fill the buffer with a
//!   deterministic position-derived pattern (byte at absolute offset
//!   `p` = `(p & 0xff)`) — same bytes for every reader of the same
//!   offset, so re-reads are reproducible, but the content will
//!   naturally fail any real hash check (that is the point: a null
//!   store never fakes verification);
//! - `truncate` tracks a virtual length (the only state); `size`
//!   reports it; `open`/`create`/`allocate`/`flush_os_buffers`/
//!   `set_bypass_page_cache` are successful no-ops (no path is ever
//!   touched).
//!
//! Feature gate: the `null-store` crate feature (non-default;
//! nothing in any release graph enables it) keeps this face out of
//! release builds — it exists for benches, tests, and stress rigs.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::disk::AllocationEffect;
use crate::disk_policy::AllocationMode;
use crate::error::StoreError;

/// The null disk writer (structure in the module docs). Cheap to
/// construct; no file, no handle, no allocation.
#[derive(Debug, Default)]
pub struct NullDiskWriter {
    /// Virtual file length (set by `truncate`; the only state a
    /// reader can observe via `size`).
    len: AtomicU64,
}

impl NullDiskWriter {
    /// Deterministic filler byte at absolute offset `p`.
    fn filler_byte(p: u64) -> u8 {
        (p & 0xff) as u8
    }
}

impl crate::disk::DiskWriter for NullDiskWriter {
    fn open(&mut self, _path: &Path, _read_only: bool) -> Result<(), StoreError> {
        Ok(())
    }

    fn open_existing(&mut self, _path: &Path, _read_only: bool) -> Result<(), StoreError> {
        // A null store has no files; "existing" is served the same way
        // everything else is — a successful no-op on a virtual void.
        Ok(())
    }

    fn create(&mut self, _path: &Path) -> Result<(), StoreError> {
        Ok(())
    }

    fn truncate(&mut self, len: u64) -> Result<(), StoreError> {
        self.len.store(len, Ordering::Relaxed);
        Ok(())
    }

    fn allocate(
        &mut self,
        _len: u64,
        _mode: AllocationMode,
    ) -> Result<AllocationEffect, StoreError> {
        // Honest reporting: nothing was allocated, the sparse-trunc
        // effect is the truthful description of a length-only claim.
        Ok(AllocationEffect::Truncated { fallback: false })
    }

    fn write_at(&self, _offset: u64, _data: &[u8]) -> Result<(), StoreError> {
        Ok(())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, StoreError> {
        for (i, slot) in buf.iter_mut().enumerate() {
            *slot = Self::filler_byte(offset + i as u64);
        }
        Ok(buf.len())
    }

    fn flush_os_buffers(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn size(&self) -> Result<u64, StoreError> {
        Ok(self.len.load(Ordering::Relaxed))
    }

    fn set_bypass_page_cache(&self) -> Result<(), StoreError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk::DiskWriter as _;

    fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("{what}: {e}"),
        }
    }

    /// Writes are discarded; reads return the deterministic filler;
    /// the virtual length tracks truncate.
    #[test]
    fn writes_discard_reads_deterministic() {
        let mut w = NullDiskWriter::default();
        ok(w.truncate(1 << 20), "truncate");
        assert_eq!(ok(w.size(), "size"), 1 << 20);
        ok(w.write_at(0, b"hello"), "write");
        ok(w.write_at(999_999, b"world"), "write");
        let mut buf = [0u8; 4];
        let n = ok(w.read_at(0x100, &mut buf), "read");
        assert_eq!(n, 4);
        assert_eq!(buf, [0x00, 0x01, 0x02, 0x03]);
        // Deterministic across instances and repeated reads.
        let mut again = [0u8; 4];
        let w2 = NullDiskWriter::default();
        ok(w2.read_at(0x100, &mut again), "read");
        assert_eq!(buf, again);
        // The written bytes did not land.
        let mut probe = [0u8; 5];
        ok(w.read_at(0, &mut probe), "read");
        assert_ne!(&probe, b"hello");
    }

    /// The volatile face inherits byte-identical read semantics (the
    /// default `read_at_volatile` delegates to `read_at`).
    #[test]
    fn volatile_read_matches_plain_read() {
        let w = NullDiskWriter::default();
        let mut a = [0u8; 8];
        let mut b = [0u8; 8];
        ok(w.read_at(7, &mut a), "read_at");
        ok(w.read_at_volatile(7, &mut b), "volatile");
        assert_eq!(a, b);
    }
}
