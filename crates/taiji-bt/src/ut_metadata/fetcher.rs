//! Requester driver: piece request scheduling, data assembly, infohash
//! verification.
//!
//! Mirrors the reference:
//! - piece count = `metadata_size` rounded up to 16KiB units
//!   (`BtConstants.h`);
//! - request scheduling = `UTMetadataRequestFactory.cc` (fill missing
//!   pieces within the avail() budget + `tracker.add`; aria2 leaves the
//!   missing-piece selection order unspecified — this implementation picks
//!   the ascending minimum);
//! - data handling = `UTMetadataDataExtensionMessage.cc`: untracked ->
//!   ignore; tracked -> remove from the bookkeeping + store the piece;
//!   complete -> assemble + SHA-1 vs infohash; mismatch -> **reset all
//!   pieces** + explicit error;
//! - reject handling = `UTMetadataRejectExtensionMessage.cc`: an
//!   unconditional disconnect-level error ("peer didn't offer metadata").
//!
//! Resource limits: the metadata_size acceptance domain is
//! `0 < size <= 8MiB` (aria2 `HandshakeExtensionMessage.cc` — beyond that
//! it silently does not enable metadata mode; this implementation errors
//! explicitly for the caller to handle equivalently); the piece-count bound
//! of 8MiB / 16KiB = 512 follows.

use bytes::Bytes;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::time::Instant;
use thiserror::Error;

use crate::ut_metadata::METADATA_PIECE_SIZE;
use crate::ut_metadata::tracker::RequestTracker;

/// metadata_size acceptance upper bound of 8MiB (aria2
/// `HandshakeExtensionMessage.cc` "Only accept metadata up to 8MiB in
/// size").
pub const MAX_METADATA_SIZE: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum MetadataError {
    #[error(
        "metadata_size {got} out of range: must be 0 < size <= {max} (HandshakeExtensionMessage.cc)"
    )]
    SizeOutOfRange { got: usize, max: usize },
    #[error("piece index {index} out of range (num_pieces = {num_pieces})")]
    IndexOutOfRange { index: usize, num_pieces: usize },
    #[error("piece {index} length {got} != expected {expected}")]
    PieceLength {
        index: usize,
        got: usize,
        expected: usize,
    },
    #[error(
        "assembled metadata infohash mismatch -> all pieces reset (UTMetadataDataExtensionMessage.cc)"
    )]
    InfoHashMismatch,
    #[error("assembly ledger exhausted: {wanted}B claim denied at {used}/{cap}B global cap ( #4)")]
    AssemblyLedgerExhausted { wanted: usize, used: i64, cap: i64 },
}

/// Process-level assembly byte ledger — a global bound on the bytes of
/// stored pieces across all in-flight [`MetadataAssembler`]s (fetch_add
/// check + rollback, the same pattern as `taiji_io::block_arena`'s
/// claim_budget).
///
/// - The default 16MiB = 2 x [`MAX_METADATA_SIZE`] — the byte form of the
///   spec's "global max 2 concurrent" clamp (more precise than counting
///   connections: residency only grows with pieces actually delivered; a
///   peer lying about a large metadata_size without sending data occupies
///   nothing, since the 8MiB domain clamp already gates
///   `MetadataAssembler::new`).
/// - Rejection semantics = the piece insert fails -> `on_data` reports
///   [`MetadataError::AssemblyLedgerExhausted`] -> session-error
///   disconnect; the magnet orchestration switches peers / retries later
///   (the 20s sweep surface already exists), and the global account refills
///   naturally once Drop/reset releases it.
/// - The normal shape (a single magnet, metadata on the order of <= 2MiB)
///   behaves identically.
pub(crate) struct AssemblyLedger {
    used: std::sync::atomic::AtomicI64,
    cap: i64,
}

impl AssemblyLedger {
    pub(crate) const fn new(cap: i64) -> Self {
        Self {
            used: std::sync::atomic::AtomicI64::new(0),
            cap,
        }
    }

    /// Claim `wanted` bytes; over cap the claim is rolled back and denied
    /// (the Err carries the snapshot at rejection, for observability).
    pub(crate) fn claim(&self, wanted: usize) -> Result<(), (i64, i64)> {
        use std::sync::atomic::Ordering;
        let w = wanted as i64;
        let prev = self.used.fetch_add(w, Ordering::Relaxed);
        if prev + w <= self.cap {
            Ok(())
        } else {
            self.used.fetch_sub(w, Ordering::Relaxed);
            Err((prev + w, self.cap))
        }
    }

    pub(crate) fn release(&self, bytes: usize) {
        use std::sync::atomic::Ordering;
        if bytes > 0 {
            self.used.fetch_sub(bytes as i64, Ordering::Relaxed);
        }
    }

    pub(crate) fn used(&self) -> i64 {
        self.used.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Global assembly ledger (default cap in the [`AssemblyLedger`] docs).
static GLOBAL_ASSEMBLY_LEDGER: AssemblyLedger = AssemblyLedger::new(2 * MAX_METADATA_SIZE as i64);

/// Single-piece delivery outcome on the requester side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataOutcome {
    /// Received but not complete: `remaining` = pieces still missing.
    Stored { remaining: usize },
    /// All pieces in place, assembled, and infohash-verified.
    Complete { metadata: Bytes },
    /// Data for an untracked piece: ignored (aria2 logs it at debug only).
    Untracked,
}

/// Requester errors (including reject's disconnect-level semantics).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum FetchError {
    #[error(
        "peer rejected metadata request -> drop connection (UTMetadataRejectExtensionMessage.cc)"
    )]
    Rejected,
    #[error(transparent)]
    Metadata(#[from] MetadataError),
}

/// Assembler: collects 16KiB pieces by index; the final piece is the
/// remainder.
// Deliberately no Clone — Drop releases the global assembly ledger, and a
// clone would double-release (stored_bytes copied x2 with two Drops = a
// latent negative-account bypass of the 16MiB cap; the only production
// holder MetadataFetchSession has no clone surface — defensively
// forbidden).
#[derive(Debug, PartialEq, Eq)]
pub struct MetadataAssembler {
    total_size: usize,
    num_pieces: usize,
    pieces: Vec<Option<Bytes>>,
    /// Stored piece bytes (= the global ledger usage; released on
    /// Drop/reset — see the [`AssemblyLedger`] docs).
    stored_bytes: usize,
}

impl Drop for MetadataAssembler {
    fn drop(&mut self) {
        GLOBAL_ASSEMBLY_LEDGER.release(self.stored_bytes);
        self.stored_bytes = 0;
    }
}

/// Global assembly ledger usage snapshot (observability/test surface).
pub fn assembly_ledger_used() -> i64 {
    GLOBAL_ASSEMBLY_LEDGER.used()
}

/// Piece count = size / 16KiB rounded up (the piece space of
/// `UTMetadataRequestFactory`; aria2 derives it from `metadataSize` with
/// the same formula).
pub fn piece_count(total_size: usize) -> usize {
    total_size.div_ceil(METADATA_PIECE_SIZE)
}

impl MetadataAssembler {
    pub fn new(total_size: usize) -> Result<Self, MetadataError> {
        if total_size == 0 || total_size > MAX_METADATA_SIZE {
            return Err(MetadataError::SizeOutOfRange {
                got: total_size,
                max: MAX_METADATA_SIZE,
            });
        }
        let num_pieces = piece_count(total_size);
        Ok(MetadataAssembler {
            total_size,
            num_pieces,
            pieces: vec![None; num_pieces],
            stored_bytes: 0,
        })
    }

    pub fn total_size(&self) -> usize {
        self.total_size
    }

    pub fn num_pieces(&self) -> usize {
        self.num_pieces
    }

    /// Canonical length of `index`'s piece (non-final pieces 16KiB, final
    /// piece the remainder, >= 1).
    fn piece_len(&self, index: usize) -> Option<usize> {
        if index >= self.num_pieces {
            return None;
        }
        let begin = index * METADATA_PIECE_SIZE;
        Some((begin + METADATA_PIECE_SIZE).min(self.total_size) - begin)
    }

    /// Write one piece (length precheck — see the module-docs divergence).
    /// Rewriting the same index: aria2's `completePiece` is idempotent, so
    /// overwriting is allowed here (identical content makes no difference;
    /// divergent content is ultimately caught by the infohash; overwriting
    /// does not double-charge the ledger — the expected length for the same
    /// index is constant). Newly occupied bytes are first claimed from the
    /// global ledger: over cap -> rejection with zero storage (session-error
    /// disconnect; the orchestration switches peers and retries).
    pub fn insert(&mut self, index: usize, data: &[u8]) -> Result<(), MetadataError> {
        let Some(expected) = self.piece_len(index) else {
            return Err(MetadataError::IndexOutOfRange {
                index,
                num_pieces: self.num_pieces,
            });
        };
        if data.len() != expected {
            return Err(MetadataError::PieceLength {
                index,
                got: data.len(),
                expected,
            });
        }
        if self.pieces[index].is_none() {
            if let Err((used, cap)) = GLOBAL_ASSEMBLY_LEDGER.claim(expected) {
                return Err(MetadataError::AssemblyLedgerExhausted {
                    wanted: expected,
                    used,
                    cap,
                });
            }
            self.stored_bytes += expected;
        }
        self.pieces[index] = Some(Bytes::copy_from_slice(data));
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.pieces.iter().all(Option::is_some)
    }

    /// When all pieces are in place, concatenate the raw info-dict bytes in
    /// index order (hashing the raw slice — the concatenation IS the raw
    /// bytes, no re-encode); returns None while incomplete.
    pub fn assemble(&self) -> Option<Bytes> {
        let mut out = Vec::with_capacity(self.total_size);
        for piece in &self.pieces {
            out.extend_from_slice(piece.as_ref()?);
        }
        Some(Bytes::from(out))
    }

    /// Reset all pieces (aria2's whole-file markPieceMissing — after an
    /// infohash failure the fetch can restart from another peer). The
    /// global ledger is released in step.
    pub fn reset(&mut self) {
        GLOBAL_ASSEMBLY_LEDGER.release(self.stored_bytes);
        self.stored_bytes = 0;
        self.pieces.iter_mut().for_each(|p| *p = None);
    }

    /// Missing pieces (ascending).
    pub fn missing_indices(&self) -> Vec<usize> {
        self.pieces
            .iter()
            .enumerate()
            .filter(|(_, p)| p.is_none())
            .map(|(i, _)| i)
            .collect()
    }
}

/// Infohash verification: SHA-1(assembled metadata) == expected value
/// (same as `UTMetadataDataExtensionMessage.cc`).
pub fn verify_infohash(metadata: &[u8], expected: &[u8; 20]) -> Result<(), MetadataError> {
    let mut hasher = Sha1::new();
    hasher.update(metadata);
    let got: [u8; 20] = {
        let out = hasher.finalize();
        let mut t = [0u8; 20];
        t.copy_from_slice(&out);
        t
    };
    if &got == expected {
        Ok(())
    } else {
        Err(MetadataError::InfoHashMismatch)
    }
}

/// Expected identity (extension: the V2 verification surface of btmh
/// magnets; V1 = the original BEP9 semantics).
#[derive(Debug, Clone, PartialEq, Eq)]
enum ExpectedIdentity {
    /// SHA-1(assembled) == btih (`UTMetadataDataExtensionMessage.cc`).
    V1([u8; 20]),
    /// SHA-256(assembled) == btmh (BEP52 multihash 1220; aria2 has no btmh
    /// magnet path — SHA-256 over the raw info bytes compared against
    /// btmh, the same shape as V1).
    V2([u8; 32]),
}

impl ExpectedIdentity {
    fn verify(&self, metadata: &[u8]) -> bool {
        match self {
            ExpectedIdentity::V1(expect) => {
                let got: [u8; 20] = Sha1::digest(metadata).into();
                got == *expect
            }
            ExpectedIdentity::V2(expect) => {
                let got: [u8; 32] = Sha256::digest(metadata).into();
                got == *expect
            }
        }
    }
}

/// Requester driver: assembler + tracker + expected infohash.
// Deliberately no Clone (embeds a MetadataAssembler; same Drop ledger
// discipline).
#[derive(Debug)]
pub struct MetadataFetcher {
    tracker: RequestTracker,
    assembler: MetadataAssembler,
    expected: ExpectedIdentity,
}

impl MetadataFetcher {
    /// `metadata_size` comes from the peer's ext handshake (already
    /// validated against the 8MiB domain); the expected infohash comes
    /// from the magnet/task metadata.
    pub fn new(metadata_size: usize, expected_infohash: [u8; 20]) -> Result<Self, MetadataError> {
        Self::with_identity(metadata_size, ExpectedIdentity::V1(expected_infohash))
    }

    /// V2 (btmh) expected identity (see [`ExpectedIdentity::V2`]).
    pub fn new_v2(
        metadata_size: usize,
        expected_infohash: [u8; 32],
    ) -> Result<Self, MetadataError> {
        Self::with_identity(metadata_size, ExpectedIdentity::V2(expected_infohash))
    }

    fn with_identity(
        metadata_size: usize,
        expected: ExpectedIdentity,
    ) -> Result<Self, MetadataError> {
        Ok(MetadataFetcher {
            tracker: RequestTracker::new(),
            assembler: MetadataAssembler::new(metadata_size)?,
            expected,
        })
    }

    pub fn metadata_size(&self) -> usize {
        self.assembler.total_size()
    }

    pub fn num_pieces(&self) -> usize {
        self.assembler.num_pieces()
    }

    /// Snapshot of in-flight indices.
    pub fn tracked_indices(&self) -> Vec<usize> {
        self.tracker.all_tracked_indices()
    }

    /// Fill requests (mirrors `UTMetadataRequestFactory.cc`): within the
    /// avail() budget (= 1), take the ascending-minimum piece that is
    /// missing and not in flight, record the bookkeeping, and return it.
    /// Budget taken / nothing missing -> an empty vector.
    pub fn next_requests(&mut self, now: Instant, max: usize) -> Vec<usize> {
        let mut out = Vec::new();
        while out.len() < max {
            if self.tracker.avail() == 0 {
                break;
            }
            let Some(index) = self
                .assembler
                .missing_indices()
                .into_iter()
                .find(|i| !self.tracker.tracks(*i))
            else {
                break;
            };
            self.tracker.add(index, now);
            out.push(index);
        }
        out
    }

    /// Timeout sweep, returning timed-out indices (ready to redispatch).
    pub fn sweep_timeouts(&mut self, now: Instant) -> Vec<usize> {
        self.tracker.remove_timeout_entries(now)
    }

    /// data(1) delivery (mirrors `UTMetadataDataExtensionMessage.cc` +
    /// the length precheck tightening, module-docs divergence 1).
    pub fn on_data(
        &mut self,
        index: usize,
        data: &[u8],
        _now: Instant,
    ) -> Result<DataOutcome, FetchError> {
        if !self.tracker.tracks(index) {
            // reference: untracked data is only logged, then ignored.
            return Ok(DataOutcome::Untracked);
        }
        self.tracker.remove(index);
        self.assembler.insert(index, data)?;
        let Some(metadata) = self.assembler.assemble() else {
            return Ok(DataOutcome::Stored {
                remaining: self.assembler.missing_indices().len(),
            });
        };
        if self.expected.verify(&metadata) {
            Ok(DataOutcome::Complete { metadata })
        } else {
            // reference: markPieceMissing over all pieces (the fetch can
            // restart from another peer); then an explicit error
            // (disconnect).
            self.assembler.reset();
            Err(FetchError::Metadata(MetadataError::InfoHashMismatch))
        }
    }

    /// reject(2) delivery (mirrors `UTMetadataRejectExtensionMessage.cc`):
    /// an unconditional disconnect-level error.
    pub fn on_reject(&mut self, _index: usize) -> Result<(), FetchError> {
        Err(FetchError::Rejected)
    }
}
