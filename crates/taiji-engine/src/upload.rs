//! The upload serving face (the upload side of tit-for-tat): the
//! download-phase partial source (`PartialFaceSource`, rejecting pieces
//! not yet written to disk) and the 30s download-byte window
//! (`RateWindow`, a leecher sort-key input).
//!
//! Owns: the read face serving only bytes already on disk (verify+write
//! double-confirmed) and the rate observation window.
//! Does not own: choke decisions (choke) and the disk-write face
//! (pipeline).
//!
//! note: the written-gating bitmap `PieceBitmap` (originally defined
//! here) moved to `crate::bitmap` when the peer_avail rows became
//! bitmaps (single source for the shared structure).
//!
//! Upstream anchor mapping: docs/design/engine.md

use std::sync::Arc;

use taiji_bt::peer::PieceSource;
use taiji_store::torrent_writer::TorrentReader;

use crate::bitmap::PieceBitmap;

/// Download-phase upload serving source: disk reads gated by the
/// **written bitmap** — only bytes this side has already written to
/// disk (verify+write double-confirmed) are served (the upload face of
/// BEP3 tit-for-tat; an unwritten piece -> Err -> reject, so sparse
/// zero data or a piece still mid-write is never served as progress).
/// note: this gate no longer consults hash-pass (the advertise face
/// moved earlier, to hash-pass, with [`Progress::PieceVerified`] —
/// libtorrent RC_2_1 `7f691246a` passed->have); it consults written
/// only: the local read path reads disk directly through TorrentReader,
/// and a verified-but-unwritten piece's bytes are still in the write
/// cache / mid-write, so a read would return sparse zero data.
/// Addressing and pad zero-fill are TorrentReader's job (same as
/// [`FaceSource`], BEP47).
pub(super) struct PartialFaceSource {
    pub(super) reader: TorrentReader,
    pub(super) goffs: Arc<Vec<u64>>,
    pub(super) written: Arc<PieceBitmap>,
}

impl PieceSource for PartialFaceSource {
    fn read_block(&self, index: u32, begin: u32, buf: &mut [u8]) -> Result<usize, String> {
        if !self.written.get(index as usize) {
            return Err(format!("piece {index} not written yet"));
        }
        let goff = self
            .goffs
            .get(index as usize)
            .ok_or_else(|| format!("wire index {index} outside face goff table"))?;
        self.reader
            .read_at(goff + u64::from(begin), buf)
            .map_err(|e| e.to_string())
    }

    fn total_len(&self) -> u64 {
        self.reader.layout().total()
    }
}

/// 30s download-byte window: a 1s tick feeds increments and `rate`
/// feeds the leecher sort key (B/s; before the window fills, averaged
/// over the buckets fed so far).
pub(super) struct RateWindow {
    pub(super) buckets: Vec<u64>,
    pub(super) cursor: usize,
    pub(super) fed: usize,
}

impl RateWindow {
    pub(super) const WINDOW_SECS: usize = 30;

    pub(super) fn new() -> RateWindow {
        RateWindow {
            buckets: vec![0; Self::WINDOW_SECS],
            cursor: 0,
            fed: 0,
        }
    }

    pub(super) fn add(&mut self, delta: u64) {
        self.buckets[self.cursor] = self.buckets[self.cursor].saturating_add(delta);
    }

    /// Advance one slot per 1s tick: the old bucket clears, the new
    /// second starts counting.
    pub(super) fn advance(&mut self) {
        self.cursor = (self.cursor + 1) % Self::WINDOW_SECS;
        self.buckets[self.cursor] = 0;
        self.fed = (self.fed + 1).min(Self::WINDOW_SECS);
    }

    pub(super) fn rate(&self) -> f64 {
        let sum: u64 = self.buckets.iter().sum();
        if self.fed == 0 {
            return 0.0;
        }
        sum as f64 / self.fed as f64
    }
}
