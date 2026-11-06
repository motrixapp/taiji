//! Piece bitmap: a fixed-size bit set packed into `Vec<u64>` words.
//!
//! Two consumers:
//! - [`crate::faces::FaceState::peer_avail`], the per-peer advertised
//! rows (`HashMap<u64, PieceBitmap>`). Packed words cost
//! `ceil(N/64) x 8` bytes per row versus `Vec<bool>`'s `N` bytes per
//! row (100k pieces x 500 peers: 6.25MB vs 50MB); holder counts and
//! interesting checks read bit words instead of per-bit bools, and a
//! bitfield advert needs no N-byte expansion clone.
//! - [`crate::faces::FaceState::written_bits`], the on-disk gating
//! bitmap, shared across tasks via `Arc` - the main loop writes,
//! peer tasks read lock-free; the `AtomicU64` words exist for that
//! contract. `peer_avail` is single-writer main-loop bookkeeping,
//! where Relaxed atomics order like plain reads anyway.
//!
//! # Bit order (pinned)
//!
//! Internal index = piece number, LSB-indexed: piece i is bit `i%64` of
//! `words[i/64]` (mask `1 << (i%64)`). Wire packed bitmaps are MSB-first
//! (BEP3: the first byte's high bit = piece 0); conversions happen only
//! at the [`PieceBitmap::or_from_packed_msb`] /
//! [`PieceBitmap::to_packed_msb`] boundaries. Every internal consumer
//! (selection, dispatch, holder counts, stat closures) reads bits by
//! index and never sees wire bit order.
//!
//! # Tail-bit invariant
//!
//! Padding bits past `len` stay zero: `set`/`clear` are bounded by
//! `len`, and [`PieceBitmap::ones`] masks the tail word - so
//! `count_ones`, `is_full`, and word-wise comparison need no second
//! masking pass.

use std::sync::atomic::{AtomicU64, Ordering};

/// Fixed-size bit-packed bitmap (grown from upload.rs's written bitmap
/// into the shared row type for peer_avail, now living here; structure
/// in the module docs).
///
/// Memory accounting (parsed terms; test anchor
/// [`Self::memory_footprint_accounting`]): `ceil(len/64) x 8` bytes per
/// row vs the old `Vec<bool>` at `len` bytes per row.
#[derive(Debug)]
pub(super) struct PieceBitmap {
    words: Vec<AtomicU64>,
    len: usize,
}

impl Clone for PieceBitmap {
    /// Bitmap clone (the diff base stashed on write in
    /// note_peer_bitfield): O(words) word copy - the bit-packed
    /// replacement for cloning a whole `Vec<bool>` row byte by byte.
    fn clone(&self) -> Self {
        PieceBitmap {
            words: self
                .words
                .iter()
                .map(|w| AtomicU64::new(w.load(Ordering::Relaxed)))
                .collect(),
            len: self.len,
        }
    }
}

/// Test assertion face (a read-only iteration bridge beside the old
/// `Vec<bool>` assertions): word-for-word equality <=> same bits, same
/// length - the tail-bit invariant keeps padding bits out.
impl PartialEq for PieceBitmap {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len
            && self
                .words
                .iter()
                .zip(other.words.iter())
                .all(|(a, b)| a.load(Ordering::Relaxed) == b.load(Ordering::Relaxed))
    }
}

impl PieceBitmap {
    /// All-zero bitmap (`bits` bits; the written_bits constructor name kept).
    pub(super) fn new(bits: usize) -> PieceBitmap {
        PieceBitmap {
            words: (0..bits.div_ceil(64)).map(|_| AtomicU64::new(0)).collect(),
            len: bits,
        }
    }

    /// All-ones bitmap (synthesized HaveAll row; the masked tail word
    /// keeps the tail-bit invariant).
    pub(super) fn ones(bits: usize) -> PieceBitmap {
        let row = PieceBitmap::new(bits);
        let (full_words, tail) = (bits / 64, bits % 64);
        for w in row.words.iter().take(full_words) {
            w.store(u64::MAX, Ordering::Relaxed);
        }
        if tail > 0 {
            if let Some(w) = row.words.get(full_words) {
                w.store((1u64 << tail) - 1, Ordering::Relaxed);
            }
        }
        row
    }

    /// Number of valid bits (= the row's piece count).
    pub(super) fn len(&self) -> usize {
        self.len
    }

    /// Read one bit (out of range = false).
    pub(super) fn get(&self, bit: usize) -> bool {
        bit < self.len
            && self
                .words
                .get(bit / 64)
                .is_some_and(|w| w.load(Ordering::Relaxed) & (1u64 << (bit % 64)) != 0)
    }

    /// Set a bit and return the OLD value (false = was 0; out of range
    /// sets nothing and returns false - the HAVE idempotence check
    /// rests on this one atomic read-modify-write).
    pub(super) fn set(&self, bit: usize) -> bool {
        match self.words.get(bit / 64) {
            Some(w) if bit < self.len => {
                let mask = 1u64 << (bit % 64);
                w.fetch_or(mask, Ordering::Relaxed) & mask != 0
            }
            _ => false,
        }
    }

    /// Clear a bit and return the old value (out of range: no-op,
    /// false). No production path clears single bits (row shrink
    /// replaces the whole row / takes a difference); consumed by the
    /// set-difference tests.
    #[cfg(test)]
    pub(super) fn clear(&self, bit: usize) -> bool {
        match self.words.get(bit / 64) {
            Some(w) if bit < self.len => {
                let mask = 1u64 << (bit % 64);
                w.fetch_and(!mask, Ordering::Relaxed) & mask != 0
            }
            _ => false,
        }
    }

    /// Set-bit count (popcount; the tail-bit invariant keeps padding bits out).
    pub(super) fn count_ones(&self) -> usize {
        self.words
            .iter()
            .map(|w| w.load(Ordering::Relaxed).count_ones() as usize)
            .sum()
    }

    /// All-ones test (= the old `iter().all(|&b| b)`: an empty bitmap
    /// is vacuously true - production rows always have n >= 1).
    /// Equivalent to `count_ones() == len` via per-word popcount,
    /// O(N/64) rather than per-bit.
    pub(super) fn is_full(&self) -> bool {
        self.count_ones() == self.len
    }

    /// Iterate set piece numbers (ascending): word scan +
    /// `trailing_zeros` extraction (Kernighan clear-lowest-bit), not
    /// per-bit probing.
    pub(super) fn iter_ones(&self) -> impl Iterator<Item = usize> + '_ {
        self.words
            .iter()
            .enumerate()
            .flat_map(|(wi, w)| {
                let mut word = w.load(Ordering::Relaxed);
                std::iter::from_fn(move || {
                    let b = word.trailing_zeros();
                    if b == 64 {
                        return None;
                    }
                    word &= word - 1;
                    Some(wi * 64 + b as usize)
                })
            })
            .take_while(|&i| i < self.len)
    }

    /// In-place set difference: `self &= !other` (word fetch_and,
    /// O(words)). Production row shrink replaces the whole row
    /// (HaveNone / peer leave); consumed by the set-difference tests.
    #[cfg(test)]
    pub(super) fn and_not(&self, other: &PieceBitmap) {
        for (w, o) in self.words.iter().zip(other.words.iter()) {
            w.fetch_and(!o.load(Ordering::Relaxed), Ordering::Relaxed);
        }
    }

    /// Merge wire packed bits (MSB order, BEP3), set-only: bit i is bit
    /// `0x80 >> (i%8)` of `bytes[i/8]`; window =
    /// min(len, bytes.len() x 8), past it untouched (trailing bits
    /// ignored + set-only merge - the note_peer_bitfield wire boundary,
    /// equal to the old per-bit `if bit(i) { entry[i] = true }`).
    pub(super) fn or_from_packed_msb(&self, bytes: &[u8]) {
        for i in 0..self.len.min(bytes.len().saturating_mul(8)) {
            if bytes[i / 8] & (0x80 >> (i % 8)) != 0 {
                self.set(i);
            }
        }
    }

    /// Row -> wire packed (MSB order, tail pad bits zero; BEP3).
    /// Reverse-direct word copy: `u64::reverse_bits` then byte-reversed
    /// little-endian yields each byte as 8 consecutive pieces packed
    /// MSB-first (no per-bit probing, O(N/8)).
    pub(super) fn to_packed_msb(&self) -> Vec<u8> {
        let mut out = vec![0u8; self.len.div_ceil(8)];
        for (wi, w) in self.words.iter().enumerate() {
            let mut bytes = w.load(Ordering::Relaxed).reverse_bits().to_le_bytes();
            bytes.reverse();
            let base = wi * 8;
            for (m, &b) in bytes.iter().enumerate() {
                if base + m < out.len() {
                    out[base + m] = b;
                }
            }
        }
        out
    }

    /// Wire packed (MSB) -> new row (full parse form; production
    /// bitfields merge into an existing row via
    /// [`Self::or_from_packed_msb`]; this constructor is the MSB
    /// boundary's round-trip test face).
    #[cfg(test)]
    pub(super) fn from_packed_msb(bytes: &[u8], bits: usize) -> PieceBitmap {
        let row = PieceBitmap::new(bits);
        row.or_from_packed_msb(bytes);
        row
    }

    /// Read-only iteration bridge (test assertion adapter: a row view
    /// for the old `Vec<bool>` assertions).
    #[cfg(test)]
    pub(super) fn to_bools(&self) -> Vec<bool> {
        (0..self.len).map(|i| self.get(i)).collect()
    }

    /// bool slice -> row (test constructor bridge).
    #[cfg(test)]
    pub(super) fn from_bools(bits: &[bool]) -> PieceBitmap {
        let row = PieceBitmap::new(bits.len());
        for (i, &b) in bits.iter().enumerate() {
            if b {
                row.set(i);
            }
        }
        row
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Basics: construction / len / get / set / clear / out-of-range
    /// defense (0 pieces, and out of range within the tail word).
    #[test]
    fn zeros_ones_get_set_clear_basics() {
        // 0 pieces: every read false, every write a no-op, count 0,
        // is_full vacuously true.
        let empty = PieceBitmap::new(0);
        assert_eq!(empty.len(), 0);
        assert!(!empty.get(0));
        assert!(!empty.set(0));
        assert_eq!(empty.count_ones(), 0);
        assert!(
            empty.is_full(),
            "empty bitmap vacuously full (same verdict as the old iter().all)"
        );
        assert_eq!(empty.to_packed_msb(), Vec::<u8>::new());

        // 100 pieces (36-bit tail in the last word): set/clear round
        // trip; out of range within the tail word does not set.
        let row = PieceBitmap::new(100);
        assert_eq!(row.len(), 100);
        assert!(!row.get(99));
        assert!(!row.set(99), "set returns the old value false");
        assert!(row.get(99));
        assert!(
            row.set(99),
            "repeated set returns the old value true (HAVE idempotence)"
        );
        assert!(row.clear(99));
        assert!(!row.get(99));
        assert!(!row.clear(99), "repeated clear returns the old value false");
        // Out of range (inside the tail word): no set, get false, count unpolluted.
        assert!(!row.set(100), "beyond len: not set (tail-bit invariant)");
        assert!(!row.get(100));
        assert!(!row.set(10_000), "beyond the words: not set");
        assert_eq!(row.count_ones(), 0);

        // ones: all ones + tail mask (count = len, is_full).
        let full = PieceBitmap::ones(100);
        assert_eq!(full.count_ones(), 100);
        assert!(full.is_full());
        assert!(full.get(0) && full.get(63) && full.get(64) && full.get(99));
        assert!(!full.get(100), "padding bits never read out past len");
        let full8 = PieceBitmap::ones(8);
        assert_eq!(full8.count_ones(), 8);
        assert!(full8.is_full());
    }

    /// iter_ones: full ascending enumeration + per-bit cross-check
    /// against get (word crossings and tail truncation included).
    #[test]
    fn iter_ones_enumerates_ascending() {
        let row = PieceBitmap::new(130); // 2 full words + a 2-bit tail word
        for i in [0usize, 1, 63, 64, 65, 127, 128, 129] {
            row.set(i);
        }
        assert_eq!(
            row.iter_ones().collect::<Vec<_>>(),
            vec![0, 1, 63, 64, 65, 127, 128, 129]
        );
        // Cross-check: iter_ones <=> per-bit get.
        let mut expect = Vec::new();
        for i in 0..row.len() {
            if row.get(i) {
                expect.push(i);
            }
        }
        assert_eq!(row.iter_ones().collect::<Vec<_>>(), expect);
        // Sparse and dense boundaries: all zero / all ones.
        assert_eq!(PieceBitmap::new(64).iter_ones().count(), 0);
        assert_eq!(PieceBitmap::ones(64).iter_ones().count(), 64);
    }

    /// count_ones: popcount summed across words (non-whole tail word included).
    #[test]
    fn count_ones_across_words() {
        let row = PieceBitmap::ones(100);
        for i in [0usize, 63, 64, 99] {
            row.clear(i);
        }
        assert_eq!(row.count_ones(), 96);
        assert!(!row.is_full());
    }

    /// and_not: in-place set difference (self AND NOT other), across
    /// words and in the tail word.
    #[test]
    fn and_not_clears_intersection() {
        let a = PieceBitmap::ones(100);
        let b = PieceBitmap::new(100);
        for i in [1usize, 64, 99] {
            b.set(i);
        }
        a.and_not(&b);
        assert_eq!(a.count_ones(), 97);
        for i in [1usize, 64, 99] {
            assert!(!a.get(i));
        }
        assert!(a.get(0) && a.get(98));
        // Self difference = all cleared.
        let c = PieceBitmap::from_bools(&[true, false, true, true]);
        c.and_not(&c);
        assert_eq!(c.count_ones(), 0);
    }

    /// MSB boundary (BEP3): non-byte-aligned piece counts / non-word
    /// piece counts / trailing pad bits ignored / a 100k-piece round
    /// trip - the packed first byte's high bit = piece 0.
    #[test]
    fn packed_msb_boundaries_and_roundtrip() {
        // 0 pieces: empty packed.
        assert_eq!(PieceBitmap::new(0).to_packed_msb(), Vec::<u8>::new());
        // Non-byte-aligned (12 pieces): piece 0 -> the first byte's MSB;
        // pieces 8..12 -> the second byte's high 4 bits; the trailing 4
        // bits stay zero.
        let row = PieceBitmap::from_packed_msb(&[0b1010_0000, 0b0000_1111], 12);
        assert!(row.get(0) && row.get(2));
        assert!(!row.get(1) && !row.get(3) && !row.get(7));
        // pieces 8..11 = the second byte 0b0000_1111's MSB-first four
        // bits 0,0,0,0 -> all 0.
        assert!(!(row.get(8) || row.get(9) || row.get(10) || row.get(11)));
        assert_eq!(row.to_packed_msb(), vec![0b1010_0000, 0b0000_0000]);
        // Counter-case: pieces 8..11 set (second byte 0b1111_0000).
        let row2 = PieceBitmap::from_packed_msb(&[0b0000_0000, 0b1111_0000], 12);
        assert!(row2.get(8) && row2.get(11));
        assert_eq!(row2.to_packed_msb(), vec![0b0000_0000, 0b1111_0000]);

        // Non-whole word (100 pieces = 1.25 words -> 13 packed bytes):
        // round trip + cross-check against the per-bit MSB reference.
        let row3 = PieceBitmap::new(100);
        for i in [0usize, 7, 8, 63, 64, 71, 99] {
            row3.set(i);
        }
        let packed = row3.to_packed_msb();
        assert_eq!(packed.len(), 13, "ceil(100/8) bytes");
        let mut reference = vec![0u8; 13];
        for i in 0..100 {
            if row3.get(i) {
                reference[i / 8] |= 0x80 >> (i % 8);
            }
        }
        assert_eq!(
            packed, reference,
            "word-reverse direct copy == per-bit MSB reference"
        );
        let back = PieceBitmap::from_packed_msb(&packed, 100);
        assert_eq!(back, row3, "packed -> row round trip is lossless");

        // 100k pieces (pattern bits) round trip + reference cross-check
        // (scale anchor: a 16-bit tail).
        let n = 100_000usize;
        let big = PieceBitmap::new(n);
        let mut expect_count = 0usize;
        for i in 0..n {
            if i % 7 == 0 || i % 11 == 0 {
                big.set(i);
                expect_count += 1;
            }
        }
        assert_eq!(big.count_ones(), expect_count);
        let packed_big = big.to_packed_msb();
        assert_eq!(packed_big.len(), n.div_ceil(8));
        let mut reference_big = vec![0u8; n.div_ceil(8)];
        for i in 0..n {
            if big.get(i) {
                reference_big[i / 8] |= 0x80 >> (i % 8);
            }
        }
        assert_eq!(packed_big, reference_big);
        assert_eq!(PieceBitmap::from_packed_msb(&packed_big, n), big);

        // or_from_packed is set-only: existing bits are not cleared by packed zero bits.
        let merged = PieceBitmap::from_bools(&[true, true, false]);
        merged.or_from_packed_msb(&[0b0100_0000]); // piece 1
        assert_eq!(merged.to_bools(), vec![true, true, false], "set-only merge");
        // Window truncation: packed bits past len are ignored.
        let short = PieceBitmap::new(3);
        short.or_from_packed_msb(&[0b1111_1111, 0b1111_1111]);
        assert_eq!(short.count_ones(), 3, "bits beyond len ignored");
    }

    /// Clone independence: later sets on the original do not leak into
    /// the clone (the write-time diff-base premise).
    #[test]
    fn clone_is_independent() {
        let row = PieceBitmap::new(64);
        row.set(5);
        let snapshot = row.clone();
        row.set(6);
        assert!(snapshot.get(5));
        assert!(
            !snapshot.get(6),
            "clone unaffected by later writes to the original row"
        );
        assert_eq!(snapshot.len(), 64);
    }

    /// Struct byte accounting (the memory test anchor): N pieces x P
    /// rows of bitmap memory = ceil(N/64) x 8 x P, vs N x P for the old
    /// `Vec<bool>` (1 B/piece/row) - N=100k, P=500: 6,252,000 B vs
    /// 50,000,000 B (spec terms "50MB -> 6.25MB"). Same accounting as
    /// the parsed terms (words.len() x 8, excluding HashMap slack).
    #[test]
    fn memory_footprint_accounting() {
        const N: usize = 100_000;
        const P: usize = 500;
        let rows: Vec<PieceBitmap> = (0..P).map(|_| PieceBitmap::ones(N)).collect();
        let bytes: usize = rows.iter().map(|r| r.words.len() * 8).sum();
        assert_eq!(
            N.div_ceil(64),
            1563,
            "100k pieces = ceil(100000/64) = 1563 words"
        );
        assert_eq!(
            bytes,
            N.div_ceil(64) * 8 * P,
            "formula anchor: ceil(N/64) x 8 x P"
        );
        assert_eq!(bytes, 6_252_000, "6.25MB semantics");
        let legacy = N * P;
        assert_eq!(legacy, 50_000_000, "old Vec<bool> = 50MB semantics");
        assert_eq!(bytes * 1000 / legacy, 125, "compression ~12.5% (-87.5%)");
    }
}
