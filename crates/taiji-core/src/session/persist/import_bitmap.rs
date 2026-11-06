//! piece->block bitmap mapping for the migration importer. A
//! **consumer** of the grid.rs semantics: this module only reads
//! [`taiji_http::grid`]'s block-grid semantics without changing its
//! encoding or verdicts (the frozen seam is the grid.rs module doc).
//!
//! Conversion rules and the golden branches: docs/design/core.md

use taiji_http::grid::{MAX_BLOCK_SIZE, MAX_TOTAL_LEN, MIN_BLOCK_SIZE};

/// Block size for an imported task: the largest power-of-two factor of
/// `piece_length` clamped into the config domain
/// (`clamp(largest pow2 factor of piece_length, 256KiB, 16MiB)`;
/// unsolvable = odd piece (factor 1) and out-of-domain factors all land
/// on the clamp bounds — the same value as "unsolvable takes
/// 256KiB"). `piece_length = 0` has no geometric meaning and lands on
/// the domain floor (the mapping face rejects 0 granularity explicitly
/// on its own; this function stays pure arithmetic).
pub fn block_size_from_piece_length(piece_length: u64) -> u64 {
    let factor = if piece_length == 0 {
        1
    } else {
        1u64 << piece_length.trailing_zeros()
    };
    factor.clamp(MIN_BLOCK_SIZE, MAX_BLOCK_SIZE)
}

/// Bitmap mapping product (same shape as the `http_task` row's three
/// bitmap columns; pure data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedBlockBitmap {
    /// Block size (bytes; a power of two inside the config domain —
    /// grid.rs semantics).
    pub block_size: u64,
    /// Total block count = ceil(total_length / block_size).
    pub block_count: u64,
    /// Block bitmap (LSB-first, bit i = block i; byte count =
    /// ceil(count/8); tail bits beyond block_count are always 0 — the
    /// `http_task.block_bitmap` encoding).
    pub bitmap: Vec<u8>,
    /// Credited byte total (the last block truncates to the total
    /// length — the grid `done_bytes` convention).
    pub done_bytes: u64,
}

/// Invalid bitmap mapping input (prefer missing over wrong: bad
/// progress is never folded into fake blocks — the caller degrades to
/// weak resume and states so in the report).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BitmapMapError {
    /// Piece length is 0 (the fork progress row was tampered with or
    /// corrupted — the reference control file rejects the same way,
    /// "piece length must not be 0", `DefaultBtProgressInfoFile.cc`).
    ZeroPieceLength,
    /// Bitfield length != `expected_bitfield_len(total, piece)` (the
    /// row was tampered with or mixed in from another source — never
    /// map a sick input).
    BitfieldLengthMismatch { expected: u64, actual: u64 },
    /// Total length exceeds the engine's authoritative cap (the same
    /// verdict as the grid constructor; defensive check).
    TotalLengthExceeded { total: u64, max: u64 },
}

impl std::fmt::Display for BitmapMapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BitmapMapError::ZeroPieceLength => write!(f, "piece length must not be 0"),
            BitmapMapError::BitfieldLengthMismatch { expected, actual } => write!(
                f,
                "bitfield length mismatch: expected {expected}, actual {actual}"
            ),
            BitmapMapError::TotalLengthExceeded { total, max } => {
                write!(f, "total length {total} exceeds the engine cap {max}")
            }
        }
    }
}

/// Piece bitmap -> block bitmap mapping (the full-coverage rule).
///
/// Input = the fork's progress facts (MSB-first piece bitmap + piece
/// length + authoritative total length); output = the block-grid
/// candidate payload. Block `b` is credited iff **every** piece
/// intersecting its byte range `[b*B, min((b+1)*B, total))` is complete
/// in the fork bitmap — pieces tile the file contiguously, so "all
/// intersecting pieces complete" <=> "the block is fully covered by
/// completed pieces". A partially covered block (a piece boundary
/// crosses it and one side is incomplete) is not credited; recovery
/// re-downloads its bytes (waste <= 1 block per piece boundary).
pub fn map_pieces_to_blocks(
    piece_bitfield: &[u8],
    piece_length: u64,
    total_length: u64,
) -> Result<MappedBlockBitmap, BitmapMapError> {
    if piece_length == 0 {
        return Err(BitmapMapError::ZeroPieceLength);
    }
    if total_length > MAX_TOTAL_LEN {
        return Err(BitmapMapError::TotalLengthExceeded {
            total: total_length,
            max: MAX_TOTAL_LEN,
        });
    }
    let expected_len = expected_bitfield_len_from_store(total_length, piece_length);
    if piece_bitfield.len() as u64 != expected_len {
        return Err(BitmapMapError::BitfieldLengthMismatch {
            expected: expected_len,
            actual: piece_bitfield.len() as u64,
        });
    }
    let block_size = block_size_from_piece_length(piece_length);
    let block_count = total_length.div_ceil(block_size);
    let mut bitmap = vec![0u8; block_count.div_ceil(8) as usize];
    let mut done_bytes = 0u64;
    for block in 0..block_count {
        let start = block * block_size;
        let end = ((block + 1) * block_size).min(total_length);
        let first_piece = start / piece_length;
        let last_piece = (end - 1) / piece_length;
        let covered = (first_piece..=last_piece).all(|p| piece_done(piece_bitfield, p));
        if covered {
            bitmap[(block / 8) as usize] |= 1 << (block % 8);
            done_bytes += end - start;
        }
    }
    Ok(MappedBlockBitmap {
        block_size,
        block_count,
        bitmap,
        done_bytes,
    })
}

/// The fork bitfield's expected length (a direct translation of the
/// store-side formula `((total + piece - 1) / piece + 7) / 8`,
/// reference `DefaultBtProgressInfoFile.cc`).
fn expected_bitfield_len_from_store(total: u64, piece: u64) -> u64 {
    total.div_ceil(piece).div_ceil(8)
}

/// Whether piece `p` is complete (MSB-first — the fork/aria2
/// BitfieldMan encoding).
fn piece_done(bitfield: &[u8], piece: u64) -> bool {
    bitfield
        .get((piece / 8) as usize)
        .is_some_and(|b| b & (0x80 >> (piece % 8)) != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use taiji_http::grid::{BlockGrid, validate_block_size};

    /// Test-side Result unwrap (lints ban unwrap/expect).
    fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("{what}: {e}"),
        }
    }

    /// MSB-first piece bitmap builder (args = piece count + done set;
    /// byte count = ceil(pieces/8), extended to fit the done set when
    /// a bit lands out of range).
    fn piece_bitmap(num_pieces: u64, done: &[u64]) -> Vec<u8> {
        let bytes = num_pieces
            .div_ceil(8)
            .max(done.iter().max().map_or(0, |m| m / 8 + 1));
        let mut bf = vec![0u8; bytes as usize];
        for p in done {
            bf[(*p / 8) as usize] |= 0x80 >> (*p % 8);
        }
        bf
    }

    /// Consumer-side golden cross-validation: feed the mapped product
    /// into BlockGrid block by block; the bitmap bytes and the credited
    /// byte total must match bit for bit (the consumer-side assertion
    /// of grid.rs semantics).
    fn assert_grid_consumer(mapped: &MappedBlockBitmap, total_length: u64) {
        let mut grid =
            BlockGrid::new(mapped.block_size, total_length).unwrap_or_else(|e| panic!("grid: {e}"));
        for block in 0..mapped.block_count {
            let mapped_set = mapped.bitmap[(block / 8) as usize] & (1 << (block % 8)) != 0;
            if mapped_set {
                let first = grid.record(block).unwrap_or_else(|e| panic!("record: {e}"));
                assert!(
                    first,
                    "block {block}: the first record must be a new completion"
                );
            }
        }
        assert_eq!(
            grid.bitmap(),
            mapped.bitmap,
            "bitmaps match byte for byte (LSB-first)"
        );
        assert_eq!(grid.block_count(), mapped.block_count);
        assert_eq!(
            grid.done_bytes(),
            mapped.done_bytes,
            "completed-byte accumulation agrees"
        );
    }

    /// Branch 1 (power-of-two aligned): piece = block = 1MiB; pieces
    /// 0/1/2/7 done -> blocks 0/1/2/7. Byte-wise golden + consumer
    /// cross-validation.
    #[test]
    fn golden_branch_power_of_two_aligned() {
        let piece = 1024 * 1024u64;
        let total = 10 * piece;
        // pieces 0,1,2,7 done (MSB-first: byte0 = 0b1110_0001).
        let bf = piece_bitmap(10, &[0, 1, 2, 7]);
        assert_eq!(bf[0], 0b1110_0001);
        let mapped = ok(map_pieces_to_blocks(&bf, piece, total), "map aligned");
        assert_eq!(
            mapped.block_size, piece,
            "a power-of-two piece -> block = piece"
        );
        assert_eq!(mapped.block_count, 10);
        assert_eq!(
            mapped.bitmap,
            vec![0b1000_0111, 0b0000_0000],
            "LSB-first golden"
        );
        assert_eq!(mapped.done_bytes, 4 * piece);
        assert_grid_consumer(&mapped, total);
    }

    /// Branch 2 (unaligned, 15MiB piece): block = the largest pow2
    /// factor 1MiB; a piece's blocks are all-or-nothing (15
    /// blocks/piece); the piece boundary 15MiB lands on a block
    /// boundary (15MiB = 15 x 1MiB) — the partial-coverage shape cannot
    /// occur here, but the golden pins the block-by-block expansion.
    #[test]
    fn golden_branch_non_aligned_piece() {
        let piece = 15 * 1024 * 1024u64;
        let total = 45 * 1024 * 1024u64; // 3 pieces
        // pieces 0 and 2 done, piece 1 not.
        let bf = piece_bitmap(3, &[0, 2]);
        assert_eq!(bf, vec![0b1010_0000]);
        let mapped = ok(map_pieces_to_blocks(&bf, piece, total), "map 15M");
        assert_eq!(
            mapped.block_size,
            1024 * 1024,
            "the largest power-of-two factor of 15MiB = 1MiB"
        );
        assert_eq!(mapped.block_count, 45);
        // Blocks 0..15 (piece 0) and 30..45 (piece 2) done; 15..30
        // clear.
        let mut want = vec![0u8; 6]; // ceil(45/8) = 6
        for b in 0..15 {
            want[(b / 8) as usize] |= 1 << (b % 8);
        }
        for b in 30..45 {
            want[(b / 8) as usize] |= 1 << (b % 8);
        }
        assert_eq!(
            mapped.bitmap, want,
            "golden: piece 0/2 fully set, piece 1 fully clear"
        );
        assert_eq!(mapped.done_bytes, 30 * 1024 * 1024);
        assert_grid_consumer(&mapped, total);
    }

    /// Branch 3 (piece < 256KiB): piece = 100KiB (largest pow2 factor
    /// 4KiB -> clamped to 256KiB); blocks span multiple pieces and
    /// **partially covered blocks are dropped** — a block crossed by a
    /// piece boundary with one side incomplete is not credited (the
    /// empirical shape of the waste bound).
    #[test]
    fn golden_branch_piece_below_block_floor() {
        let piece = 100 * 1024u64;
        let total = 1024 * 1024u64; // 1MiB -> 4 blocks; num_pieces = 11
        // Geometry (piece = 100KiB = 102400B): block0=[0,256K)
        // intersects pieces 0..=2 (piece 2 crosses the block boundary);
        // block1=[256K,512K) intersects 2..=5; block2=[512K,768K)
        // intersects 5..=7; block3=[768K,1M) intersects 7..=10.
        // Scenario a: pieces 0 and 1 done, piece 2 not -> block 0
        // partially covered, not credited.
        let bf = piece_bitmap(11, &[0, 1]);
        let mapped = ok(map_pieces_to_blocks(&bf, piece, total), "map sub-floor a");
        assert_eq!(mapped.block_size, 256 * 1024, "clamped to the domain floor");
        assert_eq!(
            mapped.bitmap,
            vec![0b0000_0000],
            "a partially covered block is not recorded"
        );
        assert_eq!(mapped.done_bytes, 0);
        // Scenario b: pieces 0..=3 done -> block 0's required 0..=2 all
        // present, credited; block 1 needs 2..=5 (4 and 5 missing), not
        // credited. A single-byte golden bitmap.
        let bf = piece_bitmap(11, &[0, 1, 2, 3]);
        let mapped = ok(map_pieces_to_blocks(&bf, piece, total), "map sub-floor b");
        assert_eq!(mapped.bitmap, vec![0b0000_0001], "only block 0 is trusted");
        assert_eq!(mapped.done_bytes, 256 * 1024);
        assert_grid_consumer(&mapped, total);
        // Scenario c: all 11 pieces done -> all 4 blocks credited; the
        // last block truncates to the total length.
        let bf = piece_bitmap(11, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let mapped = ok(map_pieces_to_blocks(&bf, piece, total), "map sub-floor c");
        assert_eq!(mapped.bitmap, vec![0b0000_1111]);
        assert_eq!(mapped.done_bytes, total);
        assert_grid_consumer(&mapped, total);
    }

    /// Branch 4 (total not block-aligned): piece = block = 4MiB,
    /// total = 10MiB -> 3 blocks (the last block [8MiB,10MiB) credited
    /// as the 2MiB truncated to the total).
    #[test]
    fn golden_branch_total_not_block_aligned() {
        let piece = 4 * 1024 * 1024u64;
        let total = 10 * 1024 * 1024u64;
        // pieces 0 and 1 done; the last piece 2 not.
        let bf = piece_bitmap(3, &[0, 1]);
        let mapped = ok(map_pieces_to_blocks(&bf, piece, total), "map tail a");
        assert_eq!(mapped.block_size, piece);
        assert_eq!(mapped.block_count, 3, "ceil(10/4) = 3 blocks");
        assert_eq!(mapped.bitmap, vec![0b0000_0011]);
        assert_eq!(mapped.done_bytes, 8 * 1024 * 1024);
        assert_grid_consumer(&mapped, total);
        // Last piece done -> last block credited; credited bytes =
        // 10MiB (the 2MiB actual length convention).
        let bf = piece_bitmap(3, &[0, 1, 2]);
        let mapped = ok(map_pieces_to_blocks(&bf, piece, total), "map tail b");
        assert_eq!(mapped.bitmap, vec![0b0000_0111]);
        assert_eq!(
            mapped.done_bytes, total,
            "the last block is accounted truncated to the total length"
        );
        assert_grid_consumer(&mapped, total);
    }

    /// Block-size derivation table: powers of two pass through /
    /// non-pow2 multiples take the largest pow2 factor / clamping at
    /// both bounds / odd and 0 land on the domain floor; every product
    /// passes the grid config-domain validation.
    #[test]
    fn block_size_derivation_table() {
        let mib = 1024 * 1024u64;
        let cases: [(u64, u64); 9] = [
            (256 * 1024, 256 * 1024),
            (mib, mib),
            (16 * mib, 16 * mib),
            (15 * mib, mib),          // 15MiB -> 1MiB (largest pow2 factor)
            (3 * mib, mib),           // 3MiB -> 1MiB
            (100 * 1024, 256 * 1024), // below the domain floor -> clamped
            (32 * mib, 16 * mib),     // above the domain cap -> clamped
            (1_000_001, 256 * 1024),  // odd (factor 1) -> domain floor
            (0, 256 * 1024),          // no geometric meaning -> domain floor
        ];
        for (piece, want) in cases {
            assert_eq!(
                block_size_from_piece_length(piece),
                want,
                "piece_length {piece}"
            );
            assert!(
                validate_block_size(block_size_from_piece_length(piece)).is_ok(),
                "the derived product must land in the grid configuration domain: piece_length {piece}"
            );
        }
    }

    /// The three invalid-input states: zero granularity / bitfield
    /// length mismatch / total length over the cap — bad progress is
    /// explicitly rejected (the caller degrades to weak resume) and
    /// never folded into fake blocks.
    #[test]
    fn invalid_inputs_rejected_without_mapping() {
        assert_eq!(
            map_pieces_to_blocks(&[0], 0, 1024),
            Err(BitmapMapError::ZeroPieceLength)
        );
        // 10 pieces -> expected 2 bytes, given 1.
        assert_eq!(
            map_pieces_to_blocks(&[0b1110_0001], 1024 * 1024, 10 * 1024 * 1024),
            Err(BitmapMapError::BitfieldLengthMismatch {
                expected: 2,
                actual: 1
            })
        );
        let total = taiji_http::grid::MAX_TOTAL_LEN;
        assert_eq!(
            map_pieces_to_blocks(&[0], 1024 * 1024, total + 1),
            Err(BitmapMapError::TotalLengthExceeded {
                total: total + 1,
                max: total
            })
        );
    }

    /// Randomized cross-validation (reproducible xorshift): random
    /// piece geometry x random done sets, with an independent model
    /// recomputing "all intersecting pieces complete" — bitmap and byte
    /// totals must agree three ways (a wide regression surface beyond
    /// the mapping core and the golden branches).
    #[test]
    fn randomized_cross_check_against_independent_model() {
        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0 = x;
                x
            }
            fn below(&mut self, n: u64) -> u64 {
                if n == 0 { 0 } else { self.next() % n }
            }
        }
        let mut rng = Rng(0x0703_96d6_1702_1b17);
        for _round in 0..64 {
            // Piece geometry: powers of two / non-pow2 multiples (x3,
            // x15) / below the domain floor, mixed.
            let base = 1u64 << (12 + rng.below(14)); // 4KiB ..= 64MiB
            let piece = match rng.below(4) {
                0 => base,
                1 => base * 3,
                2 => base * 15,
                _ => base / 3 + 1,
            };
            let num_pieces = match rng.below(3) {
                0 => 1,
                1 => 1 + rng.below(40),
                _ => 1 + rng.below(200),
            };
            let total = piece * num_pieces - rng.below(piece);
            let bf_len = total.div_ceil(piece).div_ceil(8) as usize;
            let mut bf = vec![0u8; bf_len];
            for p in 0..num_pieces.div_ceil(8) * 8 {
                if p >= num_pieces {
                    break;
                }
                if rng.below(2) == 1 {
                    bf[(p / 8) as usize] |= 0x80 >> (p % 8);
                }
            }
            let mapped = match map_pieces_to_blocks(&bf, piece, total) {
                Ok(m) => m,
                Err(BitmapMapError::TotalLengthExceeded { .. }) => continue, // over the cap: skip
                Err(e) => panic!("round: {e}"),
            };
            // Reference model: independent block-by-block recompute.
            let bs = mapped.block_size;
            let count = total.div_ceil(bs);
            let mut want = vec![0u8; count.div_ceil(8) as usize];
            let mut want_bytes = 0u64;
            for b in 0..count {
                let start = b * bs;
                let end = ((b + 1) * bs).min(total);
                let all = (start / piece..=(end - 1) / piece)
                    .all(|p| bf[(p / 8) as usize] & (0x80 >> (p % 8)) != 0);
                if all {
                    want[(b / 8) as usize] |= 1 << (b % 8);
                    want_bytes += end - start;
                }
            }
            assert_eq!(mapped.block_count, count);
            assert_eq!(mapped.bitmap, want, "round piece={piece} total={total}");
            assert_eq!(mapped.done_bytes, want_bytes, "round piece={piece}");
            assert_grid_consumer(&mapped, total);
        }
    }
}
