//! Piece addressing model (no global piece-index assumption).
//!
//! - v1: the flat global index is a protocol fact (BEP3), modeled
//!   explicitly as [`PieceId::V1`];
//! - v2: a piece belongs to `(file_index, piece_in_file)` (the per-file
//!   piece model).
//!
//! Wire index conversion (BEP52 `piece length` section: "Files are mapped
//! into this piece address space so that each non-empty file is aligned to
//! a piece boundary and occurs in the same order as in the file tree"):
//! the v2 wire index = the file's aligned base + the index within the
//! file; each file occupies `ceil(len/piece_len)` pieces, zero-length
//! files occupy 0. The v1 wire index is the identity map.

/// Piece identity: the unified key for RequestBook/progress/verification
/// (bare global u32s are forbidden).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PieceId {
    V1(u32),
    V2 { file_index: u32, piece_in_file: u32 },
}

/// Converter between wire indices and [`PieceId`]. Built by TorrentTask
/// according to the SwarmKind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Addressing {
    /// v1: flat global index (protocol fact, identity mapping).
    Flat,
    /// v2: `piece_bases[i]` = file i's aligned base (in piece counts);
    /// the total is appended at the end for interval lookup.
    /// bases[0] == 0.
    PerFile { piece_bases: Vec<u64> },
}

impl Addressing {
    /// Build v2 addressing from a file-length table + piece length (BEP52
    /// alignment rules; see the module docs).
    pub fn per_file(file_lengths: &[u64], piece_len: u32) -> Addressing {
        debug_assert!(piece_len.is_power_of_two() && piece_len >= 16 * 1024);
        let mut piece_bases = Vec::with_capacity(file_lengths.len() + 1);
        piece_bases.push(0u64);
        for &len in file_lengths {
            let pieces = len.div_ceil(u64::from(piece_len));
            let next = piece_bases.last().copied().unwrap_or_default() + pieces;
            piece_bases.push(next);
        }
        Addressing::PerFile { piece_bases }
    }

    /// wire index -> [`PieceId`]; out of range returns None (the caller
    /// treats it as a protocol violation and disconnects).
    pub fn from_wire(&self, index: u32) -> Option<PieceId> {
        match self {
            Addressing::Flat => Some(PieceId::V1(index)),
            Addressing::PerFile { piece_bases } => {
                let idx = u64::from(index);
                // bases ascending: find the last file whose base <= idx.
                let file = piece_bases
                    .windows(2)
                    .position(|w| w[0] <= idx && idx < w[1])?;
                Some(PieceId::V2 {
                    file_index: file as u32,
                    piece_in_file: (idx - piece_bases[file]) as u32,
                })
            }
        }
    }

    /// [`PieceId`] -> wire index; unknown file / out of range returns None.
    pub fn to_wire(&self, id: PieceId) -> Option<u32> {
        match (self, id) {
            (Addressing::Flat, PieceId::V1(index)) => Some(index),
            (
                Addressing::PerFile { piece_bases },
                PieceId::V2 {
                    file_index,
                    piece_in_file,
                },
            ) => {
                let base = *piece_bases.get(usize::try_from(file_index).ok()?)?;
                let wire = base + u64::from(piece_in_file);
                // piece_in_file past this file's end is invalid (before the
                // next file's base).
                let next = piece_bases.get(usize::try_from(file_index).ok()? + 1)?;
                (wire < *next).then_some(u32::try_from(wire).ok()?)
            }
            _ => None,
        }
    }

    /// [`PieceId`] -> synthetic flat piece ordinal (the global coordinate of
    /// the engine/store pipeline; v1 identity, v2 = file base + index within
    /// the file, the synthetic view). Out of range returns None.
    pub fn to_flat(&self, id: PieceId) -> Option<u64> {
        match (self, id) {
            (Addressing::Flat, PieceId::V1(index)) => Some(u64::from(index)),
            (
                Addressing::PerFile { piece_bases },
                PieceId::V2 {
                    file_index,
                    piece_in_file,
                },
            ) => {
                let base = *piece_bases.get(usize::try_from(file_index).ok()?)?;
                let flat = base + u64::from(piece_in_file);
                let next = piece_bases.get(usize::try_from(file_index).ok()? + 1)?;
                (flat < *next).then_some(flat)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Aligned bases: zero-length files consume no pieces; files progress
    /// piece-aligned by length.
    #[test]
    fn per_file_bases_align_files() {
        // piece 16KiB: len 70000 -> 5 pieces, len 30000 -> 2 pieces (the
        // aligned hybrid fixture shape)
        let a = Addressing::per_file(&[70000, 30000], 16384);
        assert_eq!(
            a,
            Addressing::PerFile {
                piece_bases: vec![0, 5, 7]
            }
        );
        // Zero-length files occupy 0 pieces.
        let b = Addressing::per_file(&[0, 16384], 16384);
        assert_eq!(
            b,
            Addressing::PerFile {
                piece_bases: vec![0, 0, 1]
            }
        );
    }

    #[test]
    fn wire_roundtrip_and_bounds() {
        let a = Addressing::per_file(&[70000, 30000], 16384);
        // File 0's pieces 0..5 -> wire 0..5; file 1's pieces 0..2 -> wire
        // 5..7.
        assert_eq!(
            a.to_wire(PieceId::V2 {
                file_index: 0,
                piece_in_file: 0
            }),
            Some(0)
        );
        assert_eq!(
            a.to_wire(PieceId::V2 {
                file_index: 0,
                piece_in_file: 4
            }),
            Some(4)
        );
        assert_eq!(
            a.to_wire(PieceId::V2 {
                file_index: 1,
                piece_in_file: 0
            }),
            Some(5)
        );
        assert_eq!(
            a.to_wire(PieceId::V2 {
                file_index: 1,
                piece_in_file: 1
            }),
            Some(6)
        );
        // piece_in_file past this file's end (file 0 has only 5 pieces) ->
        // None.
        assert_eq!(
            a.to_wire(PieceId::V2 {
                file_index: 0,
                piece_in_file: 5
            }),
            None
        );
        assert_eq!(
            a.to_wire(PieceId::V2 {
                file_index: 2,
                piece_in_file: 0
            }),
            None
        );

        for idx in [0u32, 4, 5, 6] {
            let id = a.from_wire(idx);
            assert_eq!(id.map(|i| a.to_wire(i)), Some(Some(idx)), "roundtrip {idx}");
        }
        assert_eq!(
            a.to_wire(a.from_wire(5).unwrap_or_else(|| panic!("5 in range"))),
            Some(5)
        );
        assert_eq!(a.from_wire(7), None, "out-of-bounds wire index rejected");
        assert_eq!(a.from_wire(u32::MAX), None);
    }

    #[test]
    fn flat_identity() {
        let a = Addressing::Flat;
        assert_eq!(a.to_wire(PieceId::V1(42)), Some(42));
        assert_eq!(a.from_wire(42), Some(PieceId::V1(42)));
        // v1 addressing rejects v2 identities (the swarm layer guarantees
        // kind consistency).
        assert_eq!(
            a.to_wire(PieceId::V2 {
                file_index: 0,
                piece_in_file: 0
            }),
            None
        );
    }

    /// to_flat: v1 identity; v2 = base + index within the file, out of
    /// range rejected (the engine's global coordinate conversion).
    #[test]
    fn to_flat_matches_wire_for_aligned_bases() {
        let a = Addressing::per_file(&[70000, 30000], 16384);
        assert_eq!(Addressing::Flat.to_flat(PieceId::V1(3)), Some(3));
        assert_eq!(
            a.to_flat(PieceId::V2 {
                file_index: 0,
                piece_in_file: 4
            }),
            Some(4)
        );
        assert_eq!(
            a.to_flat(PieceId::V2 {
                file_index: 1,
                piece_in_file: 1
            }),
            Some(6)
        );
        assert_eq!(
            a.to_flat(PieceId::V2 {
                file_index: 1,
                piece_in_file: 2
            }),
            None,
            "rejected: beyond end of this file"
        );
        assert_eq!(
            Addressing::Flat.to_flat(PieceId::V2 {
                file_index: 0,
                piece_in_file: 0
            }),
            None
        );
    }
}
