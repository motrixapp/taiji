//! Multi-file disk layout (SPEC §4.2 disk-layout mapping).
//!
//! v2-only: files packed contiguously in tree DFS order, no pad.
//! v1/hybrid: the v1 layout — cumulative offsets in `files` order; `.pad`
//! placeholder files (BEP47) occupy offsets but are never written to disk.
//! Pad placement, length and alignment are validated at plan time.
//!
//! Upstream anchor mapping: docs/design/store.md

use std::path::{Path, PathBuf};

use thiserror::Error;

/// Layout shape (SPEC §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LayoutKind {
    /// v2-only: compact and contiguous (no pad).
    V2Compact,
    /// v1/hybrid: v1 list order + pad placeholders.
    V1Padded,
}

/// One on-disk region of a layout (`padding = true` for pad regions; never
/// written to disk).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutFile {
    pub path: PathBuf,
    pub length: u64,
    /// Global offset within the layout (pad counts toward the total).
    pub offset: u64,
    /// BEP47 padding file (attr 'p').
    pub padding: bool,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LayoutError {
    #[error("pad file must be followed by a non-padding file (BEP47)")]
    TrailingPad,
    #[error(
        "file after pad must start at a piece boundary: offset {offset} not aligned to {piece_len} (BEP47 L85)"
    )]
    MisalignedAfterPad { offset: u64, piece_len: u32 },
    #[error(
        "pad length {got} does not fill the remainder to the next piece boundary {expected} (BEP47 L85)"
    )]
    BadPadLength { got: u64, expected: u64 },
    #[error(
        "cumulative layout length overflows u64 at {path:?}: metadata length sum is not representable"
    )]
    LengthSumOverflow { path: PathBuf },
    #[error("global offset {0} beyond layout total")]
    OffsetOutOfRange(u64),
}

/// Plan input (bt::filetree's FileEntry converted by the caller; the store
/// does not depend back on bt).
#[derive(Debug, Clone)]
pub struct PlanEntry {
    pub path: PathBuf,
    pub length: u64,
    pub padding: bool,
}

/// A planned layout: file region list (offsets ascending) + total size.
#[derive(Debug, Clone)]
pub struct Layout {
    kind: LayoutKind,
    files: Vec<LayoutFile>,
    total: u64,
    piece_len: u32,
}

impl Layout {
    /// v2-only: compact contiguous planning (DFS order guaranteed by the
    /// caller). Cumulative length overflowing u64 -> `LengthSumOverflow`
    /// (metadata integrity: an unrepresentable declared length sum is
    /// rejected rather than wrapped — a wrapped total would misalign locate
    /// and write ranges).
    pub fn plan_v2_compact(entries: &[PlanEntry], piece_len: u32) -> Result<Layout, LayoutError> {
        let mut files = Vec::with_capacity(entries.len());
        let mut offset = 0u64;
        for e in entries {
            files.push(LayoutFile {
                path: e.path.clone(),
                length: e.length,
                offset,
                padding: false,
            });
            offset =
                offset
                    .checked_add(e.length)
                    .ok_or_else(|| LayoutError::LengthSumOverflow {
                        path: e.path.clone(),
                    })?;
        }
        Ok(Layout {
            kind: LayoutKind::V2Compact,
            files,
            total: offset,
            piece_len,
        })
    }

    /// v1/hybrid: v1 list-order planning + pad alignment validation
    /// (BEP47). Cumulative length overflowing u64 -> `LengthSumOverflow`
    /// (same reason as [`plan_v2_compact`]).
    pub fn plan_v1_padded(entries: &[PlanEntry], piece_len: u32) -> Result<Layout, LayoutError> {
        let mut files = Vec::with_capacity(entries.len());
        let mut offset = 0u64;
        for (i, e) in entries.iter().enumerate() {
            let start = offset;
            offset =
                offset
                    .checked_add(e.length)
                    .ok_or_else(|| LayoutError::LengthSumOverflow {
                        path: e.path.clone(),
                    })?;
            files.push(LayoutFile {
                path: e.path.clone(),
                length: e.length,
                offset: start,
                padding: e.padding,
            });
            if e.padding {
                // A pad must be immediately followed by a non-pad file
                // (BEP47: pad is a placeholder).
                let next = entries.get(i + 1).ok_or(LayoutError::TrailingPad)?;
                if next.padding {
                    return Err(LayoutError::TrailingPad);
                }
                // The following file must start at a piece boundary; pad
                // length = the remainder to the boundary. The alignment
                // multiply also goes through checked: near u64::MAX the
                // ceiling-times-piece_len would wrap into a fake boundary.
                let aligned = offset
                    .div_ceil(u64::from(piece_len))
                    .checked_mul(u64::from(piece_len))
                    .ok_or_else(|| LayoutError::LengthSumOverflow {
                        path: e.path.clone(),
                    })?;
                if offset != aligned {
                    return Err(LayoutError::BadPadLength {
                        got: e.length,
                        expected: aligned - start,
                    });
                }
            }
        }
        Ok(Layout {
            kind: LayoutKind::V1Padded,
            files,
            total: offset,
            piece_len,
        })
    }

    pub fn kind(&self) -> LayoutKind {
        self.kind
    }

    pub fn files(&self) -> &[LayoutFile] {
        &self.files
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn piece_len(&self) -> u32 {
        self.piece_len
    }

    /// Global offset -> (file index, offset within the file); a hit on a
    /// pad returns its region (the caller decides zero-fill/skip). Beyond
    /// the total is an error.
    pub fn locate(&self, global_offset: u64) -> Result<(usize, u64), LayoutError> {
        if global_offset >= self.total && !(self.total == 0 && global_offset == 0) {
            return Err(LayoutError::OffsetOutOfRange(global_offset));
        }
        // Files are sorted by offset; a linear scan is enough (file count
        // below a few thousand).
        for (i, f) in self.files.iter().enumerate() {
            if global_offset < f.offset + f.length {
                return Ok((i, global_offset - f.offset));
            }
        }
        // Exactly at the end (at total, locating past a zero-length tail
        // file).
        match self.files.last() {
            Some(f) => Ok((self.files.len() - 1, f.length)),
            None => Err(LayoutError::OffsetOutOfRange(global_offset)),
        }
    }

    /// v2 addressing: (file_index, piece_in_file) -> layout-global offset.
    /// v2 pieces never span files (each file has its own piece space,
    /// BEP-52), so `offset = file.offset + piece_in_file * piece_len`.
    pub fn v2_piece_offset(
        &self,
        file_index: usize,
        piece_in_file: u32,
    ) -> Result<u64, LayoutError> {
        let f = self
            .files
            .get(file_index)
            .ok_or(LayoutError::OffsetOutOfRange(file_index as u64))?;
        // Checked addition (the `piece_in_file * piece_len` span itself
        // cannot overflow u64 — u32 × u32 < 2^64): a wrapping sum would
        // silently dodge the span check below and return a bogus
        // in-file offset.
        let span = u64::from(piece_in_file) * u64::from(self.piece_len);
        let off = f
            .offset
            .checked_add(span)
            .ok_or_else(|| LayoutError::LengthSumOverflow {
                path: f.path.clone(),
            })?;
        if off > f.offset + f.length {
            return Err(LayoutError::OffsetOutOfRange(off));
        }
        Ok(off)
    }

    /// Find a file index by path (used jointly by the hybrid dual
    /// representation: file-tree view -> v1 layout).
    pub fn find(&self, path: &Path) -> Option<usize> {
        self.files.iter().position(|f| f.path == path && !f.padding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Layout cross-validation against the hybrid fixture (official creator
    /// output, verified by libtorrent): a.bin[0,70000) -> .pad[70000,81920)
    /// (11920) -> b.bin[81920,111920).
    #[test]
    fn v1_padded_hybrid_fixture_shape() {
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
        let layout = Layout::plan_v1_padded(&entries, 16384).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(layout.kind(), LayoutKind::V1Padded);
        assert_eq!(layout.total(), 111920);
        let fs = layout.files();
        assert_eq!(
            (fs[0].offset, fs[0].length, fs[0].padding),
            (0, 70000, false)
        );
        assert_eq!(
            (fs[1].offset, fs[1].length, fs[1].padding),
            (70000, 11920, true)
        );
        assert_eq!(
            (fs[2].offset, fs[2].length, fs[2].padding),
            (81920, 30000, false)
        );
        assert_eq!(
            fs[2].offset % 16384,
            0,
            "after the pad the file starts on a piece boundary (BEP47 L85)"
        );
        assert_eq!(
            layout.locate(69000).unwrap_or_else(|e| panic!("{e}")),
            (0, 69000)
        );
        assert_eq!(
            layout.locate(70000).unwrap_or_else(|e| panic!("{e}")),
            (1, 0),
            "lands on the pad"
        );
        assert_eq!(
            layout.locate(81920).unwrap_or_else(|e| panic!("{e}")),
            (2, 0)
        );
        assert!(layout.find(Path::new("b.bin")) == Some(2));
        assert_eq!(
            layout.find(Path::new(".pad/11920")),
            None,
            "pads take no part in path lookup"
        );
    }

    /// v2-only compact layout + (file, piece) addressing.
    #[test]
    fn v2_compact_layout_and_addressing() {
        let entries = vec![
            PlanEntry {
                path: PathBuf::from("a"),
                length: 70000,
                padding: false,
            },
            PlanEntry {
                path: PathBuf::from("b"),
                length: 30000,
                padding: false,
            },
        ];
        let layout = Layout::plan_v2_compact(&entries, 16384).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(layout.kind(), LayoutKind::V2Compact);
        assert_eq!(layout.total(), 100000);
        // File 0 piece 1 -> compact offset 16384; file 1 piece 0 -> 70000.
        assert_eq!(
            layout
                .v2_piece_offset(0, 1)
                .unwrap_or_else(|e| panic!("{e}")),
            16384
        );
        assert_eq!(
            layout
                .v2_piece_offset(1, 0)
                .unwrap_or_else(|e| panic!("{e}")),
            70000
        );
        assert!(layout.v2_piece_offset(2, 0).is_err());
        // v2 pieces never span files: file 0 has only 5 pieces, piece 5 is
        // out of range.
        assert!(layout.v2_piece_offset(0, 5).is_err());
    }

    /// Pad violations: length not equal to the boundary remainder / pad at
    /// the end.
    #[test]
    fn pad_validation_rejections() {
        // Wrong pad length (should be 11920).
        let bad = vec![
            PlanEntry {
                path: PathBuf::from("a"),
                length: 70000,
                padding: false,
            },
            PlanEntry {
                path: PathBuf::from(".pad/x"),
                length: 100,
                padding: true,
            },
            PlanEntry {
                path: PathBuf::from("b"),
                length: 30000,
                padding: false,
            },
        ];
        assert!(matches!(
            Layout::plan_v1_padded(&bad, 16384),
            Err(LayoutError::BadPadLength {
                got: 100,
                expected: 11920
            })
        ));
        // Pad at the end.
        let trailing = vec![
            PlanEntry {
                path: PathBuf::from("a"),
                length: 70000,
                padding: false,
            },
            PlanEntry {
                path: PathBuf::from(".pad/x"),
                length: 11920,
                padding: true,
            },
        ];
        assert!(matches!(
            Layout::plan_v1_padded(&trailing, 16384),
            Err(LayoutError::TrailingPad)
        ));
        // Offset out of range.
        let ok = vec![PlanEntry {
            path: PathBuf::from("a"),
            length: 100,
            padding: false,
        }];
        let l = Layout::plan_v1_padded(&ok, 16384).unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(
            l.locate(200),
            Err(LayoutError::OffsetOutOfRange(200))
        ));
    }

    /// Cumulative length overflowing u64 -> error, not wraparound (metadata
    /// integrity): a wrapped total would push locate's out-of-range decision
    /// and the write ranges out of alignment.
    #[test]
    fn length_sum_overflow_rejected() {
        // u64::MAX - 100 + 101 > u64::MAX: the second entry overflows.
        let over = vec![
            PlanEntry {
                path: PathBuf::from("a"),
                length: u64::MAX - 100,
                padding: false,
            },
            PlanEntry {
                path: PathBuf::from("b"),
                length: 101,
                padding: false,
            },
        ];
        for (name, r) in [
            ("v1", Layout::plan_v1_padded(&over, 16384)),
            ("v2", Layout::plan_v2_compact(&over, 16384)),
        ] {
            match r {
                Err(LayoutError::LengthSumOverflow { path }) => {
                    assert_eq!(
                        path,
                        PathBuf::from("b"),
                        "{name}: the overflow point = the triggering entry"
                    );
                }
                Err(e) => panic!("{name}: expected LengthSumOverflow, got {e}"),
                Ok(l) => panic!(
                    "{name}: the overflow must error, got total {} instead",
                    l.total()
                ),
            }
        }
        // An in-bounds sum (exactly u64::MAX) is not falsely rejected.
        let exact = vec![
            PlanEntry {
                path: PathBuf::from("a"),
                length: u64::MAX - 100,
                padding: false,
            },
            PlanEntry {
                path: PathBuf::from("b"),
                length: 100,
                padding: false,
            },
        ];
        let l = Layout::plan_v1_padded(&exact, 16384).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(l.total(), u64::MAX);
    }

    // proptest: layout offsets are monotonic and contiguous
    // (offset_{i+1} = offset_i + len_i), alignment holds after pad, and
    // total == Σ len (pad counted).
    proptest::proptest! {
        #[test]
        fn layout_invariants(segs in proptest::prelude::prop::collection::vec(
            (0u64..4_000_000u64, proptest::prelude::any::<bool>()), 1..16
        )) {
            // Build a legal pad sequence: pad length = the remainder to the
            // next piece boundary.
            let piece_len = 16384u32;
            let mut entries: Vec<PlanEntry> = Vec::new();
            let mut offset = 0u64;
            for (i, (len, is_pad)) in segs.iter().enumerate() {
                if *is_pad && (entries.is_empty() || entries.last().unwrap_or_else(|| panic!("last")).padding) {
                    // Pad cannot start or continue: turn into a normal file.
                    entries.push(PlanEntry { path: PathBuf::from(format!("f{i}")), length: *len, padding: false });
                    offset += *len;
                } else if *is_pad && i + 1 < segs.len() {
                    // Pad cannot be last (BEP47: pad is a placeholder; the
                    // follower must be an aligned file).
                    let next = offset.div_ceil(u64::from(piece_len)) * u64::from(piece_len);
                    if next == offset {
                        // Already aligned: a zero-length pad is meaningless
                        // -> normal file.
                        entries.push(PlanEntry { path: PathBuf::from(format!("f{i}")), length: *len, padding: false });
                        offset += *len;
                    } else {
                        let pad = next - offset;
                        entries.push(PlanEntry { path: PathBuf::from(format!(".pad/{i}")), length: pad, padding: true });
                        offset = next;
                    }
                } else {
                    entries.push(PlanEntry { path: PathBuf::from(format!("f{i}")), length: *len, padding: false });
                    offset += *len;
                }
            }
            let layout = Layout::plan_v1_padded(&entries, piece_len).unwrap_or_else(|e| panic!("{e}"));
            let mut expect = 0u64;
            for f in layout.files() {
                assert_eq!(f.offset, expect, "offsets are contiguous");
                expect += f.length;
            }
            assert_eq!(layout.total(), expect);
            // After a pad there must be a non-pad aligned file.
            for w in layout.files().windows(2) {
                if w[0].padding {
                    assert!(!w[1].padding);
                    assert_eq!(w[1].offset % u64::from(piece_len), 0);
                }
            }
        }
    }
}
