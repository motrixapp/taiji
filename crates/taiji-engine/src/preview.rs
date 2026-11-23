//! Bounded head/tail preference within rarest-first scheduling.
//!
//! This is not a playback cursor or a sequential policy. File priorities,
//! availability, selection masks, and in-flight spreading retain precedence.

use std::ops::Range;

use serde::{Deserialize, Serialize};

use crate::strategy::{PieceSelectionStrategy, RarestFirstStrategy, SelectionCtx, StreamGeo};

/// Bytes preferred at each end of every selected payload file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewPieces {
    pub head: u64,
    pub tail: u64,
}

impl PreviewPieces {
    pub fn is_empty(&self) -> bool {
        self.head == 0 && self.tail == 0
    }

    /// Stable option echo; explicit zero disables the preference.
    pub fn option_value(&self) -> String {
        format!("head={},tail={}", self.head, self.tail)
    }
}

pub(crate) struct PreviewStrategy {
    ranges: Vec<Range<u64>>,
}

impl PreviewStrategy {
    pub(crate) fn new(config: PreviewPieces, geo: &StreamGeo) -> Self {
        let stride = u64::from(geo.piece_len);
        let mut ranges: Vec<Range<u64>> = Vec::new();
        let mut append = |range: Range<u64>| {
            if range.is_empty() {
                return;
            }
            if let Some(last) = ranges.last_mut()
                && range.start <= last.end
            {
                last.end = last.end.max(range.end);
            } else {
                ranges.push(range);
            }
        };
        for file in &geo.files {
            if file.len == 0 {
                continue;
            }
            if config.head > 0 {
                let end = (file.rem + file.len.min(config.head)).div_ceil(stride);
                append(file.base..file.base + end.min(file.pieces));
            }
            if config.tail > 0 {
                let start = (file.rem + file.len - file.len.min(config.tail)) / stride;
                append(file.base + start..file.base + file.pieces);
            }
        }
        Self { ranges }
    }

    fn preferred(&self, piece: u64) -> bool {
        let i = self.ranges.partition_point(|range| range.end <= piece);
        self.ranges.get(i).is_some_and(|range| range.start <= piece)
    }
}

impl PieceSelectionStrategy for PreviewStrategy {
    fn name(&self) -> &'static str {
        "rarest_first"
    }

    fn select_piece(&self, ctx: &SelectionCtx<'_>) -> Option<u64> {
        let available = ctx.advertised?;
        let eligible = |i: u64| {
            available.get(i as usize) && !ctx.done.get(i as usize).copied().unwrap_or(true)
        };
        // Once this peer has no unfinished preview piece, restore the ordinary
        // rarity bucket fast path instead of scanning every remaining piece.
        if !self
            .ranges
            .iter()
            .any(|range| (range.start..range.end.min(ctx.done.len() as u64)).any(eligible))
        {
            return RarestFirstStrategy.select_piece(ctx);
        }
        let rank = |i: u64| {
            ctx.priority
                .and_then(|p| p.get(i as usize))
                .copied()
                .unwrap_or(0)
                .clamp(0, 7)
                * 2
                + i8::from(self.preferred(i))
        };
        // The partial-piece hard gate keeps the same scope and tie order.
        let mut partial: Option<(u64, i8, u32)> = None;
        for &i in ctx.preferred {
            if eligible(i) {
                let q = rank(i);
                let count = ctx.stats.count(i);
                if partial.is_none_or(|(_, old_q, old_count)| {
                    q > old_q || (q == old_q && count < old_count)
                }) {
                    partial = Some((i, q, count));
                }
            }
        }
        if let Some((i, _, _)) = partial {
            return Some(i);
        }
        let (spread, plain) = ctx.stats.select_two_phase_ranked(
            eligible,
            |i| ctx.claimed.contains(i),
            rank,
            if ctx.priority.is_none() { 1 } else { 15 },
        );
        spread.or(plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bitmap::PieceBitmap, dispatch::ClaimedSet};
    use taiji_bt::piece_stat::PieceStatMan;
    use taiji_store::layout::{Layout, PlanEntry};

    fn geo(lengths: &[(u64, bool)], v2: bool) -> StreamGeo {
        let entries: Vec<_> = lengths
            .iter()
            .enumerate()
            .map(|(i, &(length, padding))| PlanEntry {
                path: format!("{i}.mkv").into(),
                length,
                padding,
            })
            .collect();
        let layout = if v2 {
            Layout::plan_v2_compact(&entries, 4)
        } else {
            Layout::plan_v1_padded(&entries, 4)
        }
        .unwrap_or_else(|e| panic!("valid layout: {e}"));
        StreamGeo::from_layout(&layout, 4)
    }

    #[test]
    fn preview_geometry_handles_unaligned_v1_and_v2_file_boundaries() {
        let preview = PreviewPieces { head: 1, tail: 1 };
        let v1 = PreviewStrategy::new(
            preview,
            &geo(&[(10, false), (10, false), (0, false)], false),
        );
        assert_eq!(v1.ranges, vec![0..1, 2..3, 4..5]);
        let v2 = PreviewStrategy::new(
            PreviewPieces { head: 1, tail: 0 },
            &geo(&[(5, false), (8, false)], true),
        );
        assert_eq!(v2.ranges, vec![0..1, 2..3]);
        let hybrid =
            PreviewStrategy::new(preview, &geo(&[(5, false), (3, true), (12, false)], false));
        assert_eq!(hybrid.ranges, vec![0..3, 4..5]);
        assert!(!hybrid.preferred(3));
        assert!(!hybrid.preferred(5));
    }

    #[test]
    fn preview_selection_respects_peer_mask_selection_priority_and_claims() {
        let strategy = PreviewStrategy::new(
            PreviewPieces { head: 4, tail: 4 },
            &geo(&[(32, false)], false),
        );
        let mut stats = PieceStatMan::new(8, &mut |n| n / 2);
        for _ in 0..10 {
            stats.add_piece(0);
        }
        let available = PieceBitmap::ones(8);
        let mut done = vec![false; 8];
        let mut claimed = ClaimedSet::with_len(8);
        let pick = |done: &[bool], claimed: &ClaimedSet, priority: Option<&[i8]>| {
            strategy.select_piece(&SelectionCtx {
                advertised: Some(&available),
                done,
                stats: &stats,
                claimed,
                preferred: &[],
                stream: None,
                priority,
            })
        };
        assert_eq!(pick(&done, &claimed, None), Some(7));
        let priority = [0, 0, 0, 0, 7, 0, 0, 0];
        assert_eq!(pick(&done, &claimed, Some(&priority)), Some(4));
        claimed.mark_claimed(0);
        claimed.mark_claimed(7);
        assert!(![Some(0), Some(7), None].contains(&pick(&done, &claimed, None)));
        done[0] = true;
        done[7] = true;
        assert!(![Some(0), Some(7), None].contains(&pick(&done, &claimed, None)));
        done.fill(true);
        assert_eq!(pick(&done, &claimed, None), None);
    }

    #[test]
    fn preview_falls_back_when_peer_has_no_edge_piece() {
        let strategy = PreviewStrategy::new(
            PreviewPieces { head: 4, tail: 4 },
            &geo(&[(32, false)], false),
        );
        let stats = PieceStatMan::new(8, &mut |n| n / 2);
        let available =
            PieceBitmap::from_bools(&[false, false, true, false, false, false, false, false]);
        let claimed = ClaimedSet::with_len(8);
        let ctx = SelectionCtx {
            advertised: Some(&available),
            done: &[false; 8],
            stats: &stats,
            claimed: &claimed,
            preferred: &[],
            stream: None,
            priority: None,
        };
        assert_eq!(strategy.select_piece(&ctx), Some(2));
    }

    #[test]
    fn preview_ranges_merge_overlaps_without_per_piece_or_descendant_copies() {
        let strategy = PreviewStrategy::new(
            PreviewPieces {
                head: 1000,
                tail: 1000,
            },
            &geo(&vec![(1, false); 100_000], true),
        );
        assert_eq!(strategy.ranges, vec![0..100_000]);
        assert_eq!(
            PreviewStrategy::new(PreviewPieces::default(), &geo(&[(100, false)], false))
                .ranges
                .len(),
            0
        );
    }
    #[test]
    fn completed_preview_regions_restore_the_default_picker_verdict() {
        let strategy = PreviewStrategy::new(
            PreviewPieces { head: 4, tail: 4 },
            &geo(&[(32, false)], false),
        );
        let stats = PieceStatMan::new(8, &mut |n| n / 2);
        let available = PieceBitmap::ones(8);
        let done = [true, false, false, false, false, false, false, true];
        let mut claimed = ClaimedSet::with_len(8);
        claimed.mark_claimed(2);
        let priorities = [0, 0, 7, 5, 0, 1, 4, 0];
        for priority in [None, Some(priorities.as_slice())] {
            let ctx = SelectionCtx {
                advertised: Some(&available),
                done: &done,
                stats: &stats,
                claimed: &claimed,
                preferred: &[],
                stream: None,
                priority,
            };
            assert_eq!(
                strategy.select_piece(&ctx),
                RarestFirstStrategy.select_piece(&ctx)
            );
        }
    }
}
