//! Ranked picker complexity and tie-order regressions for preview preferences.
use crate::piece_stat::PieceStatMan;
use std::cell::Cell;

#[test]
fn uniform_preview_rank_does_not_scan_a_hundred_thousand_candidates() {
    let stats = PieceStatMan::new(100_000, &mut |n| n / 2);
    let visited = Cell::new(0);
    let (spread, plain) = stats.select_two_phase_ranked(
        |_| {
            visited.set(visited.get() + 1);
            true
        },
        |_| false,
        |_| 1,
        1,
    );
    assert!(spread.is_some());
    assert_eq!(spread, plain);
    assert_eq!(visited.get(), 1);
}

#[test]
fn rank_ceiling_preserves_full_scan_verdict_for_claims_and_file_priorities() {
    let mut stats = PieceStatMan::new(257, &mut |n| n / 3);
    for i in 0..257 {
        for _ in 0..i % 7 {
            stats.add_piece(i);
        }
    }
    for seed in 0..32 {
        let ranks: Vec<i8> = (0..257).map(|i| ((i * 11 + seed) % 16) as i8).collect();
        let eligible = |i: u64| (i + seed) % 3 != 0;
        let claimed = |i: u64| (i + seed) % 5 == 0;
        // Existing unbounded-rank selection provides the full-scan reference.
        let expected = stats.select_two_phase(eligible, claimed, Some(&ranks));
        let actual = stats.select_two_phase_ranked(eligible, claimed, |i| ranks[i as usize], 15);
        assert_eq!(actual, expected);
    }
}

#[test]
fn unavailable_maximum_falls_back_and_claimed_maximum_keeps_normal_work_moving() {
    let stats = PieceStatMan::new(8, &mut |n| n / 2);
    let rank = |i| if i == 7 { 1 } else { 0 };
    let (spread, _) = stats.select_two_phase_ranked(|i| i != 7, |_| false, rank, 1);
    assert!(spread.is_some_and(|i| i != 7));
    let (spread, plain) = stats.select_two_phase_ranked(|_| true, |i| i == 7, rank, 1);
    assert!(spread.is_some_and(|i| i != 7));
    assert_eq!(plain, Some(7));
}
