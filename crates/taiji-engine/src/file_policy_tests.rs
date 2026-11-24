//! 引擎侧原子文件策略（selection_mask + policy_priority_mask）单元测试。

use taiji_store::layout::{Layout, PlanEntry};

use crate::dispatch::{policy_priority_mask, selection_mask};

fn plan_v1(entries: &[(&str, u64, bool)], piece_len: u32) -> Layout {
    let plan: Vec<PlanEntry> = entries
        .iter()
        .map(|&(p, length, padding)| PlanEntry {
            path: p.into(),
            length,
            padding,
        })
        .collect();
    Layout::plan_v1_padded(&plan, piece_len).unwrap_or_else(|e| panic!("构造 v1 布局失败: {e}"))
}

fn plan_v2(entries: &[(&str, u64)], piece_len: u32) -> Layout {
    let plan: Vec<PlanEntry> = entries
        .iter()
        .map(|&(p, length)| PlanEntry {
            path: p.into(),
            length,
            padding: false,
        })
        .collect();
    Layout::plan_v2_compact(&plan, piece_len).unwrap_or_else(|e| panic!("构造 v2 布局失败: {e}"))
}

/// v1 非对齐共享边界分块：仅选文件 0 时，与文件 1 共享的边界分块仍按协议选中；
/// 未选文件 1 即使携带高优先级也不得抬升共享分块的优先级。
#[test]
fn v1_shared_boundary_piece_stays_selected_and_unselected_file_never_raises_priority() {
    // piece_len = 16384:
    // file 0: [0, 10000)      -> piece 0
    // file 1: [10000, 26384)  -> piece 0 (共享边界), piece 1
    // file 2: [26384, 26384)  -> 零长文件
    // file 3: [26384, 42768)  -> piece 1 (共享边界), piece 2
    let layout = plan_v1(
        &[
            ("a.bin", 10_000, false),
            ("b.bin", 16_384, false),
            ("empty.bin", 0, false),
            ("c.bin", 16_384, false),
        ],
        16_384,
    );
    // 仅选文件 0：piece 0 与 file 0 相交 -> 必须选中；piece 1/2 未相交 -> false
    let mask =
        selection_mask(&layout, 16_384, &[0]).unwrap_or_else(|e| panic!("selection_mask: {e}"));
    assert_eq!(mask, vec![true, false, false]);

    // 若传入未选文件 1 的高优先级 7，不得影响共享 piece 0，结果应返回 None（保持全 0 快路径）
    let prio_unselected = policy_priority_mask(&layout, 16_384, Some(&[0]), &[(1, 7)])
        .unwrap_or_else(|e| panic!("policy_priority_mask: {e}"));
    assert_eq!(prio_unselected, None);

    // 仅提高已选文件 0 到 6：piece 0 应为 6，其他为 0
    let prio_f0 = policy_priority_mask(&layout, 16_384, Some(&[0]), &[(0, 6)])
        .unwrap_or_else(|e| panic!("policy_priority_mask: {e}"));
    assert_eq!(prio_f0, Some(vec![6, 0, 0]));

    // 同时选中文件 0 和文件 1，分别设 3 和 7：共享 piece 0 取两者最大值 7，piece 1 为 7，piece 2 为 0
    let prio_both = policy_priority_mask(&layout, 16_384, Some(&[0, 1]), &[(0, 3), (1, 7)])
        .unwrap_or_else(|e| panic!("policy_priority_mask: {e}"));
    assert_eq!(prio_both, Some(vec![7, 7, 0]));
}

/// hybrid padding 跳过与 v2 独立分片布局：padding 不参与索引计数，v2 无跨文件共享分块。
#[test]
fn hybrid_padding_and_v2_compact_priority_projection() {
    let hybrid = plan_v1(
        &[
            ("a.bin", 16_384, false),
            (".pad/16384", 16_384, true),
            ("b.bin", 16_384, false),
        ],
        16_384,
    );
    // 非 padding 索引 1 对应 b.bin（位于 piece 2）
    let mask =
        selection_mask(&hybrid, 16_384, &[1]).unwrap_or_else(|e| panic!("hybrid selection: {e}"));
    assert_eq!(mask, vec![false, false, true]);
    let prio = policy_priority_mask(&hybrid, 16_384, Some(&[1]), &[(1, 5)])
        .unwrap_or_else(|e| panic!("hybrid prio: {e}"));
    assert_eq!(prio, Some(vec![0, 0, 5]));

    let v2 = plan_v2(
        &[("a.bin", 16_384), ("empty.bin", 0), ("b.bin", 32_768)],
        16_384,
    );
    let mask_v2 = selection_mask(&v2, 16_384, &[0]).unwrap_or_else(|e| panic!("v2 selection: {e}"));
    assert_eq!(mask_v2, vec![true, false, false]);
    let prio_v2 = policy_priority_mask(&v2, 16_384, Some(&[0]), &[(0, 7)])
        .unwrap_or_else(|e| panic!("v2 prio: {e}"));
    assert_eq!(prio_v2, Some(vec![7, -1, -1]));
}

/// 校验非法输入（越界索引、越界等级、重复索引）均被显式拒绝。
#[test]
fn policy_priority_mask_rejects_invalid_inputs() {
    let layout = plan_v1(
        &[("a.bin", 16_384, false), ("b.bin", 16_384, false)],
        16_384,
    );
    assert!(policy_priority_mask(&layout, 16_384, Some(&[0]), &[(2, 5)]).is_err());
    assert!(policy_priority_mask(&layout, 16_384, Some(&[0]), &[(0, 8)]).is_err());
    assert!(policy_priority_mask(&layout, 16_384, Some(&[0]), &[(0, -2)]).is_err());
    assert!(policy_priority_mask(&layout, 16_384, Some(&[0]), &[(0, 1), (0, 2)]).is_err());
}
