//! v2 leaf-fetch 事件驱动唤醒行为锁定测试。

use taiji_domain::hash_fetch::{HASH_FETCH_MAX_ATTEMPTS, HashRequestPlan};

use crate::dispatch::{FileLayerState, HashFetchEvent, LayerFetchState};
use crate::run::arms::apply_leaf_hash_fetch_event;

fn sample_layer(num_plans: usize) -> FileLayerState {
    let plans = (0..num_plans)
        .map(|i| HashRequestPlan {
            index: (i as u32) * 512,
            length: 512,
        })
        .collect();
    FileLayerState {
        root: [0xAB; 32],
        leaf_total: num_plans as u64 * 512,
        piece_base: 0,
        plans,
        state: LayerFetchState::Pending,
        attempts: 0,
    }
}

/// 验证 leaf-fetch 回调的唤醒判定矩阵：
/// - 中间批 Admitted -> 推进到 Queued { next + 1 } 且立即唤醒（true）；
/// - 最终批 Admitted -> 进入 Done 且立即唤醒内容块调度（true）；
/// - 瞬时 Failed（未达上限）-> 回退到 Queued { next } 且不立即唤醒（false，走 ticker 退避）；
/// - 终态 Failed（达上限）-> 降级为 Failed 且立即唤醒走整片缓冲下载（true）。
#[test]
fn leaf_hash_fetch_event_wakeup_decision_matrix() {
    let mut layer = sample_layer(2);

    // 1. 第一批 Admitted -> 推进下一批并立即唤醒
    assert!(apply_leaf_hash_fetch_event(
        &mut layer,
        &HashFetchEvent::Admitted { next: 0 },
        0,
        0
    ));
    assert!(matches!(layer.state, LayerFetchState::Queued { next: 1 }));
    assert_eq!(layer.attempts, 0);

    // 2. 第二批瞬时失败（第 1 次到第 N-1 次）-> 不立即唤醒，保持退避
    for expected_attempts in 1..HASH_FETCH_MAX_ATTEMPTS {
        layer.state = LayerFetchState::Pending;
        assert!(!apply_leaf_hash_fetch_event(
            &mut layer,
            &HashFetchEvent::Failed { next: 1 },
            0,
            0
        ));
        assert!(matches!(layer.state, LayerFetchState::Queued { next: 1 }));
        assert_eq!(layer.attempts, expected_attempts);
    }

    // 3. 若重试成功 Admitted（最后一批）-> Done 且立即唤醒发 payload 请求
    layer.state = LayerFetchState::Pending;
    assert!(apply_leaf_hash_fetch_event(
        &mut layer,
        &HashFetchEvent::Admitted { next: 1 },
        0,
        0
    ));
    assert!(matches!(layer.state, LayerFetchState::Done));
    assert_eq!(layer.attempts, 0);

    // 4. 若连续失败达到上限 -> 降级为 Failed 且立即唤醒走整片缓冲下载
    let mut fallback_layer = sample_layer(1);
    for _ in 1..HASH_FETCH_MAX_ATTEMPTS {
        assert!(!apply_leaf_hash_fetch_event(
            &mut fallback_layer,
            &HashFetchEvent::Failed { next: 0 },
            0,
            0
        ));
    }
    assert!(apply_leaf_hash_fetch_event(
        &mut fallback_layer,
        &HashFetchEvent::Failed { next: 0 },
        0,
        0
    ));
    assert!(matches!(fallback_layer.state, LayerFetchState::Failed));
}
