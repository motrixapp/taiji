//! 权威文件策略模块：统一管理 Torrent 任务的文件选择集与多级优先级（-1 跳过 / 0 普通 / 1..=7 高优先级）。
//!
//! 设计不变量：
//! - 任何真实（非 padding）文件的有效状态由单一权威策略决定：`selected(i) <=> priority(i) != -1`；
//! - `selected_files` 为 `None` 时表示隐式全选（大文件数场景下零膨胀），为 `Some(vec)` 时保存升序去重的非空选中索引；
//! - `file_priorities` 严格只保存「当前已选且优先级在 `1..=7`」的升序去重稀疏表（空时为 `None`），
//!   不保存未选文件的陈旧优先级，也不为海量未选文件填充 `-1` 条目；
//! - `select-file` 与 `taiji.setFilePriority` 双向互通：前者保留仍在选集内文件的高优先级并清除被取消文件的旧优先级；
//!   后者以当前有效选择集为基线做局部补丁，绝不重新选中原先未选的文件。

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

use crate::metainfo::MetaFile;

use super::super::command::SessionError;

/// Torrent 任务的单一权威文件策略。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FilePolicy {
    real_count: u32,
    selected_files: Option<Vec<u32>>,
    file_priorities: Option<Vec<(u32, i8)>>,
}

impl FilePolicy {
    /// 统计元数据中真实（非 padding）文件总数。
    pub(super) fn real_file_count(files: &[MetaFile]) -> u32 {
        files.iter().filter(|f| !f.padding).count() as u32
    }

    /// 从当前任务镜像或旧版持久化数据构建规范化的权威文件策略。
    /// 兼容旧版在 `file_priorities` 中记录 `-1` 的持久化格式。
    pub(super) fn from_job(
        real_count: u32,
        selected_files: Option<&[u32]>,
        file_priorities: Option<&[(u32, i8)]>,
    ) -> Self {
        let (norm_selected, selected_set): (Option<Vec<u32>>, Option<HashSet<u32>>) =
            match selected_files {
                Some(sel) => {
                    let mut uniq: Vec<u32> =
                        sel.iter().copied().filter(|&i| i < real_count).collect();
                    uniq.sort_unstable();
                    uniq.dedup();
                    let set: HashSet<u32> = uniq.iter().copied().collect();
                    (Some(uniq), Some(set))
                }
                None => {
                    // 兼容旧版可能出现 selected_files = None 但 file_priorities 含 -1 的情况
                    let skipped: HashSet<u32> = file_priorities
                        .into_iter()
                        .flatten()
                        .filter_map(|&(idx, q)| (idx < real_count && q == -1).then_some(idx))
                        .collect();
                    if skipped.is_empty() {
                        (None, None)
                    } else {
                        let sel: Vec<u32> = (0..real_count)
                            .filter(|idx| !skipped.contains(idx))
                            .collect();
                        let set: HashSet<u32> = sel.iter().copied().collect();
                        (Some(sel), Some(set))
                    }
                }
            };

        let mut high: BTreeMap<u32, i8> = BTreeMap::new();
        if let Some(prios) = file_priorities {
            for &(idx, level) in prios {
                if idx < real_count
                    && (1..=7).contains(&level)
                    && selected_set.as_ref().is_none_or(|s| s.contains(&idx))
                {
                    high.insert(idx, level);
                }
            }
        }
        let norm_priorities = (!high.is_empty()).then(|| high.into_iter().collect());

        Self {
            real_count,
            selected_files: norm_selected,
            file_priorities: norm_priorities,
        }
    }

    /// 应用 `taiji.setFilePriority` 的局部更新（输入为 1-based 非 padding 文件索引与 `-1..=7` 等级）。
    /// 任何校验失败均返回 `Err` 且不产生副作用；未列出的文件完整保留原有选中状态与优先级。
    pub(super) fn apply_priority_patch(
        &self,
        pairs_1based: &[(u32, i8)],
    ) -> Result<Self, SessionError> {
        if pairs_1based.is_empty() {
            return Err(SessionError::failed(
                "taiji.setFilePriority: empty priority table",
            ));
        }
        let mut patch: Vec<(u32, i8)> = Vec::with_capacity(pairs_1based.len());
        let mut seen: HashSet<u32> = HashSet::with_capacity(pairs_1based.len());
        for &(index, level) in pairs_1based {
            if index == 0 || index > self.real_count {
                return Err(SessionError::failed(format!(
                    "taiji.setFilePriority: file index {index} out of range ({} files)",
                    self.real_count
                )));
            }
            if !(-1..=7).contains(&level) {
                return Err(SessionError::failed(format!(
                    "taiji.setFilePriority: priority {level} out of range (-1..=7)"
                )));
            }
            let zero_based = index - 1;
            if !seen.insert(zero_based) {
                return Err(SessionError::failed(format!(
                    "taiji.setFilePriority: duplicate file index {index}"
                )));
            }
            patch.push((zero_based, level));
        }

        let mut high: BTreeMap<u32, i8> = self
            .file_priorities
            .as_deref()
            .unwrap_or_default()
            .iter()
            .copied()
            .collect();

        let has_skip = patch.iter().any(|&(_, level)| level == -1);
        let next_selected = match &self.selected_files {
            // 原为隐式全选且补丁不含任何跳过项：保持 None（大文件数 O(p) 零膨胀）
            None if !has_skip => {
                for &(idx, level) in &patch {
                    if level == 0 {
                        high.remove(&idx);
                    } else {
                        high.insert(idx, level);
                    }
                }
                None
            }
            // 原为隐式全选且补丁含跳过项：展开为显式选中子集
            None => {
                let mut skipped: HashSet<u32> = HashSet::new();
                for &(idx, level) in &patch {
                    if level == -1 {
                        skipped.insert(idx);
                        high.remove(&idx);
                    } else if level == 0 {
                        high.remove(&idx);
                    } else {
                        high.insert(idx, level);
                    }
                }
                let selected: Vec<u32> = (0..self.real_count)
                    .filter(|idx| !skipped.contains(idx))
                    .collect();
                if selected.is_empty() {
                    return Err(SessionError::failed(
                        "taiji.setFilePriority: all files skipped (empty selection)",
                    ));
                }
                Some(selected)
            }
            // 原为显式选择子集：以该子集为基线局部增删，绝不复活未涉及的未选文件
            Some(existing) => {
                let mut selected_set: BTreeSet<u32> = existing.iter().copied().collect();
                for &(idx, level) in &patch {
                    if level == -1 {
                        selected_set.remove(&idx);
                        high.remove(&idx);
                    } else {
                        selected_set.insert(idx);
                        if level == 0 {
                            high.remove(&idx);
                        } else {
                            high.insert(idx, level);
                        }
                    }
                }
                if selected_set.is_empty() {
                    return Err(SessionError::failed(
                        "taiji.setFilePriority: all files skipped (empty selection)",
                    ));
                }
                Some(selected_set.into_iter().collect())
            }
        };

        let next_priorities = (!high.is_empty()).then(|| high.into_iter().collect());
        Ok(Self {
            real_count: self.real_count,
            selected_files: next_selected,
            file_priorities: next_priorities,
        })
    }

    /// 应用 `select-file` 整集替换（0-based 非 padding 索引）：
    /// - 保留仍在最新选择集内文件的高优先级（1..=7）；
    /// - 清除被取消选择文件的旧高优先级，防止残留幽灵优先级；
    /// - 新增选中文件默认为普通优先级 0。
    pub(super) fn apply_select_file(
        &self,
        mut selected_0based: Vec<u32>,
    ) -> Result<Self, SessionError> {
        selected_0based.sort_unstable();
        selected_0based.dedup();
        if selected_0based.is_empty() {
            return Err(SessionError::failed(
                "taiji.option.invalid: --select-file selects no files",
            ));
        }
        if let Some(&bad) = selected_0based.iter().find(|&&idx| idx >= self.real_count) {
            return Err(SessionError::failed(format!(
                "taiji.option.invalid: --select-file index {} out of range ({} files)",
                bad + 1,
                self.real_count
            )));
        }
        let keep: HashSet<u32> = selected_0based.iter().copied().collect();
        let kept_high: Vec<(u32, i8)> = self
            .file_priorities
            .as_deref()
            .unwrap_or_default()
            .iter()
            .copied()
            .filter(|&(idx, level)| (1..=7).contains(&level) && keep.contains(&idx))
            .collect();
        Ok(Self {
            real_count: self.real_count,
            selected_files: Some(selected_0based),
            file_priorities: (!kept_high.is_empty()).then_some(kept_high),
        })
    }

    /// 导出持久化/镜像所需的 `selected_files`。
    pub(super) fn selected_files(&self) -> Option<Vec<u32>> {
        self.selected_files.clone()
    }

    /// 导出持久化/镜像所需的 `file_priorities`（仅含已选的 1..=7 稀疏表）。
    pub(super) fn file_priorities(&self) -> Option<Vec<(u32, i8)>> {
        self.file_priorities.clone()
    }

    /// 导出给活跃引擎原子下发的选择集。
    pub(super) fn engine_selection(&self) -> Option<Arc<[u32]>> {
        self.selected_files.as_deref().map(Arc::from)
    }

    /// 导出给活跃引擎原子下发的稀疏优先级表（空切片表示全 0 普通优先级）。
    pub(super) fn engine_priority(&self) -> Arc<[(u32, i8)]> {
        match self.file_priorities.as_deref() {
            Some(entries) => Arc::from(entries),
            None => Arc::from(&[][..]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_job_migrates_legacy_negative_one_without_selected_files() {
        let p = FilePolicy::from_job(3, None, Some(&[(0, 7), (1, -1)]));
        assert_eq!(p.selected_files(), Some(vec![0, 2]));
        assert_eq!(p.file_priorities(), Some(vec![(0, 7)]));
    }

    #[test]
    fn from_job_strips_stale_priorities_for_unselected_files() {
        let p = FilePolicy::from_job(3, Some(&[1, 2]), Some(&[(0, 7), (1, 4), (2, -1)]));
        assert_eq!(p.selected_files(), Some(vec![1, 2]));
        assert_eq!(p.file_priorities(), Some(vec![(1, 4)]));
    }

    #[test]
    fn implicit_all_selected_priority_raise_stays_compact_for_large_file_counts() {
        let p = FilePolicy::from_job(100_000, None, None);
        let next = p
            .apply_priority_patch(&[(1, 7), (50_000, 3)])
            .unwrap_or_else(|e| panic!("大文件全选下局部提权不应失败: {e}"));
        assert_eq!(next.selected_files(), None);
        assert_eq!(next.file_priorities(), Some(vec![(0, 7), (49_999, 3)]));
        // 降回 0 后恢复全空稀疏表
        let cleared = next
            .apply_priority_patch(&[(1, 0), (50_000, 0)])
            .unwrap_or_else(|e| panic!("清零优先级失败: {e}"));
        assert_eq!(cleared.selected_files(), None);
        assert_eq!(cleared.file_priorities(), None);
        assert!(cleared.engine_priority().is_empty());
    }

    #[test]
    fn partial_update_and_select_file_interleaving_invariants() {
        // 仅选文件 1 (idx 0)
        let p = FilePolicy::from_job(3, Some(&[0]), None);
        // 提高文件 1 -> 仍仅选 0
        let p1 = p
            .apply_priority_patch(&[(1, 7)])
            .unwrap_or_else(|e| panic!("提高 1 失败: {e}"));
        assert_eq!(p1.selected_files(), Some(vec![0]));
        assert_eq!(p1.file_priorities(), Some(vec![(0, 7)]));
        // 跳过唯一已选文件 1 -> 拒绝
        assert!(p1.apply_priority_patch(&[(1, -1)]).is_err());
        // 明确选中文件 2 并设普通 0 -> 仅增加 1，2 仍未选，0 仍为 7
        let p2 = p1
            .apply_priority_patch(&[(2, 0)])
            .unwrap_or_else(|e| panic!("选中 2 失败: {e}"));
        assert_eq!(p2.selected_files(), Some(vec![0, 1]));
        assert_eq!(p2.file_priorities(), Some(vec![(0, 7)]));
        // 通过 select-file 切换到 [1, 2] -> 0 优先级被清除，1/2 为普通 0
        let p3 = p2
            .apply_select_file(vec![1, 2])
            .unwrap_or_else(|e| panic!("切换选集失败: {e}"));
        assert_eq!(p3.selected_files(), Some(vec![1, 2]));
        assert_eq!(p3.file_priorities(), None);
    }
}
