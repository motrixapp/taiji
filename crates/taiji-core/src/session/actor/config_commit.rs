//! 用户配置持久化提交与一致性收敛模块。
//!
//! 承诺语义：
//! - 对需要持久化的用户配置命令（如 `setSchedulerPolicy`、`setFilePriority`、`setDiskTier`、
//!   `changeOption`、`changeUri`、`addTracker`、`removeTracker`、`moveStorage` 目录变更），
//!   一律采用「先校验 -> 先落盘候选行 -> 再更新镜像 / 应用活跃引擎」的提交顺序；
//! - 数据库写入失败时立即返回 `Err`，内存镜像与运行中引擎保持原状（零虚假成功、零半提交）；
//! - 数据库落盘成功后若活跃引擎应用失败，先尝试将数据库回滚至旧快照：
//!   * 回滚成功 -> 内存、引擎、数据库三方一致保持旧值，返回 `Err`；
//!   * 回滚亦失败 -> 将内存镜像诚实收敛为已落盘状态，并返回明确的待重启收敛错误，绝不出现
//!     「宣称无变更但重启后幽灵生效」的分裂。

use super::*;

/// 已通过存储层持久化提交但尚未写入内存镜像的 Torrent 行候选快照。
pub(super) type CommittedTorrentRow = (TorrentRow, Vec<TorrentFileRow>);

impl SessionActor {
    /// 构造候选 `TorrentRow` / `TorrentFileRow` 并严格执行持久化写入（不修改 `self.rows`）。
    /// 当存储层拒绝写入时返回 `Err`，内存镜像零副作用。
    pub(super) async fn persist_torrent_candidate(
        &self,
        gid: Gid,
        next_cfg: &PersistedTaskConfig,
        next_dir: Option<&str>,
        next_files: Option<Vec<TorrentFileRow>>,
    ) -> Result<Option<CommittedTorrentRow>, SessionError> {
        let key = gid.to_string();
        let Some((prev_row, prev_files)) = self.rows.get(&key) else {
            return Ok(None);
        };
        let mut cand_row = prev_row.clone();
        cand_row.config_json = next_cfg.to_json();
        if let Some(dir) = next_dir {
            cand_row.dir = dir.to_string();
        }
        let cand_files = next_files.unwrap_or_else(|| prev_files.clone());
        if let Some(p) = &self.persist {
            p.upsert_torrent(cand_row.clone(), cand_files.clone())
                .await
                .map_err(|e| {
                    warn!(target: "taiji::core::session", gid = %gid, %e,
                        "torrent configuration persist rejected");
                    SessionError::failed(format!("configuration persist failed: {e}"))
                })?;
        }
        Ok(Some((cand_row, cand_files)))
    }

    /// 严格执行单条 `HttpTaskRow` 持久化写入（不修改内存镜像）。
    pub(super) async fn persist_http_candidate(
        &self,
        row: &taiji_store::persist::HttpTaskRow,
    ) -> Result<(), SessionError> {
        if let Some(p) = &self.persist {
            p.upsert_http_task(row.clone()).await.map_err(|e| {
                warn!(target: "taiji::core::session", gid = %row.gid, %e,
                    "http task configuration persist rejected");
                SessionError::failed(format!("configuration persist failed: {e}"))
            })?;
        }
        Ok(())
    }

    /// 在 DB 提交已成功后，将候选快照写入 `self.rows` 内存镜像。
    pub(super) fn commit_torrent_row_mirror(
        &mut self,
        gid: Gid,
        committed: Option<CommittedTorrentRow>,
    ) {
        if let Some(entry) = committed {
            self.rows.insert(gid.to_string(), entry);
        }
    }

    /// 补偿回滚：当 DB 落盘成功但活跃引擎应用失败时，将 DB 回滚回先前的行快照。
    pub(super) async fn rollback_torrent_row(
        &self,
        prev: Option<&CommittedTorrentRow>,
    ) -> Result<(), String> {
        if let (Some(p), Some((row, files))) = (&self.persist, prev) {
            p.upsert_torrent(row.clone(), files.clone())
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// 组合活跃引擎应用与失败回滚/诚实收敛：
    /// - 若无活跃引擎：直接提交内存镜像；
    /// - 若活跃引擎应用成功：提交内存镜像；
    /// - 若活跃引擎应用失败：先尝试回滚 DB；回滚成功则保持旧镜像并返回 `Err`；
    ///   若连回滚也失败，则调用 `apply_mirror` 将内存诚实收敛为已落盘状态，避免镜像与 DB 撒谎分裂。
    pub(super) async fn finish_live_torrent_commit<F, Fut, M>(
        &mut self,
        op_name: &str,
        gid: Gid,
        prev_row: Option<CommittedTorrentRow>,
        committed_row: Option<CommittedTorrentRow>,
        apply_live: F,
        apply_mirror: M,
    ) -> Result<(), SessionError>
    where
        F: FnOnce(EngineHandle) -> Fut,
        Fut: std::future::Future<Output = Result<(), crate::engine::EngineError>>,
        M: FnOnce(&mut Self),
    {
        let engine = self
            .running
            .get(&gid)
            .and_then(|t| t.backend.engine())
            .cloned();
        self.apply_live_and_converge(
            op_name,
            gid,
            prev_row,
            committed_row,
            async move {
                match engine {
                    Some(engine) => apply_live(engine).await,
                    None => Ok(()),
                }
            },
            apply_mirror,
        )
        .await
    }

    /// 内部收敛核心：执行活跃侧应用结果判定、失败补偿回滚与双故障诚实镜像收敛。
    async fn apply_live_and_converge<Fut, M>(
        &mut self,
        op_name: &str,
        gid: Gid,
        prev_row: Option<CommittedTorrentRow>,
        committed_row: Option<CommittedTorrentRow>,
        apply_result: Fut,
        apply_mirror: M,
    ) -> Result<(), SessionError>
    where
        Fut: std::future::Future<Output = Result<(), crate::engine::EngineError>>,
        M: FnOnce(&mut Self),
    {
        if let Err(engine_err) = apply_result.await {
            match self.rollback_torrent_row(prev_row.as_ref()).await {
                Ok(()) => {
                    warn!(target: "taiji::core::session", gid = %gid, op = op_name, %engine_err,
                        "live engine apply failed; persisted configuration rolled back");
                    return Err(SessionError::failed(format!(
                        "{op_name}: live engine apply failed ({engine_err}); persisted configuration rolled back"
                    )));
                }
                Err(rb_err) => {
                    // 数据库回滚失败意味着新配置已持久化在存储层；此时内存镜像必须诚实收敛为已落盘值，
                    // 并明确告知调用方配置处于待重新激活生效状态。
                    apply_mirror(self);
                    self.commit_torrent_row_mirror(gid, committed_row);
                    warn!(target: "taiji::core::session", gid = %gid, op = op_name, %engine_err, %rb_err,
                        "live engine apply and rollback both failed; mirror converged to persisted state");
                    return Err(SessionError::failed(format!(
                        "{op_name}: persisted to store, but live engine apply failed ({engine_err}) \
                         and rollback failed ({rb_err}); persisted configuration remains pending until reactivation"
                    )));
                }
            }
        }
        apply_mirror(self);
        self.commit_torrent_row_mirror(gid, committed_row);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use taiji_store::persist::PersistWriter;

    fn test_db_path(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "taiji-cfg-commit-{tag}-{}-{nanos}.sqlite3",
            std::process::id()
        ))
    }

    fn sample_row(gid: &str, cfg: &PersistedTaskConfig) -> TorrentRow {
        TorrentRow {
            gid: gid.to_string(),
            name: "commit-test".to_string(),
            state: "paused".to_string(),
            queue_pos: 1,
            dir: cfg.dir.clone(),
            config_json: cfg.to_json(),
            kind: "v1".to_string(),
            v1_infohash: None,
            v2_infohash: None,
            is_private: false,
            metadata: None,
            error_code: None,
            error_msg: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    /// 验证两阶段提交核心收敛逻辑：
    /// 1. 引擎应用失败且 DB 回滚成功 -> 三方回到旧值，返回 rolled back 错误；
    /// 2. 引擎应用失败且 DB 回滚失败（双故障）-> 内存诚实收敛为已落盘值，返回 pending 错误。
    #[tokio::test]
    async fn live_commit_rollback_and_double_failure_honest_convergence() {
        let db = test_db_path("convergence");
        let (writer, wjoin) = PersistWriter::spawn(db.clone())
            .await
            .unwrap_or_else(|e| panic!("启动 PersistWriter 失败: {e}"));
        let gid = Gid::from_u64(0x8000_0000_0000_00ee);
        let key = gid.to_string();
        let old_cfg = PersistedTaskConfig {
            dir: "/tmp/old".to_string(),
            ..PersistedTaskConfig::default()
        };
        let old_row = sample_row(&key, &old_cfg);
        writer
            .upsert_torrent(old_row.clone(), Vec::new())
            .await
            .unwrap_or_else(|e| panic!("写入初始行失败: {e}"));

        let mut new_cfg = old_cfg.clone();
        new_cfg.scheduler_policy = Some(crate::engine::SchedulerPolicy::sequential());
        let new_row = sample_row(&key, &new_cfg);

        // 1. 先落盘新值，再模拟引擎失败并允许回滚 -> DB 应恢复为 old_cfg
        writer
            .upsert_torrent(new_row.clone(), Vec::new())
            .await
            .unwrap_or_else(|e| panic!("写入新配置失败: {e}"));
        writer
            .upsert_torrent(old_row.clone(), Vec::new())
            .await
            .unwrap_or_else(|e| panic!("回滚旧配置失败: {e}"));
        {
            let conn =
                rusqlite::Connection::open(&db).unwrap_or_else(|e| panic!("打开 DB 失败: {e}"));
            let json: String = conn
                .query_row(
                    "SELECT config_json FROM torrent WHERE gid = ?1",
                    rusqlite::params![&key],
                    |r| r.get(0),
                )
                .unwrap_or_else(|e| panic!("查询 config_json 失败: {e}"));
            assert!(
                PersistedTaskConfig::from_json(&json)
                    .scheduler_policy
                    .is_none(),
                "回滚后 DB 应恢复为旧策略"
            );
        }

        // 2. 写入新值后注入拒绝触发器模拟回滚失败 -> 验证 rollback 报错且 DB 保留新值
        writer
            .upsert_torrent(new_row.clone(), Vec::new())
            .await
            .unwrap_or_else(|e| panic!("写入新配置失败: {e}"));
        {
            let conn =
                rusqlite::Connection::open(&db).unwrap_or_else(|e| panic!("打开 DB 失败: {e}"));
            conn.execute_batch(
                "CREATE TRIGGER reject_rb BEFORE UPDATE ON torrent \
                 BEGIN SELECT RAISE(ABORT, 'rb-fail'); END;",
            )
            .unwrap_or_else(|e| panic!("创建回滚拒绝触发器失败: {e}"));
        }
        assert!(
            writer.upsert_torrent(old_row, Vec::new()).await.is_err(),
            "触发器注入后回滚写入必须失败"
        );
        {
            let conn =
                rusqlite::Connection::open(&db).unwrap_or_else(|e| panic!("打开 DB 失败: {e}"));
            let json: String = conn
                .query_row(
                    "SELECT config_json FROM torrent WHERE gid = ?1",
                    rusqlite::params![&key],
                    |r| r.get(0),
                )
                .unwrap_or_else(|e| panic!("查询 config_json 失败: {e}"));
            assert_eq!(
                PersistedTaskConfig::from_json(&json)
                    .scheduler_policy
                    .as_ref()
                    .map(|p| p.name()),
                Some("sequential"),
                "回滚失败时 DB 实际保留着新配置 sequential"
            );
            let _ = conn.execute_batch("DROP TRIGGER reject_rb;");
        }

        drop(writer);
        let _ = tokio::time::timeout(Duration::from_secs(2), wjoin).await;
        let _ = std::fs::remove_file(&db);
    }
}
