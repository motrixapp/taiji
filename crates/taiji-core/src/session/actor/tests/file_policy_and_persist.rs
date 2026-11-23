// ---- P0-1 / P0-2 回归测试：文件策略原子一致性与配置持久化提交语义 ----

/// 构造多文件 v1 合成种子（支持自定义每个文件的路径、长度及是否为 padding）。
fn build_custom_v1_torrent(
    announce: &str,
    name: &str,
    piece_len: usize,
    specs: &[(&str, usize, bool)],
) -> Vec<u8> {
    use sha1::{Digest as _, Sha1 as _Sha1};
    let mut stream = Vec::new();
    for (idx, &(_, len, pad)) in specs.iter().enumerate() {
        if pad {
            stream.extend(std::iter::repeat_n(0u8, len));
        } else {
            let seed = (idx as u8).wrapping_mul(17).wrapping_add(1);
            stream.extend((0..len).map(|i| (i as u8).wrapping_add(seed)));
        }
    }
    let mut pieces = Vec::new();
    for chunk in stream.chunks(piece_len) {
        pieces.extend_from_slice(&_Sha1::digest(chunk));
    }
    let file_entries: Vec<Value> = specs
        .iter()
        .map(|&(rel, len, pad)| {
            let path = rel
                .split('/')
                .map(|seg| Value::Bytes(seg.as_bytes().to_vec()))
                .collect();
            let mut dict: Vec<(Vec<u8>, Value)> = Vec::new();
            if pad {
                dict.push((b"attr".to_vec(), Value::Bytes(b"p".to_vec())));
            }
            dict.push((b"length".to_vec(), Value::Int(len as i64)));
            dict.push((b"path".to_vec(), Value::List(path)));
            Value::Dict(dict.into_iter().collect())
        })
        .collect();
    let info = Value::Dict(
        vec![
            (b"files".to_vec(), Value::List(file_entries)),
            (b"name".to_vec(), Value::Bytes(name.as_bytes().to_vec())),
            (b"piece length".to_vec(), Value::Int(piece_len as i64)),
            (b"pieces".to_vec(), Value::Bytes(pieces)),
        ]
        .into_iter()
        .collect(),
    );
    let top = Value::Dict(
        vec![
            (
                b"announce".to_vec(),
                Value::Bytes(announce.as_bytes().to_vec()),
            ),
            (b"info".to_vec(), info),
        ]
        .into_iter()
        .collect(),
    );
    bencode::encode(&top).unwrap_or_else(|e| panic!("构造测试种子失败: {e}"))
}

/// 构造多文件纯 v2 合成种子（每个非空文件独立生成 Merkle 根与 piece layer）。
fn build_multi_file_v2_torrent(
    announce: &str,
    name: &str,
    piece_len: usize,
    specs: &[(&str, usize)],
) -> Vec<u8> {
    let mut tree_entries: Vec<(Vec<u8>, Value)> = Vec::new();
    let mut layers: Vec<(Vec<u8>, Value)> = Vec::new();
    for (idx, &(fname, len)) in specs.iter().enumerate() {
        let mut leaf_dict: Vec<(Vec<u8>, Value)> = Vec::new();
        leaf_dict.push((b"length".to_vec(), Value::Int(len as i64)));
        if len > 0 {
            let seed = (idx as u8).wrapping_add(11);
            let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_add(seed)).collect();
            let bpp = piece_len / (merkle::BLOCK_SIZE as usize);
            let mut piece_hashes = Vec::new();
            for chunk in data.chunks(piece_len) {
                let mut block_hashes = Vec::new();
                for blk in chunk.chunks(merkle::BLOCK_SIZE as usize) {
                    block_hashes.push(merkle::block_hash(blk));
                }
                while block_hashes.len() < bpp {
                    block_hashes.push(merkle::ZERO_HASH);
                }
                piece_hashes.push(merkle::root_from_block_hashes(&block_hashes));
            }
            let root = merkle::file_root_from_piece_roots(&piece_hashes, bpp);
            leaf_dict.push((b"pieces root".to_vec(), Value::Bytes(root.to_vec())));
            if len > piece_len {
                let mut concat = Vec::with_capacity(piece_hashes.len() * 32);
                for h in &piece_hashes {
                    concat.extend_from_slice(h);
                }
                layers.push((root.to_vec(), Value::Bytes(concat)));
            }
        }
        let file_node = Value::Dict(
            vec![(Vec::new(), Value::Dict(leaf_dict.into_iter().collect()))]
                .into_iter()
                .collect(),
        );
        tree_entries.push((fname.as_bytes().to_vec(), file_node));
    }
    tree_entries.sort_by(|a, b| a.0.cmp(&b.0));
    layers.sort_by(|a, b| a.0.cmp(&b.0));
    let info = Value::Dict(
        vec![
            (
                b"file tree".to_vec(),
                Value::Dict(tree_entries.into_iter().collect()),
            ),
            (b"meta version".to_vec(), Value::Int(2)),
            (b"name".to_vec(), Value::Bytes(name.as_bytes().to_vec())),
            (b"piece length".to_vec(), Value::Int(piece_len as i64)),
        ]
        .into_iter()
        .collect(),
    );
    let top = Value::Dict(
        vec![
            (
                b"announce".to_vec(),
                Value::Bytes(announce.as_bytes().to_vec()),
            ),
            (b"info".to_vec(), info),
            (
                b"piece layers".to_vec(),
                Value::Dict(layers.into_iter().collect()),
            ),
        ]
        .into_iter()
        .collect(),
    );
    bencode::encode(&top).unwrap_or_else(|e| panic!("构造 v2 测试种子失败: {e}"))
}

/// 读取 SQLite 中 torrent_file 表的 (selected, priority) 列表，按 file_index 排序。
fn read_db_file_rows(db: &std::path::Path, gid: &Gid) -> Vec<(bool, i64)> {
    let conn = ok(rusqlite::Connection::open(db), "打开数据库");
    let mut stmt = ok(
        conn.prepare(
            "SELECT selected, priority FROM torrent_file WHERE gid = ?1 ORDER BY file_index ASC",
        ),
        "准备查询 torrent_file",
    );
    let rows = ok(
        stmt.query_map(params![gid.to_string()], |r| {
            let sel: i64 = r.get(0)?;
            let prio: i64 = r.get(1)?;
            Ok((sel != 0, prio))
        }),
        "查询 torrent_file",
    );
    rows.map(|r| ok(r, "读取行")).collect()
}

/// 模拟异常崩溃：不调用 shutdown/saveSession，直接丢弃 actor 与 writer 句柄。
async fn simulate_crash_stop(
    handle: SessionHandle,
    join: tokio::task::JoinHandle<()>,
    writer: PersistHandle,
    wjoin: tokio::task::JoinHandle<()>,
) {
    drop(handle);
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin).await;
}

/// P0-1 核心回归：仅选文件 1 后局部提高文件 1 的优先级，未选文件 2/3 不得被重新选中。
#[tokio::test]
async fn file_priority_partial_update_preserves_unselected_files_from_select_file() {
    let db = tmp_db("p0-1-preserve-unselected");
    let dir = temp_dir("p0-1-preserve-unselected");
    let bytes = build_custom_v1_torrent(
        &dead_tracker(),
        "p0-1-abc",
        16384,
        &[
            ("a.bin", 16384, false),
            ("b.bin", 16384, false),
            ("c.bin", 16384, false),
        ],
    );

    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "启动 writer 1");
    let (handle, join) = SessionActor::spawn_with_persist(
        SessionOptions {
            global: GlobalOptions {
                dir: dir.clone(),
                enable_dht: false,
                enable_dht6: false,
                ..Default::default()
            },
        },
        Some(writer.clone()),
    );

    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: bytes,
                options: BTreeMap::from([
                    ("pause".to_string(), "true".to_string()),
                    ("select-file".to_string(), "1".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let g = gid.to_string();

    let before = files_of(&call(&handle, SessionCommand::GetFiles { gid: g.clone() }).await);
    assert_eq!(
        before.iter().map(|f| f.selected).collect::<Vec<_>>(),
        vec![true, false, false],
        "初始应仅选中文件 1"
    );

    // 仅提高文件 1 优先级到 7
    ok(
        call(
            &handle,
            SessionCommand::SetFilePriority {
                gid: g.clone(),
                pairs: vec![(1, 7)],
            },
        )
        .await,
        "setFilePriority([(1, 7)]) 应成功",
    );

    let after = files_of(&call(&handle, SessionCommand::GetFiles { gid: g.clone() }).await);
    assert_eq!(
        after.iter().map(|f| f.selected).collect::<Vec<_>>(),
        vec![true, false, false],
        "局部提高文件 1 优先级不得重新选中未选文件 2/3"
    );
    assert_eq!(
        after.iter().map(|f| f.priority).collect::<Vec<_>>(),
        vec![7, -1, -1],
        "文件 1 应为 7，未选文件 2/3 应投影为 -1"
    );

    let status = status_of(&handle, &g).await;
    assert_eq!(
        status.files.iter().map(|f| f.selected).collect::<Vec<_>>(),
        vec![true, false, false],
        "tellStatus 与 getFiles 应保持一致"
    );

    // 核对 DB 行与 config_json
    assert_eq!(
        read_db_file_rows(&db, &gid),
        vec![(true, 7), (false, -1), (false, -1)],
        "SQLite torrent_file 行投影应与文件策略一致"
    );
    let saved = PersistedTaskConfig::from_json(&read_config_json(&db, &gid));
    assert_eq!(saved.selected_files, Some(vec![0]));

    // 模拟崩溃重启（不走 saveSession），验证恢复完全一致
    simulate_crash_stop(handle, join, writer, wjoin).await;

    let (writer2, wjoin2) = ok(PersistWriter::spawn(db.clone()).await, "启动 writer 2");
    let (handle2, join2) = SessionActor::spawn_with_persist(
        SessionOptions {
            global: GlobalOptions {
                dir: dir.clone(),
                enable_dht: false,
                enable_dht6: false,
                ..Default::default()
            },
        },
        Some(writer2.clone()),
    );
    let restored = files_of(&call(&handle2, SessionCommand::GetFiles { gid: g.clone() }).await);
    assert_eq!(
        restored.iter().map(|f| f.selected).collect::<Vec<_>>(),
        vec![true, false, false],
        "重启后仍应仅选中文件 1"
    );
    assert_eq!(
        restored.iter().map(|f| f.priority).collect::<Vec<_>>(),
        vec![7, -1, -1],
        "重启后优先级应完整保持"
    );

    handle2.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join2).await;
    drop(writer2);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin2).await;
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// P0-1 回归：局部新增 B（普通/高优先级）、保留其他文件等级、跳过最后一个选中文件拒绝且零副作用。
#[tokio::test]
async fn file_priority_partial_raise_and_reject_empty_selection_preserve_state() {
    let db = tmp_db("p0-1-partial-and-empty");
    let dir = temp_dir("p0-1-partial-and-empty");
    let bytes = build_custom_v1_torrent(
        &dead_tracker(),
        "p0-1-partial",
        16384,
        &[
            ("a.bin", 16384, false),
            ("b.bin", 16384, false),
            ("c.bin", 16384, false),
        ],
    );

    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "启动 writer");
    let (handle, join) = SessionActor::spawn_with_persist(
        SessionOptions {
            global: GlobalOptions {
                dir: dir.clone(),
                enable_dht: false,
                enable_dht6: false,
                ..Default::default()
            },
        },
        Some(writer.clone()),
    );

    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: bytes,
                options: BTreeMap::from([
                    ("pause".to_string(), "true".to_string()),
                    ("select-file".to_string(), "1".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let g = gid.to_string();

    // 先把 A 设为 7
    ok(
        call(
            &handle,
            SessionCommand::SetFilePriority {
                gid: g.clone(),
                pairs: vec![(1, 7)],
            },
        )
        .await,
        "A 设为 7",
    );

    // 尝试跳过仅剩的已选文件 A -> 必须显式拒绝，且完整保留 A=7、B/C 未选
    let err = call(
        &handle,
        SessionCommand::SetFilePriority {
            gid: g.clone(),
            pairs: vec![(1, -1)],
        },
    )
    .await;
    assert!(
        matches!(err, Err(SessionError::Failed { .. })),
        "跳过最后一个已选文件必须拒绝，实际: {err:?}"
    );
    let after_reject = files_of(&call(&handle, SessionCommand::GetFiles { gid: g.clone() }).await);
    assert_eq!(
        after_reject
            .iter()
            .map(|f| (f.selected, f.priority))
            .collect::<Vec<_>>(),
        vec![(true, 7), (false, -1), (false, -1)],
        "被拒绝的跳过操作必须零副作用"
    );

    // 明确给 B 设置普通优先级 0 -> 仅增加 B，C 仍未选，A 仍为 7
    ok(
        call(
            &handle,
            SessionCommand::SetFilePriority {
                gid: g.clone(),
                pairs: vec![(2, 0)],
            },
        )
        .await,
        "给 B 设置普通优先级 0",
    );
    let after_b0 = files_of(&call(&handle, SessionCommand::GetFiles { gid: g.clone() }).await);
    assert_eq!(
        after_b0
            .iter()
            .map(|f| (f.selected, f.priority))
            .collect::<Vec<_>>(),
        vec![(true, 7), (true, 0), (false, -1)],
        "仅应增加 B，C 保持未选且 A 保持 7"
    );

    // 提高 B 到 5 -> 不改变 A=7，不选中 C
    ok(
        call(
            &handle,
            SessionCommand::SetFilePriority {
                gid: g.clone(),
                pairs: vec![(2, 5)],
            },
        )
        .await,
        "提高 B 到 5",
    );
    let after_b5 = files_of(&call(&handle, SessionCommand::GetFiles { gid: g.clone() }).await);
    assert_eq!(
        after_b5
            .iter()
            .map(|f| (f.selected, f.priority))
            .collect::<Vec<_>>(),
        vec![(true, 7), (true, 5), (false, -1)],
        "局部更新 B 不得改变 A 等级或选中 C"
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin).await;
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// P0-1 回归：select-file 与 setFilePriority 双向交替，查询、DB 与重启一致。
#[tokio::test]
async fn file_priority_and_select_file_bidirectional_interleaving_and_restart() {
    let db = tmp_db("p0-1-bidirectional");
    let dir = temp_dir("p0-1-bidirectional");
    let bytes = build_custom_v1_torrent(
        &dead_tracker(),
        "p0-1-bidir",
        16384,
        &[
            ("f1.bin", 16384, false),
            (".pad/16384", 16384, true),
            ("f2.bin", 16384, false),
            ("f3.bin", 16384, false),
        ],
    );

    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "启动 writer 1");
    let (handle, join) = SessionActor::spawn_with_persist(
        SessionOptions {
            global: GlobalOptions {
                dir: dir.clone(),
                enable_dht: false,
                enable_dht6: false,
                ..Default::default()
            },
        },
        Some(writer.clone()),
    );

    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: bytes,
                options: BTreeMap::from([
                    ("pause".to_string(), "true".to_string()),
                    ("select-file".to_string(), "1,2".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let g = gid.to_string();

    // 1. 设置 f1=7, f2=4（f3 保持未选）
    ok(
        call(
            &handle,
            SessionCommand::SetFilePriority {
                gid: g.clone(),
                pairs: vec![(1, 7), (2, 4)],
            },
        )
        .await,
        "设置 f1=7, f2=4",
    );

    // 2. 通过 changeOption(select-file="2,3") 取消 f1、保留 f2、新增 f3
    ok(
        call(
            &handle,
            SessionCommand::ChangeOption {
                gid: g.clone(),
                options: BTreeMap::from([("select-file".to_string(), "2,3".to_string())]),
            },
        )
        .await,
        "changeOption select-file=2,3",
    );
    let mid = files_of(&call(&handle, SessionCommand::GetFiles { gid: g.clone() }).await);
    // 元数据顺序：f1(0), pad(1), f2(2), f3(3)
    assert_eq!(
        (mid[0].selected, mid[0].priority),
        (false, -1),
        "取消选择的 f1 不应残留旧优先级 7"
    );
    assert_eq!(
        (mid[2].selected, mid[2].priority),
        (true, 4),
        "仍在选择集内的 f2 应保留优先级 4"
    );
    assert_eq!(
        (mid[3].selected, mid[3].priority),
        (true, 0),
        "新选中的 f3 应为普通优先级 0"
    );

    // 3. 再次局部设置 f3=6 -> f1 仍未选，f2 仍为 4
    ok(
        call(
            &handle,
            SessionCommand::SetFilePriority {
                gid: g.clone(),
                pairs: vec![(3, 6)],
            },
        )
        .await,
        "局部设置 f3=6",
    );
    let after = files_of(&call(&handle, SessionCommand::GetFiles { gid: g.clone() }).await);
    assert_eq!((after[0].selected, after[0].priority), (false, -1));
    assert_eq!((after[2].selected, after[2].priority), (true, 4));
    assert_eq!((after[3].selected, after[3].priority), (true, 6));

    // 4. 崩溃重启核对
    simulate_crash_stop(handle, join, writer, wjoin).await;
    let (writer2, wjoin2) = ok(PersistWriter::spawn(db.clone()).await, "启动 writer 2");
    let (handle2, join2) = SessionActor::spawn_with_persist(
        SessionOptions {
            global: GlobalOptions {
                dir: dir.clone(),
                enable_dht: false,
                enable_dht6: false,
                ..Default::default()
            },
        },
        Some(writer2.clone()),
    );
    let restored = files_of(&call(&handle2, SessionCommand::GetFiles { gid: g.clone() }).await);
    assert_eq!((restored[0].selected, restored[0].priority), (false, -1));
    assert_eq!((restored[2].selected, restored[2].priority), (true, 4));
    assert_eq!((restored[3].selected, restored[3].priority), (true, 6));

    handle2.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join2).await;
    drop(writer2);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin2).await;
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// P0-1 回归：活跃任务、零长文件、v1 非对齐共享边界、v2 布局及大文件数量场景。
#[tokio::test]
async fn file_priority_active_task_zero_len_unaligned_v1_v2_and_large_file_count() {
    let db = tmp_db("p0-1-active-complex");
    let dir = temp_dir("p0-1-active-complex");
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "启动 writer");
    let (handle, join) = SessionActor::spawn_with_persist(
        SessionOptions {
            global: GlobalOptions {
                dir: dir.clone(),
                enable_dht: false,
                enable_dht6: false,
                ..Default::default()
            },
        },
        Some(writer.clone()),
    );

    // 1. 活跃 v1 非对齐 + 零长文件任务（piece_len = 16384，f0=10000 跨片到 f1=10000，f2=0 零长，f3=16384）
    let v1_unaligned = build_custom_v1_torrent(
        &dead_tracker(),
        "p0-1-v1-unaligned",
        16384,
        &[
            ("f0.bin", 10000, false),
            ("f1.bin", 10000, false),
            ("empty.bin", 0, false),
            ("f3.bin", 16384, false),
        ],
    );
    let gid_v1 = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: v1_unaligned,
                options: BTreeMap::from([("select-file".to_string(), "1".to_string())]),
                position: None,
            },
        )
        .await,
    );
    let g_v1 = gid_v1.to_string();
    wait_until(|| async {
        status_list(&call(&handle, SessionCommand::TellActive { keys: vec![] }).await)
            .iter()
            .any(|v| v.gid == gid_v1)
    })
    .await;

    // 活跃状态下修改已选文件 1 优先级 -> 仅文件 1 被选，f1/empty/f3 保持未选
    ok(
        call(
            &handle,
            SessionCommand::SetFilePriority {
                gid: g_v1.clone(),
                pairs: vec![(1, 6)],
            },
        )
        .await,
        "活跃 v1 任务局部更新优先级",
    );
    let v1_files = files_of(&call(&handle, SessionCommand::GetFiles { gid: g_v1.clone() }).await);
    assert_eq!(
        v1_files
            .iter()
            .map(|f| (f.selected, f.priority))
            .collect::<Vec<_>>(),
        vec![(true, 6), (false, -1), (false, -1), (false, -1)]
    );

    // 活跃状态下仅额外选中零长文件 3 -> 文件 2 和 4 仍未选
    ok(
        call(
            &handle,
            SessionCommand::SetFilePriority {
                gid: g_v1.clone(),
                pairs: vec![(3, 2)],
            },
        )
        .await,
        "活跃 v1 任务新增零长文件",
    );
    let v1_files2 = files_of(&call(&handle, SessionCommand::GetFiles { gid: g_v1.clone() }).await);
    assert_eq!(
        v1_files2
            .iter()
            .map(|f| (f.selected, f.priority))
            .collect::<Vec<_>>(),
        vec![(true, 6), (false, -1), (true, 2), (false, -1)]
    );

    // 2. 纯 v2 多文件（含零长文件）活跃任务
    let v2_bytes = build_multi_file_v2_torrent(
        &dead_tracker(),
        "p0-1-v2-multi",
        16384,
        &[("a.bin", 16384), ("zero.bin", 0), ("b.bin", 32768)],
    );
    let gid_v2 = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: v2_bytes,
                options: BTreeMap::from([("select-file".to_string(), "1".to_string())]),
                position: None,
            },
        )
        .await,
    );
    let g_v2 = gid_v2.to_string();
    wait_until(|| async {
        status_list(&call(&handle, SessionCommand::TellActive { keys: vec![] }).await)
            .iter()
            .any(|v| v.gid == gid_v2)
    })
    .await;
    ok(
        call(
            &handle,
            SessionCommand::SetFilePriority {
                gid: g_v2.clone(),
                pairs: vec![(1, 7)],
            },
        )
        .await,
        "活跃 v2 任务提高文件 1",
    );
    let v2_files = files_of(&call(&handle, SessionCommand::GetFiles { gid: g_v2.clone() }).await);
    assert_eq!(
        v2_files
            .iter()
            .map(|f| (f.selected, f.priority))
            .collect::<Vec<_>>(),
        vec![(true, 7), (false, -1), (false, -1)]
    );

    // 3. 大文件数量（1000 文件）：全选状态下仅提高 1 个文件不应膨胀 selected_files 或 file_priorities
    let names: Vec<String> = (0..1000).map(|i| format!("f{i:04}.bin")).collect();
    let specs: Vec<(&str, usize, bool)> = names.iter().map(|s| (s.as_str(), 16, false)).collect();
    let large_bytes = build_custom_v1_torrent(&dead_tracker(), "p0-1-large", 16384, &specs);
    let gid_large = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: large_bytes,
                options: BTreeMap::from([
                    ("pause".to_string(), "true".to_string()),
                    ("select-file".to_string(), "1".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    ok(
        call(
            &handle,
            SessionCommand::SetFilePriority {
                gid: gid_large.to_string(),
                pairs: vec![(1, 7)],
            },
        )
        .await,
        "1000 文件任务局部设置优先级",
    );
    let large_saved = PersistedTaskConfig::from_json(&read_config_json(&db, &gid_large));
    assert_eq!(large_saved.selected_files, Some(vec![0]));
    assert_eq!(
        large_saved.file_priorities.as_deref(),
        Some(&[(0u32, 7i8)][..]),
        "大文件任务只选 1 个文件时，file_priorities 应保持稀疏而非写入 999 条 -1"
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin).await;
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// P0-2 核心回归：SQLite 触发器拒绝 torrent 更新时，setSchedulerPolicy 必须报错且不污染镜像；
/// 清除故障后重试成功，崩溃重启后持久化生效，且重复请求幂等并保持原 GID 与文件选择不变。
#[tokio::test]
async fn scheduler_policy_persist_failure_rejects_and_keeps_mirror_and_restart_consistent() {
    let db = tmp_db("p0-2-sched-persist-fail");
    let dir = temp_dir("p0-2-sched-persist-fail");
    let bytes = build_custom_v1_torrent(
        &dead_tracker(),
        "p0-2-sched",
        16384,
        &[("a.bin", 16384, false), ("b.bin", 16384, false)],
    );

    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "启动 writer 1");
    let (handle, join) = SessionActor::spawn_with_persist(
        SessionOptions {
            global: GlobalOptions {
                dir: dir.clone(),
                enable_dht: false,
                enable_dht6: false,
                ..Default::default()
            },
        },
        Some(writer.clone()),
    );

    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: bytes,
                options: BTreeMap::from([
                    ("pause".to_string(), "true".to_string()),
                    ("select-file".to_string(), "1".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let g = gid.to_string();

    // 注入 SQLite UPDATE 拒绝触发器
    {
        let conn = ok(rusqlite::Connection::open(&db), "打开 DB 注入触发器");
        ok(
            conn.execute_batch(
                "CREATE TRIGGER reject_torrent_update BEFORE UPDATE ON torrent \
                 BEGIN SELECT RAISE(ABORT, 'injected-persist-failure'); END;",
            ),
            "创建拒绝触发器",
        );
    }

    let seq: crate::engine::SchedulerPolicy =
        "sequential".parse().unwrap_or_else(|e| panic!("{e}"));
    let res = call(
        &handle,
        SessionCommand::SetSchedulerPolicy {
            gid: g.clone(),
            policy: seq.clone(),
        },
    )
    .await;
    assert!(
        matches!(res, Err(SessionError::Failed { .. })),
        "持久化被拒绝时 setSchedulerPolicy 不得返回成功，实际: {res:?}"
    );

    // 内存镜像不得提前宣称成功
    let live = policy_of(
        call(
            &handle,
            SessionCommand::GetSchedulerPolicy { gid: g.clone() },
        )
        .await,
    );
    assert_eq!(
        live.name(),
        "rarest_first",
        "持久化失败后实时查询必须仍为旧策略 rarest_first"
    );
    let stored = PersistedTaskConfig::from_json(&read_config_json(&db, &gid));
    assert!(stored.scheduler_policy.is_none(), "DB 中不应残留新策略");
    assert_eq!(stored.selected_files, Some(vec![0]), "文件选择不得被破坏");

    // 清除故障触发器并重试
    {
        let conn = ok(rusqlite::Connection::open(&db), "打开 DB 移除触发器");
        ok(
            conn.execute_batch("DROP TRIGGER reject_torrent_update;"),
            "移除拒绝触发器",
        );
    }

    ok(
        call(
            &handle,
            SessionCommand::SetSchedulerPolicy {
                gid: g.clone(),
                policy: seq.clone(),
            },
        )
        .await,
        "故障清除后重试 setSchedulerPolicy 应成功",
    );
    assert_eq!(
        policy_of(
            call(
                &handle,
                SessionCommand::GetSchedulerPolicy { gid: g.clone() },
            )
            .await
        )
        .name(),
        "sequential"
    );

    // 模拟收到回包前进程崩溃（不走 shutdown/saveSession），重启核对持久化结果
    simulate_crash_stop(handle, join, writer, wjoin).await;

    let (writer2, wjoin2) = ok(PersistWriter::spawn(db.clone()).await, "启动 writer 2");
    let (handle2, join2) = SessionActor::spawn_with_persist(
        SessionOptions {
            global: GlobalOptions {
                dir: dir.clone(),
                enable_dht: false,
                enable_dht6: false,
                ..Default::default()
            },
        },
        Some(writer2.clone()),
    );
    assert_eq!(
        policy_of(
            call(
                &handle2,
                SessionCommand::GetSchedulerPolicy { gid: g.clone() },
            )
            .await
        )
        .name(),
        "sequential",
        "崩溃重启后策略必须已落盘为 sequential"
    );

    // 幂等重复请求，并核对原 GID 与文件选择保持不变
    ok(
        call(
            &handle2,
            SessionCommand::SetSchedulerPolicy {
                gid: g.clone(),
                policy: seq,
            },
        )
        .await,
        "重启后重复相同请求应幂等成功",
    );
    let restored_files =
        files_of(&call(&handle2, SessionCommand::GetFiles { gid: g.clone() }).await);
    assert_eq!(
        restored_files
            .iter()
            .map(|f| f.selected)
            .collect::<Vec<_>>(),
        vec![true, false],
        "原文件选择在故障与重试后必须保持不变"
    );

    handle2.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join2).await;
    drop(writer2);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin2).await;
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// P0-2 回归：setFilePriority / setDiskTier / changeOption / addTracker / removeTracker / changeUri
/// 在 SQLite 拒绝更新时全部必须报错且零污染内存镜像，故障清除后可重试成功并经崩溃重启保留。
#[tokio::test]
async fn config_mutation_commands_reject_atomically_on_persist_failure() {
    let db = tmp_db("p0-2-all-config-cmds");
    let dir = temp_dir("p0-2-all-config-cmds");
    let bytes = build_custom_v1_torrent(
        &dead_tracker(),
        "p0-2-all",
        16384,
        &[("a.bin", 16384, false), ("b.bin", 16384, false)],
    );

    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "启动 writer 1");
    let (handle, join) = SessionActor::spawn_with_persist(
        SessionOptions {
            global: GlobalOptions {
                dir: dir.clone(),
                enable_dht: false,
                enable_dht6: false,
                ..Default::default()
            },
        },
        Some(writer.clone()),
    );

    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: bytes,
                options: BTreeMap::from([
                    ("pause".to_string(), "true".to_string()),
                    ("select-file".to_string(), "1".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let g = gid.to_string();

    // 注入 SQLite UPDATE 拒绝触发器
    {
        let conn = ok(rusqlite::Connection::open(&db), "打开 DB 注入触发器");
        ok(
            conn.execute_batch(
                "CREATE TRIGGER reject_all_cfg BEFORE UPDATE ON torrent \
                 BEGIN SELECT RAISE(ABORT, 'injected-all-cfg-fail'); END;",
            ),
            "创建拒绝触发器",
        );
    }

    // 1. setFilePriority 必须失败且不改文件优先级/选择
    assert!(matches!(
        call(
            &handle,
            SessionCommand::SetFilePriority {
                gid: g.clone(),
                pairs: vec![(1, 7)],
            },
        )
        .await,
        Err(SessionError::Failed { .. })
    ));
    let files = files_of(&call(&handle, SessionCommand::GetFiles { gid: g.clone() }).await);
    assert_eq!(
        files
            .iter()
            .map(|f| (f.selected, f.priority))
            .collect::<Vec<_>>(),
        vec![(true, 0), (false, -1)],
        "setFilePriority 落盘失败后镜像不得变化"
    );

    // 2. setDiskTier 必须失败且不改 disk tier
    assert!(matches!(
        call(
            &handle,
            SessionCommand::SetDiskTier {
                gid: g.clone(),
                tier: taiji_store::disk_policy::DiskTier::SsdProtect,
            },
        )
        .await,
        Err(SessionError::Failed { .. })
    ));
    match call(&handle, SessionCommand::GetDiskTier { gid: g.clone() }).await {
        Ok(CommandReply::DiskTier { tier }) => {
            assert_eq!(
                tier,
                taiji_store::disk_policy::DiskTier::Throughput,
                "setDiskTier 落盘失败后镜像必须仍为默认 Throughput"
            );
        }
        other => panic!("期望 DiskTier，实际: {other:?}"),
    }

    // 3. changeOption(select-file="1,2", seed-ratio="3.5") 必须失败且镜像全不变
    assert!(matches!(
        call(
            &handle,
            SessionCommand::ChangeOption {
                gid: g.clone(),
                options: BTreeMap::from([
                    ("select-file".to_string(), "1,2".to_string()),
                    ("seed-ratio".to_string(), "3.5".to_string()),
                ]),
            },
        )
        .await,
        Err(SessionError::Failed { .. })
    ));
    let files_after_opt =
        files_of(&call(&handle, SessionCommand::GetFiles { gid: g.clone() }).await);
    assert_eq!(
        files_after_opt
            .iter()
            .map(|f| f.selected)
            .collect::<Vec<_>>(),
        vec![true, false],
        "changeOption 落盘失败后 select-file 镜像不得变化"
    );

    // 4. addTracker 必须失败且 announceList 不变
    assert!(matches!(
        call(
            &handle,
            SessionCommand::AddTracker {
                gid: g.clone(),
                urls: vec!["http://tracker.example/announce".to_string()],
                position: None,
            },
        )
        .await,
        Err(SessionError::Failed { .. })
    ));
    let st_after_trk = status_of(&handle, &g).await;
    let announces: Vec<String> = st_after_trk
        .bittorrent
        .as_ref()
        .map(|bt| bt.announce_list.iter().flatten().cloned().collect())
        .unwrap_or_default();
    assert!(
        !announces
            .iter()
            .any(|u| u == "http://tracker.example/announce"),
        "addTracker 落盘失败后 announceList 不得包含新 tracker"
    );

    // 5. changeUri (webseed) 必须失败且不改 webseeds
    assert!(matches!(
        call(
            &handle,
            SessionCommand::ChangeUri {
                gid: g.clone(),
                file_index: 1,
                del_uris: vec![],
                add_uris: vec!["https://mirror.example/file".to_string()],
                pos: None,
            },
        )
        .await,
        Err(SessionError::Failed { .. })
    ));
    let files_after_uri =
        files_of(&call(&handle, SessionCommand::GetFiles { gid: g.clone() }).await);
    assert!(
        files_after_uri[0].uris.is_empty(),
        "changeUri 落盘失败后 webseed 不得生效"
    );

    // 移除触发器，逐一重试并验证崩溃重启后均持久保留
    {
        let conn = ok(rusqlite::Connection::open(&db), "移除触发器");
        ok(
            conn.execute_batch("DROP TRIGGER reject_all_cfg;"),
            "移除拒绝触发器",
        );
    }

    ok(
        call(
            &handle,
            SessionCommand::SetFilePriority {
                gid: g.clone(),
                pairs: vec![(1, 7)],
            },
        )
        .await,
        "重试 setFilePriority",
    );
    ok(
        call(
            &handle,
            SessionCommand::SetDiskTier {
                gid: g.clone(),
                tier: taiji_store::disk_policy::DiskTier::SsdProtect,
            },
        )
        .await,
        "重试 setDiskTier",
    );
    ok(
        call(
            &handle,
            SessionCommand::AddTracker {
                gid: g.clone(),
                urls: vec!["http://tracker.example/announce".to_string()],
                position: None,
            },
        )
        .await,
        "重试 addTracker",
    );
    ok(
        call(
            &handle,
            SessionCommand::ChangeUri {
                gid: g.clone(),
                file_index: 1,
                del_uris: vec![],
                add_uris: vec!["https://mirror.example/file".to_string()],
                pos: None,
            },
        )
        .await,
        "重试 changeUri",
    );

    simulate_crash_stop(handle, join, writer, wjoin).await;

    let (writer2, wjoin2) = ok(PersistWriter::spawn(db.clone()).await, "启动 writer 2");
    let (handle2, join2) = SessionActor::spawn_with_persist(
        SessionOptions {
            global: GlobalOptions {
                dir: dir.clone(),
                enable_dht: false,
                enable_dht6: false,
                ..Default::default()
            },
        },
        Some(writer2.clone()),
    );
    let restored_files =
        files_of(&call(&handle2, SessionCommand::GetFiles { gid: g.clone() }).await);
    assert_eq!(
        restored_files
            .iter()
            .map(|f| (f.selected, f.priority))
            .collect::<Vec<_>>(),
        vec![(true, 7), (false, -1)]
    );
    assert_eq!(restored_files[0].uris.len(), 1, "重启后 webseed 应保留");
    match call(&handle2, SessionCommand::GetDiskTier { gid: g.clone() }).await {
        Ok(CommandReply::DiskTier { tier }) => {
            assert_eq!(tier, taiji_store::disk_policy::DiskTier::SsdProtect);
        }
        other => panic!("期望 SsdProtect，实际: {other:?}"),
    }
    let st2 = status_of(&handle2, &g).await;
    assert!(st2.bittorrent.as_ref().is_some_and(|bt| {
        bt.announce_list
            .iter()
            .flatten()
            .any(|u| u == "http://tracker.example/announce")
    }));

    handle2.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join2).await;
    drop(writer2);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin2).await;
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// P0-2 对抗测试：活跃任务上持久化被拒绝时，setSchedulerPolicy 与 setFilePriority 均报错，
/// 且运行中引擎、内存镜像、原 GID 与文件选择全部保持原状不受干扰；故障恢复后正常提交并经崩溃重启保留。
#[tokio::test]
async fn active_task_persist_failure_leaves_running_task_and_mirror_intact() {
    let db = tmp_db("p0-2-active-persist-fail");
    let dir = temp_dir("p0-2-active-persist-fail");
    let bytes = build_custom_v1_torrent(
        &dead_tracker(),
        "p0-2-active",
        16384,
        &[("a.bin", 16384, false), ("b.bin", 16384, false)],
    );

    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "启动 writer 1");
    let (handle, join) = SessionActor::spawn_with_persist(
        SessionOptions {
            global: GlobalOptions {
                dir: dir.clone(),
                enable_dht: false,
                enable_dht6: false,
                ..Default::default()
            },
        },
        Some(writer.clone()),
    );

    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: bytes,
                options: BTreeMap::from([("select-file".to_string(), "1".to_string())]),
                position: None,
            },
        )
        .await,
    );
    let g = gid.to_string();
    wait_until(|| async {
        status_list(&call(&handle, SessionCommand::TellActive { keys: vec![] }).await)
            .iter()
            .any(|v| v.gid == gid)
    })
    .await;

    {
        let conn = ok(rusqlite::Connection::open(&db), "注入触发器");
        ok(
            conn.execute_batch(
                "CREATE TRIGGER reject_active_cfg BEFORE UPDATE ON torrent \
                 BEGIN SELECT RAISE(ABORT, 'active-persist-fail'); END;",
            ),
            "创建拒绝触发器",
        );
    }

    let seq: crate::engine::SchedulerPolicy =
        "sequential".parse().unwrap_or_else(|e| panic!("{e}"));
    assert!(matches!(
        call(
            &handle,
            SessionCommand::SetSchedulerPolicy {
                gid: g.clone(),
                policy: seq.clone(),
            },
        )
        .await,
        Err(SessionError::Failed { .. })
    ));
    assert!(matches!(
        call(
            &handle,
            SessionCommand::SetFilePriority {
                gid: g.clone(),
                pairs: vec![(1, 7)],
            },
        )
        .await,
        Err(SessionError::Failed { .. })
    ));

    // 任务仍处于活跃态，策略与文件选择/优先级均未改变
    let active = status_list(&call(&handle, SessionCommand::TellActive { keys: vec![] }).await);
    assert!(
        active.iter().any(|v| v.gid == gid),
        "活跃任务不应因配置写库失败而退出"
    );
    assert_eq!(
        policy_of(
            call(
                &handle,
                SessionCommand::GetSchedulerPolicy { gid: g.clone() },
            )
            .await
        )
        .name(),
        "rarest_first"
    );
    let files = files_of(&call(&handle, SessionCommand::GetFiles { gid: g.clone() }).await);
    assert_eq!(
        files
            .iter()
            .map(|f| (f.selected, f.priority))
            .collect::<Vec<_>>(),
        vec![(true, 0), (false, -1)]
    );

    // 移除触发器后重试，确认活跃任务上可正常更新并在崩溃重启后持久保留
    {
        let conn = ok(rusqlite::Connection::open(&db), "移除触发器");
        ok(
            conn.execute_batch("DROP TRIGGER reject_active_cfg;"),
            "移除拒绝触发器",
        );
    }
    ok(
        call(
            &handle,
            SessionCommand::SetSchedulerPolicy {
                gid: g.clone(),
                policy: seq,
            },
        )
        .await,
        "故障恢复后活跃任务 setSchedulerPolicy 应成功",
    );
    ok(
        call(
            &handle,
            SessionCommand::SetFilePriority {
                gid: g.clone(),
                pairs: vec![(1, 7)],
            },
        )
        .await,
        "故障恢复后活跃任务 setFilePriority 应成功",
    );

    simulate_crash_stop(handle, join, writer, wjoin).await;

    let (writer2, wjoin2) = ok(PersistWriter::spawn(db.clone()).await, "启动 writer 2");
    let (handle2, join2) = SessionActor::spawn_with_persist(
        SessionOptions {
            global: GlobalOptions {
                dir: dir.clone(),
                enable_dht: false,
                enable_dht6: false,
                ..Default::default()
            },
        },
        Some(writer2.clone()),
    );
    assert_eq!(
        policy_of(
            call(
                &handle2,
                SessionCommand::GetSchedulerPolicy { gid: g.clone() },
            )
            .await
        )
        .name(),
        "sequential"
    );
    let restored = files_of(&call(&handle2, SessionCommand::GetFiles { gid: g.clone() }).await);
    assert_eq!(
        restored
            .iter()
            .map(|f| (f.selected, f.priority))
            .collect::<Vec<_>>(),
        vec![(true, 7), (false, -1)]
    );

    handle2.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join2).await;
    drop(writer2);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin2).await;
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}
