# taiji–aria2 差异声明（RPC / 选项面 · v1.1）

[English](./rpc-api-diff.md) | 简体中文

> 本文档为翻译版；与英文原版不一致时，以 [英文原版](./rpc-api-diff.md) 为准
>（英文原版是受治理测试钉住的规范本体）。

本文件是 taiji 引擎与 aria2 之间**全部已知行为差异的受控清单（白名单）**
（退役对照方为 aria2 fork，下文称 "the fork"）。治理规则：

- 全量 RPC/选项差分的门禁判据 = **白名单之外零差异**；未列入本文件的任何
  差异均视为缺陷，必须在代码中修复或修订本文件（经 PR + 用户批准）。
- 交叉验证方法：同输入的双进程实测交叉验证 —— taiji 以 `--rpc-aria2-compat`
  模式 + sqlite 持久化运行（Motrix 运行时形态；方法/事件名与 the fork 严格
  同构，任一时刻只有一个 API 面），the fork 以
  `--enable-rpc --enable-sqlite3-persistence` 启动（Motrix 运行时形态）；
  同一 fixture、同一参数，逐方法比对响应形态/错误码/错误消息/事件名。
  可复现性守卫 = 集成测试 `crates/taiji-rpc/tests/aria2_compat_live_diff.rs`
  （参考二进制经 `TAIJI_DIFF_ARIA2C` 环境变量指定；默认按序探测工作区同级
  检出 `aria2/src/aria2c`（上游布局）与 Motrix fork 布局 `aria2_motrix/src/aria2c`；
  **不可用时测试默认红** —— 零比对绝不允许宣称全绿差分；只有显式
  `TAIJI_DIFF_ALLOW_SKIP=1` 才降级为 SKIP 绿，输出中带机读标记
  `SKIP(taiji.rpc.live-diff): …`，降级消费方必须一并核查）。源码级静态
  交叉验证（只读 `src/` 引用）是第二证据线。
- 每一条目均标注仓内**代码锚点**（声明的单一来源）；条目集与锚点的双向
  完备性由差分测试核查。

## 1. API 面

| 条目 | fork 行为 | taiji 行为 | 锚点 |
|---|---|---|---|
| 命名空间 | `aria2.*` | 规范名 = `taiji.*`；开启 `--rpc-aria2-compat`（默认 false，会话级）= `aria2.*` 别名 + `aria2.onXxx` 事件 + listMethods/listNotifications 呈现 aria2 面（成员集在承诺内；表序不在）；**任一时刻只存在一个 API 面；禁止双发** | `taiji-rpc::dispatch`（`canonical_method` 单点） |
| 方法面缺失条目（4 个名字 = fork 独有的 sqlite3 族；`changePosition`、`getOption`、`forcePauseAll` 此后已加入已提交集；**2 个 cookie 族名字此后已反转进入接受**） | fork 独有新增（fork 检出的 `RpcMethodFactory.cc` `HAVE_SQLITE3` 族，上游没有；sqlite3 下载记录面扩展）：`getDownloadResultCount`（空参返回 `{"count":"0"}`）/ `searchDownloadResult` / `exportSession` / `requeueDownloadResult` | 已提交集状态：4 个 sqlite3 族名字不在已提交集；兼容面调用落到 `"No such method: aria2.X"`（token 认证先行，与 the fork 相同）。**白名单治理项：4 个 fork 独有 sqlite3 族名字是否接受仍待用户批准（接受 = 扩张已提交集 + 新 ADR）** | `taiji-rpc::dispatch::tests`（已提交集 = 参考注册面 - 4 个缺失名字 + `taiji.*` 扩展） |
| 任务级 cookie 族已接受（早期立场的反转，Motrix 基线；`addUriWithCookies`/`setTaskCookies`） | the fork 的同名 `aria2.*` 方法对（`RpcMethodFactory.cc`；`parseRpcCookies` = `RpcCookie.cc`：≤300 条 / 字段白名单 name,value,domain,path,hostOnly,secure,httpOnly,expiresAt / 语法域校验 / 过期时刻 = 非负 Unix 毫秒 ≤2^53-1 / 过期记录绝不进入活动存储；`AddUriWithCookies` = 对全部 URI 的 http（s）-only 门 + 结构化 cookie 权威（手工 `Cookie:` header 被剥离，`RpcMethodImpl.cc`）；`SetTaskCookies` = 仅限等待/暂停 + `require-task-cookies` 位 + sqlite 持久化优先） | **已接受（2026-10-04 用户反转 —— 原决定的前提已不成立：存储已存在而入口全空，"同一需求无人认领"）**；规范单名 `taiji.addUriWithCookies`/`taiji.setTaskCookies`（14→16 个名字）：参数面对 `parseRpcCookies` 逐字交叉验证（crate `taiji-rpc::rpc_cookies`）；cookie 进入任务 CookieStore（与 `--load-cookies` 同一存储面，经 taiji-http 的 `CookieStore::seed/replace_with` 缝注入）；`.torrent` URL 摄入收紧为拒绝（元数据抓取面没有 cookie 消费点）。`setTaskCookies` 状态门 = 等待/暂停 + HTTP 任务形态（the fork 还要求 `require-task-cookies` 偏好位 —— 其任务存储是 opt-in，而本侧 HTTP 任务恒带存储；等价面放宽，声明为差异）；持久化 = cookie 行 upsert（与 the fork 的 replaceTaskCookies 交叉验证；持久化优先失败 = 零变更）。两方法均为写面方法（未设 secret 时被写门拒绝）。**兼容面不投影 `aria2.*` 别名** —— the fork 同名调用恒落 `"No such method"`（由实测差分钉住） | `taiji-rpc::rpc_cookies`（解析缝）+ `taiji-rpc::dispatch::tests`（`taiji_cookie_methods_shape_receipts_and_gates`）+ `taiji-core::session::actor::tests`（`add_uri_with_cookies_*`/`set_task_cookies_*`） |
| `taiji.*` 扩展方法（17 个名字） | 无 | `moveStorage`/`renameFile`/`banAddr`/`unbanAddr`/`listBans`/`setSchedulerPolicy`/`getSchedulerPolicy`/`setFilePriority`/`setStreamingPlayhead`/`getDiskTier`/`setDiskTier`/`getCapabilities`/`createTorrent`/`addTracker`/`removeTracker`/`addUriWithCookies`/`setTaskCookies` —— 两种模式下同名存在（`setFilePriority` = HTTP 任务的多级文件优先级 —— 对齐 libtorrent 的 `file_priority`/`prioritize_files` 能力的原生扩展：值域 -1/0/1..7 原生设定（aria2 无对应面）；部分更新的 pairs 形式与全量向量形式声明为差异；-1 与 select-file 选择面可组合）（`addTracker`/`removeTracker` = HTTP 任务的方案 B 动态 tracker 编辑；`addUriWithCookies`/`setTaskCookies` = HTTP 任务的结构化 cookie 直达面 —— 见上方专属条目；兼容面不投影 `aria2.*` 别名：前两个方法 fork 无对应物，后两个方法 the fork 上存在但按 §1 决定以 `taiji.*` 规范名接受） | `taiji-core::session`（`RPC_METHODS`） |
| **方法面新增：`forceRecheck`（上游无对应物）** | 无（上游 aria2 1.37.0 与 the fork 的注册面都没有 recheck RPC —— the fork 的在册面 = 36 个上游 + 4 个 fork 独有新增，无此名；调用落 `"No such method: aria2.forceRecheck"`） | taiji 能力扩展（**不是**承诺收紧）：裸名 `forceRecheck` 已注册；规范 `taiji.forceRecheck` / 兼容 `aria2.forceRecheck` / 裸名 —— 三种形式均接受，同名同义。语义：仅限 torrent 任务（magnet / metadata / HTTP 任务与终态条目显式 Err；无持久化形态时显式 Err）；活动 = 优雅停机（pause 收尾语义）→ 全量校验 → 重新入队激活；保留/暂停 = 出队校验后回到队头（保留暂停意图）；校验期间 `torrent.state='checking'`（与崩溃恢复同形）+ TellStatus `status=active`、`completedLength` 投影为已校验 piece 数 × piece_length（aria2 校验期没有独立状态值；同向交叉验证）；完成后实测位图写回进度行（损坏 piece 清零重下，完整 payload 转做种），回执 = gid。aria2 生态的 recheck 补救面（`--check-integrity` / 重新添加）由此 RPC 化 | `taiji-core::session`（`RPC_METHODS`/`SessionCommand::ForceRecheck`）、`taiji-core::session::actor::tasks`（`force_recheck`/`spawn_recheck`/`finish_recheck`）、`taiji-rpc::dispatch::tests`（`PROMISED_TAIJI_BARE_EXTENSIONS`） |
| **媒体线方法（5 个名字，统一媒体注册）** | 无（上游 aria2 无媒体面；the fork 亦然） | `taiji.addMedia(url, options?)` / `taiji.probeMedia(url)` / `taiji.getMediaFormats(gid)` / `taiji.stopRecording(gid)` / `taiji.clearMediaArchive()` —— 两种模式下同名存在（不投影 `aria2.*` 别名；无裸名形式 —— 带点扩展字面量）。read_only 判定（§9）：addMedia **写** / probeMedia **写**（§4 的探测是动作面 —— 一次外发请求 + 服务端快照缓存；无 secret = fail-closed，与写面同一姿态）/ getMediaFormats **读** / stopRecording **写** / clearMediaArchive **写**（对下载档案表的破坏性整表清空 —— 敏感度等同浏览记录的面；无 secret = fail-closed，purge 族规则；答复 `{"removed": N}`；清空后同一指纹会重新下载）。addMedia 选项 = 选择器三层面（`media-selector`：预设/谓词/`format_id=` 逃生门，多值 = 显式多流）+ 字幕/元数据/模板 + 结构化 cookie 直达（`options.cookies`，与 `parseRpcCookies` 交叉验证的形态）+ `probe-token`（服务端快照检索 —— 绝不接受客户端提交的格式树 blob，§4 防伪）；条目分类在任务的 Resolving 阶段运行（直链媒体文件以同一 GID 转入 HTTP 任务族 —— 零新面规则；非媒体条目 = `taiji.media.not_media`）。probeMedia 返回不透明 token + TTL 10 分钟（过期/未知/不匹配 = `taiji.media.probe_expired`）；全局在途上限 2 + 每源站限速（1/s）。getMediaFormats = media_format 行查询（行驱动 —— 终态拆解后也能应答）。stopRecording = 仅注册 + 分发（0.3 的 VOD 任务答显式 "not a recording task" 错误；LIVE 执行器落 0.4） | `taiji-core::session::command`（`RPC_METHOD_INFO` 描述符 + 冻结锚点测试）+ `taiji-core::session::actor`（`add_media`/`spawn_probe`/`get_media_formats`/`stop_recording`）+ `crates/taiji-core/tests/media_task_e2e.rs` |
| **addTorrent 对完整 payload 的初始校验** | 当 addTorrent 指向目录且 payload 已完整时，the fork 经其既有存储探测续传（位图/控制文件存在时）；taiji 的对照面（无控制文件的外部 payload）从零重下 | taiji 为外部已完整 payload 安排**初始全量校验**（目录中文件与种子逐文件长度吻合、未暂停、有会话库）：`torrent.state='checking'` → 实测位图写回进度行 → 重新入队激活，引擎按位图续传（完整 = `completedLength==totalLength` → `seed_after_complete` 转做种）。部分/缺失 payload 照常从零下载（规格范围 = 完整 payload）。the fork 的分叉交叉验证行为源于其控制文件机制与 taiji 的 sqlite 位图续传面结构不同；这是存储形态差异的追赶面 | `taiji-core::session::actor::tasks`（`add_torrent` 的 `payload_complete` 门 + `spawn_recheck`） |
| 扩展事件 | 无 | `taiji.recoveryStarted`/`taiji.recoveryCompleted`（恒 `taiji.*`，绝不经 compat 切换）；**`taiji.media.phaseChanged`**（同一旁路：不在 compat 开关内、不在六事件表内，`system.listNotifications` 不增长；payload `[{gid, phase, phaseDetail?, warning?{code,message}}]` —— 媒体线的告警（边车降级 / 双通道失败 / 边车拼接失败，`template_unsafe`）搭乘同一面，以 `warning` 键区分告警与阶段迁移；经 `taiji.getCapabilities` 的 notifications 列表声明） | `taiji-core::session::events`（`MEDIA_PHASE_EVENT_METHOD`）+ `taiji-rpc::server`（`media_notification_frame`，WS 第三臂） |
| 六个事件名 | `aria2.onXxx` | 兼容面逐字相同（现场 `system.listNotifications` 交叉验证，零差异）；规范面 = `taiji.onXxx`；`[{gid}]` payload 不变 | `taiji-rpc::dispatch`（`RPC_NOTIFICATIONS_ARIA2`） |
| 裸名接受 | 裸名（`addUri`）= 未知方法：`"No such method: addUri"`（the fork 只接受注册全名） | 规范已提交面恒接受裸名（Phase A 承诺，compat 模式下保留）—— taiji 超集：同一方法接受 `aria2.X` 别名、`taiji.X` 别名与裸名三种形式 | `taiji-rpc::dispatch`（`canonical_method` 精确匹配臂） |
| 未认证写门 | 未设 `--rpc-secret` 时，写方法照常执行（仅回环监听） | 未设凭据时**全部写方法 fail-closed**（`"unauthenticated write requires --rpc-secret"`；查询面与 `system.list*` 不受限）—— 安全增强 | `taiji-rpc::dispatch`（`is_read_only`/写门） |
| 模式面（RPC 与下载形态的三态） | 三态：纯下载（无 `--enable-rpc`）/ 纯守护（`--enable-rpc`，无 URI）/ **下载 + RPC 同进程**（`--enable-rpc` 与 CLI URI/种子共存 —— `DownloadEngineFactory.cc` 的 enable-rpc 分支不参数化 URI 是否存在；RPC 监听器装配与下载循环在同一进程执行；`PREF_ENABLE_RPC` 默认 false，`OptionHandlerFactory.cc`）。该选项关闭时给出的 RPC 组选项被静默存储但不用 | 三态，同形：纯下载（裸引擎循环运行，`--enable-rpc=false` 默认 —— 该路径零行为变化）/ 纯守护（无位置参数 = 空闲，RPC 恒开）/ 下载 + RPC（`--enable-rpc`：引擎路径与空闲态共享同一 SessionActor 管线；种子作为 AddTorrent 会话命令**直接**注入 —— 无 RPC 自调用，绕过写门与凭据要求，与上游引擎内直接配置同构（经交叉验证）；任务做种并驻留，进程驻留至信号/RPC 关停）。**静默 no-op 已移除（收紧声明）**：下载模式在 `--enable-rpc` 未生效时收到 RPC 组选项（`rpc-listen-port`/`rpc-secret`/`rpc-user`/`rpc-passwd`/`rpc-aria2-compat`）→ 硬错误退出码 2（stderr，与 clap 用法错误同流同码，措辞指向添加 `--enable-rpc`）—— 上游对此组合静默存储不用 | `taiji::main`（`run_download_with_rpc`/`rpc_group_conflict`）+ `crates/taiji/tests/download_rpc_e2e.rs`（生命周期 e2e / 裸运行快照 / 冲突臂） |
| `changeUri` 语义（方案 A 收束） | file-entry URI 编辑（`RpcMethodImpl.cc` = file-entry 的 `removeUri`/`insertUri`/`addUri`；臂序：gid 未命中逐字答 `"Cannot remove URIs from GID#%s"`（`findGroup` 排除终态）→ fileIndex 域校验逐字答 `"fileIndex is out of range"` → 计数回执 `[deleted, added]`；BT 文件条目无 URI 清单 → 删除臂得 `[0,0]`，添加臂将可解析 URI 入队并计 `[0,N]`（`FileEntry.cc` 无协议分叉 —— 由 webseed 面消费）；HTTP = 真源台账编辑（`FileEntry.cc` 命中即删并撤回在途请求） | 同臂序、同逐字错误消息（fileIndex 域随任务形态的文件条目数：Torrent = metainfo 文件条目，magnet/TorrentUrl/Http = 1）；**缺口声明**：本侧无 file-entry URI 台账（BEP19 webseed 不消费 —— 在 addTorrent 面声明；在途 HTTP 源台账 = 驱动器的 sources，引擎面没有源变更缝）→ 每种形态都得 `[0,0]` 空操作 —— 上游真实的增/删计数（BT `[0,N]` / HTTP `[del,N]`）不在承诺内。被劫持的动态 tracker 编辑已移除（原 `apply_tracker_change` + `SetTrackers` 调用点已抽出）；tracker 编辑扩展面**已按方案 B 落地**（2026-10-04 用户批准）：`taiji.addTracker`/`removeTracker` 进入已提交集（§1 扩展行，12→14 个名字），机制复用既有 SetTrackers 引擎耦合 + config_json 持久化；API 面为全新设计 | `taiji-core::session::actor::commands.rs`（`change_uri` 臂序与锚点注记 + `add_tracker`/`remove_tracker` 编辑面）+ `taiji-rpc::dispatch::tests`（`change_uri_positional_shape_and_counts` + `taiji_tracker_methods_shape_receipts_and_gates`）+ `taiji-core::session::actor::tests`（`change_uri_upstream_file_entry_semantics` + `taiji_tracker_edit_*`） |

## 2. getVersion

- `version`：fork = 裸版本串（`1.37.0`）；taiji = `taiji/<semver>` 前缀
  （Motrix 以此前缀识别引擎 —— 切换断言的载体）。`{version, enabledFeatures}`
  形态两侧一致。
- `enabledFeatures`：taiji 出于**诚实**只列出真实能力（`Async DNS`/
  `BitTorrent`/`HTTP`/`HTTPS`/`GZip`/`Metalink`（特性门后，编译期如实
  呈现））；the fork 的清单含其自建面（`Firefox3 Cookie`/
  `Message Digest`/`XML-RPC`/`SQLite3-Persistence` 等）。两清单**不承诺
  相等**，只承诺每项皆真。
- 锚点：`taiji-rpc::dispatch::view`（`ENABLED_FEATURES`）。

## 3. 选项面（getGlobalOption / changeGlobalOption / changeOption）

- **回显面方向**：the fork 回显其完整全局选项表（约 130 键）；taiji 回显
  Phase A 已提交子集加下一条的扩展（约 30 键）。fork 独有键的全集由本条目
  声明；taiji 不承诺补齐全表回显。
- **taiji 独有回显键**（the fork 不回显）：Phase A 扩展/改名对
  （`bt-lsd`↔`bt-enable-lpd`、`bt-tracker-file`、`bt-peer-connection-type`、
  `bt-enable-upnp`、`bt-enable-nat-pmp`、`max-connection`、
  `client-ban-prefixes`、`bt-metadata-web-sources`），钩子通知族
  （`on-download-*`/`on-bt-download-complete`）、`save-session`、
  `seed-time`、`bt-tracker`（经 RPC 改全局值时 the fork 静默忽略此键；
  taiji 以并集累加导入并回显），加上 0.2 扩展键（HTTP 调度组 §8、
  `http-incomplete-suffix`/`http-max-per-host`、FTPS `ftp-ssl` §8、
  metalink 缝命名 §6），加上四池预算三件套（`max-concurrent-seeds`/
  `max-concurrent-checks`/`media-synthesis-concurrency`，见下方专属条目）
  —— **权威全集 = 锚点表**。锚点：`taiji-core::session::options`
  （`DECLARED_OPTION_DIFFS`）。
  其中 `http-max-per-host` 此后已实际进入 getGlobalOption 回显（回显 =
  生效上限值 —— 与会话 HostCap 初始化值及经 addUri 选项的最后设置胜出
  调整保持同步，零漂移；默认 64，r7.1；CLI/全局 `--http-max-per-host` 是
  启动期选项，changeGlobalOption 不接受，重启后生效）。
- **taiji 独有回显键、接受值面（2026-10-28 回显审计 —— 每键均裁定为正当
  扩展；实测差分预算 = 钉在 `crates/taiji-rpc/tests/aria2_compat_live_diff.rs`
  的已审计表；后续新增扩展四池预算三件套行）**：the fork 的
  `getGlobalOption` 只返回**已定义 pref**（`RpcMethodImpl.cc` 跳过全局
  选项表中不存在的条目；2026-10-28 实测验证 —— 默认启动回显 132 个已定义
  键，而 `all-proxy` 这类 NO_DEFAULT pref 只在命令行设置过才出现）。taiji
  则恒回显接受值面（空串 = 未设置）—— Motrix 对齐往返 —— 于是这些
  aria2 名键在默认交叉验证形态下为 taiji 独有：`all-proxy` / `https-proxy`
  （每任务代理槽位，；全局面记录该值 —— 无全局代理默认值消费缝）、
  `async-dns` / `enable-async-dns6`（解析器形态 no-op 值面，）、
  `bt-exclude-tracker`（无排除面 —— 值面记录 Motrix tracker 管理器占位
  符）、`pause`（无全局暂停模板面；参考无 changeGlobal 位 —— Motrix
  完结任务启动守卫值面）、`dht-entry-point`（启动组会话字段；未设置 =
  空串）、`load-cookies`（见下方专属条目）。
- **共享键值差异**（3 条 Phase A 声明 + Motrix 对齐 no-op 值面；2026-10-28
  回显审计）：
  - `listen-port`：fork 默认 `6881-6999`（区间）；taiji `6881`（单值）；
  - `peer-id-prefix`：fork `A2-1-37-0-`；taiji `-TJ0001-`（命名空间决策）；
  - `seed-ratio`：fork 默认字面量 `1.0`；taiji 最小数值形式 `1`（数值
    相等；回显取最小 f64 形式，不伪造精度）；
  - 与 the fork 回显共享的 Motrix 对齐 no-op 值面行（`connect-timeout`/
    `continue`/`max-connection-per-server`/`max-download-result`/
    `max-file-not-found`/`max-mmap-limit`/`max-resume-failure-tries`/
    `max-tries`/`min-split-size`/`remote-time`/`retry-wait`/`split`/
    `timeout`/`user-agent`）：未设置时的 no-op 值面回显空串（未记录覆盖
    —— 前端最后所发值的往返面），而 the fork 对同键回显其**已定义默认
    值**（默认值在那里是已定义 pref）；分叉方向 = 与上方 taiji 独有回显
    键同一接受值面族。
- **非法值语义**：`changeGlobalOption`/`changeOption` 收到已知键的非法值
  时，the fork 报错（`"We encountered a problem while processing the
  option '--X'."`）；taiji 收窄为**忽略**该键（与未知键同路径）。例外：
  HTTP 任务的越域调度值传入 `changeOption`（如
  `max-connection-per-server` 超出 1..64）被 taiji 显式拒绝
  （`taiji.option.invalid`，不截断）—— 增强语义。
- **`select-file`（BEP53 文件选择面；接受面差异有三个方向）**：fork =
  IntegerRangeOptionHandler（1 起、逗号 + 闭区间 `1-3,5`、域 1..1M；
  INITIAL + 保留期可变位，运行中不可改，`OptionHandlerFactory.cc`）；
  taiji 接受同一语义位（addTorrent / addUri（magnet） 选项 / changeOption
  Reserved（Paused）；内部数据面统一 0 起的 `config_json.selected_files`，
  与 magnet `so=` 共享持久化通道与引擎消费点 `SetFileSelection`）；显式
  声明三处收紧：（1） 已知键的非法值被整体拒绝 `taiji.option.invalid` ——
  空串/空段/含 0/越域/重复/失序/区间重叠或倒置/非十进制（the fork 只对
  非数值与不完整区间报错；重复与失序经 `SegList::normalize` 吸收，越界
  索引在建组 `setFileFilter` 后留下静默空过滤器，`download_helper.cc`）；
  （2） **对活动任务 changeOption = 显式拒绝**（the fork 视为不可改键而
  忽略，`RpcMethod.cc`）；（3） magnet `so=` 与此键并存 = 显式冲突拒绝
  （选择面单一来源；the fork 无 `so=` 面，故无对应行为）。另：对非 BT
  任务（HTTP/.torrent URL）changeOption 此键 = 显式拒绝（接受而不生效
  即是伪装）。实时重选（libtorrent 的 `prioritize_files`，任意时刻可用）
  列为 `taiji.*` 扩展候选，不属于本面。锚点：`taiji-core::session::options`
  （`parse_select_file`/`select_file_range_error`/`resolve_select_file_for_meta`
  单点族 + 语义差异声明块）。
- **`summary-interval`（周期性任务摘要日志间隔，秒；0.2 新接受）**：同名
  aria2 项（`prefs.cc`；`OptionHandlerFactory.cc` 默认 "60"、域
  0..INT32_MAX、0 = 关闭 —— taiji 同默认值同值域，以常量
  `SUMMARY_INTERVAL_DEFAULT`/`SUMMARY_INTERVAL_MAX` 为唯一来源）。taiji
  语义：每 N 秒会话为每个活动任务发一条 INFO 摘要（gid / 速度 / 进度 /
  连接数，target `taiji::core::summary`）；无活动任务的周期不发事件。
  载体差异（有意声明）：aria2 将摘要打印到控制台读数；taiji 无控制台
  读数，摘要 = tracing INFO 事件（前端与文件日志同一面）。**能力位与
  参考对齐：changeOption 与 changeGlobalOption 均不接受**（参考工厂的
  处理器无 setChangeOption/setChangeGlobalOption 位；taiji 的
  `apply_global_patch` 无此臂 —— 传入键按未知忽略）；启动期选项，重启
  后生效。接受面：CLI `--summary-interval`（`taiji` 空闲模式与
  `taiji http` 子命令；越域值启动时报错）+ getGlobalOption 回显。锚点：
  `taiji-core::session::options`（接受名注册 + 名/默认/域/能力位交叉验证
  测试）、`taiji-core::session::actor::summary`（摘要缝）、
  `taiji-rpc::dispatch::tests`（RPC 面 e2e：回显 + 不接受）。
- **`enable-dht`（会话级 DHT 热开关）**：上游 aria2 的 enable-dht 处理器
  **没有** `setChangeGlobalOption` 位（`OptionHandlerFactory.cc`）——
  the fork 无法热重载（重启后生效）；taiji **接受运行时热更新**
  （`changeGlobalOption` 值面 + 热推入运行中的 BT 引擎：DHT 引擎拉起/
  拆解、握手位与 announce 注册即时生效；一个停滞的无 tracker 任务在热
  启用后立即复活 —— 能力参考是 libtorrent 的
  `settings_pack::enable_dht` 经 `apply_settings` 在运行时生效）。
  **显式差异声明：taiji 扩展**（扩张 the fork 的不可变集）。`enable-dht6`
  作为同类键接受（值面回显 + 能力位视图）；taiji 没有独立的 v6 DHT 门
  （v6 DHT 面跟随 `enable-dht` 主门 + IPv6 连通性门；`enable-dht6` 当前
  不改变引擎接线 —— 如实声明）。锚点：`taiji-core::session::actor::commands`
  （`push_dht_session_change` + `effective_task_dht` 合成单点）、
  `taiji-core::engine::command`（`EngineCommand::SetDhtEnabled`）、
  `taiji-core::engine::dht`（`DhtInboundGate` 运行时门）。
- **`bt-sequential-download`（以投影形式接受）**：同名 aria2 选项
  （Initial + 保留期可变位）。该键 true/false 投影到调度策略
  sequential/rarest_first —— **权威面 = `taiji.setSchedulerPolicy`**
  （两个入口回显一致；`getOption` 从任务策略投影而非独立选项存储 ——
  投影面差异声明）；addTorrent/addMagnet 接受（经 patch_config 投影进
  `scheduler_policy` payload）；changeOption Reserved 面接受（活动时
  显式拒绝 —— 实时切换走策略 RPC；相对 aria2 对不可改键静默忽略的收紧
  与 select-file 同方式声明）；HTTP/.torrent URL 任务拒绝。CLI
  `--bt-sequential-download`（裸运行 = 引导后经 SetSchedulerPolicy 下发；
  download+rpc = 经 AddTorrent 选项注入）。
- **`bt-disable-dht`（任务级 DHT 旗标；taiji 独有键）**：上游 aria2 无
  每种子 DHT 面（DHTRegistry 是全局单例）—— 本侧映射到 libtorrent 的
  `torrent_flags::disable_dht`（经 `torrent_handle::set_flags/unset_flags`
  运行时翻转，src/torrent.cpp）：bool 值面，**默认跟随会话
  `enable-dht`**（None = 跟随）；显式 `true` 对该任务禁用 DHT / `false`
  对该任务强制开启；任务级值覆盖会话值，对活动任务热生效（引擎
  `SetDhtEnabled` 活臂 + 既有 changeOption 重启语义兜底）。接受面 =
  addTorrent/addUri（magnet/.torrent URL） 选项 + changeOption（Torrent/
  Magnet 任务；HTTP 任务该键无消费面 —— 与既有 BT 族选项先例一致，不
  显式拒绝）。**BEP27 不可覆盖**：私有任务的 DHT 交互即使
  `bt-disable-dht=false` 或会话热启用也保持禁止（引擎 enable 门拒绝；
  与 torrent.cpp `priv()` 同规则）。锚点：`taiji-core::session::options`
  （`DECLARED_OPTION_DIFFS` 白名单行 + `TaskOptionPatch.bt_disable_dht`）、
  `taiji-core::session::actor`（作业镜像 + `push_dht_task_change` +
  config_json `bt_disable_dht` 持久化）、`taiji-core::engine::run::arms`
  （SetDhtEnabled 臂）。
- **无 tracker + DHT 关闭的摄入语义（差异行翻转）**：原快速失败拒绝
  （`invalid metainfo`，退出码 1）已**移除** —— 恒接受（CLI 下载与会话
  addTorrent/URL 抓取升级同一门）；DHT 关 + 无 tracker = 接受 + WARN
  （停滞指引：热启用 DHT / 添加 tracker / 重启），与两参考对齐（aria2
  `RequestGroup.cc` 只 NOTICE；libtorrent 从不拒绝）。锚点：
  `taiji-core::metainfo`（`Metainfo::check_intake` → `Option<String>`
  WARN 面）。
- **未知键**：两侧同样忽略（`changeOption`/`changeGlobalOption`/`addUri`
  选项字典；实测交叉验证零差异）。CLI 命令行上，未知选项在 taiji 是
  **错误**（与 the fork 相同；特性关闭时 `--metalink-*` 报错并点名特性）。
- **选项三方分类**（接受立场的单一来源；`taiji-core::session::options`
  中四张表）：
  1. `ARIA2_OPTION_NAMES` —— 接受的 aria2 名（对 the fork 的 `prefs.cc`
     逐名交叉验证）；
  2. `DECLARED_OPTION_DIFFS` —— 白名单扩展/立场（治理 = PR + 用户批准）；
  3. `DECLARED_NON_ACCEPTED_OPTION_NAMES` —— aria2 有而本侧不接受的名字
     的定稿声明（分体代理族 / `save-cookies` / `allow-overwrite` /
     `auto-file-renaming` / `lowest-speed-limit` / `referer` /
     `http-accept-gzip` / `use-head` / keep-alive 族 / `follow-metalink` /
     `metalink-base-uri` / FTP 代理族，约 28 个名字；`ca-certificate`
     此后已移入接受面，`load-cookies` 此后已移入接受面 —— 见下方同名
     条目）；
  4. `DECLARED_UNWIRED_OPTION_NAMES` —— 规格中命名但 0.2 未接线的扩展项
     （`http-min-chunk`；该键按未知忽略）。
- `--continue`：反转语义显式声明 —— taiji 恒续传（`false` 不丢弃进度，
  由 CLI 警告披露；RPC 选项面无此键）。
- Cookie 面（收束后）：`--load-cookies` **已接受**（下方 load-cookies
  条目）+ 两个任务级 cookie 直达方法已接受（§1 专属条目）；任务 cookie
  持久化 = 每任务 sqlite 单一真源（cookie 写回回路，任务完结/移除时
  清除），不变。`--save-cookies` 仍不接受（文件导出按需延后 —— 0.2
  定稿声明）。
- 代理面：每任务代理槽位 `all-proxy` 与 `https-proxy`（HTTPS 专用槽，
  生效序 = 专用槽 > all-proxy > 无代理）；`http-proxy` 与 `no-proxy`
  不接受；socks5（h）/socks4（a） 显式拒绝；代理认证经 URL userinfo
  （`--*-proxy-user/passwd` 族不接受）；无 FTP-over-HTTP 代理。两键的
  会话全局面是接受值 no-op 行（无全局代理默认值消费缝 —— 见上方
  taiji 独有回显键条目）。
- **`ca-certificate` 已接受（任务级 CA 面）**：PEM CA 文件路径；任务级
  根**替换**平台信任库（aria2 的 replace 语义，非追加），对 HTTPS/FTPS
  均生效；在 addUri 选项与 changeOption 下同键接受（增量语义：payload
  中缺席的键保持任务当前值）。两处收紧差异：（1） 解析期路径/PEM 校验 ——
  坏路径/坏 PEM = `taiji.option.invalid` 任务拒绝（aria2 在传输构建期才
  失败）；（2） 值域 = PEM `CERTIFICATE` 节（可多证书）；裸 DER 不接受
  （aria2 的 "must be in PEM format" 规则显式化）。同时设置
  `--check-certificate=false` 时后者胜（校验关闭，CA 文件生效面被忽略；
  与 aria2 同）。锚点：`taiji-core::session::options` 差异声明块、
  `taiji_http::client::{ClientConfig.ca_cert_path, load_ca_certificates_der}`、
  `FtpConfig.extra_ca_certs_der`。
- **`load-cookies` 已接受（第一步；任务级 cookie 摄入门）**：Netscape
  cookie 文件路径，与 aria2 同名同义（prefs.cc 同字面量；从非接受声明表
  迁移而来 —— 后经复审反转，因原 "RPC/CLI 面未接线" 声明与引擎既有
  cookie 机制直接矛盾）。三个入口 = addUri 每任务选项 +
  `changeGlobalOption` 全局面（`GlobalOptions.load_cookies`；
  getGlobalOption 回显路径回显原值/未设置时空串；空串 = 清除）+ CLI
  `taiji http --load-cookies`。生效面 = 预填任务 CookieStore（复用
  taiji-http Netscape 解析器 + `CookieStore::seed` 注入缝），与运行时
  Set-Cookie 吸收共享存储（RFC 6265 §5.2/§5.3）。**Fail-closed**：文件
  缺失/不可读/超限（>1MiB）= `taiji.option.invalid` 任务拒绝（上限锚
  `MAX_COOKIE_FILE_BYTES`）；逐行坏行保持解析器的宽容纪律（跳过一行不
  致命，与 curl 同规则 —— 见 cookies.rs 模块文档）；全坏行 = 空 jar 是
  合法形态。优先级 = 每任务 > 会话级（与 aria2 的每下载覆盖全局同序）。
  **与手工 `--header` Cookie 行的组合语义 = 存在 cookie 注入门（文件源
  或结构化直达）时，手工 `Cookie:` 行被剥离，jar 是任务 cookie 的唯一
  来源** —— 与 the fork 的 "Structured cookies are authoritative"
  同构（`RpcMethodImpl.cc`）；引擎现状在两路并存时会发出两个 Cookie
  header，而 "取第一个 header" 的服务器会静默作废 jar（接受而不生效
  即是伪装，故收紧）；无注入门的任务，手工 Cookie header 照今日一样
  透传（现状零变化）。changeOption 面接受新路径 = 替换整个种子集（下次
  激活生效；运行中任务经既有重启语义重新激活；坏路径显式拒绝且零
  变更）。锚点：`taiji-core::session::options`（ARIA2_OPTION_NAMES 注册
  + 差异声明块中的 load-cookies 条目）、`taiji-core::session::actor`
  （`load_cookie_seed`/`cookie_intake_active` 单点族 + add_uri 直读臂）、
  `taiji_http::cookies::{CookieJar, CookieStore::seed}`。
- **`select-file` 执行面完备性**：接受面差异见上方 `select-file` 条目
  （终裁：addTorrent / addUri（magnet） / changeOption Reserved（Paused）；
  对活动任务与非 BT 任务 changeOption = 显式拒绝）。本条目补全执行/
  持久化/投影三面：（1） addUri 的 http（s） `.torrent` URL 任务在同一面
  接受 `select-file`（添加面语法校验与 magnet 臂相同；抓取升级产物
  `TorrentJob.selected_files` 自同源透传，激活时经 `SetFileSelection`
  投影为掩码 —— 与 aria2 在 `download_helper.cc` 的 addUri `.torrent`
  面同规则）；（2） 越界处理两段式 —— 参考实现中，越界索引应用到
  FileEntry 时静默无匹配（download_helper.cc），changeOption 消费面只
  解析语法不查文件数边界（RpcMethodImpl.cc 惰性应用）；本侧在**有元
  数据可判时**显式拒绝（addTorrent 已解析 / 已落地任务的 changeOption，
  经 `resolve_select_file_for_meta`；被拒调用零变更），在**元数据未
  落地时**（magnet 未升级 / `.torrent` URL 未抓取）调用被接受，越界值
  在升级激活面终绐为显式任务错误（差异仅在错误显式度：静默无匹配 →
  显式错误）；（3） 选择面持久化单一来源 —— `config_json.selected_files`
  （0 起）是 magnet（`so=`/select-file 合并胜出值）、直接种子添加与
  `.torrent` URL 摄入的一条通道；重启恢复经 `MagnetJob.selected_files`/
  `TorrentJob.selected_files` 回填，`effective_magnet_selection` 是
  magnet 族的唯一合并点；（4） `getFiles`/`tellStatus.files` 的 `selected`
  真值 = `file_selected` 单源投影（pad 项恒 false）；`getOption` 的
  `select-file` 回显 = 规范化 1 起逗号串（见下一条的 （3））。锚点：
  `taiji-core::session::actor`（tasks/persist/commands/views）+
  `taiji-core::magnet`（finalize 应用点）。
- **`getOption` 回显面（单任务选项读取）**：三域定位与 the fork 对齐
  （活动 ∪ 等待 = `findGroup`，终态 = `findDownloadResult`，
  `RpcMethodImpl.cc`）；未知/非法 GID 消息为逐字 str2Gid 族（`"GID X is
  not found"`/`"Invalid GID X"`）。五处差异：（1） **回显键集 = 接受子集
  的投影** —— the fork 返回全表，因其选项面接受一切（`pushRequestOption`
  逐 pref 展开，`RpcMethodImpl.cc`）；taiji 返回接受键集 ∩ 有每任务
  真源的键（§3 选项立场表是核查依据），不伪造未接受键。（2） **基线值
  投影** —— the fork 只返回显式给过 add/changeOption 的键
  （`option->defined`）；taiji 对 `dir`/`seed-ratio`/`seed-time`/限速族
  等恒回显任务 payload 生效值（含添加时自全局回退的基线 —— 供任务选项
  对话框显示；"未设置键不回显"的方向差异由本条声明）。（3） **值形态** ——
  数字/尺寸返回最小数值形式（添加字面量 `"1M"` 返回 `"1048576"`，
  seed-ratio `1.0` 返回 `1` —— 数值相等，与 §3 `seed-ratio` 共享键值
  差异同一判据）；`select-file` 返回规范化 1 起逗号串（存储面是 0 起
  展开索引，无原串；the fork 返回解析前存储的字面量）。（4） **如实未
  处理的默认键** —— `bt-max-peers`（解析值无每任务 payload：执行面挂在
  引擎常量缝）与 `pause`（添加时的入队意图不属于任务 payload；状态由
  tellStatus `status` 承载）不回显。（5） **终态读回面** —— 终态任务自
  库中行的 `config_json` 读回（fork = `dr->option` 内存快照）：只有
  持久化键集在场（magnet 族布尔 / HTTP 运行时键不进行，终态不回显）；
  remove 后行已不在，无持久化形态 = **空表**（the fork 恒有快照）。
  活动任务限速回显 = 活桶生效值（经 `setMaxDownload/UploadSpeedLimit`
  读回，同一 `RpcMethodImpl.cc` 族）。锚点：
  `taiji-core::session::actor::commands`（`get_option`/`task_option_echo`）。

- **媒体选项族（统一注册，8 键 → 第二批后 10 键）**：首批接线的旗标族
  进入统一注册 —— `media-variant-policy` / `media-audio-lang` /
  `media-subtitles` / `media-segment-concurrency` /
  `media-staging-quota-gib` / `media-staging-dir` /
  `media-allow-private-key-url`（同一道门同时治理两条 SSRF 线：键
  URI **与** media-segment/init URL，早期草案名携带了扩大后的范围）/
  `media-ffmpeg-path` / `media-archive` + `media-info-json`（见
  下方专属条目）。getGlobalOption/changeGlobalOption 接受 + 回显（值
  校验走 taiji-media 解析面 —— 全局面上的非法值按
  gatherChangeableGlobalOption 宽容规则忽略，而 addMedia 每任务面为
  严格 `taiji.option.invalid`）；addMedia 选项面另载每任务键
  `media-selector`/`sub-lang`/`media-template`/`no-meta`/`media-muxer`/
  `media-output-format`/`probe-token`/`media-archive`/`media-info-json`
  （由 actor 臂严格解析 —— `media-selector` 与 `media-variant-policy`
  互斥，选择来源唯一）。权威集合：`taiji-core::session::options`
  （`DECLARED_OPTION_DIFFS` + `GLOBAL_PATCH_TABLE` 媒体行 + 镜像常量；
  三面一致性测试把 CLI/回显/声明钉在一起）。
- **媒体产物面（taiji 扩展 —— aria2 无档案/导出对应物）**：
  `media-archive`（默认 `false`）开启下载档案 —— Done 收尾把任务的
  两个指纹记入 `media_archive` 表（规范化 URL 摘要 + 所抓 manifest
  规范结构的一个**无 URL** 摘要 —— HLS 播放清单逐字摘要；DASH
  上是内容形态 `mpd_content_digest`，其规范文本省略 `mpd_digest`
  所绑定的入口 URL；schema 注记把行的敏感度标注为浏览记录等价物），
  两个去重检查点运行：① 激活时的 URL 摘要（零外发 —— 命中连 manifest
  都不抓取），② Resolving 中的 manifest 摘要（同一内容在切换 CDN/URL/
  镜像后于两种形态下都在此命中）。命中将任务以 **Done 形态**终绐，警告
  `taiji.media.archive_duplicate` 经 `taiji.media.phaseChanged` 旁路
  搭载（快速跳过的收尾，不是 Error；零分片流量）。破坏性清空面：
  `taiji.clearMediaArchive` RPC + 一次性 `--media-archive-clear` CLI
  预清；清空后同一指纹重新下载。`media-info-json`（默认 `false`）在
  Done 收尾写入白名单化、脱敏的 `<product>.info.json` 边车（固定字段
  记录 —— 无 map 透传，`http_headers`/`cookies`/`token` 结构性缺席；
  每个字符串值过与错误面共享的 payload 脱敏；`--no-meta` 正交 —— 它
  只管产物内嵌面）。锚点：`taiji-media::archive`（纯函数半部）+
  `taiji-store::persist`（`media_archive` 面）+ `taiji-core::session::media`
  （检查点 + 收尾）。
- **四池预算三件套（`max-concurrent-seeds` / `max-concurrent-checks` /
  `media-synthesis-concurrency`；taiji 独有回显 + 接受键，四池相位分拆
  预算模型）**：the fork 无此选项（`prefs.cc` 无 `makePref`）—— taiji
  能力扩展，白名单列入 `DECLARED_OPTION_DIFFS`。getGlobalOption/
  changeGlobalOption 接受 + 回显（`session_runtime` 面）；**非数值宽容
  忽略**（gatherChangeableGlobalOption 规则，媒体族行同形 —— 零新错误
  码），越域数值**在行上钳制**（`max-concurrent-downloads` 应用侧钳制
  先例；读侧访问器是同域第二道栅）。值域：seeds `[0,4096]`（0 =
  无限制）/ checks `[1,16]`（无无限状态）/ synthesis `[1,16]`。默认值：
  seeds **16**（两态注记 —— 无限制默认 0 以会话级连接预算为前提；实现
  时尚未合并，默认值暂收敛为 16，待其合入后翻回）、checks 2（pread+hash
  的 IO/CPU 重叠保守值，计入引擎内部 verify 池的分层磁盘负载）、
  synthesis 2（ffmpeg 进程沉重；`media-segment-concurrency` 的分层对应
  物 —— 那个管网络相位，不是本预算）。热重载 = changeGlobalOption
  触发：收窄的预算绝不抢占在途成员（只门后续准入），放宽的 seed 预算
  将停泊的 seed_wait 成员 FIFO 重新激活，绝不经下载槽路由。CLI/conf 面
  （`taiji`）：同名旗标 + conf 键，**硬域校验**（fail-fast，conf 形态），
  域同源；启动注入会话初始值。锚点：`taiji-core::session::options`
  （`GLOBAL_PATCH_TABLE` 行 + `DECLARED_OPTION_DIFFS` 条目）、
  `taiji-core::session::actor::mod`（`pump_all`，I3 预算变更触发）、
  `taiji::conf`（臂）。
- **`bt-detach-seed-only` 行为被取代（语义恒真；接受面不变）**：同名
  aria2 选项（`RequestGroup.cc` `enableSeedOnly`：选项开且下载完成 →
  完成时释放并发槽，做种脱离继续；选项关 = 做种占槽直到做种判据结束
  任务）。taiji 照常接受该键（默认 `false`，逐字回显 —— aria2 接受/
  回显面零变化），但在四池模型下**行为与取值无关恒真**：下载完成翻转
  为做种驻留（`SeedingStarted`），翻转时释放下载槽，做种不再占用下载槽
  （驻留由 seed 池自身的 `max-concurrent-seeds` 预算治理）。这是相位
  分拆预算架构对 aria2 记账补丁的取代（detach 旗标的意图 —— 下载调度
  不被非下载相位劫持 —— 被结构性吸收），**声明为架构差异而非缺陷**；
  两个取值由回归测试钉住行为相同（`taiji-core::session::actor::tests::
  bt_detach_seed_only_any_value_seeds_off_the_download_slot`）。引擎侧
  `Detached` 终态变体保留为 "曾做过种" 任务的语义标记。锚点：
  `taiji-core::session::options`（`bt_detach_seed_only` 字段 +
  `DECLARED_OPTION_DIFFS` 上下文）、`taiji-core::session::actor::tasks`
  （SeedingStarted 迁移）、`taiji-core::session::queue`（`begin_seeding`，
  先释放后回填）。
- **周期摘要口径（`emit_summary`；有意为之）**：会话的周期任务摘要
  （`--summary-interval` INFO 行）只遍历**下载池活动登记表** —— 做种/
  加工驻留者不逐任务汇总（其观测面是 tell\* 投影与 getGlobalStat 扩展
  键，见下方条目）。aria2 为其（单计数器）活动组打印摘要；分叉方向 =
  taiji 有意独有（不做四池摘要扩展）。锚点：
  `taiji-core::session::actor::summary`（`emit_summary`）。
- **注册措辞**：媒体选项族的注册文本经仓库常规变更评审流程落地；
  本文档承载规范差分声明。

## 4. 任务面（tellStatus / tell* / getFiles / getUris / getServers / getPeers）

在实测交叉验证基线（一个暂停的 FTP 任务 + 一个 magnet 任务）上：
`getUris`/`getPeers` 逐字节零差异；`getFiles`/`tellStatus` 的键集差异
全部落入以下条目：

- **`http` 子字典**（taiji 扩展；fork 侧缺席）：`finalUrl`/`connections`/
  `extentsActive`/`blocksDone`/`blocksTotal`/`encoding`（未设置 = 键
  缺席）/`renamePending`/`hostControlled`/`sources[{url,rate,state}]`。锚点：
  `taiji-rpc::dispatch::view`（`status_entry_json`）。
- **`media` 子字典**（taiji 扩展；fork 侧缺席 —— 已声明字段）：`kind`
  （`hls`）/ `phase`（media §3.2 值域：queued|resolving|downloading|
  recording|processing|verifying|finalizing|paused|error|done）/
  `phaseDetail`（暂停相位记忆 —— 非带记忆暂停则缺席）/ `tracks[{label,
  kind,state,segmentsDone,segmentsTotal}]` / `stagingDir` / `outputName`
  （净化后的模板结果）/ `selector` / `variant` / `manifestUrl`；进度
  投影搭载顶层 `completedLength`（整任务字节汇总）。getGlobalStat/
  numActive 计入媒体任务（基于队列的口径，既有先例）。锚点：
  `taiji-rpc::dispatch::view`（`media_json`）+
  `taiji-core::session::actor::views`（`job_media_view`）。
- **BT 面超集键**：taiji 对每种任务类型恒带 `numSeeders`/`seeder`
  （`"0"`/`"false"`），the fork 只对 BT 任务携带；`bittorrent` 子字典、
  `getFiles` 的 `piecesRoot`/`pieceSize`/`padding`、`getPeers` 新增的
  `transport`/`crypto` 列遵循 Phase A 声明（v2 合成面）。
- **探测前投影**：任务创建到探测/规划之间，the fork 以占位条目预填
  `getFiles`/`tellStatus.files`（`path` 空串、`length` "0"）并在
  `pieceLength` 回显默认块长；taiji 返回空 `files` 数组与 `pieceLength`
  "0"，规划完成后投影真实条目。
- **getServers**：the fork 只有活动任务可查（暂停/终态 =
  `"No active download for GID#X"` —— 暂停态与 taiji **逐字零差异**）；
  对终态（Done/Error）taiji 投影一行汇总（the fork 对终态仍报错）；
  响应是每任务单行按源汇总（`{index:"1", servers:[…]}`），the fork 每个
  在途请求一行。server 条目的速度字段 = 任务累计平均速度（fork = 每请求
  瞬时）。
- **getUris**：status 值域与 the fork 一致（`used`/`waiting`）；taiji 以
  "激活后全 `used`，激活前全 `waiting`" 近似（the fork 反映每个 URI
  触点的活态）。
- **进度记账基准（completedLength）**：存在活读时，tellStatus/tellActive/
  getFiles 的 `completedLength` 投影**字节级实时计数**（激活期间，块记账
  打底，实际写入 sink 的字节单调累加；已知总量处收敛截断 —— 同块双写/
  重试重写的浪费字节不外漏，恒 ≤ `totalLength`，终值 = 记账终值）。原
  基线注记 —— "taiji 按块计量，其 1Hz 采样的 p50/p95 不能跨引擎直接对比
  （the fork 是字节级）" —— 就此**撤回**：计量粒度已与 the fork 收敛，
  不再作为差异存在。块记账仍是持久化权威（投影 ≠ 记账；规格 §4.3 单点
  决定不动）：`http` 子字典的 `blocksDone`/`blocksTotal` 保持块单位；
  冷行（无活读）见下一条的投影。锚点：
  `taiji-core::session::actor::http_task`（`HttpLive::completed_bytes`）。
- **冷行进度投影**：无活读的排队/暂停 HTTP 行，`completedLength` 投影
  行内已完成字节（导入位图映射 / 快照管线持久化面），`totalLength` 投影
  探测的权威总量（激活探测回填后恒精确）；探测缺席时投影网格推导值
  （`block_count×block_size` —— 导入位图行形态；非对齐总量最多高估
  一块），再不行 = 0。the fork 对暂停任务返回真实值（同规则）；尚未
  开始的等待任务 the fork 同样报 0/0（与 taiji 无行进度时同形）。
  `files` 面不在本条覆盖（见上方 "探测前投影"）。锚点：
  `taiji-core::session::actor::views`（`http_cold_lengths`）。
- **saveSession**：语义 = 触发一轮全量持久化（taiji 的 sqlite 是会话
  真源）；**不**产出 aria2 文本会话文件格式。the fork 在
  `--enable-sqlite3-persistence` 运行时形态下答 OK —— 现场交叉验证
  （双方带库运行）零差异；无持久化形态时双方显式报错（fork = 持久化
  未启用错误；taiji = `saveSession: session storage is not enabled`；
  内嵌进程可能无库，而 taiji 的运行时形态恒有）。
- **getGlobalStat 口径迁移（四池模型）**：上游/fork 的 `numActive` 计入
  每个活动 RequestGroup —— 做种驻留（脱离的 BT 组留在活动清单，
  `RequestGroupMan.cc`）与媒体加工都算。taiji 的 `numActive` **迁移到
  下载池口径**：只计下载相位槽位占用者（BT/HTTP 下载、magnet 元数据
  相位、媒体 Resolving/Downloading）—— 做种/校验/加工驻留者不进计数
  （仍是 TellActive 成员 —— 成员面与计数面按声明设计分叉）。
  `numWaiting` = 四个等待段合并
  （`reserved ++ check_pending ++ seed_wait ++ proc_wait` —— 与
  tellWaiting 同口径，一个计数）。三个**扩展键**
  （aria2 无对应物；实测差分面在零差异比对前剥离它们）：`numSeeding` /
  `numChecking` / `numSynthesizing` = 三池各自的**仅在途驻留者**（各池
  等待 FIFO 不计入；等待细分 = 客户端对 tellWaiting 做状态直方图 ——
  没有第三层键）。Motrix 可见行为变化（只做种的会话 numActive 降为 0，
  而 the fork 会报驻留者数）。锚点：`taiji-core::session::view`
  （`GlobalStatView`）、`taiji-core::session::actor::commands`
  （getGlobalStat 臂）、`taiji-rpc::tests::aria2_compat_live_diff`
  （`strip_global_stat_extension_keys`）。
- **`'seeding'` 扩展状态值 + 驻留投影翻转（用户可见的状态值变化）**：
  tellStatus/tell\* 的 `status` 值域新增 **`'seeding'`** ——
  （1） 完成下载的做种**驻留**在 TellActive/tellStatus 投影 `'seeding'`
  （引擎继续运行；曾把驻留者投影为 `'active'` 的窗口期过渡已关闭 ——
  行状态与投影共享一面）；
  （2） tellWaiting 的**做种段**（`seed_wait` —— 内容完整、停泊等 seed
  预算席位、不占运行槽）投影同一 `'seeding'` 值（持久化行状态同时
  覆盖驻留 + 等待 —— 沿 `'checking'` 的 pending+在途先例）；
  （3） 校验段（`check_pending`）投影**既有** `'checking'` 值（零扩展
  —— pending 与在途校验自 Phase A 起就共享持久化的 `'checking'` 行
  状态）；
  （4） 加工段（`proc_wait`）投影 `'waiting'`（无扩展 —— 门内挂起是
  任务内相位，media 子字典承载相位细节）。
  tellWaiting 的固定段序 = reserved ++ check_pending ++ seed_wait ++
  proc_wait；changePosition 在**所属段内**解释 POS_SET/POS_OFFSET 并在
  段自身的头/尾钳制（相位段是资源域 —— 位置绝不跨段边界；非等待成员
  遵循 aria2 的非等待拒绝语义）。
  **Motrix 容忍面（端到端验证记录；Motrix @ 82829306，只读）**：Motrix
  的 `translateStatus`（`src/core/engine/aria2/translate.ts:35-71`）没有
  `'seeding'` 分支 —— 其原生做种识别以 `raw.status === 'active'` +
  `seeder === 'true'` + `bittorrent` 为门（translate.ts），于是字面量
  `'seeding'` 落到 `default → TaskStatus.Error` 臂：taiji 做种驻留者 /
  seed_wait 成员在 Motrix 的任务列表中**误标为 Error**（消费点：
  translate.ts 的 `translateRawToTask` 与 session-manager.ts 的会话恢复
  路径）。线路格式事实其余兼容 —— taiji 将 `seeder` 投影为字符串
  `"true"/"false"`（`jbool`，`taiji-rpc::dispatch::view`），做种驻留者
  报 `seeder="true"`（引擎快照的各面俱完成旗标，`taiji-engine::query`
  `EngineStatusSnapshot.seeder`），因此若 Motrix 的状态门放进
  `'seeding'`（或状态保持 `'active'`），其原生检测本可正确分类这些
  任务。误标按 "Motrix 不可见" 边界如实记录：taiji 侧声明保持（值扩展
  是唯一用户可见的状态变化），Motrix 侧修复**超出 taiji 范围 —— 升级
  为跨仓协调**，不静默吸收，也不以弯曲 taiji 声明来粉饰。锚点：
  `taiji-core::session::view`（`StatusKind::Seeding` + `as_str`）、
  `taiji-core::session::actor::views`（`seeding_live_view`）、
  `taiji-core::session::queue`（`waiting_snapshot`，固定段序）。

## 5. addUri / addTorrent（协议接受面）

- **sftp:// 延后**：the fork 支持 SFTP；taiji 0.2 显式拒绝 —— addUri 在
  任务创建时报 `taiji.sftp.deferred`（错误消息携带该码；SFTP 传输面
  （known_hosts 严格 / identity / 管线并发）随独立项目交付，`--sftp-*`
  选项族同样延后（按未知项忽略））。
- **未知 scheme**：the fork 统一报 `"No URI to download."`；taiji 显式报
  `"URI scheme not supported: …"`（接受域：magnet: / http（s） / ftp（s） /
  http（s） .torrent URL）。
- **多 URI 数组** = 同一文件的镜像多源；两侧语义共享；taiji 另提供
  `sources[]` 运行时观测面（§4 `http` 子字典）。
- **addTorrent 非法 base64**：the fork 宽容解码 base64（剥离非法字符后
  bencode 校验失败 → `"Bencode decoding failed"`）；taiji 严格校验 →
  `"torrent data is not valid base64."`。数字码两侧均为 1。
- addTorrent 的 webseed URI 参数（位置 1）：两侧接受；taiji 0.2 不消费
  （BEP19 webseed 属后续相位）—— 显式丢弃，不伪装。
- **webseed/HTTP 源请求的 `user-agent` 语义（2026-10-16）**：aria2 语义
  下，任务级 `user-agent` 选项喂给 URI/webseed 面（同一 HTTP 下载器栈）；
  taiji 有意分叉 —— **BT 任务内的全部 HTTP 外发（webseed 区间请求）恒以
  `taiji/<semver>` 自我标识**（构造性锚定于 `taiji_bt::tracker::PEER_AGENT`，
  `taiji-engine/src/webseed.rs` `HttpRangeFetch::build`），不消费该选项。
  纯 HTTP（S）/FTP 任务的 UA 覆盖语义不变。理由：BT 身份面（tracker
  announce UA / 扩展握手 `v` / webseed UA）单一来源、如实标识
  （libtorrent 的 `user_agent` 设置同源喂给 tracker+webseed 且可配置 ——
  taiji 收紧为不可配置）。两个守卫测试在 `taiji-engine/src/webseed.rs`
  （外发消息断言 + 选项保持未接线的守卫）。
- **非法 BEP53 `so=` 的显式拒绝（taiji 原生扩展面；the fork 无对应物；
  协议行为参考 = libtorrent）**：magnet URI 的 `so=` 参数存在时，taiji
  严格解析 —— 语法错（失序/重复/重叠/倒置/空段/非十进制）= 显式添加
  拒绝；越界（≥ 非 pad 文件数）= 升级链中显式失败；libtorrent 的
  `magnet_uri.cpp` `so` 分支**宽容，非法字符时跳过整个参数**（只接受
  digit/`-`/`,`，其余丢弃后继续解析）。收紧是 taiji 自有设计：静默丢失
  的选择面比显式失败更危险（用户以为选了文件，实际整个 payload 都在
  下载）。声明收束：接受面差异在 §3 `select-file` 条目
  （`select-file`/`so=` 并存冲突拒绝在同一条目）。
- **BEP53 第三段（`so=` 追加到既有 torrent）未实现；重复身份保持显式
  `duplicate download` 错误。** 四点依据：（1） BEP53 是 Draft（截至
  2017-05-24 未编号）；（2） aria2 无 `so=` 面（`src/magnet.cc` 无此参数）
  —— the fork 无可交叉验证的对应行为；（3） **libtorrent 核心同样未
  实现** —— 重复添加立即返回既有 handle，**不应用新参数的
  file_priorities**（`session_impl.cpp`）；追加语义在客户端层
  （qBittorrent 等）通过对重复 handle 调 `torrent_handle::prioritize_files`
  完成；（4） Motrix 前端对它无 UX 依赖（重复添加路径走 changeOption
  select-file 显式重选 / 重新添加）。若 Motrix 日后提出 "追加下载"
  需求，将是 `taiji.*` 扩展设计下的单独变更。锚点：
  `taiji-core::session::actor::tasks`（add_uri/add_torrent 的
  `identity_is_duplicate` 显式错误源）。

## 6. addMetalink

- **版本面**：the fork 接受 v3+v4；taiji 只接受 v4（RFC 5854）—— v3/
  未知版本 = 显式降级为 `taiji.metalink.unsupported_version`。
- **解析边界**（实测交叉验证观察）：
  - 非 XML 字节：两侧码 1（fork `"Could not parse Metalink XML
    document."`；taiji `taiji.metalink.parse_failed: …` —— 措辞差异）；
  - **合法 XML 但非 metalink 根 / 零 `<file>` 条目**：the fork 宽容返回
    空数组 `[]`；taiji 显式报 `taiji.metalink.parse_failed`（已知不支持
    特性必须显式报错 —— 不静默伪装成空结果）。
- **展开语义**：条目名展平为 basename（`--out` 的纯文件名域）；校验和
  折入六哈希（md5/sha-1/sha-224/sha-256/sha-384/sha-512 —— 与
  `--checksum` 值域同域；单一校验和优先取最强 sha-256，其余按文档序取
  首；sha3-* 等越域类型解析保留但不产出）；`<pieces>`/`<signature>`
  解析保留、下载面不消费；`url@type` 属性不消费；`<metaurl>`（BT）在
  引擎内直接转换，非 torrent mediatype 跳过并警告，metaurl 任务失败不
  影响同条目的 HTTP 源任务；返回值 = 纯 GID 字符串数组（aria2 形态）；
  合法条目零可用 = 空数组回执（不是错误）。
- **同 （dir,out） 的后续条目跳过**（+ 警告；首见条目持有独占所有权）：
  条目名展平为 basename 后，同一 `dir` 下的同名条目会并发双写同一分块
  文件（无校验和时静默损坏文件）—— the fork 的 `applyDir` 保留条目
  子目录层级，同名条目落到不同路径不相撞（展平本身由上方展开语义条目
  覆盖）；taiji 在展开缝按 （dir,out） 吸收重复：后续条目跳过，其余条目
  照常展开。
- **同文档 magnet/metaurl 去重跳过**（+ 警告；首见胜）：一个 metaurl
  URI 字面量只产出一个 BT 任务（与 the fork 的 `groupEntryByMetaurlName`
  按 URI 字面量分组同向）；同一 magnet 按 btih/btmh 双身份去重 ——
  同一种子的不同 URI 拼写（任意 dn/tr）在 the fork 按字面量分成不同组，
  taiji 跳过同身份条目并仍展开后续条目的其余面（良性重复在缝处吸收，
  不再让整个方法中途失败）。条目内 metaurl 候选逐个考察直到首个可用
  （不可用的首见不阻塞可用的后续）。锚点：`taiji-rpc::metalink`
  （`expand_add_uri_plans`）。
- **调用方提供的 out/checksum 整体剥离**：addMetalink 基础选项的
  `out`/`checksum` 键在展开缝整体剥离 —— `out` 恒自条目名派生（BT
  计划不携带）；`checksum` 仅当条目自身在文档中声明六哈希域时产出，
  未声明的条目**不继承**调用方的 `--checksum`（fail-closed 防泄漏面：
  外部值会卡死健康条目）。the fork 的 metalink 子任务路径/校验和取自
  条目自身（`Metalink2RequestGroup.cc` 直接构造 DownloadContext，不消费
  调用方的 `out`/`checksum`）—— 同向差异显式声明。锚点：
  `taiji-rpc::metalink`（`expand_add_uri_plans`）。
- **BT 计划不消费条目哈希、不携带 out/checksum**：条目的 `<hash>` 声明
  只进 HTTP 计划面（`--checksum`）；BT 完整性最终由所抓元数据的 piece
  hash 裁决，文档校验和与 BT 面无交集，BT 计划绝不携带 `out`/
  `checksum` 键 —— the fork 的直接转换同向不携带，显式声明。锚点：
  `taiji-rpc::metalink`（`AddUriPlan`）。
- **部分失败回执措辞差异**：展开中途子任务被会话拒绝（重复身份 /
  `out` 域拒绝等）时，整个方法显式失败（数字码 1），错误消息追加已创建
  GID 清单（`"(created gids: …)"`；错误对象保持 `{code,message}` 形态，
  已创建任务仍可独立移除/tellStatus）—— the fork 的方法面没有这种回执
  形态（组建组先于任何入队，失败 = 零组入队，无部分失败措辞）。锚点：
  `taiji-rpc::metalink`（`fail_with_partial`）。
- **选项族**：`metalink-language/location/os/version/preferred-protocol/
  enable-unique-protocol/force-protocol` 接受但忽略 + 警告；
  `metalink-enable-auto-discover` 接受但视为非法（the fork 1.37.0 无
  此名）；`follow-metalink`/`metalink-base-uri` 不接受。
- **字符集（ISO-8859-1 / windows-1252）**：XML 声明/BOM 携带解码；
  `ISO-8859-1` 标签经 WHATWG `windows-1252` 映射解码（encoding_rs 在此
  与 HTML 规范一致：0x80-0x9F 区间解码为 Cp1252 可打印字符而非 C1 控制
  字符 —— 严格 Latin-1 下其中某些字节是非法 XML 1.0 字符，故此映射是
  兼容面扩展）。锚点：`taiji-metalink` crate 文档与字符集向量测试。

## 7. 错误码与错误形态

- **JSON-RPC 面**：数字码 1/-32700/-32600/-32602/-32601 及其 HTTP 状态
  映射（1→400、-32600→400、-32601→404、其余→500）实测交叉验证零差异；
  参数错误消息（`"The parameter at N is required but missing."`/
  `"...has wrong type."`）、GID 消息（`"GID X is not found"`/
  `"Invalid GID X"`）与 multicall 递归禁令消息全部逐字零差异。
- **changePosition 双非法组合的校验优先级**：gid 与 how 均非法的极端
  组合中，参考实现先跑 gid 解析再查 how 值域（str2Gid 的
  `"Invalid GID …"` 在前 —— aria2-1.37.0 `RpcMethodImpl.cc`），报
  `"Invalid GID …"`；taiji 的 dispatch 层先封闭 how 字面量值域（报
  `"Illegal argument."`），gid 前缀解析在 actor 中（expandUnique 需要全量 GID
  集）—— 同一调用组合下**消息优先级反转**。各错误消息单独逐字零差异
  （上一条）；单非法面（仅 gid 非法 / 仅 how 非法）的胜出消息与参考
  一致，成功路径零差异 —— 纯错误面组合边界，无行为差异。锚点：
  `taiji-rpc::dispatch::methods`（changePosition 臂注记，与本条目
  互引）。
- **数字错误码映射表**（终态任务 `errorCode`；单一来源 =
  `taiji-rpc::error` 文档表 + 可执行镜像）。差分面条目：
  - DNS 解析失败：the fork 可达 19（NAME_RESOLVE_ERROR）；taiji 恒落 6
    （NETWORK_PROBLEM）（传输 payload 不分相位，细粒度码不可达）；
  - 磁盘错误细分：the fork 可达 15/16（FILE_OPEN/CREATE_ERROR）；taiji
    恒落 17（FILE_IO_ERROR）；
  - FTP 登录失败（530）：the fork 落 21（FTP_PROTOCOL_ERROR）；taiji 的
    数字面统一到 24（HTTP_AUTH_FAILED，字符串码 `taiji.auth.failed`
    优先）；
  - FTP 读空闲超时：taiji 落 21（the fork 的读超时不分协议恒为 2
    TIME_OUT）；
  - cookie 文件失败：the fork 记日志继续；taiji 升级为任务级失败（码
    1 + `taiji.http.cookie_file*`）；
  - taiji 的增强码 `mirror_mismatch`/`no_source`/`total_length_exceeded`/
    `coordinator_stopped`：the fork 无一一对应物，均落 1
    （UNKNOWN_ERROR）；`insecure_redirect` 落 22（HTTP_PROTOCOL_ERROR
    —— the fork 无重定向降级防线概念，该码并入 HTTP 协议错误族）；
  - 空文件探测（416+`*/0`）Done = 新成功路径（数字码 0）。
- **metalink 解析预算超时**：taiji = 数字码 1 + `taiji.metalink.timeout`
  前缀（600s 预算 —— 与 `taiji.createTorrent.timeout` 的 "无超时上限
  的同步 RPC 禁令" 同一显式兜底；超时只约束回执，不取消底层阻塞解析；
  解析是纯函数，丢弃结果不留孤儿任务）；the fork 的解析无预算上限，
  该错误面在那里不存在。锚点：`taiji-rpc::error`
  （`STR_METALINK_TIMEOUT`）、`taiji-rpc::metalink`
  （`add_metalink_method`）。
- **`--checksum` 失配** = 32（CHECKSUM_ERROR）；the fork 用同一码。

- **媒体错误码 → aria2 数字映射**：媒体 §14 错误码线穿透数字面 ——
  每个 `taiji.media.*` 码映射到 1（UNKNOWN_ERROR；无 aria2 对应物 ——
  规范字符串码逐字搭载消息），包括 `staging` 与
  `ssrf_blocked`/`key_invalid` 注记及本卡首批接线 `template_unsafe`/
  `probe_expired`/`not_media`；唯一共享行 `taiji.option.invalid` 保持
  28。锚点：`taiji-rpc::error`（`media_numeric_code` + 行清单测试）。

## 8. 传输行为差异

- **动态调度**（taiji 核心新增；fork 侧缺席）：引导式自调度 + 停滞窃取
  + 连接数 AIMD + endgame 降级；`http-scheduler=dynamic|static`。
- **跳转点数据面重定向收敛**（相位 2；对齐 aria2 `Request` 的重定向
  URI 缓存语义）：探测期收敛出的重定向终 URL 被下载数据面 Range 请求
  直接复用（单源任务启用）—— **每个块不再重走重定向链**（每块省一次
  源站往返 + 每个工作线程省一条源站 keep-alive/TLS 连接；"每数据连接
  2 个 socket" 的形态由此消除）。跳转点传输错误回退到重新解析原链
  （镜像轮换/失效自愈）；challenge 凭据跨端点剥离（Basic/Digest 限定于
  原始端点，302 跨主机本就不携带）。多源（镜像）任务保守保持重走链。
- **小任务并行 Range 快路**（taiji 核心新增；fork 侧缺席）：≤2 块、
  零续传进度、连接意图 ≥2（min（`split`,`max-connection-per-server`）；
  相位 2 起默认值 （5,16） 立即命中 —— 新的 ≤2 块任务默认走快路；此前
  默认上限=1 从不触发）的任务跳过网格装配：整文件切为近均等字节区间
  直接并行抓取 —— `min-split-size` 下限在该路径**不适用**（the fork/
  经典 aria2 在 "文件 ≤ min-split-size" 时恒单连接；这与 aria2-next 的
  按文件区间规划行为一致，后者没有 min-split-size 语义）。该路径无
  位图：中断再激活整文件重取（"宁少记、不过记" 的安全方向）；
  `--checksum` 重命名前终裁、限速与每主机上限与网格路径同面。锚点：
  `taiji-core::session::actor::http_task`（`SMALL_TASK_MAX_BLOCKS`/
  `drive_small`/`small_task_ranges`）。
- **语义重定义项**（同名不同义；接受且生效）：
  - `split`/`min-split-size`：动态调度下，split = AIMD 慢启动起点
    （连接意图即时兑现）+ 初始区间（extent）参照；连接上限归
    `max-connection-per-server`（静态模式保持原义）；
  - `max-connection-per-server`：AIMD 增长上限（域 1..=64；运行时下调
    主动收缩）。**默认 = 16**（相位 2；偏离 aria2 上游默认 1：上限为
    1 时 AIMD 判据零增长空间，动态模式在真实网络上会停留单连接 ——
    上限是天花板不是连接数，仍经 AIMD 自适应爬升；显式 1 = 钉死单
    连接）；
  - `max-tries`：每区间（extent）重试（the fork 按下载重试）；
    `retry-wait` 指数退避 ×2、封顶 30s。
- **h2**：taiji 对 HTTPS 按服务器协商自动使用 HTTP/2（h2 + rustls
  ALPN）；the fork 仅 HTTP/1.1。h2 下 "连接数" = 并发流上限语义（被
  调度器抽象为按主机许可）；流控等待已接入停滞检测排除。
- **协议模式开关 `--http-protocol=auto|h1|h2`**（taiji 能力扩展 +
  **实验窗口**；aria2 无协议选择选项）：任务级运行时选项。值域：
  `auto`（默认）= 上文 h2 现状 + 明文端点恒 HTTP/1.1 —— **默认行为
  不变**；`h1` = 整传输强制 HTTP/1.1（ALPN 宣告收窄为 http/1.1，h2
  升级关闭 —— 回退/对比旋钮）；`h2` = HTTP/2 先验知识（RFC 7540
  §3.5）：明文端点直接说 h2c（无 Upgrade、**无 h1 回退**；对仅 h1 的
  对端彻底失败），TLS 端点跳过 ALPN 直接说 h2。默认关（= auto），
  属实验窗口；未知值 = `taiji.option.invalid` 任务拒绝。命名刻意避开
  `h2c-auto`：reqwest 先验知识是单一传输级形态，没有 "自动回退" 语义，
  h2c 只是 `h2` 值在明文端点上的投影。锚点：`taiji-http::client`
  （`HttpProtocol`/`build_transport` 分支）、
  `taiji-core::session::actor::mod`（`parse_http_protocol`，单一解析
  源）；线路级锚定测试 = `crates/taiji-http/tests/h2_mock.rs`
  （（1） ALPN 协商现状 / h1 回退 / 强制 h1 的正向用例；（2） h2c 先验
  知识的正负用例 —— 默认客户端被 h2c-only 源站的 preface 检查拒绝；
  （3） 单连接多路复用 vs h1 连接风暴 + 流控窗限速观测）。
- **h2 流控窗调优 `--http2-adaptive-window` / `--http2-stream-window` /
  `--http2-connection-window`**（taiji 能力扩展 + **实验窗口**；aria2
  无窗口选项）：h2 接收流控窗面（RFC 7540 §5.2 —— 客户端宣告的接收
  窗是服务端可推数据量的天花板；单流吞吐 ≤ 流窗 / RTT）。任务级运行时
  选项：`http2-adaptive-window`（bool；默认 false = 引擎静态默认窗
  （8MiB/16MiB）—— hyper 库默认 2MiB/5MiB 只经编程式 None 比较路径
  可达，即 ping/BDP 估算动态窗增长关闭）、`http2-stream-window`
  （每流初始接收窗，字节）、`http2-connection-window`（每连接初始接收
  窗，字节，跨流共享）—— 后两者域 65535..=2^31-1（§5.2.2 窗上限），
  **默认 = 流 8MiB / 连接 16MiB 的引擎默认（在两次基准运行
  （2026-09-25）与一次 2026-09-25 运行的基础上调高并定稿：rtt100 单流
  3.8× / s16 2.9×，rtt0 零回归）**；`None`（编程式比较路径）= 流
  2MiB / 连接 5MiB 的 hyper 库默认（`hyper::proto::h2`
  DEFAULT_STREAM_WINDOW/DEFAULT_CONN_WINDOW）。越域值 =
  `taiji.option.invalid` 任务拒绝。限速背压语义不受影响（本地读侧背压
  主导流控等待，停滞判据排除持续成立 —— 只影响不限速的全速路径）。
  动机（2026-09-25 行业研究笔记）：跨洋长肥管单流被钳在 ≈2MiB/RTT
  （100ms RTT ≈160Mbps）；行业动态窗参考 —— Chrome 自 65535 起按半窗
  节奏动态增长，nghttp2 h2load 默认流窗 2^30-1，quinn 用 1.25MiB 流窗
  （100Mbps×100ms 设计）。锚点：`taiji-http::client`（三个
  `ClientConfig` 字段 + `build_transport` 投影 + DEFAULT_H2_* 常量）、
  `taiji-core::session::actor::mod`（`parse_http2_window`，单一解析
  源）；线路级锚定测试 = `crates/taiji-http/tests/h2_mock.rs`（客户端
  初始 SETTINGS 宣告 + 流 0 WINDOW_UPDATE 的服务端可见面）。
- **h2 多连接 + PING 保活 `--http2-max-connections` /
  `--http2-keep-alive-interval`**（taiji 能力扩展 + **实验窗口**；
  aria2 无对应选项）：（1） `http2-max-connections`（任务级运行时；域
  1..=8；**默认 1 = 现状**）—— h2 传输面上每源站连接的上限。动机
  （2026-09-25 基准证据）：单条 h2 连接共享一个拥塞窗；窗口调优后
  rtt100 也只达 88MiB/s，对比 h1 多连接的 382MiB/s；K>1 是多连接形态的
  实验入口。实现 = K 个独立传输实例（reqwest 池按源站合并，无 K 连接
  API —— 每实例自己的池就是自己的连接），数据面请求按原子轮转分发；
  协商落 h1 时连接分发同样适用（并发连接数由 split 面治理 —— 见下方
  K 语义注记）；每条连接照常计入 `--http-max-per-host`；K=1 与既有
  单实例逐字段等价。**K 语义注记（零行为变化）**：（a） 协商落 h1 时，
  K 并非完全惰性 —— 顺序请求分发开出 min（K, 请求数） 条连接（K=1 则
  复用单条 keep-alive 连接），以 90s 空闲回收兜底；（b） K 上限需要并发
  意图（split / max-connection-per-server / AIMD 意图）才能兑现 ——
  相位 2 起意图推导由默认上限 16 承载（此前默认上限 1 把意图钉死，K
  近似 no-op）。K 不以 h2 为门（行为变化需另行决定）。
  （2） `http2-keep-alive-interval`（任务级运行时；域 0..=3600 秒；默认
  0 = 关 = hyper 现状）—— 对池化空闲连接的 PING 活性探测（reqwest
  `http2_keep_alive_interval/timeout`），超时 = 间隔 ×2（内部固定）；
  防中间盒静默断连导致的首请求尾延迟。两选项越域值 =
  `taiji.option.invalid` 任务拒绝。锚点：`taiji-http::client`
  （`ClientConfig` 字段 + `build_standalone` K 实例组装 +
  `data_transport` 轮转）、`taiji-core::session::actor::mod`（域校验
  单一来源）；线路级锚定测试 = `crates/taiji-http/tests/h2_mock.rs`
  （5）（K>1 → 源站 TCP accept 数 = K，连接面的证据）。
- **同主机瞬时批次组预算 `--http-batch-budget`**（taiji 能力扩展；
  aria2 无批次组概念 —— 动态调度扩展）：同主机 ≥2 个单源 HTTP 小任务
  （≤2 块、零进度）组成瞬时批次组 —— 跨文件的字节 Range 队列（SRPT
  选取 = 批内窃取面）+ 文件完成即离组（预算归还池）。默认 16，域
  `2..=64`，单位 = 连接，任务级运行时选项；非法值 =
  `taiji.option.invalid` 任务拒绝。**三层上限叠扣**：每文件意图 =
  `min(split, cap)`，不被批次组放大；组存活期间，其聚合连接 ≤ 该预算
  （例外：每主机上限有空闲槽时，work-conserving 溢出至
  `max(budget, host cap − usage outside the group)`（预算与主机上限减
  组外用量取大），不爬坡、不轮询）；批次组连接全额计入
  `--http-max-per-host`（跨任务共享；硬上限不予豁免）。锚点：
  `taiji-http::batch`（组登记 / Range 队列 / 软预算门）、
  `taiji-core::session::actor::http_task`（drive_small 组入接线）、
  `taiji-core::session::options`（`DECLARED_OPTION_DIFFS` 白名单行）；
  生命周期/峰值/吞吐单调性/混合负载锚定测试 =
  `crates/taiji-core/src/session/actor/tests.rs`（五个 `batch_group_*`
  测试 + `mixed_load_*`）。
- **下载期 Range 请求收到 200 时显式失败 `taiji.http.range_ignored`**
  （B2；taiji 行为收紧；探测期语义不变）：**下载期**的分块/续传 Range
  请求 —— 探测已确认区间支持（206 + `Content-Range`）之后 —— 收到
  200 OK → 显式任务级失败（规范码 `taiji.http.range_ignored`），首次
  即终绐，不烧区间（extent）重试预算；抓取在读响应体前拒绝（200 的
  字节绝不落盘 —— 零错位覆写风险）。语义来源交叉验证 Android
  Download Manager 的 `executeDownload` "Expected partial, but
  received OK" → STATUS_CANNOT_RESUME。与**探测期** 200 同码位（规格
  §4.2 决策表行 3/4：源站诚实不支持 Range → 单连接降级）但含义不同：
  探测期 = 能力判定降级；下载期 = 与已确认能力的矛盾（能力漂移/说谎）
  —— 不静默从零重启，不降级单连接（丢弃全部位图进度的整文件重下会
  掩盖协议矛盾；没有 `--checksum` 兜底时，信任说谎服务器的完整 body
  有数据正确性风险）。RPC 数字面定稿为 8（CANNOT_RESUME，与
  `taiji.http.bad_range` 同槽 —— aria2 的 isRangeSatisfied 失败族）；
  决定已落：`try_http_numeric_code` 增一臂 + 映射表文档行同步（数字面
  e2e 锚定测试 = `range_ignored_numeric_surface_is_cannot_resume`，
  并进入 `http_failure_numeric_end_to_end_production_chain` 全码生产链
  清单）。锚点：`taiji-http::error`（`HttpError::RangeIgnored`）、
  `taiji-core::session::actor::http_task`（`WorkerRig::fatal_engine`、
  `HttpRangeTransport::fetch` 的 200 判定）；e2e 锚定测试 =
  `http_probe_confirmed_then_200_fails_explicitly`（恰 1 次数据请求后
  Error）+ `http_plain_404_keeps_retryable_unexpected_response_path`。
  **206 回显失配同判（C2）**：**下载期**响应是 206 但其 `Content-Range`
  回显与请求区间不符（`taiji.http.bad_range` —— taiji-http 的
  `validate_range_echo` 每一出口：错位/缺席/不可解析）时，与
  range_ignored 同属码 8 族的确定性协议矛盾：致命、首次即终绐、不烧
  区间重试预算（修复前走普通失败臂，重试烧穿预算），且最终名称从不
  出现；终绐失败**不**进 412 内容重启通道（回显失配是协议矛盾，不是
  内容漂移）。e2e 锚定测试 =
  `batch_group_bad_range_echo_fails_fast_single_request`（恰 1 次数据
  请求后 Error，直达规范码）。**长度维放宽（abdm-1 决定）**：上一要点
  的快速失败面收窄到**起始维** —— 206 回显的**起始与请求起始相符**
  时，body 长度（Content-Length 或 chunked 终长）≠ 请求余量不再算
  `bad_range`，按长度偏差容忍收口：过量投递（body 长于请求）读满所需
  量即关流 —— 多余 body 丢弃、连接提前关闭（欠读连接不回池），本次按
  请求量记成功；欠量投递（请求终点前 EOF）已读字节记部分进度，未满足
  余量走既有区间重试（失败预算按每次抓取的写水位重置，与 B1 相容）。
  起始失配/缺席/病态的 BadRange 快速失败与 200 → range_ignored 显式
  失败（确定性矛盾族）保持原语义。交叉引用 Android Download Manager
  `HttpPartDownloader.kt`（终点失配不致命；start/cursor 对齐则下载
  继续）；aria2 的 `isRangeSatisfied` 要求精确闭区间回显（失配即
  CANNOT_RESUME）—— 在 taiji 的收紧方向内，本放宽以 "起始 = 数据对齐
  的唯一证据" 为界。探测期决策表（规格 §4.2）不受影响：探测
  `bytes=0-0` 的终点偏差回显仍被探测层自己的表拒绝（`BadRange`）。
  连接面影响（如实）：过量投递的提前关闭意味着该连接不回池 —— 过量
  投递源站上的后续区间需要重建连接（恰好读满的连接照旧回池复用，
  不变）；h2 形态下欠读流走 RST_STREAM，连接可复用性交由传输层。
  e2e 锚定测试 = `p86_over_delivery_reads_needed_and_closes_early`
  （Done + 恰 2 次请求 + 源站 filler 写入打不穿）+
  `p86_short_delivery_completes_via_existing_retry`（经重试完成 Done）+
  回归锚 `p86_start_mismatch_keeps_bad_range_fast_fail` /
  `p86_plain_200_keeps_range_ignored_fast_fail`。
- **429/503 `Retry-After` 受理 + 钳制**（B3；taiji 能力扩展；aria2 不读
  Retry-After，只施加固定指数退避）：429/503 的 `Retry-After` 响应头
  （秒与 HTTP-date 两种形式）进入区间退避环，钳制到 `[200ms, 30s]`
  （上限 = RetryPolicy.max_wait，规格 §4.1 退避封顶；防恶意服务器吊死
  我们）。语义：**服务器值优先**于默认退避节奏（节流等待 = 服务器协议
  信号），且 `--retry-wait` 不覆盖服务器值（客户端退避参数与服务器
  协议信号是不同域）；无该头时默认节奏不变。探测期 429 仍在首次即停
  （探测没有退避环）。AIMD 的 429-Throttled 缩减乘子与礼貌等待并存。
  锚点：`taiji-http::retry`（`parse_retry_after`/`clamp_retry_after`）；
  e2e 锚定测试 = `http_retry_after_is_honored_between_attempts`（间隔
  ≥900ms，被服务器值替换）+
  `http_throttle_without_retry_after_keeps_default_pace`。
- **文件名平台兼容（立场 2：引擎层净化 + 真名回报）**：URL/
  Content-Disposition 派生名上，the fork 只做百分号编码转义（仅 MinGW
  构建）与目录穿越检测；`--out` 完全绕过净化，保留名/尾点尾空格/长度/
  NFD 全无处理 —— 非法名在磁盘 API 处作为任务错误失败。taiji 在引擎层
  净化（激活期名称解析点），净化后/自动重命名后的名称即任务最终名：
  - **URL 派生名的全通道**：非法字符 `< > : " | ? *` + 控制码（C0/DEL）
    + 路径分隔符 → `_`；Windows 保留设备名（CON/PRN/AUX/NUL/COM1-9/
    LPT1-9，含带扩展的形式）在词干后补 `_` 以保留扩展名；尾点/尾空格
    剥离；保扩展名的字节截断（完整形态 `<final name><candidate marker .N><incomplete suffix>`
    （最终名+候选标记 .N+未完成后缀）≤ 254 字节，最终名预算随
    `--http-incomplete-suffix` 收缩，默认 247）；空名回退 `download`。
  - **用户显式名（out=）的轻通道**：剥离路径成分（含 `X:` 盘符前缀）+
    同样长度截断 + 保留名后缀；**不做字符替换**（用户提供的名字最小
    触碰；非法字符留给 OS 报告）。接受面对 `--out` 的既有净化拒绝
    （分隔符/`:`/保留名/尾点尾空格）不变；轻通道补上接受面缺失的长度
    校验。
  - **真名回报**：`tellStatus`/`getFiles` 的 `files[0].path`（活
    `outPath` 与终态条目快照）、sqlite 行的 `out`（恢复/renamePending
    收口的同源）与完成日志全部携带实际磁盘名；冷投影（无活读的暂停/
    终态）优先取行镜像的计划终名而非接受面的原始 out。六个事件 payload
    `[{gid}]` 保持冻结（the fork 同形；前端取 gid + tellStatus 拿名字）。
  - **显式非目标**：macOS NFD 规范化（the fork 与所有考察过的竞品都不
    做）；`\\?\` 长路径前缀（业界以字节上限截断替代）；FAT32/exFAT
    特判（被 254 预算隐式覆盖）；自动重命名多位序号在极长名（词干 >
    预算−5 字节）下仍可能超 NAME_MAX（surge 的 240 全覆盖 / Firefox 的
    254 同样溢出 —— 同类取舍）。
  - 锚点：`taiji-http::naming`（`sanitize_generated_name_with_budget`/
    `sanitize_user_name_with_budget`/`engine_name_budget`）+
    `taiji-core::session::actor::http_task`（drive 名称解析点）。
- **FTP/FTPS**：字符集 = 路径 UTF-8 优先、Latin-1 回退转码（the fork
  不做转换）；`--ftp-pasv=false`（主动模式）显式拒绝（the fork 支持
  PORT）；`--ftp-ssl=none|auth(default)|implicit`（默认 auth）是 taiji
  能力扩展
  （the fork 无 FTPS；`ftps://` scheme 不作为 URI 输入接受）；匿名密码
  默认 `anonymous@`（fork = `ARIA2USER@`）；无 SIZE 支持的 FTP 服务器 =
  该源剔除（the fork 可无总长流式下载；taiji 收紧）；REST 被拒 = 降级
  单连接无位图（两侧同规则）。
- **metalink 选项族**见 §6；**代理/cookie 面**见 §3。
- **导入消费面**（`taiji import`）：the fork 序列化选项行的 header/UA/
  代理/凭据字段在激活组装请求时折入（解析与拒绝和 addUri 同源 ——
  非法值任务级显式失败；socks 代理 = 已声明的 taiji 传输面限制，显式
  拒绝，不绕道直连）；调度/超时域重建到新会话默认值（运行时选项不
  持久化语义；the fork 的调度模型在交叉验证承诺之外）。fork cookie
  不属于序列化任务格式 —— 导入任务以空任务 cookie 集激活，激活期间
  照常捕获 Set-Cookie；需 cookie 门的源要在源侧重建会话（导入预检
  清单中言明）。锚点：`taiji-core::session::actor::http_task`
  （`fold_imported_options`）、`taiji-core::session::persist::import_http`
  （`PREFLIGHT_CHECKLIST`）。
- **`http-max-per-host` 的 addUri 面值域（A3）**：`1..=2^32-1`（u32 域）
  —— 与 CLI 面同域，显式拒绝：addUri 选项值 > 2^32-1 报
  `taiji.option.invalid`，任务被拒（**不落任何行**）。修复前
  `parse_u64_domain` 接受任意 u64，生效面的 `set_cap` 静默钳到
  u32::MAX —— 接受而不生效即是伪装；此处按规格 §4.3 "越域值恒拒绝、
  绝不截断" 的 changeOption 纪律收口。锚点：
  `taiji-core::session::actor::tasks`（addUri 上限解析域检查）；e2e
  锚定测试 = `add_uri_host_cap_domain_rejects_above_u32_without_row`
  （2^33 拒绝 + 零行；域上界 2^32-1 接受，上限意图固定进行）。
- **`http-max-per-host` 上限调整的重启语义（A4）**：addUri 的上限调整
  随任务行 `config_json` 持久化（`host_cap` 键）；守护进程重启/恢复
  激活时，**该任务**的上限意图经与 addUri 相同的通道恢复
  （`HostCap::set_cap`，最后设置胜出）—— 既有 §3 声明只覆盖 "会话内
  回显无漂移"；本条目补全跨重启面。边界：无此选项的任务行不带该键，
  激活时不做事（其他任务行零串扰）；会话 HostCap **初始化值**（CLI/
  全局选项）的语义不变 —— 恢复走运行时调整通道，不是改写初始化面；
  会话内 addUri 即时最后设置胜出行为不变（激活面恢复 = 同一语义跨
  重启延续；恢复激活计为一次新的最后设置）。锚点：
  `taiji-core::session::actor::http_task`（`HttpPersistConfig::host_cap`）、
  `taiji-core::session::actor::tasks`（addUri 固定 + 激活恢复）；e2e
  锚定测试 = `host_cap_intent_persists_and_resumes_lowered_after_restart`
  （上限降到 2 → 关停 → 以默认上限 64 重启+恢复 → 源站并发 Range 的
  真实峰值仍为 2）。
- **续传能力回退语义，现已成文（abdm-2 决定：零行为变化，仅声明）**：
  曾分块过（有位图）的任务重启/再激活时，探测发现服务器**不再支持
  Range**（探测期 200 → 单连接降级，规格 §4.2 决策表行 3/4）—— 语义
  = 静默从零重启（位图不消费；降级路径整文件 GET）+ restarted 语义
  （与 `ResumeDecision::Restart` 的 restarted 面同名同义），与 aria2
  参考对齐（aria2 能力回退时同样从零重启，不单独失败）。双重正确性
  兜底不变：完成时 `--checksum` 终裁（数字面 32）+ If-Match 强 ETag
  条件续传的服务端前置校验（B4 —— 内容漂移在下载中以 412 拒绝并清
  位图从零重启，而不是位图写满后才被校验和发现）。感知面（探测结论
  自 "支持 range" 回退为 "不支持" 这一事实）由产品层经 RPC 事件消费；
  本声明面不新增码位。锚点：`taiji-http::probe`（§4.2 决策表）、
  `taiji-core::session::http::resume`（`ResumeDecision`/restarted
  语义）。

## 9. 远程访问与暴露面（差异声明）

本节声明**受支持的拓扑与暴露面行为**（不是 aria2 交叉验证差异 ——
aria2 无对应守卫面；差异方向 = taiji 安全增强）。锚点：
`taiji-rpc::guards`（连接台账 + 认证退避）、`taiji-rpc::server`
（`conn_gate`/`basic_gate`/弱凭据警告/组合守卫）。

- **受支持拓扑**：绑定与凭据是**两个解耦轴**（对 aria2
  `HttpListenCommand.cc` 交叉验证 —— 绑定只看 `--rpc-listen-all`，默认
  false = 仅回环，`OptionHandlerFactory.cc` A2_V_FALSE 同规则）：回环
  （默认，**无论凭据如何** —— 设置 `--rpc-secret` 或
  `--rpc-user/--rpc-passwd` 不再隐式扩大面；凭据只决定认证门）→
  `--rpc-listen-all` 显式打开 → 0.0.0.0（所有接口）。受控差异（方向 =
  taiji 安全增强；同一组合下 aria2 只 WARN 并照常监听，
  DownloadEngineFactory.cc）：`--rpc-listen-all` 且完全无凭据 →
  **启动即拒绝**（fail-closed；消息含整改指引：设 `--rpc-secret`
  （推荐）或 `--rpc-user/--rpc-passwd`，或撤销 listen-all 恢复回环）。
  无凭据回环形态保留上游 WARN 措辞 + fail-closed 写面，见 §1
  "未认证写门"。**公网裸部署不受支持** —— RPC 面是明文 HTTP（无 TLS；
  生态惯例是隧道方案：wireguard/tailscale/ssh 转发承载机密性与完整
  性），且无租户隔离（下一条）；明文假设 = 凭据可被在途观察者截获，
  须由隧道层吸收。
- **多客户端语义**：单一会话共享一个队列 —— 多客户端以相同凭据连接
  时，看到并操作**同一**任务集/全局选项；无租户隔离，无每客户端队列
  （与 the fork 一致；the fork 同样是全局单会话）。
- **连接限制（引擎常量，非 CLI 旋钮）**：总并发连接（HTTP 在途请求 +
  WS 会话合计）上限 256；每源 IP 上限 32。超限拒绝：HTTP 503 / WS 在
  升级前拒绝（101 绝不发），计入
  `taiji_rpc_conn_rejected_total{scope=total|per_ip}` 指标 + warn。
  正常本地/单客户端使用远低于阈值（门适用于每个绑定面，正常使用绝不
  触发）。
- **认证失败退避**：同一源 IP 连续 ≥5 次认证失败（token 门与 Basic 门
  合并计数）开启指数退避窗（首次 1s，之后每次 ×2，封顶 60s）；窗口期
  内该源的每次认证尝试（**包括正确凭据**）都延迟到窗口结束才处理
  —— 攻击期间同源的合法客户端同样被延迟（按源惩罚；NAT 共享源同理）；
  认证成功重置计数。指标：`taiji_rpc_auth_fail_total`（无 IP 维度标签
  —— 标签基数纪律）+ `taiji_rpc_auth_backoff_active` gauge（有活动
  窗口的源数）。
- **弱凭据警告**：`--rpc-secret` 设置且短于 16 字符 → 一条启动 warn
  （建议 16+ 字符）；不拒绝启动，零行为变化。
- **listen-all 匿名面收紧**：`--rpc-listen-all` 开 + `--rpc-secret`
  已设，且 Basic 未设**或仅用户名**（只设 `--rpc-user` 未设
  `--rpc-passwd` → 密码不校验，零熵 —— 同一裁定：知道用户名即可过
  Basic 传输门，不能算有效凭据；这包括组合守卫消息推荐的整改路径
  形态）时，两个匿名面都由 secret 本身守卫（受控差异，方向 = taiji
  安全增强；aria2 无指标面，向已完成 WS 升级的连接推送通知，无事件面
  认证）：`GET /metrics` 的唯一门 = `Authorization: Bearer <secret>`
  （常数时间比较；匿名 / 仅用户名 Basic / 错误 Bearer → 401 + 1s
  未授权延迟，失败计入认证退避台账 —— 该形态下 Basic 门不叠加：两门
  共享同一 Authorization 头，仅用户名 Basic 不添加凭据熵）；Basic
  传输门继续守卫 WS 升级与 `/jsonrpc`，WS 事件流订阅延迟到首条携带
  合法 `token:` 首参的 Text 消息 —— 非法/非 token 首消息在消耗完 1s
  延迟后断开。其余形态（secret 未设 / 非 listen-all / 带密码的
  Basic）保持现行行为（回环上 `/metrics` 匿名可读，WS 升级即订阅）。
