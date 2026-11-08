# taiji RPC API

[English](./rpc-api.md) | 简体中文

> 本文档为翻译版；与英文原版不一致时，以 [英文原版](./rpc-api.md) 为准
（英文原版是受治理测试钉住的规范本体）。

JSON-RPC 2.0，经 HTTP `POST /jsonrpc`（单条/批量/system.multicall）与
WebSocket（`GET /jsonrpc` 升级）提供服务。认证：首参 `token:` 或 HTTP
Basic（`--rpc-secret` / `--rpc-user` + `--rpc-passwd`）；未设凭据时只绑定
127.0.0.1 且写操作恒被拒绝。公网暴露请走 VPN 或终结 TLS 的反向代理
（引擎不内置 TLS）。

## API 命名面（任一时刻只有一面）

方法与事件的规范命名 = `taiji.*`（默认）。开启 `--rpc-aria2-compat`
（默认 false，会话级启动项）后，方法额外接受 `aria2.*` 别名、六个事件以
`aria2.onXxx` 推送、`system.listMethods`/`system.listNotifications` 呈现
aria2 面 —— 专供外部 aria2 前端直接替换使用与差分交叉验证场景。
**任一时刻只存在一个 API 面；禁止双发**；`system.*` 自省族与
`taiji.*` 扩展方法/事件在两种状态下同名。

## aria2 兼容方法（规范名；`--rpc-aria2-compat` 下接受同名 `aria2.*` 别名）

与 fork（aria2 fork）的完整差异由白名单制度治理：**白皮书之外零差异**；
全部已知差异及其锚点见 [rpc-api-diff.zh-CN.md](./rpc-api-diff.zh-CN.md)（受控活文档；
新条目需 PR + 用户批准）。

| 方法 | 说明 |
|---|---|
| `taiji.addUri` | 添加下载（HTTP（S）/FTP（S）/magnet/torrent URL；多 URI 数组 = 同一文件的多源镜像） |
| `taiji.addTorrent` | 添加 .torrent（base64）。外部完整 payload（目录中文件与种子逐文件长度吻合）= 添加时安排一次初始全量校验（`status=active`,`completedLength` 投影校验进度）；校验完成后按实测位图转入做种（`seed_after_complete` 语义）；payload 部分缺失则照常从零下载 |
| `taiji.remove` / `forceRemove` | 移除任务 |
| `taiji.pause` / `unpause` / `pauseAll` / `unpauseAll` / `forcePause` / `forcePauseAll` | 暂停/恢复（`forcePauseAll` = 强制暂停全部任务，恒答 `OK`;force 收尾差异遵循单任务 pause/forcePause 等价声明，参考锚 `RpcMethodImpl.cc`） |
| `taiji.forceRecheck` | 安排一次盘上复检（**taiji 能力扩展 —— 上游 aria2/fork 的注册面没有此方法**；双命名：规范 `taiji.forceRecheck` + 兼容 `aria2.forceRecheck`，同名同义接受）。仅限 torrent 任务：活动 = 优雅停机 → 全量校验 → 重新入队激活；等待/暂停 = 出队校验后队头重新入队。校验期间 `status` 保持 `active` 且 `completedLength` 投影已校验字节数（与 aria2 校验期 TellStatus 语义交叉验证）；完成后按实测位图恢复（损坏 piece 清零重下；完整 payload 转做种）。返回 gid；重复校验 / 非 torrent / 已完结任务 = 显式错误 |
| `taiji.tellStatus` | 任务状态（含 v2 合成位图与 `http` 子字典） |
| `taiji.getUris` / `getFiles` / `getPeers` / `getServers` | 任务详情 |
| `taiji.tellActive` / `tellWaiting` / `tellStopped` | 任务列表（分页/keys） |
| `taiji.changeUri` | file-entry URI 语义（上游同形臂序：gid 未命中 `Cannot remove URIs from GID#%s`、fileIndex 域校验逐字 `fileIndex is out of range`、回执 `[deleted, added]` 计数；本侧没有 file-entry URI 台账 → 恒为 `[0,0]` 空操作 —— 真实编辑缺口见 rpc-api-diff.zh-CN.md §1） |
| `taiji.changePosition` | 等待队列重排（`POS_SET`/`POS_CUR`/`POS_END` 三模式，越界钳制；只有等待队列可移动 —— 活动/错误项报 `GID#X not found in the waiting queue.`；回执为移动后的整数目标位置；重排与队头重新入队（pause/重启收尾）后 `queue_pos` 全段稳定重编号，重启后保留的 `tellWaiting` 顺序 = 停机时运行时顺序） |
| `taiji.changeOption` / `changeGlobalOption` | 热更新选项 |
| `taiji.getOption` | 任务级选项读取（跨活动/等待/完结三域定位；回显是接受键子集上的字符串值表 —— 活动任务的限速是活桶生效值，`select-file` 返回规范化的 1 起字符串；键集与值形差异见 rpc-api-diff.zh-CN.md §3） |
| `taiji.getGlobalOption` / `getGlobalStat` | 全局面 |
| `taiji.purgeDownloadResult` / `removeDownloadResult` | 记录清理 |
| `taiji.forceShutdown` | 引擎退出 |
| `taiji.getVersion` | 版本（`taiji/<semver>`） |
| `system.listMethods` / `system.listNotifications` / `system.multicall` | 自省与批量 |

## HTTP/FTP 多源下载面

- **多 URI 数组**：`taiji.addUri` 的 URI 参数是数组；多项 = 同一文件的
  镜像（aria2 语义）：全部 http（s）/ftp（s） 项加入任务的源集做多源下载
  （逐源探测与合并；长度不匹配发 `taiji.http.mirror_mismatch`，给定
  `--checksum` 时能通过校验的源胜出）。源清单随任务持久化，重启恢复保持
  同一源集。
- **`tellStatus` 的 `http` 子字典**：`finalUrl` / `connections` /
  `extentsActive` / `blocksDone` / `blocksTotal` / `encoding`（键缺席 =
  identity/未探测）/ `renamePending` / `sources[]`。`sources` 每项 =
  `{url, rate, state}`（rate = 字符串化字节/秒，实测归因；state ∈
  `waiting` | `active` | `demoted` | `removed` | `failed` —— `failed` =
  探测失败或被移出合并表；不再参与本任务的 piece 分配）。该子字典整体是
  taiji 扩展面（aria2 无此键）。
- **FTP/FTPS**:`ftp://` 源恒被接受。FTPS 经 `--ftp-ssl=none|auth
  (默认)|implicit` 表达（taiji 扩展 —— aria2 无 FTPS 能力；不接受
  `ftps://` scheme 作为 URI 输入）。任务级选项：`--ftp-user` /
  `--ftp-passwd`（默认 anonymous/anonymous@；与 `--http-user`/
  `--http-passwd` 分槽保存，不互串）、`--ftp-pasv`（只接受 `true`;
  `false` = 主动模式未实现，显式拒绝）、`--ftp-reuse-connection`（默认
  true）。FTP 差异声明（`ftp-type`/`ftp-proxy` 族不接受、SIZE 不支持源
  剔除、charset 首选 UTF-8 回退 Latin-1 等）以 taiji-core
  `session::options` 的差分声明块为唯一来源。
- **`--ca-certificate`（任务级 CA 面）**：PEM CA 文件路径；任务级是
  **替换**平台信任库（aria2 的 replace 语义，非追加），对 HTTPS 与 FTPS
  均生效；在 `addUri` 选项与 `changeOption` 中同键接受。路径错误/坏 PEM
  = `taiji.option.invalid` 任务拒绝；同时存在
  `--check-certificate=false` 时后者胜（CA 文件被忽略，与 aria2 同）。
  差异声明见 rpc-api-diff.zh-CN.md 的 ca-certificate 条目。
- **Cookie 摄入门（`--load-cookies` + 两个直达方法）**：
  - `--load-cookies <file>`（Netscape cookie 文件，与 aria2 同名同义）：
    三个入口 —— addUri 选项 / `changeGlobalOption`（全局面默认源；显式
    任务级值优先）/ CLI `taiji http` 旗标。文件缺失/不可读/超 1MiB =
    `taiji.option.invalid` 任务拒绝（fail-closed）；坏行逐行跳过（与
    curl 同规则）。生效面 = 任务 CookieStore 预填 + 运行时 Set-Cookie
    吸收（RFC 6265）。
  - `taiji.addUriWithCookies` / `taiji.setTaskCookies`：见 taiji 扩展
    方法表（与 fork 的 parseRpcCookies 形态交叉验证）。
  - **组合语义**：存在 Cookie 注入门（文件源或直达）的任务，`--header`
    中的手工 `Cookie:` 行被剥离、不转发 —— jar 是任务 Cookie 的唯一来源
    （与 fork 的"结构化 Cookie 权威"同构；两条路同时存在时，服务器
    "取第一个 header"的实现会静默丢掉 jar）；没有注入门的任务照常转发
    手工 Cookie header。

## BT 任务文件选择面（`select-file`）

- **接受面**：`addTorrent` / `addUri`（magnet 与 http（s） 的 `.torrent`
  URL）选项字典中的 `select-file` 键 + 经 `changeOption` 重选（仅限
  保留/暂停的 torrent/magnet 任务；活动任务与非 BT 任务 = 显式拒绝 ——
  收紧差异见 rpc-api-diff.zh-CN.md §3；参考 `OptionHandlerFactory.cc`:1 起
  值域 [1, 1048576]，添加面初始选项 + 保留任务走 changeOption）。
- **值语法**：逗号分隔的 1 起文件序号/闭区间，如 `"1-3,5"`。非法值
  （空段/语法错/超出 [1, 1048576] 域）= 调用被**显式拒绝**
  （`taiji.option.invalid`；收紧差异见 rpc-api-diff.zh-CN.md §3）。
- **越界（两段式）**：元数据已落地（.torrent 已解析）= 在添加/changeOption
  面显式拒绝；元数据未落地（magnet 尚未升级 / `.torrent` URL 尚未抓取
  —— 没有文件数可判） = 调用被接受，越界值在升级激活面终绐为显式任务
  错误（与参考实现的延迟应用同向，RpcMethodImpl.cc —— 差异仅在错误的
  显式度）。锚点：`session::options::resolve_select_file_for_meta`
  （单一入口）。
- **生效面**：只有被选文件下载（BEP53 掩码投影，v1 与 v2-only 布局皆
  然）；`getFiles`/`tellStatus.files` 的 `selected` 回显选择面
  （`file_selected` 是唯一来源；pad 项恒为 false）；`getOption` 对
  `select-file` 的回显是规范化的 1 起逗号串。选择随任务持久化
  （`config_json.selected_files`，与 magnet `so=` 同通道），重启恢复还原
  同一选择；等待/暂停任务的重选在重新激活时经 `SetFileSelection` 重放。
- **magnet `so=` 合并规则**（本侧的超集能力设计决策；aria2 无 `so=`
  面）：同一任务上 `so=` 与 `select-file` 并存 = 显式冲突拒绝（选择面
  单一来源 —— 即使两者展开结果相同也一样；错误信息同时点名两个来源
  键）；只给其一 = 该面生效；changeOption `select-file` 替换既有选择。

## CLI 捷径面（`taiji http`）

`taiji http <URL…> [-d dir] [-o name] [--checksum md5|sha-1|sha-224|sha-256|sha-384|sha-512=<hex>]`
= 不启动 RPC 服务的同面捷径入口：直接引导 SessionActor（addUri →
tellStatus 轮询语义），会话数据库与任务行和 RPC 面完全同构 —— 经 CLI
创建的 HTTP 任务同样出现在 `tellActive`/`tellStatus`（`http` 子字典），
并可通过常驻守护进程的 RPC 方法面管理。见用户手册的 `taiji http` 一节
（续传/并发守卫/attach 对比语义）。

## taiji 扩展方法（16 个名字）

| 方法 | 说明 |
|---|---|
| `taiji.createTorrent` | 制作种子（files/outputDir/pieceLength/format/private/announce） |
| `taiji.addTracker` / `taiji.removeTracker` | BT 任务 tracker 动态编辑（见下一节） |
| `taiji.moveStorage` / `taiji.renameFile` | 存储迁移与重命名 |
| `taiji.banAddr` / `unbanAddr` / `listBans` | peer 封禁面 |
| `taiji.setSchedulerPolicy` / `getSchedulerPolicy` | 调度策略 |
| `taiji.setStreamingPlayhead` | 流式 piece 选择播放头 |
| `taiji.setFilePriority` | 多级文件优先级的部分更新：`setFilePriority(gid, pairs)` —— pairs = `[{index, priority}]`（index 为 1 起的客户端文件序；priority ∈ -1..=7:-1 跳过 / 0 普通 / 1..7 高）；未列出的文件不动。仅限 torrent 任务；活动任务引擎内即时生效，等待/暂停任务激活时接收；-1 ⇔ 移出选择集 / 0..7 ⇔ 加入（与 `select-file` 单一选择面互恰）；持久化于 config_json（跨重启保留）。回显 = `tellStatus`/`getFiles` files[] 的 `priority` 键。写面（`--rpc-secret` 未设时被写门拒绝）。aria2 无此方法（对齐 libtorrent `file_priority` 能力的自有扩展） |
| `taiji.setDiskTier` / `getDiskTier` | 磁盘分配层级 |
| `taiji.getCapabilities` | 能力发现（扩展方法/事件清单） |
| `taiji.addUriWithCookies` | 携结构化 Cookie 添加下载（uris, cookies[], options?）：cookies 逐项 `{name, value, domain, path?, hostOnly?, secure?, httpOnly?, expiresAt?}`（fork parseRpcCookies 逐字校验 —— ≤300 条 / 未知字段拒绝 / 过期时间 = 非负 Unix 毫秒）；全部 URI 必须是 http（s）；Cookie 进入任务 CookieStore（与 `--load-cookies` 同存储面），手工 `Cookie:` header 被剥离（结构化 Cookie 权威）；不接受 `.torrent` URL（元数据面无 Cookie 消费点）。早期立场翻转后接受；Motrix 基线 |
| `taiji.setTaskCookies` | 运行时覆写等待/暂停 HTTP 任务的 Cookie jar（gid, cookies[]）：整集替换 + 行持久化（跨重启保留）；活动/非 HTTP 任务 = `Task cookies can only be set on waiting or paused cookie tasks.`。早期立场翻转后接受；Motrix 基线 |

## BT 任务 Tracker 动态编辑（`taiji.addTracker` / `taiji.removeTracker`）

- **`taiji.addTracker(gid, urls, options?)`**:`urls` 为单字符串或字符串
  数组（≥1）；可选 `options.position`（整数/数字字符串）= 插入 tier 位置
  （0 起，越界钳制到表尾），默认追加表尾。每个 URL 成为**独立 tier**
  （BEP12 每 URL 一 tier，与 `--bt-tracker` 全局导入语义对齐）；已在表中
  的 URL 跳过（幂等，不计入回执）。回执 = `{"removed":0,"added":N}`
  （实际新增数）。
- **`taiji.removeTracker(gid, urls)`**：按 URL 精确匹配删除（含
  announce-list tier 清理与 tier 编号收紧）；全部删空后空表 = 纯 DHT 面
  （合法形态）。回执 = `{"removed":N,"added":0}`。
- **生效面**：活动任务经引擎 tracker 表重建即时生效（announce 面；立即
  可见于 `getServers`/`tellStatus.announceList`）；等待/暂停任务被编辑
  并持久化（`config_json`，跨重启保留，重新激活时生效）。
- **拒绝面**（显式错误，零改动）：magnet / `.torrent` URL 元数据阶段任务
  （升级前 tracker 面不可编辑）、HTTP 任务（无 tracker 面）、已完结
  （结果域）任务（收尾时 payload 已剥离，编辑永远不会生效）。两个方法
  都是写面：`--rpc-secret` 未设时被写门拒绝。
- 与 `--bt-tracker` 全局导入的关系：全局集在任务激活时并集合并（已编辑
  的任务级表预先保留）；会话内再次全局导入仍把增量 —— 对任务级表去重后
  —— 追加到在飞任务。

## 事件（WebSocket 通知）

载荷统一为 `{"jsonrpc":"2.0","method":"…","params":[{"gid":"<hex16>"}]}`。

- 六事件（规范名 = `taiji.onXxx`;`--rpc-aria2-compat` 下为
  `aria2.onXxx`）：`onDownloadStart` / `onDownloadPause` /
  `onDownloadStop` / `onDownloadComplete` / `onDownloadError` /
  `onBtDownloadComplete`（BT 任务完成下载转入做种发
  `onBtDownloadComplete`；任务终结发 `onDownloadComplete`）
- taiji 扩展（恒为 `taiji.*`，不受 compat 切换）：`taiji.recoveryStarted`
  / `taiji.recoveryCompleted`（哈希恢复过程；载荷含文件索引）

## 主要选项

`--listen-port`、`--enable-dht`、`--enable-dht-6`、`--bt-require-crypto`、
`--bt-min-crypto-level plain|arc4`、
`--peer-connection-type tcp|utp|prefer-tcp|prefer-utp`、`--peer-id-prefix`、
`--bt-enable-upnp`、`--bt-enable-nat-pmp`、`--bt-lsd`、`--bt-stop-timeout`、
`--seed-ratio`、`--seed-time`、`--bt-tracker`、`--dht-entry-point[-6]`、
`--sqlite3-db-path`、`--rpc-secret`、`--rpc-listen-all`、`--rpc-listen-port`、
`--rpc-user`、`--rpc-passwd`、`--rpc-max-request-size`、`--rpc-allow-origin-all`、
`--rpc-aria2-compat`（API 别名面开关，见上文）、
`--max-overall-download-limit`、`--max-overall-upload-limit`、
`--max-download-limit`、`--max-upload-limit`、`--bt-hash-check-seed`、
`--check-integrity`、`--enable-falloc`、
`--max-concurrent-downloads`、
`--max-concurrent-seeds`、`--max-concurrent-checks`、
`--media-synthesis-concurrency`（四池预算三件套 —— taiji 扩展，见差分
声明 §3）。
