# taiji 引擎规格书

[English](./spec.md) | 简体中文

> 本文档为翻译版；与英文原版不一致时，以 [英文原版](./spec.md) 为准（英文原版受 spec_matrix 一致性测试钉住）。

| | |
|---|---|
| Version | v0.3 |
| Date | 2026-10-26 |
| Scope | The whole taiji engine: BitTorrent, HTTP/FTP, Metalink, session, RPC, CLI |
| Related | aria2 （read-only behavioral reference）； per-module anchors in [docs/design/](design/) |

本文档按引擎**当前实际状态**描述：系统架构、协议行为、调度、存储、各面
与资源模型。凡行为刻意偏离参照（aria2、libtorrent、BEP 文本）之处，差异
只声明一次 —— 或在本文、或在偏差登记表（§3.2）、或在
[rpc-api-diff.md](./rpc-api-diff.zh-CN.md) —— 并由测试钉住。因遗漏而未
声明的偏离按 bug 处理。

一致性注记：§3.1 矩阵与 §3.2 偏差登记表由
`crates/taiji-bt/tests/spec_matrix.rs` **执行级校验**（execution-checked）
—— 文档编辑丢掉规范性锚点、或实现不再匹配所声明的状态，都会使 CI 失败。

---

## 1. 范围与定位

**taiji** 是以 Rust 编写的多协议下载引擎，以单一 sidecar 二进制（`taiji`）
交付：在一个会话模型下覆盖 BitTorrent（v1/v2/混合）、HTTP（S）、FTP（S）
与 Metalink，由 aria2 兼容的 JSON-RPC 面驱动。

**目标**

- G1. 完整的 BitTorrent 下载/做种：v1、v2 与混合种子，含完整发现机制
  （DHT/PEX/LSD）、tracker（HTTP/UDP，双栈）、µTP、MSE、私有种子、
  超级做种、打洞。
- G2. 多源 HTTP/FTP 下载器：带 AIMD 响应的连接池、range 断点续传、校验
  和验证、Basic/Digest 认证、带 Public Suffix List 防御的 cookie、
  Metalink v4 编排。
- G3. aria2 兼容的 RPC 与选项面：Motrix 前端无需协议改动即可驱动 taiji；
  每一处差异都事先声明，而非被动发现。
- G4. 产品级会话管理：队列语义、任务级与全局选项、事件、SQLite 持久化、
  崩溃恢复、从遗留 fork 数据库迁移导入。
- G5. 内存加固的内核：每个受远端影响的分配都有上限，入口拒绝而非修复。
- G6. 在负担得起之处求确定性：引擎核心注入时钟、策略接缝表驱动，行为
  测试无需 sleep。

**非目标**

- WebTorrent/WebRTC、I2P、SSL 种子、BEP 51 DHT infohash 索引、
  BEP 17 HTTP-seed 格式（支持 BEP 19 webseed）。
- 双向 `.aria2` 控制文件兼容（只读导入）。
- libtorrent 库 API（承诺的表面是 aria2 RPC 面加 taiji 扩展）。
- 移动平台作为一等目标（CLI 在 Rust 能构建之处皆可构建；CI 门禁
  Ubuntu、macOS、Windows）。

---

## 2. 系统架构

### 2.1 进程形态

一个二进制，六种形态：

| 形态 | 命令 |
|---|---|
| 裸下载 | `taiji file.torrent [options]` —— 下载，随后做种直到 Ctrl-C |
| 下载 + RPC | 裸形态加 `--enable-rpc` —— 引擎与 RPC 服务器共享同一会话 |
| 空闲守护 | `taiji --enable-rpc ...` —— 会话常驻，任务经 RPC 到达 |
| 一次性 HTTP | `taiji http URL [options]`（也接受 `ftp://`、metalink 文件） |
| 迁移导入 | `taiji import <db> [--dry-run]` |
| 创建种子 | `taiji create-torrent <file…>` |

停机优雅且有预算：SIGINT/SIGTERM 启动 1 s 拆除预算（NAT unmap 独享
250 ms 切片）；SIGKILL 之后靠 SQLite WAL 恢复加恢复时复检路径存活。

### 2.2 Actor 拓扑

```
                 RPC (HTTP/WS/TLS)            CLI one-shot pipeline
                       │ addUri/changeOption…        │
                       ▼                             ▼
        ┌──────────────────────────  session actor (taiji-core) ─────────────┐
        │  task registry · queue semantics · option tables · events ·        │
        │  persistence (SQLite job queue) · cookie/tracker/ban policy        │
        └───────────────┬───────────────────────────┬────────────────────────┘
                        │ EngineCommand (bounded)   │ HttpTask driver
                        ▼                           ▼
        ┌────────  engine actor (taiji-engine, single writer) ──────┐   ┌─ HTTP worker pool ─┐
        │  dispatch round · peer arms · dial/assemble · verify pool  │   │ coordinator/AIMD/  │
        │  choke policy · tick (1 s) · endgame · memory walls        │   │ stall-steal/final  │
        └───────────────┬───────────────────────────────────────────┘   └─────────┬──────────┘
                        │ faces (per-task)                                        │
                        ▼                                                         ▼
        ┌────────────────────  transport (taiji-io)  ─────────────────┐   ┌─ store (taiji-store) ─┐
        │  TCP · µTP/LEDBAT · MSE · UDP demux · DNS cache · NAT ·    │   │ layouts · write cache │
        │  rate limits · knobs registry                              │   │ SQLite · recovery     │
        └─────────────────────────────────────────────────────────────┘   └───────────────────────┘
```

拓扑强制执行的规则：

- **每引擎单写者。** 所有可变引擎状态只由引擎 actor 触碰；会话与 RPC 经
  无锁镜像（原子量在单一收束点发布）与命令通道读取 —— 绝不直接伸手进
  引擎状态。
- **处处有界通道。** 图中每个队列都有容量；背压表现为队列丢弃或命令
  拒绝，绝非无界增长。
- **锁粒度小且绝不跨 `.await` 持有。** 锁中毒按策略视为致命（§8）。

### 2.3 Crate 分层

十二个 crate，依赖严格向下指：`taiji → taiji-rpc → taiji-core →
{taiji-engine, taiji-http, taiji-store} → taiji-bt → taiji-domain →
taiji-io`（`taiji-metalink` 位于 `taiji-http` 旁侧，由 core/rpc/cli 消费；
`taiji-segment` 是冻结的切分词表，由 core/engine/http/media 消费；
`taiji-media` —— HLS/DASH 编排加 ffmpeg sidecar 宿主 —— 同样位于
`taiji-http` 旁侧，由 core/cli 消费）。跨 crate 再导出保持历史路径稳定
（`taiji_core::engine::*`）。

| Crate | 职责 |
|---|---|
| `taiji-io` | uTP、MSE、UDP demux、DNS 缓存、NAT 穿透、限速、旋钮登记表 |
| `taiji-domain` | 共享领域类型：GID、metainfo 投影、hooks、做种策略 |
| `taiji-bt` | wire 协议：bencode、peer wire、DHT、tracker、PEX/LSD、magnet、BEP 52 树 |
| `taiji-store` | 磁盘布局、写缓存（先验证后落盘）、SQLite 持久化、恢复 |
| `taiji-engine` | 单写者引擎：分发、peer 臂、策略、内存墙 |
| `taiji-http` | HTTP/FTP 客户端引擎：探测、调度器、协调器、worker、收尾 |
| `taiji-metalink` | 带加固上限的 RFC 5854 解析器 |
| `taiji-segment` | 冻结的切分词表：三个 segment trait + 签名闭包 |
| `taiji-media` | HLS/DASH VOD 编排 + ffmpeg sidecar 的 exec-shim 宿主 |
| `taiji-core` | 会话 actor：任务生命周期、选项面、事件、持久化胶水 |
| `taiji-rpc` | JSON-RPC 服务器：分发、认证、TLS、WebSocket、指标 |
| `taiji` | `taiji` 二进制（包名 = bin 名）：download / daemon / http / import / createTorrent |

### 2.4 并发与失败策略

- 派生的引擎/worker 任务中的 panic 由 watcher 捕获并转为终态任务失败，
  附一次指标计数 —— 进程存活，任务如实失败。
- 锁中毒按策略视为致命：每个 crate 的 `lock()` 辅助函数带理由地 expect；
  临界区都是单字段读写，因此锁中毒意味着某条不变量被破坏，响亮失败汇入
  watcher。测试代码可保留宽松写法。
- 优雅降级是显式的：NAT unmap 与 fsync 失败降级为一条日志，而不是任务
  失败；元数据/持久化失败以真实错误链使任务失败（保留 `source()`）。
- 工作区全域禁止 `unsafe`（`unsafe_code = "forbid"`）；代码树中 unsafe 块
  为零。机密绝不进入日志或 `Debug` 输出 —— 脱敏 `Debug` 实现覆盖 RPC
  secret、任务凭据与 MSE 密钥材料。

---

## 3. BitTorrent 引擎

### 3.1 协议一致性矩阵

| BEP | 机制 | 状态 | 说明 |
|---|---|---|---|
| BEP 3 | bencode + peer wire，BT v1 | ✅ | 按上下文区分 strict/permissive；i64 域含 `i64::MIN`；v1 piece 长度接受任意正整数（入口无上限钳制；适用 §6 的墙） |
| BEP 5 | DHT（Mainline Kademlia） | ✅ | 路由表维护、bootstrap、node-id 持久化 |
| BEP 6 | fast extension | ✅ | 出站协商门控；reject/suggest/have-all+have-none；`pending items` 注记（未实现的 suggest 语义）登记于 §3.2 |
| BEP 7 | IPv6 tracker 扩展 | ✅ | HTTP 与 UDP 面上的 `peers6` |
| BEP 9 | magnet + ut_metadata | ✅ | 定尺寸 piece 协商；元数据组装器有预算（§6） |
| BEP 10 | 扩展协议 | ✅ | 以 our-id 为主路由；未知 m-dict 键忽略 |
| BEP 11 | PEX | ✅ | 首条消息豁免；flags 部分实现（仅 bit0/bit1） |
| BEP 12 | 多 tracker | ✅ | announce-list **全量 tier 摄取**（tier 内保序；每条 magnet `tr=` 成为一个 tier）；私有种子额外强制单在途门控（BEP 27） |
| BEP 14 | LSD | ✅ | IPv4 多播；opt-in `--bt-lsd`（默认关，与 aria2 对齐） |
| BEP 15 | UDP tracker | ✅ | connection-id 生命周期；重传退避 5s/10s（见 §3.2）；双栈 |
| BEP 16 | 超级做种 | ✅ | advertise 调度 |
| BEP 19/21 | webseed / upload-only | ✅ | 逐源晋升/降级；upload-only webseed 模式 |
| BEP 27 | 私有种子 | ✅ | 无 DHT/PEX/LSD；tracker 单在途门控 |
| BEP 29 | µTP | ✅ | LEDBAT 方言（RFC 6817 基础时延模型；选择性 ACK；RFC 6817 的缺失项登记为偏差） |
| BEP 32 | DHT IPv6 | ✅ | `nodes6` + 双族 `want` 语义；整回复 1024B 帧门控 |
| BEP 42 | DHT 安全 | ✅ | token 派生 + 强制执行，含文档化的豁免 |
| BEP 47 | padding / symlink 属性 | 部分支持 | padding 文件绝不写入、绝不请求，但可对外服务；`symlink` 属性被解析并保留，不在磁盘物化（已声明偏差，§3.2） |
| BEP 48 | tracker scrape | ✅ | 实现超出 aria2 表面（逐 tracker 的 scrape 面） |
| BEP 51 | DHT infohash 索引 | 非目标 | 已声明；长期做种指标超出范围 |
| BEP 52 | v2 / 混合 | ✅ | Merkle 文件树、层校验（32B 二进制层键，§5.1）、v1/v2 交叉检查、双 swarm |
| BEP 53 | magnet 文件选择 | ✅ | `so=` 区间与单索引，有上限（§6） |
| BEP 55 | 打洞 | ✅ | 打洞接线：经 PEX 中继会合，对存在探测安全的回复 |
| MSE/PE | 协议加密 | ✅ | DH-768 + ARC4；require/prefer/plain；`--bt-require-crypto`、`--bt-min-crypto-level` |

每个处理不可信字节的解码器都是全函数（畸形输入不 panic）且经 fuzz；fuzz
语料覆盖 27 个目标（`fuzz/README.md`）。本矩阵与下方偏差登记表由
`crates/taiji-bt/tests/spec_matrix.rs` **执行级校验** —— 文档编辑丢掉
规范性锚点、或实现不再匹配所声明的状态，都会使 CI 失败。

### 3.2 偏差注记

相对参照（BEP 文本、aria2、libtorrent）的偏差。凡有差异而此处无注记者，
即为 bug。

1. 元数据卫生是**拒绝而非改写** —— 名字或结构未过净化的种子被拒收，
   绝不就地修复。
2. **non-UTF-8** 遗留种子：凡线上格式允许之处，名字按字节保真保留；
   入口不做有损转码。
3. Cookie **单标签**域名：直接拒绝（public-suffix 收割防御）；多标签
   public suffix 走三表 PSL 判定。
4. piece 层缺失时降级为从文件树**哈希恢复**，前提是树本身通过校验
   （整文件准入，绝不部分信任）。
5. UDP tracker 重传保留 aria2 的 **5s/10s** 退避，而不采用 BEP 15 的
   建议阶梯（`15 × 2^n`）。
6. DHT token 按 BEP 42 绑定 **（ip, port）**；豁免清单逐字遵循 BEP 文本。
7. piece 长度入口在 §6 的墙之前使用完整 **i64** bencode 域 —— 解析时
   不做静默截断。

### 3.3 Metainfo 与文件布局

- **v2 优先的数据模型**：文件投影到 Merkle 树（逐文件 piece 层、32B
  二进制层键）；v1 是退化的单层情形；混合种子以一个 piece 空间服务两个
  swarm，用逐文件逻辑偏移。
- 入口门控（所有臂共用一条路径）：piece 长度 ≤ 16 MiB、文件数与字节
  预算、层健全性、带 Windows 保留名与长路径策略的名字净化。元数据卫生
  是拒绝而非改写。
- `info_hash` 身份：v1 是 info 字典上的 SHA-1；v2/混合是截断到 20 字节的
  Merkle 根 —— 两个 swarm 共享一个身份、各自独立 tracker announce。

### 3.4 Piece 流水线

- **请求窗口**按 peer 由带宽-时延积驱动：目标 = `3 s × rate EWMA /
  16 KiB`，钳制于 `[floor, 256]`，带慢启动（每收到一个 block +1）、滞回
  带 `[0.7w, 1.3w]`、真实世界下限，以及抖动自适应档（更长的平滑窗口）。
  遗留的 aria2 倍增启发式保留为兜底模式（`BH_REQUEST_WINDOW_BDP=0`）。
- **分发**是逐 peer 的两阶段台账（requested/writing/finished），带终局
  机制（last-mile 持有者集合、重复上限 ×2、快层忙碌门控）、相邻 piece
  链跳过、半到 piece 的软记账，以及为受限上行按预算缩放的 unchoke 槽位。
- **验证**在池中运行，有逐面 piece 预算；先验证后落盘不变量是绝对的
  （§5.2）。智能封禁按 peer 关联哈希失败并带假释窗口。
- **阻塞**：一报还一报（tit-for-tat）加乐观轮（aria2 兼容的时序）、
  做种侧排名轮，以及为受限上行按预算缩放的 unchoke 槽位（旋钮门控）。

### 3.5 DHT

Mainline Kademlia 加 BEP 42 安全扩展：token 派生与强制执行、带桶分裂的
路由表维护、从配置的 router 引导、node-id 持久化、查询速率限制、经
`nodes6` 与双族 `want` 的 IPv6。BEP 51 infohash 索引是已声明的非目标。

### 3.6 Tracker

HTTP 与 UDP 面共用一套 announce 策略：分层列表（BEP 12）、逐 tracker
间隔且遵守 `min-interval`、UDP 上的 connection-id 生命周期、scrape
（BEP 48）、IPv6（`peers6`/BEP 7）、失败退避（5s/10s，§3.2），以及逐
tracker 的凭据受理面。私有种子把 announce 门控为单在途请求（BEP 27）。

### 3.7 Peer 管理

- **阻塞**：一报还一报互惠加乐观轮（aria2 时序）；做种侧排名轮；为
  受限上行按预算缩放的 unchoke 槽位（旋钮门控，已声明的偏离）。
- **封禁**：按 peer 关联哈希失败并带假释窗口；会话启动时加载逐 IP 封禁
  清单；地址卫生（拒绝私有/保留网段、自连检测）在拨号与入口两处施加。

### 3.8 µTP 与 MSE

- **µTP（BEP 29）**：LEDBAT 拥塞控制带基础时延学习、选择性 ACK、包级
  接收台账（进程级上限），以及可配置的 TCP/µTP 拨号策略（prefer-* 每个
  传输回退一次）。
- **MSE**：DH-768 密钥交换、ARC4 方向密钥、带 plain 回退的 crypto
  provide/require 选择；`--bt-require-crypto` 拒绝遗留入站，
  `--bt-min-crypto-level` 选择 ARC4 档位。

### 3.9 做种与完成

完成判据：分享率与/或做种时长（aria2 语义），外加分离的纯做种模式（不占
并发槽位）。优雅停机在数据 fsync 屏障之后落盘最终状态。引导已完成的文件
集在盘上重新校验（`--check-integrity`、`forceRecheck`），复用与崩溃恢复
共享的唯一复检实现。

---

## 4. HTTP/FTP/Metalink 引擎

### 4.1 探测

一次 HEAD/GET 协商确立最终 URL、range 可接受性、大小与摘要提示。重定向
链在跟随时施加**目标 IP 卫生**：公共跳之后再重定向到私有/保留地址即拒绝
（fail-closed；DNS 应答以同样方式检查）。Digest 挑战按字节保真解析
（non-ASCII realm 得以幸存）。

### 4.2 调度器与 AIMD

extent 网格分配器发放租约；block 是持久化单元；薄区整块下限防止尾部
碎片化；带偷取禁令的终局门控防止尾部颠簸。AIMD：进展上加性增长、失败时
乘性下降并带失败预算；遵守 `Retry-After`；连接错峰与逐主机许可塑形冷启
动爬坡。

### 4.3 Worker 与停滞偷取

逐源 worker 池执行 extent 请求；心跳活性标记沉默 worker；协调器带安全
余量地从停滞 worker 偷取租约（偷取竞态只浪费带宽）；手动重定向与降级源
作降格处理而非使任务失败。

### 4.4 收尾与校验和

校验和验证（六个哈希族）遵循先验证后重命名顺序；带 Windows 保留名策略
的防碰撞命名；part 文件生命周期（create → write → close → rename）逐
文件原子，并有成文的目录 fsync 降级契约。

### 4.5 认证与 cookie

HTTP Basic 与 Digest（RFC 9110 解析，non-ASCII realm 按字节保真）；逐
方案凭据槽带首配即赢（first-match-wins）的代理语义；cookie 罐应用完整
Public Suffix List（三表判定：exception > exact > wildcard），两个摄取
面都有收割防御，运行时有 LRU 上限。

### 4.6 FTP

被动模式带 SSRF 防护的 `PASV` 地址策略（三态判定）、显式与隐式 TLS、逐
方案凭据槽、带回复排空失步降格的传输复用，以及特性门控的 sizing。

### 4.7 Metalink v4

RFC 5854 解析带加固上限（entity/DOCTYPE 闭合、大小与深度限制、charset
规则）、镜像选择（`language/os/version`、`preferred-protocol`、位置
优先级）、逐文件校验和验证，以及 metaurl 到种子的转换并送入 BT 引擎。

---

## 5. 存储与持久化

### 5.1 磁盘布局

v1 填充式与 v2 紧凑式文件布局，带逐文件逻辑偏移；路径净化带 Windows 保留
名与长路径（`\\?\`）策略；piece 层键是 **32B 二进制** pieces 根（绝不用
hex 文本）；稀疏预分配；逐平台打开标志（Linux/Android 用 `O_NOFOLLOW`、
Windows 用 `FILE_FLAG_OPEN_REPARSE_POINT` —— 其余 unix 移植在跟进中）。

### 5.2 写缓存与验证

`write cache → verify pool → disk`，**先验证后落盘**由 proptest 锁定的
不变量强制执行：任何字节在其哈希通过验证之前不会抵达磁盘；逐出取最小
损失；存在面向有界溢出窗口的 `spill` 旁路，且保持同样的顺序保证。
Windows 上的写门控串行化共享句柄写入，使 `Send + Sync` 承诺是结构性的。

### 5.3 SQLite 持久化

WAL 模式、单写者作业队列（所有权 = 排他性）：session、tasks、trackers、
DHT nodes、IP guard、cookies 各有其行。周期保存
（`--save-session-interval`），优雅停机导出为 aria2 兼容的文本会话格式
（原子 `tmp`+rename，0600）。迁移导入器只读地读取遗留 fork 数据库与
`.aria2` 文件，带 dry-run、去重，以及 purge-through-aria2 选项。

### 5.4 崩溃恢复

WAL 重放 + 位图信任规则 + 对在途 piece 的复检。复检路径总是把任务重新
入队，即使进度行读不出来（跳过回写，行状态照样推进）。

### 5.5 迁移导入

`taiji import` 只读地读取遗留 fork 数据库与 `.aria2` 控制文件：三层 fork
预检、导入前备份、作为只读快照的 dry-run、按身份去重、fail-closed 的
加载错误、回执导出，以及可选的 purge-through-aria2 辅助器。一个 sqlite
锁文件保证每个数据目录单一会话。

---

## 6. 资源模型（内存墙）

每个可被远端影响的计数器都有上限；超出预算的表现是拒绝、逐出或断连 ——
绝不落入无界分配。

| 预算 | 默认值 | 范围 |
|---|---|---|
| 在途未验证字节 | 384 MiB（软性；钳制 128 MiB–4 GiB） | 进程，写缓存准入 |
| µTP 接收台账 | 64 MiB | 进程，重排 + 挂起窗口 |
| magnet 元数据组装器 | 16 MiB | 逐任务 |
| DHT 路由记录 | 8 192 条 | 逐族 |
| RPC 请求 | 10 MiB 体；批量 ≤ 1 000；子调用 ≤ 10 000 | 逐请求 |
| cookie 文件 | 1 MiB；运行时条目封顶，LRU | 任务 |
| `so=` 选择 | 2²⁰ 条 | 逐 magnet |
| tracker 层级 | 256/任务，1 024 全局 | 会话 |
| piece 长度 | ≤ 16 MiB | 元数据入口（所有臂） |
| 排队元数据 | 1 024 行 / 256 MiB 估算 | RPC 入口 |

旋钮登记表：62 个 `BH_*` 环境变量（解析一次、类型化访问器、默认值与回退
在定义处成文 —— `crates/taiji-io/src/knobs.rs`）。凡经过度量的策略接缝
都有旋钮把上游（aria2/libtorrent）行为逐位还原。

---

## 7. 会话与任务模型

### 7.1 GID 与生命周期

16 位十六进制、aria2 风格的标识符，带跨重启保留。任务按 waiting →
active → complete/error 流转，队列语义镜像参照实现（同槽转换、位置操作、
force-save 区分）。

### 7.2 队列语义

队列管理器是纯的、可测试的状态机，与参照实现的逐行转写交叉核对（饱和
算术，以上游溢出为成文理由）。

只取元数据的 magnet 任务使用独立的四槽队列，文件选择流程不会被已满的文件
下载槽阻塞。暂停和启动恢复保护优先于两类队列；元数据意图跨重启持久化，
普通 magnet 自动升级任务仍使用文件下载队列。

Fetching 共用会话级 DHT 与 TCP/µTP 监听器。每个种群共享元数据组装，逐 peer
流水线请求 4–8 个块，限制重复请求数量，重派拒绝或停滞的块，并在接受元数据
前校验 infohash。PEX 传输标记触发提前 `ut_holepunch`，宿主 NAT 映射绑定当前
监听实例。magnet 明确提供的源与 peer 获取并行竞速；有界的已验证缓存只复用
info 数据，不保留旧 tracker 凭据。

### 7.3 选项面

aria2 兼容的名字面（全局 + 逐任务；启动 vs 热更新能力位），已声明的
不接受名字与已声明的语义差异登记于
[rpc-api-diff.md](./rpc-api-diff.zh-CN.md) 并由治理测试钉住。未知名字像
aria2 一样忽略；已知但未接线的名字回显其值（绝不冒充生效值）。

### 7.4 事件

六个 aria2 事件（`onDownloadStart/Pause/Stop/Complete/Error`、
`onBtDownloadComplete`）在一条总线上发出，带背压策略；规范 `taiji.onXxx`
名加兼容别名，绝不同时双发。

### 7.5 错误分类

稳定字符串码与 HTTP 状态类 1:1 映射（404→3、401→24、5xx→29、……）——
映射表可执行且逐行钉住。

---

## 8. RPC 面

JSON-RPC 2.0 位于 `POST/GET /jsonrpc`（HTTP 与 WebSocket；可选 TLS，用
`--rpc-secure/--rpc-certificate/--rpc-private-key`）。认证：secret token
（SHA-256 折叠后常数时间比较）与/或 HTTP Basic；无 secret 时写方法被
拒绝。aria2 方法面（约 40 个方法）逐字原样承诺；taiji 扩展
（`taiji.addUriWithCookies`、`taiji.setTaskCookies`、`taiji.forceRecheck`、
`taiji.createTorrent`、metalink 摄取）使用规范 `taiji.*` 名。批量与子调用
上限约束放大效应。Prometheus 指标端点暴露引擎 gauges/counters/histograms
（`crates/taiji-rpc/src/metrics.rs` 是族清单）。

---

## 9. 可观测性

- 日志：`tracing`，JSON（机器）或文本（人类）格式；URL 与凭据在 sink 处
  脱敏；逐 target 级别；安静 piece 日志旋钮用于取证噪声控制。
- 指标：上面的 RPC 端点；每个族都成文给出基数规则与注入接缝。
- 旋钮登记表兼任调优/可观测性面（§6）。

---

## 10. 安全模型

- 机密绝不进入日志或 `Debug` 输出 —— 脱敏 `Debug` 实现覆盖 RPC secret、
  任务凭据与 MSE 密钥材料；认证比较在摘要折叠后以常数时间运行。
- 不可信输入由全函数解码器解析（不 panic）并经 fuzz；入口拒绝而非修复
  （§3.2 注 1）。
- 重定向与代理地址对照私有/保留网段检查（fail-closed）；cookie 罐经 PSL
  防御收割；RPC 面给放大效应封顶。
- 静态落盘：SQLite sidecar 与会话导出以 0600 权限写入。

---

## 11. 兼容性纪律

- **aria2 是行为参照**：选项名、队列语义、RPC 形状与错误码保持对齐，除非
  差异已声明。声明存于 [rpc-api-diff.md](./rpc-api-diff.zh-CN.md)
  （表面）与 [docs/design/](design/)（指向 aria2/libtorrent 源码的机制级
  锚点，带偏离注记）。
- 这些声明在 CI 中强制执行：选项表、方法登记表、错误码映射与上面的一致
  性矩阵都对照代码检查，文档与实现无法悄然漂移。
- 上游引用使用文件 + 符号锚点（不带行号），因此在上游变动后依然有效。

---

## 12. 测试与 CI

- 2 912 个工作区测试：逐 crate 单元套件、wire/集成套件（回环
  DHT/MSE/NAT/tracker/PEX/engine-loop）、持久化与恢复套件（击杀窗口复检、
  损坏注入）、HTTP mock 服务器（probe/redirect/auth/cookies/H2/FTP 容
  器）、CLI e2e（真实二进制，≥1 GiB 夹具）、每个策略接缝的决策表、解析
  器与缓存的 proptest、27 个带种子语料的 fuzz 目标。
- CI（GitHub Actions）：Ubuntu 24.04 / macOS / Windows 上 fmt + clippy
  `-D warnings` + 全量测试，工具链钉住（1.98）以阻止 stable 通道漂移；
  非 Linux 主机跑 store/bt/http 子集；一路 no-default-features 守护
  metalink-off 构建。规格一致性套件（§3.1）经执行级校验，因此矩阵与本文
  档无法偏离代码。

---

## 13. 术语表

- **face（面）** —— 引擎里的逐任务槽位（一个 swarm = 一个面）。
- **wall（墙）/ budget（预算）/ ledger（台账）** —— 资源的硬或软上限，
  加上强制执行它的记账（§6）。
- **decision table（决策表）** —— 一种测试形态，为某策略接缝枚举输入 ×
  判定，凡上游参照存在处即从其转写而来。
- **declared divergence（已声明的偏离）** —— 相对 aria2 的有文档、有测试
  钉住的差异；其余任何差异都是 bug。
