# taiji 用户手册

[English](./user-manual.md) | 简体中文

> 本文档为翻译版；与英文原版不一致时，以 [英文原版](./user-manual.md) 为准。

## HTTP/FTP 一次性下载（`taiji http`）

```sh
taiji http <URL…> -d <dir> [-o 文件名] [--checksum sha-256=<hex>]
```

- 多个 URL = 同一文件的多个镜像（aria2 addUri 语义）；接受 ftp/ftps。
- **断点续传**：会话数据库 `taiji.sqlite3` 中的位图是续传的唯一事实源。
  进程被杀（包括 kill -9）之后，**用相同参数重跑**即可自动接续未完成任务，
  不会重复下载；`--continue=false` 不改变该行为（本引擎续传恒开 —— 这一
  反转已显式声明）。
- **`--checksum <algo>=<hex>`**（algo ∈ md5|sha-1|sha-224|sha-256|sha-384|
  sha-512）：完成时做整文件校验；不匹配 = 任务失败（退出码 1），数据以
  `<file>.part` 留在磁盘供检查，不会留下损坏的最终文件。
- 未完成数据写入 `<file>.part`（`--http-incomplete-suffix` 可配置，创建
  任务时随任务持久化），完成后原子改名。
- **并发守卫**：每个会话数据库同一时刻只允许一个 taiji 会话
  （`<db>.lock` 内核文件锁）；第二个进程立即退出并给出明确报错，绝不会
  共写同一个 `.part`。
- attach 对比：接续未完成任务时会校验其持久化选项 —— 与任务不一致的
  `--checksum` 被**拒绝**（未完成任务按创建时的 checksum 收尾）；其他
  差异（例如后缀）仅告警，持久化值优先。
- 诚实边界：任务**失败**后重跑 = 全新的任务、从零下载（错误行不在恢复面
  内；`.part` 留盘仅供排查）。
- 退出码：0 = 完成；1 = 任务失败/中断/并发拒绝/attach 拒绝；2 = 用法或
  选项值域错误。
- 其余选项（`--split`/`--timeout`/`--header`/`--all-proxy` 等）已被接受；
  在对应选项组落地前会发出明确的运行时告警（绝不让它们看起来生效而实际
  无效）。
- **需要登录的下载（Cookie 面）**：
  - `--load-cookies <netscape 文件>`：携带 Cookie 下载受保护 URL
    （curl/浏览器导出的 Netscape 格式）。文件缺失 / 超过 1MiB =
    任务拒绝；下载过程中服务器下发的 `Set-Cookie` 会被吸收并持久化，
    续传会话因此保持有效。
  - 与 `--header "Cookie: …"` 同时存在时，文件 Cookie 优先（手工
    Cookie 行被忽略 —— 避免两个 Cookie 来源冲突；fork 引擎同规则）。
  - RPC 形态额外提供结构化直达：`taiji.addUriWithCookies`（添加时逐条
    交付 Cookie）与 `taiji.setTaskCookies`（更新等待/暂停任务的 Cookie）。

可复现演示（mock 源 + 限速 + kill -9 续传 + checksum 终局判定）：

```sh
python3 scripts/http_5gb_resume_demo.py   # 对应 ≥5GiB 判据运行
```

## DNS 与 Tracker 地址恢复

HTTP、FTP、tracker 和 DHT 引导共享系统 DNS 解析与有界缓存。同域并发请求
合并为一次查询。成功结果缓存 5 分钟，失败缓存 2 秒，超时缓存 1 秒；调用取消
或本地容量不足不会被缓存为域名失败。解析保留操作系统的 hosts 文件和 VPN
DNS 设置。

Motrix 在引擎就绪时每 10 秒检查网络和 DNS 配置，桌面唤醒时立即触发检查。
检测到变化后，成功和失败缓存都会失效，旧查询结果被隔离，UDP tracker 连接
状态也会刷新；等待中的查询沿用原来的总超时预算。容器或受限环境可能缺少
部分系统信息工具，其余配置文件和接口检查仍然生效。应用无法观察到的变化
（例如地址不变的 DNS 代理内部重配置）仍依赖缓存到期。

UDP tracker 的地址不可达时会尝试其他地址，只有 CONNECT 成功的端点才会
收到 ANNOUNCE，切换地址不会延长整次尝试的超时。DNS 和地址恢复有助于发现
节点，但没有可达节点持有所需元数据时，仍然无法获取种子。
IPv6 可达性检查在后台运行，IPv6 路由无响应不会阻塞 IPv4 tracker 请求或取消。

超时的系统解析可能继续在操作系统中运行。taiji 最多允许 32 个活跃解析、
256 个活跃或排队的查询，并将它们与其他阻塞 I/O 隔离。`/metrics` 的 DNS
指标区分缓存命中、并发合并、后端查询和实际系统活动，不包含域名标签。

## 下载与做种

```sh
taiji <torrent|magnet> -d <dir>
```

- 下载完成后自动转入做种；达到 `--seed-ratio` / `--seed-time` 后停止；
  `--bt-stop-timeout` 控制空闲做种退出。
- `-V`/`--enable-dht`/`--bt-lsd` 控制发现面；私密种子自动关闭 DHT/PEX/LSD。
- `--bt-tracker "url1,url2"` 追加 tracker（运行中任务经全局导入即时感知）；
  `changeUri` 遵循上游 file-entry URI 语义，不编辑 tracker。
- **Tracker 动态编辑（RPC 面）**：`taiji.addTracker(gid, urls, options?)` /
  `taiji.removeTracker(gid, urls)` —— 按任务增删 tracker（每个 URL 独立成
  一个 tier;`options.position` 指定插入的 tier 位置，默认表尾）。活动任务
  即时生效（announce 面）；等待/暂停任务跨重启保留。magnet/.torrent URL
  元数据阶段任务、HTTP 任务与已完结任务被显式拒绝。见
  [rpc-api.zh-CN.md](./rpc-api.zh-CN.md) 的 tracker 动态编辑一节。
- **DHT 运行时热开关（RPC 面）**：`changeGlobalOption("enable-dht",
  "true"|"false")` 对运行中的会话即时生效 —— 引擎中运行 BT 任务的 DHT 面
  随之启停（对齐 libtorrent 的 `apply_settings` 能力；上游 aria2 无法热改
  enable-dht，因此这是显式声明差异的 taiji 扩展）。`enable-dht6` 在同一
  键下被接受（值面 —— taiji 没有独立的 v6 DHT 开关；v6 面跟随
  `enable-dht` 主开关与 IPv6 连通性门）。
- **任务级 DHT 旗标**：`bt-disable-dht`（bool；在 addTorrent/addUri 选项与
  `changeOption` 中以同键接受）—— 默认跟随会话 `enable-dht`；显式
  `true` 仅对该任务关闭 DHT,`false` 仅对该任务强制开启（对齐 libtorrent
  `torrent_flags::disable_dht` 能力）。对活动任务即时生效；私密种子不受
  该旗标影响（BEP27 硬门 —— DHT 交互恒关）。
- **无 tracker 种子**（announce / announce-list 均缺失）：**恒接受**
  （CLI 下载与 RPC addTorrent / addUri（.torrent URL） 同一规则）。DHT 开
  （默认）= 纯 DHT 发现；DHT 关 = 接受 + WARN 日志（没有发现源，任务会
  停滞 —— 日志给出恢复指引：`changeGlobalOption("enable-dht","true")`
  热启用复活（无需重启）；或 `taiji.addTracker` 补 tracker；或以不同的
  DHT 初始值重启）。上游交叉验证：aria2 的摄入面不因 DHT 开关而拒绝
  （`RequestGroup.cc` 仅 NOTICE），libtorrent 也从不拒绝 —— taiji 行为
  对齐。私密种子即使被接受也禁用 DHT 交互（BEP27）；无 tracker 的私密
  种子没有任何发现源，使用时请自带 tracker。
- **顺序下载**：`--bt-sequential-download`（CLI，默认 false）或 RPC 选项
  `bt-sequential-download=true`（addTorrent/addMagnet/changeOption 的
  暂停面）—— 任务按文件顺序下载 piece（v1 全局 piece 顺序 / v2 文件内
  piece 顺序）；与多级文件优先级组合时，高优先级文件的整层先行。运行时
  切换走 `taiji.setSchedulerPolicy(gid, "sequential")`（权威面；选项键
  是它的 aria2 兼容投影，`getOption` 回显的是该策略的投影）。策略回显：
  `taiji.getSchedulerPolicy`。
- **多级文件优先级（RPC 面）**：`taiji.setFilePriority(gid, pairs)` 按文件
  调整下载优先级 —— `pairs = [{index, priority}]`（index 为 1 起，与
  `getFiles`/`select-file` 同约定；priority:-1 跳过 / 0 普通 / 1..7 高
  优先 —— 数字越大越先下载）。未列出的文件不动；活动任务即时生效
  （piece 选择顺序变为"优先级 → 稀有度"），等待/暂停任务在激活时接收，
  且跨重启保留。`-1` 等价于移出选择集（与 `select-file` 同面）；`0..7`
  恢复/加入。回显：`getFiles`/`tellStatus` 的 files[] 每项带 `priority`
  键。与流式调度策略组合时，播放头优先级恒胜（高优先级文件在窗口层之外
  加速）。上游 aria2 无此面（对齐 libtorrent `file_priority` 能力；差异
  已声明）。
- **下载 + RPC 共存**（`--enable-rpc`，对齐上游三态）：给定 torrent 时
  RPC 服务器随任务一起启动，`tellActive`/事件面覆盖完整任务生命周期：

 ```sh
 taiji <torrent> -d <dir> --enable-rpc --rpc-listen-port 6800 \
 --rpc-secret <token>
 ```

 任务保持做种常驻，进程常驻直到 Ctrl-C/SIGTERM 或 RPC `shutdown`。
 `--rpc-*` 选项组（listen-port/secret/user/passwd/aria2-compat）在下载
 模式下必须与 `--enable-rpc` 成对出现，否则启动报错（退出码 2）——
 静默忽略已被移除。

## 制作种子

```sh
taiji create-torrent <file…> -o out.torrent \
    --piece-length 16384 --format hybrid --private --announce <url>
```

`--format v1|v2|hybrid`;hybrid 同时写入 file tree 与 files 视图，
piece layers 自动计算。

## RPC 守护进程

```sh
taiji --rpc-listen-all --rpc-secret <token>
```

- 无位置参数 = 纯守护形态（idle）：RPC 恒开 —— 与 aria2 `--enable-rpc`
  纯守护形态的同义面（该选项被接受但无效果；语义不变）。
- 未设置 `--rpc-secret` / `--rpc-user` 时，只绑定 127.0.0.1。
- **公网暴露**：请通过 WireGuard/Tailscale 或终结 TLS 的反向代理；
  引擎不内置 TLS。
- WebSocket 连接兼作事件订阅；重连后用 `tellActive/tellStopped` 补齐
  状态。
- 下载与 RPC 同进程形态见"下载与做种"一节（`--enable-rpc` + 位置参数，
  对齐上游三态）。

## 私密种子（PT）

- peer ID 默认 `-TJ0001-`；可用 `--peer-id-prefix` 覆盖（PT 白名单惯例）。
- UA / 扩展握手 `v` = `taiji/<semver>`。
- 严格遵循 min-interval;stopped 序列送达所有 tier。

## 存储与恢复

- 会话数据库 `taiji.sqlite3`（可用 `--sqlite3-db-path` 自定义，重启生效）。
- 文件分配 `none|trunc|falloc|prealloc`（`--enable-falloc` 等）。
- 启动时校验位图；`--check-integrity` 强制全量复检。
- 哈希恢复：v2 种子缺失 `piece layers` 时自动从种群补齐；补齐之前对应
  文件禁止下载与做种；事件 `taiji.recoveryStarted/Completed` 使其可见。

## 性能与调优

- `--peer-connection-type tcp|utp|prefer-tcp|prefer-utp`（默认 prefer-tcp）。
- 限速：全局 `--max-overall-{download,upload}-limit`，任务级
  `--max-{download,upload}-limit`（0 = 不限）。
- `--bt-peer-connection-type` 为同义面；`taiji.setSchedulerPolicy` 运行时
  切换 piece 选择策略。

## 日志与采集（运维）

- `--log-format text|json`（默认 text = 人类可读，与既有行为形态一致）。
  日志过滤跟随 `RUST_LOG`（默认 info）。
- `--log-format json`:stdout 逐行输出合法 JSON（时间戳/级别/target/
  字段，tracing-subscriber 默认结构），供日志采集 / 基准遥测 / AI 工具链
  机器消费：

```sh
taiji --log-format json --rpc-listen-port 6800 \
| jq 'select(.target=="taiji::core::engine")'
```

- ANSI 颜色仅在 stdout 直连终端（交互式 TTY）时输出；重定向到文件/管道
  自动干净（无 `\x1b` 转义序列）；设置 `NO_COLOR` 环境变量时整体关闭
  （no-color.org）。
