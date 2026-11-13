# taiji

[English](./README.md) | 简体中文

**taiji** 是用 Rust 编写的多协议下载引擎，以单一二进制（`taiji`）交付：
BitTorrent（v1 / v2 / 混合）、HTTP（S）、FTP（S）、Metalink v4 与磁力链接
运行在同一个会话模型下，通过 taiji JSON-RPC 接口驱动，并提供可选的 aria2
别名。taiji 为 Motrix 开发，作为桌面端与服务端的唯一下载引擎。

## 核心特性

- **完整的 BT 下载与做种**：v1 / v2 / 混合种子；DHT、PEX、LSD 发现；
  HTTP / UDP tracker（双栈）；µTP 传输；MSE 协议加密；私密种子（PT）；
  超级做种；NAT 打洞；v2 种子缺失 piece layers 时自动从种群做哈希恢复。
- **多源 HTTP/FTP 下载**：同一文件多镜像并发、Range 断点续传、六种哈希
  整文件校验、Basic/Digest 认证、基于 Public Suffix List 的 Cookie
  防收割、Metalink v4 镜像编排。
- **aria2 兼容 RPC 面**：约 40 个 aria2 方法原样保留（可选 `aria2.*`
  别名兼容模式）+ `taiji.*` 扩展方法；WebSocket 事件订阅；Prometheus
  指标端点。
- **产品级会话管理**：队列语义、任务级/全局选项、SQLite 持久化、
  kill -9 崩溃恢复、从旧 fork 数据库只读迁移导入。
- **内存加固**：所有受远程输入影响的分配都有上限，超限即拒绝；
  入口拒绝而非修复。
- **单一二进制、全仓库禁用 `unsafe`**。

## 安装

从源码构建（需要 Rust ≥ 1.88）：

```sh
cargo build --release
# 产物:target/release/taiji
```

> taiji 不发布到 crates.io；预编译二进制随发布矩阵提供
> （[七个平台的发布矩阵](./packaging/README.md)）。

## 快速上手

### 下载 HTTP 文件并校验

```sh
taiji http https://example.com/big.iso \
    -d ~/Downloads \
    --checksum sha-256=<hex>
```

多个 URL = 同一文件的镜像，taiji 会自动多源并发下载。

### 断点续传（无需额外操作）

续传由会话数据库 `taiji.sqlite3` 的位图驱动：**用相同参数重跑即可接续**，
进程被杀（包括 `kill -9`）也不会重复下载。未完成数据存为 `<file>.part`,
完成时原子改名。退出码：0 成功，1 任务失败/中断，2 用法错误。

### 下载磁力或种子

```sh
taiji "magnet:?xt=urn:btih:…" -d ~/Downloads   # 磁力
taiji file.torrent -d ~/Downloads              # 种子:下载完自动做种
```

做种直到达到 `--seed-ratio` / `--seed-time`;`--check-integrity=true`
可在启动前对已有文件逐块复检，已验证的部分不再重下。

### 启动 RPC 守护进程（供前端连接）

```sh
taiji --rpc-listen-port 6800 --rpc-secret <token>
```

无位置参数 = 纯守护形态；未设置 `--rpc-secret` / `--rpc-user` 时只绑定
127.0.0.1，写操作恒被拒绝。也可以让下载与 RPC 同进程：

```sh
taiji file.torrent -d ~/Downloads --enable-rpc --rpc-secret <token>
```

### 制作种子

```sh
taiji create-torrent <file…> -o out.torrent \
    --piece-length 16384 --format hybrid --announce <tracker-url>
```

### 其他

- `taiji import <旧数据库> [--dry-run]`：从旧 fork 数据库只读迁移。
- `taiji media doctor`:ffmpeg/ffprobe 健康检查（媒体下载前置诊断）。
- 同一会话数据库同一时刻只允许一个 taiji 实例（内核文件锁），
  第二个实例立即明确报错退出。

## 文档

| 文档 | English | 简体中文 |
|---|---|---|
| 用户手册 | [user-manual.md](./docs/user-manual.md) | [user-manual.zh-CN.md](./docs/user-manual.zh-CN.md) |
| RPC API | [rpc-api.md](./docs/rpc-api.md) | [rpc-api.zh-CN.md](./docs/rpc-api.zh-CN.md) |
| 构建与发布 | [build.md](./docs/build.md) | [build.zh-CN.md](./docs/build.zh-CN.md) |
| 引擎规格 | [spec.md](./docs/spec.md) | [spec.zh-CN.md](./docs/spec.zh-CN.md) |
| RPC 差异声明 | [rpc-api-diff.md](./docs/rpc-api-diff.md) | [rpc-api-diff.zh-CN.md](./docs/rpc-api-diff.zh-CN.md) |
| 设计笔记 | [design/](./docs/design/)（英文） | — |

## 与 aria2 的关系

aria2 是 taiji 的行为参照：选项名、队列语义、RPC 形态与错误码对齐，
除非差异被显式声明。所有已声明差异集中在
[docs/rpc-api-diff.zh-CN.md](./docs/rpc-api-diff.zh-CN.md)（规范本体为
[英文版](./docs/rpc-api-diff.md)）并由 CI 钉住
（文档与实现不会悄悄漂移）；未声明的差异视为 bug。

## 许可证

[GPL-2.0-or-later](./LICENSE)
