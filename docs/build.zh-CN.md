# 构建与发布

[English](./build.md) | 简体中文

## 工作区

```
crates/
  taiji-io      传输层:TCP / µTP / MSE / UDP 多路复用 / 限速 / NAT
  taiji-bt      协议层:peer wire / DHT / tracker / PEX / magnet / creator
  taiji-store   存储层:布局 / Merkle / 写缓存 / sqlite 持久化
  taiji-core    编排层:session actor / 引擎主循环 / 恢复
  taiji-rpc     JSON-RPC + WebSocket 服务
  taiji         bin(包名 = 命令名)
```

依赖方向：cli → rpc → core → {bt → {io, store}, store}；全仓库禁用
`unsafe`。

## 门禁

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

CI（GitHub Actions）：ubuntu-24.04 跑完整三件套；macos-26 /
windows-latest 跑 store/filetree 子集。模糊测试：`cargo fuzz`（见
`fuzz/`；目标覆盖 bencode / filetree / peer frame / magnet / µTP / MSE /
UDP demux / NAT-PMP / IGD XML）。

## 磁链解析延迟对照

`scripts/bench_magnet.py` 使用合成 tracker、元数据 peer 和独立配置测试。
可选参考端为 libtorrent Python 绑定与 `transmission-daemon`；两者都不是
taiji 运行依赖。在隔离环境安装 Python 绑定，构建 release 版 taiji 后运行：

```sh
python scripts/bench_magnet.py --taiji target/release/taiji \
  --samples 30 --peer-host <本机局域网IPv4> --output /tmp/magnet-comparison
```

peer 地址必须属于测试机。Transmission 拒绝 tracker 返回的回环 peer，
跨客户端测试因此使用本机局域网接口；RPC 和 tracker 仍绑定回环地址。
合成 peer 使用明文 TCP，Transmission 配置为允许明文，libtorrent 在此
fixture 中关闭 uTP；加密和传输互操作应由相应的独立测试验证。默认 fixture
不使用公网 swarm 或用户客户端配置，脚本不会安装或启动系统服务。

场景包括健康发现、64 个不回握手的 peer 后才出现可用 peer、24 个不响应的
HTTP tracker 后才出现可用 tracker，以及元数据分块延迟。`--baseline` 可
加入旧 taiji 二进制，`--clients` 选择参考端，`--scenarios` 选择场景。
执行顺序按记录的随机种子交错。输出保留全部超时与错误、每轮计数器、原生
阶段计时和仅成功样本的延迟分位数。libtorrent 会话是协议引擎参考，不代表
qBittorrent 整个界面的性能。已有结果不会覆盖，每轮应使用新的输出目录。

显式传入 `--torrent <已知种子文件> --scenarios public-trackers,public-dht`
可选择公网元数据对照。提交给客户端的只有派生 magnet，不提供本地种子内容；
DHT-only 场景去掉 tracker 提示。`--warmup 30` 给每个客户端 30 秒空闲发现
准备时间，不计入解析延迟。taiji 等待文件选择，libtorrent 使用 upload mode。
Transmission 的 RPC 不能在元数据到达前落实文件排除，因此不参加公网测试；
合成 fixture 不提供正文数据，仍可用于对照。公网测试启用参考客户端正常的 DHT
和 uTP 路径。公网与确定性 fixture 的结果分开统计，并保留失败尝试。

## 发布

- crates.io：永不发布 —— 工作区声明为 `publish = false`；引擎只以二进制
  形式分发（下方打包矩阵 + GitHub Releases）。
- 打包矩阵（`packaging/`）：macos-arm64 / macos-x64 / linux-x64 /
  linux-arm64 / windows-x64 / windows-arm64 / android-arm64。Linux 二进制
  要求 glibc ≥ 2.35。
- 版本采用普通 SemVer。在 `main` 上创建 `v<version>` 标签后，工作流构建七个
  平台的未签名归档并创建草稿发布；独立的 `sign-macos` 工作流负责两个 macOS
  二进制的签名与公证，通过后再公开发布。Windows 二进制未签名。
  详见[打包约定](../packaging/README.md)。

### 磁链基准配置与判定

候选默认使用可复现的乱序（`--peer-order seeded`），`first`、`middle`、`last`
用于固定位置探测；每条结果保留有效候选位置和重复元数据字节数。比较前先进行
真实网络预检：libtorrent 必须访问排在 24 个静默 tracker 后面的有效 tracker。
同时启用 `announce_to_all_tiers` 和 `announce_to_all_trackers`，规避 libtorrent
2.1.1 设置名称表中两个布尔项对调的问题；只读回设置无法验证实际行为。
磁链中的 tracker 分属不同 tier。延迟统计到文件列表取回并校验身份为止，
不包含随后可选的诊断 RPC。所有客户端使用相同截止时间，超时保留为失败，
不纳入成功样本的延迟百分位数。

`--scenarios v2-32k,v2-513 --clients taiji,baseline,libtorrent` 验证没有提供
piece-layer 证明时的 info-first 文件列表；完整导出与证明恢复由原生集成测试覆盖。
