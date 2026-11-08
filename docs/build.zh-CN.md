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

## 发布

- crates.io：永不发布 —— 工作区声明为 `publish = false`；引擎只以二进制
  形式分发（下方打包矩阵 + GitHub Releases）。
- 打包矩阵（`packaging/`）：macos-universal / linux-x64 / windows-x64;
  linux 目标以 glibc 2.35 为兼容下限。
