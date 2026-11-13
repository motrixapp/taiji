# Build and release

English | [简体中文](./build.zh-CN.md)

## Workspace

```
crates/
  taiji-io      transport layer: TCP / µTP / MSE / UDP demux / rate limiting / NAT
  taiji-bt      protocol layer: peer wire / DHT / tracker / PEX / magnet / creator
  taiji-store   storage layer: layout / Merkle / write cache / sqlite persistence
  taiji-core    orchestration layer: session actor / engine main loop / recovery
  taiji-rpc     JSON-RPC + WebSocket service
  taiji        bin (package name = command name)
```

Dependency direction: cli → rpc → core → {bt → {io, store}, store}; `unsafe` is
forbidden repo-wide.

## gate

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

CI (GitHub Actions): ubuntu-24.04 runs the full trio; macos-26 / windows-latest
run the store/filetree subset. Fuzzing: `cargo fuzz` (see `fuzz/`; targets
cover bencode / filetree / peer frame / magnet / µTP / MSE / UDP demux /
NAT-PMP / IGD XML).

## Release

- crates.io: never published — the workspace is `publish = false`; the engine
  ships as binaries only (the packaging matrix below + GitHub Releases).
- Packaging matrix (`packaging/`): macos-arm64 / macos-x64 / linux-x64 /
  linux-arm64 / windows-x64 / windows-arm64 / android-arm64. Linux binaries
  require glibc ≥ 2.35.
- Versions use ordinary SemVer. A `v<version>` tag on `main` builds all seven
  unsigned archives into a draft release. The separate `sign-macos` workflow
  signs and notarizes both macOS binaries before publication. Windows binaries
  are unsigned. See [the packaging contract](../packaging/README.md).
