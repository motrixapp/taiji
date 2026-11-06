# Build and release

## Workspace

```
crates/
  taiji-io      transport layer: TCP / µTP / MSE / UDP demux / rate limiting / NAT
  taiji-bt      protocol layer: peer wire / DHT / tracker / PEX / magnet / creator
  taiji-store   storage layer: layout / Merkle / write cache / sqlite persistence
  taiji-core    orchestration layer: session actor / engine main loop / recovery
  taiji-rpc     JSON-RPC + WebSocket service
  motrix-taiji  bin (command name taiji)
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

- crates.io publish order: taiji-io → taiji-bt → taiji-store → taiji-core →
  taiji-rpc → motrix-taiji (`cargo publish --dry-run` first).
- Packaging matrix (`packaging/`): macos-universal / linux-x64 / windows-x64;
  linux targets glibc 2.35 as the compatibility floor.
