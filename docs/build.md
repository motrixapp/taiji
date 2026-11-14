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

## Magnet latency comparison

`scripts/bench_magnet.py` runs synthetic tracker and metadata-peer fixtures with
fresh profiles. Optional references are libtorrent's Python binding and
`transmission-daemon`; neither is a runtime dependency of taiji. Install the
Python binding in an isolated environment, build taiji in release mode, then run:

```sh
python scripts/bench_magnet.py --taiji target/release/taiji \
  --samples 30 --peer-host <local-LAN-IPv4> --output /tmp/magnet-comparison
```

The peer address must be local to the test machine. Transmission rejects tracker
peers on loopback, so use its LAN interface for cross-client runs; RPC and tracker
servers remain on loopback. The synthetic peer speaks plaintext TCP. Transmission
is configured to tolerate plaintext and libtorrent's uTP is disabled for this
fixture; encryption and transport interoperability need their separate tests.
Default fixtures use no public swarm or user client profile. No service is
installed or started by the script.

Scenarios include healthy discovery, 64 silent handshakes before a healthy peer,
24 silent HTTP trackers before a healthy tracker, and delayed metadata blocks.
`--baseline` adds an earlier taiji binary. `--clients` selects references;
`--scenarios` selects fixtures. Runs are interleaved using a recorded seed.
Output retains all timeouts/errors, raw per-run counters, native stage timings,
and success-only latency percentiles. A libtorrent session is a protocol-engine
reference, not a measurement of qBittorrent's complete UI. Existing results are
never overwritten; use a new output directory for every run.

An explicit `--torrent <known.torrent> --scenarios public-trackers,public-dht`
opts into public metadata-only comparisons. Only the derived magnet is submitted;
the local metainfo is never supplied to a reference client. The DHT-only case
removes tracker hints. `--warmup 30` gives each client 30 seconds of idle discovery
preparation, excluded from reported resolution time. taiji waits for file
selection and libtorrent uses upload mode. Transmission is excluded from public
runs because its RPC cannot enforce unwanted files before metadata arrives;
its synthetic fixture supplies no payload and remains a valid comparison.
Public tests enable the reference clients' normal DHT and uTP paths. Keep their
results separate from deterministic fixtures and report failed attempts as well.

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
