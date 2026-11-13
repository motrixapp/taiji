# taiji

English | [简体中文](./README.zh-CN.md)

**taiji** is a multi-protocol download engine written in Rust and shipped as
a single binary (`taiji`). BitTorrent (v1/v2/hybrid), HTTP(S), FTP(S),
Metalink v4, and magnet links run under one session model, driven through an
taiji JSON-RPC surface with optional aria2 aliases. It is developed for
Motrix as the sole engine for its desktop and server applications.

## Highlights

- **Full BitTorrent download and seeding**: v1/v2/hybrid torrents; DHT, PEX,
  and LSD discovery; HTTP/UDP trackers (dual-stack); µTP transport; MSE
  protocol encryption; private torrents (PT); super-seeding; NAT hole
  punching; automatic hash recovery from the swarm when a v2 torrent is
  missing its piece layers.
- **Multi-source HTTP/FTP downloads**: concurrent mirrors for the same file,
  ranged resume, whole-file verification across six hash families,
  Basic/Digest auth, Public-Suffix-List-defended cookie handling, Metalink v4
  orchestration.
- **An aria2-compatible RPC surface**: ~40 aria2 methods kept verbatim (an
  optional `aria2.*` alias compatibility mode) plus `taiji.*` extensions;
  WebSocket event subscription; a Prometheus metrics endpoint.
- **Production-grade session management**: queue semantics, per-task and
  global options, SQLite persistence, kill -9 crash recovery, read-only
  migration import from the legacy fork database.
- **Memory-hardened**: every remotely influenced allocation has a ceiling —
  intake rejects rather than repairs.
- **One binary, zero `unsafe`**: `unsafe_code = "forbid"` across the
  workspace.

## Install

Build from source (Rust ≥ 1.88):

```sh
cargo build --release
# artifact: target/release/taiji
```

> taiji is not published to crates.io; prebuilt binaries ship with the
> [seven-platform release matrix](./packaging/README.md).

## Quick start

### Download over HTTP with verification

```sh
taiji http https://example.com/big.iso \
    -d ~/Downloads \
    --checksum sha-256=<hex>
```

Multiple URLs are mirrors of the same file; taiji downloads them
multi-source, concurrently.

### Resume (nothing to enable)

Resume is driven by the bitmap in the session database `taiji.sqlite3`:
**re-run with the same arguments and in-flight tasks continue**, even after
`kill -9`. Partial data lives in `<file>.part` and is renamed atomically on
completion. Exit codes: 0 success, 1 task failed/interrupted, 2 usage error.

### Magnets and torrents

```sh
taiji "magnet:?xt=urn:btih:…" -d ~/Downloads   # magnet
taiji file.torrent -d ~/Downloads              # torrent: seeds after completion
```

Seeding runs until `--seed-ratio` / `--seed-time` is reached;
`--check-integrity=true` re-hashes existing files piece by piece before
startup, so verified pieces are not downloaded again.

### Run an RPC daemon (for frontends)

```sh
taiji --rpc-listen-port 6800 --rpc-secret <token>
```

With no positional arguments this is the pure daemon form; without
`--rpc-secret` / `--rpc-user` it binds to 127.0.0.1 only and write methods
are always refused. Downloads and RPC can also share one process:

```sh
taiji file.torrent -d ~/Downloads --enable-rpc --rpc-secret <token>
```

### Create a torrent

```sh
taiji create-torrent <file…> -o out.torrent \
    --piece-length 16384 --format hybrid --announce <tracker-url>
```

### More

- `taiji import <db> [--dry-run]` — read-only migration from the legacy fork
  database.
- `taiji media doctor` — an ffmpeg/ffprobe health check (media download
  preflight).
- One taiji session per session database at a time (a kernel file lock): a
  second instance exits immediately with a clear error.

## Documentation

| Document | English | 简体中文 |
|---|---|---|
| User manual | [user-manual.md](./docs/user-manual.md) | [user-manual.zh-CN.md](./docs/user-manual.zh-CN.md) |
| RPC API | [rpc-api.md](./docs/rpc-api.md) | [rpc-api.zh-CN.md](./docs/rpc-api.zh-CN.md) |
| Build & release | [build.md](./docs/build.md) | [build.zh-CN.md](./docs/build.zh-CN.md) |
| Engine spec | [spec.md](./docs/spec.md) | [spec.zh-CN.md](./docs/spec.zh-CN.md) |
| RPC differential | [rpc-api-diff.md](./docs/rpc-api-diff.md) | [rpc-api-diff.zh-CN.md](./docs/rpc-api-diff.zh-CN.md) |
| Design notes | [design/](./docs/design/) (English) | — |

## Relationship to aria2

aria2 is taiji's behavioral reference: option names, queue semantics, RPC
shapes, and error codes stay aligned unless a difference is declared. Every
declared difference is registered in
[docs/rpc-api-diff.md](./docs/rpc-api-diff.md) and pinned by CI, so
documentation and implementation cannot drift silently; an undeclared
difference is treated as a bug.

## License

[GPL-2.0-or-later](./LICENSE)
