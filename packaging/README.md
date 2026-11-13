# taiji sidecar packaging

Motrix desktop and server use taiji as their only download engine. Both
repositories maintain the same RPC contract; engine releases use ordinary
SemVer without a Motrix-specific prerelease suffix.

## Layout

```text
taiji-sidecar-<platform>/
├── taiji[.exe]
├── VERSION.json
├── COPYING
├── THIRD-PARTY-NOTICES.md
├── THIRD-PARTY-LICENSES.txt
├── NOTARIZATION.json       # signed macOS assets only
└── SHA256SUMS
```

`packaging/assemble.py` checks the tag against the workspace version, records
the source commit and build parameters, gathers the runtime/build dependency
license files, and hashes every shipped file except `SHA256SUMS` itself.
Release assembly rejects a dirty tracked source tree. Missing upstream license
files are handled only by explicit, version-bound supplements in `licenses/`.

## Platforms

| Platform | Rust target | Archive |
| --- | --- | --- |
| macos-arm64 | aarch64-apple-darwin | tar.gz |
| macos-x64 | x86_64-apple-darwin | tar.gz |
| linux-x64 | x86_64-unknown-linux-gnu | tar.gz |
| linux-arm64 | aarch64-unknown-linux-gnu | tar.gz |
| windows-x64 | x86_64-pc-windows-msvc | zip |
| windows-arm64 | aarch64-pc-windows-msvc | zip |
| android-arm64 | aarch64-linux-android | tar.gz |

Linux artifacts are built on Ubuntu 22.04 (glibc 2.35). macOS x64 and Windows
arm64 are cross-compiled; Android uses the workflow's pinned NDK. Motrix may
build additional targets directly from the same locked source.

## Build and signing

`.github/workflows/release.yml` builds all seven platforms with `--locked`,
a pinned Rust toolchain and `--remap-path-prefix=<repo>=/taiji`, then creates a
draft release. The source tag must match the workspace version and belong to
`main`. These controls provide traceability, not a promise of bit-identical
binaries across build hosts.

`.github/workflows/sign-macos.yml` runs from `main` against that draft. Its
credential-bearing job checks out no source and compiles nothing. It signs
with hardened runtime and a secure timestamp, requires Apple's accepted
notarization result, then replaces the two draft macOS archives with updated
checksums and notarization receipts. A standalone command-line Mach-O cannot
be stapled; the accepted receipt records its signed binary digest. Published
release assets cannot be overwritten by these workflows. Windows binaries
are unsigned; release notes must disclose that status. Windows builds statically
link the Visual C++ runtime so Motrix does not require a separate redistributable
installation; CI checks the actual imported DLL names.

## Runtime and migration

The bundle is read-only. Motrix supplies the download directory and a separate
session database path. The host owns startup recovery holds, automatic restart,
parent-process lifetime and NAT mapping; taiji owns task execution and durable
session state. Mapping updates are tied to the current native listener binding.

The one-shot importer reads the legacy aria2 database without modifying it,
preserves task identifiers and supported resume state, and writes the taiji
database. The old engine is not started. Download data and session databases
are not part of a binary upgrade; do not replace them with the package or assume
an older engine can read a newer database schema.
