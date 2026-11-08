# taiji Engine Specification

English | [简体中文](./spec.zh-CN.md)

| | |
|---|---|
| Version | v0.3 |
| Date | 2026-10-26 |
| Scope | The whole taiji engine: BitTorrent, HTTP/FTP, Metalink, session, RPC, CLI |
| Related | aria2 (read-only behavioral reference); per-module anchors in [docs/design/](design/) |

This document describes the engine **as it stands**: system architecture,
protocol behavior, scheduling, storage, surfaces, and the resource model.
Where a behavior deliberately differs from the references (aria2, libtorrent,
the BEP text), the difference is declared once — here, in the deviation
registry (§3.2), or in [rpc-api-diff.md](rpc-api-diff.md) — and pinned by a
test. Divergence by omission is treated as a bug.

Conformance note: the §3.1 matrix and the §3.2 deviation registry are
**execution-checked** by `crates/taiji-bt/tests/spec_matrix.rs` — a doc edit
that drops a normative anchor, or an implementation that stops matching the
declared state, fails CI.

---

## 1. Scope and positioning

**taiji** is a multi-protocol download engine in Rust shipped as a single
sidecar binary (`taiji`), covering BitTorrent (v1/v2/hybrid), HTTP(S), FTP(S)
and Metalink under one session model, driven by an aria2-compatible JSON-RPC
surface.

**Goals**

- G1. Complete BitTorrent download/seeding: v1, v2 and hybrid with full
  discovery (DHT/PEX/LSD), trackers (HTTP/UDP, dual-stack), µTP, MSE,
  private torrents, super-seeding, hole punching.
- G2. A multi-source HTTP/FTP downloader: connection pools with AIMD
  response, range resume, checksum verification, Basic/Digest auth, cookies
  with Public Suffix List defense, Metalink v4 orchestration.
- G3. An aria2-compatible RPC and option surface: the Motrix frontend drives
  taiji without protocol changes; every difference is declared, not
  discovered.
- G4. Product-grade session management: queue semantics, per-task and global
  options, events, SQLite persistence, crash recovery, migration import
  from the legacy fork database.
- G5. A memory-hardened core: every remotely influenced allocation has a
  ceiling, and intake rejects rather than repairs.
- G6. Determinism where affordable: injected clocks in the engine core and
  table-driven policy seams, so behavior is testable without sleeping.

**Non-goals**

- WebTorrent/WebRTC, I2P, SSL torrents, the BEP 51 DHT infohash index,
  the BEP 17 HTTP-seed format (BEP 19 webseeds are supported).
- Bidirectional `.aria2` control-file compatibility (read-only import).
- The libtorrent library API (the committed surface is the aria2 RPC face
  plus taiji extensions).
- Mobile platforms as first-class targets (the CLI builds where Rust does;
  CI gates Ubuntu, macOS, Windows).

---

## 2. System architecture

### 2.1 Process forms

One binary, six forms:

| Form | Command |
|---|---|
| Bare download | `taiji file.torrent [options]` — download, then seed until Ctrl-C |
| Download + RPC | bare form plus `--enable-rpc` — engine and RPC server share one session |
| Idle daemon | `taiji --enable-rpc ...` — session up, tasks arrive via RPC |
| One-shot HTTP | `taiji http URL [options]` (also `ftp://`, metalink files) |
| Migration import | `taiji import <db> [--dry-run]` |
| Create torrent | `taiji create-torrent <file…>` |

Shutdown is graceful and budgeted: SIGINT/SIGTERM start a 1 s teardown
budget (NAT unmap gets its own 250 ms slice); SIGKILL is survived via SQLite
WAL recovery plus the recheck-on-resume path.

### 2.2 Actor topology

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

Rules the topology enforces:

- **Single writer per engine.** All mutable engine state is touched by the
  engine actor alone; the session and RPC read through lock-free mirrors
  (atomics published at single choke points) and command channels — never by
  reaching into engine state.
- **Bounded channels everywhere.** Every queue in the diagram has a capacity;
  backpressure is a queue-drop or a command rejection, never unbounded growth.
- **Locks are small and never held across `.await`.** Lock poisoning is fatal
  by policy (§8).

### 2.3 Crate layering

Twelve crates, dependencies point strictly downward:
`taiji → taiji-rpc → taiji-core → {taiji-engine, taiji-http,
taiji-store} → taiji-bt → taiji-domain → taiji-io` (`taiji-metalink` sits
beside `taiji-http`, consumed by core/rpc/cli; `taiji-segment` is the
frozen segmentation vocabulary consumed by core/engine/http/media;
`taiji-media` — HLS/DASH orchestration plus the ffmpeg sidecar host —
sits beside `taiji-http`, consumed by core/cli). Cross-crate re-exports
keep historical paths stable (`taiji_core::engine::*`).

| Crate | Responsibility |
|---|---|
| `taiji-io` | uTP, MSE, UDP demux, DNS cache, NAT traversal, rate limits, knob registry |
| `taiji-domain` | Shared domain types: GIDs, metainfo projection, hooks, seed policy |
| `taiji-bt` | Wire protocols: bencode, peer wire, DHT, trackers, PEX/LSD, magnet, BEP 52 trees |
| `taiji-store` | Disk layouts, write cache (verify-before-disk), SQLite persistence, recovery |
| `taiji-engine` | Single-writer engine: dispatch, peer arms, policies, memory walls |
| `taiji-http` | HTTP/FTP client engine: probe, scheduler, coordinator, workers, finalize |
| `taiji-metalink` | RFC 5854 parser with hardening caps |
| `taiji-segment` | Frozen segmentation vocabulary: the three segment traits + signature closure |
| `taiji-media` | HLS/DASH VOD orchestration + the ffmpeg sidecar exec-shim host |
| `taiji-core` | Session actor: task lifecycle, option surface, events, persistence glue |
| `taiji-rpc` | JSON-RPC server: dispatch, auth, TLS, WebSocket, metrics |
| `taiji` | The `taiji` binary (package name = bin name): download / daemon / http / import / createTorrent |

### 2.4 Concurrency and failure policy

- Panics in spawned engine/worker tasks are caught by watchers and converted
  to terminal task failures with a metric tick — the process survives, the
  task fails honestly.
- Lock poisoning is fatal by policy: a per-crate `lock()` helper expects with
  a reason; critical sections are single-field reads/writes, so a poisoned
  lock means an invariant broke and loud failure routes into the watcher.
  Test code may keep the lenient idiom.
- Graceful degradation is explicit: NAT unmap and fsync failures degrade with
  a log line, not a task failure; metadata/persist failures fail the task
  with the real error chain (`source()` preserved).
- `unsafe` is forbidden workspace-wide (`unsafe_code = "forbid"`); the tree
  contains zero unsafe blocks. Secrets never enter logs or `Debug` output —
  redacting `Debug` impls cover the RPC secret, task credentials, and MSE
  key material.

---

## 3. BitTorrent engine

### 3.1 Protocol conformance matrix

| BEP | Mechanism | State | Notes |
|---|---|---|---|
| BEP 3 | bencode + peer wire, BT v1 | ✅ | strict/permissive split per context; i64 domain incl. `i64::MIN`; the v1 piece length accepts any positive integer (no upper clamp on intake; the §6 wall applies) |
| BEP 5 | DHT (Mainline Kademlia) | ✅ | routing table maintenance, bootstrap, node-id persistence |
| BEP 6 | fast extension | ✅ | outbound negotiation gate; reject/suggest/have-all+have-none; the `pending items` note (unimplemented suggest semantics) is registered in §3.2 |
| BEP 7 | IPv6 tracker extension | ✅ | `peers6` on HTTP and UDP faces |
| BEP 9 | magnet + ut_metadata | ✅ | sized-piece negotiation; metadata assembler budgeted (§6) |
| BEP 10 | extension protocol | ✅ | our-id primary routing; unknown m-dict keys ignored |
| BEP 11 | PEX | ✅ | first-message exemption; flags partially implemented (bit0/bit1 only) |
| BEP 12 | multi-tracker | ✅ | announce-list **full tier ingestion** (order preserved within a tier; each magnet `tr=` becomes one tier); private torrents additionally enforce the single-in-flight gate (BEP 27) |
| BEP 14 | LSD | ✅ | IPv4 multicast; opt-in `--bt-lsd` (default off, aria2 parity) |
| BEP 15 | UDP tracker | ✅ | connection-id lifecycle; retransmit backoff 5s/10s (see §3.2); dual-stack |
| BEP 16 | super-seeding | ✅ | advertisement scheduling |
| BEP 19/21 | webseeds / upload-only | ✅ | per-source promotion/demotion; upload-only webseed mode |
| BEP 27 | private torrents | ✅ | no DHT/PEX/LSD; single-in-flight tracker gate |
| BEP 29 | µTP | ✅ | LEDBAT dialect (RFC 6817 base-delay model; selective ACK; the RFC 6817 absences are registered as deviations) |
| BEP 32 | DHT IPv6 | ✅ | `nodes6` + dual-family `want` semantics; whole-reply 1024B frame gate |
| BEP 42 | DHT security | ✅ | token derivation + enforcement, with the documented exemptions |
| BEP 47 | padding / symlink attr | partial support | padding files never written/requested but servable; the `symlink` attribute is parsed and preserved, not materialized on disk (declared deviation, §3.2) |
| BEP 48 | tracker scrape | ✅ | implemented beyond the aria2 surface (per-tracker scrape face) |
| BEP 51 | DHT infohash index | non-goal | declared; long-term seeding metrics are out of scope |
| BEP 52 | v2 / hybrid | ✅ | Merkle file tree, layer validation (32B binary layer keys, §5.1), v1/v2 cross-checks, dual-swarm |
| BEP 53 | magnet file selection | ✅ | `so=` ranges and single indices, capped (§6) |
| BEP 55 | hole punching | ✅ | holepunch wiring: rendezvous via PEX relays, existence-probe-safe replies |
| MSE/PE | protocol encryption | ✅ | DH-768 + ARC4; require/prefer/plain; `--bt-require-crypto`, `--bt-min-crypto-level` |

Every decoder of untrusted bytes is total (no panics on malformed input) and
fuzzed; the fuzz corpus covers 27 targets (`fuzz/README.md`). This matrix and
the deviation registry below are **execution-checked** by
`crates/taiji-bt/tests/spec_matrix.rs` — a doc edit that drops a normative
anchor, or an implementation that stops matching the declared state, fails CI.

### 3.2 Deviation notes

Deviations from the references (BEP text, aria2, libtorrent). Anything that
differs without a note here is a bug.

1. Metadata hygiene is **rejection rather than rewriting** — a torrent whose
   names or structure fail sanitization is refused, never repaired in place.
2. **non-UTF-8** legacy torrents: names are preserved byte-faithfully where
   the wire format allows; no lossy transcode on intake.
3. Cookie **single-label** domains: rejected outright (public-suffix harvest
   defense); multi-label public suffixes follow the three-table PSL decision.
4. Missing piece layers degrade to **hash recovery** from the file tree when
   the tree itself validates (whole-file admission, never partial trust).
5. UDP tracker retransmission keeps aria2's **5s/10s** backoff rather than
   the BEP 15 suggestion ladder (`15 × 2^n`).
6. DHT tokens bind **(ip, port)** per BEP 42; the exemption list follows the
   BEP text verbatim.
7. Piece-length intake uses the full **i64** bencode domain before the §6
   wall — no silent truncation at parse time.

### 3.3 Metainfo and file layouts

- **v2-first data model**: files project to a Merkle tree (piece layers per
  file, 32B binary layer keys); v1 is the degenerate single-layer case;
  hybrid serves both swarms from one piece space with per-file logical
  offsets.
- Intake gates (all arms share one path): piece length ≤ 16 MiB, file count
  and byte budgets, layer sanity, name sanitization with a Windows
  reserved-name and long-path policy. Metadata hygiene is rejection rather
  than rewriting.
- `info_hash` identity: v1 SHA-1 over the info dict; v2/hybrid the Merkle
  root truncated to 20 bytes — both swarms share one identity with separate
  tracker announces.

### 3.4 Piece pipeline

- **Request windows** are bandwidth-delay driven per peer: target = `3 s ×
  rate EWMA / 16 KiB`, clamped `[floor, 256]`, with slow start (+1 per
  received block), hysteresis band `[0.7w, 1.3w]`, a real-world floor, and a
  jitter-adaptation tier (longer smoothing window). The legacy aria2 doubling
  heuristic remains as a fallback mode (`BH_REQUEST_WINDOW_BDP=0`).
- **Dispatch** is a two-phase ledger per peer (requested/writing/finished)
  with an endgame regime (last-mile holder set, duplicate cap ×2, fast-tier
  busy gate), adjacent-piece chain skipping, soft accounting of half-arrived
  pieces, and budget-scaled unchoke slots for constrained uplinks.
- **Verification** runs in a pool with a per-face piece budget; the
  verify-before-disk invariant is absolute (§5.2). Smart banning correlates
  hash failures per peer with a parole window.
- **Choking**: tit-for-tat with optimistic rounds (aria2-compatible
  timings), seeder-side ranked rounds, and budget-scaled unchoke slots for
  constrained uplinks (knob-gated).

### 3.5 DHT

Mainline Kademlia with the BEP 42 security extension: token derivation and
enforcement, routing-table maintenance with bucket splitting, bootstrap from
configured routers, node-id persistence, query rate limits, IPv6 via
`nodes6` and dual-family `want`. The BEP 51 infohash index is a declared
non-goal.

### 3.6 Trackers

HTTP and UDP faces with a shared announce policy: tiered lists (BEP 12),
per-tracker intervals with `min-interval` compliance, connection-id
lifecycle on UDP, scrape (BEP 48), IPv6 (`peers6`/BEP 7), failure backoff
(5s/10s, §3.2), and a per-tracker accepting face for credentials. Private
torrents gate announces to a single in-flight request (BEP 27).

### 3.7 Peer management

- **Choking**: tit-for-tat reciprocity with optimistic rounds (aria2
  timings); seeder-side ranked rounds; budget-scaled unchoke slots for
  constrained uplinks (knob-gated, declared divergence).
- **Banning**: hash-failure correlation per peer with a parole window;
  per-IP blocklists loaded at session start; address hygiene
  (private/reserved range rejections, self-connect detection) applied at
  dial and intake.

### 3.8 µTP and MSE

- **µTP (BEP 29)**: LEDBAT congestion control with base-delay learning,
  selective ACK, packet-level receive ledger (process-wide ceiling), and a
  configurable TCP/µTP dial policy (prefer-* falls back once per transport).
- **MSE**: DH-768 key exchange, ARC4 direction keys, crypto provide/require
  selection with plain fallback; `--bt-require-crypto` rejects legacy
  inbound, `--bt-min-crypto-level` selects the ARC4 tier.

### 3.9 Seeding and completion

Completion criteria: share ratio and/or seed time (aria2 semantics), with
detached seed-only mode (no concurrency slot). Graceful shutdown flushes
final state behind a data-fsync barrier. Bootstrapping a completed file set
re-verifies on disk (`--check-integrity`, `forceRecheck`) reusing the single
recheck implementation shared with crash recovery.

---

## 4. HTTP/FTP/Metalink engine

### 4.1 Probe

One HEAD/GET negotiation establishes the final URL, acceptability of ranges,
size, and digest hints. Redirect chains are followed with **target-IP
hygiene**: a redirect to a private/reserved address after a public hop is
refused (fail-closed; DNS answers are checked the same way). Digest
challenges are parsed byte-faithfully (non-ASCII realms survive).

### 4.2 Scheduler and AIMD

An extent-grid allocator hands out leases; blocks are the persistence unit;
a thin-zone whole-block floor keeps tails from fragmenting; an endgame gate
with a steal ban keeps tails from thrashing. AIMD: additive increase on
progress, multiplicative decrease on failure with a failure budget;
`Retry-After` is honored; connect staggering and per-host permits shape the
cold-start ramp.

### 4.3 Workers and stall stealing

Worker pools per source execute extent requests; heartbeat liveness marks
silent workers; a coordinator steals leases from stalled workers with a
safety margin (steal races waste bandwidth only); manual redirects and
degraded sources demote rather than fail the task.

### 4.4 Finalization and checksums

Checksum verification (six hash families) with a verify-before-rename
ordering; collision-safe naming with a Windows reserved-name policy; the
part-file lifecycle (create → write → close → rename) is atomic per file
with a documented directory-fsync degradation contract.

### 4.5 Authentication and cookies

HTTP Basic and Digest (RFC 9110 parsing, byte-faithful for non-ASCII
realms); credential slots per scheme with first-match-wins proxy semantics;
the cookie jar applies the full Public Suffix List (three-table decision:
exception > exact > wildcard) with harvest defense on both ingestion faces
and a runtime LRU cap.

### 4.6 FTP

Passive mode with an SSRF-guarded `PASV` address policy (three-state
decision), explicit and implicit TLS, per-scheme credential slots, transfer
reuse with a reply-drain desync demotion, and feature-gated sizing.

### 4.7 Metalink v4

RFC 5854 parsing with hardening caps (entity/DOCTYPE closure, size and depth
limits, charset rules), mirror selection (`language/os/version`,
`preferred-protocol`, location priority), per-file checksum verification,
and metaurl-to-torrent conversion into the BT engine.

---

## 5. Storage and persistence

### 5.1 Disk layouts

v1 padded and v2 compact file layouts with per-file logical offsets; path
sanitization with a Windows reserved-name and long-path (`\\?\`) policy;
the piece-layer key is the **32B binary** pieces root (never hex text);
sparse preallocation; per-platform open flags (`O_NOFOLLOW` on Linux/
Android, `FILE_FLAG_OPEN_REPARSE_POINT` on Windows — other unix ports
tracked).

### 5.2 Write cache and verification

`write cache → verify pool → disk`, with **verify-before-disk** enforced by
proptest-locked invariants: no byte reaches the disk before its hash has
been verified; eviction is min-loss; a `spill` bypass exists for the bounded
overflow window with the same ordering guarantees. The write gate on Windows
serializes shared-handle writes so `Send + Sync` promises are structural.

### 5.3 SQLite persistence

WAL mode, single-writer job queue (ownership = exclusivity): rows for
session, tasks, trackers, DHT nodes, IP guard, cookies. Periodic save
(`--save-session-interval`), graceful-shutdown export to the aria2-compatible
text session format (atomic `tmp`+rename, 0600). Migration importer reads the
legacy fork database and `.aria2` files read-only, with dry-run, dedup, and a
purge-through-aria2 option.

### 5.4 Crash recovery

WAL replay + bitmap-trust rules + recheck of pieces that were in flight.
The recheck path always requeues the task, even when the progress row
cannot be read (the write-back is skipped, the row state advances).

### 5.5 Migration import

`taiji import` reads the legacy fork database and `.aria2` control files
read-only: three-layer fork preflight, pre-import backup, dry-run as a
read-only snapshot, dedup on identity, fail-closed load errors, receipt
export, and an optional purge-through-aria2 helper. A sqlite lock file
guarantees a single session per data directory.

---

## 6. Resource model (memory walls)

Every remote-influenceable counter has a ceiling; exceeding a budget is a
rejection, an eviction, or a disconnect — never an unbounded allocation.

| Budget | Default | Scope |
|---|---|---|
| Unverified bytes in flight | 384 MiB (soft; clamp 128 MiB–4 GiB) | process, write-cache admission |
| µTP receive ledger | 64 MiB | process, reorder + pending windows |
| Magnet metadata assembler | 16 MiB | per task |
| DHT routing records | 8 192 entries | per family |
| RPC request | 10 MiB body; batch ≤ 1 000; subcalls ≤ 10 000 | per request |
| Cookie file | 1 MiB; runtime entries capped, LRU | task |
| `so=` selection | 2²⁰ entries | per magnet |
| Tracker tiers | 256/task, 1 024 global | session |
| Piece length | ≤ 16 MiB | metadata intake (all arms) |
| Queued metadata | 1 024 rows / 256 MiB estimate | RPC intake |

Knob registry: 62 `BH_*` environment variables (parsed once, typed
accessors, defaults and fallbacks documented at the definition site —
`crates/taiji-io/src/knobs.rs`). Every policy seam that was measured has a
knob restoring the upstream (aria2/libtorrent) behavior bit-for-bit.

---

## 7. Session and task model

### 7.1 GIDs and lifecycle

16-hex aria2-style identifiers with cross-restart reservation. Tasks move
waiting → active → complete/error with queue semantics mirroring the
reference (same-slot transitions, position ops, force-save distinctions).

### 7.2 Queue semantics

The queue manager is a pure, testable state machine cross-checked against a
line-by-line transcription of the reference implementation (saturating
arithmetic with the upstream overflow documented as the reason).

### 7.3 Option surface

An aria2-compatible name surface (global + per-task, startup vs hot-reload
capability bits), with declared non-accepted names and declared semantic
differences registered in [rpc-api-diff.md](rpc-api-diff.md) and pinned by
governance tests. Unknown names are ignored like aria2; known-but-unwired
names echo their value (never masquerading as effective).

### 7.4 Events

Six aria2 events (`onDownloadStart/Pause/Stop/Complete/Error`,
`onBtDownloadComplete`) emitted on one bus with backpressure policy;
canonical `taiji.onXxx` names plus compat aliases, never both at once.

### 7.5 Error taxonomy

Stable string codes mapped 1:1 from HTTP status classes (404→3, 401→24,
5xx→29, …) — the mapping table is executable and pinned row-by-row.

---

## 8. RPC surface

JSON-RPC 2.0 at `POST/GET /jsonrpc` (HTTP and WebSocket; optional TLS with
`--rpc-secure/--rpc-certificate/--rpc-private-key`). Auth: secret token
(constant-time compare after SHA-256 folding) and/or HTTP Basic; write
methods are rejected without a secret. The aria2 method surface (~40
methods) is committed verbatim; taiji extensions (`taiji.addUriWithCookies`,
`taiji.setTaskCookies`, `taiji.forceRecheck`, `taiji.createTorrent`,
metalink intake) use canonical `taiji.*` names. Batch and subcall caps
bound amplification. A Prometheus metrics endpoint exposes engine
gauges/counters/histograms (`crates/taiji-rpc/src/metrics.rs` is the family
inventory).

---

## 9. Observability

- Logs: `tracing` with JSON (machine) or text (human) formats; URL and
  credential redaction at the sink; per-target levels; quiet piece-logging
  knob for forensic noise control.
- Metrics: the RPC endpoint above; cardinality rules and injection seams are
  documented per family.
- The knob registry doubles as the tuning/observability surface (§6).

---

## 10. Security model

- Secrets never enter logs or `Debug` output — redacting `Debug` impls cover
  the RPC secret, task credentials, and MSE key material; auth compares run
  in constant time after digest folding.
- Untrusted input is parsed by total decoders (no panics) and fuzzed; intake
  rejects rather than repairs (§3.2 note 1).
- Redirects and proxy addresses are checked against private/reserved ranges
  (fail-closed); the cookie jar defends harvest via the PSL; the RPC face
  caps amplification.
- At-rest: SQLite sidecars and session exports are written 0600.

---

## 11. Compatibility discipline

- **aria2 is the behavioral reference**: option names, queue semantics, RPC
  shapes, and error codes are aligned unless a difference is declared.
  Declarations live in [rpc-api-diff.md](rpc-api-diff.md) (surface) and
  [docs/design/](design/) (mechanism-level anchors to aria2/libtorrent
  sources, with divergence notes).
- The declarations are enforced in CI: the option tables, the method
  registry, the error-code mapping, and the conformance matrix above are
  checked against the code, so documentation and implementation cannot
  drift silently.
- Upstream citations use file + symbol anchors (no line numbers) so they
  survive upstream movement.

---

## 12. Testing and CI

- 2 912 workspace tests: unit suites per crate, wire/integration suites
  (loopback DHT/MSE/NAT/tracker/PEX/engine-loop), persistence and recovery
  suites (kill-window recheck, corruption injection), HTTP mock servers
  (probe/redirect/auth/cookies/H2/FTP containers), CLI e2e (real binary,
  ≥1 GiB fixtures), decision tables for every policy seam, proptest for
  parsers and caches, 27 fuzz targets with seed corpora.
- CI (GitHub Actions): fmt + clippy `-D warnings` + full tests on
  Ubuntu 24.04 / macOS / Windows with the toolchain pinned (1.98) to stop
  stable-channel drift; store/bt/http subsets on the non-Linux hosts; a
  no-default-features leg guards the metalink-off build. The spec
  conformance suite (§3.1) is execution-checked, so the matrix and this
  document cannot drift from the code.

---

## 13. Glossary

- **face** — a per-task slot in the engine (one swarm = one face).
- **wall / budget / ledger** — a hard or soft cap on a resource, with the
  accounting that enforces it (§6).
- **decision table** — a test shape enumerating inputs × verdicts for a
  policy seam, transcribed from the upstream reference where one exists.
- **declared divergence** — a documented, test-pinned difference from aria2;
  anything else that differs is a bug.
