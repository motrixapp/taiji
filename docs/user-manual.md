# taiji User Manual

English | [简体中文](./user-manual.zh-CN.md)

## HTTP/FTP One-Shot Download (`taiji http`)

```sh
taiji http <URL…> -d <dir> [-o filename] [--checksum sha-256=<hex>]
```

- Multiple URLs = mirrors of the same file (aria2 addUri semantics); ftp/ftps are
  accepted.
- **Resume**: the bitmap in the session database `taiji.sqlite3` is the source of
  truth for resumption. After the process is killed (including kill -9),
  **re-running with the same arguments** automatically continues in-flight tasks
  without re-downloading; `--continue=false` does not change this behavior
  (resume is always on in this engine — the inversion is declared explicitly).
- **`--checksum <algo>=<hex>`** (algo ∈ md5|sha-1|sha-224|sha-256|sha-384|
  sha-512): whole-file verification at completion; a mismatch = task failure
  (exit 1), the data stays on disk as `<file>.part` for inspection, and no
  corrupted final file is left behind.
- Unfinished data goes to `<file>.part` (`--http-incomplete-suffix`
  configurable, persisted with the task at creation) and is atomically renamed
  on completion.
- **Concurrency guard**: only one taiji session is allowed per session database
  at a time (`<db>.lock` kernel file lock); a second process exits immediately
  with a clear error and never co-writes the same `.part`.
- attach comparison: when continuing an in-flight task, its persisted options
  are checked — a `--checksum` that differs from the in-flight task is
  **rejected** (the in-flight task settles under the checksum it was created
  with); other differences (e.g. the suffix) warn, and the persisted value wins.
- Honesty boundary: a re-run after a task **failure** is a brand-new task
  downloaded from scratch (the error row is outside the recovery surface; the
  `.part` is left on disk for forensics only).
- Exit codes: 0 = completed; 1 = task failed/interrupted/concurrency refused/
  attach refused; 2 = usage or option value-range error.
- Remaining options (`--split`/`--timeout`/`--header`/`--all-proxy` etc.) are
  accepted; until the corresponding option group lands they emit an explicit
  runtime warning (they are not made to look effective while doing nothing).
- **Downloads requiring login (cookie surface)**:
  - `--load-cookies <netscape file>`: carries cookies to download protected URLs
    (Netscape format exported by curl/browsers). A missing file / over 1MiB =
    task refusal; `Set-Cookie` issued by the server during the download is
    absorbed and persisted, so resume sessions remain valid.
  - When coexisting with `--header "Cookie: …"`, file cookies are authoritative
    (manual Cookie lines are ignored — avoiding conflicts between two cookie
    sources; the fork engine follows the same rule).
  - The RPC form additionally offers structured direct delivery:
    `taiji.addUriWithCookies` (cookie-by-cookie at add time) and
    `taiji.setTaskCookies` (updates the cookies of waiting/paused tasks).

Reproducible demo (mock source + throttling + kill -9 resume + checksum final
verdict):

```sh
python3 scripts/http_5gb_resume_demo.py   # run against the ≥5GiB criterion
```

## DNS and Tracker Address Recovery

HTTP, FTP, trackers and DHT bootstrap share system DNS resolution and a bounded
cache. Same-host concurrent requests share one lookup. Successful answers are
cached for 5 minutes, failures for 2 seconds and timeouts for 1 second; a
cancelled request or local capacity limit is not cached as a hostname failure.
The resolver retains the operating system's hosts-file and VPN DNS settings.

Motrix observes network and DNS configuration while the engine is ready, with
a 10-second polling interval and an immediate check on desktop wake. Detected
changes invalidate both successful and failed cached answers, retire pending
results and refresh UDP tracker connection state. Queries keep their original
timeout budget across this transition. Optional system information tools may
be unavailable in containers or restricted environments; the remaining file
and interface observations still apply. Changes invisible to the application,
such as reconfiguration behind an unchanged DNS proxy, still rely on expiry.

UDP trackers try alternate addresses when an endpoint is unreachable. Only a
successful CONNECT endpoint receives ANNOUNCE, and changing addresses does not
extend the attempt's total timeout. DNS/endpoint recovery helps discovery but
cannot produce metadata when no reachable peer has it.
IPv6 availability checks run in the background so an unresponsive IPv6 route
does not hold up IPv4 tracker requests or cancellation.

A timed-out system lookup may continue in the OS. taiji bounds these calls to
32 active and 256 active/queued queries, and isolates them from other blocking
I/O. The `/metrics` DNS counters distinguish cache hits, coalesced callers,
backend queries and actual system activity; they do not expose hostnames.

## Magnet preparation and cache

Motrix prepares enabled DHT discovery asynchronously after connecting to its
matching taiji engine. File-list resolution has a separate four-task
queue. The metadata connection budget respects `bt-max-peers` up to 128 attempts
(128 when unlimited), including pending handshakes, with a 30/s dial rate and a
24-attempt initial burst. Pending handshakes do not count as connected peers for
tracker requests. Across metadata tasks, at most 128 ordinary connection
attempts and eight urgent hole-punch or relay attempts may run concurrently.

Verified metadata is reused in memory (128 entries / 16 MiB) and in the session
database (1024 entries / 64 MiB, at most 16 MiB per entry). Cache records contain
raw verified info and piece layers; they do not inherit outer tracker URLs,
credentials, output paths or file selections. Identity and structure are checked
again after reading disk; invalid cached data falls back to discovery. Removing
a task does not remove this bounded content cache. Existing retained task
metadata is also reusable. Schema migration v5 adds the derived cache without
replacing v4 task rows.

## Download and Seeding

```sh
taiji <torrent|magnet> -d <dir>
```

- Automatically transitions to seeding when the download completes; stops once
  `--seed-ratio` / `--seed-time` is reached; `--bt-stop-timeout` controls the
  idle-seeding exit.
- `-V`/`--enable-dht`/`--bt-lsd` control the discovery surface; private torrents
  automatically disable DHT/PEX/LSD.
- `--bt-tracker "url1,url2"` appends trackers (running tasks pick it up live via
  the global import); `changeUri` follows upstream file-entry URI semantics and
  does not edit trackers.
- **Tracker dynamic editing (RPC surface)**: `taiji.addTracker(gid, urls, options?)` /
  `taiji.removeTracker(gid, urls)` — add/remove trackers per task (each URL
  forms its own tier; `options.position` specifies the insertion tier position,
  default table end). Active tasks pick it up immediately (announce surface);
  waiting/paused tasks keep it across restarts. magnet/.torrent URL
  metadata-phase tasks, HTTP tasks, and finished tasks are explicitly refused.
  See the tracker dynamic editing section in rpc-api.md.
- **DHT runtime hot toggle (RPC surface)**: `changeGlobalOption("enable-dht",
  "true"|"false")` takes effect immediately on a running session — the DHT
  surface of the engine's running BT tasks starts/stops with it (aligned with
  libtorrent's `apply_settings` capability; upstream aria2 cannot hot-change
  enable-dht, so this is a taiji extension with the difference declared).
  `enable-dht6` is accepted under the same key (value surface — taiji has no
  separate v6 DHT gate; the v6 surface follows the `enable-dht` master gate and
  the IPv6 connectivity gate).
- **Task-level DHT flag**: `bt-disable-dht` (bool; accepted under the same key
  in addTorrent/addUri options and `changeOption`) — defaults to following the
  session `enable-dht`; explicit `true` disables DHT for that single task,
  `false` forces DHT for that single task (aligned with libtorrent
  `torrent_flags::disable_dht` capability). Hot-effective on active tasks;
  private torrents are unaffected by the flag (BEP27 hard gate — DHT
  interaction is always disabled).
- **Trackerless torrents** (both announce / announce-list missing): **always
  accepted** (the same rule for CLI download and RPC addTorrent /
  addUri(.torrent URL)). DHT on (the default) = pure DHT discovery; DHT off =
  accepted + WARN log (no discovery source, the task stalls — the log gives
  recovery guidance: `changeGlobalOption("enable-dht","true")` hot-enables it
  back to life (no restart); or `taiji.addTracker` to add a tracker; or restart
  with a different DHT initial value). Upstream cross-validation: aria2's
  ingestion surface does not refuse regardless of the DHT switch
  (`RequestGroup.cc` only NOTICEs), and libtorrent never refuses — taiji's
  behavior is aligned. Private torrents disable DHT interaction even when
  accepted (BEP27); a trackerless private torrent has no discovery source, so
  carry trackers when using one.
- **Sequential download**: `--bt-sequential-download` (CLI, default false) or
  the RPC option `bt-sequential-download=true`
  (addTorrent/addMagnet/changeOption paused surface) — the task downloads
  pieces in file order (v1 global piece order / v2 within-file piece order);
  when combined with multi-level file priorities, a higher-priority file's
  whole layer downloads first. Runtime switching goes through
  `taiji.setSchedulerPolicy(gid, "sequential")` (the authoritative surface; the
  option key is its aria2-compatible projection, and `getOption` echoes back
  the projection of the policy). Policy echo: `taiji.getSchedulerPolicy`.
- **Multi-level file priority (RPC surface)**: `taiji.setFilePriority(gid,
  pairs)` adjusts download priority per file — `pairs = [{index, priority}]`
  (index is 1-based, the same convention as `getFiles`/`select-file`; priority:
  -1 skip / 0 normal / 1..7 high priority — the larger the number, the earlier
  it downloads). Unlisted files are untouched; active tasks pick it up
  immediately (piece selection order becomes "priority → rarity"),
  waiting/paused tasks receive it on activation, and it survives restarts.
  `-1` is equivalent to moving the file out of the selection set (the same
  surface as `select-file`); `0..7` restores/joins it. Echo:
  `getFiles`/`tellStatus` files[] carry a `priority` key on each entry. When
  combined with the streaming scheduling policy, the playhead priority always
  wins (high-priority files are accelerated outside the window layer). Upstream
  aria2 has no such surface (aligned with libtorrent `file_priority`
  capability; difference declared).
- **Download + RPC coexistence** (`--enable-rpc`, upstream three-state
  alignment): with a torrent given, the RPC server starts alongside it, and
  `tellActive`/the event surface cover the full task lifecycle:

 ```sh
 taiji <torrent> -d <dir> --enable-rpc --rpc-listen-port 6800 \
 --rpc-secret <token>
 ```

 The task stays resident seeding and the process stays resident until
 Ctrl-C/SIGTERM or RPC `shutdown`. The `--rpc-*` option group
 (listen-port/secret/user/passwd/aria2-compat) in download mode must be paired
 with `--enable-rpc`, otherwise startup fails with an error (exit 2) — silent
 ignoring has been removed.

## Torrent Creation

```sh
taiji create-torrent <file…> -o out.torrent \
    --piece-length 16384 --format hybrid --private --announce <url>
```

`--format v1|v2|hybrid`; hybrid writes both the file tree and the files views,
with piece layers computed automatically.

## RPC daemon

```sh
taiji --rpc-listen-all --rpc-secret <token>
```

- No positional arguments = the pure daemon form (idle): RPC is always on — the
  synonym surface of aria2's `--enable-rpc` pure daemon form (the option is
  accepted but has no effect; semantics unchanged).
- Without `--rpc-secret` / `--rpc-user` set, binds to 127.0.0.1 only.
- **Public internet exposure**: go through WireGuard/Tailscale or a reverse
  proxy terminating TLS; the engine has no built-in TLS.
- A WebSocket connection doubles as an event subscription; after a reconnect,
  use `tellActive/tellStopped` to catch up on state.
- For the download-and-RPC same-process form, see the "Download and Seeding"
  section (`--enable-rpc` + positional arguments, upstream three-state
  alignment).

## Private Torrents (PT)

- peer ID defaults to `-TJ0001-`; `--peer-id-prefix` can override it (the PT
  whitelist convention).
- UA / ext handshake `v` = `taiji/<semver>`.
- min-interval is strictly honored; the stopped sequence is delivered to all
  tiers.

## Storage and Recovery

- Session database `taiji.sqlite3` (customizable via `--sqlite3-db-path`, takes
  effect on restart).
- File allocation `none|trunc|falloc|prealloc` (`--enable-falloc` etc.).
- The bitmap is verified at startup; `--check-integrity` forces a full recheck.
- hash recovery: when a v2 torrent lacks `piece layers`, they are automatically
  replenished from the swarm; until then the corresponding files are barred
  from download and seeding; the events `taiji.recoveryStarted/Completed` make
  this visible.

## Performance and Tuning

- `--peer-connection-type tcp|utp|prefer-tcp|prefer-utp` (default prefer-tcp).
- Rate limits: global `--max-overall-{download,upload}-limit`, per-task
  `--max-{download,upload}-limit` (0 = unlimited).
- `--bt-peer-connection-type` is a synonym surface; `taiji.setSchedulerPolicy`
  switches the piece-selection policy at runtime.

## Logging and Collection (Operations)

- `--log-format text|json` (default text = human-readable, consistent in form
  with existing behavior). Log filtering follows `RUST_LOG` (default info).
- `--log-format json`: stdout emits valid JSON line by line
  (timestamp/level/target/fields, the default tracing-subscriber structure),
  for machine consumption by log collection / benchmark telemetry / AI
  toolchains:

```sh
taiji --log-format json --rpc-listen-port 6800 \
| jq 'select(.target=="taiji::core::engine")'
```

- ANSI color is emitted only when stdout is directly attached to a terminal
  (interactive TTY); redirection to file/pipe is automatically clean (no
  `\x1b` escape sequences), and it is switched off entirely when the
  `NO_COLOR` environment variable is set (no-color.org).
