# CLI design notes

Distilled design notes behind the `taiji` CLI crate (bin of the same
name): the `import` migration subcommand, the session database
cross-process lock, the `--print-completions` generator, and the
`create-torrent` subcommand. The behavioral reference is upstream aria2,
read-only.

## import.rs

`taiji import` migrates an existing aria2-fork installation's state into
the taiji session database. One command, two source faces, both parsed
strictly read-only:

- the legacy aria2-fork sqlite database (`--from-aria2-db`): the
  BitTorrent face and the HTTP/FTP face are collected in one read-only
  pass and account for complementary tasks;
- `.aria2` control files (`--from-aria2-dir`): BitTorrent control files
  are imported directly on the BT face; HTTP-face control files are
  reconciled against fork rows, unmatched ones reported as orphans.

Plans land in the target `taiji.sqlite3` through the PersistWriter face.
The stdout report ends with the list of aria2 GIDs to deregister; with
`--purge-via-aria2` the original tasks are deregistered through the
aria2 JSON-RPC `aria2.remove` + `aria2.purgeDownloadResult` pair after
user confirmation. The engine never writes fork storage itself
(sqlite stays the single persistence source of truth). Reports go to stdout — this subcommand's user-facing
artifact; library code still logs through tracing only.

### Pipeline order and guards

The step order is load-bearing:

0. Same-path guard: if `--sqlite3-db-path` and `--from-aria2-db`
   canonicalize to the same file, the source database would be rewritten
   as the target (the backup would copy the fork db to `.v1.bak` and
   then "migrate" in place, polluting fork storage). Refused before any
   IO; canonicalize normalizes spelling variants (`/./` segments, mixed
   relative/absolute forms). The clash message reports the original fork
   path.
0.5. Three preflight layers against a still-running fork: (1) a held
   sqlite lock -> refuse and advise exiting the old version; (2) a
   live-fd scan of the fork (a WAL-normal fork holds no lock most of the
   time, so layer 1 misses an "alive but idle" old version) -> refuse on
   a hit and report the pid; (3) cannot prove (platform unsupported,
   lsof missing) -> refuse by default, with `--i-know-fork-is-closed`
   as the explicit responsibility bypass. The flag never waives layers
   (1)/(2): a held lock and a live pid are direct facts, not absence of
   proof.
1. Source collection inside `spawn_blocking`; the fork process-lock
   probe is forced to run first (preflight item 1, `ForkLocked` maps to
   "exit the old version" guidance). Control-file tasks carry no
   queue-order notion, so they take scan order after the fork tasks.
1.5. Target shape/ledger probe (read-only), before the backup: if the
   fork db were mistaken for the target, the backup's checkpoint and the
   subsequent open+migration would both write fork storage — the red
   line of read-only discipline. This is the mirror-image guard of the
   fork-side `open_fork_readonly` table-set probe.
2. Automatic pre-import backup (preflight item 4), strictly before the
   target database is opened or migrated: `.v1.bak` preserves the bytes
   that a 0.1.x build could still open before the migration ledger
   advances — the restore anchor of the §10.4 rollback runbook. Dry-run
   skips it (zero write side effects). A live target, or one left
   uncleanly shut down (`-wal`/`-shm` still on disk), is refused here —
   preflight item 3.
3. Target database: the writer opens only on the real-import face. A
   dry-run takes a read-only snapshot and never opens an existing
   database through PersistWriter, because opening it advances the
   migration ledger (v2→v3): a "dry-run first, real import second" flow
   once poisoned the `.v1.bak` rollback anchor into an already-migrated
   snapshot. The writer's join handle is kept until an exit drain — if
   process exit killed an unfinished writer thread, sqlite would have no
   clean close and the leftover sidecar files would jam the next
   import's pre-import backup.
4. Per-task planning: dedup, then metadata resolution with
   cross-validation (BT) or `HttpImportPlanner` assembly (HTTP).
5. Report assembly, shared by dry-run and real runs: every row goes
   into a buffer first, then one final print + persist.
6. Persist / deregistration list (real runs).
7. Optional aria2 deregistration (SPEC §9.3: remove +
   purgeDownloadResult), after user confirmation.

A dry-run is a read-only snapshot: the migration ledger never advances,
no pre-import backup is made, and the target database is not created.
This holds equally on an older-ledger database; a real import migrates
only after the automatic backup. An old-ledger target (a 0.1.x db) gets
an accurate notice: a dry-run itself never touches it.

### Dedup and path-conflict decisions

Dedup is keyed by `session_kv.imported_from` (SPEC §10) and surfaced in
dry-run too. A dedup kv read failure is never silently treated as "not
imported": with unknown dedup state a re-import would overwrite live
task rows with import-time state. On the real-import face the task is
reported Failed; in dry-run a snapshot read failure rejects the whole
run instead of degrading to "nothing imported yet".

HTTP-face path-conflict adjudication (second imports) uses the target
database's in-flight (dir,out) occupancy set plus earlier tasks of the
same batch. Dry-run reads it from the read-only snapshot; on the
real-import face a read failure keeps a degraded presentation (warn +
empty set) — the worst outcome of a wrong path-conflict decision there
is a "skip", not an overwrite, a different severity class than the dedup
kv overwrite risk. The default decision is skip (surfaced in the report,
never silently overwritten); `rename` re-imports under a name from the
aria2 candidate-name algorithm (`file.tar.gz` → `file.tar.1.gz`).

`.aria2` orphan reconciliation (HTTP face) keys on totalLength + output
path. A hit merges the control file into the fork row (filling in the
bitmap payload for rows without progress lines); no match marks a
standalone orphan. Read-only discipline: files and data are kept as-is
and the real import emits no row for an orphan — control files carry no
URI, so the task must be re-added by URI.

### Report receipt

Operations that change user data must leave a durable receipt. The
report buffer is the single source: buffer text = stdout output =
persisted content. Dry-run and real imports each write
`<db>.import-report-<timestamp>.txt` (millisecond UTC timestamps,
filename-safe — a dry-run and a real run back to back never collide).
The receipt path line joins the report only if the write succeeded —
stdout never claims a file that does not exist. A persistence failure
degrades to a warn and does not block. The report is finalized before
the interactive purge output: stdout after the receipt belongs to the
interactive process, not the report.

The deregistration list contains exactly the fork-source tasks that
persisted successfully; control-file sources carry no GID and stay out
of the RPC deregistration face. Exit codes: 0 = no failures; 2 = some
tasks failed (the batch still ran to completion); 1 = infrastructure
error (bad arguments, unreadable source db, preflight refusal,
unreachable deregistration endpoint).

### aria2 purge client

The JSON-RPC client is bare HTTP/1.1 with zero new dependencies (the
same shape as the rpc_smoke integration-test client); Phase A supports
http endpoints only — the LAN sidecar scenario. `https` is rejected
explicitly instead of pretending to work. URL form:
`http://[token:SECRET@]host[:port][/path]` with the aria2 defaults
(port 6800, path `/jsonrpc`); the token is prefixed `token:SECRET`, the
aria2 client convention. Every call is bounded by its own timeout
budget: deregistration runs outside the batch, so a hung fork must not
stall the process. `aria2.remove` errors on completed tasks are
expected — their result rows are cleaned up wholesale by
`aria2.purgeDownloadResult` (the SPEC §9.3 two-step semantics).
Interactive confirmation reads one line; immediate EOF on a
non-interactive stdin counts as refusal — scripts pass `--yes`
explicitly.

## db_lock.rs

The session database needs a cross-process mutex: a single-session
guard implemented as a lockfile beside the DB.

Why: the `.part` occupancy table (taiji-http `partfile`) is an
in-process `OnceLock<Mutex<HashSet>>`. Two `taiji http` processes
started with the same arguments (or a CLI and a daemon sharing the
default database) would each bootstrap-resume the same in-flight task
and co-write one `.part` across processes — truncate-restart vs
bitmap-resume trampling each other. The session model is "one database,
one writer": in-process PersistWriter serialization is only a necessary
condition; the cross-process face is closed off here — the second
process fails fast with an explicit error, it never co-writes.

Mechanism: `<db>.lock` is a minimal sqlite database. The session opens
a separate connection, runs `BEGIN EXCLUSIVE`, writes a holder record,
and holds the whole transaction until the session ends. The semantics
match `flock` (kernel file lock, released on process death) with no new
dependency and no unsafe: within this repo's MSRV (1.85) std has no
`File::try_lock` (stable since 1.89), while rusqlite/bundled is already
in the dependency set.

Hard properties:

- Lock period = session period. The lock is held while the connection
  is alive; on process death (including kill -9) the kernel releases
  the POSIX file lock and the next opener automatically recovers the
  lock database's hot journal — no stale-lock deadlock. An `O_EXCL`
  create-file scheme would leave a deadlock after kill -9, hence not
  adopted.
- The lock file is never deleted. release + unlink races with a
  concurrent opener and can swap file identity (two "holders" each
  locking a different inode); an empty lock database lingering on disk
  is harmless.
- No waiting. After a short `busy_timeout` window an occupied lock
  fails (`SQLITE_BUSY`): a concurrent second process means "fail with
  an explicit error", not queueing — queued resume would be implicit
  session serialization, beyond what a user expects.
- Zero interference with the main database. The lock lives on a
  separate file, so this process's PersistWriter writes to the main
  database are unaffected.
- The daemon (the RPC-resident form) will join the same lock: a planned
  integration; today only the `taiji http` CLI holds it.

File locks are arbitrated per connection, so a second acquire from the
same process is also reported as held.

## completions.rs

`taiji --print-completions <bash|zsh|fish>` is the minimal completion
script generator: zero third-party dependencies (no clap_complete,
hand-built word lists).

Discipline: `LONG_FLAGS` / `SUBCOMMANDS` are hardcoded ledgers that
must mirror the clap metadata of the `Cli` struct in `main.rs` verbatim
(the `#[arg(long …)]` / `long = "…"` derive names + visible aliases +
the `Command` subcommand names). Every time a flag is added to `Cli` or
a subcommand to `Command`, the ledger must be updated — the sync is not
enforced by comments but pinned by tests
(`long_flags_sync_with_clap_metadata` /
`subcommands_sync_with_clap_metadata`) that derive the expected surface
live from clap `Command` introspection, so ledger drift goes red (the
same seal-the-registration-hole pattern as conf.rs'
`conf_key_surface_matches_cli_long_options`). A new flag without a
ledger entry fails, and so does a ghost ledger entry without a flag.

Scope (minimal by design): completion of long flag names (no values)
and subcommand names; flag value domains/hints, short flags, and
in-subcommand options are out of scope. Each shell gets one minimal
snippet: bash a `complete -W` word list (flags and subcommands mixed —
compgen's prefix filtering naturally splits `--`-prefixed flags from
bare subcommand words; `-o filenames` backs up path completion for
`.torrent` positional arguments), zsh `compdef` + `_arguments` per-flag
specs plus a first-positional `_alternative` combining the subcommand
list with `_files`, and fish one `complete -c taiji -l` line per flag
plus a subcommand line gated by `__fish_is_first_arg` (built into fish
3.2+; without the gate the subcommand words would be offered as noise
after flags). The zsh script registers via a trailing `compdef` line:
loaded through `source`, an autoload registration in the `#compdef`
header comment form does not take effect, so the trailing line is the
only hook point.

The ledger excludes `help`/`version` (clap auto-generated, appended
separately so `--he<TAB>` works) and hidden derive aliases
(`bt-enable-lpd`/`rpc-port`): the completion surface follows the help
surface, and hidden aliases are not shown there. Output goes to stdout
and the process exits (meta-flag semantics; see the `main.rs`
consumption point). The shell domain is frozen by the clap
PossibleValuesParser, which references the same table — a single
source.

## create_torrent.rs

`taiji create-torrent`: an explicit file list → the
`taiji_core::create` facade (the bt::creator kernel) → a .torrent
written to disk.

The argument surface shares its source with the RPC
`taiji.createTorrent` (same facade, same rules; the RPC's `outputDir`
directory form becomes the explicit `-o <file>` file form here).
Engine freedoms — default values, announce rules, the omitted creation
date — are noted in the `taiji_core::create` module docs; aria2 has no
create-torrent to cross-check against, so the comparisons are against
libtorrent, noted per item (e.g. the default piece length 16k matches
libtorrent's automatic-mode floor, and under libtorrent's default flags
a torrent with both hash sets is hybrid — create_torrent.hpp).

BitTorrent inputs are not recursively scanned: callers enumerate files
explicitly (one file → single-file torrent named after the file; many
files → multi-file torrent named after the common parent directory, an
error when there is none). Reports go to stdout and errors to stderr —
the same rule as import.rs; the library-code stdout ban does not cover
cli-bin user-facing output.

## tests/download_rpc_e2e.rs — BT download + RPC rig

`--enable-rpc` is verified three ways in one rig:

- Same-process RPC observation: the downloading process's RPC server
  sees the full task lifecycle — the task is visible in `tellActive`,
  the completed byte count arrives, the `taiji.onBtDownloadComplete`
  event is delivered over WS, and an RPC `shutdown` closes the process
  down gracefully (exit 0).
- Bare-path control: downloading without `--enable-rpc` (the default)
  must show zero behavior change — a snapshot control pinning the
  pre-RPC shape.
- Conflict arm: RPC group options without `--enable-rpc` are a hard
  startup error (exit 2, the clap usage-error code).

Rig shape:

- The fake HTTP tracker runs in-process (announce over HTTP).
- The rqbit seeder and the taiji leecher are subprocesses.
- The BT data plane deliberately never touches the test process: the
  test-process <-> engine-subprocess raw BT stream is unreliable under
  sandbox interception in this environment, while subprocess <->
  subprocess through rqbit is verified stable.
- The seeder is rqbit, not taiji: the engine cold-starts with no
  bitmap recovery (the recovery bitmap lives in session-db rows), so
  it would not treat complete on-disk data as already downloaded;
  rqbit verifies the full payload itself before seeding.
- The RPC client is a native tokio TcpStream speaking bare HTTP/1.1
  plus an RFC 6455 WS subset (zero new dependencies; same shape as the
  rpc crate integration tests).

## http.rs

`taiji http` performs a one-shot HTTP(S)/FTP(S) download, end to end. Its
shape mirrors the existing bare-BT download mode: no RPC server is
started; the SessionActor is bootstrapped directly (session-store
persistence + bootstrap recovery).

### Resume semantics (session store = control-plane truth)

The bitmap snapshot is the resume truth: after the process is killed,
rerunning the same URL into the same directory has bootstrap rebuild the
in-flight task and resume it. Before addUri, the CLI reads the same read
path as bootstrap (active rows: queued | probing | downloading | paused)
to decide attach vs. create. On a same-source in-flight hit it does NOT
create a duplicate task — it waits for the existing one to finish. This
is the session-store counterpart of aria2's `<file>.aria2` control-file
resume; creating a duplicate would collide with the new task's `.part`
open policy (truncate-and-restart vs. bitmap-resume concurrent double
writes).

Attach option comparison (never silently drop rerun options): on a hit,
the row's persisted config is compared with this run's options — a
`--checksum` value mismatch REJECTS attach (the in-flight task finalizes
by its persisted value, so the new value would be discarded — explicit
error instead of silence); a one-sided default or a differing
`--http-incomplete-suffix` attaches with an explicit warning (the
persisted value wins).

Honesty boundary: terminal rows (error/done) are outside the recovery
read path — rerunning with the same parameters after a failure creates a
fresh task that downloads from zero (the leftover `.part` stays on disk
for forensics only and is not a resume surface; the engine-side statement
lives in the core `http_task` module).

### Single-session guard

Before bootstrapping, the CLI takes the `<db>.lock` cross-process lock
(mechanism and rationale: db_lock.rs above). Lock period = session
period; a second concurrent process fails fast with an explicit error
before touching the store, instead of co-writing the same `.part`.
Wiring the daemon (the resident RPC form) onto the same lock is
integration surface.

### Option surface (frozen names = aria2 same-name options)

Wired (driven through the addUri option map): `--dir`, `--out`,
`--checksum` (completion-time final verdict; failure = task error,
numeric code 32), `--http-incomplete-suffix` (strict validation +
persisted at creation), `--remote-time` (mtime set from the remote
Last-Modified), `--timeout`, `--connect-timeout`, `--max-tries`,
`--retry-wait`, `--user-agent`, `--header`, `--http-user`,
`--http-passwd` (Basic pre-auth + 401 Digest challenge response),
`--all-proxy` (http/https), `--check-certificate`, `--ca-certificate`,
`--load-cookies` (Netscape cookie file), `--http-max-per-host`, and the
FTP family `--ftp-user`, `--ftp-passwd`, `--ftp-ssl`, `--ftp-pasv`,
`--ftp-reuse-connection` (effective for FTP/FTPS sources;
`--ftp-pasv=false` rejects the task — active mode is not implemented, a
declared difference).

Accepted but not effective (explicitly disclosed with warnings, never
disguised as working): `--continue`, `--split`, `--min-split-size`,
`--max-connection-per-server`.

Exit codes: 0 = download complete; 1 = task failed/removed/interrupted,
concurrent session refused, or attach refused; 2 = session command error
(including the `taiji.option.invalid` value-domain rejection and lockfile
filesystem failure).

## conf.rs

The `--conf-path` layer reproduces the aria2 conf form, cross-validated
against aria2 `OptionParser.cc`.

### Parse form

Each line is `key=value`, split on the FIRST `=` (an `=` inside the value
is preserved verbatim); `#` comment lines and blank lines are skipped;
lines without `=` (or with an empty key) are skipped (the same shape as
aria2 OptionParser.cc). Hardened beyond the reference: leading/trailing
whitespace is trimmed (aria2 does not trim — a key containing spaces
would become an unknown entry; under a fail-fast surface, trimming is the
tolerance precondition), and a head UTF-8 BOM is tolerated. Same-name
keys apply in order, later values overriding earlier ones (the same
behavior as aria2 `Option::put`).

### Deliberate differences from aria2 (safety choices, not omissions)

- No implicit path loading: aria2 reads `$HOME/.aria2/aria2.conf` by
  default (option_processing.cc default-path fallback, disabled only by
  `--no-conf`). Here `--conf-path` has no default — without the flag
  there is zero file IO, and process behavior is fully determined by
  explicit input (no environment surprise).
- Unknown keys fail fast (exit 2): aria2 only WARNs on unknown conf keys
  and keeps running (OptionParser.cc) — typos are silently swallowed and
  the process runs on defaults; here it is an explicit rejection
  (wording and exit code aligned with the main.rs `rpc_group_conflict`
  hard-error style).
- Missing/unreadable file fails fast (exit 2): an explicit `--conf-path`
  pointing at a missing file behaves like aria2 (option_processing.cc
  hard error); unreadable permissions and non-UTF-8 content take the
  same face.
- A `conf-path` key inside the conf is recognized but no-op: no nested
  loading — assembly is single-pass and deterministic (aria2 likewise
  does not trigger a second load for a same-name entry inside the conf).

### Key-name surface and value domains

The key surface = the taiji CLI long-option primary names (conf keys
carry no `--` prefix, the same form as the aria2 conf; aliases are CLI
ergonomics and stay out of the conf surface; auto-generated help/version
names, positionals, and subcommands are not in the surface).
Consistency between the key surface and clap's introspected long names is
locked by `conf_key_surface_matches_cli_long_options` — a new flag
without a parse arm turns red.

Domain validation reuses existing parsers (no invented domains): enums go
through core `parse_crypto_level` / `parse_peer_connection_type`; the
bool domain is `true|false` (the same face as the CLI flags + the aria2
`BooleanOptionHandler::parseArg` domain — 1/0/yes are not accepted);
sizes go through `parse_aria2_size` (the same function as
`--rpc-max-request-size`); numeric domains match the corresponding clap
value_parsers (u16 ports / `summary-interval` 0..=SUMMARY_INTERVAL_MAX /
`http-max-per-host` >= 1).

### Priority and assembly point

defaults < conf < explicit CLI flags. "Explicit" = clap
`value_source == CommandLine` (the same criterion as
`rpc_group_conflict`; conf values and defaults are both non-command-line
sources). Conf values are written back into the same Cli fields — the
idle daemon and the download/download+rpc forms share the
`build_idle_options` + `IdleOptions::to_session_options` assembly single
point, so conf and CLI values are indistinguishable at the assembly point
(pinned by a consistency test). Domain validation runs unconditionally
(a bad value is not excused by CLI priority — a broken conf is rejected,
the same stance as unknown keys). Conf-provided values do not satisfy
`rpc_group_conflict`'s explicitness criterion (criterion = command-line
source) — in bare download mode a conf-provided RPC-group value ranks
with the default (no effect and no error).

Mode restriction (the single hard-error exception, fail-closed):
conf-provided `enable-rpc=true` in download mode = exit 2 hard error
(the main `conf_enable_rpc_download_conflict` arm, judged by the same
value_source mechanism) — download + RPC in one process is an unplanned
listening surface, enterable only via an explicit command-line
`--enable-rpc`. The CLI-flag-always-wins rule is unchanged (an explicit
`--enable-rpc=false` overrides conf `=true`, back to bare download). Idle
mode is unrestricted (idle is the daemon form, RPC always on; a conf
enable-rpc ranks with the default).

## main.rs

Run modes and assembly (mirrors the upstream three-state assembly in
aria2 `DownloadEngineFactory.cc`, plus CLI URI co-residence):

- Download mode (a `.torrent` positional): parse metainfo, run the
  DownloadEngine, then stay resident seeding after completion.
- Download + RPC (`--enable-rpc`): the RPC server runs in the same
  process; the engine path goes through the SessionActor pipeline (shared
  with idle) and the torrent is injected directly via the AddTorrent
  session command — no RPC self-call, bypassing the write gate and
  credential requirement (mirroring the upstream engine-phase direct
  RequestGroup wiring).
- Idle mode (no positional): actor-topology bootstrap + RPC service
  (axum `POST/GET /jsonrpc`, token/Basic auth, six methods).
- `import`: read-only migration import from a fork sqlite / `.aria2`
  file plus an aria2 dereg list.
- `http` subcommand / top-level URL positional: SessionActor-driven
  one-shot download with session-db bitmap resume (same pipeline and
  exit-code mapping for both entry forms).
- `--print-completions <bash|zsh|fish>`: print a minimal completion
  script to stdout and exit before any download/session mode (and before
  conf loading, tracing initialization, and the RPC group conflict
  check; all other arguments under the flag are ignored).

Option names are frozen: `--dir`/`--listen-port`/`--rpc-*` use
aria2-compatible names. aria2 `--listen-port` accepts a port range and
tries each; `taiji` takes a single value.

### Exit codes

Baseline shared by all modes, checked before mode dispatch: `2` = usage /
startup hard error (clap parse failure, `--conf-path` fail-fast with
unknown keys / unreadable files, download-mode RPC group conflicts,
conf-provided enable-rpc, out-of-domain values); `1` = process
infrastructure failure (tokio runtime build failure).

Per-mode mapping:

- `0`: download — download complete / seeding stopped / graceful
  Ctrl-C/SIGTERM stop (signal = 0); http — task Complete (signal maps to
  1, divergence A); idle — signal or RPC shutdown (still 0 past the 1s
  budget, divergence B).
- `1`: download — torrent read/parse/engine-config failure, engine
  Failed/panic, shutdown past the 1s budget; http — task error/removed,
  signal interruption, held session lock, attach rejection / in-flight
  row read failure / malformed gid, non-value-domain session command
  errors; idle — RPC bind failure (the only 1 face).
- `2`: baseline only, except http — session-command value-domain
  rejection (`taiji.option.invalid` prefix, `http::exit_code_of`),
  lock-file filesystem failure, missing URL, metalink document failures
  (read/over-cap/parse/zero entries).

Documented divergences (recorded, not changed):

- A. Signal interruption: the BT forms (bare / magnet one-shot /
  download+rpc) and idle finish gracefully on Ctrl-C/SIGTERM with 0; the
  http pipeline maps signal interruption to 1 (its terminal-state poll
  breaks with 1).
- B. Shutdown past the 1s budget: bare = 1 (the engine did not stop
  within budget; the main.rs shutdown select arm); idle = 0
  (`shutdown_session_and_server` only logs an error past the budget and
  does not propagate failure).
- C. Startup input-error granularity: bare torrent read/parse failure =
  1; the corresponding http faces (option domain / lock IO / document
  failure) = 2 — different granularity, intentionally not unified.
- D. Magnet positional one-shot (no RPC): lock faces shared with http
  (held = 1 / lock IO = 2 via `http::acquire_db_lock`), signal exit = 0,
  task Error = 1; download+rpc maps like bare (intake/injection/bind
  failure = 1, graceful shutdown = 0).
- E. Subcommands: `import`/`create-torrent` only use 0/1 (0 = success,
  1 = failure), no in-mode 2 face.

### Shutdown contracts

- `SHUTDOWN_BUDGET` (1s): total graceful-exit budget after
  Ctrl-C/SIGTERM.
- `NAT_SHUTDOWN_BUDGET` (250ms): bounded budget for the bare-exit NAT
  teardown (unmap + pump stop), matching the session actor's
  NAT_SHUTDOWN_BUDGET. The delete request is advisory (RFC 6886 §3.1 —
  the 3600s lifetime expiry reclaims the mapping gateway-side as a
  backstop); a slow or malicious IGD can stall DeletePortMapping up to
  HTTP-timeout scale (~10s per protocol). On expiry the wait is
  abandoned; the exit code is unchanged.
- Budget accounting: t0 starts at shutdown acceptance; the actor/server
  join budgets are the remaining share (not the full 1s each, which
  could exceed the total when stacked). Success = both joins finish
  within the remaining budget; a timeout is only logged (no elapsed
  re-check — sub-millisecond jitter would cause false negatives).
- The persist writer gets an extra 2s grace on drain; a timeout only
  warns (row writes are transactional; the final flush happens within
  the actor budget).
