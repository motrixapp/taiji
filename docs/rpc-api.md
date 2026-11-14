# taiji RPC API

English | [简体中文](./rpc-api.zh-CN.md)

JSON-RPC 2.0 over HTTP `POST /jsonrpc` (single/batch/system.multicall) and
WebSocket (`GET /jsonrpc` upgrade). Authentication: `token:` as the first
parameter or HTTP Basic (`--rpc-secret` / `--rpc-user` + `--rpc-passwd`); with
no credentials set, binds to 127.0.0.1 only and write operations are always
refused. Public internet exposure goes through a VPN or a reverse proxy
terminating TLS (the engine has no built-in TLS).

## API Naming Surface (one surface at any given moment)

Canonical naming of methods and events = `taiji.*` (default). With
`--rpc-aria2-compat` (default false, a session-level startup option) enabled,
methods additionally accept `aria2.*` aliases, the six events are pushed as
`aria2.onXxx`, and `system.listMethods`/`system.listNotifications` present the
aria2 surface — dedicated to drop-in use by external aria2 frontends and to
differential cross-validation scenarios. **Only one API surface exists at any
given moment; dual emission is forbidden**; the `system.*` introspection family
and the `taiji.*` extension methods/events share the same names across both
states.

## aria2-Compatible Methods (canonical names; same-named `aria2.*` aliases accepted under `--rpc-aria2-compat`)

The full differential against the fork (the aria2 fork) is governed by a
whitelist regime: **zero differences outside the whitelist**; all known
differences and their anchors are in [rpc-api-diff.md](rpc-api-diff.md) (a
controlled living document; new entries go through PR + user approval).

| Method | Description |
|---|---|
| `taiji.addUri` | Add a download (HTTP(S)/FTP(S)/magnet/torrent URL; a multi-URI array = multi-source mirroring of the same file) |
| `taiji.addTorrent` | Add a .torrent (base64). An externally complete payload (files in the directory match the torrent's per-file lengths) = the add schedules an initial full verification (`status=active`, `completedLength` projects verification progress); once verification completes it switches to seeding based on the measured bitmap (`seed_after_complete` semantics); a partial/missing payload downloads from scratch as usual |
| `taiji.remove` / `forceRemove` | Remove a task |
| `taiji.pause` / `unpause` / `pauseAll` / `unpauseAll` / `forcePause` / `forcePauseAll` | Pause/resume (`forcePauseAll` = force-pause all tasks, always answers `OK`; the force finalization difference follows the single-task pause/forcePause equivalence declaration, reference anchor `RpcMethodImpl.cc`) |
| `taiji.forceRecheck` | Schedules an on-disk recheck (**a taiji capability extension — upstream aria2/fork registration surfaces have no such method**; dual naming: canonical `taiji.forceRecheck` + compat `aria2.forceRecheck`, accepted under the same name with the same meaning). Torrent tasks only: active = graceful shutdown → full verification → requeue and reactivate; waiting/paused = dequeued for verification, then requeued at the head. During verification `status` stays `active` and `completedLength` projects the bytes verified so far (cross-validated against aria2's verification-period TellStatus semantics); on completion it restores from the measured bitmap (corrupt pieces are zeroed and re-downloaded; a complete payload switches to seeding). Returns the gid; duplicate verification / non-torrent / finished task = explicit error |
| `taiji.tellStatus` | Task status (includes the v2 synthetic bitmap and the `http` sub-dict) |
| `taiji.getUris` / `getFiles` / `getPeers` / `getServers` | Task details |
| `taiji.tellActive` / `tellWaiting` / `tellStopped` | Task lists (pagination/keys) |
| `taiji.changeUri` | file-entry URI semantics (upstream same-shape arm order: gid miss `Cannot remove URIs from GID#%s`, fileIndex domain validation verbatim `fileIndex is out of range`, receipt `[deleted, added]` counts; this side has no file-entry URI ledger → always a `[0,0]` no-op — for the real editing gap see rpc-api-diff.md §1) |
| `taiji.changePosition` | Waiting-queue reordering (`POS_SET`/`POS_CUR`/`POS_END` three modes, out-of-range clamped; only the waiting queue can be moved — active/error items report `GID#X not found in the waiting queue.`; the receipt is the integer target position after the move; after a reorder and a requeue-at-head (pause/restart finalization), `queue_pos` is renumbered stably across the whole segment, and after a restart the preserved `tellWaiting` order = the shutdown-time runtime order) |
| `taiji.changeOption` / `changeGlobalOption` | Hot option updates |
| `taiji.getOption` | Per-task option read (located across the active/waiting/finished three domains; the echo is a string value table over the accepted-key subset — a live task's rate limits are the live-bucket effective values, `select-file` returns a normalized 1-based string; for key-set and value-form differences see rpc-api-diff.md §3) |
| `taiji.getGlobalOption` / `getGlobalStat` | Global surface |
| `taiji.purgeDownloadResult` / `removeDownloadResult` | Record cleanup |
| `taiji.forceShutdown` | Engine exit |
| `taiji.getVersion` | Version (`taiji/<semver>`) |
| `system.listMethods` / `system.listNotifications` / `system.multicall` | Introspection and batch |

## HTTP/FTP Multi-Source Download Surface

- **Multi-URI array**: the URI parameter of `taiji.addUri` is an array; multiple
  entries = mirrors of the same file (aria2 semantics): all http(s)/ftp(s)
  entries join the task's source set for multi-source download (per-source
  probing and merging; on length mismatch `taiji.http.mirror_mismatch`, and
  when `--checksum` is given, the source verifiable against the checksum wins).
  The source manifest is persisted with the task, and restart recovery keeps
  the same source set.
- **The `http` sub-dict of `tellStatus`**: `finalUrl` / `connections` /
  `extentsActive` / `blocksDone` / `blocksTotal` / `encoding` (key absent =
  identity/unprobed) / `renamePending` / `sources[]`. Each item of `sources` =
  `{url, rate, state}` (rate = stringified bytes/second, measured attribution;
  state ∈ `waiting` | `active` | `demoted` | `removed` | `failed` — `failed` =
  probe failed or culled from the merge table; it does not take part in piece
  assignment within this task). This sub-dict as a whole is a taiji extension
  surface (aria2 has no such key).
- **FTP/FTPS**: `ftp://` sources are always accepted. FTPS is expressed via
  `--ftp-ssl=none|auth (default)|implicit` (a taiji extension — aria2 has no
  FTPS capability; the `ftps://` scheme is not accepted as URI input).
  Task-level options: `--ftp-user` / `--ftp-passwd` (default
  anonymous/anonymous@; kept in separate slots from `--http-user`/
  `--http-passwd`, with no cross-leakage), `--ftp-pasv` (only `true` accepted;
  `false` = active mode is not implemented and is explicitly refused),
  `--ftp-reuse-connection` (default true). The FTP difference declarations
  (the `ftp-type`/`ftp-proxy` family not accepted, SIZE does not support
  source culling, charset UTF-8 preferred with Latin-1 fallback, etc.) take
  the taiji-core `session::options` differential declaration block as the
  single source.
- **`--ca-certificate` (task-level CA surface)**: path to a PEM CA file; at
  task level it **replaces** the platform trust store (aria2 replace semantics,
  not append), effective on both HTTPS and FTPS; accepted under the same key in
  `addUri` options and `changeOption`. Bad path/bad PEM = `taiji.option.invalid`
  task refusal; when `--check-certificate=false` is also present, the latter
  wins (the CA file is ignored, same as aria2). For the difference declaration
  see the ca-certificate entry in rpc-api-diff.md.
- **Cookie ingestion gates (`--load-cookies` + two direct-delivery methods)**:
  - `--load-cookies <file>` (Netscape cookie file, same name and meaning as
    aria2): three entry points — addUri options / `changeGlobalOption` (the
    global-surface default source; explicit per-task values take precedence) /
    the CLI `taiji http` flag. A missing/unreadable/over-1MiB file =
    `taiji.option.invalid` task refusal (fail-closed); bad lines are skipped
    per line (same rule as curl). Effective surface = task CookieStore prefill
    + runtime Set-Cookie absorption (RFC 6265).
  - `taiji.addUriWithCookies` / `taiji.setTaskCookies`: see the taiji extension
    methods table (cross-validated against the fork's parseRpcCookies form).
  - **Combination semantics**: for tasks with a cookie injection gate present
    (file source or direct delivery), manual `Cookie:` lines in `--header` are
    stripped and not forwarded — the jar is the sole source of task cookies
    (isomorphic to the fork's "Structured cookies are authoritative"; with both
    paths present, a server's "take the first header" implementation would
    silently drop the jar); tasks without an injection gate forward manual
    Cookie headers as usual.

## BT Task File-Selection Surface (`select-file`)

- **Accepted surface**: the `select-file` key in the options dict of
  `addTorrent` / `addUri` (magnet and http(s) `.torrent` URL) + re-selection
  via `changeOption` (reserved/paused torrent/magnet tasks only; active tasks
  and non-BT tasks = explicit refusal — for the tightening difference see
  rpc-api-diff.md §3; reference `OptionHandlerFactory.cc`: 1-based value range
  [1, 1048576], add-surface initial options + changeOption for reserved).
- **Value syntax**: comma-separated 1-based file indices / closed ranges, e.g.
  `"1-3,5"`. Illegal values (empty segment/syntax error/value outside the
  [1, 1048576] range) = the call is **explicitly refused**
  (`taiji.option.invalid`; for the tightening difference see rpc-api-diff.md
  §3).
- **Out of range (two-phase)**: metadata already landed (.torrent parsed) =
  explicit refusal at the add/changeOption surface; metadata not landed
  (magnet not yet upgraded / `.torrent` URL not yet fetched — no file count to
  decide against) = the call is accepted, and the out-of-range value ends as
  an explicit task error at the upgrade-activation surface (same direction as
  the reference's delayed application, RpcMethodImpl.cc — the difference is
  only in error explicitness). Anchor:
  `session::options::resolve_select_file_for_meta` (single entry point).
- **Effective surface**: only selected files download (BEP53 mask projection,
  both the v1 and v2-only layouts); `selected` in `getFiles`/`tellStatus.files`
  echoes the selection surface (`file_selected` is the single source; pad
  entries are always false); the `getOption` echo of `select-file` is a
  normalized 1-based comma string. The selection persists with the task
  (`config_json.selected_files`, the same channel as magnet `so=`), and restart
  recovery restores the same selection; for waiting/paused tasks, a
  re-selection is replayed via `SetFileSelection` on re-activation.
- **magnet `so=` merge rule** (a superset-capability design decision on this
  side; aria2 has no `so=` surface): on the same task, `so=` and `select-file`
  together = explicit conflict refusal (a single selection-surface source —
  including the case where both expand identically; the error message names
  both source keys); only one given = that surface takes effect; changeOption
  `select-file` replaces an existing selection.

## Magnet selection without replacing the task

Add a magnet with `motrix-await-selection=true`. The engine fetches and verifies
metadata, then parks the upgraded torrent under the same GID before payload IO.
This selection barrier survives restart; `unpauseAll` skips it and `unpause`
rejects it until confirmation. Ordinary `pause-metadata` keeps its existing
pause semantics when this additional option is absent.

- `taiji.getTorrentMetadata(gid)` returns `{data, awaitingSelection}`. `data`
  is the original verified `.torrent` envelope encoded as base64. Clients do not
  need access to the engine's metadata directory.
- `taiji.confirmTorrentSelection(gid, options)` accepts only `dir`,
  `select-file`, and `motrix-output-paths`. `dir` must be absolute;
  `select-file` is required and uses the non-padding, 1-based convention above.
  Output mappings are JSON objects from zero-based **complete metadata file
  positions, including padding** to relative paths. They change disk paths,
  never the info hash or original metadata.
- The engine validates the whole request and persists its selection, paths,
  and run intent before starting payload IO. Invalid requests or failed writes
  leave the task parked. Repeating an accepted request with the same values
  returns the same GID without creating another task; different values are
  rejected after confirmation.

For a partial selection, task `totalLength` and `completedLength` measure the selected payload files. File lists and piece bitmaps retain whole-torrent coordinates. Boundary-piece transfer overhead is not added to the progress denominator.

Hosts should persist the user's confirmation before calling this operation so
an interrupted request can be replayed after restart. Unselected files are not
preallocated. A piece shared by selected and unselected files may still require
bytes outside the selected file for hash verification.

## Network context notification

`taiji.notifyNetworkChange()` takes no arguments and returns `"OK"`. It is a
native-only, authenticated write operation. Hosts call it after observing a
network/DNS configuration change or resume. It invalidates positive/negative
DNS cache entries, retires prior-generation results and causes tracker actors
to refresh connection state. Existing DNS callers retry within their original
deadlines; running system calls retain their real resource permits until they
finish. The operation does not change OS DNS settings or provide DNS servers.
`/metrics` exposes `taiji_dns_network_changes_total` and separate system queue
and lookup duration histograms to distinguish local contention from resolver
latency.

## CLI Shortcut Surface (`taiji http`)

`taiji http <URL…> [-d dir] [-o name] [--checksum md5|sha-1|sha-224|sha-256|sha-384|sha-512=<hex>]`
= the same-surface shortcut entry that does not start the RPC service: it
bootstraps SessionActor directly (addUri → tellStatus polling semantics), and
the session database and task rows are fully isomorphic with the RPC surface —
HTTP tasks created via the CLI likewise appear in `tellActive`/`tellStatus`
(the `http` sub-dict) and can be managed through a resident daemon's RPC method
surface. See the `taiji http` section of user-manual (resume / concurrency
guard / attach comparison semantics).

## taiji Extension Methods

| Method | Description |
|---|---|
| `taiji.createTorrent` | Torrent creation (files/outputDir/pieceLength/format/private/announce) |
| `taiji.addTracker` / `taiji.removeTracker` | BT task tracker dynamic editing (Plan B, see the next section) |
| `taiji.moveStorage` | Storage migration: `moveStorage(gid, dir)` moves a task's on-disk payload to `dir` (same-volume atomic rename; cross-volume copy+fsync+unlink via a temp sibling). Families: torrent payload (the multi-file `name` subtree / single file), HTTP `.part`, magnet & .torrent-URL tasks (dir-only swap); media tasks keep the not_supported capability face. Accepted states: waiting/paused (moves immediately), active (auto-quiesce via the changeOption restart path, then moves and reactivates at the front), seeding (seed-pause quiesce, re-enters seeding after the commit); checking/synthesis/results reject. Async acceptance: replies `"OK"` once the move journal (config_json, same row upsert, strictly before any on-disk action) is durable and the quiesce started; completion is observable via `tellStatus` `dir`. Crash safety: the source payload is never destroyed before the commit — a kill at any point is redone idempotently at the next startup (journal close-out); a failed runtime move keeps the journal (retried on restart) and the task continues at the old dir. Empty/blank `dir` = `Illegal argument.`; target nested inside the current dir and in-flight duplicates are refused |
| `taiji.renameFile` | File renaming — registered but not yet implemented (answers not_supported after GID resolution) |
| `taiji.banAddr` / `unbanAddr` / `listBans` | Peer ban surface |
| `taiji.setSchedulerPolicy` / `getSchedulerPolicy` | Scheduling policy |
| `taiji.setStreamingPlayhead` | Streaming piece-selection playhead |
| `taiji.setFilePriority` | Partial update of multi-level file priorities: `setFilePriority(gid, pairs)` — pairs = `[{index, priority}]` (index 1-based client file order; priority ∈ -1..=7: -1 skip / 0 normal / 1..7 high); unlisted files untouched. Torrent tasks only; active tasks take effect live in the engine, waiting/paused tasks receive it on activation; -1 ⇔ move out of the selection set / 0..7 ⇔ join it (mutually consistent with the single `select-file` selection surface); persisted in config_json (kept across restarts). Echo = `tellStatus`/`getFiles` files[] `priority` key. Write surface (refused by the write gate when `--rpc-secret` is unset). aria2 has no such method (an own extension aligned with libtorrent's `file_priority` capability) |
| `taiji.setDiskTier` / `getDiskTier` | Disk allocation tier |
| `taiji.getCapabilities` | Capability discovery (extension method/event inventory) |
| `taiji.addUriWithCookies` | Add a download with structured cookies (uris, cookies[], options?): cookies item by item `{name, value, domain, path?, hostOnly?, secure?, httpOnly?, expiresAt?}` (fork parseRpcCookies verbatim validation — ≤300 entries / unknown fields refused / expiry = non-negative Unix milliseconds); all URIs must be http(s); cookies go into the task's CookieStore (the same storage surface as `--load-cookies`), and manual `Cookie:` headers are stripped (structured cookies are authoritative); `.torrent` URL not accepted (no cookie consumption point on the metadata surface). Accepted after a reversal of the early stance; Motrix baseline |
| `taiji.setTaskCookies` | Runtime override of the cookie jar of waiting/paused HTTP tasks (gid, cookies[]): whole-set replacement + row persistence (kept across restarts); active/non-HTTP tasks = `Task cookies can only be set on waiting or paused cookie tasks.`. Accepted after a reversal of the early stance; Motrix baseline |

## BT Task Tracker Dynamic Editing (`taiji.addTracker` / `taiji.removeTracker`)

- **`taiji.addTracker(gid, urls, options?)`**: `urls` is a single string or an
  array of strings (≥1); optional `options.position` (integer/numeric string) =
  the insertion tier position (0-based, out-of-range clamped to the table end),
  default = append at the table end. Each URL forms an **independent tier**
  (BEP12 one URL per tier, aligned with the `--bt-tracker` global-import
  semantics); URLs already in the table are skipped (idempotent, not counted in
  the receipt). Receipt = `{"removed":0,"added":N}` (the actual number added).
- **`taiji.removeTracker(gid, urls)`**: deletes by exact URL match (including
  announce-list tier cleanup, with tier numbering tightened); once everything
  is deleted, empty tiers = the pure DHT surface (a legal form). Receipt =
  `{"removed":N,"added":0}`.
- **Effective surface**: active tasks take effect immediately via an engine
  tracker-table rebuild (announce surface; visible in both
  `getServers`/`tellStatus.announceList` right away); waiting/paused tasks get
  their payload edited and persisted (`config_json`, kept across restarts,
  effective on re-activation).
- **Refusal surface** (explicit error, zero mutation): magnet / `.torrent` URL
  metadata-phase tasks (the tracker surface is not editable before upgrade),
  HTTP tasks (no tracker surface), and finished (result-domain) tasks (the
  payload was stripped at finalization, so edits would never take effect).
  Both methods are write-surface: refused by the write gate when
  `--rpc-secret` is unset.
- Relation to the `--bt-tracker` global import: the global set is merged as a
  union at task activation (the edited per-task table is preserved up front);
  a further global import within the session still appends the increment —
  deduplicated against the per-task table — to in-flight tasks.

## Events (WebSocket Notifications)

Payload uniformly `{"jsonrpc":"2.0","method":"…","params":[{"gid":"<hex16>"}]}`.

- Six events (canonical = `taiji.onXxx`; `aria2.onXxx` under
  `--rpc-aria2-compat`): `onDownloadStart` / `onDownloadPause` /
  `onDownloadStop` / `onDownloadComplete` / `onDownloadError` /
  `onBtDownloadComplete` (a BT task finishing its download and moving to
  seeding emits `onBtDownloadComplete`; task termination emits
  `onDownloadComplete`)
- taiji extensions (always `taiji.*`, never switched by compat):
  `taiji.recoveryStarted` / `taiji.recoveryCompleted` (the hash recovery
  process; the payload includes the files index)

## Main Options

`--listen-port`, `--enable-dht`, `--enable-dht-6`, `--bt-require-crypto`,
`--bt-min-crypto-level plain|arc4`,
`--peer-connection-type tcp|utp|prefer-tcp|prefer-utp`, `--peer-id-prefix`,
`--bt-enable-upnp`, `--bt-enable-nat-pmp`, `--bt-lsd`, `--bt-stop-timeout`,
`--seed-ratio`, `--seed-time`, `--bt-tracker`, `--dht-entry-point[-6]`,
`--sqlite3-db-path`, `--rpc-secret`, `--rpc-listen-all`, `--rpc-listen-port`,
`--rpc-user`, `--rpc-passwd`, `--rpc-max-request-size`, `--rpc-allow-origin-all`,
`--rpc-aria2-compat` (the API alias-surface switch, see the section above),
`--max-overall-download-limit`, `--max-overall-upload-limit`,
`--max-download-limit`, `--max-upload-limit`, `--bt-hash-check-seed`,
`--check-integrity`, `--enable-falloc`,
`--max-concurrent-downloads`,
`--max-concurrent-seeds`, `--max-concurrent-checks`,
`--media-synthesis-concurrency` (the four-pool budget trio — taiji
extensions, see the differential declaration §3).

## HTTP publication

See [HTTP publication](http-publication.md) for `taiji.getHttpOutput`,
`taiji.finalizeHttp`, `taiji.onHttpOutputReady`, and the fixed host contract.
