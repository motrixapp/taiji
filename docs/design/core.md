# Core design notes (upstream anchor mapping)

Per-module upstream anchors and reference essays for taiji-core.
Code headers in the source files keep only a mechanism summary and point
here.

## session/events.rs

Sources: aria2 `RequestGroupMan.cc`, `WebSocketSessionMan.cc`,
`DefaultPieceStorage.cc`; SPEC §7.4/§8.1.

### Topology

SessionActor publishes the six events into a bounded
`broadcast::Sender<SessionEvent>` (capacity 256); subscribers (the
taiji-rpc WS session face, via
`super::SessionHandle::subscribe_events`) serialize and push
`{"jsonrpc":"2.0","method":"<face>.onXxx","params":[{"gid":"<hex16>"}]}`
(structure cross-validated against WebSocketSessionMan.cc). The method
name face is the canonical `taiji.onXxx`, or `aria2.onXxx`
under `--rpc-aria2-compat` — one face at a time; the presentation-face
selection lives in taiji-rpc.

### Backpressure

A broadcast send never blocks the publisher: with capacity 256 a slow
subscriber that falls behind simply lags (old values are overwritten),
and the engine/actor event paths never wait. This is a deliberate
divergence from the reference: aria2 pushes unbounded and directly
(WebSocketSessionMan.cc calls addTextMessage per session, with no
backlog concept); this repo is deliberately bounded. On the subscriber
side `RecvError::Lagged` = fell behind past the limit; the rpc face's
policy is to count, warn, then disconnect that subscriber (backpressure
is not spilled onto the engine).

### Publish points (cross-validation against RequestGroupMan
notifyDownloadEvent call sites; read-only reference)

- Start = group activation (task spawn / reactivation,
  RequestGroupMan.cc).
- Pause = pause teardown back to the queue front, non-restart branch
  only (the restart branch does not publish).
- Complete/Error/Stop = the three executeStopHook branches (FINISHED ->
  Complete; error, non IN_PROGRESS/REMOVED -> Error; everything else ->
  Stop).
- BtComplete = the moment a BT download finishes and turns to seeding
  (DefaultPieceStorage.cc); together with Complete it forms the BT
  completion double-fire — same rule as aria2, event names per
  WebSocketSessionMan.cc.

No subscribers = the send is dropped (the broadcast idles; matches the
aria2 notification semantics — with no WS session nobody consumes
notifications). HTTP-only scenarios carry no event-loss semantic
burden.

### Extension event bus (taiji.recoveryStarted/Completed)

The `taiji.*` extension events run in parallel on the same topology as
the six events: the payload carries the file set (the frozen SessionEvent
struct cannot be extended — the six-event tests stay untouched), on a
separate `broadcast::Sender<RecoveryEvent>` with the same capacity
(`EVENT_BUS_CAPACITY`); backpressure, lag-disconnect, and no-subscriber
idle semantics match item by item. Publish points = the engine state
machine (activation chain + upgrade propagation,
`engine::run::recovery_admit`) -> the HookRunner recovery notification
slot (isomorphic to the relay slot) -> the session face dedupes, stamps,
and publishes into the bus -> the rpc WS face renders
`{"jsonrpc":"2.0","method":"taiji.recoveryX",...}` frames (extension
envelope, params[0] = `{gid, files[, status]}`).

## session/persist/mod.rs — saveSession shape

The primary store is `taiji.sqlite3`; a single-writer transaction makes
each save atomic (WAL semantics:
`store::persist::PersistJob::Checkpoint`). The text export is the aria2
input-file compatible format, triggered by the `--save-session` path;
with no path set, only the store is written.

Line format anchors: aria2 `SessionSerializer.cc` — the file is written
in full to a `__temp` sibling and atomically swapped in via `renameTo`;
each entry is a URI line plus ` gid=` / ` pause=` / option lines.
Torrent tasks held by metainfo (added as raw `addTorrent` bytes) have
no URI to write and are skipped by the text export — the same rule as
SessionSerializer.cc's "Don't save download if there are no URIs".
Session rebuild for those tasks is carried entirely by the sqlite rows,
so nothing is lost.

## session/actor/lifecycle.rs — stop-family hooks and shutdown

Hook/notification split follows aria2 `RequestGroupMan.cc`
`executeStopHook`: FINISHED -> complete, error (non IN_PROGRESS/REMOVED)
-> error, REMOVED/IN_PROGRESS -> stop. A hook failure does not affect
the task state (`util.cc` semantics); the hook fires before the event
notification. `fire_stop_family` is the hook half, `stop_family_kind`
the EventKind half — same source mapping.

Shutdown follows the aria2 save-session-on-exit semantics: full row
flush, `--save-session` text export, then a checkpoint barrier. NAT
teardown delete requests are advisory (RFC 6886 §3.1); gateway-side
reclaim at mapping lifetime expiry (3600s) is the backstop, so teardown
awaits only within a bounded budget (`NAT_SHUTDOWN_BUDGET`).

## session/persist/import.rs — migration import mapping

Sources: fork sqlite schema (`task`, `task_progress`,
`task.serialized`), aria2 `message.h` ("control file(*.aria2)" naming;
`EX_INFOHASH_MISMATCH_IN_SEGFILE`), `RpcMethodImpl.cc` (readd metadata
candidate priority), `SessionSerializer.cc` (input-file line format),
`DefaultBtProgressInfoFile.cc` (`uploadLengthAtStartup + session`
accounting).

Mapping table (fork column -> taiji.sqlite3 column):

| fork side | taiji.sqlite3 |
|---|---|
| `task` (is_torrent=1, info_hash set) | `torrent` row |
| `task_progress.bitfield` + `piece_length` | `torrent_progress.v1_bitfield` 1:1 |
| `task_progress.upload_length` | `upload_at_startup` + `uploaded_total` |
| `task.serialized` (input-file text) | `config_json` |
| metadata (.torrent) announce | `tracker` row tier 0 |

Notes:
- the v1 bitmap maps 1:1: aria2 can never have in-flight v2 pieces,
  so nothing v2 is lost;
- `upload_length` feeds both `upload_at_startup` and `uploaded_total`
  (the ratio baseline chain; engine recovery reads `uploaded_total`
  as the next session's baseline);
- `task.serialized` (input-file text) maps to the `dir` / pause /
  seed / limit subset of `config_json`;
- the metadata announce becomes a `tracker` row at tier 0, rebuilt
  from metadata.

Failure semantics: a single-task failure never blocks the batch. A
`.aria2` control file whose infohash does not match the candidate
`.torrent` (`EX_INFOHASH_MISMATCH_IN_SEGFILE`, `message.h`) degrades
the task to `checking`; for fork sources the mismatch is a hard failure
instead — `task_progress.info_hash` is the authoritative identity, so
progress must not be misattributed, while for ctrl sources the paired
metadata is the identity anchor and the bitmap plus upload count are
dropped (history of a different torrent). Bitmap validation failure
(piece_length / total_length / bitfield length inconsistent with the
metadata) also degrades to `checking`, dropping the bitmap but keeping
the upload count (trusted same-torrent history).

## session/persist/import_bitmap.rs

Sources: the migration importer's bitmap-mapping rules; aria2
`DefaultBtProgressInfoFile.cc`; taiji-http `grid.rs` (frozen seam — this
module only consumes [`taiji_http::grid`] semantics without changing its
encoding or verdicts).

### Conversion rules ("bitmap mapping rules: no silent over-crediting")

The fork side's progress facts = the piece bitmap (MSB-first,
`task_progress.bitfield` / `.aria2` bitmap, fixed length =
`expected_bitfield_len(total, piece)`) + granularity `piece_length` +
`total_length`; the taiji side = the block-grid bitmap (LSB-first,
bit i = block i, block granularity a power of two in 256KiB..16MiB,
[`taiji_http::grid::BlockGrid`]).

1. **Block granularity** = the largest power-of-two factor of
   `piece_length` clamped into the config domain
   (`block_size_from_piece_length`) — keeping piece and block in an
   integer multiple relationship maximizes the trustworthy mapping
   surface; unsolvable (odd piece, largest pow2 factor = 1) and
   `piece < 256KiB` both land on the domain floor of 256KiB.
2. **Full-coverage rule**: a block's byte range is credited only if
   **all** pieces it intersects are complete — partially covered blocks
   are dropped and re-downloaded (waste bound = 1 block per piece
   boundary); in-flight pieces are not an input to this mapping (the
   control face / progress-row primary bitmap only contains verified
   pieces; in-flight segments are discarded on read). When piece
   granularity > block granularity and not a pow2 multiple, a piece
   boundary can fall inside a block: only blocks whose pieces are all
   complete on both sides are trustworthy — **under-credit rather than
   over-credit, never**.
3. **Trust chain**: the mapping's product = the `http_task` row's
   `block_size` / `block_bitmap` / `block_count` candidate payload; the
   activation-time recovery face still validates in full as usual (the
   validator verdict table + the "exists + size" second line of
   defense); any mismatch still starts from zero — the mapping creates
   no shortcut around recovery trust.

### Golden branches

| Branch | Shape | Assertion points |
|---|---|---|
| pow2 aligned | piece = block (e.g. 1MiB) | 1:1 mapping, byte-wise bitmap golden |
| unaligned | piece = 15MiB (not pow2) | block = largest pow2 factor; all-or-nothing |
| piece < 256KiB | piece = 100KiB, clamp to 256KiB | block spans pieces; partial blocks dropped |
| total not block-aligned | total = 10MiB @ 4MiB block | last block credited truncated to total |

Each branch is also cross-validated against the
[`taiji_http::grid::BlockGrid`] consumer (bitmap bytes + credited byte
totals).

## session/recheck.rs — suspend / re-entry boundary (missing layers)

A v2 file missing its piece layer (`MetaFile::layer_missing`) has no
expected root available (the v2 face build puts an all-zero root in
place, which can never pass verification) — if per-piece verification
judged as usual, disk-intact pieces would be misjudged as failed and
cleared, forcing a re-download even after the recovery layer arrives.

Boundary: pieces of such files are **suspended** (not failed, not
cleared; the bitmap keeps the previous session's values), recorded in
[`RecheckOutcome::suspended_files`]; once the recovery layer arrives
(startup read-back via `recheck_on_disk_recovering`, or a run-time
re-entry after admission), the suspended files are re-verified by
dispatch — passed pieces are kept, failed pieces are cleared as usual.

Cross-check with libtorrent: a missing-layer torrent loads normally and
waits for the swarm to fill the layer in (`torrent.cpp`); resume-data
re-injection makes verified layers directly usable
(`load_merkle_trees`) — the same principle of "a missing layer never
destroys on-disk facts; full configuration resumes once the layer
arrives".

## session/http/mod.rs

Sources: the v3 `http_task` table; SPEC §4.3/§4.5/§6/§14.1.

### Write path (bitmap snapshot pipeline, snapshot.rs)

Block-completion credit is decided at a single point on the scheduling
side before entering this module. The bitmap snapshot is persisted with
a **2s debounce** ("once per task per 2s, bounded cost"), and **every
snapshot commit is preceded by one fsync of that task's file** (core
performs the fsync before sending the snapshot-commit message) — the
timing invariant is **a power-loss bitmap must never be ahead of the
data**: for every completed block in the snapshot, its byte range is
already on disk once the fsync completes.

### Read path (startup recovery, recover.rs)

`PersistWriter::load_http_tasks_at_startup` (the active set) ->
per-task recovery validation: **file exists + block cumulative size
consistent** (the "second line of defense"; under prealloc the size
check always passes — the first line of defense is the pre-snapshot
fsync ordering). Blocks that fail fall back to incomplete, and
`total_done` is recomputed from the validated bitmap (the bitmap is the
only progress truth).

### Resume verdict (resume.rs)

The `ResumeValidator` verdict table ("range-stream friendly"): a strong
ETag or a matching Last-Modified with an equal length -> resume; none
of those but path + length match -> weak resume; mismatch -> from zero.
The types map field-by-field onto the `ResumeValidator` fields in the
taiji-http frozen seam (this crate does not depend on taiji-http — a
crate-topology constraint; the wiring is a field-by-field direct
translation).

### Block bitmap encoding (module-wide)

Bit i = block i complete; LSB-first within a byte (bitfield
convention); tail bits beyond `block_count` are invalid (ignored during
validation). The block geometry domain = powers of two in
256KiB..16MiB (the `--http-block-size` config domain, immutable
per task).

## session/actor/tasks.rs

Task face: activation (the full spawn chain for metainfo / magnet / URL
fetch), teardown dispatch (pause requeue-to-front / restart /
DownloadResult), the add/remove/pause/unpause lifecycle, metadata
upgrade (in-place upgrade + paused residency), and identity/dest dedup.
Scope is the control flow from enqueue through activation to terminal
dispatch; command intake (commands.rs), persistence payloads
(persist.rs), and shutdown propagation (lifecycle.rs) live elsewhere.

### Upstream anchors

- Start/stop hook trigger points mirror aria2 `RequestGroupMan.cc`:
  `Start` fires at group activation (restart/unpause re-activations hit
  the same face), hook first and event notice after (reference order).
- Stop-family dispatch mirrors `executeStopHook` (`RequestGroupMan.cc`)
  plus the `notifyDownloadEvent` call sites: pause requeue →
  on-download-pause / `Pause`; restart requeue → no pause hook and no
  Pause event; FINISHED → on-download-complete / `Complete`; error →
  on-download-error / `Error`; REMOVED / IN_PROGRESS (remove and
  shutdown interruption) → on-download-stop / `Stop`.
- Hook argv payload mirrors `util.cc` `executeHookByOptName`:
  firstFilename = first requested file path, numFiles = requested file
  count; requested = non-padding real files (BEP-47 pad regions are
  placeholders, not file entries). The magnet/HTTP metadata phases use
  the in-memory download projection of `util.cc` (`numFiles=0`,
  `firstFilename=""`).
- The engine-side BtComplete trigger is the notification half of aria2
  `DefaultPieceStorage.cc`, relayed to the session bus through the
  shared HookRunner.
- LSD gate and lifecycle mirror `BtSetup.cc`: private torrents disabled
  (BEP-27), the process-level receiver singleton
  (`if (!btReg->getLpdMessageReceiver())`), and degrading to running
  without LSD on init failure ("LpdMessageReceiver not initialized").
- Halt semantics mirror `ProcessStoppedRequestGroup`: a user-remove
  teardown always records Removed over natural terminal states
  (errorCode=31), and pause/restart teardown push_front rewrites the
  reserved FIFO order.
- remove persistence decision: aria2 `SessionSerializer.cc` does not
  persist removed tasks either (FINISHED/REMOVED need --force-save), so
  remove deletes the rows (FK cascade) instead of writing a `removed`
  state.
- Tracker tier merge mirrors `bittorrent_helper.cc` `adjustAnnounceUri`
  rewriting announce-list tiers in place.
- Credential handling mirrors `DigestAuth.cc` (single http-user/
  http-passwd slot serving Basic pre-setting and Digest challenges).
- Structured cookies mirror the fork's `AddUriWithCookiesRpcMethod`
  (`RpcMethodImpl.cc`) and `RpcCookie.cc`: "Structured cookies are
  authoritative. Do not retain ambient or raw Cookie headers"; "Expired
  records are valid input but must not enter the active store".
- Recovery-layer restore mirrors libtorrent's resume-data reingest in
  `torrent.cpp` and `load_merkle_trees`: re-validate persisted layers
  (count + root convergence) before merging, never serve a sick
  full-config.
- The .torrent fetch cap of 30MiB aligns with libtorrent
  `settings_pack.cpp`'s default (a complete metainfo can legitimately
  exceed the 4MiB announce tier).
- Per-task independent listen ports with per-range bind fallback mirror
  `BtSetup.cc`; aria2's global shared single listener is superseded by
  the session-shared listener wiring.

### Hard invariants

- Main-loop zero disk IO: metainfo parsing and EngineConfig assembly
  run in `spawn_blocking` (pure CPU); persistence is serialized through
  the single PersistWriter.
- Single peer_id generation point per session prefix option; the same
  value feeds tracker announce and peer handshake.
- Single selection-source rule: magnet `so=` and the `select-file`
  option are mutually exclusive; range validation defers to the upgrade
  chain when metadata is unknown.
- Same-dest (dir+name) BT tasks are exclusive: two infohashes on one
  path would corrupt data via concurrent VerifiedWriters; explicit
  `taiji.bt.path_conflict` rejection, including for paused/waiting
  tasks.
- Queued dual budget (entry count + resident Metainfo bytes) applies at
  every intake arm; magnet intake estimates 0 bytes and the upgrade
  arms re-check with real values.
- On a MagnetUpgraded notice the session backfills total_len from the
  engine query seam; terminal entries never report complete 0/0.
- Status snapshot invalidation: BtComplete is not task teardown (the
  task stays resident seeding), so the completion event enqueues its
  own cache invalidation.

## session/actor/mod.rs

SessionActor: queue scheduling, the task lifecycle command surface, the
DownloadResult table, the option faces, and the six-event notification
bus (SPEC §7.4, broadcast(256) → WS push). Hard invariants: the actor
exclusively owns all state (no locks); command mpsc(64) and internal
event mpsc(64) are bounded; locks never span await; per-task
CancellationToken children form the unified pause/remove/shutdown
cancel face; the event bus never blocks the publisher — slow
subscribers lag and are then disconnected by the rpc face (upstream has
no backlog; aria2 pushes unbounded).

### Queue semantics (reference: aria2 RequestGroupMan.cc, read-only)

- add enqueue (position-clamped insert) → fillup activates up to
  max-concurrent-downloads (`fillRequestGroupFromReserver`); paused
  items are skipped and re-inserted at the front preserving order.
- pause (active) = set the pause flag + cancel the task token
  (isomorphic to aria2's halt+pause request); teardown (engine exit
  event) requeues at the front paused (`ProcessStoppedRequestGroup`
  push_front); remove clears the pause flag (halt semantics:
  `RequestGroup.cc` setHaltRequested also calls
  setPauseRequested(false)).
- engine teardown → DownloadResult (`addDownloadResult`);
  numStoppedTotal only grows; the table is trimmed by
  `--max-download-result`.
- **Phase-split registries (the four-pool budget model)**: alongside
  the download pool (`active`/`reserved`), the QueueMan carries three
  per-phase registries with their own FIFOs — the check pool
  (`checking` in flight / `check_pending` parked within
  max-concurrent-checks), the seed pool (`seeding` residents /
  `seed_wait` parked within max-concurrent-seeds — reactivation
  occupies a seed seat only, never a download seat), and the synthesis
  pool (`processing` in flight / `proc_wait` parked within
  media-synthesis-concurrency). Every promotion point runs the
  `pump_all` sweep (check → seed → synthesis promotion, download
  fillup last); a gid belongs to exactly one registry/queue at a time
  (the deferred side-sets' transient windows converge at Ended).

### Known boundary divergences vs upstream

1. **Eliminated (four-pool)**: bt-detach-seed-only yield timing — aria2
   calls `decreaseNumActive()` at download completion
   (`RequestGroup.cc`) so seeding does not occupy a concurrency slot;
   this engine previously released the seat only at the
   `EngineEnd::Detached` teardown. Under the four-pool model the seat
   releases at the **SeedingStarted** transfer (completion → the seed
   registry, download slot backfilled in the same pump); the Detached
   terminal variant survives as the semantic marker of a task that
   once seeded, and `bt-detach-seed-only` reads as constant-true
   (declared in the differential documentation).
2. Task live stats (speed / completed length) return through the engine
   query seam; in this module's own views an active task's
   completedLength is 0 (a known value, not fabricated).
3. pause-metadata (magnet upgrade residency): the upgrade product
   (Metainfo + rebuilt bytes) rides `MagnetEnd::UpgradedPaused` to the
   session and becomes a paused torrent task at the queue head — resume
   semantics identical to a normal torrent row (aria2's
   setPauseRequested follow-up group residency).
4. Main-loop zero disk IO (SPEC §3.2 PersistWriter): metainfo parsing
   and EngineConfig assembly go through `spawn_blocking` (pure CPU);
   row persistence is serialized through the single PersistWriter (task
   registration / lifecycle / bootstrap / saveSession).

### Upstream anchors

- LSD service: `BtSetup.cc` builds the receiver at the first BT
  download and reuses it from BtRegistry; this module lazily spawns the
  session-level service at the first task that needs it and degrades
  with a warning on failure ("LpdMessageReceiver not initialized").
- External-port follow-through: NAT port changes refresh the bt::lsd
  port slot (existing entries only change the port, timers untouched);
  no extra announce cadence is introduced — the next natural announce
  cycle carries the new port.
- Status snapshot cache: polling read faces hit a 2s TTL cache so
  getGlobalStat never serializes O(active tasks) engine round trips
  through the actor; any TaskNotice for the gid invalidates the entry,
  so post-event queries always read post-event truth.

## tests/duplicate_block.rs — cross-peer duplicate block root cause

The test reproduces this end to end; the deterministic orchestration
notes (peer delays, inbound order, timeline) stay in the test file
header.

Paths by which duplicate/overlapping blocks reach push_block:

1. The dispatcher sends a piece's candidate blocks to peer 0
   (`FaceState::blocks_sent` marks `InFlight`); the request holds a slot
   in the peer's RequestBook (60 s timeout >> the 2 s redispatch
   window).
2. The block is not confirmed by the store pipeline within 2 s (slow
   peer / link lag) -> `DISPATCH_REISSUE_WINDOW` (engine.rs) redispatches
   the original coordinates — a resend to peer 0 is rejected by its
   RequestBook `Duplicate` (wire-level in-flight dedup, the request
   never goes on the wire), but the other peers' RequestBooks are
   independent -> the same coordinates go to peer 1.
3. Both peers legally hold slots and answer: both blocks pass their own
   `RequestBook::on_piece` slot matching (peer.rs) -> both enter the
   block channel -> a double delivery into the store.
4. The store's existing defenses cover only "piece already verified"
   (the writer_verified bitmap) and "piece already full" (HashPool
   PieceAlreadyComplete); a duplicate arriving while the piece is in
   flight + the goff already buffered reaches `cache_data` -> false ->
   fatal Internal (verified.rs's old `duplicate cell at goff`) -> the
   task fails explicitly.

Reference cross-validation (read-only): aria2 filters duplicate blocks
in the receive path with a per-piece block bitfield — `BtPieceMessage.cc`
`if (piece->hasBlock(slot->getBlockIndex())) { "Already have this
block." return; }`; the `assert(rv)` in `Piece.cc` is only an invariant
backstop. The local fix aligns with that architecture: the caller
filters by the received-blocks bitmap first (one of the two layers),
with the store's coverage check as backstop.

## session/options.rs

### aria2 option diff surface

Governance: a full diff under a whitelist. Accepted/echoed option names
are checked one by one against literal `makePref("<name>")` entries in
the reference `src/prefs.cc` (read-only reference checkout; CI does not
depend on it). Any accepted/echoed name not in the reference table must
be declared in `DECLARED_OPTION_DIFFS`; additions go through PR + user
approval. Semantic redefinitions (same name, different meaning) do not
enter the whitelist table — each is declared at its parse/echo points
and summarized here.

#### Semantic redefinitions (per option)

- `split` / `min-split-size` / `max-connection-per-server` (semantic
  redefinitions, accepted and effective): accepted across the whole chain
  (addUri/CLI/changeOption). Under dynamic scheduling, split/min-split-size
  only seed the initial extent (the connection-ring growth cap =
  max-connection-per-server, slow-start AIMD — aria2 uses a static
  concurrency count); under static scheduling they are the split count /
  minimum segment length. `max-connection-per-server` maps to the
  `bt-max-peers` slot on the BT option face and is the AIMD growth cap on
  the HTTP task face (domain 1..=16, out-of-range rejected; lowering at
  runtime goes through changeOption restart semantics).
- `max-tries`: redefined as per-extent retries (aria2: per URI attempt).
- `ca-certificate` (accepted face): PEM CA file path — the task-level
  root REPLACES the platform trust store (aria2 replace semantics, not
  append); effective for both HTTPS and FTPS. Two tightenings vs aria2:
  (1) parse-time path/PEM validation — a bad path or bad PEM =
  `taiji.option.invalid` task rejection (aria2 fails at transport-build
  time and does not check readability); (2) value domain = PEM
  `CERTIFICATE` sections (multiple certificates allowed); bare DER is
  rejected (aria2's "must be in PEM format" made explicit). When
  `--check-certificate=false` is also set, the latter wins (verification
  off, the CA file is ignored; aria2 same) — order preserved at both the
  parse and wiring points. changeOption accepts the same key (a missing
  key keeps the task's current value — incremental semantics).
- `bt-tracker`: tightened to union-cumulative import (aria2: a per-task
  replacement table).
- `--continue`: inverted semantics declared explicitly (always resume;
  false does not discard progress; disclosed by a CLI warning; the RPC
  face has no such key).
- `--all-proxy`: socks5(h)/socks4(a) explicitly rejected (the reqwest
  socks feature is not enabled; declared limitation).
- `--load-cookies` (accepted face): Netscape cookie file path (aria2
  same name, same meaning). Three entry points = addUri per-task options
  + changeGlobalOption global face + the CLI `taiji http` flag. File
  loading is fail-closed at task acceptance (missing/unreadable/>1MiB =
  `taiji.option.invalid` task rejection; per-line malformed lines follow
  the parse face's lenient discipline — the cookies.rs module doc, curl
  same). Effect = pre-filling the task CookieStore (the taiji-http
  `CookieStore::seed` injection seam). Combined with a manual `--header`
  Cookie header: when the cookie injection gate is present, manual Cookie
  lines are stripped (the jar is the single cookie source; the fork's
  "Structured cookies are authoritative" is isomorphic —
  `RpcMethodImpl.cc`). Cookie persistence = the sqlite single source of
  truth (capture lines written back).
- `select-file` (accepted face): aria2 INITIAL + reserved-change
  capability bits (`OptionHandlerFactory.cc`; **no** setChangeOption —
  not changeable at runtime). 1-based, comma + closed-range syntax
  (parseIntSegments, `Util.cc`), domain 1..=1048576 (aria2 `1_m`);
  accepted via addTorrent / addUri(magnet) options / changeOption
  Reserved(Paused). The internal data face is uniformly 0-based
  `cfg.selected_files` (the same persistence channel as magnet `so=` and
  the same engine consumption point SetFileSelection). Three tightenings
  vs aria2: (1) known-key invalid values are explicitly rejected with
  `taiji.option.invalid` — empty string/empty item/contains 0/out of
  domain/duplicates/out-of-order/overlapping or inverted ranges/
  non-decimal (aria2 only errors on non-numbers and incomplete ranges;
  duplicates/out-of-order are absorbed by SegList::normalize, and
  out-of-range indexes build a silently empty filter via setFileFilter
  at group construction); (2) changeOption on Active tasks is explicitly
  rejected (aria2 ignores non-changeable keys, `RpcMethod.cc`); (3)
  magnet `so=` together with this key = explicit conflict rejection (a
  single selection-face source; aria2 has no so= face). changeOption
  with this key on non-BT tasks (HTTP/.torrent URL) = explicit rejection
  (accepting without effect would be a disguise). Live reselection
  (libtorrent `prioritize_files` anytime semantics) is a `taiji.*`
  extension candidate, not on this face.
- getGlobalOption echo face = the declared subset + this list's
  whitelist items (aria2 echoes the whole table — "the echo face follows
  the declared subset" is the declared diff direction).

#### FTP diff declarations (per option)

- `ftp-user`/`ftp-passwd`: accepted and effective. Credential chain =
  URI userinfo > this pair > default; separate slots from
  http-user/http-passwd (aria2 keeps the http/ftp slots apart too); ftp
  credentials do not leak into http sources. Default password diff: the
  anonymous password = `anonymous@` (fork alignment; the aria2 reference
  = `ARIA2USER@`, `AuthConfigFactory.cc`) — declared divergence.
- `ftp-pasv`: accepted; the value false (active-mode PORT) is NOT
  accepted — explicit rejection (taiji is PASV/EPSV only; accepting
  without effect would be a disguise, so prefer rejection). Default
  true, same as aria2.
- `ftp-reuse-connection`: accepted and effective (default true, aria2
  aligned) — the control connection is reused across extents; false = a
  new connection per extent.
- `ftp-pasv-address-check` (taiji extension, whitelist table): the
  PASV/EPSV data-connection address policy peer|strict|off (default
  peer = the aligned posture, i.e. the hard-wired behavior of aria2
  `FtpNegotiationCommand.cc` preparePasvConnect; strict = adopt the
  reply IP but reject private/loopback/link-local addresses that differ
  from the control peer; off = dial the 227 reply address verbatim —
  the SSRF-protection face is disabled wholesale, for explicit opt-in on
  trusted networks only; declared divergence). aria2 has no such option
  name. Value grammar single source = taiji-http
  `PasvAddressPolicy::FromStr`; effective = the to_ftp_config projection
  `FtpConfig.pasv_policy` -> every FtpTransport::for_uri construction
  point.
- `ftp-type`: NOT accepted (unknown-option ignore, same as the
  reference) — TYPE I (binary) always; ascii transfer mode has no modern
  use case (declared divergence).
- `ftp-proxy`/`ftp-proxy-user`/`ftp-proxy-passwd`: NOT accepted — the
  FTP-over-HTTP proxy is deferred (declared divergence).
- `ftp-ssl` (taiji extension, whitelist table): FTPS tri-state
  none|auth (default)|implicit. **aria2 has no FTPS capability and no
  such option name** — a capability extension; `ftps://` is not accepted
  as URI input either (FTPS = `ftp://` + `--ftp-ssl`); ftps:// sources
  are dropped at probe time.
- Charset: FTP paths prefer UTF-8 with a Latin-1 fallback (fork
  behavior; aria2 does no conversion — declared divergence). Non-UTF-8
  path transcoding has a known UTF-8 re-encoding skew (the taiji-http
  ftp module's known boundary).
- FTP servers without SIZE support: the source is dropped (without an
  authoritative total length the block-grid accounting / checksum final
  arbitration preconditions fail); aria2 can stream without a total
  length — a taiji tightening, declared divergence. A REST refusal -> a
  single-connection downgrade without a bitmap (SPEC §4.8, aria2 same).

#### SFTP deferral

- The `sftp://` scheme is not accepted: explicit rejection at addUri
  task creation, with the `taiji.sftp.deferred` string code in the
  error message (the CLI `taiji http` and RPC share the entry). The
  SFTP transport face (SftpTransport / known_hosts strict / identity /
  pipelined concurrency) is deferred as a whole and declared in the
  diff, to be delivered by a separate project. The `--sftp-*` option
  family is deferred with it (not on the acceptance face;
  unknown-option ignore, same as the reference).

#### Method-level diff declarations

- getUris: status = a spent/remaining approximate projection
  (per-source live status for active tasks, "used" for everything
  activated, "waiting" for everything not activated — commands.rs doc).
- getServers: one aggregated row per source (aria2: one row per
  in-flight request — commands.rs doc).
- saveSession: triggers a full store flush (the HTTP row mirror flush);
  it does not produce the aria2 session file format (lifecycle.rs doc).

#### metalink diff declarations (per option)

- Accepted face (two places, neither enters the core parse arm — the
  metalink group keys are absorbed at the addMetalink seam):
  `metalink-file` (CLI `--metalink-file`, the aria2 same-name
  LocalFilePath option) + the six legacy family names
  (language/location/os/version/preferred-protocol/
  enable-unique-protocol — aria2 reference names) accepted and ignored
  with a warning (the metalink group; the seam constant = taiji-rpc
  `metalink::UNSUPPORTED_METALINK_OPTIONS`; the seam ⊆ declaration-table
  subset check test lives at that seam).
- `metalink-enable-auto-discover`: accepted but treated as invalid
  (true = warn and ignore; the aria2 1.37.0 reference has no such name —
  HEAD `rel=describedby` auto-discovery is not done).
- `metalink-force-protocol`: accepted, ignored with a warning (a legacy
  family list name; the aria2 1.37.0 prefs.cc has no such name — a
  historical option).
- aria2 names this crate does not accept (follow-metalink,
  metalink-base-uri, referer, the per-protocol proxy family, the cookie
  file family, etc.): finalized in `DECLARED_NON_ACCEPTED_OPTION_NAMES`
  (the non-acceptance declaration table — a name must migrate out of it
  with effect semantics before it can be accepted; tests pin the two
  tables disjoint).
- Missing method face: the remaining fork-increment families are not in
  the promise table; compat calls land on "No such method" (see the
  taiji-rpc dispatch layer's finalized list). changePosition/getOption/
  forcePauseAll are already in the promise table.

## session/persist/import_http.rs

The HTTP-side core of the fork migration importer (`taiji import`).

### `task.serialized` text format (the parse reference)

Fork authority = upstream `SessionSerializer.cc` (write) / `UriListParser.cc`
(read):

- The first line is the URI line: multiple URIs are written TAB-separated
  (`writeUri` writes a `\t` after each URI, then one line break); the read
  side splits with `util::split(..., '\t', true)`. This parser accepts TAB
  and space both (the writer actually emits TAB; space is the documented
  convention; neither is a legal URI character, so there is no ambiguity).
- Following lines are option lines: ` key=value` (one leading space; the
  read side also tolerates TAB). Cumulative options (e.g. `header`) are
  written as multiple lines with the same key (`writeOption` splits values
  on `\n`, one line each) — parsing preserves order and duplicates.
- Lines starting with `#` are comments (the read side skips them). The
  line format is one segment per task for the fork; input with more than
  one URI line is not this format (a second URI line is ignored, never
  passed off as an option).

### Migration mapping

- First-line multi-URI (http/https/ftp) -> the `url` column +
  `mirrors_json`: the first URI = `url`; more than one source writes
  `mirrors_json` (same shape as
  `crate::session::actor::http_task::mirrors_json_of` — the resume side
  expands it losslessly via `uris_from_mirrors`).
- `dir=` / `out=` -> the `dir` / `out` columns: `out` goes through the
  same sanitizing rules as addUri (`sanitize_out_option`); a violation =
  the task fails explicitly.
- `pause=` OR fork state="paused" -> the `state` column: queued | paused.
- The remaining option lines -> `config_json` `imported_options`: the
  full migrated inventory (header/user-agent/proxy/credentials etc.)
  stored verbatim, order-preserving, never silently dropped. The
  consumption face folds them in at activation
  (`crate::session::actor::http_task::fold_imported_options`): the
  request-identity domain enters the runtime options; the three
  persistent keys (checksum/remote-time/http-incomplete-suffix) are
  frozen into the row payload — the final adjudication reads the row
  payload; the scheduling/timeout domains are rebuilt from the new
  session defaults (runtime options are not stored); TLS trust keys are
  not folded in (fail-closed); cookies are not part of the serialized
  format — see preflight item 7 below.
- `gid=` lines are not migrated: fork GIDs are not inherited (new GIDs
  are allocated). The dedup key = `origin_fork_key`, stored on the task
  row (row present + key equal = skip; `session_kv.imported_from` is
  demoted to a reverse index).
- `task_progress.bitfield` @ `piece_length` -> `block_bitmap` /
  `block_size` / `block_count`: the piece->block bitmap mapping (the
  complete-coverage rule, `crate::session::persist::import_bitmap`); see
  the next section.

### piece->block bitmap mapping (against silent over-reporting)

The fork writes `task_progress` for HTTP tasks too (the
`Sqlite3BtProgressInfoFile.cc` save writes is_torrent=0 / info_hash=NULL
for non-BT rows), and the legacy `.aria2` control file (the non-BT
variant, `taiji_store::persist::parse_aria2_control_http`) is the
isomorphic on-disk shape. The mapping entry point is
`crate::session::persist::import_bitmap::map_pieces_to_blocks`:

- Block granularity = the largest power-of-two factor of the piece,
  clamped into 256KiB..16MiB (the grid.rs configuration domain; no
  solution / below the floor falls back to 256KiB).
- The complete-coverage rule: a block is credited only when every piece
  intersecting its byte range is complete; partially covered blocks are
  dropped and re-downloaded (waste <= one block per piece boundary).
  In-flight pieces are not in the input (the main bitmap holds only
  verified pieces) — under-reporting is preferred, over-reporting never
  happens.
- Trust chain: the mapping product is only a candidate row payload. At
  activation, the first activation runs the degraded digest gate (the
  row's `validator_digest` is seeded with the facts known at import —
  the first URI path + total length, and the absence of strong-validator
  facts; the fork leaves no etag/last_modified while real servers always
  send them, so the seeded digest would certainly drift — hence the
  first activation skips the digest comparison), and the
  "existence+size" second line of defense performs the full verification
  as usual (the adopted row's `.part` length = the fork's write frontier,
  so the equal-length gate does not apply while the per-block size
  checks do). After the first-activation probe the measured facts
  backfill `probe_json` / `validator_digest`, and later resumes return
  to the strong gate; any drift still restarts from zero — the mapping
  creates no shortcut around resume trust.
- A failed bitmap validation (zero granularity / a fixed-length mismatch
  / a total-length overflow) = the progress is explicitly dropped to a
  weak resume (visible in the report) while the task itself is imported
  as usual; a broken bitmap is never folded into fake blocks.

### `.aria2` orphan reconciliation
(`crate::session::persist::import_http::reconcile_aria2_orphans`)

Reconciliation key = totalLength + output path (the output path = the
serialized `dir=`+`out=` target with the `.aria2` suffix stripped; both
dir sides are normalized via canonicalize, falling back to the original
spelling on failure). Dispositions:

- A sqlite row matched -> merged: the `.aria2` and the DB row belong to
  the same task and no second import entry is produced. When the row
  carries progress, the DB row is the fork authority (the control file
  is redundant; a totalLength mismatch = another download generation on
  the same path, not merged). When the row has no progress row (the fork
  wrote the task row but the task_progress write failed), the control
  file's progress fills the row's bitmap payload (the real increment of
  the merge) — the fill additionally requires "on-disk data length ==
  ctrl totalLength" (the row side has no total to compare, so the
  on-disk data length is the only totalLength half-fact; a mismatch = a
  foreign source, not merged; data absent = no length fact to compare,
  and the path hit keeps the merge).
- No match -> orphan: reported separately in the dry-run report
  (triggered by a fork sqlite write-failure window / a manual copy; rare
  but reachable). The control-file format carries no URI (a
  `DefaultBtProgressInfoFile.cc` layout fact) — a URI-less row could
  only become a silent broken task, so a real import produces no
  http_task row and the file and its data stay untouched (read-only
  discipline); the report lets the user re-add the download by URI.
- The reverse (a DB row present while the `.aria2` is absent) is not a
  gap: the fork's HTTP progress authority is `task_progress` (the sqlite
  face never writes `.aria2`), and the bitmap mapping consumes the DB
  row directly.
- Extension bit 0 set = a BT-migration-face file (the BT ctrl-import
  face); this face accounts for it separately and never mixes reads. A
  corrupt file is an explicit failure entry (never silent).

### Import preflight checklist (contract copy; implemented by
[`PREFLIGHT_CHECKLIST`] + [`preflight_fork_read`] + the per-task path
check during collection + the backup face
`taiji_store::persist::backup_target_db`)

1. The fork process must be exited: when the old aria2 fork/Motrix holds
   the sqlite write lock, the read-only probe reports SQLITE_BUSY -> the
   import refuses with the "exit the old version" guidance (never
   forcing through the lock).
2. The `.motrix/p/<id>` data-move ordering: the importer restores paths
   verbatim as recorded in the fork DB; the existing Motrix task data
   must be moved into place BEFORE the import — moving it afterwards
   breaks the task paths. During collection every task's `dir` is
   checked on disk: missing = the task fails explicitly (the
   broken-link copy in the report), never a silently stored broken row.
3. The target database must be offline: a live (or uncleanly exited)
   local taiji session leaves `-wal`/`-shm` sidecars -> `TargetInUse`
   refuses (a clean shutdown removes the sidecars and the import may
   proceed).
4. The pre-import backup is automatic: `taiji.sqlite3` ->
   `taiji.sqlite3.v1.bak` (the rollback-runbook recovery anchor; an
   existing backup is kept, never overwritten — the earliest pre-import
   snapshot is the truth of the fork-era data).
5. The progress trust face: imported HTTP tasks carry a piece->block
   mapped bitmap (the complete-coverage rule — partial blocks dropped,
   never over-reported; a failed validation drops the progress
   explicitly to a weak resume); bitmap trust is still decided by the
   activation-time validator and the "existence+size" second line of
   defense — any drift restarts from zero. Metalink-source hashes cannot
   be recovered from the serialized format (the same weak-resume rule);
   tasks whose source inventory is unrecoverable are skipped explicitly.
6. Request-identity options are folded in: the header/UA/proxy/
   credentials domain is folded in when activation assembles the request
   (the same parse and rejection source as addUri — an illegal value
   fails the task explicitly; socks proxies are a declared limitation of
   the taiji transport face and are rejected explicitly, never bypassed
   with a direct connection).
7. The cookie break: the serialized task format carries no cookies (the
   fork does not put them in that format either) — imported tasks
   activate with an empty per-task cookie jar, and Set-Cookie is
   captured into the task store at activation as usual; sources
   depending on existing cookies need the session re-established on the
   source side (a declared break, never a silently faked continuation).

### Dedup and second-import path conflicts

- Dedup (a single criterion): the criterion = `origin_fork_key`, the
  fork source-identity key stored with the task row (a row config_json
  field; the key =
  `crate::session::persist::import::ImportSource::source_key`, the same
  key space as the BT import) — row present + key equal = skip and point
  back at the old GID; row absent = a re-import is allowed (the
  criterion appears/disappears with the row; no dead-marker form
  exists). `session_kv.imported_from` is demoted to a reverse index:
  apply still writes the pair and the delete close-out clears it in
  step; it serves as the fallback criterion for old-database rows
  missing the row key and for the BT face — the liveness-check
  semantics of the kv fallback stay unchanged (a missing referenced row
  invalidates the hit, and invalid keys are noted in `stale_imported`
  for the report).
- Dual-mode second import: **`.bak` restore mode** — the dedup marks
  roll back with the database (row + key restored together), so
  upgrading again = a full re-import (the weak resume/bitmap
  reconciliation backstop applies, downloaded bytes are not
  re-downloaded; the report notes it); **target-keep mode** — the row
  is in the database and an `origin_fork_key` hit skips.
- Second-import path conflicts (rollback -> a new fork-era download ->
  upgrade again): a same `(dir,out)` conflict with an in-flight target
  task or an earlier task of the batch is decided by the configured
  action: `Skip` = report the skip (the default, the decided face);
  `Rename` = the aria2 candidate-name algorithm (`RequestGroup.cc`,
  `file.tar.gz` -> `file.tar.1.gz`, reusing taiji-http
  `renamed_candidate`) picks the first candidate outside the occupied
  set. Never a silent overwrite.

### Orchestration (the `taiji import` single command, both faces)

```text
preflight_fork_liveness (three layers: lock probe -> live-fd scan ->
cannot-prove refuses by default / --i-know-fork-is-closed accepts
responsibility) -> collect_fork_all_tasks (the BT face + the HTTP face
partitioned in one read-only open) -> (per task: the origin_fork_key
row-key dedup with the kv reverse-index fallback ->
HttpImportPlanner::plan) -> [real import] backup_target_for_import ->
apply_import (BT) / apply_http_import (HTTP)
```

Dry-run = the whole flow minus the last two steps, with the target
query face going through [`read_target_snapshot_for_dry_run`] (a
read-only snapshot with zero write side effects: the existing target
database is never opened by PersistWriter — an open would advance the
migration ledger); the reports of both faces merge (one command). The
collection meeting point of the single command =
[`collect_fork_all_tasks`] (BT candidates and HTTP entries produced by
the same read-only open, with the lock probe forced first).

## magnet.rs

The magnet chain: magnet URI -> MetadataPending task -> DHT/tracker/LSD
(+ optional HTTP web-mirror) discovery -> ut_metadata fetch ->
TorrentMeta rebuild + verification -> an in-place upgrade to a real
download task.

### Orchestration semantics vs aria2 (read-only reference)

The magnet chain is linearized inside the actor: instead of aria2's
BtDependency/PostDownloadHandler machinery, this module merges the
"metadata task" and the "real task" into one [`MagnetEngine`] task:

- magnet -> an in-memory metadata download task: aria2
  `download_helper.cc` createBtMagnetRequestGroup; here the task starts
  in [`TorrentState::MetadataPending`] with no files allocated.
- Rebuilding the .torrent after ut_metadata completes: aria2
  `UTMetadataPostDownloadHandler.cc` metadata2Torrent; here
  [`metadata2torrent`] (a direct translation of bittorrent_helper.cc:
  announce-list + the raw `4:info` bytes).
- bt-save-metadata writing `<dir>/<hex(btih)>.torrent`: aria2
  `UTMetadataPostDownloadHandler.cc`; here the metadata is written as
  soon as it is ready (before the metadata-only branch, the same
  order).
- bt-metadata-only skipping the real download: aria2
  `UTMetadataPostDownloadHandler.cc`; here the
  [`MagnetEnd::MetadataFetched`] terminal.
- The followedBy/following GID chain: aria2
  `UTMetadataPostDownloadHandler.cc`, `RequestGroup.h`,
  `RequestGroup.cc` (the tellStatus fields); here [`MetadataChain`]
  (the in-place upgrade: followedBy = this GID, following = this GID;
  the RPC synthesis is a later milestone).
- pause-metadata pausing the follow-up: aria2
  `UTMetadataPostDownloadHandler.cc` setPauseRequested; here
  [`MagnetEnd::UpgradedPaused`] (the honest shape before session
  residency: the upgrade configuration is verified, the task does not
  start).
- The bt-load-saved-metadata short circuit: aria2 `download_helper.cc`
  (reads `<dir>/<hex>.torrent` -> compares the infohash, warns and
  continues the magnet path on mismatch); here
  [`MagnetEngine::load_saved`].
- The magnet `tr` list -> one announce-list tier per tr: aria2
  `bittorrent_helper.cc` parseMagnet; here tiers = `tr[i] -> (i, url)`
  (shared by the tracker actor and the rebuilt .torrent).

The ut_metadata fetch face (one task per connection): the ext handshake
(BEP10) -> registering the peer's `m.ut_metadata` + `metadata_size` ->
piece requests (at most one in flight, `UTMetadataRequestTracker.cc`,
with a 20s timeout sweep) -> assembly + the expected-identity check
(V1 = SHA-1, `UTMetadataDataExtensionMessage.cc`; V2 = SHA-256 against
btmh, this engine's BEP52-aligned extension). The serving face: a
connection already holding the metadata answers inbound requests with
data/reject (`UTMetadataRequestExtensionMessage.cc`).

### Intentional divergences from the reference (all declared; no interop
impact)

1. The upgrade is in-place (same GID): aria2 creates a new RequestGroup
   with followedBy pointing at it; the decided design is the linearized
   in-place upgrade, with the GID chain carried by the [`MetadataChain`]
   data face (the RPC layer synthesizes the followedBy/following
   fields).
2. A magnet with an empty `tr` fails explicitly: the upgraded .torrent
   must contain announce (the Metainfo contract); a DHT-only
   environment means the tracker is unreachable, not "the magnet has no
   tr". An empty tr without bt-load-saved-metadata = an explicit error
   at creation (honesty).
3. The metadata-phase budget is a local policy value: aria2 has no
   metadata-specific timeout (it relies on announce cycles and the
   download timeout); the linearized orchestration makes it explicit in
   [`MetadataPhaseConfig`] (the deadline defaults to None = wait
   honestly; with no peer, completion is never faked).

### Concurrency discipline

The metadata-phase subtasks (the tracker actor / metadata peers / DHT
event forwarding) all hang off `md_token` child tokens; everything is
cancelled as soon as the metadata is ready (the upgraded engine then
rebuilds its connection face entirely — storage/progress/announce all
re-mounted).

## create.rs

The torrent-creation face: explicit disk paths -> [`taiji_bt::creator`]
generation -> the .torrent written to disk.

### Positioning

`bt::creator` is a pure library (input = ordered relative paths + source
paths + declared lengths); this module is the wiring layer shared by the
RPC `taiji.createTorrent` and the CLI `create-torrent` (both entries
take the same parameters; the dependency direction allows cli -> core
and rpc -> core; creator.rs is untouched — a missing library API is
reported explicitly, never patched in the library).

### Input rules

- `files` is an explicit file path list (>=1); no directory recursion —
  scanning is UI semantics (deliberately not done); the caller
  enumerates.
- The in-torrent relative path = the input path minus the longest
  common component prefix of ALL input paths; `name` = a single file
  takes the file name (the creator's single-file constraint
  `files[0].path == name`), multiple files take the last component of
  the common prefix (libtorrent's `add_files` follows the same
  convention: the torrent name = the containing directory name); no
  common parent directory = an explicit Err (no name guessing).
- Relative paths are sorted by component byte order before being handed
  to the creator (the creator input order = the v1 layout order; BEP3
  canonical requires files sorted by path ascending; pads are inserted
  by the creator automatically).
- The actual file length = the stat reading (spawn_blocking); a
  directory or a missing file = an explicit Err; symlinks are followed
  via `metadata()` (hashed by target file — the creator layer does not
  support `symlink path` entries).

### Engine freedoms (aria2 has no createTorrent; no compatible defaults
to match)

- Default piece length = 16KiB (the BEP52 floor; libtorrent's automatic
  tiering floor in `create_torrent.cpp` is the same value; the local
  value is fixed and does not scale with the total length, but the
  caller may pass one explicitly).
- Default form = hybrid (with libtorrent's default `flags = {}`, having
  both the v1 and v2 hashes yields hybrid, `create_torrent.hpp`).
- Announce: 1 entry = the top-level `announce`; >=2 entries =
  `announce` (the first) + `announce-list` with one independent tier
  per entry (the BEP12 shape).
- The `creation date` is omitted by default (libtorrent writes the
  current time by default, `create_torrent.cpp`; omitting it keeps the
  output reproducible — the same material yields the same bytes).
- File attrs (h/x) are not sniffed (always default — consistent output
  across platforms, the same motivation as libtorrent's
  `no_attributes` flag, `create_torrent.hpp`).

### Blocking and timeout (per the no-timeout-bounded-sync-RPC ban)

stat / disk-read hashing / writing all run inside [`spawn_blocking`]
(the hash core is the pipeline inside `creator::create`); the overall
contract is a synchronous return with the outer
[`CREATE_TORRENT_TIMEOUT`] (600s) backstop — a timeout = an explicit
Err (the caller never hangs).

### Resource gates and the input budget

The 600s timeout bounds only the response and cannot cancel the
underlying hashing (spawn_blocking is not cancellable), and pseudo
files like `/proc/kcore` report `is_file() == true` with a huge stat —
without gates, N concurrent runs would fill the blocking pool and OOM.
Four gates close in order at this entry (the rpc/cli entries share
them; the rpc layer is unchanged):

1. Pseudo-filesystem rejection (before all IO): an absolute path under
   /proc, /dev or /sys = an explicit Err (the component-level prefix
   table [`is_pseudo_fs_source`]); `metadata()` follows symlinks, and
   the target is re-checked via canonicalize inside [`probe_files`];
   device/FIFO and other non-regular files are refused by the existing
   `is_file` gate.
2. The process-level concurrency gate ([`MAX_CONCURRENT_CREATE`]): over
   the cap, callers queue for a bounded window ([`CREATE_QUEUE_WAIT`]);
   still full = an explicit [`CreateTorrentError::Busy`] — the window
   absorbs millisecond jitter and natural multicall batch queueing (the
   batch size is capped by the rpc layer's `MAX_BATCH_ITEMS`), while a
   sustained overload fails fast; the trade-off notes live on the
   constants.
3. The timeout does not drop the gate: on the timeout path the permit
   is not handed to the task (the task cannot observe cancellation) but
   parked by a watchdog until [`ABANDONED_PERMIT_GRACE`] — the
   abandoned-but-running hash keeps occupying the gate and new calls
   are refused explicitly until it drains (the abandoned-task cap and
   the concurrency gate are unified in the permit itself, so no
   dual-counter drift exists).
4. The total input byte budget ([`MAX_INPUT_TOTAL_BYTES`]): effective
   after stat, before disk hashing — over budget = an explicit failure
   with zero disk reads (the budget is a function of the timeout
   contract; the notes live on the constant).

## session/view.rs

Sources: aria2 `RpcMethodImpl.cc` (`gatherProgressCommon`,
`gatherStoppedDownload`, `gatherProgressBitTorrent`, `createFileEntry`,
`createUriEntry`, `gatherBitTorrentMetadata`, `gatherPeer`, `tellStopped`),
`BitfieldMan.cc` (`getOffsetCompletedLength`), `GroupId.cc`
(`expandUnique`, `hexCharToUInt`), `bittorrent_helper.cc`
(`getModeString`, magnet `totalLengthIsUnknown`), `Util.cc`
(`torrentPercentEncode`); SPEC §4.4/§7.1/§7.2/§8.2; BEP3/12/27/47/52/53.

### Query face shape

The query field set is cross-validated against `gatherProgressCommon` /
`gatherStoppedDownload` / `gatherProgressBitTorrent` plus the SPEC §8.2
supplementary fields. Payloads keep core semantics: no JSON field names
in core (explicitly forbidden) — aria2 boolean strings ("true"/"false"),
hex, and percent-encoding are synthesized in the RPC layer, and every
SPEC §8.2 promised field stays present (a narrowed value domain still
emits the key unless a "None = key omitted" rule says otherwise).

### Value-domain narrowings

- `PeerEntryView::transport`: values surface live with the µTP data
  face at the connection-establishment snapshot (`tcp`/`utp`).
- `PeerEntryView::peer_choking`: the PeerTask internal state has no
  read face; the engine's dispatch face never backs off on peer choke,
  so the value is always `false` — an assumption valid for every
  connection.
- `PeerEntryView::peer_id`: captured at the handshake (the engine
  registration face); `None` only for connections whose handshake has
  not reached the registration window (the frontend treats it as
  "empty peerId"; the Motrix peer.ts rule).

### The `selected` projection

`file_selected` is the single projection source for every emitted
`selected` value (aria2 `selected = FileEntry::isRequested()`; the
libtorrent boolean equivalent = `file_priorities[i] > 0`, the BEP53
protocol behavior face). `selection` = the task selection face
(`cfg.selected_files`); the BEP53 index caliber = the client file-list
order, 0-based over non-pad entries (pad entries are BEP47 transport
placeholders, not files, and are not counted — the same anchor as the
engine `selection_mask` / `so=` parsing). `None` = select all (pad
placeholder entries included — the isRequested default; zero behavior
change for tasks without a selection); `Some(set)` = only members true;
pad entries pass `None` and are never selected on a Some face.

### GID prefix resolution

`expand_unique` is a direct translation of `GroupId.cc` `expandUnique`:
the hex string left-aligns into a 64-bit prefix (`p <<= 64 - i*4`), the
first `(gid & mask) == p` hit expands, several hits → NotUnique, zero
hits → NotFound, non-hex / overlong / empty → Invalid. This engine's
GIDs always set the top bit (shared-namespace isolation), so prefix strings match hex
digits starting `8`..`f` left-aligned.

### Synthesized progress calibers

- `completed_length` = Σ per-file verified bytes + padding counted
  full; a terminal entry is the snapshot at wrap-up.
- Per-file completedLength folds bitmap ranges
  (`getOffsetCompletedLength` direct translation); the v2 synthetic
  bitmap coordinates = file ordinal × pieces per file, and
  `file_piece_bases` gives each file's starting piece ordinal in the
  same coordinate system as the engine `ProgressModel`.
- The `torrent_top_attrs` parse is lenient (missing field / type
  mismatch → None, the `gatherBitTorrentMetadata` defaults); metainfo
  bytes are captured by the session on the addTorrent / URL upgrade
  paths, and metainfo.rs's parse face is untouched (a frozen
  cross-module interface).

## session/command.rs

Sources: aria2 `RpcMethodImpl.cc`/`RpcMethodImpl.h`, `RpcMethod.cc`
(`gatherChangeableGlobalOption`), `RequestGroupMan.cc`
(`pauseAllDownloads`, `addDownloadResult`), `IndexedList.h`, fork
`RpcCookie.cc`; SPEC §3.2/§7.2/§8.2.

### Command/reply surface

Variants and methods are 1:1 (`RPC_METHODS` = the SPEC §8.2 promise
table); payloads keep core semantics — no JSON (RPC JSON assembly is
forbidden in core), and the aria2 field-name mapping and keys/pagination
filtering execute in taiji-rpc (error mapping, same rule).

Two deliberate exceptions to 1:1, both executed in the RPC layer and
never entering the session actor:

- `system.multicall` / `system.list*`: expanded/answered at the RPC
  layer; the placeholder variants exist only for method-surface
  completeness and the actor always answers NotSupported.
- `taiji.createTorrent` and `addMetalink`: no SessionCommand variant —
  createTorrent goes straight to the `taiji_core::create` facade;
  addMetalink is parsed at the RPC consumption seam (taiji-metalink
  stays out of the core dependency graph) and expands into per-task
  `AddUri` commands ("task orchestration all takes existing paths").

### Parameter shape changes (finalized)

- Every gid-taking method takes `gid: String`: all aria2 gid parameters
  go through `str2Gid` → `GroupId::expandUnique` prefix resolution
  (RpcMethodImpl.cc + GroupId.cc); a fixed-width u64 cannot express
  prefix semantics. Resolution runs inside the actor over the
  active ∪ waiting ∪ results set.
- `TellStatus { gid, keys }` — empty keys = all fields.
- `TellWaiting/TellStopped { offset, num, keys }`; `TellActive { keys }`
  (aria2 tellActive has no pagination parameters, RpcMethodImpl.h).
  The filtering/pagination execution semantics live in the RPC layer:
  core always returns the full ordered view; the variant fields are the
  frozen seam shape.
- `CommandReply` adds the incremental variants
  `TorrentStatus`/`Files`/`Peers`/`Servers`/`Uris`/`GlobalStat`.

### Method-face governance

The method-face vocabulary single point lives in
`taiji_domain::methods`; the tests pin the registry to the method
surface in both directions (no over-/under-/duplicate registration,
order preserved) and freeze the read-only bits and the QueryList /
QueryStatus / Special kind lists, with Control implicitly locked as the
whole-set complement.

## session/http/snapshot.rs

Sources: SPEC §2.5/§2.3/§4.3/§14.1.

### The fsync-before-persist ordering

Block completion → bitmap dirty → a 2s-debounced snapshot persist;
every snapshot commit is preceded by one fsync of the task file (at
most one per task per 2s, bounded cost). Timing invariant: "a
power-loss bitmap is never ahead of the data" — every completed block
in a snapshot has its byte range already persisted when the fsync
returns; an fsync failure withholds the snapshot (the bitmap stays
dirty; the caller handles the task-level fault). Under-crediting
progress is acceptable: on power loss the bitmap at most lags the data
by ≤2s (unconfirmed blocks are re-downloaded — the safe direction).
The reverse window (a bitmap ahead of the data) is structurally
excluded by the commit order, and the recovery-phase "exists + size"
check (recover.rs) is the second line of defense.

`NotFound` from fsync refuses the commit whenever the pipeline holds
completed blocks (a file declared complete but missing = an inflated
bitmap; never disguised as success). The state/error setters mark the
pipeline dirty too, so a commit can also be reached with an empty
completed set (a state-only change before the first block); a NotFound
there is refused the same way (conservative: the change stays dirty and
retries on the backoff cadence) — no commit lands while the task file
is missing.

### Exit guard

Terminal-row consumption (`into_row`) must follow `flush_now` — the
completion path enforces the "fsync + bitmap persist → terminal
persist" order, and a row carrying an unpersisted bitmap is refused
(a done row is not in the recovery read face, so the second line of
defense never covers "full bitmap + unpersisted bytes"). The state
setters expose only state/error fields; bitmap/count/progress have no
write entrance outside the snapshot fsync order. A setter marks the
pipeline dirty: the state change rides the next debounced snapshot (or
`flush_now`) through the same fsync gate — never silently dropped on a
clean pipeline — and an unpersisted state change is refused at
`into_row` as well.

### BT-side barrier

The same timing invariant on the BT face (data fsync first, progress
row persist second): the store pipeline's terminal wrap-up is "drain
in-flight writes → fsync data files → set the barrier", and the
engine's terminal progress row waits for Flushed and is refused
otherwise — see `engine::pipeline` (the store_pipeline wrap-up) and
`engine::run::tail::final_flush`.

### Directory-entry trade-off

This module fsyncs only the task file itself; parent-directory fsync is
not in the snapshot pipeline (a one-time creation-time action belonging
to task assembly). Power loss losing the directory entry = the `.part`
missing = recovery explicitly from zero (`PartFileMissing`, the safe
direction) — an accepted trade-off; no per-snapshot parent-directory
cost is added.

### Plumbing

fsync is blocking IO → `spawn_blocking`; persistence goes through the
single-writer PersistWriter. The clock is caller-injected (monotonic
milliseconds, used only for the debounce window; monotonicity guarded
by debug_assert) — the task actor drives it with the tokio clock, and
tests use a synthetic clock (deterministic, zero sleep).
## session/actor/tests/batch.rs

E2E suite for the HTTP batch scheduler (same-host transient batch groups),
the per-host cap (`http-max-per-host`) wiring, and the HTTP driver's
failure faces. Mock origins are in-process raw-TCP servers with
controllable pacing, path-selective failures, echo drift, and accept-time
instrumentation; every concurrency assertion is paired with an anchor that
the concurrent data-plane path is really taken (a probe judged no-range
downgrades the task to one connection and the assertion idles).

### Batch parallelism and the block-granularity serialization point

A 1MiB file at a 1M block is a single-extent task, so the `split`
connection intent is inexpressible on it: batch parallelism is pinned at
min(-j, task count) x 1 connection. The many-small batch test therefore
asserts (a) the batch's concurrent Range peak >= min(split, cap), (b) the
batch wall time under half the factory-shape serial lower bound
(min(-j, N) tasks in parallel, one connection each, ceil(N/5) waves), and
(c) byte-exact files.

### Contention peak vs budget: the L1/L2 assertion layering

While a big grid-path file holds the host cap, the batch group's in-flight
Range peak must stay <= `--http-batch-budget`. The sampler records the
origin's dual in-flight counters and the group active count in the same
frame, and the assertions are layered so each pins one invariant
independent of load timing:

- L1 hard ceiling: big+small in-flight <= HOST_CAP in every frame (the
  deterministic per-connection acquire bound of HostCap; zero tolerance).
- L2 polite share: on contention-covered frames (big in-flight >=
  HOST_CAP - BUDGET), small in-flight <= BUDGET + 1 (the +1 is frame-drift
  tolerance of the sampler's non-atomic read order, not pass-through
  tolerance — pass-through workers count into the group's active slots and
  never stack above the ceiling).

Group active (including host-permit queuers) must not be the criterion: in
the ceiling formula outside = host_active - group_active, queued members
without permits count into group_active but not host_active, so a long
group queue dilutes outside and the ceiling
max(budget, host_cap - outside) self-lifts toward the host cap. That is
intended work-conserving behavior ("politeness, not correctness"), not a
ceiling failure; the ceiling's group semantics are pinned by the taiji-http
batch.rs unit tests (the gate_enter series), and this e2e observes the L2
in-flight face. The whole-run origin peak mixes contention-unrelated frames
(the group may legitimately fill host slack between big-file blocks) and is
diagnostic output only.

### Time-weighted concurrency floor

The floor (time-weighted in-flight >= 50% of the cap while the batch form
lives) is measured on origin in-flight connections (`RangePeak::inflight`),
not on `small_batch_stats().active`: gate reservations include workers
waiting for host permits, so a waiting-worker regression stays green on
that metric forever. Under the in-flight measure, permits held by waiters
directly depress the time weight and the regression is caught.

### Activation overhead bound

The bound on first-connection establishment for N concurrently submitted
tasks is deliberately loose (1.8s): full-load probe/connect jitter can eat
the nominal cost, while a truly serialized activation chain is compound
(later probes queue behind earlier tasks' in-flight connections on the
same origin) and still trips the bound.

### Per-host cap wiring

- Default cap 64, visible both in the getGlobalOption echo and
  behaviorally (three same-host tasks x 16-connection intent push the peak
  past the old default 32 but never past 64).
- addUri `http-max-per-host` is last-set-wins over the session init value
  in both directions; the echo always reports the effective value
  (GetGlobalOption = HostCap::cap()).
- A rejected addUri (illegal `out`) must not leave a cap side effect.
- Cap intent persists in the row config_json and resumes lowered after a
  restart (the origin peak ground truth is still the lowered value); rows
  without the option carry no host_cap payload.
- Value domain parity with the CLI: 2^33 rejected with
  `taiji.option.invalid` and no row persisted; 2^32-1 accepted.

### Failure faces pinned by the suite

- Deterministic protocol contradictions terminate in one data request:
  plain 200 after a 206 probe (`taiji.http.range_ignored`) and a
  start-mismatched 206 echo (`taiji.http.bad_range`, RPC code 8).
  End-dimension deviations are tolerated instead: over-delivery (inflated
  Content-Length) closes the stream after the needed bytes, under-delivery
  (shortened echo) credits partial progress and completes via the existing
  retry.
- Retry-After is honored over the default backoff (the throttle-window
  closing gap anchors the server value).
- Per-task backoff jitter spreads the first-retry phases of same-source
  failures (gaps stay >= the 200ms base and are distinct).
- Same-moment tasks stagger first-wave connects on a group-level global
  order (CONNECT_STAGGER_MS), not per-file ordinal restarts.
- Cross-file stealing carries the owner URI: per-file distinct payloads
  (sha256 of the name) are required to expose wrong-file bytes; aborts
  attribute to the owner file; fail teardown aborts and joins detached
  workers before the error row; forceRemove clears the batch registry via
  the Drop guard.

## session/actor/tests/options.rs

Option-face suite: echo governance, mutation semantics, tracker editing,
and value-domain validation at the session command surface.

### changeUri (upstream file-entry semantics)

BT tasks are no-ops with counts [0,0] and announceList untouched (file
entries keep no URI ledger — upstream removeUri never matches,
FileEntry.cc); an out-of-range fileIndex and a result-domain GID fail with
the upstream verbatim messages (RpcMethodImpl.cc; findGroup excludes
terminal states); HTTP tasks take the same no-op shape (the live source
ledger lives in the driver, with no source-change seam at the engine
face).

### Tracker editing (taiji.addTracker / removeTracker)

Three states: an active task takes effect immediately through the
SetTrackers engine coupling with a dual projection (getServers tracker
table + tellStatus announceList); a waiting task edits the payload (visible
in announceList); terminal, metadata-phase, and HTTP tasks are rejected
explicitly (accepting without effect would be a disguise). Position
inserts a tier; removal is exact-match; delete-all leaves the pure DHT
face (an empty announceList is legal) and replay is idempotent 0. Edits to
paused tasks persist through config_json and survive a restart.

### Global tracker configuration (three layers)

Built-in announce + `bt-tracker` (union-cumulative comma list, whitespace
tolerant) + `bt-tracker-file` (ngosang format). changeGlobalOption hot
reload reaches in-flight tasks and later activations; the echo is the
global set comma-joined with union dedup; the store table order = import
order (rowid). Caps: the global set at 1024, a single task's engine table
at MAX_TRACKER_TIERS (256 including the built-in slot); a 1200-entry
import completes in <1s end to end within <1MiB of URL strings.

### getOption governance

Every echo key produced by the four Job shapes, the result domain, and the
HTTP persistence/runtime families must be declared (ARIA2_OPTION_NAMES
union DECLARED_OPTION_DIFFS) — an undeclared echo key is red. The echo
covers the accepted subset with minimal numeric value forms (the reference
echoes the add-time literal; the form difference is a declared diff);
`bt-max-peers` has no per-task payload and is never fabricated; error
faces use the verbatim str2Gid family messages; terminal tasks without a
persisted shape echo an empty map; completed HTTP tasks read back from the
http_task row config_json.

### changeOption

Waiting tasks merge the payload; active tasks take restart semantics
(requeue at the front, reactivate with the merged payload). The HTTP
scheduling group validates values in one parser shared by addUri and
changeOption: out-of-domain values are rejected wholesale
(`taiji.option.invalid`, never clamped), http-block-size is immutable per
task, `--split` caps at MAX_SPLIT = 4096 (static scheduling spawns
`split` workers per source unconditionally, so an unbounded split
magnifies the task count toward OOM, and the `as u32` truncation face is
closed by the same gate), and http-stall-window floors at several
heartbeat periods (STALL_WINDOW_MIN_SECS = 3s) so one heartbeat jitter
cannot forge stall evidence. Rejected calls leave the row payload
untouched; absent keys merge onto the baseline instead of resetting.

### Scheduler policy and misc faces

SchedulerPolicy defaults to rarest_first, accepts sequential, persists the
non-default policy in config_json, and reads legacy payloads (a
non-default policy present at wiring time) back losslessly.
bt-sequential-download projects to the scheduler policy
(add/changeOption/echo faces). build_engine_config resolves the
config_json `disk_tier` override (None/unknown -> throughput default).
FTP family options validate value domains at task creation (active-mode
ftp-pasv=false and out-of-domain ftp-ssl rejected).

## session/actor/tests/http.rs

The session-level HTTP task face e2e suite plus its mock-origin
family.

### Fixture family

- `MockOrigin` / `spawn_mock_origin_full`: range/no-range/length/stall
  switches, optional Set-Cookie on every answer, optional slow chunked
  writes (32KiB/30ms) on both the 200 and 206 arms; records every
  Range fetch pair and every request's Cookie header. The range probe
  (bytes=0-0) is recorded but filtered out of the fetch assertions.
- `FlakyOrigin`: probes answer 206; data requests send a 206 head plus
  `drop_after` body bytes and disconnect (no reuse); `drop_after=0`
  disconnects with zero bytes. Data requests are timestamped for the
  failure-cadence / retry-gap assertions.
- Throttled variant: the first `throttle_first_n` data requests get
  429 (+ optional `Retry-After`), then normal 206s.
- Drifting variant: probes answer 206 (range-capable) while data
  requests always answer `data_status` (200 = the capability-drift
  shape, 404 = the retryable contrast).
- Range-counting origin: the 206/200 arms share one shape (stable
  Last-Modified -> strong-digest resume), 4KiB/30ms chunked writes
  (~136KiB/s per connection — the computable serial lower bound),
  keep-alive serving several extents per connection
  (worker-to-connection one-to-one, so the Range peak = the concurrent
  connection count). Probe Ranges (e == s) are not counted as
  in-flight.
- `EtagOrigin`: content flips v1 -> v2 with ETag and body together; a
  data request whose If-Match fails the strong comparison gets 412
  (RFC 9110 §13.1.1); `weak` (always `W/"w"`) and `no_etag` pin the
  frozen zero-If-Match seam. A per-request serving gate makes the flip
  atomic with serving the Nth data request, so request order is
  deterministic regardless of client connection scheduling (under load
  a 4MiB body can stall write_all on the loopback buffer — the root
  cause of flaky parallel runs without the gate).
- Cookie-gated origin: 200 only when the Cookie header carries the
  required `name=value`, 401 otherwise (the login-walled rejection
  arm); records every Cookie header.
- `MockProxy`: a raw-TCP forward proxy recording every request head
  block, always answering 200 + full body; paired with a dead origin,
  completion proves the request rode the proxy.
- `http_row_of` / `http_row_progress_of` / `http_table_count`: direct
  sqlite readers (independent WAL connections) for row-state and
  bitmap-survival assertions.

### Regression groups

- Grid download happy path: probe -> blocks -> bitmap snapshots ->
  finalize rename; the `http` sub-dictionary promised fields
  (finalUrl/blocks/blocksTotal/renamePending/sources).
- completedLength projection: byte-level and monotonic while a live
  view exists (may lead block accounting by less than one in-flight
  block); the stopped face stays the block-accounting authority;
  paused/cold rows project the row's total_done and the
  probe-authoritative total (probe_json > grid-derived > 0).
- Checksum: prefetch overlaps the slow download (unconsumed <=
  total/2 at finish), the degraded tee path verifies without a
  re-read, a mismatch fails with the canonical code plus the numeric
  32 (CHECKSUM_ERROR, `ChecksumCheckIntegrityEntry.cc`), and the
  folded imported checksum arbitrates before the rename (a bad final
  file never lands).
- Worker failure budget: partial-body disconnects reset the budget
  (progress) while zero-byte failures burn the cap and never complete;
  429 + Retry-After is honored (>= the server value, < the clamp
  scale), 429 without the header keeps the 200ms-class default pace.
- Capability drift: a probe-confirmed 200 at download time fails
  explicitly (`taiji.http.range_ignored`) and the request stream goes
  quiet after the terminal state (fatal once — the first AIMD wave's
  parallel requests are timing, not retries); an off-table 404 keeps
  the retryable unexpected_response path (>= 2 data requests).
- Resume family: kill-9 resume from a seeded row (one full-file Range
  starting at the surviving block), the row's persisted block_size is
  authoritative (a 1MiB bitmap is never reinterpreted at 4MiB),
  pause/saveSession/changeOption-restart all keep the fsynced bitmap
  and digest (a FromZero reactivation would refetch block 0), and
  after a kill-style stop a 16-connection task re-parallelizes (Range
  peak >= min(split, cap), wall time below the serial lower bound).
- Row lifecycle: forceRemove/reserved remove delete the http_task row
  (a restart never resurrects), the state value domain holds for the
  whole download (planning is runtime-only; probing is inside the
  recovery set), renamePending close-out is idempotent across
  restarts, stays pending when disk facts are missing, and skips
  (without renaming) while another task holds a creation-time claim
  on the final path.
- Option faces: the value-domain rejection table (timeout=0, socks, a
  non-bool check-certificate, a colon-less header,
  http-max-per-host=0, out-of-domain split) all reject at add with
  `taiji.option.invalid`; the runtime/persist option name tables pin
  their parse arms (observable consumption per name, unknown names
  ignored, ftp-pasv false rejected, ftp-pasv-address-check strict
  projected into FtpConfig, h2 keys pinned through to_client_config).
- changeOption concurrency sync: legal split/cap changes overwrite the
  config_json concurrency intent so recovery restarts from the latest
  effective values.
- Cookies: captures persist on the 2s write-back tick, clear
  on completion/removal (never on activation — the write-back loop's
  empty-set tick must not wipe a stored set), replay across restarts
  and in-session reactivations; `load-cookies` is fail-closed (a
  missing/oversized file rejects the task; changeOption shares the
  gate with zero mutation on rejection) with a changeGlobalOption
  global entry; AddUriWithCookies strips manual Cookie headers (the
  jar is authoritative) and SetTaskCookies gates active/non-HTTP
  tasks with the fork's verbatim text; error-terminal cleanup is
  mode-aware (one_shot clears immediately, a retention window GCs on
  the closeout tick, the default window is swept at graceful
  shutdown).
- Multi-source: a multi-URI add allocates across sources (EWMA
  shares, §4.7) and presents the same ordered set via sources/uris; a
  dead FTP source is dropped at probe failure (the failed terminal
  state shown honestly); mirrors_json persists with the row and
  survives restarts (string items tolerated, order-preserving dedup,
  a corrupt payload falls back to the single source).
- Import rescue chain: adoption rename (`f.iso` -> `f.iso.part`)
  makes fork data the resume input, auto-rename is suppressed when
  the adoption explains the final file's absence (a pre-existing
  final file conflicts explicitly instead of renaming to `.1`), and
  the digest gate degrades on the first activation so import-seeded
  bitmaps are not wiped by certain digest drift (the mock always
  sends Last-Modified; the seeded digest lacks it); imported_options
  (headers/UA/proxy/checksum) fold into the request assembly; cold
  imported rows project real totals/completions.
- If-Match conditional resume: a strong-ETag probe arms the feature;
  a mid-download content flip yields 412 -> bitmap clear -> re-probe
  -> restart from zero (fresh v2 bytes, exactly two probe rounds);
  weak and absent ETags carry zero If-Match.

### Determinism notes

- Bitmap-survival assertions ("block 0 fetched exactly once") pin
  `max-connection-per-server=1` where the choreography presumes
  sequential completion; under parallel scheduling a pause-time
  unfinished block 0 and its resume refetch are legitimate.
- The range_ignored fatal test pins quiescence after the terminal
  state, not an exact request count: the AIMD first wave may land a
  second designed-in request before teardown, which is timing, not a
  retry.
- unpause is retried until accepted: the actor refuses while the
  pause teardown (Ended event) bookkeeping is still in flight.

## session/actor/commands.rs

The SessionCommand dispatch face: the handle_command command table,
the query faces, GID resolution, the changeOption/changeUri subsets,
the ban/scheduler/file-priority/streaming/disk-tier extension faces,
and global tracker import.

### Global tracker import (bootstrap_global_trackers /
import_global_trackers)

Order = in-store restore (`global_tracker` rowid order) -> CLI seed
(`--bt-tracker` comma list + `--bt-tracker-file` ngosang parse via
`spawn_blocking`) -> persist the full set only when the seed added
anything (idempotent). A missing/oversized/badly encoded file
degrades to a warning, same as the bootstrap read failure ("treated
as fresh session"). changeGlobalOption bt-tracker/bt-tracker-file is
the runtime seam of the same importer: union-accumulate (bt-tracker
has a setChangeGlobalOption bit in OptionHandlerFactory.cc;
bt-tracker-file is a local extension), persist through the single
PersistWriter seam, hot-push running torrent engines via set_trackers
([`merge_global_trackers`] semantics — incremental URLs only, manual
addTracker/removeTracker edits preserved up front, one independent
tier per new URL, aria2 addAnnounceUri isomorphic), sync the job
mirror + config_json. The set is capped (MAX_GLOBAL_TRACKERS): at the
cap the surplus import is dropped with a warn. A bad file/value is
warned and ignored ("unacceptable options ignored"), never a wrong
reply and never an interruption of the other hot-changeable keys.

### Command-surface notes

- Shutdown clears the cookies of error-terminal tasks (active/paused
  cookies survive for restart resume; a SIGKILL residue is bounded by
  the 24h GC); the reply follows the sweep.
- AddUri replies before pump (the client reply never waits for
  activation); instrumentation only observes.
- pauseAll/forcePauseAll mirror pauseAllDownloads (RpcMethodImpl.cc):
  pauseRequested per group over active + reserved; the force branch
  adds setForceHaltRequested(true, NONE) (skip tracker notification);
  per-group pause failures do not short-circuit; checking tasks get
  the pause intent recorded and reserved rows persist paused.
- MoveStorage/RenameFile resolve the GID then answer NotSupported
  (SPEC §8.2).
- GetCapabilities collects from the policy/feature registry and adds
  taiji.* method names plus the RecoveryEventKind notification method
  names (extension events never re-face under --rpc-aria2-compat).
- Query faces (RpcMethodImpl.cc): tellStatus/getFiles aggregate
  active/waiting then results with the reference error texts;
  getPeers returns an empty table (not an error) without a peer face;
  getServers serves ACTIVE groups only and — declared diff — emits
  one aggregated row per source (aria2: one per in-flight request)
  with the aria2 value-domain projection of the http.sources ledger
  (terminal states never collapse to waiting) and per-source measured
  rates; getUris uses spent/remaining semantics ("used" once
  activated, "waiting" before the first run) and errors on stopped
  tasks like findGroup; getGlobalStat sums per-engine 10s sliding
  windows plus the HTTP live rate, reading engines through the status
  snapshot cache (invalidated by TaskNotice).
- changePosition validates the waiting-queue domain
  (`changeReservedGroupPosition` -1 text), reorders via
  QueueMan::move_reserved (IndexedList.h), renumbers + persists only
  on an actual move, and never pumps (a non-empty waiting queue
  implies full slots).
- changeOption: waiting merges the payload (effective at activation);
  active uses restart semantics (pauseRequestGroup +
  setRestartRequested). HTTP known-option domain violations reject
  the whole call (`taiji.option.invalid`) under
  validate-all-before-mutate (the persist/runtime/scheduler parses
  plus the max-chunk cross-key check precede any merge; baseline
  merging keeps absent keys). select-file is reserved-only (explicit
  rejection on active tasks, non-BT tasks, and so= conflicts);
  bt-sequential-download shares that gate; per-task rate limits
  apply live on active tasks; bt-disable-dht hot-pushes to the
  running engine; load-cookies swaps the seed whole-set fail-closed
  and strips manual Cookie headers. dir applies only to
  never-activated tasks.
- setTaskCookies: the fork's state gate and verbatim text
  (RpcMethodImpl.cc), persist-first whole-set replacement (expired
  entries dropped), then the in-memory seed overwrite.
- getOption echoes only accepted keys with a per-task truth source;
  active rate limits echo the live bucket values (echo face = effect
  face); the result domain reads download_result / http_task rows
  and answers empty honestly when absent. `bt-max-peers` parses but
  has no per-task payload and is omitted; max-tries infinity echoes
  "0".
- changeUri restores the upstream arm order with a declared no-op
  operation face: fileIndex is checked against the job shape's
  file-entry count (Torrent = metainfo entries; magnet/TorrentUrl/
  Http = 1), errors use the reference texts, and the URI operation
  always returns [0,0] (no file-entry URI ledger; the engine has no
  source-change seam).
- addTracker/removeTracker: shape-gated (metadata tasks are not
  editable before upgrade; HTTP has no tracker face; terminal
  payloads are gone and never rebuilt, so accepting would be a
  disguise); active tasks get SetTrackers immediately (receipt first
  — a failure mutates nothing) + mirror + config_json; waiting tasks
  get payload + config_json only.
- setSchedulerPolicy/getSchedulerPolicy: supported-policy validation
  (sequential unimplemented -> explicit Err), torrent tasks only
  (metadata tasks refused, as in changeUri), an atomic engine policy
  swap, and config_json persistence; non-torrent/finished tasks
  answer the default.
- setFilePriority: decided pairs, validate-before-mutate (1-based ->
  0-based, level domain -1..=7, duplicates and out-of-range
  rejected, file count = non-padding metadata entries), an empty
  selection rejected (the engine rejects an empty mask), live
  SetFileSelection + SetFilePriority as a pair (an all-zero table is
  sent as a single (0,0) placeholder), mirror + config_json;
  engineless tasks persist only and push at activation.
- setStreamingPlayhead: torrent + running engine only; forwarded to
  the engine and awaited; never mirrored or persisted (a transient
  cursor; the caller replays by progress after a restart).
- get/setDiskTier: mirror/config_json truth via DiskPolicy::resolve;
  the live engine gets SetDiskPolicy immediately; prealloc/falloc
  applies to new allocations only.
- Ban face: banAddr/unbanAddr/listBans keep a manual bookkeeping
  (normalized targets, a cap, timed/permanent) mirrored into
  peer_ban (reason=manual) and re-pushed to every running engine
  plus the metadata-phase session IpGuard snapshot (arc-swap; live
  magnet tasks read it per dial). Auto/client bans lift at expiry
  and have no RPC removal face. listBans = manual bookkeeping ∪
  active peer_ban rows (manual rows deduped with the bookkeeping as
  authority), sorted by (source, target). Bootstrap restores the kv
  prefix list (kv truth overrides option initials) and manual
  peer_ban rows (corrupt rows warn and skip).

## session/actor/http_task.rs

Sources: aria2 `File.cc`, `HttpDownloadCommand.cc`, `HttpServerBodyCommand.cc`,
`ChecksumCheckIntegrityEntry.cc`, `DigestAuth.cc`; RFC 1321, FIPS 180-4,
RFC 6265 §5.4, RFC 3659, RFC 7540 §5.2.2.

### Why --max-connection-per-server defaults to 16 (upstream divergence)

aria2 defaults the option to 1: upstream `-x1` means a single connection for a
single-URL download. Under this repo's AIMD execution loop a cap of 1 pins the
whole growth face:

- `AimdConfig::with_start` clamps the slow-start start into the cap domain, so
  with cap 1 the growth domain [start, cap] collapses to an empty set and
  `AimdController::grow` can only Hold at the cap - the gain criterion has
  nothing left to judge.
- The worker pool's desired count is pinned to 1: the snapshot -> spawn
  directive chain is healthy, but the snapshot value is clamped to 1.
- The multiplicative-decrease recovery path (rebuild window + optimistic probe
  back to cap) has no room under cap 1 either.

The default therefore moves to the domain ceiling 16 (the plateau). The
constant is a ceiling, never a connection hard cap: the count still climbs
adaptively by the AIMD criterion (start = the `--split` default 5; >=10% gain
doubling; threshold convergence; multiplicative decrease/recovery unchanged -
the decision-table regression pins live in taiji-http `aimd.rs`). An explicit
`--max-connection-per-server=1` still pins a single connection (domain
1..=16 unchanged). Declared in docs/rpc-api-diff.md.

### Fast-path range planning vs upstream

`small_task_ranges` cuts the whole file into k = min(`--split`,
`--max-connection-per-server`) near-equal byte intervals. This mirrors
aria2_next's per-file range planning; aria2 classic stays single-connection
for a small file when min-split-size exceeds the file size (e.g. 1MiB at a
1MiB floor). The fast path is deliberately NOT bound by the min-split-size
floor (declared in docs/rpc-api-diff.md).

### Checksum completion verdict anchoring

The verify-before-rename position is aria2 `ChecksumCheckIntegrityEntry.cc`:
verify at completion; failure = task error; the `.part` stays on disk for
inspection; the bitmap is untouched. The grid path pipelines the hash over
the contiguous completed prefix (two-phase watermarks + writer
double-checks; invalidation/timeout falls back to the full post-hoc hash);
degraded/EOF sequential streams feed a tee digest on the write path;
`drive_small` and the empty file keep the post-hoc face. Fail-closed and
mismatch-rejects-rename hold across all four verdict points. Algorithm
domain: md5|sha-1|sha-224|sha-256|sha-384|sha-512 with hex expectations
(RFC 1321 + FIPS 180-4).

### Credential slots

`--http-user/--http-passwd` and `--ftp-user/--ftp-passwd` are separate
per-protocol slots, isomorphic to aria2's. The http slot serves both Basic
pre-auth and the 401 Digest challenge response (`DigestAuth.cc` isomorphic);
the ftp slot applies to FTP probing and fetching. FTP precedence:
URI userinfo > the ftp slot > anonymous/anonymous@. FTP has no proxy face
(FTP over an HTTP proxy is a declared divergence).

### Boundary honesty inventory (former module-header declaration)

- Wired runtime groups: `--timeout` (one value shared by the reqwest read
  timeout and the task-level read-idle home), `--connect-timeout`,
  `--max-tries`/`--retry-wait`, `--user-agent`, `--header`,
  `--http-user/--http-passwd`, `--all-proxy` (http/https),
  `--check-certificate`, `--remote-time`, `--http-max-per-host`
  (session-shared per-host registry). Scheduling group: `--split`/
  `--min-split-size` (redefined semantics in dynamic mode - an
  initial-extent reference only; static = segment count / minimum segment
  length), `--max-connection-per-server` (the AIMD growth cap, 1..=16),
  `--http-stall-window` (the stall-steal decision window). Guided assembly
  keys: `--http-block-size` (4MiB), `--http-max-chunk` (32MiB). Scheduler
  default = dynamic (guided self-scheduling + AIMD connection loop +
  stall-steal); static is kept as the control/fallback baseline (fixed
  segmentation, no AIMD/steal).
- The dynamic assembly adds the stall-steal worker-side loop (taiji-http
  `ExtentHeartbeat`: per-extent byte heartbeat production, write-permit
  cancel consumption, block-completion edge reporting; worker park/idle
  branches wire `request_steal`) - dynamic-only, the static baseline
  untouched.
- The extent-line lease floor is the engine-internal sub-block constant
  block/4; `--http-min-chunk` is NOT wired and is ignored as an unknown key,
  consistent with the declared-unwired option table
  (`DECLARED_UNWIRED_OPTION_NAMES`); persistence/bookkeeping stay
  block-aligned.
- Multi-source: probing is serial in user order; segmentation consumes the
  multi-source assembly - the source ledger (EWMA weighted share
  arbitration, demotion after repeated degradation, removal after repeated
  failures, the all-sources-removed negative close-out) belongs to the
  coordinator's `spawn_dynamic_multi` (active when sources > 1); per-source
  rates are measured at sink write points (`SourceTaggedSink` attribution).
- ftp/ftps sources are always accepted: probing =
  `FtpTransport::probe` (SIZE + `REST 0`; SIZE unsupported drops the source
  - a declared divergence; aria2 can stream without a total). `ftps://`
  scheme URIs are refused - FTPS is expressed as `ftp://` + `--ftp-ssl`.
  The PASV/EPSV data-connection address check defaults to the SSRF-hardened
  aligned state (`--ftp-pasv-address-check`).
- renamePending close-out is three-layer (bootstrap replay of done+pending
  rows, in-session periodic polling, the in-process driver-side journal
  ledger); `--remote-time` is not replayed on close-out retries (they carry
  no probe record - an honest gap).
- The cancel path never forces an fsync (1s shutdown budget): the bitmap may
  lag by at most ~2s and refetching unconfirmed blocks is the safe direction
  - prefer under-recording progress to overstating it.
- Runtime options are not persisted: restored tasks are rebuilt from
  defaults + the new session's options (timeouts/credentials/proxy travel
  with the session); the persisted items are suffix/checksum/remote-time
  (`HttpPersistConfig`).
- Cookie lifecycle: per-task store, periodic write-back with
  row-level comparison, RFC 6265 §5.4 condensed request-face replay,
  clear on completion/removal - never on activation; cookies survive error
  terminals in the resident form (24h GC + shutdown sweep own cleanup).
