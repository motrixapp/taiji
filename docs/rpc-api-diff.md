# taiji–aria2 differential declaration (RPC / option surface · v1.1)

English | [简体中文](./rpc-api-diff.zh-CN.md)

This file is the **controlled list (whitelist) of every known behavioral difference**
between the taiji engine and aria2 (the retirement counterpart being the aria2 fork,
hereafter "the fork"). Governance rules:

- The gate criterion of the full RPC/option differential is **zero differences outside
  the whitelist**; any difference not listed in this file is treated as a defect and
  must be fixed in code or by revising this file (via PR + user approval).
- Cross-validation method: live two-process cross-validation with identical inputs —
  taiji runs with `--rpc-aria2-compat` mode + sqlite persistence (the Motrix runtime
  shape; method/event names strictly isomorphic to the fork's, only one API surface at
  any moment), the fork starts with `--enable-rpc --enable-sqlite3-persistence` (the
  Motrix runtime shape); same fixture, same parameters, method-by-method comparison of
  response shapes / error codes / error messages / event names. The reproducibility
  guard = the integration test `crates/taiji-rpc/tests/aria2_compat_live_diff.rs`
  (the reference binary is designated via the `TAIJI_DIFF_ARIA2C` environment variable;
  by default the workspace sibling checkouts `aria2/src/aria2c` (the upstream layout)
  and the Motrix fork layout `aria2_motrix/src/aria2c` are probed; **when unavailable the test is red by
  default** — zero comparisons must never claim a fully
  green differential; only an explicit `TAIJI_DIFF_ALLOW_SKIP=1` downgrades to a SKIP
  green, with the machine-readable marker `SKIP(taiji.rpc.live-diff): …` in the output,
  which downgrade consumers must also check). Source-level static cross-validation
  (read-only `src/` references) is the second line of evidence.
- Every entry is annotated with an in-repo **code anchor** (the declared single
  source); the bidirectional completeness of the entry set and the anchors is checked
  by the differential test.

## 1. API surface

| Entry | fork behavior | taiji behavior | Anchor |
|---|---|---|---|
| Namespace | `aria2.*` | canonical = `taiji.*`; enabling `--rpc-aria2-compat` (default false, session-level) = `aria2.*` aliases + `aria2.onXxx` events + listMethods/listNotifications present the aria2 surface (the membership set is committed; table order is not); **only one API surface exists at any moment; dual emission is forbidden** | `taiji-rpc::dispatch` (the `canonical_method` single point) |
| Method-face missing entries (fork-specific persistence, checkpoint import and HTTP retry) | Fork-version-dependent `getDownloadResultCount`, `searchDownloadResult`, `exportSession`, `requeueDownloadResult`, `getCheckpointStatus`, `addLegacyTorrentV1`, `inspectLegacyCheckpointV1`, `importLegacyCheckpointV1`, `reconcileLegacyCheckpointV1`, `getHttpRetryStatusV1`, `retryHttpDownloadV1` | taiji does not implement these legacy methods; use native SQLite sessions, offline import and native HTTP retry. Compat calls return `No such method: aria2.X`. Cookie methods remain available under `taiji.*`, without `aria2.*` aliases | `taiji-rpc/tests/aria2_compat_live_diff.rs` compares the exact declared names present in the reference build; undeclared additions still fail |
| Task-level cookie family accepted (a reversal of the early stance, Motrix baseline; `addUriWithCookies`/`setTaskCookies`) | The fork's same-name `aria2.*` method pair (`RpcMethodFactory.cc`; `parseRpcCookies` = `RpcCookie.cc`: ≤300 entries / field whitelist name,value,domain,path,hostOnly,secure,httpOnly,expiresAt / syntax-domain checks / expiry = non-negative Unix milliseconds ≤2^53-1 / expired records never enter active storage; `AddUriWithCookies` = an http(s)-only gate on all URIs + structured cookies authoritative (hand-written `Cookie:` headers stripped, `RpcMethodImpl.cc`); `SetTaskCookies` = waiting/paused only + the `require-task-cookies` bit + sqlite persistence first) | **Accepted (2026-10-04 user reversal — the original decision's premise no longer holds: the storage exists while the entry points are all empty, "the same need was left unclaimed")**; canonical single names `taiji.addUriWithCookies`/`taiji.setTaskCookies` (14→16 names): the parameter surface is cross-validated verbatim against `parseRpcCookies` (crate `taiji-rpc::rpc_cookies`); cookies enter the task CookieStore (the same storage surface as `--load-cookies`, injected through the taiji-http `CookieStore::seed/replace_with` seam); `.torrent` URL intake is tightened to rejection (the metadata-fetch surface has no cookie consumption point). The `setTaskCookies` state gate = waiting/paused + HTTP task shape (the fork additionally requires the `require-task-cookies` preference bit — its task storage is opt-in, whereas this side's HTTP tasks always carry storage; the equivalent surface is relaxed, declared as a difference); persistence = the cookie-row upsert (cross-validated against the fork's replaceTaskCookies; a persistence-first failure means zero mutation). Both methods are write-surface methods (rejected by the write gate when no secret is set). **The compat surface does not project `aria2.*` aliases** — same-name fork calls always land on `"No such method"` (pinned by the live diff) | `taiji-rpc::rpc_cookies` (the parse seam) + `taiji-rpc::dispatch::tests` (`taiji_cookie_methods_shape_receipts_and_gates`) + `taiji-core::session::actor::tests` (`add_uri_with_cookies_*`/`set_task_cookies_*`) |
| `taiji.*` extension methods (17 names) | none | `moveStorage`/`renameFile`/`banAddr`/`unbanAddr`/`listBans`/`setSchedulerPolicy`/`getSchedulerPolicy`/`setFilePriority`/`setStreamingPlayhead`/`getDiskTier`/`setDiskTier`/`getCapabilities`/`createTorrent`/`addTracker`/`removeTracker`/`addUriWithCookies`/`setTaskCookies` — present under the same names in both modes (`setFilePriority` = multi-level file priority for HTTP tasks — a native extension aligned with libtorrent's `file_priority`/`prioritize_files` capability: the value domain -1/0/1..7 is set natively (aria2 has no counterpart surface); partial-update pairs form vs whole-set vector form declared as a difference; -1 composes with the select-file selection surface) (`moveStorage` = the implemented storage-migration face: same-volume/cross-volume payload migration + config_json move-journal crash safety; `renameFile` stays not_supported; (`addTracker`/`removeTracker` = scheme-B dynamic tracker editing for HTTP tasks; `addUriWithCookies`/`setTaskCookies` = the direct cookie-passing surface for HTTP tasks — dedicated entry above; the compat surface does not project `aria2.*` aliases: the first two methods have no fork counterpart, the latter two exist on the fork but are accepted under the §1 decision as `taiji.*` canonical) | `taiji-core::session` (`RPC_METHODS`) |
| **Method-face addition: `forceRecheck` (no upstream counterpart)** | none (neither upstream aria2 1.37.0 nor the fork's registered surface has a recheck RPC — the fork's live registered surface = 36 upstream + 4 fork-only additions, with no such name; a call lands on `"No such method: aria2.forceRecheck"`) | a taiji capability extension (**not** a commitment tightening): bare `forceRecheck` is registered; canonical `taiji.forceRecheck` / compat `aria2.forceRecheck` / bare name — all three forms accepted, same name, same meaning. Semantics: torrent tasks only (magnet / metadata / HTTP tasks and terminal-state entries explicitly Err; explicit Err when no persistence form exists); active = graceful stop (pause wind-down semantics) → full verification → requeue and reactivate; reserved/paused = dequeue, verify, then return to the queue head (pause intent preserved); during verification `torrent.state='checking'` (same shape as crash recovery) + TellStatus `status=active`, `completedLength` projected as verified pieces × piece_length (aria2 has no separate status value during verification; cross-validation in the same direction); on completion the measured bitmap is written back to the progress row (corrupt pieces reset to zero and re-downloaded, complete payload turns to seeding), receipt = gid. The aria2 ecosystem's recheck remedy surface (`--check-integrity` / re-adding) is thereby RPC-ized | `taiji-core::session` (`RPC_METHODS`/`SessionCommand::ForceRecheck`), `taiji-core::session::actor::tasks` (`force_recheck`/`spawn_recheck`/`finish_recheck`), `taiji-rpc::dispatch::tests` (`PROMISED_TAIJI_BARE_EXTENSIONS`) |
| **Media-line methods (5 names, the unified media registration)** | none (upstream aria2 has no media surface; the fork likewise) | `taiji.addMedia(url, options?)` / `taiji.probeMedia(url)` / `taiji.getMediaFormats(gid)` / `taiji.stopRecording(gid)` / `taiji.clearMediaArchive()` — present under the same names in both modes (no `aria2.*` alias projection; no bare-name form — dotted extension literals). read_only adjudication (§9): addMedia **write** / probeMedia **write** (the §4 probe is an action surface — an outbound request + the server-side snapshot cache; no secret = fail-closed, same posture as the write faces) / getMediaFormats **read** / stopRecording **write** / clearMediaArchive **write** (a destructive whole-table clear of the download archive — the sensitivity-browsing-history face; no secret = fail-closed, the purge-family rule; replies `{"removed": N}`; after a clear the same fingerprints re-download). addMedia options = the selector three-layer face (`media-selector`: presets/predicates/`format_id=` escape hatch, multi-value = explicit multi-stream) + subtitles/metadata/template + the structured cookie direct pass (`options.cookies`, the `parseRpcCookies` cross-validated shape) + `probe-token` (server snapshot retrieval — a client-submitted format-tree blob is never accepted, §4 anti-forgery); entry classification runs in the task's Resolving phase (a direct media file converts to the HTTP task family with the same GID — the zero-new-surface rule; a non-media entry = `taiji.media.not_media`). probeMedia returns an opaque token + TTL 10min (`taiji.media.probe_expired` on expiry/unknown/mismatch); global in-flight cap 2 + per-origin rate limit (1/s). getMediaFormats = the media_format row query (row-driven — answers after the terminal teardown too). stopRecording = registration + dispatch only (a VOD task answers the explicit "not a recording task" error; the LIVE executor is not implemented) | `taiji-core::session::command` (`RPC_METHOD_INFO` descriptors + the frozen anchor tests) + `taiji-core::session::actor` (`add_media`/`spawn_probe`/`get_media_formats`/`stop_recording`) + `crates/taiji-core/tests/media_task_e2e.rs` |
| **addTorrent initial verification of complete payloads** | when addTorrent points at a directory whose payload is already complete, the fork resumes via its existing storage probing (when bitmap/control files are present); taiji's comparison surface (external payload without control files) re-downloads from zero | taiji schedules an **initial full verification** for external already-complete payloads (files in the directory match the torrent's per-file lengths, not paused, with a session library): `torrent.state='checking'` → measured bitmap written back to the progress row → requeued and activated, the engine resumes per the bitmap (complete = `completedLength==totalLength` → `seed_after_complete` turns to seeding). Partial/missing payloads keep downloading from zero (spec scope = complete payloads). The fork's divergent cross-validation behavior stems from its control-file mechanism being structurally different from taiji's sqlite bitmap-resume surface; it is a catch-up surface for a storage-shape difference | `taiji-core::session::actor::tasks` (the `add_torrent` `payload_complete` gate + `spawn_recheck`) |
| Extension events | none | `taiji.recoveryStarted`/`taiji.recoveryCompleted` (always `taiji.*`, never switched through compat); **`taiji.media.phaseChanged`** (the same bypass: not in the compat switch, not in the six-event table, `system.listNotifications` does not grow; payload `[{gid, phase, phaseDetail?, warning?{code,message}}]` — the media line's alarms (sidecar degradation / both-channels failure / sidecar splice failure, `template_unsafe`) ride the same face with the `warning` key distinguishing alarms from transitions; declared via `taiji.getCapabilities`'s notifications list) | `taiji-core::session::events` (`MEDIA_PHASE_EVENT_METHOD`) + `taiji-rpc::server` (`media_notification_frame`, the WS third arm) |
| The six event names | `aria2.onXxx` | the compat surface is verbatim-identical (the same six entries, with the native HTTP output event added separately); the canonical surface = `taiji.onXxx`; the `[{gid}]` payload unchanged | `taiji-rpc::dispatch` (`RPC_NOTIFICATIONS_ARIA2`) |
| Bare-name acceptance | a bare name (`addUri`) = unknown method: `"No such method: addUri"` (the fork only accepts registered full names) | the canonical committed surface always accepts bare names (a Phase A commitment, kept in compat mode) — a taiji superset: the same method accepts the `aria2.X` alias, the `taiji.X` alias, and the bare name, three forms | `taiji-rpc::dispatch` (the `canonical_method` exact-match arm) |
| Unauthenticated write gate | with no `--rpc-secret` set, write methods execute as usual (loopback-only listening) | with no credentials set, **all write methods fail closed** (`"unauthenticated write requires --rpc-secret"`; the query surface and `system.list*` are unrestricted) — a security enhancement | `taiji-rpc::dispatch` (`is_read_only`/the write gate) |
| Mode surface (the three states of RPC and download forms) | three states: pure download (no `--enable-rpc`) / pure daemon (`--enable-rpc`, no URIs) / **download + RPC in one process** (`--enable-rpc` coexisting with CLI URIs/torrents — the `DownloadEngineFactory.cc` enable-rpc branch does not parameterize URI presence; RPC listener assembly and the download loop execute in the same process; `PREF_ENABLE_RPC` defaults to false, `OptionHandlerFactory.cc`). RPC-group options given while this option is off are silently stored but unused | three states, same shape: pure download (bare engine-loop run, `--enable-rpc=false` default — zero behavior change on that path) / pure daemon (no positional arguments = idle, RPC always on) / download + RPC (`--enable-rpc`: the engine path shares the SessionActor pipeline with idle; torrents are injected **directly** as AddTorrent session commands — no RPC self-calls, bypassing the write gate and credential requirement, cross-validated as isomorphic to upstream's in-engine direct configuration; tasks seed and stay resident, the process stays resident until signal/RPC shutdown). **Silent no-op removed (a tightening declaration)**: if the download mode receives RPC-group options (`rpc-listen-port`/`rpc-secret`/`rpc-user`/`rpc-passwd`/`rpc-aria2-compat`) while `--enable-rpc` is not in effect → hard error exit 2 (stderr, same stream and code as a clap usage error, with wording pointing to adding `--enable-rpc`) — upstream silently stores this combination unused | `taiji::main` (`run_download_with_rpc`/`rpc_group_conflict`) + `crates/taiji/tests/download_rpc_e2e.rs` (lifecycle e2e / bare-run snapshot / conflict arms) |
| `changeUri` semantics (scheme A closure) | file-entry URI editing (`RpcMethodImpl.cc` = file-entry `removeUri`/`insertUri`/`addUri`; arm order: a gid miss answers verbatim `"Cannot remove URIs from GID#%s"` (`findGroup` excludes terminal states) → the fileIndex domain check answers verbatim `"fileIndex is out of range"` → count receipt `[deleted, added]`; a BT file entry has no URI list → the del arm yields `[0,0]`, the add arm enqueues parseable URIs and counts `[0,N]` (`FileEntry.cc` has no protocol split — consumed by the webseed surface); HTTP = true-source ledger editing (`FileEntry.cc` deletes on hit and withdraws in-flight requests) | same arm order and verbatim error messages (the fileIndex domain follows the task shape's file-entry count: Torrent = metainfo file entries, magnet/TorrentUrl/Http = 1); **gap declaration**: this side has no file-entry URI ledger (BEP19 webseeds are not consumed — declared on the addTorrent surface; the live HTTP source ledger = the driver's sources, and the engine surface has no source-mutation seam) → every shape yields a `[0,0]` no-op — upstream's real add/del counts (BT `[0,N]` / HTTP `[del,N]`) are not committed. The hijacked dynamic tracker editing has been removed (the original `apply_tracker_change` + `SetTrackers` call sites were extracted); the tracker-editing extension surface **has landed per scheme B** (user-approved 2026-10-04): `taiji.addTracker`/`removeTracker` enter the committed set (§1 extension row, 12→14 names), the mechanism reuses the existing SetTrackers engine coupling + config_json persistence; the API surface is an entirely new design | `taiji-core::session::actor::commands.rs` (the `change_uri` arm order and anchor note + the `add_tracker`/`remove_tracker` editing surface) + `taiji-rpc::dispatch::tests` (`change_uri_positional_shape_and_counts` + `taiji_tracker_methods_shape_receipts_and_gates`) + `taiji-core::session::actor::tests` (`change_uri_upstream_file_entry_semantics` + `taiji_tracker_edit_*`) |

Native magnet selection adds `taiji.getTorrentMetadata` and `taiji.confirmTorrentSelection`, without `aria2.*` aliases. The selection barrier and commit contract are documented in the [RPC API](rpc-api.md#magnet-selection-without-replacing-the-task).

## 2. getVersion

- `version`: fork = the bare version string (`1.37.0`); taiji = the `taiji/<semver>`
  prefix (Motrix recognizes the engine by this prefix — the carrier of the switch
  assertion). The shape `{version, enabledFeatures}` matches on both sides.
- `enabledFeatures`: taiji lists only real capabilities out of **honesty**
  (`Async DNS`/`BitTorrent`/`HTTP`/`HTTPS`/`GZip`/`Metalink` (behind the feature
  gate, presented accurately at compile time)); the fork's list includes its
  self-built surfaces (`Firefox3 Cookie`/`Message Digest`/`XML-RPC`/
  `SQLite3-Persistence`, etc.). The two lists are **not promised equal**, only that
  every entry is real.
- Anchor: `taiji-rpc::dispatch::view` (`ENABLED_FEATURES`).

## 3. Option surface (getGlobalOption / changeGlobalOption / changeOption)

- **Echo-surface direction**: the fork echoes its complete global option table
  (about 130 keys); taiji echoes the Phase A committed subset plus the extensions in
  the next bullet (about 30 keys). The full set of fork-only keys is declared by this
  entry; taiji does not promise to complete the full-table echo.
- **taiji-only echo keys** (not echoed by the fork): the Phase A extension/rename
  pairs (`bt-lsd`↔`bt-enable-lpd`, `bt-tracker-file`, `bt-peer-connection-type`,
  `bt-enable-upnp`, `bt-enable-nat-pmp`, `max-connection`,
  `client-ban-prefixes`, `bt-metadata-web-sources`), the hook notification family
  (`on-download-*`/`on-bt-download-complete`), `save-session`, `seed-time`,
  `bt-tracker` (the fork silently ignores this key when the global value is changed
  via RPC; taiji imports it cumulatively as a union and echoes it), plus the 0.2
  extension keys (the HTTP scheduling group §8, `http-incomplete-suffix`/
  `http-max-per-host`, FTPS `ftp-ssl` §8, the metalink seam names §6), plus the
  four-pool budget trio (`max-concurrent-seeds`/`max-concurrent-checks`/
  `media-synthesis-concurrency`, the dedicated entry below) — **the
  authoritative full set is the anchor table**. Anchor:
  `taiji-core::session::options` (`DECLARED_OPTION_DIFFS`).
  Among these, `http-max-per-host` has since actually entered the getGlobalOption
  echo (the echo = the effective cap value — kept in sync with the session HostCap
  initialization value and last-set-wins adjustments via the addUri option, no
  drift; default 64, r7.1; the CLI/global `--http-max-per-host` is a startup-time
  option, not accepted by changeGlobalOption, effective after restart).
- **taiji-only echo keys, accepted-value faces (the 2026-10-28 echo audit — every
  key ruled a legitimate extension; the live-diff budget = the audited table
  pinned in `crates/taiji-rpc/tests/aria2_compat_live_diff.rs`; later additions extend
  the four-pool budget trio rows)**: the
  fork's `getGlobalOption` returns **defined prefs only** (`RpcMethodImpl.cc`
  skips entries not present in the global option table; verified live
  2026-10-28 — a default startup echoes 132 defined keys, and a NO_DEFAULT pref
  such as `all-proxy` appears only once set on the command line). taiji instead
  always echoes the accepted value face (empty string = unset) — the
  Motrix-alignment round-trip — so these aria2-name keys are taiji-only at the
  default cross-validation shape: `all-proxy` / `https-proxy` (per-task proxy
  slots; the global face records the value — no global
  proxy-default consume seam), `async-dns` / `enable-async-dns6` (resolver
  shape no-op value faces), `bt-exclude-tracker` (no exclusion face
  — the value face records the Motrix tracker-manager placeholder), `pause`
  (no global pause template face; the reference has no changeGlobal bit — the
  Motrix completed-task-startup-guard value face), `dht-entry-point`
  (startup-group session field; unset = the empty string), `load-cookies` (the
  dedicated entry below).
- **Shared-key value differences** (3 Phase A declarations + the Motrix-alignment
  no-op value faces; the 2026-10-28 echo audit):
  - `listen-port`: fork default `6881-6999` (a range); taiji `6881` (a single value);
  - `peer-id-prefix`: fork `A2-1-37-0-`; taiji `-TJ0001-` (a namespacing decision);
  - `seed-ratio`: fork default literal `1.0`; taiji the minimal numeric form `1`
    (numerically equal; the echo takes the minimal f64 form and does not fabricate
    precision);
  - the Motrix-alignment no-op value-face rows shared with the fork's echo
    (`connect-timeout`/`continue`/`max-connection-per-server`/`max-download-result`/
    `max-file-not-found`/`max-mmap-limit`/`max-resume-failure-tries`/`max-tries`/
    `min-split-size`/`remote-time`/`retry-wait`/`split`/`timeout`/`user-agent`):
    unset no-op value faces echo the empty string (no override recorded — the
    round-trip face of the value the frontend last sent), while the fork echoes
    its **defined defaults** for the same keys (defaults are defined prefs
    there); the divergence direction = the same accepted-value-face family as
    the taiji-only echo keys above.
- **Invalid-value semantics**: when `changeGlobalOption`/`changeOption` receives a
  known key with an invalid value, the fork errors out (`"We encountered a problem
  while processing the option '--X'."`); taiji narrows this to **ignoring** the key
  (the same path as an unknown key). Exception: for HTTP tasks, an out-of-domain
  scheduler value passed to `changeOption` (e.g. `max-connection-per-server` outside
  1..64) is explicitly rejected by taiji (`taiji.option.invalid`, no truncation) —
  enhanced semantics.
- **`select-file` (the BEP53 file-selection surface; acceptance-surface differences
  in three directions)**: fork = IntegerRangeOptionHandler (1-based, comma + closed
  intervals `1-3,5`, domain 1..1M; the INITIAL + reserved-change bits, not changeable
  while running, `OptionHandlerFactory.cc`); taiji accepts the same semantic bits
  (addTorrent / addUri(magnet) options / changeOption Reserved(Paused); the internal
  data surface is uniformly 0-based `config_json.selected_files`, sharing the magnet
  `so=` persistence channel and the engine consumption point `SetFileSelection`);
  three tightenings declared explicitly: (1) an invalid value for the known key is
  rejected wholesale with `taiji.option.invalid` — empty strings / empty items /
  containing 0 / out of domain / duplicates / out of order / overlapping or inverted
  intervals / non-decimal (the fork only errors on non-numeric values and incomplete
  intervals; duplicates and disorder are absorbed via `SegList::normalize`, and
  out-of-range indexes leave a silently empty filter after group-creation
  `setFileFilter`, `download_helper.cc`); (2) **changeOption on an Active task =
  explicit rejection** (the fork ignores it as a non-changeable key, `RpcMethod.cc`);
  (3) coexistence of magnet `so=` and this key = explicit conflict rejection (a
  single source for the selection surface; the fork has no `so=` surface, so there is
  no counterpart). Also: changeOption of this key for non-BT tasks (HTTP/.torrent
  URL) = explicit rejection (acceptance without effect would be a masquerade). Live
  reselection (libtorrent's `prioritize_files`, available at any time) is listed as a
  `taiji.*` extension candidate and is not part of this surface. Anchor:
  `taiji-core::session::options` (the `parse_select_file`/`select_file_range_error`/
  `resolve_select_file_for_meta` single-point family + the semantic-difference
  declaration block).
- **`summary-interval` (the periodic task-summary log interval in seconds; newly
  accepted in 0.2)**: the same-named aria2 item (`prefs.cc`; `OptionHandlerFactory.cc`
  default "60", domain 0..INT32_MAX, 0 = disabled — taiji has the same default and
  value domain, with the constants `SUMMARY_INTERVAL_DEFAULT`/`SUMMARY_INTERVAL_MAX`
  as the single source). taiji semantics: every N seconds the session emits one INFO
  summary per active task (gid / speed / progress / connection count, target
  `taiji::core::summary`); periods with no active tasks emit no event. Carrier
  difference (declared intentionally): aria2 prints summaries to the console readout;
  taiji has no console readout, so a summary = a tracing INFO event (the same surface
  for the frontend and the file log). **Capability bits aligned with the reference:
  neither changeOption nor changeGlobalOption accepts it** (the reference factory's
  handler has no setChangeOption/setChangeGlobalOption bit; taiji's
  `apply_global_patch` has no such arm — a passed key is ignored as unknown); a
  startup-time option, effective after restart. Acceptance surface: CLI
  `--summary-interval` (`taiji` idle mode and the `taiji http` subcommand; an
  out-of-domain value errors at startup) + the getGlobalOption echo. Anchors:
  `taiji-core::session::options` (acceptance-name registration + name/default/domain/
  capability-bit cross-validation tests), `taiji-core::session::actor::summary`
  (the summary seam), `taiji-rpc::dispatch::tests` (RPC-surface e2e: echo +
  non-acceptance).
- **`enable-dht` (the hot session-level DHT toggle)**: upstream aria2's enable-dht
  handler has **no** `setChangeGlobalOption` bit (`OptionHandlerFactory.cc`) — the
  fork cannot hot-reload it (effective after restart); taiji **accepts runtime hot
  updates** (the `changeGlobalOption` value surface + hot push into a running BT
  engine: DHT engine spawn/teardown, the handshake bit, and announce registration
  take effect immediately; a stalled trackerless task revives as soon as it is
  hot-enabled — the capability reference is libtorrent's `settings_pack::enable_dht`
  taking effect at runtime via `apply_settings`). **Explicit difference declaration:
  a taiji extension** (expanding the fork's non-changeable set). `enable-dht6` is
  accepted as the same kind of key (value-surface echo + capability-bit view); taiji
  has no independent v6 DHT gate (the v6 DHT surface follows the `enable-dht` master
  gate + the IPv6 connectivity gate; `enable-dht6` currently does not change the
  engine wiring — declared accurately). Anchors:
  `taiji-core::session::actor::commands` (the `push_dht_session_change` +
  `effective_task_dht` synthesis single point), `taiji-core::engine::command`
  (`EngineCommand::SetDhtEnabled`), `taiji-core::engine::dht` (the `DhtInboundGate`
  runtime gate).
- **`bt-sequential-download` (accepted in projection form)**: the same-named aria2
  option (the Initial + reserved-change bits). The key true/false projects onto the
  scheduling policy sequential/rarest_first — **the authoritative surface =
  `taiji.setSchedulerPolicy`** (the two entry points echo consistently; `getOption`
  projects from the task policy rather than an independent option store — a
  projection-surface difference declaration); accepted by addTorrent/addMagnet
  (projected into the `scheduler_policy` payload via patch_config); accepted on the
  changeOption Reserved surface (explicit rejection when Active — live switching goes
  through the policy RPC; the tightening relative to aria2's silent ignoring of
  non-changeable keys is declared the same way as select-file); rejected for
  HTTP/.torrent URL tasks. CLI `--bt-sequential-download` (bare run = issued via
  SetSchedulerPolicy after spawn; download+rpc = injected via the AddTorrent
  options).
- **`bt-disable-dht` (a per-task DHT flag; a taiji-only key)**: upstream aria2 has no
  per-torrent DHT surface (DHTRegistry is a global singleton) — this side maps it to
  libtorrent's `torrent_flags::disable_dht` (flipped at runtime via
  `torrent_handle::set_flags/unset_flags`, src/torrent.cpp): a bool value surface,
  **defaulting to following the session `enable-dht`** (None = follow); an explicit
  `true` disables DHT for that one task / `false` forces it on for that one task;
  the task-level value overrides the session value and takes effect on active tasks
  hot (the engine `SetDhtEnabled` live arm + the existing changeOption restart
  semantics as a fallback). Acceptance surface = addTorrent/addUri(magnet/.torrent
  URL) options + changeOption (Torrent/Magnet tasks; for HTTP tasks the key has no
  consumption surface — consistent with the existing precedent for BT-family
  options, not explicitly rejected). **BEP27 cannot be overridden**: for private
  tasks, DHT interaction stays forbidden even with `bt-disable-dht=false` or a
  session hot-enable (the engine's enable gate rejects; same rule as torrent.cpp
  `priv()`). Anchors: `taiji-core::session::options` (the `DECLARED_OPTION_DIFFS`
  whitelist row + `TaskOptionPatch.bt_disable_dht`), `taiji-core::session::actor`
  (the job mirror + `push_dht_task_change` + config_json `bt_disable_dht`
  persistence), `taiji-core::engine::run::arms` (the SetDhtEnabled arm).
- **Intake semantics for no-tracker + DHT-off (the difference row flipped)**: the
  original fail-fast rejection (`invalid metainfo`, exit 1) is **removed** — always
  accepted (the same gate for CLI downloads and session addTorrent/URL-fetch
  upgrades); DHT off + no tracker = accepted + WARN (stall guidance: hot-enable DHT /
  add trackers / restart), aligning with both references (aria2 `RequestGroup.cc`
  only NOTICEs; libtorrent never rejects). Anchor: `taiji-core::metainfo`
  (`Metainfo::check_intake` → the `Option<String>` WARN surface).
- **Unknown keys**: ignored identically on both sides (the
  `changeOption`/`changeGlobalOption`/`addUri` option dicts; live cross-validation
  zero differences). On the CLI command line, unknown options are **errors** in
  taiji (same as the fork; when the feature is off, `--metalink-*` errors and names
  the feature).
- **Option classification** (a single source for acceptance stances; the four
  tables in `taiji-core::session::options`):
  1. `ARIA2_OPTION_NAMES` — accepted aria2 names (name-by-name cross-validation
     against the fork's `prefs.cc`);
  2. `DECLARED_OPTION_DIFFS` — whitelisted extensions/stances (governance = PR +
     user approval);
  3. `DECLARED_NON_ACCEPTED_OPTION_NAMES` — the finalized declaration of names aria2
     has but this side does not accept (the split-proxy family / `save-cookies` /
     `allow-overwrite` / `auto-file-renaming` / `lowest-speed-limit` / `referer` /
     `http-accept-gzip` / `use-head` / the keep-alive family / `follow-metalink` /
     `metalink-base-uri` / the FTP proxy family, about 28 names; `ca-certificate`
     has since moved to the accepted surface, and `load-cookies` has since moved to
     the accepted surface — see the same-named entries below);
  4. `DECLARED_UNWIRED_OPTION_NAMES` — extension items named in the spec but not
     wired in 0.2 (`http-min-chunk`; the key is ignored as unknown).
- `--continue`: the inverted semantics are declared explicitly — taiji always
  resumes (`false` does not discard progress, disclosed by a CLI warning; the RPC
  option surface has no such key).
- Cookie surface (after the closure): `--load-cookies` is **accepted** (the
  load-cookies entry below) + the two task-level direct cookie-passing methods are
  accepted (the dedicated §1 entry); task-cookie persistence = per-task sqlite as
  the single source of truth (the cookie write-back loop, cleared on task
  completion/removal), unchanged. `--save-cookies` is still not accepted (file
  export deferred as needed — the 0.2 finalized declaration).
- Proxy surface: per-task proxy slots `all-proxy` and `https-proxy` (the
  HTTPS-dedicated slot, effect order = dedicated slot > all-proxy > no proxy);
  `http-proxy` and `no-proxy` not accepted; socks5(h)/socks4(a) explicitly
  rejected; proxy authentication via URL userinfo (the `--*-proxy-user/passwd`
  family not accepted); no FTP-over-HTTP proxying. The session-global face of
  both keys is an accepted-value no-op row (no global proxy-default consume
  seam — see the taiji-only echo keys entries above).
- **`ca-certificate` accepted (the task-level CA surface)**: a path to a PEM CA
  file; a task-level root **replaces** the platform trust store (aria2's replace
  semantics, not append), effective on both HTTPS/FTPS; accepted under the same key
  in addUri options and changeOption (incremental semantics: keys absent from the
  payload keep the task's current value). Two tightening differences: (1) parse-time
  path/PEM validation — a bad path/bad PEM = a `taiji.option.invalid` task rejection
  (in aria2 this fails at transport-build time); (2) the value domain = a PEM
  `CERTIFICATE` section (possibly multiple certificates); bare DER is not accepted
  (aria2's "must be in PEM format" rule made explicit). When
  `--check-certificate=false` is also set, the latter wins (verification off, the CA
  file's effective surface ignored; same as aria2). Anchors: the
  `taiji-core::session::options` difference-declaration block,
  `taiji_http::client::{ClientConfig.ca_cert_path, load_ca_certificates_der}`,
  `FtpConfig.extra_ca_certs_der`.
- **`load-cookies` accepted (step one; the task-level cookie intake gate)**: a path
  to a Netscape cookie file, same name and same meaning as aria2's (same literal in
  prefs.cc; migrated from the non-accepted declaration table — reversed later
  re-review, since the original "not wired on the RPC/CLI surface" declaration
  directly contradicted the engine's existing cookie machinery). Three entry points
  = addUri per-task options + the `changeGlobalOption` global surface
  (`GlobalOptions.load_cookies`; the getGlobalOption echo path echoes the original
  value / an empty string when unset; an empty string = clear) + CLI
  `taiji http --load-cookies`. Effective surface = prefilling the task's CookieStore
  (reusing the taiji-http Netscape parser + the `CookieStore::seed` injection seam),
  sharing storage with runtime Set-Cookie absorption (RFC 6265 §5.2/§5.3).
  **Fail-closed**: a missing/unreadable/oversized (>1MiB) file = a
  `taiji.option.invalid` task rejection (the cap anchor `MAX_COOKIE_FILE_BYTES`);
  per-line bad lines keep the parser's lenient discipline (skipping a line is not
  fatal, same rule as curl — see the cookies.rs module docs); all-bad lines = an
  empty jar is a legal form. Priority = per-task > session level (the same order as
  aria2's per-download overriding global). **Combination semantics with hand-written
  `--header` Cookie lines = when a cookie injection gate is present (a file source
  or structured direct pass), hand-written `Cookie:` lines are stripped and the jar
  is the sole source of task cookies** — isomorphic to the fork's "Structured
  cookies are authoritative" (`RpcMethodImpl.cc`); the engine's current state emits
  two Cookie headers when both paths coexist, and a "take the first header" server
  would silently void the jar (acceptance without effect would be a masquerade,
  hence the tightening); for tasks without an injection gate, hand-written Cookie
  headers keep passing through as today (zero change to the status quo).
  changeOption-surface acceptance of a new path = replacing the whole seed set
  (effective on next activation; running tasks are reactivated via the existing
  restart semantics; a bad path is explicitly rejected with zero mutation).
  Anchors: `taiji-core::session::options` (ARIA2_OPTION_NAMES registration + the
  load-cookies entry in the difference-declaration block),
  `taiji-core::session::actor` (the `load_cookie_seed`/`cookie_intake_active`
  single-point family + the add_uri direct-read arm),
  `taiji_http::cookies::{CookieJar, CookieStore::seed}`.
- **`select-file` execution-surface completeness**: for acceptance-surface
  differences see the `select-file` entry above (final ruling: addTorrent /
  addUri(magnet) / changeOption Reserved(Paused); changeOption on Active and non-BT
  tasks = explicit rejection). This entry completes the execution/persistence/
  projection surfaces: (1) http(s) `.torrent` URL tasks of addUri accept
  `select-file` on the same surface (add-surface syntax validation identical to the
  magnet arm; the fetch-upgrade product `TorrentJob.selected_files` is passed
  through from the same source and projected as a mask via `SetFileSelection` at
  activation — the same rule as aria2's addUri `.torrent` surface in
  `download_helper.cc`); (2) out-of-range handling in two stages — in the reference,
  an out-of-range index silently matches nothing when applied to FileEntry
  (download_helper.cc), and the changeOption consumption surface only parses syntax
  without checking file-count bounds (RpcMethodImpl.cc applies lazily); this side
  explicitly rejects when **metadata is available for a decision** (addTorrent
  already parsed / changeOption on an already-landed task, via
  `resolve_select_file_for_meta`; rejected calls cause zero mutation), and when
  **metadata has not landed** (magnet not upgraded / `.torrent` URL not fetched)
  the call is accepted and the out-of-range value ends in an explicit task error on
  the upgrade-activation surface (the difference is only in error explicitness:
  silent no-match → explicit error); (3) a single persistence source for the
  selection surface — `config_json.selected_files` (0-based) is one channel across
  magnet (`so=`/select-file merged winning values), direct torrent adds, and
  `.torrent` URL intake; restart recovery backfills via
  `MagnetJob.selected_files`/`TorrentJob.selected_files`, and
  `effective_magnet_selection` is the single merge point for the magnet family;
  (4) the `selected` truth of `getFiles`/`tellStatus.files` = the `file_selected`
  single-source projection (pad entries always false); the `getOption`
  `select-file` echo = a normalized 1-based comma string (see (3) of the next
  bullet). Anchors: `taiji-core::session::actor` (tasks/persist/commands/views) +
  `taiji-core::magnet` (the finalize application point).
- **`getOption` echo surface (single-task option reads)**: the three-domain lookup
  aligns with the fork (active ∪ waiting = `findGroup`, terminal =
  `findDownloadResult`, `RpcMethodImpl.cc`); unknown/invalid GID messages are
  verbatim str2Gid family (`"GID X is not found"`/`"Invalid GID X"`). Five
  differences: (1) **the echoed key set = a projection of the accepted subset** —
  the fork returns the full table because its option surface accepts everything
  (`pushRequestOption` expands pref by pref, `RpcMethodImpl.cc`); taiji returns the
  accepted key set ∩ keys with a per-task source of truth (the §3 option-stance
  tables are the check basis) and does not fabricate unaccepted keys. (2)
  **Baseline-value projection** — the fork returns only keys explicitly given to
  add/changeOption (`option->defined`); taiji always echoes the task-payload
  effective values for `dir`/`seed-ratio`/`seed-time`/the rate-limit family and the
  like (including the baseline fallen back from global at add time — for
  task-option dialog display; the "unset keys are not echoed" direction difference
  is declared by this entry). (3) **Value shape** — numbers/sizes return the minimal
  numeric form (the add literal `"1M"` returns `"1048576"`, seed-ratio `1.0`
  returns `1` — numerically equal, the same criterion as the §3 `seed-ratio`
  shared-key value difference); `select-file` returns a normalized 1-based comma
  string (the stored surface is 0-based expanded indexes with no original string;
  the fork returns the pre-parse stored literal). (4) **Accurately-unhandled
  default keys** — `bt-max-peers` (the parsed value has no per-task payload: the
  execution surface hangs off an engine-constant seam) and `pause` (the add-time
  enqueue intent is not part of the task payload; the state is carried by
  tellStatus `status`) are not echoed. (5) **The terminal-state read-back surface**
  — terminal tasks are read back from the row's `config_json` in the library
  (fork = the `dr->option` in-memory snapshot): only the persisted key set is
  present (magnet-family booleans / HTTP runtime keys do not enter the row and are
  not echoed in terminal state); after remove the row is gone and with no
  persistence form = an **empty table** (the fork always has a snapshot). The
  live-task rate-limit echo = the live bucket effective value (read back via
  `setMaxDownload/UploadSpeedLimit`, the same `RpcMethodImpl.cc` family). Anchors:
  `taiji-core::session::actor::commands` (`get_option`/`task_option_echo`).

- **Media option family (unified registration, 8 keys → 10 with the
  second batch)**: the first-wired flag family enters the unified
  registration — `media-variant-policy` / `media-audio-lang` /
  `media-subtitles` / `media-segment-concurrency` /
  `media-staging-quota-gib` / `media-staging-dir` /
  `media-allow-private-key-url` (the same gate governs both SSRF-line
  faces: key URIs **and** media-segment/init URLs, the early-draft name
  carries the widened scope) / `media-ffmpeg-path` /
  `media-archive` + `media-info-json` (see the dedicated entry
  below). Accepted + echoed on getGlobalOption/changeGlobalOption (value
  validation through the taiji-media parse faces — an invalid value
  ignores per the gatherChangeableGlobalOption lenient rule on the global
  face, while the addMedia per-task face is strict
  `taiji.option.invalid`); the addMedia options face additionally carries
  the per-task keys `media-selector`/`sub-lang`/`media-template`/`no-meta`/
  `media-muxer`/`media-output-format`/`probe-token`/`media-archive`/
  `media-info-json` (parsed strictly by the actor arm — `media-selector`
  and `media-variant-policy` are exclusive, one selection source). The
  authoritative set: `taiji-core::session::options`
  (`DECLARED_OPTION_DIFFS` + the `GLOBAL_PATCH_TABLE` media rows + the
  mirror consts; the three-face consistency test pins CLI/echo/declaration
  together).
- **Media product faces (taiji extensions — aria2 has no
  archive/export counterpart)**: `media-archive` (default `false`) turns on
  the download archive — the Done close-out records the task's two
  fingerprints into the `media_archive` table (the normalized-URL digest +
  a **URL-free** digest of the fetched manifest's canonical structure —
  the HLS playlist digests verbatim, on DASH the content form
  `mpd_content_digest` whose canonical text omits the entry URL the
  `mpd_digest` binds; the schema annotation marks the rows' sensitivity
  as a browsing-history equivalent), and the two duplicate checkpoints
  run: ① the URL digest at activation (zero outbound — a hit never even
  fetches the manifest), ② the manifest digest in Resolving (the same
  content under a switched CDN/URL/mirror hits here on both flavors). A hit
  terminalizes the task **Done-shaped** with the
  `taiji.media.archive_duplicate` warning over the `taiji.media.
  phaseChanged` bypass (a fast-skip close-out, not an
  Error; zero segment traffic). The destructive clear faces:
  `taiji.clearMediaArchive` RPC + the one-shot `--media-archive-clear`
  CLI pre-clear; after a clear the same fingerprints re-download.
  `media-info-json` (default `false`) writes the whitelisted, redacted
  `<product>.info.json` sidecar at the Done close-out (a fixed field
  record — no map passthrough, `http_headers`/`cookies`/`token`
  structurally absent; every string value passes the payload redact that
  the error face shares; `--no-meta` is orthogonal — it governs only the
  in-product embed face). Anchors: `taiji-media::archive` (the pure
  halves) + `taiji-store::persist` (`media_archive` faces) +
  `taiji-core::session::media` (the checkpoints + the close-out).
- **Four-pool budget trio (`max-concurrent-seeds` /
  `max-concurrent-checks` / `media-synthesis-concurrency`; taiji-only
  echo + accepted keys, the four-pool phase-split budget
  model)**: the fork has no such options (no `prefs.cc` `makePref`) —
  a taiji capability extension, whitelisted in `DECLARED_OPTION_DIFFS`.
  Accepted + echoed on getGlobalOption/changeGlobalOption
  (`session_runtime` face); a **non-numeric value ignores leniently**
  (the gatherChangeableGlobalOption rule, the media-family row shape —
  zero new error codes), an out-of-domain numeric **clamps at the row**
  (the `max-concurrent-downloads` apply-side clamp precedent; the
  read-side accessors are the same-domain second fence). Value domains:
  seeds `[0,4096]` (0 = unlimited) / checks `[1,16]` (no unlimited
  state) / synthesis `[1,16]`. Defaults: seeds **16** (two-state note —
  the unlimited default 0 presupposes the  session-level
  connection budget; unmerged at implementation time, the default
  converges temporarily to 16 and flips back once the session-level
  connection budget lands),
  checks 2 (pread+hash IO/CPU overlap conservative value, the
  engine-internal verify pool's layered disk load counted in),
  synthesis 2 (an ffmpeg process is heavy; the layered counterpart of
  `media-segment-concurrency`, which governs the network phase and is
  NOT this budget). Hot reload = the changeGlobalOption trigger: a
  narrowed budget never preempts in-flight members (it gates only
  subsequent admissions), a widened seed budget reactivates
  parked seed_wait members FIFO without ever routing through a
  download slot. CLI/conf faces (`taiji`): same-name flags +
  conf keys, **hard domain validation** (fail-fast, the conf shape)
  with the same-source domains; startup injection into the session
  initial values. Anchors: `taiji-core::session::options`
  (`GLOBAL_PATCH_TABLE` rows + `DECLARED_OPTION_DIFFS` entries),
  `taiji-core::session::actor::mod` (`pump_all`, the I3
  budget-change trigger), `taiji::conf` (the arms).
- **`bt-detach-seed-only` behavior superseded (semantics constant-true;
  the acceptance face is unchanged)**: the same-named aria2 option
  (`RequestGroup.cc` `enableSeedOnly`: option on AND download complete
  → release the concurrency slot at completion, seeding keeps running
  detached; option off = seeding occupies the slot until the seed
  criteria end the task). taiji accepts the key unchanged (default
  `false`, echo verbatim — the aria2 acceptance/echo face zero
  change), but under the four-pool model the **behavior is
  constant-true regardless of the value**: a completed download flips
  to a seeding resident (`SeedingStarted`), the download slot is
  released at the flip, and seeding never occupies a download slot
  again (the seed pool's own `max-concurrent-seeds` budget governs
  residency). This is the phase-split budget architecture superseding
  the aria2 accounting patch (the detach flag's intent — download
  scheduling not held hostage by non-download phases — is subsumed
  structurally), **declared as an architecture difference, not a
  defect**; both values are pinned behaviorally identical by the
  regression test (`taiji-core::session::actor::tests::
  bt_detach_seed_only_any_value_seeds_off_the_download_slot`). The
  engine-side `Detached` terminal variant is retained as the semantic
  marker of a task that once seeded. Anchors:
  `taiji-core::session::options` (`bt_detach_seed_only` field +
  `DECLARED_OPTION_DIFFS` context), `taiji-core::session::actor::tasks`
  (the SeedingStarted transfer), `taiji-core::session::queue`
  (`begin_seeding`, the release-then-backfill).
- **Periodic summary caliber (`emit_summary`; intentional)**:
  the session's periodic task summary (the `--summary-interval` INFO
  line) iterates **only the download-pool active registry** —
  seeding/processing residents are NOT summarized per-task (their
  observation faces are the tell\* projections and the getGlobalStat
  extension keys, entries below). aria2 prints summaries for its
  (single-counter) active groups; the divergence direction is
  taiji-only-by-design (no four-pool summary extension). Anchor:
  `taiji-core::session::actor::summary` (`emit_summary`).
- **Registration wording**: the media option family's registration text
  lands through the repository's ordinary change-review process; this
  document carries the normative diff declaration.

## 4. Task surface (tellStatus / tell* / getFiles / getUris / getServers / getPeers)

On the live cross-validation baseline (a paused FTP task + a magnet task):
`getUris`/`getPeers` are byte-for-byte zero-diff; the `getFiles`/`tellStatus` key-set
differences all fall under the following entries:

- **`http` subdict** (a taiji extension; absent on the fork):
  `finalUrl`/`connections`/`extentsActive`/`blocksDone`/`blocksTotal`/`encoding`
  (unset = key absent)/`renamePending`/`hostControlled`/`sources[{url,rate,state}]`. Anchor:
  `taiji-rpc::dispatch::view` (`status_entry_json`).
- **`media` subdict** (a taiji extension; absent on the fork —
  declared fields): `kind` (`hls`) / `phase` (the media
  §3.2 domain: queued|resolving|downloading|recording|processing|verifying|
  finalizing|paused|error|done) / `phaseDetail` (the pause phase memory —
  absent unless paused-with-memory) / `tracks[{label,kind,state,
  segmentsDone,segmentsTotal}]` / `stagingDir` / `outputName` (the sanitized
  template result) / `selector` / `variant` / `manifestUrl`; progress
  projection rides the top-level `completedLength` (the whole-task byte
  rollup). getGlobalStat/numActive count media tasks (the queue-based
  caliber, the established precedent). Anchor: `taiji-rpc::dispatch::view`
  (`media_json`) + `taiji-core::session::actor::views` (`job_media_view`).
- **BT-face superset keys**: `numSeeders`/`seeder` are always present for every task
  type in taiji (`"0"`/`"false"`), while the fork carries them only for BT tasks;
  the `bittorrent` subdict, `getFiles`'s `piecesRoot`/`pieceSize`/`padding`, and
  `getPeers`'s added `transport`/`crypto` columns follow the Phase A declaration
  (the v2 synthesized surface).
- **Pre-probe projection**: between task creation and probe/planning, the fork
  pre-populates `getFiles`/`tellStatus.files` with placeholder entries (`path` empty
  string, `length` "0") and echoes the default block length in `pieceLength`; taiji
  returns an empty `files` array and `pieceLength` "0", projecting the real entries
  once planning completes.
- **getServers**: on the fork only active tasks are queryable (paused/terminal =
  `"No active download for GID#X"` — for the paused state **verbatim zero-diff**
  with taiji); for terminal states (Done/Error) taiji projects an aggregated row
  (the fork still errors on terminal states); the response is a single per-source
  aggregated row (`{index:"1", servers:[…]}`), while the fork returns one row per
  in-flight request. The server entry's speed field = the task's cumulative average
  speed (fork = per-request instantaneous).
- **getUris**: the status value domain matches the fork (`used`/`waiting`); taiji
  approximates with "all `used` once activated, all `waiting` before activation"
  (the fork reflects the live state of each URI contact point).
- **Progress accounting basis (completedLength)**: while a live read is present,
  `completedLength` in tellStatus/tellActive/getFiles projects a **byte-level
  realtime count** (during activation, block accounting lays the floor and bytes
  actually written to the sink accumulate monotonically; the known-total convergence
  truncates — wasted bytes from same-block double writes / retry rewrites do not
  leak out, always ≤ `totalLength`, and the final value = the accounting final
  value). The former baseline note — "taiji measures by blocks; its 1Hz-sampled
  p50/p95 cannot be compared directly across engines (the fork is byte-level)" — is
  hereby **withdrawn**: the measurement granularity has converged with the fork and
  no longer exists as a difference.
  Block accounting remains the persistence authority (projection ≠ accounting; the
  spec §4.3 single-point decision is untouched): the `http` subdict's
  `blocksDone`/`blocksTotal` keep block units; for cold rows (no live read) see the
  projection in the next bullet. Anchor: `taiji-core::session::actor::http_task`
  (`HttpLive::completed_bytes`).
- **Cold-row progress projection**: for queued/paused HTTP rows without a live read,
  `completedLength` projects the bytes already completed within the row (the import
  bitmap mapping / snapshot pipeline persistence surface), `totalLength` projects
  the probe's authoritative total (always exact after activation-probe backfill);
  when the probe is absent, the grid-derived value is projected
  (`block_count×block_size` — the imported-bitmap row shape; a non-aligned total is
  overestimated by at most one block), and failing that = 0. The fork returns real
  values for paused tasks (same rule); for a not-yet-started waiting task the fork
  also reports 0/0 (the same shape as taiji when there is no row progress). The
  `files` surface is not covered here (see "Pre-probe projection" above). Anchor:
  `taiji-core::session::actor::views` (`http_cold_lengths`).
- **saveSession**: semantics = triggers a full persistence pass (taiji's sqlite is
  the session truth); it does **not** produce the aria2 text session-file format.
  The fork answers OK under the `--enable-sqlite3-persistence` runtime shape — live
  cross-validation (both sides running with a library) is zero-diff; without a
  persistence form both sides error explicitly (fork = a persistence-not-enabled
  error; taiji = `saveSession: session storage is not enabled`; an embedded process
  may lack a library, while taiji's runtime shape always has one).
- **getGlobalStat caliber migration (the four-pool model)**: upstream/fork `numActive` counts every
  active RequestGroup — seeding residency (a detached BT group stays in
  the active list, `RequestGroupMan.cc`) and media-synthesis work
  included. taiji's `numActive` is **migrated to the download-pool
  caliber**: it counts only download-phase slot occupants (BT/HTTP
  downloads, magnet metadata phase, media Resolving/Downloading) —
  seeding/checking/synthesis residents are excluded from the meter (they
  are TellActive members still — the member face and the meter face
  diverge by declared design). `numWaiting` = the four waiting segments
  merged (`reserved ++ check_pending ++ seed_wait ++ proc_wait` — the
  same caliber as tellWaiting, one count). Three **extension keys**
  (aria2 has no counterpart; the live-diff face strips them before the
  zero-diff comparison): `numSeeding` / `numChecking` / `numSynthesizing`
  = the three pools' **in-flight residents only** (each pool's waiting
  FIFO is NOT included; waiting breakdown = the client's status
  histogram over tellWaiting — no third-layer keys). Motrix-visible
  behavior change (a seeding-only session's numActive drops to 0 where
  the fork would report the residents). Anchors:
  `taiji-core::session::view` (`GlobalStatView`), `taiji-core::session::
  actor::commands` (the getGlobalStat arm), `taiji-rpc::tests::
  aria2_compat_live_diff` (`strip_global_stat_extension_keys`).
- **`'seeding'` extended status value + residency projection flip
  (the user-visible status value change)**: the tellStatus/tell\* `status` value domain
  gains **`'seeding'`** —
  (1) a completed download's seeding **residency** projects `'seeding'`
  in TellActive/tellStatus (the engine keeps running; the window
  interim that projected residents as `'active'` is closed — the row
  state and the projection share one face);
  (2) the tellWaiting **seed segment** (`seed_wait` — content complete,
  parked for a seed budget seat, occupying no running slot) projects
  the same `'seeding'` value (the persisted row state covers residence
  + waiting alike — the `'checking'` pending+in-flight precedent);
  (3) the check segment (`check_pending`) projects the **existing**
  `'checking'` value (zero extension — pending + in-flight verification
  have shared the persisted `'checking'` row state since Phase A);
  (4) the synthesis segment (`proc_wait`) projects `'waiting'` (no
  extension — the gate hang is an in-task phase, the media subdict
  carries the phase detail).
  tellWaiting's fixed segment order = reserved ++ check_pending ++
  seed_wait ++ proc_wait; changePosition interprets POS_SET/POS_OFFSET
  **inside the owning segment** and clamps at the segment's own
  head/tail (a phase segment is a resource domain — a position never
  crosses a segment boundary; non-waiting members follow the aria2
  non-waiting rejection semantics).
  **Motrix tolerance face (the end-to-end verification
  record; Motrix @ 82829306, read-only)**: Motrix's
  `translateStatus` (`src/core/engine/aria2/translate.ts:35-71`) has
  no `'seeding'` case — its native seeding recognition is gated on
  `raw.status === 'active'` + `seeder === 'true'` + `bittorrent`
  (translate.ts), so the literal `'seeding'` falls through to the
  `default → TaskStatus.Error` arm: a
  taiji seeding resident / seed_wait member **mislabels as Error** in
  Motrix's task list (consumption points: `translateRawToTask` in
  translate.ts and the session restore path in session-manager.ts).
  The wire-format facts are compatible
  otherwise — taiji projects `seeder` as the strings `"true"/"false"`
  (`jbool`, `taiji-rpc::dispatch::view`) and a seeding resident
  reports `seeder="true"` (the engine snapshot's all-faces-complete
  flag, `taiji-engine::query` `EngineStatusSnapshot.seeder`), so
  Motrix's native detection would classify these tasks correctly if
  its status gate admitted `'seeding'` (or if the status stayed
  `'active'`). The mislabel is recorded honestly per the
  "invisible-to-Motrix" boundary: the taiji-side declaration stands
  (the value extension is the one user-visible status change), and
  the Motrix-side fix is **out of taiji's scope — escalated to
  cross-repo coordination**, not silently absorbed and not papered over by bending the
  taiji declaration. Anchors: `taiji-core::session::view`
  (`StatusKind::Seeding` + `as_str`), `taiji-core::session::actor::
  views` (`seeding_live_view`), `taiji-core::session::queue`
  (`waiting_snapshot`, the fixed segment order).

## 5. addUri / addTorrent (protocol acceptance surface)

- **sftp:// deferred**: the fork supports SFTP; taiji 0.2 rejects it explicitly —
  addUri reports `taiji.sftp.deferred` at task-creation time (the error message
  carries the code; the SFTP transport surface (known_hosts strict / identity /
  pipeline concurrency) ships with a separate project, and the `--sftp-*` option
  family is deferred likewise (ignored as unknown items)).
- **Unknown scheme**: the fork uniformly reports `"No URI to download."`; taiji
  explicitly reports `"URI scheme not supported: …"` (the accepted domain: magnet: /
  http(s) / ftp(s) / http(s) .torrent URLs).
- A **multi-URI array** = mirroring multi-source for the same file; both sides share
  the semantics; taiji additionally provides the `sources[]` runtime observation
  surface (§4 `http` subdict).
- **addTorrent invalid base64**: the fork decodes base64 leniently (after stripping
  illegal characters, the bencode check fails → `"Bencode decoding failed"`); taiji
  validates strictly → `"torrent data is not valid base64."`. The numeric code is 1
  on both sides.
- addTorrent's webseed URIs parameter (position 1): accepted by both sides; taiji
  0.2 does not consume it (BEP19 webseeds belong to a later phase) — dropped
  explicitly, not disguised.
- **The `user-agent` semantics of webseed/HTTP source requests (2026-10-16)**: under
  aria2 semantics, the task-level `user-agent` option feeds the URI/webseed surface
  (the same HTTP downloader stack); taiji intentionally diverges — **all HTTP
  outbounds inside BT tasks (webseed range requests) are always identified as
  `taiji/<semver>`** (`taiji_bt::tracker::PEER_AGENT` constructively anchored,
  `taiji-engine/src/webseed.rs` `HttpRangeFetch::build`) and do not consume that
  option. The UA-override semantics of pure HTTP(S)/FTP tasks are unchanged.
  Rationale: the BT identity surface (tracker announce UA / ext handshake `v` /
  webseed UA) has a single source and is identified accurately (libtorrent's
  `user_agent` setting feeds tracker+webseed from the same source and is
  configurable — taiji tightens this to non-configurable). Two guard tests live in
  `taiji-engine/src/webseed.rs` (an outbound-message assertion + a guard that the
  option stays unwired).
- **Explicit rejection of illegal BEP53 `so=` (a taiji-native extension surface; the
  fork has no counterpart; the protocol-behavior reference = libtorrent)**: if the
  magnet URI's `so=` parameter is present, taiji parses it strictly — a syntax error
  (out of order / duplicated / overlapping / inverted / empty items / non-decimal) =
  an explicit add rejection; out of range (≥ the number of non-pad files) = an
  explicit failure in the upgrade chain; libtorrent's `magnet_uri.cpp` `so` branch
  is **lenient, skipping the whole parameter** on illegal characters (only
  digit/`-`/`,` are accepted, the rest are dropped and parsing continues). The
  tightening is taiji's own design: a silently lost selection surface is more
  dangerous than an explicit failure (the user believes files were selected while
  the whole payload downloads). Declaration closure: the acceptance-surface
  difference lives in the §3 `select-file` entry (the `select-file`/`so=`
  coexistence conflict rejection is in that same entry).
- **The BEP53 third segment (`so=` appending to an existing torrent) is not
  implemented; a duplicate identity keeps the explicit `duplicate download`
  error.** Four grounds: (1) BEP53 is a Draft (unnumbered as of 2017-05-24); (2)
  aria2 has no `so=` surface (`src/magnet.cc` has no such parameter) — the fork has
  no counterpart behavior to cross-validate; (3) **libtorrent core likewise does
  not implement it** — a duplicate add returns the existing handle immediately and
  **does not apply the new params' file_priorities** (`session_impl.cpp`);
  appending semantics are done at the client layer (qBittorrent et al.) by calling
  `torrent_handle::prioritize_files` on the duplicate handle; (4) the Motrix
  frontend has no UX dependency on it (the duplicate-add path goes through explicit
  reselection via changeOption select-file / re-adding). If Motrix later raises an
  "append download" need, it will be a separate change under `taiji.*` extension
  design. Anchor: `taiji-core::session::actor::tasks` (the `identity_is_duplicate`
  explicit error source of add_uri/add_torrent).

## 6. addMetalink

- **Version surface**: the fork accepts v3+v4; taiji accepts v4 only (RFC 5854) —
  v3/unknown versions = an explicit downgrade to
  `taiji.metalink.unsupported_version`.
- **Parsing boundary** (observed in live cross-validation):
  - non-XML bytes: code 1 on both sides (fork `"Could not parse Metalink XML
    document."`; taiji `taiji.metalink.parse_failed: …` — a wording difference);
  - **valid XML but a non-metalink root / zero `<file>` entries**: the fork
    leniently returns the empty array `[]`; taiji explicitly reports
    `taiji.metalink.parse_failed` (a known unsupported feature must error
    explicitly — no silent masquerade as an empty result).
- **Expansion semantics**: entry names flatten to the basename (the `--out`
  pure-filename domain); checksums fold into the six hashes
  (md5/sha-1/sha-224/sha-256/sha-384/sha-512 — the same domain as the `--checksum`
  value domain; a single checksum prefers the strongest sha-256, the others take
  the first in document order; out-of-domain types such as sha3-* are retained in
  parsing but produce nothing); `<pieces>`/`<signature>` are retained in parsing
  and not consumed by the download surface; the `url@type` attribute is not
  consumed; `<metaurl>` (BT) is converted directly inside the engine, a non-torrent
  mediatype is skipped with a warning, and a metaurl task failure does not affect
  the same entry's HTTP source tasks; the return value = a plain GID string array
  (the aria2 shape); valid entries with zero usable = an empty-array receipt (not
  an error).
- **Later entries with the same (dir,out) are skipped** (+ a warning; the first-seen
  entry holds exclusive ownership): after entry names flatten to basenames,
  same-named entries under the same `dir` would concurrently double-write one part
  file (silently corrupting the file when no checksum exists) — the fork's
  `applyDir` preserves entry subdirectory levels, so same-named entries land on
  different paths and do not collide (flattening itself is covered by the
  expansion-semantics bullet above); taiji absorbs the duplication at the expansion
  seam keyed by (dir,out): later entries are skipped and the remaining entries
  expand as usual.
- **Same-document magnet/metaurl dedup skip** (+ a warning; first seen wins): one
  metaurl URI literal produces only one BT task (the same-direction surface as the
  fork's `groupEntryByMetaurlName` grouping by URI literal); the same magnet dedups
  by the dual btih/btmh identity — different URI spellings of the same torrent
  (arbitrary dn/tr) form separate groups on the fork by literal, while taiji skips
  same-identity entries and still expands the remaining surfaces of later entries
  (benign duplication is absorbed at the seam and no longer makes the whole method
  fail midway). Within an entry, metaurl candidates are examined one by one until
  the first usable one (an unusable first-seen does not block a usable later one).
  Anchor: `taiji-rpc::metalink` (`expand_add_uri_plans`).
- **Caller-supplied out/checksum stripped wholesale**: the `out`/`checksum` keys of
  the addMetalink base options are stripped wholesale at the expansion seam — `out`
  is always derived from the entry name (BT plans do not carry it); `checksum` is
  produced only when the entry itself declares a six-hash domain in the document,
  and entries without a declaration **do not inherit** the caller's `--checksum`
  (a fail-closed leak surface: an external value would wedge healthy entries). The
  fork takes metalink subtask paths/checksums from the entry itself
  (`Metalink2RequestGroup.cc` constructs the DownloadContext directly and does not
  consume the caller's `out`/`checksum`) — the same-direction difference declared
  explicitly. Anchor: `taiji-rpc::metalink` (`expand_add_uri_plans`).
- **BT plans consume no entry hash and carry no out/checksum**: an entry's `<hash>`
  declarations enter only the HTTP plan surface (`--checksum`); BT integrity is
  finally adjudicated by the piece hashes of the fetched metadata, the document
  checksums have no intersection with the BT surface, and BT plans never carry
  `out`/`checksum` keys — the fork's direct conversion carries none in the same
  direction, declared explicitly. Anchor: `taiji-rpc::metalink` (`AddUriPlan`).
- **Partial-failure receipt message wording difference**: when a mid-expansion
  subtask is rejected by the session (duplicate identity / an `out` domain
  rejection, etc.), the whole method fails explicitly (numeric code 1) and the
  error message appends the list of created GIDs (`"(created gids: …)"`; the error
  object keeps the `{code,message}` shape, and already-created tasks remain
  independently removable/tellStatus-able) — the fork's method surface has no such
  receipt form (group construction completes before any enqueue, so failure = zero
  groups enqueued and no partial-failure wording). Anchor: `taiji-rpc::metalink`
  (`fail_with_partial`).
- **Option family**: `metalink-language/location/os/version/preferred-protocol/
  enable-unique-protocol/force-protocol` are accepted and ignored + warned;
  `metalink-enable-auto-discover` is accepted but treated as invalid (the fork
  1.37.0 has no such name); `follow-metalink`/`metalink-base-uri` are not accepted.
- **Charsets (ISO-8859-1 / windows-1252)**: the XML declaration/BOM carries the
  decoding; an `ISO-8859-1` label decodes via the WHATWG `windows-1252` mapping
  (encoding_rs matches the HTML spec here: the 0x80-0x9F range decodes to Cp1252
  printable characters rather than C1 control characters — under strict Latin-1
  some of those bytes are illegal XML 1.0 characters, so this mapping is a
  compatibility-surface extension). Anchor: the `taiji-metalink` crate docs and
  the charset vector tests.

## 7. Error codes and error shapes

- **The JSON-RPC surface**: the numeric codes 1/-32700/-32600/-32602/-32601 and
  their HTTP status mapping (1→400, -32600→400, -32601→404, the rest→500) are live
  cross-validation zero-diff; the parameter-error messages (`"The parameter at N is
  required but missing."`/`"...has wrong type."`), the GID messages (`"GID X is not
  found"`/`"Invalid GID X"`), and the multicall recursion-ban message are all
  verbatim zero-diff.
- **Validation priority for changePosition's doubly-illegal combination**: in the
  extreme combination where both the gid and how are illegal, the reference runs
  gid parsing before checking the how value domain (str2Gid's `"Invalid GID …"`
  comes first — aria2-1.37.0 `RpcMethodImpl.cc`) and reports `"Invalid GID …"`;
  taiji's dispatch layer closes the how literal value domain first (reporting
  `"Illegal argument."`), with gid prefix parsing in the actor (expandUnique needs
  the full GID set) — for the same call combination the **message priority is
  reversed**. Each error message is individually verbatim zero-diff (previous
  bullet); for the single-illegal faces (only gid illegal / only how illegal) the
  winning message matches the reference and the success path is zero-diff — a pure
  error-surface combination boundary, no behavioral difference. Anchor:
  `taiji-rpc::dispatch::methods` (the changePosition arm comment, cross-referenced
  with this entry).
- **The numeric error-code mapping table** (terminal-state task `errorCode`; the
  single source = the `taiji-rpc::error` doc table + an executable mirror).
  Difference-surface entries:
  - DNS resolution failure: the fork can reach 19 (NAME_RESOLVE_ERROR); taiji
    always lands on 6 (NETWORK_PROBLEM) (the transport payload does not distinguish
    phases, so the fine-grained code is unreachable);
  - disk-error refinement: the fork can reach 15/16 (FILE_OPEN/CREATE_ERROR); taiji
    always lands on 17 (FILE_IO_ERROR);
  - FTP login failure (530): the fork lands on 21 (FTP_PROTOCOL_ERROR); taiji's
    numeric surface unifies on 24 (HTTP_AUTH_FAILED, with the string code
    `taiji.auth.failed` taking precedence);
  - FTP read idle timeout: taiji lands on 21 (the fork's read timeout is
    2 TIME_OUT regardless of protocol);
  - cookie-file failure: the fork logs and continues; taiji escalates to a
    task-level failure (code 1 + `taiji.http.cookie_file*`);
  - taiji's enhanced codes `mirror_mismatch`/`no_source`/`total_length_exceeded`/
    `coordinator_stopped`: the fork has no one-to-one counterpart, so they all land
    on 1 (UNKNOWN_ERROR); `insecure_redirect` lands on 22 (HTTP_PROTOCOL_ERROR —
    the fork has no concept of a redirect-downgrade defense line, so the code joins
    the HTTP protocol-error family);
  - empty-file probing (416+`*/0`) Done = a new success path (numeric code 0).
- **The metalink parsing budget timeout**: taiji = numeric code 1 + the
  `taiji.metalink.timeout` prefix (a 600s budget — the same explicit backstop as
  `taiji.createTorrent.timeout`'s "no synchronous RPC without a timeout cap" ban;
  the timeout constrains only the receipt and does not cancel the underlying
  blocking parse; the parse is a pure function, so discarding the result leaves no
  orphan tasks); the fork's parse has no budget cap and this error surface does not
  exist there. Anchors: `taiji-rpc::error` (`STR_METALINK_TIMEOUT`),
  `taiji-rpc::metalink` (`add_metalink_method`).
- **A `--checksum` mismatch** = 32 (CHECKSUM_ERROR); the fork uses the same code.

- **Media error codes → aria2 numeric mapping**: the media
  §14 error-code line threads through the numeric face — every
  `taiji.media.*` code maps to 1 (UNKNOWN_ERROR; no aria2 counterpart — the
  canonical string code rides the message verbatim), including the
  `staging` and `ssrf_blocked`/`key_invalid` annotations and this entry's
  first wirings `template_unsafe`/`probe_expired`/`not_media`; the one shared
  row `taiji.option.invalid` keeps 28. Anchor: `taiji-rpc::error`
  (`media_numeric_code` + the row-list test).

## 8. Transport behavior differences

- **Dynamic scheduling** (a taiji core addition; absent on the fork): guided
  self-scheduling + stall stealing + connection-count AIMD + endgame downgrade;
  `http-scheduler=dynamic|static`.
- **Data-plane redirect convergence at jump-off** (phase 2; aligns with aria2
  `Request`'s redirected-URI caching semantics): the redirect final URL converged
  during probing is reused directly by data-plane Range requests during download
  (enabled for single-source tasks) — **each block no longer re-walks the redirect
  chain** (saving one origin round trip per block + sparing each worker one origin
  keep-alive/TLS connection; the "2 sockets per data connection" shape is thereby
  eliminated). A transport error at jump-off falls back to re-resolving the
  original chain (mirror rotation / invalidation self-healing); challenge
  credentials are stripped across endpoints (Basic/Digest are scoped to the
  original endpoint and are not carried across hosts on a 302 anyway). Multi-source
  (mirror) tasks conservatively keep re-walking the chain.
- **The small-task parallel Range fast path** (a taiji core addition; absent on the
  fork): tasks with ≤2 blocks, no resume progress, and connection intent ≥2
  (min(`split`, `max-connection-per-server`); from phase 2 the defaults (5,16) hit
  immediately — new ≤2-block tasks take the fast path by default; the previous
  default cap=1 never triggered it) skip grid assembly: the whole file is split
  into near-equal byte ranges fetched in parallel directly — the `min-split-size`
  floor **does not apply** on this path (the fork/classic aria2 always uses a
  single connection when "file ≤ min-split-size"; this aligns with aria2-next's
  per-file range planning behavior, which has no min-split-size semantics). This
  path has no bitmap: an interrupted reactivation refetches the whole file (the
  "prefer under-recording, never over-record" safety direction); `--checksum`
  final adjudication before rename, rate limiting, and the per-host cap share the
  same surface as the grid path. Anchor: `taiji-core::session::actor::http_task`
  (`SMALL_TASK_MAX_BLOCKS`/`drive_small`/`small_task_ranges`).
- **Semantically redefined items** (same name, different meaning; accepted and in
  effect):
  - `split`/`min-split-size`: under dynamic scheduling, split = the AIMD slow-start
    starting point (connection intent honored immediately) + the initial extent
    reference; the connection cap belongs to `max-connection-per-server` (static
    mode keeps the original meaning);
  - `max-connection-per-server`: the AIMD growth cap (domain 1..=64; lowering it at
    runtime shrinks proactively). **Default = 16** (phase 2; deviates from the
    aria2 upstream default of 1: with a cap of 1 the AIMD criterion has zero room
    to grow and dynamic mode would stay single-connection on real networks — the
    cap is a ceiling, not a connection count, which still climbs adaptively via
    AIMD; an explicit 1 = pin to a single connection);
  - `max-tries`: retries per extent (the fork retries per download); `retry-wait`
    exponential backoff ×2 capped at 30s.
- **h2**: taiji automatically uses HTTP/2 for HTTPS per server negotiation (h2 +
  rustls ALPN); the fork is HTTP/1.1 only. Under h2, "connection count" = a
  concurrent-stream cap semantic (abstracted by the scheduler as per-host
  permission); the flow-control wait is already wired into the stall-detection
  exclusion.
- **The protocol-mode switch `--http-protocol=auto|h1|h2`** (a taiji capability
  extension + an **experimental window**; aria2 has no protocol-choice option): a
  task-level runtime option. Value domain: `auto` (default) = the h2 status quo
  above + cleartext endpoints always HTTP/1.1 — **the default behavior is
  unchanged**; `h1` = force HTTP/1.1 for the whole transport (ALPN advertisement
  narrowed to http/1.1, the h2 upgrade shut off — a fallback/comparison knob);
  `h2` = HTTP/2 prior knowledge (RFC 7540 §3.5): cleartext endpoints speak h2c
  directly (no Upgrade, **no h1 fallback**; fails outright against h1-only peers),
  TLS endpoints skip ALPN and speak h2 directly. Off by default (= auto), on an
  experimental-window basis; an unknown value = a `taiji.option.invalid` task
  rejection. The name deliberately avoids `h2c-auto`: reqwest prior knowledge is a
  single transport-level form with no "automatic fallback" semantics, and h2c is
  merely the projection of the `h2` value on cleartext endpoints. Anchors:
  `taiji-http::client` (the `HttpProtocol`/`build_transport` branches),
  `taiji-core::session::actor::mod` (`parse_http_protocol`, the single parsing
  source); wire-level anchored tests = `crates/taiji-http/tests/h2_mock.rs`
  ((1) positive cases for ALPN-negotiated status quo / h1 fallback / forced h1;
  (2) positive and negative h2c prior-knowledge cases — the default client is
  rejected by the preface check against an h2c-only origin; (3) single-connection
  multiplexing vs the h1 connection storm + flow-cap throttling observations).
- **h2 flow-control window tuning `--http2-adaptive-window` / `--http2-stream-window`
  / `--http2-connection-window`** (a taiji capability extension + an **experimental
  window**; aria2 has no window options): the h2 receive flow-control window surface
  (RFC 7540 §5.2 — the receive window the client advertises is the ceiling on how
  much data the server can push; single-stream throughput ≤ stream window / RTT).
  Task-level runtime options: `http2-adaptive-window` (bool; default false = the
  static engine default windows (8MiB/16MiB) — the hyper library defaults of
  2MiB/5MiB are reachable only via the programmatic None comparison path, i.e.
  ping/BDP-estimated dynamic window growth is off), `http2-stream-window` (the
  per-stream initial receive window in bytes), `http2-connection-window` (the
  per-connection initial receive window in bytes, shared across streams) — the
  latter two have the domain 65535..=2^31-1 (the §5.2.2 window cap), **default =
  the engine defaults of stream 8MiB / connection 16MiB (default raised and
  finalized on the basis of two benchmark runs (2026-09-25) and
  a 2026-09-25 run: rtt100 single stream 3.8× / s16 2.9×, zero regression
  at rtt0)**; `None` (the programmatic comparison path) = the hyper library
  defaults of stream 2MiB / connection 5MiB (`hyper::proto::h2`
  DEFAULT_STREAM_WINDOW/DEFAULT_CONN_WINDOW). Out-of-domain values = a
  `taiji.option.invalid` task rejection. Rate-limit backpressure semantics are
  unaffected (local read-side backpressure dominates the flow-control wait and the
  stall-criterion exclusion keeps holding — only the unthrottled full-speed path is
  affected). Motivation (industry research notes of 2026-09-25): a transoceanic
  long-fat pipe caps a single stream at ≈2MiB/RTT (a 100ms RTT ≈160Mbps); industry
  dynamic-window references — Chrome starts at 65535 and grows dynamically at a
  half-window pace, nghttp2 h2load defaults to a stream window of 2^30-1, quinn
  uses a 1.25MiB stream window (a 100Mbps×100ms design). Anchors:
  `taiji-http::client` (the three `ClientConfig` fields + the `build_transport`
  projection + the DEFAULT_H2_* constants), `taiji-core::session::actor::mod`
  (`parse_http2_window`, the single parsing source); wire-level anchored tests =
  `crates/taiji-http/tests/h2_mock.rs` (the client's initial SETTINGS advertisement
  + the server-visible surface of stream 0 WINDOW_UPDATE).
- **h2 multiple connections + PING keep-alive `--http2-max-connections` /
  `--http2-keep-alive-interval`** (a taiji capability extension + an **experimental
  window**; aria2 has no counterpart options): (1) `http2-max-connections`
  (task-level runtime; domain 1..=8; **default 1 = the status quo**) — a cap on
  per-origin connections on the h2 transport surface. Motivation (2026-09-25
  benchmark evidence): a single h2 connection shares one congestion window; even
  with tuned windows at rtt100 it reaches only 88MiB/s vs 382MiB/s for h1
  multi-connection; K>1 is the experimental entry point for the multi-connection
  shape. Implementation = K independent transport instances (the reqwest pool
  merges by origin and has no K-connections API — each instance's own pool is its
  own connection), with data-plane requests spread by atomic round-robin; when
  negotiation lands on h1 the connection spreading still applies (the concurrent
  connection count is governed by the split surface — see the K-semantics note
  below); every connection counts toward `--http-max-per-host` as usual; K=1 is
  field-for-field equivalent to the existing single instance. **K-semantics note
  (zero behavior change)**: (a) when negotiation lands on h1, K is not entirely
  inert — sequential request spreading opens min(K, request count) connections
  (vs a single keep-alive connection reused at K=1), with 90s idle reclamation as
  the backstop; (b) the K cap needs concurrent intent (split /
  max-connection-per-server / AIMD want) to be realized — from phase 2 the want
  derivation is carried by the default cap 16 (the previous default cap of 1 pinned
  the want down, making K a near no-op). K does not gate on h2 (a behavior change
  would need a separate decision). (2) `http2-keep-alive-interval` (task-level
  runtime; domain 0..=3600 seconds; default 0 = off = the hyper status quo) — PING
  liveness probes for idle pooled connections (reqwest
  `http2_keep_alive_interval/timeout`), with the timeout = 2× the interval (fixed
  internally); guards against first-request tail latency on connections silently
  dropped by middleboxes. Out-of-domain values of both options = a
  `taiji.option.invalid` task rejection. Anchors: `taiji-http::client` (the
  `ClientConfig` fields + the `build_standalone` K-instance assembly + the
  `data_transport` round-robin), `taiji-core::session::actor::mod` (the single
  source for domain validation); wire-level anchored tests =
  `crates/taiji-http/tests/h2_mock.rs` (5) (K>1 → the origin's TCP accept count =
  K, evidence of the connection surface).
- **The same-host transient batch-group budget `--http-batch-budget`** (a taiji
  capability extension; aria2 has no batch-group concept — a dynamic-scheduling
  extension): ≥2 single-source HTTP small tasks (≤2 blocks, zero progress) on the
  same host form a transient batch group — a cross-file byte Range queue (SRPT
  pickup = the in-batch stealing surface) + leaving the group as soon as a file
  completes (budget returns to the pool). Default 16, domain `2..=64`, unit =
  connections, a task-level runtime option; an illegal value = a
  `taiji.option.invalid` task rejection. **Three cap layers stack**: per-file
  intent = `min(split, cap)`, not amplified by the batch group; while the group
  lives, its aggregated connections ≤ this budget (exception: when the per-host cap
  has free slots, work-conserving overflow up to
  `max(budget, host cap − usage outside the group)`, no ramping, no polling);
  batch-group connections count fully toward `--http-max-per-host` (shared across
  tasks; the hard cap admits no exemption). Anchors: `taiji-http::batch` (the group
  registry / Range queue / soft-budget gate), `taiji-core::session::actor::http_task`
  (the drive_small group-entry wiring), `taiji-core::session::options` (the
  `DECLARED_OPTION_DIFFS` whitelist row); lifecycle/peak/throughput-monotonicity/
  mixed-load anchored tests = `crates/taiji-core/src/session/actor/tests.rs` (the
  five `batch_group_*` tests + `mixed_load_*`).
- **Explicit failure `taiji.http.range_ignored` for a 200 received on a
  download-phase Range request** (B2; a taiji behavior tightening; probe-phase
  semantics unchanged): when a **download-phase** chunking/resume Range request —
  after the probe has confirmed range support (206 + `Content-Range`) — receives a
  200 OK → an explicit task-level failure (the canonical code
  `taiji.http.range_ignored`), terminal on the first occurrence, not burning the
  extent retry cap; the fetch rejects before reading the response body (a 200's
  bytes never reach disk — zero risk of misaligned overwrites). The semantic source
  cross-validates Android Download Manager's `executeDownload` "Expected partial,
  but received OK" → STATUS_CANNOT_RESUME. Same code slot as the **probe-phase**
  200 (spec §4.2 decision-table rows 3/4: an origin honestly not supporting Range →
  single-connection downgrade) but a different meaning: probe phase = capability
  determination downgrade; download phase = a contradiction with the confirmed
  capability (capability drift / lying) — no silent restart from zero, no downgrade
  to a single connection (a full re-download that discards all bitmap progress
  would mask the protocol contradiction; without a `--checksum` backstop, trusting
  a lying server's full body carries a data-correctness risk). The RPC numeric
  surface is finalized as 8 (CANNOT_RESUME, the same slot as `taiji.http.bad_range`
  — the aria2 isRangeSatisfied failure family); the decision landed: one added arm
  in `try_http_numeric_code` + a synchronized mapping-table doc row (the
  numeric-surface e2e anchored test =
  `range_ignored_numeric_surface_is_cannot_resume`, also entered into the
  `http_failure_numeric_end_to_end_production_chain` full-code production chain
  list). Anchors: `taiji-http::error` (`HttpError::RangeIgnored`),
  `taiji-core::session::actor::http_task` (`WorkerRig::fatal_engine`, the
  `HttpRangeTransport::fetch` 200 determination); e2e anchored tests =
  `http_probe_confirmed_then_200_fails_explicitly` (Error after exactly 1 data
  request) + `http_plain_404_keeps_retryable_unexpected_response_path`.
  **A 206 echo mismatch is judged the same way (C2)**: when a **download-phase**
  response is a 206 but its `Content-Range` echo does not match the requested range
  (`taiji.http.bad_range` — every exit of taiji-http's `validate_range_echo`:
  misalignment / missing / unparseable), it belongs to the same code-8 family of
  deterministic protocol contradictions as range_ignored: fatal, terminal on the
  first occurrence, not burning the extent retry cap (before the fix it went
  through the ordinary failure arm and burned the cap on retries), and the final
  name never appears; the terminal failure does **not** enter the 412
  content-restart channel (an echo mismatch is a protocol contradiction, not
  content drift). e2e anchored test =
  `batch_group_bad_range_echo_fails_fast_single_request` (Error after exactly 1
  data request, the canonical code reached directly).
  **Length-dimension relaxation (the abdm-1 decision)**: the previous bullet's
  fast-fail surface narrows to the **start dimension** — when a 206 echo's
  **start matches the requested start**, a body length (Content-Length or the
  chunked final length) ≠ the requested remainder no longer counts as `bad_range`
  and is closed under length-deviation tolerance: over-delivery (a body longer
  than requested) closes the stream once the needed amount is read — the extra
  body is discarded and the connection is closed early (an under-read connection
  does not return to the pool), and this pass books success for the requested
  amount; under-delivery (EOF before the requested end) books the bytes already
  read as partial progress and the unsatisfied remainder goes through the existing
  extent retry (the failure budget resets per the per-fetch write watermark,
  compatible with B1). BadRange fast-fail for start mismatch/missing/pathological
  and 200 → range_ignored explicit failure (the deterministic-contradiction
  family) keep their semantics. Cross-reference Android Download Manager
  `HttpPartDownloader.kt` (an endpoint mismatch is not fatal; with start/cursor
  aligned the download continues); aria2's `isRangeSatisfied` demands an exact
  closed-interval echo (a mismatch means CANNOT_RESUME) — within taiji's
  tightening direction, this relaxation is bounded by "start = the single piece of
  evidence of data alignment". The probe-phase decision table (spec §4.2) is
  unaffected: an endpoint-deviation echo of the probe's `bytes=0-0` is still
  rejected by the probe layer's own table (`BadRange`). Connection-surface impact
  (accurate): the early close on over-delivery means that connection does not
  return to the pool — later extents on the over-delivering origin need to rebuild
  a connection (a connection finished exactly full returns to the pool for reuse
  as before, unchanged); in the h2 shape an under-read stream goes through
  RST_STREAM, and connection reusability is up to the transport. e2e anchored
  tests = `p86_over_delivery_reads_needed_and_closes_early` (Done + exactly 2
  requests + origin filler writes cannot punch through) +
  `p86_short_delivery_completes_via_existing_retry` (Done completed via retry) +
  the regression anchors `p86_start_mismatch_keeps_bad_range_fast_fail` /
  `p86_plain_200_keeps_range_ignored_fast_fail`.
- **429/503 `Retry-After` honored + clamped** (B3; a taiji capability extension;
  aria2 does not read Retry-After and applies only a fixed exponential backoff):
  the `Retry-After` response header of 429/503 (both the seconds and HTTP-date
  forms) enters the extent backoff loop, clamped to `[200ms, 30s]` (the cap =
  RetryPolicy.max_wait, the spec §4.1 backoff cap; prevents a malicious server from
  hanging us). Semantics: the **server value takes precedence** over the default
  backoff pace (throttling waits = a server protocol signal), and `--retry-wait`
  does not override the server value (client backoff parameters and server protocol
  signals are different domains); without the header the default pace is unchanged.
  A probe-phase 429 still stops on the first occurrence (probing has no backoff
  loop). The AIMD 429-Throttled reduction multiplier coexists with the polite wait.
  Anchors: `taiji-http::retry` (`parse_retry_after`/`clamp_retry_after`); e2e
  anchored tests = `http_retry_after_is_honored_between_attempts` (the interval
  ≥900ms, replaced by the server value) +
  `http_throttle_without_retry_after_keeps_default_pace`.
- **Filename platform compatibility (Stance 2: engine-layer sanitization + real-name
  report-back)**: for URL/Content-Disposition-derived names the fork only applies
  percent-encode escaping (MinGW builds only) and directory-traversal detection;
  `--out` bypasses sanitization entirely, with no handling at all for reserved
  names / trailing dots and spaces / length / NFD — illegal names fail at the disk
  API as task errors. taiji sanitizes at the engine layer (the activation-time name
  resolution point), and the post-sanitization/auto-rename name is the task's final
  name:
  - **The full channel for URL-derived names**: illegal characters `< > : " | ? *` +
    control codes (C0/DEL) + path separators → `_`; Windows reserved device names
    (CON/PRN/AUX/NUL/COM1-9/LPT1-9, including with extensions) get `_` appended to
    the stem to preserve the extension; trailing dots/spaces stripped; byte
    truncation preserving the extension (the full form
    `<final name><candidate marker .N><incomplete suffix>` ≤ 254 bytes, with the
    final-name budget shrinking along with `--http-incomplete-suffix`, default
    247); an empty name falls back to `download`.
  - **The light channel for user-explicit names (out=)**: path components stripped
    (including `X:` drive prefixes) + the same length truncation + reserved-name
    suffixing; **no character replacement** (user-provided names are touched
    minimally; illegal characters are left for the OS to report). The acceptance
    surface's existing sanitized rejections for `--out` (separators/`:`/reserved
    names/trailing dots and spaces) are unchanged; the light channel adds the
    length validation the acceptance surface lacks.
  - **Real-name report-back**: `tellStatus`/`getFiles`'s `files[0].path` (the live
    `outPath` and terminal-state entry snapshots), the sqlite row's `out` (the same
    source as recovery/renamePending closure), and the completion log all carry the
    actual on-disk name; cold projection (paused/terminal with no live read)
    prefers the row-mirror planned final name over the acceptance surface's
    original out. The six event payloads `[{gid}]` stay frozen (the fork's same
    shape; the frontend takes the gid + tellStatus for the name).
  - **Explicit non-goals**: macOS NFD normalization (the fork and every surveyed
    competitor skip it); `\\?\` long-path prefixes (the industry substitutes
    byte-cap truncation); FAT32/exFAT special-casing (implicitly covered by the
    254 budget); auto-rename multi-digit sequence numbers may still exceed
    NAME_MAX on extremely long names (stem > budget−5 bytes) (surge's 240 covers
    all / Firefox's 254 overflows the same way — the same class of trade-off).
  - Anchor: `taiji-http::naming` (`sanitize_generated_name_with_budget`/
    `sanitize_user_name_with_budget`/`engine_name_budget`) +
    `taiji-core::session::actor::http_task` (the drive name-resolution point).
- **FTP/FTPS**: charsets = UTF-8 first for paths with a Latin-1 fallback transcode
  (the fork does no conversion); `--ftp-pasv=false` (active mode) explicitly
  rejected (the fork supports PORT); `--ftp-ssl=none|auth(default)|implicit` is a
  taiji capability extension (the fork has no FTPS; the `ftps://` scheme is not
  accepted as URI input); the anonymous password defaults to `anonymous@`
  (fork = `ARIA2USER@`); an FTP server without SIZE support = the source is dropped
  (the fork can stream without a total length; taiji tightens this); a REST
  rejection = downgrade to a single connection with no bitmap (the same rule on
  both sides).
- For the **metalink option family** see §6; for the **proxy/cookie surfaces** see
  §3.
- **The import consumption surface** (`taiji import`): the header/UA/proxy/credential
  fields of the fork's serialized option lines are folded in when the activation
  assembles requests (parsing and rejection share one source with addUri — an
  illegal value fails explicitly at task level; socks proxies = a declared taiji
  transport-surface limitation, explicitly rejected, no bypass to direct
  connection); the scheduling/timeout domains are rebuilt to the new session
  defaults (the runtime-option-not-persisted semantics; the fork's scheduling model
  is outside the cross-validation commitment). Fork cookies are not part of the
  serialized task format — an imported task activates with an empty task cookie
  set, and Set-Cookie is captured as usual during activation; a cookie-gated source
  requires rebuilding the session on the source side (stated in the import preflight
  checklist). Anchors: `taiji-core::session::actor::http_task`
  (`fold_imported_options`), `taiji-core::session::persist::import_http`
  (`PREFLIGHT_CHECKLIST`).
- **The addUri-surface value domain of `http-max-per-host` (A3)**: `1..=2^32-1`
  (the u32 domain) — the same domain as the CLI surface, rejected explicitly: an
  addUri option value > 2^32-1 reports `taiji.option.invalid` and the task is
  rejected (**no row is persisted**). Before the fix, `parse_u64_domain` accepted
  any u64 and the effective surface's `set_cap` silently clamped to u32::MAX —
  acceptance without effect is a masquerade; this closes in line with the
  changeOption discipline of spec §4.3 "out-of-domain values are always rejected,
  never truncated". Anchor: `taiji-core::session::actor::tasks` (the addUri
  cap-parsing domain check); e2e anchored test =
  `add_uri_host_cap_domain_rejects_above_u32_without_row` (2^33 rejected + zero
  rows; the domain upper bound 2^32-1 accepted with the cap intent fixed in the
  row).
- **The restart semantics of `http-max-per-host` cap adjustments (A4)**: an addUri
  cap adjustment is persisted with the task row's `config_json` (the `host_cap`
  key); on daemon restart/resume activation the cap intent of **that task** is
  restored through the same channel as addUri (`HostCap::set_cap`, last-set-wins) —
  the existing §3 declaration only covers "no in-session echo drift"; this entry
  completes the cross-restart surface. Boundaries: task rows without this option do
  not carry the key and activation does nothing (no cross-contamination of other
  task rows); the semantics of the session HostCap **initialization value**
  (CLI/global options) are unchanged — recovery goes through the
  runtime-adjustment channel, not a rewrite of the initialization surface; the
  in-session addUri immediate last-set-wins behavior is unchanged
  (activation-surface recovery = the same semantics continued across a restart; a
  resume activation counts as a new last-set). Anchors:
  `taiji-core::session::actor::http_task` (`HttpPersistConfig::host_cap`),
  `taiji-core::session::actor::tasks` (addUri fixation + activation recovery);
  e2e anchored test = `host_cap_intent_persists_and_resumes_lowered_after_restart`
  (cap lowered to 2 → shutdown → restart+resume with the default cap 64 → the true
  peak of concurrent origin Ranges is still 2).
- **The resume capability-regression semantics, now documented (the abdm-2
  decision: no behavior change, declaration only)**: when a task that was once
  chunked (bitmap present) is restarted/reactivated and the probe finds the server
  **no longer supports Range** (probe-phase 200 → single-connection downgrade,
  spec §4.2 decision-table rows 3/4) — the semantics = a silent restart from zero
  (the bitmap is not consumed; the downgraded path does a full GET) + the
  restarted semantics (named with the same semantics as `ResumeDecision::Restart`'s
  restarted face), aligned with the aria2 reference (aria2 likewise restarts from
  zero on capability regression and does not fail separately). The dual correctness
  backstops are unchanged: `--checksum` final adjudication at completion (numeric
  surface 32) + If-Match strong-ETag conditional-resume server-side precondition
  checks (B4 — content drift is rejected with 412 during download and the bitmap is
  cleared for a from-zero restart, rather than being discovered by the checksum
  only after the bitmap is fully written). The awareness surface (the fact that
  the probe conclusion regressed from "range-capable" to "not supported") is
  consumed by the product layer via RPC events; no new code slot is added on this
  declaration surface. Anchors: `taiji-http::probe` (the §4.2 decision table),
  `taiji-core::session::http::resume` (`ResumeDecision`/the restarted semantics).

## 9. Remote access and exposure surface (difference declarations)

This section declares the **supported topology and exposure-surface behavior**
(not an aria2 cross-validation difference — aria2 has no corresponding guard
surface; the difference direction = taiji security enhancements). Anchors:
`taiji-rpc::guards` (the connection ledger + auth backoff), `taiji-rpc::server`
(`conn_gate`/`basic_gate`/weak-credential warning/combined guards).

- **Supported topology**: binding and credentials are **two decoupled axes**
  (cross-validated against aria2 `HttpListenCommand.cc` — binding looks only at
  `--rpc-listen-all`, default false = loopback only, `OptionHandlerFactory.cc`
  A2_V_FALSE same rule): loopback (default, **regardless of credentials** —
  setting `--rpc-secret` or `--rpc-user/--rpc-passwd` no longer implicitly widens
  the surface; credentials only decide the auth gate) → `--rpc-listen-all`
  explicitly opens → 0.0.0.0 (all interfaces). Controlled difference (direction =
  taiji security enhancement; for the same combination aria2 only WARNs and
  listens as usual, DownloadEngineFactory.cc): `--rpc-listen-all` with no
  credentials at all → **rejected at startup** (fail-closed; the message includes
  remediation guidance: set `--rpc-secret` (recommended) or
  `--rpc-user/--rpc-passwd`, or drop listen-all to restore loopback). The
  credential-less loopback form keeps the upstream WARN wording + a fail-closed
  write surface, see §1 "Unauthenticated write gate". **Exposed bare deployment on
  the public internet is not supported** — the RPC surface is plaintext HTTP (no
  TLS; the ecosystem convention is tunnel solutions: wireguard/tailscale/ssh
  forward carry confidentiality and integrity), and there is no tenant isolation
  (next bullet); the plaintext assumption = credentials can be intercepted by
  on-path observers and must be absorbed by the tunnel layer.
- **Multi-client semantics**: a single session shares one queue — when multiple
  clients connect with the same credentials they see and operate on the **same**
  task set / global options; no tenant isolation, no per-client queue (consistent
  with the fork; the fork is likewise a global single session).
- **Connection limits (engine constants, not CLI knobs)**: total concurrent
  connections (HTTP in-flight requests + WS sessions combined) capped at 256; per
  source IP capped at 32. Over-limit rejections: HTTP 503 / WS rejected before
  upgrade (101 never sent), counted in the
  `taiji_rpc_conn_rejected_total{scope=total|per_ip}` metric + a warn. Normal
  local/single-client usage stays far below the thresholds (the gate applies to
  every binding surface and normal use never trips it).
- **Auth-failure backoff**: ≥5 consecutive auth failures from one source IP (token
  gate and Basic gate counted jointly) open an exponential backoff window (first
  1s, then ×2 per failure, capped at 60s); during the window every auth attempt
  from that source (**including correct credentials**) is delayed until the window
  ends before processing — a same-source legitimate client is also delayed during
  an attack (per-source penalty; NAT-shared sources likewise); a successful auth
  resets the counter. Metrics: `taiji_rpc_auth_fail_total` (no IP-dimension label —
  label cardinality discipline) + the `taiji_rpc_auth_backoff_active` gauge
  (number of sources with an active window).
- **Weak-credential warning**: if `--rpc-secret` is set and shorter than 16
  characters → one startup warn (16+ characters recommended); startup is not
  refused, zero behavior change.
- **listen-all anonymous-surface tightening**: when `--rpc-listen-all` is on +
  `--rpc-secret` is set, and Basic is unset **or user-only** (only `--rpc-user` set
  without `--rpc-passwd` → the password is not checked, zero entropy — the same
  ruling: knowing the username gets through the Basic transport gate and cannot
  count as a valid credential; this includes the remediation-path form recommended
  by the combined-guard message), both anonymous surfaces are guarded by the secret
  itself (a controlled difference, direction = taiji security enhancement; aria2
  has no metrics surface and pushes notifications to connections that already
  completed the WS upgrade, with no event-surface auth): the only gate for
  `GET /metrics` = `Authorization: Bearer <secret>` (constant-time comparison;
  anonymous / user-only Basic / a wrong Bearer → 401 + a 1s unauthorized delay,
  with the failure counted into the auth-backoff ledger — in this form the Basic
  gate does not stack on top: both gates share the same Authorization header and
  user-only Basic adds no credential entropy); the Basic transport gate keeps
  guarding WS upgrades and `/jsonrpc`, and WS event-stream subscription is
  deferred until the first Text message carrying a legal `token:` first parameter
  — an invalid/non-token first message is disconnected after consuming the 1s
  delay. All other forms (secret unset / non-listen-all / Basic with a password)
  keep the current behavior (`/metrics` anonymously readable on loopback, WS
  subscription upon upgrade).

HTTP output publication adds `taiji.onHttpOutputReady` in both native and compatibility modes, including `system.listNotifications`. The original six compatibility event names and order remain unchanged; the differential excludes only this explicitly declared addition.

With partial file selection, task progress counts selected payload bytes. aria2 rounds its filtered length to the involved pieces; taiji excludes shared boundary-piece overhead from file progress. Completion still waits for verification and writing of every required piece.

Global echo extensions also include the IPv6 DHT entry `dht-entry-point6`, `motrix-peer-listeners` (bound BT listeners), and `motrix-startup-tasks` (held recovery tasks and run intent). Reference builds may already echo keys such as `async-dns` depending on compiled features. Those keys are checked as shared values; every remaining native-only key must still appear in the explicit audit table.
