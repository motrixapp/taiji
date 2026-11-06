# Domain policies — upstream anchor mapping

Design-policy notes distilled out of the `taiji-domain` module headers.
Each section maps a module's local policy onto its upstream (aria2 /
libtorrent) reference, file + symbol level only.

## redial.rs — peer redial pool (libtorrent reconnect machinery)

Reference: libtorrent RC_2_0 (BSD-3).

- **min_reconnect_time = 60s**: `src/settings_pack.cpp`
  `SET(min_reconnect_time, 60, nullptr)` — the redial cadence base.
- **Reconnect gate**: `src/peer_list.cpp`
  `session_time - last_connected < (failcount + 1) * min_reconnect_time ->
  continue` — after a disconnect, no reconnect for
  (failcount + 1) x 60s; a first reconnect waits 60s (failcount = 0),
  the same value as the pool's `REDIAL_BASE`.
- **Failure cap**: `src/settings_pack.cpp` `SET(max_failcount, 3, ...)`
  plus `src/peer_list.cpp` `failcount >= m_max_failcount` losing
  connect-candidate status — after 3 consecutive connection failures the
  peer is not retried (it does not squat forever); the pool's
  `REDIAL_MAX_FAILURES` matches.
- **Backoff shape (intentional divergence, retired)**: libtorrent is
  linear, `(failcount + 1) x min_reconnect_time` (peer_list.cpp). The
  pool originally held an exponential backoff with a cap; that divergence
  was retired in favor of the linear transcription (`redial_backoff`).
  Backoff is local scheduling policy, not wire behavior — either shape is
  interoperability-neutral.
- **Fast-dial for departed data-delivering peers**: libtorrent (RC_2_1)
  has no fast tier — the only reconnect gate is
  `(failcount + 1) x min_reconnect_time` (`src/peer_list.cpp`). The
  `FAST_RECONNECT_BASE` tier is an intentional divergence: it applies
  only to the first redial after a data-delivering peer departs; a miss
  falls back to the 60s regime, and the failure gradient plus
  max_failcount = 3 eviction are preserved unchanged.
- **Cap value**: `REDIAL_BACKOFF_CAP` = 1800s, the announce interval's
  magnitude (past it the tracker re-supplies new candidates; longer
  redial waits add nothing).
- **Stale-peer lesson**: the pool has no "unverified peer" admission
  path — the only entry point `RedialPool::note_departure` is called by
  the engine only when a peer that completed the BT handshake and was
  registered departs (raw DHT/PEX/tracker addresses never enter);
  outbound connections only, since an inbound peer's remote port is an
  ephemeral source port and cannot be redialed (the same boundary as PEX
  fresh bookkeeping, `UTPexExtensionMessage.cc`).

## seed.rs — seeding stop policy (aria2 criteria transcription)

Reference: aria2 source, read-only.

- [`SeedCriteria`]: `SeedCriteria.h` (`evaluate()` returns true when
  satisfied / `reset()` clears state).
- [`ShareRatioSeedCriteria`]: `ShareRatioSeedCriteria.cc` —
  `completedLength == 0 -> true` (divide-by-zero semantics, never
  relaxed); otherwise
  `ratio <= (uploadLengthAtStartup + sessionUploadLength) /
  completedLength`. `uploadLengthAtStartup` comes from the `.aria2`
  control file's `uploadLength` (read back by
  `DefaultBtProgressInfoFile.cc`); this engine's counterpart is
  `torrent_progress.upload_at_startup`.
- [`TimeSeedCriteria`]: `TimeSeedCriteria.cc` — `reset()` restarts the
  timer on the wallclock (`watch_ = global::wallclock()`), `evaluate()`
  = `watch_.difference(now) >= duration`.
- [`UnionSeedCriteria`]: `UnionSeedCriteria.cc` — satisfied when any
  sub-criterion is satisfied; `reset()` cascades to all sub-criteria.
- [`SeedCheck`] (a SeedCheckCommand transcription): `SeedCheckCommand.cc`
  — the `checkStarted` latch: set on the first tick where
  `downloadFinished()` is true, which also calls `criteria->reset()`
  (timing/evaluation begins at the download-completion moment); once
  set, each evaluation that is satisfied calls
  `btRuntime->setHalt(true)` (seeding ends). With no criteria (an empty
  Union) no SeedCheck is attached (`BtSetup.cc`).
- Criteria assembly: `BtSetup.cc` — `seed-time` attaches
  TimeSeedCriteria only when the option is **defined** (value in
  seconds; aria2's option face is minutes x 60, `BtSetup.cc`; undefined
  by default -> not attached); ShareRatio attaches only when
  `seed-ratio > 0.0`.
- [`BtStopTimeoutWatch`] (a BtStopDownloadCommand transcription): 1s
  tick (`BtStopDownloadCommand.cc`
  `TimeBasedCommand(cuid, e, 1_s)`); mounted only when
  `--bt-stop-timeout > 0` (`BtSetup.cc`); each tick with download speed
  > 0 resets the checkpoint; checkpoint older than the timeout -> forced
  stop ("Stop downloading torrent due to --bt-stop-timeout option.");
  the command exits after download completion / halt (active only during
  download).
- [`SessionSpeedCalc`] (a minimal SpeedCalc): 10s sliding window
  (`SpeedCalc.cc` `WINDOW_TIME = 10_s`); stale slots dropped, byte/time
  mean computed from the first slot (`SpeedCalc.cc`). The reference
  clamps elapsed <= 0 to 1ms; the local `as_millis()` truncation of
  sub-millisecond spans to 0 is clamped the same way, removing a
  zero-divisor panic.
- bt-detach-seed-only predicate: [`seed_only_detached`] <-
  `RequestGroup.cc` `enableSeedOnly()` — with the option on and the
  download finished, sets `seedOnly_` and calls
  `requestGroupMan_->decreaseNumActive()` + `requestQueueCheck()`
  (seed-only does not occupy a --max-concurrent-downloads slot). This
  module delivers the predicate and the engine return path. **Boundary
  note corrected (the earlier "Detached: exit on
  completion, no seeding residency" note was stale)**: the engine's
  completion path enters seeding residency (completion → `SeedingStarted`
  → the session's seed registry; seed criteria/stop decide the exit),
  and under the four-pool model the download slot is released at that
  flip — `bt-detach-seed-only` is behaviorally constant-true, the
  engine keeps only the `Detached` terminal variant as the semantic
  marker of a task that once seeded. The slot accounting lives in the
  session queue (the `begin_seeding` release-then-backfill), not in
  this module.

## silent.rs — silent-abandon failure ledger (libtorrent failcount)

Reference: libtorrent RC_2_0 (BSD-3).

- **Granularity**: per (ip, port) endpoint — the same granularity as
  `src/peer_list.cpp` `match_peer_endpoint(address, port)`; a peer
  changing ports naturally gets a fresh endpoint (one of the criteria
  for "new evidence re-entry").
- **Threshold**: `SILENT_MAX_FAILS` = 3, matching
  `src/settings_pack.cpp` `SET(max_failcount, 3, ...)` plus
  `src/peer_list.cpp` `int(p.failcount) >= m_max_failcount` losing
  connect-candidate status (3 consecutive failures stop dial attempts —
  this module takes a cooldown rather than deletion).
- **Backoff shape divergence (deliberate)**: libtorrent's reconnect gate
  is linear `(failcount + 1) x min_reconnect_time` (`src/peer_list.cpp`);
  this module specifies exponential backoff with a cap. Backoff is local
  scheduling policy, not wire behavior — interoperability-neutral. The
  base `SILENT_BACKOFF_BASE` = 120s = 2 x min_reconnect_time
  (`src/settings_pack.cpp` SET(min_reconnect_time, 60)) — silent
  endpoints back off more aggressively than previously-successful peers
  (60s base).
- **Cap**: `SILENT_BACKOFF_CAP` = 600s (10min).
- **Cooldown**: at the threshold the endpoint enters the cooldown table,
  `SILENT_COOLDOWN` = 1800s = the announce interval's magnitude (same
  reason as the cap: past it the tracker re-supplies new candidates).
  Cooldown expiry auto-recovers and resets the count (`src/peer_list.cpp`
  "somebody else is apparently able to connect to it" — the same spirit
  as libtorrent lowering failcount on liveness evidence: no permanent
  bans, peers may revive). **Permanent blacklisting is the IpGuard face;
  this module never crosses that boundary.**
- **New-evidence reset**: any transport handshake success (a successful
  outbound dial report, or a full success report from a peer rebuilding
  the connection via hole punching or similar) -> entry removed, count
  reset (same direction as `src/peer_list.cpp` set_failcount zeroing on
  success).
