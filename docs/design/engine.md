# Engine design notes (upstream anchor mapping)

Per-module upstream anchors and reference essays for taiji-engine.
Code headers in the source files keep only a mechanism summary and point
here.

## choke.rs

Sources: libtorrent `choker.cpp`, `session_impl.cpp`, `peer_connection.cpp`,
`torrent.cpp`; aria2 `BtLeecherStateChoke.cc`, `BtSeederStateChoke.cc`;
BEP3 (after a choke, requests are answered with reject).

### Budget-derived slots seam

The choke decision face (taiji-bt `LeecherChoke`) cannot reach the
`LimiterSet`: the rate-limiting topology lives engine-side on
`DialCtx.limiter` and stays out of the bt crate. The engine-side assembly
point (`budget_derived_slots`, read once per 15s choke round) derives N
via `budget_unchoke_slots` — `per_torrent.up` bucket rate (the session
upload limit; `--max-upload-limit` reaches the bucket through
SpeedLimits -> LimiterSet), per-peer floor `BH_UNCHOKE_PER_PEER_FLOOR_BPS`,
static fallback `BH_UNCHOKE_SLOTS` — and passes N through
`LeecherChoke::select_with_slots`'s `total_slots` parameter.

### Leecher round divergence note

libtorrent regular sort keys (`choker.cpp`): bandwidth priority -> bytes
received last round (`downloaded_in_last_round`) -> state-keeping
preference (quota completion / wait time). This repo keeps the aria2
port's regular key (30s-window download rate descending). The libtorrent
upgrade covers slots / optimistic choice / round interval / preemptive
unchoke only; the aria2 fallback (`BtLeecherStateChoke`: 3 regular slots,
planned optimistic shuffle, fast handoff) is preserved unchanged.

### Seeder round

libtorrent mode = fastest_upload (`choker.cpp`); the sort key is fed from
the engine's `peer_rates.up` 10s sliding window (rate sampled per peer
from `peer_state.rates`). aria2 fallback = the ported ordering
outstanding > recent > rate (`BtSeederStateChoke`).

### Preemptive unchoke

libtorrent unchoke's a peer as soon as it sends INTERESTED
(`peer_connection.cpp`) subject to a free-slot check (`session_impl.cpp`).
libtorrent tolerates a momentary overshoot that the regular round reins
in (`torrent.cpp` comment); this repo's pass likewise does not enter
`regular_unchoked` and converges on the next round. The count feeding the
free-slot check is the `am_unchoked` bookkeeping maintained by the round
and the pass itself.

## stall.rs

A stall window is seeder slot starvation: the unchoke slots stick to
active downloaders (seeder-side outstanding-upload first key,
`BtSeederStateChoke.cc`), so the optimistic rotation (1 random slot per
round, `BtSeederStateChoke.cc`) never lands on us; during DL=0 the
connection count keeps growing without delivering bytes.

### Countermeasures considered

Adopted:

- **Urgent re-announce** — fresh discovery face + redial supply. aria2
  `ActivePeerConnectionCommand.cc` forces an early announce via
  `btAnnounce_->overrideMinInterval(DEFAULT_ANNOUNCE_INTERVAL)` when the
  download stalls and connections drop to zero; this side sends
  `TrackerCommand::Reannounce` (resetAnnounce semantics). The actor's
  per-tracker min_interval compliance gate is kept as-is — a protocol
  line, no override face.
- **Seeder rotation** (conservative cap) — disconnect connections that
  are full-bitmap (seeder) ∧ choking us ∧ zero supply for
  `SEEDER_ROTATE_IDLE_SECS`; the peer enters the redial pool via the
  leave arm (outbound, backoff from `REDIAL_BASE` 60s, sequential single
  connection — never multiple connections to the same seeder). aria2
  anchors: `PREF_BT_TIMEOUT` default 180s disconnect without inbound
  activity (`OptionHandlerFactory.cc` + `PeerAbstractCommand.cc`) plus
  the rotation pressure of `ActivePeerConnectionCommand.cc` adding 5
  connections every 10s during slow downloads — the same pressure aimed
  at zero-supply seeder connections, capped by `SEEDER_ROTATE_BATCH` per
  action window. The value of a reconnect is not better optimistic-draw
  odds (seeder draws are uniform); it is stuck-connection self-healing
  (dead TCP/µTP, peer restart) + bookkeeping reclamation + a fresh
  optimistic ticket. aria2's 180s silent disconnect produces the same
  dynamics on a comparable swarm.
- **Dispatch reset** (cheap) — during a stall, register the dispatch
  debt face for a full extra round: a fallback re-round beyond the
  unchoke-edge re-dispatch (self-healing for request timeouts / lost
  events); the in-round decision order is unchanged.

Rejected:

- **Multiple connections to one seeder** — a protocol/etiquette line.
- **Re-announce `key` re-shuffling** — tracker identity confusion, not a
  legitimate client countermeasure.
- **Optimistic credit bookkeeping** — the redial pool's `had_data`
  eviction-order key plus the admission target->hard-cap top-up band
  already express "peers that delivered before come first"; the benefit
  of a new bookkeeping face was unclear.

### Knobs

- `STALL_DETECT_SECS` = 10: raw 1s differencing, not a sliding mean
  (window decay would postpone stall onset by ~one window); 10s is far
  below the shortest real stall and above transient slot-switch gaps.
- `STALL_ACTION_PERIOD` = 30s: between aria2's 30s choke round and
  `ActivePeerConnectionCommand`'s 10s replenish window; re-announce is
  hard-gated by tracker min_interval, so denser actions buy nothing.

## run/ecology.rs

Connection ecology governance: session-level dial throttling
(connection_speed token bucket) + the discovery-face candidate table
(synthesized sort keys + O(300) sampled top-N) + peer turnover, plus the
µTP zero-throughput, hostile-dial adaptation, and slow-peer-eviction
governance faces.

Reference: libtorrent RC_2_1 @53acefea9.

### Dial throttling (connection_speed token bucket)

- `try_connect_more_peers` grants `connection_speed` per tick
  (`src/session_impl.cpp`; tracker/DHT batch-response connect boosts are
  deducted from the quota — `m_boost_connections`: boosts go first,
  regular candidates stop dialing once the quota is exhausted, boosts
  carry across ticks). Default 30/s (`src/settings_pack.cpp`).
- Here: the token bucket lives inside the main-loop single writer (rate
  accrues continuously, 1s burst cap); every outbound dial takes 1 token
  at the spawn point (`state::spawn_peer_dial`). With the quota exhausted
  a dial is skipped without waiting — discovery candidates stay queued
  for the next drain (the boost carry-over analogy); redial entries
  self-heal via the optimistic `due()` extension (redial.rs docs); punch
  dials are exempt (introducer-asserted external evidence of
  reachability + the PeerTask-layer 4/60s self-limit, the same scope as
  the `state::DialSource` docs).
- The reference `smooth_connects` (quota clamped to limit/2) is carried
  by the 1s burst cap — the shapes differ but the "dial burst clamping"
  semantics point the same way.

### Candidate sort-key synthesis

`src/peer_list.cpp` `compare_peer` key chain, priority high to low:

1. lower failcount;
2. local address (`is_local`); here = `dht::is_exempt_ip` (the
   RFC1918/loopback/link-local/CGNAT exempt set, documented as aligned
   with `ip_helpers.cpp`);
3. earlier `last_connected` (never connected = first);
4. the `finished && maybe_upload_only` demotion key is OMITTED:
   discovery candidates are un-handshaken addresses, and
   upload-only/maybe_upload_only is decidable only for connected peers
   (BEP21/ext handshake). Connected-peer records exist
   (`PeerMeta::upload_only`, mirrored in on the inbound ext handshake,
   living with the connection), but the candidate key needs a
   cross-connection address-level projection (demote again when the peer
   disconnects and the candidate returns to the table); no such
   bookkeeping exists yet. The key slot is documented (between
   last_connected and source_rank) for future adoption;
5. higher source_rank (tracker > lsd > dht > pex,
   `src/request_blocks.cpp`);
6. higher BEP-40 symmetric rank (`src/torrent_peer.cpp`;
   `taiji_bt::peer_policy::bep40_rank`).

Candidate collection = O(300) round-robin-start sampling + top-N, not a
full sort (`src/peer_list.cpp`: `iterations = min(m_peers.size(), 300)`
round robin + `candidate_count = 10` truncation; here N = the round's
remaining dial budget).

### Reconnect gate (linear adoption)

`(failcount+1) x min_reconnect_time(60s)` (`src/peer_list.cpp`) —
`taiji_domain::redial::redial_backoff` is linear from this anchor on
(the earlier exponential divergence retired; see the redial.rs module
docs).

### Peer turnover

- Trigger: `connections_limit x peer_turnover_cutoff (90%)`, then
  optimistically disconnect `peer_turnover (4%)` (>=1) worst connections
  (`src/session_impl.cpp`). "Worst" order = the `compare_disconnect_peer`
  key chain (`src/torrent.cpp`, per-key mapping on `compare_disconnect`):
  is_disconnecting (omitted: an immediate shutdown, no disconnecting
  state) -> is_interesting -> is_seed -> on_parole (omitted: smart_ban
  absent) -> transfer (carried: the 30s download-window rate replaces
  `total_payload_download / time_connected`) -> is_choked
  (`PeerTaskHandle::is_choking_us`) -> last_received (omitted: no
  per-peer last-activity projection; the chain-tail tiebreak converges
  on the stable order). Truncation = partial_sort_copy.
- Disconnect-count divergence: the reference uses
  `min(max(n x 4%, 1), num_connect_candidates())` (session_impl.cpp);
  this codebase has no candidate-bookkeeping reading, so
  `max(n x 4%, 1)` carries no upper cap (4% is a small step anyway). The
  slow-churn predicate adopts the candidate cap.
- Interval divergence: the reference source comment pins "every 90
  seconds" (session_impl.cpp) while the setting default is
  `peer_turnover_interval = 300s` (settings_pack.cpp); this codebase
  takes 90s (higher rotation pressure).
- Division of labour: turnover governs "rigidity near the cap"
  (periodic, count-driven); the stall-valve seeder rotation (`run::stall`)
  governs "zero-rate seeds" (stall-driven, supply-recovery oriented).
  The two rotation predicates and their caps are independent; neither
  substitutes for the other.

### µTP zero-throughput connection governance

- Mechanism: LEDBAT yield semantics (BEP29 `CCONTROL_TARGET` 100ms; the
  `taiji-io::utp::ledbat` gain formula) under direct-TCP mixed traffic
  can hold `our_delay >= target`, so `delay_factor <= 0` keeps shrinking
  the window to the 150B floor; an idle connection (no in-flight
  packets) never triggers RTO, so it stays alive occupying a slot.
- Reference: `mixed_mode_algorithm = prefer_tcp` is implemented as
  setting the TCP peer class rate limits to 0 (`src/session_impl.cpp`,
  `set_{up,down}load_rate_limit(m_tcp_peer_class, 0)`); µTP yielding
  relies on LEDBAT itself plus RTO disconnecting after 3 consecutive
  timeouts (`utp_stream.cpp`). This codebase has no per-class rate-limit
  layer, so TCP is already unthrottled by µTP congestion signals — the
  rate-limiting half of prefer_tcp is naturally equivalent. The gap is
  the slot occupancy of zero-throughput µTP connections, for which the
  reference has no "zero-throughput disconnect" face to mirror.
  Intentional divergence: the engine face governs zero throughput to
  reach prefer_tcp's behaviour goal (µTP does not hog the path; slots go
  to TCP candidates); disconnects use the existing graceful shutdown
  (turnover shape; the leave arm reclaims naturally).
- Criteria: `Transport::Utp` && both directions zero-throughput (30s
  download window + 10s upload sliding window both 0) sustained for
  `UTP_MUTE_AFTER` (120s = one full rollover of the BEP29 base_delay
  two-minute sliding window — in a zero-throughput state the base bucket
  rolling over is LEDBAT's only self-recovery path; still zero output
  past the window means no recovery) -> disconnect. Same order of
  magnitude as the 90s turnover period. Fallback `BH_UTP_MUTE=0`
  (default on; off restores prior behaviour bit-for-bit).

### Self-endpoint BEP-40 note

BEP-40 rank symmetry requires both sides to compute from the same local
endpoint. The self reference = `probe_source_ip(false)` probed at
assembly (the v4 route source, the same source as the BEP42 derivation,
matching the `dht::security` divergence note). Behind NAT, a discovered
RFC1918 source degrades symmetry to a deterministic in-table tiebreak
(the DHT external-ip vote is not wired). v6 candidates have no self
reference yet (the v6 probe carries up to a 2s TCP timeout and cannot
enter the assembly critical path) -> the rank key takes the neutral 0
(sorting degrades to the keys before rank).

### Hostile-dial acceleration

- connect_speed environment adaptation (no reference counterpart —
  libtorrent `connection_speed` is a static setting; the vendored 2.1.1
  `session_impl.cpp` `update_connection_speed` only clamps negative
  values to 200, the reference's own "reasonable upper bound" semantic):
  when the dial-outcome window (`DialOutcomeWindow`) failure rate
  exceeds `DIAL_FAILURE_RATE_PCT` (with at least
  `DIAL_FAILURE_MIN_ATTEMPTS` samples), the rate shifts
  `CONNECTION_SPEED` -> `CONNECTION_SPEED_HOSTILE`, falling back when
  the window recovers; an explicit `BH_CONNECT_SPEED` wins (fallback =
  `BH_CONNECT_SPEED=30` pins the fixed default). The shift point = the
  drain-round entry (250ms cadence, not hot path).
- Dial budget cap: the drain budget reads `min(available tokens,
  candidate backlog, DIAL_HALFOPEN_CAP)` — the backlog term = "no faster
  than candidates are supplied" (slow down as the backlog shrinks); the
  512 term is the half-open concurrency guard (rate x the 10s TCP dial
  budget = the instantaneous half-open bound; home-router NAT tables
  hold roughly 1024-4096 entries). At the defaults it does not bind
  (hostile 100 < 512); it binds under large `BH_CONNECT_SPEED`
  overrides.
- v6 candidate preference key (`CandidateRow::v6_preferred`, key
  position after is_local): when the assembly-time
  `probe_source_ip(true)` global v6 probe (BEP7 `ipv6=` reuse, zero new
  probes) is available, v6 candidates are preferred — v6 peers often
  bypass NAT (BiglyBT's "prefer what connects" advice; reference
  `compare_peer` has no such key, intentional divergence). With v6
  unavailable or `BH_V6_PREF=0` the key is constantly false = neutral.

### Gear-shift oscillation fix (gear hold)

Observed failure mode: after shifting 30 -> 100, the next window rolled
to zero samples and the "zero samples = normal" guard misjudged a
fallback to 30, oscillating. Two arms fix it: (a) with insufficient
samples (< `DIAL_FAILURE_MIN_ATTEMPTS`) the current gear is HELD instead
of falling back to base — the >=20-sample guard becomes the sole
evidence gate for shifts in both directions; (b) at the shift point the
observation window is re-anchored without clearing: the window start
moves to the shift instant and counters are kept, so the shift evidence
stays visible inside the re-anchored window (the rolling clear is
deferred until a full window after the re-anchor). `BH_CONNECT_SPEED_
HOLD=0` restores prior behaviour bit-for-bit (insufficient samples ->
base + no re-anchor); the shift semantics (>=20 samples && strictly
>50%) and the override-pinning face are untouched.

### Slow-peer eviction

- Predicate (`slow_peer_churn_tick`, 30s cadence): connected peers of
  non-completed faces, ranked by the 30s download-window rate, lower
  median; the line = median x `BH_SLOW_PEER_FRAC`% (default 100); per
  round K = max(1, n x `BH_SLOW_PEER_K_PCT`%) (default 10%) worst peers
  (down_rate ascending, ties non-interesting first, then cuid ascending)
  are shut down gracefully; new peers inside the observation period
  (`BH_SLOW_PEER_MIN_AGE_SECS`, default 45s < a full 30s window) are
  exempt; the pool-floor gate `SLOW_CHURN_MIN_POOL` (8) leaves small
  swarms alone; **candidates = 0 means no replacement, no disconnect** —
  adopting the reference candidate cap
  `min(max(n x 4%, 1), num_connect_candidates())` (session_impl.cpp),
  closing the turnover divergence gap above; the candidate reading =
  `dial_candidates.len()` (a ready-made drain-round face). median=0 (an
  all-zero pool) -> threshold 0 -> nobody evictable (an all-zero pool is
  left to the stall valve / utp_mute; this predicate governs only
  "online but slow").
- Eviction marks (`SLOW_CHURN_MARK_TTL` 300s): the addr is recorded
  before the disconnect and consumed by the leave arm's redial
  admission — on a hit within the TTL, had_data is forced false onto the
  60s base tier (the libtorrent `min_reconnect_time` default, gate
  `(f+1) x 60` in peer_list.cpp), preventing the 5s first redial from
  re-dialing an "online but slow" peer straight into an idle slot — the
  redial fast path targets "peers that had delivered data and went
  missing" (session-restart churn; redial.rs source ranks), slow-evicted
  peers are not missing (divergence documented on `slow_evict_marked`).
- External cross-check: aggressive eviction of unproductive peers
  (other clients drop dead peers at scale); the 30s cadence x 10% per
  round sits between the reference turnover pressure and those
  aggressive policies. Fallback `BH_SLOW_PEER_CHURN=0` restores prior
  behaviour wholesale.
- Division of labour (the active-disconnect family): turnover governs
  rigidity near the cap (count-driven), utp_mute governs zero-throughput
  µTP (transport gate + both-way zero + window), slow_churn governs
  online-but-slow TCP (rate-distribution driven) — three independent
  predicates; the stall valve's seeder rotation (`run::stall`) governs
  zero-rate seeds, independent of all three.

### Bounded discipline

Candidate-table capacity `DIAL_CANDIDATE_CAP` (full rejects new entries,
counted) with TTL sweep; budget/table/rotation bookkeeping is all
main-loop exclusive (no shared locks); time is an injected `Instant`;
unit tests never sleep (the silent.rs / redial.rs style).

## strategy.rs

- Scheduler policy surface: `SchedulerPolicy` is an enum with three variants
  (rarest_first is the default, plus sequential and streaming). The
  adjacent-tag JSON form `{"policy":"rarest_first","params":{}}` is carried
  in config_json; parameter keys may grow without changing the method shape.
- Rarest-first is a line-for-line port of the original semantics: a spread
  round (`select_advertised_piece_spread`, skipping pieces in flight at
  other peers — the aria2 `getMissingPiece` `isPieceUsed` exclusion)
  followed by a fallback to the original selection
  (`select_advertised_piece`) so peers stay busy when few pieces remain.
  The main path later switched to a single-pass two-record scan
  (`select_rarest_two_phase_one_pass`), mathematically the same verdict
  (each min replaces only on strict less-than) at 1xO(N) instead of 2xO(N)
  per peer per round.
- Smart enhancements (adaptive whole-torrent endgame, bandwidth-aware
  dispatch, reciprocity tie-break) deliberately do not live in the strategy
  objects: they land as constant notes on the dispatch gate (the empty
  `StreamingParams` struct is the precedent shape — enhancement semantics
  are on by default with no tunable constants), keeping the trait surface
  and `SelectionCtx` shape frozen.

## run/recovery_admit.rs

- Trust model: a recovered piece layer is admitted only after whole-file
  convergence (`merkle::validate_piece_layer`: entry count + root
  recomputation), then inserted into the `HashTreeCache` anchor domain with
  the same trust level as a metadata-carried layer. The root is protected
  by the infohash, so convergence implies trust — single source, no voting
  (libtorrent proof-chain cross-check: merkle_tree.cpp plus the root's
  provenance in torrent.cpp).
- libtorrent parity: torrents with missing per-file layers still load
  (torrent.cpp `valid = false; continue`); once the layer converges into
  the tree through the proof chain, the file's surfaces unlock naturally
  (`on_blocks_hashed` unlocking adjacent pieces).
- Bad hashes: libtorrent drops them and disconnects (bt_peer_connection.cpp)
  as a local policy; here the entry is re-staged and refetched from another
  peer (an intentional divergence — BEP-52 only mandates disconnecting on
  malformed frames). The whole file is the refetch unit, matching the
  whole-file admission granularity.
- AlreadyAnchored unified promotion: promotion happens at the consume point
  for every same-root Pending file rather than de-duplicating recovery
  entries by root at build time — the latter would change the merged
  data-plane registration semantics, and per-file entries keep independent
  re-stage/reset bookkeeping.
- recheck linkage (recovered-layer reverification / suspend re-entry /
  hybrid v1 on-disk piece v2 backfill) is out of scope for this module; only
  the persistence half touches it.

## run/dial.rs

- PEX immediate dialing anchor: rqbit dials PEX/table-discovered new peers
  immediately (peer state queued→dialing without periodic batching delay);
  the event-driven direct-dial precedent is punch_dial in run::holepunch
  (spawned inside the ut_holepunch event arm, not queued). rqbit's "boost
  first, stop dialing regular candidates when quota is out" maps to
  table-insert-first, remove-on-spawn-success.
- libtorrent source-rank bit positions come from request_blocks.cpp
  (tracker 1<<5, DHT 1<<3, PEX 1<<2).
- Inbound admission parity: aria2 `PeerReceiveHandshakeCommand.cc`
  `(!finished && downloadSpeed < threshold) || lessThanMaxPeers()`.
  Divergence: upstream decides after the handshake, here the gate sits at
  accept (an equivalent, cheaper point — the peer-visible result is the
  same).
- Inbound sniff/demux anchor: aria2 `ReceiverMSEHandshakeCommand.cc`.
- getPeers port=0 inbound semantics: aria2 RpcMethodImpl.cc. Inbound PORT:
  BtPortMessage.cc (port=0 filtering already at the peer layer). PEX
  handling anchor: aria2 UTPexExtensionMessage.cc `doReceivedAction`
  (fresh/dropped both enter PeerStorage).
- Self-connect fix: the guard previously compared config listen_port; the
  session-form engine spawns with listen_port = 0 (ephemeral), so announce
  echoes containing the engine's own address caused self-connection. The
  guard now uses the actual announce port.

## webseed.rs

- aria2 webseed: the HTTP source competes with BT peers in the same
  request-bookkeeping pool (`WebRequestGroup`), fetching Ranges at piece
  boundaries.
- libtorrent: BEP-19 + url-list (web_seed_t, torrent.cpp `add_web_seed`).
- Local divergence: instead of a separate request pool for HTTP sources,
  each URL is materialized as one "infinitely patient fast seeder"
  pseudo-peer; the HTTP fetch hides behind the BT wire responder, so the
  engine-side observation surface (getPeers / rates / dispatch stats) is
  fully isomorphic to a BT peer.
- 200-on-Range handling: aria2 judges Range-less webseed sources unusable;
  libtorrent web_seed retries/fails directly on 200. The prefetch cache and
  its caps are local-shape companions (aria2 Segments have no explicit cap;
  libtorrent web seeds have no piece cache).
- v2 coverage: aria2 has no v2 support; libtorrent's per-file v2 url seeds
  are a separate design — v2-only torrents get no webseed face here.

## run/tick.rs

Sources: aria2 `BtStopDownloadCommand.cc`, `SeedCheckCommand.cc`,
`OptionHandlerFactory.cc`, `DefaultPeerStorage.cc`, `DHTConstants.h`;
libtorrent `session_impl.cpp`, `torrent.cpp`.

- stop-timeout: download phase only; the aria2 command exits after
  `downloadFinished`. speed > 0 resets the checkpoint (SpeedCalc 10s
  sliding window); expiry forces a stop (warn message verbatim).
- SeedCheck: the latch is set and reset at `downloadFinished` (the timer
  starts at completion); satisfaction halts seeding (MSG_SEEDING_END).
- autosave: 60s cadence = the `--auto-save-interval` default
  (`OptionHandlerFactory.cc`). Ban sweep cadence is independent of
  per-entry expiry checks (`DefaultPeerStorage.cc`).
- DHT announce cadence: the registry drops an entry after 30min without
  a re-issue (PURGE); the base cadence is `DHT_PEER_ANNOUNCE_INTERVAL`
  = 15min (`DHTConstants.h`). Two fast paths re-register at 1/3 cadence
  (5min): all faces with zero connected peers (the discovery vacuum
  window), and — `BH_CONN_FILL_DHT` gated (=0 restores the plain
  cadence) — connection count below `dht_ramp_min_peers` (threshold
  from libtorrent `torrent.cpp`). Upstream `prioritize_dht`
  (`session_impl.cpp`) re-arms the announce timer at 0s and drains a
  priority queue; this 2s-tick shape has no priority-queue semantics,
  so the 1/3 cadence stands.
- peer turnover: past the hard cap, disconnect the worst max(n*4%, 1)
  every 90s (`session_impl.cpp` snapshot + `torrent.cpp` worst-first).
- uTP mute: upstream prefer_tcp caps the TCP class at rate 0; the local
  rate-limit half is naturally equivalent, the occupancy half is
  covered by disconnecting zero-throughput uTP connections
  (`BH_UTP_MUTE=0` restores the plain behavior).
- slow-peer churn: eviction line = pool median x frac%, K = max(1,
  n*k%) worst per round, no disconnect without a replacement candidate
  (aggressive dead-peer eviction as in rqbit + libtorrent peer-churn
  semantics; `BH_SLOW_PEER_CHURN=0` restores the plain behavior).
- bitmap write barrier (autosave): fsync dirty faces before the bitmap
  row; fsync failure fails closed (row skipped, dirty flag kept). The
  full invariant chain lives on `autosave_snapshot` in the source.

## verify_pool.rs

Sources: libtorrent `docs/features.rst` ("multiple disk I/O threads",
"verifying SHA-1 hash of pieces in multiple threads"); libtorrent commit
`7f691246a` (passed->have on verification).

- Parallel verify/write is an established upstream optimization; this
  pool is its verify-before-write equivalent: a hash-pass piece is
  advertised immediately (`Progress::PieceVerified` / early HAVE,
  commit `7f691246a`) without waiting for the write; `Written` follows
  once flushed.
- Verdict-channel capacity is budgeted in pieces (not job slots) so a
  batch-dispatching pipeline can never deadlock in a four-way send
  ring; the formula and argument live on `verdict_channel_capacity`.

## dht.rs

Sources: aria2 `DHTSetup.cc`, `DHTConstants.h`, `OptionHandlerFactory.cc`;
libtorrent `node.cpp`, `peer_list.cpp`, `session_impl.cpp`
(`get_listen_port`/`udp_external_port`), `src/settings_pack.cpp`.

- v6 router fallback table: aria2's `--dht-entry-point[-6]` have no
  defaults (`OptionHandlerFactory.cc` NO_DEFAULT_VALUE), so the v6
  table is an intentional local enhancement, not aria2 behavior.
  Hostnames only (AAAA filtered per family at resolution);
  `router.bittorrent.com` and `router.utorrent.com` are excluded (no
  real / unstable AAAA).
- v6 connectivity gate: `probe_source_ip(true)` = None skips the whole
  v6 bootstrap; on v4 the probe only serves BEP 42 node_id derivation
  (probe failure keeps the status quo — `node.cpp` calculate_node_id's
  unspecified -> random rule).
- v6 bind address: a probed GUA binds as the face address (outbound
  source = GUA, consistent with the BEP 42 derivation source);
  otherwise `[::]` (status quo).
- Per-family announce port: libtorrent keeps an external port per
  listen socket (`session_impl.cpp` `get_listen_port(transport, s)`
  reading `udp_external_port()`); the v6 face always announces the
  actual port so a v4 NAT port cannot pollute v6 discovery.
- Dial dedup `last_admitted` mirrors libtorrent `last_connected` 0 =
  never-first (`peer_list.cpp`).

## run/holepunch.rs

Upstream reference: libtorrent RC_2_1 @ 53acefea9 (read-only).

- Relay: `bt_peer_connection.cpp` rendezvous arm — the four-branch
  decision order (not_connected / no_support / no_self / introduce) is
  carried by `taiji_bt::holepunch::relay_decision` (table-driven tests
  in bt; the `supports_holepunch` gate). This module does the swarm
  projection: `find_peer` = a connection-table (ip, port) lookup
  (`torrent.cpp`), scoped to the requester's face exactly like
  libtorrent's torrent-scoped `associated_torrent()->find_peer(ep)` in
  `bt_peer_connection.cpp`; supports_holepunch = the handle's
  negotiation mirror. The two connect payloads: the requester receives
  connect(target ep), the target receives connect(requester's mapped
  address, `remote()`) — both addresses belong to the relay's live
  handshake connections, so forwarding cannot amplify.
- Punch dial: `bt_peer_connection.cpp` connect arm — banned addresses
  are not dialed (the IpGuard filter point), already-connected is not
  re-dialed (add_peer / already-connected gate -> the same-IP guard),
  everything else enters the normal outbound dial path
  (`connect_to_peer` + `supports_utp = true` + `set_holepunch_mode`;
  locally the regular spawn_peer_dial path, converging with ad-aware
  dispatch after the handshake).
- Trigger: `peer_connection.cpp` — the direct connection failed AND an
  introducer exists (the gate includes `!m_holepunch_mode`, so
  punch-state connections do not re-trigger; `find_introducer`,
  `torrent.cpp`: a ut_pex connection that delivered that address, which
  must support holepunch) -> send rendezvous to the introducer.
  Locally: the failure book is `HpDialReport` over all outbound dials;
  the introducer book is ut_pex first-wins
  (`HolepunchBook::note_introduced`); backoff 60s
  (RENDEZVOUS_ASK_BACKOFF).
- holepunch mode: libtorrent marks holepunch-created connections with
  holepunch mode (fast retry + sticky uTP, `set_holepunch_mode` +
  `supports_utp = true`). The Punch dial source here matches:
  `DialJob::punch` -> the `crate::transit` dedicated path (uTP sticky +
  in-window fast retry + silent give-up). `BH_HOLEPUNCH_MODE=0`
  restores plain same-discipline dialing (observation stays additive).

## config.rs

Sources: aria2 `OptionHandlerFactory.cc`, `DefaultPieceStorage.cc`,
`BtCheckIntegrityEntry.cc`, `HandshakeExtensionMessage`; BEP 3/9/19/
27/47/52.

- The v2-only data plane is enabled by this module's `engine_config`.
- Hybrid cross-verification follows BEP 47 alignment: stream piece k =
  exactly one real file's piece; the v2 side recomputes the piece root
  from content, the v1 side hashes content + pad zeros ("content of
  padding file is all zeros", BEP 47).
- Layer-missing files hold all-zero expected roots (SHA-256 preimage
  resistance makes them structurally unverifiable and unwritable until
  the layer arrives — no content enters the anchor/lazy-fetch domain
  before a whole file converges).
- Hook trigger: only bt-complete is consumed (`DefaultPieceStorage.cc`:
  the BT download completion moment, no option gate); the
  bt-enable-hook-after-hash-check gate belongs to the
  verification-complete trigger point (`BtCheckIntegrityEntry.cc`).
- ut_metadata serving mirrors aria2: any BT download carrying the
  metadata answers inbound ut_metadata requests
  (`HandshakeExtensionMessage` surface).
- PEX/DHT defaults mirror aria2 option defaults
  (`OptionHandlerFactory.cc`): `--enable-peer-exchange` default true;
  `--enable-dht` default true.

## ban.rs

Sources: libtorrent `torrent.cpp` (parole chain, trust_points),
`smart_ban.cpp`.

- trust_points: -2 per hash failure, +1 per piece pass (capped at 0
  locally — upstream has no positive cap), ban at <= -7 (upstream
  "trust <= -7 bans directly"). IP-keyed, not reset on reconnect.
- Evidence self-certification follows `smart_ban.cpp`: per-block
  digests recorded at piece failure; the same peer giving two digests
  for one block = contradiction -> immediate ban; at piece pass,
  recorded digests that mismatch the good data identify the bad-block
  source. Divergence: evidence is produced by the verify worker before
  the cell is destroyed (upstream reads back from disk because it
  persists data first); equivalent evidence, one less disk IO.
- Capacity bounds (failed-block evidence 4096, trust IPs 4096) are
  local policies; libtorrent relies on piece-lifetime reclamation.
  When full, new evidence/IPs are conservatively not recorded; the
  sliding-window ban surface is untouched (`BH_SMART_BAN=0` /
  `BH_SMART_BAN_PAROLE=0` fall back independently).
## run/assemble.rs

Sources: aria2 `BtSetup.cc`, `PeerListenCommand.cc`,
`PeerInteractionCommand.cc`, `DefaultBtProgressInfoFile.cc`,
`DefaultBtAnnounce.cc`; libtorrent `session_impl.cpp`, `src/torrent.cpp`,
`bt_peer_connection.cpp`.

- Listen fallback: `BtSetup.cc` walks the `--listen-port 6881-6999` range
  port by port; `PeerListenCommand.cc` moves on after a single-port
  failure. aria2 tries randomly against one global listener; this engine
  uses a per-task listener with deterministic ascending attempts over
  `listen_port..=+118` (119 ports, the aria2 range width). Convergence is
  the same: the first bindable port wins; 0 = a single OS ephemeral port.
  Listen failure degrades to outbound-only, never a fatal exit.
- ut_pex gate: the `PeerInteractionCommand.cc` condition
  `(metadataGetMode || !privateTorrent) && enable-peer-exchange`. The
  engine is never in metadata mode, so the gate is
  `!private && peer_exchange`; private torrents neither advertise nor
  consume PEX (BEP27, swarm-leak prevention).
- BEP5: the DHT bit is `reserved[7]&0x01`, set on new outbound/inbound
  handshakes only when DHT is enabled.
- BEP7 `ipv6=`: the local global-scope v6 comes from one
  `probe_source_ip(true)` call (v4 route lookup is a UDP connect query, no
  packet; v6 uses a TCP connect probe because under mixed ULA+GUA
  addressing UDP source selection can pick the ULA while TCP matches the
  real outbound path). The same probe result feeds the v6 candidate
  preference in `EngineLoop.self_v6_global`.
- Cross-session counters: `DefaultBtProgressInfoFile.cc` — the control
  file / progress-row `uploaded_total` (plus downloaded, active, seed
  time) becomes this session's uploadLengthAtStartup baseline; read via
  the LoadTorrentProgress job on the single serialized write connection.
- Seeding assembly: `BtSetup.cc` — SeedCheck with an empty Union means
  seed forever; bt-stop-timeout mounts only when > 0.
- Announce ports: the tracker actor's `listen_port` is a single
  spawn-time constant, matching libtorrent's single
  `m_ses.listen_port()` (src/torrent.cpp, one value for v4/v6 carriers;
  `session_impl.cpp` `tcp_external_port`). Per-family announce ports
  exist only in the engine's DHT announce surface
  (`family_announce_port`: v6 always reports actual_port, only v4
  consumes the NAT external-port snapshot). Deliberate divergence:
  libtorrent's DHT PORT message advertises the UDP external port
  (`bt_peer_connection.cpp` `external_udp_port`), a different protocol
  surface from the tracker's TCP external port; this engine maps TCP+UDP
  (SPEC §6.8) and typical gateways agree on all ports, so the TCP-first
  BT data port is advertised for both until a DHT-surface seam exists.
  The NAT initial mapping round is awaited during assembly, so the first
  announce already carries the external port.
- Announce crypto: `mse::announce_crypto_param` maps require ->
  `requirecrypto=1`, otherwise `supportcrypto=1` (cross-checked with
  `DefaultBtAnnounce.cc`).
- BEP27 private: DHT disabled engine-wide (also enforced at the DhtTarget
  type level) and the tracker actor falls back to serial single-flight
  announce scheduling ("use only one tracker at a time").
- Bitfield restore trust: a stored row is committed only after its data
  files are fsynced — regular rows via the snapshot barrier (run/tick.rs
  autosave_snapshot: dirty-face fsync first, fail-closed row skip),
  final rows via the final-state barrier (run/tail.rs final_flush). So
  bits restored straight into the written/verified models cannot mistake
  sparse zeros for verified data; forced recheck (re-entering the
  checking state) is the explicit escape hatch. The preset path
  (--check-integrity) never flips `resume_existing`: allocation stays on
  so missing files are created instead of hitting a write-path Fatal.
- Swarm snapshot initial value: aria2 adjusts to
  STARTED_AFTER_COMPLETION via `allDownloadFinished()` before the first
  announce (`DefaultBtAnnounce.cc`; its pieceStorage loads from the
  control file before the announce command starts). The restored
  bitfield's completion state is therefore in place before the actor's
  first read; afterwards the 2s tick remains authoritative.
- Hybrid faces: both faces write the same bytes of the same files, each
  verifying and writing its own; TorrentWriter guarantees pads never
  reach disk. The ratio source uses face 0's v1 layout view (pad
  included), matching aria2's v1 handling of hybrid torrents.
- 1s tick: cross-checked with `BtStopDownloadCommand.cc`
  TimeBasedCommand 1_s (SeedCheck / stop-timeout / time totals /
  autosave share the cadence).
- Choke round interval is mode-dependent: libtorrent 15s default, aria2
  fallback 10s (`BH_CHOKE_ARIA2=1`); FaceState choke objects read the
  same knob (bt::choke::choke_mode_from_env), parsed once per process.
- µTP wiring: the accept merge channel keeps a sender clone in the
  engine so an idle arm sees Pending rather than None (no spinning
  select); accept delivery and delegated dialing are split into two
  tasks because the old single-task select could park the dial queue
  behind accept backpressure indefinitely.

## run/arms.rs

Sources: libtorrent `smart_ban.cpp`, `torrent.cpp`, `peer_connection.cpp`,
RC_2_1 commit `7f691246a`; aria2 `BtPieceMessage.cc`,
`DefaultBtInteractive.cc`, `DefaultBtAnnounce.cc`,
`DefaultPieceStorage.cc`, `RequestGroup.cc`, `RequestGroupMan.cc`,
`PieceStatMan.cc`.

- smart_ban details (trust scoring, contradiction ban, pass compare,
  fallback knobs) are mapped in the ban.rs section; the arms only carry
  the v1-only gate (`trees.is_none()`), mirroring `smart_ban.cpp`
  returning nullptr for the plugin when `has_v2()`.
- v1 whole-piece hash failure: every sender of the piece's blocks counts
  once; the SPEC §13 sliding window (>=3 failures per 10min) auto-bans.
  aria2's single-point counterpart is `BtPieceMessage.cc` bad piece hash
  -> addBadPeer. Forensic fields (culprit cuid/ip, whether we had
  requested from the peer) are observation-only.
- Block settle sibling withdrawal: libtorrent `torrent.cpp` — a block
  written to disk with `picker().num_peers(block) > 1` runs
  `torrent::cancel_block`, cancelling the request on every connection
  (the first landing copy withdraws all sibling in-flights). aria2 1.37.0
  `BtPieceMessage.cc` only drops an already-owned block on receive
  ("Already have this block.", redundant bytes still counted in
  updateDownload). This engine keeps the hedge (x2 fanout untouched) and
  adds the withdrawal half for landed duplicate coordinates; a cancel
  frame reaching an already-delivered peer is a harmless no-op, and
  cancelled slots tolerate late delivery via RequestBook grace.
- Verify/flush phases: RC_2_1 `7f691246a` — announce at hash-pass
  (passed->have); completion uses the flushed half (have->flushed), so
  the seeding full source reads disk ungated and entry requires
  everything flushed.
- Hook event order: the on-bt-download-complete trigger ports
  `DefaultPieceStorage.cc` — the hook fires at BT download completion,
  before enableSeedOnly, with no option gate; on-download-complete
  happens later at the teardown executeStopHook (FINISHED), per the
  `RequestGroupMan.cc` event order.
- bt-detach-seed-only: the port of `RequestGroup.cc` enableSeedOnly —
  semantically **constant-true since the four-pool budget model**
  (a completed download's seeding never occupies a download slot; the
  session-side seat accounting releases at SeedingStarted, not at
  teardown). The engine itself keeps only the `Detached` **terminal
  variant** as the semantic marker of a task that once seeded (the
  original "option on AND download complete → seed-only" gate and the
  decreaseNumActive-equivalent bookkeeping are superseded by the
  phase-split budget model; the option's acceptance/echo face is
  unchanged — declared in the differential documentation).
- BEP3 bitfield after handshake: aria2 queues a Bitfield only when
  `completedLength > 0`; fast negotiation sends HaveNone for empty
  possession, non-fast sends nothing (`DefaultBtInteractive.cc`). Most
  real clients FIN an all-zero bitfield, so this side takes the non-fast
  branch (empty possession sends nothing); HaveNone awaits fast wiring.
- Seeding-state registration: BEP21 upload_only is caught up on new
  registrations; under BEP16 super-seeding no full bitfield is sent
  (libtorrent bt_peer_connection.cpp "pretend to not have any piece and
  don't send a bitfield"), replaced by a bootstrap assignment of at most
  two pieces.
- BEP6 have_all: treated as a full-possession advertisement replacing
  the bitfield ("replace the Have Bitfield"), unlocking dispatch through
  the normal Bitfield path. Deliberate freeze: the super-seed book is
  not fed on have_all (get_piece_to_super_seed's availability input must
  stay unchanged); rotation still proceeds via HAVE events.
- Preemptive unchoke: libtorrent peer_connection.cpp — an INTERESTED
  rising edge while choked with a free slot unchokes immediately (saves
  one round RTT); slot test and mode gate live in the engine choke
  module.
- Leave path: SPEC §6.9 — an unchoked+interested peer leaving reruns the
  choke round immediately on the leecher side (seeding keeps its 10s
  cadence). Redial admission requires a completed registration (no
  registration/leave events on handshake failure), outbound only, and
  not banned per the live IpGuard snapshot. Rarity subtraction follows
  `PieceStatMan.cc` (`remove_peer` = subtract_bitfield).

## run/state.rs

Sources: aria2 `BtRuntime.h`, `BtRuntime.cc`, `BitTorrentOptions.cc`,
`BtSettings.cc`, `ActivePeerConnectionCommand.cc`,
`PeerReceiveHandshakeCommand.cc`, `TrackerWatcherCommand.cc`,
`PeerInitiateConnectionCommand.cc`, `OptionHandlerFactory.cc`; libtorrent
`settings_pack.cpp`, `src/torrent.cpp`, `peer_list.cpp`.

- Admission form: `BtRuntime.h` — admit while
  `maxPeers_ == 0 || connections_ < maxPeers_`. The threshold is the
  hard cap when `hard_cap` or seeding, otherwise the outbound target.
- Rescue arm: `PeerReceiveHandshakeCommand.cc`
  `(!finished && downloadSpeed < threshold) || lessThanMaxPeers()` and
  `ActivePeerConnectionCommand.cc`
  `downloadSpeed < threshold || lessThanMinPeers()` — slow download
  means connection count yields to supply. Divergence: the rescue is
  tightened to at most the hard cap (never unbounded; unbounded growth
  with no supply only burns CPU). aria2's slow-download top-up is also
  count-bounded (at most 5 connections per 10s, inside `bt-max-peers`).
  The seeder branch has no rescue arm.
- Hard cap 120: aria2-next 2.8.3 ships per-torrent `bt-max-peers` = 100
  (`BitTorrentOptions.cc` `PREF_BT_MAX_PEERS`) and global
  `connections_limit` = 500 (`PREF_BT_MAX_CONNECTIONS`, written into
  libtorrent `settings_pack::connections_limit` via `BtSettings.cc`) —
  2.5x libtorrent's default 200 (`settings_pack.cpp`); libtorrent caps
  the setting by process fd capacity at construction (20% reserved for
  files). 120 = 100 x 1.2, headroom for in-flight handshake overshoot
  (same reasoning as the earlier 64, one step above aria2's default 55).
  Intentional divergence: not aria2's 100 itself — the cap carries the
  handshake window. Memory bound: ~7.5 MiB of block-pool cap headroom
  (120 peers x 16 KiB x 4 checkout pieces); the pipeline capacity
  formulas consume `peer_connections_max` and size with it (caps, not
  preallocations).
- Target 100: aligned with aria2-next's per-torrent `bt-max-peers` = 100.
  The discovery top-up chain — `TrackerWatcherCommand.cc`
  `while (lessThanMinPeers())` and `PeerInitiateConnectionCommand.cc`'s
  chained `lessThanEqMinPeers()` gate — keeps its semantics. Intentional
  divergence: not `max * 0.8` (aria2 `BtRuntime.cc`
  `minPeers_ = maxPeers * 0.8`, the old 51; under aria2-next's config
  that formula gives 80, still below its per-torrent cap). TARGET is a
  steady-state target for hostile/NAT environments where most dial
  attempts fail, not an aspirational figure. `target < hard cap` is an
  ordering invariant, enforced by a clamp.
- Runtime overrides: `BH_PEER_MAX` / `BH_PEER_TARGET` read lazily once
  per process (`taiji_io::knobs`); parse failure or zero restores the
  defaults; `BH_PEER_MAX=64` / `BH_PEER_TARGET=51` restore the previous
  configuration bit-for-bit.
- Rescue threshold 50 KiB/s: aria2 `--bt-request-peer-speed-limit`
  default 50K (`OptionHandlerFactory.cc`); explicit 0 = always healthy =
  rescue arm off (aria2's NumberOptionHandler min 0 covers the same
  domain).
- DHT hot switch: `EngineCommand::SetDhtEnabled` counterparts libtorrent
  `apply_settings(enable_dht)` runtime toggling plus the per-torrent
  `torrent_flags::disable_dht` flag flip (src/torrent.cpp). The private
  gate follows `torrent.cpp` `priv()` — a hard gate no flag or session
  switch can override (regression-pinned).
- Dial budget: connection_speed 30/s — see the run/ecology.rs section;
  the gate order here is hygiene -> redial admission (hard-cap form) ->
  silent ledger (Discovery only) -> token bucket (Punch exempt). The
  Discovery gate sits at the arm side so a refused address never burns
  its dedup window.
- Webseed exemption: turnover / slow-churn / stall sweeps skip webseed
  pseudo-peers (CDN patience, transient slowness, no replacement
  candidate); entries are pre-registered at assembly and never removed
  on leave (capacity bound 8).

## dispatch.rs

Sources: aria2 `DefaultBtInteractive.cc`, `DefaultPieceStorage.cc`,
`DefaultBtMessageDispatcher.cc`, `BtPieceMessage.cc`; libtorrent
`request_blocks.cpp`, `piece_picker.cpp`, `piece_picker.hpp`,
`peer_connection.cpp`, `torrent.cpp`, `stat.cpp`, `hash_picker.cpp`,
`bt_peer_connection.cpp`, `settings_pack.cpp`; rqbit `live/mod.rs`; BEP 3,
BEP 6, BEP 47, BEP 52, BEP 53.

The dispatch face owns "who is asked for which blocks": selection, the
dispatch loop, in-flight/reply/refetch bookkeeping, BEP 53 mask
projection, and the v2 lazy hash fetch. It does not move block data or
decide choking.

### Two-phase in-flight bookkeeping

libtorrent's per-block tri-state requested/writing/finished
(`piece_picker.hpp`) maps locally onto `BlockState`: `InFlight`/
`InFlightDup` = requested (network phase), `Settling`/`SettlingDup` =
writing (store phase), `Buffered` = finished. Reissue judgments consult
only the requested age (`torrent.cpp` mark_as_writing / mark_as_finished):
once bytes arrive, the peer's wire slot has retired, so resending is pure
waste — store-confirmation lag never re-dispatches. The store-phase guard
(`STORE_PENDING_GUARD`, 30s) is warn + count only; libtorrent has no
counterpart constant (its writing state is untimed), a structural
divergence.

Per-block timestamps collapse into a piece-level shared timestamp
(`PieceSentLedger`): any dispatch write refreshes it. Exact per-block
adaptive timeouts stay on the RequestBook side (bt crate); the engine
timestamp only feeds claimed projection / reissue candidates / guard
warnings.

### Reissue window

`max(2s, min(adaptive, ceil))` — the adaptive input is the target peer's
`adaptive_request_timeout`; libtorrent's counterpart is
`request_timeout()` (`peer_connection.cpp`, 0 samples -> the settings
default, no evidence-free scaling; the local 5s ceiling leans the same
way). aria2 has no standalone reissue-window constant (its reissue is
RequestBook-slot driven). rqbit has no block-level reissue at all
(in-flight is reclaimed only on peer death, `live/mod.rs`
`mark_chunk_requests_canceled`). Knobs: `BH_REISSUE_CEIL_SECS` (default 5,
clamped [2, 300]; `=5` default arm).

### Dispatch debt

A dispatch round is an O(peers x pieces) full-order rarity scan, so event
arms register debt instead of dispatching per event. Settlement fires on
any of: supply quiet (no unsettled in-flight on any debted face), a
settle batch (`K = clamp(peers / 2, 1, 16)`), or the debt-age backstop
(5ms) — the latency bound for HAVE storms and long-quiet faces. In-round
decision order is unchanged; the debt surface is bypassed by the
decision-table tests.

### Adaptive full endgame

Trigger (recomputed per round, like libtorrent's per-pick `set_endgame`):
condition A `in_flight_pieces >= missing_pieces` — the complement of
libtorrent's `get_download_queue_size() < num_want_left()`
(`request_blocks.cpp`: "if the number of pieces we have + the number of
pieces we're requesting from is less than the number of pieces in the
torrent, there are still some unrequested pieces and we're not strictly
speaking in end-game mode yet"; `num_want_left()` = "the number of pieces
we want and don't have", `piece_picker.hpp`); or condition B, ETA =
remaining bytes / aggregate rate < 30s (matched to the 30s rate window;
zero rate never triggers). Local in-flight pieces = pieces holding fresh
InFlight blocks — slightly more conservative than libtorrent, whose
finished/writing blocks stay queued.

Once triggered, the claimed input blanks (missing pieces go to every
holder) and the cursor pick is two-level: unowned pieces first; busy
pieces only through `endgame_busy_admitted` — (1) the strict gate
(in-flight pieces >= missing; libtorrent `strict_end_game_mode`,
`dont_pick_busy_blocks` when `get_download_queue_size() < num_want_left()`)
and (2) the peer empty-handed gate (`dq.size() + rq.size() > 0` skips busy
picks, `request_blocks.cpp`), giving the invariant at most 1 busy piece
per peer. Deliberate divergence: libtorrent's busy granularity is the
block and only request-starved peers enter; the local allocation
granularity is the piece, so "requests cannot be filled" maps to the
unowned pick coming up empty. The x2 copy cap (`ENDGAME_MAX_COPIES`)
governs timeouts (the slow-peer fallback ceiling); the busy gate governs
generation.

Dispatch order (`endgame_peer_order`): 30s-window rate descending — the
libtorrent anchor sorts peers by `download_queue_time(16*1024)` ascending
("The earlier a peer is in the list, the sooner we will fully download
the block", `torrent.cpp`, re-sorted per request, derived from the
payload rate in `peer_connection.cpp` with a 30s/peak-rate fallback and a
50 B/s floor); tie-break interested first (tit-for-tat credit, the BiToS
idea); final key connection index.

Dials: `BH_ENDGAME_STRICT` (default on; `=0` restores the single-level x2
cursor), `BH_ENDGAME_FAST_BUSY_K` (default 2; fast-tier peers may hold K
busy pieces, slow-tier stays strict; `=0` restores the old gate), with
fast tier = rate >= 2x median AND >= 100KiB/s (the median multiple is
conservative: 1x passes half the peers, 3x starves the fast window; the
absolute floor blocks the phantom fast tier of a near-dead swarm).

### Last-mile wide fan-out

`BH_ENDGAME_LASTMILE` (default 4; `=0` = the fallback switch): with
missing pieces <= N the busy gates lift, the copy cap relaxes to the
holder count (relax-only, `max(holders, x2)`), fresh InFlightDup blocks
owned by others may re-dispatch (block-level first-wins), and ordering
switches to `endgame_lastmile_peer_order` (pure rate order, no interested
tie-break — reciprocity is meaningless in a seconds-scale tail). Domain
split by design: rqbit runs first-arrival-wins broadcast with no copy
accounting; libtorrent keeps `strict_end_game_mode`. Outside last-mile
the strict semantics are bit-for-bit. Duplicate-byte bound = N x piece
length x peer count; first-wins lands far below (store-side covers drops
duplicates benignly; the exactly-once `was_dup` semantics are untouched).

### Partial hard gate

`num_partials > peers * 3 / 2 || partial_blocks > 2048` (libtorrent
`piece_picker.cpp`, both strictly >; its source note: "2048 corresponds to
32 MiB"). The local partial-block count sums each partial piece's own
uncovered blocks instead of the reference's constant multiply — same
intent, more precise for short tail pieces. Gate rounds inject the
partial-piece table via `preferred` (the prioritize_partials landing;
libtorrent also clears `prefer_contiguous`, which has no local consumer).

### Multi-piece (cross-piece) supply

Anchors: `whole_pieces_threshold` = 20s (`settings_pack.cpp`) and the
8MiB cap `std::min(download_window, 8 MiB)` (`request_blocks.cpp`) give
`contiguous = min(rate x 20s, 8MiB) / piece_len`, with a budget floor on
top (`BH_MULTI_PIECE_BUDGET_FLOOR`, default 4, clamped [0, 8]; `=0` =
the old value). Rate input divergence: the reference uses the
per-connection 5s payload average (`stat.cpp` `m_5_sec_average`); the
local engine has no projection of the bt-side `RateEwma`, so the 30s
engine download window is the single source (conservative both ways:
slower decay, protocol overhead included). Floor rationale: a peer's
supply rate responds causally to our request depth, so slow peers sit at
computed budgets of 0-1 under the single-piece rhythm; rqbit runs a
standing 128-deep request window (`live/mod.rs`) with no such gate.

Checkout cap `BH_MULTI_PIECE_SUPPLY_MAX` (default 16, history 4 -> 8 ->
16): the reference bound is 8MiB/256KiB = 32 pieces; high-RTT BDP needs
deeper pipes, and with soft accounting the cap is the only depth governor
for fast peers (16 x 16 = 256 >= the BDP window cap). Soft accounting
(`BH_CHECKOUT_SOFT_ACCOUNTING`, default on; `=0` = whole-piece counting):
secondary occupancy = `ceil(live blocks / blocks per piece)`, so
half-arrived pieces release slots proportionally. Red line: only the cap
dimension widens; the window dimension stays clamped by `supply_cap`.

Adjacent chain softening `BH_ADJACENT_SKIP_N` (default 2; `=0` = the old
break-at-first-ineligible behavior): soft breakpoints (done / claimed /
unadvertised but goff-contiguous) are skipped up to N per round; hard
breakpoints (goff discontinuity = file-boundary padding, gaps,
zero-length pieces, or torrent end) still break — the read-ahead
contiguous-run semantics stay guarded on every step. Selection-side
only.

### Recovery hash fetch (piece-layer)

libtorrent anchors: at most 1 in-flight hash request per peer
(`bt_peer_connection.cpp` `m_hash_requests.size() > 1` -> return),
coverage-evidence pick (`hash_picker.cpp` pick_hashes requests only when
the bitfield covers a piece of the 512-piece bucket; BEP 52 "prioritize
requests where they can be certain that the other party must have the
necessary data"). Local freedoms: any-v2-peer fallback (trust comes from
the whole-file layer recompute converging to the info pieces root) and
download-face timeout/retry constants instead of libtorrent's 3s
per-bucket re-request interval. Peer-switch memory carries a 90s cooldown
(the audit-recommended 60-120s midpoint; >= 9x the fetch timeout, so the
post-budget cadence is 1 probe per window per file); fresh
Have/Bitfield/HaveAll evidence resets a peer's cooldown, HaveNone does
not.

### Selection and availability bookkeeping

libtorrent `peer_connection.cpp`: "if we haven't received a bitfield, it
was probably omitted, which is the same as 'have_none'" — missing
evidence means zero requests, never a blind pick (the removed
`unwrap_or(current)` fallback drew FINs from real seeds). Spread-round
selection is aria2 `DefaultPieceStorage.cc` getMissingPiece(peer) (one
checkout per peer, `isPieceUsed` -> null) with a divergence: claims age
out at the reissue window instead of holding the piece until completion
(a more aggressive self-healing, not a line-by-line port). Choked peers
get zero requests (the aria2 `fillPiece` gate): while choked only
allowed-fast requests are accepted (BEP 6; none are sent locally), and
blind injection ends in the snub -> choke-exclusion tit-for-tat deadlock.
Cancel-on-verified generalizes libtorrent `torrent::cancel_block`
(`num_peers(block) > 1` -> cancel) to the piece completion moment;
PieceDropped / PieceEvicted deliberately do not cancel (the in-flight
delivery IS the refetch).

### Knobs

| Knob | Default | Fallback |
|---|---|---|
| `BH_REISSUE_CEIL_SECS` | 5 (clamped [2, 300]) | `=5` default anchor |
| `BH_ENDGAME_STRICT` | on | `=0` single-level x2 cursor |
| `BH_ENDGAME_LASTMILE` | 4 | `=0` strict everywhere |
| `BH_ENDGAME_FAST_BUSY_K` | 2 | `=0` old two-level gate |
| `BH_TWO_PHASE_LEDGER` | on | `=0` single-state face |
| `BH_MULTI_PIECE_SUPPLY` | on | `=0` single-piece rhythm |
| `BH_MULTI_PIECE_SUPPLY_MAX` | 16 | `=4` / `=8` history steps |
| `BH_MULTI_PIECE_BUDGET_FLOOR` | 4 (clamped [0, 8]) | `=0` ported value |
| `BH_CHECKOUT_SOFT_ACCOUNTING` | on | `=0` whole-piece counting |
| `BH_ADJACENT_SKIP_N` | 2 | `=0` break at first ineligible |

## query.rs

Sources: aria2 `RpcMethodImpl.cc` (`gatherProgressCommon`, `gatherPeer`,
`isIncomingPeer`), `SpeedCalc.cc`; BEP3, BEP 52; SPEC §4.4/§8.2.

- Snapshot synthesis uses face 0 as the canonical face: hybrid dual
  faces always have equal piece counts and completion state propagates
  across faces (the BEP 52-aligned mapping); connection counts sum over
  all faces and seeder requires every face complete
  (`group->isSeeder`).
- `pack_bitfield` emits the BEP3 wire layout (MSB-first, trailing pad
  bits zero); the `Some` arm copies bitmap words bit-reversed via
  `PieceBitmap::to_packed_msb`.
- `CounterDrain` splits the downlink delta by the registration-time
  transport (`PeerMeta::transport`); the scope is wire-received bytes,
  counted at Piece frame reception before duplicate-block
  discrimination, so the parts cross-check additively against
  `bytes_down_total` (`down == down_tcp + down_utp`).
- Ported reading-face rules: inbound connections report port 0
  (`isIncomingPeer`); `bitfield = Some` iff valid bits > 0
  (`getBitfieldLength() > 0`); speeds are the 10s sliding window
  (SpeedCalc); session upload includes the pre-start baseline
  (`allTimeUploadLength`).

## tracker.rs

Sources: aria2 `DefaultBtAnnounce.cc`, `BtAnnounce.h`
(`DEFAULT_ANNOUNCE_INTERVAL` = 2 min), `AnnounceList.cc`.

- `TrackerMirror` is a shadow instance of the same frozen state machine
  the actor runs (`bt::tracker::AnnounceList`), driven by the identical
  transition sequence; attribution = the shadow's `get_announce()`.
  Known boundary: a completed-flag flip and an in-flight default
  announce can reorder within one tick, so a success may be attributed
  with completed semantics; tracker rows are cache-grade data and the
  impact self-heals on the next announce.
- `sync_adjust` ports the actor's pre-announce event adjust (stopped >
  completed > default; STARTED_AFTER_COMPLETION under default when all
  pieces are complete). All-tier failure reset re-times the next
  announce at `DEFAULT_ANNOUNCE_INTERVAL` (aria2 restarts at
  minInterval on reset).
- Persistence shape: the main loop only enqueues row snapshots (no lock
  across await); a dedicated flusher task writes serially; teardown
  does a final flush before aborting.

## upload.rs

Sources: BEP3 (tit-for-tat upload side), BEP 47; libtorrent RC_2_1
commit `7f691246a` (passed->have on verification).

- `PartialFaceSource` gates serving on the written bitmap only, not
  hash-pass: the advertise face moved to hash-pass (commit `7f691246a`),
  but reads go straight to disk through TorrentReader, so a
  verified-but-unwritten piece would still read as sparse zero data.
- `RateWindow` is the 30s download-byte window feeding the leecher sort
  key; before the window fills, the rate averages over the buckets fed.

## error.rs

- Engine command-face error. Invariant: variant semantics and Display
  strings are verbatim-identical to the corresponding
  `session::SessionError` arms; the session-side
  `From<EngineError> for SessionError` maps per variant, so both
  sides' literals must evolve in sync (a new variant = added in both
  places), keeping the RPC error-code mapping and the `match`
  classification at zero drift.

## superseed.rs

Sources: BEP 21, BEP 16; libtorrent `src/torrent.cpp`.

- Seeding entry is idempotent and shared by the download-complete and
  recovery-as-complete paths: the BEP21 `upload_only` broadcast (the
  transition is itself the re-advertise, `torrent::send_upload_only`)
  with registration-arm catch-up for connections registered
  afterwards; BEP16 super-seed bookkeeping created when the
  task-static `super_seeding` switch is on
  (`torrent::set_super_seeding(on)`). The off face is unsupported
  locally — the switch never flips mid-run.

## redial.rs

- Channel shape between dial tasks and the main loop: `RedialReport`
  (only redial dials carry a report sender) and `DialOutcome`
  (Connected / Failed / Blocked). The report channel is bounded at 64;
  a full channel awaits (backpressure); at engine teardown the channel
  closes and reports are silently dropped.

## pipeline.rs

Sources: aria2 `PREF_DISK_CACHE` (the 16MiB frozen write-cache floor)
and `BtPieceMessage.cc` (the receive-path duplicate-filter
architecture: `piece->hasBlock(...)` -> "Already have this block.");
libtorrent `precomputed_block_hashes` (write-path block-hash
precompute) and `torrent.cpp` (recovery/merkle trees persisted with the
resume data — upstream promotion rides a restart; here the
expected-root backfill is promoted live in-session, no restart); BEP 52
("If any inconsistency is detected they may either abort or fall back"
— this engine aborts on v1/v2 hash inconsistency).

### Write-cache / spill sizing

Under verify-before-write, the write cache is an assembly buffer for
unverified data, not aria2's disk write cache (the cache.rs
"intentional divergence"): it drains only when a piece verifies.
Aggregate in-flight demand ~ connection cap x per-peer checkout
residency, so both the write cache and the spill budget size as
`max(16MiB frozen default, 2 x connection cap x [checkout cap x]
piece_len)`. Both are caps, not preallocations: steady RSS/disk
footprint unchanged, only the ceiling grows. `BH_PEER_MAX` resizes the
formulas in step; `BH_SPILL_FIXED=1` pins the spill cap to the
write-cache size bit-for-bit; `BH_BLOCK_ARENA=0` falls the block pool
back to direct allocation bit-for-bit.

### Snapshot / terminal write barriers

The bitmap-persistence invariant "the outage bitmap never runs ahead of
data" is shared with the HTTP snapshot pipeline
(`session/http/snapshot.rs`): data fsync first, progress-row upsert
second. The terminal barrier drains all dispatched writes (verdict
channel drained to None), fsyncs in the write-external exclusive
domain, then sets Flushed/Failed (Failed = the terminal row is refused
— never over-record). The 60s autosave uses the lighter snapshot
barrier (`autosave_snapshot`, fail-closed row skip): draining every
in-flight write per minute would be too heavy.

## metrics.rs

- Label cardinality discipline: rpc method names anchor to the
  `RPC_METHODS` list (unknown methods collapse into one slot);
  state/transport/direction/family/kind are fixed enums; identifiers
  (gid/path/info-hash/URL/secret) never become labels.
- `taiji_torrents{state}` exposes the six aria2 status values
  (StatusKind), not nine; derived by the rpc layer from the existing
  query faces (getGlobalStat/tellWaiting/tellStopped).
- `taiji_dht_queries_total{kind}` covers the four BEP5 KRPC message
  kinds; counters increment at the bt::dht `send_query`
  outbound-enqueue success point and reach the session face as 1s-tick
  `DhtSnapshot` deltas (v4/v6 engines sum).
- Snapshot reads are independent Relaxed loads: a non-consistent
  snapshot with no cross-field atomicity (projection tests must not
  assert cross-field consistency).
- The io registry seam: DNS/HTTP/disk/persist families are produced by
  taiji-io feed points into the process-default registry and pulled
  into the snapshot over the core->io edge.

## bitmap.rs

BEP3 packed bitfields are MSB-first (the first byte's high bit is
piece 0); the internal `PieceBitmap` representation is LSB-indexed by
piece number. Conversions live only at `or_from_packed_msb` /
`to_packed_msb`; selection, dispatch, and holder counting always read
by internal index. Memory model: `ceil(N/64) x 8` bytes per row versus
`Vec<bool>`'s `N` bytes per row (the 100k-piece x 500-peer table:
about 50MB -> 6.25MB). Tail-bit invariant: padding bits past `len`
stay zero, so `count_ones`/`is_full`/word comparison need no second
masking pass.

## progress.rs

- Two-phase completion events follow libtorrent commit `7f691246a`:
  `PieceVerified` = passed->have (advertise at hash-pass, write still
  in flight); `PieceWritten` = have->flushed (upload gating and
  persistence wait for the flushed half).
- `EngineEnd::Detached` ports aria2 `RequestGroup.cc` `enableSeedOnly`:
  seed-only after completion does not hold a concurrency slot
  (`decreaseNumActive()` + `requestQueueCheck()`).
- Intentional deviation: aria2's `DefaultBtProgressInfoFile.cc`
  persists and restores in-flight pieces (`addInFlightPiece` on load);
  this engine's bitmaps record only written (verify + write confirmed)
  pieces, so a crash loses at most unconfirmed blocks — correctness
  rests on verify-before-write (SPEC §5.2). `upload_at_startup` maps
  the `.aria2` control-file uploadLength baseline.
- v2 restore: `v2_file_bits` is authoritative per-file; the
  `v1_bitfield` fallback relies on BEP52 hybrid alignment (equal piece
  counts, global coordinate k <-> k).

## transit.rs

Outbound dial / handshake / connection-attach transport face.
Sources: aria2 `InitiatorMSEHandshakeCommand.cc`,
`PeerInitiateConnectionCommand.h`, `DefaultBtInteractive.cc`,
`RpcMethodImpl.cc`; libtorrent RC_2_1 `bt_peer_connection.cpp`,
`peer_connection.cpp`, `peer_list.cpp`, `settings_pack.cpp`,
`utp_stream.cpp`; SPEC §6.1/§11; BEP 3/5/6/10/21/29.

### Block direct-delivery seam (FaceBlockSink)

libtorrent `peer_connection::incoming_piece`
(src/peer_connection.cpp) hands a received block straight to
`m_disk_thread.async_write` on the receive thread — the sink is the
tokio isomorph of that receive-point hand-off. Crossing the task
boundary through the bounded face channel (capacity 256, the prior
figure) is an intentional divergence (single network thread -> two
tokio tasks). Ordering divergence from the old forward path:
attribution insert + pre-registration increment happen only after a
successful enqueue — on a full channel the payload returns to the
caller for the backpressure slow path with no partial registration
(a half-done registration would corrupt the last-arrival-wins record
the hash-failure ban reads).

### Punch window sizing (holepunch mode)

- uTP sticky: `bt_peer_connection.cpp`'s connect arm sets
  `p->supports_utp = true` before `connect_to_peer(p, true)`; the
  regular failure arm's mark-uTP-unsupported +
  immediate-TCP-reconnect is skipped in holepunch mode
  (`peer_connection.cpp` `!m_holepunch_mode`) — a uTP failure never
  degrades to TCP here.
- Fast retry: `set_holepunch_mode()` + the failure arm's
  `fast_reconnect(true)` (`peer_connection.cpp`); the reconnect gate
  re-arms so the `(f+1)x60s` door reopens immediately. Local
  materialization: `PUNCH_ATTEMPT_MAX` = 3 = libtorrent
  `max_failcount` (`settings_pack.cpp`), zero inter-attempt gap (the
  reference's immediate redial), `PUNCH_ATTEMPT_BUDGET` = 3s =
  `utp_connect_timeout` (`settings_pack.cpp`); the SYN (no RTT
  estimate) packet timeout is the same 3000 (`utp_stream.cpp`
  packet_timeout's none-state arm) and an unconfirmed socket dies on
  its first timeout (the `!m_confirmed` arm) — the reference's
  give-up window for one unanswered uTP attempt is exactly 3s. The
  3x3s ~ 9s window covers >= 2 SYN rounds per side (initial RTO
  1000ms + doubling, BEP29 timeouts; io `Rtt::default` note).
- `punch-timeout` stays out of the silent ledger (intentional
  divergence: the regular `handshake` class books — inside the window
  the backoff was already cashed by the fast retries; re-triggering
  is rate-limited by RENDEZVOUS_ASK_BACKOFF 60s + the 10min dial
  dedup). libtorrent has no NAT-attribution counter counterpart.

### Outbound crypto shape (CryptoShape)

- require -> MSE only; under force/require aria2 forbids a legacy
  retry after an MSE failure (`InitiatorMSEHandshakeCommand.cc`).
- arc4 + !require -> MSE-first + fresh-connection legacy fallback:
  aria2's outbound default is MSE-first
  (`PeerInitiateConnectionCommand.h` defaults
  `mseHandshakeEnabled=true`); on MSE failure (non-force/require) it
  retries legacy on a NEW connection
  (`InitiatorMSEHandshakeCommand.cc` — the failed negotiation's
  bytes are not reusable); libtorrent `out_enc_policy=pe_enabled`
  alternates prefer/fallback per-peer `pe_support`
  (`bt_peer_connection.cpp`: an encrypted handshake completion keeps
  the preference, a plaintext handshake success records
  non-preference). The local mapping is more conservative than
  aria2's default: the default plain shape does not probe (no
  protocol-probe round trip against legacy-only peers).
- The MSE/handshake budget is 10s, the same tier as the outbound
  connect budget; the fallback reuses the same-tier budgets (no new
  constants). libtorrent avoids the repeated first-connect cost with
  per-peer `pe_support` memory; this side deliberately keeps none
  (the silent ledger escalates repeated silent endpoints at the dial
  gate).
- Announce-bit consistency: under arc4-prefer the announce still
  carries `supportcrypto=1` (assemble.rs via
  `mse::announce_crypto_param`; only require adds `requirecrypto=1`,
  the `DefaultBtAnnounce.cc` stance) — legacy inbound and outbound
  fallback stay accepted, so the bit is correct.

### uTP dial budget (UtpDial::connect)

`UtpDial::connect`'s await used to be the only timeout-free point in
the peer_connect chain: the bounded(64) delegation queue's send and
the oneshot reply were both unbounded, so a stalled consumer (accept
backpressure / consumer exit) queued dead-address uTP fallback
requests without bound. The whole window (queueing + delegation +
reply) now sits under `utp_dial_budget` =
`BH_UTP_DIAL_TIMEOUT_SECS` (default 10 = `MSE_HANDSHAKE_TIMEOUT`,
an upper bound over queueing + the SYN retransmit window; =0 restores
the unbounded behavior). Timeout / closed queue / dead reply end all
route to the existing utp-connect failure class (not silent per
`plan_is_silent`).

### Dead-address uTP-arm trim (skip_dead_utp_arm)

fails >= 1 (the silent ledger remembers silence) AND the Utp arm AND
`BH_DIAL_DEAD_TCP_ONLY` (default on; =0 full plan). Rationale: a dead
address's second uTP try feeds the bounded(64) queue (hung supply)
and a dead connect leaves 120s of io-driver debris (toward the 512
routing-table cap). Intentional divergence: libtorrent's
connect-candidate eligibility (`peer_list.cpp`) is endpoint-level,
not per transport arm; the endpoint's TCP arm stays in the plan.

### uTP-preferred plan flip (outbound_dial_plan)

`BH_DIAL_PREFER_UTP` (opt-in, default off): PreferTcp flips
[Tcp, Utp] -> [Utp, Tcp] — the uTP fallback arm becomes primary so
outbound runs BEP29 LEDBAT and yields to browsing (the ADSL
guardrail). Pure types are never second-guessed; PreferUtp is already
uTP-primary; inbound is unaffected. Orthogonal to the trim (the flip
orders arms, the trim filters them; order-then-filter).

### BEP10 negotiation gate (attach_peer)

The ext handshake is sent only when the peer's handshake
reserved[5]&0x10 declares the extension face — aria2 queues it only
under `peer_->isExtendedMessagingEnabled()`
(`DefaultBtInteractive.cc` `doPostHandshakeProcessing`). Sending
unconditionally is a protocol violation: real Canonical seedboxes FIN
immediately on an unnegotiated ext handshake, killing downloads on
real swarms.

### Per-peer counters bridging

PeerConfig's up/down are per-connection atomics; the torrent-level
session totals are bridged from deltas by the main loop's 1s tick
(`drain_peer_counters`) — announce / stop-timeout / persistence
readings unchanged, a <=1s granularity added.

## faces.rs

Swarm-face runtime state and bookkeeping. Sources: aria2
`BtRuntime.h`, `DefaultBtAnnounce.cc`, `RpcMethodImpl.cc`,
`SpeedCalc.cc`, `BtLeecherStateChoke.cc`, `DefaultPieceStorage.cc`,
`PieceStatMan.cc`, `UTPexExtensionMessage.cc`; libtorrent
`docs/manual.rst`, `piece_picker.cpp`, `torrent.cpp`, `peer_list.cpp`,
commit `7f691246a`; BEP 3/11/21/47/52/53.

### numwant gate (tracker_min_peers)

The old threshold was the direct port of aria2 `BtRuntime.h`
DEFAULT_MIN_PEERS 40 (`lessThanMinPeers` = connections below min
peers; `DefaultBtAnnounce.cc` asks numwant=0 at 40). In swarms heavy
with dead candidates the registered count stalls in the 40-100 band
and "40 reached, ask 0" switches tracker supply off in the window
that needs it most. The default is now the outbound target reading
(`peer_connections_target` = 100, keep requesting until the target);
`BH_TRACKER_MIN_PEERS=40` restores the aria2 value. libtorrent's
announce always requests numwant (`announce_entry.cpp` has no
min-peers shutoff) — the local stance sits between. The gate's only
runtime consumer is `FaceView::less_than_min_peers`; the metadata
phase's magnet gate (taiji-core magnet.rs `MIN_PEERS` = 40) is
independent and unchanged.

### Read coalescing caps

`FACE_READ_COALESCE_MAX_BYTES` = 1MiB,
`FACE_READ_COALESCE_MAX_RANGES` = 64: the same cap basis as the
store `read_coalesced` test tier; libtorrent `docs/manual.rst`
"coalesce the small bittorrent requests" (the store disk_policy
reference shares the source). First-cut engineering values.

### PeerState merge

`FaceState.peer_state` merges the 11 former keyed tables (peer_ips,
peer_meta, peer_rates, down_windows, last_unchoke, am_unchoked,
last_opt_unchoke, utp_mute_since, peer_piece, peer_extra_pieces +
EngineLoop.peer_registered_at) into one cuid-keyed row: one hash
lookup per consumer with row locality; the seeder path's index-keyed
dual keyspace (and its stale-misread after leave shifts) dissolves.
down_window stays at the design-fixed 30s (aria2
`BtLeecherStateChoke.cc` TIME_FRAME=20s; libtorrent a per-round delta
+ 5s low-pass), sort direction (download rate descending) as both.
The piece checkout is the port of aria2 `DefaultPieceStorage.cc`
getMissingPiece(peer) whole-piece checkout, extended with a
secondary-piece vector (adjacent goff chains) for fast peers.

### peer_avail bitmap / peer_seeds

The availability row is bitmap-compressed (ceil(N/64)x8 bytes per
peer; 100k pieces x 500 peers: 50MB -> 6.25MB) with the O(N/64)
bit-word dividend for holder counts / interesting checks; row width
is always piece_count, MSB wire conversion only at the
dispatch::note_peer_bitfield / query::pack_bitfield boundaries.
peer_seeds mirrors libtorrent `piece_picker.cpp`
inc/dec_refcount_all's m_seeds single counter: seed rarity goes
through PieceStatMan add/remove_seed instead of per-piece counting;
the all-ones evidence row stays materialized for selection/dispatch.

### blocks_sent ledger

Fixed-width inline rows (8B per block slot, 128B per piece row)
replace the former per-piece HashMap + global dispatch table. Two
phases: InFlight = network segment (re-dispatch past the adaptive
window); Settling = store segment (`STORE_PENDING_GUARD` warn+count
only, never re-dispatched); Buffered = in write cache. Ownership (a
peer_cuids index per slot) lives across segments;
`PieceSentLedger::reindex_owners` repairs leave shifts (wired in
run::arms::handle_peer_left).

### verify/write event split (commit 7f691246a)

on_piece_verified = the passed->have half: advertise (HAVE) and
progress at hash-pass, before the write — peers trade instead of
stalling behind a slow disk. on_piece_written = the have->flushed
half: the upload-service gate lifts (`PartialFaceSource` reads the
written bits) and the persisted bitmap advances. Completion
(`recheck_face_completion`) reads only written_count — a face with
selected pieces verified-but-unwritten must not complete (the
seeding full source reads disk ungated). The persisted bitmap never
leads the disk: only PieceWritten advances written_progress, so
restored rows cannot mistake sparse zeros for verified data (forced
recheck is the escape hatch).

### Parole set

`parole_peers` ports the libtorrent `torrent.cpp` parole chain:
peers involved with a hash-failed piece claim only unowned whole
pieces (unambiguous attribution) and are excluded from endgame busy;
a passing piece clears suspicion (digest-matched good data); leave
clears (cuids never reused, the set stays bounded).
`BH_SMART_BAN_PAROLE=0` keeps the set empty.

### PEX candidates

The 60s-window fresh/dropped bookkeeping projects aria2
`PeerStorage` getUsedPeers/getDroppedPeers; only outbound
connections are booked (`UTPexExtensionMessage.cc` addFreshPeer
precondition); the seeder flag is frozen false (no per-peer
completeness reading; the BEP11 flags bit is an optional hint frozen
by the codec).

### upload_only mirror (PeerMeta)

`PeerMeta::upload_only` mirrors the peer's ext handshake
`upload_only=1` (overwritten per handshake; missing key/0 = false).
libtorrent `compare_peer`'s `finished && maybe_upload_only` demotion
key (peer_list.cpp) needs a cross-connection address-level
projection that does not exist yet — the key slot is documented for
future adoption; connected-peer governance (turnover is_seed) uses
the all-ones bitmap instead.

## tests.rs

The engine test suite pins the wiring faces described in the sections
above. Coverage map, in file order:

- Dispatch reply draining (`drain_dispatch_replies_core`): Ok and
  Duplicate keep in-flight marks, WindowFull/Closed clear and refetch
  with piece-truncated lengths, Empty waits for the next round.
- TrackerMirror row rebuild on SetTrackers: keep, register, remove,
  clear dangling success pointers.
- Progress restore: v2 per-file bitmap roundtrip, v1 global bitfield
  (MSB order), corrupt-payload defense, v2-over-v1 precedence.
- PEX candidate bookkeeping: inbound never recorded, outbound marks
  dirty, leave moves to dropped, fresh/dropped windows anchored
  independently (`UTPexExtensionMessage.cc`).
- Choke wiring: the leecher 8-slot decision table (libtorrent mode:
  interested filter, rate sort, 7+1 slots, 30s optimistic phase,
  idempotent landings); budget-derived slots over `per_torrent.up`
  (16KiB/s per-peer floor, cap 32, static fallback 8); preemptive
  unchoke edges; seeder fastest_upload top-8 (`choker.cpp`).
- Advertisement-aware dispatch: the zero-request table for
  un-advertised pieces (libtorrent `request_blocks.cpp`/181 +
  `piece_picker.cpp`; aria2 `DefaultPieceStorage.cc`), HAVE / bitfield
  / have_all / have_none bookkeeping under BEP6 replacement
  semantics, and spread selection (`select_advertised_piece_spread` =
  isPieceUsed exclusion + per-peer checkout + getMissingFastPiece
  fallback).
- Supply window: the `supply_cap` saturating subtraction; the budget
  `min(rate x 20s, 8MiB) / piece_len` (a `request_blocks.cpp` port)
  with the floor knob; adjacent-chain fill to the checkout cap; stale
  secondary drain before append; soft accounting (ceil folding) in
  both arms; adjacent soft-break skipping with a round budget.
- Reissue window: the adaptive per-peer window clamped to
  [DISPATCH_REISSUE_WINDOW, REISSUE_WINDOW_CEIL]; transfer implies
  cancel (the `DefaultBtMessageDispatcher.cc` cancel half);
  cancel-on-verified at piece settlement.
- have timing: HAVE at hash-pass, upload serving gated on written
  (commit `7f691246a`), completion recheck reads written_count only.
- Endgame: trigger conditions A/B (`request_blocks.cpp` reverse-
  condition complement); the strict gate and empty-handed gate; x2
  copy metering; the tiered fast busy gate; last-mile wide fan-out
  (relax-only copies cap, pure rate order); the full strict gate
  chain from activation to release; sibling cancel on settle
  (`torrent.cpp`) through the arrival->settle sequence.
- Two-phase ledger: arrival / settle / reply / lifecycle transition
  tables, the store-pending guard scan, claimed-set rebuild and busy
  counting re-tracked on the adaptive window.
- Levers: connection admission (aria2 bt-max-peers semantics with the
  `ActivePeerConnectionCommand.cc` count-gated backfill), the
  stall valve state machine, seeder rotation, slow-peer churn with the
  webseed exemption, uTP mute.
- BEP53 masks: v2-only cursor projection, v1 byte grid, single/empty
  file shapes, error semantics.
- Structural: DispatchScratch and ClaimedSet reuse, the PeerState
  merged row, getPeers lazy bitfield packing, completion releasing
  the scratch and the stat_man bucket view.

Test bodies assert Chinese string messages verbatim by policy; those
literals are not part of the comment distillation.

## addr_hygiene.rs

Discovery-source address hygiene: peer addresses from the four discovery
sources — tracker (peers/peers6), DHT (`PeersFound` values), ut_pex
(`added`/`added6`), x.pe — are all untrusted input. A malicious tracker
or peer can inject v4-mapped IPv6 (`::ffff:a.b.c.d`, riding a v6 carrier
past the per-family accounting / ban face's v4 keys — the mapped-form
family split PoC) and bogon addresses (loopback / link-local / multicast
— probing the local host). `sanitize_discovered_addr` is the single
decision point (v4-mapped normalized to a v4 endpoint + bogon rejection);
every discovery-source entry (engine main-loop tracker/DHT/PEX arms, the
outbound-dial choke point `spawn_peer_dial`, the magnet metadata dial
`spawn_dial`) reuses it; scattered reimplementations are forbidden.

Classification authority order: BEP text > libtorrent > aria2.

### Reject list

All classes are RFC/libtorrent-backed; no invented ranges.

- v4-mapped — v6 `::ffff:0:0/96` -> normalized to v4, then classified.
  RFC 4291 §2.5.5.2; libtorrent `make_address_v4(v4_mapped, ..)`
  `src/bt_peer_connection.cpp`.
- Unspecified — v4 `0.0.0.0`, v6 `::`. RFC 1122 §3.2.1.3 / RFC 4291
  §2.5.2; libtorrent `peer_list::add_peer` "obviously invalid"
  `src/peer_list.cpp`.
- Port 0/1 — both families. libtorrent `add_peer` rejects explicitly
  (`src/peer_list.cpp`; port 0 has no endpoint semantics; 1 matches
  libtorrent's mainstream floor).
- Loopback — v6 `::1` (v4 loopback is allowed, see the allow list).
  RFC 4291 §2.5.3 (the local-probing face); via the reused
  `taiji_bt::dht::security::is_global_v6`.
- Link-local — v4 `169.254.0.0/16`, v6 `fe80::/10`. RFC 3927 / RFC 4291
  §2.5.6; libtorrent `add_peer` rejects v6 link-local explicitly
  (connect EINVAL, `src/peer_list.cpp`) + `is_link_local`
  `src/ip_helpers.cpp`.
- Multicast — v4 `224.0.0.0/4`, v6 `ff00::/8`. RFC 1112 / RFC 4291 §2.7.
- Documentation — v4 `192.0.2.0/24` `198.51.100.0/24` `203.0.113.0/24`,
  v6 `2001:db8::/32`. RFC 5737 / RFC 3849 (the same domain as std
  `is_documentation`).
- ULA — v6 `fc00::/7`. RFC 4193 (via `is_global_v6`, whose exempt/global
  semantics align with libtorrent `is_local` `src/ip_helpers.cpp`).

### Allow list (over-rejection red line: wholesale dropping is forbidden)

- Normal global unicast (any 2000::/3 v6 address, ordinary public v4) is
  always allowed.
- RFC1918 private ranges (10/8, 172.16/12, 192.168/16) and CGNAT
  100.64/10 are ALLOWED: LAN swarms are a real use case, BEP42's
  enforcement section "Any peer on a local network address is exempt"
  points the same way, and the design reject list does not list private
  ranges (libtorrent `add_peer` does not reject them either).
- v4 loopback (127.0.0.0/8) is ALLOWED — an intentional divergence from
  the design reject list: same-host multi-client swarms are a real BT
  topology; libtorrent `add_peer`'s reject set is {unspecified, port
  0/1, v6 link-local} (`src/peer_list.cpp`) — v4 loopback is not in it;
  and every in-process interop/regression assembly in this repo
  (engine_loop / dht_wire / tracker_wire / pex_engine / magnet)
  discovers peers on loopback endpoints, so rejecting them would
  systematically break the "existing tests unchanged" criterion. The
  design's loopback rejection lands on v6 (::1) via the reused
  `is_global_v6`; v4 loopback's abuse face (self-connect spinning) is
  covered by the existing self-connect guard (loopback AND announce port
  equal), and any other loopback endpoint carries the same exposure as
  any other local service (libtorrent has the same shape). A mapped
  wrapper `::ffff:127.0.0.1` normalizes to the same verdict as the
  literal v4 form (no new hole: family unification is exactly the
  mapped-form fix goal — wrappers no longer produce a separate v6 key).

### Cross-checks

- libtorrent's peer-table admission (`peer_list::add_peer`) is itself
  the "reject obviously invalid" blacklist form (unspecified / port 0/1
  / v6 link-local), not a GUA whitelist — this implementation has the
  same shape; `is_global` is used only on the v6 reuse face (the ULA row
  above).
- aria2 has no counterpart face (no loopback/multicast/mapped
  classification of discovered addresses anywhere in src;
  `DefaultPeerStorage::addPeer` inserts directly) — no upstream
  reference exists for this class.

### Self-connect detection extension

The original guard = "loopback AND announce port" (the engine's
tracker/DHT/PEX/holepunch arms + magnet `spawn_dial`, all the same
form). Three synonymous endpoints bypass it: `0.0.0.0:<port>`
(unspecified — the observable form of the kernel landing the connection
back on the local host), `[::ffff:127.0.0.1]:<port>` (a v4-mapped
wrapper), and the local host's non-loopback interface addresses (a
tracker/DHT announce echo carrying the local LAN address + our own
announce port = a true self-connect the loopback test cannot cover).

The fix = the single predicate `is_self_endpoint`: announce port equal
AND (loopback OR unspecified OR v4-mapped loopback OR a member of the
`LocalIpSet` local address set). The four arms and magnet reuse the same
predicate (the former scattered `is_loopback()` tests all converge here;
scattered reimplementations are forbidden).

`LocalIpSet` trade-off (documented): enumerated once per process
(`LocalIpSet::shared` lazy init + a session-start warm-up), NOT
re-enumerated on interface changes. Rationale:
1. enumeration is a local getifaddrs syscall (no network IO); a
   once-per-process cost is effectively zero;
2. runtime re-enumeration adds countermeasure complexity (change
   detection cadence / jitter) for negligible benefit — the self-connect
   source is "our own address inside announce echoes", and the address
   set is highly stable over a task's lifetime;
3. enumeration failure (restricted environments) = an empty set =
   degradation to the original loopback-only test (fail-open to the old
   semantics; connectivity unaffected; the ban gate unaffected).

