# Tracker subsystem: upstream anchor mapping

Reference source: aria2, reference commit `9e7273583f83e881e3ec067b523ba88724088d2f`
(read-only), plus libtorrent where noted.

## mod.rs (tracker family conventions)

- Announce URL parameter order and fields: `aria2/src/DefaultBtAnnounce.cc`
  (`info_hash` / `peer_id` / `uploaded` / `downloaded` / `left` /
  `compact=1` / `key` / `numwant` / `no_peer_id=1` + `port` + `event` +
  `trackerid` + `requirecrypto` / `supportcrypto`).
- `numwant`: 50 when there are peers left to fetch, otherwise 0
  (`DefaultBtAnnounce.cc`, HTTP and UDP paths).
- HTTP `key` = last 8 bytes of the peer_id (`DefaultBtAnnounce.cc`);
  UDP `key` = a random number.
- `interval` / `min interval` handling: `DefaultBtAnnounce.cc`.
- `peers6` (BEP7 IPv6 tracker extension): `DefaultBtAnnounce.cc`.
- peer_id generation: prefix + random fill up to 20B
  (`aria2/src/bittorrent_helper.cc`). aria2's default prefix is
  `A2-<maj>-<min>-<mic>-` (`OptionHandlerFactory.cc`); taiji uses the BEP20
  Azureus-style `-TJ0001-` (its own identity). The `--peer-id-prefix`
  default value, overlong-prefix truncation, and short-prefix random fill
  match aria2 `usage_text.h` (see `generate_peer_id`).
- Local identity string (User-Agent and ext-handshake `v`): `PEER_AGENT` =
  `taiji/<CARGO_PKG_VERSION>`. libtorrent's ext-handshake `v` defaults to
  `user_agent` (`bt_peer_connection.cpp`), and `user_agent` itself defaults
  to `"libtorrent/" LIBTORRENT_VERSION` (`settings_pack.cpp`) — the same
  "product/version" string serves as both UA and `v`. The configurable
  surface is kept separate from `peer-id-prefix`.
- Compact peers: 4B IPv4 + 2B port (big-endian) per entry (BEP23; BEP3
  `compact=1`); IPv6 is 16B + 2B (`DefaultBtAnnounce.cc` `extractPeer`,
  AF_INET6).

## announce_list.rs (tier state machine, BEP12)

Direct translation of aria2 `AnnounceTier`/`AnnounceList`, reference commit
`9e7273583f83e881e3ec067b523ba88724088d2f` (read-only):

- Seven event states: `aria2/src/AnnounceTier.h`.
- `nextEvent` / `nextEventIfAfterStarted` transitions:
  `aria2/src/AnnounceTier.cc`.
- Tier initialization (constructed already in the STARTED state):
  `aria2/src/AnnounceTier.cc`.
- `announceSuccess` (advance the event + move the URL to the tier front +
  return to the first tier): `aria2/src/AnnounceList.cc`.
- `announceFailure` (advance URL/tier; at the end of the tiers, force
  `nextEventIfAfterStarted`): `aria2/src/AnnounceList.cc`.
- `resetTier` = `resetIterator`: `aria2/src/AnnounceList.cc`.
- stopped/completed allowed sets and `moveTo*AllowedTier` (ring search,
  `find_wrap_if` = search from current to last, then from first to
  current): `AnnounceList.cc`, `aria2/src/a2algo.h`.
- `allTiersFailed` (currentTier == end): `AnnounceList.cc`.
- `reconfigure` skips empty tiers: `AnnounceList.cc`.
- `shuffle` (shuffle URLs within each tier): `AnnounceList.cc`.

Implementation note: aria2 expresses "end of tiers / all failed" with deque
iterators plus `currentTrackerInitialized_`; this port uses indices
(`current_tier == tiers.len()` is equivalent to
`currentTier_ == end(tiers_)`), with per-item semantics matching the
anchors above one to one.

## scrape.rs (HTTP scrape, BEP48)

aria2 has no scrape implementation: a full grep of `src/` finds only
`UDPTrackerClient.cc` discarding SCRAPE replies as "unexpected scrape
action reply". Protocol facts therefore follow the BEP48 text (Tracker
Protocol Extension: Scrape) directly:

- URL derivation: "locating the string `announce` in the path section of
  the announce URL and replacing it with the string `scrape`"; scrape URLs
  not built this way are "outside of the scope of this specification".
- Request: no body, only the `info_hash` query parameter, which "can be
  appended multiple times ... for collecting data about multiple swarms in
  one request".
- Response: a bencode dict with the single key `files`, mapping a 20-byte
  info_hash to {`complete` (active peers that finished downloading),
  `incomplete` (active peers still downloading), `downloaded` (historical
  completions)}; failure -> `failure reason`.
- Scrape is a read-only query, "no effect on a peer's participation in a
  swarm".

UDP scrape (BEP15) is implemented in `udp.rs` (sourced from the BEP15 text
the same way).

## http.rs (HTTP/HTTPS announce)

Reference source: aria2, reference commit
`9e7273583f83e881e3ec067b523ba88724088d2f` (read-only):

- Full URL parameter order (base -> port -> event -> trackerid ->
  requirecrypto/supportcrypto): `aria2/src/DefaultBtAnnounce.cc`.
- `trackerid` (appended percent-encoded): `DefaultBtAnnounce.cc`.
- `bt-force-encryption || bt-require-crypto` -> `requirecrypto=1`,
  otherwise `supportcrypto=1`: `DefaultBtAnnounce.cc`.
- The `tracker id` key backfills trackerId_: `DefaultBtAnnounce.cc`;
  key-name table: `aria2/src/BtAnnounce.cc` ("failure reason" / "warning
  message" / "tracker id" / "interval" / "min interval" / "complete" /
  "incomplete" / "peers" / "peers6").
- interval/min-interval: `interval_` updates only when `interval > 0`;
  when `min interval > 0`, `minInterval = min(minInterval, interval)`,
  otherwise `minInterval = interval`: `DefaultBtAnnounce.cc`.
- peers6 (BEP7 IPv6 tracker extension, compact 18B/entry):
  `DefaultBtAnnounce.cc`.
- Default ports http=80/https=443; udp has no default port (a missing
  port makes the URL invalid): `aria2/src/FeatureConfig.cc`,
  `aria2/src/uri.cc`.
- `--bt-tracker-timeout` / `--bt-tracker-connect-timeout` (defaults 60/60):
  aria2's tracker HTTP request timeout options
  (`OptionHandlerFactory.cc` PREF_BT_TRACKER_TIMEOUT /
  PREF_BT_TRACKER_CONNECT_TIMEOUT).
- `--bt-tracker-interval`, the user override of the re-announce interval
  (0 = no override): `DefaultBtAnnounce.cc` (userDefinedInterval_ takes
  precedence over minInterval), `aria2/src/RequestGroup.cc`.

BEP7 `ipv6=` request parameter encoding: the current BEP7 revision
removed the `ipv4=`/`ipv6=` parameter definitions and declares them
discouraged, so libtorrent's interop behavior is followed:
`src/http_tracker_connection.cpp` percent-escapes the address in textual
form (`escape_string(v6.to_string())`).

Response-body transfer caps are tiered: announce/scrape/mirror 4 MiB
(`MAX_BODY_BYTES`, equal to taiji-core `magnet.rs`
`WEB_MIRROR_BODY_CAP`); .torrent URL fetch 30 MiB
(`TORRENT_FETCH_MAX_BODY_BYTES`, taken from libtorrent
`src/settings_pack.cpp` `max_metadata_size` = 31457280). The BEP-9
ut_metadata `MAX_METADATA_SIZE` (8 MiB) tier is separate and unchanged.

## udp.rs (UDP tracker, BEP15)

Direct translation of aria2's UDPTrackerClient, reference commit
`9e7273583f83e881e3ec067b523ba88724088d2f` (read-only):

- Magic connection id `0x41727101980`: `aria2/src/UDPTrackerClient.h`
  `UDPT_INITIAL_CONNECTION_ID` (= the BEP15 protocol_id).
- action/event/error enums: `aria2/src/UDPTrackerRequest.h`
  (CONNECT=0/ANNOUNCE=1/SCRAPE=2/ERROR=3; EVT_NONE=0/COMPLETED=1/
  STARTED=2/STOPPED=3).
- Transaction table (pending/inflight/connect-wait + connectionIdCache)
  and `createRequest`/`requestSent`/`requestFail`/`receiveReply`/
  `handleTimeout`/`failConnect`/`failAll`: `UDPTrackerClient.cc`.
- Retransmission boundary: failCount==0 and >= 5s since the first send ->
  resend once (failCount -> 1, back to the front of pending); otherwise
  >= 10s since the (re)send -> timeout failure (CONNECT additionally
  fails same-host waiters via failConnect) — `UDPTrackerClient.cc`
  (TimeoutCheck; handleTimeout moves the request back to the front of
  pending). BEP15's suggested 15x2^n backoff (n <= 8) is a general
  suggestion; taiji keeps the aria2 5s/10s values by design.
- connection id lifetime: CONNECTED and lastUpdated older than 1min ->
  discarded and reconnected (`UDPTrackerClient.cc`); = BEP15 "a client
  can use a connection ID until one minute after it has received it".
- Connect frame construction: `UDPTrackerClient.cc`.
- Announce frame construction (100B layout): `UDPTrackerClient.cc`.
- Reply parsing (CONNECT exactly 16B / ANNOUNCE >= 20B / ERROR >= 8B /
  peers in 6B steps): `UDPTrackerClient.cc`.
- UDP announce parameters (event mapping, random key, numwant 50/0,
  ip=0, extensions=0): `aria2/src/DefaultBtAnnounce.cc`.
- UDP reply interval semantics: `minInterval = interval`,
  `interval_ = minInterval`: `DefaultBtAnnounce.cc`.

Extension beyond upstream (BEP15 text): aria2 never sends SCRAPE and
drops SCRAPE replies as unexpected (`UDPTrackerClient.cc`). This module
adds scrape per the BEP15 text: request = connection_id(8B) + action=2(4B)
+ transaction_id(4B) + 20B info_hashes; reply = action(4B) +
transaction_id(4B) + 12B per hash (seeders/completed/leechers, in request
order).

Carrier-family peers parsing: the BEP15 connect/announce/scrape frame
surface is family-agnostic (connection_id/action carry no address family;
the announce frame's `ip` field is 4B and always 0 — under a v6 carrier
the tracker identifies the client by source address, the same ip=0 as the
aria2 port). Reply peers parse by carrier family, never mixed (family =
the address family of the remote the reply came from):

- v4 carrier -> 6B/entry (BEP23; `UDPTrackerClient.cc` unpackcompact
  AF_INET).
- v6 carrier -> 18B/entry (16B address + 2B port, BEP32 shape); a length
  that is not a multiple of 18 is an explicit error.
- Source (libtorrent read-only, `src/udp_tracker_connection.cpp`):
  `int const ip_stride = aux::is_v6(m_target) ? 18 : 6;` (stride = the
  carrier's remote family); a stride that does not divide evenly fails
  explicitly with `invalid_tracker_response_length`; a v6 target yields
  peers6 16B+2B, otherwise peers4 4B+2B, never mixed.

## actor.rs (TrackerActor, announce orchestration)

Direct-translation sources: aria2, reference commit
`9e7273583f83e881e3ec067b523ba88724088d2f`, plus libtorrent where noted
(authority order: BEP text > libtorrent > aria2):

- Announce readiness and priority (stopped > completed > default):
  `aria2/src/DefaultBtAnnounce.cc` (the `isAnnounceReady` family).
- Event adjustment (`adjustAnnounceList`): stopped/completed need
  `moveTo*AllowedTier` + `setEvent`; default with the download finished
  while the event is still STARTED -> STARTED_AFTER_COMPLETION.
- Periodic gate: `trackers_ == 0 && elapsed >= (bt-tracker-interval ||
  minInterval)` && !allTiersFailed (userDefinedInterval comes from
  `--bt-tracker-interval`, `aria2/src/RequestGroup.cc`).
- Success handling: `processAnnounceResponse` (trackerid backfill,
  interval/min-interval, complete/incomplete, peers/peers6) ->
  `announceSuccess()` + `resetAnnounce()`
  (`aria2/src/TrackerWatcherCommand.cc`).
- Failure handling: `announceFailure()`; all tiers failed ->
  `resetAnnounce()` (`TrackerWatcherCommand.cc` + `DefaultBtAnnounce.cc`).
- Termination: `noMoreAnnounce` (halt && no stopped-allowed tier,
  `DefaultBtAnnounce.cc`) -> the stopped event sequence completes.
- Default period: `DEFAULT_ANNOUNCE_INTERVAL = 2_min`
  (`aria2/src/BtAnnounce.h`).
- UDP: `DefaultBtAnnounce.cc` (request construction: event mapping,
  random key, numwant, ip=0, extensions=0) + reply (`minInterval =
  interval; interval_ = minInterval`); retransmit/timeout in `udp.rs`.
- Scrape: after a successful announce, batch scrape the same host
  (HTTP=BEP48, UDP=BEP15; upstream-blank, sources in `scrape.rs`);
  results go into the ScrapeCache (the in-memory side of the tracker
  table's seeds/leechers; sqlite persistence via PersistWriter = blocked).

### Announce parallel scheduling (scheduling semantics change; libtorrent behavior authoritative)

The delivered surface was aria2 single-flight: a single `in_flight` field
plus the `trackers_ == 0` gate (`DefaultBtAnnounce.cc`) — at most one
in-flight announce per torrent at any time, so a 74-tracker first round
queued serially. Changed to **per-tracker independent announce state +
one round draining all due trackers** (libtorrent semantics):

- Per-tracker independent timer state: libtorrent keeps
  `next_announce`/`min_announce`/`updating`/`fails` per announce_entry x
  endpoint x info_hash (`include/libtorrent/aux_/announce_entry.hpp`).
  Success books per tracker `next_announce = now + interval; min_announce
  = now + resp.min_interval; updating = false; fails = 0`
  (`src/torrent.cpp`); failure backs off per tracker via
  `a.failed(tracker_backoff, retry_interval)` (`src/torrent.cpp` ->
  `src/announce_entry.cpp`; constants tracker_retry_delay_min = 5s,
  tracker_retry_delay_max = 60min, ratio = tracker_backoff default 250 in
  `src/settings_pack.cpp`). `TrackerSlot` maps to these one to one.
- One round drains all due trackers: `announce_with_tracker` walks all
  trackers, issues a request for each `can_announce` one and sets its
  `updating = true` (`src/torrent.cpp`) — the fully parallel form of
  libtorrent's `announce_to_all_trackers`/`announce_to_all_tiers = true`
  (the settings default of false keeps a single working tracker; taiji
  specifies parallel + an in-flight cap, so the first announce lands at
  the fastest tracker's latency). Due = the min over trackers of
  `max(next_announce, min_announce)` (`update_tracker_timer`'s single
  timer wheel drives the same drain path).
- In-flight cap (a taiji addition): libtorrent has no per-torrent
  in-flight cap; `ANNOUNCE_MAX_IN_FLIGHT` bounds it against self-flooding
  (a local scheduling policy, not wire behavior).
- interval/min_interval compliance (protocol red line, kept verbatim):
  after success a tracker is not re-announced before its own min_interval
  (the `can_announce` gates, `src/announce_entry.cpp`); the period = the
  tracker's reply `interval` (`finish_success` books
  `max(interval, min_interval)` — libtorrent `next_announce = now +
  interval`; earlier code mistakenly used min_interval as the period).
  The user override keeps aria2's formula (userInterval > 0 uses user,
  `DefaultBtAnnounce.cc`), made per-tracker.
- The tier event machine is kept: the AnnounceTier seven states
  (STARTED -> DOWNLOADING etc.) and the stopped/completed sequence
  semantics unchanged (stopped only sends to stopped-allowed tiers,
  noMoreAnnounce completes HALTED); URL failure advance within a tier and
  the tier-end `nextEventIfAfterStarted` (`AnnounceList.cc`) are
  preserved per-tier inside the halt sequence. The periodic path's
  failure handling changes from aria2's cursor advance to libtorrent
  per-tracker backoff retry (`failure_backoff`) — under aria2 semantics a
  failed tracker waits for the whole-table resetAnnounce before
  retrying; backoff retry is strictly more aggressive. The cursor state
  machine `announce_list::AnnounceList` stays as the BEP12 reference
  implementation with its direct-translation tests; it no longer drives
  this actor.
- BEP27 private single-flight gate: for private torrents
  (`info.private` = 1, the engine projection
  `TrackerActorConfig::private`) parallel waves are fully off — "each
  peer MUST use only one tracker at a time": the in-flight cap drops to 1
  (one tracker of one tier at a time) and candidate selection narrows to
  "pin the last success + table-order advance on failure" (the
  table-order equivalent of aria2's single-flight order: `announceSuccess`
  moves the URL to the queue front / `announceFailure` advances,
  `AnnounceList.cc`). The parallel form is a BEP27 violation for private
  torrents (private-tracker risk control can see simultaneous
  announcements to multiple sites / double-counted snatches). Public
  torrents are unchanged (parallel waves as-is).
- Duplicate announces to one tracker are forbidden: the `updating`
  in-flight gate (announce_entry.cpp `!updating`) + UDP same-endpoint
  in-flight dedup.
- Result routing and entry folding: HTTP results land by the slot
  identity token taken at issue time (aligned with UDP routing by remote
  addr) — the first version matched by URL string first-match, so two
  slots with the same URL (reachable via a duplicated `tr=` magnet) sent
  both results to the first slot and the second stayed stuck in
  `updating` (the `slot_due` gate -> never announces again, `in_flight`
  leaks, the halt sequence blocks); the same announce URL is folded at
  the `build_tables` sink (first occurrence kept, the same semantics as
  libtorrent's one announce_entry per URL), covering the
  magnet/SetTrackers/global-import entries.

### Observability surface (unchanged)

One line per announce lifecycle: `announce attempt` (url/scheme/tier/
event) -> `announce ok` (interval/elapsed_ms) or `announce failed`
(class/reason/elapsed_ms); class = `TrackerError::class` (dns /
connect-tls / connect / timeout / http-status / malformed /
tracker-reason / invalid-url). The tier number = the configured
(tier, url) tier value (the tracker table row key convention). Per-tracker
logs are kept after parallelization; failure fast-forward = failure
results are processed in the same tick before the wave issues (DNS /
invalid-url fail immediately, freeing the slot without waiting for a
timeout).

### UDP domain resolution carrier

announce/scrape udp:// hosts previously only accepted literal IPs (a
domain failed as invalid-url — real tracker lists are full of domain
forms, all failing into backoff). Resolution now goes through the shared
[`taiji_io::dns`] layer (reference: aria2 `NameResolveCommand.cc`):

- Resolver seam: the SharedDns shared service (resolver + TTL cache; the
  production default instance wraps tokio DNS in a 30s resolve-timeout
  decorator (aria2's `--dns-timeout` default), getaddrinfo on the
  blocking pool; tests inject a stub via `with_resolver` into a separate
  instance — real DNS is forbidden).
- Literal IP pass-through: a successful `parse::<IpAddr>()` is used
  directly, zero resolution overhead (the isNumericHost pass-through
  shape of `NameResolveCommand.cc`).
- Domains go through the shared service: a per-host whole-list TTL cache
  (5min / capacity in host entries / a hit issues no query / negatives
  not cached; **backfill happens only inside the service, as a whole
  list** — the actor reads only per-family projections). On a miss a
  resolve task spawns and the result returns via the result channel — a
  non-blocking tick (the decoupling shape of `NameResolveCommand.cc`'s
  independent command that only addRequests onSuccess; announce results
  land by slot token, the same path as HTTP). Behavior notes: a cache
  hit followed by connection failure does not evict; the UDP projection
  keeps a single address with no list fallback (a dead IP stays pinned
  for the TTL); a list with no record of the family = an empty
  projection Err without re-query — authoritative statements in the
  `taiji_io::dns` module docs.
- Failure classification: resolution failure = the retryable class
  "dns" (`NameResolveCommand.cc` res.empty() -> onFailure -> UDPT_ERR_
  NETWORK network class), not invalid-url (permanent); backoff goes
  through `finish_failure`'s failure_backoff system; the log
  class/reason matches existing failures.

### IPv6 UDP carrier

At delivery, v6 resolution results took an "IPv6-UDP unsupported"
rejection path (then an open question); once v6 UDP carriers were ruled
supported, the rejection path was removed and the v6 carrier surface
landed as follows:

- Dual-stack separate announce: udp:// domain URLs expand into v4/v6
  face slots (`TrackerSlot::udp_family`), issued in parallel within the
  same period (the wave-drain semantics cover them automatically); a
  literal v4/v6 URL is a single face (family = the literal family). The
  face model mirrors libtorrent `announce_entry::endpoints` per-endpoint
  independent state (`include/libtorrent/aux_/announce_entry.hpp`) +
  endpoint failure isolation (`src/udp_tracker_connection.cpp`).
- Per-family resolution: the V4 face resolves A, the V6 face AAAA
  (ResolveFamily; the BEP15 carrier family = the transport family —
  libtorrent `udp_tracker_connection.cpp` picks the peers stride by
  destination family). No AAAA / resolution failure -> that v6 face
  silently skips with independent backoff (the attached face does not
  enter `TrackerActorEvent::AnnounceFailed`,
  `TrackerSlot::silent_failure`; debug logs kept), without affecting the
  v4 face announce. The v4 face (primary) and single-face slots
  (including a literal v6 URL — that tracker's only carrier) report
  failures as usual.
- v6 availability gate: before issuing, a v6 face passes `v6_gate` —
  `crate::dht::security::probe_source_ip(true)` (v6 = a time-limited TCP
  connect probe; the `V6_PROBE_TTL` cache); no global v6 -> the whole v6
  face finishes as an "unavailable" failure (silent/report as above — a
  single-face slot must report, or the halt sequence has no failure
  bookkeeping to converge on). The design forbids a blind v6 announce
  without the probe; test seam `with_v6_probe_override`.
- Response parsing: the carrier family is known (the reply's remote) ->
  v4 6B / v6 18B peers, never mixed (see `udp.rs`).
- HTTP surface/core unchanged: outbound v6 frames go through the
  existing channel and the core routes by destination family
  (`assemble.rs` `addr.is_ipv4` dispatch carries the v6 face); HTTP
  trackers (reqwest's own DNS, existing peers6) are untouched.

### Channel capacities

Commands `mpsc(16)` + oneshot replies, events `mpsc(16)` (contract); UDP
carrier: outbound `mpsc(64)` / inbound `mpsc(256)` (aligned with the
demux `tracker_tx(256)` / outbound `OutboundPacket` magnitudes; duplex
channels stand in for tests until the demux lands).





