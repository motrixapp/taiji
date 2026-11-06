# taiji-io design notes

Distilled design and upstream-anchor notes for `crates/taiji-io`. Code
module headers keep a short mechanism summary and point here.

## knobs.rs

Upstream anchor mapping for the `BH_*` env-knob registry
(`crates/taiji-io/src/knobs.rs`):

- `BH_UNCHOKE_SLOTS`: default 8 = libtorrent `settings_pack.cpp`
  `unchoke_slots_limit`; the optimistic share max(1, N/5) mirrors
  `OPTIMISTIC_SLOTS_AUTO`. Clamp floor 3 = 2 regular + 1 optimistic slot.
- `BH_REQ_WINDOW_FLOOR`: `=2` restores the libtorrent reference
  `min_request_queue`; the earlier in-tree default was 24.
- `BH_REQ_WINDOW_INIT`: `=6` restores aria2 `BtConstants.h`; the initial
  window doubles as the slow-start starting point.
- `BH_REISSUE_CEIL_SECS`: rqbit has no per-block reissue — in-flight is
  reclaimed only when a peer dies (librqbit live/mod.rs
  `mark_chunk_requests_canceled`), so deep queues are never disturbed by
  a reissue window. A 5s ceiling voids deep queues (a tail block older
  than the window gets reissued to another peer and the original holder
  cancelled); the knob makes that ceiling configurable.
- `BH_DHT_RAMP_MIN_PEERS`: `=50` restores the libtorrent threshold
  (torrent.cpp `num_peers < 50`).
- `BH_TRACKER_MIN_PEERS`: `=40` restores aria2 `BtRuntime.h`
  `DEFAULT_MIN_PEERS`.
- `BH_DHT_FRONTIER_K`: `=8` restores the aria2
  `DHTAbstractNodeLookupTask` candidate-table truncation width.
- `BH_SERVE_PENDING_CAP`: default 256 ≈ the peer target-window ceiling,
  the same anchor as aria2 `BtConstants.h` `UB_MAX_OUTSTANDING_REQUEST`
  and the doubling adaptive ceiling: normal pipelining keeps ≤ 256
  outstanding requests per peer; beyond that is a window violation or a
  stalled completion drain. At cap the bt `read_pool::ServeQueue`
  answers BEP-6 Reject Request.
- `BH_ENDGAME_FAST_BUSY_K`: the strict busy gate (one busy piece per peer)
  is the `request_blocks.cpp` port. K-tiering keeps the replica cap ×2
  (`ENDGAME_MAX_COPIES`) and the last-mile boundary
  (`BH_ENDGAME_LASTMILE`) fixed; K only widens the busy-pieces-per-peer
  dimension for peers ≥ 2× the peer-rate median and ≥ 100KiB/s.
- `BH_ADJACENT_SKIP_N`: in claim-dense regions adjacent chains often
  break at the first piece, degrading to single-piece cadence and losing
  the seeder sequential-read benefit of goff-contiguous spans. Soft
  breakpoints (completed/claimed/unadvertised, goff still contiguous)
  may be skipped, at most N per round; hard breakpoints (goff
  non-contiguous) still break the chain. Skipped pieces are not
  dispatched, not claimed, and not counted against checkout occupancy.
- `BH_CHECKOUT_SOFT_ACCOUNTING`: whole-piece checkout counting with
  release-on-arrival collapses in-flight 128 -> 0 and refills in one
  batch (sawtooth); soft weighting `ceil(Σ pending blocks / blocks per
  piece)` refills slots block by block. rqbit keeps no piece-level
  checkout and refills a constant 128-deep request window per block
  (librqbit live/mod.rs). Invariant: only the "cap" dimension is
  relaxed; the "window" dimension stays clamped by supply_cap.
- `BH_DIAL_PREFER_UTP`: flipping the outbound plan to `[Utp, Tcp]` puts
  outbound connections under BEP-29 LEDBAT congestion control, which
  yields to user traffic; inbound is unaffected.
- `BH_UNCHOKE_BUDGET_SLOTS` / `BH_UNCHOKE_PER_PEER_FLOOR_BPS`:
  budget-derived slots N = clamp(upload budget / per-peer floor, 4, 32);
  unlimited upload falls back to the static `BH_UNCHOKE_SLOTS` value;
  the 16KiB/s floor is the minimum meaningful per-peer unchoke rate.
- `BH_SEED_PASSIVE_DHT` (default off; exactly `=1` opts in, full rule in
  the accessor docs): discloses the service-level degradation — with the
  flag set (=1), a completed torrent's DHT seed visibility decays to zero
  within 30 min (the BT engine's PeerAnnounceCheck clears the registry
  every 30 min), so remote peers stop finding the torrent via DHT and
  upload supply falls; the tracker face is unaffected; a new download
  task immediately resumes active announces.
  Behavior zero-change: the flag only gates the completed-state re-issue
  rounds; the default (off) keeps the always-active announce face.

## redact.rs

- aria2/libtorrent log raw URLs at debug; this crate strips credentials
  at every level by default (debug is the "please paste your logs"
  sharing mode, so the fullest form must not be a log-level side effect).
- tracing-subscriber 0.3.x `escape.rs` EscapeGuard covers ESC/BEL/C1
  only; `escape_control_chars` fills the CR/LF/NUL gap so raw control
  characters cannot forge or replay log lines.

## dns.rs

Upstream anchors (aria2, read-only reference; libtorrent):

- Literal-IP passthrough (zero resolution cost): aria2
  `NameResolveCommand.cc` `util::isNumericHost(hostname)` pushes the
  hostname straight into the result list. The same branch exists in
  `SharedDns::resolve_for_transport`; on the reqwest/hyper-util path it
  is dead code (hyper-util's `try_parse` short-circuits first) and is
  kept for direct-call faces such as FTP.
- First-address use: `NameResolveCommand.cc` onSuccess assigns
  `req_->remoteAddr = addrs[0]`. The taiji single-address view
  (`pick_addr`) takes the first IPv4, or the first v6 when only v6
  exists — the same orientation as aria2's
  `PREF_DISABLE_IPV6 → setFamily(AF_INET)`; taiji has no such option and
  expresses it as a preference order, and v6-only results are handed to
  the v6 carrier face instead of a rejection path.
- Resolution failure is network-class retryable: `NameResolveCommand.cc`
  `res.empty() → onFailure()` sets `req_->error = UDPT_ERR_NETWORK` —
  not URL-class (permanent). taiji maps it to the retryable error class
  "dns" and reuses the actor's existing failure-backoff machinery.
- Resolution is decoupled from the request: aria2 enqueues the request
  only on resolve onSuccess. taiji spawns the resolve task inside the
  actor and returns the result through the result channel (non-blocking
  tick).
- Bad-IP rotation: aria2 rotates known-bad addresses
  (`markBadIPAddress`, `AbstractCommand.cc` / `DownloadEngine.cc`);
  taiji deliberately does not implement that rotation — a stale cache
  entry can compound with upper-layer retries.
- `DNS_TIMEOUT` = 30s is anchored to aria2's `--dns-timeout` default of
  30 (a hidden option in `OptionHandlerFactory.cc`, range 1..=60).
- Log levels: aria2 logs all four resolution points at INFO — cache hit
  (`MSG_DNS_CACHE_HIT`, `AbstractCommand.cc`), resolving
  (`MSG_RESOLVING_HOSTNAME`, `AsyncNameResolverMan.cc`), resolution
  complete (`MSG_NAME_RESOLUTION_COMPLETE`), resolution failed
  (`MSG_NAME_RESOLUTION_FAILED`). taiji deliberately drops
  hit/miss/complete to debug and keeps failure at info: the shared layer
  is the single source for every transport, hit/miss are high-frequency
  events that would flood INFO, and failures are rare and
  triage-critical (frequency discipline outranks the reference levels).
  Log target: `taiji::io::dns` (the `taiji::<crate>::<module>` shape).

Cache capacity accounting: `HOST_CACHE_CAPACITY` (256) counts host
entries — a dual-stack host's A and AAAA records share one whole-list
entry. Under the earlier per-family shape the same constant spent two
slots per dual-stack host, so the shape upgrade doubled the physical
capacity behind an unchanged constant.

## nat/igd.rs

Protocol facts (UPnP Forum "WANIPConnection:2 Service" Standardized DCP,
2010-09-10; v1 semantics are backward-compatible — same action names and
parameters; v1-specific behavior noted separately):

- Service identification: `urn:schemas-upnp-org:service:WANIPConnection:1|:2`
  (v2 spec §2.1/§5); routers also commonly expose the same port-mapping
  actions as `WANPPPConnection:1` (the miniupnpc-compatible face).
  Discovery runs over SSDP: M-SEARCH to `239.255.255.250:1900` (UPnP
  Device Architecture §1 Discovery).
- AddPortMapping (v2 §2.5.16, Table 2-39): IN = NewRemoteHost/
  NewExternalPort/NewProtocol/NewInternalPort/NewInternalClient/
  NewEnabled/NewPortMappingDescription/NewLeaseDuration. "creates a new
  port mapping or overwrites an existing mapping with the same internal
  client"; if the same ExternalPort+Protocol pair is already mapped by
  **another** internal client, an error is returned ("If the
  ExternalPort and PortMappingProtocol pair is already mapped to another
  internal client, an error is returned") — conflict code 718
  ConflictInMappingEntry (§2.5.23 Table 2-51: "The port mapping entry
  specified conflicts with a mapping assigned previously to another
  client").
- LeaseDuration semantics (§2.5.16.2/§2.5.16.3): the control point must
  send 1..=604800 seconds; '0' = an out-of-band permanent mapping (a v2
  gateway must interpret 0 as 604800s) and the control point must not
  send it; "It is RECOMMENDED that NewPortMappingLeaseDuration value
  would be no more than 3600 seconds" — this crate uses 3600s, renewed
  every 60min by re-issuing AddPortMapping (the §2.5.16 overwrite
  semantics).
- AddAnyPortMapping (v2 §2.5.17): same arguments; "where the specified
  port is not free... the gateway reserves any free NewExternalPort and
  NewProtocol pair and returns the NewReservedPort" — the output-port
  source of the conflict fallback.
- GetSpecificPortMappingEntry (§2.5.15, Table 2-37): IN =
  NewRemoteHost/NewExternalPort/NewProtocol; OUT = NewInternalPort/
  NewInternalClient/NewEnabled/NewPortMappingDescription/
  NewLeaseDuration — the query face for mapping presence and actual
  lease (including permanent-mapping detection: read back lease=0).
  Absent → 714 NoSuchEntryInArray (§2.5.23 Table 2-51).
- GetExternalIPAddress (§2.5.20): OUT = NewExternalIPAddress.
- DeletePortMapping (§2.5.18, Table 2-43): IN = NewRemoteHost/
  NewExternalPort/NewProtocol.
- NewProtocol is "TCP"/"UDP" (§2.5.16.2 "PortMappingProtocol is either
  TCP or UDP"); any other value → 601 Argument Value Out of Range.

Timeout/cap anchors: libtorrent's upnp face uses a 10s SOAP connect
completion timeout and a 30s description GET (`upnp.cpp`); the body-cap
reference is `default_max_bottled_buffer_size = 2MiB`
(`http_connection.hpp`). The XML hardening rationale (rupnp 3.0's
fetch/parse has no injection point: a fresh hyper Client per call, an
unbounded `collect().to_bytes()` body read, inline roxmltree parsing on
the actor task, and a recursion-unguarded `DeviceSpec::from_xml`) and
the mitigation design (total-budget timeouts, body caps, depth precheck,
spawn_blocking isolation, error-string truncation) live in the module
docs of `crates/taiji-io/src/nat/igd.rs`.

Location-host validation basis: libtorrent's `upnp_ignore_nonrouters`
subnet-matches the SSDP response **source address** with
`match_addr_mask(listen, from, netmask)` (`upnp.cpp`); ssdp-client 2.x
does not expose the response source address (`SearchResponse` field
set), so the Location host is validated instead (RFC 1918 / RFC 3927
literals only).

## nat.rs

NAT port mapping (SPEC §6.8): a single-instance `NatActor` owning the
Map/Renew/Unmap/Snapshot command surface, protocol selection, a 60-minute
renewal cadence, failure backoff, and RFC 6886 §3.6 epoch state-loss
response. Submodules: `nat/natpmp.rs` (NAT-PMP per RFC 6886, hand-rolled
packet codec + client) and `nat/igd.rs` (UPnP IGD via the rupnp crate:
SSDP discovery and WAN{IP,PPP}Connection actions).

Message contract (frozen names): commands
`NatCommand{Map{proto,port,lease}, Renew, Unmap, Snapshot}` on an mpsc
channel of capacity 16 with oneshot replies; events
`NatEvent{Mapped{external_port}|Failed{reason}}` on an mpsc channel of
capacity 16, consumed as the announce-port input (the engine wiring
lives in taiji-core).

Behavior:

- Map the listen port on both TCP and UDP. NAT-PMP requests a 3600s
  lifetime; IGD uses `NewLeaseDuration` = 3600 (the spec RECOMMENDS
  <=3600, and 0 = permanent is never sent — see `nat/igd.rs` docs).
- Renewal ticks every 60min (SPEC §6.8; the divergence from RFC 6886
  §3.3 halfway is described under `nat/natpmp.rs` below). A UPnP
  readback of lease=0 (permanent) stops renewal; NAT-PMP renewals
  suggest the gateway-assigned external port (RFC 6886 §3.3 final
  paragraph — port stability across gateway reboots).
- Failure backoff: after a failed full round, retry on the
  `natpmp::ROUND_BACKOFF` table without giving up (converges once the
  device returns). The first entry into the failed state emits `Failed`;
  recovery emits `Mapped` (events are state edges, not per-attempt spam).
- Conflicts (occupied port): NAT-PMP is covered by the gateway-side MUST
  (§3.3 "If that external port is not available, the NAT gateway MUST
  return an available external port if possible") — the reply port is
  the fact, and the `Mapped` event reports the actual port. IGD conflict
  (718 ConflictInMappingEntry) falls back to AddAnyPortMapping on a v2
  service (§2.5.17 NewReservedPort); v1 has no output-port surface and
  counts as failure (see `nat/igd.rs` docs).
- External IP change: a NAT-PMP epoch regression (RFC 6886 §3.6, below
  the conservative estimate by more than 2s) means state loss; after a
  uniform-random 0-5s delay all mappings are recreated immediately
  (§3.7). The external address is refreshed by polling on a local-policy
  10min period (opcode 0 address request / GetExternalIPAddress — the
  poll frequency has no spec-anchored value; listening for gateway
  multicast announcements, RFC 6886 §3.2.1 on 224.0.0.1:5350, remains an
  enhancement awaiting real-environment validation).
- Protocol selection: NAT-PMP first (one RTT of packets vs the SOAP/XML
  round trip). The gateway address comes from explicit configuration or
  is derived from the IGD device URL host (the IGD device is the router
  itself). If SSDP fails and nothing is configured, NAT-PMP is skipped:
  querying the default gateway via the routing table needs platform
  APIs, unsafe is banned repo-wide, and there is no ADR for one.

Concurrency discipline: lock-free (state owned exclusively by the
actor, driven by commands and timers); command and event channels are
bounded(16) and `try_send` drops events when full with a warn (events
only accelerate snapshots; `Snapshot` always yields the full truth).
Gateway IO is all async (UDP/Hyper); the XML-parsing blocking boundary
is documented in `nat/igd.rs`. The actor executes gateway operations
inline (new commands queue in the bounded channel while one is being
processed — NAT gateway operations are a seconds-scale low-frequency
surface, so this is acceptable; the worst full retransmission round is
~127s per RFC 6886 §3.1, and tests inject short schedules).

Validation and robustness:

- Gateway identity is decoupled: a NAT-PMP gateway derived from the IGD
  host is recorded in a revocable ledger (`derived_gateway`); repeated
  failures discard it and rediscover (re-running the SSDP Location
  check) — the session is no longer pinned to the first discovered
  device. Explicit configuration is unaffected.
- PMP reply hardening: external port 0 in a success reply is rejected; a
  too-small granted lifetime falls back to the requested value (the
  renewal-cadence poisoning surface); epoch regressions inside a short
  window trip `natpmp::EpochPoisonGuard`, which disables NAT-PMP once
  the strikes fill (cutting off forged-reply-driven permanent recreate
  loops). Opcode/source-address/internal-port attribution checks were
  already in place.
- `NatHandle::map` tries each protocol independently: a single-protocol
  failure no longer short-circuits, so UDP always enters wanted and
  stays reachable through backoff retries.
- SSDP keeps polling through single errors: see `nat/igd.rs`.

Constants: `COMMAND_CHANNEL_CAPACITY`/`EVENT_CHANNEL_CAPACITY` frozen
at 16; `DEFAULT_LEASE` 3600s; `DEFAULT_ADDRESS_POLL` 10min (local
policy); `DEFAULT_SSDP_TIMEOUT` 3s (local policy — ssdp-client responses
are randomly delayed within MX and the window must cover them; it is
the rupnp `discover(timeout, ..)` timeout). Actor timers all use the
tokio clock so paused-time tests advance deterministically; std
`Instant` appears only inside `natpmp::EpochTracker` as its own
baseline and is never mixed in.

## nat/natpmp.rs

NAT-PMP client (SPEC §6.8). All protocol facts are quoted from RFC 6886
clauses (aria2 has no NAT-PMP implementation, so there is no upstream
code reference); no constant is written from memory — every byte layout
and deadline carries a section number.

Packet facts (RFC 6886):

- Transport: requests go to UDP port 5351 of the default gateway (§3.1
  "a NAT-PMP client sends its request packet to port 5351 of its
  configured gateway address"). Opcodes 0-127 are client requests,
  128-255 the corresponding server responses (§2).
- External address request (§3.2): 2 bytes `[Vers=0, OP=0]`; the reply
  is 12 bytes `[Vers=0, OP=128, ResultCode u16be, SSSoE u32be,
  ExternalIPv4 4B]`. When result != 0 the address field is "undefined
  (the sender must zero it, the receiver must ignore it)".
- Map request (§3.3): 12 bytes `[Vers=0, OP=1|2, Reserved u16,
  InternalPort u16be, SuggestedExternalPort u16be, Lifetime u32be]`;
  opcode 1 = Map UDP, 2 = Map TCP; Reserved "MUST be set to zero on
  transmission and MUST be ignored on reception". The reply is 16 bytes
  `[Vers=0, OP=128+x, ResultCode u16be, SSSoE u32be, InternalPort u16be,
  MappedExternalPort u16be, Lifetime u32be]` and "'x' in the OP field
  MUST match what the client requested".
- Retransmission (§3.1): wait 250ms after the first try, then double
  each time (250ms -> 500ms -> ... -> 64s); "after sending its ninth
  attempt (and then waiting for 64 seconds)" — 9 sends total. ICMP Port
  Unreachable may give up immediately (an OS-level send/recv error here,
  folded into `NatPmpError::Io`).
- Result codes (§3.5): 0 Success / 1 Unsupported Version / 2 Not
  Authorized / 3 Network Failure / 4 Out of resources / 5 Unsupported
  opcode; "Undefined results codes MUST be treated as fatal errors of
  the request" (the decode layer stays neutral — any result must
  decode; the semantic layer decides).
- Unsupported-version response (§3.5): 8 bytes
  `[0, 0, ResultCode=1, SSSoE]`.
- Delete mapping (§3.4): a map request carrying Lifetime=0 and
  SuggestedExternalPort=0 ("The Suggested External Port MUST be set to
  zero by the client"); success = result 0 + the requested internal port
  + external port 0 + lifetime 0; deleting a nonexistent mapping MUST
  also be answered as success.
- Epoch (§3.6): every gateway packet carries Seconds-Since-Start-of-
  Epoch; the client's conservative estimate = the last packet's SSSoE +
  7/8 of the local-clock elapsed time; a new packet more than 2 seconds
  below the estimate means gateway reboot/state loss — "MUST immediately
  renew all its active port mapping leases" (§3.7: delay a uniform-
  random 0-5s first, then recreate serially).
- Renewal (§3.3 final paragraph): "The client SHOULD begin trying to
  renew the mapping halfway to expiry time"; the renewal packet is the
  original request format but with SuggestedExternalPort set to the
  gateway-assigned port; the gateway "MAY reduce the lifetime".

Divergences from the RFC (SPEC-established local policy):

- Requested lifetime is 3600s; the RFC 6886 §3.3 RECOMMENDED 7200s is
  intentionally not used (SPEC §6.8 sets the 60min renewal cadence, see
  `renew_delay`).
- Renewal cadence is 60min per SPEC §6.8; RFC §3.3 halfway (30min for a
  3600s lease) is not used. A 60min renewal lands exactly on the
  nominal expiry point, but the renewal request is itself a new map
  request (§3.3 packets are idempotent and self-describing), so the
  worst case is a sub-second window. When the gateway reduces the
  lifetime (granted < 60min), the code falls back to halfway (§3.3
  SHOULD) to avoid renewing an already-expired mapping.

## nat/tests.rs

NAT test suite layout:

- Packet vectors: 13 NAT-PMP codec vectors, each annotated with its
  RFC 6886 section.
- Table-driven: retransmission schedule (§3.1), renewal delay
  (SPEC §6.8 + RFC §3.3), round backoff (local policy), epoch
  regression (§3.6).
- Mock four-path integration over in-process loopback (no real
  network): map / renew / conflict (occupied port) / device-offline
  degradation, exercised over both NAT-PMP (UDP packets) and IGD (local
  HTTP/XML).
- Out of scope: real-router interop (SSDP multicast discovery, gateway
  announcement listening) — environment-dependent, not a milestone
  gate.

Timing: mocks use real loopback I/O (sub-millisecond RTT) with 30-50ms
timer windows (~100x margin); paused virtual clocks are not used
because auto-advance would skip timer windows before real I/O completes
and is unreliable alongside sockets. Renewal/backoff waits total ~3s of
real time.

Robustness negatives ride on the mock IGD attack branches (default
empty = stock behavior): a slow gateway is abandoned within the request
timeout (`igd::HTTP_REQUEST_TIMEOUT` = 10s, 300ms injected in tests);
body bombs are rejected by the Content-Length precheck and, when no CL
header is present, by the `http_body_util::Limited` streaming fallback;
2000-layer deep nesting is rejected by the depth precheck (quote-aware,
so fake closes inside attributes cannot deflate the count) without
aborting the process; attacker-controlled error strings are clipped in
logs while error-code semantics (upnp_code) survive; SSDP Location host
validation accepts RFC 1918 private and RFC 3927 link-local literals
and rejects loopback/public/domain/v6/unspecified/multicast/CGNAT
hosts (the host-side equivalent of libtorrent `upnp_ignore_nonrouters`,
upnp.cpp); the SSDP stream consumes single errors without ending the
discovery round.

## utp/conn.rs

Protocol facts, quoted section by section from BEP-29, plus the
handshake seq_nr decision record for the connection driver
(`crates/taiji-io/src/utp/conn.rs`).

### BEP-29 facts realized here

- Connection setup (§"connection setup"): initiator
  `c.state=CS_SYN_SENT; c.seq_nr=1; c.conn_id_recv=rand();
  c.conn_id_send=c.conn_id_recv+1`, the SYN carries
  `conn_id=c.rcv_conn_id`; acceptor
  `receive_conn_id=pkt.conn_id+1; send_conn_id=pkt.conn_id;
  seq_nr=rand(); ack_nr=pkt.seq_nr; state=CS_SYN_RECV`, answers
  ST_STATE (annotated `seq_nr=c.seq_nr`, not incremented, and
  `ack_nr=c.ack_nr`); initiator on ST_STATE: `state=CS_CONNECTED;
  c.ack_nr=pkt.seq_nr-1`.
- Sending rule (§"overview", verbatim): "A socket may only send a
  packet if cur_window + packet_size is less than or equal to
  min(max_window, wnd_size)."
- Sequence numbers (§"overview"/§"seq_nr"): counted per packet, not
  per byte; payload-less packets (ST_STATE) do not increase seq_nr
  (§"type" ST_STATE).
- Packet loss (§"packet loss"): >=3 packets selective-acked past the
  oldest unacked => lost; 3 duplicate acks => ack_nr+1 lost; every
  sacked packet counts once toward duplicate acks; "When a packet is
  lost, the max_window is multiplied by 0.5".
- Timeouts (§"timeouts"): every send/receive resets the timeout
  counter; on firing, "set its packet_size and max_window to the
  smallest packet size (150 bytes)"; consecutive timeouts double;
  rtt/rtt_var update only for packets sent exactly once.
- Selective ACK (§"Selective ACK"): sent only on a skip; the first
  bit = ack_nr+2.
- Unexpected FIN/RESET/SYN (§"type"/§"connection setup"): ST_FIN
  records eof_pkt and packets after it may still arrive; ST_STATE is
  "only an ACK"; ST_SYN on an existing connection "will be unexpected
  in the existing stream, and ignored".
- LEDBAT initial window = 2xMSS per RFC 6817 §2.5: "INIT_CWND and
  MIN_CWND SHOULD both be 2." (MSS = this implementation's packet
  size cap).
- Implementation-local parameters (no BEP-29/RFC source; each is
  marked "implementation-local" in [`crate::utp::UtpConfig`]): the
  scan-round period, the consecutive-timeout round cap, the reorder
  buffer cap, the packet size cap, and the give-up idle threshold.

### Handshake seq_nr decision (frozen-surface change rationale)

The acceptor's SYN-ACK (ST_STATE) does not consume a sequence
number: after sending it, seq_nr is not incremented and the local
first ST_DATA reuses the SYN-ACK's seq; the initiator completes the
connection with the ack baseline `SYN-ACK.seq_nr - 1`. Triple
evidence:

1. BEP-29 §"type" ST_STATE (the normative sentence): "Packets that
   don't include any payload do not increase the seq_nr." The
   §"connection setup" figure's `seq_nr=c.seq_nr++` annotation
   conflicts with it; the normative sentence plus the reference
   implementations decide (BEP-29 is self-inconsistent here; the
   implementations align with each other, not with the figure).
2. Reference implementation libutp (uTorrent, utp_internal.cpp):
   `UTPSocket::send_ack` assigns `pfa.pf.seq_nr = seq_nr` directly
   (no increment => the first ST_DATA reuses the same seq);
   `UTP_ProcessIncoming`'s CS_SYN_SENT branch:
   `conn->ack_nr = (pk_seq_nr - 1) & SEQ_NR_MASK`.
3. Peer librqbit-utp 0.7.0 (the interop matrix's µTP-format peer,
   stream_dispatch.rs): `StreamArgs::new_incoming` (the acceptor's
   first DATA = the SYN-ACK's seq), `new_outgoing` (initiator
   `last_consumed_remote_seq_nr = remote_ack.seq_nr - 1`), and the
   SynAckSent guard (a first packet with `ack_nr != seq_nr-1` is
   dropped => SYN-ACK retransmits until
   `MaxSynAckRetransmissionsReached`).

Both interop failure directions map to this defect one-to-one: our
outbound dial (direction A) trips the rqbit guard, which drops the
third-leg ack/data; a rqbit inbound dial (direction B) puts our
first ST_DATA at R+1 instead of R and rqbit's assembler stalls
out-of-order forever. Two symmetric implementations of the same
defect interoperate by accident; only cross-implementation interop
exposes it.

## mse.rs

Upstream anchor mapping for the MSE/PE handshake
(`crates/taiji-io/src/mse.rs`); all constants and flows cross-checked
against aria2 (`aria2/src/`):

- Group: 768-bit prime + generator 2 (`MSEHandshake.cc`); private
  key 160 bit (`MSEHandshake.cc dh_->init(..., GENERATOR, 160)`);
  public key / shared secret encoded big-endian fixed-width 96B
  (`MSEHandshake.h KEY_LENGTH=(768+7)/8`; the left zero-padding
  matches `LibgmpDHKeyExchange.cc getPublicKey/computeSecret`'s
  memset+offset).
- Key derivation (`MSEHandshake.cc initCipher`): the local direction
  is `SHA1(("keyA"|"keyB") || S || infohash)`, prefixes swapped for
  the peer direction; the two directions are independent ARC4
  instances, each dropping the first 1024B of keystream; the
  initiator's VC probe marker = the first 8B of the peer-direction
  keystream XOR the all-zero VC.
- Hashes (`MSEHandshake.cc`): req1 = SHA1("req1"||S); req2/req3 =
  SHA1("req2"||infohash) XOR SHA1("req3"||S).
- Wire format: VC = 8B of zeros; crypto_provide/select = 4B
  big-endian bitmaps with CRYPTO_PLAIN_TEXT=0x01 / CRYPTO_ARC4=0x02
  (`MSEHandshake.h`); pad lengths are 2B big-endian and <= 512
  (`MAX_PAD_LENGTH`, `verifyPadLength`); step2 layout =
  req1||req23||[VC+provide+padC+len(IA)] (initiator) /
  [VC+select+padD] (receiver); the IA length cap = the 68B BT
  handshake (vs `BtHandshakeMessage.cc MESSAGE_LENGTH=68`). step2
  pad content is always zeros; the pubkey-attached pad content is
  random (`generateNonce`).
- Sync windows (`MSEHandshake.cc`): the initiator's VC-marker search
  window is 616B, the receiver's req1-marker search window 628B.
- Sniffing (`identifyHandshakeType`): first byte 0x13 + "BitTorrent
  protocol" => legacy, otherwise encrypted; the [`identify`] pure
  function receives the legacy prefix from the caller (io stays
  protocol-agnostic).
- Option semantics: provide excludes plain under require-crypto or
  min-level=arc4 (`MSEHandshake.cc`); the receiver picks plain only
  if provided and allowed, the initiator reads the select with the
  ARC4 bit taking precedence; no agreed crypto => disconnect.

Deliberate divergence (an upstream defect not copied): the DH modpow
semantics follow aria2's GMP backend
(`LibgmpDHKeyExchange.cc generatePublicKey/computeSecret`, i.e. real
g^x mod p). aria2's pure-software fallback `InternalDHKeyExchange.cc`
writes `mul_mod(...)` (bignum multiplication, not modular
exponentiation) — a known defect of builds without a crypto library
that cannot interoperate with real DH peers (libtorrent /
qBittorrent / mainstream aria2 builds); intentionally not copied.

Test vectors (`mse/tests.rs`): ARC4 uses the official IETF RFC 6229
§2 KATs (including offset 1024, directly anchoring the "drop 1024B"
semantics); the DH/hash/full-step2 vectors are golden vectors
produced by the independent second implementation in
`scripts/gen_mse_vectors.py` (Python hashlib SHA-1 + hand-written
RC4, formulas cross-checked against `MSEHandshake.cc`) with a fixed
private key and zero pads, stored in
`tests/fixtures/mse_vectors.json`.

## metrics.rs

Histogram shape contract (mirrors the core rpc latency histogram):
non-cumulative bucket storage, the rendering face converts to the
cumulative form and derives the +Inf bucket, sum accumulates in
integer microseconds, and samples beyond every bucket land only in
count/sum. Injection seam: the registry is constructible, production
binds the OnceLock process default, tests inject independent
registries; no metric without a feed point; snapshots are
non-consistent reads of many atomics.

Bucket tables are pinned to consumer thresholds: the DNS table tops
out at the `crate::dns::DNS_TIMEOUT` backstop; the HTTP connection
table straddles the 300ms happy-eyeballs interleave point with the
0.25/0.5 buckets; the slow-start table spans the AIMD ramp domain
(500ms..120s); the disk table spans local millisecond operations to
30s network-drive fsync tails (the observability face of the Motrix
PR #2132 SMB lesson); the persistence table covers the single-row
sqlite commit domain. `conn_establish_seconds` is a DNS+TCP+TLS
combined timing (the connector tower layer sees only new
connections), so connect+TLS is recovered analysis-side as the
combined mean minus the `dns_resolve_seconds` mean.

## udp_demux.rs

Upstream anchor mapping for the dispatch contract
(`crates/taiji-io/src/udp_demux.rs`):

- Rule 2 magic: the fixed connection_id of the BEP-15 connect
  request, matched by aria2 `UDPTrackerClient.h
  UDPT_INITIAL_CONNECTION_ID` (`0x41727101980`).
- Rule 3 action table: aria2 `UDPTrackerRequest.h
  UDPT_ACT_{CONNECT=0,ANNOUNCE=1,SCRAPE=2,ERROR=3}`;
  `UDPTrackerClient.cc receiveReply` dispatches by action. The 16B
  minimum reply length (connect reply = action+txid+connection_id)
  hardens against 4-byte garbage flooding the tracker channel; the
  cost — short truncated/empty error replies classify as Drop — is
  bounded and integrity stays with the consumer.
- Rule 4 (µTP v1 nibbles): aria2 has no µTP implementation, so the
  branch follows the BEP-29 header-format text directly.
- Port scan: aria2 `PeerListenCommand.cc bindPort` shuffles and
  takes the first bindable; the default range "6881-6999" comes
  from `OptionHandlerFactory.cc` (SPEC §11 "random start"). The
  random start + ring walk here covers the interval equivalently
  without the O(n) shuffle allocation.
- v6 bind: aria2 `SocketCore.cc` sets `IPV6_V6ONLY=1` on AF_INET6
  sockets before `::bind`; under the Linux ipv6(7) `bindv6only=0`
  default a bare [::] is a dual-stack socket that cannot share a
  port with 0.0.0.0 (EADDRINUSE), so the v6 face could never bind.
  macOS/Windows default V6ONLY=1 and merely look fine.
- Batching: rebuilding the `select!` arm futures plus a ready-arm
  repoll per packet costs user-space time on the same order as the
  forwarding logic at real download packet rates; draining to
  WouldBlock within one readiness event converges the per-packet
  cost to one `try_recv_from` + classify + forward, and the batch
  cap is the fairness fuse keeping the other select arms scheduled.

## rate_limit.rs

- aria2 has no token-bucket limiter (no `SpeedLimiter` anywhere in its
  sources). Limits apply as static per-group quotas via `RequestGroupMan`
  (RequestGroupMan.cc) plus command-poll throttling; the token bucket with
  `await` on the read path is a deliberate improvement that produces the
  same back-pressure shape as removing the polling throttle (the peer
  window collapses while a permit is pending).
- `0 = unlimited` follows the aria2 option semantics; the unlimited path is
  a zero-overhead short-circuit at both bucket and stream level.
- Rate hot-update mirrors the aria2 RPC surface
  changeGlobalOption/changeOption -> setMaxDownloadSpeedLimit
  (RpcMethodImpl.cc): an atomic store plus waking waiters to re-estimate;
  it applies to in-flight streams immediately.

## utp.rs

- Module overview: packet codec / LEDBAT / conn driver / listener. aria2
  has no uTP implementation, so BEP-29 is the sole protocol reference;
  RFC 6817 (LEDBAT) and RFC 5681 (slow start/RTO) cover the congestion-
  control clauses.
- All channels are bounded (64 per connection inbound/outbound, app
  uplink/downlink, accept queue). A full inbound packet queue drops — UDP
  best-effort semantics backstopped by retransmission.
- Retransmission runs as a periodic scan with period clamp(RTT/2,
  retrans_scan_min, retrans_scan_max); the doubling of consecutive timeout
  rounds lives on the scan interval, not in the Rtt estimate.
- `MAX_INBOUND_PAYLOAD = 1452` and why the receive criterion is independent
  of the send chunking parameter: see utp/packet.rs below.

## utp/packet.rs

Protocol-fact source: BEP-29, quoted by section name (aria2 has no uTP
implementation, so BEP-29 is the sole reference).

BEP-29 "header format" (version 1 header, 20 bytes):

```text
0 4 8 16 24 32
+-------+-------+---------------+---------------+---------------+
| type  | ver   | extension     | connection_id |
+-------+-------+---------------+---------------+---------------+
| timestamp_microseconds                                        |
+---------------+---------------+---------------+---------------+
| timestamp_difference_microseconds                             |
+---------------+---------------+---------------+---------------+
| wnd_size                                                      |
+---------------+---------------+---------------+---------------+
| seq_nr                | ack_nr                                |
+---------------+---------------+---------------+---------------+
```

- Byte order: BEP-29 "header format", "All fields are in network byte
  order (big endian)."
- version: BEP-29 "version", "The current version is 1."
- type: BEP-29 "type" defines ST_DATA=0 / ST_FIN=1 / ST_STATE=2 /
  ST_RESET=3 / ST_SYN=4. Type occupies the high nibble and version the low
  nibble of byte 0 — the current diagram after the BEP-29 Post-History
  entry "Fixed typo in uTP header (type and version were swapped)".
- extension: BEP-29 "extension", "The type of the first extension in a
  linked list of extension headers. 0 means no extension." Each chain
  entry carries two bytes `{next_extension, len}` right after the header;
  "0 terminates the list"; unknown extensions "can be skipped by simply
  advancing len bytes".
- Selective ACK: BEP-29 "Selective ACK" — the mask is >= 32 bits and a
  multiple of 32 bits; len is in bytes, >= 4 and a multiple of 4; "The
  first bit in the mask therefore represents ack_nr + 2."; "The bitmask
  has reverse byte order. The least significant bit in the byte represents
  ack_nr + 2, the most significant bit in the byte represents ack_nr + 2 +
  7." (within a byte LSB->MSB maps ack_nr+2 -> ack_nr+9, the next byte
  continues +8). Extension type value: BEP-29 only names it ("There is
  currently one extension: Selective acks") without a number; the value 1
  is the de-facto libutp SELECTIVE_ACK=1 (interop-behavior evidence).
- MAX_INBOUND_PAYLOAD = 1452 = 1500 (ethernet MTU) - 20 (IPv4) - 8 (UDP) -
  20 (uTP v1 header). Reference libutp `get_packet_size() = mtu - 20`
  (utp_internal.cpp): a conservative initial full size of 1435, then 1452
  after ethernet path MTU discovery. libtorrent / Transmission / uTorrent
  all send full-size ST_DATA payloads > 1400, so rejecting inbound data by
  the send parameter would skip the ack, trap the peer in a retransmit
  loop, and stall the connection until the idle give-up — hence the
  receive criterion is independent of `max_packet_payload`.

## utp/ledbat.rs

Protocol-fact sources, quoted by section: BEP-29 "congestion control" /
"overview" / "packet loss" / "timeouts"; RFC 6817 for LEDBAT structure.

- Delay measurement (BEP-29 "congestion control", "overview"): each socket
  keeps reply.micro = now - the peer's timestamp_microseconds, echoed back
  in timestamp_difference_microseconds on every packet. base_delay: BEP-29,
  "Each socket keeps a sliding minimum of the lowest value for the last two
  minutes." — minute-bucketed minima, 2 buckets. Compare RFC 6817 §3.1.1
  BASE_HISTORY (RFC 6817 §2.7 suggests 10 minutes; BEP-29 narrows to 2 and
  BEP-29 wins). our_delay = sample - base_delay (BEP-29: "When subtracting
  the base_delay from the timestamp difference in each packet you get a
  measurement of the current buffering delay").
- Gain formula (BEP-29 "congestion control", line by line):

```text
delay_factor = off_target / CCONTROL_TARGET;
window_factor = outstanding_packet / max_window;
scaled_gain = MAX_CWND_INCREASE_PACKETS_PER_RTT * delay_factor * window_factor;
max_window += scaled_gain;
```

  CCONTROL_TARGET: "Currently the delay target is set to 100 ms" ->
  CCONTROL_TARGET_US = 100_000 us. off_target = CCONTROL_TARGET -
  our_delay, so our_delay > target shrinks the window. BEP-29's closing
  prose sentence ("This will make the window smaller if off_target is
  greater than 0 and grow the window if off target is less than 0.")
  reverses its own formula's sign — an erratum; the formula direction wins,
  matching libtorrent/libutp behavior. MAX_CWND_INCREASE_PACKETS_PER_RTT
  has no BEP-29 value — a local tuning knob (LedbatConfig). Floor: "If
  max_window becomes less than 0, it is set to 0."
- Slow start x2/RTT: BEP-29's current text has no slow-start section; RFC
  6817 §2.2: "a slow start mechanism can be used as specified in
  [RFC5681]"; RFC 5681 §3.1: "During slow start, a TCP increments cwnd by
  at most SMSS bytes for each ACK received that cumulatively acknowledges
  new data." — about cwnd/MSS acks per RTT, each +MSS => doubling per RTT.
  Initial window 2xMSS: RFC 6817 §2.5 "INIT_CWND and MIN_CWND SHOULD both
  be 2."
- Loss: BEP-29 "packet loss", "When a packet is lost, the max_window is
  multiplied by 0.5 to mimic TCP." (Post-History: "update the loss factor
  from 0.78 to 0.5" — the current value is 0.5).
- Timeout: BEP-29 "timeouts", "It will set its packet_size and max_window
  to the smallest packet size (150 bytes)." -> MIN_PACKET_SIZE.
- Rtt estimator: same-section formulas (rtt_var += (|delta| - rtt_var)/4;
  rtt += (packet_rtt - rtt)/8; timeout = max(rtt + rtt_var*4, 500); "The
  initial timeout is set to 1000 milliseconds"; "The rtt and rtt_var is
  only updated for packets that were sent only once."). The section's
  consecutive-timeout doubling applies to the driver's retransmit
  scan-round interval, not this estimate: folding doubling into the
  estimate makes it unrecoverable while cumulative acks are blocked by a
  gap, stalling the connection for minutes.
