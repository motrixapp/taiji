# Multi-interface listen faces (`taiji.listen-interfaces`)

Phase 2 of the interface-effectiveness work (phase 1 = the `--interface`
egress bind; phase 3 = `can_route` dispatch + ingress verification —
now landed, see the phase-3 section). This note is the design record:
the option grammar, the parse -> enumerate -> expand -> diff-rebuild
pipeline, the rider map (what moved to listen-socket lifetime, what
stayed global and why), the `--interface` combination matrix, and the
phase-3 per-destination dispatch + ingress verification semantics.

Upstream anchors (read-only oracle `third_party/libtorrent`):

- Grammar: `settings_pack::listen_interfaces`, parsed by
  `src/string_util.cpp:180-250` (per-entry invalid collection — never
  wholesale failure).
- Enumerate + expand + diff: `src/session_impl.cpp:2090-2230`
  (`enum_net_interfaces` -> `interface_to_endpoints` ->
  `expand_unspecified_address` -> `partition_listen_sockets`: close only
  the removed, open only the new, untouched sockets keep their riders).
- Listen-socket discipline: `include/libtorrent/aux_/session_impl.hpp:
  134-239` (flags, OS netmask, per-transport NAT port mappings
  NAT-PMP-before-UPnP, monotonic never-reused id).
- Platform degradation: Android netlink-unavailable keeps the wildcard
  socket (`src/session_impl.cpp:2178-2190`) — the precedent for the
  enumeration-failure fallback here.
- Routing (phase 3): `can_route` `src/session_impl.cpp:340-355`; the
  uTP socket choice ("almost, but not quite, like can_route()") in
  `bind_outgoing_socket` `src/session_impl.cpp:5408-5437`; netmask
  attachment `expand_devices` `src/session_impl.cpp:311-338`;
  `match_addr_mask` `src/enum_net.cpp:582-604`; ingress verification
  `verify_bound_address` `src/session_impl.cpp:5483-5512` with the
  accept-path rejection (`peer_blocked_alert::invalid_local_interface`)
  at `src/session_impl.cpp:3146-3190`.

## Option surface

- CLI: `--taiji-listen-interfaces "device-or-IP:port,device-or-IP:port"`
  (conf key `taiji-listen-interfaces` mirrors the raw value). The
  `taiji.` prefix marks the extension namespace (no aria2 counterpart;
  aria2 has no listen-interfaces option at all — the capability shape is
  libtorrent's).
- Grammar: comma list of `device-or-IP:port`; IPv6 literals require the
  `[v6]:port` bracket form (the first-colon split rule; upstream the
  same). Port domain `0..=65535` (0 = OS-assigned per face). **No
  suffix flags** (`s`/`l` upstream): trailing characters after the port
  digits make the entry invalid — a stated minimal-surface divergence
  (there is no SSL or local-network face to drive here). No quoted
  device names.
- Invalid entries warn individually and are skipped — never a startup
  refusal (upstream's per-entry `err` list discipline).
- Default unset = the exact standing single-listen behavior (the
  wildcard v4 + `[::]` v6 dual-stack listener and the per-family UDP
  demux pair, zero change).
- Startup-only (the `--listen-port` rule): the RPC option surface has
  no key; runtime reconfiguration is not in the option face.

## Pipeline (engine crate, `taiji_engine::listen`)

1. **Parse** (`parse_listen_interfaces`) at the CLI single point
   (`listen_interfaces_from_cli`); the raw entry table travels through
   the session global (`GlobalOptions.listen_interfaces`) into
   `EngineConfig.listen_interfaces`. Device names stay unresolved until
   bind time (upstream resolves in `reopen_listen_sockets`).
2. **Enumerate** (`enumerate_interface_addrs`): getifaddrs via if-addrs
   (an existing workspace dependency; a local syscall, no network IO) —
   each row carries name, address, and the address's OS netmask (the
   phase-3 route context source). Failure, or an empty expansion,
   degrades to the standing single-wildcard listen with one warning
   (the platform capability fallback — a user who pinned addresses must
   not get a silent wildcard; only a *capability* failure falls back).
3. **Expand** (`expand_listen_interfaces`, pure, table-injected for
   tests): IP literals pass through; device names expand to one
   endpoint per interface address (`interface_to_endpoints` shape);
   wildcards expand to one endpoint per same-family interface address
   (`expand_unspecified_address` shape, the BEP 32/45 multi-homed rule),
   deduplicated against explicit `(addr, port)` pairs; literal
   endpoints adopt the owning interface's netmask + device name
   (`expand_devices`: the first row whose subnet contains the literal;
   an unclaimed literal keeps the family `/0` — match-everything — and
   the gateway classification); expanded rows classify local-network on
   the loopback/link-local address subset; the egress bind family
   narrows the set; final dedup by `(addr, port)`, first-wins.
   Simplifications vs upstream (declared, see residuals): the
   `preferred`/up-state interface filters and the route-table-dependent
   arm of the local-network classification are not implemented (every
   enumerated address counts; loopback/link-local classify local).
4. **Bind** (`bind_listen_faces`): one TCP listener + one UDP demux per
   endpoint. Exact ports — no per-face port walk (upstream retries
   higher ports on bind failure; here a failed bind degrades that
   face's transport with a warning instead of silently moving the port,
   because the single announce-port seam makes divergent per-face ports
   counterproductive; a stated divergence). TCP binds first so a spec
   port of 0 propagates the OS-assigned port to the demux (the
   unified-port rule per face). A face survives with either transport;
   both failing drops the face. v6 sockets set `IPV6_V6ONLY` before
   bind (the uniform aria2/libtorrent discipline; wildcards never reach
   this path — expansion replaced them with concrete addresses).
5. **Diff rebuild** (`partition_listen_faces`): keyed by
   `(address, port)` — kept faces stay exactly as-is with their riders,
   removed faces close, unmatched endpoints open fresh. Upstream also
   matches device/flags; the device name is informational here (the
   same bind is the same face). **Trigger today: engine assembly only**
   (the existing set is empty at start, so the partition degenerates to
   open-everything); the function is the seam a future runtime-rebuild
   trigger (an `EngineCommand`, network-change notification, or the
   incremental-rebuild non-goal being revisited) plugs into.

## ID discipline

`ListenFaceId` comes from a process-wide monotonic counter, never
reused once its face closes (the `listen_socket_t::id` rule,
`session_impl.hpp:168-170`). A rebuilt face for the same endpoint gets
a fresh, strictly larger id — long-lived referents (observation
surfaces, the phase-3 route context) cannot alias an unrelated new
face. Observable in the diff unit tests.

## Rider map (phase 2)

| Rider | Before (phase 1) | After (phase 2 + phase 3) |
|---|---|---|
| TCP listeners | one wildcard v4 + best-effort `[::]` v6, single port, one merge pair | **per face** (one listener + accept task per endpoint; all feed the single main-loop accept channel) |
| UDP demux (uTP/DHT/UDP-tracker shared socket) | one per family on the unified port (`spawn_udp_face`) | **per face**; each family's first-bound face is the *primary* |
| uTP listener | one per family face | **per face** (inbound accepts on every face merge into one channel) |
| uTP dial service | per family | **per face dial route** (phase 3): every uTP-serving face carries a delegated-dial pump; the face for one destination is picked by route context (`pick_route_face`) — the netmask-matching face of the destination family, the family primary as the fallback |
| DHT engine | one per family, riding the family's single face | one per family, riding the family's **primary** face; **secondary faces' DHT inbound merges into the family engine** through the inbound gate's engine slot (same warm/disable semantics as the gate's own pump); DHT egress = the primary face |
| UDP tracker egress routing | per family (the family's only face) | **per destination** (phase 3): each outbound tracker packet picks its face through the same `pick_route_face` route context (netmask match, primary fallback) |
| UDP tracker inbound | per family dispatcher | **per face** dispatcher (transaction-id self-filtering absorbs multi-face replies) |
| Ingress verification | — (none) | **phase 3**: with `--interface` armed, the TCP accept paths and the per-face uTP inbound pumps verify the connection's local address against the egress address (`verify_bound_address` shape); rejections drop at the door and count `taiji_peer_blocked_ingress_total` |
| NAT mapping (NAT-PMP/UPnP) | session-global actor maps the single announce port (TCP+UDP) | **unchanged** — global-with-reasons (below) |
| LSD (BEP14) | session-level multicast socket (default off), announces `--listen-port` | **unchanged** — architecturally global (below) |

Declared globals (not silent):

- **NAT**: the io::nat actor's desired-mapping state is one mapping per
  protocol (`HashMap<Protocol, WantedMapping>`, `taiji-io/src/nat.rs`),
  and every announce surface (tracker actor's spawn-time constant, the
  DHT family ports, the LSD port) consumes a single port. Mapping N
  ports would have no consumer and needs an io::nat multi-port
  extension plus per-socket announce seams — the phase-2 cut maps the
  single announce port (the first v4 face's port; faces sharing that
  port are covered by the mapping, distinct-port faces are unmapped).
  Phase-2 residual.
- **LSD**: BEP14 is link-local multicast on the default route
  (239.192.152.143:6771, TTL 1) — a per-listen-socket multicast face
  would announce N times into the same group with no discovery gain.
  Stays the session-level socket; with `taiji.listen-interfaces` set it
  announces the `--listen-port` value (the single-announce-port seam).
- **DHT per-socket nodes** (BEP 32/45's strict reading: one DHT node
  state per interface): one engine per family riding the primary face
  with secondary-face inbound merging is the standing cut; per-socket
  routing state would multiply `dht_state` persistence rows and
  announce fan-out. Still residual after phase 3 (the per-face route
  context exists now; the DHT-side split is its own work, if ever).

## Phase 3: per-destination dispatch (`can_route`) + ingress verification

### Route context on every face

Every expanded endpoint carries the OS netmask of its owning interface
and the local-network classification (`ListenEndpoint::netmask` /
`.local_network`); the default-path faces (wildcard v4 / probed-GUA or
`[::]` v6) carry the bind address with a `/0` netmask and the gateway
classification — a `/0` matches every same-family destination, so the
default path routes exactly as it did before (one face per family).

### `can_route` (the boolean mirror, `listen::can_route`)

| arm | verdict |
|---|---|
| family mismatch | false |
| v6 and scope ids differ | false — taiji listen endpoints are scope-less `std` addresses (local scope always 0), so a scoped destination (a `SocketAddrV6` with `scope_id != 0`) never matches; the grammar cannot express scoped binds |
| exact address equality | true |
| wildcard local address | true (the default-path faces) |
| netmask match (`match_addr_mask`) | true |
| otherwise | `!local_network` — a gateway-classified face routes the rest (loopback destinations are always routable from gateway faces via this arm); a local-network face (loopback/link-local expanded address) refuses off-subnet destinations |

The proxy arm of the upstream `can_route` has no taiji counterpart
(no proxy faces exist).

### The dispatch table (`listen::pick_route_face`)

Both UDP egress surfaces — the uTP dial service
(`UtpDial::connect_bounded`) and the tracker-UDP outbound router —
pick a face per destination through the same function (the uTP
socket-choice arm of upstream `bind_outgoing_socket`):

1. same-family faces only (a family with no face = the dial/send
   fails, the existing family-unavailable class);
2. the **last** netmask-matching face wins (the upstream loop
   overwrites its match per hit — with overlapping subnets the most
   specific-late-listed face serves);
3. no netmask match → the first **non-local** face of the family
   (the deterministic stand-in for the upstream random pick among
   gateway faces — same candidate set, minus the randomness, so the
   dispatch stays observable/testable);
4. no gateway candidate → the family primary (an all-loopback family
   keeps the phase-2 primary pick — the single-face
   exact-degeneration rule outranks the upstream's hard error there).

**Degeneration guarantee**: with one face per family (default unset,
egress-bound, or a single listen entry — every pre-phase-3
configuration), each pick IS the family primary — behavior identical
to phase 2. TCP egress needs no dispatch: phase 1's `--interface`
already binds every outbound peer TCP dial (`dial_tcp`), the two faces
of egress selection being "bind the socket" (TCP, per-connection) vs
"pick the bound socket" (UDP, per-destination over the face set).

### Ingress verification (`listen::IngressVerify`)

When `--interface` is set (an address at the engine boundary — the CLI
resolves device names first), an inbound peer connection's local
address must equal the egress address (the IP-literal arm of upstream
`verify_bound_address`; the device-name arm is absorbed by the CLI
parse). Verification points: the multi-listen TCP face accept tasks
(constant verdict per face), the default-path dual-stack accept merge
(per-connection `local_addr` — the listeners are wildcard), and the
per-face uTP inbound pumps (constant verdict per face, the demux bind
address). Rejected connections drop at the door (stream drop = close)
and count `taiji_peer_blocked_ingress_total` — the upstream
`invalid_local_interface` shape, counter-observed instead of alerted
(no alert storms, no per-packet logs). `--interface` unset = zero
verification, zero counting (status quo). DHT and UDP-tracker inbound
packets are not connections — no verification there (upstream
likewise verifies peer connections only).

## Combination matrix (`--interface` x `--taiji-listen-interfaces`)

The egress bind family narrows the expanded endpoint set — an
egress-bound engine does not listen on the other family (the same leak
rationale as the phase-1 UDP-face plan: a wildcard face of the other
family would accept traffic that cannot egress back on the chosen
interface).

| `--interface` | `--taiji-listen-interfaces` | TCP listen | UDP faces |
|---|---|---|---|
| unset | unset | wildcard v4 + `[::]` v6, one port (status quo) | v4 wildcard + v6 probed-GUA/`[::]` (status quo) |
| unset | set | one listener per expanded face | one demux per face |
| set (v4 or v6) | unset | status quo listeners, **inbound verified** (local address must equal the egress address; the other family's inbound is rejected+counted) | the egress family's face only, bound to the egress address (phase 1) |
| set (v4 or v6) | set | expanded faces filtered to the egress family, inbound allowed only on faces whose local address equals the egress address (others rejected+counted) | same-filtered faces, per-destination dispatch (netmask match, primary fallback) |

Notes: with both set, endpoints of the other family are dropped with a
warning naming the count; a same-family face whose address differs
from the egress address (e.g. `--interface 10.0.0.5` +
`0.0.0.0:6881` expanding to every v4 address) still listens but its
inbound is rejected+counted — source consistency over silent asymmetry
(the upstream `verify_bound_address` verdict).

## Announce-port seam

One port remains the announce convention (the tracker actor constant,
the NAT mapping, the DHT PORT payload): the first **v4** face's TCP
port (v4 = the NAT-mapped family), falling back to the first face of
either family, then UDP ports, then the `--listen-port` value. The v6
DHT announce uses the v6 primary face's own port (v6 has no NAT
semantics). Divergent-port multi-face configs are where this seam
shows; per-socket announce surfaces remain post-phase-3 residual
material (with NAT multi-port, see the residuals list).

## Tests

- Unit (`taiji_engine::listen`): parse grammar/invalid-entry tables,
  port domain; expansion against injected interface tables (device
  multi-address, wildcard per-interface, dedup, unknown-device and
  dead-wildcard warnings, egress narrowing, netmask/classification
  attachment — literal adoption, unclaimed-literal `/0`, loopback and
  link-local classification); `can_route` truth table + the v6 scope
  gate; `match_addr_mask` table; `pick_route_face` (last-match-wins,
  gateway fallback skipping a local primary, all-local primary
  fallback, single-face degeneration, absent family); the
  `IngressAllowlist` literal-equality table; diff semantics (kept ids
  stable across overlapping reconfigures, removed-only-gone,
  new-only-added, identical-set no-op); id monotonicity/never-reuse.
- Unit (`taiji_engine::transit`): the two-face uTP dial rig — a
  destination inside the secondary face's subnet dials through that
  face's channel, off-subnet falls back to the primary, a family with
  no route returns None fast.
- Unit (`taiji_engine::run::assemble`): the two-face tracker-UDP rig
  (real demux sockets on two 127/8 addresses) — a destination inside
  the secondary face's netmask egresses through that face's socket
  (observable as the UDP source address the receiver sees), the
  off-subnet destination through the family primary.
- Unit (`taiji_engine::run::assemble`): the uTP inbound-gate rig — an
  off-allowlist face-local address drops the inbound accept at the
  door and counts; the unarmed default admits.
- Engine config default: `engine_config` yields the empty table (the
  zero-change pin; the session-global default likewise).
- Integration (`taiji-core/tests/listen_interfaces.rs`): a real engine
  with two loopback listen faces (127.0.0.1 + [::1], same port; v6-less
  environments fall back to the 127.0.0.2 alias form, covering the
  same-family secondary-face path) serves an inbound BT handshake per
  face — each answered with the engine's handshake (info_hash echo);
  the ingress-verification engine (`--interface 127.0.0.1`, default
  dual-stack listeners) rejects the `[::1]` inbound at the door,
  counts exactly one rejection, and still serves the 127.0.0.1 arm.
- CLI: parse/projection tests (`listen_interfaces_project_to_session_global`)
  and the conf passthrough row (the key-surface lock test walks every
  key).

## Residuals

- **NAT multi-port** (phase 2): the io::nat actor maps the single
  announce port; distinct-port faces are unmapped (see the declared
  globals above).
- **Route-table-dependent classification** (phase 3): the
  `!is_global && has_any_internet_route && !has_internet_route(name)`
  arm of the upstream local-network classification needs route-table
  enumeration (netlink), which this build does not carry — only the
  loopback/link-local address subset classifies local. The
  `preferred`/up-state interface filters of `expand_unspecified_address`
  are likewise not implemented (every enumerated address counts).
- **Random gateway fallback**: the upstream uTP pick falls back to a
  random gateway face; `pick_route_face` is deterministic (first
  non-local face, then the family primary) — same candidate set,
  observable dispatch.
- **All-local family off-subnet dial**: upstream errors the uTP dial
  when no gateway face exists; here the family primary serves (the
  single-face exact-degeneration rule) — the SYN goes out from the
  loopback face exactly as it did before phase 3.
- **DHT per-socket routing state** (phase 2): unchanged residual (see
  the declared globals above).
- **v6 scoped binds**: the listen grammar cannot express
  `fe80::x%zone` binds (std `IpAddr` carries no scope); link-local v6
  faces bind unscoped and `can_route` refuses scoped destinations.
