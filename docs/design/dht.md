# DHT design notes (upstream anchor mapping)

Per-module upstream anchors and reference-source essays for the taiji-bt DHT.
Code headers in the source files keep only a mechanism summary and point here.

## message.rs (`crate::taiji_bt::dht::message`)

Sources: BEP5 (KRPC), BEP32, BEP42; fields cross-checked item by item against
aria2 commit `9e7273583f83e881e3ec067b523ba88724088d2f`.

### Wire format (BEP5 KRPC)

Three top-level dicts (all keys are bencode strings):

```text
query    d1:ad2:id20:<sender id>…1:q<method>1:t<tid>1:y1:qe
response d1:rd2:id20:<responder id>…e1:t<tid>1:y1:re
error    d1:eli<code>e<len>:<msg>e1:t<tid>1:y1:ee
extra    1:v<client version> (optional; aria2 DHTMessageFactoryImpl.cc)
```

Query a-dict fields (aria2 `getArgument()` per message class):

| method | fields | source |
|---|---|---|
| `ping` | id | `DHTPingMessage.cc` |
| `find_node` | id, target | `DHTFindNodeMessage.cc` |
| `get_peers` | id, info_hash | `DHTGetPeersMessage.cc` |
| `announce_peer` | id, [implied_port], info_hash, port, token | `DHTAnnouncePeerMessage.cc` |

Response r-dict fields (aria2 `getResponse()` per reply class):

| method | fields | source |
|---|---|---|
| `ping`/`announce_peer` | id | `DHTPingReplyMessage.cc`, `DHTAnnouncePeerReplyMessage.cc` |
| `find_node` | id, nodes/nodes6 (always written, may be empty) | `DHTFindNodeReplyMessage.cc` |
| `get_peers` | id, token, nodes?, values? (non-empty only) | `DHTGetPeersReplyMessage.cc` |

Top-level `ip` field (BEP42 "Bootstrapping"): the compact endpoint of the
requester as observed by the responder (big-endian address 4B/16B + big-endian
port 2B = 6B/18B, outside the r dict); see `ResponseMessage::requester_endpoint`.

### Validation strictness (aria2 `DHTMessageFactoryImpl.cc`)

- id/target/info_hash: bencode string of exactly 20 bytes (`validateID`);
- announce_peer `port`: integer with `0 < port < 65535` (`validatePort`;
  65535 is rejected too); `token`: string (length unchecked);
- unknown method names are rejected ("Unsupported message type");
- `t` (transaction id): string, length unbounded (locally generated ids are
  always 4B, `DHTConstants.h`);
- response bodies are sniffed by content (token → get_peers, nodes/nodes6 →
  find_node, otherwise id-only → ping); ping and announce_peer responses are
  byte-identical on the wire, so the transaction layer checks the body with
  `ResponseBody::as_kind` against the expected kind (aria2 dispatches on the
  message type recorded by its tracker, `DHTMessageTracker.cc`);
- `values` elements that are not strings or have the wrong length are skipped,
  matching aria2; hybrid 6/18B values lists must parse (BEP32 mandates it).

### The `values` key and BEP32 (IPv6)

get_peers responses carry `values` as a single key of single-family compact
units; there is no "values6" split key. BEP32 (bittorrent.org/beps/
bep_0032.html, "Changes to get_peers"):

- unit length follows the request's network layer: "a list of 6-octet strings
  if the request was sent over IPv4, and a list of 18-octet strings if the
  request was sent over IPv6";
- sending hybrid lists is forbidden: "implementations should not send such
  hybrid lists, and must not send hybrid lists in a reply to an IPv4 request
  that doesn't contain a "want" parameter" — the encoder reports
  `DhtError::MixedAddressFamilies` for mixed v4/v6 values; which family is
  sent is filtered by the engine per the request's network layer
  (engine/wire.rs `on_query`; libtorrent `src/kademlia/dht_storage.cpp`
  `requester.is_v4() ? peers4 : peers6`, single key);
- parsing hybrid lists is mandatory: "Implementations of this specification
  must be able to properly parse hybrid "values" lists -- lists containing
  an arbitrary mixture of 6-octet IPv4 values and 18-octet IPv6 values" —
  `parse_values` self-identifies 6/18B per element, so legacy peers that send
  mixed lists interoperate without regression.

### The `want` parameter and the nodes/nodes6 dual keys (BEP32 "DHT Size")

find_node/get_peers queries may carry an optional `want` (list of "n4"/"n6",
`WantFamilies`): ""n4": the node requests the presence of a "nodes" key",
""n6": ... a "nodes6" key". "For future extensibility, other strings may be
present in the list, and must be silently ignored on reception" — unknown
elements are silently ignored; a non-list key → MalformedField (known-field
types are strict, same policy as v/ip). Reply keys are decided by the
requester's want (engine/wire.rs filters the nodes families per request):
"A reply should include a "nodes" parameter if the request's "want" parameter
contained the string "n4", and should include a "nodes6" parameter if ...
contained the string "n6""; "In the absence of a "want" parameter, the reply
should include "nodes" if the request was sent over IPv4, and should include
"nodes6" if the request was sent over IPv6". Codec side: encoding splits by
family (`pack_nodes_split`; a mixed list becomes nodes + nodes6 dual keys — a
legal shape, not ambiguity); decoding merges both keys (v4 entries first, v6
entries after — canonical order) and no longer reports AmbiguousNodes (once
want is implemented, dual-key replies from peers are normal, and dropping the
whole frame would break interop).

Erratum (an earlier design text said "split into values6"): that key existed
for one day in a BEP32 draft; the Post-History explicitly removed it —
"15-Oct-2009: Promote same ID in IPv6 and IPv4 nodes. **Drop values6.**".
libtorrent has no "values6" anywhere in its tree (single key on both sides:
`get_peers.cpp` / `dht_storage.cpp`); aria2 is the same
(`DHTGetPeersReplyMessage.cc`). Following the authority order (BEP32 text >
libtorrent > aria2), this lands as a single key plus request-side family
filtering; a literal "values6" key would be read by no mainstream peer, which
would change "lose half of the v6 peers" into "lose all of them".

### Server error replies

BEP5 "Errors" duty: when a query cannot be processed, answer `y = "e"`,
`e = [code, msg]`. Code list: 201 Generic Error, 202 Server Error, 203
"Protocol Error, such as a malformed packet, invalid arguments, or bad token",
204 "Method Unknown". `incoming_error_reply` classifies malformed queries into
the 203/204 tiers (a reply is sent only when the tid can be echoed, and never
on non-query faces — anti-amplification; see the function docs). Engine wiring
and per-source rate limiting live in engine/wire.rs and engine/error_limit.rs.

### Intentional divergence

bencode uses strict canonical decoding (dict keys strictly ascending); aria2
does not check key order. Unknown fields are ignored (as in aria2); therefore
`encode(decode(x)) == x` does not hold (extra fields are projected away) and
the roundtrip assertion is `decode(encode(m)) == m`. See the divergence list
in the `crate::dht` module docs.

## mod.rs (`crate::taiji_bt::dht`)

Protocol facts (constant anchors, aria2):

| Constant | Value | Source |
|---|---|---|
| Node ID length | 20B | aria2 `src/DHTConstants.h` |
| Transaction ID length | 4B | aria2 `src/DHTConstants.h` |
| Transaction timeout | 10s | aria2 `src/DHTConstants.h` (`DHT_MESSAGE_TIMEOUT`) |
| Node contact interval (questionable threshold) | 15min | aria2 `src/DHTConstants.h` |
| Bucket refresh interval | 15min | aria2 `src/DHTConstants.h` |
| Token secret rotation | 10min | aria2 `src/DHTConstants.h` |
| K (bucket capacity) | 8 | aria2 `src/DHTBucket.h` |
| Replacement cache capacity | 2 | aria2 `src/DHTBucket.h` |
| Bad-node score threshold | 5 | aria2 `src/DHTNode.cc` (`BAD_CONDITION`) |
| Compact peer length v4/v6 | 6B/18B | aria2 `src/BtConstants.h` |
| Token secret length | 4B | aria2 `src/DHTTokenTracker.h` |

Message formats are field-checked against `DHTMessageFactoryImpl.cc`
(decoding) and the `DHT{Query,Response,Ping,FindNode,GetPeers,AnnouncePeer}`
message encoders (encoding); the message set and token clauses follow the
BEP5 text (`bittorrent.org/beps/bep_0005.html`).

Intentional divergences from aria2 (none affect interoperability):

1. Token formula: implemented per SPEC §6.7 / BEP5 as
   `SHA1(secret || ip || port)`; aria2 actually computes
   `SHA1(infoHash || compact(ip,port) || secret)` (`DHTTokenTracker.cc`).
   A token is opaque — only the generating side validates it (BEP5 token
   clause) — so the formula is not an interoperability surface.
2. Bencode strictness: KRPC decoding takes the strict canonical path (dict
   keys must be strictly ascending); aria2 does not check key order.
   Mainstream client encoders emit ordered dicts; the design explicitly
   forbids relaxing message strictness.
3. Transaction matching: exact `(transaction_id, SocketAddr)`; aria2 also
   tolerates `::ffff:` IPv4-mapped string forms
   (`DHTMessageTrackerEntry.cc`) — an artifact of storing IPs as strings;
   with `SocketAddr` value semantics the dual form does not exist.
4. Unknown fields: ignored at decode time (aria2 picks fields by key, same
   behavior); therefore `encode(decode(x)) == x` does not hold (extra
   fields are projected away) and the fuzz assertion is the inner round
   trip `decode(encode(m)) == m`.
5. Dual-family default bootstrap fallback: aria2 `--dht-entry-point[-6]`
   has no default value (`OptionHandlerFactory.cc` NO_DEFAULT_VALUE). This
   repo extends the SPEC §6.7 "empty table -> router fallback" enhancement
   (v4 constant `DEFAULT_BOOTSTRAP_NODES`) to v6 as well: the v6 fallback
   constant table lives on the core bootstrap side (`taiji-core`
   engine/dht.rs `DEFAULT_BOOTSTRAP_NODES_V6`; entry-domain/AAAA existence
   checks and their dating are documented there; this crate does not
   extend the table, and the v4 constant + bootstrap-round mechanism are
   unchanged). Companion guard: when no global v6 connectivity exists
   (`probe_source_ip(true)` fails), core skips the v6 bootstrap entirely
   instead of emitting doomed outbound traffic — engineering hardening,
   not protocol behavior.

## engine/mod.rs

Behavior mapping (this engine vs the reference, aria2 unless noted):

| Behavior | Source |
|---|---|
| Per-family init; deserialization failure -> new node ID | `DHTSetup.cc` |
| Restored nodes non-empty -> forced bucket refresh | `DHTSetup.cc` |
| Bootstrap: entry pings; success -> lookup + refresh | `DHTEntryPointNameResolveCommand.cc` |
| Bucket refresh check period 5min | `DHTConstants.h` + `DHTBucketRefreshCommand.cc` |
| Token secret rotation 10min | `DHTConstants.h` + `DHTTokenUpdateCommand` |
| Peer announce: 15min / 5min check / 30min purge | `DHTConstants.h` + `DHTPeerAnnounceStorage.cc` |
| Autosave 30min; save on halt | `DHTSetup.cc` + `DHTAutoSaveCommand.cc` |
| get_peers reply: token + values + closest K | `DHTGetPeersMessage.cc` + `dht_storage.cpp` |
| announce_peer reply: token + record peer | `DHTAnnouncePeerMessage.cc`, `DHTTokenTracker.cc` |
| Inbound message -> markGood + addGoodNode | `DHTMessageReceiver.cc` |
| Query sender ID == our ID -> drop | `DHTMessageReceiver.cc` |
| Transaction timeout / error reply -> node scoring -> bad | `DHTMessageTracker.cc` |
| PORT receive: port=0 ignored; ping; lookup on one bucket | `BtPortMessage.cc` |
| PORT send: our DHT port after handshake | `DefaultBtInteractive.cc` |

Intentional divergences from the reference (none affect interoperability):

1. Hardcoded bootstrap router fallback: aria2 `--dht-entry-point[-6]` has
   no default (`OptionHandlerFactory.cc` NO_DEFAULT_VALUE) — no entry, no
   bootstrap. This engine provides `router.bittorrent.com` etc. as
   hardcoded v4 fallback constants (`DEFAULT_BOOTSTRAP_NODES`) per SPEC
   §6.7, offered as an upper-layer option; a deliberate SPEC enhancement,
   not aria2 behavior. Default resolution / the option surface belong to
   core/cli.
2. v2 support: get_peers/announce_peer target = truncated sha256 v2 face
   (SPEC §6.7). aria2 has no v2 DHT (its DHT face is v1 info-hash only).
   Discovered v2 peers join via the handshake identity first; hash-exchange
   identity verification relies on the requester pulling (transitional
   policy until that lands).
3. implied_port: BEP5 allows announce_peer to carry `implied_port=1`, in
   which case the receiver substitutes the UDP source port for the port
   field. aria2 does not parse the field; this engine implements it per
   BEP5 (libtorrent-interop friendly) — a permissive-side enhancement.
4. Own resend registry: the reference's per-torrent resends live in
   `DHTGetPeersCommand` (15min per torrent / 5min at low peer count);
   TorrentTask wiring is core scope, so this engine provides an equivalent
   registry: a registered `Announce` is resent every 15min by the
   PeerAnnounceCheck timer and removed after 30min without a resend
   command (PURGE policy). The resend cadence starts at the completion of
   a lookup that actually sent >= 1 announce_peer (zero sends do not enter
   the quiet window); entries never announced are re-dispatched when
   bootstrap settles (in the core assembly order registration lands before
   bootstrap settles, so without this the cold-start discovery start would
   slip to the first PeerAnnounceCheck).
5. Responder table ID: both the response and query paths enter the table
   with the wire-carried `r.id`/`a.id`; aria2 reuses the node tracked at
   send time on the response path (a bootstrap entry's random ID would
   enter the table with its ping reply,
   `DHTMessageTracker::messageArrived`) — the wire ID matches Kademlia
   semantics and keeps random IDs out of the routing table.
6. Peer record capacity caps (`wire::MAX_PEER_RECORD_KEYS` keys plus
   `MAX_PEER_RECORDS_PER_KEY` records per key): the reference
   DHTPeerAnnounceStorage has no key-count cap (only 30min sanitization);
   per-torrent peers do have a set capacity (libtorrent `dht_max_peers`
   default 500, settings_pack.cpp) and a reply sampling cap
   (`dht_max_peers_reply` default 100, dht_storage.cpp). This engine adds
   a hard key-count cap against local memory growth (evicting the oldest
   key) and implements the per-key 500 cap plus dual caps truncating
   get_peers reply values (anti-reflection amplification); sources and
   trade-offs in the wire constants and the `state::PeerRecordSet` docs.

BEP42 scope: the text constrains only storage ("MUST never be used to
store information on" + "Requests ... should always be serviced").
Excluding non-compliant nodes from the routing table has no textual
basis, and mainstream bootstrap routers ship non-compliant ids —
exclusion would cut the node off the network.

## engine/bootstrap.rs

Default bootstrap nodes (v4): `router.bittorrent.com`,
`dht.transmissionbt.com`, `router.utorrent.com` — all three had valid DNS
A records at inclusion; `router.bitcomet.com` has no A record and is not
included. `dht.libtorrent.org:25401` was evaluated and rejected: it
resolves and is libtorrent's official default bootstrap, but adding it as
a fourth entry degraded cold-start bootstrap; not included.

Bootstrap settle semantics: aria2's entry round joins on all entries
settling, so one unreachable entry's retry budget (retry x transaction
timeout) delays settling; libtorrent `node::bootstrap` joins all entries
into one concurrent walk (`src/kademlia/node.cpp`, each entry added with
`observer::flag_initial`) without waiting per entry. This engine settles
on the first success (select) and cancels the round's remaining pings.

## security.rs (`crate::taiji_bt::dht::security`)

DHT security extension, BEP42 (node_id bound to the external IP). Authority
order: the BEP text > libtorrent > aria2.

### Spec source (BEP42, bittorrent.org/beps/bep_0042.html)

1. node_id derivation ("The expression to calculate a valid ID prefix"):
   - IPv4: `crc32c((ip & 0x030f3fff) | (r << 29))`
   - IPv6 (`ip` = the address's high 64 bits):
     `crc32c((ip & 0x0103070f1f3f7fff) | (r << 61))`
   - `r` in [0, 7], random; "The resulting integer ... is supposed to be
     big-endian before hashed" — the masked **byte sequence** (network
     order) goes straight into CRC32C;
   - "The first (most significant) 21 bits of the node ID ... MUST match
     the first 21 bits of the resulting hash";
   - random tail byte: the spec's example code sets
     `node_id[19] = rand` (`rand` a random byte, `r = rand & 0x7`) — the
     tail byte carries r's low 3 bits; the middle 16B and the low 3 bits
     of id[2] are independent random.
2. Inbound verification exemption (enforcement section "Any peer on a
   local network address is exempt"): 10/8, 172.16/12, 192.168/16,
   169.254/16, 127/8. The text lists no IPv6 forms — these follow
   libtorrent `is_local` (ip_helpers.cpp): loopback / link-local /
   site-local / multicast / ULA fc00::/7, plus 100.64/10 (CGNAT, a
   libtorrent addition, noted as a divergence).
3. Enforcement (verbatim): "a peer that uses a non-matching ID MUST never
   be used to store information on, regardless of which request";
   "Requests from peers whose node ID does not match their external IP
   should always be serviced" — i.e. **refuse storage, not service**:
   queries are answered normally (token still issued), but (a) the peer
   does not enter the local routing table, (b) its announce_peer is not
   recorded, (c) no announce_peer is sent to it (it is a storage endpoint,
   so nothing may be written to it). No disconnection or error escalation
   (at the KRPC level, "answered as usual").
4. Re-derivation on IP change: libtorrent `node::update_node_id`
   (src/kademlia/node.cpp) — if the current id still verifies against the
   new address it is kept; otherwise it is re-derived from the new address
   (table nodes are retained; the routing table skeleton is rebuilt).

### Cross-validation anchors (libtorrent RC_2_0)

- Derivation: `src/kademlia/node_id.cpp` (generate_id_impl: masking,
  `ip[0] |= (r & 0x7) << 5`, CRC32C, id[0..3] take the hash's top 21
  bits, `id[19] = r & 0xff`);
- Verification: `src/kademlia/node_id.cpp` (verify_id: local-address
  exemption + recompute the hash with `nid[19]` as r and compare
  `id[0]==h[0] && id[1]==h[1] && (id[2]&0xf8)==(h[2]&0xf8)` — exactly 21
  bits);
- CRC32C: `src/crc32c.cpp` (`boost::crc_optimal<32, 0x1EDC6F41,
  0xFFFFFFFF, 0xFFFFFFFF, true, true>` = the standard reflected CRC-32C
  (Castagnoli), init/xorout all ones) — byte-sequence processing
  (network-order input, consistent with the in-memory read-back in
  crc32c.cpp process_bytes and node_id.cpp). The hand-rolled table-driven
  implementation (this module must not add dependencies) is double
  anchored on the CRC-32C standard check value
  `crc32c(b"123456789") == 0xE3069283` and the BEP42 test vectors.
- Interop test vectors: the 5 entries of BEP42's "test vectors" section
  (IP + rand → full node ID), cross-checked byte by byte
  (tests::bep42_test_vectors_reproduced).
- aria2 has no BEP42 implementation (no crc32c / node-id-IP binding path
  anywhere in src), so there is no aria2 reference face.

### Intentional divergence (no interop impact)

1. External address source: libtorrent maintains a vote from socket
   observers and the DHT reply `ip` field (dht_sec.rst "bootstrapping");
   this implementation takes an explicit push from the caller
   (`probe_source_ip` probing +
   `super::engine::DhtCommand::SetExternalIp`). The message face is
   already wired on the send side: replies carry the top-level `ip`
   reporting the requester's observed endpoint per BEP42 (compact 6B/18B;
   encoding and quotes in
   `message::ResponseMessage::requester_endpoint`); the inbound `ip` is
   decoded into that field, but the **vote consumption is not yet wired**
   (inbound reply ip → external-address vote → id re-derivation, a
   pending follow-up).
2. NAT shape: `probe_source_ip` behind NAT may find an RFC1918 source —
   the derived id looks like a random id to outside observers (they
   verify against their public source address), which is no worse than
   random and loses no interop; on a direct connection the probed address
   is the public one and derivation takes effect.

## routing_table.rs (`crate::taiji_bt::dht::routing_table`)

K=8 K-bucket binary routing table, a direct translation of aria2
`DHTBucket.{h,cc}` / `DHTBucketTree.{h,cc}` / `DHTRoutingTable.{h,cc}`
(upstream commit `9e7273583f83e881e3ec067b523ba88724088d2f`).

### Semantics cross-checked against aria2

- Bucket capacity K=8 (`DHTBucket.h`); replacement cache capacity 2
  (`DHTBucket.h`);
- a bucket is the closed `[min, max]` range compared in 20B byte order
  (`DHTBucket.cc`);
- `add_node` (`DHTBucket.cc`): already present (by ID) → move to the tail
  (most recently seen); not full → append; full and the **front** (least
  recently seen, LRS) is bad → evict the front and append; otherwise
  fail;
- `cache_node` (`DHTBucket.cc`): push to the replacement cache's front,
  truncate to 2;
- `drop_node` (`DHTBucket.cc`): only when the cache is non-empty, the
  cache front **replaces** the dropped node — with an empty cache the
  node stays (aria2's dropNode is really a replacement);
- `split_allowed` (`DHTBucket.cc`): `prefix_len < 159` and the local node
  in range;
- `split` (`DHTBucket.cc`): flip bit `prefix_len` — returns the **lower
  half** (bit = 0) and self becomes the **upper half** (bit = 1); node
  sorting happens in the .cc; on the tree side `DHTBucketTree.cc` uses
  the split() return value as the **left** child and the original bucket
  (upper half) as the **right** child;
- Tree invariant: an internal node ⟺ it lies on the local node's path
  (only buckets containing the local node ever split, per the
  `splitAllowed` condition); therefore the sibling subtree of any
  ancestor of the key's leaf is a leaf, and `collectUpward` can safely
  take sibling buckets directly (`DHTBucketTree.cc`);
- `find_closest_k_nodes` (`DHTBucketTree.cc`): collect downward from the
  key leaf's parent subtree with the **leaf side first**, then upward one
  level at a time gathering sibling buckets, filtering bad
  (collectNodes → getGoodNodes, `DHTBucket.cc`), finally truncated to K;
- `needs_refresh` (`DHTBucket.cc`): fewer than K nodes or 15min without
  an update (`DHTConstants.h`);
- Routing insert (`DHTRoutingTable.cc`): the local ID is refused; a full
  splittable bucket → split and descend; otherwise a good node enters the
  replacement cache;
- Transaction timeout scoring (`DHTMessageTracker.cc`): node.timeout()
  once per timeout; reaching the bad threshold replaces it out of the
  bucket;
- Inbound message contact (`DHTMessageReceiver.cc`): markGood +
  updateLastContact + insert under the good semantics.

### Time convention

aria2 reads time via `Timer`/`global::wallclock()`; this implementation
threads `now: Instant` explicitly into the methods that need time, so
tests can inject a deterministic clock.

## task.rs (`crate::taiji_bt::dht::task`)

DHT tasks and the dual-queue executor, the actor-driven half. Upstream
anchors: aria2 commit `9e7273583f83e881e3ec067b523ba88724088d2f`.

### Upstream anchor mapping

- Dual queues + 15-way concurrency + refill semantics:
  `NUM_CONCURRENT_TASK` = `DHTTaskQueueImpl.cc` `NUM_CONCURRENT_TASK = 15`;
  `TaskQueue::refill` is a direct translation of `DHTTaskExecutor.cc
  update()` — finished tasks are removed first, then tasks are taken from
  the queue head and `startup()`-ed; only tasks still unfinished after
  startup occupy a concurrency slot (a task that finishes during startup
  frees the loop to take the next head);
- Two queues are an intentional simplification: upstream runs three queues
  (periodic1/periodic2/immediate, 15 slots each); this implementation
  merges periodic1/2 into `QueueKind::Periodic`. Queue assignment only
  affects scheduling priority, not protocol behavior;
- node/peer lookup state machine: `LookupTask` is a direct translation of
  `DHTAbstractNodeLookupTask.h` (ALPHA=3 in-flight cap; candidate table
  replace/merge/stable XOR-distance sort/dedup/truncate — this side
  truncates to the widened `LOOKUP_FRONTIER_K` = 16 instead of K = 8, a
  documented divergence; `in_flight == 0` completion) and of
  `DHTPeerLookupTask.cc` (token caching; on finish, announce_peer to the K
  probed nodes);
- ping retries: `PingTask` translates `DHTPingTask.cc` (`onTimeout`
  increments `numRetry` first, then compares against `numMaxRetry` with
  the inclusive bound);
- bucket refresh: `RefreshTask` translates `DHTBucketRefreshTask.cc`
  (`force || needsRefresh` → `notifyUpdate` + a range-random ID + dispatch
  a node lookup; the task itself completes immediately).

Tasks do no IO themselves: packet sends and transaction registration are
performed by the engine (`super::engine`) while driving the tasks — the
module is pure state machines, synchronously testable.

### Config knob

`BH_DHT_FRONTIER_K` (read via `taiji_io::knobs::dht_frontier_k`,
trim + usize parse): failure or 0 falls back to the default
`LOOKUP_FRONTIER_K` = 16; an explicit `=8` restores the aria2 K = 8
frontier width bit-for-bit. ALPHA and the announce target width (take(K))
are never affected by the knob; outbound politeness stays with the
per-source query limiter (engine/query_limit.rs).

## engine/tests.rs (`crate::taiji_bt::dht::engine::tests`)

Engine-level regression suite. Conventions and anchors used across the
tests:

- `fast_cfg()` compresses the upstream maintenance table to millisecond
  scale on the same intervals; rate-limit parameters stay at defaults
  because test query volume (single digits per source) is far below the
  25pps/50burst defaults, so limiting behavior is unchanged;
- upstream ratios for the announce registry: 15min reissue interval /
  5min check / 30min sanitization (DHTConstants.h), compressed
  proportionally in the tests;
- BEP42 behaviors are exercised end-to-end: invalid-id get_peers is still
  serviced and routed (storage-only enforcement, "Requests ... should
  always be serviced"); 127/8 and ::1 sources are exempt; invalid-id
  announce_peer is answered but never stored ("MUST never be used to
  store information on"); the ping reply carries the top-level `ip`
  field (asserted on raw wire bytes); SetExternalIp re-derives the node
  id, keeps it while the address is unchanged, and exempt addresses never
  trigger re-derivation (libtorrent node.cpp update_node_id semantics);
  the lookup announce stage never sends announce_peer to non-compliant
  ids;
- error replies: 203 for malformed known-method queries, 204 for unknown
  methods (BEP5 "Errors" code list + libtorrent incoming_error default of
  203), tid echoed, silent faces stay silent, and the per-source error
  budget (`ERROR_REPLY_BURST`) drops excess silently;
- boundedness (regression tests for the reflection-amplification PoC
  shapes): a 700-port announce flood into one key yields a bounded
  get_peers reply (values capped at 50, single family, whole frame below
  one MTU), storage capped per key and in total, truncation counted; the
  v6 variant proves the BEP32 1024-octet whole-frame gate;
- BEP32 want: reply node keys follow the request's want ([n4,n6] → dual
  keys, [n6] → nodes6 only, absent → the request family's single key);
  outbound find_node/get_peers queries always carry want=[n4,n6]; v6
  nodes learned in a v4 engine stay in the table for advertisement but
  are never query candidates (single-stack outbound);
- bootstrap: the first reachable entry settles the round and cancels the
  remaining pings (libtorrent `node::bootstrap` probes entries
  concurrently; aria2 joins each round, where unreachable entries delay
  settlement); bootstrap with no reachable entry degrades without
  crashing; announce registrations made before bootstrap settlement are
  redispatched on settlement, and a zero-send lookup does not consume the
  announce quiet window.
