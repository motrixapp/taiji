# Peer protocol design notes (upstream anchor mapping)

Long-form upstream references distilled out of the `taiji-bt` peer module
headers. One section per file; upstream anchors are file + symbol only.

## crates/taiji-bt/src/peer/mod.rs — `BlockSink` direct delivery

Reference (libtorrent): `peer_connection::incoming_piece`
(src/peer_connection.cpp) hands a received block to
`m_disk_thread.async_write(...)` on the same thread, and
`deferred_submit_jobs()` wakes the disk queue once per batch — zero
intermediate queue semantics.

Intentional divergence: libtorrent receives and dispatches on the single
network thread (zero hops means zero cross-thread hops); here the peer task
and the store pipeline task are separate tokio tasks. "Direct" removes the
intermediate forwarding-task hop; the task boundary still crosses a bounded
channel, and a full channel backpressures: while
`BlockSink::deliver_backpressure` awaits, this connection's frame reading
pauses and the peer's send window closes (same shape as peer_connection.cpp's
write-buffer overflow making the peer stop reading).

## crates/taiji-bt/src/choke.rs — choking policy

Two semantic modes: `ChokeMode::Libtorrent` (default) and
`ChokeMode::Aria2` (fallback, selected by `BH_CHOKE_ARIA2=1`, parsed at
construction via `choke_mode_from_env`).

### libtorrent default mode (RC_2_1 anchors)

- Slots: `unchoke_slots_limit` default 8 (`settings_pack.cpp`); the
  optimistic slot = max(1, total/5) (`num_optimistic_unchoke_slots`
  default 0 = auto, `session_impl.cpp`) and counts against the total slot
  budget.
- Round cadence: regular recompute 15s / optimistic recompute 30s
  (`session_impl.cpp`).
- Optimistic choice: `last_optimistically_unchoked` ascending — the peer
  waiting longest wins (None = never = waited longest, sorts first). A
  current optimistic peer that still ranks in the top N keeps the slot for
  another round (`session_impl.cpp`).
- Seeding sort policies (`seed_choking_algorithm`, `choker.cpp`):
  fastest_upload is implemented (upload rate over the last round,
  descending); round_robin and anti_leech are registration stubs.
- Partial ordering: `std::nth_element` guarantees only the top K, O(n)
  (`choker.cpp`).

### aria2 fallback mode (`BH_CHOKE_ARIA2=1`)

- Round interval 10s: `aria2/src/DefaultPeerStorage.cc`
  (`constexpr auto CHOKE_ROUND_INTERVAL = 10_s;`).
- Leecher (`BtLeecherStateChoke.cc`):
  - 3 regular slots (`int count = 3;`); candidates = interested and not
    snubbed (executeChoke excludes snubbing outright);
  - regular slots ordered by download speed descending
    (PeerEntry::operator<), speed measured over a 20s window
    (`constexpr auto TIME_FRAME = 20_s;`);
  - planned optimistic unchoke: on round==0 one peer is drawn shuffled
    from the "interested and not chokingRequired" pool
    (plannedOptimisticUnchoke); the round phase wraps after 3
    (executeChoke `if (++round_ == 3) round_ = 0;`);
  - fast optimistic handoff: when the regular slots pick the current
    optimistic peer, the optimistic flag transfers to the first remaining
    interested peer (regularUnchoke);
  - the regular-slot pool keeps previous regular unchokers first
    (isRegularUnchoker partition + sort).
- Seeder (`BtSeederStateChoke.cc`):
  - ordering operator<: peers with an outstanding upload first, then most
    recently unchoked (within the 20s window, newer lastAmUnchoking wins),
    then upload speed descending;
  - slots are 4 on round==2 else 3; the round phase wraps after 3.
- Event-triggered rerun (an unchoked+interested peer leaves): the engine
  calls `select` immediately on peer exit (semantically equivalent to
  aria2 `DefaultBtInteractive::onPeerLeak`).

### Deliberate divergences

- The leecher regular sort key is the aria2 one in both modes
  (keep-position partition + download speed descending). libtorrent's
  bandwidth-priority / last-round-bytes keys (`choker.cpp`) are
  deliberately not adopted.
- Optimistic reselection shares the regular round cadence (every
  OPTIMISTIC_ROUND_EVERY rounds = 30s, phase aligned); libtorrent uses an
  independent timer (`session_impl.cpp`).
- Preemptive unchoke (INTERESTED rising edge + free slot) is wired on the
  engine side (libtorrent `peer_connection.cpp`); the aria2 fallback mode
  does not enable it (aria2 has no such semantics).
- Seeder fastest_upload input is the engine's `peer_rates.up` 10s sliding
  window (fed at 1s ticks); libtorrent uses per-round (~15s) delta bytes /
  measured unchoke interval — same direction. Session-level optimistic
  allocation across faces (`session_impl.cpp` candidate eligibility spans
  download and seeding torrents) is not modeled; the seeding face uses 8
  all-regular slots. libtorrent's `compare_peers` common prefix comparator
  (peer class priority -> the peer's last-round download to us) has no
  peer-class equivalent here and is not modeled.
- Budget-derived slots: the engine can derive the leecher total from the
  upload budget (quotient of budget and per-peer floor, clamped [4, 32]);
  a missing budget face falls back to the static slot count rather than
  guessing. The aria2 fallback branch and the seeder face never read the
  override.

## crates/taiji-bt/src/peer_wire.rs — wire rules

Handshake anchors (read-only reference, aria2 `BtHandshakeMessage.cc`):
pstrlen=19 + "BitTorrent protocol"; default reserved bits set fast =
`[7]|0x04` and extended messaging = `[5]|0x10`; predicates
`isFastExtensionSupported = [7]&0x04`, `isExtendedMessagingEnabled =
[5]&0x10`, `isDHTEnabled = [7]&0x01`. The BEP-52 v2 upgrade bit `[7]&0x10`
comes from SPEC §6.2 (libtorrent convention; aria2 has no such check).
aria2 `test/Bt*MessageTest.cc` gives the message structure rules and
negative cases (payload length mismatch / id mismatch must be rejected).
`ExtensionMessageRegistry.cc` holds the extension name table
`{"ut_metadata", "ut_pex"}`; `HandshakeExtensionMessageTest.cc` provides
BEP-10 handshake dict samples.

Byte order: the current BEP text is big-endian throughout (v1/v2 alike).
Zero copy: `bitfield`/`piece`/`extended` payloads are held as
`bytes::Bytes`.

- Frame guard: `MAX_FRAME_LEN` 64KiB — the largest piece frame is
  9 + 16KiB (block cap); over-limit frames disconnect (defense against
  malicious length prefixes).
- Handshake decode is stricter than aria2 `create()` (which copies by
  offset only): pstr must match, so non-BT traffic is dropped early with
  no interop cost.
- ExtHandshake shape per aria2 `HandshakeExtensionMessage`: `m` dict
  (extension name -> msg id), `p`, `v`, `metadata_size`, `reqq`.
  BEP-21 `upload_only`: encode only when true (integer 1; BEP-21 defines
  only the value 1, never send 0 — same rule as libtorrent
  `bt_peer_connection.cpp`); decode non-zero = true, missing = false.
- m-dict ids: a value of 0 means "not supported / disabled" (BEP-10) and 0
  is also the ext handshake's own reserved id, so 0 is filtered to None at
  the decode source. bencode integers pass `try_from` domain checks first
  — negatives/out-of-range values used to silently truncate to the bit
  width, forging wrong ids/ports.
- Extension registry defaults per aria2: ut_pex=1, ut_metadata=2
  (HandshakeExtensionMessageTest sample); aria2 has no ut_holepunch in its
  name table, so it is never advertised by default. BEP-10 ids are local —
  interop does not depend on the advertised value (libtorrent advertises 4
  for holepunch; the uTorrent-customary 0x20 is used here).
- BEP-52 hash request/hashes/reject MUSTs enforced by the codec: length
  >= 2 and a power of two (SHOULD <= 512 not enforced), index a multiple
  of length, exact hash count = length + max(0, proof - (log2(length)-1))
  (whole-subtree proof layers omitted but counted).
- Hardening: the `proof` field is capped at 32 (a u32 length domain bounds
  tree depth at 31; BEP-52 does not bound the domain). Oversized proofs
  used to overflow the count arithmetic — remote panic on debug builds,
  silent wraparound past the count MUST on release. The count derivation
  saturates and stays total for any input.
- FrameCodec zero copy: frozen-body decode shares the read buffer with
  piece/bitfield/extended payloads via `Bytes::slice` refcounts; with a
  `BlockArena` the body is copied into a pooled block instead (avoiding
  the freeze that pins the Framed BytesMut), returning blocks to the pool
  when message refcounts drop — same reuse theme as libtorrent
  chained_buffer (`src/chained_buffer.cpp`) and packet_pool
  (`include/libtorrent/aux_/packet_pool.hpp`). Off by default
  (`BH_BLOCK_ARENA=0`).

## crates/taiji-bt/src/bencode.rs — strictness divergence from aria2

aria2's `BencodeParser` (`src/BencodeParser.cc`) tolerates several
non-canonical inputs to survive corrupt torrents; taiji rejects all of them
because non-canonical bytes would let one logical object map to several
infohashes, breaking hash integrity and swarm addressing. Test cases are
tagged `strict-divergence`:

1. Trailing garbage: aria2 consumes up to the end of the top-level value and
   reports the remaining position (`src/BencodeParser.cc`,
   `test/ValueBaseBencodeParserTest.cc`). taiji's `decode` treats any
   trailing byte as `Trailing`.
2. Floats / scientific notation inside integer fields: `i-1.134E+3e` -> 0
   (`src/BencodeParser.cc`; the comment there says some seeding tools emit
   it). taiji rejects.
3. dict key order/duplicates, leading zeros in integers and string lengths,
   `-0`: unchecked by aria2 (its Dict is an ordered map, so out-of-order
   keys are silently reordered). taiji rejects all (BEP3 canonical
   requirement); duplicate keys are rejected on both decode and encode.
4. Empty input: aria2 yields "no value" (`ValueBaseBencodeParserTest.cc`);
   taiji requires exactly one top-level value.

Nesting depth cap 50 mirrors `src/BencodeParser.cc`
(`stateStack_.size() >= 50` -> `ERR_STRUCTURE_TOO_DEEP`); the boundary is
locked by `test/ValueBaseBencodeParserTest.cc` (a 51-level list errors; a
50-level list wrapping a dict errors too because the state stack counts the
dict).

Out-of-range anchors: `ERR_NUMBER_OUT_OF_RANGE` (i64 values),
`ERR_STRING_LENGTH_OUT_OF_RANGE` (string lengths).

The permissive decoder exists for peer-message dicts only (BEP10 extended
handshake, PEX): real clients — aria2 included — send unsorted top-level
keys (`HandshakeExtensionMessageTest.cc` puts `1:v` before `1:md`), and
enforcing order there would mis-reject valid traffic. Because `Value::get`
binary search relies on ascending entries, the permissive decoder sorts
every dict level after parsing; duplicate keys are kept (adjacent after
sorting, `get` hits one) and `encode` still rejects them.

## crates/taiji-bt/src/magnet.rs — upstream anchors and tightenings

Mechanism mirrors aria2 `src/magnet.cc` + `src/bittorrent_helper.cc`:

- `magnet:?` prefix is case-sensitive (`magnet.cc` startsWith).
- Parameters split on `&`; each is divided at its **first** `=` (no `=`
  means key + empty value); keys are not percent-decoded.
- Values go through `util::percentDecode` — lenient: invalid `%` sequences
  kept verbatim, `+` is not a space.
- Same-name parameters accumulate into multi-value lists.
- `xt` is required (`bittorrent_helper.cc`); after `urn:btih:` either 32
  base32 chars (must decode to exactly 20 bytes) or 40 hex chars (either
  case, `util::fromHex`); the scan takes the first valid btih; all invalid
  -> explicit error. `tr` entries go into the announce list in order.
- `urn:btmh:` (BEP52; aria2 has no such form): the multihash must be the
  `1220` prefix (0x12 = sha256, 0x20 = 32B) + 64 hex -> `[u8;32]`.
- `xl`: aria2 does not read this parameter (no path in
  `bittorrent_helper.cc`, no error). This parser takes the first parseable
  value and ignores unparseable ones (lenient, noted).

`x.pe` — a common BEP9-ecosystem extension (direct peer addresses) with no
BEP text. Syntax reference = libtorrent `src/magnet_uri.cpp` (a successful
`parse_endpoint` pushes the endpoint; failures are skipped, lenient) +
`src/socket_io.cpp parse_endpoint` (value trimmed of ASCII whitespace; `[`
prefix parses as IPv6: `]` closes the bracket, immediately followed by
`:port`; otherwise IPv4: the first `:` splits host:port; addresses are
strict literals, no DNS — direct-connect semantics; port numeric and
1..=65535).

Deliberate tightenings (documented, no interop impact):

- **Single `x.pe` address** (first valid, same first-valid rule as the btih
  scan; libtorrent collects all). Direct connect is a fallback discovery
  source; one address is enough within the metadata-phase dial budget.
- **All-numeric port**: `atoi` accepts truncated trailing garbage (`6881x`
  -> 6881); this parser requires the whole string to be digits. Direct
  addresses do not tolerate dirty data.
- **Strict `so=`** (BEP53): BEP53 defines no error surface; invalid syntax
  is rejected explicitly, silent skipping forbidden. Ranges are expanded
  per-index ("Dashes mean inclusive ranges"); the expanded sequence must be
  strictly ascending. The expansion is capped at 2^20 entries (local DoS
  bound: BEP53 defines no limit and magnet URIs are semi-trusted input, so
  a 20-char `so=0-4294967295` must not expand to ~16 GiB; over-cap is an
  explicit `InvalidSo` error). The "append to existing indices" behavior
  (BEP53 §3) is session-task level, not part of this parser.

## crates/taiji-bt/src/holepunch.rs — libtorrent branch anchors

Authoritative order: BEP text > libtorrent > aria2. The BEP text does not
cover ut_holepunch; libtorrent is the behavioral authority.

- Carrier: BEP10 extended handshake `m` dict ("message IDs are local to the
  peer"). libtorrent reads the peer's `ut_holepunch` entry and advertises
  its own (`src/bt_peer_connection.cpp`; its local id constant is 4,
  `include/libtorrent/bt_peer_connection.hpp`). taiji advertises 0x20 (the
  uTorrent convention value); values need not agree on the two sides.
- Wire format: libtorrent `write_holepunch_msg`
  (`src/bt_peer_connection.cpp`): `[1B sub-op][1B address family][4B|16B
  address][2B port]`, `failed` appending a 4B big-endian error code
  (`aux::read_uint32`, `aux::write_uint32`). The design text said "1B error
  code"; libtorrent is authoritative and the divergence is noted.
- Relay decision (`on_holepunch` rendezvous arm): target not connected ->
  `failed(not_connected)`; target connection did not negotiate ->
  `failed(no_support)` (checked before no_self); target is the requester ->
  `failed(no_self)`; otherwise send `connect(target ep)` to the requester
  and `connect(requester remote address)` to the target — both sides dial
  at the same time.
- Connect-arm dial-in: dial like a normal candidate (`add_peer` +
  `connect_to_peer`; the new connection is put in holepunch mode for fast
  retry).
- Trigger surface: libtorrent's connect-failure callback
  (`src/peer_connection.cpp`): direct dial failed and an introducer is
  known (`find_introducer`, `src/torrent.cpp` — the connection that
  delivered the address via ut_pex) -> rendezvous to the introducer.
  taiji: introducer bookkeeping fed by ut_pex discovery events; trigger
  gate = "a dial plan actually ran out" (engine dial-failure reports).
- `failed(0x02)` handling: libtorrent only logs it (its handling logic is
  a TODO there); taiji does the same — debug log, no action.
- Malformed input: every malformed branch in libtorrent is a silent return
  (no disconnect); taiji mirrors that with record-and-ignore decode
  errors.

## crates/taiji-bt/src/lsd.rs — upstream anchors and implementation notes

Reference anchors (aria2):

- Multicast address/port `239.192.152.143:6771`: `src/BtConstants.h`
  (LPD_MULTICAST_ADDR / LPD_MULTICAST_PORT).
- Announce packet (`BT-SEARCH * HTTP/1.1` + Host/Port/Infohash headers,
  trailing `\r\n\r\n\r\n`): `src/LpdMessageDispatcher.cc createLpdRequest`
  (the format string byte-for-byte; infohash is 40 lowercase hex via
  `util::toHex`).
- Interval semantics: announce ready when the timer is >= interval old
  (`LpdMessageDispatcher.cc`); the timer resets after a successful send;
  default 5 min (`LpdMessageDispatcher.h` default argument
  `interval = 5_min`).
- Send-failure retry: 5 consecutive failures reset the timer
  (`LpdDispatchMessageCommand.cc`: success/exception -> reset + try=0;
  failure -> try+1; try >= 5 -> reset + try=0).
- Multicast init: TTL=1, loop=1, local egress address as the multicast
  interface (`src/BtSetup.cc dispatcher->init(localAddr, /*ttl*/1,
  /*loop*/1)`); the receiver binds and joins the group
  (`LpdMessageReceiver.cc`).
- Packet parsing: the datagram must contain a complete HTTP header block;
  `Infohash` = 40 hex -> 20B, `Port` = numeric, <= 65535, != 0
  (`LpdMessageReceiver.cc`).
- Private torrents disable LPD (BEP27; `BtSetup.cc` initializes only when
  `!privateTorrent`). The gate lives in the session actor task layer
  (`taiji-core/src/session/actor/tasks.rs`: `metainfo.private` skips
  announce registration; withdraw uses the same gate).
- `bt-lsd` defaults to **false** (aria2 `PREF_BT_ENABLE_LPD` likewise).

Implementation notes (non-protocol facts):

- The receive socket binds `0.0.0.0:6771` then joins the group (aria2
  binds the multicast address directly off Windows; bind 0.0.0.0 is the
  equivalent idiom under Rust std — same multicast semantics).
- One socket is shared for send and receive (aria2 uses separate
  dispatcher/receiver sockets; merging them does not change wire bytes).
- REUSEADDR/REUSEPORT: the reference sets SO_REUSEADDR on every socket
  (`SocketCore.cc`) so multiple consumers on one host can share the 6771
  multicast port. taiji sets it too (via the safe socket2 wrapper, no
  unsafe) and additionally SO_REUSEPORT on unix (the hard BSD/macOS
  requirement for UDP port sharing — both sockets must set it to bind; on
  Linux both sides setting REUSEPORT for multicast is valid and no weaker
  than the reference's REUSEADDR).

## crates/taiji-bt/src/pex — protocol-fact provenance table

reference = aria2 (read-only). Constants and behaviors:

| Constant / behavior | Value | source |
|---|---|---|
| fresh/dropped hard caps | 50 each (v4+v6 combined) | `UTPexExtensionMessage.cc` |
| send interval / freshness window | 1 min | `UTPexExtensionMessage.h` |
| extension name | `"ut_pex"` | `UTPexExtensionMessage.cc` |
| fresh admission | outbound AND first contact < interval | `UTPexExtensionMessage.cc` |
| dropped admission | outbound AND drop start < interval | `UTPexExtensionMessage.cc` |
| seeder flag bit | 0x02 / otherwise 0x00 | `UTPexExtensionMessage.cc` |
| empty lists' keys not written | added.f only appears with added | `UTPexExtensionMessage.cc` |
| decode leniency: non-dict / ragged lengths -> 0 peers, no error | | `UTPexExtensionMessage.cc` |
| decode ignores added.f/added6.f (no read path) | | `UTPexExtensionMessage.cc` |
| inbound caps: first frame truncated at 300, later frames rejected | BEP11 exemption | BEP11 |
| outbound cadence 60s, stop when full | empty frames skipped | `DefaultBtInteractive.cc` |
| outbound gate = peer negotiated AND utPexEnabled | | `DefaultBtInteractive.cc` |
| private torrent (non-metadata mode): no ut_pex | | `PeerInteractionCommand.cc` |
| not enabled -> registry removal (no advertise) | | `DefaultBtInteractive.cc` |

Decode leniency details: a string length that is not a multiple of the
family unit size is skipped (`bittorrent_helper.h`). The BEP11 first-message
exemption quote: "Except for the initial PEX message the combined amount of
added v4/v6 contacts should not exceed 50 entries. The same applies to
dropped entries." (no replacement value is given). The empty-frame quote:
"Messages must contain at least one of the following fields: added, added6,
dropped, dropped6." — an empty dict violates that MUST; aria2 enqueues the
empty message unconditionally, the BEP text wins here.

Compact peer encoding reuses `crate::dht::compact` (same constants as
`BtConstants.h`; vectors in `BittorrentHelperTest.cc`).

Outbound cadence mirrors `DefaultBtInteractive.cc`: gates first (not
negotiated / not enabled -> None), then the interval throttle, fresh
candidates filtered by `isActive()` and the peer's own IP with the
`freshPeersAreFull()` guard, dropped candidates likewise. The timer still
resets even when the frame is skipped, so the 60s cadence grid does not
drift.

### Extended-message sequence walkthrough

```text
Peer A                 Peer B (taiji)
 |== BEP10 handshake {m:{ut_pex:1}} ==>| ExtHandshake::decode -> B records A's id
 |<== BEP10 handshake {m:{ut_pex:2}} ==| B advertises per pex_offered (private -> no key)
 | ...every 60s (PexSwarmSender.due)... DefaultBtInteractive.cc
 |<== Extended{id=1, added/dropped} ===| PexMessage::decode -> fresh_peers()
 |  (peers fed to engine connection management, same path as DhtEvent::PeersFound)
 |== Extended{id=2, added/dropped} ===>| PexSwarmSender::maybe_build outbound
```

## crates/taiji-bt/src/ut_metadata — protocol-fact provenance table

reference = aria2 (read-only). Constants and behaviors:

| Behavior | source |
|---|---|
| piece size 16KiB (METADATA_PIECE_SIZE = 16_k) | `BtConstants.h` |
| request timeout sweep **20s** (design-spec "1s" was a typo) | `UTMetadataRequestTracker.cc` |
| timeout check `elapsed >= TIMEOUT`, boundary inclusive | `UTMetadataRequestTracker.h` |
| in-flight request cap 1 (MAX_OUTSTANDING_REQUEST) | `UTMetadataRequestTracker.cc` |
| extension name `"ut_metadata"` | `UTMetadataExtensionMessage.cc` |
| msg_type 0=request / 1=data / 2=reject | `UTMetadata*ExtensionMessage.cc` |
| request payload `d8:msg_typei0e5:piecei<index>ee` | `UTMetadataRequestExtensionMessageTest.cc` |
| data payload = dict + raw piece bytes after the value | `UTMetadataDataExtensionMessage.cc` |
| reject payload `d8:msg_typei2e5:piecei<index>ee` | `UTMetadataRejectExtensionMessageTest.cc` |
| responder: no metadata -> reject; bad index disconnects | `UTMetadataRequestExtensionMessage.cc` |
| requester: untracked data ignored; mismatch resets all | `UTMetadataDataExtensionMessage.cc` |
| requester: reject -> disconnect (see quote below) | `UTMetadataRejectExtensionMessage.cc` |
| metadata_size domain `0 < size <= 8MiB`, else not started | `HandshakeExtensionMessage.cc` |

The data-frame split (dict then raw bytes) is decoded by
`DefaultExtensionMessageFactory.cc` via its `end` out-param. An infohash
mismatch also raises an explicit error after the reset. The metadata_size
domain check mirrors aria2, which silently skips metadata mode beyond 8MiB;
taiji errors explicitly for the caller to handle equivalently.

The infohash check works on BEP9's metadata = the info dict's **raw
bytes**; assembled pieces are hashed directly (same as
`UTMetadataDataExtensionMessage.cc`), no decode->re-encode round-trip.
Added on top of the reference: the V2 (btmh) expected identity —
SHA-256(info) == btmh (a BEP52-aligned local extension; aria2 has no btmh
magnet form).

Intentional divergences (no interop impact):

1. Piece-length precheck: non-final pieces must be exactly 16KiB and the
   final piece exactly the remainder; aria2 does not check lengths and
   only exposes bad pieces via the eventual infohash failure. Only the
   error timing changes; the final verdict is identical.
2. Piece scheduling order: missing pieces requested in ascending order
   (aria2's `getMissingPiece` order is unspecified).

### Extended-message sequence walkthrough

```text
Peer (has metadata, responder)  Peer (magnet cold start, requester = taiji)
 |== ext handshake {m:{ut_metadata:2}, metadata_size:N} ==>| Fetcher::new(N, btih)
 |<== ext handshake {m:{ut_metadata:2}} ===================|
 |<== Extended{id=2, msg_type:0, piece:i} =================| next_requests()
 |    (in flight <= 1, 20s sweep)
 |== Extended{id=2, msg_type:1, piece:i, total_size:N}+data >| on_data()
 |    (bookkeeping removed -> piece stored)
 | ...loop per piece until piece_count(N) met... | MetadataAssembler::assemble()
 |    (no metadata -> msg_type:2 reject; out of range -> requester drops)
 | -> verify_infohash(sha1, btih)
```

## crates/taiji-bt/src/peer/conn.rs — message loop write path

### Batched outbound writes (libtorrent cork)

`OutboundWriter::send_batch` encodes the whole command-drain window into
one flush: a single outbound `write` carries the entire request batch —
one TCP segment per batch (partial writes continue through the flush
loop, `write_all` semantics). Upstream anchor (libtorrent write path):
cork-mode RAII merges a batch of `write_message` sends into one
`setup_send`/writev at destructor time (struct `cork` / `~cork`,
include/libtorrent/aux_/peer_connection.hpp; the RC_2_0 form lives in
include/libtorrent/peer_connection.hpp). `chained_buffer` fills the
spare tail capacity of the queued buffer so small messages need no
separate allocation (src/chained_buffer.cpp); `setup_send` aggregates
writes in the same header. aria2 sends request messages through the
same cork batching — fewer TCP segments, smaller loss blast radius:
without batching each request leaves in its own ~17-byte segment, one
lost segment costs one request, and the pipeline idles through TCP
retransmission.

Wire bytes are bit-identical: encoding goes through the same
`FrameCodec` / `Message::encode` (4-byte length prefix included); only
the flush rhythm changes from per-frame to once per batch. BT stream
framing splits on the length prefix and has no message-boundary
semantics (BEP3), so the peer cannot observe write granularity — the
observable behavior equals a local `BytesMut` batch plus one
`write_all`.

### Command channel capacity

`COMMAND_CHANNEL_CAPACITY` = 64 is the command-queue buffer, sized as
`min(target window, 64)`. The target window cap defaults to 256,
aligned with aria2 `BtConstants.h` UB_MAX_OUTSTANDING_REQUEST;
libtorrent `settings_pack.cpp` max_out_request_queue = 500 is the
cross-check reference. The capacity is not the supply window: the
authoritative supply cap is the RequestBook window plus the engine
dispatch round's `min(target − in-flight, channel slack)` bound
(taiji-core `dispatch::supply_cap`). Bounded-channel discipline holds:
a full channel makes `try_send` fail and the caller retries on the
next dispatch round.

### Idle-gated keepalive

Keepalive is sent only after outbound silence >= keepalive_interval
(default 120s), mirroring libtorrent `peer_connection.cpp` keep_alive's
`m_last_sent` gate. `last_sent_at` starts at connection assembly, like
aria2 `DefaultBtInteractive.cc` `doPostHandshakeProcessing` resetting
`keepAliveTimer_`. The check period stays flooding_interval, so an
actual send lags the threshold by at most one check interval. Our own
keepalives never feed FloodGuard (it observes inbound only).

## crates/taiji-bt/src/peer/inbound.rs — choke, reject pump, unsolicited policy

### Inbound choke keeps dispatched slots

A choke does NOT clear dispatched in-flight slots. libtorrent's
incoming choke clears only the not-yet-sent `m_request_queue` and keeps
already-sent `m_download_queue` entries (`peer_connection.cpp`;
`clear_request_queue` touches only `m_request_queue`) — requests the
peer accepted before choking still arrive, and clearing our slots would
misjudge those legitimate deliveries as unsolicited. aria2's
`doChokedAction` clears all non-allowed-fast slots (`BtChokeMessage.cc`
+ `DefaultBtMessageDispatcher.cc`); the libtorrent reading is taken as
the authority (BEP text > libtorrent > aria2). Slots converge via
reject (fast ext) or the timeout grace.

### Reject-pump guard (request while choked)

libtorrent `peer_connection.cpp`: "allow peers to send request up to 2
seconds after getting choke, then disconnect them". taiji keeps the
grace but starts the clock only when we actually send a Choke frame
(libtorrent keys off the connection state); early requests while
initially choked (BEP-3: both sides start choked) are only rejected,
never disconnected — one notch wider than the reference, interop
leniency for optimistic pipelining.

### Unsolicited acceptance policy

Unsolicited = neither an in-flight request of ours (including the
timeout grace) nor in the connection's allowed-fast set nor suggested
by the peer. BEP-6 allowed-fast members may be delivered while we are
choked; a suggest may be followed by an early delivery before our
request arrives. libtorrent records redundant bytes for any
non-requested block instead of disconnecting (`peer_connection.cpp`
incoming_piece); taiji deliberately narrows tolerance to those two sets
and keeps the disconnect outside them.

Set membership does not legalize coordinates: pushes within the sets
still pass the wire request geometry check (begin 16KiB-aligned,
length in (0, 16KiB], begin + length within the piece's expected bytes)
or the connection dies with `BadBlockCoords` — otherwise a malicious
peer could feed misaligned blocks into the store via AllowedFast plus a
misaligned Piece and poison its accounting.

### have_all / have_none

BEP-6 requires non-fast faces to close on receipt ("MUST close the
connection"; libtorrent `bt_peer_connection.cpp` agrees). The
connection layer does not track fast negotiation, so both frames are
accepted leniently and raised as availability events (trusting an
advertisement carries no extra risk; the disconnect gate is out of
scope at this layer).

## crates/taiji-bt/src/peer/ext.rs — BEP-10 routing, gates, holepunch

### Inbound routing on ids

Primary route = our own advertised id; secondary = the peer's
advertised id. BEP-10: "message IDs are local to the peer" — the m dict
value is the id other peers should use when sending to the advertiser.
aria2's inbound demux likewise looks up the local registry
(`DefaultExtensionMessageFactory.cc`; local ids initialized in
`PeerInteractionCommand.cc`) while outbound uses the peer's
advertisement (`UTMetadataRequestExtensionMessage.cc`).

Interoperability constraint: rqbit advertises ut_metadata = 3
(librqbit-peer-protocol `MY_EXTENDED_UT_METADATA`) but still sends data
frames on our advertised id = 2, so routing only on the peer's
advertisement misfiles them.

Deliberate leniency: a peer violating BEP-10 by sending on its own
advertised id is still routed; aria2 raises and disconnects on
unregistered ids (`DefaultExtensionMessageFactory.cc`), taiji keeps
log-and-ignore and only ignores when neither id matches — an extension
id disagreement never escalates to a disconnect.

### Gate semantics

With the local gate off (private torrent / peer exchange disabled),
neither route consumes ut_pex — aria2 `apply_pex_negotiation` registry
removal: the inbound id no longer parses as ut_pex, so the frame is
treated as unknown. The same shape applies to ut_holepunch (None = no
advertise, no consume). BEP-21 `upload_only` is suppressed under
super-seeding — "if we're super seeding, don't say we're upload only,
since it might make peers disconnect" (libtorrent
`bt_peer_connection.cpp`): a super-seed advertises one piece and
upload_only would make peers misjudge it and disconnect early.

### m dict value 0 = disabled

BEP-10: "Setting an extension number to zero means that the extension
is not supported/disabled"; 0 is also the ext handshake's own reserved
id, and decode filters 0 to None at the source. Consumers treat an
advertised 0 as disabled: no ut_pex outbound sender is built, the
ut_holepunch negotiation mirror stays unset (libtorrent
`supports_holepunch()` = `m_holepunch_id != 0`,
`bt_peer_connection.cpp`), and no ut_metadata fetch session is created
(the spec reports Failed — the aria2-equivalent "metadata mode not
enabled" outcome; the orchestration layer retries on another peer).

### ut_holepunch handling

Behavior authority: BEP text > libtorrent > aria2 (the BEP text does
not cover ut_holepunch). Malformed / unknown sub-op / unknown address
family: ignored, no disconnect (each libtorrent `on_holepunch` branch
silently returns, `bt_peer_connection.cpp`). failed frames are
informational and only logged (libtorrent does the same). The rate
limits (4/60s rendezvous, 4/60s connect, 4/60s inbound ut_pex) are
local abuse hardening with no reference counterpart; each accepted
connect is one engine-side hole-punch dial with a 10s budget, so the
window cap prevents dial churn manufactured by a malicious relay.

## crates/taiji-bt/src/peer/read_pool.rs — disk-thread-pool counterpart

libtorrent = one network thread + many disk threads: all network state is
serialized on a single io_context; disk I/O is split into an independent
thread pool (`session_impl.hpp` `m_disk_thread`; `disk_io_thread_pool`
scales on demand, `aio_threads` default 10 = `settings_pack.cpp`). Read
serving jobs run on disk threads, and completions are posted back to the
network thread merged (the `mmap_disk_io` job pipeline) — the peer read
path never blocks the event loop.

This pool is that disk-thread-pool counterpart: the peer_loop is the
"network thread" (the select message loop); serve reads enter a bounded
queue as jobs, dispatchers execute them in `spawn_blocking`, and
completions are re-injected to PeerTask in request order. Divergence:
libtorrent posts completions out of order and lets the request bookkeeping
realign them; here `ServeQueue` preserves order by seq, keeping the wire
frame order of the inline path unchanged. The dispatcher cap of 4 is
deliberately below libtorrent's `aio_threads` default of 10
(`settings_pack.cpp`): loopback/page-cache reads dominate.
