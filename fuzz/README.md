# taiji-fuzz

cargo-fuzz targets (a standalone workspace, outside the main repo's CI
gate; the fuzz gate runs on the nightly cluster, zero crash tolerance).

## Target registry (29; fully registered after the security-audit gap
## work and the media-line additions)

| Target | Coverage | Seeds |
|---|---|---|
| `aria2_ctrl` | aria2 control-file parsing (save/load round-trip) | ✅ seeds/ |
| `bencode` | bencode decoding: no panic + canonical round-trip assertion | ✅ |
| `cookies` | Netscape cookie file parsing | ✅ |
| `dht_packet` | DHT KRPC packets: inner roundtrip assertion | ✅ |
| `dht_persist` | dual parsers for the dht_state-owned BLOB | ✅ |
| `emule_dat` | ipfilter rule round-trip + IpGuard assembly | ✅ |
| `filetree` | v1/v2 file tree parsing + sanitization | ✅ |
| `igd_device_xml` | IGD description XML (DTD rejection + depth precheck face) | ✅ |
| `lsd_packet` | LSD BT-SEARCH packets | ✅ |
| `magnet` | magnet URI parsing + structural invariants | ✅ |
| `metalink_v4` | metalink v4 whole documents | ✅ |
| `mse_handshake` | MSE handshake | ✅ |
| `nat_pmp_reply` | NAT-PMP reply decoding | ✅ |
| `peer_frame` | BT peer wire frame layer | ✅ |
| `rpc_base64` | RPC base64 payload decoding | ✅ |
| `rpc_basic_auth` | HTTP Basic header parsing | ✅ |
| `trackerslist` | ngosang trackerslist text | ✅ |
| `udp_demux_classify` | UdpDemux first-byte classifier | ✅ |
| `udp_tracker_reply` | UDP tracker reply schema | ✅ |
| `ut_metadata` | BEP9 payloads | ✅ |
| `ut_pex` | BEP11 payloads | ✅ |
| `utp_header` | µTP packet headers | ✅ |
| `metainfo_parse` | Metainfo::parse top level + resident_estimate | ✅ |
| `options_parse` | parse_size / parse_select_file | ✅ |
| `parse_http_date` | RFC 7231 dates | ✅ |
| `parse_www_authenticate` | WWW-Authenticate header | ✅ |
| `naming_sanitize` | generated/user-name sanitization (control-char invariants) | ✅ |
| `m3u8_parse` | the m3u8 manifest parse surface (semantics asserted through the fuzz surface) | ✅ |
| `data_uri` | the media-key `data:` URI parser | ✅ |
| `vtt_splice` | the WebVTT cue parser + timeline splice | ✅ |
| `bmff` | the ISO-BMFF read surface; later rounds added the multi-track entry points (`parse_init_tracks`, `fold_track_for`, `select_init_track`) | ✅ |
| `template` | output-template expansion + forced sanitization (the untrusted-remote-string line; injection-vector seed corpus; surfaced and fixed the padded `.`/`..` degenerate-name passthrough) | ✅ |
| `selector` | the three-layer selector expression parse + resolution invariants (expression-matrix seed corpus) | ✅ |

Evaluated and skipped: GID string parsing (no standalone pure-function face —
bound to the actor's resolve_gid; hex validation is covered by fixed-width
assertions in the rpc layer).

`seeds/<target>/` — seed corpora (committed); `corpus/` — runtime corpora (not
committed).

## Running

Requires nightly + `cargo install cargo-fuzz`. **Unified flags** (default
`-max_len=65536`: matches the main request/packet cap so unbounded inputs do
not dilute the corpus; over-long seeds are still admitted):

```sh
# single target, 60s
cargo fuzz run bencode fuzz/corpus/bencode fuzz/seeds/bencode -- \
  -max_total_time=60 -max_len=65536
# full sweep (script: N seconds per target, default 30)
./run.sh 30
```
