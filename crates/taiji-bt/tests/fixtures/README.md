# fixtures

## hybrid_16k.torrent (880 bytes)
- Generator: `scripts/gen_hybrid_fixture.py` (Python stdlib, no third-party
  dependencies, reproducible)
- Rules: BEP52 (file tree / piece layers / per-file merkle root, piece=16KiB,
  leaf hashes past EOF zeroed), BEP47 (`.pad/11920` entry, attr=p, pad zero
  bytes counted into v1 pieces), BEP3 (canonical bencode, keys in strict
  ascending order)
- Cross-validation: libtorrent 2.1.1.0 (the engine inside qBittorrent)
  — `torrent_info::info_hashes()` matches the generator's SHA-1/SHA-256
  computed over the "raw info byte slice" exactly; `.pad/11920` is recognized
  by the engine as a pad file
- Purpose: the hybrid fixture's v2 infohash matches qBittorrent's
