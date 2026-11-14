# Store design notes (upstream anchor mapping)

Per-module upstream anchors and reference essays for taiji-store.
Code headers in the source files keep only a mechanism summary and point
here.

## merkle.rs

Rules quoted from BEP52 (bittorrent.org `beps/bep_0052.rst`) and its
official reference implementation `bep_0052_torrent_creator.py` (same
repo; "creator" below):

- Leaf hash = `SHA256(block)`, block = 16 KiB ("constructed from 16 KiB
  blocks of the file", `pieces root` section; creator `sha256(block)`).
  No prefix bytes: interior nodes = `SHA256(left || right)` (creator
  `sha256(l + r)`). The 0x00/0x01 prefixes of early drafts never made it
  into the current text; do not add them from memory.
- Tree balancing: leaf slots beyond end-of-file required to build upper
  layers are set to 32 zero bytes ("The remaining leaf hashes beyond the
  end of the file required to construct upper layers of the merkle tree
  are set to zero"; creator `bytes(32)`). The zeros themselves, not the
  hash of zero bytes.
- The single-file root is independent of piece size ("identical files
  always result in the same root hash"): when the file fits in one
  piece, the leaf count is padded to the next power of two of the block
  count (creator comment "padded to the next power of two instead of the
  next piece boundary"); with more than one piece, one tree is built per
  piece and the last (possibly short) group is padded to
  `blocks_per_piece`.
- `piece layers` stores the layer where "one hash covers `piece length`
  bytes" (`piece layers` section), i.e. the concatenation of the piece
  roots in order. "Layer hashes which exclusively cover data beyond the
  end of file … are omitted" => entry count = `ceil(file_len /
  piece_len)`; a file no larger than the piece size has no entry.
- Piece-root layer -> file root: when the piece-root count is not a
  power of two, pad by repeating the root of the all-zero-leaf tree with
  `blocks_per_piece` leaves (creator "balance the tree by padding with
  zero hashes"); a single piece root is the file root itself.
- Load validation: "A torrent is not valid if … the contained hashes do
  not match the merkle roots or are not from the correct layer". Layer
  count consistency plus a matching recomputed root is the implementable
  test for "correct layer".

## layout.rs

Multi-file disk layout mapping (SPEC §4.2). Rule sources:

- v2-only: files are packed contiguously in file-tree DFS order, no pad;
  request addressing is (file piece index, begin).
- v1/hybrid: the v1 layout — cumulative offsets in `files` list order;
  `.pad` placeholder files (BEP47) occupy offsets but are never written
  to disk; v2 verification reads each file at its offset within the v1
  layout.
- BEP47 (beps/bep_0047.rst): "Padding files are synthetic files inserted
  into the file list to let the following file start at a piece boundary
  … For the calculation of piece hashes the content of padding file is
  all zeros." -> this module validates: a pad must be immediately
  followed by a non-pad file whose offset lands on a piece boundary, and
  the pad length must equal the remainder to the next piece boundary; a
  violation rejects the load.
- BEP47: pads are not written to disk and requests to them are avoided;
  reads must be served with zeros — the zero-fill happens in
  `crate::torrent_writer`.
- BEP47: the recommended pad path is `[".pad", "N"]`; parsing decides by
  the attr 'p', not by path shape.

## precomputed_block_hashes.rs

v2 block-hash write-path precompute table, cross-validated against
libtorrent `src/precomputed_block_hashes.cpp` (the motif of feeding a
precomputed hash into a dedicated hash queue at the moment a block
enters the cache).

### Rule sources (cross-validation anchors)

- `store` (libtorrent `precomputed_block_hashes.cpp`): a write-path hash
  enters its per-piece entry as soon as it completes (lazy allocation,
  positioned by block index, duplicate writes overwrite);
- `take` (same file): a hash2 job consumes an entry by moving it out
  whole; the entry is released with the job (mapped here to: released
  with the PieceJob once the completed piece is promoted);
- `drop` (same file): piece reset/eviction drops the entry in step with
  the table;
- consumer side (`pread_disk_io.cpp` `fill_precomputed_v2`): the hash2
  job consults the table first and reads back from disk only uncomputed
  slots — with the table on, piece verification does zero re-reads and
  zero recompute.

### Intentional divergence

- No dedicated hasher thread: libtorrent computes asynchronously via
  `m_v2_hash_queue` (buffer ownership travels with it); here the
  precompute runs inline in the store pipeline's existing
  `spawn_blocking` batch buffer (spec: the SHA-256 of the blocks in a
  batch shares the batch's bounds — no new thread hops). With no
  cross-thread handoff, no all-zero "uncomputed" sentinel is needed
  (libtorrent uses an all-zero hash as the sentinel,
  `precomputed_block_hashes.cpp`; here `None` = miss slot).
- Key surface: libtorrent keys by `(storage, piece, block)`; this table
  is per-face (one per swarm face), keyed by `(flat piece index, block
  index within the piece)` — the v2 face's piece index is a synthetic
  flat order ((file, piece_in_file) <-> flat mapping lives in the
  bt-side base-offset table, see the `crate::hashpool::HashPool` field
  docs); cardinality is equivalent.
- Only "when it is computed" changes, not "when it is trusted": the
  table only moves hash values around (SHA-256(16KiB) is per-block
  independent, BEP-52 `pieces root` section); piece verification still
  requires the merkle bottom-up convergence to the metadata piece root
  (`crate::merkle`), and miss slots fall back to locating the hash in
  the pool (the existing path; the value is identical — the same
  function of the same bytes at the same time).

## disk_policy.rs

Parameter provenance for the three disk-protection tiers
(`crates/taiji-store/src/disk_policy.rs`):

- **falloc / prealloc / trunc** semantics cross-checked against aria2
  `--file-allocation` (usage_text.h): on ext4/btrfs/xfs, 'falloc'
  "allocates large(few GiB) files almost instantly" (SSD tier — less
  write amplification); 'prealloc' writes zeros segment by segment (HDD
  anti-fragmentation, the customary tier for mechanical disks among BT
  clients); 'trunc' = sparse ftruncate (the pre-existing behavior).
- **Flush cadence**: the hdd tier's 60s is cross-checked against the
  aria2 `--auto-save-interval` default of 60 (`OptionHandlerFactory.cc`
  `PREF_AUTO_SAVE_INTERVAL` "60"); the ssd tier's 30s balances the
  power-loss window against fsync overhead (initial engineering value,
  to be tuned against real-hardware evidence).
- **Read merge / large sequential reads**: libtorrent `docs/manual.rst`
  "coalesce the small bittorrent requests" — merging wire-level 16KiB
  requests into large sequential IO is an established performance
  surface in mainstream implementations (HDD anti-seek-jitter).
- **IO ops/s quota**: read serving and write flushing share one token
  bucket (quota fairness) plus a periodic flush cadence (staggered
  beats); the two mechanisms together prevent mutual starvation. The
  numbers are initial engineering figures: HDD physical seeks cap
  around ~120 IOPS, so 512 ops/s carries burst headroom; SSD is relaxed
  to 4096.

## persist/writer/write_recovery.rs

recovered_layer derived-table write/read face. Cross-validated against
libtorrent resume data: libtorrent persists each file's merkle-tree
sparse vector with the resume data (`torrent.cpp` `build_sparse_vector`
-> `ret.merkle_trees` / `merkle_tree_mask` / `verified_leaf_hashes`);
read-back re-feeds them file by file via `load_merkle_trees`
(`torrent.cpp` has_v2 dispatch; pad/empty files skipped; the sparse and
mask forms). The vehicle here is a sqlite derived table (sqlite as the single
writer), and the persistence granularity is the whole-file piece layer
(the admission granularity) rather than the tree's sparse vector — a
layer read back re-runs `validate_piece_layer` for convergence
re-verification (equivalent to the "verified" level implied by
`verified_leaf_hashes` in its resume data); the root anchor stays
protected by the infohash.

## persist/writer/mod.rs

PersistWriter: the sole writer of `taiji.sqlite3` (SPEC §3.2
PersistWriter row, §5.4; digest dedup follows the upstream
fork's `lastDigest_` trick, source read-only).

Shape: a dedicated `spawn_blocking` thread owns the `Connection`
(`Connection` is not `Sync`, so ownership is the single-writer proof);
the async side submits PersistJobs over a bounded mpsc and receives
results via oneshot; once every handle is dropped the thread finishes
the queue and exits.

### Business rows

- TorrentRow/TorrentFileRow: `torrent`/`torrent_file` rows (SPEC §5.3,
  field by field). Neither table's v1 DDL has a digest column (schema
  frozen, in-place table changes forbidden) -> dedup uses row-level
  comparison (the TrackerRow precedent); `created_at`/`updated_at` are
  observability fields ("when the content last changed", same as
  DhtStateRow::saved_at) and do not participate — a skip keeps the older
  in-db values.
- HttpTaskRow: `http_task` rows (the phase-B data-model increment,
  settled once as v3) — a whole-row upsert per task
  (UpsertHttpTask; a changed bitmap/state/validator payload overwrites);
  the recovery read face LoadHttpTasksAtStartup returns only the active
  set (queued|probing|downloading|paused); terminal tasks are not
  rebuilt. The task cookie set replays with the recovery read face
  (HttpTaskSnapshot); the write faces are
  UpsertHttpTaskCookies (whole-set single-transaction replacement) and
  ClearHttpTaskCookies (cleared on completion/delete — deletion
  additionally has the FK cascade as a backstop). The four media tables
  are a DDL freeze surface that 0.3 enables writes for; zero writes in
  0.2 (no messages).
- Remove semantics: SPEC §5.3's state set has no `removed`, and aria2's
  session save also does not persist removed tasks
  (`SessionSerializer.cc` writes a DownloadResult only for
  FINISHED/REMOVED and only with `--force-save`) -> remove =
  DeleteTorrent (row-level FK cascade clears the subtables); persisted
  DownloadResults are the terminal form of the torrent row
  (`done`/`error`, within the state set), stored via
  InsertDownloadResult.
- Recovery read face LoadTorrentsAtStartup: returns only the active set
  (SPEC §5.4: state ∈ queued|metadata|checking|allocating|downloading|
  seeding|paused; terminal done/error are not rebuilt and stay as
  purgeable/removable persisted results).

### In-flight block bitmap (SPEC §5.4 vs the reference)

aria2 persists and restores in-flight pieces in its `.aria2` control
file (`DefaultBtProgressInfoFile.cc` writes the in-flight segment and
`addInFlightPiece`s it after load); this engine's `torrent_progress`
bitmap records only verified pieces, and the in-flight block bitmap is
dropped on recovery — an intentional simplification relative to the
reference (correctness is guaranteed by SPEC §5.2's "verify before
persist" crash-consistency model: at worst unconfirmed blocks are
re-downloaded, nothing is over-recorded). The migration importer reads
the in-flight segment and discards it.

## recovery.rs

Upstream anchors for whole-file admission of recovered piece layers
(`crates/taiji-store/src/recovery.rs`):

- **Trust anchor = root convergence**: libtorrent's single-source proof
  chain, `merkle_tree.cpp` (`merkle_validate_and_insert_proofs` checks a
  delivered proof chain up to the root) plus the root source
  `torrent.cpp` (`fs.root_ptr(i)`, from the info dictionary) — there is
  never any cross-peer consistency voting.
- **Missing-recoverable / corrupt-hard-error split**: `torrent.cpp`
  treats an empty layer as "load the torrent anyway and wait for the
  swarm" (`valid = false; continue`), while a present layer whose
  recomputed root mismatches clears the whole tree and raises the
  `torrent_invalid_piece_layer` hard error. This module takes only the
  "missing -> recovery" branch; "present but corrupt" is hard-rejected
  at the parse face (`taiji-bt::filetree`) and never enters recovery.
- **Admission granularity is an engine degree of freedom** (BEP-52 says
  nothing about recovery); libtorrent inserting proofs per block
  (`merkle_tree.cpp`) is a product of its progressive verification
  structure.

## torrent_writer.rs

Upstream anchor mapping for the layout-aware multi-file writer/reader
(`crates/taiji-store/src/torrent_writer.rs`):

- Cross-file write splitting: aria2 `MultiDiskAdaptor.cc` `writeData` —
  locate the first file, then write each file's span in turn; reads work
  the same way.
- Pad semantics (a divergence from aria2, which has no BEP47 support):
  BEP47 L85 — piece hashes are computed with pad bytes as all-zero;
  BEP47 L87 — pads are never written to disk and must be served as
  zeros.
- Handle cap: aria2 `OpenedFileCounter.cc` counts globally open files,
  default 100 (`OptionHandlerFactory.cc` `--bt-max-open-files`). Closing
  evicted handles by LRU (instead of failing the task) is the improvement
  noted in SPEC §5.1; the read pool mirrors libtorrent's read-only file
  tables (`file_view_pool` / `file_pool_impl<FileEntry>`,
  `file_view_pool.cpp`).
- Zero-length files are created too (`aria2/src/MultiDiskAdaptor.cc`
  comment).
- Allocation on existing files: aria2 `AbstractDiskWriter::openFile` —
  try `openExistingFile` (O_RDWR, no O_TRUNC) first and only create via
  `initAndOpenFile` → `createFile` on ENOENT; `MultiDiskAdaptor.cc`
  applies the same policy per file. aria2 additionally refuses a task by
  default when files already exist on disk without a control file
  (`RequestGroup.cc` FILE_ALREADY_EXISTS; only `--check-integrity` /
  `--allow-overwrite` / `--bt-seed-unverified` let it through). The add
  path here has no startup recheck flow, so it takes the
  `--allow-overwrite` open semantics: existing bytes are preserved and
  the bitmap downloads from zero. falloc/prealloc run only for newly
  created files — the allocation contract is only ever valid for new
  empty files.
- Zero global write serialization (cross-validation with libtorrent):
  the mmap backend's write jobs synchronously memcpy into the page cache
  with no application-level write lock (`src/mmap_disk_io.cpp`); the
  pread backend merges contiguous blocks into a single pwritev
  (`visit_block_iovecs`). `write_at(&self)` with pooled `Arc` handles is
  the same philosophy in equivalent form under the verify-before-disk
  discipline: piece goff spans never overlap, so per-file pwrites outside
  the pool lock are safe without a global write lock (unix POSIX
  pread/pwrite per-offset atomicity; Windows relies on the upper layer's
  write-exclusive domain instead).
- Read failure policy (missing/unopenable files propagate as errors):
  aria2 surfaces read failures and refuses unservable piece requests
  instead of silently returning zeros. Returning a zero buffer with Ok
  would serve sparse zeros for pieces the bitmap claims complete →
  swarm hash-fail storms and local bans.
- fsync/bypass handles open read-write: Windows `FlushFileBuffers` needs
  write access and fails a read-only handle with ACCESS_DENIED (escalated
  to Fatal by the periodic flush arm); unix allows fsync on O_RDONLY, so
  read-only opens never exposed the difference. Best-effort bypass is the
  same as aria2's `AbstractDiskWriter::openFileWithFlags` F_NOCACHE
  branch.

## spill.rs

The unverified spill area: sidecar staging when the write cache is full
(`crates/taiji-store/src/spill.rs`).

### Motivation and upstream anchor

Under verify-before-write (`crate::verified`), write-cache eviction means
destroy-and-refetch (`cache.rs` `update_min_loss`, an intentional
divergence from aria2's largest-first flush). Even at a fixed capacity,
extreme shapes — endgame trickles over deep connections — still evict
pieces mid-assembly. Spill does not destroy on cache overflow: the victim
piece's cells go to a sidecar file and are read back at piece assembly,
keeping the main data files verified-bytes-only while the refetch traffic
disappears.

Cross-validation anchor: libtorrent RC_2_1 `disk_cache.cpp` — four-pass,
cost-increasing eviction plus the "never pay a readback cost for hashed
data" philosophy. taiji's analog is "never pay refetch traffic for
unverified data"; spill is the verify-before-write model's way to get
both (aria2's part-file idea ported to the BT face, read-only reference).

### Lifecycle

- Task-level directory: `<dest sibling>/.taiji-spill/<task name>/face<N>/`.
- Crash-disposable: spill is not in the persisted bitmap; the semantics
  of lost spill bytes are "never received" (refetch self-heals).
- Residue directories of the same task+face (crash restart) are cleared
  at `SpillStore::open`, only after the face lock is held.
- Task teardown (`VerifiedWriter` drop → this struct's drop) deletes the
  face directory and rmdirs task/root when empty (best effort; non-empty
  is silently kept — sibling faces are still in use). The lock file
  itself is never deleted (release+unlink races a concurrent opener and
  swaps inode identity), so task/root rmdir failing on it is expected;
  footprint is bounded at one lock file per dest×face.

### Same-dest exclusion

The task directory is derived from the dest hash — two tasks with
different infohashes whose dest resolves to the same path would share
`<task>/face<N>`: the second open's residue cleanup would delete the
first task's in-flight spilled pieces, and two stores appending/deleting
in one face directory would trample each other. Opening therefore takes
the face lock (`<task>/face<N>.lock`, a `BEGIN EXCLUSIVE` transaction on
a minimal sqlite database — kernel-arbitrated, so process death releases
it; the mechanism mirrors the session layer's `db_lock.rs` discipline).
Busy = a definite `None` refusal (the caller degrades to no spill face,
the destroy-refetch status quo); another task's directory is never
cleaned. Same-session same-dest double tasks are excluded by the session
layer's addTorrent; this lock is defense in depth (stale processes /
import residue / recovery replay).

### Disk budget

The spill cap is caller-given (pipeline default = the write-cache
capacity; `BH_SPILL_BYTES` overrides). Over-limit handling has two
layers:

- Single entry over cap (theoretical bound: a piece longer than the
  budget) → not absorbed; falls back to destroy-refetch.
- Cumulative over cap → spill entries are displaced FIFO (oldest first)
  to make room; displaced entries are destroyed through the caller's
  existing per-source teardown (pool reset + precomputed entry clearing +
  upstream bookkeeping invalidation). Nothing is deleted until the new
  write succeeds (zero unnecessary loss on IO failure).

### Crash / IO semantics

The sidecar is a pure optimization: any IO failure degrades to "this data
was never received" (store failure = today's destroy-refetch; read-back
failure = piece reset-refetch); it is never fatal, and unverified bytes
never enter the main data files. Spill files carry no fsync — losing
pages to a crash means the same as "never received" (disposability is a
design premise, not a defect).

### Write-half coalescing exclusion

Spill writes (`SpillStore::store`) stay per-cell `write_at` and do not
join `BH_WRITE_COALESCE`: spill is piece-file-granular (one sidecar file
per piece; a same-piece merge is an append at the `file_len` cursor) and
its trigger face — write-cache overflow victims — is near-zero in normal
operation, so both byte volume and call counts are a small share of the
main-file write face. Coalescing gain would be ~0 while the rewrite would
couple the sidecar layout/accounting to the append cursor. The
main-file write face (completed-piece batch writes) is the coalescing
lever; see `crate::verified`.

## cache.rs

The write cache (`WrDiskCache`) is a direct translation of the aria2
write-disk cache index with per-piece cell buffers (SPEC §5.2). Upstream
anchors:

- `DataCell {goff, data, offset, len, capacity}`, kept goff-ascending:
  `aria2/src/WrDiskCacheEntry.h`. This implementation drops `offset`
  (cells own their data; no external buffer reuse). The other fields keep
  their semantics.
- `cacheData`: deduplicating insert (the same goff is refused), size
  accumulates — `aria2/src/WrDiskCacheEntry.cc`.
- `append`: extends in place only when contiguous with the **last** cell
  (`last.goff + last.len == goff`), capped at `capacity`; returns the
  actually absorbed byte count (0 = not absorbed) —
  `aria2/src/WrDiskCacheEntry.cc`.
- Index `add` / accounting touch / `ensureLimit`:
  `aria2/src/WrDiskCache.cc` — each touch bumps the clock; `ensureLimit`
  runs after accounting.
- `writeToDisk`: writes the cells to disk in goff order, swallowing
  errors into an error flag, and clears the cells regardless of success
  (`aria2/src/WrDiskCacheEntry.cc`). This port is a pure in-memory
  structure: eviction **hands the cells to the caller** to write; the
  consequences of a failed write are the caller's decision (see
  `verified.rs`'s verify-before-write discipline).
- Cell capacity source: the download path `BtPieceMessage.cc` builds
  cells with block-length capacity; `Piece::updateWrCache` /
  `appendWrCache` (`aria2/src/Piece.cc`) handle cache insertion and delta
  reporting.
- Cache default 16M: `aria2/src/OptionHandlerFactory.cc`
  (`PREF_DISK_CACHE` default `"16M"`).

Intentional divergence from aria2: aria2 lets unverified data reach disk
through the cache and verifies whole pieces on completion; here the
cache holds only unverified data and evicting an unverified piece means
destroy-and-refetch (`verified.rs`), not a disk write. The accounting and
touch machinery mirrors aria2; the eviction order diverges on purpose —
aria2's largest-first eviction (`WrDiskCacheEntry.h` `operator<`)
maximizes bytes freed per flush, which is a flush-efficiency goal that
only exists when eviction writes to disk. Under destroy semantics,
largest-first systematically kills near-complete pieces (they are always
the largest entries, so a saturated cache self-destructs its
closest-to-completion work), so the victim order became
smallest-size-first (oldest on ties): minimize received bytes discarded
per eviction. See `update_min_loss` for the protected key and termination
contract.

## hashpool.rs

HashPool is the piece verification state machine (SPEC §4.3/§4.5.2,
`crates/taiji-store/src/hashpool.rs`). Rules:

- v1: whole-piece SHA-1. The pool does no arrival-order digest
  accumulation. Upstream anchor: aria2 `Piece.cc` `updateHash` gates on
  `begin == nextBegin_` — out-of-order blocks are not fed to the digest,
  and completion recomputes via `getDigestWithWrCache`. This pool has no
  such gate, so arrival-order accumulation would necessarily misalign;
  it was removed from the `verify` path. Authoritative v1 verification
  recomputes at completion from the cached cells in `verified.rs`
  `piece_matches`.
- v2: per-block SHA-256 hashes are collected and the piece root is
  recomputed at piece completion against the metadata (piece-tree rules
  in `crate::merkle`; the creator's "sole piece padded to a power of two
  / other pieces padded to blocks_per_piece" branches are covered by the
  split between `merkle::piece_root_from_block_hashes` and the file-level
  `merkle::file_root`).
- M0 scope (honesty note): block-level incremental verification needs
  base-layer (16KiB granularity) sibling hashes, which the metadata does
  not carry; lazy base-layer hash requests are later work (SPEC
  §4.3/§6.3). M0's v2 verification granularity is therefore "at piece
  completion", the same moment as v1; v2's payoff (a failure refetches
  only one block) lands once the base layer is available.

No byte reaches disk before verification passes — HashPool only computes
hashes; the write decision lives in `crate::verified`.

## persist/fork_import.rs

Migration importer, storage face: read-only access to the legacy fork
database plus binary parsing of legacy `.aria2` control files.

Fork schema authority: `aria2 src/Sqlite3Migrations.cc` (the
task/task_progress DDL), `kCurrentSchemaVersion = 1`
(`Sqlite3Migrations.h`); the task-row write face is
`Sqlite3SessionStore.cc` (serialized = input-file text, line format per
`SessionSerializer.cc` / read per `UriListParser.cc`). Read-only
discipline: the fork DB is opened with `SQLITE_OPEN_READ_ONLY`, so
sqlite itself rejects every write statement; the module has no write
path. The table-set probe (meta/task/task_progress must exist) also
catches this engine's own `taiji.sqlite3` passed in by mistake — both
are `user_version = 1` with different table sets.

### `.aria2` control file byte layout (BT variant)

Authority: `DefaultBtProgressInfoFile.cc` (save and load paths). All
integers are network byte order (from version 0001 on):

```text
offset size field
0      2    version = 0x0001 (written as {0x00,0x01})
2      4    extension (BT download = low byte bit0 set)
6      4    infoHashLength (BE u32; BT must be 20)
10     20   infoHash (SHA-1, BEP3)
30     4    pieceLength (BE u32, must be non-zero)
34     8    totalLength (BE u64)
42     8    uploadLength (BE u64; uploadLengthAtStartup + session sum)
50     4    bitfieldLength (BE u32; must equal
            ((total+piece-1)/piece+7)/8)
54     n    bitfield (MSB-first piece bitmap, n bytes)
54+n   4    numInFlightPiece (BE u32)
each in-flight piece:
  4    index (BE u32, < numPieces)
  4    length (BE u32, <= pieceLength)
  4    bitfieldLength (BE u32, = (length+7)/8, block unit
       Piece::BLOCK_LENGTH = 16 KiB)
  m    piece bitfield
```

Version policy: anything != 0x0001 is explicitly rejected, including
version 0000 (the upstream load also accepts 0000 as host byte order).
Host-order files are not portable across machines, so refusing beats
misreading. Trailing extra bytes are ignored (the reference load does
not check EOF either).

In-flight pieces are read, bounds-validated (index/length/bitfield
length), and then discarded: this engine's progress bitmap only records
verified pieces, so in-flight blocks are never imported. Validation
still happens first so a corrupt segment cannot desynchronize the skip.

Allocation-safety invariant: the parser checks `need(fixed_len)` before
`vec![0u8; fixed_len]`. The expected bitmap length is derived from the
*declared* totalLength, so a ~34-byte file declaring a 32 GiB total with
1-byte pieces would otherwise force a ~4 GiB zeroed allocation before
the truncation error; the need-first ordering clamps every allocation to
bytes actually on disk (immediate `Truncated` with exact
offset/need/have).

### HTTP/FTP variant (`parse_aria2_control_http`)

Same layout, non-BT branch: save writes extension = 0, infoHashLength =
0, uploadLength = 0 for non-BT downloads (`torrentDownload = false`).
Load-side tolerances: infoHashLength <= 20 is accepted and that many
bytes are skipped (HTTP loading does not enable infohash checking —
`infoHashCheckEnabled = extension[3] & 1 && isTorrentDownload()`).
In-flight pieces follow the same validate-then-discard rule. Routing by
extension bit0: set = a BT-migration-face file, reported as
`Aria2CtrlError::IsBitTorrent` so the caller routes it (never mixed
reads); clear = HTTP/FTP, reported as `NotBitTorrent` from the BT face
(directory scans hit both, skipping is not an error).

### Fork liveness fd scan

The SQLITE_BUSY lock probe only catches the "currently writing" window;
a WAL-mode fork holds no lock most of the time. Layer 2 therefore scans
the process table for open handles to the fork DB / `-wal` / `-shm`
(a sqlite connection always holds these fds, writing or not). Three
states: `Clean` (provable "fork is closed"), `Alive` (holder pids;
import refused, not exempted by the override flag), `Uncertain`
(platform unsupported / lsof missing — treated as default-refuse, never
silently clean; `--i-know-fork-is-closed` explicitly accepts the risk).
macOS runs `lsof -Fn`, Linux walks `/proc/<pid>/fd` readlink; the
canonical-spelling candidates exist because macOS lsof reports
`/tmp/...` under its vnode name `/private/tmp/...`.

## disk.rs

Single-file DiskWriter. The trait keeps positioned writes, three-mode
allocation, fsync, and `ENOSPC` classification; the platform matrix and
upstream anchors live here.

### Upstream anchor mapping (read-only reference:
`aria2/src/AbstractDiskWriter.cc`)

- `openFile`: open the existing file first, fall back to creating a new
  file on `ENOENT` — mirrored by `DiskWriter::open`.
- `openFileWithFlags`: open loop retries EINTR, `make_fd_cloexec`, and
  `fcntl(fd, F_NOCACHE, 1)` under `__APPLE__` (failure ignored,
  best-effort) — std `File` opens are cloexec already; the F_NOCACHE
  status is in `DiskWriter::set_bypass_page_cache`.
- `createFile`: `mkdirs` for parent directories +
  `O_CREAT|O_RDWR|O_TRUNC` — mirrored by `DiskWriter::create`.
- `writeDataInternal`: short-write loop — std `write_all_at` (unix) /
  the `seek_write` loop (Windows) are equivalent.
- `isDiskFullError`: `ENOSPC` -> `NOT_ENOUGH_DISK_SPACE` — mirrored by
  `classify_io` into `StoreError::NoSpace` (native codes per platform,
  never mixed across platforms).
- `flushOSBuffers`: `fsync` — mirrored by `flush_os_buffers`
  (`sync_all` / `FlushFileBuffers`).
- `allocate`: the three platform branches map to Trunc (ftruncate
  sparse) / Falloc (fast path stubbed to trunc) / Prealloc (zero fill,
  a direct translation of `SingleFileAllocationIterator.cc`, 256 KiB
  buffer, final truncate to the target length).
- Falloc fast path: Linux fallocate(2) / macOS F_PREALLOCATE need
  unsafe libc, forbidden by the workspace's `unsafe_code = forbid`; a
  safe wrapper crate would be a new dependency. The fallback to sparse
  trunc is design-specified, logged by the caller, and reported
  honestly as `AllocationEffect::Truncated { fallback: true }`.

### Windows semantics (authority order: libtorrent, read-only
reference)

Positioned writes = OVERLAPPED `WriteFile` short-write loop
(`file.cpp` `pwrite_all`); allocation = `SetEndOfFile` (`file.cpp`);
the real falloc fast path = `SetFileValidData` (`file.cpp` privileged
call_once, needs `SE_MANAGE_VOLUME_NAME`); open = `CreateFileW` with
`FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE` (std default
share mode matches); no_cache = open-time `FILE_FLAG_WRITE_THROUGH`.
The implementation picks `FileExt::seek_write` with a short-write loop
(std's safe wrapper for OVERLAPPED positioned writes) because raw
OVERLAPPED FFI is forbidden workspace-wide and a Win32 binding crate
would be a new dependency. `seek_write` cursor side effects are
irrelevant here (all IO is positioned); concurrency is routed by the
SharedDiskWriter write-exclusive domain on Windows.

### Symlink defense (both platforms)

`create`/`open_existing` protect the final path component: unix sets
`O_NOFOLLOW` (open fails with `ELOOP` for a symlink final component;
the constant is inlined per platform because std does not export it;
other unix is a gap), Windows sets `FILE_FLAG_OPEN_REPARSE_POINT` and
then rejects the handle explicitly via `is_symlink()` — CREATE_ALWAYS
is avoided because its "replace" semantics combined with reparse points
could destroy the target before the check. Without this, a symlink
pre-planted in the download directory made the bare `O_CREAT|O_TRUNC`
open punch through and write an arbitrary target. Vectored-write
chunking caps one pwritev at 512 iovecs (half of `IOV_MAX = 1024`,
which returns `EINVAL`); callers' structural bounds are far below, so
the cap is trait-face defense.

## persist/mod.rs

`taiji.sqlite3` persistence: schema ledger, single-writer task, and the
import face (probe/snapshot/backup).

### Migration ledger semantics

`PRAGMA user_version` is the ledger. The version read and all pending
migrations run inside one `BEGIN IMMEDIATE` write transaction: any
failure rolls everything back and the version does not advance, so a
kill mid-migration replays safely on reopen. This also closes the
concurrent-open race structurally: with the read outside the
transaction, a loser could read the old version and crash its DDL
against the winner's committed tables; inside the transaction the
loser blocks on the write lock (busy_timeout-bounded) and replays
nothing (SPEC §14.7 single-writer semantics). `busy_timeout` is set
before any other PRAGMA so concurrent opens wait instead of failing.
Refusing a newer database (`current > supported`) writes nothing:
open-phase PRAGMAs are connection-level configuration and the immediate
transaction rolls back — old binaries can be pointed at old ledgers via
`open_and_migrate_up_to`.

At-rest hardening: the database file and its `-wal`/`-shm` sidecars get
0600 on unix (best-effort, idempotent per open) — the database stores
plaintext cookies, tracker passkeys, and config_json credentials.

### Ledger v4: the one-shot state-CHECK tightening

Ledger v4 (pre-release; see `schema.rs`'s module docs for the freeze
posture) is a **one-shot rebuild**, not an expand-contract migration:
inside its single transaction it DROPs every table of the v1∪v2∪v3 union
— child tables before their FK parents (`torrent_file`/
`torrent_progress`/`tracker`/`recovered_layer` before `torrent`;
`media_format`/`media_track`/`media_segment`/`media_key` before
`media_task`; then `task_cookie`/`media_archive`/`http_task` and the v1
standalone tables) — and re-creates the full set with the one semantic
addition: the three persisted task `state` columns (`torrent.state`,
`http_task.state`, `media_task.state`) carry
`CHECK(state IN (<the unified 15-word vocabulary>))`.

Why a full DROP instead of rebuilding only the three task tables: the
open face runs `PRAGMA foreign_keys=ON` before the migration
transaction, and that pragma is a documented no-op inside a
transaction — parent tables cannot be dropped under live child FKs, so
a partial rebuild would need the exact FK deactivation that is
structurally unavailable. Dropping child-first sidesteps every FK
ordering hazard at the cost of the millisecond-scale double build on
the fresh-database path (v1..v3 create, v4 drops and re-creates).
Accepted pre-release only.

Semantics for existing databases (the hard premise of the
protocol/internal split plan): any `user_version` in {1,2,3} that opens
under the v4 binary is **rebuilt with its data cleared** — no dual
write, no backfill, no row salvage. This is a dev-database-only event:
the project is unreleased (no external databases exist), and the first
external release moves the freeze point from v4 to v5, after which
every persistence change must go through expand-contract migrations
and this one-shot path is retired. Rollback = revert the v4 commit
(the ledger returns to 3) plus restore the pre-upgrade backup
(`sqlite3 .backup`); the migration is atomic, so a kill mid-v4 leaves
the database at its old version untouched.

The CHECK word list is hand-written inside the v4 DDL string (the
ledger's `sqls` are compile-time constants; a whole DDL string is never
byte-equal to a status word, so the rpc leak counter does not see it —
guard counting rule). Single-source discipline: the word list is pinned
against `TaskPhase` (the `task_phase` derivation face) by tests — the
three tables accept exactly the 15-word union (INSERT/UPDATE pins),
reject out-of-domain words (`Paused`, `waiting`, `active`, …), and the
`sqlite_master` CHECK text is compared word-for-word against the
`TaskPhase` emission table; an old v3 database that opens under the v4
binary must land at `user_version = 4` with the CHECKs present and its
rows cleared. The v1/v2/v3 SQL texts are never edited (released
hash-recovery binaries occupy ledger v2); v4 carries its own full DDL.

### Ledger v5: bounded verified metadata cache

v5 adds `metadata_cache` and lookup indexes while preserving existing v4 task
rows. The cache is derived content, owned by the same PersistWriter connection:
at most 1024 entries / 64 MiB, with a 16 MiB per-entry limit and LRU eviction.
Full v1 and v2 identities have separate indexes; hybrid lookups require both.
On a miss, an indexed lookup can reuse a retained task's metadata BLOB.

The core verifies the original info bytes and complete metainfo structure before
caching, preserves raw info and validated piece layers, and drops outer trackers,
web seeds and task settings. Disk hits are verified again in `spawn_blocking`;
invalid derived entries are evicted without deleting task-owned metadata.
Cache writes are transactional and unchanged bytes are not rewritten. Hits
update recency only when reading disk; there is no periodic cache write task.
Removing a task does not delete its derived cache entry. Cache eviction never
changes task ownership or file selection.

### Pre-import backup anchor (`.v1.bak`)

The backup must run before the target's first open/migration so it
preserves the bytes a 0.1.x binary can open (the rollback target).
"Target offline" is enforced by WAL sidecar detection (`-wal`/`-shm`
present = a live local session or unclean exit), not by checkpoint
busy: idle-connection checkpoint busy semantics are unreliable across
platforms. With sidecars absent, a best-effort
`wal_checkpoint(TRUNCATE)` folds residual WAL in, then the copy is a
consistent single-file snapshot. Copy atomicity: temp file in the same
directory (rename stays filesystem-atomic) + fsync + atomic rename +
a directory fsync on unix; a torn copy can never reach the anchor name,
and an existing anchor is only kept after a readability check (never
overwritten — the earliest pre-import snapshot is the fork-era truth).

Read-only import faces use `immutable=1` URIs when sidecars are absent:
a plain read-only open would create `-shm`/`-wal` that a read-only
connection never cleans up, wedging the next import's offline probe.
URI paths are percent-encoded byte by byte (everything outside RFC 3986
unreserved plus `/`).

### Import dedup criterion

The single hit criterion is "row present + key equal": the http_task
row's `origin_fork_key` in config_json. The criterion lives and dies
with the row (no dead-marker form). `session_kv.imported_from` is only
a reverse-index fallback (old databases missing row keys, and the BT
import face); a fallback hit is liveness-checked against the present
task tables, and a hit whose referenced row is gone counts as
not-imported and is reported via `stale_imported`. With no task table
present at all, the hit is conservatively kept (dedup is the
conservative face of overwrite protection). BT/HTTP gid namespaces are
disjoint (top-bit namespace isolation).

## verified.rs

The verified write pipeline (`crates/taiji-store/src/verified.rs`):
block -> HashPool digest -> WrDiskCache buffer -> whole-piece
verification -> DiskWriter write (SPEC §4.5.2).

### Verify-before-disk (the discipline, vs aria2)

aria2's cache lets unverified data reach disk and verifies whole pieces
at completion (`BtPieceMessage.cc` `checkPieceHash` -> on failure
`clearAllBlock`); taiji tightens this: no byte reaches disk before
verification passes.

- A piece whose bytes are complete is verified at once: pass -> cells
  written in goff order; fail -> cells dropped and the piece resets for
  refetch (`PieceFailed`).
- Cache overflow evicting an unverified piece = destroy-and-refetch
  (`PieceAbortedUnverified`), never a write.
- Therefore only verification-passed bytes ever appear on disk.

The unverified spill area (`crate::spill`, attached by opt-in) is the
single sanctioned bypass of that invariant: a cache-overflow victim is
staged in the sidecar (the main data files still hold zero unverified
bytes) and read back at assembly; outside the budget it falls back to
destroy-and-refetch (same semantics).

Download-path cross-validation: aria2 `BtPieceMessage.cc` (slot match
-> snubbing cleared -> duplicate block skipped -> cell into cache ->
completeBlock -> updateHash -> whole-piece verification). Slot matching
and duplicate-block dedup belong to the RequestBook/caller; this module
owns verification and the write discipline.

### SharedDiskWriter: write de-serialization (lock domain split)

The old shape `Arc<Mutex<Box<dyn DiskWriter>>>` put every face's disk
writes behind one global lock, serializing away the gains of
worker-parallel verification on the write half (a profile showed the
mutex wait as a large share of the verify-pool write half). The current
shape splits locks by domain:

- Positioned-write hot path (`write_batch`): the concurrent face (unix
  and `BH_PARALLEL_WRITES`) executes under the read lock — `pwrite` at
  different offsets on one fd is safe (POSIX). Cross-validation:
  libtorrent's mmap backend writes are plain memcpy into the page cache
  with no write-back queue (`mmap_disk_io.cpp`), and its pread backend
  merges contiguous blocks into single pwritev calls
  (`visit_block_iovecs`) — the same zero-global-write-serialization
  philosophy in equivalent form under verify-before-disk. Piece goff
  spans never overlap (pipeline invariant) and one worker writes a
  piece's cells in goff order, so per-piece write order is unchanged;
  interleaving happens only at piece boundaries.
- Non-write operations (`with_exclusive`): open/create/truncate/
  allocate/fsync/fence points keep the exclusive lock (fsync semantics
  unchanged, no crash-recovery regression).
- Platform domain: Windows' write hot path always takes the write lock
  (`seek_write` is not thread-safe).
- `BH_PARALLEL_WRITES` defaults off (a measured decision: concurrent
  same-file pwrite pushes the wait into the kernel, and per-file kernel
  contention loses badly to the user-space whole-piece mutex; Linux and
  multi-file faces unmeasured — measure before modify). The concurrent
  face is retained for explicit opt-in measurement.

### BH_WRITE_COALESCE (write-path batching)

When on: (1) a completed piece writes its adjacent contiguous cell runs
as one vectored write (unix `pwritev`, zero-copy iovecs); (2) adjacent-
goff completed pieces within one pipeline batch are stitched into a
single `write_batch`. Bytes/coordinates/order are exactly the per-cell
writes; only syscall granularity changes. The pipeline grouping face
and the `VerifiedWriter` write face must share one decision source
(`write_coalesce_enabled`): grouping and vectorization are driven by
the same switch; when off, no grouping happens.

### Eviction observability

Under verify-before-disk, eviction destroys data + digests together (it
cannot flush). That event used to be purely silent — silent discard of
nearly all in-flight bytes with zero warnings is one link of
progress-stall loops — so the observability face came first: eviction
registration (`take_evicted`), count + byte totals
(`evicted_unverified`, `evicted_unverified_bytes`), and sampled
warnings (the first 10 individually, then every 100th). With spill
enabled the count is the "residual eviction count";
`spill_fallback_destroy_bytes` splits budget-side destruction (FIFO
displacement victims + not-absorbed entries) from status-quo evictions
and read-back failures.

### v1 verification decoupled from arrival order

Completion is judged by byte counting (`piece_complete`), and
verification moves to the completion path, per format. A v1 digest
accumulated in arrival order would necessarily misalign for
out-of-order arrival (the real-swarm norm: multiple peers, window
slides, late resends); the original implementation misjudged correct
pieces as PieceFailed forever. Upstream cross-validation `Piece.cc`:
`updateHash` order-gates (`begin == nextBegin_`) and completion
recomputes via read-back (`updateHashWithRead`). This repo forbids
unverified bytes on disk, so the equivalent is reading back the cache
cells (goff-ascending, non-overlapping), assembling, and taking one
SHA-1 (`piece_matches`); when the cells tile the piece span seamlessly
the SHA-1 is streamed per cell (byte-identical input, no whole-piece
copy). v2 block hashes are positioned by in-piece order — naturally
out-of-order safe.

### Duplicate delivery is benign

Duplicate blocks are the norm on real swarms (timeout resends, endgame,
fast-extension double sends, late blocks), so fatalizing would turn
data-correct tasks into explicit failures. aria2 filters upstream
(`BtPieceMessage.cc` `piece->hasBlock`, a per-piece block bitfield) and
`Piece.cc`'s `assert(rv)` is only a backstop; here the last line of
defense converges into one benign outcome (`DuplicateDropped`),
observable via `duplicate_drops` with sampled logging. Red line: only
full coverage drops; partial overlaps carry new bytes and fall into the
append/residual-cell semantics, ending in the `cache_data` same-goff
refusal backstop — un-cached residuals are then caught by the
completion hash gate (no silent data-error swallowing).

### Failed-piece smart-ban evidence

`failed_block_digests` snapshots per-block SHA-1s of a failed piece
(v1 only; v2 block-level verification attributes failures naturally;
libtorrent `smart_ban.cpp` returns nullptr from the plugin when
`has_v2()`). Consumption timing: after `verify() == Ok(false)`, before
the job is dropped. libtorrent's `on_piece_failed` rereads the disk
because its data already landed; here the failed piece exists only in
the job's memory cells, so the structural equivalent is recomputing
inside the assembly buffer — equivalent evidence, one less disk IO.
