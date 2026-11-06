# Piece verification design notes (BEP-52 merkle)

Distilled upstream-reference notes behind the v2/hybrid piece verification
code in `crates/taiji-bt` (file tree parsing, sanitization, `piece layers`
validation, torrent creation).

## File tree parsing (`crates/taiji-bt/src/filetree.rs`)

Rules quoted from the current BEP-52 text (bittorrent.org
`beps/bep_0052.rst`).

### File tree shape

- `file tree` is a tree of "dictionary keys represent UTF-8 path elements".
  A zero-length key (`""`) is the file marker ("Entries with zero-length
  keys describe the properties of the composed path at that point"); its
  value is `{length, "pieces root"?}`.
- The tree root itself must not be a file ("`file tree` root dictionary
  itself must not be a file", i.e. no `""` at the root level).
- The presence of `length` declares a file ("it must not have any sibling
  entries"): a file marker `""` must not coexist with other keys.
- `pieces root`: "For non-empty files this is the root hash of a merkle
  tree"; empty files must not carry it (the official creator writes only
  `length` for length==0). A v2 non-empty file must have a root; a missing
  root is a load rejection.
- File order = file tree pre-order (DFS) order ("occurs in the same order
  as in the file tree"). The official creator requires directory entries
  handled in sorted order; bencode dict keys are stored byte-sorted, so the
  two agree.
- Unknown/future keys (siblings of `pieces root`) are ignored for forward
  compatibility. Extra `piece layers` entries matching no file are also
  ignored (not forbidden by the BEP).
- Empty directories: not forbidden by the BEP; libtorrent also preserves
  them. They produce no `FileEntry`.
- `.pad` (BEP-47) never appears in a v2 file tree (padding is a v1-layout
  concept; the official creator writes it only into the v1 `files` list).

### Path sanitization

"Implementations must be prepared to sanitize them. On most platforms path
components exactly matching '.' and '..' must be sanitized since they could
lead to directory traversal attacks." This implementation rejects instead of
rewriting: an explicit error is preferred over guessing user intent.

Rejected forms: `.`, `..`, any `/` (multiple layers in one key breaks the
"key = path element" model), control characters (`char::is_control`, i.e.
C0 / DEL / C1), display-spoofing / hidden-injection code points (12 bidi
overrides + 3 zero-width + 2 line/paragraph separators, single source
`taiji_io::text::is_spoofing_char`), components over 255 bytes, invalid
UTF-8, Windows reserved device names (including `nul.txt` forms), and the
three Windows rules below. Control characters are a log/alert injection
surface (`\n`/`\r` fake lines) and are illegal names on Windows
(0x01-0x1F), so a remote peer could otherwise kill a whole task; MS Naming
Conventions reserves the whole 0x00-0x1F range. Zero-width characters make
`evil\u{200B}.exe` look identical to `evil.exe`; U+2028/U+2029 are residual
log-line injection and are covered by neither `is_ascii_control` nor
`is_control`.

The 255-byte component cap is the strictest cross-platform NAME_MAX (Linux
ext4 255 B, macOS APFS 255 UTF-8 bytes, Windows without long paths 255
UTF-16 units). A longer component hits ENAMETOOLONG on strict filesystems,
failing the first file create and rejecting the whole task. Only `>`
rejects; exactly at the cap is legal. This is deliberately a rejection face
(names declared in the user's torrent are never silently rewritten), unlike
the 254-byte truncation in naming.rs. The core `session::actor` `--out`
intake face uses the same cap.

### Windows component rules

Torrents are cross-platform artifacts: a key accepted on a POSIX host may
later be written to a Windows volume, so these rules apply unconditionally
on all platforms, like the existing reserved-name check.

- Backslash: libtorrent `torrent_info.cpp` `filter_path_character` filters
  `/` and `\` unconditionally on every platform ("forward- and backslash
  are filtered unconditionally and separately from this function") — but
  that is write-side stripping; this parser rejects instead. MS "Naming
  Files, Paths, and Namespaces", Naming Conventions: "You cannot use a
  backslash in the name for the actual file or directory"; UNC names
  "always start with two backslash characters" — `\\` is namespace path
  syntax, never a name component.
- Colon: libtorrent `valid_path_character` (Windows invalid set
  `?<>\"|\b*:` includes ':') and aria2 `util.cc` `escapePath` (MinGW
  `WIN_INVALID_PATH_CHARS` includes ':') both treat ':' as unusable in a
  name. MS Naming Conventions reserves ':'; `C:tmp.txt` resolves
  drive-relative ("tmp.txt in the current directory of drive C"), and a
  colon also opens an NTFS alternate data stream (`file:stream`), so any
  ':' is rejected, not just the `X:` form.
- Trailing dot/space: MS: "Do not end a file or directory name with a space
  or a period. Although the underlying file system may support such names,
  the Windows shell and user interface does not." Win32 namespace
  normalization strips trailing dots/spaces, so names silently drift on
  disk (`...` -> `..`, `nul.` -> `nul` device). libtorrent
  `torrent_info.cpp` (TORRENT_WINDOWS branch) strips them on write ("These
  aren't allowed in filenames on windows"); since this repo forbids
  silently rewriting file names on write, it rejects at parse time. aria2
  has no rule here (`detectDirTraversal`/`escapePath` ignore trailing
  dots/spaces).
- Reserved device names: only the stem before the first '.' is checked —
  MS: "avoid these names followed immediately by an extension; for example,
  NUL.txt and NUL.tar.gz are both equivalent to NUL".

### `meta version` and `piece length`

- "Implementations must check this field first": the version gate precedes
  all other structural validation. Present and not 2 is a version error
  before any other check; `file tree` present without `meta version` is
  invalid (the version semantics cannot be asserted).
- Per-face `piece length` constraints (BEP-3 vs BEP-52): BEP-3 only asks
  "number of bytes in each piece", so the v1-only face accepts any positive
  integer and legacy torrents with 20000, 8192 etc. stay legal. "It must be
  a power of two and at least 16KiB" (BEP-52 `piece length` section)
  constrains the v2 merkle block-leaf math; a hybrid shares the same
  `piece length` key feeding the v2 face, so the BEP-52 constraint applies
  there too — decided by key presence inside the v1 parser, with no
  ordering assumption about the caller running v2 parsing first.
- Engineering cap of 16 MiB on both faces: BEP-3/BEP-52 set no upper
  bound, but piece length is the common multiplier of webseed whole-piece
  fetch buffers, in-flight verify (workers x queue x piece length) and the
  fixed-size write cache (2 x peers x piece length); a legal-in-u32 4 GiB
  piece would mean GiB-scale RSS per task. qBittorrent's creator caps at
  16 MiB, libtorrent is the same order, and existing torrents above 16 MiB
  are practically nonexistent.

### `piece layers` load-time validation

- Keys are merkle roots; values are the ordered concatenation of the layer
  where each hash covers `piece_length` bytes. "A torrent is not valid if
  ... the contained hashes do not match the merkle roots or are not from
  the correct layer." Files <= piece size have no entry.
- At load time each file's layer is re-derived and checked (BEP-52 infohash
  section: "must also check that the `piece layers` hashes ... match the
  `pieces root` fields"); the math lives in `taiji_store::merkle`.
- Missing vs corrupt split (SPEC §4.2 missing-layer degradation):
  - entry **missing** for a multi-piece file with an intact root: degrade
    to a `layer_missing` marker and keep loading; hash recovery repairs it
    from the swarm. libtorrent `torrent.cpp` `initialize_merkle_trees`
    does the same (`valid = false; continue`). The pieces root inside
    `info` is the trust anchor, so SHA-256 convergence guarantees a
    recovered layer is verifiable;
  - entry **present but invalid** (count or root mismatch): hard reject —
    corrupt metadata, not missing. libtorrent
    `torrent_invalid_piece_layer` is likewise a hard error;
  - root missing: hard reject (`MissingPiecesRoot`) — no trust anchor,
    mathematically unrecoverable, never enters recovery;
  - file <= piece size with no entry: spec behavior, never flagged
    (recovery is never triggered for it).

## Torrent creation (`crates/taiji-bt/src/creator.rs`)

The write-side mirror of the parse side: every generated torrent must pass
`filetree::parse` + `filetree::parse_v1_files` + the piece-layers
re-validation losslessly. Hash primitives reuse the `taiji_store::merkle`
public API (bt -> store, one way); both sides share the same BEP-52 tree
shape (16KiB leaves, zero-leaf padding to a power of two, balanced
piece-root layer). The official-creator vectors in merkle.rs serve as the
dual reference: parsing verifies "read roots", creation generates "written
roots".

### BEP-52 output rules

- `meta version: 2` implies v2 semantics; `piece layers` lives at the top
  level (outside info), key = 32B raw merkle root ("All hashes are stored
  in their binary format"), value = the ordered concatenation of the layer
  where each hash covers piece_length. Files <= piece size have no entry;
  with no entries at all the whole field is omitted.
- Identical files always produce the same root hash ("identical files
  always result in the same root hash"), and dict keys are unique, so
  same-root entries collapse to one (libtorrent `create_torrent.cpp`
  `file_pieces[m_fileroots[fi].to_string()]` writes by key and
  overwrites). The layer is a pure function of (content, piece length), so
  collapsing is lossless.
- File tree: "root dictionary itself must not be a file" — single-file
  torrents wrap the file under its name as the key (libtorrent
  `create_torrent.cpp` does not strip the name prefix for single files;
  the official `test/test_torrents/v2_only.torrent` tree is
  `{"test1MB": {"": ...}}`).
- Empty files carry only `length`, no `pieces root` ("For non-empty
  files ...").
- Hybrid: v1 keys (`pieces` + `files`/`length`) and v2 keys coexist in the
  same info; both infohashes are computed over the raw info byte slice,
  located by `bencode::decode_with_info_span` on the produced bytes — no
  decode->re-encode round trip.
- v1-only: no `meta version`/`file tree` (the BEP-3 shape).
- attr strings are emitted in `p,h,x,l` order (libtorrent
  `create_torrent.cpp` `add_file_attrs`); single-file torrents write the
  v1 attr at the info top level, multi-file torrents inside each `files`
  entry. `private: 1` (BEP-27) is passed through.

### BEP-47 padding on creation

Pads are synthetic files that align the following file to a piece
boundary: `attr: "p"`, recommended path `[".pad", "<N>"]`, content counted
as all zeros in the v1 piece hashes. Pads go only into the v1 `files`
list, never the v2 file tree. Divergence from libtorrent
`src/file_storage.cpp` canonicalize: libtorrent 2.0.8+ also appends a
trailing pad (aligning EOF to a piece boundary); this module does not —
BEP-47 defines only following-file alignment, and the repo's hybrid
fixture (generated by the official creator algorithm, interop-verified
against libtorrent 2.1.1.0) has no trailing pad. No pad is inserted before
the first file (offset 0 is aligned) or after the last (no following
file). Input entries carrying attr 'p' conflict with automatic planning
and are rejected; symlinks without `symlink path` support are rejected.

### Input model and execution

The caller provides an ordered file list (v1 layout order) + on-disk
source paths + piece length + target form; directory scanning, announce
editing and CLI/RPC wiring are out of scope. A file path that is a prefix
of another is rejected (the v2 file tree cannot represent a file and
directory with the same name; same verdict as libtorrent
`torrent_inconsistent_files`). Hashing runs in `spawn_blocking`, one
streaming pass: the same 16KiB block reads feed both the v1 global SHA-1
(with pad zero spans hashed per BEP-47) and the v2 per-file SHA-256 block
hashes; large files never load into memory.
