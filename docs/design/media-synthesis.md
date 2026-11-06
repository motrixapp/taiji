# taiji-media synthesis line (design record)

Design record for the media synthesis line: the local per-track
playlist rewrite, the native write side + its qualification-gate
matrix, the ffmpeg fallback channel, the VTT sidecar, the three
prechecks, and the Processing→Verifying pipeline, as specified by the
media-line specification. The session/RPC mount over all of this is
the orchestration mount.

## 0. Carrier decision (as amended 2026-10-28)

The originally named native carrier `mp4ff` **does not exist in the
Rust ecosystem** (Eyevinn/mp4ff is a Go library; crates.io never
published it — docs.rs 404; verified 2026-10-28 during the design
review). The adjudicated replacement: a **self-built minimal ISO-BMFF
write side, zero new dependencies**. The nearest crates.io candidate (`mp4`
0.14, MIT) was rejected for its write-side codec whitelist (only
AvcConfig/HevcConfig/Vp9Config/AacConfig/TtxtConfig stsd entries can
be written — AC3-family HLS audio would degrade) and its missing
covr/chpl faces; the fold logic (moof/trun → stbl) had to be written
either way.

Codecs: `bmff.rs` (read/fold) + `mp4write.rs` (progressive writer).
The amended carrier property — **stsd passthrough verbatim, any
codec** — is pinned by the probe's byte-equality assertion.

Fold base resolution (ISO/IEC 14496-12 §8.8.7; hardened across
review rounds 2-3): the fold consumes the caller's **exact
segment-file spans** (`bmff::SegmentSpan` — the rewrite entries'
`archive_offset`/`archive_len`, i.e. the ledger data the pipeline
already holds) — **no boundary heuristics**. The round-2 heuristic
("a new file opens after each mdat") was itself defeated by the
round-3 shape: one legal multi-fragment segment FILE
(moof1/mdat1/moof2/mdat2) with explicit bases — moof2's inferred
"file start" overshot by moof2.start, shifting its samples into
mdat2's payload slack → `Ok` with silently wrong bytes. Under the
exact-span contract: `default-base-is-moof` anchors at the moof's
own archive offset; an **explicit `base-data-offset` is
segment-file-absolute**, resolved as the enclosing span's
`archive_offset` plus the file-relative value (correct for both
per-segment concatenations and multi-fragment single files).
Consistency defenses, all fail-loud under `taiji.media.staging`:
every span must be non-empty, inside the archive and **aligned with
the box structure** (span start = a box start, span end = a box
end); a moof outside every span is a ledger/archive disagreement;
every sample span must fall inside an mdat payload **within its own
segment span** — the silent-misread shapes of both review rounds are
refused. Regressions:
`fold_explicit_base_two_segment_archive_bytes`,
`fold_explicit_base_styp_preamble`,
`fold_refuses_cross_segment_mdat_landing`,
`fold_multi_fragment_file_explicit_base_exact_offsets`.

## 1. Per-track playlist rewrite (`rewrite.rs`)

Input: the source playlist plus the ledger rows (plaintext
`seg_len`). Product per track: `local-<label>.m3u8` in staging + the
typed `TrackRewrite`.

Form (the golden face):

* every segment line names the archive file with an explicit
  `#EXT-X-BYTERANGE:<seg_len>@<archive_offset>` — offsets are the
  cumulative Σ plaintext lengths in playlist order; whole-resource
  source segments gain an explicit range too (the archive-interval
  form);
* **plaintext form**: no `EXT-X-KEY` lines at all (not even a
  synthetic `METHOD=NONE`) — the archive holds decrypted bytes, the
  playlist is semantically METHOD=NONE everywhere; key material
  lives only in `media_key` (keys-never-in-playlist discipline);
* `EXT-X-MAP` → `init-<label>-<n>.mp4`, re-emitted
  on every MAP change (the first segment included); the MAP's own
  BYTERANGE attribute is dropped (the file holds exactly the init
  bytes);
* structural tags preserved: VERSION/TARGETDURATION/MEDIA-SEQUENCE
  (identity anchor)/DISCONTINUITY-SEQUENCE/PLAYLIST-TYPE/
  INDEPENDENT-SEGMENTS/`EXT-X-DISCONTINUITY` per segment/ENDLIST.
  Unknown tags are dropped (the closed form; the forward-compat
  ignore face belongs to the source parser);
* `source.m3u8` untouched (the raw archive).

Consumption faces:

| face | input |
|---|---|
| native channel | the typed entries + archive + init files directly (the m3u8 text is a product, not a native input) |
| ffmpeg fallback | the `local-<label>.m3u8` **is** the HLS-demuxer input (`-protocol_whitelist file -allowed_extensions ALL -i local-v.m3u8`) |
| ffprobe dual-run | probes the synthesized **product**: duration ∈ ΣEXTINF ×[0.98,1.02], stream count = selected content tracks |

## 2. Native write side — the qualification-gate matrix

Matrix of record (measured by `tests/native_matrix.rs`: construct a
source, write it natively, assert by read-back (probe) plus an ffprobe
dual-run when a local pair exists; every fixture carries real box grammar — init moov + moof/
mdat pairs with default-base-is-moof/tfdt/trun):

| item | verdict | carrier note |
|---|---|---|
| tx3g embedded subtitles | **PASS** | `tx3g_track_spec` (2-byte-length text samples, CR line breaks, empty-filler continuity) + the `tx3g` stsd entry; VTT markup stripped at conversion |
| covr cover art | **PASS** | `udta.meta.ilst.covr.data`, well-known type 13 (JPEG)/14 (PNG) — the iTunes meta form with a real `hdlr` box |
| chpl chapters | **PASS** | Nero-style: version 1 + reserved u32 + count u8 + per chapter (u64 **100 ns** timestamp + u8 length + UTF-8 title). Unit convention note: GPAC/Nero uses 100 ns; matrix capability face only — product wiring lands later |
| faststart | **PASS** | `ftyp, moov, mdat` by construction; chunk offsets resolved in a two-pass serialize (stco→co64 switch above 4 GiB, re-measured) |
| multi-track merge | **PASS** | N traks over one mdat, one chunk per track; stsd passthrough byte-pinned by the probe |
| multi-Period concat | **PASS** | same-stsd sample-stream concat into one trak (the same-shape precondition; a codec change across periods cannot live in one progressive stsd → fallback, see §3) |
| MKV | **degraded → ffmpeg fallback** | MP4-family-only writer decision: the writer emits the MP4 family only; the verdict routes MKV to the fallback (`-f matroska`, no faststart), `ffmpeg_missing` at start when no pair |

Native-support verdict (`synth::native_support`): MP4 output + fMP4
inits (a TS/raw line — no init — is 0.4's native face) + one stsd
shape per track across MAPs + single-trak inits. Anything else is a
fallback form.

## 3. ffmpeg fallback channel (`ffmpegmux.rs`)

A **consumer of the shared ffmpeg infrastructure** — discovery, the
`-version` LGPL gate, the capability table and the whole
`MediaCommand` orchestration (argv array, absolute paths, explicit
`-f`, piped trio, watchdog, process limits) are reused; no second
process-governance line. Trigger conditions: native-unsupported
forms + matrix-degraded items + the user-explicit face
(`--media-muxer=ffmpeg`) + the native channel's own failure (the
dual-channel net, both directions).

**`--media-ffmpeg-path=auto` probe failure × degraded item
behavior**: a Required form with no usable pair refuses with
`taiji.media.ffmpeg_missing` **before any synthesis work** (and, in
the task activation chain, before any segment traffic); an Optional
form proceeds native-only with a warning (the net is absent,
surfaced in the report).

## 4. VTT sidecar (`vtt.rs`)

Cue-level parse (header/ids/timestamps with `.`/`,` ms separators,
NOTE/STYLE skip, payload caps) → splice → render. **Timeline
continuity rule** (deterministic, the yt-dlp detection form): a
segment whose minimum cue start ≤ accumulated position + 1 s is
treated as **relative** to the segment start and shifts by the
accumulated ΣEXTINF position; cues beyond that pass through
(absolute timeline). X-TIMESTAMP-MAP is not remapped in 0.3 (header
lines skipped; noted). **DISCONTINUITY does not reset** the sidecar
timeline — the gap bridges via the next segment's EXTINF
accumulation.

**Every sidecar failure degrades** (§6 grading policy: degraded completion +
warning, never the both-channels state, never a task Error):
unparseable segments, a non-UTF-8 archive, a ledger span outside the
on-disk bytes (truncated staging — the content tracks'
`rewrite_total == archive.len()` cross-check has no subtitle
equivalent at the channel layer, so the bounds check lives here) and
the sidecar write itself. The step runs **before** the product
rename, so no sidecar outcome can leave a "renamed product + task
Error" state behind. Fuzz target `vtt_splice` (red line: the
splice re-bases timestamps).

## 5. The three prechecks (`precheck.rs` + `synth.rs`)

① **disk** — peak ≈ 2× product + 64 MiB margin (the standard
PRECHECK_MARGIN form); product estimate = Σ staged archive bytes
(remux, no re-encode). Free bytes via rustix statfs (unix); other
platforms / stat failures = **optimistic pass** (§7); ENOSPC during
synthesis surfaces through the existing `taiji.media.staging` face.

② **both-channels terminal** — native + ffmpeg both failed = task
Error: the compound error embeds both channel texts under the
`taiji.media.staging` annotation face (no new error code — a
dedicated `synthesis_failed` code remains an error-registry
candidate); staging/archives **retained**,
the failed `.part` removed; Processing re-run is the retry
(pinned by the e2e's corrupt→error→repair→converge sequence).

③ **sidecar start** — `fallback_need` (Required/Optional/None) ×
pair presence: Required + absent = `ffmpeg_missing` at start (zero
segment traffic — the task activation chain consumes the same
decision before the download starts); Optional + absent =
native-only warning. Wiring into the task activation chain is the
orchestration mount.

## 6. Verification + phases (`probe.rs` + `synth.rs`)

Processing → Verifying → Done, recorded as `Phase` entries (the
`phaseChanged` payload basis). The native probe is the independent
key assertion: two invariant sets —

* **structural** (always): ftyp/moov/mdat layout (moov before mdat
  = faststart; `free` boxes tolerated), mvhd duration ±2 %, per
  track tkhd/hdlr kinds, stts/stsz/stsc count consistency, chunk
  offsets inside the mdat, Σ sample sizes == mdat payload, stss
  order/range;
* **native passthrough** (native channel only): stsd byte-equality
  vs the source init (the any-codec passthrough proof), mdhd
  timescale equality, the writer's single-chunk layout. ffmpeg
  products legitimately rebuild stsd/stbl in their own shape.

ffprobe dual-run runs whenever the fallback face is present
(duration ±2 % + stream count). The native channel is in-process
computation: an interrupted run re-runs whole
over the same staging — no child to kill on that path. The VTT
sidecar step resolves every degradable face **before** the product
rename (§4); the product lands as `<out>.part` and renames only
after verification passes and the sidecar has settled; the
DB-journal completion face belongs to the orchestration mount.

## 7. Memory posture (0.3, on record)

Archives and products are processed whole in memory (`&[u8]` /
`Vec<u8>`), bounded by the staging quota semantics. A streamed
fold/write is a follow-up if the remux-throughput gate
(≥ sequential-write 80 %) or the RSS gate demands it.

## 8. Option faces wired (registration lands with the RPC mount)

`--media-ffmpeg-path` (`auto|<dir>|path:<dir>`),
`--media-output-format` (`mp4|mkv`), `--media-muxer`
(`native|ffmpeg|auto` — the user-explicit fallback trigger face).
All parse strictly (require_equals discipline; trim tolerance per
the earlier media option faces).
