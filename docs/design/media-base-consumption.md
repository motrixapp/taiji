# taiji-media ↔ taiji-http base consumption record

Design record for the media line's consumption of the base crate. The
media layers consume the foundation crate's published faces only — every
scheduling/transport capability the media line uses is a published base
face, zero private re-implementation. A base face found **not to fit**
is a base bug: the wiring stops and the fix goes through the base
crate's own change path — no shim, no fork, no media-private scheduler.

## Consumption list (layer by layer)

### Shared faces (both layers)

| Base face | Media consumption site |
|---|---|
| `HttpClient` (`get`/`get_range`, manual redirects, identity encoding) | manifest/playlist/init-section fetches (`mediadl::http_get_bytes`, `trackdl::fetch_whole_or_range`); the (a)/(b) segment fetches ride the transports below |
| `RequestCtx` | the per-source request context threaded through every transport call |
| `taiji_http::reqwest` re-export | RFC 3986 relative-URI resolution against the manifest base (a minimal base face — one type re-export, no protocol logic) |
| `PartFile` (+ `PartOpenPolicy`/`FileAllocation`) | per-track archives: positional (a)-layer writes, ordered-append (b)-layer writes, fsync-before-ledger ordering, symlink-refusal and create/reuse decisions (`.part` semantics reused verbatim for the archive reuse-by-length decision) |
| `transport::HttpRangeTransport` / `transport::HttpBodyTransport` | the only HTTP protocol implementations the media line touches: Range GETs ((a) spans, BYTERANGE sub-ranges inside (b), init sections with BYTERANGE) and whole-body GETs ((b) segments, init sections); the 206-echo validation, over/under-send read loop and stream caps are the base's |
| `error::HttpError` | transport failure surface carried into track states verbatim (redacted) |

### (a) known-length layer (BYTERANGE tracks)

| Base face | Media consumption site |
|---|---|
| `grid::BlockGrid` (+ `MIN_BLOCK_SIZE`/`DEFAULT_BLOCK_SIZE` domain) | the virtual byte space's persistent bitmap; resume seeding from the persisted segment prefix (the core's resume pattern, http_task.rs's grid preload) |
| `scheduler::GuidedPlan`/`GuidedConfig` | dynamic allocation over the virtual space with the resume predicate consumed at build time |
| `coordinator::spawn_dynamic` + `CoordinatorHandle` (`acquire`/`complete_block`/`abandon`/`extent_succeeded`/`runtime_stats`) | the single decision point: extent allocation, block-completion adjudication (first-report-wins), failure recycling via Abandon |
| `aimd::AimdConfig` + `pool::WorkerPool` + `worker::supervisor_directives` + `worker::last_complete_block` | the AIMD connection execution ring: grow/shrink directives consumed by the track driver's launch loop; whole-block completion catch-up per extent |
| `limiter::ThrottledSink::with_rate_reporter` (pass-through `HttpLimiter::new(None)`) + `RateSampleReporter for CoordinatorHandle` | per-write rate samples feed the coordinator's EWMA/AIMD inputs — the base's own observation face, zero media instrumentation |
| `traits::SegmentSink` | the media archive sink (`write_at` → positional archive write; `complete_block` → live counter) + the span `ShiftSink` (virtual↔resource offset mapping — media glue over the base transport, not a protocol fork) |

### (b) unknown-length layer (whole-segment tracks)

| Base face | Media consumption site |
|---|---|
| `sequence::run_sequence` + `SequenceConfig`/`SequenceSink`/`TransportFor` (base crate) | the URI-sequence scheduler/worker wiring behind `SegmentPlan::UriSequence` (the media spec's sequence-engine item): bounded lookahead window, reorder buffer, ordered delivery, per-segment retry budget, resume prefix predicate |
| `sequence` named anchors (`LOOKAHEAD_SEGMENTS_PER_WORKER`=8, `LOOKAHEAD_BUFFER_CAP_BYTES`=32MiB, `MAX_SEGMENT_BUFFER_BYTES`) | spec constant anchors, asserted by tests on both sides |
| `traits::SegmentTransport` via `HttpBodyTransport`/`HttpRangeTransport` per index | whole-resource segments and BYTERANGE sub-ranges inside a sequence (the `RangeOnceTransport` wrapper rewrites the engine's EOF-sentinel extent to the segment's real range — an adapter around the base transport, not a reimplementation) |

### Persistence faces (store side)

| Store face | Media consumption site |
|---|---|
| `PersistWriter` jobs `UpsertMediaTask`/`ReplaceMediaTrack`/`LoadMediaTracks`/`DeleteMediaTask` | the `MediaLedger` trait's sqlite implementation; FK-anchored rows, single-transaction segment-set replacement, recovery read |
| v3 DDL (`media_task`/`media_track`/`media_segment`) + `validator_digest` column | the ledger schema the media line uses; segment identity = absolute media sequence |

## Deviations and honest boundaries (not shims)

1. **Media worker loop** (`trackdl::launch_grid_worker`): the base's
   `launch_worker`/`WorkerRig` is URI-source-bound and requires the
   full core host assembly (telemetry/HostCap/FTP config); the media
   track runs a compact worker speaking the *same*
   `CoordinatorHandle` protocol. **Steal requests are not issued**:
   without the base's `ExtentHeartbeat` ring there is no stall
   evidence to grant one (the coordinator's decision face denies
   evidence-less requests by design); liveness rides the
   failure→Abandon→retry path. Full worker-ring parity (heartbeat
   stealing included) belongs to the later orchestration mount; the
   coordinator-side steal machinery itself is exercised by the base's
   own tests.
2. **Span splitting** (`layout.spans` ∩ extent): the ≤8 merge is a
   transport-layer concern (one GET per maximal same-URI contiguous
   span); extents stay byte-granular. A span crossing an extent
   boundary yields one GET per (span∩extent) piece — the merge unit
   is the GET, never the extent.
3. **`RangeOnceTransport`** (b-layer BYTERANGE adapter): rewrites the
   sequence engine's EOF-sentinel extent to the segment's real range
   and delegates to the untouched base Range transport.
4. **Sequence engine placement**: implemented inside the base crate
   (`sequence.rs`) — a to-build item, not an existing capability,
   implemented inside the taiji-http base crate, not as a media-line
   private path. The 0.3.0 re-plan proposal (2026-10-28) is pending
   adjudication; if approved it carries this sub-item forward, and
   either way the delivery is the same base-crate wiring.
5. **Error codes**: `cross_volume`/`staging_quota_exceeded` are the
   inherited SPEC family; `taiji.media.staging` (staging I/O with no
   more precise inherited code — `staging_quota_exceeded`/
   `cross_volume` each have precise meanings, and `taiji.http.disk`
   is the HTTP task family's namespace) was registered before merge
   in the media error-code registry. Segment-fetch failure texts ride
   track-state payloads, not new codes.

## AES-128 line additions (keys/decrypt/SSRF)

The AES-128 line adds these base consumptions (same discipline):

| Base face | Media consumption site |
|---|---|
| `HttpClient::get` + `RequestCtx` | key-body fetches (`keys::fetch_key`) — the task's request context rides the base client verbatim; per-attempt retry driven by the consumer (the base never retries implicitly) |
| `taiji_io::dns::SharedDns::shared_default` + `resolve_for_transport` | the SSRF resolved-IP layer's production resolver (`ssrf::ProductionSsrfResolver`) — the same process-shared, TTL-cached resolver the base's redirect guard and transports use, so the SSRF decision and the actual connection see one view |
| base redirect IP hygiene (`redirect_guard`, wired inside `HttpClient`) | the SSRF line's **redirect-endpoint** coverage: a non-restricted initial URL plus a restricted hop target is refused by the base (`HttpError::RedirectToRestrictedIp`); a restricted initial (a localhost/LAN media source under `--media-allow-private-key-url`) passes every hop. The media-owned faces cover the **initial** target only (`ssrf::decide_uri` — scheme whitelist + literal + resolved layers). Registered residual (deliberate, no base fork): with the flag on, a *public* key/segment host redirecting into a private network remains refused by the base guard — the flag's contract is "my media source is on the private network", not "any public host may pivot private mid-chain" |
| `PartFile::write_all_at` + raw `File::set_len` | the (a)-layer decrypt rewrite pass (ciphertext fetched positionally through the grid, then rewritten as plaintext in place and truncated to Σ plaintext — the same faces `TrackArchive` already used) |

Media-owned pure faces (no base dependency): the AES-128-CBC decrypt
core (`decrypt`), the `data:` URI parser (`datauri`), the SSRF
decision function + injected resolver trait (`ssrf` — the IP
classification mirrors the base `redirect_guard` list deliberately;
the base classifier is `pub(crate)` and routing a visibility change
for it would be a base-crate change — a documented mirror was the
lower-cost honest choice).

### Deviations and honest boundaries

1. **`ssrf_blocked`/`key_invalid` codes**: registered before merge in
   the media error-code registry (the SSRF line's refusal face for
   key URIs and media-segment/init URLs, and the key-material face
   for data: oversize/wrong-length/bad-KEYFORMAT/fetch failures);
   `segment_decrypt_failed` is the inherited media error family code
   now wired.
2. **(a)-layer encrypted tracks** are downloaded as ciphertext through
   the unchanged grid pipeline, then decrypted by a whole-track
   rewrite pass (plaintext lengths strictly trail the ciphertext
   offsets, so the in-place forward rewrite is safe); the (b) layer
   decrypts at the delivery boundary (decrypt-as-consume). The wire
   merge is untouched — decryption splits at segment boundaries with
   per-segment IVs (a wire merge does not imply a decryption merge).
3. **Mock-e2e migration policy**: the mock
   sources live on the loopback, which the SSRF default-deny refuses —
   the integration tests run with
   `allow_private_key_url: true` (the flag is the documented local/
   mock-source escape hatch; production localhost/LAN media sources
   use the same flag).

## Mismatch handling path

If a base face is found not to fit the media consumption (signature
unable to express the need, semantics incompatible with the staging
invariants):

1. **Stop the wiring** at the mismatch; record the exact face and the
   need here.
2. The fix routes through the **base crate's own change path** (with
   its own design note when a frozen signature is involved —
   `traits.rs` is a frozen seam).
3. No media-side shim/fork: a private scheduler/transport
   implementation inside taiji-media is the explicitly forbidden
   outcome.

No mismatch was hit during the wiring: the additions the wiring
needed were additive base faces (the `sequence` module — itself the
sequence-engine item; the `reqwest` type re-export), not changes
to frozen signatures.
