# taiji-http design notes

Distilled design and upstream-anchor notes for `crates/taiji-http`.
Code module headers keep a short mechanism summary and point here.

## auth.rs

Authentication challenge/response design notes
(`crates/taiji-http/src/auth.rs`):

- Reference boundary: aria2 serves both Basic and Digest challenges
  from the same `--http-user/--http-passwd` pair (`DigestAuth.cc`;
  Basic is preset by default and the 401 `WWW-Authenticate` challenge
  selects the response scheme). This layer is isomorphic: credentials
  are extracted from `AuthScheme` (both variants equal), Basic is
  preset at the client layer, and 401 Digest challenges are answered
  here.
- Digest algorithms (RFC 7616 §3.3): `MD5` is the reference baseline
  (the only algorithm in aria2 `DigestAuth.cc`) and the legacy-server
  default; `SHA-256` is the RFC-recommended algorithm (sha2 is
  already a workspace dependency). `-sess` variants and unknown
  algorithms fail with an explicit error — no silent plaintext
  downgrade.
- MD5 is hand-rolled (RFC 1321, test vectors pinned): the dependency
  tree has no md-5 crate. It is used only for Digest authentication
  responses, never for any integrity/checksum surface (`--checksum`
  accepts sha-1/sha-256 only).
- qop surface: `qop="auth"` (RFC 7616 §3.4, with nc/cnonce) and RFC
  2069 legacy (no qop; response = H(HA1:nonce:HA2)) are supported.
  `auth-int` is rejected: the engine has no request-body re-hashing
  surface.

## degraded.rs

Single-connection degraded path (`crates/taiji-http/src/degraded.rs`):

- In the two-layer scheduling model, extent scheduling serves only the
  Range domain (206 sources after probe merging, authoritative total
  length known). The degraded forms run single-connection: no grid,
  no bitmap, no offset resume (recovery always from zero), not going
  through the scheduler (the same boundary as the `crate::scheduler`
  module docs):
  - no-range: all sources are 200, no authoritative total length
    (`DegradedReason::NoTotalLength`);
  - non-identity encoding: with `Content-Encoding != identity` the
    Range semantics are unknown and the bitmap stays off
    (`DegradedReason::NonIdentityEncoding`);
  - no REST (FTP form) and the single-connection-cap form take the
    same path.
- Full pipeline (`DegradedJob::run`): plan_output (creation-time
  conflict check) -> PartFile::open (Restart: recovery from zero) ->
  FileSink (positional writes via write_all_at) fed by
  SegmentTransport::fetch (single connection) -> sync_all (data
  before intent) -> close (closes the handle-backed credentials) ->
  Finalizer::finalize (intent before action -> rename -> directory
  fsync).
- Where "resume from zero" lands: the degraded job never reads a
  bitmap and always opens with `PartOpenPolicy::Restart` — a stale
  `.part` is truncated and redownloaded whether or not its length
  happens to match (the `crate::naming::decide_part_reuse` decision).

## lib.rs (crate map)

`taiji-http` is the HTTP download foundation crate: the frozen
three-trait contract seams plus support types, the reqwest client
wrapper, and the scheduling side of the two-layer scheduling model
with the full disk-write/rename pipeline. Module map:

- `client`: reqwest client wrapper — manual redirects, credential
  stripping, UA, timeouts, retry parameters, identity-only compression
  policy; the URI probe transport face (SPEC §4.2).
- `conn_timing`: connection-establishment timing middleware (plugs
  into the reqwest `connector_layer`; feed layer for the
  `taiji_http_conn_establish_*` connection-profile metrics).
- `cookies`: `--load-cookies` Netscape parsing + per-domain jar
  (≤1MiB; the parser is on the fuzz list) + task cookie storage
  (`CookieStore`: Set-Cookie capture during download / RFC 6265
  replay).
- `retry`: `--max-tries`/`--retry-wait` backoff parameters (consumed
  by the extent-level drivers).
- Block grid + dynamic extent two-layer scheduler (SPEC §4.3/§4.4,
  the SegmentSource abstraction); multi-source allocation (SPEC §4.7).
- `grid`: block grid + bitmap accounting (the persistence-layer
  progress unit; frozen bitmap-semantics seam, byte-compatible with
  the `http_task.block_bitmap` persistence encoding).
- `scheduler`: `--http-scheduler=dynamic` guided self-scheduling with
  the rate-synthesis formula (default) and `=static` fixed splitting
  (fixed seg_len; comparison and fallback baseline).
- `coordinator`: the ExtentCoordinator actor — the single serial
  decision point for extent allocation and block-completion
  accounting (first arrival wins, late arrivals dropped), endgame
  degradation and no-steal decisions (SPEC §4.4.2), stall steal
  (byte-level heartbeat staleness + `last_acked+1` safety margin +
  write-permission transfer cancellation, SPEC §4.4.3), AIMD
  connection-count wiring (SPEC §4.4.4), multi-source allocation
  (SPEC §4.7: EWMA-weighted share arbitration + source demotion/
  removal + failover, `spawn_dynamic_multi`).
- `rate`: per-source rate EWMA (the rate term of the synthesis
  formula; windowed consumer of the permit-wait observation seam,
  limiter-dominated windows excluded).
- `sources`: per-source health ledger and EWMA-weighted share
  arbitration (SPEC §4.7) — consecutive-extent-failure demotion (3) /
  removal (5) counters, the all-sources-removed `no_source` negative,
  and clamping of fast-source over-allocation.
- `aimd`: connection-count AIMD adaptation (SPEC §4.4.4/§4.4.4a) —
  slow-start doubling (start = the spec baseline `min(2, cap)`, raised
  by explicit user concurrency intent `--split` at assembly), gain
  threshold ×2, congestion multiplicative decrease ×0.75 and recovery,
  permit-wait/cap-contention window exclusion (an input-signal
  definition: rate-limit waits are not congestion), SFTP deep-domain
  parameter slot (B3 interface seam).
- `pool`: the AIMD connection execution ring (fulfills the SPEC §4.4.4
  scale directives) — consumes AIMD snapshots to produce spawn
  directives and stop tickets (graceful shrink); workers actually
  appear/disappear.
- `heartbeat`: the worker-side execution ring for stall stealing
  (SPEC §4.4.3) — per-extent byte-heartbeat production (cadence +
  catch-up after a pause), write-permission cancellation consumption
  (hung-transport watchdog), block completion reported as written
  (the `last_acked` watermark advances with writes).
- `limiter`: download rate limiting (global + task-level dual token
  buckets, per-task bucket) and the sink write-path gate; the
  permit-wait observation seam flows into the coordinator via
  `RateSampleReporter`.
- `probe`: URI probing (all 7 rows of the SPEC §4.2 decision table +
  multi-source probe merging).
- `naming`: `.part` naming and creation-time path conflict checks
  (SPEC §4.5) — `--http-incomplete-suffix` strict validation +
  persist-at-creation, auto-file-renaming (aria2 `RequestGroup.cc`
  direct translation), the `.part` reuse decision; platform filename
  sanitization — a full channel for URL/CD-derived names, a light
  channel for explicit user names (channel grading in the module
  docs).
- `partfile`: the `.part` on-disk surface — `write_all_at` positional
  writes + prealloc (trunc semantics) + handle-closing credentials
  before rename (SPEC §4.5).
- `finalize`: recoverable completion-rename semantics — DB as
  journal, intent before action, 3 backoff retries →
  `Done + renamePending`, idempotent startup retry, and the
  directory-fsync network-drive degradation contract (platform-split
  decision: Windows Win32 1/50, POSIX only EINVAL/EROFS —
  server-confirmed).
- `degraded`: the single-connection degraded path (no-range /
  non-identity encoding — no bitmap, resume from zero), full-pipeline
  driver and fixtures.
- `ftp`: FTP/FTPS transport adapter (SPEC §4.8) — REST segmentation +
  EPSV/explicit/implicit TLS + charset fallback + connection reuse
  pool; REST rejection → single-stream degradation (`FtpNoResume`).
- `transport`: the HTTP `SegmentTransport` implementation —
  Range-domain extent fetches (206 validation + echo consumption +
  final-url jump self-healing) and the degraded single-connection
  full GET (disk writes injected via `SegmentSink`; DB/bitmap belong
  to core).
- `worker`: the grid worker execution ring — source-bound worker loop
  body (claim extent → fetch → block-completion report), AIMD shrink
  claims and snapshot → spawn-directive conversion, heartbeat/sink
  chain assembly; task telemetry/persistence reach the host via the
  `WorkerTelemetry`/`WorkerOpts`/fatal-channel injection seams (the
  protocol layer holds no task telemetry or row-image state).

Scheduler/transport implementations extend within the same crate.
Dependency direction: no taiji-store, no taiji-core (see the crate
header).

## remotetime.rs

`--remote-time` and HTTP-date handling
(`crates/taiji-http/src/remotetime.rs`):

- Posture: RFC 9110 §5.6.7 HTTP-date. What production servers and
  probe records actually send is IMF-fixdate; the obsolete RFC 850 and
  asctime spellings are accepted per spec (tolerant parsing). A parse
  or mtime failure → None/Err: the caller warns and skips — never a
  task failure (aria2 `HttpResponseCommand` is likewise best-effort,
  logging only).
- Hand-rolled discipline: the date parser introduces no new third-party
  dependency (no httpdate/chrono/time). The day↔unix-seconds conversion
  uses Hinnant's civil-from-days / days_from_civil algorithms (public
  domain), pinned by vector tests including leap-year and century
  anchors.
- Unification: the RFC 3659 §2.3 MDTM reply value converts to an
  IMF-fixdate string, so the FTP probe's `last_modified` and the HTTP
  Last-Modified share the single `parse_http_date` parser for both
  resume validation and `--remote-time`.
- Fuzz hardening: non-ASCII month names never slice a char boundary;
  year fields are bounded (IMF/asctime 4DIGIT, RFC 850 2DIGIT) so
  unbounded years cannot produce absurd far-future timestamps.

## tests/ftp_container_matrix.rs

The FTP container matrix cross-validates the in-process mock matrix
(`ftp_mock.rs`) against real server implementations (vsftpd + proftpd):
behavior asserted on the mock must reproduce identically on real
servers (REST extents / EPSV / explicit + implicit TLS / anonymous +
authenticated / charset).

Container fixtures:

- Images build natively from the
  `tests/fixtures/ftp-container/local-build/` Dockerfiles
  (`taiji-ftp-it-vsftpd:matrix` = vsftpd + openbsd-inetd on Debian
  bookworm; `taiji-ftp-it-proftpd:matrix` = proftpd + mod_tls on
  Debian trixie) so non-amd64 hosts need no Rosetta/QEMU translation —
  amd64-only third-party images are unreliable under translation at
  the fork+privsep boundary. A missing image is built by the test
  itself (`docker build`, reused afterwards).
  `TAIJI_FTP_IT_IMAGE_VSFTPD` / `TAIJI_FTP_IT_IMAGE_PROFTPD` override
  the references (e.g. registry prefixes).
- Service shape: vsftpd runs under inetd (one vsftpd process per
  connection; the image CMD writes /etc/inetd.conf and receives
  `INETD_PORT`: plaintext 21 / implicit 990) — see the defect note
  below. proftpd runs standalone (`--nodaemon`), stable across
  sessions.
- Config injection: `tests/fixtures/ftp-container/*.conf` is
  bind-mounted read-only (vsftpd → `/etc/vsftpd/taiji.conf`, proftpd →
  `/etc/proftpd/proftpd.conf`). TLS uses
  `fixtures/ftp-test-ca/container_server_*` (local self-signed RSA
  test certificate, SAN=127.0.0.1/localhost, not real credentials);
  the client pins its DER as an added trust anchor (certificate
  validation on by default).
- Content dir: files are generated at process start in a temp dir with
  the same deterministic pattern and lengths as the mock matrix, and
  mounted read-only at `/srv/ftp/pub` (anonymous root and auth-user
  home point there).
- Auth user: `useradd taiji` (password taijipass) after the plaintext
  instances start — a local system user existing only inside the test
  container.
- Readiness: container startup is asynchronous and the readiness check
  is the protocol surface itself — loop [`FtpTransport::probe`] until
  it succeeds (bounded retries).
- Host ports avoid common ranges: vsftpd 12121 (plaintext + explicit
  TLS) / proftpd 12122 / vsftpd implicit 12123 / proftpd implicit
  12124; PASV ranges are per-instance (50100-50199 / 51100-51199 /
  52100-52199 / 53100-53199) so parallel cases in one test process do
  not interfere.

vsftpd resident-listener defect (found during interop testing): vsftpd
3.0.3 (the final upstream release, unmaintained since 2015) segfaults
right after one successful RETR in `listen=YES` mode in this matrix
environment (Linux VM native arm64; Debian bullseye/bookworm/trixie and
Alpine musl builds; glibc and OpenSSL 1.1.1/3.0/3.5; curl and rustls
clients; container-local disk and bind mounts; sendfile and isolate
both on and off): the daemon exits with signal 11. The defect is in the
server implementation, not in the mock matrix or [`FtpTransport`]; the
matrix therefore serves vsftpd under inetd (one process per
connection), under which every behavior row is stable across sessions.

Explicit skip policy (no fake green): when containers are unavailable
(no docker CLI, daemon down, image pull/build failure, or
`TAIJI_FTP_IT_OFF=1`) the matrix rows do not run — the test prints
`SKIP(taiji.ftp.container-matrix): …` to stderr and returns. The exit
code is green but the skip is visible; nothing silently "passes".

- The SKIP marker prints on the spawn_blocking thread: libtest output
  capture is thread-local, so stderr from other threads reaches the
  terminal even under default `cargo test` output.
- With `TAIJI_FTP_IT_REQUIRE=1` (CI strict mount) unavailability panics
  (red) on the test thread, a path output capture cannot swallow.

Behavior mapping to the mock matrix (ftp_mock.rs):

- anonymous + auth (530 → taiji.auth.failed)
  → anonymous_full_download_with_probe / login_failure_maps_to_auth_failed
- REST extents (probe SIZE / REST 0 reconciliation)
  → rest_rejected_degrades_to_single_stream
- EPSV (server 229 + REST + RETR data plane)
  → epsv_selected_for_ipv6 / pasv_selected_for_ipv4
- explicit TLS (AUTH TLS + PBSZ 0 + PROT P) → tls_explicit_end_to_end
- implicit TLS (port 990 shape) → tls_implicit_end_to_end
- charset (UTF-8 direct / Latin-1 re-encode) → charset_utf8_and_latin1_paths

## stall.rs

Stall detection (`crates/taiji-http/src/stall.rs`) — the byte-level
heartbeat consumer, the task-level destination of `--timeout` read
idle:

- Semantics (SPEC §4.4.3 "rate-agnostic"): stall = zero byte growth
  over a continuous `window`. The heartbeat source is cumulative bytes
  written (a monotonic counter): any connection writing any byte
  refreshes it, and multi-connection tasks are judged on the
  task-level aggregate. The single-connection reqwest read-idle
  timeout (`read_timeout`) is the per-read transport-layer floor of
  the same window; both layers agree (no data for `window` seconds =
  failure, `taiji.http.transport: read idle`).
- h2 flow-control wait exclusion (SPEC §15.1): under HTTP/2,
  "connection count" = concurrent streams. When the connection-level
  flow-control window is exhausted by local read-side backoff (the
  typical case: the limiter holds the write path → no more chunks are
  pulled → rwnd/flow window shrinks to zero), stream bytes show zero
  growth — this is "waiting for a flow slot", NOT stall evidence (the
  flow-control window is not directly observable at the reqwest
  layer). Observable approximation:
  - permit waits = evidence of local backoff: only arriving data
    triggers a write-path permit request; permit waits inside the
    window mean the transport is being fed but cannot write — local
    backoff, including the flow-control waits it causes — so not stall
    evidence;
  - direction correctness: a truly stopped server sends no chunks and
    no permit requests, so both counters stay flat for a full window
    and stall fires (no missed detection); local rate/flow backoff
    keeps permit waits occurring, the liveness counters move, and no
    false positive arises. Long permit waits (at a low rate a single
    chunk's permit can exceed the window) are the extreme form of a
    flow-control wait and are excluded the same way.
- Landing: the stall input is a dual liveness counter — bytes written
  plus flow-control wait events ([`ByteHeartbeat::note`] /
  [`ByteHeartbeat::note_flow_wait`]); either changing inside the
  window refreshes the stall baseline. The coordinator-side steal
  decision reuses the same exclusion once the worker heartbeat
  producer carries wait events; until that producer exists, stealing
  has no evidence stream and no dual-counter comparison is pre-wired.
  This module does not change the coordinator message contract (the
  worker→coordinator byte heartbeat reuses the semantics on an
  independent channel).
- Detection granularity: sampling step = `window/4` (floor 10ms);
  detection latency ∈ [window, window + window/4]; each sample is two
  atomic reads, negligible cost.

## perhost.rs

Per-host connection cap (`crates/taiji-http/src/perhost.rs`,
`--http-max-per-host`) — a registry shared across tasks:

- Cap scope is engine-global: the SessionActor holds one `HostCap` and
  all HTTP tasks share it via Arc; in-flight connections per host are
  counted across tasks, first come first served. AIMD (dynamic
  scheduling) decisions also pass through this cap first.
- Host key = `scheme://host:port` (case/default-port normalized; the
  same dimension as the credential scope — a protocol+endpoint change
  is a different host). SFTP tasks count 1 connection
  (single-connection model); the SFTP adapter can use the same
  registry — this module is protocol-agnostic.
- Waiting: when the cap is full, `acquire` waits on
  `tokio::sync::Notify` (waking one waiter at a time) — no busy-wait,
  no unbounded queue (waiters park on the Notify). A runtime cap
  decrease (the changeOption face) never reclaims existing permits; it
  only constrains new acquisitions.
- Permit residency: the acquire/hold policy belongs to the connection
  driver side. The old form — workers acquired before activation and
  held for their whole lifetime — let parked workers (waiting for pool
  allocation or steal) keep occupying slots, amplifying per-host cap
  contention for other tasks. Resolved as "yield while parked": the
  driver (the core `http_task` worker ring) acquires at the activation
  point, releases the slot before parking (Drop returns it +
  `notify_one` wakes a waiter) and re-acquires on re-activation; cap
  contention waits still flow into the AIMD window via the observation
  seam (the `cap_waited` bit). This module's semantics are independent
  of the holding form (holding = counted; Drop/explicit release
  returns; `set_cap` wakes re-evaluation). Regression test:
  `parked_worker_does_not_hog_per_host_permit`.
- Observation: `HostCap::active` exposes per-host in-flight
  connections (the per-host in-flight data source for SPEC §12
  `/metrics`).
- Default: 64 (`DEFAULT_MAX_PER_HOST`), raised from the original 32
  after controlled experiments showed stable gains and no pathological
  interaction with loss or AIMD recovery.

## limiter.rs

Rate-limit integration (`crates/taiji-http/src/limiter.rs`):

- HTTP download traffic enters the existing global + per-task dual
  token buckets (`taiji_io::rate_limit`); the per-task bucket is the
  task-level pair of `LimiterSet`. `0 = unlimited` keeps the io-layer
  semantics (bucket-level zero-cost short-circuit). Session-side
  assembly: the global pair is Arc-shared, the task pair is created
  per task — hot-updating the global pair takes effect on running
  tasks immediately.
- Integration face (write-path gate): worker disk writes must go
  through the `SegmentSink` seam (frozen, not to be bypassed); rate
  limiting wraps the core-injected sink with `ThrottledSink`: each
  `write_at` takes a permit for the byte count first, then lets the
  inner write through — permit waits push back the read window (the
  same backpressure semantics as the BT-side `Throttled` stream).
  `complete_block` (accounting) is not rate-limited (its serialization
  lives in the coordinator), and accounting is never double-charged —
  the permit only gates disk-bound bytes.
- Permit wait observation seam (the dynamic-scheduling consumer face):
  `Permit::waited` exposes a permit's wait duration; the scheduler
  distinguishes "rate-limit waits" from "slow sources" by not counting
  windows whose permit-wait ratio exceeds 50% (the limiter exposes
  per-task permit wait durations to the Coordinator). Consumption
  path: with `ThrottledSink::with_rate_reporter` attached, every write
  reports a `(source, bytes, permit_waited)` triple via
  `RateSampleReporter::report` — the producer is the coordinator
  handle (bounded mpsc message type), and the coordinator windows the
  samples into the per-source rate EWMA (`crate::rate`). Sync
  contract: the reporter must not block — samples are dropped when the
  channel is full (EWMA is robust to lost samples; the write path is
  never backpressured by the observation face).

## conn_timing.rs

Connection-establishment timing middleware
(`crates/taiji-http/src/conn_timing.rs`):

- Mounted via the reqwest public API `ClientBuilder::connector_layer`
  (inner position below the `connect_timeout` layer; no feature gate
  since reqwest 0.12). The connector service is the mandatory point of
  the pool-miss path and pool-hit requests never reach it, so the
  layer's timing and counting naturally cover new connections only —
  the first observable face of pool behavior. The direct pool hit rate
  remains unmeasurable; this layer is a proxy for the new-connection
  face (boundary clauses in SPEC §12 with the metrics value table).
- Feed-point exit (on successful establishment) calls
  `taiji_io::metrics::HttpMetrics::note_conn_established`:
  - `taiji_http_conn_establishments_total` (counter) and
    `taiji_http_conn_establish_seconds` (histogram) always book the
    same success event in equal amounts. Failed attempts never pass
    this feed point — connection-failure classification stays with the
    existing classification seam (`taiji_http_errors_total{class}`),
    and the latency profile only takes successful samples.
  - DNS deduction convention: timing starts at the connector service
    call and ends when connection establishment returns, so it covers
    the combined DNS + TCP + TLS latency (plus tunnel establishment
    under a proxy; phase splits are unavailable).
    "connect+TLS combined ≈ this histogram − taiji_dns_resolve_seconds"
    — there is no per-sample reconciliation seam between the two
    families; the deduction is an analysis-side, mean-based component
    estimate (sum diff / count diff), not a per-sample difference.
  - Pinned hosts (DNS override) produce no DNS component and no
    `taiji_dns_lookups_*` counts (the override layer short-circuits
    before the shared resolver); for such connections the combined
    latency ≈ the raw connect+TLS value.
  - The data-plane and probe-plane transport instances mount this
    layer equally (two instances, one shared registry) — probe
    connections are real new connections and are counted under the
    same convention.
- Generic form: the reqwest connector stack's request/response types
  have no public names (sealed upstream), so — like the upstream doc
  example (`tower::timeout::TimeoutLayer`) — the layer and service stay
  generic over the inner types and pass requests through, reading the
  tables only at the success exit. Futures are boxed (one allocation
  per new connection; connection establishment is low-frequency and
  the connector stack is already type-erased, so the cost is
  negligible).

## checksum.rs

`--checksum` streaming digest tee (`crates/taiji-http/src/checksum.rs`):

- Finalization pipelining: digest consumption moves from "post-hoc
  full read after completion" to "incremental feeding during the
  download". The six-hash digesters (md5/sha-1/sha-224/sha-256/
  sha-384/sha-512, all sequential Merkle–Damgård family) require
  in-order byte consumption — this module provides only the write-byte
  callback seam (`TeeSink`); the digester itself and the
  "out-of-order block writes → ordered digest consumption" coordination
  (the grid path's contiguous-prefix watermark + late-write gate; the
  degraded path's sequential stream needs zero coordination) are
  assembled core-side. The hash crate dependencies live in core; this
  crate pulls none.
- Tee position: the inner layer of the rate gate
  (`ThrottledSink(TeeSink(FileSink))`) — the bytes the callback sees
  already hold a rate permit and correspond one-to-one with the final
  on-disk bytes. In the sequential-stream form (single-connection
  degraded/EOF stream) the write order is the byte order, so the
  digest final value fixes at fetch completion and the finalization
  comparison no longer re-reads the file (hashing is absorbed by the
  download duration; completion-perception latency no longer includes
  digest time).
- Feeding precedes the inner write: the callback content = the final
  on-disk bytes; an inner write failure fails the task and the digest
  is never consumed (a failed task has no finalization face). A `None`
  feed is a zero-cost pass-through, byte-identical in behavior to the
  existing sink chain.

## finalize.rs

Recoverable rename semantics for task completion (`crates/taiji-http/
src/finalize.rs`): the database is the journal.

Design input: Motrix PR #2132's SMB lesson — its finalize lived
outside the engine and had to build a separate journal subsystem.
taiji's structural advantage is that the sqlite single writer *is*
the journal: completion state and the rename intent are recorded
before the action in the same transaction, so the crash window cannot
lose the intent. The recovery surface has only two reachable states
(not yet renamed / renamed but not cleared), both converged by
idempotent close-out.

Crash matrix (the self-evidencing property of DB-as-journal):

| Crash point | Recovery |
|---|---|
| Before the intent is journaled | No trace; task not complete (bitmap/`.part` resume as usual) |
| Intent journaled, before the rename | Pending in the journal; startup retry performs the rename |
| Renamed, before the directory fsync | Target present with matching size → idempotent close-out |
| Renamed, before clearing | Same (clear_intent is idempotent) |

Directory fsync degradation contract (Motrix PR #2132 same
semantics): a network drive's "unsupported" answer is accepted as
server acknowledgement only for Win32 error 1/50 on the Windows face
and errno EINVAL(22)/EROFS(30) on the POSIX face — relaxable only
with an SMB 2+ handle confirmation. The same numeric value means
different things across the faces (errno 1 = EPERM, 50 = Darwin
ENETDOWN), so the verdict is platform-scoped with hardcoded constants
(no libc dependency). File fsync is never relaxed — it lives in
`partfile::PartFile::sync_all`.

Windows platform note: std `File::open` rejects directories (always
Access Denied — which once made every local-disk finalize rename look
fatal, pinning tasks in RenamePending forever because the journal was
write-only), so the directory handle is opened via
`OpenOptionsExt::custom_flags` with `FILE_FLAG_BACKUP_SEMANTICS` (a
safe API, no unsafe; same platform-abstraction precedent as the store
disk layer) and `FlushFileBuffers` lands on the handle through
`File::sync_all`.

Known TOCTOU window: a foreign file appearing at the target path
between the close-out probe and the rename is atomically overwritten
by posix rename / Windows MoveFileEx. No rollback: `RENAME_NOREPLACE`
semantics would need platform syscall faces beyond std; the target
path was already conflict-resolved at creation time by
`crate::naming::plan_output`, so occupation inside the window is a
hostile cross-process writer (aria2 has no such state: its finalize
resolves conflicts at creation time).

## batch.rs

Same-host transient batch-group scheduling (`crates/taiji-http/src/
batch.rs`): a cross-file byte-range queue, in-batch work stealing,
and a connection-budget soft-cap gate.

Three-layer cap stacking rules (the written core):

1. Per-task cap (`--max-connection-per-server`, domain 1-16): one
   file's connection intent = min(split, cap); driver planning is
   unchanged — the batch group never amplifies a single file's
   intent.
2. Batch-group budget (`--http-batch-budget`, default 16, domain
   2-64): the group's aggregated cross-file connection budget (unit
   = connections). Semantics: "the batch group's polite share as one
   logical task" — the same magnitude as the single-task cap ceiling
   (16), preventing a batch group from steamrolling other same-host
   tasks with Σ(N×cap) intent. In force only once the group holds
   ≥ BATCH_MIN_FILES (K=2) active files; the single-file shape keeps
   the status-quo fast-path semantics. While in force the group's
   active-connection ceiling is max(budget, host cap − outside
   occupancy) — work-conserving and polite (below).
3. Per-host cap (`--http-max-per-host`, default 64, unit =
   connections, shared across tasks): batch-group connections count
   in full (HostCap::acquire before every fetch; the activation
   point draws and holds the permit for the fetch round) — no
   exemption, no bypass. Effective bound chain: per-file
   min(split, cap) → group ≤ max(budget, host cap − outside
   occupancy) → host cap 64, global first-come-first-served (hard
   ceiling).

K = 2 rationale: the smallest unit of batch benefit is reusing a
connection/budget across one file boundary, which two files already
deliver. A larger K would never trigger at default concurrency
(`--max-concurrent-downloads=5`; same-host queues of small tasks are
often just 2-3), turning the batch group into dead code; K=1 is no
group at all (a single file not being budget-constrained is the
other face of K=2). Engine constant, no CLI knob — the budget value
is the only knob (option-sprawl discipline).

Work-conserving ceiling derivation: `ceiling = max(budget, host_cap
− outside_occupancy)` where `outside_occupancy = host_active −
group_active` (atomic snapshot, possibly slightly stale). Host idle
(outside 0) → ceiling = host cap: the group takes the full cap in
one step, no "within budget → overflow" two-phase ramp (an earlier
overflow-try + yield-poll design left connection-utilization gaps in
the half-idle regime). Host contention (outside ≥ host cap −
budget) → ceiling = budget: the group falls back to its polite
share, and the host-permit fair queue applies as usual — permits
yielded by other tasks are fairly queued for within the group;
in-flight connections are never preempted. The host cap itself stays
the hard ceiling (acquire per connection); stale instantaneous
readings only jitter the ceiling by the concurrent-connect count — a
politeness, not a correctness, property.

First-wave stagger across files: before the fix the stagger ordinal
was the per-file range index (0..ranges.len()), so K tasks joining
at the same moment each opened an ordinal-0 connection at once — the
group-forming burst was never staggered inside the group (the ramp
only ran within one file). The fix allocates ordinals globally per
group: a task's first `workers` workers pre-reserve one contiguous
ordinal range `[base, base+workers)`, consumed by the driver-side
`stagger_delay(ordinal, warm)` (first-connect delay = ordinal ×
step). The counter resets when the group disbands: a same-moment
connect burst only exists among tasks joining within one group's
lifetime, so a post-disband batch is a new burst and should re-ramp
from 0 (group lifetime = the natural boundary of the burst window).
Keeping a monotonic counter across group lifetimes would pin
ordinals at the driver-side cap CONNECT_STAGGER_MAX_ORDINAL:
post-disband tasks would all wait the same saturated delay and the
same-moment herd would reappear at +saturated-delay while paying the
startup latency for nothing (uniform delay != stagger). Within a
long-lived group, natural growth is absorbed by the same cap (delay
bounded ~320ms; the stagger-step semantics hold).

## probe.rs

URI probing (`crates/taiji-http/src/probe.rs`): HEAD is never a
probing mechanism — HEAD semantics are not enforced across HTTP
implementations (servers may omit Content-Length/entity headers, or
lie for HEAD). The only probe is a single GET with
`Range: bytes=0-0` and `Accept-Encoding: identity`, reading the
response headers and dropping the stream (the body is never read;
cost bounded by the 1-byte probe body).

Upstream anchor mapping:

- Echo mismatch → bad_range: aria2 `HttpResponse.cc`
  `isRangeSatisfied` failure → CANNOT_RESUME.
- Throttling with Retry-After: aria2 `parseUnavailableHeaders`
  semantics; the download-phase 200-after-206 contradiction is aria2
  `executeDownload`'s "Expected partial, but received OK" →
  STATUS_CANNOT_RESUME.
- URI-level retry: aria2's URI-level max-tries; the probe adds a
  50ms backoff floor so 5 attempts span 50/100/200/400ms and
  necessarily cross a same-moment connect-burst window (tens of ms)
  — backoff absorbs connect-phase RST noise.
- Content-Range parsing covers the two RFC 7233 shapes; `bytes */*`
  and unparseable forms are outside the classification table.
- The engine total-length cap (grid::MAX_TOTAL_LEN, 16 TiB) rejects
  a malicious 2^63-scale TOTAL / Content-Length at the
  classification layer as a task-level error, so a giant bitmap
  allocation is never reachable through a mixed-source merge.

The Content-Encoding rule outranks status-shape classification
inside the 200/206 arms: even a 206+TOTAL answer cannot map bytes
onto the grid under a non-identity encoding (TOTAL describes the
encoded entity), so the source always degrades. The rule is gated to
success statuses — gzip on 4xx/5xx error pages is routine, and such
a page must not be accepted as a usable source through the rule,
swallowing the real status.

Multi-source merge decision order: drop probe-failed sources →
length consistency (mirror_mismatch; with `--checksum` the first
source's length group stays authoritative and the completion-time
checksum has the final say) → Content-Type differences warn only
(aria2 does not compare types) → only 206+TOTAL sources segment →
all non-segmentable degrades to the first source → all removed fires
`no_source`. Empty files take the first source's shape.

## error.rs

Error-code face policy (`crates/taiji-http/src/error.rs`): each
variant carries a canonical `taiji.*` string code; the HTTP-failure
→ aria2 numeric-error-code mapping is a separate table single-sourced
in taiji-rpc (out-of-table codes fall to its UNKNOWN fallback row).
New engine variants never pre-allocate RPC numeric codes.

Code-face stability decisions:

- DnsPermanent keeps the `taiji.http.transport` string face (RPC
  numeric code 6): the retry semantics changed (permanent DNS
  failure never enters the retry loop, matching aria2
  `NAME_RESOLVE_ERROR` / `AbstractCommand.cc` DL_ABORT_EX2), the
  code face did not. The DNS-specific split of numeric code 19 is
  unreachable in the production rendering chain.
- FtpDns (typed payload) keeps the `taiji.http.ftp` string face and
  Display shape of Ftp (RPC numeric code 21), so the taiji-rpc
  mapping row `"taiji.http.ftp" => 21` resolves both payloads.
- PreconditionFailed (412 under If-Match) reuses the
  `taiji.http.bad_range` family: same path as the probe's 416
  length-changed shape — a deterministic resource-identity drift;
  consumers go fatal once and clear the bitmap (restart from zero)
  instead of paying for extent retries or a misaligned resume.
- RetryAfter stays in the `taiji.http.unexpected_response` family
  (no new external code); the server hint wins, clamped to 30s by
  `retry::clamp_retry_after` before backing off.

Classification/feed discipline: the transport class is counted at
the client's classification seam before the reqwest error chain is
flattened, so `error_class()` returns None for Transport-family
variants (no double count). The `is_connection_reset` criterion is
deliberately conservative — only peer-interruption signatures
("connection reset (by peer)", "broken pipe", "connection closed
before message completed") qualify, because the AIMD decrease
trigger (the aimd.rs pending-items gate) must never fire on
ordinary failure noise: wrong statuses, DNS, timeouts, connection
refused, and protocol short/over reads all test false.

## coordinator.rs

### Block-completion decision semantics (frozen: first report wins)

Workers report completed blocks to the actor (`CoordinatorMsg::BlockDone`);
adjudication runs serially inside the actor loop:

1. the task grid bitmap already has the bit set -> the late report is
   dropped (under a steal race two workers finish the same block with
   identical content; only the first report takes effect);
2. first report -> set the bit and advance the persisted bitmap via
   `SegmentSink::complete_block` (the only entry point to the persisted
   bitmap; the write face must not bypass the sink — the core-injected
   implementation owns the fsync-before-snapshot ordering invariant and
   the `UpsertHttpTask` bitmap persistence).

So even when stall stealing causes duplicate writes, the worst case is
wasted bandwidth, never interleaved corruption (the structural backstop
for steal races).

### Endgame degradation and the steal ban

The endgame predicate is unchanged: fewer blocks left in the pool than
the task's worker count (`scheduler::in_endgame`). In endgame, dynamic
allocation degrades to single-sub-block granularity
(`GuidedPlan::pop_single_granule`, bypassing the composition formula —
fragmentation lands in the sub-block domain, so every worker can always
claim work during the endgame). Stealing is denied in endgame by
default: every steal request (`CoordinatorMsg::StealRequest`) passes
this actor's single decision point and is denied without stall evidence
(`StealVerdict::DeniedEndgame`, preventing endgame thrash and livelock;
the evidence gate runs first, see the steal section below).

### Byte watermark for block completion (wire/bookkeeping decoupling)

Starter-level leases are byte-granular (the sub-block floor = the
engine-internal constant `block/4`, `scheduler::sub_block_granule`;
adjacent leases are constrained to disjoint byte ranges), so one block
can be written by adjacent leases and a thief together. Block completion
is no longer decided by a single worker's boundary crossing but by the
per-block written-byte watermark filling up: the actor tracks the
written-byte watermark per in-flight extent (`CoordinatorMsg::Heartbeat`
increments plus the fetch-final flush; message FIFO keeps the watermark
exact at decision time), accumulates written bytes per block, and
decides a block inside the actor once its watermark is full
(`BlockGrid::record` first-report-wins -> `SegmentSink::complete_block`
persistence). Single-point adjudication and fsync discipline are
unchanged; bitmap semantics are unchanged (a block is still the only
persistence unit; a half-written block never persists).

### Stall steal (byte-level stall detection with a safety margin)

Stall detection uses byte-level heartbeats: each worker reports once per
second (`HEARTBEAT_INTERVAL`) "bytes written since the last heartbeat"
over the existing mpsc channel. The actor folds it into the `StallWatch`
decision table per in-flight extent: only zero byte growth over a full
`--http-stall-window` (default 15s) counts as stalled — rate-independent
(a slow connection that keeps writing is never stalled).

A non-endgame steal decision is a single-point re-verification: the
grant trusts only stall evidence the actor itself maintains from
heartbeats (never the requester's assertion — heartbeats that arrived
before the request was enqueued were consumed first under FIFO, so the
evidence is current). Two further gates apply:

- rate-limit wait exclusion: no grant while the owner source is inside
  its rate-limit wait activity shadow (`crate::rate`, shadow window
  `max(window, waited)`). Rate-limit waiting is not stall evidence: with
  a low rate limit stretching chunk gaps past the stall window, the zero
  growth is a pacing gap, not a stall.
- removed sources are always denied: inside the window where a removal
  is landing, a parked worker must not re-enter through stealing.

The endgame predicate for stealing uses the same
`scheduler::in_endgame`, but "remaining" counts total live work
(unallocated pool + undecided in-flight blocks,
`ExtentCoordinator::steal_denied_endgame`): an emptied pool with a
visible in-flight tail is exactly the steal target, and the pool-only
view would misread the task as endgame so stealing would never grant.
The total-live view puts the "single-block granularity" ban in its
literal domain — a true tail where each worker's remaining share is
< 1 block (a steal would only leave a 1-block scrap and pure endgame
thrash/livelock risk); there stealing is always denied.

On a grant, the stolen range = `[last_acked+1 block, extent end)`
(a safety margin of 1 block compensating blocks the owner may advance
during heartbeat/cancel message flight; same-block double writes are
covered by single-point block adjudication — at most 1 block wasted per
steal, no interleaved corruption). Write ownership transfers at once:
the old owner receives the cancel at its next block boundary via the
heartbeat reply (`HeartbeatAck::Cancelled`) and stops writing the
extent; the thief continues the tail with the `StealVerdict::Approved`
allocation (the extent number is kept — the `SegId` reconciliation
contract). A grant also resets the stall baseline (a full window of
grace for the new owner), so concurrent steal requests on the same
evidence never double grant. Stealing transfers write ownership only,
never pool accounting: `Abandon` recovers by current owner and steal
watermark (a stale owner's abandon has nothing to recover; the current
owner's abandon recovers only undecided blocks past the watermark).

### AIMD decision wiring

The AIMD decision is this actor's established responsibility. In dynamic
mode the actor exclusively owns the per-source `AimdBook`, driven by two
message types (additive extensions of the coordinator message surface):

- `CoordinatorMsg::RateSample` (observation seam): besides the rate
  EWMA, the same source feeds the AIMD gain window (lazily closed; see
  `crate::aimd`). Cap-competition waits are reported by the connection
  driver side (write-path samples carry zero; per-host cap waits during
  worker activation are injected via the `cap_waited` field of
  zero-byte samples).
- `CoordinatorMsg::CongestionSignal`: server-side throttling/reset
  features observed on the worker transport path -> multiplicative
  decrease. Rate-limit waiting is not congestion — local limiter waits
  only participate in the window exclusion through the RateSample
  observation seam, never through this message.

Decisions (Grow/Hold/Decrease) are recorded in the book and logged at
debug level. The worker scale ring (the HttpTask connection ring,
`crate::pool`) consumes decisions via `CoordinatorMsg::AimdSnapshot`
snapshots — grow = spawn instructions, shrink = graceful excess-worker
exit claims (the decrease path) — realized each tick of the driver
loop. Static mode assembles no AIMD (control baseline); the congestion
and snapshot faces are no-ops.

### Multi-source allocation (EWMA-weighted rotation, demotion/removal, failover)

Multi-URI source-set management (`crate::sources`) is assembled by
`spawn_dynamic_multi` (source count = the probe merge table's Segmented
product):

- EWMA-weighted share arbitration: the allocation size still comes from
  the single composition formula, but when source i's in-flight holdings
  exceed its weighted share (`live * w_i / sum(w)`, w = the per-source
  rate EWMA, halved while demoted) the allocation is clamped to
  min-chunk — fast sources claim more, slow sources less (the formula
  output is not rewritten by the arbitration).
- Demotion/removal: extent failures (`CoordinatorMsg::Abandon`) count by
  windowed failure rate (>= threshold failures within the last
  `crate::sources::OUTCOME_WINDOW` extent outcomes). A "consecutive"
  count decided in arrival order would be reset by isolated successes
  and let flapping sources evade removal forever. 3 failures in the
  window demote (weight halved), 5 remove (the source's Acquire closes
  out). `CoordinatorMsg::ExtentSucceeded` enters the window; a demoted
  source recovers only once windowed failures fall back below the
  demotion threshold (an isolated success does not clear the record).
- Failover: a failed source returns its unfinished blocks to the pool
  through the existing Abandon semantics (the grid decision face is the
  source of truth) and the surviving sources claim them — no new
  mechanism. All sources removed with pool work remaining -> Acquire
  answers `HttpError::NoSource` (the task-level negative close-out).
- Runtime length mismatch: probe-time mismatches are decided by the
  `crate::probe` merge table; runtime length drift shows up as a
  transport-class failure for that source, is counted in this ledger,
  and the source is removed so the survivors take over (the source-set
  product of the same merge table).

Single-source assembly (`spawn`/`spawn_dynamic`) assembles no source
ledger: behavior stays byte-identical to the pre-existing semantics
(Abandon/success reports bookkeep as no-ops).

### Actor boundary

- worker <-> coordinator communication is all messages (bounded mpsc,
  capacity = 2 x workers; a full queue backpressures the worker's
  acquire/report/heartbeat call sites — the unbounded-queue ban).
  Byte-level heartbeats are an additional message type on the same
  channel and do not change the capacity contract; block-completion
  reports backpressuring a worker on a full channel is the expected
  throttle face.
- sink persistence failure = task-level fault (progress cannot be
  recorded): the actor ends with the error instead of poisoning the
  session; later handle calls get `Err` (the actor has stopped).
- no `Mutex`/`RwLock` across `await`: grid and queue state belong to
  the actor exclusively (message passing is the synchronization point);
  no shared locks.

### Allocation strategy (static fixed split / dynamic guided self-scheduling)

- static: allocations come from `crate::scheduler::StaticPlan` — block 0
  at 1-block granularity with top priority (file head preview), then
  fixed segments FIFO; an abandoned extent is restored at the queue head
  keeping its original sequence number.
- dynamic: allocations come from `crate::scheduler::GuidedPlan` — each
  allocation slices by the rate composition formula
  (`min(remaining/(2*W), rate*3s)`, sub-block aligned; W = the snapshot
  of active workers at allocation time; the rate term = the per-source
  EWMA `crate::rate::SourceRateBook`, fed by `CoordinatorMsg::
  RateSample` write-path observations). In-flight accounting (active W)
  is maintained here: register on allocation, decrement on block
  completion, deregister on abandon with the grid decision face as the
  source of truth for the pool return.

## scheduler.rs

Scheduling modes and allocation plans
(`crates/taiji-http/src/scheduler.rs`).

### Two-layer model

The extent layer serves only the Range domain: post-probe merged 206
sources with a known authoritative total length
(`ResumeValidator::total_len = Some`). The no-range shape (all 200
sources) degrades to a single connection, builds no grid, and has no
offset resume (recovery restarts from zero) — it never reaches this
scheduler (the same boundary as the degraded path).

### static: fixed segmentation (aria2 split semantics)

Cross-validation reference: upstream aria2 `--split` / `--min-split-size`
static-split intent (local defaults: `split` 5, `min_split_size` 20MiB).
Segment count `n = min(split, max(1, total / min-split-size))`; segment
lengths align down to the block granule (sub-block extents are
forbidden) and the remainder folds into the last segment (its end is the
total length and may include a partial last block). Collapses to a
single segment when `total <= block_size` or the aligned length is 0.
`MAX_SPLIT` (4096) bounds the value range because static's first wave
spawns `split` workers per source unconditionally (split is a
task-amplification factor); it has three single-sourced consumers:
creation-side parsing (taiji-core `parse_split_value`), the runtime
backstop in `SchedulerConfig::validate` (replayed poisoned rows /
programmatic configs bypass the creation parse), and replay clamping of
persisted concurrency intent (taiji-core
`HttpConcurrencyPersist::apply_to` — without it a poisoned
`split=u32::MAX` row would replay as-is on every restart and reproduce
the OOM across reboots).

### dynamic: guided self-scheduling + rate composition

Guided self-scheduling is the self-split form of Kruskal & Weiss (1985):
each allocation takes `remaining/(2*W)` with W the active-worker
snapshot at allocation time. The rate cap composes a single worker's 3s
lease `rate_ewma*3s/W` — never hand out more than ~3s of work, which
prevents fast sources from hoarding long extents and slowing the
rebalance response. `rate_ewma` is the per-source aggregate rate shared
by all W workers; sizing one lease at aggregate-rate*3s would
over-provision by W and inflate it to `W*3s` (48s+ at 16 connections),
moving the pool into flight early and idling workers. While the EWMA is
unestablished the lease is capped at the block granule (the cold-start
lease bound; the engine-side equivalent of fork `min-split-size`):
during the cold-start burst all workers' acquires arrive within
milliseconds and the W snapshot ramps per request (the first lease sees
W=1), so pure guided would carve max-chunk-scale giant leases.

Thin-zone whole-block floor: once `remaining < 2W*block` (iff the guided
share drops below the block granule — the predicate is the formula
itself, adding no constant and invariant to block scale), the guided
term is clamped back up to a whole block. Tail leases stay whole instead
of shrinking into fragments; fragmented leases amortize more request
rounds per byte and bite back on tail throughput. The floor applies to
the guided term before the min with the rate term: the rate term's 3s
lease-cap semantics survive (slow sources stay capped) and the `max`
composition keeps `len` monotone in `remaining` — a floor applied after
the clamp would let the lower bound jump at the boundary and break the
monotonicity argument.

Line/ledger decoupling: persistence and bookkeeping stay block-aligned
while line-level leases are byte-granular, with the lease floor and
alignment clamp at the sub-block floor (`SUBBLOCK_PER_BLOCK` = block/4,
an engine-internal constant with no CLI knob; the block domain floor of
256KiB implies a sub-block floor >= 64KiB). Adjacent leases claim
disjoint byte domains; block completion remains the sole persistence
unit (a block completes when its byte watermark is full; the
single-point decision/fsync discipline in `crate::coordinator` is
untouched). The old "always >= 1 block after alignment" structural floor
is thereby removed: wave quantization (24 blocks x 16 connections always
produced a 2-wave tail with idle workers) closes with sub-block leases.

Block 0 is special-cased in both modes: the first claiming worker takes
it at 1-block granularity, highest priority (file header preview).

Guided vs static recycling: static requeues the original extent at the
queue front with its original sequence number; guided returns the
unwritten byte domain to the pool (dropping whole blocks the grid marks
done) and re-splits with a new sequence number — extent sequence
numbers promise only runtime uniqueness, not stability across recycling.

### endgame

The criterion is unchanged: endgame begins when the remaining block
count in the pool drops below the task's worker count (`in_endgame`).
Endgame allocation granularity is a single sub-block
(`GuidedPlan::pop_single_granule`), bypassing the composition formula —
fragmenting into sub-blocks makes every piece independently claimable so
no worker idles; whole-block granularity would reintroduce wave
quantization into the tail. Stealing is rejected by default during
endgame (guards against endgame oscillation/livelock; exception:
requests carrying stall evidence with a non-empty tail pass). The single
rejection point for steal requests lives in `crate::coordinator` (the
StealRequest decision); the shared predicate is `in_endgame` (also
consumed by the endgame-metric simulation, so the criteria cannot
drift).

## aimd.rs

Per-source connection-count AIMD control
(`crates/taiji-http/src/aimd.rs`).

### Growth/shrink rules

Fully integer; the connection count is always `u32`. Initial count =
the slow-start start (`AimdConfig::start_connections`): spec baseline
`min(2, cap)`; `AimdConfig::with_start` raises it to the user's explicit
`--split` intent. When the start decouples from user intent, the ramp
amortization loss on short tasks dwarfs the task itself (the
cross-validation reference aria2 has no slow start and opens
`min(split, ...)` connections immediately). Raising the start only
changes where the ramp begins — growth, decrease, and convergence
semantics are unchanged.

Evaluation window (default `EVAL_WINDOW` 5s) aggregating gain >=
`GAIN_THRESHOLD` (10%) -> x2 (slow-start doubling), capped at the growth
cap; gain < 10% -> stop growing (hold; no step-back, overshoot at most
one doubling step). Congestion signals -> multiplicative decrease
`max(1, floor(n*k))`, then a **baseline reset** — later windows rebuild
the baseline and re-judge gain, so growth can recover (the decrease and
recovery paths are paired).

### Recovery timing

Baseline-absent windows (the establishment face: "establish a baseline +
optimistic probe Grow") all use the short window: the task's cold-start
first window and the post-`Reset` rebuild window are isomorphic and
share the `RECOVERY_WINDOW` (2s) floor; after a `Throttled` decrease the
spec window is kept (`in_recovery` cleared, `ever_established` set —
fast re-probing of a throttling source is neither polite nor effective).

Rationale for the Reset recovery window: recovery is one whole window
(rebuild the baseline + optimistic probe Grow straight back to the cap),
so the window length is the recovery latency. A 5s window is far longer
than the injected reset interval (~1.5-2s), so the rebuild window keeps
being invalidated by the next hit and the connection count ratchets down
monotonically without a single recovery. A 2s window approximates the
hit interval: at most one hit behind, then back to full. Sample-size
argument: 2s x 12 connections x ~250KiB/s is about 5.8MiB — judging the
10% gain threshold is unaffected by the shorter window because that
window only rebuilds the baseline and probes, with no gain re-judgment.

Rationale for the graded decrease: a Reset is a connection-level single
death (1 of 16 = -6% capacity), not source-level congestion evidence, so
0.75 over-penalizes; the depth collapse is secondarily amplified
end-to-end (a collapsed tail crawls on 3-4 connections). Throttled (a
429, source-level limiting) keeps the spec 3/4 — a face the server has
explicitly called to a stop does not get a lighter penalty. Grading only
parameterizes the coefficient: the decrease keeps the same structure
(multiplicative decrease + floor 1 + baseline reset); gain x2, lazy
window closing, and per-host cap semantics are untouched. The last
signal wins: a Reset immediately followed by a 429 hands over to
source-level throttling (spec window, no accelerated re-probe), and the
reverse hands back to the connection level (early rebuild window).

### Window protocol (causal order of gain evidence)

Window k runs on the connection count produced by window k-1's decision:
gain >= 10% means "the previous doubling was confirmed", < 10% means
"unconfirmed, stop". The first valid window has no baseline to compare ->
optimistic probe (without probing there would never be gain evidence to
judge) — establish the baseline and double once. Under the
per-connection-bandwidth-bound shape, gain stays >= 10% up to the cap
and connections converge on the gain-threshold point (= the cap) +/- 1.

### Input signals

A window's input is the bytes actually transferred by this source's
connections inside a permit window (the observation seam is
`Permit::waited()`, flowing in via `CoordinatorMsg::RateSample`). Two
non-congestive factors are excluded whole-window — no gain evaluation,
baseline preserved, and never any decision:

- rate-limiter-dominated window: permit wait share > 50% of the window.
  Share = sum of permit waits / (window length x connections) —
  normalized per connection, robust to concurrency. Division of labor
  with `crate::rate`: that face's windows are short and guard against
  concurrency-sum inflation inside one window; this face's window is a
  long 5s where normalization is the intent.
- cap-contention window: the per-host cap held by other tasks with
  waiting share > 50% (`crate::perhost::HostCap`; reported by the
  connection driver side; currently fed zeros while the connection loop
  is not wired).

Congestion vs limiting: limiter waits are not congestion — the local
limiter's waits only lower evaluation quality (whole-window exclusion)
and never convict a connection; only server-side signatures
(`CongestionKind`) trigger a decrease. The baseline persists across
excluded windows ("not counted" means not evaluated, not that the
evaluation anchor is dropped); a zero-byte window neither establishes
nor evaluates (stalled observations belong to the stall face).

### Decrease triggers -> closed loop

Both `CongestionKind` signals are wired: `Throttled` (HTTP 429
throttling signature) and `Reset` — peer RST / connection interruption,
the primary decrease trigger. Production wiring lives in the transport
error classifier: the `HttpError::is_connection_reset` signature test
plus the failed extent's real written-byte watermark (wave-phase
verdict). The signature test converges conservatively on peer
interruption; ordinary request failures (status codes / DNS / timeouts /
short protocol reads) are not misclassified as congestion. Zero-byte
failures (the observed connect-storm shape — first-wave connection
races bursting the accept queue into RSTs) do not trigger a decrease, so
the decrease is not knocked off the AIMD growth ramp by wave-phase
noise. Regression pins: `connection_reset_signature_table`
(positive/negative signature table),
`mid_transfer_reset_triggers_aimd_decrease` (steady-state positive),
`connect_phase_reset_does_not_trigger_aimd_decrease` (wave-phase
negative).

A congestion event also discards the in-flight window (congestion-
polluted observations must not enter the baseline). Recovery is
structurally sound: baseline reset -> a recovery/spec-window close ->
the `evaluate` establishment branch optimistically probing
`min(2n, cap)` straight back to the cap. "No recovery" at cap 1 is the
shadow of an empty probe space (1 -> 1 is always Hold), not a defect of
the recovery path.

### SFTP seam

Under the single-connection model AIMD tunes the pipeline depth instead
of the connection count (domain 1..=`SFTP_PIPELINE_DEPTH_MAX`, 32). The
controller is domain-agnostic (it counts and clamps against a cap); a
future SftpTransport constructs
`AimdConfig { max_connections: SFTP_PIPELINE_DEPTH_MAX, .. }` to plug
in. The SFTP transport itself is out of scope of this module.

## client.rs (reqwest client wrapper)

Manual redirects: the client is built with `redirect(Policy::none())`,
so the redirect loop is fully controlled in this layer — each hop
rebuilds the request, rejects loops via a visited set, and enforces the
hop cap (`MAX_REDIRECTS`, cross-checked against aria2 `--max-redirect`,
default 20).

- Loop detection key = (scheme, host, port, path): query is not resource
  identity, so a query-variant loop (`/a?i=1` -> `/a?i=2` -> ...) must
  be rejected as RedirectLoop instead of burning the hop budget into a
  RedirectLimit misreport.
- Credential scope = (scheme, host, port): any change counts as
  cross-host and strips credential-class headers (`Authorization`,
  explicit `Cookie`, `Cookie2`, `Proxy-Authorization`). Stripping is
  monotonic and irreversible: an adjacent-hop comparison would let a
  same-host self-hop after a cross-host hop recompute keep back to true
  and leak the origin credentials (one hop is enough for an attacker to
  harvest them), so stripping only ever advances. Jar / task-store
  cookies are unaffected (domain matching never crosses domains by
  itself; `cookies::CookieJar` / `cookies::CookieStore`).
- https->http downgrade is rejected by default; even when allowed, the
  scheme change strips credentials (conservative, aligned with browser
  semantics).
- Redirect-target IP hygiene (`crate::redirect_guard`): the initial URL
  is classified once (before the first hop, `all` rule — a mixed-family
  host must not form a restricted anchor); each hop target is checked
  under the `any` rule (resolution failure fail-closed); a restricted
  target with a non-restricted initial aborts with
  `HttpError::RedirectToRestrictedIp` — the SSRF / intranet-probing
  surface of a malicious source 302-ing to cloud metadata or intranet
  host:port. localhost/LAN initial URLs allow all hops (aligned with
  the initial policy; trusted topologies unaffected).
- Data-plane fragment/probe requests send `Accept-Encoding: identity`
  (the compression single-fact: a response still carrying a
  non-identity encoding routes the probe layer to its downgrade path).
  `identity_encoding = false` hands negotiation back to reqwest
  (reserved). The probe plane runs on a transport with
  auto-decompression off — automatic decompression strips the raw
  `Content-Encoding` header and would blind the probe decision.
- Task cookies: `RequestCtx.task_cookies` attaches a per-task store;
  `Set-Cookie` from every hop response is absorbed and replayed per
  RFC 6265 domain/path/Secure. Layered under cross-host credential
  stripping: explicit cookie pairs / credential headers are still
  stripped; store cookies are bounded by domain matching (a Secure
  cookie is not replayed across an https->http downgrade).
- Retry parameters are only registered here (`RetryPolicy`); driving
  belongs to the extent-level consumer — the client never retries
  implicitly, avoiding double counting.
- Connection pool `pool_idle_timeout = 90s`; h1/h2 both available (the
  workspace reqwest `http2` feature is enabled): https negotiates h2
  via rustls ALPN (http/1.1 fallback when the server lacks h2);
  plaintext h2c prior knowledge is the `HttpProtocol::Http2`
  experimental switch (`--http-protocol`, default Auto = status quo).
  3xx hop response bodies are drained to EOF (cap
  `MAX_REDIRECT_DRAIN_BYTES`) so the connection returns to the pool;
  past the cap reuse is abandoned.

### Authentication boundary

- Basic is pre-sent on the first hop. Digest is challenge-response: a
  401 `WWW-Authenticate` challenge -> `crate::auth::respond_digest`
  builds the re-answer, answered exactly once per URL; a further 401 =
  `HttpError::AuthFailed`. Exception: a `stale=true` challenge
  (RFC 7616 §3.6 — only the nonce expired, credentials valid) allows
  one re-answer, at most once per URL.
- Multiple challenges in one header (RFC 9110 §11.6.1 list) are parsed
  by `crate::auth::parse_www_authenticate`.
- `--http-user/--http-passwd` serve both challenge types with one
  credential pair (isomorphic to aria2 `DigestAuth.cc`) — credentials
  are extracted equally from both `AuthScheme` variants.
- A server 401 with no credentials present is re-raised as-is (the
  probe layer's 401 classification is unchanged).

### Shared client pool and warm-pool signal

- `SHARED_CLIENTS`: `HttpClient::new` (empty jar) returns a cheap clone
  of one transport instance per full `ClientConfig` key, so reqwest's
  pool (90s idle) survives across tasks and Range slices. Isolation:
  the full config is in the key (zero cross-config connection
  sharing); `with_jar` never pools (task-private jar); task cookies
  live outside the shared jar (read-only at runtime); pool semantics
  belong entirely to reqwest. Entries are never evicted (finite config
  combinations); safe across runtimes (hyper dials lazily and
  health-checks dead connections on use).
- `HOST_WARMTH`: a per-host "data-plane success within the 90s window"
  timestamp table (capacity `HOST_WARMTH_CAP`, LRU by last-lit; reads
  never touch recency) consulted at the connection-stagger site: warm
  hosts skip the first-wave ramp (pooled reuse likely), cold hosts keep
  it (guards against same-instant connect storms). Only the data plane
  lights it; the probe plane's connections are pool-separated.

### h2 tuning

- Default flow-control windows: stream 8MiB, connection 16MiB
  (`DEFAULT_H2_STREAM_WINDOW` / `DEFAULT_H2_CONN_WINDOW`); hyper's
  library defaults (2MiB/5MiB) remain reachable only through the
  programmatic `None` path.
- `http2_max_connections` (experimental): K independent transport
  instances (reqwest merges pools per origin, no K-connection API);
  data-plane requests spread by atomic round-robin; ineffective on h1.
- `http2_keep_alive_interval` (experimental): PING probes for idle
  pooled connections, timeout = 2x interval; `keep_alive_while_idle`
  is forced on — with reqwest's default false, hyper never pings idle
  connections and the feature would be void (wire evidence:
  tests/h2_mock.rs).

### Error classification seam

reqwest errors are stripped of the URL (no query/credential leak
surface) and the chain is expanded to one line. Before flattening into
`Transport(String)`, the error is classified single-sourced through
`taiji_io::dns::classify_error_chain` into
`taiji_http_errors_total{class}`. Permanent DNS failures (NXDOMAIN
class) are carried typed as `HttpError::DnsPermanent` (retry semantics
cross-checked against aria2 `NAME_RESOLVE_ERROR` direct failure,
`AbstractCommand.cc`); the string code stays `taiji.http.transport`.
`Other` is not counted.

### CA certificates

`--ca-certificate` loads PEM `CERTIFICATE` sections only (aria2: "must
be in PEM format"; bare DER rejected). With verification on, the
file's CAs **replace** the platform trust store (`tls_certs_only`,
aria2 replacement semantics, not append); with
`--check-certificate=false` the file is ignored unread. Load/parse
failure = client build error, never silent.

## redirect_guard.rs (redirect-target IP hygiene)

Defect closed: the manual redirect loop previously checked only the
scheme whitelist / https downgrade / loop detection, so a malicious
HTTP source could 302 to `http://169.254.169.254/latest/meta-data/`
(cloud metadata) or any intranet host:port (error shape and timing
differences report intranet liveness / open ports back through task
state), and the response body would be written to disk. The FTP surface
(`crate::ftp::PasvAddressPolicy`) and the BT surface (`addr_hygiene`)
already had equivalent defenses.

Classification table (restricted = true):

| Class | v4 | v6 | Basis |
|---|---|---|---|
| Loopback | `127.0.0.0/8` | `::1` | RFC 1122 §3.2.1.3 / RFC 4291 §2.5.3 |
| RFC1918 private | `10/8`, `172.16/12`, `192.168/16` | — | RFC 1918 (std `is_private`) |
| Link-local | `169.254.0.0/16` | `fe80::/10` | RFC 3927 / RFC 4291 §2.5.6 |
| ULA | — | `fc00::/7` | RFC 4193 |
| v4-mapped | — | `::ffff:0:0/96` -> embedded v4 | RFC 4291 §2.5.5.2 |
| NAT64 | — | `64:ff9b::/96` -> embedded v4 (WKP) | RFC 6052 §2.1 |
| Unspecified | `0.0.0.0` | `::` | RFC 1122 / RFC 4291 §2.5.2 |
| Multicast | `224.0.0.0/4` | `ff00::/8` | RFC 1112 / RFC 4291 §2.7 |

Notes: the cloud-metadata endpoint 169.254.169.254 sits in the v4
link-local range. The NAT64 local-use prefix `64:ff9b:1::/48` is not
listed (outside this spec's list). Everything else is non-restricted
(publicly routable). Deliberately **not** listed (the
anti-over-blocking red line): CGNAT `100.64/10` (carrier middle range,
not the local intranet), RFC 5737/3849 documentation ranges (test
surfaces, no intranet-reachability semantics), and the deprecated
site-local `fec0::/10`.

Decision policy (aligned with the initial classification):

- The task's initial URL is classified exactly once (before the first
  hop, `classify_host_all`) under the **all** rule: all resolved
  addresses must be restricted to form a restricted anchor — a
  mixed-family host (public A + restricted AAAA via static DNS
  poisoning) must not form one, or the "restricted initial -> allow all
  hops" short-circuit branch disables the whole guard.
- Each redirect hop: the target is classified under the **any** rule
  (`classify_host_any`); a restricted target with a non-restricted
  initial aborts with `HttpError::RedirectToRestrictedIp` (payload
  carries the target host, no credentials).
- A restricted initial (localhost/LAN task) allows every hop: trusted
  LAN/tunnel topologies (local services, router admin pages, intranet
  mirrors) are real usage, same spirit as the FTP surface's "pass when
  the reply equals the control peer".
- Host decision order: `pinned_resolve` pins (reqwest's overrides layer
  sits above the injected resolver — the pin address is the actual
  connect target, so a decision ignoring pins would be a bypass seam) >
  literal IP classified directly (zero resolution) > shared resolver.
  Pins/literals are single-address decisions; any/all differ only on
  resolver address lists.
- Failure surface (fail-closed, differentiated by rule): a hop target
  that fails to resolve / yields an empty list is rejected as
  Restricted — such a hop could not download anyway, and negatives are
  not cached, so allowing would leave a deterministic two-query bypass
  (guard query -> SERVFAIL, connect query -> private address). An
  initial anchor that fails / yields an empty list counts as Public
  (guard stays armed): an empty list carries no "all restricted"
  evidence, and all-over-empty (vacuous truth) forming a restricted
  anchor would disarm the guard — an opening in the opposite direction
  of the per-hop fail-closed surface, deliberately not taken.

Residuals (registered):

- any/all divergence shows only on resolver multi-address lists:
  all-public and all-restricted lists decide identically under both; a
  mixed family is Public as an initial anchor (tightened) and
  Restricted as a hop target (conservative). Over-blocking shape: a
  legitimate dual-stack host (public A + ULA AAAA intranet service) as
  the initial URL arms the guard as public, so hops to its intranet
  address are rejected — the user resolves this with a literal-IP
  initial URL or `pinned_resolve` (single address, no rule ambiguity).
  A mixed hop target is rejected even when connect path selection would
  land on the public address (selection prefers v4 and shares nothing
  with the decision) — conservative, security-first.
- Failure-surface residual: the guard decision and the connection are
  two independent queries (negatives uncached). "Guard fails + connect
  succeeds" is closed by fail-closed (reject on failure, no bypass);
  "guard succeeds + record changed before connect" falls into the
  rebinding window below.
- A theoretical DNS rebinding window remains between decision and
  connect (the record changes in between). The shared resolver's TTL
  cache makes the two queries mostly same-source same-value: the window
  is narrowed but not zero (not pin-elimination — the same water level
  as industry-wide redirect protection). Resolver and transport share
  the `taiji_io::dns::SharedDns` process-level instance
  (`SharedDns::shared_default`).

## cookies.rs

### PSL generated tables

The multi-label public suffix tables live in
`cookies_psl_generated.rs`, a committed file produced by
`scripts/gen_psl.py` from the official PSL (publicsuffix.org): the
exact table (ICANN + PRIVATE + legacy curated segments, 8672 entries),
the wildcard table (`*.tail` normalized form, 311 entries) and the
exception table (`!` rules minus the prefix, 8 entries; www.ck plus 7
Japanese city domains). The single-label-rule exclusion criteria are
documented in that file's header. The generator never runs at build
time (no build.rs, no network fetch), so builds stay offline and
deterministic; the table ships with the source and is refreshed by
re-running the script.

### Multi-label public suffix decision

`is_multi_label_public_suffix` mirrors libpsl's three-step check and
the order is semantic — exceptions beat the other two steps:

1. Exception table hit -> NOT a public suffix: exception entries are
   themselves registrable domains (`www.ck` beats `*.ck`,
   `city.kawasaki.jp` beats `*.kawasaki.jp`).
2. Exact table hit (`co.uk`, `github.io`) -> public suffix.
3. Wildcard table: strip the leftmost label from the candidate and
   probe `*.{tail}`; a hit -> public suffix. `*` matches exactly one
   label, so `foo.kawasaki.jp` is a public suffix (rejected) while
   `bar.foo.kawasaki.jp` is a registrable domain (allowed).
   Single-label tails behave the same: `*.ck` makes `foo.ck` a public
   suffix and `a.b.ck` registrable.

All three tables carry a strict-alphabetical-order invariant (locked
by self-check tests), which keeps `binary_search` at O(log n); at
8600+/311/8 entries a linear scan would turn every property resolution
into an O(n) full sweep.

### Cookie-harvesting defense (why the tables exist)

A domain cookie whose domain is a public suffix — single-label
(`.com`/`com`) or multi-label (`.co.uk` exact, `foo.kawasaki.jp`
wildcard) — is dropped on every ingestion face (Netscape file parse
and Set-Cookie alike): tail-match would send that cookie to any
.com/.co.uk sibling site, a classic harvesting attack. Host-only
single-label domains (localhost) and exact domains (co.uk as its own
site) are unaffected; exception entries (registrable domains such as
`www.ck`) pass. Both sides of every comparison — request host and
`Domain` attribute — are normalized the same way (lowercase, DNS
absolute-form trailing dots stripped), because the url parser
preserves trailing-dot host forms and an unnormalized `Domain=co.uk.`
would slip past the tables while still tail-matching a trailing-dot
host (leak face: the trailing-dot sibling site).

### Runtime entry cap

The file parse path is bounded by the 1MiB `MAX_COOKIE_FILE_BYTES`
cap. Runtime `Set-Cookie` ingestion is bounded separately by
`MAX_RUNTIME_COOKIE_ENTRIES` (4096): a malicious server can inject
any number of headers per response, and without a cap memory grows
without bound. Eviction is least-recently-active; same-key updates
refresh recency, never count as new entries and never trigger
eviction. `seed` bypasses the cap on purpose: its call sources (the
1MiB-capped file, structured direct passing) are bounded already, and
capping would silently drop the caller's explicit injection set.

## worker.rs

### First-wave connect stagger

The k-th first-wave worker delays its first connect by k x 5ms
(`CONNECT_STAGGER_MS`), capped at ordinal 64 (~320ms). A 16-connection
wave therefore spreads over ~75ms, so the number of connects arriving
inside one accept window stays bounded and server accept queues — the
loopback test fixture and real servers alike — are not overrun; an
overrun surfaces as RSTs that burn seconds of startup in failed retry
rounds. Scale waves carry no delay (not a storm shape). A warm pool
skips the stagger: a recent data-plane success on that source host
(`uri_on_warm_pool`) means the connect likely lands on a pooled
keep-alive connection with zero setup, and waiting would be pure
loss.

### Failure budget and the aria2 correspondence

`failure_budget_step` resets the budget to 1 when the fetch wrote
bytes (heartbeat write watermark > 0) and increments otherwise. This
mirrors aria2's `mMadeProgress -> mNumFailed=1`: aria2 resets
mMadeProgress at each download execution start and sets it during
execution; one fetch is one execution, so the per-fetch watermark is
its exact counterpart. A sticky cross-fetch progress flag is
deliberately avoided: stickiness would retry a source forever after
it fully dies, breaking the cap's negative closure. Progress is
task-progress evidence, not source-health evidence — the removal
ledger (source window failure rate) still books downgrades and
removals regardless.

### Retry backoff tiers

Ordinary failures keep 200ms (thundering-herd guard for unknown
source health). Connection-reset signatures drop to 50ms: an RST is a
connection-level single event, other connections to the same host
still flowing is direct evidence of source health, and the failed
extent is already abandoned and claimable — the backoff only delays
the resetting worker's return. A server `Retry-After` wins over
everything after clamping (30s ceiling, 200ms floor); the user's
`--retry-wait` never overrides it (different domains). All arms add
0-25% additive jitter so simultaneous same-source failures across
tasks do not retry in lockstep. A `RetryAfter` abandon carries the
clamped (not fuzzed) window back to the pool, so no other worker
claims the extent inside the server's wait window. Retry density
stays bounded by `WORKER_FAILURE_CAP` and AIMD multiplicative
decrease.

### Per-host permit yield

A worker holds its per-host permit only for the active round (claim
-> allocation/park decision -> fetch). Before parking on an empty
pool, and before any backoff >= 500ms, the permit is dropped (count
falls back, `notify_one` wakes waiters) so other tasks' connections
to the same host are not pinned by one parked or backing-off worker;
the re-acquire re-queues at the existing claim point (no queue
jumping). Short backoffs keep the permit to avoid acquire/release
churn. Releasing a permit is never a worker exit: the pool ledger's
note_spawn/note_exit pairing is unaffected. The wait for a contended
permit is observed as a zero-byte rate sample with the cap_waited bit
(input to the cap-contention window exclusion).

### The fatal slot vs the 412 restart signal

One worker-exit slot (`WorkerRig::fatal`, written via `set_fatal`),
consumed by the task driver tick. The slot is priority-ordered with
first-writer-wins within a rank, so two workers hitting different fatal
faces on different sources inside one tick cannot race the consumption
order; shadowed/superseded signals are logged, never silently dropped:

- `Fatal::Protocol` (rank 2; `(HttpError, String)`) — deterministic
  protocol contradictions: `RangeIgnored` (download-time 200 after
  the probe confirmed range support = capability drift) and `BadRange`
  (a 206 whose content-range echo start is mismatched, missing or
  pathological; the client layer's `validate_range_echo` converges all
  exits to BadRange). Both are code-8-family contradictions (the
  isRangeSatisfied failure family): retrying only collects the same
  response again, so the failure is terminal and never burns the
  failure cap or backoff. End-point dimension deviation is excluded:
  a start-matching long deviation is tolerated by the read loop
  (over-send books success, under-send retries as partial progress),
  keeping the fatal face narrowed to the start dimension. Multi-source
  per-source isolation would need coordinator message extensions;
  explicit failure is the fail-closed direction.
- `Fatal::Restart` (rank 1): `PreconditionFailed` (412, If-Match
  rejected). 412 is a self-healing deterministic fact — the driver
  clears the bitmap and re-downloads from zero after a re-probe;
  unlike `Fatal::Protocol` it is not terminal.
- `Fatal::NoSource` (rank 0): acquire returned NoSource with pool
  slack — all sources removed; task-level failure.

### Stolen extents and the heartbeat ring

Dynamic scheduling groups assemble an `ExtentHeartbeat` per fetch:
byte-heartbeat production (cadence + pause catch-up + final flush,
driving the decision face's write watermark and block-completion
decisions), write-right cancellation consumption (a watchdog for hung
transports), and block completion reported as written. The steal
resume point is the watermark byte boundary, so the owner's written
region is never re-granted and double-write waste stays within one
sub-block of in-flight overshoot. A worker that loses the write right
stops writing and finishes without abandon, failure count, or success
report. The failure arm flushes the watermark before abandoning:
without it, a fast-failure shape (mid-body RST before the first 1s
beat) leaves covered at 0, the reclaim domain degrades to the whole
unwritten extent, and the written prefix re-downloads in a loop
against the failure cap. The static baseline keeps the old
block-aligned whole-block catch-up (block b complete iff
(b+1)*bs <= written end) and assembles no heartbeat, so its failure
budget and AIMD behavior are unchanged.

### Slow-start criterion

Two arms on the RuntimeStats poll: total AIMD connections across
sources >= cap x registered sources, or any source's AIMD settled
(first Hold window: gain below ~10%, i.e. aggregate rate at ~90%+ of
baseline, or cap reached). No AIMD state -> always false; the metric
only samples dynamic tasks.

## naming.rs

### Channel tiering (competitor anchors)

URL/Content-Disposition derived names are the dirty-data source
(server-controlled attack surface); pure rejection would cost a
meaningful failure rate, and no competitor rejects illegal characters
outright. The full channel (`sanitize_generated_name`) maps illegal
characters, control codes, spoofing codepoints and separators to `_`
— separators included so the product stays a single path component
(Chromium/Motrix do the same; aria2 uses %XX escaping, this module
follows the GUI-product mainstream). Control codes are replaced, not
deleted (surge deletes; Chromium/Motrix replace). Windows reserved
names get `_` appended to the stem (Chromium prefixes `_`; this
module matches Motrix sanitize.rs with a suffix, which sorts better
on stems). Truncation keeps the extension within 254 bytes, the same
value as Firefox `kDefaultMaxFileNameLength`; the budget is sized for
the full `<final name><auto-rename marker><incomplete suffix>` form,
because a 254-byte final name plus `.part` overflows `NAME_MAX`
(macOS error 63). The empty fallback `download` matches Chromium
`kFinalFallbackName`. The light channel (`sanitize_user_name`) for
user-explicit `out=` names strips path components (including `X:`
drive prefixes — Windows `Path::join` replaces the base directory for
prefixed arguments, a cross-directory write face), applies the same
truncation and reserved-name suffix, but does not replace characters:
touch user names minimally and hand illegal characters to the OS
error (surge `ResolveDestination` consensus). The acceptance layer
(`sanitize_out_option`) already rejects separators, colons, reserved
names, trailing dots/spaces and spoofing codepoints with a 255-byte
cap; the light channel enforces the engine budget beneath it.

### Explicit non-goals

- NFD normalization: not done on macOS (only ChromeOS among Chromium
  ports; no competitor does it).
- `\\?\` long-path prefixes: the industry truncates by byte cap
  instead; no competitor adds the prefix.
- FAT32/exFAT special-casing: the 254-byte cap covers them
  implicitly.
- Extensions longer than 24 bytes are treated as payload (truncate
  whole, do not keep the extension), matching Motrix sanitize.rs
  `MAX_EXTENSION_BYTES`.

### Incomplete suffix

`--http-incomplete-suffix` (default `.part`) is a `taiji.*` extension
option (industry convention hardcodes `.part`/`.crdownload`). Strict
validation (`^\.[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`, hand-rolled —
regex is not a crate dependency) collapses the path-injection surface
to the naming domain; out-of-domain input is always
`taiji.option.invalid`. The suffix is persisted into
`http_task.config_json` at creation and restore prefers the persisted
value over the session default, so a default change never breaks
in-flight resumes. Conflict checks and auto-renaming run with the
configured suffix.

### Creation-time conflict check vs aria2

`plan_output` resolves conflicts at task creation: target exists ->
rename per the aria2 candidate algorithm (`renamed_candidate`, direct
translation of `RequestGroup.cc` `fmt("%s.%d%s", fn, i, ext)`) or
reject. The occupancy predicate unions disk presence with the
in-process final-path registry (an in-flight task's decided-but-not-
yet-written name counts), and the claim is taken on the final path —
before the fix the claim hung only off the `.part` path, so two tasks
with different suffixes could race and finalize's atomic rename would
silently swallow the earlier final file. One listed aria2 difference:
aria2's candidate check also probes for an `.aria2` sidecar control
file; this engine keeps control state in sqlite (the DB is the
journal), so candidates check only the target name.

## transport.rs

The HTTP `SegmentTransport` implementations
(`crates/taiji-http/src/transport.rs`):

- Assembly contract: one transport instance per worker, bound to its
  URI/source ordinal (the per-source accounting key propagates for
  real; EWMA share arbitration belongs to the coordinator). The
  frozen trait signature carries no `SegId`, so the worker registers
  the allocated extent ordinal via `HttpRangeTransport::arm` before
  `fetch` (the `SegId` carrier seam). Disk writes go through the
  injected `SegmentSink` (no taiji-store dependency; the DB/bitmap
  pipeline belongs to the core-side sink).
- Final-URL jump (`request_uri`): the data plane starts from the
  redirect-final URL converged at probe time instead of re-walking
  the redirect chain per request — one source round trip and one
  per-worker origin keep-alive/TLS connection saved per block (the
  measured earlier shape was two sockets per data connection: the
  origin 302 connection plus the mirror data connection; static and
  dynamic scaling amplified the same cost during ramp-up). Mirrors
  aria2 `Request`'s redirected-URI cache (final URL pinned,
  re-resolve on invalidation). Injection is single-source only: for
  multi-source tasks the convergence holds only for the
  authoritative source, so `None` re-walks the chain conservatively.
  A start-hop transport error with start != source-entry URI falls
  back to the original chain once (the redirect chain is the only
  authoritative mirror-discovery face; success self-heals the start
  via `note_final`). When the start URL and source entry differ in
  origin, challenge credentials are stripped — the same
  cross-endpoint rule as the manual redirect loop (a 302 across
  hosts carries no Authorization anyway); same-origin keeps ctx
  intact so 401 challenge-response semantics are unchanged.
- Download-phase 200 after a 206 probe = explicit failure
  (`HttpError::RangeIgnored`), the same verdict as aria2
  `executeDownload`'s "Expected partial, but received OK" →
  STATUS_CANNOT_RESUME. No extent-retry burn (deterministic shape,
  retry is worthless) and no silent restart from zero
  (misaligned-overwrite risk). Chosen over degradation for three
  reasons: (1) the reference fails on the same shape; (2)
  degrading discards all bitmap progress and re-downloads in full —
  bandwidth papering over a protocol contradiction, and the server
  has just proven its responses do not match its requests, so
  without a `--checksum` backstop trusting its full body carries a
  data-correctness risk — degradation rewards misreporting; (3)
  degrading means no bitmap and recovery from zero — a running grid
  task switching to a single connection is outside the engine's
  scheduling surface. The probe-time 200 shares the status code but
  not the decision: there it is a source-capability verdict
  (SPEC §4.2 table rows 3/4) routing to single-connection
  degradation before any grid exists.
- 412 (If-Match rejected) maps to `HttpError::PreconditionFailed`:
  deterministic, retry-worthless, same family as the probe-time
  416 + `bytes */N` → BadRange. The consumer goes fatal once, the
  task clears the bitmap and re-downloads from zero — misaligned
  bytes are rejected server-side and never reach disk, without
  waiting for the checksum to adjudicate. A 412 without If-Match
  (odd server) takes the same mapping; restarting from zero is the
  safe direction.
- 429/503 carrying `Retry-After` (aria2 `parseUnavailableHeaders`
  shape): the error carries the server-suggested wait explicitly;
  the consumer clamps it (`retry::clamp_retry_after`) before
  backing off. Missing/malformed header → plain
  `UnexpectedResponse` (politeness is best-effort; a malformed
  header is not a failure).
- Length-dimension deviation tolerance: `validate_range_echo`
  anchors only the 206 start; the read loop closes out body-vs-
  requested deviations. Over-send: stop reading at the requested
  amount and drop the Response (closing the connection early — an
  unread body keeps hyper from pooling; surplus bytes discarded,
  success booked for the requested amount). Under-send (early EOF):
  bytes read are already booked (partial progress); the trailing
  short-read error takes the existing failure arm — abandon returns
  the extent at the watermark and the remainder retries. Exact-full
  ends cleanly with the connection pooled (no pool-economics
  regression). The old `body overruns extent` rejection is retired
  on the Range face.
- Unknown-length stream cap (`MAX_UNBOUNDED_STREAM_BYTES`, 1 TiB):
  identity streams have no amplification and real large files
  declare Content-Length or support Range; encoded amplification
  (gzip bombs >1000:1) is cut here. Uncapped, an endless stream
  never trips the read-idle timeout (the 60s timer advances only
  without progress) and would write/decompress to ENOSPC. aria2 has
  no corresponding cap — a deliberate tightening. Cap selection
  (`stream_cap`): only the EOF-delimited sentinel (`u64::MAX-1`,
  the only length that can exceed the engine's declared 16 TiB
  domain) is capped; bounded forms pass `u64::MAX`.
- Degraded single connection (`HttpBodyTransport`): full GET,
  `complete_block` always Ok (FileSink semantics), honest
  `SegId{0,0}`. The read loop enforces the same
  bound discipline (`body_stream_step` / `stream_cap`) the Range
  face has; its error shape keeps the `body overruns extent`
  Transport payload (no Range echo anchor exists, so any overrun
  contradicts the probe declaration and is not tolerated).
- Outbound URIs in logs/errors pass `redact_uri` (query/fragment
  stripped), the crate-wide single redaction point. Both
  transports feed `request_seconds{phase=total}` at extent level,
  success and failure sampled alike.

## sources.rs

Per-source health ledger and EWMA-weighted share arbitration
(`crates/taiji-http/src/sources.rs`):

- Health vs rate: the two ledgers do not substitute for each other —
  rate weights come from the per-source EWMA (`crate::rate`,
  allocation preference: fast sources claim more); demotion/removal
  is driven by transport-class extent failures (source reliability,
  the admission decision).
- Windowed failure rate: within the last `OUTCOME_WINDOW` (8) extent
  outcomes, failures >= `DEMOTE_THRESHOLD` (3) demote (weight
  halved), >= `REMOVE_THRESHOLD` (5) remove (terminal). The window
  domain replaces "consecutive in decision order" for concurrency
  correctness: success and failure reports arrive interleaved, and
  an isolated success zeroing a consecutive counter would let
  failure/success flapping evade demotion/removal forever — the
  worker failure-cap rebirth loop (spawn → fail 5 extents → exit →
  respawn) would never converge on budget. The window is robust to
  interleaving while not wronging healthy sources: successes push
  failures out of the window and a demoted source recovers full
  weight once in-window failures fall below the demotion threshold
  (an isolated success never clears the account).
- All removed with pool work remaining → `taiji.http.no_source`
  (re-entry would let a faulty source pollute shard progress
  repeatedly). Unregistered ordinals count as removed.
- Runtime length drift: probe-time mismatches are decided by the
  `crate::probe` merge table (`mirror_mismatch` / `--checksum`
  length-group elimination); runtime drift surfaces as that
  source's Range/transport-class failure, is booked in this ledger,
  and removal hands the unfinished work to the survivors.
- EWMA-weighted share arbitration (layered on the coordinator's
  composition formula, never rewriting it): source i's in-flight
  undecided holdings must not exceed `live × w_i / Σw`; an
  over-share allocation clamps to the min-chunk floor, within-share
  allocations pass through unchanged. Weights share the unit of
  rate (bytes/s): established sources take their EWMA; unestablished
  sources anchor to the established-source mean (`DEFAULT_WEIGHT`
  equal shares only when no evidence exists at all). The anchor
  exists because shares normalize by `w_i / Σw` — a constant 1.0
  beside MB/s-scale EWMAs dilutes the unestablished source below
  the minimum granule (clamped starvation); mean anchoring starts a
  new source at the proven sources' average expected rate and
  transitions smoothly to measured weights. Non-finite/non-positive
  rates never count as evidence. Demotion stacks on the anchor
  (`DEMOTED_WEIGHT_FACTOR` 0.5); removed sources weigh zero.

## grid.rs

Block grid (`crates/taiji-http/src/grid.rs`) — the fixed-granularity
progress unit of the persistence layer:

- Two-layer position: the persistence layer keeps `block` (bitmap /
  resume / progress / RPC / recovery validation); the runtime layer
  keeps `extent` (block-aligned byte ranges that vanish on
  completion, never persisted; scheduling/retry/steal/multi-source
  allocation).
- Frozen bitmap seam (byte-compatible with the
  `http_task.block_bitmap` persistence encoding; any change is
  breaking): bit i = block i complete, LSB-first within a byte;
  tail bits beyond `block_count` invalid; the last block truncated
  by the authoritative total length (progress counts only real
  bytes); block completion is first-report-wins with late reports
  dropped (`BlockGrid::record` idempotent `false`; the decision
  point is `crate::coordinator::ExtentCoordinator`); `block_size`
  is task-level immutable after construction-time validation (no
  mutation face; runtime option changes rejected with
  `taiji.option.invalid`).
- Block completion does not mean the bytes are contiguously
  trustworthy: same-block double writes under steal races are legal
  (worst case wasted bandwidth, never interleaved corruption);
  accounting follows first-report-wins.
- Total-length ceiling 16 TiB (2^44): aria2 imposes no hard cap;
  this engine pins the worst-case bitmap allocation at
  `16TiB ÷ 256KiB (min block) ÷ 8 = 8MiB`, so a malicious 2^63-scale
  `Content-Range` total / `Content-Length` is rejected task-level
  (`taiji.http.total_length_exceeded`) and a giant bitmap
  allocation (`handle_alloc_error` aborting the process) is
  unreachable at the construction face. The probe face rejects at
  the same ceiling first; the grid re-checks as a pub-API defense
  (never assume the layer above has decided). Out-of-domain
  `block_size` is always rejected, no silent clamping
  (powers of two within 256KiB..16MiB).
- Line/ledger decoupling: `blocks_covered` keeps the strict
  block-aligned invariant for the static face (silently absorbing an
  unaligned start by division would fold a misaligned extent into a
  false block number and amplify into cross-block misaccounting);
  `blocks_spanned` takes floor/ceil division for dynamic line-level
  leases that may start at any sub-block boundary (the coordinator's
  in-flight register/unregister face).

## retry.rs

Retry/backoff parameters (`crates/taiji-http/src/retry.rs`):

- `--max-tries` (default 5) is redefined per-extent (aria2 reads it
  per download); `--retry-wait` (default 0s) is the exponential
  base; backoff ×2 capped at 30s (saturating arithmetic — attempt
  u32::MAX converges to the cap). Driving belongs to the
  extent-level consumer; the client never retries implicitly, so
  client-level and scheduler-level retries never double count.
- `Retry-After` parsing covers both RFC 9110 §10.2.3 shapes
  (delta-seconds and HTTP date, reusing the hand-rolled remotetime
  parser; a past date → 0 so clock skew never yields a negative
  wait); parse failure → `None`, the caller falls back to its own
  rhythm (politeness is best-effort, a malformed header is not a
  failure).
- Clamping (`clamp_retry_after`): server value wins over the
  `--retry-wait`-derived exponential rhythm — a throttle wait is a
  protocol signal from the server while user config is a client-side
  backoff parameter; different domains, server wins within its own.
  Ceiling = the 30s `max_wait` (a malicious huge value must not hang
  the task; the aria2 `MAX_RETRY_AFTER` shape); floor = 200ms
  (`RETRY_AFTER_FLOOR_MS` — `Retry-After: 0` / a past date must not
  degrade into machine-gun retries; engine magnitude instead of
  aria2's 30s).
- Additive-only fuzz (`fuzz_delay`, aria2 `fuzzDelay` shape):
  `wait × (1 + U[0, 25%])` spreads retry phases so same-instant
  same-source failures across tasks do not reconverge (self-sustaining
  thundering herd). Additive-only preserves every existing
  lower-bound semantics (the clamped server value, the 50ms RST
  short backoff) and cannot breach the 200ms floor or the 30s
  ceiling magnitude. Engine constant, no CLI knob. Scope = the
  three task-level backoff computation points (grid worker failure
  arm / per-piece arm / batch-group arm); not the probe face
  (independent 50ms-floor exponential rhythm + storm-window
  semantics) and not the generic `retry_with` helper (its consumers
  include the probe). Random source: hand-rolled SplitMix64, seed =
  nanosecond clock ⊕ process-level counter — independent sampling
  across tasks and backoff points (the reset-storm defense).
- `transport_retryable`: `Transport` transients retry;
  `DnsPermanent` (NXDOMAIN-class resolution endgame) never retries —
  aria2 fails directly on `NAME_RESOLVE_ERROR`
  (`AbstractCommand.cc` DL_ABORT_EX2); deterministic protocol
  errors / out-of-table statuses are not a retry face.
- `retry_with` feeds `taiji_http_retries_total` on real retry
  decisions only (exhaustion and non-retryable failures do not
  count); `retry_with_counted` is the registry-injectable form for
  tests.

## traits.rs

The three-trait contract (`crates/taiji-http/src/traits.rs`) — the
foundation crate's frozen seam with the media layer (signature or
supporting-type field changes require an ADR):

- async desugaring: `fetch`/`write_at`/`complete_block` are
  conceptually async, but `SegmentTransport::fetch` takes
  `&dyn SegmentSink`, so the trait must stay object-safe — RPITIT
  is not dyn-compatible and `async-trait` is not in the dependency
  whitelist. Hence explicit `BoxFuture` (`Pin<Box<dyn Future +
  Send>>`): a Send future awaitable across actor boundaries;
  implementors `Box::pin(async move { .. })`, no macro, no lifetime
  black hole.
- Scheduler-agnostic principle: the scheduler knows neither
  transport nor source — dynamic segmentation, adaptive concurrency,
  and retries apply equally to media segments; the three traits are
  the frozen face of that decoupling.
- `Extent`: runtime block-aligned byte range; vanishes on
  completion, never persisted. `end()` saturates on u64 overflow so
  bound comparisons stay conservative (no wrap into a false
  interval). Sub-block extents are forbidden (config domain).
- `SegId`: minimal pair frozen as final — `source` (per-task
  ordinal, the weighted-rotation accounting domain) and `extent`
  (coordinator-allocated ordinal, kept through a steal; runtime
  identity for sink instrumentation and diagnostics, never
  persisted).
- `RequestCtx` is deliberately transport-agnostic (no reqwest
  types) so FTP/SFTP adapters build their protocol faces from the
  same context; task cookies layer under cross-host credential
  stripping (explicit pairs stripped, store cookies bounded by
  domain matching per RFC 6265).
- `same_origin` = `scheme://host:port` (the per-host cap's host_key
  dimension); parse failure conservatively means different-origin
  (caller falls back as if the face were absent). Consumed by the
  transport's start-URL credential-scope decision.
- `ResumeValidator` fields are the probe record verbatim: strong
  ETag/Last-Modified + length → resume; path+length only → weak;
  mismatch → from zero; `--checksum` is the strongest validator
  (completion-time final say); `encoding_ok = false` means Range
  semantics are unknowable and the bitmap stays off.
- `SegmentSource` is deliberately not `Send + Sync`; consumers
  needing cross-thread holds express `dyn SegmentSource + Send +
  Sync` — more evolvable than retroactive supertraits (a breaking
  change inside a frozen seam).
- Sink contract: same-block double writes under steal races are
  allowed (worst case wasted bandwidth, never interleaved
  corruption); `complete_block` is the only entry point to the
  persisted bitmap, adjudicated at the coordinator's single serial
  decision point (first report wins; endgame steal ban enforced
  scheduler-side). Implementations should tolerate a concurrent
  call face consistent with disk writes (blocking IO on their own
  spawn_blocking side).

## rate.rs

Per-source rate EWMA (`crates/taiji-http/src/rate.rs`) — the rate
term of the scheduler's composition formula:

- Sample source: the write path takes permits through
  `limiter::ThrottledSink`; each `Permit` carries its wait duration
  (the observation seam). The sink reports
  `(source, bytes, permit_waited)` per write
  (`CoordinatorMsg::RateSample`); the ledger windows samples inside
  the coordinator actor: `rate = bytes / elapsed`.
- Throttle-dominated window exclusion: a window whose **largest
  single** permit wait exceeds 50% of its length (`THROTTLE_RATIO`)
  is discarded whole (no EWMA entry, no warmup advance) — folding
  local rate-limit waits into source rate would collapse extent
  sizes and distort the AIMD gain window. The max measure (not sum)
  is deliberate: summed waits grow linearly with concurrency, so
  healthy multi-connection sources each waiting 25% would read as
  100% throttle-dominated.
- Second consumer — stall-steal flow-control exclusion ("a
  rate-limit wait is not stall evidence"): `rate_limit_shadow`
  keeps a liveness shadow from the most recent qualifying permit
  wait; the decision face cross-checks before granting a steal.
  Shadow = `max(window, waited)`: the wait ends at the observation
  instant but covers the feeding period `[at − waited, at]`; when
  throttling stretches chunk gaps past the stall window (≈ < 4.3KB/s
  with 64KiB chunks / 15s window), a full window of zero growth is
  a pacing gap, and a low-rate-limit source should not be stolen
  from anyway (the thief shares the task rate limit — pure
  duplicate writes). A genuinely stopped server sends no chunks →
  no permit requests → the shadow expires and stall evidence stands
  (the exclusion misses nothing).
- Recording floor (`RATE_WAIT_FLOOR`, 100ms): sub-floor waits are
  pass-through/measurement noise (unlimited buckets still yield
  sub-microsecond nonzero `Permit::waited`); counting them would
  let unthrottled tasks refresh the steal-decision shadow on every
  write (over-exclusion). Fakeable stall rhythms sit far above the
  floor.
- Warmup (`RATE_WARMUP`, 10s): `rate()` returns `None` (formula
  rate term +∞ → pure guided) until accepted windows accumulate
  10s; discarded windows do not advance warmup (throttled rates do
  not reflect source capability). Smoothing α = 0.5 (one-sample
  half-life; converges within the 3s decision window); windows
  shorter than `MIN_WINDOW` (50ms) merge forward so bursty small
  writes do not pollute samples; zero-byte windows produce no
  sample (stalled observations belong to the stall face).

## pool.rs

AIMD connection execution ring (`crates/taiji-http/src/pool.rs`) —
materializes decision-face numbers as real worker spawn/exit:

- Boundary: `crate::aimd::AimdBook` (coordinator actor) only
  produces numbers; this ring (held by the HttpTask driver loop,
  Arc-shared) consumes `aimd_snapshot` values — grow = spawn
  directives, shrink = a lowered desired count that in-place
  workers resolve at extent boundaries (never interrupting an
  in-flight extent).
- Shrink protocol (surplus-slot claiming): `want(source)` is the
  downward target written only by `apply` (supervisor,
  single-threaded); `alive` is booked by `note_spawn` and worker
  exits. `should_stop` is a CAS verdict — only `alive > want` may
  claim an exit and self-decrement, so exits are bounded by the
  surplus at verdict time (no overshoot) and converge exactly to
  `want`; if `want` rises before a claimed exit lands, the surplus
  is gone and remaining workers stay (no claim-then-honor dangling
  tickets). Claimed exits must not call `note_exit` again.
- `note_exit` (failure cap / close-out cancellations) defends a
  zero floor with CAS: an exit visible before its spawn
  acknowledgment would underflow a naive `fetch_sub` into an
  astronomic u64 (desire comparisons distorted wholesale); the
  floor holds and a late acknowledgment self-heals the count.
- want semantics: snapshot value clamped `[1, cap]`; snapshot-absent
  sources (the AimBook is lazily built) keep the slow-start start
  `min(2, cap)` — `with_start` raises it with the user's explicit
  concurrency intent, sharing source and value with the decision
  face's `AimdConfig::with_start` (a decoupled start would make the
  first snapshot emit spurious directives); removed sources (the
  driver's projection of RuntimeStats source health) get want = 0
  — snapshot values never override a removal (removal wins), all
  registered workers claim out, and failover leaves the source no
  participation face.
- `fixed` is the static baseline: constant per-source desired, no
  snapshots, `should_stop` always false.
- All-atomic counters, lock-free; race face = single writer
  (supervisor) many readers (workers via `should_stop`/`note_exit`);
  no locks across await.

## ftp.rs

FTP/FTPS transport adapter (`crates/taiji-http/src/ftp.rs`) — the
[`SegmentTransport`] implementation over suppaftp 12.x (features
`tokio-rustls-ring` + `rustls-ring` + `deprecated`: rustls 0.23 +
tokio-rustls 0.26 match the workspace TLS stack version-for-version;
`rustls-ring` exists only to reach the crate's `suppaftp::rustls`
re-export for building rustls configs — the sync API is unused). The
session type is uniformly `ImplAsyncFtpStream<AsyncRustlsStream>`
(plaintext sessions hold `DataStream::Tcp`; after a TLS upgrade they
hold `Ssl` and the data channel is wrapped automatically — one type,
no enum dispatch).

Transport surface:

- Extent mapping: one control connection per fetch (pooled checkout or
  new); extent = `REST <offset>` + `RETR <path>`; the data channel
  goes through PASV/EPSV — a resolved IPv6 address family forces EPSV
  (RFC 2428; PASV has no IPv6 semantics), IPv4 uses PASV. A `REST 0`
  probe rejection (5xx) -> `FtpProbe::resume_supported` = false -> the
  scheduler degrades to a single stream (`DegradedReason::FtpNoResume`;
  no bitmap, recovery from zero, no new persistence form); an offset
  fetch hitting a REST rejection returns
  `HttpError::FtpResumeUnsupported`.
- TLS: explicit by default — upgrade only when FEAT advertises
  `AUTH TLS` (AUTH TLS + PBSZ 0 + PROT P, RFC 4217); no blind attempt
  without an advertisement — a server without TLS capability keeps
  plaintext: capability negotiation, not a silent downgrade (the
  no-advertisement path warns explicitly). Implicit TLS (990) via
  `FtpTlsMode::Implicit`. Certificate verification matches the TLS
  baseline (rustls ring + platform trust-store roots;
  `--check-certificate=false` disables explicitly with a warning).
  After PROT P the data channel rides TLS too (suppaftp wraps it per
  `tls_ctx`).
- PASV/EPSV address decision (SSRF hardening, `PasvAddressPolicy`):
  the data-connection dial target does not trust the 227 reply IP.
  Default `AlignPeer` dials only the control peer (reply port kept;
  aligned with aria2 `FtpNegotiationCommand.cc` `preparePasvConnect`:
  data endpoint = control peer address + PASV port; semantically the
  same as suppaftp `set_passive_nat_workaround`) — a malicious or
  MITM'd reply cannot point the client at any host:port (including the
  cloud-metadata endpoint 169.254.169.254). `DenyPrivate` serves
  asymmetric-NAT deployments: the reply IP is accepted, but
  private/loopback/link-local replies that differ from the control
  peer are rejected. `ReplyAsIs` (the `off` escape hatch) decides
  nothing — the 227 reply is dialed as-is (suppaftp's native behavior;
  the SSRF surface reopens, trusted networks only). The three states
  are expressed via `--ftp-pasv-address-check=peer|strict|off`
  (default peer), the value grammar pinned in
  `PasvAddressPolicy`'s `FromStr` (out-of-domain values rejected as
  `taiji.option.invalid`). Wiring: the config carries
  `FtpConfig::pasv_policy`, the task side projects through taiji-core
  `HttpTaskOpts::to_ftp_config` into every `FtpTransport::for_uri`
  construction site; the builder `FtpTransport::with_pasv_policy` is
  the explicit override. EPSV replies are already peer-aligned
  (suppaftp synthesizes control peer IP + reply port), so peer/strict
  agree with the peer and off adopts the synthesized address as-is.
  Implemented through suppaftp's `passive_stream_builder` hook; the
  data-channel connect is bounded by `--connect-timeout` too
  (suppaftp's default data connection has no timeout — closed here as
  well).
- Charset: path bytes prefer UTF-8, fall back to Latin-1 (fork
  behavior); a non-UTF-8 path is transcoded through Latin-1 and sent
  as a `String` — the wire bytes may deviate from the original
  percent-decoded bytes via UTF-8 re-encoding (a known boundary).
- Connection reuse (`--ftp-reuse-connection`, default true, aligned
  with aria2): control connections live across extents in the reuse
  pool; false = one connection per extent, closed with QUIT. The
  frozen trait signature has no worker identity bit, so the pool
  approximates "one per worker" by checkout/release; idle connections
  left over after an AIMD shrink close when the transport drops (the
  control plane's TCP close without QUIT; the server reclaims by
  session timeout). Before a pooled checkout a NOOP liveness probe
  runs: server-side timeout reclamation, half-closed connections, and
  desync from leftover replies are dropped and replaced at checkout —
  a stale connection's first-fetch failure never surfaces as an extent
  failure (the consecutive-failure ledger counts real transfer
  failures only). After a mid-extent truncation one completion reply
  is drained explicitly (suppaftp's drop semantics leave the reply for
  the next command and swallow 4xx replies — servers violating the
  RFC 959 single-reply contract with a 426+226 pair leave a residual
  tail after the drain; a non-2xx NOOP after the drain means the
  control plane is desynced: the connection is demoted to single-use
  and never returned to the pool).
- Auth: URI userinfo > `RequestCtx.auth` (Basic/Digest user/passwd
  both taken) > the anonymous/anonymous@ default (the aria2 default).

## partfile.rs

The `.part` on-disk surface (`crates/taiji-http/src/partfile.rs`):
positional writes + preallocation + a handle-closing guard before
rename.

Position in the write path: SegmentWorker -> SegmentSink (frozen seam,
`traits.rs`) -> in production the core-injected store disk layer (its
`write_all_at` positional writes + `--file-allocation` true
preallocation; the crate topology forbids taiji-http depending on
taiji-store). This module owns the HTTP-side task-file lifecycle — the
part decoupled from disk writes and coupled with the rename
orchestration:

- Open policy (`PartOpenPolicy`): degraded/length mismatch -> truncate
  from zero (recovery always restarts); length match -> keep
  resuming.
- Preallocation (`FileAllocation`, `--file-allocation`): `Prealloc`
  places the file with a trunc-semantics `set_len` (cross-validating
  aria2 `--file-allocation=prealloc`'s truncate fallback path; the
  platform fallocate fast path belongs to the store disk layer).
- Positional writes: unix `FileExt::write_all_at` short-write loop /
  Windows `seek_write` equivalent, same semantics as the store disk
  layer; blocking calls always run in `spawn_blocking`.
- Close before rename: `PartFile::close` releases the OS handle and
  produces the `HandlesClosed` credential — finalize takes the
  credential as its argument (type as proof: a rename cannot start
  with handles still open), satisfying Windows/SMB handle-sharing and
  oplock constraints.

Symlink defense: the open sets `O_NOFOLLOW` (platform constants
matching taiji-store `disk.rs`; std does not export them and
taiji-http has no rustix dependency) — a symlink preset at the `.part`
path must not be followed (following + set_len = truncating an
arbitrary local file); ELOOP propagates, no fallback.

In-process claim tables:

- `.part` claims: a session-scoped per-path registry —
  `PartFile::open` claims atomically (Mutex-serialized; the TOCTOU
  between a plan_output existence check and the actual open no longer
  admits co-writers), released on close or last-handle drop. The claim
  stays held while writes are in flight: the in-flight write count is
  incremented synchronously before `spawn_blocking` and decremented by
  the WriteTicket guard inside the blocking body; claim release is
  structurally ordered after all in-flight writes (guards hold
  `Arc<PartInner>`), closing the "stale write lands after truncate"
  revival window. A bounded defensive drain (100ms) covers a
  discipline-violating close; an open future abandoned mid-await is
  covered by a claim guard that releases on drop.
- Final-path claims: `final path -> holder gid`, spanning the task
  lifetime — taken when plan_output decides the output name, released
  when the rename settles (the finalize close-out) or the task is
  removed; held across the close->rename window and renamePending
  polling. Same-key re-claim is idempotent (task reactivation and
  poll rounds do not self-reject); a different holder gets
  `taiji.http.path_conflict` — the final path is a task's exclusive
  output domain (per-task incomplete suffixes do not isolate: two
  tasks with the same dir/out and different suffixes would both pass,
  and finalize's atomic rename would silently swallow the earlier
  final file). `release_all_final_claims` clears a holder's stale
  claims wholesale before a re-run (a gid drives at most once at a
  time — actor-serial activation — so key-scoped release only touches
  the task's own claims).
- Credential transfer: close **transfers** the `.part` claim into
  `HandlesClosed` instead of releasing it — the release point moves to
  rename settlement, so during the close->rename window (journal
  round-trip + probe + backoff retries) no new task may enter the same
  `.part`. A credential dropped without close-out (teardown/cancel)
  releases the claim immediately (the Drop backstop; no permanent
  in-process conflict); the renamePending shape keeps it via
  `hold_for_pending`.

Concurrency discipline: positional writes use no shared cursor
(`write_all_at`/`seek_write` are `&self`), so concurrent multi-worker
writes to one task file are legal (same-block double writes are
backstopped by the single-point accounting). `close` must run after
all in-flight writes complete (the worker set is joined first); writes
after close fail immediately (defensive).

## heartbeat.rs

The worker-side execution ring for stall stealing
(`crates/taiji-http/src/heartbeat.rs`) — the per-extent byte-heartbeat
producer and write-right cancellation consumer facing the coordinator
decision face (`crate::coordinator`).

Division of labor: the decision face (the `ExtentCoordinator` actor)
keeps stall evidence (`StallWatch`), grants steals at the single point
(the `last_acked+1` safety margin) and transfers write rights
(`HeartbeatAck::Cancelled`); the execution ring (this module, one
`ExtentHeartbeat` assembled per extent fetch) produces the byte
heartbeats (cadence + catch-up after a pause), consumes cancellation
(write right lost -> abort the fetch — the watchdog for hung
transports), and reports block completion as written (the
`last_acked` watermark advances with writes).

Heartbeat semantics ("the worker reports, once per second, the bytes
written since the last heartbeat"): stall = zero byte growth over a
continuous window (rate-independent — a slow connection that keeps
writing is not stalled). Two producers feed the coordinator on the
same cadence face:

- The ticker (one per extent, `ExtentHeartbeat::spawn_ticker`) reports
  the write-path byte delta each second; zero-growth beats do not
  refresh the stall baseline. A hung transport (server stopped, fetch
  stuck in a read) produces no write-path beats, so the ticker becomes
  the only delivery face for the cancel reply — after the write right
  is stolen, the next beat returns `Cancelled` and the watchdog aborts
  the fetch (otherwise the hung worker never returns and blocks task
  closeout).
- Pause catch-up (the write path, `SegmentSink::write_at` entry): if
  at least one interval has passed since the last **growing** beat, a
  fresh beat is sent before the write lands — when a steal grant lands
  inside a write pause (a slow/hung transport resuming), the resumed
  **first write** learns Cancelled here before touching disk, so zero
  new bytes land in the stolen region (the key closure for
  overlap = 0; ticker-only delivery lags up to one beat, enough for
  the owner to double-write the stolen first block). The catch-up
  timing baseline counts only growing beats: during a pause the ticker
  keeps sending zero-growth beats; if those refreshed the baseline the
  catch-up condition would be permanently false (dead code) and the
  first write would only learn of the cancel at the next beat — on a
  fast connection the stolen first block could double-write megabytes.

Block completion reported as written (the write-byte watermark; wire/
ledger decoupling): each write reports every block that has become
**fully written and fully inside the extent domain** (first arrival
wins, idempotent — see the coordinator module docs). Line-level leases
are byte-granular and an extent start can fall inside a block, so the
start block (its head belongs to the predecessor lease) is not in this
report domain; its completion is closed by the coordinator's
per-block byte-watermark-full decision (adjacent lease + thief
watermarks combined). The steal breakpoint is byte-granular for the
same reason (the `last_acked+1` block safety margin converges
in-flight overshoot to <= 1 sub-block); reporting as written keeps the
watermark advancing so a hung owner's written blocks are not swallowed
by the steal grant region. Unwritten regions are finished by the
thief; same-block double writes are backstopped by the single-point
block adjudication (no interleaved corruption).

Final flush: beyond the ticker/catch-up cadence, the worker flushes
the final watermark delta once after a successful fetch
(`ExtentHeartbeat::flush`) — the tail/shared block's watermark-full
decision does not wait for the next beat.

Assembly domain: dynamic scheduling groups only. The static baseline
assembles none: under static assembly the extent is not in the
decision face's in-flight ledger, every heartbeat would return
Cancelled, and all extents would wrongly stop writing. The assembly
decision belongs to the worker loop (core dispatches by scheduling
mode); this module is mode-agnostic.

Ticker abort guard (leak closure): the old form relied on the
caller's explicit `abort()` at the fetch closeout line; on paths where
the worker future is aborted wholesale between assembly and that line
(cancel/shutdown parent selects, task abort, panic) the ticker held a
strong clone of the host and kept beating forever (the `interval`
never ends and a stopped coordinator maps to `Beat::Live`), leaking
the sink chain and the watch sender. Two-sided closure:

- Drop-guard abort (`spawn_ticker` registers the task's `AbortHandle`;
  `Drop for ExtentHeartbeat` aborts when the last host handle is
  dropped) — the main closure: when the worker future dies, the host
  handles leave the stack with it and the ticker is reaped along the
  way, with no reachability requirement on the closeout line.
- Host-death self-detection (the ticker holds only a
  `std::sync::Weak`; a failed `upgrade` each beat exits) — the
  backstop: on every path but pathological strong retention, the
  strong count reaching zero self-heals.

Regression: `ticker_is_reaped_when_host_dropped_without_abort`
(`heartbeats_total` freezes after the host dies).
