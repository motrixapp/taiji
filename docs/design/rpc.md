# taiji-rpc design notes

Distilled design and upstream-anchor notes for `crates/taiji-rpc`.
Code module headers keep a short mechanism summary and point here.

## guards.rs

Threat-model residual-exposure countermeasures for the RPC surface
(`crates/taiji-rpc/src/guards.rs`):

- Unauthenticated connection floods -> `ConnLedger`: every inbound
  HTTP request / WS session holds one RAII lease (`ConnLease`), with
  separate total and per-source-IP concurrency caps (engine constants
  256/32; small values injectable for tests via `RpcGuards` — no CLI
  knobs). Over limit -> HTTP 503 + metrics
  `taiji_rpc_conn_rejected_total{scope}` + warn. The server layer
  (`ConnLeaseSlot`) transfers the handshake-request lease to the WS
  session (released on session exit); plain HTTP requests release after
  the response is produced.
- Online credential guessing -> `AuthBackoff`: consecutive auth
  failures from one source IP at or above the threshold (5, injectable)
  arm an exponential backoff window (first 1s, doubling per further
  failure, capped at 60s). While a window is active, every auth attempt
  from that IP — correct credentials included — sleeps until the window
  ends before processing (tokio async sleep, never blocking the
  runtime); a successful auth resets to zero. Failures at the token
  gate and the Basic gate accumulate into the same per-IP ledger.

Discipline:

- Credential contents never enter metrics or logs (standing rule); a
  backoff warn carries only the IP and the window length.
- Backoff state expires by lazy sweeping (no timers): inert entries (no
  window and below threshold) are swept only at the accounting access
  point (note_failure, triggered at the sweep line); the rendering
  access point (active_windows) only counts and never mutates the
  table — periodic /metrics scrapes must not reset failure
  accumulation. Over the table capacity cap the whole table is cleared
  (fail-open — availability over rate-limit bookkeeping; a warn counts
  the dropped entries).
- The credential-less localhost form never touches these ledgers: when
  neither the secret nor Basic is configured (decided at the call
  sites), behavior and overhead are unchanged.

## view.rs

aria2 JSON value surface (`crates/taiji-rpc/src/dispatch/view.rs`):
`CommandReply` (core semantic payloads) -> aria2-compatible JSON
rendering. Moved from dispatch.rs with the implementation unchanged;
visibility widened to `pub(crate)` for sibling reuse.

Responsibilities:

- `encode_reply`: field names / stringification for immediate semantic
  replies (getVersion/shutdown/addUri ...): GID hex16, length fields as
  string values, changeUri `[del, add]` integer list, getSessionInfo
  sessionId dict.
- tellStatus/tell* single-entry and list rendering: the field set
  branches by live/stopped (gatherProgressCommon +
  gatherProgressBitTorrent vs gatherStoppedDownload), keys filtering,
  pagination slicing and negative-offset reversal.
- getFiles/getPeers/getServers single-entry rendering and the
  bittorrent sub-dict.

Convention: numbers -> strings, booleans -> "true"/"false" (aria2 uitos
convention); all pagination arithmetic is saturating (security review
fix). Per-function upstream anchors live in the code comments.

## auth.rs

RPC authentication surface (`crates/taiji-rpc/src/auth.rs`): the
`token:` first parameter + HTTP Basic.

`token:` path (semantics frozen, cross-checked against the read-only
aria2 reference):

- Stripping: `RpcMethod.cc` — only when params[0] is a string starting
  with `token:` is it taken out and popped; otherwise params are kept
  as-is (a non-string first parameter is not stripped).
- Validation: `DownloadEngine.cc` validateToken — no secret set is
  always true; with a secret, the token must match. The reference
  avoids timing leaks through an HMAC indirection; this implementation
  is isomorphic: both sides are first folded to fixed-length SHA-256
  digests, then compared byte-wise in constant time — plaintext `==`
  compares length first and short-circuits per byte, leaking
  prefix-match progress (see `validate`).
- Failure: throw "Unauthorized" (RpcMethod.cc) -> code 1 + deferred
  flag.

Basic path, a direct translation of `HttpServer.cc` — plaintext
secrets do not linger: at construction (`BasicAuth::new`, matching
setUsernamePassword in HttpServer.cc) user/passwd are folded into
fixed-length tags by an HMAC-SHA1 keyed with an in-process random key
(`HMAC::createRandom`, util_security.cc; random key = digest length;
only ipad/opad are stored, util_security.cc). Only the tags are kept
afterwards; at compare time the HMAC of the incoming credentials is
computed fresh and compared in constant time (`HMACResult::operator==`
-> util::compare, util_security.h).

--rpc-secret (token path) and --rpc-user/--rpc-passwd (Basic path) are
two independent layers: in the reference, token consumes only
PREF_RPC_SECRET (DownloadEngine.cc) and Basic only
PREF_RPC_USER/PREF_RPC_PASSWD (HttpServerCommand.cc); with both set,
each layer gates independently (HTTP-layer Basic precedes RPC-layer
token).

## rpc_cookies.rs

Task-cookie direct-pass parameter parsing
(`crates/taiji-rpc/src/rpc_cookies.rs`; shared by
taiji.addUriWithCookies / taiji.setTaskCookies). Cross-checked against
`RpcCookie.cc parseRpcCookies` line by line, including all error texts
and the validation order:

- Cap of 300 entries ("Too many task cookies.").
- Each entry must be an object ("Task cookie must be an object.").
- Field whitelist = `name`/`value`/`domain`/`path`/`hostOnly`/`secure`/
  `httpOnly`/`expiresAt`; unknown fields are rejected explicitly
  ("Unknown task cookie field." — never silently ignored).
- `name`/`value`/`domain` are required strings, `path` is optional
  (default `/`), the three booleans are optional (type errors =
  "Invalid task cookie string/boolean field.").
- Syntax checks ("Invalid task cookie syntax."): name non-empty and in
  the RFC 6265 token charset, name+value <= 4096, domain non-empty
  <= 254, path <= 4096 and starting with `/` (cookie_helper.cc
  goodPath), value/path free of CTL/DEL/`;` (safeValue — the Cookie
  header injection surface).
- Domain checks ("Invalid task cookie domain."): a leading dot means
  hostOnly defaults to false and is stripped; canonicalization =
  lowercase (cookie_helper.cc); numeric hosts force host-only;
  `..`/leading/trailing dots/illegal characters are rejected
  (non-numeric hosts limited to `[a-z0-9-.]`).
- `expiresAt` = non-negative Unix **milliseconds** <= 2^53-1 (verbatim
  text "Task cookie expiry must be nonnegative Unix milliseconds.");
  the conversion to seconds truncates by integer division; default =
  session cookie.
- Expired records are legal input but do not enter active storage —
  expiry eviction on this side happens at the core actor conversion
  point (`cookies_from_specs`).

Error shape: DL_ABORT_EX texts flow through `RpcError::generic` as
numeric code 1 + original text (the same mapping chain as method-body
errors).

## lib.rs

Crate map and compatibility freeze (`crates/taiji-rpc/src/lib.rs`):

- Compatibility freeze: the method registration surface =
  `taiji_core::session::RPC_METHODS` (the promised-method table, 35
  names unchanged).
- API presentation, one face at a time: the default presents canonical
  `taiji.*` method names + the six `taiji.onXxx` events + the
  `taiji.*` listMethods/listNotifications face; with
  `--rpc-aria2-compat` on, methods additionally accept `aria2.<name>`
  aliases (aria2 registers only prefixed names, RpcMethodFactory.cc),
  the six events are pushed as `aria2.onXxx`, and
  listMethods/listNotifications present the aria2 face. Alias
  normalization and face gating have a single source:
  `dispatch::canonical_method` / `dispatch::method_face_names` /
  `dispatch::notification_face`.
- Dependency direction: depends only on `taiji-core`.

## dispatch/tests.rs

### Method-surface promise table

- The registered face (`RPC_METHODS`) and the promised face are
  set-equal: 40 aria2 reference names (`RpcMethodFactory.cc`) minus 4
  non-promised names, plus 16 `taiji.*` named extensions, plus the
  bare-name extension `forceRecheck`. `addMetalink` joins only with the
  `metalink` feature.
- The 4 non-promised aria2 names are the fork's sqlite3 download-record
  additions: `exportSession`, `getDownloadResultCount`,
  `requeueDownloadResult`, `searchDownloadResult` (absent from upstream
  `RpcMethodFactory.cc`). Compat-face calls fall through to "No such
  method"; they form the "RPC method-surface gaps" difference category.
- Face model (one API face at a time): bare registry names
  project to `taiji.<bare>` in the canonical face and `aria2.<bare>` in
  the compat face; `system.*` / `taiji.*` entries stay verbatim in both.
  `canonical_method` is the single alias point: bare / `taiji.X` always
  accepted, `aria2.X` only in compat mode; dotted alias stacks never
  match. `system.listMethods` / `system.listNotifications` present the
  projected face; the six notification names switch as a whole table
  (`taiji.onXxx` / `aria2.onXxx`), pinned to core `EventKind`
  (`notification_method` / `aria2_notification_method`).
- Every promised name must have a real dispatch arm (an exhaustive
  dispatch test turns a missing arm into an `unreachable!` panic).

### Declared differences

`DECLARED_DIFFERENCE_REGISTRY` is the in-repo baseline of all
deviations from the aria2 reference (scheduler stances and redefined
option semantics, method gaps/additions, event face, metalink v3
fallback and option family, metalink expansion semantics, saveSession
format, cookies, proxy shapes, FTP face, experimental h2 protocol
options, enabledFeatures, SFTP deferral, non-accepted HTTP options).
Execution anchors: option stances in core `session::options`, error
codes in the `crate::error` mapping table, metalink expansion semantics
in the `crate::metalink` module docs. New categories require updating
the whitelist assertion.

### Auth and gates

- Token auth mirrors RpcMethod.cc: the `token:` first parameter is
  stripped and checked; failures answer "Unauthorized" with a delay
  flag. Auth runs before unknown-method reporting.
- Write gate: without `--rpc-secret` every write method fails closed
  (including shutdown and extensions); read-only and `system.list*`
  faces stay anonymous. The gate sits before parameter decoding, so
  read-family methods still reach the param-error face.

### Transport semantics pinned by tests

- multicall: success slots wrap `[result]`; error slots inline in
  place; `checkRequiredParam<List>` texts; any unauthorized sub-call
  sets the whole-response delay flag (RpcMethodImpl.cc,
  HttpServerBodyCommand.cc).
- Batch caps: over `MAX_BATCH_ITEMS` the whole batch is one error
  object; the same cap covers multicall specs; a request-level budget
  also bounds the total multicall sub-calls inside a batch (the
  recursion guard previously caught only multicall-in-multicall,
  leaving ~10^6 sub-calls reachable from one authenticated request).
- Pagination (`getPaginationRange`, RpcMethodImpl.h): slice semantics
  including negative-offset tail anchoring; negative offsets reverse in
  the render layer; saturating arithmetic at i64 extremes (a prior
  overflow made the slice panic — a remote DoS).
- Numeric error codes: engine structured failures reach
  `status_entry_json.errorCode` through `EngineFailure::of_http_error`
  (checksum → 32, auth → 24, 404 → 3 via the Status refinement,
  transport timeout → 2, FTP family → 21, fallback 1 = UNKNOWN_ERROR);
  `range_ignored` shares slot 8 with `bad_range` (CANNOT_RESUME, the
  aria2 isRangeSatisfied failure family).

## server.rs

### Upstream anchor mapping

- Unauthorized delay: `HttpServerBodyCommand.cc` DelayedCommand 1_s; on
  halt the response is abandoned (select on the shutdown token). The WS
  message path consumes the same delay — otherwise one WS connection
  could guess tokens at high speed.
- Basic auth: checked at the request-header layer in
  `HttpServerCommand.cc`, before the body is read, so 401 precedes the
  413 over-limit face; unauthorized answers disableKeepAlive plus
  `WWW-Authenticate: Basic realm="aria2"`; OPTIONS preflight is exempt.
  Comparison logic lives in `crate::auth` (HttpServer.cc:
  process-random HMAC + constant-time compare).
- Content-Length precheck over the cap: `HttpServerCommand.cc` drops
  the connection; here it is an explicit 413 +
  `taiji.request.too_large` (string code registered in error.rs).
- CORS/preflight: `HttpServerBodyCommand.cc` (OPTIONS → 200 +
  allow-methods / max-age 1728000 / echo of allow-headers; CORS headers
  only when allow-origin-all and the request carries Origin +
  Access-Control-Request-Method). Responses use `application/json-rpc`.
- WS oversized messages: `WebSocketSession.cc` drops the bytes and
  answers -32700 as a parse failure.
- WS notification push: `WebSocketSessionMan.cc` envelope
  (`{jsonrpc:"2.0", method, params:[{gid}]}`); the same message goes to
  every session, realized here with a broadcast subscription. Event
  names: canonical `taiji.onXxx` (core `EventKind::notification_method`)
  / compat `aria2.onXxx` (`aria2_notification_method`, frozen names).

### Security hardening beyond the reference

Browser-driven faces exist in upstream aria2 too; taiji closes them:

- WS upgrades check Origin same-origin (WS is cross-origin by nature; a
  browser can reach a loopback service). Allowed: no Origin header,
  Origin authority equal to Host (ASCII case-insensitive), or explicit
  `--rpc-allow-origin-all`. `Origin: null` is rejected.
- `/metrics` sits behind the same Basic gate as `/jsonrpc`.
- With `listen_all` + secret and Basic unset or user-only (a password
  slot of None is never checked — zero entropy), the secret directly
  guards the two anonymous faces: /metrics requires
  `Authorization: Bearer <secret>`; WS event subscription waits for the
  first Text message carrying a valid token (an invalid one consumes
  the 1s delay and disconnects with no reply). aria2 pushes
  notifications to upgraded WS connections without authenticating that
  event face — a controlled difference.
- `listen_all` without usable credentials refuses to start
  (fail-closed); aria2 only WARNs (DownloadEngineFactory.cc) and
  listens anyway. Usable credentials: a non-empty normalized secret or
  Basic with a password. Blank/whitespace secrets normalize to unset
  (aria2 semantics: empty string = unset).
- WS protocol caps: `max_message_size` / `max_frame_size` =
  `max_request_size + 1`, same as the HTTP face. Without them,
  tungstenite buffers a whole message up to 64MiB before the app-layer
  check runs — an unauthenticated OOM face; with only the message cap,
  frames over tungstenite's default 16MiB would be silently dropped
  while HTTP answers the same size (an inter-face asymmetry).

### Operational invariants

- Bind axis and credential axis are decoupled: binding only follows
  `--rpc-listen-all` (HttpListenCommand.cc adds AI_PASSIVE only for
  listen-all); credentials only decide auth gates.
- The shutdown token drives axum graceful shutdown, the WS session
  loop, and the unauthorized delay; `unauthorized_delay` returns false
  on shutdown and the response is abandoned.
- Connection gate: per-request concurrency leases against total and
  per-IP caps, 503 with `taiji_rpc_conn_rejected_total{scope}`; WS
  upgrades transfer the handshake lease into a session lease via
  `ConnLeaseSlot` (one accounting entry); the middleware drop is the
  RAII fallback.
- Auth failures (Basic, Bearer, WS first token) share one per-IP
  backoff ledger; success clears it; the backoff wait applies before
  checks.
- Backpressure: the event bus is bounded at 256 and senders never
  block; a lagged subscriber is counted, warned, and disconnected
  (aria2 pushes unbounded with no backlog concept).
- recovery extension events reuse the six-event envelope with `taiji.*`
  names; params[0] carries `gid` (hex16) and `files` (1-based client
  file order, numbers as strings); completed adds `status` ("ready" —
  no failure terminal state exists).

## dispatch.rs

Dispatch-order cross-validation reference (read-only) for
`crates/taiji-rpc/src/dispatch.rs`:

- `rpc_helper.cc`: getMethod -> execute; unknown methods land in
  NoSuchMethodRpcMethod via `RpcMethodFactory.cc`.
- `RpcMethod.cc`: authorize runs before process — unknown methods are
  authenticated first too (NoSuchMethodRpcMethod inherits the authorize
  prefix of `RpcMethod::execute`).
- `RpcMethodImpl.cc`: system.listMethods / system.listNotifications
  override execute and skip authorize (unauthenticated).
- `RpcMethodImpl.cc`: system.multicall also overrides execute, sinking
  auth into the sub-calls; any unauthorized sub-call sets the delayed
  bit for the whole response (together with `HttpServerBodyCommand.cc`).
- Success wraps in a list, errors inline, recursion forbidden:
  `RpcMethodImpl.cc`.

multicall expands at the RPC layer into multiple `SessionHandle::call`s
and does not enter core (the `SessionCommand` surface is untouched).

## methods.rs

- The 35 aria2 methods plus the `taiji.*` extensions decode into
  `SessionCommand`s in `crates/taiji-rpc/src/dispatch/methods.rs`;
  method-name routing and parameter validation semantics are frozen.
  The routing category comes from the core `RpcMethodKind` descriptor
  as the single point.
- shutdown/forceShutdown reply "OK" (`createOKResponse`,
  `RpcMethodImpl.cc`) and cancel the server shutdown token.
- The query families (tellStatus/tellActive/tellWaiting/tellStopped/
  getFiles/getPeers/getServers/getUris/getOption) share one table-driven
  loop (`QUERY_METHODS`); governance tests lock that table to the core
  descriptor table (same names, categories, order).

## metalink.rs

Expansion semantics for `crates/taiji-rpc/src/metalink.rs` (read-only
cross-validation reference: `Metalink2RequestGroup.cc`, plus declared
differences). Entries expand in document order; the produced order is
the addMetalink reply GID order.

1. metaurl direct BT conversion (`mediatype="torrent"`, case
   insensitive per RFC 5854): hits the existing torrent entries —
   `magnet:` URIs become magnet tasks; http(s) URIs whose path ends in
   `.torrent` become `.torrent` metadata-download placeholder tasks
   (upgraded in place to a torrent under the same GID after fetch).
   The same metaurl URI yields at most one BT task per document (the
   by-URL-grouping rule of aria2 `groupEntryByMetaurlName`; the BT GID
   sits at the first occurrence, ahead of that entry's HTTP GIDs — the
   same shape as aria2 pushing torrentRg before rg). Duplicate URIs are
   skipped with a warning (first occurrence wins). Magnets are further
   deduplicated by btih/btmh identity (the same source as the session's
   addUri duplicate decision — core session `magnet_identity`):
   different spellings of the same torrent (any dn/tr) are likewise
   skipped with a warning while later entries proceed — benign
   duplicates are absorbed at the seam instead of failing the whole
   method halfway through the document (aria2 has the same direction:
   one torrent, one task per group). Within an entry, candidates are
   examined until the first usable BT task is produced (an unusable
   first candidate no longer blocks later usable ones). A metaurl that
   is neither magnet nor `.torrent` is skipped with a warning (aria2
   falls back to post-download content sniffing; the direct-conversion
   semantics has no such fallback — declared difference).
2. HTTP multi-mirror task: `<url>` filtered to http(s)/ftp(s) mirrors
   (the http/https/ftp family of aria2 `dropUnsupportedResource`; the
   scheme is case-insensitive per RFC 3986 §3.1) and stably pre-sorted
   by `priority` ascending at expansion time (1 = best; equal
   priorities keep document order), then go through the addUri
   multi-source path; `out` = the entry-name basename (the `--out`
   domain is a plain file name — aria2's applyDir subdirectory form is
   flattened, a declared difference; entries that cannot produce a
   legal out name — leading `-`, backslash, drive colon, Windows
   reserved stem, trailing dot or space — are skipped with a warning).
   The same (dir,out) may be occupied only by the first entry (the
   flatten-collision guard: sub1/a.iso and sub2/a.iso would co-write
   one part file after flattening — later entries skipped with a
   warning). `checksum` = the entry's own `<hash>` declaration folded
   in (`<hash type>=<hex>` — the same six-hash domain and shape as
   `--checksum`: md5/sha-1/sha-224/sha-256/sha-384/sha-512; with a
   single checksum the strongest wins: sha-256 first, otherwise the
   first in document order — entries declaring only weak algorithms
   still get a verdict). The caller's `out`/`checksum` keys are
   stripped wholesale at this seam: entries without a document
   checksum do not inherit the caller's `--checksum` (the leak surface
   = an external value failing closed on healthy entries).
3. Zero usable tasks (all entries dropped / zero entries) = an empty
   array reply (the aria2 `result.empty()` branch — not an error).

Declared differences:

- Per-entry metaurl group merging (aria2 shares one multi-file torrent
  across `<file>` entries and emits one GID) is not done — each entry
  is an independent task, GID, and status (the structured expression of
  "a metaurl task failing does not affect the HTTP source tasks of the
  same `<file>`").
- The metaurl BT plan does not consume the entry's `<hash>`
  declarations (`<hash>` feeds `--checksum` only on the HTTP plan; BT
  integrity is decided by the fetched metadata's piece hashes —
  aria2's direct conversion likewise carries none).
- `<pieces>` piece hashes, `<signature>`, and `url@type="bittorrent"`
  resources are dropped (the model does not consume the type attribute
  — superset behavior).
- `metaurl@name` is validated at parse but not consumed at expansion
  (aria2 uses it for in-torrent path selection; the direct BT
  conversion's naming comes from the metadata).
- `url@priority` is consumed as a one-time stable pre-sort at expansion
  (aria2's InOrderURISelector picks at runtime — a same-direction
  difference).
- The legacy `--metalink-*` option family (language/location/os/
  version/preferred-protocol/force-protocol/tr) is unsupported,
  ignored with a warning; HTTP header auto-discovery
  (`metalink-enable-auto-discover`) defaults off — true is accepted
  but treated as invalid with a warning (content-sniffing
  auto-conversion is not in this build).

## error.rs

HTTP failure -> aria2 numeric error code mapping for
`crates/taiji-rpc/src/error.rs` (the doc table in the code; its
executable mirror is `try_http_numeric_code`, pinned row by row by
tests). The full numeric-code source (read-only reference):
`error_code.h` `error_code::Value` (0=FINISHED .. 32=CHECKSUM_ERROR).
The HTTP engine-side code semantics single source is the taiji-http
`HttpError::code()`; this table maps engine-side failure -> wire
numeric code, maintained alongside the declared differences. Rows:

- Probe 416 + `bytes */0` -> empty-file Done -> 0 (FINISHED): creating
  a 0-byte output is success, not an error; aria2 has no 416 probe
  face; an empty file reaches FINISHED via 200+CL=0.
- `taiji.http.bad_range` (probe 416 + `*/N>0`; a 206 echo not matching
  the request; an extent out of range) -> 8 (CANNOT_RESUME): the Range
  conflicts with the authoritative length (`HttpResponse.cc`
  isRangeSatisfied -> EX_INVALID_RANGE_HEADER -> CANNOT_RESUME; the
  206 data-plane echo is validated at the same point); when resume is
  infeasible, restart from zero (`AbstractCommand.cc`).
- `taiji.http.range_ignored` (a download-phase Range request answered
  200 after the probe confirmed resumability) -> 8 (CANNOT_RESUME):
  the same slot as `bad_range` — the aria2 isRangeSatisfied failure
  family (expected 206, got 200 = Range unsatisfied,
  `HttpResponse.cc` EX_INVALID_RANGE_HEADER -> CANNOT_RESUME);
  semantically cross-validated against the Android Download Manager
  "Expected partial, but received OK" -> STATUS_CANNOT_RESUME.
  Difference: aria2 restarts from zero (`AbstractCommand.cc`); taiji
  fails the task explicitly once, terminally.
- `taiji.http.unexpected_response` (404) -> 3 (RESOURCE_NOT_FOUND):
  `HttpSkipResponseCommand.cc`; with `--max-file-not-found>0` aria2
  retries instead of failing immediately.
- `taiji.http.unexpected_response` (401) -> 24 (HTTP_AUTH_FAILED):
  `HttpSkipResponseCommand.cc` (case 401 -> EX_AUTH_FAILED; retries
  first while a Basic challenge can still be activated).
- `taiji.http.unexpected_response` (403) -> 22 (HTTP_PROTOCOL_ERROR):
  the reference has no 403-specific arm — the status switch
  (`HttpSkipResponseCommand.cc`) lists only 401/404/502/503/504, so
  403 falls to the EX_BAD_STATUS fallback. An early draft merged 403
  into the 401->24 row, contradicting the reference; corrected.
- `taiji.http.unexpected_response` (502/503/504) -> 29
  (HTTP_SERVICE_UNAVAILABLE): `HttpSkipResponseCommand.cc` (502/503
  retry first when retry-wait>0; 504 always retries).
- `taiji.http.unexpected_response` (other statuses/shapes) -> 22
  (HTTP_PROTOCOL_ERROR): `HttpSkipResponseCommand.cc` (the
  EX_BAD_STATUS fallback), `HttpResponse.cc` (unexpected 304 / missing
  Location / unexpected status).
- `taiji.http.transport` (read idle timeout) -> 2 (TIME_OUT):
  `AbstractCommand.cc` (EX_TIME_OUT); the only direct fine-grained
  row — the task-level stall closure (`--timeout` zero byte growth).
- `taiji.http.transport` (DNS failure / connect refused / reset / TLS
  — all other transport failures) -> 6 (NETWORK_PROBLEM): the
  transport payload is reqwest error-chain text, always Bare —
  aria2's DNS-specific code 19 (NAME_RESOLVE_ERROR,
  `AbstractCommand.cc`, `NameResolver.cc`) is unreachable in the
  production render chain; falls to the 6 fallback, listed in the
  differences.
- `taiji.http.redirect_limit` -> 23 (HTTP_TOO_MANY_REDIRECTS):
  `HttpSkipResponseCommand.cc` (MAX_REDIRECT exhausted).
- `taiji.http.redirect_loop` -> 23 (HTTP_TOO_MANY_REDIRECTS): aria2
  detects the loop as exhausted hops (same code); taiji's visited-set
  rejects earlier (a semantic subset, the same wire code).
- `taiji.http.insecure_redirect` -> 22 (HTTP_PROTOCOL_ERROR): a taiji
  enhancement (https->http downgrade rejection) with no aria2
  counterpart — listed in the differences.
- `taiji.http.mirror_mismatch` -> 1 (UNKNOWN_ERROR): a taiji
  enhancement (cross-mirror length comparison), aria2 does not do it
  — listed in the differences.
- `taiji.http.no_source` -> 1 (UNKNOWN_ERROR): all sources removed;
  aria2's all-URI failure lands on the generic code after retries
  (the `RequestGroup.cc` UNKNOWN_ERROR fallback).
- `taiji.http.path_conflict` -> 13 (FILE_ALREADY_EXISTS): the
  `--allow-overwrite=false` with the file already existing semantics
  (`RequestGroup.cc`; error_code.h).
- `taiji.http.cookie_file_too_large` / `taiji.http.cookie_file` -> 1
  (UNKNOWN_ERROR): a difference — aria2's `--load-cookies` read
  failure only logs and continues (`MultiUrlRequestInfo.cc`, no
  numeric code); taiji escalates to a task-level failure, a tightening
  listed in the differences.
- `taiji.http.total_length_exceeded` -> 1 (UNKNOWN_ERROR): a taiji
  enhancement (authoritative total length sanity cap -> task-level
  rejection); aria2 has no length cap — listed in the differences.
- `taiji.http.coordinator_stopped` -> 1 (UNKNOWN_ERROR): a taiji
  enhancement (scheduler actor stopped state); no aria2 counterpart —
  listed in the differences.
- `taiji.http.disk` (open/create/alloc/read-write/fsync, the whole
  family) -> 17 (FILE_IO_ERROR): `AbstractDiskWriter.cc`
  (FILE_IO_ERROR); the payload is always Bare — aria2's finer codes
  15 (FILE_OPEN_ERROR) / 16 (FILE_CREATE_ERROR) are unreachable in
  the production render chain; falls to 17, listed in the
  differences.
- HTTP auth challenge exhaustion (`taiji.auth.failed`) -> 24
  (HTTP_AUTH_FAILED): `HttpSkipResponseCommand.cc`.
- `taiji.http.ftp` (FTP/FTPS control-plane protocol errors /
  data-plane IO) -> 21 (FTP_PROTOCOL_ERROR): the reference's whole
  FTP control path shares this code (`FtpNegotiationCommand.cc`,
  `FtpConnection.cc`, EX_FTP_PROTOCOL_ERROR).
- `taiji.http.ftp_resume_unsupported` (an offset range hitting a
  REST-less server) -> 21 (FTP_PROTOCOL_ERROR): a REST refusal is an
  FTP command failure (the `FtpNegotiationCommand.cc` recvRest
  default arm); the probe face routes to single-stream downgrade,
  this row only catches explicit failures the probe missed.
- `taiji.sftp.deferred` (the `sftp://` scheme at addUri) -> no numeric
  row: rejected at task creation (code 1 + the string code), no task
  terminal state — the SFTP transport plane is deferred wholesale.
- `--checksum` final verification mismatch
  (`taiji.http.checksum_mismatch`) -> 32 (CHECKSUM_ERROR):
  `ChecksumCheckIntegrityEntry.cc`; the string code is minted here and
  carried from the core code-emitting side through the view to the
  render layer (`http_numeric_code`).
- `taiji.option.invalid` (changeOption out of domain etc.) -> 28
  (OPTION_ERROR): an illegal option value (error_code.h).

Declared differences:

- taiji enhancement codes: `mirror_mismatch`/`no_source`/
  `insecure_redirect`/`total_length_exceeded`/`coordinator_stopped`
  have no one-to-one aria2 counterpart and uniformly land on 1
  (UNKNOWN_ERROR); empty-file probe Done is a new success path
  (numeric 0, not an error).
- Cookie file failure escalation: aria2 logs and continues; taiji
  fails the task — a semantic tightening.
- Transport/disk fine-grained boundaries (final): the read idle
  timeout (the task-level `--timeout` stall closure) reaches 2
  (TIME_OUT); the unexpected_response status family reaches directly
  (404->3, 401->24, 502..504->29, others->22). reqwest error-chain
  text (DNS/connect refused/reset/TLS) and disk payloads stay Bare —
  the finer aria2 codes 19/15/16 are unreachable in the production
  render chain (`of_http_error` -> `engine_kind` ->
  `http_numeric_code` always falls to the 6/17 fallback rows).
- FTP read-idle difference (final): an FTP read idle produces
  `taiji.http.ftp` -> 21 (FTP_PROTOCOL_ERROR); the same shape on HTTP
  falls to the task-level stall closure -> 2 (TIME_OUT) — the same
  shape with a different code (aria2's read timeout is EX_TIME_OUT
  regardless of protocol -> 2), listed in the differences.
- Auth numeric face (final): `taiji.auth.failed` is uniformly 24
  (HTTP_AUTH_FAILED). Known deviation: an FTP login failure (530)
  lands on aria2's EX_BAD_STATUS -> 21; taiji's numeric face is
  always 24 (string-code uniformity wins).
- API face: method aliases, the six event names, and the
  listMethods/listNotifications presentation all switch from the
  single `--rpc-aria2-compat` gate (default false = the single
  canonical `taiji.*` face; on = the aria2 face). Only one API face
  exists at a time; dual emission is forbidden; the `system.*`
  introspection family and the `taiji.*` extension methods/events
  keep the same names across both states. A dispatch-combination
  tripwire test pins this.
- SFTP deferral: the `sftp://` scheme is rejected explicitly at addUri
  task creation with the `taiji.sftp.deferred` string code; the SFTP
  transport plane (host-key strict / known_hosts parsing / pipeline
  concurrency) is deferred to separate work. No numeric row (no task
  terminal state).

## metrics.rs

The Prometheus `/metrics` rendering surface
(`crates/taiji-rpc/src/metrics.rs`). `GET /metrics` shares the port
and bind face with `/jsonrpc` (precedent: the rqbit admin plane) and
sits behind the same Basic gate via the server-layer `metrics_gate`;
with no `--rpc-user` configured the gate is always open, in which
case the bind face is loopback-only. The metric face carries no
sensitive fields: rpc-secret/user/passwd never appear in any metric
or label.

Naming rules (Prometheus convention): the `taiji_` prefix;
snake_case; counters end in `_total`; base units bytes/seconds; label
cardinality is bounded — every label value is a fixed enum
(state/transport/direction/family/kind/method); gids, paths,
info-hashes, and tracker URLs never become labels. The `method`
label is anchored to the frozen `RPC_METHODS` table; unknown method
names merge into one `unknown` slot (client-invented names cannot
raise the cardinality).

Data sources:

- Session/connection/protocol/internal-pool counters: the core
  `MetricsSnapshot` (see the `taiji-core::session::metrics` module
  doc for the feed-point table).
- The `taiji_dns_*` families: io shared-resolver feed points pulled
  into `MetricsSnapshot` through the core snapshot aggregation seam
  (rpc does not depend on io directly); the bucket table
  `DNS_RESOLVE_BUCKETS_SECONDS` is re-exported through core.
  Accounting lives in the `taiji-io::dns` module doc.
- The `taiji_http_errors_total`/`request_seconds`/`retries`/
  `extent_reassign`/`mirror_events`/`stall_detected`/`aimd_events`/
  `slowstart_seconds` families: HTTP transport feed points (taiji-io
  observation types plus the taiji-http/core seams) through the same
  aggregation seam; accounting in the `taiji-io::metrics` module's
  `HttpMetrics` doc.
- `taiji_http_conn_establishments_total`/`conn_establish_seconds`:
  the connection-profile family, fed by the tower timing layer hooked
  into the reqwest `connector_layer`. Pool reuse bypasses the
  connector, so the count naturally covers only fresh establishments;
  `establish_seconds` times DNS+TCP+TLS combined, so connect+TLS is
  approximated at analysis time as the combined latency minus
  `dns_resolve_seconds` (mean-level component subtraction —
  per-sample pairing is unavailable).
- `taiji_disk_sink_writes_total`/`_bytes_total`/`sink_inflight`/
  `finalize_seconds`/`prealloc_seconds`: disk/finalize feed points
  through the same seam; accounting in the `taiji-io::metrics`
  module's `DiskMetrics` doc (`sink_inflight` = in-flight write_at
  concurrency; `op=file_fsync` counts fsync for all task files —
  merged accounting).
- `taiji_persist_queue_depth`/`taiji_persist_commit_seconds`:
  persistence feed points — the store PersistWriter thread via the
  `PersistObserve` callback seam (store and io do not depend on each
  other; core is the single adapter). `queue_depth` is the latest
  writer-thread observation; `commit_seconds` excludes channel
  queuing.
- The `taiji_holepunch_*_total` family (rendezvous_sent,
  relayed_connects, punch_dials, punch_established, introducer_hits,
  no_introducer, punch_failed_nat): seven punch counters, bridged as
  1s-tick deltas by the core engine; rendered names add the `_total`
  suffix per the repo counter naming discipline.
- `taiji_peer_leaves_total{reason}`: five closed leave-reason
  counters (local/peer-closed/io/protocol/cancelled) fed directly by
  the core engine's leave arms — the carrier for attributing
  connection loss to "the peer closed / we closed / transport error";
  `cancelled` is excluded from diagnosis denominators.
- `taiji_torrents{state}`: derived from the existing query face
  (getGlobalStat + tellWaiting + tellStopped; the `SessionCommand`
  surface unchanged).
- `taiji_rpc_requests_total{method}` /
  `taiji_rpc_request_duration_seconds`: fed at the dispatch entry
  (`dispatch::process_call`).

Value-range narrowing (honest accounting):

- `taiji_dht_queries_total{kind}`: kind = the four BEP5 message kinds
  (ping/find_node/get_peers/announce_peer); the feed point is the
  successful outbound enqueue in the bt::dht engine `send_query` path
  (per-kind counting inside the engine), accumulated into the
  snapshot as 1s-tick deltas.
- `taiji_wrcache_events_total` has only the `flush`/`evict` kinds
  (`hit` is a cache-internal folded concept with no event source).
- `taiji_torrents{state}` uses the six aria2 status states
  (active/waiting/paused/complete/error/removed).
- `taiji_peer_connections` always contains the transport="utp" series
  (an honest zero while no µTP connection exists).
- `taiji_http_conn_aimd` renders as an aggregate gauge (the
  label-cardinality discipline — gid never becomes a label); the
  per-task face goes through the tellStatus `http` sub-dict. The
  static baseline task (no AIMD assembled) reads a constant zero.
