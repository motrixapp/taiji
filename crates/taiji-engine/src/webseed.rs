//! BEP-19 webseeding engine face: url-list HTTP sources join the BT data
//! plane as pseudo-peers — the remote half of a `tokio::io::duplex` speaks
//! BT wire (Request → HTTP Range fetch → Piece), the local half goes through
//! the [`crate::transit::attach_peer`] `S: AsyncRead+AsyncWrite` generic
//! seam: register/interest/dispatch/delivery/leave are reused wholesale, with
//! zero changes to dispatch/choke/endgame/RequestBook. Assembly (duplex +
//! handshake + attach_peer orchestration) lives in
//! `run::dial::attach_webseeds`; this module is the protocol and fetch
//! surface.
//!
//! # Responder protocol
//!
//! - Handshake: server form (read our 68 B → check pstr/info_hash → reply
//! 68 B). reserved sets only the fast bit (HaveAll is a BEP-6 fast-ext
//! message, so the advertised bit and the message surface are
//! self-consistent; no ext/DHT/v2 bits — the BEP-10 negotiation gate
//! (attach_peer's peer_ext param) stays closed, zero ut_metadata/PEX/
//! holepunch noise).
//! - Opens with `Unchoke` + `HaveAll` (BEP-6 "replace the Have Bitfield"):
//! the FaceState consumer (dispatch.rs `note_peer_have_all`) takes the O(1)
//! peer_seeds fast path and unlocks dispatch (the AvailEvent::HaveAll arm).
//! FrameCodec already has the HaveAll variant (peer_wire.rs
//! MessageId::HaveAll = 14) — no all-ones BitField fallback needed.
//! - `Request{index,begin,length}` → the fetch is queued; `Cancel` → remove
//! the matching pending entry. Interested/NotInterested/KeepAlive/Have/
//! Bitfield/Choke/Unchoke from our side are ignored (a pure seeder
//! responder does not care about our interest/choke state). Extended is
//! tolerated (not a close): when our engine finishes downloading and turns
//! seeder, `SetUploadOnly` re-sends an ext handshake unconstrained by the
//! negotiation gate (conn.rs has no ext_enabled gate on that command arm);
//! the pseudo-peer just ignores it rather than misjudging a known
//! self-produced frame as out of protocol.
//! - Out-of-protocol messages (Piece/Reject/Suggest/AllowedFast/HaveAll/
//! HaveNone/Port/HashRequest/Hashes/HashReject — our leecher engine never
//! sends these, and a pseudo-peer should never receive them) → close the
//! stream (fail-safe; mirrors the bt-side from_wire disconnect discipline
//! for real peers).
//! - Every `Piece{index,begin,block}` reply aligns exactly with the requested
//! (index,begin,length) — RequestBook `on_piece` matches on the five-tuple
//! (request_book.rs); any length drift is an unsolicited disconnect.
//!
//! # Fetch strategy (piece-granular prefetch cache)
//!
//! - The first Request for a piece → one [`HttpClient::get_range`] (Range
//! end inclusive) for the whole piece `goffs[P] .. goffs[P]+piece_len[P]-1`
//! (Range aligned to piece boundaries; aria2 cuts webseed Segments at
//! piece boundaries the same way); later block requests slice the cached
//! response.
//! - wire index → global offset via `FaceConfig.piece_goffs` (the table is
//! common to v1/v2/hybrid); a short last piece is expressed by the
//! `piece_bytes` table (the final block request is truncated). Face choice
//! (executed at assembly): only v1 faces (v1-only, or a hybrid's v1 face —
//! its v1 piece space includes pad placeholders, and an HTTP source
//! supplying that layout is the only self-consistent pairing with the v1
//! verification surface). v2-only torrents are not attached (BEP-19
//! predates BEP-52 and has no v2 semantics to lean on — aria2 has no v2
//! support; libtorrent's per-file v2 url seeds are a separate design).
//! - Single-URL global-offset semantics: Range addresses the synthetic
//! stream of one url-list URL (the canonical BEP-19 single-file form). The
//! per-file path form for multi-file torrents ("GET {url}/{file_path}") is
//! out of scope — multi-file url-list tasks send global-offset requests,
//! the server's 404/416 takes the failure path, and the BT face is
//! unaffected.
//! - Cache LRU cap [`WEBSEED_CACHE_CAP`] (32 MiB); concurrent whole-piece
//! fetches ≤ [`WEBSEED_FETCH_PARALLEL`] (a Semaphore; excess queues at
//! acquire).
//! - Failure semantics: a single fetch failure is retried by the consumer
//! under the taiji-http `RetryPolicy` (the client itself never retries
//! implicitly — one group per piece, max_tries attempts per group);
//! exhausted retries count one failure; [`WEBSEED_FAIL_CLOSE`]
//! consecutive piece failures → close the stream (a permanent exit: v1 has
//! no re-entrancy — aria2 likewise abandons dead webseeds). Any success
//! resets the consecutive counter.
//! - While a piece fails, its Requests go unanswered (the whole piece's
//! pending table clears) — the engine's RequestBook timeout naturally
//! re-dispatches to other sources; a re-dispatch to this source
//! (retry-driven) spawns a new fetch. Duplicate delivery follows the
//! existing RequestBook timeout-grace semantics (`on_piece` expired
//! grace, request_book.rs).
//!
//! In scope: the BT wire responder (`WebseedResponder`), the piece prefetch
//! cache and failure semantics, the fetch seam ([`RangeFetch`]). Out of
//! scope: url-list parsing/option chain (the metainfo/session config face),
//! pseudo-peer assembly (`run::dial::attach_webseeds`), multi-URL health
//! arbitration, the HTTP transport itself (taiji-http).
//!
//! Upstream anchor mapping: docs/design/engine.md

use std::collections::{HashMap, HashSet, VecDeque};
use std::pin::Pin;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::{Semaphore, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use taiji_bt::peer_wire::{HANDSHAKE_LEN, Handshake, MAX_FRAME_LEN, Message};
use taiji_http::client::{ClientConfig, HttpClient};
use taiji_segment::traits::RequestCtx;

use taiji_bt::peer_wire::Reserved;
/// Pseudo-peer duplex buffer (the same magnitude as the repo's peer test
/// fixtures/engine attach surface: 64 KiB ≈ 4 16 KiB block frames, so the
/// write-side backpressure granularity is block-level).
pub(super) const WEBSEED_DUPLEX_BUF: usize = 64 * 1024;
/// Default cap on the webseeds assembled by the engine face (excess
/// truncated; `BH_WEBSEED_MAX` overrides). 8 is a conservative local choice —
/// aria2/libtorrent have no such cap and use the whole url-list — protecting
/// the connection table from very long url-lists (each webseed occupies a
/// peer slot).
pub(super) const WEBSEED_DEFAULT_MAX: usize = 8;
/// Piece prefetch cache byte cap (32 MiB ≈ 8 4 MiB or 128 256 KiB pieces).
/// Magnitude anchors: aria2 webseed Segments have no explicit cap (fetched
/// and consumed at piece boundaries), libtorrent web seeds have no piece
/// cache (block-by-block passthrough) — this cap is the anti-bloat companion
/// of the piece-prefetch shape (4 concurrent in flight + 32 MiB held ≈ a
/// ~48 MiB/URL upper bound).
const WEBSEED_CACHE_CAP: usize = 32 * 1024 * 1024;
/// Concurrent whole-piece in-flight cap (4; excess queues at Semaphore
/// acquire — queued, never rejected).
const WEBSEED_FETCH_PARALLEL: usize = 4;
/// Consecutive-piece-failure exit threshold (3: transient CDN jitter of 1-2
/// pieces is tolerable; 3 straight failures = the source is structurally
/// unusable).
const WEBSEED_FAIL_CLOSE: u32 = 3;
/// Read-pump → responder message channel capacity (the backpressure
/// granularity for request storms: 64 Requests ≈ 1 MiB of in-flight
/// bookkeeping; when full, the read pump awaits).
const WEBSEED_FRAME_CHANNEL: usize = 64;
/// Fetch-subtask → responder completion-event channel capacity (4x the
/// concurrency cap of 4, so subtask completion never blocks).
const WEBSEED_DONE_CHANNEL: usize = 16;
/// webseed reply block-length cap (= the bt side's 16 KiB inbound Request
/// validation — the pseudo-peer follows the same discipline; over-length is
/// a protocol error and closes).
const WEBSEED_MAX_BLOCK: u32 = 16 * 1024;

/// Engine-face fallback switch (default on; =0 → the assembly face never
/// spawns pseudo-peers — an emergency engine-face fallback). Orthogonal to
/// the `enable-http-seeding` config key: that key empties the webseeds list
/// (a clear() in the assembly/activation chain), while this switch governs
/// engine assembly (the list can stay non-empty yet unwired). Parse/read-
/// timing registry: `taiji_io::knobs` (read at construction, uncached).
pub(super) fn webseed_enabled() -> bool {
    taiji_io::knobs::webseed_enabled()
}

/// Assembly cap read (`BH_WEBSEED_MAX`; a parse failure or zero falls back to the default 8).
pub(super) fn webseed_max_urls() -> usize {
    taiji_io::knobs::webseed_max(WEBSEED_DEFAULT_MAX)
}

/// Range fetch seam (the test injection point: simulate success/failure/
/// slowness deterministically without a network). Production form =
/// [`HttpRangeFetch`]. Desugared as an explicit BoxFuture (the taiji-http
/// traits.rs style; async-trait is not on the dependency allowlist).
pub(crate) type RangeFetchFuture<'a> =
    Pin<Box<dyn std::future::Future<Output = Result<Bytes, String>> + Send + 'a>>;

/// Per-URL Range fetch trait: `start..=end_inclusive` (end inclusive,
/// matching the [`HttpClient::get_range`] semantics).
pub(crate) trait RangeFetch: Send + Sync + 'static {
    fn fetch_range<'a>(
        &'a self,
        url: &'a str,
        start: u64,
        end_inclusive: u64,
    ) -> RangeFetchFuture<'a>;
}

/// Production fetch form: taiji-http [`HttpClient`] with a consumer-driven
/// RetryPolicy.
///
/// Response handling never leaves this closure (reqwest types stay out of
/// the core dependencies — `Followed.response` is consumed by inference;
/// status/bytes are inherent methods). Status semantics: 206 = the fetch is
/// valid; 200 = the Range was ignored → counted as failure (prevents
/// whole-file buffering and mismatches ranged semantics; aria2 likewise
/// judges Range-less webseed sources unusable, and libtorrent web_seed
/// retries/fails directly on 200); any other non-206 also counts as failure.
pub(crate) struct HttpRangeFetch {
    client: HttpClient,
    ctx: RequestCtx,
}

impl HttpRangeFetch {
    /// Constructor (ClientConfig defaults: 60 s read/connect timeouts, 20
    /// redirects, retry parameters = the aria2 `--timeout`/`--max-tries`/
    /// `--retry-wait` default family). UA = `taiji_bt::tracker::PEER_AGENT`,
    /// fixed at construction: the BT identity surface (tracker announce UA /
    /// ext handshake `v` / webseed requests) always presents
    /// `taiji/<semver>` from one source — never the taiji-http default
    /// string by coincidence, and never the task-level `user-agent` option
    /// (aria2 semantics would apply it to webseed/URI — an intentional
    /// divergence: pure-HTTP-task UA overrides do not reach the BT face).
    /// The same config returns the same transport instance from the
    /// taiji-http shared pool — keep-alive reuse across tasks comes free.
    /// Failure = initialization errors such as the TLS backend (the caller
    /// abandons that URL with a warn).
    pub(crate) fn build() -> Result<Self, taiji_http::error::HttpError> {
        Ok(Self {
            client: HttpClient::new(ClientConfig {
                user_agent: taiji_bt::tracker::PEER_AGENT.to_string(),
                ..ClientConfig::default()
            })?,
            ctx: RequestCtx::default(),
        })
    }
}

impl RangeFetch for HttpRangeFetch {
    fn fetch_range<'a>(
        &'a self,
        url: &'a str,
        start: u64,
        end_inclusive: u64,
    ) -> RangeFetchFuture<'a> {
        Box::pin(async move {
            // Retry driving belongs to the consumer (the client.rs
            // retry_policy doc: the client never retries implicitly, avoiding
            // double counting) — one group of max_tries attempts per piece,
            // backoff per policy (default retry-wait 0s = immediate retry).
            let policy = self.client.retry_policy().clone();
            let want = usize::try_from(end_inclusive.saturating_sub(start).saturating_add(1))
                .unwrap_or(usize::MAX);
            let tries = policy.max_tries.max(1);
            let mut last = "no attempt".to_string();
            for attempt in 0..tries {
                if attempt > 0 {
                    tokio::time::sleep(policy.wait_before_retry(attempt)).await;
                }
                match self
                    .client
                    .get_range(url, &self.ctx, start, end_inclusive)
                    .await
                {
                    Ok(mut followed) => {
                        let status = followed.response.status().as_u16();
                        if status != 206 {
                            // 200 (Range ignored) / 4xx / 5xx: the status
                            // alone is a failure (this loop owns the retries;
                            // Retry-After pacing is an existing taiji-http
                            // consumer enhancement — the webseed face uses
                            // simple backoff).
                            last = format!("http status {status}");
                            continue;
                        }
                        // Streaming clamped read: never buffer the whole
                        // response — stop once `want` bytes accumulate, so
                        // over-sent bytes never enter the process heap (the
                        // memory bound = want + one chunk; stopping early
                        // discards the connection and the server's write side
                        // sees the close, matching the tracker
                        // `get_body_capped` "reject malicious oversized
                        // bodies before they reach the heap" pattern).
                        // Content-Length precheck: a declared length over
                        // want violates the Range contract and is rejected
                        // before reading (saves the 60 s timeout window).
                        if let Some(cl) = followed
                            .response
                            .headers()
                            .get("content-length")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<u64>().ok())
                        {
                            if cl > want as u64 {
                                last = format!("oversized body {cl}/{want}");
                                continue;
                            }
                        }
                        let mut buf = BytesMut::with_capacity(want.min(256 * 1024));
                        let mut read_err: Option<String> = None;
                        while buf.len() < want {
                            match followed.response.chunk().await {
                                Ok(Some(chunk)) => {
                                    buf.extend_from_slice(&chunk);
                                }
                                Ok(None) => break,
                                Err(e) => {
                                    read_err = Some(format!("body read: {e}"));
                                    break;
                                }
                            }
                        }
                        if let Some(e) = read_err {
                            last = e;
                            continue;
                        }
                        if buf.len() < want {
                            last = format!("short body {}/{want}", buf.len());
                            continue;
                        }
                        return Ok(if buf.len() == want {
                            buf.freeze()
                        } else {
                            buf.freeze().slice(0..want)
                        });
                    }
                    Err(e) => {
                        last = e.to_string();
                    }
                }
            }
            Err(format!("range fetch exhausted {tries} tries: {last}"))
        })
    }
}

/// wire index → (global offset, piece length). v1-face linear + a short last
/// piece expressed by the table (`FaceConfig.piece_goffs`/`piece_bytes`,
/// common to all three kinds at assembly — this consumer only attaches to
/// the v1 face, see the module doc's face-choice note).
pub(crate) fn piece_span(goffs: &[u64], lens: &[u64], index: u32) -> Option<(u64, u64)> {
    let i = usize::try_from(index).ok()?;
    let g = *goffs.get(i)?;
    let l = *lens.get(i)?;
    (l > 0).then_some((g, l))
}

/// Inbound Request validation (the responder mirror of the bt side's inbound
/// Request discipline): the piece index is in the table ∧ block length
/// 1..=16 KiB ∧ begin+length ≤ piece length. A violation = protocol error
/// (close the stream — the same verdict as the bt `handle_inbound`
/// disconnect on over-length requests).
fn validate_request(lens: &[u64], index: u32, begin: u32, length: u32) -> Result<(), &'static str> {
    let i = usize::try_from(index).map_err(|_| "piece index out of range")?;
    let piece_len = *lens.get(i).ok_or("piece index out of range")?;
    if length == 0 || length > WEBSEED_MAX_BLOCK {
        return Err("bad request length");
    }
    if u64::from(begin) + u64::from(length) > piece_len {
        return Err("request beyond piece tail");
    }
    Ok(())
}

/// Piece prefetch cache (LRU: HashMap + a recency-ordered VecDeque, capacity
/// in bytes). Piece-granular entries (Bytes slices share the underlying
/// buffer, so block replies are zero-copy).
pub(crate) struct PieceCache {
    cap: usize,
    held: usize,
    map: HashMap<u32, Bytes>,
    order: VecDeque<u32>,
}

impl PieceCache {
    fn new(cap: usize) -> Self {
        PieceCache {
            cap,
            held: 0,
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Hit lookup (with touch — repeatedly requested pieces stay at the tail).
    fn get(&mut self, index: u32) -> Option<Bytes> {
        let data = self.map.get(&index).cloned()?;
        if let Some(pos) = self.order.iter().position(|&k| k == index) {
            self.order.remove(pos);
            self.order.push_back(index);
        }
        Some(data)
    }

    /// Insert a piece; evict least-recently-used over the cap. A single
    /// piece over the cap (a pathological torrent with piece_len > 32 MiB)
    /// is not cached (the direct answer path is unaffected — one entry cannot
    /// blow the cap and invalidate the whole cache).
    fn insert(&mut self, index: u32, data: Bytes) {
        if let Some(old) = self.map.remove(&index) {
            self.held = self.held.saturating_sub(old.len());
            self.order.retain(|&k| k != index);
        }
        if data.len() > self.cap {
            return;
        }
        self.held += data.len();
        self.map.insert(index, data);
        self.order.push_back(index);
        while self.held > self.cap {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if let Some(old) = self.map.remove(&oldest) {
                self.held = self.held.saturating_sub(old.len());
            }
        }
    }
}

/// Fetch completion event (subtask → responder main loop).
enum PieceDone {
    Ok(u32, Bytes),
    Failed(u32, String),
}

/// Responder decision flow: `Break` = close the stream (protocol error / consecutive-failure exit).
enum ResponderFlow {
    Continue,
    Close,
}

/// BT wire responder body: the duplex remote half + the fetch seam + face geometry.
pub(crate) struct WebseedResponder<F: RangeFetch> {
    fetch: Arc<F>,
    url: String,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    goffs: Arc<Vec<u64>>,
    lens: Vec<u64>,
    cache: PieceCache,
    /// Piece → pending block requests (begin, length) (the unit Cancel matches and removes).
    pending: HashMap<u32, Vec<(u32, u32)>>,
    /// Pieces with a spawned fetch (dedup: concurrent Requests for one
    /// piece trigger a single whole-piece fetch).
    inflight: HashSet<u32>,
    /// Consecutive piece-failure counter (reset on success; closing the
    /// stream at [`WEBSEED_FAIL_CLOSE`]).
    consecutive_fails: u32,
    /// Concurrent whole-piece in-flight gate (acquire_owned queues = "excess queues").
    permits: Arc<Semaphore>,
}

impl<F: RangeFetch> WebseedResponder<F> {
    pub(crate) fn new(
        fetch: Arc<F>,
        url: String,
        info_hash: [u8; 20],
        peer_id: [u8; 20],
        goffs: Arc<Vec<u64>>,
        lens: Vec<u64>,
    ) -> Self {
        WebseedResponder {
            fetch,
            url,
            info_hash,
            peer_id,
            goffs,
            lens,
            cache: PieceCache::new(WEBSEED_CACHE_CAP),
            pending: HashMap::new(),
            inflight: HashSet::new(),
            consecutive_fails: 0,
            permits: Arc::new(Semaphore::new(WEBSEED_FETCH_PARALLEL)),
        }
    }

    /// Main loop: handshake → the Unchoke/HaveAll opening → select{messages,
    /// fetch completions, cancels}. Exiting drops the write half → EOF at the
    /// engine side → the attach task's leave event reclaims it naturally (the
    /// pseudo-peer is inbound=true, so the redial/PEX surfaces skip it).
    pub(crate) async fn run(mut self, stream: DuplexStream, token: CancellationToken) {
        let mut stream = stream;
        // ---- Handshake (server form: read 68 B → validate → reply 68 B) ----
        let mut buf = [0u8; HANDSHAKE_LEN];
        if let Err(e) = stream.read_exact(&mut buf).await {
            debug!(target: "taiji::core::engine::webseed", url = %taiji_io::redact::redact_url_for_log(&self.url), %e,
                "webseed handshake read failed");
            return;
        }
        let theirs = match Handshake::decode(&buf) {
            Ok(h) => h,
            Err(e) => {
                debug!(target: "taiji::core::engine::webseed", url = %taiji_io::redact::redact_url_for_log(&self.url), %e,
                    "webseed handshake malformed");
                return;
            }
        };
        if theirs.info_hash != self.info_hash {
            debug!(target: "taiji::core::engine::webseed", url = %taiji_io::redact::redact_url_for_log(&self.url),
                "webseed handshake info_hash mismatch (wrong swarm)");
            return;
        }
        let mine = Handshake {
            reserved: webseed_reserved(),
            info_hash: self.info_hash,
            peer_id: self.peer_id,
        };
        if let Err(e) = stream.write_all(&mine.encode()).await {
            debug!(target: "taiji::core::engine::webseed", url = %taiji_io::redact::redact_url_for_log(&self.url), %e,
                "webseed handshake write failed");
            return;
        }
        // ---- Opening: Unchoke → HaveAll (BEP-6; frame order locked — HaveAll
        // arriving after Unchoke lets our choke-mirror flip release the
        // dispatch gate first) ----
        let (r_half, mut w_half) = tokio::io::split(stream);
        if write_frame(&mut w_half, Message::Unchoke).await.is_err()
            || write_frame(&mut w_half, Message::HaveAll).await.is_err()
        {
            return;
        }
        // Read pump (a separate task: read_exact across awaits is not
        // cancel-safe; the select side only consumes the channel — a
        // cancel-safe frame face; EOF/frame error = channel close = the main
        // loop exits on None).
        let (msg_tx, mut msg_rx) = mpsc::channel::<Message>(WEBSEED_FRAME_CHANNEL);
        let pump_token = token.clone();
        tokio::spawn(read_pump(r_half, msg_tx, pump_token));
        let (done_tx, mut done_rx) = mpsc::channel::<PieceDone>(WEBSEED_DONE_CHANNEL);
        info!(target: "taiji::core::engine::webseed", url = %taiji_io::redact::redact_url_for_log(&self.url),
            pieces = self.lens.len(), "webseed wire responder up (unchoke+have_all)");
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                msg = msg_rx.recv() => match msg {
                    None => break, // read pump gone (EOF/frame error)
                    Some(m) => {
                        if let ResponderFlow::Close =
                            self.on_msg(m, &mut w_half, &done_tx, &token).await
                        {
                            break;
                        }
                    }
                },
                done = done_rx.recv() => match done {
                    None => break, // all fetch subtasks gone (token closed)
                    Some(d) => {
                        if let ResponderFlow::Close = self.on_done(d, &mut w_half).await {
                            break;
                        }
                    }
                },
            }
        }
        // Shutdown: explicitly shut down the write half (tokio::io::split's
        // WriteHalf dropped alone does not close the write direction — the
        // ReadHalf still shares the underlying stream; only shutdown sends
        // EOF to the engine side, and the leave event is reclaimed naturally
        // by the attach task); dropping done_tx → in-flight subtask sends
        // fail and they exit (the token concurrently cancels the fetch
        // awaits).
        let _ = w_half.shutdown().await;
        debug!(target: "taiji::core::engine::webseed", url = %taiji_io::redact::redact_url_for_log(&self.url),
            fails = self.consecutive_fails, "webseed wire responder closed");
    }

    /// Single-message decision (the protocol surface in the module doc:
    /// Request/Cancel handling, ignoring our regular outbound frames,
    /// Extended tolerance, closing on out-of-protocol).
    async fn on_msg<W: AsyncWrite + Unpin>(
        &mut self,
        msg: Message,
        w: &mut W,
        done_tx: &mpsc::Sender<PieceDone>,
        token: &CancellationToken,
    ) -> ResponderFlow {
        match msg {
            Message::Request {
                index,
                begin,
                length,
            } => {
                if validate_request(&self.lens, index, begin, length).is_err() {
                    debug!(target: "taiji::core::engine::webseed", url = %taiji_io::redact::redact_url_for_log(&self.url),
                        index, begin, length, "webseed request invalid -> close");
                    return ResponderFlow::Close;
                }
                // Cache hit: answer immediately by slicing (no fetch).
                if let Some(piece) = self.cache.get(index) {
                    return self.write_block(w, index, begin, length, piece).await;
                }
                self.pending.entry(index).or_default().push((begin, length));
                if self.inflight.insert(index) {
                    self.spawn_fetch(index, done_tx, token);
                }
                ResponderFlow::Continue
            }
            Message::Cancel {
                index,
                begin,
                length,
            } => {
                // Remove the matching pending entries (an in-flight fetch is
                // not interrupted: it completes into the cache; Cancel only
                // affects the answer surface — the engine re-dispatches).
                if let Some(blocks) = self.pending.get_mut(&index) {
                    blocks.retain(|&(b, l)| !(b == begin && l == length));
                }
                debug!(target: "taiji::core::engine::webseed", url = %taiji_io::redact::redact_url_for_log(&self.url),
                    index, begin, "webseed cancel: pending block removed");
                ResponderFlow::Continue
            }
            // Our engine's regular outbound frames (interest/choke rounds/
            // progress ads/idle keepalive): irrelevant to a pure seeder
            // responder — ignored.
            Message::KeepAlive
            | Message::Choke
            | Message::Unchoke
            | Message::Interested
            | Message::NotInterested
            | Message::Have { .. }
            | Message::Bitfield { .. } => ResponderFlow::Continue,
            // Extended tolerated (see the module doc: SetUploadOnly re-sends
            // bypass the negotiation gate).
            Message::Extended { .. } => ResponderFlow::Continue,
            // Out of protocol (our leecher engine never sends it; a
            // pseudo-peer should never receive it) → close, fail-safe.
            _ => {
                debug!(target: "taiji::core::engine::webseed", url = %taiji_io::redact::redact_url_for_log(&self.url),
                    ?msg, "webseed protocol-external message -> close");
                ResponderFlow::Close
            }
        }
    }

    /// Fetch completion decision: success → reset the consecutive-failure
    /// counter, answer the pending requests, insert into the cache; failure →
    /// abandon the piece's pending answers + increment the counter (close at
    /// the threshold). A payload length mismatching the piece length is
    /// treated as failure (a truncated response face — the first gate before
    /// piece-level hash verification).
    async fn on_done<W: AsyncWrite + Unpin>(
        &mut self,
        done: PieceDone,
        w: &mut W,
    ) -> ResponderFlow {
        let (index, outcome) = match done {
            PieceDone::Ok(index, data) => (index, Ok(data)),
            PieceDone::Failed(index, reason) => (index, Err(reason)),
        };
        self.inflight.remove(&index);
        let want = piece_span(&self.goffs, &self.lens, index).map(|(_, l)| l);
        match (outcome, want) {
            (Ok(data), Some(want)) if data.len() as u64 == want => {
                self.consecutive_fails = 0;
                if let Some(blocks) = self.pending.remove(&index) {
                    for (begin, length) in blocks {
                        let block = data.slice(begin as usize..begin as usize + length as usize);
                        if matches!(
                            self.write_block_owned(w, index, begin, block).await,
                            ResponderFlow::Close
                        ) {
                            return ResponderFlow::Close;
                        }
                    }
                }
                self.cache.insert(index, data);
                ResponderFlow::Continue
            }
            (Ok(data), want) => {
                let reason = match want {
                    Some(want) => format!("piece len {}/{}", data.len(), want),
                    None => "piece index out of span table".to_string(),
                };
                self.note_failure(index, reason);
                self.failure_gate()
            }
            (Err(reason), _) => {
                self.note_failure(index, reason);
                self.failure_gate()
            }
        }
    }

    fn note_failure(&mut self, index: u32, reason: String) {
        // Abandon the piece's pending answers (the engine's RequestBook
        // timeout re-dispatches to other sources; a re-dispatch to this
        // source re-spawns the fetch — the retry-driven face).
        self.pending.remove(&index);
        self.consecutive_fails += 1;
        debug!(target: "taiji::core::engine::webseed", url = %taiji_io::redact::redact_url_for_log(&self.url), index,
            consecutive = self.consecutive_fails, %reason, "webseed piece fetch failed");
    }

    fn failure_gate(&self) -> ResponderFlow {
        if self.consecutive_fails >= WEBSEED_FAIL_CLOSE {
            info!(target: "taiji::core::engine::webseed", url = %taiji_io::redact::redact_url_for_log(&self.url),
                consecutive = self.consecutive_fails,
                "webseed dead: {WEBSEED_FAIL_CLOSE} consecutive piece failures, closing stream");
            ResponderFlow::Close
        } else {
            ResponderFlow::Continue
        }
    }

    /// Cache-hit sliced reply (the Bytes clone shares the buffer; the slice is zero-copy).
    async fn write_block<W: AsyncWrite + Unpin>(
        &self,
        w: &mut W,
        index: u32,
        begin: u32,
        length: u32,
        piece: Bytes,
    ) -> ResponderFlow {
        let block = piece.slice(begin as usize..begin as usize + length as usize);
        self.write_block_owned(w, index, begin, block).await
    }

    async fn write_block_owned<W: AsyncWrite + Unpin>(
        &self,
        w: &mut W,
        index: u32,
        begin: u32,
        block: Bytes,
    ) -> ResponderFlow {
        let msg = Message::Piece {
            index,
            begin,
            block,
        };
        match write_frame(w, msg).await {
            Ok(()) => ResponderFlow::Continue,
            Err(e) => {
                debug!(target: "taiji::core::engine::webseed", url = %taiji_io::redact::redact_url_for_log(&self.url), %e,
                    "webseed piece write failed -> close");
                ResponderFlow::Close
            }
        }
    }

    /// Whole-piece fetch subtask: Semaphore queueing → Range fetch (the
    /// RetryPolicy in-group retries live in the fetch implementation) → the
    /// completion event back to the main loop.
    fn spawn_fetch(
        &self,
        index: u32,
        done_tx: &mpsc::Sender<PieceDone>,
        token: &CancellationToken,
    ) {
        let Some((goff, len)) = piece_span(&self.goffs, &self.lens, index) else {
            return; // unreachable — the validation face already covers this; defensive arm
        };
        let fetch = Arc::clone(&self.fetch);
        let url = self.url.clone();
        let permits = Arc::clone(&self.permits);
        let token = token.clone();
        let done_tx = done_tx.clone();
        tokio::spawn(async move {
            // Concurrency gate: at most 4 whole pieces in flight, excess
            // queues here (never rejected — the request is already in the
            // pending table, so queueing propagates backpressure).
            let Ok(_permit) = permits.acquire_owned().await else {
                return;
            };
            let outcome = tokio::select! {
                _ = token.cancelled() => None,
                r = fetch.fetch_range(&url, goff, goff + len - 1) => Some(r),
            };
            match outcome {
                Some(Ok(data)) => {
                    let _ = done_tx.send(PieceDone::Ok(index, data)).await;
                }
                Some(Err(e)) => {
                    let _ = done_tx.send(PieceDone::Failed(index, e)).await;
                }
                None => {} // engine shutdown: exit silently
            }
        });
    }
}

/// Read pump: the frame loop (4 B length prefix + body) → the channel. EOF /
/// over-cap length / body decode failure = exit (the channel closes → the
/// main loop shuts down). A keepalive (len=0) is delivered as
/// [`Message::KeepAlive`] (ignored by the main loop).
async fn read_pump<R: AsyncRead + Unpin>(
    mut r: R,
    tx: mpsc::Sender<Message>,
    token: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            frame = read_frame(&mut r) => match frame {
                Ok(Some(msg)) => {
                    if tx.send(msg).await.is_err() {
                        break; // main loop already exited
                    }
                }
                Ok(None) | Err(_) => break, // EOF / frame error (fail-safe close)
            },
        }
    }
}

/// Single-frame read (body decoding reuses `FrameCodec`'s [`Message`]
/// `decode_body_from` — the length-prefix/cap/decode discipline is the same
/// implementation as the bt side; the symmetric encoder is
/// [`write_frame`]). `Ok(None)` = EOF.
async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Option<Message>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Ok(Some(Message::KeepAlive));
    }
    if len > MAX_FRAME_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame length over cap",
        ));
    }
    let mut body = BytesMut::zeroed(len);
    r.read_exact(&mut body).await?;
    Message::decode_body_from(body.freeze())
        .map(Some)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

/// Single-frame write: [`Message::encode`] (the 4 B length prefix included —
/// the same implementation as the FrameCodec encoding face, wire-identical
/// bytes) in one write_all.
async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, msg: Message) -> std::io::Result<()> {
    w.write_all(&msg.encode()).await
}

/// Pseudo-peer reserved: the fast bit only (reserved[7]&0x04, BEP-6 —
/// HaveAll/Reject are fast-ext messages, so the advertised bit and the
/// opening frames are self-consistent; no ext/DHT/v2 bits).
pub(crate) fn webseed_reserved() -> Reserved {
    // `from_bytes` is the existing pub constructor (peer_wire.rs Reserved);
    // an 8-byte literal always succeeds, the Err fallback = empty bits
    // (defensive, unreachable).
    Reserved::from_bytes(&[0, 0, 0, 0, 0, 0, 0, 0x04]).unwrap_or_else(|_| Reserved::empty())
}

/// webseed pseudo-peer peer_id (a synthetic 20 B): the `-TJ0001-ws` prefix +
/// the first 10 B of the URL's SHA-1 (deterministic — the same URL yields
/// the same id across sessions, distinct URLs differ; recognizable in
/// getPeers/logs). The prefix follows the repo's peer_id convention
/// (`-TJ0001-`, the session options.rs `--peer-id-prefix` default); the
/// spec sketch's "-TS40ws-" version segment was aligned to the repo's
/// current `-TJ0001-` (divergence note).
pub(crate) fn webseed_peer_id(url: &str) -> [u8; 20] {
    use sha1::{Digest as _, Sha1};
    let mut id = *b"-TJ0001-ws..........";
    let digest = Sha1::digest(url.as_bytes());
    id[10..20].copy_from_slice(&digest[..10]);
    id
}

/// URL port extraction (for the synthetic PeerMeta.port): the scheme default
/// (http 80 / https 443) + an explicit `:port` (taken after `]` for IPv6
/// literals). core has no url-crate dependency (reqwest is not a direct
/// dependency), so this is a hand-written conservative parse — scheme
/// legality is already guaranteed by the url-list parsing face (an http/
/// https prefix filter, metainfo.rs). With userinfo (`user:pass@host`),
/// `rsplit_once(':')` still finds the port after the host, and a missing
/// port falls back to the default (a synthetic metadata face; precision
/// sufficient).
pub(crate) fn url_endpoint_port(url: &str) -> u16 {
    let https = url
        .get(..5)
        .is_some_and(|s| s.eq_ignore_ascii_case("https"));
    let default_port: u16 = if https { 443 } else { 80 };
    let Some((_, rest)) = url.split_once("://") else {
        return default_port;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.starts_with('[') {
        // IPv6 literal: the ":port" after ']'.
        match authority.split_once(']') {
            Some((_, tail)) => tail
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(default_port),
            None => default_port,
        }
    } else {
        authority
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse().ok())
            .unwrap_or(default_port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    // ---- Decision tables: offset mapping / request validation / LRU / port extraction ----

    /// Rows 1-3 v1 linear (goffs = k×piece_len); row 4 the short last piece;
    /// row 5 out of range None; row 6 the empty-table defense.
    #[test]
    fn piece_span_decision_table() {
        let goffs = vec![0u64, 4, 8];
        let lens = vec![4u64, 4, 2];
        assert_eq!(
            piece_span(&goffs, &lens, 0),
            Some((0, 4)),
            "row 1: first piece"
        );
        assert_eq!(
            piece_span(&goffs, &lens, 1),
            Some((4, 4)),
            "row 2: mid piece"
        );
        assert_eq!(
            piece_span(&goffs, &lens, 2),
            Some((8, 2)),
            "rows 3+4: short last piece"
        );
        assert_eq!(piece_span(&goffs, &lens, 3), None, "row 5: out of range");
        assert_eq!(
            piece_span(&[], &lens, 0),
            None,
            "row 6: empty-table defense"
        );
    }

    /// Request validation decision table: valid / zero length / over 16 KiB
    /// / beyond the piece tail / index out of range.
    #[test]
    fn validate_request_decision_table() {
        let lens = vec![16u64 * 1024, 1024];
        assert!(
            validate_request(&lens, 0, 0, 16 * 1024).is_ok(),
            "whole block"
        );
        assert!(validate_request(&lens, 0, 0, 1).is_ok(), "minimum block");
        assert!(
            validate_request(&lens, 1, 0, 1024).is_ok(),
            "whole last piece"
        );
        assert!(
            validate_request(&lens, 0, 0, 0).is_err(),
            "zero length rejected"
        );
        assert!(
            validate_request(&lens, 0, 0, 16 * 1024 + 1).is_err(),
            "over 16KiB rejected"
        );
        assert!(
            validate_request(&lens, 1, 0, 1025).is_err(),
            "past the last piece's tail rejected"
        );
        assert!(
            validate_request(&lens, 1, 1021, 4).is_err(),
            "begin+length past the piece tail"
        );
        assert!(
            validate_request(&lens, 2, 0, 16).is_err(),
            "index past the table rejected"
        );
    }

    /// LRU eviction decision table: all resident under the cap → evict the
    /// oldest over the cap → a re-fetch touch changes the eviction order →
    /// an overwrite insertion reclaims quota → an over-cap single piece is
    /// not cached.
    #[test]
    fn cache_lru_eviction_decision_table() {
        let piece = |fill: u8| Bytes::from(vec![fill; 4]);
        let mut c = PieceCache::new(8);
        c.insert(0, piece(0));
        c.insert(1, piece(1));
        assert!(
            c.get(0).is_some() && c.get(1).is_some(),
            "all resident under the cap"
        );
        // Cap 8: the 3rd piece (12 B total) triggers eviction — piece 0 (the oldest) goes.
        c.insert(2, piece(2));
        assert!(c.get(0).is_none(), "the oldest piece 0 evicted");
        assert!(
            c.get(1).is_some() && c.get(2).is_some(),
            "new pieces resident"
        );
        // Touch semantics: after get(2), piece 1 is the oldest → the next insert evicts it.
        assert!(c.get(2).is_some());
        c.insert(3, piece(3));
        assert!(
            c.get(1).is_none(),
            "after the touch, piece 1 is the oldest and evicted"
        );
        assert!(c.get(2).is_some() && c.get(3).is_some());
        // Overwrite insertion: the old entry's byte quota is reclaimed (held does not leak).
        let mut c2 = PieceCache::new(4);
        c2.insert(7, piece(7));
        c2.insert(7, piece(8));
        assert!(c2.get(7).is_some_and(|b| b[0] == 8), "same-piece overwrite");
        assert_eq!(c2.held, 4, "after the overwrite the quota = one piece");
        // Over-cap single piece: not cached (the answer path is unaffected).
        let mut c3 = PieceCache::new(2);
        c3.insert(9, Bytes::from(vec![0u8; 4]));
        assert!(
            c3.get(9).is_none(),
            "an over-cap single piece is not cached"
        );
        assert_eq!(c3.held, 0);
    }

    /// URL port extraction decision table: http/https defaults / explicit
    /// port / path truncation / IPv6 literal / userinfo.
    #[test]
    fn url_endpoint_port_decision_table() {
        assert_eq!(
            url_endpoint_port("http://cdn.test/f.bin"),
            80,
            "http default"
        );
        assert_eq!(
            url_endpoint_port("https://cdn.test/f.bin"),
            443,
            "https default"
        );
        assert_eq!(
            url_endpoint_port("http://cdn.test:8080/f.bin"),
            8080,
            "explicit port"
        );
        assert_eq!(
            url_endpoint_port("https://cdn.test:9443/a/b?x=1"),
            9443,
            "path/query truncation"
        );
        assert_eq!(
            url_endpoint_port("http://[::1]:9000/f.bin"),
            9000,
            "IPv6 literal explicit port"
        );
        assert_eq!(
            url_endpoint_port("http://[::1]/f.bin"),
            80,
            "IPv6 literal default"
        );
        assert_eq!(
            url_endpoint_port("http://u:pa@cdn.test:7000/f"),
            7000,
            "port after userinfo"
        );
        assert_eq!(
            url_endpoint_port("http://u:pa@cdn.test/f"),
            80,
            "userinfo without a port falls back to the default"
        );
    }

    /// peer_id synthesis: the prefix convention + same-URL determinism + distinct URLs differ.
    #[test]
    fn webseed_peer_id_shape_and_stability() {
        let a = webseed_peer_id("http://cdn.test/a");
        assert_eq!(&a[..10], b"-TJ0001-ws", "the in-repo prefix + ws marker");
        assert_eq!(
            webseed_peer_id("http://cdn.test/a"),
            a,
            "same URL deterministic"
        );
        assert_ne!(
            webseed_peer_id("http://cdn.test/b"),
            a,
            "distinct URLs differ"
        );
    }

    /// reserved: the fast bit present, the ext/DHT bits absent (HaveAll
    /// self-consistency + the negotiation gate closed).
    #[test]
    fn webseed_reserved_advertises_fast_only() {
        let r = webseed_reserved();
        assert!(
            r.supports_fast(),
            "the fast bit (BEP6 HaveAll self-consistency)"
        );
        assert!(!r.supports_extended(), "no ext bit (the BEP10 gate closed)");
        assert!(!r.supports_dht(), "no DHT bit (never sends PORT)");
    }

    // ---- Range-fetch seam injection mock ----

    /// Counting + scripted + gated mock: `started` counts after the Semaphore
    /// (the fetch_range body runs after spawn_fetch's acquire — the count
    /// observes "past the gate"); while a test holds the `gate` lock, all
    /// in-flight fetches suspend (the queueing observation window for the
    /// concurrency gate); the script queue is consumed item by item (empty =
    /// always succeed with an 0xA5 fill).
    struct MockFetch {
        started: AtomicUsize,
        script: std::sync::Mutex<std::collections::VecDeque<Result<Vec<u8>, String>>>,
        gate: tokio::sync::Mutex<()>,
    }

    impl MockFetch {
        fn always_ok() -> Arc<Self> {
            Arc::new(Self {
                started: AtomicUsize::new(0),
                script: std::sync::Mutex::new(std::collections::VecDeque::new()),
                gate: tokio::sync::Mutex::new(()),
            })
        }

        fn scripted(outcomes: Vec<Result<Vec<u8>, String>>) -> Arc<Self> {
            Arc::new(Self {
                started: AtomicUsize::new(0),
                script: std::sync::Mutex::new(outcomes.into()),
                gate: tokio::sync::Mutex::new(()),
            })
        }

        fn started(&self) -> usize {
            self.started.load(Ordering::SeqCst)
        }
    }

    impl RangeFetch for MockFetch {
        fn fetch_range<'a>(
            &'a self,
            _url: &'a str,
            start: u64,
            end_inclusive: u64,
        ) -> RangeFetchFuture<'a> {
            let outcome = {
                let mut q = self.script.lock().unwrap_or_else(|e| e.into_inner());
                match q.pop_front() {
                    Some(r) => r,
                    None => Ok(vec![0xA5u8; (end_inclusive - start + 1) as usize]),
                }
            };
            Box::pin(async move {
                // Count past the gate (the fetch_range body runs after acquire_owned).
                self.started.fetch_add(1, Ordering::SeqCst);
                let _held = self.gate.lock().await;
                outcome.map(Bytes::from)
            })
        }
    }

    /// Direct-drive responder fixture: a real duplex + the test playing the
    /// engine side (raw frame io). Geometry: 8 pieces × 8 bytes (linear
    /// goffs).
    struct ResponderFixture {
        local: DuplexStream,
    }

    async fn spawn_responder(fetch: Arc<MockFetch>) -> ResponderFixture {
        let (local, remote) = tokio::io::duplex(WEBSEED_DUPLEX_BUF);
        let goffs = Arc::new((0..8u64).map(|k| k * 8).collect::<Vec<_>>());
        let responder = WebseedResponder::new(
            fetch,
            "http://webseed.test/payload".into(),
            [7u8; 20],
            webseed_peer_id("http://webseed.test/payload"),
            goffs,
            vec![8u64; 8],
        );
        let token = CancellationToken::new();
        tokio::spawn(responder.run(remote, token));
        ResponderFixture { local }
    }

    /// Engine-side handshake (play the outbound 68 B, read the reply 68 B).
    async fn engine_handshake(fx: &mut ResponderFixture) {
        let mine = Handshake {
            reserved: Reserved::aria2_default(),
            info_hash: [7u8; 20],
            peer_id: *b"-TJ0001-ENGINEENGIN1",
        };
        fx.local
            .write_all(&mine.encode())
            .await
            .unwrap_or_else(|e| panic!("write hs: {e}"));
        let mut buf = [0u8; HANDSHAKE_LEN];
        fx.local
            .read_exact(&mut buf)
            .await
            .unwrap_or_else(|e| panic!("read hs: {e}"));
        let theirs = Handshake::decode(&buf).unwrap_or_else(|e| panic!("decode hs: {e}"));
        assert_eq!(
            theirs.info_hash, [7u8; 20],
            "the handshake reply's info_hash"
        );
        assert!(
            theirs.reserved.supports_fast(),
            "the fast bit advertised (HaveAll self-consistency)"
        );
        assert!(
            !theirs.reserved.supports_extended(),
            "no ext bit (the negotiation gate closed)"
        );
    }

    /// Read one wire frame (returns (id, body); a 400 ms budget). EOF/timeout = None.
    async fn read_frame_raw(fx: &mut ResponderFixture) -> Option<(u8, Vec<u8>)> {
        tokio::time::timeout(Duration::from_millis(400), async {
            let mut len_buf = [0u8; 4];
            fx.local.read_exact(&mut len_buf).await.ok()?;
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; len];
            fx.local.read_exact(&mut body).await.ok()?;
            Some((body.first().copied().unwrap_or(0), body))
        })
        .await
        .ok()
        .flatten()
    }

    async fn write_frame_raw(fx: &mut ResponderFixture, msg: &Message) {
        fx.local
            .write_all(&msg.encode())
            .await
            .unwrap_or_else(|e| panic!("write frame: {e}"));
    }

    /// Wait for local-half EOF (responder shutdown observation; a 2 s budget).
    async fn wait_eof(fx: &mut ResponderFixture) -> bool {
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut buf = [0u8; 16];
            loop {
                match fx.local.read(&mut buf).await {
                    Err(_) | Ok(0) => break true,
                    Ok(_) => continue,
                }
            }
        })
        .await
        .unwrap_or(false)
    }

    /// Wait until the past-gate fetch count reaches n (a 2 s polling budget).
    async fn wait_started(fetch: &MockFetch, n: usize) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while fetch.started() < n {
            assert!(
                Instant::now() < deadline,
                "the past-gate fetch count never reached {n} (currently {})",
                fetch.started()
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Wait until started == n and stable (no excess fetch may pass the
    /// gate: the queueing observation).
    async fn settle_started(fetch: &MockFetch, n: usize) {
        wait_started(fetch, n).await;
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(
            fetch.started(),
            n,
            "an out-of-gate fetch must not pass the gate (concurrency cap \
             {WEBSEED_FETCH_PARALLEL})"
        );
    }

    /// Opening sequence: handshake reply → Unchoke → HaveAll (BEP-6; the
    /// frame order is locked — HaveAll must arrive after Unchoke so the
    /// choke-mirror flip releases the dispatch gate first).
    #[tokio::test]
    async fn responder_opens_with_unchoke_then_have_all() {
        let fetch = MockFetch::always_ok();
        let mut fx = spawn_responder(fetch).await;
        engine_handshake(&mut fx).await;
        let (id1, _) = read_frame_raw(&mut fx)
            .await
            .unwrap_or_else(|| panic!("the first frame missing"));
        let (id2, _) = read_frame_raw(&mut fx)
            .await
            .unwrap_or_else(|| panic!("the second frame missing"));
        assert_eq!(id1, 1, "first frame = Unchoke (id 1)");
        assert_eq!(id2, 14, "second frame = HaveAll (id 0x0E, BEP6)");
    }

    /// Request → whole-piece fetch → sliced block replies: piece 2's two
    /// blocks (begin 0/4, 4 B each) are sliced from one whole-piece fetch
    /// (started == 1 = piece-granular prefetch); the replies align exactly on
    /// (index,begin,block).
    #[tokio::test]
    async fn request_slices_piece_from_single_fetch() {
        let fetch = MockFetch::always_ok();
        let _gate = fetch.gate.lock().await;
        let mut fx = spawn_responder(fetch.clone()).await;
        engine_handshake(&mut fx).await;
        // Consume the two opening frames.
        let _ = read_frame_raw(&mut fx).await;
        let _ = read_frame_raw(&mut fx).await;
        for begin in [0u32, 4] {
            write_frame_raw(
                &mut fx,
                &Message::Request {
                    index: 2,
                    begin,
                    length: 4,
                },
            )
            .await;
        }
        wait_started(&fetch, 1).await;
        drop(_gate);
        let (id, body) = read_frame_raw(&mut fx)
            .await
            .unwrap_or_else(|| panic!("the first block reply missing"));
        assert_eq!(id, 7, "Piece (id 7)");
        assert_eq!(&body[1..5], &2u32.to_be_bytes(), "index aligned");
        assert_eq!(&body[5..9], &0u32.to_be_bytes(), "begin aligned");
        assert_eq!(body.len(), 13, "9B header + 4B block (length exact)");
        let (id2, body2) = read_frame_raw(&mut fx)
            .await
            .unwrap_or_else(|| panic!("the second block reply missing"));
        assert_eq!(id2, 7);
        assert_eq!(
            &body2[5..9],
            &4u32.to_be_bytes(),
            "second block begin aligned"
        );
        assert_eq!(body2.len(), 13);
        assert_eq!(
            fetch.started(),
            1,
            "one whole-piece fetch (two blocks, one fetch)"
        );
    }

    /// Concurrency gate + queueing: 6 concurrent piece requests → the
    /// past-gate count pins at 4 (the rest queue; after the gate releases,
    /// all pass and all 6 pieces are eventually answered — no rejection).
    #[tokio::test]
    async fn fetch_concurrency_capped_at_four_with_queueing() {
        let fetch = MockFetch::always_ok();
        let gate = fetch.gate.lock().await;
        let mut fx = spawn_responder(fetch.clone()).await;
        engine_handshake(&mut fx).await;
        let _ = read_frame_raw(&mut fx).await;
        let _ = read_frame_raw(&mut fx).await;
        for index in 0u32..6 {
            write_frame_raw(
                &mut fx,
                &Message::Request {
                    index,
                    begin: 0,
                    length: 8,
                },
            )
            .await;
        }
        settle_started(&fetch, WEBSEED_FETCH_PARALLEL).await;
        drop(gate);
        let mut pieces = 0;
        while pieces < 6 {
            let (id, _) = read_frame_raw(&mut fx)
                .await
                .unwrap_or_else(|| panic!("piece {}'s Piece reply missing", pieces + 1));
            assert_eq!(id, 7);
            pieces += 1;
        }
        wait_started(&fetch, 6).await;
        assert_eq!(
            fetch.started(),
            6,
            "queueing never rejects: everything passes the gate"
        );
    }

    /// Cancel removes pending: request (while pending) → Cancel → no Piece
    /// reply even after the fetch completes (a 400 ms observation window).
    #[tokio::test]
    async fn cancel_removes_pending_block() {
        let fetch = MockFetch::always_ok();
        let gate = fetch.gate.lock().await;
        let mut fx = spawn_responder(fetch.clone()).await;
        engine_handshake(&mut fx).await;
        let _ = read_frame_raw(&mut fx).await;
        let _ = read_frame_raw(&mut fx).await;
        write_frame_raw(
            &mut fx,
            &Message::Request {
                index: 1,
                begin: 0,
                length: 8,
            },
        )
        .await;
        write_frame_raw(
            &mut fx,
            &Message::Cancel {
                index: 1,
                begin: 0,
                length: 8,
            },
        )
        .await;
        drop(gate);
        assert!(
            read_frame_raw(&mut fx).await.is_none(),
            "no Piece reply after Cancel"
        );
    }

    /// 3 consecutive piece failures → close the stream (EOF observed); the
    /// failed pieces' pending requests are abandoned (zero replies
    /// throughout).
    #[tokio::test]
    async fn three_consecutive_failures_close_stream() {
        let fetch = MockFetch::scripted(vec![
            Err("boom-1".into()),
            Err("boom-2".into()),
            Err("boom-3".into()),
        ]);
        let mut fx = spawn_responder(fetch.clone()).await;
        engine_handshake(&mut fx).await;
        let _ = read_frame_raw(&mut fx).await;
        let _ = read_frame_raw(&mut fx).await;
        for index in 0u32..3 {
            write_frame_raw(
                &mut fx,
                &Message::Request {
                    index,
                    begin: 0,
                    length: 8,
                },
            )
            .await;
            // A failed completion has no wire signal — the past-gate count +
            // settle window ensure the done event is consumed before the next
            // request (deterministic consecutive semantics).
            wait_started(&fetch, usize::try_from(index).unwrap_or(0) + 1).await;
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
        assert!(
            read_frame_raw(&mut fx).await.is_none(),
            "zero replies during failed pieces (pending requests abandoned)"
        );
        assert!(
            wait_eof(&mut fx).await,
            "the stream closes after the 3rd failure (EOF)"
        );
    }

    /// Success resets consecutive failures: 2 failures, 1 success, then 2
    /// more → no close (consecutive semantics, not cumulative); the
    /// successful piece gets exactly one reply.
    #[tokio::test]
    async fn success_resets_consecutive_failures() {
        let fetch = MockFetch::scripted(vec![
            Err("a".into()),
            Err("b".into()),
            Ok(vec![0xA5u8; 8]),
            Err("c".into()),
            Err("d".into()),
        ]);
        let mut fx = spawn_responder(fetch.clone()).await;
        engine_handshake(&mut fx).await;
        let _ = read_frame_raw(&mut fx).await;
        let _ = read_frame_raw(&mut fx).await;
        for index in 0u32..5 {
            write_frame_raw(
                &mut fx,
                &Message::Request {
                    index,
                    begin: 0,
                    length: 8,
                },
            )
            .await;
            wait_started(&fetch, usize::try_from(index).unwrap_or(0) + 1).await;
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
        // The 3rd piece succeeds → exactly one Piece reply; 4 total failures
        // but ≤ 2 consecutive → no close.
        let (id, _) = read_frame_raw(&mut fx)
            .await
            .unwrap_or_else(|| panic!("the successful piece's reply missing"));
        assert_eq!(id, 7);
        assert!(
            read_frame_raw(&mut fx).await.is_none(),
            "the remaining failed pieces produce zero replies"
        );
        assert!(
            !wait_eof(&mut fx).await,
            "consecutive failures reset by success: no close"
        );
    }

    /// Out-of-protocol message → close (a pseudo-peer should never receive
    /// Piece — our engine never sends it, and for real peers the bt side
    /// disconnects the same way).
    #[tokio::test]
    async fn protocol_external_message_closes() {
        let fetch = MockFetch::always_ok();
        let mut fx = spawn_responder(fetch.clone()).await;
        engine_handshake(&mut fx).await;
        let _ = read_frame_raw(&mut fx).await;
        let _ = read_frame_raw(&mut fx).await;
        write_frame_raw(
            &mut fx,
            &Message::Piece {
                index: 0,
                begin: 0,
                block: Bytes::from_static(b"12345678"),
            },
        )
        .await;
        assert!(wait_eof(&mut fx).await, "an out-of-protocol frame -> close");
    }

    /// Invalid Request (beyond the piece tail) → close (mirroring the bt
    /// side's inbound Request validation).
    #[tokio::test]
    async fn invalid_request_closes() {
        let fetch = MockFetch::always_ok();
        let mut fx = spawn_responder(fetch.clone()).await;
        engine_handshake(&mut fx).await;
        let _ = read_frame_raw(&mut fx).await;
        let _ = read_frame_raw(&mut fx).await;
        write_frame_raw(
            &mut fx,
            &Message::Request {
                index: 0,
                begin: 4,
                length: 8,
            },
        )
        .await;
        assert!(
            wait_eof(&mut fx).await,
            "a request past the piece tail -> close"
        );
    }

    /// RetryPolicy group exhaustion counting: a local 500 server +
    /// max_tries=3 → the server receives exactly 3 requests and the fetch
    /// fails (the webseed wiring of taiji-http's consumer-driven retry; the
    /// client.rs retry_policy anchor).
    #[tokio::test]
    async fn http_fetch_retries_then_fails_after_max_tries() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
        let hits = Arc::new(AtomicUsize::new(0));
        let server_hits = Arc::clone(&hits);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let hits = Arc::clone(&server_hits);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 1024];
                    // Answer 500 as soon as the request head arrives (Connection: close).
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                                    hits.fetch_add(1, Ordering::SeqCst);
                                    let resp = "HTTP/1.1 500 Internal Server Error\r\n\
                                                Content-Length: 0\r\nConnection: close\r\n\r\n";
                                    let _ = sock.write_all(resp.as_bytes()).await;
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        // Client construction with explicit retry params (ClientConfig.retry injected).
        let client = HttpClient::new(ClientConfig {
            retry: taiji_http::retry::RetryPolicy {
                max_tries: 3,
                base_wait: Duration::from_millis(10),
                max_wait: Duration::from_millis(50),
            },
            ..ClientConfig::default()
        })
        .unwrap_or_else(|e| panic!("client: {e}"));
        let fetch = HttpRangeFetch {
            client,
            ctx: RequestCtx::default(),
        };
        let url = format!("http://{addr}/payload.bin");
        let got = fetch.fetch_range(&url, 0, 7).await;
        assert!(got.is_err(), "fails after retries are exhausted");
        assert_eq!(
            hits.load(Ordering::SeqCst),
            3,
            "exactly 3 attempts within the group"
        );
    }

    /// 200 (Range ignored) counts as failure: the body is not accepted even
    /// when long enough (prevents whole-file buffering + a ranged-semantics
    /// mismatch).
    #[tokio::test]
    async fn http_fetch_rejects_range_ignored_200() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
        tokio::spawn(async move {
            let (mut sock, _) = listener
                .accept()
                .await
                .unwrap_or_else(|e| panic!("accept: {e}"));
            let mut buf = vec![0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                            let body = vec![0u8; 8];
                            let head = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            );
                            let _ = sock.write_all(head.as_bytes()).await;
                            let _ = sock.write_all(&body).await;
                            break;
                        }
                    }
                }
            }
        });
        let client = HttpClient::new(ClientConfig {
            retry: taiji_http::retry::RetryPolicy {
                max_tries: 1,
                base_wait: Duration::ZERO,
                max_wait: Duration::from_millis(10),
            },
            ..ClientConfig::default()
        })
        .unwrap_or_else(|e| panic!("client: {e}"));
        let fetch = HttpRangeFetch {
            client,
            ctx: RequestCtx::default(),
        };
        let got = fetch
            .fetch_range(&format!("http://{addr}/payload.bin"), 0, 7)
            .await;
        assert!(got.is_err(), "200 = the Range ignored -> failure");
    }

    /// Body-clamp decision table for webseed 206 reads, three arms: (a) a
    /// declared Content-Length over want → rejected before reading
    /// (oversized); (b) no CL, connection-close framing, only 4 B sent
    /// (want=8) → a clean stream end becomes a short-body failure (the retry
    /// takes over); (c) no CL, 16 B over-sent in one write (want=8) →
    /// truncated to the want prefix, the over-sent bytes never enter the
    /// heap.
    #[tokio::test]
    async fn http_fetch_body_clamp_decision_table() {
        /// Single-connection dumb server: answers per `mode` after reading
        /// the request head (cl=0 → no Content-Length header,
        /// connection-close framing).
        async fn serve_once(
            listener: tokio::net::TcpListener,
            mode: (&'static str, usize, usize), // (status line, declared CL, bytes actually sent)
        ) {
            let (mut sock, _) = listener
                .accept()
                .await
                .unwrap_or_else(|e| panic!("accept: {e}"));
            let mut buf = vec![0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                }
            }
            let (line, cl, send) = mode;
            let head = format!(
                "{line}\r\nContent-Range: bytes 0-7/8\r\n{}Connection: close\r\n\r\n",
                if cl == 0 {
                    String::new()
                } else {
                    format!("Content-Length: {cl}\r\n")
                }
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(&vec![0xABu8; send]).await;
            let _ = sock.shutdown().await;
        }
        let client = || {
            HttpClient::new(ClientConfig {
                retry: taiji_http::retry::RetryPolicy {
                    max_tries: 1,
                    base_wait: Duration::ZERO,
                    max_wait: Duration::from_millis(10),
                },
                ..ClientConfig::default()
            })
            .unwrap_or_else(|e| panic!("client: {e}"))
        };
        let fetch = |c: HttpClient| HttpRangeFetch {
            client: c,
            ctx: RequestCtx::default(),
        };

        // (a) CL=16 > want=8 → oversized, rejected before reading.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = l.local_addr().unwrap_or_else(|e| panic!("addr: {e}"));
        let srv = tokio::spawn(serve_once(l, ("HTTP/1.1 206 Partial Content", 16, 16)));
        let got = fetch(client())
            .fetch_range(&format!("http://{addr}/p.bin"), 0, 7)
            .await;
        let _ = srv.await;
        let err = match got {
            Ok(_) => panic!("a CL over want must be rejected"),
            Err(e) => e,
        };
        assert!(
            err.contains("oversized body 16/8"),
            "the error face must be oversized, got: {err}"
        );

        // (b) No CL, 4 B sent → short body 4/8.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = l.local_addr().unwrap_or_else(|e| panic!("addr: {e}"));
        let srv = tokio::spawn(serve_once(l, ("HTTP/1.1 206 Partial Content", 0, 4)));
        let got = fetch(client())
            .fetch_range(&format!("http://{addr}/p.bin"), 0, 7)
            .await;
        let _ = srv.await;
        let err = match got {
            Ok(_) => panic!("a short body must fail"),
            Err(e) => e,
        };
        assert!(
            err.contains("short body 4/8"),
            "the error face must be short body, got: {err}"
        );

        // (c) No CL, 16 B over-sent in one write (want=8) → Ok with exactly the 8 B prefix.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = l.local_addr().unwrap_or_else(|e| panic!("addr: {e}"));
        let srv = tokio::spawn(serve_once(l, ("HTTP/1.1 206 Partial Content", 0, 16)));
        let got = fetch(client())
            .fetch_range(&format!("http://{addr}/p.bin"), 0, 7)
            .await;
        let _ = srv.await;
        let body =
            got.unwrap_or_else(|e| panic!("over-sent truncation to want should succeed: {e}"));
        assert_eq!(body.len(), 8, "must truncate to want");
        assert!(body.iter().all(|&b| b == 0xAB));
    }

    /// Guard 1: the webseed outbound request UA == `PEER_AGENT` (asserted on
    /// the wire, not at construction) — built via production
    /// `HttpRangeFetch::build()`, a local server captures the raw request
    /// head, and a 206 reply walks the full fetch chain.
    #[tokio::test]
    async fn http_fetch_sends_peer_agent_ua_on_wire() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let sink = captured.clone();
        tokio::spawn(async move {
            let (mut sock, _) = listener
                .accept()
                .await
                .unwrap_or_else(|e| panic!("accept: {e}"));
            let mut buf = vec![0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        sink.lock()
                            .unwrap_or_else(|e| panic!("lock: {e}"))
                            .extend_from_slice(&buf[..n]);
                        if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                            let body = vec![0u8; 8];
                            let head = format!(
                                "HTTP/1.1 206 Partial Content\r\n\
                                 Content-Range: bytes 0-7/8\r\n\
                                 Content-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            );
                            let _ = sock.write_all(head.as_bytes()).await;
                            let _ = sock.write_all(&body).await;
                            break;
                        }
                    }
                }
            }
        });
        // Production construction (not a test-specific ClientConfig
        // injection) — the UA is pinned inside build(); this test locks its
        // on-the-wire result.
        let fetch = HttpRangeFetch::build().unwrap_or_else(|e| panic!("build: {e}"));
        let got = fetch
            .fetch_range(&format!("http://{addr}/payload.bin"), 0, 7)
            .await;
        assert!(got.is_ok(), "the 206 fetch chain works end to end: {got:?}");
        let raw = captured
            .lock()
            .unwrap_or_else(|e| panic!("lock: {e}"))
            .clone();
        let text = String::from_utf8_lossy(&raw);
        let want = format!("user-agent: {}", taiji_bt::tracker::PEER_AGENT);
        assert!(
            text.to_ascii_lowercase()
                .contains(&want.to_ascii_lowercase()),
            "the outbound UA must be PEER_AGENT {:?}, received header:\n{text}",
            taiji_bt::tracker::PEER_AGENT
        );
    }

    /// Guard 2: `build()` carries no per-request UA override — the task-level
    /// `user-agent` option (consumed by the webseed/URI face under aria2
    /// semantics) is not wired into the webseed request context. If that
    /// option is ever wired into the BT task's HTTP face, this assertion is
    /// the boundary check (the intentional-divergence note is in the build()
    /// doc).
    #[test]
    fn build_carries_no_user_agent_ctx_override() {
        let fetch = HttpRangeFetch::build().unwrap_or_else(|e| panic!("build: {e}"));
        assert!(
            fetch.ctx.user_agent.is_none(),
            "the webseed request context must not carry a UA override (the BT \
             identity face is always PEER_AGENT)"
        );
    }

    // ---- wire sequencing (a real duplex + a real PeerTask; the engine
    // tests' peer fixture shape — this group upgrades the "engine side" from
    // hand-written frames to the full PeerTask chain: handshake →
    // Unchoke/HaveAll consumption → a RequestPiece command → RequestBook
    // slot-matched Piece delivery → CancelPiece with no delivery) ----

    /// Real PeerTask × responder full-chain sequencing: (1) handshake (the
    /// handshake_exchange engine form); (2) the opening Unchoke is consumed
    /// by PeerTask (the choke mirror flips) + HaveAll surfaces as an
    /// AvailEvent; (3) RequestPiece → whole-piece fetch → block replies into
    /// the data channel (RequestBook five-tuple slot matching = protocol
    /// self-consistency); (4) CancelPiece removes the pending entry before
    /// the fetch completes → no delivery.
    #[tokio::test]
    async fn responder_full_chain_with_real_peer_task() {
        use taiji_bt::peer::PeerCommand;
        use taiji_bt::peer::PeerHandle as _;
        use taiji_bt::peer::PeerTask;
        use taiji_bt::piece_id::PieceId;

        const PIECE: u64 = 16 * 1024;
        let fetch = MockFetch::always_ok();
        let gate = fetch.gate.lock().await;
        // Responder (the remote half; 2 pieces × 16 KiB, content = the mock's 0xA5 fill).
        let (local, remote) = tokio::io::duplex(WEBSEED_DUPLEX_BUF);
        let goffs = Arc::new(vec![0u64, PIECE]);
        let responder = WebseedResponder::new(
            Arc::clone(&fetch),
            "http://webseed.test/payload".into(),
            [7u8; 20],
            webseed_peer_id("http://webseed.test/payload"),
            goffs,
            vec![PIECE, PIECE],
        );
        let root = CancellationToken::new();
        tokio::spawn(responder.run(remote, root.child_token()));
        // (1) Engine-side handshake (the outbound form — the same chain as
        // dial::attach_webseeds).
        let (stream, theirs) = taiji_bt::peer::handshake_exchange(
            local,
            &[7u8; 20],
            b"-TJ0001-ENGINEENGIN1",
            Reserved::aria2_default(),
            Duration::from_secs(5),
        )
        .await
        .unwrap_or_else(|e| panic!("handshake: {e}"));
        assert!(theirs.reserved.supports_fast(), "the responder's fast bit");
        // (2) PeerTask spawn (the avail channel present — the HaveAll event observation face).
        let (avail_tx, mut avail_rx) = mpsc::channel(16);
        let config = taiji_bt::peer::PeerConfig {
            avail_tx: Some(avail_tx),
            ..taiji_bt::peer::PeerConfig::flat()
        };
        let (handle, _join, mut data_rx) = PeerTask::spawn(&root, stream, config);
        // The choke mirror flipping = Unchoke consumed (a 2 s polling budget).
        let deadline = Instant::now() + Duration::from_secs(2);
        while handle.is_choking_us() {
            assert!(Instant::now() < deadline, "the unchoke mirror did not flip");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // The HaveAll event surfaces (its order vs Unchoked is unspecified — loop until seen).
        let mut saw_have_all = false;
        let deadline = Instant::now() + Duration::from_secs(2);
        while !saw_have_all {
            assert!(Instant::now() < deadline, "the HaveAll event missing");
            match tokio::time::timeout(Duration::from_millis(400), avail_rx.recv()).await {
                Ok(Some(taiji_bt::peer::AvailEvent::HaveAll { .. })) => saw_have_all = true,
                Ok(Some(_)) => continue,
                Ok(None) => panic!("the avail channel closed"),
                Err(_) => panic!("the HaveAll event timed out"),
            }
        }
        // (3) Request → fetch (the gate released) → block replies into the data channel.
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        handle
            .command(PeerCommand::RequestPiece {
                id: PieceId::V1(0),
                begin: 0,
                length: PIECE as u32,
                reply: reply_tx,
            })
            .unwrap_or_else(|e| panic!("command: {e:?}"));
        reply_rx
            .await
            .unwrap_or_else(|e| panic!("request reply: {e}"))
            .unwrap_or_else(|e| panic!("request rejected: {e:?}"));
        drop(gate);
        let data = tokio::time::timeout(Duration::from_secs(2), data_rx.recv())
            .await
            .unwrap_or_else(|_| panic!("piece data timed out"))
            .unwrap_or_else(|| panic!("the data channel closed"));
        assert_eq!(data.id, PieceId::V1(0), "the reply's piece index aligned");
        assert_eq!(data.begin, 0, "the reply's begin aligned");
        assert_eq!(
            data.block.len(),
            PIECE as usize,
            "the reply's length aligned"
        );
        assert!(
            data.block.iter().all(|&b| b == 0xA5),
            "content = the mock fill"
        );
        // (4) Cancel: close the gate again → request (the fetch suspended)
        // → Cancel → release → no delivery.
        let gate = fetch.gate.lock().await;
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        handle
            .command(PeerCommand::RequestPiece {
                id: PieceId::V1(1),
                begin: 0,
                length: PIECE as u32,
                reply: reply_tx,
            })
            .unwrap_or_else(|e| panic!("command: {e:?}"));
        reply_rx
            .await
            .unwrap_or_else(|e| panic!("request reply: {e}"))
            .unwrap_or_else(|e| panic!("request rejected: {e:?}"));
        // Cancel is sent only after the fetch has passed the gate (the
        // started count in place) — this fixes the order of pending removal
        // vs fetch completion (the gate guarantees the fetch has not
        // finished).
        wait_started(&fetch, 2).await;
        let _ = handle.command(PeerCommand::CancelPiece {
            id: PieceId::V1(1),
            begin: 0,
            length: PIECE as u32,
        });
        // A settle window for the Cancel frame (PeerTask command → wire
        // write → read pump → responder pending removal is async end to end;
        // the fetch cannot complete while the gate is held — releasing after
        // the settle fixes Cancel-before-done).
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(gate);
        assert!(
            tokio::time::timeout(Duration::from_millis(300), data_rx.recv())
                .await
                .is_err(),
            "no piece delivery after Cancel"
        );
        root.cancel();
    }
}
