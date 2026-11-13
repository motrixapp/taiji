//! BEP-10 extension face: ext handshake registration, frame dispatch
//! for ut_metadata (requester + responder) and the ut_pex consumption
//! half, plus the extension config types ([`ExtConfig`],
//! [`MetadataSource`], [`MetadataFetchSpec`], ...) and the requester
//! fetch session. Inbound routing: primary = our own advertised id,
//! secondary = the peer's advertised id (BEP-10 "message IDs are local
//! to the peer"; the lenient fallback is documented at the dispatch
//! function).
//!
//! Upstream anchor mapping: docs/design/peer-protocol.md

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tracing::debug;

use super::conn::OutboundWriter;
use super::{PexEvent, PexExt};
use crate::holepunch::UtHolepunch;
use crate::peer_wire::{ExtHandshake, Message};
use crate::pex::{PexInboundSession, PexOffer, PexSwarmSender};
use crate::ut_metadata::{MetadataError, MetadataFetcher, UtMetadata};

/// Our ut_metadata outbound msg id (BEP-10 reserves id 0 for the ext
/// handshake itself; ut_metadata = 2, the aria2 default
/// `ExtRegistry::aria2_default`, HandshakeExtensionMessageTest.cc).
pub const OUTBOUND_UT_METADATA_ID: u8 = 2;

/// Our ut_pex outbound msg id (the same defaults: `ut_metadata = 2,
/// ut_pex = 1`, HandshakeExtensionMessageTest.cc vectors +
/// `peer_wire::ExtRegistry::aria2_default`; BEP-10 ids are local — the
/// peer replies using the ids from our handshake's m dict).
pub const OUTBOUND_UT_PEX_ID: u8 = 1;

/// Our ut_holepunch advertised id: the uTorrent-conventional 0x20
/// (libtorrent itself advertises 4 — BEP-10 ids are local; see the
/// `crate::holepunch` module docs). Inbound routing matches
/// ut_metadata/ut_pex: primary = our advertised id, secondary = the
/// peer's.
pub use crate::holepunch::OUTBOUND_UT_HOLEPUNCH_ID;

/// Inbound ut_holepunch rendezvous fixed-window rate limit (abuse
/// guard: over-limit frames are ignored, not disconnects). libtorrent
/// has no counterpart (on_holepunch processes directly) — this is a
/// deliberate local gate with no reference numbers: in a legitimate
/// swarm rendezvous appears only around hole punching (a per-minute
/// rate), so 4/60s is far above legitimate need.
pub const HOLEPUNCH_REQUEST_WINDOW: Duration = Duration::from_secs(60);
/// Rendezvous in-window cap (same rationale).
pub const HOLEPUNCH_REQUEST_LIMIT: u32 = 4;
/// Separate fixed window for inbound connect (each accepted connect =
/// one engine-side hole-punch dial with a 10s budget; the window cap
/// prevents a malicious relay from manufacturing dial churn).
/// Legitimate hole punches are 1-2 per event; 4/60s is a similarly
/// loose bound.
pub const HOLEPUNCH_CONNECT_WINDOW: Duration = Duration::from_secs(60);
/// Connect in-window cap (same rationale).
pub const HOLEPUNCH_CONNECT_LIMIT: u32 = 4;
/// Inbound ut_pex fixed-window rate limit (abuse guard: over-limit
/// frames ignored, not disconnects — the same shape and rationale as
/// the ut_holepunch limits). BEP-11: "shouldn't send these messages
/// more often than once a minute" (the legitimate cadence = one frame
/// per 60s, [`crate::pex::DEFAULT_INTERVAL`]); the decode cap already
/// bounds addresses per frame (the first frame <=
/// [`crate::pex::FIRST_PEX_MAX`] x2, later ones <= 100), and this
/// window bounds frame frequency — a legitimate swarm sends one frame
/// per peer per window, so 4/60s is far above legitimate need.
pub const PEX_MESSAGE_WINDOW: Duration = Duration::from_secs(60);
/// ut_pex in-window cap (same rationale).
pub const PEX_MESSAGE_LIMIT: u32 = 4;

/// Expected identity for the magnet's dual hash (the ut_metadata
/// assembly check anchor).
///
/// - `V1`: SHA-1(info) == btih (BEP-9 semantics,
///   `UTMetadataDataExtensionMessage.cc`);
/// - `V2`: SHA-256(info) == btmh (BEP-52 multihash 1220; aria2 has no
///   btmh magnet path — this check is a local BEP-52-aligned extension;
///   the ut_metadata payload is the raw info dict bytes, hashed directly
///   and compared against btmh).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedInfoHash {
    V1([u8; 20]),
    V2([u8; 32]),
}

/// ut_metadata fetch result (at most one Complete or Failed is reported
/// per connection).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataFetched {
    /// The assembled, identity-verified raw info dict bytes.
    Complete(Bytes),
    /// Fetch failed (reject / infohash mismatch / metadata_size out of
    /// domain / connection terminated).
    Failed(String),
}

/// Metadata fetch spec (driven inside PeerTask: ext handshake → piece
/// requests → assemble + verify → report). A full `tx` drops the
/// message (try_send; if the caller is gone the result is moot).
#[derive(Clone)]
pub struct MetadataFetchSpec {
    pub expected: ExpectedInfoHash,
    pub tx: mpsc::Sender<MetadataFetched>,
    pub shared: Option<crate::ut_metadata::SharedMetadataSpec>,
}

/// Metadata serving source: holds the complete raw info dict bytes
/// (upgraded engine / seeder; the serving face mirrors
/// `UTMetadataRequestExtensionMessage.cc`).
pub trait MetadataSource: Send + Sync {
    fn metadata(&self) -> &[u8];
}

/// [`MetadataSource`] adapter for `Bytes` (core engine side).
pub struct MetadataBytes(pub Bytes);

impl MetadataSource for MetadataBytes {
    fn metadata(&self) -> &[u8] {
        &self.0
    }
}

/// BEP-10 extension face configuration (consumed across the magnet
/// chain).
#[derive(Clone, Default)]
pub struct ExtConfig {
    /// Send our ext handshake right after the wire handshake (BEP-10;
    /// advertises `ut_metadata = OUTBOUND_UT_METADATA_ID`, attaches
    /// `metadata_size` when metadata is held — the same face as aria2
    /// `HandshakeExtensionMessage`).
    pub enabled: bool,
    /// Metadata serving source (None = every inbound request is
    /// rejected, `UTMetadataRequestExtensionMessage.cc`).
    pub metadata: Option<Arc<dyn MetadataSource>>,
    /// Metadata requester (magnet cold start; None = no ut_metadata
    /// fetch).
    pub fetch: Option<MetadataFetchSpec>,
    /// ut_pex advertise/consume gate: Some = advertise `ut_pex =
    /// OUTBOUND_UT_PEX_ID` in the ext handshake m dict, consume inbound
    /// ut_pex frames (discovered peers go up via [`PexExt::tx`]) and
    /// emit outbound on the [`crate::pex::PexSwarmSender`] cadence;
    /// None = no advertise, no consume (private torrent / peer exchange
    /// off — the `crate::pex::pex_offered` decision; aria2
    /// `apply_pex_negotiation` "registry removal" semantics:
    /// negotiation is ignored and inbound frames with that id are not
    /// parsed).
    pub pex: Option<PexExt>,
}

impl ExtConfig {
    /// Serving face (no requester).
    pub fn serve(metadata: Option<Arc<dyn MetadataSource>>) -> ExtConfig {
        ExtConfig {
            enabled: true,
            metadata,
            fetch: None,
            pex: None,
        }
    }

    /// Requester face (magnet metadata phase).
    pub fn fetch(spec: MetadataFetchSpec) -> ExtConfig {
        ExtConfig {
            enabled: true,
            metadata: None,
            fetch: Some(spec),
            pex: None,
        }
    }
}

impl std::fmt::Debug for ExtConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtConfig")
            .field("enabled", &self.enabled)
            .field(
                "metadata",
                &self.metadata.as_ref().map(|_| "MetadataSource"),
            )
            .field("fetch", &self.fetch.as_ref().map(|_| "MetadataFetchSpec"))
            .field("pex", &self.pex)
            .finish()
    }
}

/// Requester fetch session (created after the ext handshake completes
/// peer registration).
pub(super) struct MetadataFetchSession {
    /// Result reporting end (split from [`MetadataFetchSpec`]; the spec
    /// is consumed).
    tx: mpsc::Sender<MetadataFetched>,
    fetcher: Option<MetadataFetcher>,
    shared: Option<crate::ut_metadata::SharedMetadataPeer>,
    /// The peer's inbound ut_metadata msg id (from its m dict).
    peer_id: u8,
    terminal_reported: bool,
}

impl MetadataFetchSession {
    fn new(
        expected: ExpectedInfoHash,
        tx: mpsc::Sender<MetadataFetched>,
        peer_id: u8,
        metadata_size: Option<usize>,
        shared: Option<crate::ut_metadata::SharedMetadataSpec>,
        cuid: u64,
    ) -> Result<MetadataFetchSession, MetadataError> {
        let (fetcher, shared) = if let Some(spec) = shared {
            (
                None,
                Some(spec.coordinator.attach(cuid, spec.source, metadata_size)?),
            )
        } else {
            let size = metadata_size.unwrap_or(0);
            let fetcher = match expected {
                ExpectedInfoHash::V1(h) => MetadataFetcher::new(size, h)?,
                ExpectedInfoHash::V2(h) => MetadataFetcher::new_v2(size, h)?,
            };
            (Some(fetcher), None)
        };
        Ok(MetadataFetchSession {
            tx,
            fetcher,
            shared,
            peer_id,
            terminal_reported: false,
        })
    }

    pub(super) fn is_shared(&self) -> bool {
        self.shared.is_some()
    }
    pub(super) fn sweep(&mut self, now: Instant) {
        if let Some(fetcher) = &mut self.fetcher {
            fetcher.sweep_timeouts(now);
        }
    }
    fn on_data(
        &mut self,
        index: usize,
        total: usize,
        data: &[u8],
        now: Instant,
    ) -> Result<crate::ut_metadata::DataOutcome, crate::ut_metadata::FetchError> {
        if let Some(shared) = &mut self.shared {
            return shared.data(index, total, data, now);
        }
        let fetcher = self
            .fetcher
            .as_mut()
            .unwrap_or_else(|| unreachable!("requester driver"));
        if total != fetcher.metadata_size() {
            return Ok(crate::ut_metadata::DataOutcome::Untracked);
        }
        fetcher.on_data(index, data, now)
    }

    /// Send a bounded batch from either the shared coordinator or the legacy
    /// single-peer driver. One flush avoids per-request Nagle/ACK stalls.
    pub(super) async fn issue(
        &mut self,
        writer: &mut OutboundWriter<impl tokio::io::AsyncWrite + Unpin>,
        now: Instant,
    ) -> Result<(), crate::peer_wire::PeerWireError> {
        if self.terminal_reported {
            return Ok(());
        }
        let requests = if let Some(shared) = &mut self.shared {
            match shared.requests(now) {
                Ok(requests) => requests,
                Err(error) => {
                    self.terminal_reported = true;
                    let _ = self.tx.try_send(MetadataFetched::Failed(error.to_string()));
                    Vec::new()
                }
            }
        } else {
            self.fetcher
                .as_mut()
                .unwrap_or_else(|| unreachable!())
                .next_requests(now, 1)
        };
        if !requests.is_empty() {
            let messages = requests.into_iter().map(|index| Message::Extended {
                ext_id: self.peer_id,
                payload: Bytes::from(UtMetadata::Request { index }.encode().unwrap_or_default()),
            });
            writer.send_batch(messages).await?;
        }
        Ok(())
    }
}

/// Parameter pack for Extended frame handling (keeps the main match
/// body manageable).
pub(super) struct ExtendedCtx<'a, S: AsyncRead + AsyncWrite + Unpin> {
    pub(super) writer: &'a mut OutboundWriter<tokio::io::WriteHalf<S>>,
    pub(super) peer_ut_metadata_id: &'a mut Option<u8>,
    /// The peer's ut_pex advertised id (our outbound keys off it).
    pub(super) peer_ut_pex_id: &'a mut Option<u8>,
    pub(super) metadata_serve: Option<&'a Arc<dyn MetadataSource>>,
    pub(super) fetch_session: &'a mut Option<MetadataFetchSession>,
    pub(super) fetch_spec: &'a mut Option<MetadataFetchSpec>,
    pub(super) metadata_abort: &'a mut bool,
    /// ut_pex advertise/consume wiring (None = disabled).
    pub(super) pex_ext: Option<&'a PexExt>,
    /// Outbound cadence state machine (rebuilt by the handshake branch,
    /// keyed by the peer's advertised id).
    pub(super) pex_sender: &'a mut PexSwarmSender,
    /// This connection's cuid (echoed on PexEvent).
    pub(super) cuid: u64,
    /// ut_holepunch advertise/consume wiring (None = no advertise, no
    /// consume).
    pub(super) holepunch: Option<&'a super::HolepunchExt>,
    /// The peer's ut_holepunch advertised id (our outbound keys off it).
    pub(super) peer_ut_holepunch_id: &'a mut Option<u8>,
    /// Peer negotiation mirror write face (the handle's Arc; set by the
    /// handshake branch).
    pub(super) peer_supports_holepunch: &'a std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Rendezvous fixed-window origin (rate-limit state; see
    /// [`HOLEPUNCH_REQUEST_WINDOW`]).
    pub(super) hp_rv_window: &'a mut Instant,
    /// Rendezvous in-window count.
    pub(super) hp_rv_count: &'a mut u32,
    /// Connect fixed-window origin (see [`HOLEPUNCH_CONNECT_WINDOW`]).
    pub(super) hp_ct_window: &'a mut Instant,
    /// Connect in-window count.
    pub(super) hp_ct_count: &'a mut u32,
    /// Inbound ut_pex fixed-window origin (see [`PEX_MESSAGE_WINDOW`]).
    pub(super) pex_window: &'a mut Instant,
    /// Inbound ut_pex in-window count.
    pub(super) pex_count: &'a mut u32,
    /// Tiered inbound ut_pex decode session (the first frame of a
    /// connection is exempt, truncated at [`crate::pex::FIRST_PEX_MAX`];
    /// later frames are rejected whole above the 50 cap).
    pub(super) pex_inbound: &'a mut PexInboundSession,
    /// Client identity re-check callback (None = no re-check).
    pub(super) client_deny: Option<&'a super::ClientDenyCheck>,
    /// The re-check verdict payload (violation reason). Set by the ext
    /// handshake arm → the caller ends the connection as
    /// [`super::PeerError::ClientBanned`].
    pub(super) client_deny_hit: &'a mut Option<String>,
    /// Inbound BEP-21 upload_only mirror (None = not recorded — see
    /// [`super::PeerConfig::peer_upload_only`]).
    pub(super) peer_upload_only: Option<&'a std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

/// BEP-10 extended frame handling:
/// - `ext_id == 0`: ext handshake — register the ut_metadata id from
///   the peer's m dict (unknown extension names are not registered, per
///   ExtensionMessageRegistry name-table filtering); the requester
///   creates a fetch session when `metadata_size` is present (8MiB
///   acceptance domain, `HandshakeExtensionMessage.cc` — out of domain
///   means Failed, the same orchestration outcome as aria2 silently not
///   enabling metadata mode: this connection cannot fetch metadata).
///   `m_ut_pex` is registered too, and the outbound cadence state
///   machine is rebuilt from (peer advertised id, local gate) — the
///   aria2 `DefaultBtInteractive` interaction object is likewise
///   constructed after the handshake (`pexTimer_` starts then).
/// - ut_metadata frames (request/data/reject): the inbound id routes on
///   **our own advertised id** ([`OUTBOUND_UT_METADATA_ID`]) — BEP-10:
///   the m dict value is the id other peers should use when sending to
///   the advertiser; aria2's inbound demux likewise looks up the local
///   registry (`DefaultExtensionMessageFactory.cc`; local ids
///   initialized in `PeerInteractionCommand.cc`) while its outbound
///   uses the peer's advertisement
///   (`UTMetadataRequestExtensionMessage.cc`). Some peers (rqbit
///   advertises ut_metadata=3) still send data on our id=2, so routing
///   on the peer's advertisement alone would misfile them. Leniency: if
///   the peer violates BEP-10 and sends on **its own** advertised id,
///   we still route — aria2 raises and disconnects on unregistered ids
///   (`DefaultExtensionMessageFactory.cc`), we keep the existing
///   log-and-ignore interop face and only ignore when neither id
///   matches.
/// - ut_pex frames: the same routing (primary = our advertised id
///   [`OUTBOUND_UT_PEX_ID`], secondary = the peer's); **when the local
///   gate is off (private torrent / peer exchange disabled) neither
///   route consumes** — aria2 `apply_pex_negotiation` registry removal:
///   the inbound id no longer parses as ut_pex, so the frame is treated
///   as unknown.
/// - any other id: logged and ignored (BEP-10 interop).
pub(super) async fn handle_extended<S>(ext_id: u8, payload: &[u8], mut ctx: ExtendedCtx<'_, S>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if ext_id == 0 {
        let hs = match ExtHandshake::decode(payload) {
            Ok(hs) => hs,
            Err(e) => {
                debug!(target: "taiji::bt::peer", %e, "bad ext handshake (ignored)");
                return;
            }
        };
        // The second identity dimension: the peer_id was judged at
        // handshake time (engine attach face, `client_violation`); `v`
        // only becomes available now. A case-insensitive substring hit
        // sets the verdict payload — the caller ends the connection as
        // PeerEnd::Violation(ClientBanned) (the same enforcement surface
        // as the handshake-time verdict). Short-circuit on hit: no
        // negotiation registration, no fetch session.
        if let (Some(check), Some(v)) = (ctx.client_deny, hs.v.as_deref())
            && let Some(reason) = check(v)
        {
            debug!(target: "taiji::bt::peer", %v,
                    "ext handshake v matches client deny rule ");
            *ctx.client_deny_hit = Some(reason);
            return;
        }
        if let Some(id) = hs.m_ut_metadata {
            *ctx.peer_ut_metadata_id = Some(id);
        }
        if let Some(id) = hs.m_ut_pex {
            *ctx.peer_ut_pex_id = Some(id);
        }
        // Register the peer's ut_holepunch advertised id + set the
        // negotiation mirror (supports_holepunch = m_holepunch_id != 0,
        // the same rule as bt_peer_connection.cpp; the mirror feeds the
        // engine's lock-free relay/introducer eligibility check. An m
        // dict value of 0 = disabled was already filtered to None at
        // decode — is_some means non-zero, the same verdict as
        // libtorrent).
        if hs.m_ut_holepunch.is_some() {
            ctx.peer_supports_holepunch
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        if let Some(id) = hs.m_ut_holepunch {
            *ctx.peer_ut_holepunch_id = Some(id);
        }
        // BEP-21 upload_only inbound consumption: store the peer's
        // seeding announcement into the profile mirror — overwritten on
        // every ext handshake (missing key = false, following the
        // peer's state-transition resend; libtorrent
        // on_extended_handshake reads the dict per frame,
        // bt_peer_connection.cpp). The outbound half (SetUploadOnly
        // resend) already exists; this only records the inbound state.
        if let Some(mirror) = ctx.peer_upload_only {
            mirror.store(hs.upload_only, std::sync::atomic::Ordering::Relaxed);
        }
        // Outbound state machine rebuild: peer advertised id + local
        // gate (the timer starts at handshake arrival — the first
        // outbound window opens 60s later, the same start as aria2
        // pexTimer_). An m dict value of 0 = disabled was already
        // filtered to None — no sender is built (maybe_build stays None,
        // no Extended{0}).
        *ctx.pex_sender = PexSwarmSender::new(
            PexOffer::from_negotiation(ctx.pex_ext.is_some()),
            hs.m_ut_pex,
            Instant::now(),
        )
        .with_interval(
            ctx.pex_ext
                .as_ref()
                .map(|p| p.interval)
                .unwrap_or(crate::pex::DEFAULT_INTERVAL),
        );
        // Create the fetch session: the peer supports ut_metadata and
        // announced metadata_size (a value of 0 = disabled was filtered
        // to None → falls into the "unsupported" branch below and
        // reports Failed, no session).
        if let Some(session) = ctx.fetch_session.as_mut() {
            if let (Some(shared), Some(id), Some(size)) =
                (&mut session.shared, hs.m_ut_metadata, hs.metadata_size)
            {
                match shared.observe_size(size as usize) {
                    Ok(()) => {
                        session.peer_id = id;
                        let _ = session.issue(ctx.writer, Instant::now()).await;
                    }
                    Err(error) => {
                        let _ = session
                            .tx
                            .try_send(MetadataFetched::Failed(error.to_string()));
                        *ctx.metadata_abort = true;
                    }
                }
            }
        }
        if let Some(spec) = ctx.fetch_spec.take() {
            let session = match (hs.m_ut_metadata, hs.metadata_size) {
                (Some(pid), size) if size.is_some() || spec.shared.is_some() => {
                    MetadataFetchSession::new(
                        spec.expected,
                        spec.tx.clone(),
                        pid,
                        size.map(|size| size as usize),
                        spec.shared,
                        ctx.cuid,
                    )
                    .map_err(|e| e.to_string())
                }
                // The peer does not support ut_metadata / holds no
                // metadata: the fetch fails (the same aria2 outcome —
                // metadata mode not enabled; the orchestration layer
                // retries on another peer).
                _ => Err("peer advertises no ut_metadata/metadata_size".to_string()),
            };
            match session {
                Ok(mut s) => {
                    let now = Instant::now();
                    if let Err(e) = s.issue(ctx.writer, now).await {
                        debug!(target: "taiji::bt::peer", %e, "ut_metadata issue write failed");
                        return;
                    }
                    *ctx.fetch_session = Some(s);
                }
                Err(reason) => {
                    debug!(target: "taiji::bt::peer", %reason, "metadata fetch unavailable on this peer");
                    let _ = spec.tx.try_send(MetadataFetched::Failed(reason)).ok();
                    // Spec consumed: no retry on this connection (the
                    // caller switches peers).
                }
            }
        }
        return;
    }
    // Inbound routing: primary = our advertised id (BEP-10 semantics,
    // see the function docs); secondary = the peer's advertised id
    // (tolerance for peers sending on their own id; the divergence from
    // the reference is documented). Outbound still keys off the peer's
    // advertised id (session.issue's peer_id;
    // `UTMetadataRequestExtensionMessage.cc` same rule).
    if ext_id == OUTBOUND_UT_METADATA_ID || Some(ext_id) == *ctx.peer_ut_metadata_id {
        handle_ut_metadata(payload, &mut ctx).await;
        return;
    }
    // ut_pex inbound: the local gate comes first (private / off → not
    // consumed; same-id frames are ignored as unknown — the "registry
    // removal" semantics, DefaultBtInteractive.cc).
    if ctx.pex_ext.is_some()
        && (ext_id == OUTBOUND_UT_PEX_ID || Some(ext_id) == *ctx.peer_ut_pex_id)
    {
        handle_ut_pex(payload, &mut ctx).await;
        return;
    }
    // ut_holepunch inbound: the same gate shape (None = no advertise, no
    // consume).
    if ctx.holepunch.is_some()
        && (ext_id == OUTBOUND_UT_HOLEPUNCH_ID || Some(ext_id) == *ctx.peer_ut_holepunch_id)
    {
        handle_ut_holepunch(payload, &mut ctx).await;
        return;
    }
    debug!(target: "taiji::bt::peer", ext_id, len = payload.len(),
        "unknown extended message id (ignored, BEP10 interop)");
}

/// ut_pex frame handling (the consumption half): fixed-window rate
/// limit → tiered decode (the first frame of a connection is exempt and
/// truncated at [`crate::pex::FIRST_PEX_MAX`] — the BEP-11 first-frame
/// exemption; later frames keep the 50-cap whole-frame rejection) →
/// discovered peers are raised to the caller (the engine connection
/// manager; the caller-side projection of aria2
/// `UTPexExtensionMessage::doReceivedAction` — both fresh and dropped
/// lists go into the peer storage; both lists are passed through and
/// the dial decision lives in the engine). Malformed frames: ignored
/// (a broken peer implementation; the same lenient interop face as
/// ut_metadata, not escalated to a disconnect).
async fn handle_ut_pex<S>(payload: &[u8], ctx: &mut ExtendedCtx<'_, S>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(pex) = ctx.pex_ext else {
        return; // defense: already gated at routing; no tx = advertise only
    };
    // Fixed-window rate limit (the ut_holepunch shape), before decode —
    // over-limit frames pay no decode cost; over limit = ignore, no
    // disconnect (abuse guard, see [`PEX_MESSAGE_WINDOW`]).
    let now = Instant::now();
    if now.duration_since(*ctx.pex_window) >= PEX_MESSAGE_WINDOW {
        *ctx.pex_window = now;
        *ctx.pex_count = 0;
    }
    *ctx.pex_count += 1;
    if *ctx.pex_count > PEX_MESSAGE_LIMIT {
        debug!(target: "taiji::bt::peer", count = *ctx.pex_count,
            "ut_pex over per-connection rate limit (ignored, )");
        return;
    }
    match ctx.pex_inbound.decode(payload) {
        Ok(msg) => {
            let fresh: Vec<std::net::SocketAddr> =
                msg.fresh_peers().iter().map(|p| p.addr).collect();
            let dropped: Vec<std::net::SocketAddr> =
                msg.dropped_peers().iter().map(|p| p.addr).collect();
            debug!(target: "taiji::bt::peer",
                added = fresh.len(), dropped = dropped.len(),
                "ut_pex received -> peers to connection manager");
            let ev = PexEvent {
                from: ctx.cuid,
                capabilities: msg.fresh_peers().to_vec(),
                fresh,
                dropped,
            };
            // Low frequency (>= 60s per peer per frame); dropped on full
            // (the caller deduplicates rediscoveries, lossless).
            let _ = pex.tx.try_send(ev);
        }
        Err(e) => {
            debug!(target: "taiji::bt::peer", %e, "malformed ut_pex (ignored)");
        }
    }
}

/// ut_holepunch frame handling: decode → fixed-window rate limit
/// (separate rendezvous/connect windows) → the event is raised to the
/// caller (relay and dial-out need a swarm-wide view; PeerTask decides
/// nothing locally). Behavior authority and branch rules:
/// - malformed / unknown sub-op / unknown address family: ignored (each
///   libtorrent on_holepunch branch silently returns,
///   bt_peer_connection.cpp), no disconnect;
/// - rendezvous/connect: raised within the limit (over limit = ignore,
///   no disconnect — the local abuse guard; libtorrent has no
///   counterpart, see the constant docs);
/// - failed: logged only (libtorrent treats it as informational too).
async fn handle_ut_holepunch<S>(payload: &[u8], ctx: &mut ExtendedCtx<'_, S>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(hp) = ctx.holepunch else {
        return; // defense: already gated at routing
    };
    let msg = match UtHolepunch::decode(payload) {
        Ok(m) => m,
        Err(e) => {
            debug!(target: "taiji::bt::peer", %e, "malformed ut_holepunch (ignored)");
            return;
        }
    };
    // Fixed-window rate limit (the HASH_REQUEST_WINDOW shape): over
    // limit = ignore, no disconnect. failed frames are informational:
    // logged only, not rate-limited or counted (they answer a previous
    // request of ours; libtorrent only logs them too).
    let now = Instant::now();
    let rate_slot = match msg {
        UtHolepunch::Rendezvous { .. } => Some((
            &mut *ctx.hp_rv_window,
            &mut *ctx.hp_rv_count,
            HOLEPUNCH_REQUEST_LIMIT,
        )),
        UtHolepunch::Connect { .. } => Some((
            &mut *ctx.hp_ct_window,
            &mut *ctx.hp_ct_count,
            HOLEPUNCH_CONNECT_LIMIT,
        )),
        UtHolepunch::Failed { ep, error } => {
            debug!(target: "taiji::bt::peer", %ep, error = ?error,
                "ut_holepunch failed received (informational)");
            None
        }
    };
    let Some((window, count, limit)) = rate_slot else {
        return;
    };
    if now.duration_since(*window) >= HOLEPUNCH_REQUEST_WINDOW {
        *window = now;
        *count = 0;
    }
    *count += 1;
    if *count > limit {
        debug!(target: "taiji::bt::peer", count = *count, limit,
            "ut_holepunch rate limited: ignored (no disconnect)");
        return;
    }
    // Event handed over with await backpressure (bounded 16; a dead
    // peer or engine teardown → dropped, meaning this hole-punch chance
    // is forfeited — no protocol loss).
    let ev = super::HolepunchEvent {
        from: ctx.cuid,
        msg,
    };
    if hp.tx.send(ev).await.is_err() {
        debug!(target: "taiji::bt::peer", "holepunch event channel closed (dropped)");
    }
}

/// ut_metadata frame handling (requester + responder halves; the
/// reference source is noted per branch).
async fn handle_ut_metadata<S>(payload: &[u8], ctx: &mut ExtendedCtx<'_, S>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let msg = match UtMetadata::decode(payload) {
        Ok(m) => m,
        Err(e) => {
            // Malformed ut_metadata: a broken peer implementation;
            // ignored (not a bitfield-level flood surface, so not
            // escalated to a disconnect — aria2's factory layer throws
            // and disconnects; that tightening was not adopted, keep
            // ignore plus a sampled log).
            debug!(target: "taiji::bt::peer", %e, "malformed ut_metadata (ignored)");
            return;
        }
    };
    match msg {
        UtMetadata::Request { index } => {
            // Responder (UTMetadataRequestExtensionMessage.cc): no
            // metadata → reject; out-of-range index → disconnect.
            let answer = match ctx.metadata_serve {
                Some(src) => crate::ut_metadata::serve_request(src.metadata(), index),
                None => Ok(crate::ut_metadata::ServeOutcome::Reject { index }),
            };
            match answer {
                Ok(crate::ut_metadata::ServeOutcome::Data {
                    index,
                    total_size,
                    data,
                }) => {
                    let frame = UtMetadata::Data {
                        index,
                        total_size,
                        data,
                    };
                    match frame.encode() {
                        Ok(bytes) => {
                            let _ = ctx
                                .writer
                                .send(Message::Extended {
                                    ext_id: OUTBOUND_UT_METADATA_ID,
                                    payload: Bytes::from(bytes),
                                })
                                .await;
                        }
                        Err(e) => {
                            debug!(target: "taiji::bt::peer", %e, "ut_metadata data encode failed")
                        }
                    }
                }
                Ok(crate::ut_metadata::ServeOutcome::Reject { index }) => {
                    debug!(target: "taiji::bt::peer", index,
                        "ut_metadata request -> reject (no metadata)");
                    let frame = UtMetadata::Reject { index };
                    if let Ok(bytes) = frame.encode() {
                        let _ = ctx
                            .writer
                            .send(Message::Extended {
                                ext_id: OUTBOUND_UT_METADATA_ID,
                                payload: Bytes::from(bytes),
                            })
                            .await;
                    }
                }
                Err(e) => {
                    // ServeError::IndexTooBig → disconnect (the reference
                    // throws DL_ABORT_EX — an out-of-range request is a
                    // peer violation); via the abort flag we exit Clean
                    // (the connection ends; a peer-level error does not
                    // spread to the torrent).
                    debug!(target: "taiji::bt::peer", %e, "ut_metadata request out of range: disconnecting");
                    *ctx.metadata_abort = true;
                }
            }
        }
        UtMetadata::Data {
            index,
            total_size,
            data,
        } => {
            // Requester (UTMetadataDataExtensionMessage.cc): store the
            // piece; complete → assemble + verify the expected identity
            // → Complete; verification failure → reset all pieces +
            // Failed + disconnect. A total_size differing from the
            // session = the peer lied: the infohash check is the
            // backstop (a wrong size misaligns assembly → length
            // validation or hashing exposes it).
            let Some(session) = ctx.fetch_session.as_mut() else {
                debug!(target: "taiji::bt::peer", index,
                    "untracked ut_metadata data (no fetch session): ignored");
                return;
            };
            let now = Instant::now();
            match session.on_data(index, total_size, &data, now) {
                Ok(crate::ut_metadata::DataOutcome::Complete { metadata }) => {
                    debug!(target: "taiji::bt::peer", len = metadata.len(),
                        "ut_metadata complete: identity verified");
                    let _ = session
                        .tx
                        .try_send(MetadataFetched::Complete(metadata))
                        .ok();
                    // Fetch complete: session and spec end together (the
                    // connection is left to the upper layers).
                    *ctx.fetch_session = None;
                }
                Ok(_) => {
                    // Not complete yet: request the next piece
                    // immediately, refilling the requester's bounded window.
                    if let Err(e) = session.issue(ctx.writer, now).await {
                        debug!(target: "taiji::bt::peer", %e, "ut_metadata next request write failed");
                    }
                }
                Err(e) => {
                    // reject (FetchError::Rejected) or assembly /
                    // verification failure: Failed reported + disconnect
                    // (the aria2 abort semantics).
                    let reason = e.to_string();
                    debug!(target: "taiji::bt::peer", %reason, "ut_metadata fetch failed: disconnecting");
                    let _ = session.tx.try_send(MetadataFetched::Failed(reason)).ok();
                    *ctx.fetch_session = None;
                    *ctx.metadata_abort = true;
                }
            }
        }
        UtMetadata::Reject { index } => {
            // Requester (UTMetadataRejectExtensionMessage.cc): an
            // unconditional disconnect-level error ("peer didn't offer
            // metadata").
            let Some(session) = ctx.fetch_session.as_mut() else {
                debug!(target: "taiji::bt::peer", index, "untracked ut_metadata reject: ignored");
                return;
            };
            if let Some(shared) = &mut session.shared {
                shared.reject(index, Instant::now());
                debug!(target: "taiji::bt::peer", index, "metadata peer temporarily unavailable; requests reassigned");
                return;
            }
            let reason = "peer rejected metadata request (ut_metadata reject)".to_string();
            debug!(target: "taiji::bt::peer", index, %reason);
            let _ = session.tx.try_send(MetadataFetched::Failed(reason)).ok();
            *ctx.fetch_session = None;
            *ctx.metadata_abort = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc as StdArc;
    use std::time::Duration;

    use tokio::io::AsyncWriteExt as _;
    use tokio_util::sync::CancellationToken;

    use super::ExtHandshake;
    use crate::peer::{ClientDenyCheck, PeerConfig, PeerEnd, PeerError, PeerTask};
    use crate::peer_policy::IpGuard;
    use crate::peer_wire::Message;

    /// Regression (wire face): a peer whose peer_id prefix escapes the
    /// handshake-time check but whose ext handshake `v` self-reports a
    /// deny hit must end as `PeerEnd::Violation(ClientBanned)` (the
    /// engine's existing violation channel + same-IP block — one
    /// enforcement surface); no hit → the connection stays. The callback
    /// injects real matching semantics (IpGuard::client_blocks) and the
    /// engine-shaped reason wrapper (`client-ban:<hit>`).
    #[tokio::test]
    async fn ext_handshake_v_hit_ends_connection_as_client_ban() {
        let root = CancellationToken::new();
        // Rows: a v hit (case-insensitive substring) → disconnect; no
        // hit → keep.
        let rows = [("Xunlei 5.0.1.2", true), ("qBittorrent v4.2.5", false)];
        for (v, expect_ban) in rows {
            let guard = StdArc::new(IpGuard::new([], []).with_client_deny(["xunlei".to_string()]));
            let check: ClientDenyCheck = {
                let g = StdArc::clone(&guard);
                StdArc::new(move |s: &str| {
                    g.client_blocks(None, Some(s))
                        .map(|hit| format!("client-ban:{hit}"))
                })
            };
            let (local, mut remote) = tokio::io::duplex(64 * 1024);
            let config = PeerConfig {
                client_deny: Some(check),
                ..PeerConfig::flat()
            };
            let (_handle, join, _data) = PeerTask::spawn(&root, local, config);
            // Inject the peer's ext handshake (a clean peer_id escapes
            // the handshake-time prefix check; `v` is first available
            // here).
            let hs = ExtHandshake {
                v: Some(v.to_string()),
                ..ExtHandshake::default()
            };
            let payload = hs.encode().unwrap_or_else(|e| panic!("{e}"));
            let frame = Message::Extended { ext_id: 0, payload }.encode();
            remote
                .write_all(&frame)
                .await
                .unwrap_or_else(|e| panic!("{e}"));
            if expect_ban {
                let end = tokio::time::timeout(Duration::from_secs(2), join)
                    .await
                    .unwrap_or_else(|e| panic!("row {v}: timeout: {e}"))
                    .unwrap_or_else(|e| panic!("row {v}: join: {e}"));
                match end {
                    PeerEnd::Violation(PeerError::ClientBanned(reason)) => {
                        assert_eq!(reason, "client-ban:xunlei", "row {v}");
                    }
                    other => panic!("row {v}: expected ClientBanned, got {other:?}"),
                }
            } else {
                let alive = tokio::time::timeout(Duration::from_millis(300), join).await;
                assert!(alive.is_err(), "row {v}: clean v must keep the connection");
                root.cancel();
            }
        }
        root.cancel();
    }

    /// BEP-21 upload_only inbound consumption (wire face): a peer ext
    /// handshake with `upload_only = 1` stores the seeding marker in the
    /// profile mirror (BEP-21 "Setting the value of this key to 1
    /// indicates that this peer is not interested in downloading
    /// anything."); a resent handshake **without the key** follows back
    /// to false (libtorrent on_extended_handshake reads the dict per
    /// frame, bt_peer_connection.cpp; BEP-21 missing = false). The
    /// outbound half (SetUploadOnly resend) already exists; this test
    /// locks the inbound mirror following updates. Determinism: a
    /// frame-order sentinel (an out-of-set Piece → Violation end).
    #[tokio::test]
    async fn ext_handshake_upload_only_mirror_follows_updates() {
        for (handshakes, expect) in [
            (
                vec![ExtHandshake {
                    upload_only: true,
                    ..ExtHandshake::default()
                }],
                true,
            ),
            (
                vec![
                    ExtHandshake {
                        upload_only: true,
                        ..ExtHandshake::default()
                    },
                    // A resend without the upload_only key (BEP-21
                    // missing = false) → back to false.
                    ExtHandshake::default(),
                ],
                false,
            ),
        ] {
            let root = CancellationToken::new();
            let mirror = StdArc::new(std::sync::atomic::AtomicBool::new(false));
            let (local, mut remote) = tokio::io::duplex(64 * 1024);
            let config = PeerConfig {
                peer_upload_only: Some(StdArc::clone(&mirror)),
                ..PeerConfig::flat()
            };
            let (handle, join, _data) = PeerTask::spawn(&root, local, config);
            for hs in &handshakes {
                let payload = hs.encode().unwrap_or_else(|e| panic!("{e}"));
                let frame = Message::Extended { ext_id: 0, payload }.encode();
                remote
                    .write_all(&frame)
                    .await
                    .unwrap_or_else(|e| panic!("{e}"));
            }
            // Sentinel: an out-of-set Piece → Violation (join returning
            // proves the earlier handshakes were fully processed, no
            // polling race).
            let sentinel = Message::Piece {
                index: 9,
                begin: 0,
                block: bytes::Bytes::from_static(b"sentinel"),
            }
            .encode();
            remote
                .write_all(&sentinel)
                .await
                .unwrap_or_else(|e| panic!("{e}"));
            let end = tokio::time::timeout(Duration::from_secs(2), join)
                .await
                .unwrap_or_else(|e| panic!("timeout: {e:?}"))
                .unwrap_or_else(|e| panic!("join: {e}"));
            assert!(
                matches!(
                    end,
                    PeerEnd::Violation(PeerError::UnsolicitedPiece { index: 9, .. })
                ),
                "sentinel must disconnect via the unsolicited push (proves all frames were processed), got {end:?}"
            );
            assert_eq!(
                mirror.load(std::sync::atomic::Ordering::Relaxed),
                expect,
                "inbound upload_only profile must follow the peer's advertisement (rows: {} frames)",
                handshakes.len()
            );
            root.cancel();
            drop(handle);
        }
    }
}
