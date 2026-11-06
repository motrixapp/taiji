//! ut_pex peer exchange (BEP11).
//!
//! Protocol half only, no network IO (received peers are fed to the
//! engine's connection management by the caller — the same consumption path
//! as DHT `DhtEvent::PeersFound`):
//!
//! - [`message`]: ut_pex message codec (added/added.f/added6/added6.f/
//! dropped/dropped6 dict) and membership admission semantics (fresh/
//! dropped each <= 50 combined v4+v6, 1min freshness window);
//! - [`PexSwarmSender`]: per-connection outbound cadence (60s interval +
//! negotiation/private gates, mirroring aria2
//! `DefaultBtInteractive::addPeerExchangeMessage`);
//! - [`pex_offered`] / [`apply_pex_negotiation`]: negotiation surface
//! (private torrents disable PEX).
//!
//! The protocol-fact provenance table (aria2 anchors) and the
//! extended-message sequence walkthrough live in
//! `docs/design/peer-protocol.md`. Compact peer encoding reuses
//! [`crate::dht::compact`] (same constants as `BtConstants.h`).

use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::peer_wire::ExtRegistry;

pub mod message;

#[cfg(test)]
mod tests;

pub use message::{
    DEFAULT_INTERVAL, FIRST_PEX_MAX, MAX_DROPPED_PEER, MAX_FRESH_PEER, PexError, PexMessage,
};

/// Extension name (BEP11; `UTPexExtensionMessage.cc`).
pub const EXTENSION_NAME: &str = "ut_pex";

/// Wire-side peer entry: compact address + added.f flag bits (BEP11).
///
/// # added.f flag bits (BEP11 text, authoritative)
///
/// - bit0 `0x01`: **prefers encryption** ("as indicated by `e` field in
/// extension handshake" — the encryption-preference bit of
/// BEP10/MESSAGESRC);
/// - bit1 `0x02`: **seed / upload_only** (BEP11 wording; BEP21 names the
/// same semantics upload_only — seeding/partial-seeding state, not
/// interested in downloading);
/// - remaining bits reserved (BEP11: "Other bits are reserved for future
/// use"; not produced or read here).
///
/// Divergence from the reference (noted; the BEP text wins): aria2
/// `UTPexExtensionMessage.cc` produces only bit1 (seeder view) and its
/// decoder never reads added.f; this implementation produces both bits and
/// honors them on decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PexPeer {
    pub addr: std::net::SocketAddr,
    /// bit0 `0x01`: the peer prefers encryption (projection of the ext
    /// handshake `e` bit).
    pub encrypted: PrefersEncryption,
    /// bit1 `0x02`: seed / upload_only (BEP21 naming).
    pub upload_only: UploadOnly,
}

/// added.f bit0 `0x01` projection (BEP11; "prefers encryption" — the
/// encryption-preference bit of BEP10/MESSAGESRC, the `e` field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefersEncryption {
    /// bit0 clear: no encryption preference advertised.
    No,
    /// bit0 set: the peer prefers encryption.
    Yes,
}

impl PrefersEncryption {
    /// added.f byte -> bit0 projection (decode side; a short/missing flag
    /// byte arrives here already expanded to `0x00` = [`Self::No`]).
    pub fn from_flag(flags: u8) -> Self {
        if flags & 0x01 != 0 {
            PrefersEncryption::Yes
        } else {
            PrefersEncryption::No
        }
    }
}

/// added.f bit1 `0x02` projection (BEP11 wording "seed"; BEP21 names the
/// same semantics upload_only — seeding/partial-seeding state, not
/// interested in downloading).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadOnly {
    /// bit1 clear: a downloading (leeching) peer.
    No,
    /// bit1 set: seed / upload_only.
    Yes,
}

impl UploadOnly {
    /// added.f byte -> bit1 projection (decode side; a short/missing flag
    /// byte arrives here already expanded to `0x00` = [`Self::No`]).
    pub fn from_flag(flags: u8) -> Self {
        if flags & 0x02 != 0 {
            UploadOnly::Yes
        } else {
            UploadOnly::No
        }
    }
}

impl PexPeer {
    pub fn new(addr: std::net::SocketAddr, upload_only: UploadOnly) -> Self {
        PexPeer {
            addr,
            encrypted: PrefersEncryption::No,
            upload_only,
        }
    }

    /// All-flags constructor (decode path; the caller expands the added.f
    /// byte).
    pub fn with_flags(
        addr: std::net::SocketAddr,
        encrypted: PrefersEncryption,
        upload_only: UploadOnly,
    ) -> Self {
        PexPeer {
            addr,
            encrypted,
            upload_only,
        }
    }
}

/// Candidate entry at announce-build time — the PEX-view projection of
/// aria2's `Peer` object (the wire side only has [`PexPeer`]; admission
/// checks need session-side state).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PexCandidate {
    pub peer: PexPeer,
    /// Inbound connection (aria2 `isIncomingPeer`) — PEX only advertises
    /// outbound connections (`UTPexExtensionMessage.cc`).
    pub incoming: bool,
    /// Session-active (aria2 `isActive`; only fresh candidates are
    /// filtered, `DefaultBtInteractive.cc`).
    pub active: bool,
    /// First-contact instant (aria2 `firstContactTime_`; base of the fresh
    /// freshness window).
    pub first_contact: Instant,
    /// Instant the peer entered the drop state (aria2 `startDrop()`;
    /// None = not dropped; base of the dropped admission window).
    pub drop_started: Option<Instant>,
}

impl PexCandidate {
    pub fn fresh(peer: PexPeer, first_contact: Instant) -> Self {
        PexCandidate {
            peer,
            incoming: false,
            active: true,
            first_contact,
            drop_started: None,
        }
    }

    pub fn dropped(peer: PexPeer, drop_started: Instant) -> Self {
        PexCandidate {
            peer,
            incoming: false,
            active: false,
            first_contact: drop_started,
            drop_started: Some(drop_started),
        }
    }
}

/// Download mode of the assembling session (aria2 `metadataGetMode`):
/// the offer gate's first term.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetMode {
    /// Metadata-only download (the magnet/ut_metadata face): the privacy
    /// term of the gate is overridden (aria2 evaluates
    /// `metadataGetMode ||` before the private-torrent check).
    Metadata,
    /// Regular payload download: the privacy term reads the torrent
    /// context.
    Torrent,
}

/// Torrent privacy x user-option context: the remaining two terms of the
/// offer gate as named states (aria2 `privateTorrent` x
/// `--enable-peer-exchange`; a positional `(bool, bool)` pair is the
/// boolean trap this type replaces).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PexContext {
    /// Private torrent (BEP27): the privacy term fails, so PEX is only
    /// offered under the [`GetMode::Metadata`] override.
    Private,
    /// Public torrent with `--enable-peer-exchange` on: the option term
    /// passes.
    PublicEnabled,
    /// Public torrent with `--enable-peer-exchange` off: the option term
    /// fails whatever the mode.
    PublicDisabled,
}

/// Whether ut_pex is advertised with the ext handshake (the outbound PEX
/// master gate).
///
/// Mirrors aria2 `PeerInteractionCommand.cc`:
/// `(metadataGetMode || !privateTorrent) && --enable-peer-exchange`.
/// Private torrents disable PEX (BEP27); "a private torrent silently
/// leaking peers" is an explicitly forbidden failure mode of this module.
pub fn pex_offered(get_mode: GetMode, context: PexContext) -> bool {
    match context {
        // option term fails -> never offered (bit-identical to the
        // reference expression's `&& option_enabled` right term).
        PexContext::PublicDisabled => false,
        // privacy term cannot fail -> always offered.
        PexContext::PublicEnabled => true,
        // privacy term fails -> only the metadata-get-mode override
        // short-circuits it (the reference expression's first term).
        PexContext::Private => get_mode == GetMode::Metadata,
    }
}

/// Registry convergence after the ext handshake completes (aria2
/// `DefaultBtInteractive.cc`): ext messaging enabled but ut_pex not
/// enabled -> remove ut_pex from our registry.
/// Effect: our m dict does not advertise ut_pex, and the msg id of inbound
/// extended frames resolves to nothing in the registry (peer frames are
/// not consumed — "negotiated ignore").
pub fn apply_pex_negotiation(registry: &mut ExtRegistry, enabled: bool) {
    if !enabled {
        registry.remove(EXTENSION_NAME);
    }
}

/// Session-level ut_pex advertisement switch (the [`pex_offered`] result
/// at assembly; aria2 `utPexEnabled_`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PexOffer {
    /// The offer gate passed: outbound frames are built when due.
    On,
    /// The gate failed (private torrent / option off): frames are never
    /// built (`maybe_build` returns None).
    Off,
}

impl PexOffer {
    /// Negotiation-sourced conversion (the two sender build sites: the
    /// session-level gate already applied, the remaining fact is whether
    /// our ext handshake carries ut_pex).
    pub fn from_negotiation(negotiated: bool) -> Self {
        if negotiated {
            PexOffer::On
        } else {
            PexOffer::Off
        }
    }
}

/// Per-connection outbound PEX state machine (mirrors aria2
/// `DefaultBtInteractive`'s pexTimer_).
///
/// Responsibilities: 60s throttle, candidate filtering (active / exclude
/// our own address), capacity guards, and the negotiation/private double
/// gate. The produced [`PexMessage`] is sent by the caller with the
/// peer-negotiated msg id via `Message::Extended` (registry ids are
/// dynamically allocated, see `ExtRegistry`).
#[derive(Debug, Clone)]
pub struct PexSwarmSender {
    /// The ut_pex msg id the peer advertised in its ext handshake;
    /// None = not negotiated -> do not send (`DefaultBtInteractive.cc`
    /// `peer_->getExtensionMessageID(UT_PEX)`). An m dict value of 0 means
    /// the extension is disabled (BEP10: "Setting an extension number to
    /// zero means that the extension is not supported / disabled."); the
    /// decode source already filters that to None — this field never holds
    /// Some(0), so outbound never sends Extended{0}.
    peer_msg_id: Option<u8>,
    /// Session-level switch = the [`pex_offered`] result (`utPexEnabled_`).
    enabled: bool,
    /// Instant of the last build (aria2 `pexTimer_`; construction = now,
    /// first send one interval later).
    timer: Instant,
    interval: Duration,
    max_fresh: usize,
    max_dropped: usize,
}

impl PexSwarmSender {
    pub fn new(offer: PexOffer, peer_msg_id: Option<u8>, now: Instant) -> Self {
        PexSwarmSender {
            peer_msg_id,
            enabled: offer == PexOffer::On,
            timer: now,
            interval: message::DEFAULT_INTERVAL,
            max_fresh: MAX_FRESH_PEER,
            max_dropped: MAX_DROPPED_PEER,
        }
    }

    /// Capacity override (aria2 `setMaxFreshPeer`/`setMaxDroppedPeer`,
    /// `UTPexExtensionMessage.cc`; for test injection).
    pub fn with_limits(mut self, max_fresh: usize, max_dropped: usize) -> Self {
        self.max_fresh = max_fresh;
        self.max_dropped = max_dropped;
        self
    }

    /// Interval override (test injection; in aria2 this is the constant
    /// `DEFAULT_INTERVAL` with no option surface — production always uses
    /// the default. The injection exists so integration/benchmark harnesses
    /// can drive the same 60s state machine at realistic timescales; do not
    /// use it to relax the production cadence).
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Whether a full interval has passed since the last send
    /// (`DefaultBtInteractive.cc`).
    pub fn due(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.timer) >= self.interval
    }

    /// Build the outbound message when due; returns (peer-negotiated msg
    /// id, message).
    ///
    /// Mirrors `DefaultBtInteractive.cc`:
    /// - gates: not negotiated or not enabled -> None;
    /// - throttle: interval not yet full -> None;
    /// - fresh candidates: `isActive() && ip != peer ip &&
    /// !freshPeersAreFull()`, then addFreshPeer's incoming/freshness
    /// filter;
    /// - dropped candidates: `ip != peer ip && !droppedPeersAreFull()`;
    /// - empty-frame skip (explicit divergence from the reference): if
    /// added/added6/dropped/dropped6 all come out empty, no frame is
    /// built (returns None) — BEP11: "Messages must contain at least one
    /// of the following fields: added, added6, dropped, dropped6.", and
    /// an empty dict frame violates that MUST; aria2 enqueues an empty
    /// message unconditionally, the BEP text wins here. The timer still
    /// resets (the 60s cadence grid must not drift because of empty
    /// frames);
    /// - reset the timer.
    pub fn maybe_build(
        &mut self,
        fresh: &[PexCandidate],
        dropped: &[PexCandidate],
        peer_ip: Option<IpAddr>,
        now: Instant,
    ) -> Option<(u8, PexMessage)> {
        let msg_id = self.peer_msg_id?;
        if !self.enabled {
            return None;
        }
        if !self.due(now) {
            return None;
        }
        let mut msg = PexMessage::with_limits(self.max_fresh, self.max_dropped, self.interval);
        for cand in fresh {
            if msg.fresh_peers_are_full() {
                break;
            }
            if !cand.active {
                continue;
            }
            if peer_ip == Some(cand.peer.addr.ip()) {
                continue;
            }
            msg.add_fresh_peer(cand, now);
        }
        for cand in dropped {
            if msg.dropped_peers_are_full() {
                break;
            }
            if peer_ip == Some(cand.peer.addr.ip()) {
                continue;
            }
            msg.add_dropped_peer(cand, now);
        }
        self.timer = now;
        // BEP11: "Messages must contain at least one of the following
        // fields: added, added6, dropped, dropped6." — two empty lists
        // would encode as an empty dict, violating the MUST: skip this
        // frame (the timer is already reset, so the 60s cadence grid does
        // not drift). A non-empty result always encodes >= 1 key (every
        // entry belongs to v4 or v6), so the Some branch needs no extra
        // empty-frame filtering.
        if msg.fresh_peers().is_empty() && msg.dropped_peers().is_empty() {
            return None;
        }
        Some((msg_id, msg))
    }
}

/// Per-connection inbound PEX decode session (the BEP11 first-frame
/// exemption decision point).
///
/// BEP11 exempts the **first** ut_pex of each connection from the 50 cap
/// (see the [`message::FIRST_PEX_MAX`] note); the first-frame decision is
/// connection-level state and lives in this session (the inbound half,
/// symmetric to the [`PexSwarmSender`] outbound half).
///
/// - first frame -> [`PexMessage::decode_first`] (accepted, truncated to
/// [`FIRST_PEX_MAX`]);
/// - later frames -> [`PexMessage::decode`] (50 whole-frame rejection,
/// hardening kept).
///
/// The exemption is consumed once: the first ut_pex **reaching the
/// decoder** on a connection burns it regardless of decode success — a
/// malformed first frame consumes it too (hardening first: blocks the
/// "garbage frame probing + big frame free-riding the exemption"
/// combination; a malformed first frame carries no discovery value, and
/// later frames are incremental anyway, so they need no exemption).
#[derive(Debug, Clone)]
pub struct PexInboundSession {
    seen_first: bool,
}

impl PexInboundSession {
    pub fn new() -> Self {
        PexInboundSession { seen_first: false }
    }

    /// Tiered decode (first-frame exemption / later-frames cap); semantics
    /// in the type docs.
    pub fn decode(&mut self, payload: &[u8]) -> Result<PexMessage, PexError> {
        if self.seen_first {
            PexMessage::decode(payload)
        } else {
            self.seen_first = true;
            PexMessage::decode_first(payload)
        }
    }
}

impl Default for PexInboundSession {
    fn default() -> Self {
        PexInboundSession::new()
    }
}
