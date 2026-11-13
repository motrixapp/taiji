//! ut_pex message codec and membership admission semantics (BEP11).
//!
//! Encoding mirrors aria2 `UTPexExtensionMessage::getPayload` and
//! `createCompactPeerListAndFlag`; decoding mirrors `create`; admission
//! semantics mirror `addFreshPeer`/`addDroppedPeer` and the capacity
//! checks.
//!
//! # Alignment with / divergence from the reference
//!
//! - dict key order `added < added.f < added6 < added6.f < dropped <
//! dropped6` matches the reference output bytes (its Dict is an ordered
//!   map; see the `UTPexExtensionMessageTest.cc` vectors).
//! - Keys for empty lists are not written; flags appear only alongside
//!   their address string.
//! - Decode leniency (interop surface): a non-dict top level -> 0 peers,
//!   no error (the `if (dict)` guard); an address string whose length is
//!   not a multiple of the family unit size is skipped
//!   (`bittorrent_helper.h`); `added.f`/`added6.f` **are read per the
//!   BEP11 text** (bit0 encrypted / bit1 upload_only, paired per unit,
//!   missing/short treated as 0) — an explicit divergence from the
//!   reference's "never reads flags"; the BEP text wins. See
//!   [`PexMessage::decode`].
//! - Deliberate tightening: `encode` returns `Result` (the canonical
//!   encoder rejects out-of-order keys); the reference gets that
//!   implicitly from its C++ ordered map.

use std::time::{Duration, Instant};

use bytes::Bytes;
use thiserror::Error;

use crate::bencode::{self, Value};
use crate::dht::compact::{self, COMPACT_LEN_IPV4, COMPACT_LEN_IPV6};
use crate::pex::{PexCandidate, PexPeer, PrefersEncryption, UploadOnly};

/// Fresh-candidate hard cap (v4+v6 combined). aria2
/// `UTPexExtensionMessage.cc`.
pub const MAX_FRESH_PEER: usize = 50;
/// Dropped-candidate hard cap (v4+v6 combined). aria2
/// `UTPexExtensionMessage.cc`.
pub const MAX_DROPPED_PEER: usize = 50;
/// Tiered cap for the per-connection **first** inbound ut_pex (fresh or
/// dropped each, v4+v6 combined). BEP11 exempts the first message from the
/// 50 cap: "Except for the initial PEX message the combined amount of
/// added v4/v6 contacts should not exceed 50 entries. The same applies to
/// dropped entries." — and gives no replacement value; mainstream clients'
/// first PEX frame often carries >50 peers, and whole-frame rejection would
/// zero out cold-start discovery. The decode-cost hardening still needs a
/// bound (exemption != unbounded): 300 is the compromise (300 v4 units =
/// 1.8KB, v6 = 5.4KB, both within a single 64KiB extended frame, covering
/// mainstream first-frame bursts). Over the cap the **first N units are
/// accepted by truncation** rather than whole-frame rejection — rejecting
/// the frame loses the whole discovery set, truncation only loses the tail
/// (see [`PexMessage::decode_first`]).
pub const FIRST_PEX_MAX: usize = 300;
/// Send interval = freshness window. aria2 `UTPexExtensionMessage.h`
/// (`constexpr static auto DEFAULT_INTERVAL = 1_min`).
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(60);

/// bit1 `0x02`: seed / upload_only (BEP11 added.f bit1; aria2
/// `UTPexExtensionMessage.cc`'s seeder bit has the same value — BEP21
/// names that semantics upload_only).
pub const FLAG_SEEDER: u8 = 0x02;
/// bit0 `0x01`: prefers encryption (BEP11 added.f bit0, "as indicated by
/// `e` field in extension handshake").
pub const FLAG_ENCRYPTED: u8 = 0x01;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum PexError {
    #[error(
        "ut_pex payload too small: must be at least 1 byte (reference len<1 rejection, UTPexExtensionMessage.cc)"
    )]
    TooSmall,
    #[error("ut_pex bencode: {0}")]
    Bencode(#[from] bencode::BencodeError),
    /// Inbound list over cap: the `added`/`added6` combined total or the
    /// `dropped`/`dropped6` combined total exceeds the outbound-side cap
    /// ([`MAX_FRESH_PEER`]/[`MAX_DROPPED_PEER`]) -> whole frame rejected.
    /// Those constants previously constrained only our outbound side (the
    /// full guards on add_fresh_peer/add_dropped_peer callers); with
    /// uncapped inbound, a single 64KiB extended frame decoded ~10.9k v4
    /// addresses (6B/unit), and the engine consumer's per-address
    /// full-table scan amplified CPU.
    #[error("ut_pex {list} over inbound cap: {count} > {cap} (, frame rejected)")]
    TooManyPeers {
        list: &'static str,
        count: usize,
        cap: usize,
    },
}

/// One ut_pex message: the fresh/dropped lists + capacity/window
/// parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PexMessage {
    fresh: Vec<PexPeer>,
    dropped: Vec<PexPeer>,
    max_fresh: usize,
    max_dropped: usize,
    interval: Duration,
}

impl PexMessage {
    /// Default capacities 50/50, window 1min.
    pub fn new() -> Self {
        PexMessage {
            fresh: Vec::new(),
            dropped: Vec::new(),
            max_fresh: MAX_FRESH_PEER,
            max_dropped: MAX_DROPPED_PEER,
            interval: DEFAULT_INTERVAL,
        }
    }

    pub fn with_limits(max_fresh: usize, max_dropped: usize, interval: Duration) -> Self {
        PexMessage {
            fresh: Vec::new(),
            dropped: Vec::new(),
            max_fresh,
            max_dropped,
            interval,
        }
    }

    pub fn fresh_peers(&self) -> &[PexPeer] {
        &self.fresh
    }

    pub fn dropped_peers(&self) -> &[PexPeer] {
        &self.dropped
    }

    pub fn max_fresh(&self) -> usize {
        self.max_fresh
    }

    pub fn max_dropped(&self) -> usize {
        self.max_dropped
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// Fresh admission (reference `addFreshPeer`): only outbound
    /// connections whose first contact is less than interval ago. Capacity
    /// is not checked here — the reference guards it on the caller side via
    /// `freshPeersAreFull()`; kept consistent.
    /// Returns whether the peer was included.
    pub fn add_fresh_peer(&mut self, cand: &PexCandidate, now: Instant) -> bool {
        if cand.incoming {
            return false;
        }
        if now.saturating_duration_since(cand.first_contact) < self.interval {
            self.fresh.push(cand.peer.clone());
            true
        } else {
            false
        }
    }

    /// `freshPeersAreFull`.
    pub fn fresh_peers_are_full(&self) -> bool {
        self.fresh.len() >= self.max_fresh
    }

    /// Dropped admission (reference `addDroppedPeer`): only outbound
    /// connections whose drop started less than interval ago; not dropped
    /// (`drop_started == None`) is not included (the reference's null-Timer
    /// difference check fails).
    pub fn add_dropped_peer(&mut self, cand: &PexCandidate, now: Instant) -> bool {
        if cand.incoming {
            return false;
        }
        match cand.drop_started {
            Some(t) if now.saturating_duration_since(t) < self.interval => {
                self.dropped.push(cand.peer.clone());
                true
            }
            _ => false,
        }
    }

    /// `droppedPeersAreFull`.
    pub fn dropped_peers_are_full(&self) -> bool {
        self.dropped.len() >= self.max_dropped
    }

    /// Encode the dict payload (no BEP10 ext msg id byte — this codebase's
    /// `Message::Extended` keeps ext_id separate). Mirrors the reference
    /// `getPayload`.
    pub fn encode(&self) -> Result<Vec<u8>, PexError> {
        let mut dict: Vec<(Vec<u8>, Value)> = Vec::new();
        let (added, added_f) = pack_peers_with_flags(&self.fresh);
        let (added6, added6_f) = pack_peers_with_flags_v6(&self.fresh);
        let dropped = pack_peers(&self.dropped);
        let dropped6 = pack_peers_v6(&self.dropped);
        // Key order = ascending bytes (added < added.f < added6 < added6.f <
        // dropped < dropped6), consistent with the canonical-encoder
        // constraint; keys for empty lists are not written.
        if !added.is_empty() {
            dict.push((b"added".to_vec(), Value::Bytes(added)));
            dict.push((b"added.f".to_vec(), Value::Bytes(added_f)));
        }
        if !added6.is_empty() {
            dict.push((b"added6".to_vec(), Value::Bytes(added6)));
            dict.push((b"added6.f".to_vec(), Value::Bytes(added6_f)));
        }
        if !dropped.is_empty() {
            dict.push((b"dropped".to_vec(), Value::Bytes(dropped)));
        }
        if !dropped6.is_empty() {
            dict.push((b"dropped6".to_vec(), Value::Bytes(dropped6)));
        }
        Ok(bencode::encode(&Value::Dict(dict))?)
    }

    /// Decode the dict payload (no ext msg id byte). Mirrors the reference
    /// `create`: an empty payload -> error; broken bencode -> error; a
    /// non-dict top level -> an empty message with 0 peers (the reference
    /// `if (dict)` semantics).
    ///
    /// Inbound cap tiers: this entry point is the **later-frames** path —
    /// fresh/dropped are each checked against
    /// [`MAX_FRESH_PEER`]/[`MAX_DROPPED_PEER`] (v4+v6 combined) and the
    /// whole frame is rejected when over (hardening kept); the
    /// **per-connection first** message goes through
    /// [`PexMessage::decode_first`] (BEP11 first-message exemption +
    /// truncate-and-accept); the first-frame decision point is
    /// [`crate::pex::PexInboundSession`].
    ///
    /// # added.f / added6.f (honored on inbound — explicit divergence from
    /// the reference)
    ///
    /// aria2's decoder never reads the flags (`UTPexExtensionMessage.cc`
    /// has no read path); this reader follows the BEP11 text: the flags
    /// string is paired with the address string unit by unit (bit0
    /// encrypted / bit1 upload_only). Leniency (interop first): flags
    /// missing -> all 0; a length mismatch with the address unit count ->
    /// pair on the **shorter** length, the remainder ignored (BEP11 flags
    /// are optional hints; missing/truncated flags are not a local error).
    pub fn decode(payload: &[u8]) -> Result<Self, PexError> {
        Self::decode_capped(payload, MAX_FRESH_PEER, MAX_DROPPED_PEER, false)
    }

    /// Decode entry for a connection's first ut_pex (BEP11 first-message
    /// exemption): fresh/dropped each **accept the first N units by
    /// truncation** at [`FIRST_PEX_MAX`] (v4+v6 combined). Trade-off:
    /// rejecting the whole frame would zero the peer's initial full set
    /// (cold-start discovery lost), while truncation only drops the tail
    /// and preserves order (dict order: added before added6, unit order
    /// within a family kept) — interop first; the decode-cost bound is
    /// maintained by [`FIRST_PEX_MAX`] (exemption != unbounded).
    pub fn decode_first(payload: &[u8]) -> Result<Self, PexError> {
        Self::decode_capped(payload, FIRST_PEX_MAX, FIRST_PEX_MAX, true)
    }

    /// Tiered decode core: `truncate = false` rejects the whole frame when
    /// over cap (the engine consumer settles naturally: decode Err -> the
    /// caller ignores the malformed frame); `truncate = true` accepts the
    /// units within the remaining budget (first-frame exemption path, see
    /// `decode_first`).
    fn decode_capped(
        payload: &[u8],
        fresh_cap: usize,
        dropped_cap: usize,
        truncate: bool,
    ) -> Result<Self, PexError> {
        if payload.is_empty() {
            return Err(PexError::TooSmall);
        }
        let value = bencode::decode_permissive(payload)?;
        let mut msg = PexMessage::new();
        let Value::Dict(dict) = &value else {
            // The reference's downcast failure silently returns an empty
            // message.
            return Ok(msg);
        };
        // Fetch the flags strings first (flags and addresses live under
        // different keys; paired by family at decode).
        let mut added_f: Option<&[u8]> = None;
        let mut added6_f: Option<&[u8]> = None;
        for (key, val) in dict {
            match (key.as_slice(), val) {
                (b"added.f", Value::Bytes(b)) => added_f = Some(b),
                (b"added6.f", Value::Bytes(b)) => added6_f = Some(b),
                _ => {}
            }
        }
        for (key, val) in dict {
            let Value::Bytes(blob) = val else {
                continue; // non-String values ignored (the reference's downcast<String> failure skips)
            };
            let (list, family_v4, (cap, list_name)) = match key.as_slice() {
                b"added" => (&mut msg.fresh, true, (fresh_cap, "added")),
                b"dropped" => (&mut msg.dropped, true, (dropped_cap, "dropped")),
                b"added6" => (&mut msg.fresh, false, (fresh_cap, "added")),
                b"dropped6" => (&mut msg.dropped, false, (dropped_cap, "dropped")),
                // added.f/added6.f already prefetched; unknown keys ignored
                // (BEP11 interop).
                _ => continue,
            };
            let flags = if family_v4 { added_f } else { added6_f };
            let unit = if family_v4 {
                COMPACT_LEN_IPV4
            } else {
                COMPACT_LEN_IPV6
            };
            // Length not a multiple of the unit size -> skip the whole
            // string (bittorrent_helper.h).
            if blob.len() % unit != 0 {
                continue;
            }
            // Inbound cap (fresh/dropped each by v4+v6 combined, matching
            // the constant docs): unpacking fixed-length units always
            // succeeds, so the string's unit count is the decoded address
            // count; the cap is checked before accumulation, so cross-key
            // (added+added6) totals are also bounded.
            let units = blob.len() / unit;
            let take = if truncate {
                // First-frame exemption: accept the units within the
                // remaining budget (rejecting the frame loses discovery;
                // truncation only loses the tail).
                cap.saturating_sub(list.len()).min(units)
            } else {
                // Over cap: whole-frame rejection.
                if list.len() + units > cap {
                    return Err(PexError::TooManyPeers {
                        list: list_name,
                        count: list.len() + units,
                        cap,
                    });
                }
                units
            };
            for (n, chunk) in blob.chunks_exact(unit).take(take).enumerate() {
                // Each unit is family-fixed-length, so compact::unpack_peer's
                // auto length detection degenerates to an always-true branch
                // (v4=6B / v6=18B are unambiguous).
                let Ok(addr) = compact::unpack_peer(chunk) else {
                    continue; // unpackcompact failure -> skip the unit
                };
                // Flags paired per unit; out of range (short/missing) = 0
                // (leniency, see above).
                let flag = flags.and_then(|f| f.get(n).copied()).unwrap_or(0x00);
                list.push(
                    PexPeer::with_flags(
                        addr,
                        PrefersEncryption::from_flag(flag),
                        UploadOnly::from_flag(flag),
                    )
                    .with_transport_flags(flag),
                );
            }
        }
        Ok(msg)
    }
}

impl Default for PexMessage {
    fn default() -> Self {
        PexMessage::new()
    }
}

fn flag_of(p: &PexPeer) -> u8 {
    (if p.encrypted == PrefersEncryption::Yes {
        FLAG_ENCRYPTED
    } else {
        0x00
    }) | (if p.upload_only == UploadOnly::Yes {
        FLAG_SEEDER
    } else {
        0x00
    }) | if p.supports_utp { 0x04 } else { 0 }
        | if p.supports_holepunch { 0x08 } else { 0 }
}

fn pack_peers_with_flags(peers: &[PexPeer]) -> (Vec<u8>, Vec<u8>) {
    let mut addrs = Vec::new();
    let mut flags = Vec::new();
    for p in peers {
        if p.addr.is_ipv4() {
            compact::pack_peer(p.addr, &mut addrs);
            // Flags are produced in the same loop, unit by unit with the
            // addresses — the added.f unit count always equals that
            // family's address unit count (same shape as the reference
            // createCompactPeerListAndFlag).
            flags.push(flag_of(p));
        }
    }
    (addrs, flags)
}

fn pack_peers(peers: &[PexPeer]) -> Vec<u8> {
    let mut addrs = Vec::new();
    for p in peers {
        if p.addr.is_ipv4() {
            compact::pack_peer(p.addr, &mut addrs);
        }
    }
    addrs
}

fn pack_peers_with_flags_v6(peers: &[PexPeer]) -> (Vec<u8>, Vec<u8>) {
    let mut addrs = Vec::new();
    let mut flags = Vec::new();
    for p in peers {
        if p.addr.is_ipv6() {
            compact::pack_peer(p.addr, &mut addrs);
            flags.push(flag_of(p));
        }
    }
    (addrs, flags)
}

fn pack_peers_v6(peers: &[PexPeer]) -> Vec<u8> {
    let mut addrs = Vec::new();
    for p in peers {
        if p.addr.is_ipv6() {
            compact::pack_peer(p.addr, &mut addrs);
        }
    }
    addrs
}

/// Convenience wrapper encoding the full extended-frame payload (`ext_id` +
/// dict) for callers building `Message::Extended` directly. ext_id is the
/// **peer's** negotiated ut_pex msg id (aria2 outbound uses
/// `peer_->getExtensionMessageID(UT_PEX)`).
pub fn encode_frame(ext_id: u8, msg: &PexMessage) -> Result<Bytes, PexError> {
    let mut out = Vec::with_capacity(1 + 64);
    out.push(ext_id);
    out.extend_from_slice(&msg.encode()?);
    Ok(Bytes::from(out))
}
