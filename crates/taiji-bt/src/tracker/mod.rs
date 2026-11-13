//! Tracker client family (BEP3 tracker section, BEP12 tiers, BEP15 UDP,
//! BEP23 compact peers, BEP7 peers6, BEP48 scrape).
//!
//! Submodules: [`announce_list`] tier state machine (BEP12); [`http`]
//! HTTP/HTTPS announce (reqwest rustls + gzip) and response parsing;
//! [`dns`] resolver-seam re-export (implementation lives in the shared
//! `taiji_io::dns` layer: host -> (host, family) -> IpAddr cache, A/AAAA
//! per-family resolution, resolve timeout decorator); [`udp`] UDP tracker
//! (BEP15 connect -> announce -> scrape with retransmission; v4/v6 carriers
//! have equal standing, 6/18 bytes per peer by carrier family); [`scrape`]
//! HTTP scrape (BEP48) with a seeds/leechers cache; [`actor`] TrackerActor
//! command/event surface; `lsd` (crate root) BEP14 local service discovery.
//!
//! Compatibility surface: `AnnounceRequest`, `build_announce_url`,
//! `announce`, `TrackerEvent`, `DEFAULT_NUMWANT` and friends are the
//! existing public surface (the taiji-core engine calls them) and keep
//! their shape; the full parameter surface is [`http::HttpAnnounce`].
//!
//! Upstream anchor mapping: docs/design/tracker.md

pub mod actor;
pub mod announce_list;
pub mod dns;
pub mod http;
pub mod scrape;
pub mod trackerslist;
pub mod udp;

pub use announce_list::{AnnounceList, AnnounceTier, TierEvent};
pub use http::{
    AnnounceRequest, AnnounceResponse, HttpAnnounce, PeerAddr6, TrackerOptions, announce,
    announce_http, build_announce_url, parse_announce_response, parse_http_url,
};
pub use scrape::{ScrapeCache, ScrapeStats};
pub use trackerslist::{
    TRACKERSLIST_MAX_BYTES, TrackerslistError, parse_trackerslist, read_trackerslist,
};

use std::net::Ipv4Addr;

use thiserror::Error;

/// peer_id length (BEP3).
pub const PEER_ID_LEN: usize = 20;
/// taiji peer_id prefix (BEP20 Azureus style: '-TJ' + 4-digit version + '-').
///
/// This value is also the effective prefix when `--peer-id-prefix` is unset
/// (the default source of the session option `GlobalOptions::peer_id_prefix`
/// — default behavior unchanged).
pub const PEER_ID_PREFIX: &str = "-TJ0001-";
/// Default `numwant` (when peers remain to fetch; aria2
/// `DefaultBtAnnounce.cc`).
pub const DEFAULT_NUMWANT: u32 = 50;
/// Local identity string: the HTTP announce `User-Agent` and the BEP10
/// ext-handshake `v` carry the same string.
///
/// Authoritative order: libtorrent's ext-handshake `v` defaults to
/// `user_agent` (`bt_peer_connection.cpp`), and `user_agent` defaults to
/// `"libtorrent/" LIBTORRENT_VERSION` (`settings_pack.cpp`) — i.e. the same
/// "product/version" string serves as both UA and `v`. This side is
/// isomorphic: `taiji/<CARGO_PKG_VERSION>` (single-sourced from the
/// workspace version, the same version source as the RPC `getVersion`
/// `taiji/<semver>` via `taiji-core::version_string`, replacing the old
/// hardcoded fake version `taiji/0.1`).
///
/// Configuration surfaces stay separate: the UA/`v` string does not follow
/// `--peer-id-prefix`, and no user option for it is offered here — private
/// tracker sites check UA and peer id independently against whitelists, so
/// binding them to one value would let a single misconfiguration pollute
/// both. aria2 likewise has two independent options (`--peer-id-prefix`,
/// `OptionHandlerFactory.cc`; `--peer-agent`).
pub const PEER_AGENT: &str = concat!("taiji/", env!("CARGO_PKG_VERSION"));

/// Generate a peer_id: prefix + random fill up to 20 bytes (single
/// generation point — the one byte source shared verbatim by tracker
/// announce and peer handshake).
///
/// Semantics match aria2 (`bittorrent_helper.cc` + help text
/// `usage_text.h`): a prefix longer than 20 bytes is truncated to the first
/// 20 bytes, never rejected (`peerId.erase(20)`); a shorter prefix is
/// padded with random bytes; exactly 20 bytes leaves no random segment.
/// libtorrent agrees (`generate_peer_id.cpp`: overlong `resize(20)`, short
/// padded via `url_random`). Prefix bytes are not charset-checked (aria2's
/// DefaultOptionHandler does no charset validation; bytes enter the peer_id
/// verbatim).
pub fn generate_peer_id(prefix: &[u8], rand: impl FnMut() -> u8) -> [u8; PEER_ID_LEN] {
    let mut id = [0u8; PEER_ID_LEN];
    let prefix_len = prefix.len().min(PEER_ID_LEN);
    id[..prefix_len].copy_from_slice(&prefix[..prefix_len]);
    let mut rand = rand;
    for b in &mut id[prefix_len..] {
        *b = rand();
    }
    id
}

/// Percent-encode: keep unreserved characters (alnum and `-_.~`), encode
/// everything else as %XX (matches aria2 `util::percentEncode`; required
/// for info_hash/peer_id in the query string).
pub fn percent_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for &b in bytes {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// One peer address returned by a tracker (compact form, BEP23, IPv4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerAddr {
    pub ip: Ipv4Addr,
    pub port: u16,
}

/// Tracker error. The original variants keep their shape; transport-surface
/// variants were added.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TrackerError {
    #[error("tracker failure reason: {0}")]
    Failed(String),
    #[error("malformed announce response: {0}")]
    Malformed(String),
    #[error("tracker transport error: {0}")]
    Network(String),
    /// Unsupported URL scheme / invalid URL (aria2 `uri.cc`: a scheme with
    /// no default port, including udp per `FeatureConfig.cc`, is invalid
    /// when the port is missing).
    #[error("invalid tracker url: {0}")]
    InvalidUrl(String),
}

impl TrackerError {
    /// Failure classification (observability surface; protocol semantics
    /// unchanged — a read-only derivation giving logs / last_error a
    /// machine-checkable class).
    ///
    /// The class of the `Network` variant is decided by the prefix tag
    /// written by the [`super::http`] transport layer
    /// ("dns:"/"connect-tls:"/"connect:"/"timeout:"/"request:"); a missing
    /// prefix (legacy strings / other Network sources) maps to "network".
    pub fn class(&self) -> &'static str {
        match self {
            TrackerError::Failed(_) => "tracker-reason",
            TrackerError::Malformed(m) if m.starts_with("http-status:") => "http-status",
            // Response-body transfer cap on the receive path (`get_body_capped`
            // truncation / Content-Length precheck) — a distinct failure class,
            // kept in the classification log surface.
            TrackerError::Malformed(m) if m.starts_with("max-size:") => "max-size",
            TrackerError::Malformed(_) => "malformed",
            TrackerError::InvalidUrl(_) => "invalid-url",
            TrackerError::Network(m) => {
                for (prefix, class) in [
                    ("dns:", "dns"),
                    ("connect-tls:", "connect-tls"),
                    ("connect:", "connect"),
                    ("timeout:", "timeout"),
                    ("request:", "request"),
                ] {
                    if m.starts_with(prefix) {
                        return class;
                    }
                }
                "network"
            }
        }
    }

    /// Reason string (the inner message, without the thiserror Display
    /// prefix wrapper; used for the log `reason` field — the class is
    /// reported separately, so repeating the prefix adds nothing).
    pub fn reason(&self) -> String {
        match self {
            TrackerError::Failed(m)
            | TrackerError::Malformed(m)
            | TrackerError::Network(m)
            | TrackerError::InvalidUrl(m) => m.clone(),
        }
    }
}

/// Announce event (BEP3; empty = periodic).
///
/// Note: this is the value enum for the URL `event` parameter; the tier
/// state machine's seven states live in [`announce_list::TierEvent`]
/// (BEP12 / aria2 AnnounceTier).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackerEvent {
    Started,
    Completed,
    Stopped,
    Periodic,
}

impl TrackerEvent {
    pub fn as_str(self) -> &'static str {
        match self {
            TrackerEvent::Started => "started",
            TrackerEvent::Completed => "completed",
            TrackerEvent::Stopped => "stopped",
            TrackerEvent::Periodic => "",
        }
    }
}

// The single source for URL log redaction / the verbatim switch moved up to
// `taiji_io::redact` (cross-protocol: the HTTP download surface shares the
// same switch). Consumers here (tracker announce + engine webseed) use it
// via this re-export, so call sites are unchanged. Policy and decision-table
// tests live in that module.
pub use taiji_io::redact::{redact_url_for_log, set_url_log_verbatim};

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-for-byte regression of the default: with no custom prefix
    /// (= [`PEER_ID_PREFIX`]) the peer_id matches existing behavior byte
    /// for byte — prefix `-TJ0001-` + random fill to 20B (same shape as
    /// bittorrent_helper.cc).
    #[test]
    fn peer_id_default_prefix_byte_regression() {
        let id = generate_peer_id(PEER_ID_PREFIX.as_bytes(), || 0xAB);
        assert_eq!(&id[..PEER_ID_PREFIX.len()], PEER_ID_PREFIX.as_bytes());
        assert!(id[PEER_ID_PREFIX.len()..].iter().all(|&b| b == 0xAB));
        assert_eq!(id.len(), 20);
        // Constant shape: BEP20 Azureus style `-'XX'` + 4-digit version + `-`.
        assert!(PEER_ID_PREFIX.starts_with("-TJ") && PEER_ID_PREFIX.ends_with('-'));
        assert_eq!(PEER_ID_PREFIX.len(), 8);
    }

    /// Custom prefix: the generation point honors any prefix passed in
    /// (announce and handshake consume the same prefix through the same
    /// generation point — the structural basis of one source, one value).
    #[test]
    fn peer_id_custom_prefix() {
        let id = generate_peer_id(b"-qB4550-", || 0x11);
        assert_eq!(&id[..8], b"-qB4550-");
        assert!(id[8..].iter().all(|&b| b == 0x11));
        assert_eq!(id.len(), 20);
    }

    /// Overlong prefix is truncated, not rejected (aria2 semantics:
    /// `bittorrent_helper.cc erase(20)`; help text `usage_text.h`:
    /// "only first 20 bytes are used"): a 25B prefix yields the first 20B
    /// with an empty random segment (the identity holds because rand is
    /// never called).
    #[test]
    fn peer_id_overlong_prefix_truncated_not_rejected() {
        let long = [b'x'; 25];
        let id = generate_peer_id(&long, || panic!("no random bytes must be drawn"));
        assert_eq!(id.as_slice(), &long[..20]);
    }

    /// Exactly 20B prefix = no random segment; empty prefix = 20B fully
    /// random (the two endpoints of aria2's `len = 20 - prefix.size()`).
    #[test]
    fn peer_id_exact_20_and_empty_prefix_endpoints() {
        let full = [b'y'; 20];
        let id = generate_peer_id(&full, || panic!("20B prefix leaves no room for random"));
        assert_eq!(id.as_slice(), &full);
        let empty = generate_peer_id(b"", || 0x5A);
        assert!(empty.iter().all(|&b| b == 0x5A));
    }

    /// UA/ext-v identity string has the `taiji/<semver>` shape (same source
    /// as the workspace `CARGO_PKG_VERSION`; replaces the old hardcoded
    /// `taiji/0.1`).
    #[test]
    fn peer_agent_is_taiji_slash_workspace_semver() {
        assert_eq!(
            PEER_AGENT,
            concat!("taiji/", env!("CARGO_PKG_VERSION")),
            "UA/ext-v string must derive from the workspace version"
        );
        // Cargo validates the full SemVer, including prerelease/build suffixes.
        let version = PEER_AGENT.strip_prefix("taiji/").unwrap_or_default();
        let v = version.split(['-', '+']).next().unwrap_or_default();
        assert!(
            !v.is_empty()
                && v.split('.').count() == 3
                && v.chars().all(|c| c.is_ascii_digit() || c == '.'),
            "semver shape expected, got {v}"
        );
    }

    /// Identification-table compatibility: the `-TJ0001-` prefix must not
    /// be misidentified with zero changes to the client_id table (own
    /// identity maps to Unknown; identification surface is not the identity
    /// generation surface).
    #[test]
    fn own_peer_id_prefix_not_misidentified() {
        let id = generate_peer_id(PEER_ID_PREFIX.as_bytes(), || 0);
        assert_eq!(
            crate::client_id::identify_client(Some(&id), None),
            crate::client_id::PeerClient::Unknown
        );
        // The same string must also not match any entry via the v field
        // (v string = PEER_AGENT).
        assert_eq!(
            crate::client_id::identify_client(Some(&id), Some(PEER_AGENT)),
            crate::client_id::PeerClient::Unknown
        );
    }

    /// Announce surface: a custom prefix reaches the announce URL's
    /// `peer_id=` parameter through the single generation point
    /// (percent-encoding preserves the Azureus shape verbatim).
    #[test]
    fn announce_url_carries_custom_prefix_peer_id() {
        let req = super::http::AnnounceRequest {
            announce_url: "http://t.example/announce".into(),
            info_hash: [0x12; 20],
            peer_id: generate_peer_id(b"-qB4550-", || b'0' + 1),
            port: 6881,
            uploaded: 0,
            downloaded: 0,
            left: 1,
            event: TrackerEvent::Started,
            numwant: 50,
        };
        let url = super::http::build_announce_url(&req);
        assert!(url.contains("peer_id=-qB4550-111111111111"), "got {url}");
    }

    /// Percent-encode: unreserved characters kept, info_hash binary fully
    /// escaped.
    #[test]
    fn percent_encode_unreserved_and_binary() {
        assert_eq!(percent_encode(b"abc-_.~123"), "abc-_.~123");
        assert_eq!(percent_encode(b"\x00\x0f\xff"), "%00%0F%FF");
    }

    /// Classification table: variant -> class; Network prefix-tag decision
    /// plus fallback.
    #[test]
    fn tracker_error_class_table() {
        assert_eq!(TrackerError::Failed("x".into()).class(), "tracker-reason");
        assert_eq!(
            TrackerError::Malformed("http-status: 403 Forbidden".into()).class(),
            "http-status"
        );
        assert_eq!(
            TrackerError::Malformed("missing `interval`".into()).class(),
            "malformed"
        );
        assert_eq!(
            TrackerError::InvalidUrl("bad port".into()).class(),
            "invalid-url"
        );
        for (msg, want) in [
            ("dns: error sending request", "dns"),
            ("connect-tls: invalid peer certificate", "connect-tls"),
            ("connect: error sending request", "connect"),
            ("timeout: error sending request", "timeout"),
            ("request: error sending request", "request"),
            ("legacy reason without tag", "network"),
        ] {
            assert_eq!(TrackerError::Network(msg.into()).class(), want, "msg={msg}");
        }
        // reason() = inner message (no Display prefix wrapper).
        assert_eq!(
            TrackerError::Network("connect: x".into()).reason(),
            "connect: x"
        );
        assert_eq!(
            TrackerError::Malformed("missing `interval`".into()).reason(),
            "missing `interval`"
        );
    }

    // URL redaction decision-table and verbatim-phase tests moved with the
    // implementation to taiji_io::redact (single source — tests follow the
    // implementation; this module consumes via re-export, and behavior is
    // locked by the tests there).
}
