//! HTTP/HTTPS tracker announce (BEP3 tracker section + BEP23 compact +
//! BEP7 dual-stack peers6).
//!
//! Two surfaces. The frozen surface (`AnnounceRequest`/`build_announce_url`/
//! `announce`/`announce_http`/`parse_http_url`) has zero production callers
//! (the production tracker actor and the magnet-mirror path use
//! `HttpAnnounce`); it keeps its shape, but `announce_http` concatenates
//! path/host/query with no CRLF rejection — add CRLF validation before
//! wiring it into production. The full surface
//! ([`HttpAnnounceParams`]/[`build_announce_url_full`]/[`HttpAnnounce`]) is
//! reqwest(rustls) + gzip + timeout options + trackerid + requirecrypto +
//! peers6.
//!
//! Upstream anchor mapping: docs/design/tracker.md

use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::Duration;

use tracing::debug;

use crate::bencode::{self, Value};

use super::dns::SharedDns;
use super::{PEER_ID_LEN, PeerAddr, TrackerError, TrackerEvent, percent_encode};
use crate::tracker::announce_list::TierEvent;

// ---------------------------------------------------------------------------
// Frozen surface (shape unchanged)
// ---------------------------------------------------------------------------

/// Announce request parameters (field semantics match `DefaultBtAnnounce.cc`).
#[derive(Debug, Clone)]
pub struct AnnounceRequest {
    pub announce_url: String,
    pub info_hash: [u8; 20],
    pub peer_id: [u8; PEER_ID_LEN],
    /// Local TCP listen port (0 = omit from the URL).
    pub port: u16,
    pub uploaded: u64,
    pub downloaded: u64,
    pub left: u64,
    pub event: TrackerEvent,
    /// [`DEFAULT_NUMWANT`] when peers remain to fetch, otherwise 0.
    pub numwant: u32,
}

/// Build the announce URL (parameter order matches aria2
/// `DefaultBtAnnounce.cc`; key = last 8 bytes of the peer_id). Frozen
/// surface: no crypto/trackerid parameters.
pub fn build_announce_url(req: &AnnounceRequest) -> String {
    let key = percent_encode(&req.peer_id[PEER_ID_LEN - 8..]);
    let mut url = String::with_capacity(req.announce_url.len() + 256);
    url.push_str(&req.announce_url);
    // Announce URLs that already carry a query join with & (aria2
    // `uriHasQuery`).
    url.push_str(if req.announce_url.contains('?') {
        "&"
    } else {
        "?"
    });
    url.push_str(&format!(
        "info_hash={}&peer_id={}&uploaded={}&downloaded={}&left={}&compact=1&key={}&numwant={}&no_peer_id=1",
        percent_encode(&req.info_hash),
        percent_encode(&req.peer_id),
        req.uploaded,
        req.downloaded,
        req.left,
        key,
        req.numwant,
    ));
    if req.port != 0 {
        url.push_str(&format!("&port={}", req.port));
    }
    if !req.event.as_str().is_empty() {
        url.push_str("&event=");
        url.push_str(req.event.as_str());
    }
    url
}

/// One IPv6 peer address returned by a tracker (peers6 compact, BEP7;
/// 16B + 2B big-endian).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerAddr6 {
    pub ip: Ipv6Addr,
    pub port: u16,
}

/// Tracker options (aria2-compatible option names).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrackerOptions {
    /// `--bt-tracker-interval` (seconds; 0 = no override): user override
    /// of the re-announce interval (`DefaultBtAnnounce.cc`
    /// userDefinedInterval_ semantics).
    pub bt_tracker_interval: u64,
    /// `--bt-tracker-timeout` (default 60s).
    pub bt_tracker_timeout: Duration,
    /// `--bt-tracker-connect-timeout` (default 60s).
    pub bt_tracker_connect_timeout: Duration,
    /// Local global IPv6 address: when set, HTTP announce requests carry
    /// the `ipv6=` parameter (BEP7; None = omit). Not an aria2 option — a
    /// local policy value; see `taiji_bt::dht::security::probe_source_ip`
    /// for the probe.
    pub local_ipv6: Option<Ipv6Addr>,
}

impl Default for TrackerOptions {
    fn default() -> Self {
        TrackerOptions {
            bt_tracker_interval: 0,
            bt_tracker_timeout: Duration::from_secs(60),
            bt_tracker_connect_timeout: Duration::from_secs(60),
            local_ipv6: None,
        }
    }
}

/// Announce response (BEP3 + BEP23 + BEP7; see [`apply_interval_settings`]
/// for how interval/min-interval land, ported from `DefaultBtAnnounce.cc`).
#[derive(Debug, Clone)]
pub struct AnnounceResponse {
    /// Re-announce interval (seconds; raw `interval` value, may be 0).
    pub interval: u64,
    /// Raw `min interval` value (missing or <= 0 -> None; key names from
    /// BtAnnounce.cc).
    pub min_interval: Option<u64>,
    pub peers: Vec<PeerAddr>,
    /// peers6 (BEP7, 18 bytes per compact entry).
    pub peers6: Vec<PeerAddr6>,
    pub complete: Option<u64>,
    pub incomplete: Option<u64>,
    pub warning: Option<String>,
    /// `tracker id` (echoed back into subsequent announces when present).
    pub tracker_id: Option<String>,
}

/// Apply interval/min-interval (port of `DefaultBtAnnounce.cc`):
/// `interval_` updates only when `interval > 0`; when `min interval > 0`,
/// `minInterval = min(minInterval, interval)`, otherwise
/// `minInterval = interval_`.
pub fn apply_interval_settings(
    resp: &AnnounceResponse,
    interval: &mut u64,
    min_interval: &mut u64,
) {
    if resp.interval > 0 {
        *interval = resp.interval;
    }
    match resp.min_interval {
        Some(mi) if mi > 0 => *min_interval = mi.min(*interval),
        _ => *min_interval = *interval,
    }
}

/// Parse an announce response (bencode dict; `peers` accepts both the
/// compact form (BEP23) and the dict-list form (BEP3) — dict-form IPv6 ip
/// entries go into `peers6` (BEP7), and bad entries are skipped
/// individually instead of failing the whole payload; `peers6` accepts
/// compact (BEP7); `failure reason` present means an error). A missing
/// `peers` is not an error (port of `DefaultBtAnnounce.cc`: a missing peer
/// list only logs).
pub fn parse_announce_response(body: &[u8]) -> Result<AnnounceResponse, TrackerError> {
    let top = bencode::decode(body).map_err(|e| TrackerError::Malformed(e.to_string()))?;
    if let Some(reason) = top.get(b"failure reason").and_then(Value::as_bytes) {
        return Err(TrackerError::Failed(
            String::from_utf8_lossy(reason).into_owned(),
        ));
    }
    let interval = top
        .get(b"interval")
        .and_then(Value::as_int)
        .ok_or_else(|| TrackerError::Malformed("missing `interval`".into()))?;
    if interval < 0 {
        return Err(TrackerError::Malformed("negative `interval`".into()));
    }
    let mut peers = Vec::new();
    let mut peers6 = Vec::new();
    match top.get(b"peers") {
        Some(Value::Bytes(compact)) => {
            if compact.len() % 6 != 0 {
                return Err(TrackerError::Malformed(format!(
                    "compact peers length {} not multiple of 6",
                    compact.len()
                )));
            }
            for chunk in compact.as_chunks::<6>().0 {
                peers.push(PeerAddr {
                    ip: std::net::Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]),
                    port: u16::from_be_bytes([chunk[4], chunk[5]]),
                });
            }
        }
        Some(Value::List(list)) => {
            // dict peers (BEP3 non-compact model: one dict per peer with
            // ip/port): parsed entry by entry; bad entries are skipped with
            // a debug log — one bad entry loses only that peer, not the
            // whole payload (tolerance mirrors KRPC values per-element
            // skipping, dht/message.rs `parse_values`). ip is tried as v4
            // then v6: v6 entries go into peers6 (BEP7 IPv6 tracker
            // extension; the entry shape mirrors compact peers6). The
            // peer_id field is ignored (the no_peer_id=1 request surface
            // does not consume it).
            for p in list {
                let skip = |why: &str| debug!(target: "taiji::bt::tracker", why, "bad dict peer entry skipped");
                let (ip, port) = match (
                    p.get(b"ip").and_then(Value::as_bytes),
                    p.get(b"port").and_then(Value::as_int),
                ) {
                    (Some(ip), Some(port)) if (0..=65535).contains(&port) => (ip, port),
                    _ => {
                        skip("missing ip/port or port out of range");
                        continue;
                    }
                };
                let Ok(ip_str) = std::str::from_utf8(ip) else {
                    skip("ip not utf-8");
                    continue;
                };
                if let Ok(v4) = ip_str.parse::<std::net::Ipv4Addr>() {
                    peers.push(PeerAddr {
                        ip: v4,
                        port: port as u16,
                    });
                } else if let Ok(v6) = ip_str.parse::<Ipv6Addr>() {
                    peers6.push(PeerAddr6 {
                        ip: v6,
                        port: port as u16,
                    });
                } else {
                    skip("ip not IPv4/IPv6 literal");
                }
            }
        }
        // aria2 DefaultBtAnnounce.cc: missing peers -> no peers, no error.
        Some(_) => return Err(TrackerError::Malformed("`peers` not bytes/list".into())),
        None => {}
    }
    // peers6: 18 bytes per compact entry (BEP7; aria2
    // DefaultBtAnnounce.cc runs peers6 through extractPeer AF_INET6);
    // v6 entries from dict peers were already merged above.
    if let Some(Value::Bytes(compact6)) = top.get(b"peers6") {
        if compact6.len() % 18 != 0 {
            return Err(TrackerError::Malformed(format!(
                "compact peers6 length {} not multiple of 18",
                compact6.len()
            )));
        }
        for chunk in compact6.as_chunks::<18>().0 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&chunk[..16]);
            peers6.push(PeerAddr6 {
                ip: Ipv6Addr::from(octets),
                port: u16::from_be_bytes([chunk[16], chunk[17]]),
            });
        }
    }
    Ok(AnnounceResponse {
        interval: interval as u64,
        min_interval: top
            .get(b"min interval")
            .and_then(Value::as_int)
            .filter(|mi| *mi > 0)
            .map(|mi| mi as u64),
        peers,
        peers6,
        // complete/incomplete are swarm counts (BEP3, non-negative): a
        // negative value from a malicious tracker (`i-1e`) is not
        // representable — it becomes None (absent), never a silent `as
        // u64` wrap into u64::MAX.
        complete: top
            .get(b"complete")
            .and_then(Value::as_int)
            .and_then(|v| u64::try_from(v).ok()),
        incomplete: top
            .get(b"incomplete")
            .and_then(Value::as_int)
            .and_then(|v| u64::try_from(v).ok()),
        warning: top
            .get(b"warning message")
            .and_then(Value::as_bytes)
            .map(|w| String::from_utf8_lossy(w).into_owned()),
        tracker_id: top
            .get(b"tracker id")
            .and_then(Value::as_bytes)
            .map(|t| String::from_utf8_lossy(t).into_owned()),
    })
}

/// Minimal URL parsing (frozen surface: http scheme only; the full
/// surface uses [`parse_announce_url`]).
pub fn parse_http_url(url: &str) -> Result<(String, u16, String), TrackerError> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| TrackerError::Malformed("only http:// supported in M0".into()))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse()
                .map_err(|_| TrackerError::Malformed("bad port in url".into()))?,
        ),
        None => (authority.to_string(), 80),
    };
    Ok((host, port, path.to_string()))
}

/// Announce network transfer (frozen surface): plaintext HTTP GET.
/// Returns the response body (bencode).
///
/// Wire shape: `GET <path>?<query> HTTP/1.0\r\nHost: <host>\r\n\r\n`;
/// after the response headers the body is read per Content-Length or
/// until the peer closes (common for HTTP/1.0 trackers).
pub async fn announce_http(url: &str, query: &str) -> Result<Vec<u8>, TrackerError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (host, port, path) = parse_http_url(url)?;
    let mut stream = tokio::net::TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|e| TrackerError::Malformed(format!("connect: {e}")))?;
    // UA = [`crate::tracker::PEER_AGENT`] (`taiji/<CARGO_PKG_VERSION>`,
    // same version source as getVersion; replaces the old hardcoded fake
    // "taiji/0.1").
    let request = format!(
        "GET {path}?{query} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: {}\r\n\r\n",
        crate::tracker::PEER_AGENT
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| TrackerError::Malformed(format!("write: {e}")))?;
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .await
        .map_err(|e| TrackerError::Malformed(format!("read: {e}")))?;
    // Status line + headers are separated from the body by \r\n\r\n; the
    // body is passed to parse_announce_response as-is.
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| TrackerError::Malformed("no header terminator".into()))?;
    let status_line = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| TrackerError::Malformed("bad status line".into()))?
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    if !status_line.contains(" 200 ") && !status_line.ends_with(" 200") {
        return Err(TrackerError::Malformed(format!(
            "http status: {status_line}"
        )));
    }
    Ok(raw[header_end + 4..].to_vec())
}

/// Convenience composition (frozen surface): build the URL query, run the
/// announce, and parse the response.
pub async fn announce(req: &AnnounceRequest) -> Result<AnnounceResponse, TrackerError> {
    // build_announce_url returns the full URL; the query is everything
    // after the first '?'.
    let full = build_announce_url(req);
    let (url, query) = match full.split_once('?') {
        Some((u, q)) => (u.to_string(), q.to_string()),
        None => (full, String::new()),
    };
    let body = announce_http(&url, &query).await?;
    parse_announce_response(&body)
}

// ---------------------------------------------------------------------------
// Full surface
// ---------------------------------------------------------------------------

/// Transfer-path cap on HTTP response bodies — the announce/scrape/mirror
/// tier: 4 MiB. info dicts / announce bencode responses are far smaller;
/// the cap stops a malicious site or compromised mirror (or an HTTP
/// template MITM) from pouring unbounded chunked/gzip data into memory.
/// Same value as taiji-core `magnet.rs`'s `WEB_MIRROR_BODY_CAP` (kept
/// there as a second line of defense before parsing). The .torrent URL
/// fetch is not on this tier — see [`TORRENT_FETCH_MAX_BODY_BYTES`].
pub const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// .torrent URL fetch tier cap: 30 MiB. addUri http(s) .torrent
/// fetch/refetch (taiji-core `fetch_torrent_bytes`) consumes full
/// metainfo whose legal size grows linearly with the piece hash string
/// (total_len / piece_len x 20B) plus the file table, so >4MiB is
/// entirely legal.
///
/// Value source (libtorrent read-only reference): `src/settings_pack.cpp`
/// `SET(max_metadata_size, 3 * 1024 * 10240, nullptr)` = 31457280 = 30 MiB.
/// Tier invariant: [`MAX_BODY_BYTES`] (announce/scrape/mirror, 4 MiB) and
/// the BEP-9 ut_metadata `MAX_METADATA_SIZE` (8 MiB, `ut_metadata/fetcher.rs`)
/// tiers are unchanged.
pub const TORRENT_FETCH_MAX_BODY_BYTES: usize = 30 * 1024 * 1024;

/// Parsed tracker URL (scheme/host/port/path+query).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnounceUrl {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    /// Path and query starting at the first '/'.
    pub path_query: String,
}

/// Tracker URL scheme (UDP goes through [`super::udp`]; the carrier
/// family is decided by the parse result / literal address — IPv6 UDP
/// carriers are supported).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
    Udp,
}

/// Parse a tracker URL (http/https/udp).
///
/// Default ports http=80/https=443; udp has no default port -> a missing
/// port is invalid (aria2 `FeatureConfig.cc` + `uri.cc`: when
/// getDefaultPort==0 and no explicit port is given, parsing fails).
/// IPv6 literal hosts (`[..]:port`) are supported.
pub fn parse_announce_url(url: &str) -> Result<AnnounceUrl, TrackerError> {
    let invalid = |m: &str| Err(TrackerError::InvalidUrl(m.to_string()));
    let (scheme, rest) = if let Some(r) = url.strip_prefix("http://") {
        (Scheme::Http, r)
    } else if let Some(r) = url.strip_prefix("https://") {
        (Scheme::Https, r)
    } else if let Some(r) = url.strip_prefix("udp://") {
        (Scheme::Udp, r)
    } else {
        return invalid("unsupported scheme (need http/https/udp)");
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    // IPv6 literal: [host]:port; otherwise host:port or bare host.
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        let close = stripped
            .find(']')
            .ok_or_else(|| TrackerError::InvalidUrl("unclosed IPv6 literal".into()))?;
        let host = &stripped[..close];
        let after = &stripped[close + 1..];
        let port = after
            .strip_prefix(':')
            .ok_or_else(|| TrackerError::InvalidUrl("IPv6 host requires :port".into()))?;
        (
            host.to_string(),
            port.parse()
                .map_err(|_| TrackerError::InvalidUrl("bad port in url".into()))?,
        )
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse()
                    .map_err(|_| TrackerError::InvalidUrl("bad port in url".into()))?,
            ),
            None => (
                authority.to_string(),
                match scheme {
                    Scheme::Http => 80,
                    Scheme::Https => 443,
                    Scheme::Udp => {
                        return invalid("udp tracker url requires explicit port (aria2 uri.cc)");
                    }
                },
            ),
        }
    };
    if host.is_empty() {
        return invalid("empty host");
    }
    Ok(AnnounceUrl {
        scheme,
        host,
        port,
        path_query: path.to_string(),
    })
}

/// Full announce parameters (port of `DefaultBtAnnounce::getAnnounceUrl`).
pub struct HttpAnnounceParams<'a> {
    /// The tier's current URL (`announceList_.getAnnounce()`).
    pub announce_url: &'a str,
    pub info_hash: [u8; 20],
    pub peer_id: [u8; PEER_ID_LEN],
    pub port: u16,
    pub uploaded: u64,
    pub downloaded: u64,
    pub left: u64,
    /// Tier event (`announceList_.getEventString()`; values per
    /// `TierEvent::event_str`, "" meaning no event parameter).
    pub event: TierEvent,
    /// [`super::DEFAULT_NUMWANT`] when peers remain to fetch, otherwise 0.
    pub numwant: u32,
    /// `trackerid` (backfilled from the response's `tracker id`).
    pub tracker_id: Option<&'a str>,
    /// `bt-force-encryption || bt-require-crypto` -> requirecrypto=1,
    /// otherwise supportcrypto=1.
    pub require_crypto: bool,
}

/// Build the full announce URL (parameter order ported from
/// `DefaultBtAnnounce.cc`).
pub fn build_announce_url_full(p: &HttpAnnounceParams<'_>) -> String {
    compose_announce_url(
        p.announce_url,
        &p.info_hash,
        &p.peer_id,
        p.port,
        p.uploaded,
        p.downloaded,
        p.left,
        p.event,
        p.numwant,
        p.tracker_id,
        p.require_crypto,
    )
}

/// Owned announce parameters (for spawning across tasks; field semantics
/// as [`HttpAnnounceParams`]).
#[derive(Debug, Clone)]
pub struct OwnedAnnounceParams {
    pub announce_url: String,
    pub info_hash: [u8; 20],
    pub peer_id: [u8; PEER_ID_LEN],
    pub port: u16,
    pub uploaded: u64,
    pub downloaded: u64,
    pub left: u64,
    pub event: TierEvent,
    pub numwant: u32,
    pub tracker_id: Option<String>,
    pub require_crypto: bool,
}

impl OwnedAnnounceParams {
    /// Borrowed view (reuses the frozen surface's URL builder).
    pub fn borrow(&self) -> HttpAnnounceParams<'_> {
        HttpAnnounceParams {
            announce_url: &self.announce_url,
            info_hash: self.info_hash,
            peer_id: self.peer_id,
            port: self.port,
            uploaded: self.uploaded,
            downloaded: self.downloaded,
            left: self.left,
            event: self.event,
            numwant: self.numwant,
            tracker_id: self.tracker_id.as_deref(),
            require_crypto: self.require_crypto,
        }
    }
}

/// URL composition kernel (order: base -> base fields -> port -> event
/// -> trackerid -> requirecrypto/supportcrypto).
#[expect(
    clippy::too_many_arguments,
    reason = "pure kernel mirrors the BEP3 announce field list one-to-one; a params struct adds indirection, not fewer inputs"
)]
fn compose_announce_url(
    announce_url: &str,
    info_hash: &[u8; 20],
    peer_id: &[u8; PEER_ID_LEN],
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
    event: TierEvent,
    numwant: u32,
    tracker_id: Option<&str>,
    require_crypto: bool,
) -> String {
    let key = percent_encode(&peer_id[PEER_ID_LEN - 8..]);
    let mut url = String::with_capacity(announce_url.len() + 320);
    url.push_str(announce_url);
    // uriHasQuery (aria2).
    url.push_str(if announce_url.contains('?') { "&" } else { "?" });
    url.push_str(&format!(
        "info_hash={}&peer_id={}&uploaded={}&downloaded={}&left={}&compact=1&key={}&numwant={}&no_peer_id=1",
        percent_encode(info_hash),
        percent_encode(peer_id),
        uploaded,
        downloaded,
        left,
        key,
        numwant,
    ));
    if port != 0 {
        url.push_str(&format!("&port={port}"));
    }
    let event = event.event_str();
    if !event.is_empty() {
        url.push_str("&event=");
        url.push_str(event);
    }
    if let Some(tid) = tracker_id
        && !tid.is_empty()
    {
        url.push_str("&trackerid=");
        url.push_str(&percent_encode(tid.as_bytes()));
    }
    if require_crypto {
        url.push_str("&requirecrypto=1");
    } else {
        url.push_str("&supportcrypto=1");
    }
    url
}

/// reqwest DNS adapter, deliberately a zero-logic shell (the orphan rule
/// forces `impl reqwest::dns::Resolve` into this crate; all bridging logic
/// is single-sourced in `SharedDns::resolve_for_transport` — this shell
/// only calls the bridge and converts types, with no branching; logic
/// growing here is the guard signal that the assembly approach is being
/// reopened).
struct DnsAdapter(Arc<SharedDns>);

impl reqwest::dns::Resolve for DnsAdapter {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let dns = self.0.clone();
        let host = name.as_str().to_string();
        Box::pin(async move {
            // Port is always 0: hyper-util fills port 0 in
            // resolver-returned addresses by scheme convention / overrides
            // it with the URL's explicit port (cache entries hold only
            // IpAddr; the port is synthesized by hyper-util).
            match dns.resolve_for_transport(&host, 0).await {
                Ok(addrs) => Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs),
                Err(e) => Err(super::dns::box_resolve_error(e)),
            }
        })
    }
}

/// HTTP/HTTPS announce client (reqwest rustls + gzip; timeouts wired to
/// `--bt-tracker-timeout`/`--bt-tracker-connect-timeout`).
#[derive(Clone)]
pub struct HttpAnnounce {
    client: reqwest::Client,
    /// Payload of the BEP7 `ipv6=` request parameter (local global IPv6;
    /// None = omit).
    local_ipv6: Option<Ipv6Addr>,
}

impl HttpAnnounce {
    /// Build from options (TLS = rustls; gzip decompression on). The DNS
    /// side is the process-wide shared service default instance (TTL cache +
    /// 30s resolve timeout; same cache as the HTTP download transport —
    /// behavior notes in [`super::dns`]'s re-export source
    /// `taiji_io::dns`).
    pub fn new(opts: &TrackerOptions) -> Result<Self, TrackerError> {
        Self::with_dns(opts, SharedDns::shared_default())
    }

    /// Use the same resolver service as the caller's UDP and download paths.
    pub fn with_dns(opts: &TrackerOptions, dns: Arc<SharedDns>) -> Result<Self, TrackerError> {
        // TLS provider: reqwest's rustls-no-provider build() reads a
        // process-level default; the idempotent installer lives in
        // taiji-io (shared foundation; this and the other build sites,
        // plus the taiji-http transport, share one install).
        taiji_io::tls::install_ring_provider_default();
        let client = reqwest::Client::builder()
            .dns_resolver(Arc::new(DnsAdapter(dns)))
            // Redirects are not followed: this client carries both
            // announce and .torrent fetches — the default policy
            // auto-follows up to 10 hops, and a malicious 302 could
            // silently point a fetch/announce at an internal address
            // (e.g. 169.254.169.254), with the failure shape leaking
            // internal ports/liveness through task state. BEP3 semantics
            // treat non-200 as an error: 3xx lands on `get_body_capped`'s
            // existing http-status error path. taiji-http's HttpClient
            // does a manual redirect loop (its own judgment surface), out
            // of scope here.
            .redirect(reqwest::redirect::Policy::none())
            .gzip(true)
            .connect_timeout(opts.bt_tracker_connect_timeout)
            .timeout(opts.bt_tracker_timeout)
            .build()
            .map_err(|e| TrackerError::Network(e.to_string()))?;
        Ok(HttpAnnounce {
            client,
            local_ipv6: opts.local_ipv6,
        })
    }

    /// GET and return the response body; non-200 ->
    /// [`TrackerError::Malformed`] (same status handling as
    /// `announce_http`; BEP3 only carries a bencode response on 200).
    /// Transport errors get a class prefix via [`classify_transport_error`].
    ///
    /// The body read has a transfer-path cap: the stream is truncated at
    /// [`MAX_BODY_BYTES`], so an oversized malicious payload is rejected
    /// before entering the process heap.
    pub async fn get_body(&self, url: &str) -> Result<Vec<u8>, TrackerError> {
        self.get_body_capped(url, MAX_BODY_BYTES).await
    }

    /// Capped variant of [`get_body`]: the body is read as a stream
    /// (`Response::chunk` — chunks in arrival order, decompressed bytes
    /// when gzip is on); once the running total exceeds `cap` the read is
    /// aborted and a `max-size`-classified error is returned (the
    /// connection is dropped immediately — the server's write side sees
    /// the close and stops sending); a `Content-Length` declaring an
    /// over-cap body is rejected before reading. The cap is tiered per
    /// caller: tracker announce (BEP3 bencode responses) and mirror
    /// .torrent use [`get_body`]'s 4 MiB tier ([`MAX_BODY_BYTES`]); addUri
    /// .torrent fetches use [`TORRENT_FETCH_MAX_BODY_BYTES`] (30 MiB).
    pub async fn get_body_capped(&self, url: &str, cap: usize) -> Result<Vec<u8>, TrackerError> {
        let mut resp = self
            .client
            .get(url)
            // Same UA string as the frozen-surface announce_http
            // (PEER_AGENT = taiji/<CARGO_PKG_VERSION>, same version source
            // as getVersion).
            .header("User-Agent", crate::tracker::PEER_AGENT)
            .send()
            .await
            .map_err(|e| TrackerError::Network(format!("{}: {e}", classify_transport_error(&e))))?;
        // Non-200 rejected before reading (BEP3 carries a bencode body
        // only on 200; the original checked the status only after
        // buffering the whole body — moved earlier in the streaming
        // rewrite, the "http-status" class is unchanged).
        let status = resp.status();
        if status != reqwest::StatusCode::OK {
            return Err(TrackerError::Malformed(format!("http-status: {status}")));
        }
        // Content-Length precheck: a declared over-cap body is rejected
        // outright (under gzip the declared value is compressed bytes;
        // decompression blowup is caught by the streaming truncation
        // below).
        if let Some(len) = resp.content_length()
            && len as usize > cap
        {
            return Err(TrackerError::Malformed(format!(
                "max-size: content-length {len} over {cap} cap"
            )));
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| TrackerError::Network(format!("{}: {e}", classify_transport_error(&e))))?
        {
            if body.len().saturating_add(chunk.len()) > cap {
                return Err(TrackerError::Malformed(format!(
                    "max-size: body over {cap} cap"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    /// Full announce: build URL -> GET -> parse.
    pub async fn announce_full(
        &self,
        p: &HttpAnnounceParams<'_>,
    ) -> Result<AnnounceResponse, TrackerError> {
        let url = append_ipv6_param(build_announce_url_full(p), self.local_ipv6);
        let body = self.get_body(&url).await?;
        parse_announce_response(&body)
    }

    /// Announce taking owned parameters (for actor spawns across tasks).
    pub async fn announce_owned(
        &self,
        p: &OwnedAnnounceParams,
    ) -> Result<AnnounceResponse, TrackerError> {
        self.announce_full(&p.borrow()).await
    }
}

/// Classify reqwest transport errors (observability surface): decides
/// dns / connect-tls / connect / timeout / request from the source-chain
/// text plus reqwest predicates. Thin wrapper over [`classify_error_dyn`]
/// with predicate injection.
///
/// Timeout semantics: on reqwest 0.12.28 the connect timeout
/// (`ClientBuilder::connect_timeout`, tower TimeoutLayer -> Elapsed ->
/// `error::TimedOut`) and the total timeout (Kind::Request + `TimedOut`)
/// produce **identically shaped** errors that the public API cannot
/// distinguish — both classify as "timeout"; which of
/// `bt-tracker-connect-timeout` / `bt-tracker-timeout` fired can be
/// inferred from the reqwest text in the reason string.
pub(crate) fn classify_transport_error(e: &reqwest::Error) -> &'static str {
    classify_error_dyn(e, e.is_timeout(), e.is_connect())
}

/// Classification core over `&(dyn Error)` (reqwest-free seam for
/// table-driven tests): the DNS arm's attribution is single-sourced in
/// [`super::dns::error_chain_is_dns`] (taiji-io: source-chain downcast of
/// `ResolveError` first, Display-text fallback); the other arms
/// (TLS/timeout/connect/request) are this crate's observability
/// predicates.
fn classify_error_dyn(
    e: &(dyn std::error::Error + 'static),
    is_timeout: bool,
    is_connect: bool,
) -> &'static str {
    // DNS: a type-preserved ResolveError anywhere in the chain
    // classifies as dns (type check, immune to reqwest/hyper-util Display
    // wording drift); chains that lost the type / bypassed the shared
    // resolver are caught by the text fallback in the core.
    if super::dns::error_chain_is_dns(e) {
        return "dns";
    }
    let chain = error_chain_text(e);
    classify_error_chain(&chain.to_lowercase(), is_timeout, is_connect)
}

/// Classification kernel (pure function, table-driven test surface):
/// lowercased source-chain text + reqwest predicates. The DNS arm has
/// moved up to the taiji-io single source ([`classify_error_dyn`] decides
/// first) — no text matching of "dns error" here.
fn classify_error_chain(chain_lower: &str, is_timeout: bool, is_connect: bool) -> &'static str {
    // TLS (rustls certificate/alert text: "invalid peer certificate:
    // ...", "received fatal alert: ...", "tls").
    if chain_lower.contains("certificate")
        || chain_lower.contains("alert")
        || chain_lower.contains("tls")
    {
        return "connect-tls";
    }
    if is_timeout {
        return "timeout";
    }
    if is_connect {
        return "connect";
    }
    "request"
}

/// Concatenated source-chain text: the error's own Display plus each
/// `source()` Display.
fn error_chain_text(e: &dyn std::error::Error) -> String {
    let mut text = e.to_string();
    let mut src = e.source();
    while let Some(err) = src {
        text.push_str(" | ");
        text.push_str(&err.to_string());
        src = err.source();
    }
    text
}

/// BEP7 `ipv6=` request parameter: appended to the announce URL when the
/// local host has a global IPv6 address.
///
/// Encoding source: the current BEP7 revision (post-2020) removed the
/// `ipv4=`/`ipv6=` parameter definitions and declares them discouraged
/// ("An earlier version of this BEP specified new HTTP parameters ...
/// These are discouraged") — the parameter encoding has no ruling in the
/// current text, so libtorrent's mainstream interop behavior is followed:
/// `src/http_tracker_connection.cpp` does `url += "&ipv6=";
/// url += escape_string(v6.to_string())` — the address is percent-escaped
/// in **textual form** (e.g. `2001:db8::1` -> `2001%3Adb8%3A%3A1`).
/// This is a request-side addition; the peers6 response surface (BEP7)
/// predates it and is unchanged.
fn append_ipv6_param(url: String, local_ipv6: Option<Ipv6Addr>) -> String {
    let Some(v6) = local_ipv6 else {
        return url;
    };
    let mut url = url;
    url.push_str("&ipv6=");
    url.push_str(&percent_encode(v6.to_string().as_bytes()));
    url
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Announce URL: parameter order/fields match aria2
    /// DefaultBtAnnounce.cc.
    #[test]
    fn announce_url_matches_aria2_shape() {
        let req = AnnounceRequest {
            announce_url: "http://tracker.example/announce".into(),
            info_hash: [0x12; 20],
            peer_id: *b"-TJ0001-AAAAAAAAAAAA",
            port: 6881,
            uploaded: 1,
            downloaded: 2,
            left: 3,
            event: TrackerEvent::Started,
            numwant: 50,
        };
        let url = build_announce_url(&req);
        // Parameter order and fields match DefaultBtAnnounce.cc; key =
        // last 8 bytes of the peer_id = "AAAAAAAA" (unreserved, kept
        // verbatim).
        assert_eq!(
            url,
            "http://tracker.example/announce?\
             info_hash=%12%12%12%12%12%12%12%12%12%12%12%12%12%12%12%12%12%12%12%12&\
             peer_id=-TJ0001-AAAAAAAAAAAA&uploaded=1&downloaded=2&left=3&compact=1&\
             key=AAAAAAAA&numwant=50&no_peer_id=1&port=6881&event=started"
        );
    }

    /// Announce URLs that already carry a query join with & (aria2
    /// `uriHasQuery` semantics).
    #[test]
    fn announce_url_appends_with_ampersand_when_query_present() {
        let req = AnnounceRequest {
            announce_url: "http://t.example/announce?pass=secret".into(),
            info_hash: [0; 20],
            peer_id: [0; 20],
            port: 0,
            uploaded: 0,
            downloaded: 0,
            left: 0,
            event: TrackerEvent::Periodic,
            numwant: 0,
        };
        let url = build_announce_url(&req);
        assert!(
            url.contains("/announce?pass=secret&info_hash="),
            "got {url}"
        );
        assert!(
            url.ends_with("no_peer_id=1"),
            "port=0 omitted, no event for periodic announces"
        );
    }

    /// Compact peers (BEP23) parsing + failure reason surfaced as an
    /// error.
    #[test]
    fn parse_compact_peers_and_failure() {
        let body = b"d8:completei2e10:incompletei3e8:intervali1800e\
             5:peers12:\x0A\x00\x00\x01\x1A\xE1\x0A\x00\x00\x02\x1A\xE2e";
        let resp = parse_announce_response(body).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(resp.interval, 1800);
        assert_eq!(resp.complete, Some(2));
        assert_eq!(resp.peers.len(), 2);
        assert_eq!(resp.peers[0].ip.to_string(), "10.0.0.1");
        assert_eq!(resp.peers[0].port, 6881);
        assert_eq!(resp.peers[1].port, 6882);
        // failure reason -> Failed (BEP3).
        let err = parse_announce_response(b"d14:failure reason6:errorse");
        assert!(matches!(err, Err(TrackerError::Failed(ref m)) if m == "errors"));
        // Compact length not a multiple of 6 -> Malformed.
        assert!(matches!(
            parse_announce_response(b"d8:intervali1e5:peers7:xxxxxxxe"),
            Err(TrackerError::Malformed(_))
        ));
    }

    /// peers dict-list form (BEP3 non-compact).
    #[test]
    fn parse_peers_dict_list() {
        let body = b"d8:intervali60e5:peersld2:ip9:127.0.0.14:porti7000eeee";
        let resp = parse_announce_response(body).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(resp.peers.len(), 1);
        assert_eq!(resp.peers[0].ip.to_string(), "127.0.0.1");
        assert_eq!(resp.peers[0].port, 7000);
    }

    /// Negative `complete`/`incomplete` (malicious tracker, e.g. `i-1e`)
    /// are treated as absent (None) instead of wrapping through the old
    /// `as u64` into u64::MAX and poisoning the swarm statistics;
    /// non-negative values still parse (boundary: i64::MAX, and 0).
    #[test]
    fn negative_complete_incomplete_become_none() {
        // Keys in ascending order (complete < incomplete < interval).
        let body = b"d8:completei-1e10:incompletei-2e8:intervali60ee";
        let resp = parse_announce_response(body).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(resp.complete, None, "i-1 must not wrap to u64::MAX");
        assert_eq!(resp.incomplete, None, "i-2 must not wrap");
        assert_eq!(resp.interval, 60, "unrelated fields unaffected");

        // Non-negative counts keep parsing; i64::MAX is the positive
        // boundary (u64::try_from passes, value preserved verbatim).
        let body = b"d8:completei9223372036854775807e10:incompletei0e8:intervali60ee";
        let resp = parse_announce_response(body).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(resp.complete, Some(9_223_372_036_854_775_807u64));
        assert_eq!(resp.incomplete, Some(0));

        // Missing keys still read as None (unchanged absence semantics).
        let resp = parse_announce_response(b"d8:intervali60ee").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(resp.complete, None);
        assert_eq!(resp.incomplete, None);
    }

    /// dict peers mixing v4+v6: v4 into `peers`, v6 into `peers6` (BEP7
    /// "IPv6 trackers": v6 peers are reported via peers6, the entry shape
    /// mirroring compact peers6); individually unparseable entries (non-
    /// v4/v6 literals, missing port, out-of-range port) are skipped and
    /// the announce still succeeds — one bad entry does not sink the
    /// whole response (tolerance mirrors KRPC values per-element
    /// skipping, message.rs `parse_values`). Before the fix: a v6 ip
    /// failed `Ipv4Addr::parse` -> whole payload Malformed.
    #[test]
    fn dict_peers_v6_into_peers6_and_bad_entries_skipped() {
        let body = b"d8:intervali60e5:peersl\
             d2:ip9:127.0.0.14:porti7000ee\
             d2:ip11:2001:db8::14:porti7001ee\
             d2:ip7:not-ip!4:porti7002eeee";
        let resp = parse_announce_response(body).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(resp.peers.len(), 1, "v4 entry lands in peers");
        assert_eq!(resp.peers[0].ip.to_string(), "127.0.0.1");
        assert_eq!(resp.peers[0].port, 7000);
        assert_eq!(
            resp.peers6.len(),
            1,
            "v6 entry lands in peers6 (list shape, same shape as compact peers6)"
        );
        assert_eq!(resp.peers6[0].ip.to_string(), "2001:db8::1");
        assert_eq!(resp.peers6[0].port, 7001);

        // Missing port / port outside 0..=65535: the entry is skipped,
        // the payload still succeeds.
        let body2 = b"d8:intervali60e5:peersl\
             d2:ip9:127.0.0.1e\
             d2:ip9:127.0.0.24:porti70000eeee";
        let resp2 = parse_announce_response(body2).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            resp2.peers.is_empty() && resp2.peers6.is_empty(),
            "all bad entries skipped: peers={:?} peers6={:?}",
            resp2.peers,
            resp2.peers6
        );
        assert_eq!(resp2.interval, 60);
    }

    /// Minimal URL parsing (frozen surface: http only).
    #[test]
    fn parse_http_url_minimal() {
        assert_eq!(
            parse_http_url("http://t.example:8080/a?x=1").unwrap_or_else(|e| panic!("{e}")),
            ("t.example".to_string(), 8080, "/a?x=1".to_string())
        );
        assert_eq!(
            parse_http_url("http://t.example").unwrap_or_else(|e| panic!("{e}")),
            ("t.example".to_string(), 80, "/".to_string())
        );
        assert!(
            parse_http_url("https://t.example/a").is_err(),
            "frozen surface is http-only (https goes through parse_announce_url/HttpAnnounce)"
        );
    }

    /// announce_http full roundtrip (frozen surface, local loopback).
    #[tokio::test]
    async fn announce_http_roundtrip_local() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap_or_else(|e| panic!("{e}"));
            // Read until the request head ends (a single read may stop
            // mid-request; unread residue would trigger an RST).
            let mut req = Vec::new();
            let mut chunk = [0u8; 512];
            loop {
                let n = sock
                    .read(&mut chunk)
                    .await
                    .unwrap_or_else(|e| panic!("{e}"));
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&chunk[..n]);
                if req.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&req).into_owned();
            // Request shape assertions (tracker conformance vectors).
            assert!(text.starts_with("GET /announce?"), "got {text}");
            assert!(text.contains("info_hash="));
            assert!(text.contains("compact=1"));
            // UA assertion: UA = PEER_AGENT (taiji/<semver>, same
            // version source as getVersion) — replaces the old hardcoded
            // fake "taiji/0.1".
            assert!(
                text.contains(&format!("User-Agent: {}", crate::tracker::PEER_AGENT)),
                "got {text}"
            );
            let body = b"d8:intervali600e5:peers6:\x7F\x00\x00\x01\x1A\xE1e";
            let head = format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
            sock.write_all(head.as_bytes())
                .await
                .unwrap_or_else(|e| panic!("{e}"));
            sock.write_all(body).await.unwrap_or_else(|e| panic!("{e}"));
        });

        let resp = announce_http(
            &format!("http://{addr}/announce"),
            "info_hash=abc&compact=1",
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));
        let parsed = parse_announce_response(&resp).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(parsed.interval, 600);
        assert_eq!(parsed.peers.len(), 1);
        assert_eq!(parsed.peers[0].ip.to_string(), "127.0.0.1");
        assert!(server.await.is_ok());
    }

    /// Non-200 status -> Malformed (including the status line).
    #[tokio::test]
    async fn non_200_status_rejected() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap_or_else(|e| panic!("{e}"));
            // Drain the request first (closing with unread residue
            // triggers an RST).
            let mut req = Vec::new();
            let mut chunk = [0u8; 512];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = sock
                    .read(&mut chunk)
                    .await
                    .unwrap_or_else(|e| panic!("{e}"));
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&chunk[..n]);
            }
            sock.write_all(b"HTTP/1.0 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap_or_else(|e| panic!("{e}"));
        });
        let err = announce_http(&format!("http://{addr}/announce"), "x=1").await;
        assert!(
            matches!(err, Err(TrackerError::Malformed(ref m)) if m.contains("403")),
            "actual: {err:?}"
        );
        assert!(server.await.is_ok());
    }

    // ---------------------- Vectors ----------------------

    /// Test helper: build baseline full parameters (DefaultBtAnnounce.cc
    /// shape).
    fn full_params<'a>(
        announce_url: &'a str,
        event: TierEvent,
        numwant: u32,
        require_crypto: bool,
    ) -> HttpAnnounceParams<'a> {
        HttpAnnounceParams {
            announce_url,
            info_hash: [0xde; 20],
            peer_id: *b"-TJ0001-0123456789AB",
            port: 6881,
            uploaded: 10,
            downloaded: 20,
            left: 30,
            event,
            numwant,
            tracker_id: None,
            require_crypto,
        }
    }

    /// Vectors 1-4: full-URL shapes for the four events (parameter order
    /// matches DefaultBtAnnounce.cc; key = last 8B of the peer_id =
    /// "456789AB").
    #[test]
    fn full_url_vectors_events_and_crypto() {
        // Vector 1: started + supportcrypto (default).
        let p = full_params(
            "http://t.example:8080/announce",
            TierEvent::Started,
            50,
            false,
        );
        assert_eq!(
            build_announce_url_full(&p),
            "http://t.example:8080/announce?\
             info_hash=%DE%DE%DE%DE%DE%DE%DE%DE%DE%DE%DE%DE%DE%DE%DE%DE%DE%DE%DE%DE&\
             peer_id=-TJ0001-0123456789AB&uploaded=10&downloaded=20&left=30&compact=1&\
             key=456789AB&numwant=50&no_peer_id=1&port=6881&event=started&supportcrypto=1"
        );
        // Vector 2: completed.
        let u2 = build_announce_url_full(&full_params(
            "http://t.example:8080/announce",
            TierEvent::Completed,
            50,
            false,
        ));
        assert!(u2.ends_with("&event=completed&supportcrypto=1"), "got {u2}");
        // Vector 3: stopped.
        let u3 = build_announce_url_full(&full_params(
            "http://t.example:8080/announce",
            TierEvent::Stopped,
            50,
            false,
        ));
        assert!(u3.contains("&event=stopped&"), "got {u3}");
        // Vector 4: DOWNLOADING/SEEDING -> no event parameter
        // (getEventString = "", AnnounceList.cc).
        let u4 = build_announce_url_full(&full_params(
            "http://t.example:8080/announce",
            TierEvent::Downloading,
            50,
            false,
        ));
        assert!(!u4.contains("event="), "got {u4}");
        assert!(u4.ends_with("&supportcrypto=1"));
    }

    /// Vector 5: STARTED_AFTER_COMPLETION's event is "started"
    /// (AnnounceList.cc getEventString); port=0 is omitted.
    #[test]
    fn full_url_started_after_completion_vector() {
        let p = HttpAnnounceParams {
            announce_url: "http://t.example/announce",
            info_hash: [0; 20],
            peer_id: [0; 20],
            port: 0,
            uploaded: 0,
            downloaded: 0,
            left: 0,
            event: TierEvent::StartedAfterCompletion,
            numwant: 0,
            tracker_id: None,
            require_crypto: false,
        };
        let url = build_announce_url_full(&p);
        assert!(url.contains("&event=started&"), "got {url}");
        assert!(!url.contains("port="), "got {url}");
    }

    /// Vector 6: requirecrypto=1 (bt-force-encryption/bt-require-crypto,
    /// DefaultBtAnnounce.cc).
    #[test]
    fn full_url_require_crypto_vector() {
        let url = build_announce_url_full(&full_params(
            "http://t.example/announce",
            TierEvent::Seeding,
            0,
            true,
        ));
        assert!(url.ends_with("&requirecrypto=1"), "got {url}");
        assert!(!url.contains("supportcrypto"), "got {url}");
    }

    /// Vector 7: trackerid appended and percent-encoded.
    #[test]
    fn full_url_tracker_id_vector() {
        let mut p = full_params("http://t.example/announce", TierEvent::Seeding, 0, false);
        p.tracker_id = Some("id with space/&=");
        let url = build_announce_url_full(&p);
        assert!(
            url.contains("&trackerid=id%20with%20space%2F%26%3D&supportcrypto=1"),
            "got {url}"
        );
    }

    /// Vector 8: URLs with an existing query join with & and keep
    /// parameter order (uriHasQuery semantics); HTTPS announce URLs are
    /// isomorphic.
    #[test]
    fn full_url_existing_query_vector() {
        let p = HttpAnnounceParams {
            announce_url: "https://t.example/announce?passkey=XYZ",
            info_hash: [1; 20],
            peer_id: [2; 20],
            port: 6881,
            uploaded: 0,
            downloaded: 0,
            left: 1,
            event: TierEvent::Started,
            numwant: 50,
            tracker_id: None,
            require_crypto: false,
        };
        let url = build_announce_url_full(&p);
        assert!(
            url.starts_with("https://t.example/announce?passkey=XYZ&info_hash="),
            "got {url}"
        );
        assert!(url.contains("&peer_id=%02%02"), "got {url}");
    }

    /// Vectors 9-12: URL parsing (default port / explicit port / udp
    /// without port invalid / IPv6 literal; default ports from
    /// FeatureConfig.cc, udp-missing-port invalid per uri.cc).
    #[test]
    fn announce_url_parse_vectors() {
        let u = parse_announce_url("http://t.example/announce").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            (u.scheme, u.port, u.path_query.as_str()),
            (Scheme::Http, 80, "/announce")
        );
        let u =
            parse_announce_url("https://t.example:7001/a?x=1").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            (u.scheme, u.port, u.path_query.as_str()),
            (Scheme::Https, 7001, "/a?x=1")
        );
        let u = parse_announce_url("udp://tracker.example:1337/announce")
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((u.scheme, u.port), (Scheme::Udp, 1337));
        assert!(matches!(
            parse_announce_url("udp://tracker.example/announce"),
            Err(TrackerError::InvalidUrl(_))
        ));
        let u = parse_announce_url("http://[2001:db8::1]:8080/announce")
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((u.host.as_str(), u.port), ("2001:db8::1", 8080));
    }

    /// Vector 13: peers6 parsing (BEP7, 18B per compact entry) + min
    /// interval semantics (DefaultBtAnnounce.cc: mi>0 takes
    /// min(mi, interval), otherwise interval).
    #[test]
    fn peers6_and_min_interval_vectors() {
        let ip6 = [
            0x20u8, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let mk_body = |min_interval: Option<u64>| {
            let mut body = Vec::new();
            body.extend_from_slice(b"d8:intervali1800e");
            if let Some(mi) = min_interval {
                body.extend_from_slice(format!("12:min intervali{mi}e").as_bytes());
            }
            body.extend_from_slice(b"6:peers6");
            body.extend_from_slice(b"18:");
            body.extend_from_slice(&ip6);
            body.extend_from_slice(&7000u16.to_be_bytes());
            body.extend_from_slice(b"e");
            body
        };
        let resp = parse_announce_response(&mk_body(Some(900))).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(resp.interval, 1800);
        assert_eq!(resp.min_interval, Some(900));
        assert_eq!(resp.peers6.len(), 1);
        assert_eq!(resp.peers6[0].ip.to_string(), "2001:db8::1");
        assert_eq!(resp.peers6[0].port, 7000);
        let resp2 = parse_announce_response(&mk_body(Some(9999))).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(resp2.min_interval, Some(9999));
        let resp3 = parse_announce_response(&mk_body(None)).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(resp3.min_interval, None, "no min interval");

        // Landing table (port of DefaultBtAnnounce.cc).
        let mut iv = 60u64;
        let mut mi = 60u64;
        apply_interval_settings(&resp, &mut iv, &mut mi);
        assert_eq!((iv, mi), (1800, 900), "min(900, 1800)");
        apply_interval_settings(&resp2, &mut iv, &mut mi);
        assert_eq!((iv, mi), (1800, 1800), "min(9999, 1800)");
        apply_interval_settings(&resp3, &mut iv, &mut mi);
        assert_eq!(mi, 1800, "no min interval -> falls back to interval");
        // interval=0 (abnormal packet) does not update (only >0
        // assigns).
        let zero = AnnounceResponse {
            interval: 0,
            min_interval: None,
            peers: vec![],
            peers6: vec![],
            complete: None,
            incomplete: None,
            warning: None,
            tracker_id: None,
        };
        apply_interval_settings(&zero, &mut iv, &mut mi);
        assert_eq!((iv, mi), (1800, 1800));
    }

    /// Vector 14: tracker id / warning message backfill (key names from
    /// BtAnnounce.cc; DefaultBtAnnounce.cc).
    #[test]
    fn tracker_id_and_warning_backfill_vectors() {
        // Keys in ascending order: interval < peers < tracker id <
        // warning message ("warning message" is 15 chars, BtAnnounce.cc;
        // empty peers list).
        let body = b"d8:intervali60e5:peersle10:tracker id3:abc15:warning message4:warne";
        let resp = parse_announce_response(body).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(resp.warning.as_deref(), Some("warn"));
        assert_eq!(resp.tracker_id.as_deref(), Some("abc"));
    }

    /// Vector 15: numwant decision (DefaultBtAnnounce.cc: full/halted ->
    /// 0, peers to fetch -> 50).
    #[test]
    fn numwant_vector() {
        assert!(
            build_announce_url_full(&full_params(
                "http://t/announce",
                TierEvent::Downloading,
                50,
                false
            ))
            .contains("&numwant=50&")
        );
        assert!(
            build_announce_url_full(&full_params(
                "http://t/announce",
                TierEvent::Downloading,
                0,
                false
            ))
            .contains("&numwant=0&")
        );
    }

    // ===== BEP7 `ipv6=` request parameter =====

    /// Encoding unit test: local global v6 ->
    /// `&ipv6=<percent-escaped textual form>` (libtorrent
    /// http_tracker_connection.cpp); None -> URL unchanged.
    #[test]
    fn ipv6_param_encoding_matches_libtorrent_textual_form() {
        let base = "http://tracker.example/announce?info_hash=x&numwant=50".to_string();
        // Fully expanded address: colons escaped, no other escapes
        // needed in the address text.
        let v6: Ipv6Addr = "2001:0db8:0000:0000:0000:0000:0000:0001"
            .parse()
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            append_ipv6_param(base.clone(), Some(v6)),
            format!("{base}&ipv6=2001%3Adb8%3A%3A1"),
            "text form + colon escapes (the compressed form is Ipv6Addr::to_string's job)"
        );
        // No global v6 -> URL unchanged (parameter omitted).
        assert_eq!(append_ipv6_param(base.clone(), None), base);
        // Multiple colons each escaped.
        let v62: Ipv6Addr = "fe80::1".parse().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            append_ipv6_param(base.clone(), Some(v62)),
            format!("{base}&ipv6=fe80%3A%3A1")
        );
    }

    /// Option defaults: local_ipv6 defaults to None (zero-change
    /// semantics for existing TrackerOptions::default() consumers).
    #[test]
    fn tracker_options_default_carries_no_ipv6() {
        assert_eq!(TrackerOptions::default().local_ipv6, None);
    }

    // ===== Local identity string =====

    /// UA assertion on the reqwest transport path: `get_body`'s
    /// `User-Agent` header = PEER_AGENT (taiji/<semver>, same version
    /// source as getVersion — replaces the old hardcoded fake
    /// "taiji/0.1").
    #[tokio::test]
    async fn get_body_sends_peer_agent_user_agent() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("addr: {e}"));
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener
                .accept()
                .await
                .unwrap_or_else(|e| panic!("accept: {e}"));
            let mut req = Vec::new();
            let mut chunk = [0u8; 512];
            loop {
                let n = sock
                    .read(&mut chunk)
                    .await
                    .unwrap_or_else(|e| panic!("read: {e}"));
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&chunk[..n]);
                if req.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&req).into_owned();
            assert!(
                text.contains(&format!("user-agent: {}", crate::tracker::PEER_AGENT))
                    || text.contains(&format!("User-Agent: {}", crate::tracker::PEER_AGENT)),
                "got {text}"
            );
            let body = b"d8:intervali60ee";
            let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
            sock.write_all(head.as_bytes())
                .await
                .unwrap_or_else(|e| panic!("write: {e}"));
            sock.write_all(body)
                .await
                .unwrap_or_else(|e| panic!("write: {e}"));
        });
        let http =
            HttpAnnounce::new(&TrackerOptions::default()).unwrap_or_else(|e| panic!("client: {e}"));
        let body = http
            .get_body(&format!("http://{addr}/announce"))
            .await
            .unwrap_or_else(|e| panic!("get_body: {e}"));
        assert_eq!(
            parse_announce_response(&body)
                .unwrap_or_else(|e| panic!("{e}"))
                .interval,
            60
        );
        assert!(server.await.is_ok());
    }

    // ===== Transport error classification =====

    /// Test chain construction: single-layer wrapper (custom Display
    /// text + source pointing at the inner error), mimicking how
    /// reqwest/hyper-util pass sources layer by layer — the DNS downcast
    /// arm must see through the wrapper to the inner ResolveError.
    struct ChainLink {
        display: String,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    }

    impl std::fmt::Display for ChainLink {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.display)
        }
    }

    impl std::fmt::Debug for ChainLink {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "ChainLink({:?})", self.display)
        }
    }

    impl std::error::Error for ChainLink {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.source
                .as_ref()
                .map(|b| b.as_ref() as &(dyn std::error::Error + 'static))
        }
    }

    /// DNS-arm positive and negative cases ([`classify_error_dyn`] —
    /// downcast first + text fallback; the attribution core is
    /// single-sourced in taiji-io, this locks the bt-side wiring):
    /// - A type-preserved `ResolveError` hits by downcast: the chain
    ///   Display carries **no** dns wording, so only the source-chain
    ///   downcast can find it (direct proof the adapter layer must not
    ///   `to_string()` and break the chain);
    /// - A pure io error is not misjudged (connect refusal classifies as
    ///   connect, not dns);
    /// - Broken-chain case: the payload is only "dns error: ..." text
    ///   (nothing to downcast) -> the text fallback path still catches it;
    /// - DNS attribution outranks the connect predicate (priority kept).
    #[test]
    fn classify_error_dyn_dns_arm_downcast_and_fallback() {
        // Positive 1: type-preserved ResolveError (hyper-util-style
        // wrapper) -> downcast hit (chain text has no "dns error"/"failed
        // to lookup").
        let preserved = ChainLink {
            display: "client error (connect)".to_string(),
            source: Some(super::super::dns::box_resolve_error(
                super::super::dns::ResolveError::Timeout(Duration::from_millis(50)),
            )),
        };
        assert_eq!(classify_error_dyn(&preserved, false, true), "dns");

        // Positive 2: text fallback (broken-chain form) — real
        // hyper_util legacy ConnectError wording (lowercased), no type to
        // downcast.
        let stringified = ChainLink {
            display: "dns error: failed to lookup address information: \
                      name or service not known"
                .to_string(),
            source: None,
        };
        assert_eq!(classify_error_dyn(&stringified, false, true), "dns");

        // Priority: DNS attribution (downcast) outranks the connect
        // predicate.
        assert_eq!(classify_error_dyn(&preserved, true, true), "dns");

        // Negative: pure io connection refusal is not misjudged as dns
        // (classifies as connect).
        let refused = ChainLink {
            display: "client error (connect)".to_string(),
            source: Some(Box::new(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "tcp connect error: connection refused (os error 61)",
            ))),
        };
        assert_eq!(classify_error_dyn(&refused, false, true), "connect");

        // Negative 2: broken chain with no legacy wording -> not dns
        // (the fallback word list excludes ResolveError's own Display,
        // avoiding a self-fulfilling loop).
        let broken = ChainLink {
            display: "dns resolution failed: nxdomain".to_string(),
            source: None,
        };
        assert_eq!(classify_error_dyn(&broken, false, false), "request");
    }

    /// Classification kernel table (classify_error_chain): chain text +
    /// predicates -> class. Text samples are real hyper_util legacy
    /// ConnectError / rustls Display shapes (lowercased). The DNS arm has
    /// moved to the taiji-io single source (see the
    /// [`classify_error_dyn`] table); this table locks the other arms.
    #[test]
    fn classify_error_chain_table() {
        let table = [
            (
                "client error (connect) | invalid peer certificate: unknownissuer",
                false,
                true,
                "connect-tls",
            ),
            (
                "client error (connect) | received fatal alert: handshakefailure",
                false,
                true,
                "connect-tls",
            ),
            (
                "error sending request for url (): operation timed out",
                true,
                false,
                "timeout",
            ),
            (
                "client error (connect) | tcp connect error: connection refused (os error 61)",
                false,
                true,
                "connect",
            ),
            (
                "error sending request for url (): channel closed",
                false,
                false,
                "request",
            ),
        ];
        for (chain, is_timeout, is_connect, want) in table {
            assert_eq!(
                classify_error_chain(chain, is_timeout, is_connect),
                want,
                "chain={chain}"
            );
        }
        // Priority (remaining arms): TLS text outranks the
        // timeout/connect predicates.
        assert_eq!(
            classify_error_chain("certificate revoked", true, true),
            "connect-tls"
        );
    }

    /// get_body non-200 -> Malformed("http-status: ...") (the prefix
    /// contract behind TrackerError::class() returning "http-status").
    #[tokio::test]
    async fn get_body_non_200_classified_http_status() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap_or_else(|e| panic!("{e}"));
            let mut req = Vec::new();
            let mut chunk = [0u8; 512];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = sock
                    .read(&mut chunk)
                    .await
                    .unwrap_or_else(|e| panic!("{e}"));
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&chunk[..n]);
            }
            sock.write_all(b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap_or_else(|e| panic!("{e}"));
        });
        let client =
            HttpAnnounce::new(&TrackerOptions::default()).unwrap_or_else(|e| panic!("{e}"));
        let outcome = client.get_body(&format!("http://{addr}/announce")).await;
        match outcome {
            Ok(body) => panic!("expected error, got {body:?}"),
            Err(e) => {
                assert!(
                    matches!(e, TrackerError::Malformed(ref m) if m.starts_with("http-status:")),
                    "got {e:?}"
                );
                assert_eq!(e.class(), "http-status");
            }
        }
        let _ = server.await;
    }

    /// HttpAnnounce::new reads the option: opts.local_ipv6 -> carried by
    /// the client.
    #[test]
    fn http_announce_picks_up_local_ipv6_from_options() {
        let mut opts = TrackerOptions::default();
        assert!(
            HttpAnnounce::new(&opts)
                .unwrap_or_else(|e| panic!("{e}"))
                .local_ipv6
                .is_none()
        );
        opts.local_ipv6 = Some("2001:db8::1".parse().unwrap_or_else(|e| panic!("{e}")));
        let client = HttpAnnounce::new(&opts).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            client.local_ipv6,
            Some("2001:db8::1".parse().unwrap_or_else(|e| panic!("{e}")))
        );
    }

    // ===== Response-body transfer cap regressions =====

    /// Drain the request head (a single read may stop mid-request; same
    /// method as the existing tests).
    async fn drain_request_head<S: tokio::io::AsyncRead + Unpin>(sock: &mut S) {
        use tokio::io::AsyncReadExt as _;
        let mut req = Vec::new();
        let mut chunk = [0u8; 512];
        while !req.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut chunk))
                .await
                .unwrap_or_else(|e| panic!("read timeout: {e}"))
                .unwrap_or_else(|e| panic!("read: {e}"));
            if n == 0 {
                break;
            }
            req.extend_from_slice(&chunk[..n]);
        }
    }

    /// Regression: a malicious mirror's unbounded chunked stream. The
    /// old implementation buffered everything via `resp.bytes()` before
    /// magnet.rs checked the 4MiB cap — the cap never acted on the
    /// transfer path. Now the stream is truncated: the client aborts and
    /// drops the connection at cap+1. Bounded-memory assertion: the
    /// server must **fail to finish** writing the 64MiB total (the old
    /// path always finished and returned Ok(64MiB)), and the error class
    /// is `max-size` (a distinct class, preserved in the log surface).
    #[tokio::test]
    async fn get_body_truncates_malicious_chunked_stream_at_cap() {
        use tokio::io::AsyncWriteExt as _;
        const TOTAL: usize = 64 * 1024 * 1024;
        const CHUNK: usize = 64 * 1024;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap_or_else(|e| panic!("{e}"));
            drain_request_head(&mut sock).await;
            if sock
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .is_err()
            {
                return false;
            }
            let chunk = vec![0u8; CHUNK];
            let mut sent = 0usize;
            while sent < TOTAL {
                if sock
                    .write_all(format!("{CHUNK:x}\r\n").as_bytes())
                    .await
                    .is_err()
                {
                    return false;
                }
                if sock.write_all(&chunk).await.is_err() {
                    return false;
                }
                if sock.write_all(b"\r\n").await.is_err() {
                    return false;
                }
                sent += CHUNK;
            }
            // Terminating chunk: only the old unbounded read would ever
            // get this far.
            let _ = sock.write_all(b"0\r\n\r\n").await;
            true
        });
        let client =
            HttpAnnounce::new(&TrackerOptions::default()).unwrap_or_else(|e| panic!("{e}"));
        let outcome = client
            .get_body(&format!("http://{addr}/torrent/deadbeef.torrent"))
            .await;
        match outcome {
            Ok(body) => panic!("expected cap error, got {} bytes", body.len()),
            Err(e) => {
                assert_eq!(e.class(), "max-size", "got {e:?}");
            }
        }
        let completed = tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .unwrap_or_else(|e| panic!("server join timeout: {e}"))
            .unwrap_or_else(|e| panic!("server task: {e}"));
        assert!(
            !completed,
            "server delivered the full {TOTAL} bytes: unbounded read path is back"
        );
    }

    /// Content-Length precheck: a declared over-cap body is rejected
    /// before any read — judged with zero body bytes sent beyond the
    /// headers; error class `max-size`.
    #[tokio::test]
    async fn get_body_content_length_precheck_rejects_declared_oversize() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap_or_else(|e| panic!("{e}"));
            drain_request_head(&mut sock).await;
            // Declare 5MiB (> MAX_BODY_BYTES), then send no body bytes.
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5242880\r\n\r\n")
                .await
                .unwrap_or_else(|e| panic!("{e}"));
            // Keep the peer half-open until the client decides and
            // returns (it hangs on read while waiting).
            let mut buf = [0u8; 64];
            let _ = sock.read(&mut buf).await;
        });
        let client =
            HttpAnnounce::new(&TrackerOptions::default()).unwrap_or_else(|e| panic!("{e}"));
        let outcome = client
            .get_body(&format!("http://{addr}/torrent/deadbeef.torrent"))
            .await;
        match outcome {
            Ok(body) => panic!("expected precheck rejection, got {body:?}"),
            Err(e) => {
                assert_eq!(e.class(), "max-size", "got {e:?}");
                assert!(e.to_string().contains("content-length"), "got {e:?}");
            }
        }
        let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
    }

    /// A regular chunked response (multiple chunks + terminating chunk)
    /// assembles verbatim within the cap — the streaming rewrite's
    /// happy-path regression (the fix must not break legitimate response
    /// reads).
    #[tokio::test]
    async fn get_body_assembles_chunked_response_within_cap() {
        use tokio::io::AsyncWriteExt as _;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
        let body: &[u8] = b"d8:intervali600e5:peers6:\x7F\x00\x00\x01\x1A\xE1e";
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap_or_else(|e| panic!("{e}"));
            drain_request_head(&mut sock).await;
            sock.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .unwrap_or_else(|e| panic!("{e}"));
            for part in body.chunks(12) {
                sock.write_all(format!("{:x}\r\n", part.len()).as_bytes())
                    .await
                    .unwrap_or_else(|e| panic!("{e}"));
                sock.write_all(part).await.unwrap_or_else(|e| panic!("{e}"));
                sock.write_all(b"\r\n")
                    .await
                    .unwrap_or_else(|e| panic!("{e}"));
            }
            sock.write_all(b"0\r\n\r\n")
                .await
                .unwrap_or_else(|e| panic!("{e}"));
        });
        let client =
            HttpAnnounce::new(&TrackerOptions::default()).unwrap_or_else(|e| panic!("{e}"));
        let got = client
            .get_body(&format!("http://{addr}/announce"))
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(got, body);
        // The assembled body is still a valid announce response (the
        // parse-side integration is intact).
        let parsed = parse_announce_response(&got).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(parsed.interval, 600);
        let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
    }

    /// Cap boundary: a body exactly at the cap passes (the check is
    /// `> cap`); cap + 1 truncates.
    #[tokio::test]
    async fn get_body_cap_boundary_is_inclusive() {
        use tokio::io::AsyncWriteExt as _;
        let cap = MAX_BODY_BYTES;
        // Exactly cap bytes: the Content-Length precheck passes, and the
        // running total touches but never exceeds the cap.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap_or_else(|e| panic!("{e}"));
            drain_request_head(&mut sock).await;
            sock.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {cap}\r\n\r\n").as_bytes())
                .await
                .unwrap_or_else(|e| panic!("{e}"));
            let chunk = vec![0u8; 64 * 1024];
            let mut sent = 0usize;
            while sent < cap {
                sock.write_all(&chunk)
                    .await
                    .unwrap_or_else(|e| panic!("{e}"));
                sent += chunk.len();
            }
        });
        let client =
            HttpAnnounce::new(&TrackerOptions::default()).unwrap_or_else(|e| panic!("{e}"));
        let got = client
            .get_body(&format!("http://{addr}/a"))
            .await
            .unwrap_or_else(|e| panic!("exactly-cap body must pass: {e}"));
        assert_eq!(got.len(), cap);
        let _ = tokio::time::timeout(Duration::from_secs(10), server).await;

        // cap + 1: truncated (Malformed classified max-size).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap_or_else(|e| panic!("{e}"));
            drain_request_head(&mut sock).await;
            sock.write_all(
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", cap + 1).as_bytes(),
            )
            .await
            .unwrap_or_else(|e| panic!("{e}"));
            let mut sent = 0usize;
            let chunk = vec![0u8; 64 * 1024];
            while sent <= cap {
                if sock.write_all(&chunk).await.is_err() {
                    break;
                }
                sent += chunk.len();
            }
        });
        let client =
            HttpAnnounce::new(&TrackerOptions::default()).unwrap_or_else(|e| panic!("{e}"));
        let outcome = client.get_body(&format!("http://{addr}/a")).await;
        assert!(
            matches!(outcome, Err(ref e) if e.class() == "max-size"),
            "got {outcome:?}"
        );
        let _ = tokio::time::timeout(Duration::from_secs(10), server).await;
    }

    /// Test helper for the tiered caps: one-shot HTTP server — drains
    /// the request head, then replies 200 + Content-Length + the full
    /// body. Write failures after the peer drops early end silently (the
    /// rejection arms always cause that; not an assertion surface).
    async fn serve_static_body(body: Vec<u8>) -> std::net::SocketAddr {
        use tokio::io::AsyncWriteExt as _;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            drain_request_head(&mut sock).await;
            let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
            if sock.write_all(head.as_bytes()).await.is_err() {
                return;
            }
            let _ = sock.write_all(&body).await;
        });
        addr
    }

    /// Tier-asymmetry regression: the same 5MiB response — the announce
    /// tier ([`get_body`], 4 MiB) deterministically rejects with max-size
    /// (no tier regression), while the .torrent fetch tier
    /// ([`get_body_capped`] + [`TORRENT_FETCH_MAX_BODY_BYTES`], 30 MiB)
    /// fetches it in full (legal metainfo over 4MiB is no longer capped
    /// by the transfer tier).
    #[tokio::test]
    async fn torrent_fetch_tier_accepts_body_over_announce_cap() {
        let body = vec![0xA5u8; 5 * 1024 * 1024];
        let client =
            HttpAnnounce::new(&TrackerOptions::default()).unwrap_or_else(|e| panic!("{e}"));
        // Announce tier: 4MiB precheck rejection (no regression).
        let addr = serve_static_body(body.clone()).await;
        let outcome = client.get_body(&format!("http://{addr}/a")).await;
        let Err(err) = outcome else {
            panic!("announce tier must reject body over 4MiB");
        };
        assert_eq!(err.class(), "max-size", "got {err:?}");
        // Fetch tier: the same response fetched in full, bytes verbatim.
        let addr = serve_static_body(body.clone()).await;
        let got = client
            .get_body_capped(
                &format!("http://{addr}/big.torrent"),
                TORRENT_FETCH_MAX_BODY_BYTES,
            )
            .await
            .unwrap_or_else(|e| panic!("fetch tier must pass: {e}"));
        assert_eq!(got, body);
    }

    /// Fetch-tier boundary: exactly 30MiB passes (the `> cap` check,
    /// same semantics as the 4MiB tier); one byte over (declared via
    /// Content-Length) is rejected at the precheck; an over-cap chunked
    /// stream is truncated and classified max-size (semantics carried
    /// over to the 30MiB tier).
    #[tokio::test]
    async fn torrent_fetch_cap_boundary_is_inclusive() {
        use tokio::io::AsyncWriteExt as _;
        let cap = TORRENT_FETCH_MAX_BODY_BYTES;
        let client =
            HttpAnnounce::new(&TrackerOptions::default()).unwrap_or_else(|e| panic!("{e}"));
        // Exactly equal: the full body is fetched verbatim.
        let body = vec![0x5Au8; cap];
        let addr = serve_static_body(body).await;
        let got = client
            .get_body_capped(&format!("http://{addr}/a"), cap)
            .await
            .unwrap_or_else(|e| panic!("exactly-cap body must pass: {e}"));
        assert_eq!(got.len(), cap);
        // One byte over: Content-Length = cap + 1 -> rejected before
        // reading.
        let addr = serve_static_body(vec![0u8; cap + 1]).await;
        let outcome = client
            .get_body_capped(&format!("http://{addr}/a"), cap)
            .await;
        assert!(
            matches!(outcome, Err(ref e) if e.class() == "max-size"),
            "got {outcome:?}"
        );
        // Chunked stream (no Content-Length to precheck): crossing the
        // cap drops the connection — the server cannot finish; the error
        // class is max-size.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
        let server = tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return false;
            };
            drain_request_head(&mut sock).await;
            if sock
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .is_err()
            {
                return false;
            }
            const CHUNK: usize = 64 * 1024;
            // The 64MiB overload total far exceeds kernel buffers +
            // hyper readahead (as in the 4MiB-tier malicious-stream
            // test): overshooting by a single chunk would be absorbed by
            // the buffering window and the server could finish before the
            // drop — the "cannot finish" invariant needs this order-of-
            // magnitude margin.
            const TOTAL: usize = 64 * 1024 * 1024;
            let chunk = vec![0u8; CHUNK];
            let mut sent = 0usize;
            while sent < TOTAL {
                if sock
                    .write_all(format!("{CHUNK:x}\r\n").as_bytes())
                    .await
                    .is_err()
                {
                    return false;
                }
                if sock.write_all(&chunk).await.is_err() {
                    return false;
                }
                if sock.write_all(b"\r\n").await.is_err() {
                    return false;
                }
                sent += CHUNK;
            }
            true
        });
        let outcome = client
            .get_body_capped(&format!("http://{addr}/a"), cap)
            .await;
        assert!(
            matches!(outcome, Err(ref e) if e.class() == "max-size"),
            "got {outcome:?}"
        );
        let completed = tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .unwrap_or_else(|e| panic!("server join timeout: {e}"))
            .unwrap_or_else(|e| panic!("server task: {e}"));
        assert!(
            !completed,
            "server delivered past the {cap} cap: unbounded read path is back"
        );
    }

    /// 302 redirects are not followed: when a source 302's Location
    /// points at an "internal target" (simulated by a local decoy
    /// listener), the client must treat the 3xx as a non-200 error (BEP3:
    /// only 200 carries a bencode response) rather than auto-following —
    /// following would silently GET the Location target, and the failure
    /// shape would leak internal ports/liveness through task state. Two
    /// assertions: the result is an `http-status` error (deterministic),
    /// and the decoy is never contacted (after the fix no connection is
    /// made at all, so the count stays 0 regardless of scheduling; the
    /// following path would complete before `get_body` returns, so the
    /// red state is caught deterministically by the first assertion).
    #[tokio::test]
    async fn redirect_response_rejected_not_followed() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use tokio::io::AsyncWriteExt as _;

        // Decoy: the Location-target stand-in. Counts hits + answers
        // 200; must see zero hits after the fix.
        let decoy = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind decoy: {e}"));
        let decoy_addr = decoy.local_addr().unwrap_or_else(|e| panic!("{e}"));
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_watch = hits.clone();
        let decoy_task = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = decoy.accept().await else {
                    return;
                };
                hits_watch.fetch_add(1, Ordering::SeqCst);
                drain_request_head(&mut sock).await;
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\npwned!")
                    .await;
            }
        });

        // Source: answers the single request with a 302 -> decoy.
        let source = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind source: {e}"));
        let source_addr = source.local_addr().unwrap_or_else(|e| panic!("{e}"));
        let server = tokio::spawn(async move {
            let (mut sock, _) = source.accept().await.unwrap_or_else(|e| panic!("{e}"));
            drain_request_head(&mut sock).await;
            sock.write_all(
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://{decoy_addr}/inner\r\nContent-Length: 0\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        });

        let client =
            HttpAnnounce::new(&TrackerOptions::default()).unwrap_or_else(|e| panic!("{e}"));
        let outcome = client
            .get_body(&format!("http://{source_addr}/x.torrent"))
            .await;
        // Assertion 1 (deterministic): the 3xx lands on the non-200
        // error path, and the status text contains 302.
        assert!(
            matches!(&outcome, Err(e) if e.class() == "http-status"
                && format!("{e:?}").contains("302")),
            "3xx must surface as http-status error, got: {outcome:?}"
        );
        // Assertion 2: zero decoy hits (no connection is made after the
        // fix; the wait window only relaxes observation, not the verdict
        // direction).
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "client followed the 302 and reached the Location target"
        );
        decoy_task.abort();
        let _ = tokio::time::timeout(Duration::from_secs(10), server).await;
    }

    /// max-size classification: prefix decision checks.
    #[test]
    fn tracker_error_class_max_size_prefix() {
        let e = TrackerError::Malformed("max-size: body over 4194304 cap".into());
        assert_eq!(e.class(), "max-size");
        // Existing classes are unaffected by the new arm.
        assert_eq!(TrackerError::Malformed("other".into()).class(), "malformed");
        assert_eq!(
            TrackerError::Malformed("http-status: 404".into()).class(),
            "http-status"
        );
    }
}
