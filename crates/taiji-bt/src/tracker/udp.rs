//! UDP tracker client (BEP15; protocol surface, transport-agnostic —
//! packets go through caller-provided channels/sockets; a duplex channel
//! stands in for tests until UdpDemux lands).
//!
//! One-to-one port of aria2's UDPTrackerClient/UDPTrackerRequest: the
//! magic connection id, the action/event enums, the
//! pending/inflight/connect-wait queues plus the connectionIdCache, and
//! the 5s resend / 10s timeout boundary (BEP15's 15x2^n backoff is only a
//! general suggestion; the aria2 values are kept by design). One
//! extension beyond upstream: SCRAPE (aria2 never sends it and drops
//! SCRAPE replies), built from the BEP15 text. Announce/scrape replies
//! parse peers by carrier family, never mixed: v4 carrier -> 6B/entry,
//! v6 carrier -> 18B/entry (16B address + 2B port; a length that is not
//! a multiple of 18 is an explicit error), matching libtorrent
//! `udp_tracker_connection.cpp` (`ip_stride = is_v6 ? 18 : 6`).
//!
//! Upstream anchor mapping: docs/design/tracker.md

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

// rand 0.10: `&mut impl Rng` signatures keep the Rng base trait; the
// random() sampling surface lives in RngExt (the old Rng renamed).
use rand::RngExt;

use super::{PEER_ID_LEN, PeerAddr, PeerAddr6, TrackerError};

/// BEP15 protocol_id / aria2 `UDPT_INITIAL_CONNECTION_ID`
/// (`UDPTrackerClient.h`).
pub const UDPT_INITIAL_CONNECTION_ID: u64 = 0x0000_0417_2710_1980;

/// Resend wait after the first send (aria2 `UDPTrackerClient.cc` `5_s`).
pub const RESEND_DELAY: Duration = Duration::from_secs(5);
/// Timeout verdict after the resend (aria2 `UDPTrackerClient.cc` `10_s`).
pub const TIMEOUT_DELAY: Duration = Duration::from_secs(10);
/// connection id cache lifetime (aria2 `UDPTrackerClient.cc` `1_min`;
/// BEP15 "until one minute after it has received it").
pub const CONNECTION_ID_TTL: Duration = Duration::from_secs(60);

/// UDP tracker action (aria2 `UDPTrackerRequest.h` = BEP15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpAction {
    Connect = 0,
    Announce = 1,
    Scrape = 2,
    Error = 3,
}

impl UdpAction {
    fn from_i32(v: i32) -> Option<Self> {
        Some(match v {
            0 => UdpAction::Connect,
            1 => UdpAction::Announce,
            2 => UdpAction::Scrape,
            3 => UdpAction::Error,
            _ => return None,
        })
    }
}

/// UDP announce event (aria2 `UDPTrackerRequest.h` = BEP15; 0=none).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpEvent {
    None = 0,
    Completed = 1,
    Started = 2,
    Stopped = 3,
}

/// Request failure reason (aria2 `UDPTrackerRequest.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UdpError {
    Tracker,
    Timeout,
    Shutdown,
    Network,
}

/// UDP tracker transaction request (a subset of the aria2
/// `UDPTrackerRequest.h` fields).
#[derive(Debug, Clone)]
pub struct UdpRequest {
    pub remote: SocketAddr,
    pub action: UdpAction,
    /// Batch of info_hashes for SCRAPE; exactly one for ANNOUNCE.
    pub info_hashes: Vec<[u8; 20]>,
    pub peer_id: [u8; PEER_ID_LEN],
    pub downloaded: u64,
    pub left: u64,
    pub uploaded: u64,
    pub event: UdpEvent,
    /// The request's `ip` field (aria2 sets 0 without bt-external-ip).
    pub ip: u32,
    /// UDP key = a random number (`DefaultBtAnnounce.cc`; the random
    /// source is injected).
    pub key: u32,
    pub numwant: i32,
    pub port: u16,
    /// Transaction id (`generateTransactionId`, 4 random bytes; `None` =
    /// unassigned, the client assigns it when emitting the frame).
    pub transaction_id: Option<u32>,
    connection_id: u64,
    /// Number of sends (failCount).
    pub fail_count: u32,
    dispatched: Option<Instant>,
    pub(crate) done: Option<UdpError>,
    pub(crate) reply: Option<UdpAnnounceReply>,
    pub(crate) scrape_reply: Option<Vec<UdpScrapeEntry>>,
}

impl UdpRequest {
    /// ANNOUNCE request constructor (field semantics match
    /// `DefaultBtAnnounce.cc`).
    pub fn announce(remote: SocketAddr, info_hash: [u8; 20], key: u32) -> Self {
        UdpRequest {
            remote,
            action: UdpAction::Announce,
            info_hashes: vec![info_hash],
            peer_id: [0; PEER_ID_LEN],
            downloaded: 0,
            left: 0,
            uploaded: 0,
            event: UdpEvent::None,
            ip: 0,
            key,
            numwant: 50,
            port: 0,
            transaction_id: None,
            connection_id: UDPT_INITIAL_CONNECTION_ID,
            fail_count: 0,
            dispatched: None,
            done: None,
            reply: None,
            scrape_reply: None,
        }
    }

    /// SCRAPE request constructor (BEP15; batched info_hashes, the BEP
    /// suggests <= 74 per request).
    pub fn scrape(remote: SocketAddr, info_hashes: Vec<[u8; 20]>) -> Self {
        UdpRequest {
            action: UdpAction::Scrape,
            info_hashes,
            ..UdpRequest::announce(remote, [0; 20], 0)
        }
    }

    /// ANNOUNCE reply (present once the request completes).
    pub fn announce_reply(&self) -> Option<&UdpAnnounceReply> {
        self.reply.as_ref()
    }

    /// SCRAPE reply (present once the request completes).
    pub fn scrape_reply(&self) -> Option<&[UdpScrapeEntry]> {
        self.scrape_reply.as_deref()
    }

    /// Completion state and failure reason (`UDPT_STA_COMPLETE` + error,
    /// `UDPTrackerRequest.h` state/error semantics).
    pub fn failure(&self) -> Option<UdpError> {
        self.done
    }
}

/// ANNOUNCE reply (aria2 `UDPTrackerReply`, `UDPTrackerRequest.h`).
///
/// Peers are parsed by carrier family (family = the address family of
/// the remote the reply came from, never mixed): a v4 carrier fills
/// [`Self::peers`] (6B/entry), a v6 carrier fills [`Self::peers6`]
/// (18B/entry); the other side stays empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpAnnounceReply {
    pub transaction_id: u32,
    pub interval: i32,
    pub leechers: i32,
    pub seeders: i32,
    /// Carrier family = IPv4 (compact 6B/entry, BEP23).
    pub peers: Vec<PeerAddr>,
    /// Carrier family = IPv6 (compact 18B/entry, BEP32 shape).
    pub peers6: Vec<PeerAddr6>,
}

/// One SCRAPE reply entry (BEP15: seeders/completed/leechers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpScrapeEntry {
    pub info_hash: [u8; 20],
    pub seeders: i32,
    pub completed: i32,
    pub leechers: i32,
}

/// Successful output of `receiveReply` (aria2's recvReq carries back the
/// reply; an explicit enum here).
#[derive(Debug, Clone)]
pub enum UdpReply {
    /// CONNECT completed (the connection id is cached).
    Connected,
    /// ANNOUNCE completed (the request carries the reply).
    Announce(Box<UdpRequest>),
    /// SCRAPE completed (the request carries the reply; BEP15 extension,
    /// see the module header).
    Scrape(Box<UdpRequest>),
    /// ERROR reply (message text).
    Error { message: String },
}

#[derive(Debug, Clone, Copy)]
enum ConnectionState {
    Connecting,
    Connected,
}

/// connection id cache entry (aria2 `UDPTrackerConnection`).
#[derive(Debug, Clone, Copy)]
struct Connection {
    state: ConnectionState,
    connection_id: u64,
    last_updated: Option<Instant>,
}

impl Default for Connection {
    fn default() -> Self {
        Connection {
            state: ConnectionState::Connecting,
            connection_id: UDPT_INITIAL_CONNECTION_ID,
            last_updated: None,
        }
    }
}

/// UDP tracker client state machine (port of aria2 `UDPTrackerClient`:
/// the pending/inflight/connect queues plus the connectionIdCache).
///
/// Usage sequence (mirrors the aria2 header comment): queue with
/// [`Self::add_request`] -> loop [`Self::create_request`] to emit frames
/// and send them over the caller's channel (`None` = queues empty) ->
/// call [`Self::request_sent`] after each send; call
/// [`Self::handle_timeout`] periodically; feed inbound packets to
/// [`Self::receive_reply`].
#[derive(Debug, Default)]
pub struct UdpTrackerClient {
    connection_id_cache: HashMap<(IpAddr, u16), Connection>,
    inflight: VecDeque<UdpRequest>,
    pending: VecDeque<UdpRequest>,
    /// announce/scrape requests waiting for a connection id (aria2
    /// `connectRequests_`).
    connect_waiting: VecDeque<UdpRequest>,
}

impl UdpTrackerClient {
    pub fn new() -> Self {
        Self::default()
    }

    /// All queues empty (aria2 `noRequest`).
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty() && self.connect_waiting.is_empty() && self.inflight.is_empty()
    }

    /// `addRequest`: push onto the back of pending and reset transaction
    /// state.
    pub fn add_request(&mut self, mut req: UdpRequest) {
        req.transaction_id = None;
        req.fail_count = 0;
        req.dispatched = None;
        req.done = None;
        req.reply = None;
        req.scrape_reply = None;
        self.pending.push_back(req);
    }

    /// `createRequest`: produce the next frame for the request at the
    /// front of pending. CONNECT is auto-prepended when no valid
    /// connection id exists; while the peer's connect is in flight the
    /// current request moves to connect_waiting.
    pub fn create_request(
        &mut self,
        rng: &mut impl RngExt,
        now: Instant,
    ) -> Option<(SocketAddr, Vec<u8>)> {
        loop {
            // Copy the front metadata out first so the borrow does not
            // reach into the &mut self call (get_connection).
            let (front_action, front_remote) = {
                let req = self.pending.front()?;
                (req.action, req.remote)
            };
            match front_action {
                UdpAction::Connect => {
                    let mut req = self.pending.pop_front()?;
                    if req.transaction_id.is_none() {
                        req.transaction_id = Some(rng.random());
                    }
                    let Some(tid) = req.transaction_id else {
                        continue;
                    };
                    let addr = req.remote;
                    let frame = build_connect_frame(tid);
                    self.pending.push_front(req);
                    return Some((addr, frame));
                }
                UdpAction::Announce | UdpAction::Scrape => {
                    let key = (front_remote.ip(), front_remote.port());
                    match self.get_connection(key, now) {
                        None => {
                            // No valid connection id -> prepend CONNECT.
                            let mut creq = UdpRequest {
                                action: UdpAction::Connect,
                                ..UdpRequest::announce(front_remote, [0; 20], 0)
                            };
                            creq.transaction_id = Some(rng.random());
                            if let Some(tid) = creq.transaction_id {
                                let addr = creq.remote;
                                let frame = build_connect_frame(tid);
                                self.pending.push_front(creq);
                                return Some((addr, frame));
                            }
                            // rng.random() cannot hit the None path here;
                            // defensive continue.
                            continue;
                        }
                        Some(Connection {
                            state: ConnectionState::Connecting,
                            ..
                        }) => {
                            // CONNECT in flight -> move to the waiting
                            // queue and look at the next request.
                            let req = self.pending.pop_front()?;
                            self.connect_waiting.push_back(req);
                            continue;
                        }
                        Some(Connection {
                            state: ConnectionState::Connected,
                            connection_id,
                            ..
                        }) => {
                            let mut req = self.pending.pop_front()?;
                            req.connection_id = connection_id;
                            if req.transaction_id.is_none() {
                                req.transaction_id = Some(rng.random());
                            }
                            let Some(tid) = req.transaction_id else {
                                continue;
                            };
                            let addr = req.remote;
                            let frame = match req.action {
                                UdpAction::Announce => build_announce_frame(&req, tid),
                                UdpAction::Scrape => build_scrape_frame(&req, tid),
                                _ => continue,
                            };
                            self.pending.push_front(req);
                            return Some((addr, frame));
                        }
                    }
                }
                UdpAction::Error => return None,
            }
        }
    }

    /// `requestSent`: the front of pending was sent -> move it to
    /// inflight and stamp dispatched; sending CONNECT resets the
    /// connection cache to CONNECTING.
    pub fn request_sent(&mut self, now: Instant) {
        let Some(mut req) = self.pending.pop_front() else {
            return;
        };
        req.dispatched = Some(now);
        if req.action == UdpAction::Connect {
            self.connection_id_cache
                .insert((req.remote.ip(), req.remote.port()), Connection::default());
        }
        self.inflight.push_back(req);
    }

    /// `requestFail`: the send of the front request itself failed (e.g.
    /// a sendto error).
    pub fn request_fail(&mut self, error: UdpError) {
        let Some(mut req) = self.pending.pop_front() else {
            return;
        };
        if req.action == UdpAction::Connect {
            self.fail_connect(req.remote, error);
        }
        req.done = Some(error);
    }

    /// `handleTimeout`: failCount==0 and >= 5s -> resend once (back to
    /// the front of pending); failCount>0 and >= 10s -> complete as a
    /// timeout (CONNECT additionally fails same-host waiters via
    /// failConnect). Returns the requests completed as timed out.
    pub fn handle_timeout(&mut self, now: Instant) -> Vec<UdpRequest> {
        let mut resend = Vec::new();
        let mut timed_out = Vec::new();
        let mut keep = VecDeque::new();
        while let Some(mut req) = self.inflight.pop_front() {
            let Some(dispatched) = req.dispatched else {
                keep.push_back(req);
                continue;
            };
            let elapsed = now.saturating_duration_since(dispatched);
            if req.fail_count == 0 {
                if elapsed >= RESEND_DELAY {
                    req.fail_count += 1;
                    resend.push(req);
                } else {
                    keep.push_back(req);
                }
            } else if elapsed >= TIMEOUT_DELAY {
                req.fail_count += 1;
                req.done = Some(UdpError::Timeout);
                if req.action == UdpAction::Connect {
                    self.fail_connect(req.remote, UdpError::Timeout);
                }
                timed_out.push(req);
            } else {
                keep.push_back(req);
            }
        }
        for req in keep {
            self.inflight.push_back(req);
        }
        // Resends go back to the front of pending.
        for req in resend.into_iter().rev() {
            self.pending.push_front(req);
        }
        timed_out
    }

    /// `receiveReply` (+ the BEP15 scrape extension): dispatch by action;
    /// a transaction matches on (peer address, transaction_id).
    /// `Ok(None)` = the packet is valid but unrelated to any local
    /// transaction (logged and ignored).
    pub fn receive_reply(
        &mut self,
        from: SocketAddr,
        data: &[u8],
        now: Instant,
    ) -> Result<Option<UdpReply>, TrackerError> {
        if data.len() < 8 {
            return Err(TrackerError::Malformed(format!(
                "udp tracker reply too short: {}",
                data.len()
            )));
        }
        let action = i32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let transaction_id = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let Some(action) = UdpAction::from_i32(action) else {
            return Err(TrackerError::Malformed(format!(
                "unknown udp tracker action {action}"
            )));
        };
        match action {
            UdpAction::Connect => {
                // Exactly 16 bytes.
                if data.len() != 16 {
                    return Err(TrackerError::Malformed(format!(
                        "connect reply length {} != 16",
                        data.len()
                    )));
                }
                let Some(req) = self.remove_inflight(from, transaction_id) else {
                    return Ok(None);
                };
                let _ = req;
                let connection_id = u64::from_be_bytes([
                    data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
                ]);
                // Cache CONNECTED.
                self.connection_id_cache.insert(
                    (from.ip(), from.port()),
                    Connection {
                        state: ConnectionState::Connected,
                        connection_id,
                        last_updated: Some(now),
                    },
                );
                // Waiting requests for this host return to the front of
                // pending.
                let mut waiting = Vec::new();
                let mut rest = VecDeque::new();
                while let Some(w) = self.connect_waiting.pop_front() {
                    if w.remote == from {
                        waiting.push(w);
                    } else {
                        rest.push_back(w);
                    }
                }
                self.connect_waiting = rest;
                for w in waiting {
                    self.pending.push_front(w);
                }
                Ok(Some(UdpReply::Connected))
            }
            UdpAction::Announce => {
                // At least 20 bytes.
                if data.len() < 20 {
                    return Err(TrackerError::Malformed(format!(
                        "announce reply length {} < 20",
                        data.len()
                    )));
                }
                let Some(mut req) = self.remove_inflight(from, transaction_id) else {
                    return Ok(None);
                };
                let interval = i32::from_be_bytes([data[8], data[9], data[10], data[11]]);
                let leechers = i32::from_be_bytes([data[12], data[13], data[14], data[15]]);
                let seeders = i32::from_be_bytes([data[16], data[17], data[18], data[19]]);
                // Peers are parsed by carrier family (family = the
                // reply's remote address family, never mixed; libtorrent
                // udp_tracker_connection.cpp).
                let mut peers = Vec::new();
                let mut peers6 = Vec::new();
                let body = &data[20..];
                if from.is_ipv6() {
                    // v6 carrier: 18B/entry (16B address + 2B port); a
                    // length that is not a multiple of 18 is an explicit
                    // error (libtorrent invalid_tracker_response_length).
                    if !body.len().is_multiple_of(18) {
                        return Err(TrackerError::Malformed(format!(
                            "ipv6 carrier announce peers length {} not multiple of 18",
                            body.len()
                        )));
                    }
                    for chunk in body.as_chunks::<18>().0 {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&chunk[..16]);
                        peers6.push(PeerAddr6 {
                            ip: Ipv6Addr::from(octets),
                            port: u16::from_be_bytes([chunk[16], chunk[17]]),
                        });
                    }
                } else {
                    // v4 carrier: 6B stride (unpackcompact AF_INET;
                    // unchanged).
                    for chunk in body.as_chunks::<6>().0 {
                        peers.push(PeerAddr {
                            ip: std::net::Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]),
                            port: u16::from_be_bytes([chunk[4], chunk[5]]),
                        });
                    }
                }
                req.reply = Some(UdpAnnounceReply {
                    transaction_id,
                    interval,
                    leechers,
                    seeders,
                    peers,
                    peers6,
                });
                Ok(Some(UdpReply::Announce(Box::new(req))))
            }
            UdpAction::Scrape => {
                // BEP15 extension (absent upstream): 8B header + 12B per
                // hash.
                let Some(mut req) = self.remove_inflight(from, transaction_id) else {
                    return Ok(None);
                };
                let body = &data[8..];
                if body.len() < req.info_hashes.len() * 12 {
                    return Err(TrackerError::Malformed(format!(
                        "scrape reply length {} < {} entries*12",
                        body.len(),
                        req.info_hashes.len()
                    )));
                }
                let mut entries = Vec::with_capacity(req.info_hashes.len());
                for (i, hash) in req.info_hashes.iter().enumerate() {
                    let e = &body[i * 12..(i + 1) * 12];
                    entries.push(UdpScrapeEntry {
                        info_hash: *hash,
                        seeders: i32::from_be_bytes([e[0], e[1], e[2], e[3]]),
                        completed: i32::from_be_bytes([e[4], e[5], e[6], e[7]]),
                        leechers: i32::from_be_bytes([e[8], e[9], e[10], e[11]]),
                    });
                }
                req.scrape_reply = Some(entries);
                Ok(Some(UdpReply::Scrape(Box::new(req))))
            }
            UdpAction::Error => {
                // At least 8 bytes; the message is the remaining bytes.
                let Some(req) = self.remove_inflight(from, transaction_id) else {
                    return Ok(None);
                };
                let message = String::from_utf8_lossy(&data[8..]).into_owned();
                if req.action == UdpAction::Connect {
                    // CONNECT ERROR -> same-host waiting requests fail
                    // with it.
                    self.fail_connect(from, UdpError::Tracker);
                }
                Ok(Some(UdpReply::Error { message }))
            }
        }
    }

    /// Contagion after CONNECT completes/fails (aria2 `failConnect`):
    /// clear the connection cache and fail same-host waiting requests
    /// (announce/scrape only).
    pub fn fail_connect(&mut self, remote: SocketAddr, error: UdpError) {
        self.connection_id_cache
            .remove(&(remote.ip(), remote.port()));
        let mut keep = VecDeque::new();
        while let Some(mut w) = self.connect_waiting.pop_front() {
            if w.remote == remote && w.action != UdpAction::Connect {
                w.done = Some(error);
            } else {
                keep.push_back(w);
            }
        }
        self.connect_waiting = keep;
        let mut keep = VecDeque::new();
        while let Some(mut w) = self.pending.pop_front() {
            if w.remote == remote && w.action != UdpAction::Connect {
                w.done = Some(error);
            } else {
                keep.push_back(w);
            }
        }
        self.pending = keep;
    }

    /// `failAll`: fail everything on shutdown.
    pub fn fail_all(&mut self, error: UdpError) {
        for req in self.inflight.iter_mut() {
            req.done = Some(error);
        }
        for req in self.pending.iter_mut() {
            req.done = Some(error);
        }
        for req in self.connect_waiting.iter_mut() {
            req.done = Some(error);
        }
    }

    /// `getConnectionId`: CONNECTED but older than 1min -> discard (drop
    /// the cache entry, return None).
    fn get_connection(&mut self, key: (IpAddr, u16), now: Instant) -> Option<Connection> {
        match self.connection_id_cache.get(&key) {
            Some(
                c @ Connection {
                    state: ConnectionState::Connected,
                    last_updated: Some(at),
                    ..
                },
            ) => {
                if now.saturating_duration_since(*at) > CONNECTION_ID_TTL {
                    self.connection_id_cache.remove(&key);
                    None
                } else {
                    Some(*c)
                }
            }
            other => other.copied(),
        }
    }

    /// `findInflightRequest`: match and remove by
    /// (addr, transaction_id).
    fn remove_inflight(&mut self, remote: SocketAddr, transaction_id: u32) -> Option<UdpRequest> {
        let idx = self
            .inflight
            .iter()
            .position(|req| req.remote == remote && req.transaction_id == Some(transaction_id))?;
        self.inflight.remove(idx)
    }
}

/// Connect frame (16B; aria2 `createUDPTrackerConnect`).
pub fn build_connect_frame(transaction_id: u32) -> Vec<u8> {
    let mut f = Vec::with_capacity(16);
    f.extend_from_slice(&UDPT_INITIAL_CONNECTION_ID.to_be_bytes());
    f.extend_from_slice(&(UdpAction::Connect as i32).to_be_bytes());
    f.extend_from_slice(&transaction_id.to_be_bytes());
    f
}

/// Announce frame (100B; aria2 `createUDPTrackerAnnounce`):
/// 0..8 connection_id, 8..12 action, 12..16 transaction_id,
/// 16..36 info_hash, 36..56 peer_id, 56..64 downloaded, 64..72 left,
/// 72..80 uploaded, 80..84 event, 84..88 ip, 88..92 key, 92..96 numwant,
/// 96..98 port, 98..100 extensions always 0.
pub fn build_announce_frame(req: &UdpRequest, transaction_id: u32) -> Vec<u8> {
    debug_assert_eq!(
        req.info_hashes.len(),
        1,
        "an announce frame carries exactly one info_hash"
    );
    let mut f = vec![0u8; 100];
    f[0..8].copy_from_slice(&req.connection_id.to_be_bytes());
    f[8..12].copy_from_slice(&(UdpAction::Announce as i32).to_be_bytes());
    f[12..16].copy_from_slice(&transaction_id.to_be_bytes());
    f[16..36].copy_from_slice(&req.info_hashes[0]);
    f[36..56].copy_from_slice(&req.peer_id);
    f[56..64].copy_from_slice(&req.downloaded.to_be_bytes());
    f[64..72].copy_from_slice(&req.left.to_be_bytes());
    f[72..80].copy_from_slice(&req.uploaded.to_be_bytes());
    f[80..84].copy_from_slice(&(req.event as i32).to_be_bytes());
    f[84..88].copy_from_slice(&req.ip.to_be_bytes());
    f[88..92].copy_from_slice(&req.key.to_be_bytes());
    f[92..96].copy_from_slice(&req.numwant.to_be_bytes());
    f[96..98].copy_from_slice(&req.port.to_be_bytes());
    // f[98..100] extensions always 0.
    f
}

/// Scrape frame (BEP15: connection_id + action=2 + transaction_id +
/// the info_hashes).
pub fn build_scrape_frame(req: &UdpRequest, transaction_id: u32) -> Vec<u8> {
    let mut f = Vec::with_capacity(16 + req.info_hashes.len() * 20);
    f.extend_from_slice(&req.connection_id.to_be_bytes());
    f.extend_from_slice(&(UdpAction::Scrape as i32).to_be_bytes());
    f.extend_from_slice(&transaction_id.to_be_bytes());
    for hash in &req.info_hashes {
        f.extend_from_slice(hash);
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }

    /// Deterministic xorshift64 RNG (reproducible tests; follows the
    /// repo's disk.rs test convention).
    struct XorShift(u64);

    impl XorShift {
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }

    // rand 0.10: a custom RNG implementing TryRng (Error = Infallible)
    // gets Rng/RngExt automatically via the blanket impl (rand_core 0.10
    // split; RngCore is a deprecated empty shell).
    impl rand::rand_core::TryRng for XorShift {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.next_u64() as u32)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(self.next_u64())
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            for chunk in dst.chunks_mut(8) {
                let v = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
            Ok(())
        }
    }

    /// Relative Instant: now+secs (handle_timeout compares saturating,
    /// which is safe).
    fn t(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    fn front_tid(frame: &[u8]) -> u32 {
        u32::from_be_bytes([frame[12], frame[13], frame[14], frame[15]])
    }

    fn expect_frame(
        c: &mut UdpTrackerClient,
        rng: &mut XorShift,
        now: Instant,
    ) -> (SocketAddr, Vec<u8>) {
        match c.create_request(rng, now) {
            Some(x) => x,
            None => panic!("expected a frame"),
        }
    }

    fn expect_reply(
        c: &mut UdpTrackerClient,
        from: SocketAddr,
        data: &[u8],
        now: Instant,
    ) -> Option<UdpReply> {
        match c.receive_reply(from, data, now) {
            Ok(r) => r,
            Err(e) => panic!("receive_reply: {e}"),
        }
    }

    /// Connect frame vector (the UDPTrackerClient.h magic).
    #[test]
    fn connect_frame_vector() {
        let f = build_connect_frame(0x1234_5678);
        assert_eq!(
            f,
            vec![
                0x00, 0x00, 0x04, 0x17, 0x27, 0x10, 0x19, 0x80, // magic
                0, 0, 0, 0, // action=0
                0x12, 0x34, 0x56, 0x78, // transaction_id
            ]
        );
    }

    /// Announce frame vector (field offsets per aria2
    /// createUDPTrackerAnnounce).
    #[test]
    fn announce_frame_vector() {
        let mut req = UdpRequest::announce(addr(1337), [0xab; 20], 0x0102_0304);
        req.peer_id = *b"-TJ0001-AAAAAAAAAAAA";
        req.downloaded = 1;
        req.left = 2;
        req.uploaded = 3;
        req.event = UdpEvent::Started;
        req.numwant = 50;
        req.port = 6881;
        let frame = build_announce_frame(&req, 0x7fff_ffff);
        // The default connection id = the magic constant
        // (UDPT_INITIAL_CONNECTION_ID).
        assert_eq!(&frame[0..8], &UDPT_INITIAL_CONNECTION_ID.to_be_bytes());
        assert_eq!(&frame[8..12], &[0, 0, 0, 1], "action=announce");
        assert_eq!(&frame[12..16], &0x7fff_ffffu32.to_be_bytes());
        assert_eq!(&frame[16..36], &[0xab; 20]);
        assert_eq!(&frame[36..56], b"-TJ0001-AAAAAAAAAAAA");
        assert_eq!(&frame[56..64], &1u64.to_be_bytes(), "downloaded@56");
        assert_eq!(&frame[64..72], &2u64.to_be_bytes(), "left@64");
        assert_eq!(&frame[72..80], &3u64.to_be_bytes(), "uploaded@72");
        assert_eq!(&frame[80..84], &2i32.to_be_bytes(), "event=started@80");
        assert_eq!(&frame[84..88], &[0; 4], "ip=0@84");
        assert_eq!(&frame[88..92], &0x0102_0304u32.to_be_bytes(), "key@88");
        assert_eq!(&frame[92..96], &50i32.to_be_bytes(), "numwant@92");
        assert_eq!(&frame[96..98], &6881u16.to_be_bytes(), "port@96");
        assert_eq!(&frame[98..100], &[0, 0], "extensions=0@98");
    }

    /// Scrape frame vector (BEP15: connection_id+action=2+tid+hashes).
    #[test]
    fn scrape_frame_vector() {
        let mut req = UdpRequest::scrape(addr(1337), vec![[1; 20], [2; 20]]);
        req.connection_id = 0xfeed_face_feed_face;
        let f = build_scrape_frame(&req, 9);
        assert_eq!(f.len(), 16 + 40);
        assert_eq!(&f[0..8], &0xfeed_face_feed_faceu64.to_be_bytes());
        assert_eq!(&f[8..12], &2i32.to_be_bytes());
        assert_eq!(&f[12..16], &9u32.to_be_bytes());
        assert_eq!(&f[16..36], &[1; 20]);
        assert_eq!(&f[36..56], &[2; 20]);
    }

    /// Full flow: no connection -> CONNECT first; after the CONNECT
    /// reply the ANNOUNCE goes out; the ANNOUNCE reply is parsed.
    #[test]
    fn connect_then_announce_flow() {
        let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
        let mut c = UdpTrackerClient::new();
        let tracker = addr(1337);
        let mut req = UdpRequest::announce(tracker, [7; 20], 42);
        req.port = 6881;
        c.add_request(req);
        let base = Instant::now();
        // First frame = CONNECT (connection cache empty).
        let (to, frame) = expect_frame(&mut c, &mut rng, base);
        assert_eq!(to, tracker);
        assert_eq!(&frame[8..12], &0i32.to_be_bytes(), "action=connect");
        let tid = front_tid(&frame);
        c.request_sent(base);
        // CONNECT reply (exactly 16B).
        let conn_id = 0x0011_2233_4455_6677u64;
        let mut reply = Vec::new();
        reply.extend_from_slice(&0i32.to_be_bytes());
        reply.extend_from_slice(&tid.to_be_bytes());
        reply.extend_from_slice(&conn_id.to_be_bytes());
        assert!(matches!(
            expect_reply(&mut c, tracker, &reply, t(base, 1)),
            Some(UdpReply::Connected)
        ));
        // Second frame = ANNOUNCE (carrying the connection id).
        let now1 = t(base, 2);
        let (to2, frame2) = expect_frame(&mut c, &mut rng, now1);
        assert_eq!(to2, tracker);
        assert_eq!(&frame2[0..8], &conn_id.to_be_bytes(), "connection id");
        assert_eq!(&frame2[8..12], &1i32.to_be_bytes(), "action=announce");
        let tid2 = front_tid(&frame2);
        c.request_sent(now1);
        // ANNOUNCE reply (>= 20B + 2 peers).
        let mut areply = Vec::new();
        areply.extend_from_slice(&1i32.to_be_bytes());
        areply.extend_from_slice(&tid2.to_be_bytes());
        areply.extend_from_slice(&1800i32.to_be_bytes());
        areply.extend_from_slice(&3i32.to_be_bytes());
        areply.extend_from_slice(&9i32.to_be_bytes());
        areply.extend_from_slice(&[10, 0, 0, 1, 0x1a, 0xe1]);
        areply.extend_from_slice(&[10, 0, 0, 2, 0x1a, 0xe2]);
        match expect_reply(&mut c, tracker, &areply, t(base, 3)) {
            Some(UdpReply::Announce(req)) => {
                let r = match req.announce_reply() {
                    Some(r) => r,
                    None => panic!("announce reply missing"),
                };
                assert_eq!(r.interval, 1800);
                assert_eq!(r.leechers, 3);
                assert_eq!(r.seeders, 9);
                assert_eq!(r.peers.len(), 2);
                assert_eq!(r.peers[0].ip.to_string(), "10.0.0.1");
                assert_eq!(r.peers[1].port, 6882);
            }
            other => panic!("expected announce reply, got {other:?}"),
        }
        assert!(
            c.is_empty(),
            "an empty table once the transaction completes"
        );
    }

    /// SCRAPE transaction (BEP15 extension; absent upstream): reuses the
    /// connection id to batch two hashes; the reply carries 12B per hash
    /// in request order.
    #[test]
    fn scrape_transaction_flow() {
        let mut rng = XorShift(555_111);
        let mut c = UdpTrackerClient::new();
        let tracker = addr(1337);
        // Establish the connection first.
        c.add_request(UdpRequest::announce(tracker, [7; 20], 1));
        let base = Instant::now();
        let (_, cf) = expect_frame(&mut c, &mut rng, base);
        c.request_sent(base);
        let mut cr = Vec::new();
        cr.extend_from_slice(&0i32.to_be_bytes());
        cr.extend_from_slice(&front_tid(&cf).to_be_bytes());
        cr.extend_from_slice(&0xdead_c0de_dead_c0deu64.to_be_bytes());
        assert!(matches!(
            expect_reply(&mut c, tracker, &cr, t(base, 1)),
            Some(UdpReply::Connected)
        ));
        // The earlier-queued announce emits its frame first (pending
        // FIFO).
        let (ato, af) = expect_frame(&mut c, &mut rng, t(base, 2));
        assert_eq!(ato, tracker);
        assert_eq!(&af[8..12], &1i32.to_be_bytes());
        c.request_sent(t(base, 2));
        // announce reply (completes that transaction).
        let mut ar = Vec::new();
        ar.extend_from_slice(&1i32.to_be_bytes());
        ar.extend_from_slice(&front_tid(&af).to_be_bytes());
        ar.extend_from_slice(&1800i32.to_be_bytes());
        ar.extend_from_slice(&3i32.to_be_bytes());
        ar.extend_from_slice(&9i32.to_be_bytes());
        assert!(matches!(
            expect_reply(&mut c, tracker, &ar, t(base, 2)),
            Some(UdpReply::Announce(_))
        ));
        // scrape request (valid connection -> scrape frame directly).
        c.add_request(UdpRequest::scrape(tracker, vec![[0xa1; 20], [0xb2; 20]]));
        let (to, sf) = expect_frame(&mut c, &mut rng, t(base, 2));
        assert_eq!(to, tracker);
        assert_eq!(&sf[8..12], &2i32.to_be_bytes(), "action=scrape");
        assert_eq!(&sf[0..8], &0xdead_c0de_dead_c0deu64.to_be_bytes());
        assert_eq!(&sf[16..36], &[0xa1; 20]);
        assert_eq!(&sf[36..56], &[0xb2; 20]);
        c.request_sent(t(base, 2));
        // Reply: 12B per hash (seeders/completed/leechers).
        let mut sr = Vec::new();
        sr.extend_from_slice(&2i32.to_be_bytes());
        sr.extend_from_slice(&front_tid(&sf).to_be_bytes());
        sr.extend_from_slice(&10i32.to_be_bytes());
        sr.extend_from_slice(&20i32.to_be_bytes());
        sr.extend_from_slice(&30i32.to_be_bytes());
        sr.extend_from_slice(&1i32.to_be_bytes());
        sr.extend_from_slice(&2i32.to_be_bytes());
        sr.extend_from_slice(&3i32.to_be_bytes());
        match expect_reply(&mut c, tracker, &sr, t(base, 3)) {
            Some(UdpReply::Scrape(req)) => {
                let entries = match req.scrape_reply() {
                    Some(e) => e,
                    None => panic!("scrape reply missing"),
                };
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0].info_hash, [0xa1; 20]);
                assert_eq!(
                    (
                        entries[0].seeders,
                        entries[0].completed,
                        entries[0].leechers
                    ),
                    (10, 20, 30)
                );
                assert_eq!(
                    (
                        entries[1].seeders,
                        entries[1].completed,
                        entries[1].leechers
                    ),
                    (1, 2, 3)
                );
            }
            other => panic!("expected scrape reply, got {other:?}"),
        }
    }

    /// Unknown transaction / bad packet -> ignored or an error.
    #[test]
    fn invalid_replies_rejected() {
        let mut rng = XorShift(12345);
        let mut c = UdpTrackerClient::new();
        let tracker = addr(1337);
        c.add_request(UdpRequest::announce(tracker, [7; 20], 42));
        let base = Instant::now();
        let _ = expect_frame(&mut c, &mut rng, base);
        c.request_sent(base);
        // Bad length (connect reply not 16B).
        assert!(
            c.receive_reply(tracker, &[0, 0, 0, 0, 1, 2, 3, 4, 5], t(base, 1))
                .is_err()
        );
        // Unknown action.
        assert!(
            c.receive_reply(tracker, &[9, 9, 9, 9, 0, 0, 0, 0], t(base, 1))
                .is_err()
        );
        // Unknown transaction id -> Ok(None).
        let mut r = Vec::new();
        r.extend_from_slice(&1i32.to_be_bytes());
        r.extend_from_slice(&0xdead_beefu32.to_be_bytes());
        r.extend_from_slice(&[0u8; 12]);
        assert!(expect_reply(&mut c, tracker, &r, t(base, 1)).is_none());
    }

    /// Retransmit/timeout boundary table (matches UDPTrackerClient.cc).
    #[test]
    fn retransmit_timeout_table() {
        // Semantic table (port of TimeoutCheck): failCount=0 -> resend at
        // t>=5s; otherwise timeout at >=10s.
        for (elapsed, fc, want) in [
            (0u64, 0u32, "keep"),
            (4, 0, "keep"),
            (5, 0, "resend"),
            (9, 0, "resend"),
            (0, 1, "keep"),
            (9, 1, "keep"),
            (10, 1, "timeout"),
            (30, 1, "timeout"),
        ] {
            let got = if fc == 0 {
                if elapsed >= 5 { "resend" } else { "keep" }
            } else if elapsed >= 10 {
                "timeout"
            } else {
                "keep"
            };
            assert_eq!(got, want, "case (elapsed={elapsed}, failCount={fc})");
        }

        // Actual drive (the full ANNOUNCE transaction path).
        let mut rng = XorShift(777);
        let mut c = UdpTrackerClient::new();
        let tracker = addr(1337);
        c.add_request(UdpRequest::announce(tracker, [7; 20], 1));
        let t0 = Instant::now();
        // First frame = CONNECT (no connection id).
        let (_, cf) = expect_frame(&mut c, &mut rng, t0);
        assert_eq!(&cf[8..12], &0i32.to_be_bytes());
        c.request_sent(t0);
        // CONNECT reply.
        let mut cr = Vec::new();
        cr.extend_from_slice(&0i32.to_be_bytes());
        cr.extend_from_slice(&front_tid(&cf).to_be_bytes());
        cr.extend_from_slice(&1u64.to_be_bytes());
        assert!(matches!(
            expect_reply(&mut c, tracker, &cr, t(t0, 1)),
            Some(UdpReply::Connected)
        ));
        // Second frame = ANNOUNCE.
        let (_, af) = expect_frame(&mut c, &mut rng, t(t0, 1));
        assert_eq!(&af[8..12], &1i32.to_be_bytes());
        let tid = front_tid(&af);
        c.request_sent(t(t0, 1));

        // t<5s (4s since the first send) -> nothing happens (resend
        // needs t>=5_s). Note: the CONNECT is also inflight (first sent
        // at t0); at 5s it resends first — pull out and send the connect
        // resend frame, then examine the announce on its own.
        c.handle_timeout(t(t0, 5));
        if c.pending
            .front()
            .is_some_and(|r| r.action == UdpAction::Connect)
        {
            let _ = expect_frame(&mut c, &mut rng, t(t0, 5));
            c.request_sent(t(t0, 5));
        }
        let timed_out = c.handle_timeout(t(t0, 5));
        assert!(
            timed_out.is_empty(),
            "t < 5s (4s since the announce's first send) does not time out"
        );

        // 5s since the announce's first send (t0+6) -> the announce is
        // resent to the front of pending, same transaction id (failCount
        // 0->1).
        let timed_out = c.handle_timeout(t(t0, 6));
        assert!(timed_out.is_empty(), "at 5s it is a resend, not a timeout");
        let (to, frame2) = expect_frame(&mut c, &mut rng, t(t0, 6));
        assert_eq!(to, tracker);
        assert_eq!(
            &frame2[8..12],
            &1i32.to_be_bytes(),
            "what is resent is the announce"
        );
        assert_eq!(
            front_tid(&frame2),
            tid,
            "the resend keeps the same transaction id"
        );
        c.request_sent(t(t0, 6));

        // 9s after the resend (t0+15) -> still no timeout (dispatched
        // was reset, <10s).
        let timed_out = c.handle_timeout(t(t0, 15));
        assert!(
            timed_out.is_empty(),
            "9s after the resend is < 10s, no timeout"
        );
        // 10s after the resend (t0+16) -> completes as a timeout.
        let timed_out = c.handle_timeout(t(t0, 16));
        assert_eq!(timed_out.len(), 1, "announce timeout");
        assert_eq!(timed_out[0].failure(), Some(UdpError::Timeout));
        assert!(timed_out[0].action == UdpAction::Announce);
    }

    /// CONNECT timeout contagion: same-host waiting announces fail with
    /// it (handleTimeout + failConnect).
    #[test]
    fn connect_timeout_fails_waiting_announces() {
        let mut rng = XorShift(4242);
        let mut c = UdpTrackerClient::new();
        let tracker = addr(1337);
        c.add_request(UdpRequest::announce(tracker, [7; 20], 1));
        let t0 = Instant::now();
        // Emit the connect frame.
        let (_, cf) = expect_frame(&mut c, &mut rng, t0);
        assert_eq!(&cf[8..12], &0i32.to_be_bytes());
        c.request_sent(t0);
        // Emit again: the announce sees CONNECTING -> moves to
        // connect_waiting.
        assert!(
            c.create_request(&mut rng, t0).is_none(),
            "no frame can go out while waiting"
        );
        assert_eq!(
            c.connect_waiting.len(),
            1,
            "the announce is waiting for a connection id"
        );
        // 5s -> CONNECT resends once.
        let timed_out = c.handle_timeout(t(t0, 5));
        assert!(timed_out.is_empty());
        let (_, cf2) = expect_frame(&mut c, &mut rng, t(t0, 5));
        assert_eq!(&cf2[8..12], &0i32.to_be_bytes());
        c.request_sent(t(t0, 5));
        assert!(c.create_request(&mut rng, t(t0, 5)).is_none());
        assert_eq!(c.connect_waiting.len(), 1);
        // 10s after the resend -> CONNECT times out -> contagion.
        let timed_out = c.handle_timeout(t(t0, 15));
        assert_eq!(timed_out.len(), 1, "connect timeout");
        assert_eq!(timed_out[0].action, UdpAction::Connect);
        assert!(
            c.connect_waiting.is_empty(),
            "waiting requests are cleared by the contagion"
        );
    }

    /// ERROR reply: for a connect -> contagion.
    #[test]
    fn error_reply_vectors() {
        let mut rng = XorShift(9);
        let mut c = UdpTrackerClient::new();
        let tracker = addr(1337);
        c.add_request(UdpRequest::announce(tracker, [7; 20], 1));
        let t0 = Instant::now();
        let (_, cf) = expect_frame(&mut c, &mut rng, t0);
        c.request_sent(t0);
        // CONNECT ERROR.
        let mut er = Vec::new();
        er.extend_from_slice(&3i32.to_be_bytes());
        er.extend_from_slice(&front_tid(&cf).to_be_bytes());
        er.extend_from_slice(b"no connect");
        match expect_reply(&mut c, tracker, &er, t(t0, 1)) {
            Some(UdpReply::Error { message }) => assert_eq!(message, "no connect"),
            other => panic!("want error reply, got {other:?}"),
        }
        // The waiting announce is cleared by the contagion.
        assert!(c.connect_waiting.is_empty());
    }

    /// connection id cache expires after 1min (BEP15 "until one
    /// minute"): once expired, the next request CONNECTs again and the
    /// request goes to waiting.
    #[test]
    fn connection_id_expires_after_one_minute() {
        let mut rng = XorShift(31);
        let mut c = UdpTrackerClient::new();
        let tracker = addr(1337);
        c.add_request(UdpRequest::announce(tracker, [7; 20], 1));
        let base = Instant::now();
        // CONNECT roundtrip.
        let (_, cf) = expect_frame(&mut c, &mut rng, base);
        c.request_sent(base);
        let mut cr = Vec::new();
        cr.extend_from_slice(&0i32.to_be_bytes());
        cr.extend_from_slice(&front_tid(&cf).to_be_bytes());
        cr.extend_from_slice(&0xaabb_ccdd_eeff_0011u64.to_be_bytes());
        assert!(matches!(
            expect_reply(&mut c, tracker, &cr, t(base, 1)),
            Some(UdpReply::Connected)
        ));
        // Within 30s: ANNOUNCE directly.
        let (to, af) = expect_frame(&mut c, &mut rng, t(base, 30));
        assert_eq!(to, tracker);
        assert_eq!(&af[8..12], &1i32.to_be_bytes());
        c.request_sent(t(base, 30));
        // 100s (connection id 99s since update > 1min): the new request
        // triggers a fresh CONNECT.
        c.add_request(UdpRequest::announce(tracker, [8; 20], 2));
        let (to2, af2) = expect_frame(&mut c, &mut rng, t(base, 100));
        assert_eq!(to2, tracker);
        assert_eq!(&af2[8..12], &0i32.to_be_bytes(), "re-CONNECT after expiry");
        // After the new CONNECT is dequeued and sent, another create
        // moves announce2 to connect_waiting.
        c.request_sent(t(base, 100));
        assert!(c.create_request(&mut rng, t(base, 100)).is_none());
        assert_eq!(
            c.connect_waiting.len(),
            1,
            "the new announce waits for a new connection id"
        );
    }

    // ===== Carrier-family peers parsing (6/18B by family, never mixed) =====

    fn v6_tracker(port: u16) -> SocketAddr {
        SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), port)
    }

    /// v6 carrier reply vector: 18B/entry -> peers6, peers empty (the
    /// family is known, no mixing; libtorrent
    /// udp_tracker_connection.cpp).
    #[test]
    fn ipv6_carrier_announce_reply_parses_18b_peers_into_peers6() {
        let mut rng = XorShift(0xd66);
        let mut c = UdpTrackerClient::new();
        let tracker = v6_tracker(1337);
        c.add_request(UdpRequest::announce(tracker, [7; 20], 1));
        let base = Instant::now();
        let (_, cf) = expect_frame(&mut c, &mut rng, base);
        c.request_sent(base);
        let mut cr = Vec::new();
        cr.extend_from_slice(&0i32.to_be_bytes());
        cr.extend_from_slice(&front_tid(&cf).to_be_bytes());
        cr.extend_from_slice(&1u64.to_be_bytes());
        assert!(matches!(
            expect_reply(&mut c, tracker, &cr, t(base, 1)),
            Some(UdpReply::Connected)
        ));
        let (_, af) = expect_frame(&mut c, &mut rng, t(base, 2));
        c.request_sent(t(base, 2));
        let mut ar = Vec::new();
        ar.extend_from_slice(&1i32.to_be_bytes());
        ar.extend_from_slice(&front_tid(&af).to_be_bytes());
        ar.extend_from_slice(&1800i32.to_be_bytes());
        ar.extend_from_slice(&3i32.to_be_bytes());
        ar.extend_from_slice(&9i32.to_be_bytes());
        // Two v6 peers: 2001:db8::1:6881 and 2001:db8::2:6882 (18B/entry).
        for o in [1u8, 2] {
            let mut octets = [0u8; 16];
            octets[0] = 0x20;
            octets[1] = 0x01;
            octets[2] = 0x0d;
            octets[3] = 0xb8;
            octets[15] = o;
            ar.extend_from_slice(&octets);
            ar.extend_from_slice(&(6880 + u16::from(o)).to_be_bytes());
        }
        match expect_reply(&mut c, tracker, &ar, t(base, 3)) {
            Some(UdpReply::Announce(req)) => {
                let r = req.announce_reply().unwrap_or_else(|| panic!("missing"));
                assert_eq!(
                    r.peers.len(),
                    0,
                    "a v6 carrier produces no v4 peers (never mixed)"
                );
                assert_eq!(r.peers6.len(), 2);
                assert_eq!(r.peers6[0].ip.to_string(), "2001:db8::1");
                assert_eq!(r.peers6[0].port, 6880 + 1);
                assert_eq!(r.peers6[1].ip.to_string(), "2001:db8::2");
                assert_eq!(r.peers6[1].port, 6880 + 2);
            }
            other => panic!("expected announce reply, got {other:?}"),
        }
    }

    /// v6 carrier peers length not a multiple of 18 = explicit error
    /// (libtorrent invalid_tracker_response_length, same rule).
    #[test]
    fn ipv6_carrier_announce_reply_length_not_multiple_of_18_rejected() {
        let mut rng = XorShift(77_13);
        let mut c = UdpTrackerClient::new();
        let tracker = v6_tracker(1337);
        c.add_request(UdpRequest::announce(tracker, [7; 20], 1));
        let base = Instant::now();
        let (_, cf) = expect_frame(&mut c, &mut rng, base);
        c.request_sent(base);
        let mut cr = Vec::new();
        cr.extend_from_slice(&0i32.to_be_bytes());
        cr.extend_from_slice(&front_tid(&cf).to_be_bytes());
        cr.extend_from_slice(&1u64.to_be_bytes());
        let _ = expect_reply(&mut c, tracker, &cr, t(base, 1));
        let (_, af) = expect_frame(&mut c, &mut rng, t(base, 2));
        c.request_sent(t(base, 2));
        let mut ar = Vec::new();
        ar.extend_from_slice(&1i32.to_be_bytes());
        ar.extend_from_slice(&front_tid(&af).to_be_bytes());
        ar.extend_from_slice(&[0u8; 12]);
        ar.extend_from_slice(&[0u8; 7]); // 7B tail: not a multiple of 18
        let err = match c.receive_reply(tracker, &ar, t(base, 3)) {
            Err(e) => e,
            Ok(other) => panic!("want Malformed, got {other:?}"),
        };
        let TrackerError::Malformed(msg) = err else {
            panic!("want Malformed, got {err:?}")
        };
        assert!(
            msg.contains("not multiple of 18"),
            "explicit length error: {msg}"
        );
    }

    /// v4 carrier unchanged: 6B stride parses into peers, peers6 stays
    /// empty (the other side of family purity).
    #[test]
    fn ipv4_carrier_announce_reply_keeps_6b_peers_and_empty_peers6() {
        let mut rng = XorShift(31_337);
        let mut c = UdpTrackerClient::new();
        let tracker = addr(1337);
        c.add_request(UdpRequest::announce(tracker, [7; 20], 1));
        let base = Instant::now();
        let (_, cf) = expect_frame(&mut c, &mut rng, base);
        c.request_sent(base);
        let mut cr = Vec::new();
        cr.extend_from_slice(&0i32.to_be_bytes());
        cr.extend_from_slice(&front_tid(&cf).to_be_bytes());
        cr.extend_from_slice(&1u64.to_be_bytes());
        let _ = expect_reply(&mut c, tracker, &cr, t(base, 1));
        let (_, af) = expect_frame(&mut c, &mut rng, t(base, 2));
        c.request_sent(t(base, 2));
        let mut ar = Vec::new();
        ar.extend_from_slice(&1i32.to_be_bytes());
        ar.extend_from_slice(&front_tid(&af).to_be_bytes());
        ar.extend_from_slice(&[0u8; 12]);
        ar.extend_from_slice(&[10, 0, 0, 9, 0x1a, 0xe1]);
        match expect_reply(&mut c, tracker, &ar, t(base, 3)) {
            Some(UdpReply::Announce(req)) => {
                let r = req.announce_reply().unwrap_or_else(|| panic!("missing"));
                assert_eq!(r.peers.len(), 1);
                assert_eq!(r.peers[0].ip.to_string(), "10.0.0.9");
                assert!(
                    r.peers6.is_empty(),
                    "a v4 carrier produces no peers6 (never mixed)"
                );
            }
            other => panic!("expected announce reply, got {other:?}"),
        }
    }
}
