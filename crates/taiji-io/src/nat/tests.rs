//! NAT tests.
//!
//! - **Packet vectors**: 13 NAT-PMP codec vectors, each annotated with its
//!   RFC 6886 section;
//! - **Table-driven**: retransmission schedule (§3.1), renewal delay
//!   (SPEC §6.8 + RFC §3.3), round backoff (local policy), epoch regression
//!   (§3.6);
//! - **Mock four-path** (in-process loopback, no real network): map /
//!   renew / conflict (occupied port) / device-offline degradation,
//!   exercised over both NAT-PMP (UDP packets) and IGD (local HTTP/XML);
//! - **Out of scope**: real-router interop (SSDP multicast discovery,
//!   gateway announcement listening) — environment-dependent, not a
//!   milestone gate.
//!
//! Time: mocks use real loopback I/O (sub-millisecond RTT) with 30-50ms
//! timer windows (~100x margin); no paused virtual clock — auto-advance
//! would skip timer windows before real I/O completes and is unreliable
//! alongside sockets. Renewal/backoff waits total ~3s real time.
//!
//! Upstream anchor mapping: docs/design/io.md

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use super::igd;
use super::natpmp::{
    self, DecodeError, Protocol, RESULT_NETWORK_FAILURE, RESULT_NOT_AUTHORIZED,
    RESULT_OUT_OF_RESOURCES, RESULT_UNSUPPORTED_VERSION, Reply, Request,
};
use super::{NatConfig, NatEvent, NatSnapshot};

// ---------------------------------------------------------------------------
// NAT-PMP packet vectors (each annotated with its RFC 6886 section)
// ---------------------------------------------------------------------------

/// Vector 1 (§3.2): external address request = 2B `[Vers=0, OP=0]`.
#[test]
fn vector_01_external_address_request() {
    let enc = Request::ExternalAddress.encode();
    assert_eq!(enc, vec![0x00, 0x00]);
}

/// Vector 2 (§3.2): address reply, 12B — result 0 / epoch / external address.
#[test]
fn vector_02_external_address_reply() {
    // [Vers=0, OP=128, Result=0, SSSoE=1000, 81.13.5.1]
    let raw = [0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE8, 81, 13, 5, 1];
    let reply = natpmp::decode_reply(&raw).unwrap_or_else(|e| panic!("decode: {e}"));
    match reply {
        Reply::ExternalAddress {
            result,
            epoch_secs,
            address,
        } => {
            assert_eq!(result, 0);
            assert_eq!(epoch_secs, 1000);
            assert_eq!(address, std::net::Ipv4Addr::new(81, 13, 5, 1));
        }
        other => panic!("wrong reply kind: {other:?}"),
    }
}

/// Vector 3 (§3.3): Map UDP request, 12B — internal 6881 / suggested 6881 /
/// lifetime 3600 (big endian; Reserved must be zero).
#[test]
fn vector_03_map_udp_request() {
    let enc = Request::Map(natpmp::MapRequest {
        protocol: Protocol::Udp,
        internal_port: 6881,
        suggested_external_port: 6881,
        lifetime_secs: 3600,
    })
    .encode();
    assert_eq!(
        enc,
        vec![
            0x00, // Vers = 0
            0x01, // OP = 1 (Map UDP)
            0x00, 0x00, // Reserved u16 = 0 (§3.3 MUST, lower 16 bits of the 32-bit row)
            0x1A, 0xE1, // Internal Port = 6881
            0x1A, 0xE1, // Suggested External Port = 6881
            0x00, 0x00, 0x0E, 0x10, // Lifetime = 3600
        ]
    );
    assert_eq!(enc.len(), 12, "§3.3 map request = 12B");
}

/// Vector 4 (§3.3): Map TCP request — opcode 2 distinguishes the protocol.
#[test]
fn vector_04_map_tcp_request() {
    let enc = Request::Map(natpmp::MapRequest {
        protocol: Protocol::Tcp,
        internal_port: 6881,
        suggested_external_port: 0, // §3.3: 0 = gateway's choice
        lifetime_secs: 7200,
    })
    .encode();
    assert_eq!(enc[1], 0x02, "OP = 2 (Map TCP)");
    assert_eq!(&enc[6..8], &[0x00, 0x00], "suggested external = 0");
    assert_eq!(&enc[8..12], &[0x00, 0x00, 0x1C, 0x20], "lifetime 7200");
}

/// Vector 5 (§3.3): map reply, 16B — external port granted as requested.
#[test]
fn vector_05_map_reply_granted() {
    // [Vers=0, OP=129, Result=0, SSSoE=10932, internal 6881, external 6881, lifetime 3600]
    let raw = [
        0x00, 0x81, 0x00, 0x00, 0x00, 0x00, 0x2A, 0x94, 0x1A, 0xE1, 0x1A, 0xE1, 0x00, 0x00, 0x0E,
        0x10,
    ];
    let reply = natpmp::decode_reply(&raw).unwrap_or_else(|e| panic!("decode: {e}"));
    match reply {
        Reply::Map {
            protocol,
            result,
            epoch_secs,
            internal_port,
            external_port,
            lifetime_secs,
        } => {
            assert_eq!(protocol, Protocol::Udp);
            assert_eq!(result, 0);
            assert_eq!(epoch_secs, 0x2A94);
            assert_eq!(internal_port, 6881);
            assert_eq!(external_port, 6881);
            assert_eq!(lifetime_secs, 3600);
            assert!(reply.success());
            assert_eq!(reply.opcode(), 0x80 | 1);
        }
        other => panic!("wrong reply kind: {other:?}"),
    }
}

/// Vector 6 (§3.3): gateway "MUST return an available external port" — the
/// map reply carries an external port different from the request (the
/// protocol fact behind the conflict path).
#[test]
fn vector_06_map_reply_reassigned_port() {
    // TCP map: OP=130; external 6881 occupied, gateway assigns 40001.
    let raw = [
        0x00, 0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x1A, 0xE1, 0x9C, 0x41, 0x00, 0x00, 0x0E,
        0x10,
    ];
    let reply = natpmp::decode_reply(&raw).unwrap_or_else(|e| panic!("decode: {e}"));
    match reply {
        Reply::Map {
            protocol,
            external_port,
            ..
        } => {
            assert_eq!(protocol, Protocol::Tcp);
            assert_eq!(external_port, 40001);
        }
        other => panic!("wrong reply kind: {other:?}"),
    }
}

/// Vector 7 (§3.5): error reply result=2 Not Authorized — a map error reply
/// must still echo the internal port (§3.5 "The Internal Port MUST be set
/// to the client's requested Internal Port").
#[test]
fn vector_07_map_reply_not_authorized() {
    let raw = [
        0x00, 0x81, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x1A, 0xE1, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let reply = natpmp::decode_reply(&raw).unwrap_or_else(|e| panic!("decode: {e}"));
    assert_eq!(reply.result(), RESULT_NOT_AUTHORIZED);
    assert!(!reply.success());
    match reply {
        Reply::Map { internal_port, .. } => assert_eq!(internal_port, 6881),
        other => panic!("wrong reply kind: {other:?}"),
    }
}

/// Vector 8 (§3.5): Unsupported Version reply, 8B `[0, 0, Result=1, SSSoE]`.
/// Its opcode lacks the response bit (the special form answering a "wrong
/// version" request) — this client only sends version 0 and never receives
/// it; [`natpmp::decode_reply`] rejects it as a non-response.
#[test]
fn vector_08_unsupported_version_reply() {
    let raw = [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2A];
    // OP=0 has no response bit => undecodable as a reply for this
    // version-0-only client.
    assert_eq!(
        natpmp::decode_reply(&raw),
        Err(DecodeError::NotAResponse(0x00)),
    );
    // Field semantics check (byte-for-byte against the spec example):
    assert_eq!(
        raw[2..4],
        [0x00, 0x01],
        "Result Code = 1 (Unsupported Version)"
    );
    assert_eq!(RESULT_UNSUPPORTED_VERSION, 1);
}

/// Vector 9 (§3.4): delete request = lifetime 0 and suggested external 0
/// (both MUSTs).
#[test]
fn vector_09_delete_request() {
    let enc = Request::unmap(Protocol::Udp, 6881).encode();
    assert_eq!(
        enc,
        vec![
            0x00, 0x01, // Vers 0 / OP 1
            0x00, 0x00, // Reserved u16 = 0
            0x1A, 0xE1, // internal 6881
            0x00, 0x00, // suggested external = 0 (§3.4 MUST)
            0x00, 0x00, 0x00, 0x00, // lifetime = 0 (§3.4 MUST)
        ]
    );
}

/// Vector 10 (§3.4): delete success reply — result 0 + requested internal
/// port + external 0 + lifetime 0; deleting a nonexistent mapping MUST also
/// answer as success.
#[test]
fn vector_10_delete_reply() {
    let raw = [
        0x00, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x1A, 0xE1, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let reply = natpmp::decode_reply(&raw).unwrap_or_else(|e| panic!("decode: {e}"));
    match reply {
        Reply::Map {
            external_port,
            lifetime_secs,
            ..
        } => {
            assert_eq!(external_port, 0);
            assert_eq!(lifetime_secs, 0);
        }
        other => panic!("wrong reply kind: {other:?}"),
    }
}

/// Vector 11 (§3.5): Network Failure (3) / Out of resources (4) result
/// codes.
#[test]
fn vector_11_error_result_codes() {
    let mk = |result: u16| {
        let mut raw = vec![0x00, 0x81];
        raw.extend_from_slice(&result.to_be_bytes());
        raw.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // epoch
        raw.extend_from_slice(&[0x1A, 0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        raw
    };
    let net_fail =
        natpmp::decode_reply(&mk(RESULT_NETWORK_FAILURE)).unwrap_or_else(|e| panic!("decode: {e}"));
    let out_of_res = natpmp::decode_reply(&mk(RESULT_OUT_OF_RESOURCES))
        .unwrap_or_else(|e| panic!("decode: {e}"));
    assert_eq!(net_fail.result(), 3);
    assert_eq!(out_of_res.result(), 4);
    // §3.5: undefined result codes MUST be treated as fatal — the decode
    // layer passes any code through (the semantic layer decides fatality);
    // this verifies decoding does not reject.
    let undefined = natpmp::decode_reply(&mk(0xBEEF)).unwrap_or_else(|e| panic!("decode: {e}"));
    assert_eq!(undefined.result(), 0xBEEF);
}

/// Vector 12: malformed inputs (total-function contract shared with the
/// fuzz target).
#[test]
fn vector_12_malformed_inputs() {
    assert_eq!(natpmp::decode_reply(&[]), Err(DecodeError::TooShort(0)));
    assert_eq!(
        natpmp::decode_reply(&[0x00, 0x80, 0x00]),
        Err(DecodeError::TooShort(3))
    );
    // Version != 0 (§3.2 diagram fixes Vers=0).
    assert_eq!(
        natpmp::decode_reply(&[0x01, 0x80, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0]),
        Err(DecodeError::UnsupportedVersion(1))
    );
    // Request form (no response bit) is not a valid reply.
    assert_eq!(
        natpmp::decode_reply(&[0x00, 0x01, 0x00, 0x00]),
        Err(DecodeError::NotAResponse(0x01))
    );
    // Unknown response opcode.
    assert_eq!(
        natpmp::decode_reply(&[0x00, 0xFF, 0x00, 0x00, 0, 0, 0, 0]),
        Err(DecodeError::UnknownOpcode(0xFF))
    );
    // Address reply truncated (needs 12B, given 10B).
    assert_eq!(
        natpmp::decode_reply(&[0x00, 0x80, 0x00, 0x00, 0, 0, 0, 0, 1, 2]),
        Err(DecodeError::TooShort(10))
    );
}

/// Vector 13: encode -> decode roundtrip (map reply echoes the §3.3
/// request format).
#[test]
fn vector_13_roundtrip() {
    let req = Request::Map(natpmp::MapRequest {
        protocol: Protocol::Tcp,
        internal_port: 12345,
        suggested_external_port: 12345,
        lifetime_secs: 60,
    });
    // Mock server side builds the reply: OP = 128 + x (§3.3).
    let mut reply = vec![0x00, req.opcode() | 0x80, 0x00, 0x00];
    reply.extend_from_slice(&42u32.to_be_bytes());
    reply.extend_from_slice(&12345u16.to_be_bytes());
    reply.extend_from_slice(&54321u16.to_be_bytes());
    reply.extend_from_slice(&60u32.to_be_bytes());
    let decoded = natpmp::decode_reply(&reply).unwrap_or_else(|e| panic!("decode: {e}"));
    assert_eq!(
        decoded,
        Reply::Map {
            protocol: Protocol::Tcp,
            result: 0,
            epoch_secs: 42,
            internal_port: 12345,
            external_port: 54321,
            lifetime_secs: 60,
        }
    );
}

// ---------------------------------------------------------------------------
// Table-driven
// ---------------------------------------------------------------------------

/// Retransmission schedule (RFC 6886 §3.1: doubling from 250ms, 9 sends,
/// final 64s wait).
#[test]
fn table_retransmit_schedule() {
    let s = natpmp::RETRANSMIT_SCHEDULE;
    assert_eq!(s.len(), 9, "§3.1 nine attempts");
    assert_eq!(s[0], Duration::from_millis(250));
    assert_eq!(s[1], Duration::from_millis(500));
    for pair in s.windows(2) {
        assert_eq!(pair[1], pair[0] * 2, "§3.1 doubling");
    }
    assert_eq!(s[8], Duration::from_secs(64), "§3.1 final 64s wait");
}

/// Renewal delay (SPEC §6.8 60min mark + RFC §3.3 granted/2 fallback +
/// permanent mappings).
#[test]
fn table_renew_delay() {
    // Lease >= 60min -> the 60min cadence (SPEC §6.8; intentional
    // divergence from the RFC halfway rule — see docs/design/io.md).
    assert_eq!(
        natpmp::renew_delay(Duration::from_secs(3600)),
        Some(Duration::from_secs(3600))
    );
    assert_eq!(
        natpmp::renew_delay(Duration::from_secs(7200)),
        Some(Duration::from_secs(3600))
    );
    // Gateway reduced the lifetime (§3.3 "MAY reduce") -> halfway
    // (§3.3 SHOULD).
    assert_eq!(
        natpmp::renew_delay(Duration::from_secs(1800)),
        Some(Duration::from_secs(900))
    );
    assert_eq!(
        natpmp::renew_delay(Duration::from_secs(60)),
        Some(Duration::from_secs(30))
    );
    // 0 = permanent (IGD lease=0 readback) -> no renewal needed.
    assert_eq!(natpmp::renew_delay(Duration::ZERO), None);
}

/// Backoff table (local policy: starts at 1s, tail caps while retries
/// continue).
#[test]
fn table_round_backoff() {
    assert_eq!(natpmp::round_backoff(0), Duration::from_secs(1));
    assert_eq!(natpmp::round_backoff(1), Duration::from_secs(2));
    assert_eq!(natpmp::round_backoff(4), Duration::from_secs(16));
    // Past the table end -> tail (never gives up; converges once the
    // device recovers).
    assert_eq!(natpmp::round_backoff(5), Duration::from_secs(16));
    assert_eq!(natpmp::round_backoff(50), Duration::from_secs(16));
}

/// Epoch regression (RFC 6886 §3.6: conservative estimate = last + 7/8
/// elapsed; new value < estimate - 2s => state loss).
#[test]
fn table_epoch_regression() {
    let t0 = std::time::Instant::now();
    let mut tracker = natpmp::EpochTracker::default();
    // The first packet only establishes the baseline.
    assert!(!tracker.observe(1000, t0));
    // Normal progress: after 60s expected >= 1000 + 52; reporting 1055 is
    // fine.
    assert!(!tracker.observe(1055, t0 + Duration::from_secs(60)));
    // Gateway reboot: SSSoE reset to ~0 -> regression far beyond 2s.
    assert!(tracker.observe(3, t0 + Duration::from_secs(120)));
    // Small jitter after re-baselining (within clock granularity, < 2s) is
    // not a regression.
    let mut tracker = natpmp::EpochTracker::default();
    assert!(!tracker.observe(100, t0));
    // elapsed 0s -> estimate 100; 100+2 < 100 is false.
    assert!(!tracker.observe(100, t0));
    // 101 > 100-2 -> normal.
    assert!(!tracker.observe(101, t0 + Duration::from_secs(0)));
}

// ---------------------------------------------------------------------------
// Mock NAT-PMP server (loopback UDP; programmable behavior + request log)
// ---------------------------------------------------------------------------

/// Mock server behavior modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PmpMode {
    /// Normal: echo the request (conflict simulation = assign a different
    /// port).
    Normal,
    /// Reject all map-class requests with the given result code (address
    /// requests still succeed).
    FailMap(u16),
    /// Fully silent (device offline).
    Silent,
    /// Drop replies to the first `n` requests (retransmission-path
    /// simulation).
    LoseFirst(usize),
    /// Only TCP maps (opcode 2) are rejected with Not Authorized; UDP and
    /// address requests succeed.
    FailTcp,
    /// Success replies, but the external port is always 0 (the §3.4 delete
    /// reply shape smuggled into a map reply — the poisoning surface).
    ZeroExternal,
    /// Success replies, but the granted lifetime is always the given value
    /// (a too-small lifetime poisons the renewal cadence).
    GrantLifetime(u32),
    /// Epoch alternates 10000/0 — each low value against the previous high
    /// baseline forms a §3.6 regression (a sustained recreate stream driven
    /// by forged replies).
    EpochPoison,
}

struct PmpState {
    mode: PmpMode,
    /// Remaining drops for LoseFirst.
    to_lose: usize,
    /// Received requests (opcode, internal, suggested, lifetime).
    requests: Vec<(u8, u16, u16, u32)>,
    epoch_base: u32,
    /// Conflict simulation: suggested port occupied -> assign
    /// `assigned_external`.
    assigned_external: u16,
    /// Alternation counter for EpochPoison.
    poison_seq: u32,
}

impl PmpState {
    fn epoch(&self) -> u32 {
        self.epoch_base
            + std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as u32 % 3600)
    }
}

/// In-process NAT-PMP server (bound to a random loopback port).
struct PmpServer {
    state: Arc<Mutex<PmpState>>,
    addr: SocketAddr,
}

impl PmpServer {
    async fn start(mode: PmpMode) -> Self {
        Self::start_with(mode, 3600, 0).await
    }

    /// With `assigned_external != 0`, simulates "suggested port occupied"
    /// (§3.3: the gateway assigns a different available port).
    async fn start_with(mode: PmpMode, grant_secs: u32, assigned_external: u16) -> Self {
        let _ = grant_secs; // grant always echoes the request (§3.3 SHOULD NOT exceed requested)
        let socket = Arc::new(
            UdpSocket::bind(("127.0.0.1", 0))
                .await
                .unwrap_or_else(|e| panic!("mock bind: {e}")),
        );
        let addr = socket
            .local_addr()
            .unwrap_or_else(|e| panic!("mock local_addr: {e}"));
        let state = Arc::new(Mutex::new(PmpState {
            mode,
            requests: Vec::new(),
            epoch_base: 1000,
            assigned_external,
            to_lose: if let PmpMode::LoseFirst(n) = mode {
                n
            } else {
                0
            },
            poison_seq: 0,
        }));
        let task_state = state.clone();
        let task_socket = socket.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            loop {
                let (n, src) = match task_socket.recv_from(&mut buf).await {
                    Ok(io) => io,
                    Err(_) => return,
                };
                let Some((opcode, internal, suggested, lifetime)) = parse_request(&buf[..n]) else {
                    continue;
                };
                let (reply_mode, epoch, external, grant, result) = {
                    let mut st = task_state.lock().unwrap_or_else(|p| p.into_inner());
                    st.requests.push((opcode, internal, suggested, lifetime));
                    let mode = st.mode;
                    // EpochPoison alternates 10000/0 (each low value against
                    // the high baseline forms a §3.6 regression); other
                    // modes use the time-based baseline.
                    let epoch = if let PmpMode::EpochPoison = mode {
                        st.poison_seq = st.poison_seq.wrapping_add(1);
                        if st.poison_seq % 2 == 1 { 10000 } else { 0 }
                    } else {
                        st.epoch()
                    };
                    let external = if let PmpMode::ZeroExternal = mode {
                        0
                    } else if st.assigned_external != 0 && suggested != 0 {
                        st.assigned_external
                    } else if suggested != 0 {
                        suggested
                    } else {
                        40001
                    };
                    // Real gateway semantics (§3.3 "SHOULD NOT offer a lease
                    // lifetime greater than that requested"): grant = request
                    // value; GrantLifetime overrides with a fixed grant (the
                    // too-small-lifetime poisoning input).
                    let grant = match mode {
                        PmpMode::GrantLifetime(fixed) => fixed,
                        _ => lifetime,
                    };
                    let result = match mode {
                        PmpMode::Normal => 0u16,
                        PmpMode::FailMap(code) if opcode != 0 => code,
                        // Reject only TCP (opcode 2).
                        PmpMode::FailTcp if opcode == 2 => RESULT_NOT_AUTHORIZED,
                        _ => 0,
                    };
                    (mode, epoch, external, grant, result)
                };
                if reply_mode == PmpMode::Silent {
                    continue;
                }
                if let PmpMode::LoseFirst(_) = reply_mode {
                    let mut st = task_state.lock().unwrap_or_else(|p| p.into_inner());
                    if st.to_lose > 0 {
                        st.to_lose -= 1;
                        continue;
                    }
                }
                let payload = build_reply(opcode, result, epoch, internal, external, grant);
                let _ = task_socket.send_to(&payload, src).await;
            }
        });
        Self { state, addr }
    }

    fn requests(&self) -> Vec<(u8, u16, u16, u32)> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .requests
            .clone()
    }

    fn set_mode(&self, mode: PmpMode) {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).mode = mode;
    }
}

/// Parse a request (opcode, internal, suggested, lifetime; zeros for
/// address requests).
fn parse_request(buf: &[u8]) -> Option<(u8, u16, u16, u32)> {
    if buf.len() < 2 {
        return None;
    }
    match buf[1] & 0x7f {
        0 => Some((0, 0, 0, 0)),
        op @ (1 | 2) if buf.len() >= 12 => Some((
            op,
            u16::from_be_bytes([buf[4], buf[5]]),
            u16::from_be_bytes([buf[6], buf[7]]),
            u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
        )),
        _ => None,
    }
}

/// Build a reply (§3.2 address 12B / §3.3 map 16B; §3.4 delete reply has
/// external=0).
fn build_reply(
    opcode: u8,
    result: u16,
    epoch: u32,
    internal: u16,
    external: u16,
    lifetime: u32,
) -> Vec<u8> {
    let mut b = vec![0x00, 0x80 | opcode];
    b.extend_from_slice(&result.to_be_bytes());
    b.extend_from_slice(&epoch.to_be_bytes());
    if opcode != 0 {
        b.extend_from_slice(&internal.to_be_bytes());
        b.extend_from_slice(&external.to_be_bytes());
        b.extend_from_slice(&lifetime.to_be_bytes());
    } else {
        b.extend_from_slice(&[81, 13, 5, 1]);
    }
    b
}

// ---------------------------------------------------------------------------
// Mock IGD (local HTTP/XML; device description + SOAP control)
// ---------------------------------------------------------------------------

const MOCK_EXTERNAL_IP: &str = "203.0.113.7";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IgdMode {
    /// All actions succeed (GetSpecific reads back lease = `lease_secs`).
    Normal,
    /// AddPortMapping conflict (718) -> AddAnyPortMapping assigns 40001.
    Conflict,
    /// All actions report Not Authorized (606).
    FaultAll(u16),
}

struct IgdState {
    mode: IgdMode,
    lease_secs: u32,
    add_port_mapping_calls: usize,
    add_any_port_calls: usize,
    delete_calls: usize,
    query_calls: usize,
    /// NewExternalPort values carried by AddPortMapping requests
    /// (frame-level assertion surface for the renewal port discipline).
    add_port_externals: Vec<u16>,
    /// Paths of received POST requests (assertion surface for URLBase merge
    /// results).
    post_paths: Vec<String>,
    /// Attack overrides (default empty = stock behavior).
    attacks: AttackOverrides,
    /// Dedicated reply override for AddAnyPortMapping (default None = stock
    /// behavior; unlike the all-actions `control` override this matches one
    /// action, for the two-stage "AddPortMapping fault 718 ->
    /// AddAnyPortMapping returns NewReservedPort 0" scenario).
    any_port_override: Option<String>,
}

/// In-process IGD device (loopback TCP; `/desc.xml` + `/control`).
struct IgdServer {
    state: Arc<Mutex<IgdState>>,
    device_url: String,
}

impl IgdServer {
    async fn start(mode: IgdMode, lease_secs: u32) -> Self {
        Self::start_with_attacks(mode, lease_secs, AttackOverrides::default()).await
    }

    /// Constructor with attack overrides (default empty = stock paths
    /// unchanged).
    async fn start_with_attacks(mode: IgdMode, lease_secs: u32, attacks: AttackOverrides) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap_or_else(|e| panic!("mock igd bind: {e}"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("mock igd addr: {e}"))
            .port();
        let state = Arc::new(Mutex::new(IgdState {
            mode,
            lease_secs,
            add_port_mapping_calls: 0,
            add_any_port_calls: 0,
            delete_calls: 0,
            query_calls: 0,
            add_port_externals: Vec::new(),
            post_paths: Vec::new(),
            attacks,
            any_port_override: None,
        }));
        let task_state = state.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let st = task_state.clone();
                tokio::spawn(async move {
                    let _ = serve_http(stream, st).await;
                });
            }
        });
        Self {
            state,
            device_url: format!("http://127.0.0.1:{port}/desc.xml"),
        }
    }

    /// Conflict mode plus a dedicated AddAnyPortMapping reply override (the
    /// 718 fallback path receives `body`; other actions take the normal
    /// dispatch).
    async fn start_conflict_with_any_port(mode_setter_lease: u32, body: String) -> Self {
        let server =
            Self::start_with_attacks(IgdMode::Conflict, mode_setter_lease, Default::default())
                .await;
        server
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .any_port_override = Some(body);
        server
    }

    fn counts(&self) -> (usize, usize, usize, usize) {
        let st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        (
            st.add_port_mapping_calls,
            st.add_any_port_calls,
            st.delete_calls,
            st.query_calls,
        )
    }

    /// NewExternalPort sequence carried by AddPortMapping requests
    /// (assertion surface).
    fn add_port_externals(&self) -> Vec<u16> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .add_port_externals
            .clone()
    }

    /// Received POST path sequence (assertion surface for SOAP endpoint
    /// merging).
    fn post_paths(&self) -> Vec<String> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .post_paths
            .clone()
    }

    /// Start the IGD server with a given device-description XML (the desc
    /// override path serves one close-delimited response; parameterizes the
    /// <URLBase> shape).
    async fn start_with_desc_xml(xml: String) -> Self {
        Self::start_with_attacks(
            IgdMode::Normal,
            3600,
            AttackOverrides {
                desc: Some(DescCarrier {
                    body: xml,
                    declared_len: None,
                    stall_after: None,
                    omit_content_length: false,
                }),
                control: None,
            },
        )
        .await
    }

    /// Server authority (device_url minus the /desc.xml path).
    fn authority(&self) -> &str {
        self.device_url.trim_end_matches("/desc.xml")
    }
}

/// Minimal HTTP/1.1 server (path + SOAPAction dispatch; exercises the
/// rupnp client).
async fn serve_http(mut stream: TcpStream, state: Arc<Mutex<IgdState>>) -> std::io::Result<()> {
    loop {
        // Read the header.
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = stream.read(&mut byte).await?;
            if n == 0 {
                return Ok(());
            }
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
            if head.len() > 64 * 1024 {
                return Ok(());
            }
        }
        let head_text = String::from_utf8_lossy(&head).to_string();
        let mut parts = head_text.split("\r\n");
        let request_line = parts.next().unwrap_or_default().to_string();
        let mut content_length = 0usize;
        let mut soap_action = String::new();
        for line in parts {
            let lower = line.to_ascii_lowercase();
            if let Some(v) = lower.strip_prefix("content-length:") {
                content_length = v.trim().parse().unwrap_or(0);
            }
            if let Some(v) = lower.strip_prefix("soapaction:") {
                soap_action = line
                    .split(':')
                    .skip(1)
                    .collect::<String>()
                    .trim()
                    .to_string();
                let _ = v;
            }
        }
        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            stream.read_exact(&mut body).await?;
        }

        if request_line.starts_with("GET /desc.xml") {
            // Attack override branch (default empty = stock path).
            let carrier = state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .attacks
                .desc
                .clone();
            match carrier {
                Some(carrier) => {
                    // The override reply consumes the connection (one-shot;
                    // no keep-alive).
                    let _ = serve_desc_carrier(stream, carrier).await;
                    return Ok(());
                }
                None => {
                    let _ = stream.write_all(&http_ok(device_xml(), "text/xml")).await;
                }
            }
            continue;
        }
        if request_line.starts_with("POST ") {
            // Path bookkeeping + dispatch on any path (frame-level
            // assertions for the SOAP endpoint merge need distinct servers
            // per path; the stock /control route is a subset).
            let path = request_line
                .split(' ')
                .nth(1)
                .unwrap_or_default()
                .to_string();
            {
                let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
                st.post_paths.push(path);
            }
            let action = soap_action
                .rsplit('#')
                .next()
                .unwrap_or_default()
                .trim_matches('"')
                .to_string();
            // AddAnyPortMapping-specific override branch (default None =
            // stock path untouched; matches one action, enabling the
            // two-stage 718 -> 0 port scenario).
            let any_port = state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .any_port_override
                .clone();
            if action == "AddAnyPortMapping"
                && let Some(body) = any_port
            {
                let _ = stream.write_all(&http_ok(&body, "text/xml")).await;
                continue;
            }
            // Raw control reply override branch (default None = stock path).
            let override_body = state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .attacks
                .control
                .clone();
            if let Some(body) = override_body {
                let _ = stream.write_all(&http_ok(&body, "text/xml")).await;
                continue;
            }
            let body_text = String::from_utf8_lossy(&body).to_string();
            let resp = handle_control(&state, &action, &body_text);
            let _ = stream.write_all(&http_ok(&resp, "text/xml")).await;
            continue;
        }
        let _ = stream.write_all(&http_ok("", "text/plain")).await;
    }
}

/// SOAP control dispatch (WANIPConnection:2 behavior; spec clauses in
/// docs/design/io.md).
fn handle_control(state: &Mutex<IgdState>, action: &str, body: &str) -> String {
    let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
    match action {
        "GetExternalIPAddress" => soap_response(
            "GetExternalIPAddress",
            &format!("<NewExternalIPAddress>{MOCK_EXTERNAL_IP}</NewExternalIPAddress>"),
        ),
        "AddPortMapping" => {
            st.add_port_mapping_calls += 1;
            // Record NewExternalPort from the request frame (renewal port
            // discipline).
            if let Some(rest) = body.split("<NewExternalPort>").nth(1)
                && let Some(digits) = rest.split("</NewExternalPort>").next()
                && let Ok(port) = digits.parse::<u16>()
            {
                st.add_port_externals.push(port);
            }
            match st.mode {
                IgdMode::Normal => soap_response("AddPortMapping", ""),
                IgdMode::Conflict => soap_fault(718, "ConflictInMappingEntry"),
                IgdMode::FaultAll(code) => soap_fault(code, "ActionNotAuthorized"),
            }
        }
        "AddAnyPortMapping" => {
            st.add_any_port_calls += 1;
            match st.mode {
                IgdMode::FaultAll(code) => soap_fault(code, "ActionNotAuthorized"),
                // §2.5.17: the gateway reserves any free port and returns
                // NewReservedPort.
                _ => soap_response(
                    "AddAnyPortMapping",
                    "<NewReservedPort>40001</NewReservedPort>",
                ),
            }
        }
        "GetSpecificPortMappingEntry" => {
            st.query_calls += 1;
            match st.mode {
                IgdMode::FaultAll(code) => soap_fault(code, "ActionNotAuthorized"),
                // §2.5.15 OUT arguments (internal port/client/enabled/
                // description/lease).
                _ => soap_response(
                    "GetSpecificPortMappingEntry",
                    &format!(
                        "<NewInternalPort>6881</NewInternalPort>\
                         <NewInternalClient>192.168.1.10</NewInternalClient>\
                         <NewEnabled>1</NewEnabled>\
                         <NewPortMappingDescription>taiji</NewPortMappingDescription>\
                         <NewLeaseDuration>{}</NewLeaseDuration>",
                        st.lease_secs
                    ),
                ),
            }
        }
        "DeletePortMapping" => {
            st.delete_calls += 1;
            match st.mode {
                IgdMode::FaultAll(code) => soap_fault(code, "ActionNotAuthorized"),
                _ => soap_response("DeletePortMapping", ""),
            }
        }
        _ => soap_fault(401, "InvalidAction"),
    }
}

fn soap_response(action: &str, args: &str) -> String {
    format!(
        r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:{action}Response xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:2">{args}</u:{action}Response></s:Body></s:Envelope>"#
    )
}

fn soap_fault(code: u16, description: &str) -> String {
    format!(
        r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>{code}</errorCode><errorDescription>{description}</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>"#
    )
}

fn device_xml() -> &'static str {
    r#"<?xml version="1.0" encoding="utf-8"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:2</deviceType>
    <friendlyName>mock-igd</friendlyName>
    <manufacturer>taiji-tests</manufacturer>
    <UDN>uuid:00000000-0000-0000-0000-000000000001</UDN>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType>
        <serviceId>urn:upnp-org:serviceId:WANIPConn</serviceId>
        <SCPDURL>/scpd.xml</SCPDURL>
        <controlURL>/control</controlURL>
        <eventSubURL>/event</eventSubURL>
      </service>
    </serviceList>
  </device>
</root>"#
}

/// Device description with <URLBase> (UDA 1.1 §2.3 — URLBase is the merge
/// base for relative URLs in the description; controlURL is parameterized:
/// absolute or relative path).
fn device_xml_with_url_base(url_base: &str, control_url: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <URLBase>{url_base}</URLBase>
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:2</deviceType>
    <friendlyName>mock-igd-urlbase</friendlyName>
    <manufacturer>taiji-tests</manufacturer>
    <UDN>uuid:00000000-0000-0000-0000-000000000002</UDN>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType>
        <serviceId>urn:upnp-org:serviceId:WANIPConn</serviceId>
        <SCPDURL>/scpd.xml</SCPDURL>
        <controlURL>{control_url}</controlURL>
        <eventSubURL>/event</eventSubURL>
      </service>
    </serviceList>
  </device>
</root>"#
    )
}

fn http_ok(body: &str, content_type: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

// ---------------------------------------------------------------------------
// NAT-PMP client transactions (retransmission / source filter / opcode match)
// ---------------------------------------------------------------------------

fn test_config(pmp: &PmpServer, schedule: &[u64]) -> NatConfig {
    NatConfig {
        gateway: Some(std::net::Ipv4Addr::LOCALHOST),
        natpmp_port: pmp.addr.port(),
        enable_natpmp: true,
        enable_upnp: false,
        lease: Duration::from_secs(2),
        retransmit_schedule: schedule
            .iter()
            .map(|ms| Duration::from_millis(*ms))
            .collect(),
        unmap_schedule: vec![Duration::from_millis(50)],
        ..NatConfig::default()
    }
}

/// Transaction success with retransmission progress (the first request's
/// reply is silently lost -> the second attempt succeeds; RFC 6886 §3.1
/// semantics).
#[tokio::test]
async fn pmp_client_transact_retransmits_then_succeeds() {
    // The first request's reply is lost (the motivation for §3.1
    // retransmission).
    let server = PmpServer::start(PmpMode::LoseFirst(1)).await;
    let socket = UdpSocket::bind(("127.0.0.1", 0))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let client = natpmp::NatPmpClient::with_schedule(
        socket,
        server.addr,
        vec![Duration::from_millis(50), Duration::from_millis(50)],
    );
    let req = Request::Map(natpmp::MapRequest {
        protocol: Protocol::Tcp,
        internal_port: 6881,
        suggested_external_port: 6881,
        lifetime_secs: 3600,
    });
    let reply = client
        .transact(&req)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    match reply {
        Reply::Map {
            protocol,
            external_port,
            ..
        } => {
            assert_eq!(protocol, Protocol::Tcp);
            assert_eq!(external_port, 6881);
        }
        other => panic!("wrong reply: {other:?}"),
    }
    assert_eq!(server.requests().len(), 2, "1 lost + 1 retransmit");
}

/// Non-zero result code -> [`natpmp::NatPmpError::Result`] (§3.5
/// semantic-layer fatal).
#[tokio::test]
async fn pmp_client_surfaces_result_codes() {
    let server = PmpServer::start(PmpMode::FailMap(RESULT_OUT_OF_RESOURCES)).await;
    let socket = UdpSocket::bind(("127.0.0.1", 0))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let client =
        natpmp::NatPmpClient::with_schedule(socket, server.addr, vec![Duration::from_millis(50)]);
    let reply = client
        .transact(&Request::Map(natpmp::MapRequest {
            protocol: Protocol::Udp,
            internal_port: 6881,
            suggested_external_port: 6881,
            lifetime_secs: 60,
        }))
        .await;
    let err = match reply {
        Err(e) => e,
        Ok(r) => panic!("result 4 must surface as fatal (§3.5), got {r:?}"),
    };
    assert!(
        matches!(err, natpmp::NatPmpError::Result(RESULT_OUT_OF_RESOURCES)),
        "unexpected: {err}"
    );
}

/// Silent gateway -> schedule exhausted -> NoResponse (§3.1: unsupported).
#[tokio::test]
async fn pmp_client_times_out_against_silent_gateway() {
    let server = PmpServer::start(PmpMode::Silent).await;
    let socket = UdpSocket::bind(("127.0.0.1", 0))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let client = natpmp::NatPmpClient::with_schedule(
        socket,
        server.addr,
        vec![Duration::from_millis(30); 3],
    );
    let err = match client.transact(&Request::ExternalAddress).await {
        Err(e) => e,
        Ok(r) => panic!("silent gateway must time out, got {r:?}"),
    };
    assert!(
        matches!(err, natpmp::NatPmpError::NoResponse { attempts: 3 }),
        "unexpected: {err}"
    );
    assert_eq!(server.requests().len(), 3, "every window sends one request");
}

// ---------------------------------------------------------------------------
// IGD client (the IGD half of the mock four-path set)
// ---------------------------------------------------------------------------

/// IGD map -> conflict (718) falls back to AddAnyPortMapping
/// (§2.5.17 NewReservedPort) -> query -> delete.
#[tokio::test]
async fn igd_client_map_conflict_query_delete() {
    let server = IgdServer::start(IgdMode::Conflict, 1800).await;
    let uri: rupnp::http::Uri = server.device_url.parse().unwrap_or_else(|e| panic!("{e}"));
    let client = igd::IgdClient::from_device_url(uri)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        client.gateway_hint(),
        Some(std::net::Ipv4Addr::LOCALHOST),
        "device host = gateway hint"
    );
    // Conflict path: 718 -> v2 fallback -> NewReservedPort 40001.
    let external = client
        .add_mapping(
            &igd::IgdMapping {
                protocol: Protocol::Tcp,
                internal_port: 6881,
                external_port: 6881,
                lease_secs: 3600,
                description: "taiji".into(),
            },
            std::net::Ipv4Addr::new(192, 168, 1, 10),
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(external, 40001, "§2.5.17 NewReservedPort");
    // Query (presence + lease readback).
    let info = client
        .query_mapping(Protocol::Tcp, 40001)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        info,
        Some(igd::MappingInfo {
            internal_port: 6881,
            internal_client: std::net::Ipv4Addr::new(192, 168, 1, 10),
            lease_secs: 1800,
        })
    );
    // Delete.
    client
        .remove_mapping(Protocol::Tcp, 40001)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let (add, any, delete, query) = server.counts();
    assert_eq!((add, any, delete, query), (1, 1, 1, 1));
}

/// IGD external address + plain mapping (no conflict).
#[tokio::test]
async fn igd_client_external_ip_and_plain_map() {
    let server = IgdServer::start(IgdMode::Normal, 3600).await;
    let uri: rupnp::http::Uri = server.device_url.parse().unwrap_or_else(|e| panic!("{e}"));
    let client = igd::IgdClient::from_device_url(uri)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        client.external_ip().await.unwrap_or_else(|e| panic!("{e}")),
        MOCK_EXTERNAL_IP
            .parse::<std::net::Ipv4Addr>()
            .unwrap_or_else(|e| panic!("{e}"))
    );
    client
        .add_mapping(
            &igd::IgdMapping {
                protocol: Protocol::Udp,
                internal_port: 6881,
                external_port: 6881,
                lease_secs: 3600,
                description: "taiji".into(),
            },
            std::net::Ipv4Addr::new(192, 168, 1, 10),
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let (add, any, _, _) = server.counts();
    assert_eq!(
        (add, any),
        (1, 0),
        "no conflict means AddAnyPortMapping is not used"
    );
}

// ---------------------------------------------------------------------------
// NatActor integration (the four mock paths)
// ---------------------------------------------------------------------------

/// Paths 1-2, map + renew (NAT-PMP): TCP+UDP Mapped events, snapshot view,
/// gateway reboot (epoch regression §3.6) -> recreate after 0-5s jitter
/// (§3.7).
#[tokio::test]
async fn actor_natpmp_map_and_snapshot() {
    let server = PmpServer::start(PmpMode::Normal).await;
    let (handle, mut events, join) = super::spawn(test_config(&server, &[50, 50, 50]));
    handle
        .map(6881, Duration::from_secs(2))
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    // Mapped events for both protocols (external port = requested port).
    let mut mapped = Vec::new();
    for _ in 0..2 {
        match events.recv().await {
            Some(NatEvent::Mapped {
                protocol,
                external_port,
            }) => {
                mapped.push((protocol, external_port));
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }
    assert!(mapped.contains(&(Protocol::Tcp, 6881)));
    assert!(mapped.contains(&(Protocol::Udp, 6881)));

    let snap: NatSnapshot = handle.snapshot().await.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(snap.backend, Some(super::Backend::NatPmp));
    assert!(!snap.degraded);
    assert_eq!(
        snap.external_address,
        Some(std::net::Ipv4Addr::new(81, 13, 5, 1))
    );
    assert_eq!(snap.mappings.len(), 2);
    let grant = snap.mappings.iter().all(|m| m.granted_lease_secs == 2);
    assert!(grant, "server echoes requested lifetime 2s");

    // Renewal: lease 2s -> renewal delay 1s (renew_delay table) -> wait for
    // the renewal requests to arrive.
    tokio::time::sleep(Duration::from_millis(1800)).await; // renewal point 1s + tick margin
    let reqs = server.requests();
    // 2 protocols x (initial map 1 + address 1 + renewals >=1).
    let tcp_maps = reqs.iter().filter(|(op, ..)| *op == 2).count();
    let udp_maps = reqs.iter().filter(|(op, ..)| *op == 1).count();
    assert!(tcp_maps >= 2, "tcp map + renew, got {tcp_maps}");
    assert!(udp_maps >= 2, "udp map + renew, got {udp_maps}");
    // RFC 6886 §3.3: renewal requests suggest the assigned external port.
    let renews = reqs
        .iter()
        .filter(|(op, _, suggested, _)| *op != 0 && *suggested == 6881)
        .count();
    assert!(
        renews >= 4,
        "renewals reuse assigned external, got {renews}"
    );

    handle.unmap().await.unwrap_or_else(|e| panic!("{e}"));
    let snap = handle.snapshot().await.unwrap_or_else(|e| panic!("{e}"));
    assert!(snap.mappings.is_empty());
    assert_eq!(snap.backend, None);
    // Delete requests arrived (lifetime 0; §3.4).
    let deletes = server
        .requests()
        .iter()
        .filter(|(op, _, suggested, lifetime)| *op != 0 && *suggested == 0 && *lifetime == 0)
        .count();
    assert_eq!(deletes, 2, "one delete per protocol");
    drop(handle);
    let _ = join.await;
}

/// Path 3, conflict (occupied port, NAT-PMP): the gateway assigns a
/// different external port (§3.3 MUST) -> the Mapped event reports the
/// actual port (the input to the announce port discipline).
#[tokio::test]
async fn actor_natpmp_conflict_reports_assigned_port() {
    let server = PmpServer::start_with(PmpMode::Normal, 3600, 40001).await;
    let (handle, mut events, join) = super::spawn(test_config(&server, &[50, 50, 50]));
    handle
        .map_one(Protocol::Tcp, 6881, Duration::from_secs(3600))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    match events.recv().await {
        Some(NatEvent::Mapped {
            protocol,
            external_port,
        }) => {
            assert_eq!(protocol, Protocol::Tcp);
            assert_eq!(external_port, 40001, "the gateway-granted port is the fact");
        }
        other => panic!("unexpected event: {other:?}"),
    }
    let snap = handle.snapshot().await.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(snap.mappings.len(), 1);
    assert_eq!(snap.mappings[0].external_port, 40001);
    drop(handle);
    let _ = join.await;
}

/// Path 4, device-offline degradation (NAT-PMP): silent gateway -> Failed
/// event + degraded snapshot -> backoff retries never give up -> Mapped on
/// recovery.
#[tokio::test]
async fn actor_natpmp_offline_degrades_then_recovers() {
    let server = PmpServer::start(PmpMode::Silent).await;
    let (handle, mut events, join) = super::spawn(test_config(&server, &[30, 30, 30]));
    let err = match handle
        .map_one(Protocol::Udp, 6881, Duration::from_secs(2))
        .await
    {
        Err(e) => e,
        Ok(()) => panic!("offline gateway must fail"),
    };
    assert!(matches!(
        err,
        super::NatError::NatPmp(natpmp::NatPmpError::NoResponse { .. })
    ));
    // First failure -> Failed event (state edge, a single one).
    match events.recv().await {
        Some(NatEvent::Failed { reason }) => assert!(!reason.is_empty()),
        other => panic!("unexpected event: {other:?}"),
    }
    let snap = handle.snapshot().await.unwrap_or_else(|e| panic!("{e}"));
    assert!(snap.degraded);
    assert_eq!(snap.backend, None);

    // Device recovers (gateway answers again) -> a backoff retry lands ->
    // Mapped.
    server.set_mode(PmpMode::Normal);
    match tokio::time::timeout(Duration::from_secs(5), events.recv()).await {
        Ok(Some(NatEvent::Mapped {
            protocol,
            external_port,
        })) => {
            assert_eq!(protocol, Protocol::Udp);
            assert_eq!(external_port, 6881);
        }
        other => panic!("expected recovery Mapped, got {other:?}"),
    }
    let snap = handle.snapshot().await.unwrap_or_else(|e| panic!("{e}"));
    assert!(!snap.degraded);
    assert_eq!(snap.backend, Some(super::Backend::NatPmp));
    drop(handle);
    let _ = join.await;
}

/// IGD-backend actor integration: direct device description (bypassing
/// SSDP) -> map -> events/snapshot -> renewal (driven by the short lease
/// readback) -> Unmap issues deletes.
#[tokio::test]
async fn actor_igd_map_renew_unmap() {
    let server = IgdServer::start(IgdMode::Normal, 2).await;
    let config = NatConfig {
        gateway: Some(std::net::Ipv4Addr::LOCALHOST),
        enable_natpmp: false,
        enable_upnp: true,
        igd_device_url: Some(server.device_url.clone()),
        lease: Duration::from_secs(2),
        address_poll: Duration::from_secs(3600),
        ..NatConfig::default()
    };
    let (handle, mut events, join) = super::spawn(config);
    handle
        .map_one(Protocol::Tcp, 6881, Duration::from_secs(2))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    match events.recv().await {
        Some(NatEvent::Mapped {
            protocol,
            external_port,
        }) => {
            assert_eq!(protocol, Protocol::Tcp);
            assert_eq!(external_port, 6881);
        }
        other => panic!("unexpected event: {other:?}"),
    }
    let snap = handle.snapshot().await.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(snap.backend, Some(super::Backend::Igd));
    assert_eq!(
        snap.external_address,
        MOCK_EXTERNAL_IP.parse::<std::net::Ipv4Addr>().ok()
    );
    // Lease readback 2s -> renew_delay 1s -> renewal re-issues
    // AddPortMapping (overwrite).
    tokio::time::sleep(Duration::from_millis(1800)).await; // renewal point 1s + tick margin
    let (adds, _, _, _) = server.counts();
    assert!(adds >= 2, "renewal re-issues AddPortMapping, got {adds}");

    // Unmap -> DeletePortMapping.
    handle.unmap().await.unwrap_or_else(|e| panic!("{e}"));
    let (_, _, deletes, _) = server.counts();
    assert_eq!(deletes, 1);
    let snap = handle.snapshot().await.unwrap_or_else(|e| panic!("{e}"));
    assert!(snap.mappings.is_empty());
    drop(handle);
    let _ = join.await;
}

/// IGD total fault (Not Authorized 606) -> actor degradation.
#[tokio::test]
async fn actor_igd_fault_degrades() {
    let server = IgdServer::start(IgdMode::FaultAll(606), 3600).await;
    let config = NatConfig {
        enable_natpmp: false,
        enable_upnp: true,
        igd_device_url: Some(server.device_url.clone()),
        retransmit_schedule: vec![Duration::from_millis(30)],
        ..NatConfig::default()
    };
    let (handle, mut events, join) = super::spawn(config);
    let err = match handle
        .map_one(Protocol::Udp, 6881, Duration::from_secs(60))
        .await
    {
        Err(e) => e,
        Ok(()) => panic!("faulting igd must fail"),
    };
    assert!(matches!(err, super::NatError::Igd(_)), "got {err}");
    match events.recv().await {
        Some(NatEvent::Failed { .. }) => {}
        other => panic!("unexpected event: {other:?}"),
    }
    drop(handle);
    let _ = join.await;
}

/// IGD conflict fallback at the actor level: 718 -> AddAnyPortMapping ->
/// Mapped with 40001.
#[tokio::test]
async fn actor_igd_conflict_falls_back_to_any_port() {
    let server = IgdServer::start(IgdMode::Conflict, 3600).await;
    let config = NatConfig {
        enable_natpmp: false,
        enable_upnp: true,
        igd_device_url: Some(server.device_url.clone()),
        ..NatConfig::default()
    };
    let (handle, mut events, join) = super::spawn(config);
    handle
        .map_one(Protocol::Tcp, 6881, Duration::from_secs(3600))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    match events.recv().await {
        Some(NatEvent::Mapped { external_port, .. }) => {
            assert_eq!(external_port, 40001);
        }
        other => panic!("unexpected event: {other:?}"),
    }
    let (adds, anys, _, _) = server.counts();
    assert_eq!((adds, anys), (1, 1));
    drop(handle);
    let _ = join.await;
}

/// Command surface hygiene: port 0 rejected; empty Snapshot; dropping all
/// handles -> actor exits.
#[tokio::test]
async fn actor_command_surface_sanitation() {
    let server = PmpServer::start(PmpMode::Normal).await;
    let (handle, _events, join) = super::spawn(test_config(&server, &[30]));
    let err = match handle
        .map_one(Protocol::Udp, 0, Duration::from_secs(2))
        .await
    {
        Err(e) => e,
        Ok(()) => panic!("port 0 must be rejected"),
    };
    assert!(matches!(err, super::NatError::InvalidArgs(_)));
    let snap = handle.snapshot().await.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(snap, NatSnapshot::default());
    drop(handle);
    assert!(
        tokio::time::timeout(Duration::from_secs(2), join)
            .await
            .is_ok(),
        "actor exits after all handles dropped"
    );
}

/// Event channel drop-on-full policy (bounded(16); explicit backpressure
/// surface).
#[tokio::test]
async fn actor_event_channel_full_drops() {
    let server = PmpServer::start(PmpMode::Normal).await;
    let (handle, mut events, join) = super::spawn(test_config(&server, &[30]));
    // Do not consume events; repeated remaps with new ports pile up Mapped
    // events.
    for port in [
        6000u16, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008, 6009,
    ] {
        let _ = handle
            .map_one(Protocol::Tcp, port, Duration::from_secs(2))
            .await;
    }
    // The snapshot always has the truth (the last mapping is in place).
    let snap = handle.snapshot().await.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(snap.mappings.len(), 1);
    assert_eq!(snap.mappings[0].internal_port, 6009);
    drop(handle);
    let _ = join.await;
    // Drain the receiver to avoid channel-handle leak warnings.
    while events.try_recv().is_ok() {}
}

/// Event channel capacity contract (frozen at 16).
#[test]
fn channel_capacities_are_frozen() {
    assert_eq!(super::COMMAND_CHANNEL_CAPACITY, 16);
    assert_eq!(super::EVENT_CHANNEL_CAPACITY, 16);
}

/// An address request failing against a silent gateway leaves the snapshot
/// clean (`external_address` stays None).
#[tokio::test]
async fn actor_failed_address_poll_keeps_snapshot_clean() {
    let server = PmpServer::start(PmpMode::FailMap(RESULT_NETWORK_FAILURE)).await;
    let (handle, _events, join) = super::spawn(test_config(&server, &[30]));
    let _ = handle
        .map_one(Protocol::Udp, 6881, Duration::from_secs(2))
        .await;
    // Under FailMap the mapping fails (result 3) — snapshot degraded +
    // last_error.
    let snap = handle.snapshot().await.unwrap_or_else(|e| panic!("{e}"));
    assert!(snap.degraded);
    assert!(snap.mappings.is_empty());
    assert!(snap.external_address.is_none());
    drop(handle);
    let _ = join.await;
}

// ---------------------------------------------------------------------------
// Bounded-surface negative assertions (carried by the mock IGD attack
// branches above; stock paths unchanged)
// ---------------------------------------------------------------------------

/// Attack overrides (default empty = stock mock behavior).
#[derive(Debug, Clone, Default)]
struct AttackOverrides {
    /// Raw GET /desc.xml reply override (slow gateway / body bomb / deep
    /// nesting).
    desc: Option<DescCarrier>,
    /// Fixed 200 raw reply for POST /control (fault bombs / garbage ports).
    control: Option<String>,
}

/// desc override: header declares `declared_len` (may lie), body stalls
/// after `stall_after` bytes holding the connection (slowloris shape);
/// `omit_content_length` = no CL header (close-delimited frame — the input
/// for the Limited streaming fallback path).
#[derive(Debug, Clone)]
struct DescCarrier {
    body: String,
    declared_len: Option<usize>,
    stall_after: Option<usize>,
    omit_content_length: bool,
}

/// Override reply: declare Content-Length, then send the body; the stall
/// variant emits the prefix then hangs the connection forever (the client
/// must give up within the request timeout — the hang-elimination surface).
async fn serve_desc_carrier(mut stream: TcpStream, carrier: DescCarrier) -> std::io::Result<()> {
    let head = if carrier.omit_content_length {
        "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nConnection: close\r\n\r\n".to_string()
    } else {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\n\r\n",
            carrier.declared_len.unwrap_or(carrier.body.len())
        )
    };
    stream.write_all(head.as_bytes()).await?;
    let body = carrier.body.as_bytes();
    match carrier.stall_after {
        Some(cut) => {
            stream.write_all(&body[..cut.min(body.len())]).await?;
            stream.flush().await?;
            // Connection stays open, reply never completes (slow-gateway
            // override).
            std::future::pending::<()>().await;
            Ok(())
        }
        None => stream.write_all(body).await,
    }
}

/// Deeply nested deviceList override (`levels` layers; deviceType is always
/// a valid URN — ensures rejection happens in the depth precheck, not URN
/// parsing).
fn deep_device_xml(levels: usize) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><specVersion><major>1</major><minor>0</minor></specVersion><device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:2</deviceType><friendlyName>deep</friendlyName>"#,
    );
    for _ in 0..levels {
        xml.push_str(
            "<deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:2</deviceType><friendlyName>layer</friendlyName>",
        );
    }
    for _ in 0..levels {
        xml.push_str("</device></deviceList>");
    }
    xml.push_str("</device></root>");
    xml
}

/// Hang negative assertion: a slow gateway (header + partial body, then
/// silence) is abandoned within the request timeout and classified as a
/// timeout — the actor's inline execution has no unbounded hang point.
/// (Same function surface as the actor's production path,
/// `from_device_url`/`call`, with constant `igd::HTTP_REQUEST_TIMEOUT` =
/// 10s; 300ms is injected here to avoid a long real-time wait.)
#[tokio::test]
async fn slow_gateway_times_out_within_budget() {
    let carrier = DescCarrier {
        body: device_xml().to_string(),
        declared_len: None,
        stall_after: Some(32),
        omit_content_length: false,
    };
    let server = IgdServer::start_with_attacks(
        IgdMode::Normal,
        3600,
        AttackOverrides {
            desc: Some(carrier),
            control: None,
        },
    )
    .await;
    let uri: rupnp::http::Uri = server.device_url.parse().unwrap_or_else(|e| panic!("{e}"));
    let started = std::time::Instant::now();
    let err = match igd::IgdClient::from_device_url_bounded(
        uri,
        igd::MAX_HTTP_BODY,
        Duration::from_millis(300),
    )
    .await
    {
        Err(e) => e,
        Ok(_) => panic!("slow gateway must time out"),
    };
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "client must abort promptly, took {elapsed:?}"
    );
    assert!(
        err.to_string().contains("did not respond within"),
        "unexpected error: {err}"
    );
}

/// Unbounded-allocation negative assertion: both body-bomb shapes are
/// rejected as cap errors — (1) declared 256MiB (a small document actually
/// sent) -> rejected at the Content-Length precheck without reading the
/// body; (2) declared 16B but 8KiB sent (a lie) -> truncated by
/// [`http_body_util::Limited`] streaming fallback (locking in the
/// "never trust Content-Length without a cap" rule).
#[tokio::test]
async fn body_bomb_rejected_by_precheck_and_limited() {
    // (1) Precheck path: the declared value exceeds the cap; rejected at
    // the header.
    let carrier = DescCarrier {
        body: device_xml().to_string(),
        declared_len: Some(256 * 1024 * 1024),
        stall_after: None,
        omit_content_length: false,
    };
    let server = IgdServer::start_with_attacks(
        IgdMode::Normal,
        3600,
        AttackOverrides {
            desc: Some(carrier),
            control: None,
        },
    )
    .await;
    let uri: rupnp::http::Uri = server.device_url.parse().unwrap_or_else(|e| panic!("{e}"));
    let err = match igd::IgdClient::from_device_url(uri).await {
        Err(e) => e,
        Ok(_) => panic!("overstated content-length must be rejected"),
    };
    assert!(err.to_string().contains("body cap"), "got {err}");

    // (2) Limited path: no Content-Length (close-delimited), 8KiB actually
    // sent (> the 1KiB test cap) -> streaming truncation — with no CL there
    // is nothing to precheck, so the Limited fallback must hold
    // independently (locking in "never trust Content-Length without a
    // cap").
    let carrier = DescCarrier {
        body: "x".repeat(8 * 1024),
        declared_len: None,
        stall_after: None,
        omit_content_length: true,
    };
    let server = IgdServer::start_with_attacks(
        IgdMode::Normal,
        3600,
        AttackOverrides {
            desc: Some(carrier),
            control: None,
        },
    )
    .await;
    let uri: rupnp::http::Uri = server.device_url.parse().unwrap_or_else(|e| panic!("{e}"));
    let err = match igd::IgdClient::from_device_url_bounded(uri, 1024, Duration::from_secs(5)).await
    {
        Err(e) => e,
        Ok(_) => panic!("oversized close-delimited stream must hit Limited"),
    };
    assert!(err.to_string().contains("body cap"), "got {err}");
}

/// Abort negative assertion: a 2000-layer deviceList (~280KiB, below the
/// body cap — proving the size cap alone is insufficient) is rejected by
/// the depth precheck instead of blowing the task stack; the process
/// survives, proven by a full flow against a healthy gateway afterwards
/// (description -> mapping).
#[tokio::test]
async fn deep_nesting_rejected_without_aborting_process() {
    let carrier = DescCarrier {
        body: deep_device_xml(2000),
        declared_len: None,
        stall_after: None,
        omit_content_length: false,
    };
    let server = IgdServer::start_with_attacks(
        IgdMode::Normal,
        3600,
        AttackOverrides {
            desc: Some(carrier),
            control: None,
        },
    )
    .await;
    let uri: rupnp::http::Uri = server.device_url.parse().unwrap_or_else(|e| panic!("{e}"));
    let err = match igd::IgdClient::from_device_url(uri).await {
        Err(e) => e,
        Ok(_) => panic!("deep nesting must be rejected"),
    };
    assert!(err.to_string().contains("depth cap"), "got {err}");

    // Process alive + control plane healthy: a normal mock completes one
    // mapping.
    let healthy = IgdServer::start(IgdMode::Normal, 3600).await;
    let uri: rupnp::http::Uri = healthy.device_url.parse().unwrap_or_else(|e| panic!("{e}"));
    let client = igd::IgdClient::from_device_url(uri)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let external = client
        .add_mapping(
            &igd::IgdMapping {
                protocol: Protocol::Tcp,
                internal_port: 6881,
                external_port: 6881,
                lease_secs: 3600,
                description: "taiji".into(),
            },
            std::net::Ipv4Addr::new(192, 168, 1, 10),
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(external, 6881);
}

/// Log amplification surface: attacker-controlled error strings are
/// clipped — (1) an 8KiB SOAP fault errorDescription is clipped before
/// storage (the error code is preserved: 718/714 fallback decisions are
/// unaffected by clipping); (2) an 8KiB garbage port in a reply argument is
/// clipped verbatim.
#[tokio::test]
async fn attacker_controlled_error_strings_clipped() {
    // (1) Fault description clipping.
    let fault = soap_fault(606, &"A".repeat(8 * 1024));
    let server = IgdServer::start_with_attacks(
        IgdMode::Normal,
        3600,
        AttackOverrides {
            desc: None,
            control: Some(fault),
        },
    )
    .await;
    let uri: rupnp::http::Uri = server.device_url.parse().unwrap_or_else(|e| panic!("{e}"));
    let client = igd::IgdClient::from_device_url(uri)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let err = match client
        .add_mapping(
            &igd::IgdMapping {
                protocol: Protocol::Udp,
                internal_port: 6881,
                external_port: 6881,
                lease_secs: 3600,
                description: "taiji".into(),
            },
            std::net::Ipv4Addr::new(192, 168, 1, 10),
        )
        .await
    {
        Err(e) => e,
        Ok(_) => panic!("faulting control override must fail"),
    };
    let rendered = err.to_string();
    assert!(
        rendered.len() < 256,
        "fault text must be clipped, got {}B: {rendered}",
        rendered.len()
    );
    // Clipping must not break error-code semantics (mapping fallback
    // depends on upnp_code).
    match &err {
        igd::IgdError::Action { source, .. } => {
            assert_eq!(igd::IgdError::upnp_code(source), Some(606));
        }
        other => panic!("expected Action error, got {other:?}"),
    }

    // (2) Port text (InvalidPort) clipping: a garbage NewInternalPort
    // reply.
    let garbage = "9".repeat(8 * 1024);
    let control = soap_response(
        "GetSpecificPortMappingEntry",
        &format!(
            "<NewInternalPort>{garbage}</NewInternalPort>\
             <NewInternalClient>192.168.1.10</NewInternalClient>\
             <NewEnabled>1</NewEnabled>\
             <NewPortMappingDescription>d</NewPortMappingDescription>\
             <NewLeaseDuration>3600</NewLeaseDuration>"
        ),
    );
    let server = IgdServer::start_with_attacks(
        IgdMode::Normal,
        3600,
        AttackOverrides {
            desc: None,
            control: Some(control),
        },
    )
    .await;
    let uri: rupnp::http::Uri = server.device_url.parse().unwrap_or_else(|e| panic!("{e}"));
    let client = igd::IgdClient::from_device_url(uri)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let err = match client.query_mapping(Protocol::Tcp, 6881).await {
        Err(e) => e,
        Ok(info) => panic!("garbage port must fail, got {info:?}"),
    };
    assert!(matches!(err, igd::IgdError::InvalidPort(_)), "got {err}");
    let rendered = err.to_string();
    assert!(
        rendered.len() < 256,
        "port text must be clipped, got {}B",
        rendered.len()
    );
}

/// Precheck bypass resistance: fake close tags hidden inside attribute
/// values (a shape that deflates the byte-level depth count) are still
/// rejected by the depth check — quote awareness is a security property of
/// the precheck; legitimate shallow documents are unaffected.
#[test]
fn depth_precheck_resists_attribute_fake_closes() {
    // 40 open-tag layers, each attribute embedding 2 fake </device>:
    // without quote awareness the byte-level depth would deflate layer by
    // layer (+1 -2) and the deep document would reach roxmltree, triggering
    // a recursive abort.
    let mut xml = String::from("<root>");
    for _ in 0..40 {
        xml.push_str("<device attr=\"</device></device>\"><deviceList>");
    }
    for _ in 0..40 {
        xml.push_str("</deviceList></device>");
    }
    xml.push_str("</root>");
    assert!(
        igd::precheck_xml_depth(&xml).is_err(),
        "fake closes inside attributes must not defeat the depth cap"
    );
    // A legitimate document (the mock IGD device description) passes.
    assert!(igd::precheck_xml_depth(device_xml()).is_ok());
}

// ---------------------------------------------------------------------------
// Discovery-side negative assertions (stock paths unchanged)
// ---------------------------------------------------------------------------

/// SSDP Location host validation table (RFC 1918 §3 private + RFC 3927
/// §2.1 link-local IPv4 literals pass; loopback/public/domain/v6/
/// unspecified/multicast/CGNAT rejected; when an explicit gateway is
/// configured the host must match — the host-side equivalent of libtorrent
/// `upnp_ignore_nonrouters`, upnp.cpp).
#[test]
fn location_host_validation_table() {
    let parse =
        |url: &str| -> rupnp::http::Uri { url.parse().unwrap_or_else(|e| panic!("{url}: {e}")) };
    // Accept set (private/link-local literals; no gateway configured).
    for url in [
        "http://192.168.1.1:5431/dyndev/uuid:x",
        "http://10.0.0.1/desc.xml",
        "http://172.16.5.5:80/",
        "http://172.31.255.254/desc",
        "http://169.254.10.10:5000/x",
    ] {
        let uri = parse(url);
        assert!(
            igd::validate_location_host(&uri, None).is_ok(),
            "must accept local-link literal: {url}"
        );
    }
    // Reject set (SSRF/hijack shapes).
    for (url, why) in [
        (
            "http://127.0.0.1:5000/desc.xml",
            "loopback (localhost SSRF surface)",
        ),
        ("http://203.0.113.7/desc.xml", "public literal (TEST-NET-3)"),
        (
            "http://example.com/desc.xml",
            "domain name (off-link DNS trust step)",
        ),
        (
            "http://[::1]/desc.xml",
            "IPv6 literal (discovery face is v4 multicast)",
        ),
        ("http://0.0.0.0/desc.xml", "unspecified address"),
        ("http://224.0.0.1/desc.xml", "multicast range"),
        ("http://100.64.0.1/desc.xml", "CGNAT (outside RFC1918)"),
    ] {
        let uri = parse(url);
        assert!(
            igd::validate_location_host(&uri, None).is_err(),
            "must reject {url} ({why})"
        );
    }
    // Explicit gateway match: host == configured gateway passes; a
    // different host is rejected (other LAN devices' self-advertisements
    // are not candidates).
    let gw = std::net::Ipv4Addr::new(192, 168, 1, 1);
    assert!(igd::validate_location_host(&parse("http://192.168.1.1/desc.xml"), Some(gw)).is_ok());
    assert!(
        igd::validate_location_host(&parse("http://10.0.0.1/desc.xml"), Some(gw)).is_err(),
        "host must match explicitly configured gateway"
    );
    // No host (path-only URI) is rejected.
    assert!(igd::validate_location_host(&parse("/desc.xml"), None).is_err());
}

/// SSDP stream consumption skeleton — a single Err is logged and counted
/// and the round continues; a hit ends the round early (locking in the
/// opposite of rupnp's `parse()?` one-error-kills-the-round semantics).
#[tokio::test]
async fn ssdp_stream_single_error_continues() {
    // Scenario 1: bad-good-bad-good-bad stream, the second good item hits
    // -> skipped = 2, and the hit ends the round (trailing bad items
    // unconsumed).
    let items: Vec<Result<i32, &'static str>> = vec![
        Err("malformed-1"),
        Ok(1),
        Err("malformed-2"),
        Ok(2),
        Err("malformed-3"),
    ];
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    let mut stream = futures::stream::iter(items);
    let (skipped, found) = igd::for_each_ssdp_response(&mut stream, move |item| {
        let sink = sink.clone();
        async move {
            sink.lock().unwrap_or_else(|p| p.into_inner()).push(item);
            if item == 2 { Some("hit") } else { None }
        }
    })
    .await;
    assert_eq!(found, Some("hit"), "hit must short-circuit the round");
    assert_eq!(
        skipped, 2,
        "two malformed responses skipped, round continued"
    );
    assert_eq!(
        *seen.lock().unwrap_or_else(|p| p.into_inner()),
        vec![1, 2],
        "items processed despite interleaved errors"
    );

    // Scenario 2: no hit -> the stream drains and the round ends; bad items
    // do not terminate (skipped = 2).
    let items: Vec<Result<i32, &'static str>> =
        vec![Err("malformed-1"), Ok(1), Ok(3), Err("malformed-2")];
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    let mut stream = futures::stream::iter(items);
    let (skipped, found) = igd::for_each_ssdp_response(&mut stream, move |item| {
        let sink = sink.clone();
        async move {
            sink.lock().unwrap_or_else(|p| p.into_inner()).push(item);
            None::<i32>
        }
    })
    .await;
    assert_eq!(found, None);
    assert_eq!(skipped, 2);
    assert_eq!(*seen.lock().unwrap_or_else(|p| p.into_inner()), vec![1, 3]);
}

/// Epoch poisoning breaker table, short tier (pure state machine; the
/// [`natpmp::EPOCH_POISON_STRIKES`]-th regression within the short
/// [`natpmp::EPOCH_POISON_WINDOW`] window = the poisoned terminal state;
/// sparse regressions reset the count — legitimate occasional reboots are
/// unaffected). The guard is two-tier: the long tier
/// ([`natpmp::EPOCH_POISON_LONG_STRIKES`] regressions per
/// [`natpmp::EPOCH_POISON_LONG_WINDOW`]) has its own tests below; these
/// sequences never fill it before the short tier trips (the last
/// regression of the second sequence fills both tiers at once).
#[test]
fn epoch_poison_guard_table() {
    // Constant lock-in (local policy; see the constant docs).
    assert_eq!(natpmp::EPOCH_POISON_WINDOW, Duration::from_secs(60));
    assert_eq!(natpmp::EPOCH_POISON_STRIKES, 4);

    let t0 = std::time::Instant::now();
    // Consecutive regressions within the window: the 4th trips -> poisoned
    // terminal state (always true afterwards).
    let mut guard = natpmp::EpochPoisonGuard::default();
    assert!(!guard.observe_regression(t0), "first regression = baseline");
    assert!(!guard.observe_regression(t0 + Duration::from_secs(1)));
    assert!(!guard.observe_regression(t0 + Duration::from_secs(2)));
    assert!(
        guard.observe_regression(t0 + Duration::from_secs(3)),
        "4th regression within window = poisoning （recreate loop)"
    );
    assert!(guard.poisoned());
    assert!(guard.observe_regression(t0 + Duration::from_secs(4)));

    // Sparse regressions (>= a window apart) reset the count: legitimate
    // occasional reboots never trip.
    let mut guard = natpmp::EpochPoisonGuard::default();
    assert!(!guard.observe_regression(t0));
    assert!(
        !guard.observe_regression(t0 + Duration::from_secs(120)),
        "sparse regression resets the strike counter"
    );
    assert!(!guard.observe_regression(t0 + Duration::from_secs(240)));
    assert!(!guard.observe_regression(t0 + Duration::from_secs(241)));
    assert!(!guard.observe_regression(t0 + Duration::from_secs(242)));
    assert!(
        guard.observe_regression(t0 + Duration::from_secs(243)),
        "4 consecutive within window still trips after reset"
    );
}

/// Long tier (rate limit): regressions paced just past the short window
/// reset the short count on every strike (each gap >= 60s), yet the
/// [`natpmp::EPOCH_POISON_LONG_STRIKES`]-th regression within one
/// [`natpmp::EPOCH_POISON_LONG_WINDOW`] still trips the breaker — a slow
/// forged cadence can no longer keep the recreate loop alive forever.
#[test]
fn epoch_poison_guard_slow_cadence_trips_long_window() {
    // Constant lock-in (local policy; see the constant docs).
    assert_eq!(natpmp::EPOCH_POISON_LONG_WINDOW, Duration::from_secs(3600));
    assert_eq!(natpmp::EPOCH_POISON_LONG_STRIKES, 6);

    let t0 = std::time::Instant::now();
    // 70s apart: every gap exceeds the short window (the short count
    // resets each time), all inside the first long window.
    let step = Duration::from_secs(70);
    let mut guard = natpmp::EpochPoisonGuard::default();
    for i in 0..5u32 {
        assert!(
            !guard.observe_regression(t0 + step * i),
            "regression at t0 + {i} x 70s stays below the long-tier strike count"
        );
    }
    assert!(
        guard.observe_regression(t0 + step * 5),
        "6th regression within the long window (t0 + 350s) = poisoning"
    );
    assert!(guard.poisoned());
    assert!(guard.observe_regression(t0 + step * 6), "terminal state");
}

/// Long-tier window roll: the window is fixed, opened by its first
/// regression; a regression at/after its end (the >= boundary) rolls it
/// over and counts as the new window's first strike — a real gateway's
/// occasional reboots never accumulate across windows into a trip.
#[test]
fn epoch_poison_guard_long_window_rolls() {
    let t0 = std::time::Instant::now();
    let step = Duration::from_secs(70);
    let mut guard = natpmp::EpochPoisonGuard::default();
    for i in 0..5u32 {
        assert!(!guard.observe_regression(t0 + step * i));
    }
    // The 6th lands on the long-window end (t0 + 1h): the window rolls
    // instead of filling.
    let t1 = t0 + natpmp::EPOCH_POISON_LONG_WINDOW;
    assert!(
        !guard.observe_regression(t1),
        "a regression at/after the long-window end rolls the window, no trip"
    );
    assert!(!guard.poisoned());
    // The rolled window counts from that regression (strike 1): four more
    // stay below the strike count, its own 6th trips.
    for i in 1..5u32 {
        assert!(!guard.observe_regression(t1 + step * i));
    }
    assert!(
        guard.observe_regression(t1 + step * 5),
        "the rolled window fills at its own 6th regression"
    );
}

/// `map` attempts each protocol independently — when TCP is selectively
/// rejected (FailTcp mode), UDP is still mapped and entered into wanted
/// (the old implementation short-circuited on TCP via `?`, so UDP was never
/// recorded and never retried; the trigger surface of a TCP-targeting
/// hostile gateway).
#[tokio::test]
async fn map_collects_protocols_tcp_failure_still_maps_udp() {
    let server = PmpServer::start(PmpMode::FailTcp).await;
    let (handle, mut events, join) = super::spawn(test_config(&server, &[30, 30, 30]));
    let err = match handle.map(6881, Duration::from_secs(2)).await {
        Err(e) => e,
        Ok(()) => panic!("tcp-directed failure must surface"),
    };
    assert!(
        matches!(
            err,
            super::NatError::NatPmp(natpmp::NatPmpError::Result(RESULT_NOT_AUTHORIZED))
        ),
        "unexpected: {err}"
    );
    // The UDP mapping exists (TCP failure does not take UDP down).
    let snap = handle.snapshot().await.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        snap.mappings.len(),
        1,
        "udp mapping must exist despite tcp failure"
    );
    assert_eq!(snap.mappings[0].protocol, Protocol::Udp);
    assert_eq!(snap.mappings[0].external_port, 6881);
    // Event surface: Failed for the TCP round + Mapped for the UDP round.
    let (mut failed, mut mapped) = (false, false);
    for _ in 0..2 {
        match events.recv().await {
            Some(NatEvent::Failed { .. }) => failed = true,
            Some(NatEvent::Mapped { .. }) => mapped = true,
            other => panic!("unexpected event: {other:?}"),
        }
    }
    assert!(failed && mapped, "both round outcomes must be reported");
    drop(handle);
    let _ = join.await;
}

/// External port 0 in a success map reply (the §3.4 delete-reply shape
/// smuggled in) fails the whole round — port 0 must never reach the
/// mapping/watch/announce surface.
#[tokio::test]
async fn zero_external_port_reply_rejected() {
    let server = PmpServer::start(PmpMode::ZeroExternal).await;
    let (handle, mut events, join) = super::spawn(test_config(&server, &[30, 30, 30]));
    let err = match handle
        .map_one(Protocol::Tcp, 6881, Duration::from_secs(2))
        .await
    {
        Err(e) => e,
        Ok(()) => panic!("external port 0 success reply must be rejected "),
    };
    assert!(
        matches!(
            err,
            super::NatError::NatPmp(natpmp::NatPmpError::InvalidReply(_))
        ),
        "unexpected: {err}"
    );
    let snap = handle.snapshot().await.unwrap_or_else(|e| panic!("{e}"));
    assert!(
        snap.mappings.is_empty(),
        "poisoned port must not enter the mapping/watch surface"
    );
    // Event surface: one Failed, zero Mapped.
    match events.recv().await {
        Some(NatEvent::Failed { .. }) => {}
        other => panic!("unexpected event: {other:?}"),
    }
    assert!(events.try_recv().is_err(), "no Mapped event for port 0");
    drop(handle);
    let _ = join.await;
}

/// A too-small granted lifetime (1s < the 60s floor) is recorded as the
/// requested value — snapshot lock-in plus the §3.3 halfway renewal cadence
/// must not compress to 500ms (negative assertion of the poisoning
/// surface).
#[tokio::test]
async fn tiny_granted_lifetime_falls_back_to_request() {
    let server = PmpServer::start(PmpMode::GrantLifetime(1)).await;
    let (handle, mut events, join) = super::spawn(test_config(&server, &[30, 30, 30]));
    handle
        .map_one(Protocol::Tcp, 6881, Duration::from_secs(3600))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    match events.recv().await {
        Some(NatEvent::Mapped { external_port, .. }) => assert_eq!(external_port, 6881),
        other => panic!("unexpected event: {other:?}"),
    }
    // Grant 1s < [`natpmp::MIN_GRANTED_LIFETIME_SECS`] -> recorded as the
    // requested 3600s.
    let snap = handle.snapshot().await.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(snap.mappings.len(), 1);
    assert_eq!(
        snap.mappings[0].granted_lease_secs, 3600,
        "tiny grant must fall back to the requested lifetime"
    );
    // Honoring the 1s grant -> halfway renewal every 500ms; honoring the
    // requested 3600s -> the renewal point is 60min away. Zero renewal
    // requests within the 1.2s window.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let tcp_maps = server.requests().iter().filter(|(op, ..)| *op == 2).count();
    assert_eq!(tcp_maps, 1, "no renewal hammering, got {tcp_maps}");
    drop(handle);
    let _ = join.await;
}

/// Epoch poisoning end-to-end — forged replies alternating 10000/0 drive
/// sustained §3.6 regressions; filling the short window trips the breaker:
/// the PMP transaction surface goes quiet (after the 4th regression), new
/// map commands report Poisoned, and unmap sends no delete transactions
/// (the degraded "disable PMP" semantics; the IGD backend continues). The
/// jitter injection makes the run deterministic (§3.7's random 0-5s delay
/// pinned via the `NatConfig::recreate_jitter` test seam).
#[tokio::test]
async fn epoch_poisoning_trips_circuit_breaker() {
    let server = PmpServer::start(PmpMode::EpochPoison).await;
    let mut config = test_config(&server, &[50, 50, 50]);
    // Jitter pinned to 1ms (non-zero = deterministic test-seam advance;
    // ZERO = production semantics, the §3.7 random 0-5s) — the recreate
    // cadence is deterministic and 4 rounds complete in milliseconds.
    config.recreate_jitter = Duration::from_millis(1);
    config.address_poll = Duration::from_secs(3600);
    let (handle, _events, join) = super::spawn(config);
    handle
        .map_one(Protocol::Tcp, 6881, Duration::from_secs(3600))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    // 4 regressions = 4 rounds (map + address) = 8 requests, then the
    // breaker goes quiet.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if server.requests().len() >= 8 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "circuit breaker did not trip: {:?}",
            server.requests()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // The request surface stays quiet after the trip (no recreate loop —
    // the negative assertion of the attack path).
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        server.requests().len(),
        8,
        "no PMP traffic after the poisoning trip"
    );
    // A new map command -> Poisoned (the disable semantics, directly
    // observable).
    let err = match handle
        .map_one(Protocol::Tcp, 6882, Duration::from_secs(60))
        .await
    {
        Err(e) => e,
        Ok(()) => panic!("poisoned nat-pmp must be disabled"),
    };
    assert!(
        matches!(err, super::NatError::NatPmp(natpmp::NatPmpError::Poisoned)),
        "unexpected: {err}"
    );
    // Unmap sends no delete transaction (breaker first; the advisory delete
    // is backstopped by gateway lease expiry).
    handle.unmap().await.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(server.requests().len(), 8);
    drop(handle);
    let _ = join.await;
}

/// IGD-side symmetric check: NewReservedPort 0 on the 718 fallback path is
/// rejected as invalid (mirroring the port=0 pollution guard on the announce
/// surface, in the readback direction).
#[tokio::test]
async fn igd_reserved_port_zero_rejected() {
    let zero = soap_response("AddAnyPortMapping", "<NewReservedPort>0</NewReservedPort>");
    let server = IgdServer::start_conflict_with_any_port(3600, zero).await;
    let uri: rupnp::http::Uri = server.device_url.parse().unwrap_or_else(|e| panic!("{e}"));
    let client = igd::IgdClient::from_device_url(uri)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let err = match client
        .add_mapping(
            &igd::IgdMapping {
                protocol: Protocol::Tcp,
                internal_port: 6881,
                external_port: 6881,
                lease_secs: 3600,
                description: "taiji".into(),
            },
            std::net::Ipv4Addr::new(192, 168, 1, 10),
        )
        .await
    {
        Err(e) => e,
        Ok(port) => panic!("NewReservedPort 0 must be rejected, got {port}"),
    };
    assert!(matches!(err, igd::IgdError::InvalidPort(_)), "got {err}");
}

/// Unmap wait bounded (lock-in): against a silent gateway the delete wait
/// is capped by the short retransmission schedule (50ms x 2) with no
/// unbounded hang — the foundation under the session-level
/// `NAT_SHUTDOWN_BUDGET` (250ms) and the CLI shutdown budget (a slow
/// gateway must not erode the SPEC §8.1 shutdown budget).
#[tokio::test]
async fn unmap_wait_bounded_by_retransmit_schedule() {
    let server = PmpServer::start(PmpMode::Normal).await;
    let mut config = test_config(&server, &[30, 30, 30]);
    // Two-window delete schedule (the test_config default is one window;
    // §3.1 deletes are advisory and may be shorter than 9 tries).
    config.unmap_schedule = vec![Duration::from_millis(50), Duration::from_millis(50)];
    let (handle, _events, join) = super::spawn(config);
    handle
        .map_one(Protocol::Tcp, 6881, Duration::from_secs(3600))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    // The gateway goes silent (device offline / slow gateway shape).
    server.set_mode(PmpMode::Silent);
    let started = std::time::Instant::now();
    handle.unmap().await.unwrap_or_else(|e| panic!("{e}"));
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(90),
        "delete must actually retry both windows, took {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "unmap must stay schedule-bounded, took {elapsed:?}"
    );
    let deletes = server
        .requests()
        .iter()
        .filter(|(op, _, suggested, lifetime)| *op == 2 && *suggested == 0 && *lifetime == 0)
        .count();
    assert_eq!(deletes, 2, "one delete attempt per unmap window");
    let snap = handle.snapshot().await.unwrap_or_else(|e| panic!("{e}"));
    assert!(snap.mappings.is_empty());
    drop(handle);
    let _ = join.await;
}

/// Smoke test for the IGD parsing fuzz shims (the in-process contract; the
/// real libfuzzer driver is fuzz/fuzz_targets/igd_device_xml.rs).
#[test]
fn igd_fuzz_entry_points_smoke() {
    // Legitimate document Ok; deep nesting rejected by the depth precheck
    // (before roxmltree).
    assert!(igd::parse_device_description_for_fuzz(device_xml().as_bytes()).is_ok());
    assert!(igd::parse_device_description_for_fuzz(deep_device_xml(2000).as_bytes()).is_err());
    // Arbitrary garbage only ever Ok/Err, never panics (fuzz contract).
    for garbage in [
        &b""[..],
        b"\xff\xfe<><><>",
        b"<a><b></a></b>",
        b"<?xml ?><root attr=\"</root>\">",
    ] {
        let _ = igd::parse_device_description_for_fuzz(garbage);
    }
    // SOAP reply surface: fault -> Err (error-code semantics preserved),
    // valid reply -> Ok, garbage does not panic.
    assert!(
        igd::parse_action_response_for_fuzz("AddPortMapping", soap_fault(718, "x").as_bytes())
            .is_err()
    );
    assert!(
        igd::parse_action_response_for_fuzz(
            "AddPortMapping",
            soap_response("AddPortMapping", "").as_bytes()
        )
        .is_ok()
    );
    let _ = igd::parse_action_response_for_fuzz("AddPortMapping", b"\x00\xff garbage");
}

// ---------------------------------------------------------------------------
// Renewal port write-back (NAT-PMP + IGD) and IGD URLBase relativization
// ---------------------------------------------------------------------------

/// After the gateway assigns a different external port, the timer-driven
/// renewal path (due_for_renewal -> ensure_wanted) must resend the map
/// request with suggested external port = the assigned value (RFC 6886
/// §3.3 final paragraph: renewals MUST suggest the assigned external port
/// — port stability across gateway reboots/reassignment). The echo-same-
/// port mock (actor_natpmp_map_and_snapshot) cannot detect this defect:
/// its suggested value always equals the assigned value, so whether the
/// suggestion was written back is indistinguishable. Red = the second map
/// frame still suggests the internal port 6881.
#[tokio::test]
async fn pc11_natpmp_timer_renewal_suggests_assigned_port() {
    // assigned_external=40001: the suggested port is occupied -> the
    // gateway assigns another (§3.3 "If that external port is not
    // available, the NAT gateway MUST return an available external port if
    // possible").
    let server = PmpServer::start_with(PmpMode::Normal, 3600, 40001).await;
    let (handle, mut events, join) = super::spawn(test_config(&server, &[50, 50, 50]));
    handle
        .map_one(Protocol::Tcp, 6881, Duration::from_secs(2))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    match events.recv().await {
        Some(NatEvent::Mapped { external_port, .. }) => {
            assert_eq!(external_port, 40001, "the gateway-granted port is the fact");
        }
        other => panic!("unexpected event: {other:?}"),
    }
    // Grant 2s -> renewal point 1s (renew_delay halfway); 1800ms = cadence
    // + tick margin.
    tokio::time::sleep(Duration::from_millis(1800)).await;
    let suggested: Vec<u16> = server
        .requests()
        .iter()
        .filter(|(op, ..)| *op == 2)
        .map(|(_, _, suggested, _)| *suggested)
        .collect();
    assert!(
        suggested.len() >= 2,
        "map + timer renewal must both arrive, got {suggested:?}"
    );
    assert_eq!(
        suggested[0], 6881,
        "first map suggests external port = internal port (the RFC 6886 §3.3 norm)"
    );
    assert_eq!(
        suggested[1], 40001,
        "RFC 6886 §3.3: the renewal request suggests external port = the assigned value 40001"
    );
    drop(handle);
    let _ = join.await;
}

/// The IGD-side counterpart — after AddAnyPortMapping assigns 40001, the
/// timer-driven renewal's AddPortMapping must carry NewExternalPort = the
/// written-back reserved port (eliminating the per-round
/// 718 -> AddAnyPortMapping loop; renewal semantics = the §2.5.16
/// same-port overwrite). Red = the renewal request still carries 6881.
#[tokio::test]
async fn pc11_igd_timer_renewal_uses_reserved_port() {
    // Conflict mode: AddPortMapping always 718 -> v2 fallback NewReservedPort
    // 40001; lease readback 2s -> renewal point 1s.
    let server = IgdServer::start(IgdMode::Conflict, 2).await;
    let config = NatConfig {
        enable_natpmp: false,
        enable_upnp: true,
        igd_device_url: Some(server.device_url.clone()),
        lease: Duration::from_secs(2),
        address_poll: Duration::from_secs(3600),
        ..NatConfig::default()
    };
    let (handle, mut events, join) = super::spawn(config);
    handle
        .map_one(Protocol::Tcp, 6881, Duration::from_secs(2))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    match events.recv().await {
        Some(NatEvent::Mapped { external_port, .. }) => {
            assert_eq!(external_port, 40001, "§2.5.17 NewReservedPort");
        }
        other => panic!("unexpected event: {other:?}"),
    }
    tokio::time::sleep(Duration::from_millis(1800)).await;
    let ports = server.add_port_externals();
    assert!(
        ports.len() >= 2,
        "map + timer renewal must both arrive, got {ports:?}"
    );
    assert_eq!(
        ports[0], 6881,
        "first map requests external port = internal port"
    );
    assert_eq!(
        ports[1], 40001,
        "the renewal AddPortMapping must carry the written-back reserved port 40001"
    );
    drop(handle);
    let _ = join.await;
}

/// Device-description <URLBase> relativization (UDA 1.1 §2.3 — when
/// URLBase is present, relative URLs in the description merge against it;
/// the default base is the description retrieval URL). Three shapes:
/// (1) absolute-path controlURL + URLBase changing the authority — SOAP
/// goes to the URLBase authority (real routers changing ports); (2)
/// relative-path controlURL + trailing-slash URLBase — prefix kept
/// (/root/ + control -> /root/control); (3) no trailing slash — the last
/// segment is replaced (/root + control -> /control). (1) is an RFC 3986
/// §5.3 absolute-path reference; (2)/(3) are §5.2.3 merge (locking in the
/// merge difference between the two real shapes). Red = controlURL always
/// based on the description URL authority ((1) hits the description
/// server; (2)/(3) are rejected at the scan layer by PathAndQuery parsing
/// — a path not starting with '/' is unresolvable).
#[tokio::test]
async fn pc11_igd_urlbase_relativizes_control_url() {
    let mapping = || igd::IgdMapping {
        protocol: Protocol::Tcp,
        internal_port: 6881,
        external_port: 6881,
        lease_secs: 3600,
        description: "taiji".into(),
    };

    // (1) Absolute-path controlURL: URLBase = the control server's
    // authority (no path, a different loopback port — the real-router
    // "URLBase changes the port" shape).
    {
        let ctl = IgdServer::start(IgdMode::Normal, 3600).await;
        let xml = device_xml_with_url_base(ctl.authority(), "/control");
        let desc = IgdServer::start_with_desc_xml(xml).await;
        let uri: rupnp::http::Uri = desc.device_url.parse().unwrap_or_else(|e| panic!("{e}"));
        let client = igd::IgdClient::from_device_url(uri)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let external = client
            .add_mapping(&mapping(), std::net::Ipv4Addr::new(192, 168, 1, 10))
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(external, 6881);
        assert_eq!(
            desc.post_paths(),
            Vec::<String>::new(),
            "SOAP must not hit the description server's authority"
        );
        assert_eq!(
            ctl.post_paths(),
            vec!["/control".to_string()],
            "absolute-path reference merged onto the URLBase authority + path"
        );
    }

    // (2) Relative-path controlURL + trailing-slash URLBase: /root/ +
    // control.
    {
        let ctl = IgdServer::start(IgdMode::Normal, 3600).await;
        let xml = device_xml_with_url_base(&format!("{}/root/", ctl.authority()), "control");
        let desc = IgdServer::start_with_desc_xml(xml).await;
        let uri: rupnp::http::Uri = desc.device_url.parse().unwrap_or_else(|e| panic!("{e}"));
        let client = igd::IgdClient::from_device_url(uri)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        client
            .add_mapping(&mapping(), std::net::Ipv4Addr::new(192, 168, 1, 10))
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            ctl.post_paths(),
            vec!["/root/control".to_string()],
            "trailing-slash URLBase: prefix kept (RFC 3986 §5.2.3 merge)"
        );
    }

    // (3) Relative-path controlURL + URLBase without trailing slash:
    // /root + control.
    {
        let ctl = IgdServer::start(IgdMode::Normal, 3600).await;
        let xml = device_xml_with_url_base(&format!("{}/root", ctl.authority()), "control");
        let desc = IgdServer::start_with_desc_xml(xml).await;
        let uri: rupnp::http::Uri = desc.device_url.parse().unwrap_or_else(|e| panic!("{e}"));
        let client = igd::IgdClient::from_device_url(uri)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        client
            .add_mapping(&mapping(), std::net::Ipv4Addr::new(192, 168, 1, 10))
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            ctl.post_paths(),
            vec!["/control".to_string()],
            "no-trailing-slash URLBase: last segment yields (RFC 3986 §5.2.3 merge)"
        );
    }
}
