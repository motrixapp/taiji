//! Acceptance: the NAT option-face wiring end to end (`--bt-enable-upnp` /
//! `--bt-enable-nat-pmp` -> `spawn_supervisor` powering -> `EngineConfig::nat`
//! injection -> the engine's existing Map/watch consumption -> shutdown
//! unmap, the full chain).
//!
//! Harness = a real SessionActor + a mock IGD (a minimal replica of the
//! existing io nat tests pattern: loopback HTTP `/desc.xml` + SOAP
//! control) + fake tracker / mini seeder (hook_session shape). The io-layer
//! protocol behavior (map/renew/conflict/offline paths, packet vectors) is
//! pinned in the `taiji_io::nat` tests; zero duplication here. The engine
//! consumption face (assemble triggering Map, tick following the external
//! port) is existing code, unchanged by this module — what this file pins
//! is the **session assembly chain**:
//!
//! - mock IGD full chain: powering -> engine activates Map (TCP+UDP) ->
//!   the external-port watch snapshot is visible
//!   ([`SessionHandle::nat_external_ports`]) -> the gateway reassigning
//!   (Conflict -> 40001) feeds the input face -> shutdown unmap (mock
//!   DeletePortMapping counts);
//! - default zero change: defaults (both options false) -> no powering, no
//!   assembly; behavior is bit-identical to the pre-wiring state; explicit
//!   both-on (`true`/`true`, the libtorrent settings_pack.cpp
//!   cross-validation shape) plus an unreachable gateway (dead endpoints)
//!   -> mapping failure degrades without blocking the download — the task
//!   still completes and the external-port snapshot keeps its default
//!   (the announce metric falls back to the local port); observable
//!   behavior matches the `nat: None` shape;
//! - all-off zero change: both options false -> no powering (snapshot face
//!   None) -> the download proceeds as usual.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha1::{Digest as _, Sha1};
use taiji_bt::bencode::{self, Value};
use taiji_core::nat::ExternalPorts;
use taiji_core::session::{
    CommandReply, GlobalOptions, SessionActor, SessionCommand, SessionError, SessionHandle,
    SessionOptions,
};
use taiji_io::nat::NatConfig;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const PIECE_LEN: u32 = 16384;

fn test_content() -> Vec<u8> {
    const P: &[&[u8]] = &[b"taiji-p107-nat-"];
    P.iter()
        .flat_map(|p| p.iter().copied().cycle())
        .take(2 * PIECE_LEN as usize)
        .collect()
}

/// Assembles a single-file v1 .torrent (hook_session shape).
fn build_v1_torrent(content: &[u8], announce: &str) -> (Vec<u8>, [u8; 20]) {
    let mut pieces = Vec::new();
    for c in content.chunks(PIECE_LEN as usize) {
        pieces.extend_from_slice(&Sha1::digest(c));
    }
    let info = Value::Dict(vec![
        (b"length".to_vec(), Value::Int(content.len() as i64)),
        (b"name".to_vec(), Value::Bytes(b"blob.bin".to_vec())),
        (b"piece length".to_vec(), Value::Int(PIECE_LEN as i64)),
        (b"pieces".to_vec(), Value::Bytes(pieces)),
    ]);
    let info_bytes = bencode::encode(&info).unwrap_or_else(|e| panic!("{e}"));
    let mut hasher = Sha1::new();
    hasher.update(&info_bytes);
    let infohash: [u8; 20] = hasher.finalize().into();
    let top = Value::Dict(vec![
        (
            b"announce".to_vec(),
            Value::Bytes(announce.as_bytes().to_vec()),
        ),
        (b"info".to_vec(), info),
    ]);
    (
        bencode::encode(&top).unwrap_or_else(|e| panic!("{e}")),
        infohash,
    )
}

/// Fake tracker: replies with compact peers = the seeder address
/// (hook_session shape).
async fn fake_tracker(seeder_addr: std::net::SocketAddr) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    tokio::spawn(async move {
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
        let std::net::IpAddr::V4(v4) = seeder_addr.ip() else {
            panic!("test expects IPv4 seeder addr");
        };
        let ip = v4.octets();
        let port = seeder_addr.port().to_be_bytes();
        let mut peers = Vec::new();
        peers.extend_from_slice(&ip);
        peers.extend_from_slice(&port);
        let mut raw = Vec::new();
        raw.extend_from_slice(b"d8:intervali60e5:peers");
        raw.extend_from_slice(peers.len().to_string().as_bytes());
        raw.push(b':');
        raw.extend_from_slice(&peers);
        raw.push(b'e');
        let head = format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n", raw.len());
        sock.write_all(head.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        sock.write_all(&raw).await.unwrap_or_else(|e| panic!("{e}"));
    });
    addr
}

/// Mini seeder: interested -> unchoke, request -> piece (hook_session
/// shape).
async fn spawn_mini_seeder(
    listener: tokio::net::TcpListener,
    content: Vec<u8>,
    info_hash: [u8; 20],
) {
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap_or_else(|e| panic!("{e}"));
        let mut hs = [0u8; 68];
        sock.read_exact(&mut hs)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(&hs[28..48], &info_hash, "engine handshake info_hash");
        let mut resp = [0u8; 68];
        resp[0] = 19;
        resp[1..20].copy_from_slice(b"BitTorrent protocol");
        resp[25] = 0x10; // extended
        resp[27] = 0x04; // fast
        resp[28..48].copy_from_slice(&info_hash);
        resp[48..68].copy_from_slice(b"SEEDERSEEDERSEEDER00");
        sock.write_all(&resp)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        // Full bitfield advertisement (2 pieces).
        sock.write_all(&[0, 0, 0, 2, 5, 0b1100_0000])
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        loop {
            let mut len_buf = [0u8; 4];
            if sock.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let len = u32::from_be_bytes(len_buf) as usize;
            if len == 0 {
                continue;
            }
            let mut body = vec![0u8; len];
            sock.read_exact(&mut body)
                .await
                .unwrap_or_else(|e| panic!("{e}"));
            match body[0] {
                2 => {
                    sock.write_all(&[0, 0, 0, 1, 1])
                        .await
                        .unwrap_or_else(|e| panic!("{e}"));
                }
                6 => {
                    let index = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
                    let begin = u32::from_be_bytes([body[5], body[6], body[7], body[8]]);
                    let length = u32::from_be_bytes([body[9], body[10], body[11], body[12]]);
                    let offset = index as usize * PIECE_LEN as usize + begin as usize;
                    let block = content[offset..offset + length as usize].to_vec();
                    let mut frame = Vec::new();
                    frame.extend_from_slice(((9 + block.len()) as u32).to_be_bytes().as_slice());
                    frame.push(7u8);
                    frame.extend_from_slice(&index.to_be_bytes());
                    frame.extend_from_slice(&begin.to_be_bytes());
                    frame.extend_from_slice(&block);
                    sock.write_all(&frame)
                        .await
                        .unwrap_or_else(|e| panic!("{e}"));
                }
                _ => {}
            }
        }
    });
}

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let d = std::env::temp_dir().join(format!("bh-p107-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap_or_else(|e| panic!("{e}"));
    d
}

fn gid_of(reply: Result<CommandReply, SessionError>) -> taiji_core::gid::Gid {
    match reply.unwrap_or_else(|e| panic!("{e}")) {
        CommandReply::Gid(g) => g,
        other => panic!("expected Gid, got {other:?}"),
    }
}

/// Polls for download completion (verify-then-write -> all pieces on disk
/// = download complete; hook_session shape).
async fn wait_download_complete(dir: &std::path::Path, content: &[u8], timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        if std::fs::read(dir.join("blob.bin"))
            .map(|bytes| bytes == content)
            .unwrap_or(false)
        {
            return;
        }
        if Instant::now() > deadline {
            panic!("download did not complete in time");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Polls the external-port snapshot until the predicate holds (the watch
/// snapshot face; panics on timeout).
async fn wait_nat_ports(
    handle: &SessionHandle,
    pred: impl Fn(&ExternalPorts) -> bool,
) -> ExternalPorts {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(ports) = handle.nat_external_ports()
            && pred(&ports)
        {
            return ports;
        }
        if Instant::now() > deadline {
            panic!(
                "external ports predicate not met in time, got {:?}",
                handle.nat_external_ports()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ---------------------------------------------------------------------------
// Mock IGD (a minimal replica of the existing IgdServer pattern from the
// io nat tests: Normal = everything succeeds; Conflict = 718 ->
// AddAnyPortMapping reassigns 40001)
// ---------------------------------------------------------------------------

const MOCK_EXTERNAL_IP: &str = "203.0.113.7";
const ANY_PORT: u16 = 40001;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IgdMode {
    Normal,
    Conflict,
}

#[derive(Default)]
struct IgdState {
    add_port_mapping_calls: usize,
    add_any_port_calls: usize,
    delete_calls: usize,
}

struct IgdServer {
    state: Arc<Mutex<IgdState>>,
    device_url: String,
}

impl IgdServer {
    async fn start(mode: IgdMode) -> Self {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap_or_else(|e| panic!("mock igd bind: {e}"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("mock igd addr: {e}"))
            .port();
        let state = Arc::new(Mutex::new(IgdState::default()));
        let task_state = state.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let st = task_state.clone();
                let mode = mode;
                tokio::spawn(async move {
                    let _ = serve_http(stream, st, mode).await;
                });
            }
        });
        Self {
            state,
            device_url: format!("http://127.0.0.1:{port}/desc.xml"),
        }
    }

    fn counts(&self) -> (usize, usize, usize) {
        let st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        (
            st.add_port_mapping_calls,
            st.add_any_port_calls,
            st.delete_calls,
        )
    }
}

/// Minimal HTTP/1.1 server (path + SOAPAction dispatch; the rupnp client
/// face).
async fn serve_http(
    mut stream: tokio::net::TcpStream,
    state: Arc<Mutex<IgdState>>,
    mode: IgdMode,
) -> std::io::Result<()> {
    loop {
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
            if lower.starts_with("soapaction:") {
                soap_action = line
                    .split(':')
                    .skip(1)
                    .collect::<String>()
                    .trim()
                    .to_string();
            }
        }
        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            stream.read_exact(&mut body).await?;
        }

        if request_line.starts_with("GET /desc.xml") {
            let _ = stream.write_all(&http_ok(device_xml(), "text/xml")).await;
            continue;
        }
        if request_line.starts_with("POST /control") {
            let action = soap_action
                .rsplit('#')
                .next()
                .unwrap_or_default()
                .trim_matches('"')
                .to_string();
            let resp = handle_control(&state, mode, &action);
            let _ = stream.write_all(&http_ok(&resp, "text/xml")).await;
            continue;
        }
        let _ = stream.write_all(&http_ok("", "text/plain")).await;
    }
}

/// SOAP control dispatch (WANIPConnection:2 behavior face, same rule as
/// the io mock).
fn handle_control(state: &Mutex<IgdState>, mode: IgdMode, action: &str) -> String {
    let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
    match action {
        "GetExternalIPAddress" => soap_response(
            "GetExternalIPAddress",
            &format!("<NewExternalIPAddress>{MOCK_EXTERNAL_IP}</NewExternalIPAddress>"),
        ),
        "AddPortMapping" => {
            st.add_port_mapping_calls += 1;
            match mode {
                IgdMode::Normal => soap_response("AddPortMapping", ""),
                IgdMode::Conflict => soap_fault(718, "ConflictInMappingEntry"),
            }
        }
        "AddAnyPortMapping" => {
            st.add_any_port_calls += 1;
            soap_response(
                "AddAnyPortMapping",
                &format!("<NewReservedPort>{ANY_PORT}</NewReservedPort>"),
            )
        }
        "GetSpecificPortMappingEntry" => soap_response(
            "GetSpecificPortMappingEntry",
            "<NewInternalPort>6881</NewInternalPort>\
             <NewInternalClient>192.168.1.10</NewInternalClient>\
             <NewEnabled>1</NewEnabled>\
             <NewPortMappingDescription>taiji</NewPortMappingDescription>\
             <NewLeaseDuration>3600</NewLeaseDuration>",
        ),
        "DeletePortMapping" => {
            st.delete_calls += 1;
            soap_response("DeletePortMapping", "")
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
        r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>{code}</errorCode><errorDescription>{description}</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>"#
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

fn http_ok(body: &str, content_type: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// A directed NatConfig for the mock IGD (the device description URL
/// bypasses SSDP; NAT-PMP off — single-backend determinism; a 3600 s
/// lease read-back avoids renewal noise; a fast in-test retransmit
/// schedule).
fn igd_nat_config(server: &IgdServer, mode: IgdMode) -> NatConfig {
    let _ = mode;
    NatConfig {
        enable_natpmp: false,
        enable_upnp: true,
        igd_device_url: Some(server.device_url.clone()),
        lease: Duration::from_secs(3600),
        address_poll: Duration::from_secs(3600),
        retransmit_schedule: vec![Duration::from_millis(20)],
        unmap_schedule: vec![Duration::from_millis(20)],
        ..NatConfig::default()
    }
}

/// Standard download environment: seeder + fake tracker + single-file v1
/// torrent.
async fn setup_swarm(tag: &str) -> (Vec<u8>, std::net::SocketAddr, Vec<u8>, PathBuf) {
    let content = test_content();
    let seeder_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let seeder_addr = seeder_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"));
    let tracker_addr = fake_tracker(seeder_addr).await;
    let (torrent, infohash) =
        build_v1_torrent(&content, &format!("http://{tracker_addr}/announce"));
    spawn_mini_seeder(seeder_listener, content.clone(), infohash).await;
    let tmp = temp_dir(tag);
    (torrent, seeder_addr, content, tmp)
}

// ---------------------------------------------------------------------------
// End to end
// ---------------------------------------------------------------------------

/// Mock IGD full chain: options power the supervisor -> the engine
/// activates Map (TCP+UDP) -> the external-port watch snapshot is visible
/// -> the download is never blocked -> shutdown unmap (DeletePortMapping
/// counts). Mapping happens only when EngineConfig.nat is really injected
/// and the engine triggers Map with its actual port — this test is the
/// behavioral proof of the "options -> powering -> injection" chain.
#[tokio::test]
async fn mock_igd_full_chain_map_watch_and_shutdown_unmap() {
    let server = IgdServer::start(IgdMode::Normal).await;
    let (torrent, _seeder, content, tmp) = setup_swarm("full-chain").await;

    // Single-backend UPnP (natpmp off): option face upnp=true, natpmp=false
    // — the boolean composition semantics ride the same production chain
    // (build_nat_config).
    let (handle, join) = SessionActor::spawn_with(SessionOptions {
        global: GlobalOptions {
            bt_enable_upnp: true,
            bt_enable_natpmp: false,
            listen_port: 0, // ephemeral port: the map request port = the engine's actual bound port
            nat_config_override: Some(igd_nat_config(&server, IgdMode::Normal)),
            ..Default::default()
        },
    });
    assert!(
        handle.nat_external_ports().is_some(),
        "the snapshot face is ready after powering (None = not powered)"
    );
    let gid = gid_of(
        handle
            .call(SessionCommand::AddTorrent {
                torrent,
                options: BTreeMap::from([("dir".to_string(), tmp.display().to_string())]),
                position: None,
            })
            .await,
    );
    let _ = gid;

    // Engine activated -> assemble triggers Map (TCP first, UDP after) ->
    // the watch snapshot has both slots ready (Normal mode external port =
    // requested port = the engine's actual bound port, identical for both
    // protocols).
    let ports = wait_nat_ports(&handle, |p| p.tcp.is_some() && p.udp.is_some()).await;
    assert_eq!(
        ports.tcp, ports.udp,
        "both protocols map to the same requested port (the io mock's Normal-mode rule)"
    );
    // Mapping does not block the download (assemble semantics) -> the full
    // chain downloads to completion.
    wait_download_complete(&tmp, &content, Duration::from_secs(30)).await;

    // Shutdown path: unmap best-effort reverts (the engine does not unmap
    // by itself — session shutdown is the single point).
    let (adds, anys, deletes) = server.counts();
    assert!(adds >= 2, "TCP+UDP AddPortMapping, got {adds}");
    assert_eq!(anys, 0, "no conflict fallback in Normal mode");
    assert_eq!(
        deletes, 0,
        "the engine/session must not unmap before shutdown"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let (_, _, deletes) = server.counts();
    assert_eq!(deletes, 2, "shutdown unmap：TCP+UDP DeletePortMapping");
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Gateway reassignment (Conflict -> AddAnyPortMapping 40001): the
/// external-port watch follows the change — peer-side evidence for the
/// engine tick's input face (DHT announce re-port). The consumption face
/// is existing engine code; this module neither changes nor retests it.
#[tokio::test]
async fn mock_igd_conflict_reassigns_port_and_watch_follows() {
    let server = IgdServer::start(IgdMode::Conflict).await;
    let (handle, join) = SessionActor::spawn_with(SessionOptions {
        global: GlobalOptions {
            bt_enable_upnp: true,
            bt_enable_natpmp: false,
            listen_port: 0,
            nat_config_override: Some(igd_nat_config(&server, IgdMode::Conflict)),
            ..Default::default()
        },
    });
    let (torrent, _seeder, _content, tmp) = setup_swarm("conflict").await;
    let _ = handle
        .call(SessionCommand::AddTorrent {
            torrent,
            options: BTreeMap::from([("dir".to_string(), tmp.display().to_string())]),
            position: None,
        })
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    // 718 -> AddAnyPortMapping -> NewReservedPort 40001: the watch carries
    // the factual port.
    let ports = wait_nat_ports(&handle, |p| p.tcp == Some(ANY_PORT)).await;
    assert_eq!(
        ports.udp,
        Some(ANY_PORT),
        "the UDP face is granted the same 40001"
    );
    let (adds, anys, _) = server.counts();
    assert!(
        adds >= 2 && anys >= 2,
        "each protocol went through one conflict fallback: {adds}/{anys}"
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Explicit both-on + unreachable gateway (the degrading half): mapping
/// failure degrades without blocking the download — the task still
/// completes and the external-port snapshot keeps its default (the watch
/// does not fire -> the announce metric falls back to the local port).
/// Observable behavior identical to the pre-wiring `nat: None` shape:
/// completion artifacts, terminal state, snapshot face all the same
/// (locally the default is false; true/true is the libtorrent
/// settings_pack.cpp cross-validation shape — see the GlobalOptions field
/// docs; dead endpoints = deterministic fast failure, no real network
/// face involved).
#[tokio::test]
async fn both_true_with_dead_router_degrades_without_blocking() {
    let (torrent, _seeder, content, tmp) = setup_swarm("degrade").await;
    let (handle, join) = SessionActor::spawn_with(SessionOptions {
        global: GlobalOptions {
            bt_enable_upnp: true,
            bt_enable_natpmp: true,
            listen_port: 0,
            nat_config_override: Some(NatConfig {
                gateway: Some(std::net::Ipv4Addr::LOCALHOST),
                natpmp_port: 1,
                igd_device_url: Some("http://127.0.0.1:1/desc.xml".into()),
                retransmit_schedule: vec![Duration::from_millis(5)],
                unmap_schedule: vec![Duration::from_millis(5)],
                ..NatConfig::default()
            }),
            ..Default::default()
        },
    });
    assert!(
        handle.nat_external_ports().is_some(),
        "powered with both on (the snapshot default state)"
    );
    let _ = handle
        .call(SessionCommand::AddTorrent {
            torrent,
            options: BTreeMap::from([("dir".to_string(), tmp.display().to_string())]),
            position: None,
        })
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    // The NAT chain fails entirely (NoBackend) -> degradation without
    // blocking: the download still completes (the only difference from the
    // pre-wiring state is one more failed mapping attempt; observable
    // behavior unchanged).
    wait_download_complete(&tmp, &content, Duration::from_secs(30)).await;
    assert_eq!(
        handle.nat_external_ports(),
        Some(ExternalPorts::default()),
        "mapping failure → the watch keeps the default (announce semantics = \
         the local port, zero change)"
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&tmp);
}

/// All-off zero change: both options false -> no powering (snapshot face
/// None = no supervisor constructed) -> the download proceeds as usual
/// (the existing `nat: None` shape).
#[tokio::test]
async fn both_options_false_never_powers_nat() {
    let (torrent, _seeder, content, tmp) = setup_swarm("all-off").await;
    let (handle, join) = SessionActor::spawn_with(SessionOptions {
        global: GlobalOptions {
            bt_enable_upnp: false,
            bt_enable_natpmp: false,
            listen_port: 0,
            nat_config_override: Some(igd_nat_config(
                &IgdServer::start(IgdMode::Normal).await,
                IgdMode::Normal,
            )),
            ..Default::default()
        },
    });
    assert!(
        handle.nat_external_ports().is_none(),
        "all-off = no powering (no NatSupervisor constructed)"
    );
    let _ = handle
        .call(SessionCommand::AddTorrent {
            torrent,
            options: BTreeMap::from([("dir".to_string(), tmp.display().to_string())]),
            position: None,
        })
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    wait_download_complete(&tmp, &content, Duration::from_secs(30)).await;
    assert!(handle.nat_external_ports().is_none());

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Literal-default zero change (the main half): `SessionOptions::default()`
/// (both options default false) -> no supervisor constructed, no NAT
/// actor, zero NAT network face — session behavior bit-identical to the
/// pre-wiring state; the download still completes.
#[tokio::test]
async fn default_options_never_power_nat_or_touch_network() {
    let (torrent, _seeder, content, tmp) = setup_swarm("literal-default").await;
    let (handle, join) = SessionActor::spawn_with(SessionOptions::default());
    assert!(
        handle.nat_external_ports().is_none(),
        "no powering by default (zero change from the pre-wiring nat: None shape)"
    );
    let _ = handle
        .call(SessionCommand::AddTorrent {
            torrent,
            options: BTreeMap::from([("dir".to_string(), tmp.display().to_string())]),
            position: None,
        })
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    wait_download_complete(&tmp, &content, Duration::from_secs(30)).await;
    assert!(handle.nat_external_ports().is_none());

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&tmp);
}
