//! End-to-end discovery through injected DNS and real loopback tracker/peer
//! sockets. No system DNS settings or public network services are involved.
use sha1::{Digest as _, Sha1};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use taiji_bt::bencode::{self, Value};
use taiji_bt::peer_wire::ExtHandshake;
use taiji_bt::tracker::announce_list::TierEvent;
use taiji_bt::tracker::http::{HttpAnnounce, OwnedAnnounceParams, TrackerOptions};
use taiji_bt::ut_metadata::{ServeOutcome, UtMetadata, serve_request};
use taiji_core::gid::GidAllocator;
use taiji_core::magnet::{
    MagnetEnd, MagnetEngine, MagnetOptions, MagnetServices, MagnetTaskConfig, MetadataPhaseConfig,
};
use taiji_core::metainfo::Metainfo;
use taiji_io::dns::{HostResolver, ListResolverFuture, ResolverFuture, SharedDns};
use taiji_io::metrics::MetricsRegistry;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

const HOST: &str = "shared-dns-discovery.test";
const CONNECTION_ID: u64 = 0x1122_3344_5566_7788;
type TorrentFixtures = HashMap<[u8; 20], (Vec<u8>, Vec<u8>)>;

fn ok<T, E: std::fmt::Display>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| panic!("{error}"))
}
fn dict(mut entries: Vec<(&[u8], Value)>) -> Value {
    entries.sort_by(|a, b| a.0.cmp(b.0));
    Value::Dict(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_vec(), value))
            .collect(),
    )
}
fn fixture(label: &str) -> (Vec<u8>, [u8; 20], Vec<u8>) {
    let payload = vec![37u8; 32768];
    let info = ok(bencode::encode(&dict(vec![
        (b"length", Value::Int(payload.len() as i64)),
        (b"name", Value::Bytes(format!("{label}.bin").into_bytes())),
        (b"piece length", Value::Int(16384)),
        (
            b"pieces",
            Value::Bytes(payload.chunks(16384).flat_map(Sha1::digest).collect()),
        ),
        // Exercise several BEP9 fragments while keeping the fixture offline.
        (b"x-fixture", Value::Bytes(vec![b'x'; 32768])),
    ])));
    let hash = Sha1::digest(&info).into();
    (info, hash, payload)
}

struct DomainResolver {
    calls: Arc<AtomicUsize>,
    release: watch::Receiver<bool>,
}
impl HostResolver for DomainResolver {
    fn resolve(&self, host: String) -> ResolverFuture {
        let future = self.resolve_list(host);
        Box::pin(async move {
            future
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| "empty fixture".into())
        })
    }
    fn resolve_list(&self, host: String) -> ListResolverFuture {
        let calls = Arc::clone(&self.calls);
        let mut release = self.release.clone();
        Box::pin(async move {
            if host != HOST {
                return Err(format!("unexpected external DNS name in fixture: {host}"));
            }
            calls.fetch_add(1, Ordering::SeqCst);
            while !*release.borrow_and_update() {
                release.changed().await.map_err(|error| error.to_string())?;
            }
            // The first address has no responding tracker. Both addresses are
            // loopback; the healthy tracker is bound only to 127.0.0.1.
            Ok(vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
            ])
        })
    }
}

async fn write_frame(stream: &mut TcpStream, message: &[u8]) -> io::Result<()> {
    stream
        .write_all(&(message.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(message).await
}
async fn serve_metadata_peer(
    mut stream: TcpStream,
    fixtures: Arc<TorrentFixtures>,
    metadata_requests: Arc<AtomicUsize>,
    payload_requests: Arc<AtomicUsize>,
) -> io::Result<()> {
    let mut handshake = [0u8; 68];
    stream.read_exact(&mut handshake).await?;
    let hash: [u8; 20] = handshake[28..48]
        .try_into()
        .map_err(|_| io::Error::other("hash"))?;
    let (info, payload) = fixtures
        .get(&hash)
        .ok_or_else(|| io::Error::other("unexpected swarm"))?;
    let mut response = [0u8; 68];
    response[0] = 19;
    response[1..20].copy_from_slice(b"BitTorrent protocol");
    response[25] = 0x10;
    response[28..48].copy_from_slice(&hash);
    response[48..68].copy_from_slice(b"DNSFIXTUREPEER000001");
    stream.write_all(&response).await?;
    write_frame(&mut stream, &[5, 0xc0]).await?;
    let ext = ExtHandshake {
        m_ut_metadata: Some(7),
        metadata_size: Some(info.len() as u32),
        ..Default::default()
    };
    let mut frame = vec![20, 0];
    frame.extend(ok(ext.encode()));
    write_frame(&mut stream, &frame).await?;
    let mut remote_metadata = 2;
    loop {
        let length = stream.read_u32().await? as usize;
        if length == 0 {
            continue;
        }
        if length > 65536 {
            return Err(io::Error::other("oversized fixture frame"));
        }
        let mut message = vec![0; length];
        stream.read_exact(&mut message).await?;
        match message[0] {
            2 => write_frame(&mut stream, &[1]).await?,
            6 if message.len() == 13 => {
                payload_requests.fetch_add(1, Ordering::SeqCst);
                let piece = u32::from_be_bytes(ok(message[1..5].try_into())) as usize;
                let begin = u32::from_be_bytes(ok(message[5..9].try_into())) as usize;
                let count = u32::from_be_bytes(ok(message[9..13].try_into())) as usize;
                let offset = piece * 16384 + begin;
                let block = payload
                    .get(offset..offset + count)
                    .ok_or_else(|| io::Error::other("payload range"))?;
                let mut response = vec![7];
                response.extend_from_slice(&message[1..9]);
                response.extend_from_slice(block);
                write_frame(&mut stream, &response).await?;
            }
            20 if message.len() >= 2 && message[1] == 0 => {
                let remote = ExtHandshake::decode(&message[2..])
                    .map_err(|error| io::Error::other(error.to_string()))?;
                remote_metadata = remote.m_ut_metadata.unwrap_or(2);
            }
            20 if message.len() >= 2 && message[1] == 7 => {
                if let Ok(UtMetadata::Request { index }) = UtMetadata::decode(&message[2..]) {
                    metadata_requests.fetch_add(1, Ordering::SeqCst);
                    let response = match serve_request(info, index)
                        .map_err(|error| io::Error::other(error.to_string()))?
                    {
                        ServeOutcome::Data {
                            index,
                            total_size,
                            data,
                        } => UtMetadata::Data {
                            index,
                            total_size,
                            data,
                        },
                        ServeOutcome::Reject { index } => UtMetadata::Reject { index },
                    };
                    let mut frame = vec![20, remote_metadata];
                    frame.extend(ok(response.encode()));
                    write_frame(&mut stream, &frame).await?;
                }
            }
            _ => {}
        }
    }
}

async fn metadata_peer(
    fixtures: TorrentFixtures,
    root: &CancellationToken,
    metadata_requests: Arc<AtomicUsize>,
    payload_requests: Arc<AtomicUsize>,
) -> SocketAddr {
    let listener = ok(TcpListener::bind("127.0.0.1:0").await);
    let address = ok(listener.local_addr());
    let token = root.clone();
    let fixtures = Arc::new(fixtures);
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                _ = token.cancelled() => return,
                accepted = listener.accept() => accepted,
            };
            let Ok((stream, _)) = accepted else {
                return;
            };
            let token = token.clone();
            let fixtures = Arc::clone(&fixtures);
            let metadata_requests = Arc::clone(&metadata_requests);
            let payload_requests = Arc::clone(&payload_requests);
            tokio::spawn(async move {
                tokio::select! {
                    _ = token.cancelled() => {},
                    _ = serve_metadata_peer(stream, fixtures, metadata_requests, payload_requests) => {},
                }
            });
        }
    });
    address
}

async fn udp_tracker(
    peer: SocketAddr,
    root: &CancellationToken,
    announces: Arc<AtomicUsize>,
    scrapes: Arc<AtomicUsize>,
) -> SocketAddr {
    let socket = ok(UdpSocket::bind("127.0.0.1:0").await);
    let address = ok(socket.local_addr());
    let token = root.clone();
    tokio::spawn(async move {
        let mut packet = [0u8; 2048];
        loop {
            let received = tokio::select! {
                _ = token.cancelled() => return,
                result = socket.recv_from(&mut packet) => result,
            };
            let Ok((length, remote)) = received else {
                return;
            };
            if length < 16 {
                continue;
            }
            let action = u32::from_be_bytes(ok(packet[8..12].try_into()));
            let tid = &packet[12..16];
            let mut response = Vec::new();
            response.extend_from_slice(&action.to_be_bytes());
            response.extend_from_slice(tid);
            match action {
                0 => response.extend_from_slice(&CONNECTION_ID.to_be_bytes()),
                1 if length >= 98 => {
                    assert_eq!(
                        u64::from_be_bytes(ok(packet[..8].try_into())),
                        CONNECTION_ID
                    );
                    announces.fetch_add(1, Ordering::SeqCst);
                    response.extend_from_slice(&60u32.to_be_bytes());
                    response.extend_from_slice(&0u32.to_be_bytes());
                    response.extend_from_slice(&1u32.to_be_bytes());
                    let IpAddr::V4(ip) = peer.ip() else {
                        return;
                    };
                    response.extend_from_slice(&ip.octets());
                    response.extend_from_slice(&peer.port().to_be_bytes());
                }
                2 if length >= 36 => {
                    scrapes.fetch_add(1, Ordering::SeqCst);
                    for _ in 0..(length - 16) / 20 {
                        response.extend_from_slice(&1u32.to_be_bytes());
                        response.extend_from_slice(&0u32.to_be_bytes());
                        response.extend_from_slice(&0u32.to_be_bytes());
                    }
                }
                _ => continue,
            }
            if socket.send_to(&response, remote).await.is_err() {
                return;
            }
        }
    });
    address
}

async fn serve_http_tracker(mut socket: TcpStream) -> io::Result<()> {
    let mut request = Vec::new();
    let mut buffer = [0u8; 512];
    while !request.windows(4).any(|part| part == b"\r\n\r\n") {
        let count = socket.read(&mut buffer).await?;
        if count == 0 {
            return Ok(());
        }
        request.extend_from_slice(&buffer[..count]);
        if request.len() > 8192 {
            return Err(io::Error::other("request too large"));
        }
    }
    let body = b"d8:intervali60e5:peers0:e";
    socket
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await?;
    socket.write_all(body).await
}

async fn http_tracker(root: &CancellationToken) -> SocketAddr {
    let listener = ok(TcpListener::bind("127.0.0.1:0").await);
    let address = ok(listener.local_addr());
    let token = root.clone();
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                _ = token.cancelled() => return,
                result = listener.accept() => result,
            };
            let Ok((socket, _)) = accepted else {
                return;
            };
            let token = token.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = token.cancelled() => {},
                    _ = serve_http_tracker(socket) => {},
                }
            });
        }
    });
    address
}
fn config(
    hash: [u8; 20],
    tracker: SocketAddr,
    dest: std::path::PathBuf,
    services: Arc<MagnetServices>,
) -> MagnetTaskConfig {
    let hash = hash
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    MagnetTaskConfig {
        services: Some(services),
        dht_ipv6_enabled: false,
        dht_entry_point_v6_override: None,
        dht_message_timeout: Duration::from_secs(1),
        nat: None,
        tracker_updates: None,
        gid: GidAllocator::new().allocate(),
        magnet_uri: format!(
            "magnet:?xt=urn:btih:{hash}&tr=udp://{HOST}:{}/announce",
            tracker.port()
        ),
        dest,
        peer_id: *b"-TJ0001-DNSACCEPT001",
        options: MagnetOptions {
            pause_metadata: true,
            ..Default::default()
        },
        phase: MetadataPhaseConfig {
            metadata_deadline: Some(Duration::from_secs(8)),
            peer_metadata_timeout: Duration::from_secs(3),
            discovery_round: Duration::from_millis(100),
            ..Default::default()
        },
        dht: None,
        dht_entry_points: Vec::new(),
        dht_entry_point_override: None,
        dht_enabled: false,
        webseeding_enabled: false,
        lsd: None,
        seed: Default::default(),
        seed_after_complete: false,
        persist: None,
        select_file: None,
        limiter: None,
        hook: None,
        web: None,
        stats: None,
        ip_guard: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_dns_failover_fetches_two_magnets_without_payload_download() {
    let root = CancellationToken::new();
    let _cancel = root.clone().drop_guard();
    let temp = ok(tempfile::tempdir());
    let (info_a, hash_a, payload_a) = fixture("first");
    let (info_b, hash_b, payload_b) = fixture("second");
    let metadata_requests = Arc::new(AtomicUsize::new(0));
    let payload_requests = Arc::new(AtomicUsize::new(0));
    let peer = metadata_peer(
        HashMap::from([
            (hash_a, (info_a.clone(), payload_a)),
            (hash_b, (info_b.clone(), payload_b)),
        ]),
        &root,
        Arc::clone(&metadata_requests),
        Arc::clone(&payload_requests),
    )
    .await;
    let announces = Arc::new(AtomicUsize::new(0));
    let scrapes = Arc::new(AtomicUsize::new(0));
    let tracker = udp_tracker(peer, &root, Arc::clone(&announces), Arc::clone(&scrapes)).await;
    let http = http_tracker(&root).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let (release, gate) = watch::channel(false);
    let registry = Arc::new(MetricsRegistry::new());
    let dns = Arc::new(SharedDns::with_registry(
        Arc::new(DomainResolver {
            calls: Arc::clone(&calls),
            release: gate,
        }),
        Arc::clone(&registry),
    ));
    let services = Arc::new(MagnetServices::with_dns(None, Arc::clone(&dns)));
    let a = config(
        hash_a,
        tracker,
        temp.path().join("first"),
        Arc::clone(&services),
    );
    let b = config(
        hash_b,
        tracker,
        temp.path().join("second"),
        Arc::clone(&services),
    );
    let gid_a = a.gid;
    let gid_b = b.gid;
    assert_ne!(gid_a, gid_b);
    let http_client = ok(HttpAnnounce::with_dns(
        &TrackerOptions {
            bt_tracker_timeout: Duration::from_secs(5),
            bt_tracker_connect_timeout: Duration::from_secs(4),
            ..Default::default()
        },
        dns,
    ));
    let request = OwnedAnnounceParams {
        announce_url: format!("http://{HOST}:{}/announce", http.port()),
        info_hash: hash_a,
        peer_id: [7; 20],
        port: 6881,
        uploaded: 0,
        downloaded: 0,
        left: 32768,
        event: TierEvent::Started,
        numwant: 50,
        tracker_id: None,
        require_crypto: false,
    };
    let started = Instant::now();
    let a = MagnetEngine::spawn(a, &root);
    let b = MagnetEngine::spawn(b, &root);
    let http = tokio::spawn(async move { http_client.announce_owned(&request).await });
    let entered = tokio::time::timeout(Duration::from_secs(3), async {
        while registry.snapshot().dns.lookups_miss < 3 || calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    let _ = release.send(true);
    assert!(
        entered.is_ok(),
        "two tracker actors and HTTP client did not reach the same DNS service"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "all consumers share a single cold lookup"
    );
    let completed =
        tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(a, b, http) }).await;
    let discovery_elapsed = started.elapsed();
    root.cancel();
    services.shutdown().await;
    let (a, b, http) = ok(completed);
    assert!(
        ok(http).is_ok(),
        "HTTP consumes the same injected address list"
    );
    for (end, expected_hash, expected_info, expected_gid) in [
        (ok(a), hash_a, info_a, gid_a),
        (ok(b), hash_b, info_b, gid_b),
    ] {
        let MagnetEnd::UpgradedPaused {
            chain,
            meta,
            torrent,
        } = end
        else {
            panic!("metadata must stop at file selection");
        };
        assert!(chain.paused);
        assert_eq!(chain.task_gid, expected_gid);
        assert_eq!(chain.metadata_gid, expected_gid);
        assert_eq!(meta.meta.identity.v1, Some(expected_hash));
        assert_eq!(meta.info_bytes.as_ref(), expected_info.as_slice());
        assert_eq!(
            ok(Metainfo::parse(&torrent)).meta.identity.v1,
            Some(expected_hash)
        );
    }
    assert!(
        discovery_elapsed < Duration::from_secs(5),
        "healthy second address must not wait for the old 15 second retry cycle"
    );
    assert_eq!(
        announces.load(Ordering::SeqCst),
        2,
        "only each winning endpoint receives its logical announce"
    );
    assert!(
        metadata_requests.load(Ordering::SeqCst) >= 6,
        "both multi-fragment metadata payloads were fetched"
    );
    assert_eq!(
        payload_requests.load(Ordering::SeqCst),
        0,
        "file data must await user selection"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(!temp.path().join("first/first.bin").exists());
    assert!(!temp.path().join("second/second.bin").exists());
    eprintln!(
        "DNS_DISCOVERY_ACCEPTANCE {}",
        serde_json::json!({
            "elapsed_ms": discovery_elapsed.as_millis(),
            "dns_backend_calls": calls.load(Ordering::SeqCst),
            "announces": announces.load(Ordering::SeqCst),
            "metadata_requests": metadata_requests.load(Ordering::SeqCst),
            "payload_requests": payload_requests.load(Ordering::SeqCst),
            "completed_magnets": 2,
        })
    );
}
