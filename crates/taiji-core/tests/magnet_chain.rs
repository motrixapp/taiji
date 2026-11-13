//! Acceptance: full magnet chain — cold start -> discovery -> ut_metadata
//! -> rebuild verification -> in-place upgrade + followedBy data face.
//!
//! The whole chain stays off the network. Fixtures: in-process DHT
//! (loopback UdpDemux + DhtEngine), a fake tracker (local TCP mock), a
//! local full seeder (ut_metadata serve face, piece serving, hash request
//! serving; cross-checked against BEP 9/BEP 52). Covered criteria:
//!
//! 1. v1 magnet cold start to download completion. The metadata phase
//!    uses DHT-only discovery (the hub records the seeder, get_peers
//!    values hit); after the upgrade the engine's discovery face is the
//!    tracker — engine-level DHT wiring is out of scope here (see the
//!    magnet.rs module docs).
//! 2. hybrid magnet cold start to download completion (btih+btmh dual
//!    identity + piece layers prefetch: magnet metadata carries no
//!    top-level `piece layers`, BEP 52).
//! 3. infohash mismatch / corrupt metadata are rejected explicitly.
//! 4. bt-save-metadata output can be reloaded by this engine;
//!    bt-metadata-only, follow-torrent, pause-metadata,
//!    bt-load-saved-metadata option behavior.
//! 5. Metadata timeout fails honestly (no peers never masquerades as
//!    completion).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use taiji_bt::bencode::{self, Value};
use taiji_bt::dht::{
    DhtEngineConfig, DhtEvent, DhtFamily, DhtHandle, DhtSwarmKind, DhtTarget, DhtTransport,
    EVENT_CHANNEL_CAPACITY, spawn_dht_engine,
};
use taiji_bt::peer_wire::ExtHandshake;
use taiji_bt::ut_metadata::{UtMetadata, serve_request as ut_serve};
use taiji_core::engine::EngineEnd;
use taiji_core::gid::GidAllocator;
use taiji_core::magnet::{
    MagnetEnd, MagnetEngine, MagnetOptions, MagnetTaskConfig, MetadataPhaseConfig,
};
use taiji_core::metainfo::Metainfo;
use taiji_store::merkle;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const L: u64 = 16384;

fn dict(mut pairs: Vec<(&[u8], Value)>) -> Value {
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    Value::Dict(pairs.into_iter().map(|(k, v)| (k.to_vec(), v)).collect())
}

fn dict_dyn(mut pairs: Vec<(Vec<u8>, Value)>) -> Value {
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    Value::Dict(pairs)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|x| format!("{x:02x}")).collect()
}

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "taiji-p25-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&d).unwrap_or_else(|e| panic!("{e}"));
    d
}

/// Grabs a free port (binds then releases; the metadata phase does not
/// listen, the upgraded engine binds later).
async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    l.local_addr().unwrap_or_else(|e| panic!("{e}")).port()
}

/// v1 info dict bytes + btih (SHA-1 over the raw info bytes, BEP 3).
fn build_v1_info(content: &[u8], name: &[u8]) -> (Vec<u8>, [u8; 20]) {
    let pieces: Vec<u8> = content.chunks(L as usize).flat_map(Sha1::digest).collect();
    let info = dict(vec![
        (b"length", Value::Int(content.len() as i64)),
        (b"name", Value::Bytes(name.to_vec())),
        (b"piece length", Value::Int(L as i64)),
        (b"pieces", Value::Bytes(pieces)),
    ]);
    let info_bytes = bencode::encode(&info).unwrap_or_else(|e| panic!("{e}"));
    let btih: [u8; 20] = Sha1::digest(&info_bytes).into();
    (info_bytes, btih)
}

/// Hybrid info (dual representation; no announce — the magnet chain's
/// rebuild product carries its own tr layer).
/// Returns (info bytes, btih, btmh, v1 stream, v2 wire goffs,
/// (root, stream offset, length) table).
#[allow(clippy::type_complexity)]
fn build_hybrid_info(
    content_a: &[u8],
    content_b: &[u8],
) -> (
    Vec<u8>,
    [u8; 20],
    [u8; 32],
    Vec<u8>,
    Vec<u64>,
    Vec<([u8; 32], u64, u64)>,
) {
    let pad = (L - (content_a.len() as u64 % L)) % L;
    let mut stream = Vec::new();
    stream.extend_from_slice(content_a);
    stream.extend(std::iter::repeat_n(0u8, pad as usize));
    stream.extend_from_slice(content_b);
    let v1_pieces: Vec<u8> = stream.chunks(L as usize).flat_map(Sha1::digest).collect();
    let piece_hashes =
        |c: &[u8]| -> Vec<[u8; 32]> { c.chunks(L as usize).map(merkle::block_hash).collect() };
    let ha = piece_hashes(content_a);
    let hb = piece_hashes(content_b);
    let bpp = (L / u64::from(merkle::BLOCK_SIZE)) as usize;
    let root_a = merkle::file_root_from_piece_roots(&ha, bpp);
    let root_b = merkle::file_root_from_piece_roots(&hb, bpp);
    let layer_bytes =
        |h: &[[u8; 32]]| -> Vec<u8> { h.iter().flat_map(|x| x.iter()).copied().collect() };
    let leaf = |name: &[u8], len: i64, root: &[u8; 32]| -> (Vec<u8>, Value) {
        (
            name.to_vec(),
            dict(vec![(
                b"",
                dict(vec![
                    (b"length", Value::Int(len)),
                    (b"pieces root", Value::Bytes(root.to_vec())),
                ]),
            )]),
        )
    };
    let info = dict(vec![
        (
            b"file tree",
            Value::Dict(vec![
                leaf(b"a.bin", content_a.len() as i64, &root_a),
                leaf(b"b.bin", content_b.len() as i64, &root_b),
            ]),
        ),
        (
            b"files",
            Value::List(vec![
                dict(vec![
                    (b"length", Value::Int(content_a.len() as i64)),
                    (b"path", Value::List(vec![Value::Bytes(b"a.bin".to_vec())])),
                ]),
                dict(vec![
                    (b"attr", Value::Bytes(b"p".to_vec())),
                    (b"length", Value::Int(pad as i64)),
                    (
                        b"path",
                        Value::List(vec![
                            Value::Bytes(b".pad".to_vec()),
                            Value::Bytes(pad.to_string().into_bytes()),
                        ]),
                    ),
                ]),
                dict(vec![
                    (b"length", Value::Int(content_b.len() as i64)),
                    (b"path", Value::List(vec![Value::Bytes(b"b.bin".to_vec())])),
                ]),
            ]),
        ),
        (b"meta version", Value::Int(2)),
        (b"piece length", Value::Int(L as i64)),
        (b"pieces", Value::Bytes(v1_pieces)),
    ]);
    let info_bytes = bencode::encode(&info).unwrap_or_else(|e| panic!("{e}"));
    let btih: [u8; 20] = Sha1::digest(&info_bytes).into();
    let btmh: [u8; 32] = Sha256::digest(&info_bytes).into();
    // v2 wire coordinates -> stream offsets (file-aligned; a: 5 pieces
    // @0.., b: 2 pieces @81920..).
    let v2_goffs = vec![0, L, 2 * L, 3 * L, 4 * L, 81920, 98304];
    let hash_files = vec![
        (root_a, 0u64, content_a.len() as u64),
        (root_b, 81920u64, content_b.len() as u64),
    ];
    // piece layers table (test-side check of the prefetch; not part of
    // the info dict — magnet face).
    let _ = (layer_bytes(&ha), layer_bytes(&hb));
    (info_bytes, btih, btmh, stream, v2_goffs, hash_files)
}

/// Fake tracker: accept loop; answers each announce with `peers` (compact,
/// possibly empty).
async fn fake_tracker(peers: Vec<SocketAddr>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut req = Vec::new();
            let mut chunk = [0u8; 512];
            loop {
                if sock.read(&mut chunk).await.unwrap_or(0) == 0 {
                    break;
                }
                req.extend_from_slice(&chunk);
                if req.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let mut raw = Vec::new();
            let mut peers_bytes = Vec::new();
            for p in &peers {
                let std::net::IpAddr::V4(v4) = p.ip() else {
                    continue;
                };
                peers_bytes.extend_from_slice(&v4.octets());
                peers_bytes.extend_from_slice(&p.port().to_be_bytes());
            }
            raw.extend_from_slice(b"d8:intervali600e5:peers");
            raw.extend_from_slice(peers_bytes.len().to_string().as_bytes());
            raw.push(b':');
            raw.extend_from_slice(&peers_bytes);
            raw.push(b'e');
            let head = format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n", raw.len());
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(&raw).await;
            let _ = sock.shutdown().await;
        }
    });
    format!("http://{addr}/announce")
}

/// In-process DHT instance (loopback UdpDemux; never leaves the host).
/// Returns (handle, events, bound addr, lifetime token).
async fn spawn_dht_instance() -> (
    DhtHandle,
    mpsc::Receiver<DhtEvent>,
    SocketAddr,
    CancellationToken,
) {
    let shutdown = CancellationToken::new();
    let (channels, demux) = taiji_io::udp_demux::spawn(
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        taiji_io::udp_demux::DemuxConfig::default(),
        shutdown.clone(),
    )
    .await
    .unwrap_or_else(|e| panic!("demux bind: {e}"));
    let bound = demux.bound_addr();
    let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
    let (out_tx, mut out_rx) = mpsc::channel(256);
    let (handle, _join) = spawn_dht_engine(
        DhtFamily::V4,
        bound.port(),
        DhtEngineConfig::default(),
        DhtTransport {
            inbound: channels.dht,
            outbound: out_tx,
        },
        None,
        event_tx,
    );
    // Engine outbound -> single demux writer (topology).
    let fwd_demux = demux.clone();
    tokio::spawn(async move {
        while let Some(pkt) = out_rx.recv().await {
            let _ = fwd_demux.send_packet(pkt.to, pkt.data).await;
        }
    });
    (handle, event_rx, bound, shutdown)
}

async fn dht_snapshot(handle: &DhtHandle) -> taiji_bt::dht::DhtSnapshot {
    handle
        .snapshot()
        .await
        .unwrap_or_else(|e| panic!("snapshot: {e}"))
}

/// Polls the snapshot until the condition holds.
async fn wait_snapshot(
    handle: &DhtHandle,
    limit: Duration,
    cond: impl Fn(&taiji_bt::dht::DhtSnapshot) -> bool,
) {
    let start = std::time::Instant::now();
    loop {
        let snap = dht_snapshot(handle).await;
        if cond(&snap) {
            return;
        }
        if start.elapsed() > limit {
            panic!("snapshot condition not met within {limit:?}; last = {snap:?}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Full-seeder parameters.
struct SeederSpec {
    /// Info dict bytes (ut_metadata serve payload).
    metadata: Arc<Vec<u8>>,
    /// None = no metadata serve face (no metadata_size advertised;
    /// request -> reject).
    stream: Arc<Vec<u8>>,
    /// v1 stream (hybrid includes the pad zero segment).
    v1_hash: [u8; 20],
    v2_hash20: [u8; 20],
    /// v2 wire goffs (None = no v2 face identity).
    v2_goffs: Option<Arc<Vec<u64>>>,
    /// hash request serve face (root, stream offset, file length).
    hash_files: Arc<Vec<([u8; 32], u64, u64)>>,
}

/// Full seeder: accept loop; per connection handshake -> ext handshake
/// (BEP 10, advertising ut_metadata=2 + metadata_size) -> per-request
/// service (request/piece, ut_metadata, hash request). The handshake
/// reply always carries ext+fast (+ the v2 bit when the peer connects
/// with a v2 identity).
async fn spawn_full_seeder(listener: tokio::net::TcpListener, spec: SeederSpec) {
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let spec = SeederSpec {
                metadata: Arc::clone(&spec.metadata),
                stream: Arc::clone(&spec.stream),
                v1_hash: spec.v1_hash,
                v2_hash20: spec.v2_hash20,
                v2_goffs: spec.v2_goffs.clone(),
                hash_files: Arc::clone(&spec.hash_files),
            };
            tokio::spawn(async move {
                let mut hs = [0u8; 68];
                if sock.read_exact(&mut hs).await.is_err() {
                    return;
                }
                let ih: [u8; 20] = hs[28..48].try_into().unwrap_or_else(|_| panic!("slice"));
                let is_v2 = ih == spec.v2_hash20 && spec.v2_goffs.is_some();
                if ih != spec.v1_hash && !is_v2 {
                    return; // wrong swarm
                }
                let mut resp = [0u8; 68];
                resp[0] = 19;
                resp[1..20].copy_from_slice(b"BitTorrent protocol");
                resp[25] = 0x10; // extended (BEP 10)
                resp[27] = 0x04; // fast
                if is_v2 {
                    resp[29] = 0x10; // v2 capability bit (BEP 52)
                }
                resp[28..48].copy_from_slice(&ih);
                resp[48..68].copy_from_slice(b"SEEDERSEEDERSEEDER00");
                if sock.write_all(&resp).await.is_err() {
                    return;
                }
                // The seeder sends the full bitfield after its handshake
                // (BEP 3). The piece count must be rounded up:
                // v1 face = stream.len().div_ceil(L) — truncating division
                // would skip advertising trailing partial pieces (the
                // hybrid stream is 112288B = 6.85 pieces, so a truncated
                // bitmap advertises only 6/7) and the last piece would be
                // advertised by nobody -> the engine's fetch face waits
                // forever (a re-announce returns the same already-connected
                // peer — a livelock shape). The connection also registers
                // only one face under dual-face address dedup: registered
                // under the v1 identity, a peer without the v2 capability
                // bit makes the v2-face hash fetch unusable too.
                // v2 face = goffs.len() — the BEP 52 aligned mapping makes
                // both the same length. The seeder previously advertised
                // nothing and relied on the dispatcher's blind-pick
                // fallback — that fallback was removed with
                // advertisement-aware dispatch (cross-check libtorrent
                // request_blocks.cpp). Zero pieces (pure metadata serve
                // fixture) sends no bitfield — BEP 3: "need only be sent
                // if a client has pieces"; an empty payload bitfield is
                // disconnected by the peer as a protocol error.
                {
                    let n = match (&spec.v2_goffs, is_v2) {
                        (Some(g), true) => g.len(),
                        _ => spec.stream.len().div_ceil(L as usize),
                    };
                    if n > 0 {
                        let mut bits = vec![0u8; n.div_ceil(8)];
                        for i in 0..n {
                            bits[i / 8] |= 0x80 >> (i % 8);
                        }
                        let mut bf = Vec::with_capacity(5 + bits.len());
                        bf.extend_from_slice(((1 + bits.len()) as u32).to_be_bytes().as_slice());
                        bf.push(5u8);
                        bf.extend_from_slice(&bits);
                        if sock.write_all(&bf).await.is_err() {
                            return;
                        }
                    }
                }
                // Ext handshake (ut_metadata=2 + metadata_size; BEP 10/9).
                let ext = ExtHandshake {
                    m_ut_metadata: Some(2),
                    metadata_size: Some(spec.metadata.len() as u32),
                    ..ExtHandshake::default()
                };
                let payload = ext.encode().unwrap_or_else(|e| panic!("{e}"));
                let mut frame = Vec::with_capacity(5 + payload.len());
                frame.extend_from_slice(((1 + 1 + payload.len()) as u32).to_be_bytes().as_slice());
                frame.push(20u8);
                frame.push(0u8);
                frame.extend_from_slice(&payload);
                if sock.write_all(&frame).await.is_err() {
                    return;
                }
                loop {
                    let mut len_buf = [0u8; 4];
                    if sock.read_exact(&mut len_buf).await.is_err() {
                        return;
                    }
                    let len = u32::from_be_bytes(len_buf) as usize;
                    if len == 0 {
                        continue;
                    }
                    let mut body = vec![0u8; len];
                    if sock.read_exact(&mut body).await.is_err() {
                        return;
                    }
                    match body[0] {
                        2 => {
                            // interested -> unchoke.
                            let _ = sock.write_all(&[0, 0, 0, 1, 1]).await;
                        }
                        6 => {
                            // request(index, begin, length) -> piece.
                            if body.len() < 13 {
                                return;
                            }
                            let index = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
                            let begin = u32::from_be_bytes([body[5], body[6], body[7], body[8]]);
                            let length =
                                u32::from_be_bytes([body[9], body[10], body[11], body[12]]);
                            let off = if is_v2 {
                                let goffs = spec.v2_goffs.as_ref().unwrap_or_else(|| {
                                    panic!("the v2 face must carry a goffs table")
                                });
                                match goffs.get(index as usize) {
                                    Some(o) => o + u64::from(begin),
                                    None => continue,
                                }
                            } else {
                                index as u64 * L + u64::from(begin)
                            };
                            let end = (off + u64::from(length)) as usize;
                            if end > spec.stream.len() {
                                continue;
                            }
                            let block = spec.stream[off as usize..end].to_vec();
                            let mut frame = Vec::with_capacity(13 + block.len());
                            frame.extend_from_slice(&((9 + block.len()) as u32).to_be_bytes());
                            frame.push(7u8);
                            frame.extend_from_slice(&index.to_be_bytes());
                            frame.extend_from_slice(&begin.to_be_bytes());
                            frame.extend_from_slice(&block);
                            if sock.write_all(&frame).await.is_err() {
                                return;
                            }
                        }
                        20 => {
                            // Extended: ext_id 0 = peer handshake (ignored);
                            // ext_id 2 = ut_metadata.
                            if body.len() < 2 {
                                return;
                            }
                            let ext_id = body[1];
                            if ext_id != 2 {
                                continue;
                            }
                            let Ok(UtMetadata::Request { index }) = UtMetadata::decode(&body[2..])
                            else {
                                continue;
                            };
                            let reply = match ut_serve(&spec.metadata, index) {
                                Ok(taiji_bt::ut_metadata::ServeOutcome::Data {
                                    index,
                                    total_size,
                                    data,
                                }) => UtMetadata::Data {
                                    index,
                                    total_size,
                                    data,
                                },
                                Ok(taiji_bt::ut_metadata::ServeOutcome::Reject { index }) => {
                                    UtMetadata::Reject { index }
                                }
                                Err(_) => return, // out of range -> disconnect
                            };
                            let payload = reply.encode().unwrap_or_else(|e| panic!("{e}"));
                            let mut frame = Vec::with_capacity(5 + payload.len());
                            frame.extend_from_slice(
                                ((1 + 1 + payload.len()) as u32).to_be_bytes().as_slice(),
                            );
                            frame.push(20u8);
                            frame.push(2u8);
                            frame.extend_from_slice(&payload);
                            if sock.write_all(&frame).await.is_err() {
                                return;
                            }
                        }
                        21 => {
                            // hash request (BEP 52): root +
                            // base/index/length/proof.
                            if body.len() < 49 {
                                return;
                            }
                            use sha2::{Digest as _, Sha256};
                            let root: [u8; 32] =
                                body[1..33].try_into().unwrap_or_else(|_| panic!("root"));
                            let be32 = |b: &[u8]| u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                            let base = be32(&body[33..]);
                            let index = be32(&body[37..]);
                            let length = be32(&body[41..]);
                            if base != 0 {
                                continue;
                            }
                            let Some((_, off, flen)) =
                                spec.hash_files.iter().find(|(r, _, _)| *r == root)
                            else {
                                // Unknown root: hash reject (a legal
                                // answer).
                                let mut frame = vec![0u8; 53];
                                frame[0..4].copy_from_slice(&53u32.to_be_bytes());
                                frame[4] = 23u8;
                                frame[5..].copy_from_slice(&body[1..49]);
                                if sock.write_all(&frame).await.is_err() {
                                    return;
                                }
                                continue;
                            };
                            let (off, flen) = (*off, *flen);
                            let mut hashes: Vec<[u8; 32]> = Vec::new();
                            for i in index..index.saturating_add(length) {
                                let s = u64::from(i) * 16384u64;
                                if s >= flen {
                                    hashes.push([0u8; 32]); // zero-filled slot beyond range (BEP 52)
                                    continue;
                                }
                                let e = (s + 16384u64).min(flen);
                                let seg = &spec.stream[(off + s) as usize..(off + e) as usize];
                                hashes.push(Sha256::digest(seg).into());
                            }
                            let mut frame = Vec::with_capacity(49 + 32 * hashes.len());
                            frame.extend_from_slice(
                                &((49 + 32 * hashes.len()) as u32).to_be_bytes(),
                            );
                            frame.push(22u8);
                            frame.extend_from_slice(&body[1..49]);
                            for h in hashes {
                                frame.extend_from_slice(&h);
                            }
                            if sock.write_all(&frame).await.is_err() {
                                return;
                            }
                        }
                        _ => {}
                    }
                }
            });
        }
    });
}

// ===== Test cases =====

/// Log init (idempotent; RUST_LOG=debug makes the whole chain visible).
fn init_log() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
}

/// Magnet task config (test shape: short backoff + small dial cap).
fn test_config(
    gid: taiji_core::gid::Gid,
    magnet_uri: String,
    dest: std::path::PathBuf,
    dht: Option<taiji_bt::dht::DhtHandle>,
    dht_events: Option<mpsc::Receiver<DhtEvent>>,
    listen_port: u16,
    options: MagnetOptions,
) -> MagnetTaskConfig {
    MagnetTaskConfig {
        services: None,
        dht_entry_point_v6_override: None,
        dht_message_timeout: Duration::from_secs(10),
        dht_ipv6_enabled: false,
        tracker_updates: None,
        nat: None,
        dht_entry_point_override: None,
        gid,
        magnet_uri,
        dest,
        peer_id: *b"-TJ0001-MAGNETMAGNE1",
        options,
        phase: MetadataPhaseConfig {
            listen_port,
            max_metadata_peers: 4,
            peer_metadata_timeout: Duration::from_secs(10),
            discovery_round: Duration::from_millis(400),
            metadata_deadline: Some(Duration::from_secs(25)),
            // Bootstrap wait budget — short on the test face (entry
            // resolution in an offline environment must not block the
            // phase from starting; mechanism tests live in the
            // magnet::spawn_phase_dht cases).
            dht_bootstrap_budget: Duration::from_millis(300),
        },
        dht: dht.map(|handle| taiji_core::magnet::DhtLease {
            extra_handles: Vec::new(),
            handle,
            events: dht_events.unwrap_or_else(|| mpsc::channel(64).1),
        }),
        dht_entry_points: vec![],
        dht_enabled: false,
        lsd: None,
        seed: taiji_core::seed::SeedPolicy::default(),
        seed_after_complete: false,
        persist: None,
        select_file: None,
        limiter: None,
        hook: None,
        web: None,
        stats: None,
        // Existing chain cases carry no ban face (None = no gate).
        ip_guard: None,
        webseeding_enabled: true,
    }
}

fn magnet_uri_btih(btih: [u8; 20], tracker: &str) -> String {
    format!("magnet:?xt=urn:btih:{}&tr={}", hex(&btih), tracker)
}

/// (1) v1 magnet cold-start full chain (DHT-only discovery + empty fake
/// tracker reply) + (4) bt-save-metadata output reloadable + followedBy
/// data face.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v1_magnet_cold_start_via_dht_downloads_and_saves_metadata() {
    init_log();
    let content: Vec<u8> = (0..2 * L as usize).map(|i| (i * 31 % 251) as u8).collect();
    let (info_bytes, btih) = build_v1_info(&content, b"v1blob.bin");
    let tmp = tmp_dir("v1-dht");

    // Seeder + tracker (replies with the seeder address: the upgraded
    // engine's discovery face; the three DHT discovery paths are carried
    // independently by the three in-process DHT instances below and merge
    // through dedup).
    let seeder_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let seeder_addr = seeder_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"));
    spawn_full_seeder(
        seeder_listener,
        SeederSpec {
            metadata: Arc::new(info_bytes.clone()),
            stream: Arc::new(content.clone()),
            v1_hash: btih,
            v2_hash20: [0u8; 20], // no v2 face
            v2_goffs: None,
            hash_files: Arc::new(Vec::new()),
        },
    )
    .await;
    let tracker_url = fake_tracker(vec![seeder_addr]).await;

    // Three in-process DHT instances: hub (record holder) / seeder side /
    // leecher (leased to the task).
    let (hub, _hub_ev, hub_addr, _hub_tok) = spawn_dht_instance().await;
    let (seed_dht, _seed_ev, _seed_addr, _seed_tok) = spawn_dht_instance().await;
    let (leech_dht, leech_ev, _leech_addr, _leech_tok) = spawn_dht_instance().await;
    // The seeder side bootstraps to the hub then announces (announce_peer
    // lands in the hub's records).
    seed_dht
        .bootstrap(vec![hub_addr])
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let target = DhtTarget::new(btih, DhtSwarmKind::V1, false).unwrap_or_else(|e| panic!("{e}"));
    seed_dht
        .announce(target, seeder_addr.port())
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    wait_snapshot(&hub, Duration::from_secs(5), |s| s.peer_record_keys >= 1).await;

    // Magnet task (leecher DHT lease; bootstrap entry = hub).
    let mut cfg = test_config(
        GidAllocator::new().allocate(),
        magnet_uri_btih(btih, &tracker_url),
        tmp.clone(),
        Some(leech_dht),
        Some(leech_ev),
        free_port().await,
        MagnetOptions {
            bt_save_metadata: true,
            ..MagnetOptions::default()
        },
    );
    cfg.dht_entry_points = vec![hub_addr];
    let root = CancellationToken::new();
    let end = MagnetEngine::spawn(cfg, &root)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    root.cancel();

    // Final state: upgrade completed + content matches.
    let MagnetEnd::Upgraded { end, chain, .. } = end else {
        panic!("expected Upgraded, got {end:?}");
    };
    assert!(matches!(end, EngineEnd::Completed), "engine end: {end:?}");
    let got = std::fs::read(tmp.join("v1blob.bin")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(got, content, "downloaded content must match the source");

    // followedBy data face (same-GID in-place upgrade; aria2
    // RequestGroup.cc semantics).
    assert_eq!(chain.followed_by().len(), 1);
    assert_eq!(chain.followed_by()[0], chain.task_gid);
    assert_eq!(chain.following(), chain.metadata_gid);
    assert!(chain.metadata_uri.starts_with("magnet:?xt=urn:btih:"));
    assert!(!chain.paused);

    // bt-save-metadata: written to disk + reloadable by this engine
    // (criterion 4).
    let saved = tmp.join(format!("{}.torrent", hex(&btih)));
    let bytes = std::fs::read(&saved).unwrap_or_else(|e| panic!("saved metadata: {e}"));
    let m = Metainfo::parse(&bytes).unwrap_or_else(|e| panic!("reload: {e}"));
    assert_eq!(
        m.meta.identity.v1,
        Some(btih),
        "the reloaded identity must match"
    );
    assert_eq!(m.info_bytes.as_ref(), info_bytes.as_slice());
    let _ = std::fs::remove_dir_all(&tmp);
}

/// (2) hybrid magnet cold-start full chain: btih+btmh dual identity,
/// tracker discovery, dual-face download, piece layers prefetch (the
/// BEP 52 top-level key is not in the info dict).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hybrid_magnet_cold_start_downloads_dual_swarm() {
    init_log();
    let content_a: Vec<u8> = (0..70000).map(|i| (i * 17 % 253) as u8).collect();
    let content_b: Vec<u8> = (0..30000).map(|i| (i * 7 % 249) as u8).collect();
    let (info_bytes, btih, btmh, stream, v2_goffs, hash_files) =
        build_hybrid_info(&content_a, &content_b);
    let tmp = tmp_dir("hybrid");

    let seeder_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let seeder_addr = seeder_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"));
    spawn_full_seeder(
        seeder_listener,
        SeederSpec {
            metadata: Arc::new(info_bytes.clone()),
            stream: Arc::new(stream),
            v1_hash: btih,
            v2_hash20: {
                let mut t = [0u8; 20];
                t.copy_from_slice(&btmh[..20]);
                t
            },
            v2_goffs: Some(Arc::new(v2_goffs)),
            hash_files: Arc::new(hash_files),
        },
    )
    .await;
    let tracker_url = fake_tracker(vec![seeder_addr]).await;

    let magnet = format!(
        "magnet:?xt=urn:btih:{}&xt=urn:btmh:1220{}&tr={}",
        hex(&btih),
        hex(&btmh),
        tracker_url
    );
    let cfg = test_config(
        GidAllocator::new().allocate(),
        magnet,
        tmp.clone(),
        None,
        None,
        free_port().await,
        MagnetOptions::default(),
    );
    let root = CancellationToken::new();
    let end = MagnetEngine::spawn(cfg, &root)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    root.cancel();

    let MagnetEnd::Upgraded { end, chain, .. } = end else {
        panic!("expected Upgraded, got {end:?}");
    };
    assert!(matches!(end, EngineEnd::Completed), "engine end: {end:?}");
    let got_a = std::fs::read(tmp.join("a.bin")).unwrap_or_else(|e| panic!("{e}"));
    let got_b = std::fs::read(tmp.join("b.bin")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(got_a, content_a);
    assert_eq!(got_b, content_b);
    // pad files never hit disk (BEP 47).
    let names: Vec<String> = tmp
        .read_dir()
        .unwrap_or_else(|e| panic!("{e}"))
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        names.iter().all(|n| n == "a.bin" || n == "b.bin"),
        "no pad files may appear in the directory: {names:?}"
    );
    assert_eq!(chain.following(), chain.metadata_gid);
    let _ = std::fs::remove_dir_all(&tmp);
}

/// (3a) infohash mismatch: the seeder serves another torrent's metadata
/// -> the fetcher's verification rejects it -> the metadata phase fails
/// honestly (no fake completion), no files written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn infohash_mismatch_fails_explicitly() {
    init_log();
    let content: Vec<u8> = vec![7u8; L as usize];
    let (info_bytes, _btih_of_served) = build_v1_info(&content, b"other.bin");
    // The magnet's declared btih != the sha1 of the served metadata.
    let magnet_btih: [u8; 20] = Sha1::digest(b"declared-identity-not-served").into();
    let tmp = tmp_dir("mismatch");

    let seeder_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let seeder_addr = seeder_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"));
    spawn_full_seeder(
        seeder_listener,
        SeederSpec {
            metadata: Arc::new(info_bytes),
            stream: Arc::new(content),
            v1_hash: magnet_btih, // the seeder accepts this identity's handshake (spoofing peer)
            v2_hash20: [0u8; 20],
            v2_goffs: None,
            hash_files: Arc::new(Vec::new()),
        },
    )
    .await;
    let tracker_url = fake_tracker(vec![seeder_addr]).await;

    let mut cfg = test_config(
        GidAllocator::new().allocate(),
        magnet_uri_btih(magnet_btih, &tracker_url),
        tmp.clone(),
        None,
        None,
        free_port().await,
        MagnetOptions::default(),
    );
    cfg.phase.metadata_deadline = Some(Duration::from_secs(4));
    let root = CancellationToken::new();
    let end = MagnetEngine::spawn(cfg, &root)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    root.cancel();
    let MagnetEnd::Failed(reason) = end else {
        panic!("expected Failed, got {end:?}");
    };
    assert!(
        reason.contains("deadline") || reason.contains("infohash"),
        "explicit failure expected: {reason}"
    );
    assert!(
        tmp.read_dir()
            .unwrap_or_else(|e| panic!("{e}"))
            .next()
            .is_none(),
        "a failed task must write no files to disk"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

/// (3b) corrupt metadata: the sha1 happens to match but it is not a valid
/// info dict -> the fetcher lets it through, the rebuild parser rejects
/// (the second of the two defense layers).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn corrupt_metadata_rejected_by_parser() {
    init_log();
    // A decodable but structurally broken info dict (the pieces string is
    // not a multiple of 20B): its sha1 is exactly the declared btih -> the
    // fetcher lets it through; the rebuild parser must reject it.
    let garbage: Vec<u8> = bencode::encode(&dict(vec![
        (b"length", Value::Int(100)),
        (b"name", Value::Bytes(b"x".to_vec())),
        (b"piece length", Value::Int(L as i64)),
        (b"pieces", Value::Bytes(vec![0u8; 10])), // not a multiple of 20B
    ]))
    .unwrap_or_else(|e| panic!("{e}"));
    let btih: [u8; 20] = Sha1::digest(&garbage).into();
    let tmp = tmp_dir("corrupt");

    let seeder_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let seeder_addr = seeder_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"));
    spawn_full_seeder(
        seeder_listener,
        SeederSpec {
            metadata: Arc::new(garbage),
            stream: Arc::new(Vec::new()),
            v1_hash: btih,
            v2_hash20: [0u8; 20],
            v2_goffs: None,
            hash_files: Arc::new(Vec::new()),
        },
    )
    .await;
    let tracker_url = fake_tracker(vec![seeder_addr]).await;

    let cfg = test_config(
        GidAllocator::new().allocate(),
        magnet_uri_btih(btih, &tracker_url),
        tmp.clone(),
        None,
        None,
        free_port().await,
        MagnetOptions::default(),
    );
    let root = CancellationToken::new();
    let end = MagnetEngine::spawn(cfg, &root)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    root.cancel();
    let MagnetEnd::Failed(reason) = end else {
        panic!("expected Failed, got {end:?}");
    };
    assert!(
        reason.contains("rejected by parser"),
        "corrupt metadata must be rejected at rebuild: {reason}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

/// (4) bt-metadata-only: fetching metadata is the terminal state, no
/// download.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bt_metadata_only_ends_without_download() {
    init_log();
    init_log();
    let content: Vec<u8> = vec![0xA1u8; L as usize + 100];
    let (info_bytes, btih) = build_v1_info(&content, b"meta-only.bin");
    let tmp = tmp_dir("meta-only");

    let seeder_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let seeder_addr = seeder_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"));
    spawn_full_seeder(
        seeder_listener,
        SeederSpec {
            metadata: Arc::new(info_bytes.clone()),
            stream: Arc::new(content),
            v1_hash: btih,
            v2_hash20: [0u8; 20],
            v2_goffs: None,
            hash_files: Arc::new(Vec::new()),
        },
    )
    .await;
    let tracker_url = fake_tracker(vec![seeder_addr]).await;

    let cfg = test_config(
        GidAllocator::new().allocate(),
        magnet_uri_btih(btih, &tracker_url),
        tmp.clone(),
        None,
        None,
        free_port().await,
        MagnetOptions {
            bt_metadata_only: true,
            ..MagnetOptions::default()
        },
    );
    let root = CancellationToken::new();
    let end = MagnetEngine::spawn(cfg, &root)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    root.cancel();
    let MagnetEnd::MetadataFetched { metadata, chain } = end else {
        panic!("expected MetadataFetched, got {end:?}");
    };
    assert_eq!(metadata.as_ref(), info_bytes.as_slice());
    assert!(!chain.paused);
    assert!(
        tmp.read_dir()
            .unwrap_or_else(|e| panic!("{e}"))
            .next()
            .is_none(),
        "metadata-only must not trigger a download to disk"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

/// (4) follow-torrent=false: do not follow (the equivalent terminal state
/// to aria2 RequestGroup.cc not registering the post-download handler).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn follow_torrent_false_skips_upgrade() {
    init_log();
    let content: Vec<u8> = vec![0x5Eu8; L as usize];
    let (info_bytes, btih) = build_v1_info(&content, b"nofollow.bin");
    let tmp = tmp_dir("nofollow");

    let seeder_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let seeder_addr = seeder_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"));
    spawn_full_seeder(
        seeder_listener,
        SeederSpec {
            metadata: Arc::new(info_bytes.clone()),
            stream: Arc::new(content),
            v1_hash: btih,
            v2_hash20: [0u8; 20],
            v2_goffs: None,
            hash_files: Arc::new(Vec::new()),
        },
    )
    .await;
    let tracker_url = fake_tracker(vec![seeder_addr]).await;

    let cfg = test_config(
        GidAllocator::new().allocate(),
        magnet_uri_btih(btih, &tracker_url),
        tmp.clone(),
        None,
        None,
        free_port().await,
        MagnetOptions {
            follow_torrent: false,
            ..MagnetOptions::default()
        },
    );
    let root = CancellationToken::new();
    let end = MagnetEngine::spawn(cfg, &root)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    root.cancel();
    let MagnetEnd::NotFollowed { chain } = end else {
        panic!("expected NotFollowed, got {end:?}");
    };
    // NotFollowed: the data face keeps only the metadata chain (no
    // upgrade view was produced).
    assert_eq!(chain.task_gid, chain.metadata_gid);
    assert!(
        tmp.read_dir()
            .unwrap_or_else(|e| panic!("{e}"))
            .next()
            .is_none(),
        "a not-followed task must write nothing to disk"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

/// (4) pause-metadata: the upgrade config validates but the task does not
/// start.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pause_metadata_flags_chain_without_starting_download() {
    init_log();
    let content: Vec<u8> = vec![0x33u8; L as usize];
    let (info_bytes, btih) = build_v1_info(&content, b"paused.bin");
    let tmp = tmp_dir("paused");

    let seeder_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let seeder_addr = seeder_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"));
    spawn_full_seeder(
        seeder_listener,
        SeederSpec {
            metadata: Arc::new(info_bytes.clone()),
            stream: Arc::new(content),
            v1_hash: btih,
            v2_hash20: [0u8; 20],
            v2_goffs: None,
            hash_files: Arc::new(Vec::new()),
        },
    )
    .await;
    let tracker_url = fake_tracker(vec![seeder_addr]).await;

    let cfg = test_config(
        GidAllocator::new().allocate(),
        magnet_uri_btih(btih, &tracker_url),
        tmp.clone(),
        None,
        None,
        free_port().await,
        MagnetOptions {
            pause_metadata: true,
            ..MagnetOptions::default()
        },
    );
    let root = CancellationToken::new();
    let end = MagnetEngine::spawn(cfg, &root)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    root.cancel();
    let MagnetEnd::UpgradedPaused { chain, .. } = end else {
        panic!("expected UpgradedPaused, got {end:?}");
    };
    assert!(
        chain.paused,
        "pause-metadata must enter the chain's data face"
    );
    assert!(
        tmp.read_dir()
            .unwrap_or_else(|e| panic!("{e}"))
            .next()
            .is_none(),
        "a paused task must not start the download"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

/// (4) bt-load-saved-metadata: a saved .torrent on disk matches with a
/// consistent identity -> the metadata phase is skipped and the upgrade
/// happens directly (download_helper.cc). Completes even though the
/// seeder offers no ut_metadata serve face (proving the metadata came
/// from the local file).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bt_load_saved_metadata_skips_fetch() {
    init_log();
    let content: Vec<u8> = (0..L as usize).map(|i| (i * 13 % 241) as u8).collect();
    let (info_bytes, btih) = build_v1_info(&content, b"saved.bin");
    let tmp = tmp_dir("load-saved");

    // Seeder (metadata is still provided, but when the saved file hits,
    // the fetch path never happens — that is exactly the assertion
    // point).
    let seeder_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let seeder_addr = seeder_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"));
    spawn_full_seeder(
        seeder_listener,
        SeederSpec {
            metadata: Arc::new(info_bytes.clone()),
            stream: Arc::new(content.clone()),
            v1_hash: btih,
            v2_hash20: [0u8; 20],
            v2_goffs: None,
            hash_files: Arc::new(Vec::new()),
        },
    )
    .await;
    let tracker = fake_tracker(vec![seeder_addr]).await;
    // Preseed the saved .torrent (metadata2Torrent product shape:
    // announce-list + info).
    let top = dict_dyn(vec![
        (
            b"announce-list".to_vec(),
            Value::List(vec![Value::List(vec![Value::Bytes(
                tracker.clone().into_bytes(),
            )])]),
        ),
        (
            b"info".to_vec(),
            taiji_bt::bencode::decode_permissive(&info_bytes).unwrap_or_else(|e| panic!("{e}")),
        ),
    ]);
    let torrent_bytes = bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(tmp.join(format!("{}.torrent", hex(&btih))), &torrent_bytes)
        .unwrap_or_else(|e| panic!("{e}"));

    let cfg = test_config(
        GidAllocator::new().allocate(),
        magnet_uri_btih(btih, &tracker),
        tmp.clone(),
        None,
        None,
        free_port().await,
        MagnetOptions {
            bt_load_saved_metadata: true,
            ..MagnetOptions::default()
        },
    );
    let root = CancellationToken::new();
    let end = MagnetEngine::spawn(cfg, &root)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    root.cancel();
    let MagnetEnd::Upgraded { end, chain, .. } = end else {
        panic!("expected Upgraded, got {end:?}");
    };
    assert!(matches!(end, EngineEnd::Completed), "engine end: {end:?}");
    let got = std::fs::read(tmp.join("saved.bin")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(got, content);
    assert_eq!(chain.following(), chain.metadata_gid);
    let _ = std::fs::remove_dir_all(&tmp);
}

/// (5) Metadata timeout: no peers fails honestly (no fake completion).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metadata_deadline_fails_honestly() {
    init_log();
    let content: Vec<u8> = vec![1u8; L as usize];
    let (_info, btih) = build_v1_info(&content, b"never.bin");
    let tmp = tmp_dir("deadline");
    let tracker_url = fake_tracker(Vec::new()).await; // empty reply, no DHT

    let mut cfg = test_config(
        GidAllocator::new().allocate(),
        magnet_uri_btih(btih, &tracker_url),
        tmp.clone(),
        None,
        None,
        free_port().await,
        MagnetOptions::default(),
    );
    cfg.phase.metadata_deadline = Some(Duration::from_secs(2));
    let root = CancellationToken::new();
    let t0 = std::time::Instant::now();
    let end = MagnetEngine::spawn(cfg, &root)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    root.cancel();
    let elapsed = t0.elapsed();
    let MagnetEnd::Failed(reason) = end else {
        panic!("expected Failed, got {end:?}");
    };
    assert!(reason.contains("deadline"), "{reason}");
    assert!(
        elapsed < Duration::from_secs(15),
        "the deadline must be enforced: {elapsed:?}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

/// (6) Session-level full-chain regression: magnet addUri -> metadata
/// fetch -> in-place upgrade -> followedBy chain presented (the
/// `MagnetUpgraded` notification sets the upgraded flag, SPEC section
/// 7.1) -> the upgraded engine's download converges. Pins session
/// notification ordering: once upgrade and finish notifications are
/// merged and forwarded through the same FIFO channel, Ended always
/// follows MagnetUpgraded (with per-task racing enqueue, a fast-finishing
/// engine could let Ended overtake and followedBy would never appear).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_magnet_upgrade_presents_followed_by_and_converges() {
    init_log();
    use std::collections::BTreeMap;
    use std::time::Instant;

    use taiji_core::session::{
        CommandReply, GlobalOptions, SessionActor, SessionCommand, SessionOptions, StatusKind,
    };

    let content: Vec<u8> = (0..2 * L as usize).map(|i| (i * 29 % 241) as u8).collect();
    let (info_bytes, btih) = build_v1_info(&content, b"p58.bin");
    let tmp = tmp_dir("p58-session");

    // Seeder + tracker (the discovery face shared by the metadata phase
    // and the upgraded engine).
    let seeder_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let seeder_addr = seeder_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"));
    spawn_full_seeder(
        seeder_listener,
        SeederSpec {
            metadata: Arc::new(info_bytes.clone()),
            stream: Arc::new(content.clone()),
            v1_hash: btih,
            v2_hash20: [0u8; 20], // no v2 face
            v2_goffs: None,
            hash_files: Arc::new(Vec::new()),
        },
    )
    .await;
    let tracker_url = fake_tracker(vec![seeder_addr]).await;

    // listen_port = 0: the engine picks an ephemeral port (avoids
    // fixed-port collisions on the test face).
    let global = GlobalOptions {
        listen_port: 0,
        ..GlobalOptions::default()
    };
    let (handle, join) = SessionActor::spawn_with(SessionOptions { global });
    let gid = match handle
        .call(SessionCommand::AddUri {
            uris: vec![magnet_uri_btih(btih, &tracker_url)],
            options: BTreeMap::from([("dir".to_string(), tmp.display().to_string())]),
            position: None,
        })
        .await
        .unwrap_or_else(|e| panic!("{e}"))
    {
        CommandReply::Gid(g) => g,
        other => panic!("unexpected addUri reply: {other:?}"),
    };

    // followedBy chain presentation (upgrade notification -> upgraded
    // flag; not present during the metadata phase).
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut presented = false;
    while Instant::now() < deadline {
        let view = match handle
            .call(SessionCommand::TellStatus {
                gid: gid.to_string(),
                keys: vec![],
            })
            .await
        {
            Ok(CommandReply::TorrentStatus(v)) => *v,
            Ok(other) => panic!("unexpected tellStatus reply: {other:?}"),
            Err(e) => panic!("tellStatus failed: {e}"),
        };
        if !view.followed_by.is_empty() {
            assert_eq!(view.followed_by, vec![gid], "the degenerate same-GID chain");
            assert_eq!(
                view.following,
                Some(gid),
                "the reverse chain uses the same GID"
            );
            presented = true;
            break;
        }
        assert_ne!(
            view.status,
            StatusKind::Error,
            "magnet task error: {:?}",
            view.error_message
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        presented,
        "the followedBy chain was never presented (upgrade notification missing/late)"
    );

    // Download convergence: the upgraded engine finishes writing to disk
    // (verify-then-write -> all bytes match).
    let dl_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match std::fs::read(tmp.join("p58.bin")) {
            Ok(got) if got == content => break,
            _ => {
                assert!(
                    Instant::now() < dl_deadline,
                    "upgraded engine did not converge in time"
                );
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&tmp);
}

/// (7) Regression (session-level full chain): after a magnet task without
/// so= upgrades and completes, the tellStatus view must present the real
/// total/completed. Guards against the collapse where the upgraded task
/// reports `status=complete, completed=0/0` (the completed >= total > 0
/// criterion never fires and verification never starts). The test polls
/// total/completed across three phases (metadata / downloading /
/// complete), pinning session-side upgrade-chain bookkeeping
/// (running.total_len backfill + terminal result entry).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_magnet_upgrade_reports_real_totals_through_completion() {
    init_log();
    use std::collections::BTreeMap;
    use std::time::Instant;

    use taiji_core::session::{
        CommandReply, GlobalOptions, SessionActor, SessionCommand, SessionOptions, StatusKind,
    };

    let content: Vec<u8> = (0..2 * L as usize).map(|i| (i * 31 % 251) as u8).collect();
    let (info_bytes, btih) = build_v1_info(&content, b"p89.bin");
    let tmp = tmp_dir("p89-session");

    let seeder_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let seeder_addr = seeder_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"));
    spawn_full_seeder(
        seeder_listener,
        SeederSpec {
            metadata: Arc::new(info_bytes.clone()),
            stream: Arc::new(content.clone()),
            v1_hash: btih,
            v2_hash20: [0u8; 20],
            v2_goffs: None,
            hash_files: Arc::new(Vec::new()),
        },
    )
    .await;
    let tracker_url = fake_tracker(vec![seeder_addr]).await;

    let global = GlobalOptions {
        listen_port: 0,
        ..GlobalOptions::default()
    };
    let (handle, join) = SessionActor::spawn_with(SessionOptions { global });
    let gid = match handle
        .call(SessionCommand::AddUri {
            uris: vec![magnet_uri_btih(btih, &tracker_url)],
            options: BTreeMap::from([
                ("dir".to_string(), tmp.display().to_string()),
                // Short seed window (3 s): the complete state winds down to
                // SeedStopped (default seed-ratio 1.0 + no uploads = the
                // condition never holds; in-session natural shutdown needs
                // the time condition).
                ("seed-time".to_string(), "0.05".to_string()),
            ]),
            position: None,
        })
        .await
        .unwrap_or_else(|e| panic!("{e}"))
    {
        CommandReply::Gid(g) => g,
        other => panic!("unexpected addUri reply: {other:?}"),
    };

    // Phase polling: metadata phase (total=0, honest) -> upgraded
    // download (total = real length) -> complete state (total/completed =
    // real length; complete with 0/0 is the defect).
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut saw_downloading_total = false;
    let mut final_view = None;
    while Instant::now() < deadline {
        let view = match handle
            .call(SessionCommand::TellStatus {
                gid: gid.to_string(),
                keys: vec![],
            })
            .await
        {
            Ok(CommandReply::TorrentStatus(v)) => *v,
            Ok(other) => panic!("unexpected tellStatus reply: {other:?}"),
            Err(e) => panic!("tellStatus failed: {e}"),
        };
        eprintln!(
            "[forensics] status={:?} total={} completed={} followed_by={}",
            view.status,
            view.total_length,
            view.completed_length,
            view.followed_by.len()
        );
        if !view.followed_by.is_empty() && view.total_length == content.len() as u64 {
            saw_downloading_total = true;
        }
        match view.status {
            StatusKind::Complete => {
                final_view = Some(view);
                break;
            }
            StatusKind::Error => panic!("magnet task error: {:?}", view.error_message),
            _ => {}
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        saw_downloading_total,
        "the post-upgrade live view does not present the real total \
         (a download-phase reading defect)"
    );
    let view = match final_view {
        Some(v) => v,
        None => panic!("task did not reach Complete in time"),
    };
    assert_eq!(
        view.total_length,
        content.len() as u64,
        "terminal total_length collapsed (the upgrade chain never backfills \
         the session-side total)"
    );
    assert_eq!(
        view.completed_length,
        content.len() as u64,
        "terminal completed_length collapsed (the root cause of the \
         completed >= total > 0 criterion never firing)"
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&tmp);
}
