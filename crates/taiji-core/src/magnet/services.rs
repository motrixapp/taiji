//! Session-owned metadata listener, warm dual-stack DHT and verified cache.
//! A subscription owns swarm routing and withdraws it as soon as fetching ends.
use super::*;
use std::collections::HashMap;
use std::sync::Mutex;
use taiji_io::udp_demux::{InboundPacket, UdpDemuxHandle};
use tokio::sync::Notify;

struct Subscriber {
    faces: Vec<MetaFace>,
    peer_id: [u8; 20],
    peers: mpsc::Sender<network::Incoming>,
    dht: mpsc::Sender<DhtEvent>,
    dht_enabled: bool,
    ipv6: bool,
}
type Subscribers = Arc<Mutex<HashMap<u64, Subscriber>>>;
type Retired = Arc<Mutex<HashSet<DhtTarget>>>;
struct Runtime {
    network: network::Network,
    controls: Arc<Mutex<Vec<(DhtFamily, DhtHandle)>>>,
    bootstrap_controls: Mutex<Vec<(DhtFamily, tokio::sync::watch::Sender<bool>)>>,
    events: mpsc::Sender<DhtEvent>,
    subscribers: Subscribers,
    retired: Retired,
    changed: Arc<Notify>,
    pump: tokio::task::JoinHandle<()>,
}
pub(super) struct Subscription {
    id: u64,
    subscribers: Subscribers,
    retired: Retired,
    candidates: network::Candidates,
    changed: Arc<Notify>,
}
fn update_candidates(subscribers: &HashMap<u64, Subscriber>, candidates: &network::Candidates) {
    *crate::lock(candidates) = subscribers
        .values()
        .flat_map(|s| {
            s.faces
                .iter()
                .map(|face| (face.info_hash, face.reserved, s.peer_id))
        })
        .collect();
}
impl Drop for Subscription {
    fn drop(&mut self) {
        let mut subscribers = crate::lock(&self.subscribers);
        if let Some(removed) = subscribers.remove(&self.id) {
            for face in removed.faces {
                if let Ok(target) = DhtTarget::new(face.info_hash, face.dht_kind, false) {
                    crate::lock(&self.retired).insert(target);
                }
            }
        }
        update_candidates(&subscribers, &self.candidates);
        self.changed.notify_one();
    }
}

type CachedTorrent = (Option<[u8; 20]>, Option<[u8; 32]>, Bytes);

pub struct MagnetServices {
    runtime: tokio::sync::Mutex<Option<Runtime>>,
    persist: Option<PersistHandle>,
    binding: crate::nat::PeerNetworkBinding,
    sequence: AtomicU64,
    cache: Mutex<Vec<CachedTorrent>>,
}
impl MagnetServices {
    pub fn new(persist: Option<PersistHandle>) -> Self {
        Self {
            runtime: tokio::sync::Mutex::new(None),
            persist,
            binding: crate::nat::PeerNetworkBinding::new(rand::random()),
            sequence: AtomicU64::new(1),
            cache: Mutex::new(Vec::new()),
        }
    }
    pub fn network(&self) -> crate::nat::PeerNetworkBinding {
        self.binding.clone()
    }
    pub(super) fn cached(&self, v1: Option<[u8; 20]>, v2: Option<[u8; 32]>) -> Option<Bytes> {
        let mut cache = crate::lock(&self.cache);
        let index = cache.iter().position(|(a, b, _)| {
            v1.is_some_and(|hash| *a == Some(hash)) || v2.is_some_and(|hash| *b == Some(hash))
        })?;
        let entry = cache.remove(index);
        let bytes = entry.2.clone();
        cache.push(entry);
        Some(bytes)
    }
    pub(super) fn remember(&self, v1: Option<[u8; 20]>, v2: Option<[u8; 32]>, torrent: &[u8]) {
        const CAP: usize = 16 * 1024 * 1024;
        if torrent.len() > CAP {
            return;
        }
        let Ok((_, span)) = taiji_bt::bencode::decode_with_info_span(torrent) else {
            return;
        };
        let info = &torrent[span];
        if super::check_identity(info, v1, v2).is_err() {
            return;
        }
        // Cache content, not credentials or network policy from another add.
        let canonical = super::metadata2torrent(info, &[], &cached_layers(torrent));
        let torrent = canonical.as_slice();
        if torrent.len() > CAP {
            return;
        }
        let mut cache = crate::lock(&self.cache);
        cache.retain(|(a, b, _)| !(v1.is_some() && *a == v1 || v2.is_some() && *b == v2));
        while cache.len() >= 128
            || cache.iter().map(|(_, _, bytes)| bytes.len()).sum::<usize>() + torrent.len() > CAP
        {
            cache.remove(0);
        }
        cache.push((v1, v2, Bytes::copy_from_slice(torrent)));
    }
    pub(super) async fn open(
        &self,
        cfg: &MagnetTaskConfig,
        faces: &[MetaFace],
        parent: &CancellationToken,
    ) -> Result<(network::Network, Option<DhtLease>), String> {
        let mut guard = self.runtime.lock().await;
        if guard.is_none() {
            *guard = Some(self.start(cfg).await?);
        }
        let runtime = guard.as_mut().unwrap_or_else(|| unreachable!());
        if cfg.dht_enabled {
            if let Some(carrier) = runtime.network.dht.take() {
                self.start_dht(runtime, cfg, DhtFamily::V4, carrier).await;
            }
            if cfg.dht_ipv6_enabled {
                if let Some(carrier) = runtime.network.dht6.take() {
                    self.start_dht(runtime, cfg, DhtFamily::V6, carrier).await;
                }
            }
        }
        let (peers, incoming) = mpsc::channel(64);
        let (dht, events) = mpsc::channel(128);
        let id = self.sequence.fetch_add(1, Ordering::Relaxed);
        {
            let mut subscribers = crate::lock(&runtime.subscribers);
            if subscribers.len() >= 128 {
                return Err("metadata subscription limit reached".into());
            }
            subscribers.insert(
                id,
                Subscriber {
                    faces: faces.to_vec(),
                    peer_id: cfg.peer_id,
                    peers,
                    dht,
                    dht_enabled: cfg.dht_enabled,
                    ipv6: cfg.dht_ipv6_enabled,
                },
            );
            update_candidates(&subscribers, &runtime.network.candidates);
        }
        let registration = Subscription {
            id,
            subscribers: runtime.subscribers.clone(),
            retired: runtime.retired.clone(),
            candidates: runtime.network.candidates.clone(),
            changed: runtime.changed.clone(),
        };
        let network = network::Network::lease(
            runtime.network.dialer.clone(),
            incoming,
            registration,
            parent,
        );
        let mut handles: Vec<_> = crate::lock(&runtime.controls)
            .iter()
            .filter(|(family, _)| {
                cfg.dht_enabled && (*family == DhtFamily::V4 || cfg.dht_ipv6_enabled)
            })
            .map(|(_, handle)| handle.clone())
            .collect();
        let lease = if handles.is_empty() {
            None
        } else {
            Some(DhtLease {
                handle: handles.remove(0),
                extra_handles: handles,
                events,
            })
        };
        Ok((network, lease))
    }
    async fn start(&self, cfg: &MagnetTaskConfig) -> Result<Runtime, String> {
        let root = CancellationToken::new();
        let nat = cfg
            .nat
            .clone()
            .filter(|nat| !nat.is_host_managed())
            .map(|nat| self.binding.observe(nat))
            .unwrap_or_else(|| self.binding.engine());
        let mut network = network::Network::bind(
            cfg.phase.listen_port,
            cfg.peer_id,
            Vec::new(),
            Some(nat),
            &root,
        )
        .await?;
        let mut incoming = std::mem::replace(&mut network.incoming, mpsc::channel(1).1);
        let subscribers: Subscribers = Arc::new(Mutex::new(HashMap::new()));
        let retired: Retired = Arc::new(Mutex::new(HashSet::new()));
        let controls: Arc<Mutex<Vec<(DhtFamily, DhtHandle)>>> = Arc::new(Mutex::new(Vec::new()));
        let changed = Arc::new(Notify::new());
        let (events, mut event_rx) = mpsc::channel(128);
        let routes = subscribers.clone();
        let retired_targets = retired.clone();
        let control = controls.clone();
        let changes = changed.clone();
        let persist = self.persist.clone();
        let pump = tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(mut peer)=incoming.recv()=>{
                        let target={let subscribers=crate::lock(&routes);subscribers.values().filter(|s|!s.peers.is_closed()).find_map(|s|s.faces.iter().find(|f|f.info_hash==peer.handshake.info_hash).map(|f|(f.index,s.peers.clone())))};
                        if let Some((face,tx))=target {peer.face=face;let _=tx.try_send(peer);}
                    }
                    event=event_rx.recv()=>match event {
                        Some(DhtEvent::PeersFound{info_hash,face,peers})=>{
                            for subscriber in crate::lock(&routes).values().filter(|s|s.dht_enabled) {
                                if subscriber.faces.iter().any(|f|f.info_hash==info_hash&&f.dht_kind==face) {
                                    let peers:Vec<_>=peers.iter().copied().filter(|p|p.is_ipv4()||subscriber.ipv6).collect();
                                    let _=subscriber.dht.try_send(DhtEvent::PeersFound{info_hash,face,peers});
                                }
                            }
                        }
                        Some(DhtEvent::Persist{family,node_id,routing_table})=>{
                            if let Some(persist)=&persist {
                                let row=taiji_store::persist::DhtStateRow{family:if family==DhtFamily::V4{"v4"}else{"v6"}.to_string(),node_id:node_id.to_vec(),routing_table,saved_at:crate::engine::addr_hygiene::epoch_secs()};
                                if let Err(error)=persist.upsert_dht_state(row).await {warn!(target:"taiji::core::magnet",%error,"shared dht persistence failed");}
                            }
                        }
                        None=>break,
                    },
                    _=changes.notified()=>{
                        let retired=std::mem::take(&mut *crate::lock(&retired_targets));
                        for target in retired {
                            let active=crate::lock(&routes).values().any(|s|s.dht_enabled&&s.faces.iter().any(|f|f.info_hash==target.info_hash()&&f.dht_kind==target.face()));
                            if !active {
                                let handles=crate::lock(&control).clone();
                                for (_,handle) in handles {let _=handle.withdraw(target).await;}
                            }
                        }
                    }
                }
            }
        });
        Ok(Runtime {
            network,
            controls,
            bootstrap_controls: Mutex::new(Vec::new()),
            events,
            subscribers,
            retired,
            changed,
            pump,
        })
    }
    async fn start_dht(
        &self,
        runtime: &Runtime,
        cfg: &MagnetTaskConfig,
        family: DhtFamily,
        (inbound, demux): (mpsc::Receiver<InboundPacket>, UdpDemuxHandle),
    ) {
        let restore = match &self.persist {
            Some(p) => crate::engine::load_dht_restore_state(p, family).await,
            None => None,
        };
        let (out_tx, out_rx) = mpsc::channel(64);
        let (handle, _) = spawn_dht_engine(
            family,
            demux.bound_addr().port(),
            DhtEngineConfig {
                message_timeout: cfg.dht_message_timeout,
                ..DhtEngineConfig::default()
            },
            DhtTransport {
                inbound,
                outbound: out_tx,
            },
            restore,
            runtime.events.clone(),
        );
        forward_outbound(out_rx, demux);
        crate::lock(&runtime.controls).push((family, handle.clone()));
        let subscribers = runtime.subscribers.clone();
        let token = runtime.network.cancellation();
        let explicit = if family == DhtFamily::V4 {
            cfg.dht_entry_point_override.clone()
        } else {
            cfg.dht_entry_point_v6_override.clone()
        };
        let sources: Vec<String> = if let Some(entry) = explicit {
            vec![entry]
        } else if !cfg.dht_entry_points.is_empty() {
            cfg.dht_entry_points
                .iter()
                .filter(|address| address.is_ipv4() == (family == DhtFamily::V4))
                .map(ToString::to_string)
                .collect()
        } else if family == DhtFamily::V4 {
            taiji_bt::dht::DEFAULT_BOOTSTRAP_NODES
                .iter()
                .map(|(host, port)| format!("{host}:{port}"))
                .collect()
        } else {
            vec![
                "dht.transmissionbt.com:6881".into(),
                "dht.libtorrent.org:25401".into(),
            ]
        };
        let (enabled_tx, mut enabled) = tokio::sync::watch::channel(true);
        crate::lock(&runtime.bootstrap_controls).push((family, enabled_tx));
        tokio::spawn(async move {
            use futures::StreamExt;
            loop {
                let active = *enabled.borrow_and_update();
                if !active {
                    tokio::select! {_=token.cancelled()=>return, result=enabled.changed()=>{if result.is_err(){return;}}}
                    continue;
                }
                let mut probes = futures::stream::FuturesUnordered::new();
                for source in sources.clone() {
                    let handle = handle.clone();
                    probes.push(async move {
                        let addresses = if let Ok(address) = source.parse::<std::net::SocketAddr>()
                        {
                            vec![address]
                        } else {
                            let Some((host, port)) = source.rsplit_once(':') else {
                                return 0;
                            };
                            let Ok(port) = port.parse::<u16>() else {
                                return 0;
                            };
                            let dns = taiji_io::dns::SharedDns::shared_default();
                            match tokio::time::timeout(
                                Duration::from_secs(3),
                                dns.resolve_for_transport(host, port),
                            )
                            .await
                            {
                                Ok(Ok(addresses)) => addresses,
                                _ => Vec::new(),
                            }
                        };
                        let addresses = addresses
                            .into_iter()
                            .filter(|address| address.is_ipv4() == (family == DhtFamily::V4))
                            .collect::<Vec<_>>();
                        if addresses.is_empty() {
                            0
                        } else {
                            handle.bootstrap(addresses).await.unwrap_or(0)
                        }
                    });
                }
                loop {
                    let count = tokio::select! {_=token.cancelled()=>return, result=enabled.changed()=>{if result.is_err(){return;}break;}, value=probes.next()=>match value{Some(count)=>count,None=>break}};
                    if count == 0 {
                        continue;
                    }
                    let targets: HashSet<_> = crate::lock(&subscribers)
                        .values()
                        .filter(|s| s.dht_enabled)
                        .flat_map(|s| {
                            s.faces.iter().filter_map(|face| {
                                DhtTarget::new(face.info_hash, face.dht_kind, false).ok()
                            })
                        })
                        .collect();
                    for target in targets {
                        let _ = handle.get_peers(target).await;
                    }
                }
                drop(probes);
                let active = *enabled.borrow();
                if !active {
                    continue;
                }
                let warm = handle
                    .snapshot()
                    .await
                    .is_ok_and(|snapshot| snapshot.num_nodes >= 8);
                tokio::select! {_=token.cancelled()=>return, result=enabled.changed()=>{if result.is_err(){return;}}, _=tokio::time::sleep(Duration::from_secs(if warm {300} else {30}))=>{}}
            }
        });
        info!(target:"taiji::core::magnet",?family,"shared metadata dht ready");
    }
    pub async fn set_dht_enabled(&self, v4: bool, v6: bool) {
        let guard = self.runtime.lock().await;
        if let Some(runtime) = guard.as_ref() {
            let handles = crate::lock(&runtime.controls).clone();
            for (family, handle) in handles {
                let active = if family == DhtFamily::V4 { v4 } else { v6 };
                if !active {
                    for (kind, control) in crate::lock(&runtime.bootstrap_controls)
                        .iter()
                        .filter(|(kind, _)| *kind == family)
                    {
                        let _ = kind;
                        control.send_if_modified(|value| {
                            let changed = *value != active;
                            *value = active;
                            changed
                        });
                    }
                }
                let _ = handle.set_enabled(active).await;
                if active {
                    for (_, control) in crate::lock(&runtime.bootstrap_controls)
                        .iter()
                        .filter(|(kind, _)| *kind == family)
                    {
                        control.send_if_modified(|value| {
                            let changed = *value != active;
                            *value = active;
                            changed
                        });
                    }
                }
            }
        }
    }

    pub async fn shutdown(&self) {
        if let Some(runtime) = self.runtime.lock().await.take() {
            let controls = crate::lock(&runtime.controls).clone();
            for (_, handle) in controls {
                let _ = tokio::time::timeout(Duration::from_secs(2), handle.shutdown()).await;
            }
            drop(runtime.events);
            let mut pump = runtime.pump;
            if tokio::time::timeout(Duration::from_secs(2), &mut pump)
                .await
                .is_err()
            {
                pump.abort();
            }
            drop(runtime.network);
        }
        let (id, _) = self.binding.snapshot();
        self.binding.release(&id);
    }
}

/// Preserve verified BEP52 layers when rebuilding a cached torrent with this
/// add operation's trackers. The info dictionary itself is never re-encoded.
pub(super) fn cached_layers(torrent: &[u8]) -> Vec<([u8; 32], Vec<u8>)> {
    use taiji_bt::bencode::Value;
    let Ok(Value::Dict(top)) = taiji_bt::bencode::decode(torrent) else {
        return Vec::new();
    };
    let Some(Value::Dict(layers)) = top
        .iter()
        .find(|(key, _)| key.as_slice() == b"piece layers")
        .map(|(_, value)| value)
    else {
        return Vec::new();
    };
    layers
        .iter()
        .filter_map(|(root, data)| match data {
            Value::Bytes(data) => root
                .as_slice()
                .try_into()
                .ok()
                .map(|root| (root, data.clone())),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::magnet::tests::{metadata_fixture_config, web_mirror_torrent};
    fn faces(hash: [u8; 20]) -> Vec<MetaFace> {
        vec![MetaFace {
            index: 0,
            info_hash: hash,
            reserved: Reserved::aria2_default(),
            expected: ExpectedInfoHash::V1(hash),
            dht_kind: DhtSwarmKind::V1,
        }]
    }
    #[tokio::test]
    async fn shared_listener_routes_by_hash_and_withdraws_dropped_subscriptions() {
        let services = MagnetServices::new(None);
        let root = CancellationToken::new();
        let a = [1; 20];
        let b = [2; 20];
        let mut ca = metadata_fixture_config(a, PathBuf::new());
        let mut cb = metadata_fixture_config(b, PathBuf::new());
        ca.peer_id = [3; 20];
        cb.peer_id = [4; 20];
        let (mut na, _) = services
            .open(&ca, &faces(a), &root)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let (mut nb, _) = services
            .open(&cb, &faces(b), &root)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(na.dialer.port, nb.dialer.port);
        let connect = async |hash: &[u8; 20]| {
            let stream = tokio::net::TcpStream::connect(("127.0.0.1", na.dialer.port))
                .await
                .unwrap_or_else(|e| panic!("{e}"));
            taiji_bt::peer::handshake_exchange(
                stream,
                hash,
                &[9; 20],
                Reserved::aria2_default(),
                Duration::from_secs(1),
            )
            .await
        };
        let (_, handshake) = connect(&b).await.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(handshake.peer_id, cb.peer_id);
        let accepted = tokio::time::timeout(Duration::from_secs(1), nb.incoming.recv())
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(accepted.map(|p| p.handshake.info_hash), Some(b));
        assert!(na.incoming.try_recv().is_err());
        nb.release_registration();
        assert!(connect(&b).await.is_err());
        let (_, handshake) = connect(&a).await.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(handshake.peer_id, ca.peer_id);
        services.shutdown().await;
        assert_eq!(services.network().snapshot().1, 0);
    }
    #[tokio::test]
    async fn dht_is_reused_across_magnets_and_disable_keeps_peer_listener_alive() {
        let services = MagnetServices::new(None);
        let root = CancellationToken::new();
        let hash = [1; 20];
        let mut cfg = metadata_fixture_config(hash, PathBuf::new());
        cfg.dht_enabled = true;
        cfg.dht_entry_points = vec!["127.0.0.1:9".parse().unwrap_or_else(|e| panic!("{e}"))];
        let (mut network, lease) = services
            .open(&cfg, &faces(hash), &root)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let handle = lease.unwrap_or_else(|| panic!("dht")).handle;
        let target =
            DhtTarget::new(hash, DhtSwarmKind::V1, false).unwrap_or_else(|e| panic!("{e}"));
        handle
            .announce(target, network.dialer.port)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let first = handle.snapshot().await.unwrap_or_else(|e| panic!("{e}"));
        network.release_registration();
        for _ in 0..50 {
            if handle
                .snapshot()
                .await
                .unwrap_or_else(|e| panic!("{e}"))
                .announce_entries
                == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            handle
                .snapshot()
                .await
                .unwrap_or_else(|e| panic!("{e}"))
                .announce_entries,
            0
        );
        let (next, lease) = services
            .open(&cfg, &faces(hash), &root)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let second = lease
            .unwrap_or_else(|| panic!("dht"))
            .handle
            .snapshot()
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(first.node_id, second.node_id);
        assert_eq!(network.dialer.port, next.dialer.port);
        services.set_dht_enabled(false, false).await;
        assert!(handle.get_peers(target).await.is_err());
        assert!(
            tokio::net::TcpStream::connect(("127.0.0.1", next.dialer.port))
                .await
                .is_ok()
        );
        services.set_dht_enabled(true, false).await;
        assert!(handle.get_peers(target).await.is_ok());
        services.shutdown().await;
        assert!(handle.snapshot().await.is_err());
    }
    #[tokio::test]
    async fn cache_is_hash_checked_and_does_not_reuse_previous_trackers() {
        let services = Arc::new(MagnetServices::new(None));
        let (torrent, hash, _) = web_mirror_torrent();
        services.remember(Some([0; 20]), None, &torrent);
        assert!(services.cached(Some([0; 20]), None).is_none());
        services.remember(Some(hash), None, &torrent);
        let cached = services
            .cached(Some(hash), None)
            .unwrap_or_else(|| panic!("cached"));
        assert!(
            Metainfo::parse(&cached)
                .unwrap_or_else(|e| panic!("{e}"))
                .announce
                .is_empty()
        );
        let dir =
            std::env::temp_dir().join(format!("taiji-shared-cache-{}", rand::random::<u64>()));
        let mut cfg = metadata_fixture_config(hash, dir.clone());
        cfg.services = Some(services.clone());
        cfg.magnet_uri = format!("magnet:?xt=urn:btih:{}", hex_lower(&hash));
        let root = CancellationToken::new();
        let end = MagnetEngine::spawn(cfg, &root)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(end, MagnetEnd::MetadataFetched { .. }), "{end:?}");
        assert_eq!(services.network().snapshot().1, 0);
        std::fs::remove_dir_all(dir).unwrap_or_else(|e| panic!("{e}"));
    }
}
