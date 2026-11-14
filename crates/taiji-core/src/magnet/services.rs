//! Session-owned metadata listener, warm dual-stack DHT and verified cache.
//! A subscription owns swarm routing and withdraws it as soon as fetching ends.
use super::DiscoveryConfig;
use super::*;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU8};
use taiji_io::udp_demux::{InboundPacket, UdpDemuxHandle};
use tokio::sync::{Notify, OnceCell};

type DhtCarrier = (mpsc::Receiver<InboundPacket>, UdpDemuxHandle);

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
    events: Mutex<Option<mpsc::Sender<DhtEvent>>>,
    subscribers: Subscribers,
    retired: Retired,
    changed: Arc<Notify>,
    pump: Mutex<Option<tokio::task::JoinHandle<()>>>,
    carriers: Mutex<Vec<(DhtFamily, DhtCarrier)>>,
    dht4: OnceCell<()>,
    dht6: OnceCell<()>,
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

pub struct MagnetServices {
    runtime: OnceCell<Runtime>,
    lifetime: CancellationToken,
    preparing: AtomicBool,
    dht_policy: AtomicU8,
    persist: Option<PersistHandle>,
    binding: crate::nat::PeerNetworkBinding,
    sequence: AtomicU64,
    resolutions: super::resolution::ResolutionBook,
    cache: super::cache::MetadataCache,
    dns: Arc<taiji_io::dns::SharedDns>,
}
impl MagnetServices {
    pub fn new(persist: Option<PersistHandle>) -> Self {
        Self::with_dns(persist, taiji_io::dns::SharedDns::shared_default())
    }

    /// Reuse one resolver across metadata tracker and DHT discovery.
    /// Embedders can supply a service with their own resolution policy.
    pub fn with_dns(persist: Option<PersistHandle>, dns: Arc<taiji_io::dns::SharedDns>) -> Self {
        Self {
            runtime: OnceCell::new(),
            lifetime: CancellationToken::new(),
            preparing: AtomicBool::new(false),
            dht_policy: AtomicU8::new(0),
            persist: persist.clone(),
            binding: crate::nat::PeerNetworkBinding::new(rand::random()),
            sequence: AtomicU64::new(1),
            resolutions: super::resolution::ResolutionBook::default(),
            cache: super::cache::MetadataCache::new(persist),
            dns,
        }
    }
    pub(super) fn dns(&self) -> Arc<taiji_io::dns::SharedDns> {
        Arc::clone(&self.dns)
    }

    pub fn queue_resolution(&self, gid: Gid) {
        self.resolutions.queued(gid);
    }
    pub(crate) fn admit_resolution(&self, gid: Gid) -> Arc<MagnetResolution> {
        self.resolutions.admit(gid)
    }
    pub(super) fn claim_resolution(&self, gid: Gid) -> Arc<MagnetResolution> {
        self.resolutions.claim(gid)
    }
    pub fn resolution(&self, gid: Gid) -> Option<Arc<MagnetResolution>> {
        self.resolutions.get(gid)
    }

    pub fn network(&self) -> crate::nat::PeerNetworkBinding {
        self.binding.clone()
    }
    pub(super) async fn cached(
        &self,
        v1: Option<[u8; 20]>,
        v2: Option<[u8; 32]>,
    ) -> Option<super::cache::CacheHit> {
        self.cache.load(v1, v2).await
    }
    pub(crate) async fn remember(
        &self,
        v1: Option<[u8; 20]>,
        v2: Option<[u8; 32]>,
        torrent: &[u8],
    ) {
        self.cache.remember(v1, v2, torrent).await;
    }
    pub(super) async fn open(
        &self,
        cfg: &MagnetTaskConfig,
        faces: &[MetaFace],
        parent: &CancellationToken,
    ) -> Result<(network::Network, Option<DhtLease>), String> {
        self.prepare(&DiscoveryConfig::from(cfg)).await?;
        let runtime = self.runtime.get().ok_or("discovery is not prepared")?;
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
    /// Coalesce background requests, including callers arriving during startup.
    pub fn request_preparation(self: &Arc<Self>, config: DiscoveryConfig) {
        if self.lifetime.is_cancelled() || self.preparing.swap(true, Ordering::AcqRel) {
            return;
        }
        let services = self.clone();
        tokio::spawn(async move {
            if let Err(error) = services.prepare(&config).await {
                debug!(target:"taiji::core::magnet", %error, "discovery preparation unavailable");
            }
            services.preparing.store(false, Ordering::Release);
        });
    }

    /// Prepare shared sockets and DHT without submitting a torrent. Concurrent
    /// callers share one initialization and never hold a mutex across IO.
    pub async fn prepare(&self, cfg: &DiscoveryConfig) -> Result<(), String> {
        if self.lifetime.is_cancelled() {
            return Err("discovery service is shut down".into());
        }
        let runtime = self.runtime.get_or_try_init(|| self.start(cfg)).await?;
        for (family, enabled, initialized) in [
            (DhtFamily::V4, cfg.dht_enabled, &runtime.dht4),
            (
                DhtFamily::V6,
                cfg.dht_enabled && cfg.dht_ipv6_enabled,
                &runtime.dht6,
            ),
        ] {
            if enabled && self.dht_allowed(family) {
                initialized
                    .get_or_init(|| async {
                        let carrier = {
                            let mut carriers = crate::lock(&runtime.carriers);
                            carriers
                                .iter()
                                .position(|(kind, _)| *kind == family)
                                .map(|index| carriers.remove(index).1)
                        };
                        if let Some(carrier) = carrier {
                            self.start_dht(runtime, cfg, family, carrier).await;
                        }
                    })
                    .await;
            }
        }
        if self.lifetime.is_cancelled() {
            Self::close_runtime(runtime).await;
            return Err("discovery service is shut down".into());
        }
        Ok(())
    }

    fn dht_allowed(&self, family: DhtFamily) -> bool {
        let policy = self.dht_policy.load(Ordering::Acquire);
        policy & 4 == 0 || policy & (if family == DhtFamily::V4 { 1 } else { 2 }) != 0
    }

    async fn start(&self, cfg: &DiscoveryConfig) -> Result<Runtime, String> {
        let root = self.lifetime.child_token();
        let nat = cfg
            .nat
            .clone()
            .filter(|nat| !nat.is_host_managed())
            .map(|nat| self.binding.observe(nat))
            .unwrap_or_else(|| self.binding.engine());
        let mut network =
            network::Network::bind(cfg.listen_port, cfg.peer_id, Vec::new(), Some(nat), &root)
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
        let mut carriers = Vec::new();
        if let Some(carrier) = network.dht.take() {
            carriers.push((DhtFamily::V4, carrier));
        }
        if let Some(carrier) = network.dht6.take() {
            carriers.push((DhtFamily::V6, carrier));
        }
        Ok(Runtime {
            network,
            controls,
            bootstrap_controls: Mutex::new(Vec::new()),
            events: Mutex::new(Some(events)),
            subscribers,
            retired,
            changed,
            pump: Mutex::new(Some(pump)),
            carriers: Mutex::new(carriers),
            dht4: OnceCell::new(),
            dht6: OnceCell::new(),
        })
    }
    async fn start_dht(
        &self,
        runtime: &Runtime,
        cfg: &DiscoveryConfig,
        family: DhtFamily,
        (inbound, demux): (mpsc::Receiver<InboundPacket>, UdpDemuxHandle),
    ) {
        let restore = match &self.persist {
            Some(p) => crate::engine::load_dht_restore_state(p, family).await,
            None => None,
        };
        let (out_tx, out_rx) = mpsc::channel(64);
        let Some(events) = crate::lock(&runtime.events).clone() else {
            return;
        };
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
            events,
        );
        forward_outbound(out_rx, demux);
        let enabled = self.dht_allowed(family);
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
        let (enabled_tx, mut enabled) = tokio::sync::watch::channel(enabled);
        crate::lock(&runtime.bootstrap_controls).push((family, enabled_tx.clone()));
        crate::lock(&runtime.controls).push((family, handle.clone()));
        self.apply_dht_policy(family, &handle, &enabled_tx).await;
        let dns = Arc::clone(&self.dns);
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
                    let dns = Arc::clone(&dns);
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
    async fn apply_dht_policy(
        &self,
        family: DhtFamily,
        handle: &DhtHandle,
        control: &tokio::sync::watch::Sender<bool>,
    ) {
        loop {
            let before = self.dht_policy.load(Ordering::Acquire);
            let active =
                before & 4 == 0 || before & (if family == DhtFamily::V4 { 1 } else { 2 }) != 0;
            if !active {
                control.send_if_modified(|value| {
                    let changed = *value;
                    *value = false;
                    changed
                });
            }
            let _ = handle.set_enabled(active).await;
            if active {
                control.send_if_modified(|value| {
                    let changed = !*value;
                    *value = true;
                    changed
                });
            }
            if before == self.dht_policy.load(Ordering::Acquire) {
                break;
            }
        }
    }

    pub async fn set_dht_enabled(&self, v4: bool, v6: bool) {
        self.dht_policy
            .store(4 | u8::from(v4) | (u8::from(v6) << 1), Ordering::Release);
        if let Some(runtime) = self.runtime.get() {
            let handles = crate::lock(&runtime.controls).clone();
            for (family, handle) in handles {
                let control = crate::lock(&runtime.bootstrap_controls)
                    .iter()
                    .find(|(kind, _)| *kind == family)
                    .map(|(_, control)| control.clone());
                if let Some(control) = control {
                    self.apply_dht_policy(family, &handle, &control).await;
                }
            }
        }
    }

    pub async fn shutdown(&self) {
        self.lifetime.cancel();
        if let Some(runtime) = self.runtime.get() {
            Self::close_runtime(runtime).await;
        }
        let (id, _) = self.binding.snapshot();
        self.binding.release(&id);
    }

    async fn close_runtime(runtime: &Runtime) {
        runtime.network.cancellation().cancel();
        let controls = crate::lock(&runtime.controls).clone();
        for (_, handle) in controls {
            let _ = tokio::time::timeout(Duration::from_secs(2), handle.shutdown()).await;
        }
        crate::lock(&runtime.events).take();
        let pump = crate::lock(&runtime.pump).take();
        if let Some(mut pump) = pump {
            if tokio::time::timeout(Duration::from_secs(2), &mut pump)
                .await
                .is_err()
            {
                pump.abort();
                let _ = pump.await;
            }
        }
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
        let preparation = DiscoveryConfig::from(&cfg);
        let (first_prepare, second_prepare) = tokio::join!(
            services.prepare(&preparation),
            services.prepare(&preparation)
        );
        first_prepare.unwrap_or_else(|e| panic!("{e}"));
        second_prepare.unwrap_or_else(|e| panic!("{e}"));
        let runtime = services
            .runtime
            .get()
            .unwrap_or_else(|| panic!("prepared runtime"));
        assert!(crate::lock(&runtime.subscribers).is_empty());
        assert_eq!(crate::lock(&runtime.controls).len(), 1);
        let prepared_dht = crate::lock(&runtime.controls)[0].1.clone();
        assert_eq!(
            prepared_dht
                .snapshot()
                .await
                .unwrap_or_else(|e| panic!("{e}"))
                .announce_entries,
            0
        );
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
        services.remember(Some([0; 20]), None, &torrent).await;
        assert!(services.cached(Some([0; 20]), None).await.is_none());
        services.remember(Some(hash), None, &torrent).await;
        let cached = services
            .cached(Some(hash), None)
            .await
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

    #[tokio::test]
    async fn preparation_obeys_disabled_policy_and_shutdown_releases_the_listener() {
        let services = Arc::new(MagnetServices::new(None));
        let mut cfg = metadata_fixture_config([8; 20], PathBuf::new());
        cfg.dht_enabled = true;
        cfg.dht_entry_points = vec!["127.0.0.1:9".parse().unwrap_or_else(|e| panic!("{e}"))];
        let preparation = DiscoveryConfig::from(&cfg);
        services.set_dht_enabled(false, false).await;
        services
            .prepare(&preparation)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let runtime = services.runtime.get().unwrap_or_else(|| panic!("runtime"));
        assert!(crate::lock(&runtime.controls).is_empty());
        services.set_dht_enabled(true, false).await;
        services
            .prepare(&preparation)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(crate::lock(&runtime.controls).len(), 1);
        let port = runtime.network.dialer.port;
        services.shutdown().await;
        let listener = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(listener) = tokio::net::TcpListener::bind(("0.0.0.0", port)).await {
                    break listener;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|e| panic!("listener not released: {e}"));
        assert!(services.prepare(&preparation).await.is_err());
        drop(listener);
    }
}
