//! Metadata connection ownership, PEX introducers and BEP55 coordination.
use super::*;
use std::net::SocketAddr;
use std::time::Instant;
use taiji_bt::holepunch::{HolepunchBook, HpError, RelayAction, UtHolepunch, relay_decision};
use taiji_bt::peer::{HolepunchEvent, HolepunchExt, PexExt};
use taiji_bt::utp::{PeerConnectionType, Transport};

#[expect(
    clippy::too_many_arguments,
    reason = "metadata connection assembly keeps identity, transport and lifecycle ownership explicit"
)]
pub(super) fn spawn_dial_with_network(
    cfg: &MagnetTaskConfig,
    faces: &[MetaFace],
    face: usize,
    address: SocketAddr,
    source: &'static str,
    peers: &Arc<AtomicUsize>,
    dialed: &Arc<std::sync::Mutex<HashSet<(usize, SocketAddr)>>>,
    total: &Arc<AtomicUsize>,
    live: &LivePeers,
    tx: mpsc::Sender<MetadataFetched>,
    token: &CancellationToken,
    signals: Option<Arc<PeerSignals>>,
) {
    let Some(address) = crate::engine::addr_hygiene::sanitize_discovered_addr(address) else {
        return;
    };
    if cfg.ip_guard.as_ref().is_some_and(|guard| {
        guard
            .load()
            .blocks(address.ip(), crate::engine::addr_hygiene::epoch_secs())
            .is_some()
    }) {
        return;
    }
    let local_port = signals
        .as_ref()
        .map_or(cfg.phase.listen_port, |s| s.network.port);
    if crate::engine::addr_hygiene::is_self_endpoint(
        address,
        local_port,
        crate::engine::addr_hygiene::LocalIpSet::shared(),
    ) {
        return;
    }
    let punch = source == "holepunch";
    let relay = source == "relay-utp";
    if crate::lock(live).iter().any(|p| {
        p.face == face
            && p.address == address
            && !p.token.is_cancelled()
            && (!relay || p.transport == Transport::Utp)
    }) {
        return;
    }
    let key = (face, address);
    if total.load(Ordering::Relaxed)
        >= cfg.phase.max_metadata_peers + if punch || relay { 4 } else { 0 }
    {
        return;
    }
    if !crate::lock(dialed).insert(key) {
        return;
    }
    total.fetch_add(1, Ordering::Relaxed);
    let face_config = faces[face].clone();
    let (peers, dialed, total, live) = (peers.clone(), dialed.clone(), total.clone(), live.clone());
    let token = token.child_token();
    let peer_id = cfg.peer_id;
    let limiter = cfg.limiter.clone();
    let timeout = cfg.phase.peer_metadata_timeout;
    let policy = if relay {
        PeerConnectionType::Utp
    } else if matches!(source, "pex-utp" | "pex-holepunch")
        && matches!(
            cfg.options.bt_peer_connection_type,
            PeerConnectionType::PreferTcp | PeerConnectionType::PreferUtp
        )
    {
        PeerConnectionType::PreferUtp
    } else {
        signals
            .as_ref()
            .map_or(cfg.options.bt_peer_connection_type, |signals| {
                crate::lock(&signals.candidates).policy(
                    face,
                    address,
                    cfg.options.bt_peer_connection_type,
                )
            })
    };
    tokio::spawn(async move {
        peers.fetch_add(1, Ordering::Relaxed);
        if relay {
            // libtorrent rejects a second transport for the same peer ID.
            // Retire TCP before upgrading this introducer to its observed UDP
            // endpoint; pending introductions survive the connection change.
            for previous in crate::lock(&live)
                .iter()
                .filter(|p| p.face == face && p.address == address && p.transport == Transport::Tcp)
            {
                previous.token.cancel();
            }
            for _ in 0..50 {
                if !crate::lock(&live).iter().any(|p| {
                    p.face == face && p.address == address && p.transport == Transport::Tcp
                }) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        let connected = if let Some(signals) = &signals {
            let connect = signals.network.connect(
                address,
                &face_config.info_hash,
                &peer_id,
                face_config.reserved,
                policy,
                punch,
                punch || relay,
                &token,
            );
            tokio::pin!(connect);
            if signals.enabled && source == "pex-holepunch" {
                tokio::select! {
                    result = &mut connect => result,
                    _ = tokio::time::sleep(Duration::from_millis(750)) => {
                        let _ = signals.reports.try_send(PeerReport::Slow { face, address });
                        connect.await
                    }
                }
            } else {
                connect.await
            }
        } else {
            let connect = async {
                let stream = tokio::net::TcpStream::connect(address).await.ok()?;
                let (stream, hs) = taiji_bt::peer::handshake_exchange(
                    stream,
                    &face_config.info_hash,
                    &peer_id,
                    face_config.reserved,
                    HANDSHAKE_TIMEOUT,
                )
                .await
                .ok()?;
                Some((Box::new(stream) as network::Stream, hs, Transport::Tcp))
            };
            tokio::select! { _ = token.cancelled() => None, value = tokio::time::timeout(DIAL_TIMEOUT, connect) => value.ok().flatten() }
        };
        crate::lock(&dialed).remove(&key);
        match connected {
            Some((stream, handshake, transport)) => {
                if let Some(signals) = &signals {
                    crate::lock(&signals.candidates).connected(
                        face,
                        address,
                        transport,
                        Instant::now(),
                    );
                }
                debug!(target: "taiji::core::magnet", %address, source, transport = transport.as_transport_str(), "metadata connection established");
                if punch {
                    info!(target: "taiji::core::magnet", %address, "metadata holepunch established");
                }
                peer_session(
                    stream,
                    handshake,
                    transport,
                    false,
                    face,
                    address,
                    source,
                    peer_id,
                    &face_config,
                    tx,
                    &live,
                    token,
                    limiter,
                    timeout,
                    signals,
                )
                .await;
            }
            None if token.is_cancelled() => {}
            None => {
                if let Some(signals) = &signals {
                    crate::lock(&signals.candidates).failed(face, address, Instant::now());
                    let _ = signals
                        .reports
                        .send(PeerReport::Failed { face, address })
                        .await;
                }
                debug!(target: "taiji::core::magnet", %address, source, "metadata peer dial failed");
            }
        }
        peers.fetch_sub(1, Ordering::Relaxed);
        total.fetch_sub(1, Ordering::Relaxed);
    });
}

#[expect(
    clippy::too_many_arguments,
    reason = "metadata connection assembly keeps identity, transport and lifecycle ownership explicit"
)]
pub(super) fn spawn_incoming_peer(
    cfg: &MagnetTaskConfig,
    faces: &[MetaFace],
    incoming: network::Incoming,
    peers: &Arc<AtomicUsize>,
    total: &Arc<AtomicUsize>,
    live: &LivePeers,
    tx: mpsc::Sender<MetadataFetched>,
    token: &CancellationToken,
    signals: Arc<PeerSignals>,
) {
    if total.load(Ordering::Relaxed) >= cfg.phase.max_metadata_peers + 4 {
        return;
    }
    if cfg.ip_guard.as_ref().is_some_and(|guard| {
        guard
            .load()
            .blocks(
                incoming.address.ip(),
                crate::engine::addr_hygiene::epoch_secs(),
            )
            .is_some()
    }) {
        return;
    }
    let Some(face_config) = faces.get(incoming.face).cloned() else {
        return;
    };
    let (peers, total, live) = (peers.clone(), total.clone(), live.clone());
    let peer_id = cfg.peer_id;
    let timeout = cfg.phase.peer_metadata_timeout;
    let limiter = cfg.limiter.clone();
    let token = token.child_token();
    total.fetch_add(1, Ordering::Relaxed);
    tokio::spawn(async move {
        peers.fetch_add(1, Ordering::Relaxed);
        info!(target: "taiji::core::magnet", address = %incoming.address, transport = incoming.transport.as_transport_str(), "metadata incoming connection established");
        peer_session(
            incoming.stream,
            incoming.handshake,
            incoming.transport,
            true,
            incoming.face,
            incoming.address,
            "incoming",
            peer_id,
            &face_config,
            tx,
            &live,
            token,
            limiter,
            timeout,
            Some(signals),
        )
        .await;
        peers.fetch_sub(1, Ordering::Relaxed);
        total.fetch_sub(1, Ordering::Relaxed);
    });
}

#[expect(
    clippy::too_many_arguments,
    reason = "metadata connection assembly keeps identity, transport and lifecycle ownership explicit"
)]
async fn peer_session(
    stream: network::Stream,
    handshake: taiji_bt::peer_wire::Handshake,
    transport: Transport,
    inbound: bool,
    face: usize,
    address: SocketAddr,
    source: &'static str,
    peer_id: [u8; 20],
    face_config: &MetaFace,
    tx: mpsc::Sender<MetadataFetched>,
    live: &LivePeers,
    token: CancellationToken,
    limiter: Option<Arc<LimiterSet>>,
    timeout: Duration,
    signals: Option<Arc<PeerSignals>>,
) {
    let id = signals
        .as_ref()
        .map_or_else(rand::random, |s| s.next_id.fetch_add(1, Ordering::Relaxed));
    let (metadata_tx, mut metadata_rx) = mpsc::channel(4);
    let mut ext = taiji_bt::peer::ExtConfig::fetch(MetadataFetchSpec {
        expected: face_config.expected,
        shared: signals
            .as_ref()
            .map(|signals| taiji_bt::ut_metadata::SharedMetadataSpec {
                coordinator: signals.metadata[face].clone(),
                source: handshake.peer_id,
            }),
        tx: metadata_tx,
    });
    if let Some(signals) = &signals {
        ext.pex = Some(PexExt {
            tx: signals.pex.clone(),
            interval: taiji_bt::pex::DEFAULT_INTERVAL,
        });
    }
    let config = PeerConfig {
        cuid: id,
        remote_ip: Some(address.ip()),
        listen_port: signals
            .as_ref()
            .map_or(0, |s| s.network.advertised(transport, address)),
        addressing: taiji_bt::piece_id::Addressing::Flat,
        ext,
        holepunch: signals
            .as_ref()
            .filter(|s| s.enabled)
            .map(|s| HolepunchExt {
                tx: s.holepunch.clone(),
            }),
        ..PeerConfig::flat()
    };
    let peer_token = token.child_token();
    let (handle, mut join, _data_rx) =
        PeerTask::spawn(&peer_token, Throttled::maybe(stream, limiter), config);
    {
        let mut registry = crate::lock(live);
        let duplicate = registry
            .iter()
            .find(|p| p.face == face && p.peer_id == handshake.peer_id && !p.token.is_cancelled())
            .cloned();
        if let Some(previous) = duplicate {
            let preferred_incoming = peer_id > handshake.peer_id;
            let replace = (transport == Transport::Utp && previous.transport == Transport::Tcp)
                || (transport == previous.transport
                    && inbound == preferred_incoming
                    && previous.inbound != preferred_incoming);
            if !replace {
                peer_token.cancel();
                return;
            }
            previous.token.cancel();
        }
        registry.push(MetadataPeer {
            face,
            id,
            address,
            handle: handle.clone(),
            token: peer_token.clone(),
            transport,
            peer_id: handshake.peer_id,
            inbound,
        });
    }
    if let Some(signals) = &signals {
        let _ = signals
            .reports
            .send(PeerReport::Connected {
                face,
                address,
                id,
                source,
            })
            .await;
    }
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    let mut progress_tick = tokio::time::interval(
        timeout
            .max(Duration::from_millis(1))
            .min(Duration::from_millis(250)),
    );
    let mut last_progress = 0;
    let lifetime = tokio::time::sleep(Duration::from_secs(300));
    tokio::pin!(lifetime);
    let mut received = false;
    let mut introducer = false;
    let mut nat_changes = signals
        .as_ref()
        .and_then(|s| s.network.nat.as_ref())
        .map(|nat| nat.subscribe_external_ports());
    loop {
        tokio::select! {
            biased;
            _ = token.cancelled() => break,
            message = metadata_rx.recv(), if !received && !introducer => {
                let Some(message) = message else { break };
                received = matches!(&message, MetadataFetched::Complete(_));
                // A PEX/holepunch introducer need not serve metadata itself.
                let unavailable = matches!(&message, MetadataFetched::Failed(reason) if reason == "peer advertises no ut_metadata/metadata_size" || reason.starts_with("peer rejected metadata request"));
                if unavailable && handle.supports_holepunch() {
                    if let Some(signals) = &signals {
                        if signals.introducers.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| (n < signals.max_introducers).then_some(n + 1)).is_ok() {
                            introducer = true;
                            debug!(target: "taiji::core::magnet", %address, "retaining metadata introducer");
                            continue;
                        }
                    }
                }
                if tx.send(message).await.is_err() || !received { break; }
            }
            _ = &mut join => break,
            _ = &mut deadline, if !received && !introducer => break,
            _ = &mut lifetime, if !received => break,
            _ = progress_tick.tick(), if !received && !introducer => {
                let progress = signals.as_ref().map_or(0, |s| s.metadata[face].peer_progress(id));
                if progress > last_progress {
                    if last_progress == 0 { debug!(target: "taiji::core::magnet", %address, "metadata first block received"); }
                    last_progress = progress;
                    deadline.as_mut().reset(tokio::time::Instant::now() + timeout);
                }
            }
            changed = async { match nat_changes.as_mut() { Some(rx) => rx.changed().await.is_ok(), None => std::future::pending().await } } => {
                if !changed { nat_changes = None; continue; }
                if let Some(signals) = &signals { let _ = handle.command(PeerCommand::SetListenPort(signals.network.advertised(transport, address))); }
            }
        }
    }
    if let Some(signals) = &signals {
        if received || last_progress > 0 {
            crate::lock(&signals.candidates).useful(face, address, Instant::now());
        } else if !introducer && !token.is_cancelled() && !peer_token.is_cancelled() {
            crate::lock(&signals.candidates).failed(face, address, Instant::now());
        }
    }
    peer_token.cancel();
    if !join.is_finished() {
        let _ = join.await;
    }
    crate::lock(live).retain(|p| p.id != id);
    if let Some(signals) = &signals {
        if introducer {
            signals.introducers.fetch_sub(1, Ordering::Relaxed);
        }
        let _ = signals.reports.send(PeerReport::Closed(id)).await;
    }
}

pub(super) fn retry_metadata_rendezvous(
    live: &LivePeers,
    books: &mut [HolepunchBook],
    queue: &mut VecDeque<(usize, SocketAddr, &'static str)>,
    pending: &mut Vec<(usize, SocketAddr, SocketAddr)>,
) {
    let peers = crate::lock(live).clone();
    let now = Instant::now();
    for (face, book) in books.iter_mut().enumerate() {
        // Only discovered/actually failed targets qualify for introductions.
        for target in book.failed_targets(now) {
            let Some(id) = book.introducer(&target, now) else {
                continue;
            };
            let Some(peer) = peers.iter().find(|p| {
                p.id == id
                    && !p.token.is_cancelled()
                    && p.face == face
                    && p.handle.supports_holepunch()
            }) else {
                continue;
            };
            if peer.transport != Transport::Utp {
                if !pending
                    .iter()
                    .any(|&(f, r, t)| f == face && r == peer.address && t == target)
                    && pending.len() < 512
                {
                    pending.push((face, peer.address, target));
                }
                queue_metadata_peer(queue, face, peer.address, "relay-utp");
                continue;
            }
            if book.rendezvous_target(&target, now).is_some() {
                if peer
                    .handle
                    .command(PeerCommand::SendHolepunch(UtHolepunch::Rendezvous {
                        ep: target,
                    }))
                    .is_ok()
                {
                    info!(target: "taiji::core::magnet", target = %target, relay = %peer.address, "metadata holepunch rendezvous sent");
                }
            }
        }
    }
}

pub(super) fn handle_metadata_holepunch(
    event: HolepunchEvent,
    live: &LivePeers,
    queue: &mut VecDeque<(usize, SocketAddr, &'static str)>,
) {
    let peers = crate::lock(live).clone();
    let Some(requester) = peers
        .iter()
        .find(|p| p.id == event.from && !p.token.is_cancelled() && p.handle.supports_holepunch())
    else {
        return;
    };
    match event.msg {
        UtHolepunch::Connect { ep } => {
            if crate::engine::addr_hygiene::sanitize_discovered_addr(ep).is_none() {
                return;
            }
            info!(target: "taiji::core::magnet", target = %ep, "metadata holepunch connect received");
            queue_metadata_peer(queue, requester.face, ep, "holepunch");
        }
        UtHolepunch::Rendezvous { ep } => {
            let target = peers
                .iter()
                .find(|p| p.face == requester.face && p.address == ep && !p.token.is_cancelled());
            match relay_decision(
                requester.id,
                target.map(|p| (p.id, p.handle.supports_holepunch())),
            ) {
                RelayAction::Introduce => {
                    if let Some(target) = target {
                        let _ = requester.handle.command(PeerCommand::SendHolepunch(
                            UtHolepunch::Connect { ep: target.address },
                        ));
                        let _ = target.handle.command(PeerCommand::SendHolepunch(
                            UtHolepunch::Connect {
                                ep: requester.address,
                            },
                        ));
                    }
                }
                action => {
                    let error = match action {
                        RelayAction::ReplyNoSupport => HpError::NoSupport,
                        RelayAction::ReplyNoSelf => HpError::NoSelf,
                        _ => HpError::NotConnected,
                    };
                    let _ =
                        requester
                            .handle
                            .command(PeerCommand::SendHolepunch(UtHolepunch::Failed {
                                ep,
                                error,
                            }));
                }
            }
        }
        UtHolepunch::Failed { .. } => {}
    }
}
