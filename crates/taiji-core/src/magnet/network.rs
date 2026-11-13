//! Metadata peer transport. TCP, uTP and DHT use the same bound port;
//! the embedding host may map that listener through the NAT binding watch.
use crate::nat::NatEngine;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use taiji_bt::peer_wire::{Handshake, Reserved};
use taiji_bt::utp::{PeerConnectionType, Transport};
use taiji_io::udp_demux::{self, DemuxChannels, DemuxConfig, UdpDemuxHandle};
use taiji_io::utp::{UtpConfig, UtpConnectHalf};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

pub(super) trait PeerIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> PeerIo for T {}
pub(super) type Stream = Box<dyn PeerIo>;

pub(super) struct Incoming {
    pub stream: Stream,
    pub address: SocketAddr,
    pub face: usize,
    pub transport: Transport,
    pub handshake: Handshake,
}

pub(super) struct Dialer {
    pub port: u16,
    pub nat: Option<NatEngine>,
    v4: UtpConnectHalf,
    v6: Option<UtpConnectHalf>,
}

impl Dialer {
    pub fn advertised(&self, transport: Transport, address: SocketAddr) -> u16 {
        if address.is_ipv6() {
            return self.port;
        }
        self.nat
            .as_ref()
            .and_then(|nat| match transport {
                Transport::Tcp => nat.external_ports().tcp,
                Transport::Utp => nat.external_ports().udp,
            })
            .unwrap_or(self.port)
    }

    async fn attempt(
        &self,
        address: SocketAddr,
        hash: &[u8; 20],
        peer_id: &[u8; 20],
        reserved: Reserved,
        transport: Transport,
        budget: Duration,
    ) -> Option<(Stream, Handshake, Transport)> {
        tokio::time::timeout(budget, async {
            let stream: Stream = match transport {
                Transport::Tcp => {
                    let stream = tokio::net::TcpStream::connect(address).await.ok()?;
                    let _ = stream.set_nodelay(true);
                    Box::new(stream)
                }
                Transport::Utp => Box::new(
                    if address.is_ipv4() {
                        &self.v4
                    } else {
                        self.v6.as_ref()?
                    }
                    .connect(address),
                ),
            };
            let (stream, handshake) =
                taiji_bt::peer::handshake_exchange(stream, hash, peer_id, reserved, budget)
                    .await
                    .ok()?;
            if handshake.peer_id == *peer_id {
                return None;
            }
            Some((stream, handshake, transport))
        })
        .await
        .ok()
        .flatten()
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "metadata connection assembly keeps identity, transport and lifecycle ownership explicit"
    )]
    pub async fn connect(
        &self,
        address: SocketAddr,
        hash: &[u8; 20],
        peer_id: &[u8; 20],
        reserved: Reserved,
        policy: PeerConnectionType,
        punch: bool,
        urgent: bool,
        token: &CancellationToken,
    ) -> Option<(Stream, Handshake, Transport)> {
        // Bound process-wide half-open pressure independently of live peers.
        static DIALS: std::sync::OnceLock<Arc<Semaphore>> = std::sync::OnceLock::new();
        static URGENT: std::sync::OnceLock<Arc<Semaphore>> = std::sync::OnceLock::new();
        let permits = if urgent {
            URGENT.get_or_init(|| Arc::new(Semaphore::new(8)))
        } else {
            DIALS.get_or_init(|| Arc::new(Semaphore::new(64)))
        };
        let _permit = tokio::select! { _ = token.cancelled() => return None, permit = permits.acquire() => permit.ok()? };
        let run = async {
            if punch {
                for _ in 0..3 {
                    if let Some(result) = self
                        .attempt(
                            address,
                            hash,
                            peer_id,
                            reserved,
                            Transport::Utp,
                            Duration::from_secs(3),
                        )
                        .await
                    {
                        return Some(result);
                    }
                }
                return None;
            }
            let plan = taiji_bt::utp::dial_plan(policy);
            let budget = Duration::from_secs(8);
            let preferred = self.attempt(address, hash, peer_id, reserved, plan[0]?, budget);
            if let Some(fallback) = plan[1] {
                race_transports(
                    preferred,
                    self.attempt(address, hash, peer_id, reserved, fallback, budget),
                    Duration::from_millis(250),
                )
                .await
            } else {
                preferred.await
            }
        };
        tokio::select! { _ = token.cancelled() => None, result = run => result }
    }
}

/// Launch the fallback after a short head start, or immediately on failure.
/// Dropping the losing future closes its TCP/uTP stream and handshake.
async fn race_transports<T>(
    first: impl std::future::Future<Output = Option<T>>,
    second: impl std::future::Future<Output = Option<T>>,
    delay: Duration,
) -> Option<T> {
    tokio::pin!(first);
    tokio::pin!(second);
    tokio::select! {
        result = &mut first => { return match result { Some(value) => Some(value), None => second.await }; }
        _ = tokio::time::sleep(delay) => {}
    }
    tokio::select! {
        result = &mut first => match result { Some(value) => Some(value), None => second.await },
        result = &mut second => match result { Some(value) => Some(value), None => first.await },
    }
}

pub(super) type Candidates = Arc<std::sync::Mutex<Vec<([u8; 20], Reserved, [u8; 20])>>>;

pub(super) struct Network {
    pub dialer: Arc<Dialer>,
    pub incoming: mpsc::Receiver<Incoming>,
    pub dht: Option<(mpsc::Receiver<udp_demux::InboundPacket>, UdpDemuxHandle)>,
    pub dht6: Option<(mpsc::Receiver<udp_demux::InboundPacket>, UdpDemuxHandle)>,
    pub candidates: Candidates,
    pub _registration: Option<super::services::Subscription>,
    token: CancellationToken,
}

impl Drop for Network {
    fn drop(&mut self) {
        self.token.cancel();
    }
}

impl Network {
    pub fn cancellation(&self) -> CancellationToken {
        self.token.clone()
    }

    pub fn release_registration(&mut self) {
        self._registration.take();
    }

    pub fn lease(
        dialer: Arc<Dialer>,
        incoming: mpsc::Receiver<Incoming>,
        registration: super::services::Subscription,
        parent: &CancellationToken,
    ) -> Self {
        Self {
            dialer,
            incoming,
            dht: None,
            dht6: None,
            candidates: Arc::new(std::sync::Mutex::new(Vec::new())),
            _registration: Some(registration),
            token: parent.child_token(),
        }
    }
    pub async fn bind(
        requested: u16,
        peer_id: [u8; 20],
        candidates: Vec<([u8; 20], Reserved)>,
        nat: Option<NatEngine>,
        parent: &CancellationToken,
    ) -> Result<Self, String> {
        let token = parent.child_token();
        let mut bound = None;
        let count = if requested == 0 { 1 } else { 119 };
        for offset in 0..count {
            let port = requested.saturating_add(offset);
            let Ok(tcp) = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).await else {
                continue;
            };
            let port = tcp.local_addr().map_err(|e| e.to_string())?.port();
            match udp_demux::spawn(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                DemuxConfig {
                    port,
                    ..Default::default()
                },
                token.clone(),
            )
            .await
            {
                Ok((channels, demux)) => {
                    bound = Some((tcp, port, channels, demux));
                    break;
                }
                Err(_) => continue,
            }
        }
        let Some((tcp, port, channels, demux)) = bound else {
            return Err("metadata peer listener could not bind TCP and UDP".into());
        };
        if let Some(nat) = &nat {
            // External mapping ownership is asynchronous. A slow router cannot
            // block peer discovery; its watch still publishes a later result.
            let _ = tokio::time::timeout(Duration::from_secs(2), nat.map_listen_port(port)).await;
        }
        let (tx, incoming) = mpsc::channel(64);
        let permits = Arc::new(Semaphore::new(64));
        let candidates: Candidates = Arc::new(std::sync::Mutex::new(
            candidates
                .into_iter()
                .map(|(hash, flags)| (hash, flags, peer_id))
                .collect(),
        ));
        tcp_accept(
            tcp,
            tx.clone(),
            permits.clone(),
            candidates.clone(),
            peer_id,
            token.clone(),
        );
        let DemuxChannels { dht, tracker, utp } = channels;
        drop(tracker);
        let (listener, _) = taiji_io::utp::listener::spawn_utp(
            utp,
            demux.clone(),
            UtpConfig::default(),
            token.clone(),
        );
        let v4 = listener.connect_half();
        utp_accept(
            listener,
            tx.clone(),
            permits.clone(),
            candidates.clone(),
            peer_id,
            token.clone(),
        );
        let mut v6 = None;
        let mut dht6 = None;
        if let Ok((channels6, demux6)) = udp_demux::spawn(
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            DemuxConfig {
                port,
                ..Default::default()
            },
            token.clone(),
        )
        .await
        {
            dht6 = Some((channels6.dht, demux6.clone()));
            drop(channels6.tracker);
            let (listener, _) = taiji_io::utp::listener::spawn_utp(
                channels6.utp,
                demux6,
                UtpConfig::default(),
                token.clone(),
            );
            v6 = Some(listener.connect_half());
            utp_accept(
                listener,
                tx.clone(),
                permits.clone(),
                candidates.clone(),
                peer_id,
                token.clone(),
            );
            if let Ok(tcp6) = TcpListener::bind((Ipv6Addr::UNSPECIFIED, port)).await {
                tcp_accept(
                    tcp6,
                    tx,
                    permits,
                    candidates.clone(),
                    peer_id,
                    token.clone(),
                );
            }
        }
        Ok(Self {
            dialer: Arc::new(Dialer { port, nat, v4, v6 }),
            incoming,
            dht: Some((dht, demux)),
            dht6,
            candidates,
            _registration: None,
            token,
        })
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "metadata connection assembly keeps identity, transport and lifecycle ownership explicit"
)]
fn accept_one(
    stream: Stream,
    address: SocketAddr,
    transport: Transport,
    tx: mpsc::Sender<Incoming>,
    permits: Arc<Semaphore>,
    candidates: Candidates,
    _peer_id: [u8; 20],
    token: CancellationToken,
) {
    let Some(address) = crate::engine::addr_hygiene::sanitize_discovered_addr(address) else {
        return;
    };
    let Ok(permit) = permits.try_acquire_owned() else {
        return;
    };
    tokio::spawn(async move {
        let _permit = permit;
        let accept = async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut stream = stream;
            let mut bytes = [0; taiji_bt::peer_wire::HANDSHAKE_LEN];
            stream.read_exact(&mut bytes).await.ok()?;
            let handshake = Handshake::decode(&bytes).ok()?;
            let candidate = crate::lock(&candidates)
                .iter()
                .enumerate()
                .find(|(_, (hash, _, _))| *hash == handshake.info_hash)
                .map(|(face, (_, flags, own_id))| (face, *flags, *own_id));
            let (face, reserved, own_id) = candidate?;
            if handshake.peer_id == own_id {
                return None;
            }
            stream
                .write_all(
                    &Handshake {
                        reserved,
                        info_hash: handshake.info_hash,
                        peer_id: own_id,
                    }
                    .encode(),
                )
                .await
                .ok()?;
            stream.flush().await.ok()?;
            Some((stream, face, handshake))
        };
        let result = tokio::select! {
            _ = token.cancelled() => return,
            result = tokio::time::timeout(Duration::from_secs(10),accept) => result.ok().flatten(),
        };
        if let Some((stream, face, handshake)) = result {
            tokio::select! {
                _ = token.cancelled() => {},
                _ = tx.send(Incoming { stream, address, face, transport, handshake }) => {},
            }
        }
    });
}

fn tcp_accept(
    listener: TcpListener,
    tx: mpsc::Sender<Incoming>,
    permits: Arc<Semaphore>,
    candidates: Candidates,
    peer_id: [u8; 20],
    token: CancellationToken,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                accepted = listener.accept() => match accepted {
                    Ok((stream, address)) => {
                        let _=stream.set_nodelay(true);
                        accept_one(Box::new(stream), address, Transport::Tcp, tx.clone(), permits.clone(), candidates.clone(), peer_id, token.clone());
                    },
                    Err(_) => break,
                }
            }
        }
    });
}

fn utp_accept(
    mut listener: taiji_io::utp::UtpListenerHandle,
    tx: mpsc::Sender<Incoming>,
    permits: Arc<Semaphore>,
    candidates: Candidates,
    peer_id: [u8; 20],
    token: CancellationToken,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                accepted = listener.accept_from() => match accepted {
                    Some((address, stream)) => accept_one(Box::new(stream), address, Transport::Utp, tx.clone(), permits.clone(), candidates.clone(), peer_id, token.clone()),
                    None => break,
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn transport_race_does_not_wait_for_a_stalled_preference() {
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            race_transports(
                std::future::pending::<Option<u8>>(),
                async { Some(2) },
                Duration::from_millis(10),
            ),
        )
        .await;
        assert_eq!(result.unwrap_or_else(|e| panic!("{e}")), Some(2));
        assert_eq!(
            race_transports(async { None }, async { Some(3) }, Duration::from_secs(10)).await,
            Some(3)
        );
        assert_eq!(
            race_transports(
                async { Some(1) },
                std::future::pending::<Option<u8>>(),
                Duration::from_secs(1)
            )
            .await,
            Some(1)
        );
    }
}
