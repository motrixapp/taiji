//! DhtEngine spawn side and command handle (split out of engine.rs; pure
//! move).
//!
//! Owns: the `spawn` assembly entry (the core wiring point), the
//! `DhtHandle` command handle, and `forward_outbound` bridging (engine
//! outbound channel -> demux single writer).
//! Does not own: the command/event type definitions (see `contract`) and
//! the actor state machine (see `state` and the responsibility modules).

use std::net::{IpAddr, SocketAddr};

use taiji_io::udp_demux::{OutboundPacket, UdpDemuxHandle};
use tokio::sync::{mpsc, oneshot};

use super::*;

/// Bridge the engine outbound channel into the demux single-writer handle
/// (the core wiring point; exits when the channel closes).
pub fn forward_outbound(
    mut rx: mpsc::Receiver<OutboundPacket>,
    demux: UdpDemuxHandle,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(pkt) = rx.recv().await {
            let _ = demux.send_packet(pkt.to, pkt.data).await;
        }
    })
}

/// Assemble and spawn a DhtEngine (the core wiring point: once per
/// family; returns the command handle + task handle. The event channel is
/// created and consumed by the caller).
pub fn spawn(
    family: persist::DhtFamily,
    dht_port: u16,
    cfg: DhtEngineConfig,
    transport: DhtTransport,
    restore: Option<DhtRestoreState>,
    event_tx: mpsc::Sender<DhtEvent>,
) -> (DhtHandle, tokio::task::JoinHandle<()>) {
    let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
    let engine = DhtEngine::new(family, dht_port, cfg, transport, restore, event_tx, cmd_rx);
    let handle = DhtHandle { cmd_tx, dht_port };
    let join = tokio::spawn(engine.run());
    (handle, join)
}

/// Engine command handle (cheap to clone). `dht_port()` lets the peer
/// layer send the PORT message after handshake
/// (`DefaultBtInteractive.cc`).
#[derive(Clone)]
pub struct DhtHandle {
    cmd_tx: mpsc::Sender<DhtCommand>,
    dht_port: u16,
}

impl DhtHandle {
    pub async fn set_enabled(&self, enabled: bool) -> Result<(), DhtEngineError> {
        self.call(|reply| DhtCommand::SetEnabled { enabled, reply })
            .await
    }

    /// Our DHT UDP port (the PORT message payload).
    pub fn dht_port(&self) -> u16 {
        self.dht_port
    }

    async fn call<R>(
        &self,
        make: impl FnOnce(oneshot::Sender<R>) -> DhtCommand,
    ) -> Result<R, DhtEngineError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(make(tx))
            .await
            .map_err(|_| DhtEngineError::Closed)?;
        rx.await.map_err(|_| DhtEngineError::Closed)
    }

    /// Announce (register + immediate peer lookup; discoveries come back
    /// as events).
    pub async fn announce(&self, target: DhtTarget, port: u16) -> Result<(), DhtEngineError> {
        self.call(|reply| DhtCommand::Announce {
            target,
            port,
            reply,
        })
        .await?
    }

    pub async fn withdraw(&self, target: DhtTarget) -> Result<(), DhtEngineError> {
        self.cmd_tx
            .send(DhtCommand::Withdraw { target })
            .await
            .map_err(|_| DhtEngineError::Closed)
    }

    /// get_peers iteration only.
    pub async fn get_peers(&self, target: DhtTarget) -> Result<(), DhtEngineError> {
        self.call(|reply| DhtCommand::GetPeers { target, reply })
            .await?
    }

    /// Bootstrap; the reply is the number of successfully pinged entries.
    pub async fn bootstrap(&self, entry_points: Vec<SocketAddr>) -> Result<usize, DhtEngineError> {
        self.call(|reply| DhtCommand::Bootstrap {
            entry_points,
            reply,
        })
        .await
    }

    /// Feed the PORT message receive side (peer layer after receiving
    /// Port{id=9}).
    pub async fn add_port_node(&self, ip: IpAddr, dht_port: u16) -> Result<(), DhtEngineError> {
        // No reply for this command (fire-and-forget: failures are only
        // logged, BtPortMessage semantics).
        self.cmd_tx
            .send(DhtCommand::AddPortNode { ip, dht_port })
            .await
            .map_err(|_| DhtEngineError::Closed)
    }

    /// BEP42 external address delivery (fire-and-forget): the engine
    /// re-derives node_id per libtorrent update_node_id semantics (the
    /// current id is kept if it still verifies). The session startup probe
    /// and later IP changes both arrive through this face.
    pub async fn set_external_ip(&self, ip: IpAddr) -> Result<(), DhtEngineError> {
        self.cmd_tx
            .send(DhtCommand::SetExternalIp { ip })
            .await
            .map_err(|_| DhtEngineError::Closed)
    }

    /// Runtime snapshot.
    pub async fn snapshot(&self) -> Result<DhtSnapshot, DhtEngineError> {
        self.call(|reply| DhtCommand::Snapshot { reply }).await
    }

    /// Save and stop the actor (await the join handle separately).
    pub async fn shutdown(&self) -> Result<(), DhtEngineError> {
        self.call(|reply| DhtCommand::Shutdown { reply }).await
    }
}
