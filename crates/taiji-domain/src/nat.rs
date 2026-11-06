//! NAT assembly.
//!
//! Responsibilities:
//! - Supervisor for the single-instance [`taiji_io::nat`] NatActor;
//! - Engine consumption surface [`NatEngine`]: Map (TCP+UDP) is triggered
//! once the listen port is decided; the `NatEvent::Mapped` external port
//! is published through a watch so the announce port can follow;
//! - Engine wiring: `EngineConfig::nat` (None = no change); an external
//! port change re-triggers DHT announce registration inside the engine.
//!
//! Consumers:
//! - DHT: on external port change the engine re-sends announce registration
//! with the new port (`spawn_dht_announces`; the DHT engine keeps sending
//! from the registry with the new port) — wired inside the engine.
//! - Tracker: at tracker actor spawn, [`resolve_announce_port`] reads the
//! snapshot and injects `TrackerActorConfig::listen_port` (the mapped
//! external port if present; otherwise the actual local port). The
//! actor's listen_port is a spawn-time constant, so external port changes
//! after spawn are not followed. libtorrent instead reads
//! `tcp_external_port` fresh for every announce it constructs
//! (`session_impl.cpp`); dynamic re-porting would need a bt-seam
//! extension. Under common gateways the external port equals the
//! requested port and is stable for the session, so the snapshot is the
//! final value.
//! - LSD: activation uses the same [`resolve_announce_port`] snapshot; on
//! external port change the session main loop's watch arm refreshes the
//! bt::lsd port slot (existing entries only change the port, timers are
//! untouched), taking effect on the next natural announce cycle (no extra
//! announce cadence; see the session actor `run()`).
//!
//! Full-stack protocol behavior (map/renew/conflict/offline paths, packet
//! vectors, timer tables) is locked by `taiji-io::nat` tests (the io leaf
//! crate carries its own mock server); this module's tests lock the watch
//! snapshot pure functions and the supervisor lifecycle.

use std::time::Duration;

use taiji_io::nat::{self, NatConfig, NatError, NatEvent, NatHandle, NatProtocol};
use tokio::sync::watch;
use tracing::{debug, info};

/// External port snapshot (watch state; one slot per protocol).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExternalPorts {
    /// TCP mapping's external port.
    pub tcp: Option<u16>,
    /// UDP mapping's external port.
    pub udp: Option<u16>,
}

impl ExternalPorts {
    /// Announce port policy (local policy; no spec-anchored value): if TCP
    /// and UDP map to the same port (common gateway behavior) use it; on
    /// mismatch prefer TCP (the BT data plane rides mainly on inbound TCP);
    /// if unmapped, fall back to the local listen port.
    pub fn effective(&self, local: u16) -> u16 {
        match (self.tcp, self.udp) {
            (Some(t), Some(u)) if t == u => t,
            (Some(t), _) => t,
            (None, Some(u)) => u,
            (None, None) => local,
        }
    }
}

/// Single entry point for the announce-reported port (shared by the
/// tracker/LSD consumers): when NAT mapping is up and a watch snapshot is
/// present, [`ExternalPorts::effective`] (TCP mapping preferred); with no
/// mapping (None) or no power, `local` (status quo, zero behavior change).
///
/// Authority anchor: libtorrent's announce port is the `announce_port`
/// setting (user override), else the listen socket's TCP external port
/// (`tcp_external_port` in `session_impl.cpp`). The `local` argument here
/// is the caller's current local port (tracker = actual_port, LSD = the
/// --listen-port option).
pub fn resolve_announce_port(external: Option<ExternalPorts>, local: u16) -> u16 {
    external.map_or(local, |p| p.effective(local))
}

/// Engine-side NAT consumption surface (Clone; injected via
/// `EngineConfig::nat`).
#[derive(Clone)]
pub struct NatEngine {
    handle: NatHandle,
    external_rx: watch::Receiver<ExternalPorts>,
    lease: Duration,
}

impl NatEngine {
    /// Triggers Map for the listen port (TCP+UDP).
    pub async fn map_listen_port(&self, port: u16) -> Result<(), NatError> {
        self.handle.map(port, self.lease).await
    }

    /// Current external port snapshot.
    pub fn external_ports(&self) -> ExternalPorts {
        *self.external_rx.borrow()
    }

    /// Subscribes to external port changes (the consumer interface; see the
    /// module docs).
    pub fn subscribe_external_ports(&self) -> watch::Receiver<ExternalPorts> {
        self.external_rx.clone()
    }

    /// Revokes the mapping (engine shutdown path). If never called, the
    /// actor best-effort unmaps when the handle drops; lease expiry (3600s)
    /// reclamation on the gateway side is the backstop.
    pub async fn unmap(&self) -> Result<(), NatError> {
        self.handle.unmap().await
    }
}

/// Single-instance supervisor (one NatActor per process; core assembly
/// entry point).
pub struct NatSupervisor {
    engine: NatEngine,
    pump: tokio::task::JoinHandle<()>,
}

impl NatSupervisor {
    /// Engine consumption surface (each call clones the same actor's
    /// handle and watch).
    pub fn engine(&self) -> NatEngine {
        self.engine.clone()
    }

    /// Shutdown: unmap plus stop the event pump (the NatActor finalizes and
    /// exits when its handle drops).
    pub async fn shutdown(self) {
        let _ = self.engine.unmap().await;
        self.pump.abort();
    }
}

/// Assembles the single-instance NAT surface (events-to-watch pump).
pub fn spawn_supervisor(config: NatConfig) -> NatSupervisor {
    let lease = config.lease;
    let (handle, mut events, actor_join) = nat::spawn(config);
    let (tx, rx) = watch::channel(ExternalPorts::default());
    // Event pump: Mapped updates the watch slot; Failed only logs (the
    // watch keeps the last known external port — the mapping may still be
    // valid on the gateway side; the authoritative state is the actor
    // Snapshot).
    let join = tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            match event {
                NatEvent::Mapped {
                    protocol,
                    external_port,
                } => {
                    info!(
                        target: "taiji::core::nat", %protocol, external_port,
                        "nat mapped"
                    );
                    tx.send_modify(|ports| match protocol {
                        NatProtocol::Tcp => ports.tcp = Some(external_port),
                        NatProtocol::Udp => ports.udp = Some(external_port),
                    });
                }
                NatEvent::Failed { reason } => {
                    debug!(target: "taiji::core::nat", %reason, "nat failed (degraded)");
                }
                // Forward-compat: unknown future variants are logged and
                // ignored (the watch keeps the last known external port).
                _ => {
                    debug!(target: "taiji::core::nat", "unhandled nat event");
                }
            }
        }
    });
    // The actor task handle is entrusted to a pump task (reclaimed when the
    // pump exits).
    tokio::spawn(async move {
        let _ = actor_join.await;
    });
    NatSupervisor {
        engine: NatEngine {
            handle,
            external_rx: rx,
            lease,
        },
        pump: join,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Locks the announce port policy table (the module-doc local policy).
    #[test]
    fn effective_port_resolution_table() {
        let local = 6881;
        // Unmapped: local port.
        assert_eq!(ExternalPorts::default().effective(local), local);
        // Both protocols map to the same port (common gateways).
        assert_eq!(
            ExternalPorts {
                tcp: Some(6881),
                udp: Some(6881)
            }
            .effective(local),
            6881
        );
        // Gateway grants a different port (conflict path): report what was
        // actually granted.
        assert_eq!(
            ExternalPorts {
                tcp: Some(40001),
                udp: Some(40001)
            }
            .effective(local),
            40001
        );
        // Mismatch: TCP preferred (data-plane policy).
        assert_eq!(
            ExternalPorts {
                tcp: Some(40001),
                udp: Some(40002)
            }
            .effective(local),
            40001
        );
        // Single-protocol mapping.
        assert_eq!(
            ExternalPorts {
                tcp: None,
                udp: Some(40003)
            }
            .effective(local),
            40003
        );
    }

    /// Three-state behavior of announce port resolution against the watch
    /// snapshot. The read pattern matches the consumer points verbatim
    /// (`external_ports()` = `*external_rx.borrow()` fed to
    /// [`resolve_announce_port`]): (1) no mapping / no power: falls back to
    /// the local port (status quo, zero behavior change); (2) mapped (the
    /// gateway grants a different port): announce reports the external
    /// port; (3) mapping change: the next read follows (announce consumers
    /// pick up the new port on their next snapshot read).
    #[test]
    fn announce_port_follows_watch_snapshot_three_states() {
        let local = 6881;
        let (tx, rx) = watch::channel(ExternalPorts::default());
        // Consumer read pattern: watch borrow (same shape as
        // NatEngine::external_ports).
        let resolve = || resolve_announce_port(Some(*rx.borrow()), local);
        // (1) No mapping: falls back to actual_port; the None (no power)
        // form resolves the same.
        assert_eq!(
            resolve(),
            local,
            "no mapping falls back to the current port (zero behavior change)"
        );
        assert_eq!(
            resolve_announce_port(None, local),
            local,
            "no-power form resolves the same"
        );
        // (2) Mapped (conflict grant 40001): announce reports the external
        // port.
        tx.send_modify(|p| {
            p.tcp = Some(40001);
            p.udp = Some(40001);
        });
        assert_eq!(resolve(), 40001, "mapped -> report the external port");
        // (3) Mapping change: the next announce read follows.
        tx.send_modify(|p| p.tcp = Some(40002));
        assert_eq!(resolve(), 40002, "mapping change -> next read follows");
        // UDP-only mapping follows the same way (existing effective
        // policy).
        tx.send_modify(|p| {
            p.tcp = None;
            p.udp = Some(40003);
        });
        assert_eq!(resolve(), 40003, "single-protocol mapping follows the same");
    }

    /// Supervisor lifecycle: an unreachable gateway degrades without
    /// panic; the watch keeps defaults; shutdown returns cleanly.
    #[tokio::test]
    async fn supervisor_survives_unreachable_gateway() {
        let supervisor = spawn_supervisor(NatConfig {
            gateway: Some(std::net::Ipv4Addr::LOCALHOST),
            natpmp_port: 1, // reserved port, guaranteed unreachable
            enable_upnp: false,
            enable_natpmp: true,
            retransmit_schedule: vec![Duration::from_millis(5)],
            ..NatConfig::default()
        });
        let engine = supervisor.engine();
        // Port 1 is unreachable: Map fails (error surfaced as NatError),
        // no panic.
        assert!(engine.map_listen_port(6881).await.is_err());
        assert_eq!(engine.external_ports(), ExternalPorts::default());
        supervisor.shutdown().await;
    }
}
