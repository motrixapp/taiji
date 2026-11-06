//! NAT port mapping (SPEC §6.8).
//!
//! Submodules: [`natpmp`] (NAT-PMP per RFC 6886, hand-rolled packet codec +
//! client) and [`igd`] (UPnP IGD via the rupnp crate: SSDP discovery and
//! WAN{IP,PPP}Connection actions). This file hosts the single-instance
//! [`NatActor`]: the Map/Renew/Unmap/Snapshot command surface, protocol
//! selection, the 60-minute renewal cadence, failure backoff, and epoch
//! state-loss response.
//!
//! Hard invariants: command/event channels frozen at capacity 16; lease 0
//! never reaches the wire on either protocol (NAT-PMP lifetime 0 = delete,
//! IGD lease 0 = permanent); a success reply with external port 0 fails the
//! round; a too-small granted lifetime falls back to the requested value;
//! epoch regressions inside a short window poison NAT-PMP for the session.
//!
//! Upstream anchor mapping: docs/design/io.md

pub mod igd;
pub mod natpmp;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
// Actor timers all use the tokio clock (paused-time tests can advance it
// deterministically; std Instant only serves as its own baseline inside
// [`natpmp::EpochTracker`] and is never mixed in).
use tokio::time::Instant;

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use natpmp::{EpochTracker, NatPmpClient, Protocol, Reply, Request};

/// Command channel capacity (frozen at 16; do not change).
pub const COMMAND_CHANNEL_CAPACITY: usize = 16;
/// Event channel capacity (same).
pub const EVENT_CHANNEL_CAPACITY: usize = 16;

/// Default mapping lease (3600s; IGD spec §2.5.16.3 RECOMMENDS <=3600;
/// NAT-PMP see [`natpmp::REQUESTED_LEASE_SECS`]).
pub const DEFAULT_LEASE: Duration = Duration::from_secs(3600);
/// External address poll period (local policy, not spec-anchored; see the
/// "external IP change response" section in docs/design/io.md).
pub const DEFAULT_ADDRESS_POLL: Duration = Duration::from_secs(10 * 60);
/// SSDP search window (local policy; ssdp-client responses are randomly
/// delayed within MX and the window must cover them — this value is the
/// rupnp `discover(timeout, ..)` timeout).
pub const DEFAULT_SSDP_TIMEOUT: Duration = Duration::from_secs(3);

/// Mapping protocol (re-export of [`natpmp::Protocol`]).
pub use natpmp::Protocol as NatProtocol;

/// NAT backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// NAT-PMP (RFC 6886).
    NatPmp,
    /// UPnP IGD (WANIPConnection/WANPPPConnection).
    Igd,
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Backend::NatPmp => f.write_str("nat-pmp"),
            Backend::Igd => f.write_str("upnp-igd"),
        }
    }
}

/// Actor configuration (mock tests inject loopback endpoints per field;
/// production uses `Default`).
#[derive(Debug, Clone)]
pub struct NatConfig {
    /// Explicit NAT-PMP gateway (None = derive from IGD discovery; if that
    /// fails, NAT-PMP is skipped — see "protocol selection" in
    /// docs/design/io.md).
    pub gateway: Option<Ipv4Addr>,
    /// NAT-PMP server port (default 5351 per RFC 6886 §3.1; mock tests
    /// override it).
    pub natpmp_port: u16,
    /// Enable NAT-PMP.
    pub enable_natpmp: bool,
    /// Enable UPnP IGD.
    pub enable_upnp: bool,
    /// Direct IGD device-description URL (None = SSDP discovery; for mock
    /// tests and deployment overrides).
    pub igd_device_url: Option<String>,
    /// SSDP search window.
    pub ssdp_timeout: Duration,
    /// Requested lease (same for both protocols; overridable per Map
    /// command).
    pub lease: Duration,
    /// External address poll period.
    pub address_poll: Duration,
    /// NAT-PMP request retransmission schedule (default RFC 6886 §3.1;
    /// shortened in tests).
    pub retransmit_schedule: Vec<Duration>,
    /// Delete-request retransmission schedule (§3.1: deletes are advisory
    /// and may retry fewer than 9 times).
    pub unmap_schedule: Vec<Duration>,
    /// Jitter injection for the post-regression recreate (test seam; ZERO
    /// (default) = production semantics, the uniform-random 0-5s of §3.7
    /// via [`natpmp::reboot_recreate_delay`]; non-zero = a fixed jitter so
    /// tests advance the recreate cadence deterministically — no production
    /// semantics change; sole consumer [`NatActor::observe_pmp_reply`]).
    pub recreate_jitter: Duration,
}

impl Default for NatConfig {
    fn default() -> Self {
        NatConfig {
            gateway: None,
            natpmp_port: natpmp::SERVER_PORT,
            enable_natpmp: true,
            enable_upnp: true,
            igd_device_url: None,
            ssdp_timeout: DEFAULT_SSDP_TIMEOUT,
            lease: DEFAULT_LEASE,
            address_poll: DEFAULT_ADDRESS_POLL,
            retransmit_schedule: natpmp::RETRANSMIT_SCHEDULE.to_vec(),
            unmap_schedule: vec![Duration::from_millis(250), Duration::from_millis(500)],
            recreate_jitter: Duration::ZERO,
        }
    }
}

/// Command surface (mpsc(16); oneshot replies).
#[derive(Debug)]
pub enum NatCommand {
    /// Map or update a mapping (lease == 0 is treated as
    /// [`DEFAULT_LEASE`] — 0 is dangerous in both protocols: NAT-PMP
    /// lifetime 0 = delete (RFC 6886 §3.4), IGD lease 0 = permanent
    /// (§2.5.16.2); the command layer never forwards it).
    Map {
        /// Mapping protocol.
        protocol: Protocol,
        /// Local listening port.
        port: u16,
        /// Requested lease.
        lease: Duration,
        /// Reply: the mapping state once this command is processed.
        reply: oneshot::Sender<Result<(), NatError>>,
    },
    /// Renew all active mappings immediately.
    Renew {
        /// Reply.
        reply: oneshot::Sender<Result<(), NatError>>,
    },
    /// Unmap everything this actor created (best effort: deletes are
    /// advisory per RFC 6886 §3.1; the gateway also reclaims leases on
    /// expiry).
    Unmap {
        /// Reply.
        reply: oneshot::Sender<Result<(), NatError>>,
    },
    /// Runtime snapshot.
    Snapshot {
        /// Reply.
        reply: oneshot::Sender<NatSnapshot>,
    },
}

/// Event surface (mpsc(16)).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NatEvent {
    /// A mapping was established or its external port changed (one event
    /// per protocol; consumers feed (protocol, external_port) into the
    /// announce port selection).
    Mapped {
        /// Mapping protocol.
        protocol: Protocol,
        /// External port actually assigned by the gateway.
        external_port: u16,
    },
    /// Mapping failed or was lost (emitted once on entering the failed
    /// state, reset on recovery; `reason` is a human-readable diagnostic).
    Failed {
        /// Failure reason.
        reason: String,
    },
}

/// Actor-level error (normalized across backends).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NatError {
    /// NAT-PMP errors.
    #[error(transparent)]
    NatPmp(#[from] natpmp::NatPmpError),
    /// IGD errors.
    #[error(transparent)]
    Igd(#[from] igd::IgdError),
    /// Local socket errors.
    #[error("nat: {0}")]
    Io(#[from] std::io::Error),
    /// No usable backend (both protocols disabled or discovery failed).
    #[error("nat: no usable backend (nat-pmp and/or upnp-igd discovery failed)")]
    NoBackend,
    /// Invalid command arguments.
    #[error("nat: {0}")]
    InvalidArgs(String),
    /// Actor channel closed.
    #[error("nat: actor closed")]
    Closed,
}

/// Runtime snapshot (reply to the `Snapshot` command).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NatSnapshot {
    /// Active backend (None = no mapping has succeeded yet).
    pub backend: Option<Backend>,
    /// Gateway external address (from address requests/polling; None =
    /// unknown).
    pub external_address: Option<Ipv4Addr>,
    /// Active mappings (one per protocol).
    pub mappings: Vec<MappingView>,
    /// Degraded (the last mapping round failed; retrying with backoff).
    pub degraded: bool,
    /// Most recent failure reason.
    pub last_error: Option<String>,
}

/// View of a single mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingView {
    /// Mapping protocol.
    pub protocol: Protocol,
    /// Local listening port.
    pub internal_port: u16,
    /// External port assigned by the gateway.
    pub external_port: u16,
    /// Granted lease in seconds (0 = permanent mapping).
    pub granted_lease_secs: u32,
}

/// Command sender handle (Clone; once all handles drop, the actor exits
/// and best-effort unmaps).
#[derive(Debug, Clone)]
pub struct NatHandle {
    cmd: mpsc::Sender<NatCommand>,
}

impl NatHandle {
    /// Map the port on both TCP and UDP.
    ///
    /// Each protocol is attempted independently: one protocol failing does
    /// not short-circuit — both Map commands are recorded by the actor
    /// (wanted is always entered, so backoff retries can reach it), and the
    /// first error is returned. (An earlier implementation returned on TCP
    /// failure via `?`, so UDP never entered wanted and was never retried;
    /// a gateway that fails only TCP could silently strip the UDP mapping.)
    pub async fn map(&self, port: u16, lease: Duration) -> Result<(), NatError> {
        let mut first_err: Option<NatError> = None;
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            if let Err(e) = self.map_one(protocol, port, lease).await {
                first_err.get_or_insert(e);
            }
        }
        first_err.map_or(Ok(()), Err)
    }

    /// Map a single protocol.
    pub async fn map_one(
        &self,
        protocol: Protocol,
        port: u16,
        lease: Duration,
    ) -> Result<(), NatError> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(NatCommand::Map {
                protocol,
                port,
                lease,
                reply: tx,
            })
            .await
            .map_err(|_| NatError::Closed)?;
        rx.await.map_err(|_| NatError::Closed)?
    }

    /// Renew immediately.
    pub async fn renew(&self) -> Result<(), NatError> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(NatCommand::Renew { reply: tx })
            .await
            .map_err(|_| NatError::Closed)?;
        rx.await.map_err(|_| NatError::Closed)?
    }

    /// Unmap everything.
    pub async fn unmap(&self) -> Result<(), NatError> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(NatCommand::Unmap { reply: tx })
            .await
            .map_err(|_| NatError::Closed)?;
        rx.await.map_err(|_| NatError::Closed)?
    }

    /// Snapshot.
    pub async fn snapshot(&self) -> Result<NatSnapshot, NatError> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(NatCommand::Snapshot { reply: tx })
            .await
            .map_err(|_| NatError::Closed)?;
        rx.await.map_err(|_| NatError::Closed)
    }
}

/// Spawn the single [`NatActor`] instance (SPEC §3.2 single instance; the
/// assembly entry point for taiji-core).
///
/// Returns (handle, event receiver, task join handle). The event consumer
/// must keep calling `recv` (drop-on-full policy: see [`NatEvent`] and
/// docs/design/io.md).
pub fn spawn(
    config: NatConfig,
) -> (
    NatHandle,
    mpsc::Receiver<NatEvent>,
    tokio::task::JoinHandle<()>,
) {
    let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
    let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
    let actor = NatActor::new(config, cmd_rx, event_tx);
    let join = tokio::spawn(actor.run());
    (NatHandle { cmd: cmd_tx }, event_rx, join)
}

/// Kind of the next timer action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tick {
    /// Retry the mapping round for missing protocols after backoff.
    Retry,
    /// Renewal due.
    Renew,
    /// External address poll.
    PollAddress,
    /// Post-regression recreate after jitter (RFC 6886 §3.7).
    Recreate,
}

/// Active mapping (actor-internal state).
struct ActiveMapping {
    protocol: Protocol,
    internal_port: u16,
    external_port: u16,
    /// Granted lease; None = permanent (IGD lease=0 readback).
    granted: Option<Duration>,
    /// Next renewal time (None = permanent).
    renew_at: Option<Instant>,
}

/// Desired mapping (the wanted set).
#[derive(Debug, Clone, Copy)]
struct WantedMapping {
    internal_port: u16,
    lease_secs: u32,
    /// Suggested external port: first creation = internal port (RFC 6886
    /// §3.3 "The client normally requests the external port matching the
    /// internal port"); recreate/renew = the already-assigned value.
    suggested_external: u16,
}

/// Single-instance NAT actor (SPEC §3.2).
struct NatActor {
    config: NatConfig,
    cmd_rx: mpsc::Receiver<NatCommand>,
    event_tx: mpsc::Sender<NatEvent>,
    /// Active backend.
    backend: Option<Backend>,
    /// NAT-PMP client (created once the gateway is known; (gateway, client)).
    pmp: Option<(Ipv4Addr, NatPmpClient)>,
    /// IGD client (cached after successful discovery).
    igd: Option<igd::IgdClient>,
    /// Internal client address for IGD (AddPortMapping NewInternalClient).
    internal_client: Option<Ipv4Addr>,
    /// Active mappings.
    active: HashMap<Protocol, ActiveMapping>,
    /// Desired mappings.
    wanted: HashMap<Protocol, WantedMapping>,
    /// External address.
    external_address: Option<Ipv4Addr>,
    /// RFC 6886 §3.6 epoch tracking.
    epoch: EpochTracker,
    /// Consecutive failed full rounds (indexes the backoff table).
    failed_rounds: u32,
    /// Degraded state (Failed event sent, not yet recovered).
    degraded: bool,
    last_error: Option<String>,
    /// Next timer deadline (recomputed by schedule_next).
    next: Option<(Instant, Tick)>,
    /// Next address-poll time.
    poll_at: Option<Instant>,
    /// Recreate time after an epoch regression (post §3.7 jitter).
    recreate_at: Option<Instant>,
    /// NAT-PMP gateway derived from IGD (decoupled from `config.gateway`):
    /// the derived value is revocable along with discard-and-rediscover, so
    /// the session cannot be pinned to the first IGD host; explicit
    /// configuration is operator input and is never revoked.
    derived_gateway: Option<Ipv4Addr>,
    /// Consecutive failed IGD mapping rounds (discard-and-rediscover: at
    /// [`IGD_REDISCOVER_AFTER_FAILURES`] the cached client and derived
    /// gateway are dropped and the next round rediscovers; reset on
    /// success).
    igd_failures: u32,
    /// NAT-PMP epoch poisoning breaker (poisoned = PMP disabled for the
    /// session).
    poison: natpmp::EpochPoisonGuard,
}

impl NatActor {
    fn new(
        config: NatConfig,
        cmd_rx: mpsc::Receiver<NatCommand>,
        event_tx: mpsc::Sender<NatEvent>,
    ) -> Self {
        NatActor {
            config,
            cmd_rx,
            event_tx,
            backend: None,
            pmp: None,
            igd: None,
            internal_client: None,
            active: HashMap::new(),
            wanted: HashMap::new(),
            external_address: None,
            epoch: EpochTracker::default(),
            failed_rounds: 0,
            degraded: false,
            last_error: None,
            next: None,
            poll_at: None,
            recreate_at: None,
            derived_gateway: None,
            igd_failures: 0,
            poison: natpmp::EpochPoisonGuard::default(),
        }
    }

    async fn run(mut self) {
        loop {
            self.schedule_next();
            // Copy the deadline out to shed the borrow (each select arm needs
            // &mut self).
            let tick_at = self
                .next
                .map(|(at, tick)| (tokio::time::Instant::from_std(at.into_std()), tick));
            let tick_fut = async move {
                match tick_at {
                    Some((at, tick)) => {
                        tokio::time::sleep_until(at).await;
                        Some(tick)
                    }
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                cmd = self.cmd_rx.recv() => match cmd {
                    Some(NatCommand::Map { protocol, port, lease, reply }) => {
                        let lease = if lease.is_zero() { self.config.lease } else { lease };
                        let outcome = self.handle_map(protocol, port, lease).await;
                        let _ = reply.send(outcome);
                    }
                    Some(NatCommand::Renew { reply }) => {
                        let outcome = self.renew_all().await;
                        let _ = reply.send(outcome);
                    }
                    Some(NatCommand::Unmap { reply }) => {
                        self.unmap_all().await;
                        let _ = reply.send(Ok(()));
                    }
                    Some(NatCommand::Snapshot { reply }) => {
                        let _ = reply.send(self.snapshot());
                    }
                    None => {
                        // All handles dropped: best-effort unmap (advisory,
                        // RFC 6886 §3.1), then exit; lease expiry is the
                        // backstop (3600s automatic reclaim).
                        self.unmap_all().await;
                        break;
                    }
                },
                tick = tick_fut => match tick {
                    Some(Tick::Retry) => self.retry_missing().await,
                    Some(Tick::Renew) => self.due_for_renewal().await,
                    Some(Tick::PollAddress) => self.poll_address().await,
                    Some(Tick::Recreate) => self.recreate_all().await,
                    None => std::future::pending::<()>().await,
                },
            }
        }
    }

    /// Map command: record wanted, unmap the old mapping on a port change,
    /// run a mapping round.
    async fn handle_map(
        &mut self,
        protocol: Protocol,
        port: u16,
        lease: Duration,
    ) -> Result<(), NatError> {
        if port == 0 {
            return Err(NatError::InvalidArgs("port 0 is not mappable".into()));
        }
        let old = self
            .active
            .get(&protocol)
            .map(|m| (m.internal_port, m.external_port));
        self.wanted.insert(
            protocol,
            WantedMapping {
                internal_port: port,
                lease_secs: clamp_lease_secs(lease),
                // First creation suggests external = internal port (§3.3);
                // an update over an existing active mapping uses the
                // assigned value.
                suggested_external: old.map(|(_, e)| e).unwrap_or(port),
            },
        );
        // Same protocol, new port: unmap the old mapping (limits stale
        // forwarding; deletes are advisory).
        if let Some((old_internal, old_external)) = old
            && old_internal != port
        {
            self.unmap_one(protocol, old_internal, old_external).await;
            self.active.remove(&protocol);
        }
        self.ensure_wanted(protocol).await
    }

    /// Retry the wanted protocols that are still missing.
    async fn retry_missing(&mut self) {
        let missing: Vec<Protocol> = self
            .wanted
            .keys()
            .filter(|p| !self.active.contains_key(*p))
            .copied()
            .collect();
        for protocol in missing {
            if let Err(e) = self.ensure_wanted(protocol).await {
                debug!(target: LOG_TARGET, %e, "retry round failed");
            }
        }
    }

    /// Renew mappings whose renew_at <= now.
    async fn due_for_renewal(&mut self) {
        let now = Instant::now();
        let due: Vec<Protocol> = self
            .active
            .iter()
            .filter(|(_, m)| m.renew_at.is_some_and(|at| at <= now))
            .map(|(p, _)| *p)
            .collect();
        for protocol in due {
            if let Err(e) = self.ensure_wanted(protocol).await {
                debug!(target: LOG_TARGET, %e, "timer renew failed");
            }
        }
    }

    /// Recompute the next timer deadline (earliest wins).
    fn schedule_next(&mut self) {
        let mut next: Option<(Instant, Tick)> = None;
        let consider = |at: Instant, tick: Tick, cur: &mut Option<(Instant, Tick)>| {
            if cur.is_none_or(|(t, _)| at < t) {
                *cur = Some((at, tick));
            }
        };
        if let Some(at) = self.recreate_at {
            consider(at, Tick::Recreate, &mut next);
        }
        let pending = self.wanted.keys().any(|p| !self.active.contains_key(p));
        if pending {
            let at = Instant::now() + natpmp::round_backoff(self.failed_rounds);
            consider(at, Tick::Retry, &mut next);
        }
        for m in self.active.values() {
            if let Some(at) = m.renew_at {
                consider(at, Tick::Renew, &mut next);
            }
        }
        if self.backend.is_some()
            && let Some(at) = self.poll_at
        {
            consider(at, Tick::PollAddress, &mut next);
        }
        self.next = next;
    }

    /// Ensure the wanted mapping for one protocol exists (full round:
    /// protocol selection -> map -> state advance -> event/backoff
    /// accounting). Returns the final state for the command reply.
    async fn ensure_wanted(&mut self, protocol: Protocol) -> Result<(), NatError> {
        let Some(w) = self.wanted.get(&protocol).copied() else {
            return Ok(());
        };
        match self.map_round(protocol, &w).await {
            Ok(mapped) => {
                self.failed_rounds = 0;
                // RFC 6886 §3.3 final paragraph: renewal/recreate requests
                // MUST suggest the gateway-assigned external port — a
                // successful round writes it back into wanted (the
                // timer-driven due_for_renewal and retry_missing paths do
                // not reset the suggestion; the explicit write-back in the
                // renew_all/recreate_all command paths has the same
                // effect). Same for the IGD side: once AddAnyPortMapping
                // grants a different port, renewals via AddPortMapping
                // request the reserved port directly, eliminating the
                // per-round 718-conflict -> fallback loop (§2.5.16
                // same-port overwrite).
                if let Some(w) = self.wanted.get_mut(&protocol) {
                    w.suggested_external = mapped.external_port;
                }
                let previously = self.active.insert(
                    protocol,
                    ActiveMapping {
                        protocol,
                        internal_port: w.internal_port,
                        external_port: mapped.external_port,
                        granted: mapped.granted,
                        renew_at: mapped
                            .granted
                            .and_then(natpmp::renew_delay)
                            .map(|d| Instant::now() + d),
                    },
                );
                let port_changed = previously
                    .map(|p| p.external_port != mapped.external_port)
                    .unwrap_or(true);
                if port_changed {
                    self.emit(NatEvent::Mapped {
                        protocol,
                        external_port: mapped.external_port,
                    });
                }
                info!(target: LOG_TARGET,
                    backend = %self.backend.map_or("unknown".into(), |b| b.to_string()),
                    %protocol, internal = w.internal_port,
                    external = mapped.external_port,
                    "port mapped");
                if self.degraded {
                    self.degraded = false;
                    self.last_error = None;
                }
                Ok(())
            }
            Err(e) => {
                self.failed_rounds = self.failed_rounds.saturating_add(1);
                self.last_error = Some(e.to_string());
                if !self.degraded {
                    self.degraded = true;
                    self.emit(NatEvent::Failed {
                        reason: e.to_string(),
                    });
                }
                warn!(target: LOG_TARGET, %e, round = self.failed_rounds, "nat map round failed");
                Err(e)
            }
        }
    }

    /// One mapping attempt for one protocol (selection inline: NAT-PMP
    /// first, IGD on failure).
    async fn map_round(
        &mut self,
        protocol: Protocol,
        w: &WantedMapping,
    ) -> Result<MappedNow, NatError> {
        let mut last: Option<NatError> = None;
        if self.config.enable_natpmp {
            match self.pmp_map(protocol, w).await {
                Ok(mapped) => return Ok(mapped),
                Err(e) => {
                    debug!(target: LOG_TARGET, %e, "nat-pmp map failed");
                    last = Some(e);
                }
            }
        }
        if self.config.enable_upnp {
            match self.igd_map(protocol, w).await {
                Ok(mapped) => return Ok(mapped),
                Err(e) => {
                    debug!(target: LOG_TARGET, %e, "igd map failed");
                    last = Some(e);
                }
            }
        }
        Err(last.unwrap_or(NatError::NoBackend))
    }

    /// NAT-PMP mapping (unknown gateway = skip — see "protocol selection"
    /// in docs/design/io.md). On success, one serial address request
    /// follows (§3.1 serial request discipline); its failure is not fatal.
    ///
    /// Hardening: short-circuits once poisoned; external port 0 in a
    /// success reply is invalid (0 belongs only to §3.4 delete replies); a
    /// too-small granted lifetime falls back to the requested value (the
    /// renewal-cadence poisoning surface).
    async fn pmp_map(
        &mut self,
        protocol: Protocol,
        w: &WantedMapping,
    ) -> Result<MappedNow, NatError> {
        if self.poison.poisoned() {
            return Err(NatError::NatPmp(natpmp::NatPmpError::Poisoned));
        }
        let Some(client) = self.pmp_client().await? else {
            return Err(NatError::NatPmp(natpmp::NatPmpError::NoGateway));
        };
        let request = Request::Map(natpmp::MapRequest {
            protocol,
            internal_port: w.internal_port,
            suggested_external_port: w.suggested_external,
            lifetime_secs: w.lease_secs,
        });
        let reply = client.transact(&request).await?;
        self.observe_pmp_reply(&reply);
        let Reply::Map {
            external_port,
            lifetime_secs,
            ..
        } = reply
        else {
            return Err(NatError::NatPmp(natpmp::NatPmpError::OpcodeMismatch {
                reply: reply.opcode(),
                expected: request.opcode() | natpmp::RESPONSE_OP_FLAG,
            }));
        };
        // A success reply granting lifetime 0 is a protocol violation
        // (0 belongs only to §3.4 delete replies).
        if lifetime_secs == 0 {
            return Err(NatError::NatPmp(natpmp::NatPmpError::Result(
                natpmp::RESULT_UNSUPPORTED_OPCODE,
            )));
        }
        // External port 0 in a success map reply is likewise a protocol
        // violation (§3.4 reserves external port 0 for delete replies; a 0
        // reaching the Mapped event/watch poisons the whole announce
        // surface) — fail the round, fall back to IGD or backoff retry.
        if external_port == 0 {
            return Err(NatError::NatPmp(natpmp::NatPmpError::InvalidReply(
                "external port 0 in success reply",
            )));
        }
        // A too-small granted lifetime (< [`natpmp::MIN_GRANTED_LIFETIME_SECS`])
        // is treated as the requested value — the §3.3 halfway renewal
        // cadence must not be compressed by a forged lifetime (granted 1s
        // -> a burst every 500ms); real early reclaim self-heals via the
        // idempotent renewal.
        let granted_lifetime = if lifetime_secs < natpmp::MIN_GRANTED_LIFETIME_SECS {
            w.lease_secs
        } else {
            lifetime_secs
        };
        if self.backend != Some(Backend::NatPmp) {
            self.backend = Some(Backend::NatPmp);
            self.poll_at = Some(Instant::now() + self.config.address_poll);
        }
        // Serial address request (§3.1 "SHOULD NOT issue multiple concurrent
        // requests" — sent after the map transaction); failure only delays
        // address visibility.
        if let Some(client) = self.pmp_client().await?
            && let Ok(addr_reply) = client.transact(&Request::ExternalAddress).await
        {
            self.observe_pmp_reply(&addr_reply);
            if let Reply::ExternalAddress {
                address, result, ..
            } = addr_reply
                && result == natpmp::RESULT_SUCCESS
            {
                self.record_external_address(address);
            }
        }
        Ok(MappedNow {
            external_port,
            granted: Some(Duration::from_secs(u64::from(granted_lifetime))),
        })
    }

    /// IGD mapping (direct device-description URL or SSDP discovery;
    /// conflict fallback in [`igd::IgdClient::add_mapping`]). On success,
    /// one serial external address query follows (as above; failure not
    /// fatal).
    ///
    /// Hardening: gateway derivation is decoupled from the IGD host —
    /// derived values go to [`NatActor::derived_gateway`] (revocable)
    /// instead of being pinned onto `config.gateway`; after
    /// [`IGD_REDISCOVER_AFTER_FAILURES`] consecutive failures the cached
    /// client and derived gateway are dropped and the next round force-
    /// rediscovers (re-running the Location check), so a stale or hijacked
    /// device cannot be pinned for the session.
    async fn igd_map(
        &mut self,
        protocol: Protocol,
        w: &WantedMapping,
    ) -> Result<MappedNow, NatError> {
        let client = match self.resolve_igd().await {
            Ok(client) => client,
            Err(e) => {
                self.note_igd_failure();
                return Err(e);
            }
        };
        let internal_client = self.internal_client.ok_or_else(|| {
            NatError::Igd(igd::IgdError::Description(
                "internal client address unavailable".into(),
            ))
        })?;
        let mapping = igd::IgdMapping {
            protocol,
            internal_port: w.internal_port,
            external_port: w.suggested_external,
            lease_secs: w.lease_secs,
            description: DESCRIPTION.into(),
        };
        let external_port = match client.add_mapping(&mapping, internal_client).await {
            Ok(port) => port,
            Err(e) => {
                self.note_igd_failure();
                return Err(NatError::Igd(e));
            }
        };
        self.igd_failures = 0;
        // In-place query for the real lease (0 = permanent -> stop
        // renewing); query failure is not fatal (the mapping is live; an
        // unknown lease renews at the requested value).
        let granted = match client.query_mapping(protocol, external_port).await {
            Ok(Some(info)) if info.lease_secs == 0 => None,
            Ok(Some(info)) => Some(Duration::from_secs(u64::from(info.lease_secs))),
            Ok(None) | Err(_) => Some(Duration::from_secs(u64::from(w.lease_secs))),
        };
        if self.backend != Some(Backend::Igd) {
            self.backend = Some(Backend::Igd);
            self.poll_at = Some(Instant::now() + self.config.address_poll);
        }
        // Gateway derivation side channel: the IGD device host is a NAT-PMP
        // gateway candidate (revocable ledger, not pinned into config —
        // see the function doc for the decoupling).
        if self.config.gateway.is_none() {
            self.derived_gateway = client.gateway_hint();
        }
        if let Ok(addr) = client.external_ip().await {
            self.record_external_address(addr);
        }
        Ok(MappedNow {
            external_port,
            granted,
        })
    }

    /// IGD round failure accounting (discard-and-rediscover): once
    /// consecutive failures reach the threshold, drop the cached client
    /// and derived gateway — the next mapping round rediscovers (SSDP +
    /// Location check).
    fn note_igd_failure(&mut self) {
        self.igd_failures = self.igd_failures.saturating_add(1);
        if self.igd_failures < IGD_REDISCOVER_AFTER_FAILURES {
            return;
        }
        if self.igd.take().is_some() || self.derived_gateway.take().is_some() {
            debug!(target: LOG_TARGET,
                failures = self.igd_failures,
                "igd client discarded after repeated failures, rediscovering next round ");
        }
    }

    /// Renew all active mappings immediately (Renew command).
    async fn renew_all(&mut self) -> Result<(), NatError> {
        let protocols: Vec<Protocol> = self.active.keys().copied().collect();
        let mut first_err: Option<NatError> = None;
        for protocol in protocols {
            let external = match self.active.get(&protocol) {
                Some(m) => m.external_port,
                None => continue,
            };
            // RFC 6886 §3.3: renewals suggest the assigned external port.
            let entry = self
                .wanted
                .entry(protocol)
                .or_insert_with(|| WantedMapping {
                    internal_port: self
                        .active
                        .get(&protocol)
                        .map(|m| m.internal_port)
                        .unwrap_or_default(),
                    lease_secs: clamp_lease_secs(self.config.lease),
                    suggested_external: external,
                });
            entry.suggested_external = external;
            if let Err(e) = self.ensure_wanted(protocol).await {
                first_err.get_or_insert(e);
            }
        }
        first_err.map_or(Ok(()), Err)
    }

    /// Recreate after an epoch regression (jitter elapsed): move active
    /// mappings to wanted (suggested external port = the previously
    /// assigned value, §3.7 post-reboot port stability) and rerun a
    /// mapping round per protocol.
    async fn recreate_all(&mut self) {
        self.recreate_at = None;
        let protocols: Vec<Protocol> = self.active.keys().copied().collect();
        for protocol in protocols {
            if let Some(m) = self.active.remove(&protocol) {
                let entry = self
                    .wanted
                    .entry(protocol)
                    .or_insert_with(|| WantedMapping {
                        internal_port: m.internal_port,
                        lease_secs: clamp_lease_secs(self.config.lease),
                        suggested_external: m.external_port,
                    });
                entry.internal_port = m.internal_port;
                entry.suggested_external = m.external_port;
            }
        }
        let protocols: Vec<Protocol> = self.wanted.keys().copied().collect();
        for protocol in protocols {
            if let Err(e) = self.ensure_wanted(protocol).await {
                debug!(target: LOG_TARGET, %e, "recreate failed");
            }
        }
    }

    /// External address poll (local-policy period; NAT-PMP opcode 0 / IGD
    /// GetExternalIPAddress).
    async fn poll_address(&mut self) {
        self.poll_at = Some(Instant::now() + self.config.address_poll);
        match self.backend {
            Some(Backend::NatPmp) => {
                // Once poisoned, never talk to the suspect reply source
                // again (breaker semantics).
                if self.poison.poisoned() {
                    debug!(target: LOG_TARGET, "address poll skipped: nat-pmp poisoned");
                    return;
                }
                if let Some(client) = self.pmp_client().await.ok().flatten() {
                    match client.transact(&Request::ExternalAddress).await {
                        Ok(reply) => {
                            self.observe_pmp_reply(&reply);
                            if let Reply::ExternalAddress {
                                address, result, ..
                            } = reply
                                && result == natpmp::RESULT_SUCCESS
                            {
                                self.record_external_address(address);
                            }
                        }
                        Err(e) => debug!(target: LOG_TARGET, %e, "address poll failed"),
                    }
                }
            }
            Some(Backend::Igd) => {
                if let Ok(client) = self.resolve_igd().await {
                    match client.external_ip().await {
                        Ok(addr) => self.record_external_address(addr),
                        Err(e) => debug!(target: LOG_TARGET, %e, "address poll failed"),
                    }
                }
            }
            None => {}
        }
    }

    /// Record the external address (log on change — announce only cares
    /// about the port).
    fn record_external_address(&mut self, addr: Ipv4Addr) {
        if self.external_address != Some(addr) {
            info!(target: LOG_TARGET, %addr, "external address updated");
        }
        self.external_address = Some(addr);
    }

    /// Epoch accounting for NAT-PMP replies (§3.6); a regression schedules
    /// the §3.7 jittered recreate. Regressions filling the short window =
    /// epoch poisoning -> trip the breaker and disable NAT-PMP (cuts off
    /// the permanent recreate loop driven by forged replies).
    fn observe_pmp_reply(&mut self, reply: &Reply) {
        let now = Instant::now();
        if self.epoch.observe(reply.epoch_secs(), now.into()) {
            warn!(target: LOG_TARGET,
                "nat gateway epoch regression (state lost), recreating mappings");
            if self.poison.observe_regression(now.into()) {
                // Poisoned terminal state: disable PMP (later
                // pmp_map/poll/unmap short-circuit), cancel the pending
                // recreate, drop the transaction socket — recreate/poll
                // would only talk to the forged replies again. The IGD
                // backend continues.
                self.recreate_at = None;
                self.pmp = None;
                warn!(target: LOG_TARGET,
                    "nat-pmp disabled: epoch poisoning circuit-breaker tripped ");
                return;
            }
            if self.recreate_at.is_none() {
                let jitter = if self.config.recreate_jitter.is_zero() {
                    natpmp::reboot_recreate_delay()
                } else {
                    self.config.recreate_jitter
                };
                self.recreate_at = Some(now + jitter);
            }
        }
    }

    /// Resolve the NAT-PMP client (lazy creation; rebuilt when the gateway
    /// changes). None = gateway unknown.
    async fn pmp_client(&mut self) -> Result<Option<&NatPmpClient>, NatError> {
        let Some(gateway) = self.resolve_pmp_gateway().await? else {
            return Ok(None);
        };
        let already_bound = matches!(self.pmp.as_ref(), Some((gw, _)) if *gw == gateway);
        if !already_bound {
            // No connect: keep the send_to/recv_from explicit source-check
            // surface (§3.2/§3.3 MUST; BSD also rejects recv_from on a
            // connected UDP socket).
            let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).await?;
            let client = NatPmpClient::with_schedule(
                socket,
                SocketAddr::from((gateway, self.config.natpmp_port)),
                self.config.retransmit_schedule.clone(),
            );
            // Internal client address = the source IP this host routes to
            // the gateway with (UDP connect semantics on a throwaway probe
            // socket; same source as IGD NewInternalClient).
            if self.internal_client.is_none() {
                self.internal_client = local_ip_towards(gateway).await;
            }
            self.pmp = Some((gateway, client));
        }
        Ok(self.pmp.as_ref().map(|(_, client)| client))
    }

    /// Resolve the NAT-PMP gateway: explicit config -> IGD-derived side
    /// channel (decoupled: stored in the revocable `derived_gateway`
    /// ledger, invalidated on discard-and-rediscover) -> None (skip).
    async fn resolve_pmp_gateway(&mut self) -> Result<Option<Ipv4Addr>, NatError> {
        if let Some(gw) = self.config.gateway {
            return Ok(Some(gw));
        }
        if self.derived_gateway.is_none()
            && self.config.enable_upnp
            && self.resolve_igd().await.is_ok()
        {
            self.derived_gateway = self.igd.as_ref().and_then(|c| c.gateway_hint());
        }
        Ok(self.derived_gateway)
    }

    /// Resolve the IGD client (direct URL or SSDP discovery; caches on
    /// success and derives the internal address).
    async fn resolve_igd(&mut self) -> Result<igd::IgdClient, NatError> {
        if let Some(c) = &self.igd {
            return Ok(c.clone());
        }
        let client = match &self.config.igd_device_url {
            Some(url) => {
                let uri: rupnp::http::Uri = url.parse().map_err(|_| {
                    NatError::Igd(igd::IgdError::Description(format!("bad device url {url}")))
                })?;
                igd::IgdClient::from_device_url(uri).await?
            }
            None => igd::IgdClient::discover(self.config.ssdp_timeout, self.config.gateway).await?,
        };
        info!(target: LOG_TARGET, name = client.friendly_name(), "igd device resolved");
        // Internal client address = the source IP this host routes to the
        // gateway with (UDP connect semantics; no platform API / unsafe).
        if self.internal_client.is_none()
            && let Some(gw) = client.gateway_hint()
        {
            self.internal_client = local_ip_towards(gw).await;
        }
        self.igd = Some(client.clone());
        Ok(client)
    }

    /// Unmap one protocol (best effort; failures silent — advisory,
    /// RFC 6886 §3.1).
    async fn unmap_one(&mut self, protocol: Protocol, internal_port: u16, external_port: u16) {
        match self.backend {
            Some(Backend::NatPmp) => {
                // Once poisoned, no delete transaction (advisory, RFC 6886
                // §3.1 — lease expiry reclaims on the gateway side as the
                // backstop; breaker semantics take precedence).
                if self.poison.poisoned() {
                    debug!(target: LOG_TARGET, "unmap skipped: nat-pmp poisoned");
                    return;
                }
                let schedule = self.config.unmap_schedule.clone();
                if let Some(client) = self.pmp_client().await.ok().flatten() {
                    let req = Request::unmap(protocol, internal_port);
                    let _ = client.transact_with_schedule(&schedule, &req).await;
                }
            }
            Some(Backend::Igd) => {
                if let Ok(client) = self.resolve_igd().await {
                    let _ = client.remove_mapping(protocol, external_port).await;
                }
            }
            None => {}
        }
    }

    /// Unmap everything and clear state.
    async fn unmap_all(&mut self) {
        let protocols: Vec<Protocol> = self.active.keys().copied().collect();
        for protocol in protocols {
            let (internal, external) = match self.active.get(&protocol) {
                Some(m) => (m.internal_port, m.external_port),
                None => continue,
            };
            self.unmap_one(protocol, internal, external).await;
            self.active.remove(&protocol);
        }
        self.wanted.clear();
        self.backend = None;
        self.poll_at = None;
        self.recreate_at = None;
    }

    /// Snapshot.
    fn snapshot(&self) -> NatSnapshot {
        NatSnapshot {
            backend: self.backend,
            external_address: self.external_address,
            mappings: self
                .active
                .values()
                .map(|m| MappingView {
                    protocol: m.protocol,
                    internal_port: m.internal_port,
                    external_port: m.external_port,
                    granted_lease_secs: m.granted.map(|g| g.as_secs() as u32).unwrap_or(0),
                })
                .collect(),
            degraded: self.degraded,
            last_error: self.last_error.clone(),
        }
    }

    /// Emit an event (bounded; drop on full + warn — see the concurrency
    /// notes in docs/design/io.md).
    fn emit(&self, event: NatEvent) {
        if let Err(mpsc::error::TrySendError::Full(_)) = self.event_tx.try_send(event) {
            warn!(target: LOG_TARGET,
                "nat event channel full, event dropped (snapshot remains authoritative)");
        }
    }
}

/// Immediate result of a mapping attempt.
struct MappedNow {
    external_port: u16,
    /// Granted lease; None = permanent.
    granted: Option<Duration>,
}

/// Clamp lease seconds (Duration -> u32 seconds; floor 1 — for the danger
/// of 0 see the [`NatCommand::Map`] docs).
fn clamp_lease_secs(lease: Duration) -> u32 {
    lease.as_secs().min(u64::from(u32::MAX)).max(1) as u32
}

/// Source IPv4 this host routes to `target` (UDP connect semantics; no
/// platform API/unsafe).
async fn local_ip_towards(target: Ipv4Addr) -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
        .await
        .ok()?;
    sock.connect(SocketAddr::from((target, 80))).await.ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    }
}

/// IGD mapping description label (NewPortMappingDescription; no protocol
/// semantics).
const DESCRIPTION: &str = "taiji";

/// IGD consecutive-failure discard threshold (local policy, not
/// spec-anchored). Granularity is one single-protocol mapping round (TCP
/// and UDP each count), so 6 ≈ 3 full dual-protocol rounds; combined with
/// the backoff table (1s rising to a 16s cap), discard-and-rediscover runs
/// at most about every 30-50s — not an SSDP multicast storm. In the
/// healthy state there is no failure signal, so no periodic proactive
/// rediscovery is added (a dropped or hijacked device necessarily surfaces
/// through the failure path; proactive multicast only adds noise).
const IGD_REDISCOVER_AFTER_FAILURES: u32 = 6;

/// tracing target.
const LOG_TARGET: &str = "taiji::io::nat";
