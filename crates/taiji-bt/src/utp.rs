//! bt-layer µTP integration placeholder.
//!
//! # Responsibility boundary
//!
//! The µTP protocol itself lives in [`taiji_io::utp`] (an IO leaf crate,
//! protocol-agnostic). This module holds only **policy knowledge**:
//! outbound connection-type negotiation (`--bt-peer-connection-type`), the
//! downgrade sequence, and the data source for the `getPeers`
//! `transport: tcp|utp` field (exposed over RPC). Engine wiring (core
//! ownership) is in place — the outbound dial loop tries [`dial_plan`] in
//! order (the winning transport is recorded into PeerMeta.transport);
//! inbound µTP connections are taken from
//! `taiji_io::utp::UtpListenerHandle::accept_from` (the peer address comes
//! with the queue) and then follow the same `bt::peer` accept path as TCP
//! inbound (the frozen PeerTransport seam).
//!
//! # Outbound policy
//!
//! `--bt-peer-connection-type = tcp|utp|prefer-utp|prefer-tcp` (default
//! prefer-tcp): "prefer-*" means that after the preferred transport fails
//! or times out, the other transport is **retried once**; plain `tcp`/`utp`
//! do not downgrade. The default prefer-tcp ships first; metric-driven
//! tuning does not block later milestones.

/// Outbound peer connection type (`--bt-peer-connection-type`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum PeerConnectionType {
    /// TCP only.
    Tcp,
    /// µTP only.
    Utp,
    /// µTP preferred, downgrade to TCP on failure (one retry).
    PreferUtp,
    /// TCP preferred, downgrade to µTP on failure (one retry) — the
    /// **default**.
    #[default]
    PreferTcp,
}

/// The transport of a single outbound attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// TCP (`TcpStream` plus optional MSE).
    Tcp,
    /// µTP (BEP29, `taiji_io::utp`).
    Utp,
}

impl Transport {
    /// The `getPeers` `transport` field value (lowercase enum name; a
    /// `taiji.*` extension field outside aria2's option namespace).
    pub fn as_transport_str(self) -> &'static str {
        match self {
            Transport::Tcp => "tcp",
            Transport::Utp => "utp",
        }
    }
}

/// Outbound dial plan: expand [`PeerConnectionType`] into an ordered
/// attempt sequence.
///
/// - `Tcp` -> `[Tcp]`; `Utp` -> `[Utp]` (no downgrade);
/// - `PreferTcp` -> `[Tcp, Utp]`; `PreferUtp` -> `[Utp, Tcp]` (after the
/// preferred transport fails or times out, retry once with the other).
///
/// Engine wiring: try in order, use the first success; if all fail, log
/// only (reconnection is driven by the announce/DHT discovery cycles).
pub fn dial_plan(t: PeerConnectionType) -> heapless_vec::DialPlan {
    use PeerConnectionType as P;
    match t {
        P::Tcp => [Some(Transport::Tcp), None],
        P::Utp => [Some(Transport::Utp), None],
        P::PreferTcp => [Some(Transport::Tcp), Some(Transport::Utp)],
        P::PreferUtp => [Some(Transport::Utp), Some(Transport::Tcp)],
    }
}

/// Dial-plan carrier (fixed length 2, avoiding a heapless dependency).
pub mod heapless_vec {
    /// Fixed-length-2 attempt sequence (`None` = end of sequence).
    pub type DialPlan = [Option<super::Transport>; 2];
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Default = prefer-tcp.
    #[test]
    fn default_is_prefer_tcp() {
        assert_eq!(PeerConnectionType::default(), PeerConnectionType::PreferTcp);
    }

    /// Dial plans: pure types do not downgrade; prefer-* retries once.
    #[test]
    fn dial_plan_sequences() {
        assert_eq!(
            dial_plan(PeerConnectionType::Tcp),
            [Some(Transport::Tcp), None]
        );
        assert_eq!(
            dial_plan(PeerConnectionType::Utp),
            [Some(Transport::Utp), None]
        );
        assert_eq!(
            dial_plan(PeerConnectionType::PreferTcp),
            [Some(Transport::Tcp), Some(Transport::Utp)]
        );
        assert_eq!(
            dial_plan(PeerConnectionType::PreferUtp),
            [Some(Transport::Utp), Some(Transport::Tcp)]
        );
    }

    /// The `getPeers` transport field data source.
    #[test]
    fn transport_strings() {
        assert_eq!(Transport::Tcp.as_transport_str(), "tcp");
        assert_eq!(Transport::Utp.as_transport_str(), "utp");
    }
}
