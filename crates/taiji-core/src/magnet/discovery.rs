//! Configuration for preparing discovery before the first magnet arrives.
use std::net::SocketAddr;
use std::time::Duration;

use crate::nat::NatEngine;

/// Only session network policy: preparing this service never registers a swarm.
#[derive(Clone)]
pub struct DiscoveryConfig {
    pub listen_port: u16,
    pub peer_id: [u8; 20],
    pub nat: Option<NatEngine>,
    pub dht_enabled: bool,
    pub dht_ipv6_enabled: bool,
    pub dht_message_timeout: Duration,
    pub dht_entry_points: Vec<SocketAddr>,
    pub dht_entry_point_override: Option<String>,
    pub dht_entry_point_v6_override: Option<String>,
}

impl From<&super::MagnetTaskConfig> for DiscoveryConfig {
    fn from(task: &super::MagnetTaskConfig) -> Self {
        Self {
            listen_port: task.phase.listen_port,
            peer_id: task.peer_id,
            nat: task.nat.clone(),
            dht_enabled: task.dht_enabled,
            dht_ipv6_enabled: task.dht_ipv6_enabled,
            dht_message_timeout: task.dht_message_timeout,
            dht_entry_points: task.dht_entry_points.clone(),
            dht_entry_point_override: task.dht_entry_point_override.clone(),
            dht_entry_point_v6_override: task.dht_entry_point_v6_override.clone(),
        }
    }
}
