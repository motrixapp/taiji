//! Background discovery preparation uses the same service as real magnet jobs.
use std::time::Duration;

use super::SessionActor;
use crate::magnet::DiscoveryConfig;

impl SessionActor {
    pub(super) fn prepare_discovery(&self) {
        // Respect the user's disabled discovery policy. Preparation registers no
        // info hash and never consumes a download or metadata queue slot.
        if !self.global.enable_dht {
            return;
        }
        let config = DiscoveryConfig {
            listen_port: self.global.listen_port,
            peer_id: taiji_bt::tracker::generate_peer_id(
                self.global.peer_id_prefix.as_bytes(),
                rand::random,
            ),
            nat: self.nat.as_ref().map(|supervisor| supervisor.engine()),
            dht_enabled: self.global.enable_dht,
            dht_ipv6_enabled: self.global.enable_dht6,
            dht_message_timeout: Duration::from_secs(self.global.dht_message_timeout),
            dht_entry_points: Vec::new(),
            dht_entry_point_override: self.global.dht_entry_point.clone(),
            dht_entry_point_v6_override: self.global.dht_entry_point6.clone(),
        };
        self.magnet_services.request_preparation(config);
    }
}
