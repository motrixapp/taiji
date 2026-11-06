//! Capability discovery (`taiji.getCapabilities`): a declarative view of
//! the engine's policy/feature registries — the single source of truth.
//!
//! Principle: no hand-maintained second list —
//! - `scheduler.available` = [`crate::SchedulerPolicy::NAMES`] (the
//! registry) filtered through `is_supported`; `setSchedulerPolicy`
//! explicitly rejects anything outside this set, so the two faces
//! reconcile;
//! - `diskPolicy.available` = [`taiji_store::disk_policy::DiskTier::NAMES`]
//! (the tier parameter registry);
//! - `features` = this module's [`FEATURES`] registry, one declared row
//! per feature (a new feature = one registry row + engine wiring; the
//! capability follows automatically);
//! - `rpcExtensions` = the session `RPC_METHODS` commitment table
//! filtered to the `taiji.` prefix (injected by the actor at assembly —
//! the engine does not depend back on the session face);
//! - `protocol.bep` = [`SUPPORTS_BEPS`].
//!
//! The JSON shape (schema_version=1, camelCase keys — the shared
//! `taiji.*` camelCase convention) is fixed by the taiji-rpc rendering
//! layer; this layer supplies only the core semantic payload.

/// Engine feature entry (two states: `supported` = the engine has it;
/// `enabled` = active in the current session — switch-driven entries read
/// back accurately, static entries are always true).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeatureCapability {
    /// Feature name (lowercase short name: `utp`/`dht`/`pex`/...; a
    /// frozen wire-face value).
    pub name: &'static str,
    /// The engine has this feature (false = not implemented, declared
    /// honestly).
    pub supported: bool,
    /// Active in the current session.
    pub enabled: bool,
}

/// Session-level feature toggle readings (the actor injects values taken
/// from the session's global options, GlobalOptions in the session
/// namespace; this layer does not depend back on session option structs).
#[derive(Debug, Clone, Copy, Default)]
pub struct FeatureToggles {
    /// `--enable-dht` (current session value).
    pub dht: bool,
    /// `--enable-dht6`.
    pub dht6: bool,
    /// `--bt-lsd`.
    pub lsd: bool,
}

/// Feature row (registry entry): static `supported` declaration +
/// `enabled_of` evaluated against the session toggles. Rows whose enabled
/// state shares its source with supported (e.g. mse: always present,
/// always active) ignore the toggles in their closure.
type FeatureRow = (&'static str, bool, fn(&FeatureToggles) -> bool);

/// Feature registry (declarative single source of truth).
const FEATURES: &[FeatureRow] = &[
    // µTP (BEP29): the accept face always takes TCP+µTP (dual accept);
    // outbound follows --bt-peer-connection-type — feature activation is
    // not narrowed by the switch (accept is always on); enabled always
    // true.
    ("utp", true, |_| true),
    // DHT (BEP5): session `--enable-dht` (applies to tasks created
    // afterwards; aria2 is also restart-effective — this reads the
    // session's current value).
    ("dht", true, |t| t.dht),
    // DHT IPv6 (`--enable-dht6`; best-effort v6 family binding).
    ("dht6", true, |t| t.dht6),
    // ut_pex (BEP11): engine gate always on (private torrents disable it
    // per task, BEP27 — a task attribute, not a session switch).
    ("pex", true, |_| true),
    // LSD (BEP14): session `--bt-lsd` (default false, same as aria2).
    ("lsd", true, |t| t.lsd),
    // ut_holepunch: enabled by default (internal config_json switch,
    // applies to new connections).
    ("holepunch", true, |_| true),
    // BEP42 DHT security extension: active with the DHT face (node_id
    // derivation + inbound storage checks).
    ("bep42", true, |t| t.dht),
    // MSE encrypted handshake (`--bt-require-crypto`/
    // `--bt-min-crypto-level`; the policy face is always available).
    ("mse", true, |_| true),
    // Fast Extension (BEP6;
    // suggest/have-all/have-none/reject/allowed-fast).
    ("fastExtension", true, |_| true),
    // ut_metadata (BEP9; metadata fetch + serving face).
    ("utMetadata", true, |_| true),
    // BEP16 super-seeding (engine switch, per-task face).
    ("superseeding", true, |_| true),
    // hash recovery (missing-layer gating / lazy-fetch convergence +
    // event face): the live production path once v2 parsing degrades to
    // layer_missing — missing-layer files converge via peer hash exchange
    // (whole file stored, gate upgraded); the admin-visible face =
    // taiji.recoveryStarted/Completed events + the getFiles
    // recoveryStatus projection. Always present at session level (the
    // missing-layer shape is per-task; no session switch).
    ("hashRecovery", true, |_| true),
    // BEP19 web seeding: `url-list` parsing (both forms) +
    // `EngineConfig.webseeds` projection + the
    // `--enable-http-seeding`/`enable-http-seeding` switch (default
    // true — off only clears the webseed set; the task's BT face
    // continues). Session-level always present and active (the per-task
    // override is a task attribute, not a session switch — same shape as
    // pex).
    ("webseeding", true, |_| true),
];

/// BEP protocols implemented by this engine (`protocol.bep`). Entry 19 =
/// the web seeding engine face (url-list parsing + a pseudo-peer HTTP
/// source feeding the BT data plane).
pub const SUPPORTS_BEPS: &[u16] = &[
    3, 5, 6, 9, 10, 11, 12, 14, 15, 16, 19, 21, 23, 27, 29, 32, 42, 47, 52, 53,
];

/// Engine capability view (core semantic payload; the
/// `taiji.getCapabilities` reply).
#[derive(Debug, Clone, PartialEq)]
pub struct CapabilitiesView {
    /// Engine version string (`taiji/<semver>`, same source as
    /// getVersion).
    pub version: String,
    /// Configurable scheduler policy names (registry ∩ implemented — the
    /// accepted domain of `setSchedulerPolicy`).
    pub scheduler_available: Vec<&'static str>,
    /// Session default policy name.
    pub scheduler_default: &'static str,
    /// Per-task override supported (`taiji.setSchedulerPolicy`
    /// per-torrent face).
    pub scheduler_per_task_override: bool,
    /// All disk tier names (accepted domain of `setDiskTier`).
    pub disk_tiers: Vec<&'static str>,
    /// Disk tiers are NOT config-only: applied live on a running engine
    /// (IoGate quota / flush cadence / write-coalescing window switch
    /// immediately; the prealloc allocation method only affects new
    /// allocations — per the RPC docs). Always false (landing face).
    pub disk_config_only: bool,
    /// Two-state feature table (registry order).
    pub features: Vec<FeatureCapability>,
    /// Implemented BEP protocol numbers.
    pub beps: &'static [u16],
    /// `taiji.*` RPC extension method names (filtered from the session
    /// commitment table, actor-injected).
    pub rpc_extensions: Vec<&'static str>,
    /// `taiji.*` extension notification event names (recovery event face;
    /// the single name source =
    /// `crate::recovery::RecoveryEventKind::notification_method`,
    /// actor-injected — same rule as [`Self::rpc_extensions`]: the engine
    /// does not depend back on the session face). The frozen aria2
    /// six-name table and `system.listNotifications` do not carry this
    /// face (extension events are declared via capabilities).
    pub notifications: Vec<&'static str>,
}

impl CapabilitiesView {
    /// Collected from the policy/feature registries (single source of
    /// truth; the actor's assembly entry). `version` =
    /// `taiji_core::version_string` (the core-side root function, same
    /// source as getVersion; injected by the caller to break a dependency
    /// cycle).
    pub fn collect(toggles: FeatureToggles, version: String) -> CapabilitiesView {
        use crate::SchedulerPolicy;
        // Registry ∩ implemented: sequential is explicitly unimplemented
        // -> not in available (reconciled with setSchedulerPolicy's
        // explicit rejection face).
        let scheduler_available: Vec<&'static str> = SchedulerPolicy::NAMES
            .iter()
            .copied()
            .filter(|name| {
                name.parse::<SchedulerPolicy>()
                    .is_ok_and(|p| p.is_supported())
            })
            .collect();
        let features = FEATURES
            .iter()
            .map(|&(name, supported, enabled_of)| FeatureCapability {
                name,
                supported,
                enabled: supported && enabled_of(&toggles),
            })
            .collect();
        CapabilitiesView {
            version,
            scheduler_available,
            scheduler_default: SchedulerPolicy::default().name(),
            scheduler_per_task_override: true,
            disk_tiers: taiji_store::disk_policy::DiskTier::NAMES.to_vec(),
            disk_config_only: false,
            features,
            beps: SUPPORTS_BEPS,
            rpc_extensions: Vec::new(),
            // taiji.* extension event names (actor-injected; same rule
            // as rpc_extensions — the engine does not depend back on the
            // session face).
            notifications: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SchedulerPolicy;

    /// scheduler.available = registry ∩ implemented (all three policies
    /// pass); default shares the registry's source.
    #[test]
    fn scheduler_capabilities_match_registry() {
        let view = CapabilitiesView::collect(FeatureToggles::default(), "taiji/0.0.0".into());
        assert_eq!(
            view.scheduler_available,
            vec!["rarest_first", "sequential", "streaming"],
            "NAMES order ∩ is_supported"
        );
        assert_eq!(view.scheduler_default, "rarest_first");
        assert!(view.scheduler_per_task_override);
        // The registry (NAMES) and the FromStr parse share a value domain
        // (this module does not let the faces drift).
        assert_eq!(SchedulerPolicy::NAMES.len(), 3);
        for name in SchedulerPolicy::NAMES {
            let p: SchedulerPolicy = name.parse().unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(p.name(), *name, "{name} roundtrip");
        }
    }

    /// disk_policy face: all three tiers + config_only=false (the
    /// live-application declaration).
    #[test]
    fn disk_policy_capabilities_declare_live_application() {
        let view = CapabilitiesView::collect(FeatureToggles::default(), "taiji/0.0.0".into());
        assert_eq!(
            view.disk_tiers,
            vec!["throughput", "ssd-protect", "hdd-sequential"]
        );
        assert!(!view.disk_config_only, "live application = not config-only");
    }

    /// features two states: every registry row appears; toggle-driven
    /// rows (dht/lsd/dht6/bep42) read back the session switches; static
    /// rows (utp/pex/holepunch/mse/fastExtension/utMetadata/
    /// superseeding/webseeding) are always true.
    #[test]
    fn features_two_state_table_is_declared() {
        let on = CapabilitiesView::collect(
            FeatureToggles {
                dht: true,
                dht6: true,
                lsd: true,
            },
            String::new(),
        );
        let by_name = |name: &str| {
            on.features
                .iter()
                .find(|f| f.name == name)
                .unwrap_or_else(|| panic!("feature {name} missing"))
                .to_owned()
        };
        for name in [
            "utp",
            "dht",
            "dht6",
            "pex",
            "lsd",
            "holepunch",
            "bep42",
            "mse",
            "fastExtension",
            "utMetadata",
            "superseeding",
            "webseeding",
        ] {
            assert!(
                on.features.iter().any(|f| f.name == name),
                "{name} row missing"
            );
        }
        for name in [
            "utp",
            "pex",
            "holepunch",
            "mse",
            "fastExtension",
            "utMetadata",
            "superseeding",
            // webseeding: switch defaults true (off = per-task/CLI
            // clearing of the webseed set, not a session-level toggle —
            // a static always-active row).
            "webseeding",
        ] {
            let f = by_name(name);
            assert!(
                f.supported && f.enabled,
                "{name} always supported and enabled"
            );
        }
        for name in ["dht", "dht6", "lsd", "bep42"] {
            assert!(by_name(name).enabled, "{name} enabled with all toggles on");
        }
        let ws = by_name("webseeding");
        assert!(
            ws.supported && ws.enabled,
            "webseeding supported and enabled (switch defaults true; per-task override, not a session row)"
        );

        // Session switches off -> toggle-driven rows go dark (the
        // observable face of the two-state semantics).
        let off = CapabilitiesView::collect(FeatureToggles::default(), String::new());
        let by_name_off = |name: &str| {
            off.features
                .iter()
                .find(|f| f.name == name)
                .unwrap_or_else(|| panic!("feature {name} missing"))
                .enabled
        };
        assert!(!by_name_off("dht"));
        assert!(!by_name_off("dht6"));
        assert!(!by_name_off("lsd"));
        assert!(!by_name_off("bep42"), "DHT off = BEP42 not enabled");
        assert!(by_name_off("utp"), "static rows ignore toggles");
    }

    /// protocol.bep: includes the core protocol numbers and BEP19;
    /// strictly ascending (stable wire order — the rendering layer does
    /// not sort again).
    #[test]
    fn bep_list_matches_spec_matrix() {
        let view = CapabilitiesView::collect(FeatureToggles::default(), String::new());
        assert!(
            view.beps.windows(2).all(|w| w[0] < w[1]),
            "strictly ascending"
        );
        for n in [3, 5, 9, 10, 11, 19, 27, 29, 47, 52, 53] {
            assert!(view.beps.contains(&n), "BEP {n} should be listed");
        }
        assert!(
            !view.beps.contains(&17),
            "BEP17 HTTP seed is out of surface, not listed"
        );
    }
}
