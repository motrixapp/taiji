//! Session option surface: global options (the SPEC §11 frozen-name/
//! default subset), per-task option subset parsing (shared by
//! addUri/addTorrent options and changeOption), the getGlobalOption echo
//! (rpc-secret is never echoed), and pure changeUri tracker-table
//! transforms.
//!
//! Option names/defaults are frozen (SPEC §11). Value parsing aligns with
//! aria2: bool = "true"/"false"; size = bare bytes or a K/M/G suffix
//! (base 1024); seed-time unit = minutes. Unknown options are always
//! ignored — aria2 `RpcMethod.cc`: "Just ignore the unacceptable options
//! in this context".
//!
//! Upstream anchor mapping: docs/design/core.md

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use crate::metainfo::TorrentMeta;

/// seed-time upper bound (minutes) = 2^40. An absurdly generous panic
/// guard: no legal seeding duration reaches it, so nothing in-domain is
/// rejected. Without this bound, any large finite value (e.g. 1e30)
/// panics at the minutes->seconds conversion (`Duration::from_secs_f64`,
/// the panicking form that this function's consumers previously reached
/// through): seconds past u64::MAX kill the session actor (all RPC
/// SessionClosed), and once the value lands in config_json, bootstrap
/// replays it and panics again on restart (persistent DoS). 2^40 minutes
/// = 2^40 * 60 seconds; integers < 2^53 are exact in f64, so in-domain
/// conversion loses no precision.
pub(crate) const MAX_SEED_TIME_MIN: f64 = 1_099_511_627_776.0;

/// Single conversion point for seed-time minutes -> Duration (five
/// consumers: the add payload `seed_policy_from`, bootstrap replay x2,
/// changeOption x2).
///
/// None = out of domain (negative/NaN/inf/past [`MAX_SEED_TIME_MIN`]).
/// Callers treat it as invalid (skip the seed setting and warn; no
/// panic — the actor face must not panic, and `Duration::from_secs_f64`
/// panics on out-of-domain values; internally `try_from_secs_f64` folds
/// them to None).
pub(crate) fn seed_duration_from_minutes(m: f64) -> Option<Duration> {
    if !(m.is_finite() && (0.0..=MAX_SEED_TIME_MIN).contains(&m)) {
        return None;
    }
    Duration::try_from_secs_f64(m * 60.0).ok()
}

/// Single domain check for seed-ratio (consumers: the import parse arm +
/// bootstrap replay x2; the RPC task-option arm applies the same
/// `is_finite && >= 0.0` rule). None = out of domain (negative/NaN/±inf)
/// — callers treat it as invalid (skip the criterion and warn, no panic).
///
/// Why out-of-domain values are harmful: a non-finite value serializes
/// to null via serde_json, so the recovery face's from_json fails
/// wholesale (unwrap_or_default drops the whole config); finite +inf
/// makes `SeedCheck::build` attach an unsatisfiable ShareRatio = seed
/// forever; NaN/negative silently swallow the criterion in the
/// `seed_ratio > 0.0` test. No upper bound (ratio has no absurd-value
/// bound, unlike the seed-time panic guard).
pub(crate) fn checked_seed_ratio(r: f64) -> Option<f64> {
    if r.is_finite() && r >= 0.0 {
        Some(r)
    } else {
        None
    }
}

/// Session-level global options (actor-exclusive; fields mutated
/// directly, no lock).
#[derive(Debug, Clone)]
pub struct GlobalOptions {
    /// `--dir` (download directory; default ".").
    pub dir: PathBuf,
    /// `--max-concurrent-downloads` (default 5, SPEC §7.2/§11).
    pub max_concurrent_downloads: usize,
    /// Seed-pool budget (the four-pool budget model): the max
    /// number of concurrently **seeding-resident** BT tasks (the seed
    /// pool's `max-concurrent-seeds`; value domain [0,4096], 0 =
    /// unlimited — read through [`Self::seed_budget`], which clamps).
    /// **Option face landed later** (the RPC accepted key + echo row +
    /// the CLI/conf faces — the field/accessor themselves stay the
    /// prior entries; the close-out check re-verified no duplicate
    /// landed). **Two-state default**: the unlimited default
    /// presupposes the session-level connection budget; with
    /// not yet merged at implementation time the default
    /// converges temporarily to 16 (the card flips it back to
    /// 0 = unlimited when it lands).
    pub max_concurrent_seeds: usize,
    /// Check-pool budget (the four-pool budget model): the max
    /// number of concurrently **in-flight** on-disk rechecks (the check
    /// pool's `max-concurrent-checks`; value domain [1,16], read through
    /// [`Self::check_budget`], which clamps). **Option face landed in
    /// (the RPC accepted key + echo row + the CLI/conf faces —
    /// the field/accessor themselves stay the originals; the close-out
    /// close-out check re-verified no duplicate landed; the
    /// `max_concurrent_seeds` same-shape precedent).
    /// Default 2: a recheck is a pread+hash IO/CPU mixed stream — 2
    /// concurrent checks overlap IO and CPU, more starts thrashing the
    /// disk (the conservative value counting the engine-internal verify
    /// pool's layered disk load; the check budget governs session-level
    /// rechecks only, never the engine verify pool).
    pub max_concurrent_checks: usize,
    /// Synthesis-pool budget (the four-pool budget model): the max
    /// number of concurrently **synthesizing** media tasks (the
    /// synthesis pool's `media-synthesis-concurrency`; value domain
    /// [1,16], read through [`Self::synthesis_budget`], which clamps).
    /// **Option face landed later** (the RPC accepted key + echo row +
    /// the CLI/conf faces — the field/accessor themselves stay the
    /// prior entries; the close-out check re-verified no duplicate
    /// landed; the same-shape precedent). Default 2: an ffmpeg
    /// synthesis process is heavy (stream-copy light, transcode/burn-in
    /// heavy) — the layered counterpart of `media-segment-concurrency`
    /// (the network-phase knob, deliberately **not** governed by this
    /// budget; the §2 layering note). A narrowed budget never preempts: an in-flight synthesis
    /// always runs to completion — a narrowed budget only constrains
    /// subsequent permit grants; shares are not transferable (an idle download pool
    /// never enlarges this one).
    pub media_synthesis_concurrency: usize,
    /// `--max-overall-download-limit` (0 = unlimited). Numeric face +
    /// token-bucket enforcement face: hot-reloaded through the shared
    /// bucket in [`super::limits::SpeedLimits`].
    pub max_overall_download_limit: u64,
    /// `--max-overall-upload-limit` (0 = unlimited; same enforcement).
    pub max_overall_upload_limit: u64,
    /// `--enable-dht` (default true, SPEC §11). Runtime hot-reload:
    /// flipping it via changeGlobalOption pushes the effective value to
    /// every running BT engine (engine DHT spawn/teardown; counterpart of
    /// libtorrent `apply_settings` — aria2 cannot hot-reload this key;
    /// taiji's extension is declared). The activation chain and the
    /// session flip merge through a single task-flag point
    /// (`SessionActor::effective_task_dht`, consuming the per-task
    /// `bt-disable-dht` override) into `DhtWireConfig.enabled`.
    pub enable_dht: bool,
    /// `--enable-dht6` (default false). Value face: accepted, echoed,
    /// shown in the capability-bit view. There is no independent v6 DHT
    /// gate here — the v6 DHT face follows the [`Self::enable_dht`]
    /// master gate plus the IPv6 connectivity gate (probe_source_ip);
    /// this key currently does not change engine wiring (declared
    /// divergence).
    pub enable_dht6: bool,
    /// `--dht-entry-point` (v4; `HOST:PORT`, the aria2
    /// HostPortOptionHandler `PREF_DHT_ENTRY_POINT` — **no default**).
    /// Some = the bootstrap entry **replaces** the SPEC §6.7 router
    /// fallback constants (projected to `DhtWireConfig.entry_points_v4`,
    /// parsed entry by entry at the bootstrap face); None = the fallback
    /// constants (a taiji enhancement, not aria2 behavior). Startup-only
    /// option: aria2 gives it no changeGlobalOption/changeOption bit (the
    /// factory's DHT group has no set* calls), so changeGlobalOption does
    /// not accept it — takes effect on restart. Consumed by the actor's
    /// activation-time snapshot into `config.dht.entry_points_v4` (the
    /// magnet upgrade chain does not inject it yet — declared residual:
    /// the upgrade engine uses the fallback constants).
    pub dht_entry_point: Option<String>,
    /// `--dht-message-timeout` (seconds; the aria2 NumberOptionHandler
    /// default "10", domain 1..=60 — the OptionHandlerFactory.cc DHT-group
    /// anchors, pinned by [`DHT_MESSAGE_TIMEOUT_DEFAULT_SECS`]/MIN/MAX).
    /// Effective face = the DHT engine transaction timeout
    /// (`DhtEngineConfig.message_timeout`; the frozen taiji-bt
    /// `DHT_MESSAGE_TIMEOUT` is the same 10s, so the default is a zero
    /// change). Startup-only option (the reference has no change bit) —
    /// takes effect on restart.
    pub dht_message_timeout: u64,
    /// `--enable-peer-exchange` (default **true** — the aria2
    /// `PREF_ENABLE_PEER_EXCHANGE` A2_V_TRUE default). Effective face =
    /// the ut_pex advertise/consume gate (`EngineConfig.peer_exchange` →
    /// `bt::pex::pex_offered`; injected by the actor's activation-time
    /// snapshot). aria2 carries the setChangeGlobalOption bit
    /// (OptionHandlerFactory.cc), so changeGlobalOption accepts it
    /// (applies to tasks activated afterwards; running tasks are not
    /// hot-changed — per-download semantics). The per-task override face
    /// (an aria2 per-download option) is not provided here — declared
    /// divergence.
    pub enable_peer_exchange: bool,
    /// `--bt-detach-seed-only` (default false): seed-only tasks do not
    /// occupy a concurrency slot (SPEC §7.2; a flag consumed with
    /// EngineEnd::Detached).
    pub bt_detach_seed_only: bool,
    /// `--seed-ratio` (default 1.0).
    pub seed_ratio: f64,
    /// `--seed-time` (minutes, the aria2 unit; default 0 = no time
    /// condition).
    pub seed_time_min: f64,
    /// `--bt-max-peers` (default 55, SPEC §7.2).
    pub bt_max_peers: usize,
    /// `--listen-port` (wired; SPEC §11 frozen name; default 6881 = the
    /// first port of aria2's default range 6881-6999). Previously idle
    /// mode (session) always spawned the engine with port 0 (an OS
    /// ephemeral port) — self-consistent for announce but broken for port
    /// mapping/firewall scenarios. When a non-zero port is taken, the
    /// engine falls back through the range with aria2's retry semantics
    /// (`engine.rs` bind_listen_with_fallback; `BtSetup.cc` same rule).
    /// Startup-only option: changeGlobalOption does not accept it.
    pub listen_port: u16,
    /// `--bt-require-crypto` (wired; SPEC §11/§6.4; default false).
    /// true = outbound connections must start with MSE (no plaintext
    /// fallback), legacy inbound is refused, announce carries
    /// `requirecrypto=1` — enforced by [`taiji_bt::mse::CryptoPolicy`]
    /// injected through engine_config.
    pub bt_require_crypto: bool,
    /// `--bt-min-crypto-level` (SPEC §11; default plain).
    pub bt_min_crypto_level: taiji_bt::mse::CryptoLevel,
    /// `--bt-peer-connection-type` (SPEC §6.1/§11 frozen name; values
    /// tcp|utp|prefer-utp|prefer-tcp; default prefer-tcp). Wired: engine
    /// outbound dialing follows the four-state plan in
    /// [`taiji_bt::utp::dial_plan`] (TCP/µTP; prefer-* retries once on
    /// failure without downgrading the type), inbound always accepts both
    /// TCP and µTP (SPEC §6.1). Effective for the download/seed engines
    /// the session spawns and the magnet upgrade engine; the metadata
    /// discovery phase always dials TCP (explicit gap noted in
    /// magnet.rs).
    pub bt_peer_connection_type: taiji_bt::utp::PeerConnectionType,
    /// `--bt-lsd` (wired; SPEC §11/§2 matrix BEP14; default **false** —
    /// same as aria2 `PREF_BT_ENABLE_LPD`, `OptionHandlerFactory.cc`).
    /// true = the session bootstraps an LSD service (BEP14 multicast
    /// 239.192.152.143:6771 send/receive; the aria2 receiver is a
    /// process-level singleton, `BtSetup.cc` isomorphic): announce on
    /// torrent activation (**disabled for private torrents**,
    /// BtSetup.cc; v2-only torrents have no v1 infohash to announce) and
    /// withdraw on teardown; the magnet metadata phase consumes PeerFound
    /// via subscription (ut_metadata discovery face). changeGlobalOption
    /// accepts it (the reference setChangeGlobalOption bit,
    /// `OptionHandlerFactory.cc`); the change applies to tasks activated
    /// afterwards (same rule as enable-dht; running tasks are not
    /// interrupted).
    pub bt_lsd: bool,
    /// `--http-max-per-host` (taiji extension; default
    /// [`taiji_http::perhost::DEFAULT_MAX_PER_HOST`] = 64). The
    /// session-initialization value of the per-host connection cap:
    /// SessionActor spawn builds the session-level
    /// [`taiji_http::perhost::HostCap`] from it (session/actor/mod.rs
    /// `spawn_with_persist`). Startup-only option: changeGlobalOption
    /// does not accept it (takes effect on restart); runtime adjustment
    /// goes through the addUri option `http-max-per-host` (last-set-wins
    /// on the shared cap — previously the CLI value never reached the
    /// session HostCap initialization and was silently dropped on the
    /// attach/recovery path; addUri was the only channel). getGlobalOption
    /// echoes the effective cap value (the commands.rs GetGlobalOption
    /// arm overrides the echo with `HostCap::cap`, so the echo does not
    /// drift after a runtime addUri adjustment).
    pub http_max_per_host: u32,
    /// The media family's session defaults (unified
    /// registration: the P90-P93 flag family mounts on the global
    /// option face). **Consumed**: every addMedia task merges absent
    /// per-task keys from these values (a per-task option present in
    /// the payload wins — `media_task::media_cfg_from_options`'s
    /// merge, wired at the actor's add face), so changeGlobalOption
    /// media-* is live for tasks added afterwards. The values' single
    /// parse/validation source = taiji-media's option faces, stored
    /// here as their canonical string forms.
    /// `--media-variant-policy` (default "highest"; P90).
    pub media_variant_policy: String,
    /// `--media-audio-lang` (None = policy chain unchanged; P91).
    pub media_audio_lang: Option<String>,
    /// `--media-subtitles` (default "sidecar"; P91).
    pub media_subtitles: String,
    /// `--media-segment-concurrency` (default 8, domain 1..=64; P91).
    pub media_segment_concurrency: u32,
    /// `--media-staging-quota-gib` (default 50; P91).
    pub media_staging_quota_gib: u64,
    /// `--media-staging-dir` (None = <dir>/.taiji-b same-volume; P91).
    pub media_staging_dir: Option<String>,
    /// `--media-allow-private-key-url` (default false; P92 — governs
    /// both SSRF-line faces).
    pub media_allow_private_key_url: bool,
    /// `--media-ffmpeg-path` (default "auto"; P93).
    pub media_ffmpeg_path: String,
    /// `--media-archive` (default false): the
    /// download-archive face's session default — per-task `media-archive`
    /// keys merge over it (the family rule). On = the Done close-out
    /// records the two fingerprints + the duplicate checkpoints run.
    pub media_archive: bool,
    /// `--media-info-json` (default false): the
    /// whitelisted+redacted info.json sidecar export's session default
    /// (per-task `media-info-json` keys merge over it; orthogonal to
    /// `--no-meta` — the embed face is no-meta's, the export face is
    /// this flag's alone).
    pub media_info_json: bool,
    /// `--rpc-secret`: stored only, never echoed (getGlobalOption
    /// removes it explicitly; the `RpcMethodImpl.cc` PREF_RPC_SECRET
    /// branch is the same rule).
    pub rpc_secret: Option<String>,
    /// `--rpc-user` (Basic auth user; deprecated in aria2 but kept for
    /// compatibility, `OptionHandlerFactory.cc`). Echoed — the reference
    /// only strips PREF_RPC_SECRET (`RpcMethodImpl.cc`).
    pub rpc_user: Option<String>,
    /// `--rpc-passwd` (Basic auth password): treated as a secret —
    /// **never echoed** (the reference does echo the deprecated
    /// rpc-passwd; SPEC §13's "secrets never echo" discipline tightens it
    /// to the same removal class as rpc-secret).
    pub rpc_passwd: Option<String>,
    /// `--save-session`: text export path for saveSession (input-file
    /// compatible format; `SessionSerializer.cc` writes atomically via
    /// `__temp` + rename). None = only taiji.sqlite3 (the primary store;
    /// SPEC §8.2 declares the shape difference); on graceful shutdown the
    /// same path also gets a text copy (the aria2 save-session
    /// save-on-exit semantics).
    pub save_session: Option<PathBuf>,
    /// `--save-session-interval` (reference name, prefs.cc; default
    /// **0** = disabled — `OptionHandlerFactory.cc`
    /// `NumberOptionHandler(…, "0", 0)` is the default anchor).
    /// Effective face = the SessionActor periodic tick triggers a full
    /// flush every N seconds (task-row/HTTP-row flush +
    /// `--save-session` text export + WAL checkpoint — the same
    /// `save_session` entry point as graceful shutdown); the tick is not
    /// assembled when the persistence layer is absent (store-open
    /// failure degrades). **Startup-only option**: changeGlobalOption
    /// does not accept it (same stance as summary-interval); takes
    /// effect on restart. Divergence note: in aria2 this interval drives
    /// periodic `.aria2` control-file writes; here sqlite persistence
    /// writes continuously (the PersistWriter per-event face) and the
    /// tick closes out flush / text export / checkpoint — the semantic
    /// difference is declared as-is.
    pub save_session_interval_secs: u64,
    /// The six hook commands + `bt-enable-hook-after-hash-check`
    /// (frozen names, SPEC §11; default empty = not executed; the
    /// hash-check gate defaults to true — aria2
    /// `OptionHandlerFactory.cc`). Semantics live in `crate::hook`.
    pub hooks: crate::hook::HookSet,
    /// `--bt-tracker` (SPEC §11 frozen name, comma-separated list). The
    /// in-memory source of truth for the globally imported tracker set
    /// (persistent mirror = the taiji.sqlite3 `global_tracker` table via
    /// the PersistWriter seam); effective through the three-layer merge
    /// in [`merge_global_trackers`] (per-torrent table ∪ global set,
    /// union dedup).
    ///
    /// Divergence from the reference (declared): aria2's bt-tracker is a
    /// non-persistent option that rewrites announce-list in place via
    /// `adjustAnnounceUri` at each download setup
    /// (`bittorrent_helper.cc`); changeGlobalOption only affects later
    /// downloads. Because taiji requires persistent import + hot update
    /// of in-flight tasks, the semantics extend to union-cumulative
    /// import (changeGlobalOption bt-tracker = union the new values into
    /// the global set, persist immediately and push to running engines;
    /// no removal face — bt-exclude-tracker is out of this module's
    /// scope).
    pub bt_tracker: Vec<String>,
    /// `--bt-tracker-file` (taiji addition; aria2 has no such option).
    /// Path to an ngosang/trackerslist file (one URL per line, `#`
    /// comments and blank lines skipped, ≤1MiB — parsed by
    /// [`taiji_bt::tracker::trackerslist`]). Value face = the last-set
    /// path (echoed by getGlobalOption; parsing happens at import time:
    /// once on startup bootstrap and once per changeGlobalOption hot
    /// update, reading the file inside spawn_blocking).
    pub bt_tracker_file: Option<PathBuf>,
    /// One-shot mode flag (a process lifetime bound to a single task —
    /// the bare CLI shapes). The old cookie coupling (one-shot =
    /// clear-on-error, resident = 24h retention) is retired by
    /// Both modes clear cookies on the **full
    /// terminal set** (done and error) identically; the flag keeps its
    /// process-lifetime meaning only.
    pub one_shot: bool,
    /// Client-identity ban prefixes (** addition**,
    /// config_json/internal face — aria2 has no counterpart and the name
    /// carries no aria2 compatibility promise). Each entry matches a
    /// peer_id byte prefix **or** a case-insensitive substring of the
    /// ext handshake `v` field (`bt::peer_policy::IpGuard::client_blocks`);
    /// default **empty list = ban no client** (identification is not
    /// banning; the switch defaults off). Effective for activated engines
    /// (SetBanConfig pushed wholesale; changeGlobalOption
    /// `client-ban-prefixes` hot-updates running engines with the comma
    /// list and persists to session_kv across restarts). Identification
    /// table: see the `bt::client_id` module docs.
    pub client_ban_prefixes: Vec<String>,
    /// `--bt-metadata-web-sources` (taiji addition; aria2 has no such
    /// option; , no aria2 compatibility promise for the
    /// name). Comma-separated list of URL templates; the `{INFOHASH}`
    /// placeholder = lowercase v1 btih hex40 (the itorrents/btcache style
    /// of public cache sites); default **empty = feature off, zero HTTP
    /// outbound**. Effective for the metadata phase of magnet tasks
    /// created afterwards (a fourth source racing DHT/tracker/LSD; first
    /// validated wins).
    ///
    /// Privacy semantics: configuring a mirror sends the infohash to a
    /// third-party site, exposing download intent. Responses that fail
    /// validation (infohash mismatch / bad piece layers) are discarded,
    /// not written (§2.1.8). Template parsing/circuit breaker: see
    /// `crate::magnet`. changeGlobalOption accepts it (same rule as
    /// client-ban-prefixes; applies to later tasks).
    pub bt_metadata_web_sources: Vec<String>,
    /// `--bt-enable-upnp` (wired; SPEC §11 has no anchor — **upstream
    /// aria2 has no such option** (verified against the reference; a
    /// full-history `git log -S` pickaxe finds zero hits), so there is no
    /// aria2 default to compare against; the comparison implementation
    /// libtorrent RC_2_0 defaults `enable_upnp` to **true**
    /// (`settings_pack.cpp`) — noted; taiji defaults to **false**,
    /// matching the "defaults must not enable behavior" and "defaults
    /// cause zero behavior change" criteria). true = the session powers
    /// the NAT singleton actor (UPnP IGD participates in listen-port
    /// mapping, SPEC §6.8; a mapping failure degrades without blocking
    /// downloads — existing assemble semantics; note assemble waits
    /// inline for the mapping, so a slow gateway delays announce/download
    /// start — slow IGD mappings can take minutes, hence default off with
    /// explicit user opt-in). Startup-only option: changeGlobalOption
    /// does not accept it (same rule as listen-port); takes effect on
    /// restart.
    pub bt_enable_upnp: bool,
    /// `--bt-enable-nat-pmp` (wired; default **false** — same stance as
    /// [`Self::bt_enable_upnp`]; libtorrent `settings_pack.cpp` defaults
    /// `enable_natpmp` to true, noted for contrast). true = NAT-PMP
    /// (RFC 6886) participates in port mapping. Startup-only option
    /// (takes effect on restart, as above).
    pub bt_enable_natpmp: bool,
    /// NAT assembly override (**internal injection seam, not an option
    /// face** — no aria2 naming promise, never echoed by getGlobalOption):
    /// a test/deployment-targeted `NatConfig` (mock IGD direct URL,
    /// gateway/port/retransmit-table/lifetime overrides). None =
    /// `NatConfig::default` with the two booleans layered on (see
    /// [`Self::build_nat_config`]). Not consumed by production CLI/RPC.
    pub nat_config_override: Option<taiji_io::nat::NatConfig>,
    /// `--summary-interval` (reference name, `prefs.cc`; default
    /// [`SUMMARY_INTERVAL_DEFAULT`] = 60, domain
    /// 0..=[`SUMMARY_INTERVAL_MAX`], 0 = disabled — anchored to
    /// `OptionHandlerFactory.cc`). Interval in seconds for periodic task
    /// summary logs: every N seconds the SessionActor emits one INFO
    /// summary per active task (gid/speed/progress/connections, target
    /// `taiji::core::summary`); nothing is emitted when no task is active
    /// (log hygiene). Startup-only option: capability bits align with the
    /// reference (the factory handler has no setChangeOption/
    /// setChangeGlobalOption call), so changeOption/changeGlobalOption do
    /// not accept it (apply_global_patch has no arm for it — the key is
    /// ignored as unknown, the reference's "unacceptable options" rule);
    /// takes effect on restart.
    pub summary_interval: u32,
    /// `--peer-id-prefix` (wired; aria2-compatible name — `prefs.cc`
    /// `PREF_PEER_ID_PREFIX`, registered in `OptionHandlerFactory.cc`).
    /// Effective at the session-level peer ID **single generation point**
    /// [`taiji_bt::tracker::generate_peer_id`]: tracker announce and peer
    /// handshake share one value (one peer_id per engine task;
    /// libtorrent `torrent.cpp` is per-torrent, isomorphic). Prefix +
    /// random fill to 20B; **overlong prefixes are truncated to the first
    /// 20B, not rejected** — the aria2 stance (`bittorrent_helper.cc`
    /// `erase(20)`, help text `usage_text.h`); no charset validation
    /// (aria2's DefaultOptionHandler does not validate either). Default =
    /// [`taiji_bt::tracker::PEER_ID_PREFIX`] (`-TJ0001-`; byte-identical
    /// to prior behavior when unset).
    ///
    /// Startup-only option: changeGlobalOption does not accept it (takes
    /// effect on restart — no peer ID runtime hot-reload; same rule as
    /// listen-port/bt-enable-upnp).
    ///
    /// Kept **separate** from the UA/ext-handshake `v` string
    /// ([`taiji_bt::tracker::PEER_AGENT`]): PT risk control checks UA and
    /// peer id against two independent whitelists, so binding one value
    /// to both would let a misconfiguration poison both faces (aria2 also
    /// has two independent options: `--peer-id-prefix` and
    /// `--peer-agent`, both in `OptionHandlerFactory.cc`).
    pub peer_id_prefix: String,
    /// `--load-cookies` (reference name, `prefs.cc`
    /// `makePref("load-cookies")`; accepted): the **session-level default
    /// source** of Netscape cookie file paths. Effective for HTTP tasks
    /// created afterwards (when addUri carries no per-task
    /// `load-cookies`, this value applies; an explicit per-task value
    /// overrides the global one — aria2's per-download precedence, same
    /// order). Loading is fail-closed at task acceptance (missing/
    /// unreadable/>1MiB = `taiji.option.invalid` task rejection, anchored
    /// at [`taiji_http::cookies::MAX_COOKIE_FILE_BYTES`]); this field
    /// does no load-time validation (value face = the path string; empty
    /// string = clear back to default). aria2 gives this option a
    /// setChangeGlobalOption bit, so changeGlobalOption accepts it
    /// (applies to later tasks, same rule as enable-dht — running tasks
    /// are not backfilled).
    pub load_cookies: Option<PathBuf>,
    /// `--bt-tracker-interval` (wired; seconds; 0 = do not override —
    /// same as the aria2 NumberOptionHandler default "0",
    /// `OptionHandlerFactory.cc`). Effective in the engine tracker
    /// actor's announce client (`TrackerOptions.bt_tracker_interval` ->
    /// `apply_interval_settings` userDefinedInterval_, a direct
    /// translation of `DefaultBtAnnounce.cc`); 0 = follow the tracker's
    /// reply interval. changeGlobalOption accepts it (same reference
    /// bit), applying to tasks activated afterwards.
    pub bt_tracker_interval: u64,
    /// `--bt-tracker-timeout` (wired; seconds; domain 1..=600, default
    /// 60 — `OptionHandlerFactory.cc` anchor). Effective as the overall
    /// HTTP announce client timeout (reqwest timeout, bt::tracker
    /// TrackerOptions).
    pub bt_tracker_timeout_secs: u64,
    /// `--bt-tracker-connect-timeout` (wired; seconds; domain 1..=600,
    /// default 60 — `OptionHandlerFactory.cc` anchor). Effective as the
    /// HTTP announce connect timeout (reqwest connect_timeout, same).
    pub bt_tracker_connect_timeout_secs: u64,
    /// `--bt-stop-timeout` (wired; seconds; 0 = no watchdog — same as
    /// the aria2 default, `OptionHandlerFactory.cc`). Effective as the
    /// engine's seeding-stall watchdog (`SeedPolicy.stop_timeout` ->
    /// BtStopTimeoutWatch, a direct translation of `BtSetup.cc`: N
    /// consecutive seconds of zero throughput while seeding -> wrap-up).
    /// Consumed through the `seed_policy_from` task-policy projection
    /// (per-task `bt-stop-timeout` overrides this value).
    /// changeGlobalOption accepts it (same reference bit), applying to
    /// tasks activated afterwards.
    pub bt_stop_timeout_secs: u64,
    /// The aria2-compatible "accepted but no-op" global value face
    /// (**DEPRECATED semantics** — the value is accepted and recorded, no
    /// engine behavior change; the explicit extension face that closes the
    /// Motrix frontend's actually-sent changeGlobalOption subset). Keys =
    /// the [`GLOBAL_PATCH_TABLE`] no-op row names (split/user-agent/
    /// async-dns/...), values = the last accepted raw string; a missing
    /// key = unset (getGlobalOption echoes the empty string — the
    /// save-session/load-cookies unset shape). Values get no type/domain
    /// validation (the value does not affect behavior; per-key wiring
    /// reasons live in the table row notes). Consumed by each no-op row's
    /// echo projection (single point, [`global_option_echo`]).
    pub unwired_option_values: BTreeMap<String, String>,
}

impl Default for GlobalOptions {
    fn default() -> Self {
        GlobalOptions {
            dir: PathBuf::from("."),
            max_concurrent_downloads: 5,
            // pre-merge state of the seed-budget knob (see the field doc's
            // two-state note; returns to 0 once the session-level connection
            // budget lands).
            max_concurrent_seeds: 16,
            // Check budget default 2 (pread+hash IO/CPU
            // overlap; the layered disk load with the engine verify pool
            // counted in).
            max_concurrent_checks: 2,
            // Synthesis budget default 2 (an ffmpeg process
            // is heavy — stream-copy light, transcode/burn-in heavy; the
            // layered counterpart of media-segment-concurrency).
            media_synthesis_concurrency: 2,
            max_overall_download_limit: 0,
            max_overall_upload_limit: 0,
            enable_dht: true,
            enable_dht6: false,
            // DHT entry point default unset (None = the SPEC §6.7 router
            // fallback constant shape); transaction timeout default 10s
            // (the aria2 handler default "10" and the taiji-bt
            // DHT_MESSAGE_TIMEOUT are the same value); PEX default on
            // (the A2_V_TRUE default).
            dht_entry_point: None,
            dht_message_timeout: DHT_MESSAGE_TIMEOUT_DEFAULT_SECS,
            enable_peer_exchange: true,
            bt_detach_seed_only: false,
            seed_ratio: 1.0,
            seed_time_min: 0.0,
            bt_max_peers: 55,
            listen_port: 6881,
            bt_require_crypto: false,
            bt_min_crypto_level: taiji_bt::mse::CryptoLevel::Plain,
            bt_peer_connection_type: taiji_bt::utp::PeerConnectionType::default(),
            bt_lsd: false,
            // Per-host cap initialization defaults to 64; single source
            // = the taiji-http constant.
            http_max_per_host: taiji_http::perhost::DEFAULT_MAX_PER_HOST,
            media_variant_policy: "highest".into(),
            media_audio_lang: None,
            media_subtitles: "sidecar".into(),
            media_segment_concurrency: taiji_media::DEFAULT_SEGMENT_CONCURRENCY,
            media_staging_quota_gib: taiji_media::DEFAULT_STAGING_QUOTA_GIB,
            media_staging_dir: None,
            media_allow_private_key_url: false,
            media_ffmpeg_path: "auto".into(),
            media_archive: false,
            media_info_json: false,
            rpc_secret: None,
            rpc_user: None,
            rpc_passwd: None,
            save_session: None,
            // `--save-session-interval` default 0 = disabled (the
            // reference default anchor, OptionHandlerFactory.cc —
            // see the field doc note).
            save_session_interval_secs: 0,
            hooks: crate::hook::HookSet::default(),
            bt_tracker: Vec::new(),
            one_shot: false,
            bt_tracker_file: None,
            client_ban_prefixes: Vec::new(),
            bt_metadata_web_sources: Vec::new(),
            // Default false (zero behavior change by default; "defaults
            // must not enable behavior". The libtorrent settings_pack.cpp
            // default-true contrast and the slow-gateway rationale are in
            // the field docs.)
            bt_enable_upnp: false,
            bt_enable_natpmp: false,
            nat_config_override: None,
            // `--peer-id-prefix` default = `-TJ0001-` (BEP20
            // Azureus-style own identity; taken from the bt frozen
            // constant — default behavior byte-identical).
            peer_id_prefix: taiji_bt::tracker::PEER_ID_PREFIX.to_string(),
            // `--summary-interval` default 60 (single source: reference
            // OptionHandlerFactory.cc "60"; 0 = disabled).
            summary_interval: SUMMARY_INTERVAL_DEFAULT,
            // `--load-cookies` default unset (None = no session-level
            // cookie source).
            load_cookies: None,
            // Four tracker keys default to the aria2 defaults (zero
            // default-behavior difference): interval 0 = no override;
            // both tracker timeouts 60s; stop-timeout 0 = no stall
            // watchdog.
            bt_tracker_interval: 0,
            bt_tracker_timeout_secs: 60,
            bt_tracker_connect_timeout_secs: 60,
            bt_stop_timeout_secs: 0,
            // The no-op value face defaults to an empty map (a missing key
            // = unset = the empty-string echo).
            unwired_option_values: BTreeMap::new(),
        }
    }
}

impl GlobalOptions {
    /// NAT assembly face (the session's single source; shared by the
    /// bare CLI shape and session bootstrap — the CLI crate does not
    /// depend on io directly): the injected override
    /// (None = `NatConfig::default`) is the base and the two boolean
    /// switches layer on top — a disabled protocol does not participate
    /// in mapping (the io actor picks the route).
    pub fn build_nat_config(&self) -> taiji_io::nat::NatConfig {
        let mut cfg = self.nat_config_override.clone().unwrap_or_default();
        cfg.enable_upnp = self.bt_enable_upnp;
        cfg.enable_natpmp = self.bt_enable_natpmp;
        cfg
    }

    /// Either switch on = the session powers the NAT singleton (all off
    /// = no spawn — zero change from the previous nat: None shape).
    pub fn nat_enabled(&self) -> bool {
        self.bt_enable_upnp || self.bt_enable_natpmp
    }

    /// Seed-pool budget read (the single consumption point; value
    /// domain [0,4096] clamped at read — the max-concurrent-downloads
    /// clamp precedent, but read-side because this card's field has no
    /// parse/RPC face yet; a direct construction feeding an
    /// out-of-domain value gets clamped, never panics). 0 = unlimited.
    pub fn seed_budget(&self) -> usize {
        self.max_concurrent_seeds.min(4096)
    }

    /// Check-pool budget read (the single consumption point, the
    /// model; value domain [1,16] clamped at read — the seed_budget
    /// read-side shape: the field had no parse/RPC face at first, so
    /// a direct construction feeding an out-of-domain value gets
    /// clamped, never panics; the lower clamp 1 keeps at least one
    /// recheck admitted — unlike the seed pool there is no "unlimited"
    /// state). Consumed per promotion by pump_check: an in-flight
    /// recheck always runs to completion (a narrowed budget never preempts — it
    /// only constrains subsequent admissions).
    pub fn check_budget(&self) -> usize {
        self.max_concurrent_checks.clamp(1, 16)
    }

    /// Synthesis-pool budget read (the single consumption point, the
    /// model; value domain [1,16] clamped at read — the
    /// seed_budget/check_budget read-side shape: the field has no
    /// parse/RPC face at first, so a direct construction feeding an
    /// out-of-domain value gets clamped, never panics; the lower clamp 1
    /// keeps at least one synthesis admitted — unlike the seed pool
    /// there is no "unlimited" state). Consumed per promotion by
    /// pump_all's synthesis segment: an in-flight synthesis always runs
    /// to completion (a narrowed budget only constrains
    /// subsequent permit grants; shares are not transferable — an idle download pool
    /// never enlarges this one).
    pub fn synthesis_budget(&self) -> usize {
        self.media_synthesis_concurrency.clamp(1, 16)
    }
}

/// SessionActor construction parameters (CLI/test injection; `spawn`
/// uses full defaults).
#[derive(Debug, Clone, Default)]
pub struct SessionOptions {
    pub global: GlobalOptions,
}

/// getGlobalOption echo table (values are always strings, the aria2
/// getGlobalOption shape; `RpcMethodImpl.cc`). Keys come from two
/// sources: (1) the declaration-table echo-bit projection
/// ([`GLOBAL_PATCH_TABLE`] rows with `face.echo` registered — the echo
/// value shape for the changeGlobalOption acceptance domain is
/// registered in the same table as the acceptance arm); (2) the
/// hand-written section of this function (echoes of session fields
/// outside the hot-reload domain). `rpc-secret` is explicitly excluded —
/// same as the PREF_RPC_SECRET removal branch in `RpcMethodImpl.cc`.
pub fn global_option_echo(g: &GlobalOptions) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("dir".into(), g.dir.display().to_string());
    m.insert(
        "bt-detach-seed-only".into(),
        g.bt_detach_seed_only.to_string(),
    );
    m.insert("seed-ratio".into(), format_seed_ratio(g.seed_ratio));
    m.insert("seed-time".into(), format_minutes(g.seed_time_min));
    m.insert("bt-max-peers".into(), g.bt_max_peers.to_string());
    // aria2 getGlobalOption full echo face (all four are in the
    // reference option table; value shape = frozen string face).
    m.insert("listen-port".into(), g.listen_port.to_string());
    m.insert("bt-require-crypto".into(), g.bt_require_crypto.to_string());
    m.insert(
        "bt-min-crypto-level".into(),
        crypto_level_str(g.bt_min_crypto_level).into(),
    );
    m.insert(
        "bt-peer-connection-type".into(),
        peer_connection_type_str(g.bt_peer_connection_type).into(),
    );
    // http-max-per-host echo = the option-face value (taiji extension;
    // default 64). The live getGlobalOption face is overridden by the
    // actor GetGlobalOption arm with the effective cap value
    // (HostCap::cap), so the echo does not drift after a runtime addUri
    // adjustment (last-set-wins); this function's value is the spawn-time
    // fallback (same source as the HostCap initialization).
    m.insert("http-max-per-host".into(), g.http_max_per_host.to_string());
    // Media family echo (unified registration; canonical string
    // forms — the parse faces' single source stays taiji-media).
    m.insert(
        "media-variant-policy".into(),
        g.media_variant_policy.clone(),
    );
    m.insert(
        "media-audio-lang".into(),
        g.media_audio_lang.clone().unwrap_or_default(),
    );
    m.insert("media-subtitles".into(), g.media_subtitles.clone());
    m.insert(
        "media-segment-concurrency".into(),
        g.media_segment_concurrency.to_string(),
    );
    m.insert(
        "media-staging-quota-gib".into(),
        g.media_staging_quota_gib.to_string(),
    );
    m.insert(
        "media-staging-dir".into(),
        g.media_staging_dir.clone().unwrap_or_default(),
    );
    m.insert(
        "media-allow-private-key-url".into(),
        g.media_allow_private_key_url.to_string(),
    );
    m.insert("media-ffmpeg-path".into(), g.media_ffmpeg_path.clone());
    m.insert("media-archive".into(), g.media_archive.to_string());
    m.insert("media-info-json".into(), g.media_info_json.to_string());
    // save-session: aria2 echoes the path verbatim; unset = empty
    // string.
    m.insert(
        "save-session".into(),
        g.save_session
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
    );
    // bt-tracker echo = the global import set joined by commas (value
    // face = effective face; union-cumulative semantics in the field
    // docs); empty set = empty string (aria2's unset echo shape).
    m.insert("bt-tracker".into(), g.bt_tracker.join(","));
    // bt-tracker-file echo = the last-set path; unset = empty string.
    m.insert(
        "bt-tracker-file".into(),
        g.bt_tracker_file
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
    );
    // NAT switch echo (value shape = "true"/"false" strings; default
    // false = zero behavior change by default — the libtorrent
    // default-true contrast is in the field docs). Startup-only option:
    // changeGlobalOption does not accept them (same rule as
    // listen-port).
    m.insert("bt-enable-upnp".into(), g.bt_enable_upnp.to_string());
    m.insert("bt-enable-nat-pmp".into(), g.bt_enable_natpmp.to_string());
    // peer-id-prefix echo (an aria2 option-table entry — the reference
    // getGlobalOption echoes it too; default `-TJ0001-`; startup-only
    // option, changeGlobalOption does not accept it — apply_global_patch
    // has no key for it).
    m.insert("peer-id-prefix".into(), g.peer_id_prefix.clone());
    // summary-interval echo (reference option-table entry — prefs.cc;
    // value shape = decimal seconds string; startup-only option,
    // changeGlobalOption does not accept it — apply_global_patch has no
    // arm, capability bits aligned with the reference).
    m.insert("summary-interval".into(), g.summary_interval.to_string());
    // DHT startup-group echo (reference option-table entries; the unset
    // dht-entry-point = the empty string — the aria2 NO_DEFAULT unset
    // shape; dht-message-timeout = the decimal seconds string, default
    // 10. Neither is changeGlobalOption-accepted — apply_global_patch has
    // no arm, capability bits aligned with the reference).
    m.insert(
        "dht-entry-point".into(),
        g.dht_entry_point.clone().unwrap_or_default(),
    );
    m.insert(
        "dht-message-timeout".into(),
        g.dht_message_timeout.to_string(),
    );
    // enable-peer-exchange echo (a reference option-table entry; default
    // true — the A2_V_TRUE default; the hot-reload value face projects
    // through the GLOBAL_PATCH_TABLE row).
    m.insert(
        "enable-peer-exchange".into(),
        g.enable_peer_exchange.to_string(),
    );
    // Hook option echo (unset = empty string, the aria2 getGlobalOption
    // shape; option names come from HookEvent::ALL, single source, no
    // drift).
    for ev in crate::hook::HookEvent::ALL {
        m.insert(
            ev.option_name().into(),
            g.hooks.command(ev).unwrap_or_default().to_string(),
        );
    }
    // rpc-user: echoed when set (the reference only strips
    // PREF_RPC_SECRET, RpcMethodImpl.cc); rpc-passwd is secret-class and
    // never enters the table.
    if let Some(u) = &g.rpc_user {
        m.insert("rpc-user".into(), u.clone());
    }
    // Declaration-table echo-bit projection: keys of the
    // changeGlobalOption acceptance domain (max-concurrent family / limit
    // family / dht family / bt-lsd / ban lists / hook gate / load-cookies
    // — value-shape functions registered in the same table as the
    // acceptance arms, single-point maintenance).
    for decl in GLOBAL_PATCH_TABLE {
        if let Some(echo) = decl.face.echo {
            m.insert(decl.name.into(), echo(g));
        }
    }
    m
}

/// Option value string for `CryptoLevel` (SPEC §11 domain plain|arc4;
/// the OptionHandler value face of aria2 `--bt-min-crypto-level`).
pub fn crypto_level_str(l: taiji_bt::mse::CryptoLevel) -> &'static str {
    match l {
        taiji_bt::mse::CryptoLevel::Plain => "plain",
        taiji_bt::mse::CryptoLevel::Arc4 => "arc4",
    }
}

// ---- aria2 option diff surface (per-option diff declarations) ----
//
// Governance: a full diff under a whitelist. Every accepted/echoed name
// below is either a literal aria2 `src/prefs.cc` `makePref("<name>")`
// name (see [`ARIA2_OPTION_NAMES`]; the reference checkout is read-only
// and CI does not depend on it) or must be declared in
// [`DECLARED_OPTION_DIFFS`] (accepted-face extension; grows only via PR
// + user approval). Semantic redefinitions (same name, different
// meaning) do not enter the whitelist table — each is declared at its
// parse/echo points.
//
// Semantic diff declarations (per-option summary):
// - `split`/`min-split-size`/`max-connection-per-server` (semantic
// redefinitions, accepted and effective): accepted across the
// addUri/CLI/changeOption chains; under the dynamic scheduler,
// split/min-split-size only seed the initial extent (the connection
// ring growth cap = max-connection-per-server, slow-start AIMD — aria2
// uses a static concurrency count); under the static scheduler they
// are the split count / minimum segment length. On the BT option face
// max-connection-per-server maps to the bt-max-peers slot; the HTTP
// task face uses it as the AIMD growth cap (domain 1..=16, out-of-range
// rejected).
// - `max-tries`: semantic redefinition = per-extent retries (aria2:
// per-URI contact).
// - `ca-certificate`: task-level PEM CA file — REPLACES the platform
// trust store (aria2 replace semantics), effective for HTTPS/FTPS.
// Two tightenings: parse-time path/PEM validation (a bad path/bad PEM =
// `taiji.option.invalid` task rejection) and the PEM `CERTIFICATE`
// value domain. `--check-certificate=false` wins when both are set
// (aria2 same).
// - `bt-tracker`: semantics tightened to union-cumulative import (aria2
// rewrites the per-task announce table).
// - `--continue`: declared inverted semantics (always resumes; false
// does not discard progress, a warning discloses it). Since the Motrix
// alignment batch, changeGlobalOption also accepts it — as a no-op
// value face (the Motrix engine-supervisor sends it post-ready; the
// value does not affect the always-resume behavior).
// - Motrix frontend alignment batch (extracted from the frontend's
// changeGlobalOption/changeOption call sites — engine-supervisor /
// completed-task-startup-guard / tracker-manager / set-selected-files /
// aria2-adapter): the acceptance face gains dir/seed-ratio/bt-enable-lpd
// (wired rows — the values land in existing engine-consumed fields) +
// bt-max-peers (a typed value face; the engine connection cap is a
// taiji-engine constant seam — wired=false) + the no-op value-face
// segment (split/min-split-size/max-connection-per-server/user-agent/
// connect-timeout/timeout/max-tries/retry-wait/remote-time/async-dns/
// continue/pause/bt-exclude-tracker/all-proxy/https-proxy — DEPRECATED
// semantics, per-key reasons in the GLOBAL_PATCH_TABLE row notes) +
// per-task bt-tracker (parse-accepted, the consume arm lives in the
// actor — wired=false; the native equivalent is taiji.addTracker/
// removeTracker).
// - max/proxy/dht/enable-family adjudication (aria2 1.37.0
// OptionHandlerFactory.cc capability bits verified one by one): the
// acceptance face gains enable-peer-exchange (a typed hot-reload row —
// the EngineConfig.peer_exchange gate) + dht-entry-point/
// dht-message-timeout (startup-only session fields + echo — injected
// into DhtWireConfig/DhtEngineConfig at activation). The no-op value
// face = max-download-result/max-file-not-found/max-resume-failure-tries/
// max-mmap-limit/enable-async-dns6 (wired=false, per-key reasons in
// the row notes). Declared non-accepted = dht-listen-port (DHT and BT
// share one socket demux; the port belongs to --listen-port) and
// dht-file-path (DHT persistence = the taiji.sqlite3 dht_state table,
// the single primary store).
// - Domain 2 (proxy slotting + HTTP knobs): `https-proxy`/`referer`/
// `http-accept-gzip` are accepted on the per-task HTTP runtime face —
// https-proxy = the HTTPS-dedicated proxy slot (effect order =
// dedicated slot > all-proxy > no proxy; socks forms rejected like
// all-proxy), referer = carried on every probe/fetch hop
// (`RequestCtx.referer`; aria2 only affects the first request — an
// extension), http-accept-gzip = true stops sending
// `Accept-Encoding: identity` (transparent decompression; the probe
// face downgrades to a single connection on a non-identity encoding).
// - `--all-proxy`: socks5(h)/socks4(a) explicitly rejected (the reqwest
// socks feature is not enabled — a declared limitation).
// - `--load-cookies`: accepted (Netscape cookie file path, aria2 same
// name and meaning). Three entry points = addUri per-task options +
// the changeGlobalOption global face + the CLI `taiji http` flag;
// fail-closed loading (missing/unreadable/>1MiB =
// `taiji.option.invalid` task rejection). Effect = pre-filling the
// task CookieStore (taiji-http `CookieStore::seed`).
// - `select-file`: aria2 INITIAL + reserved-change bits; 1-based/
// comma+closed-range syntax, domain 1..=1048576. Acceptance =
// addTorrent / addUri(magnet) options / changeOption Reserved.
// Internal data face = 0-based `cfg.selected_files`. Three
// tightenings: known-key invalid values are explicitly rejected with
// `taiji.option.invalid`; changeOption on Active tasks is explicitly
// rejected; coexistence with the magnet `so=` face is an explicit
// conflict rejection.
// - getGlobalOption echo face = the Phase A promised subset + this
// whitelist (aria2 echoes the full table — the declared divergence
// direction).
//
// The per-option diff declarations (HTTP/FTP/SFTP/metalink stances and
// method-level diffs) live in docs/design/core.md
// ("session/options.rs").

/// The aria2 option-name reference face (names involved in this crate's
/// acceptance/echo faces; source = literal `makePref` names from the
/// reference `src/prefs.cc`, read-only cross-check). Tests pin: names not
/// in this table must not appear on any option acceptance/echo face
/// unless declared in [`DECLARED_OPTION_DIFFS`] (accepted-face extension)
/// or [`DECLARED_NON_ACCEPTED_OPTION_NAMES`] (non-acceptance
/// declaration).
///
/// Public export (single declaration source): diff tests and new-option
/// acceptance outside core (the taiji-rpc seam, the taiji CLI
/// face) consume this table directly for subset checks.
pub const ARIA2_OPTION_NAMES: &[&str] = &[
    // Global/task-common (getGlobalOption echo + parse_task_options).
    "dir",
    "out",
    "pause",
    "seed-ratio",
    "seed-time",
    "bt-max-peers",
    "max-download-limit",
    "max-upload-limit",
    "bt-save-metadata",
    "bt-metadata-only",
    "follow-torrent",
    "pause-metadata",
    "bt-load-saved-metadata",
    // BEP53 selection face (reference prefs.cc `makePref("select-file")`;
    // accepted via addTorrent/addUri(magnet) INITIAL + changeOption
    // reserved; the three tightenings are in the select-file diff
    // declaration, docs/design/core.md).
    "select-file",
    "bt-enable-hook-after-hash-check",
    "max-concurrent-downloads",
    "max-overall-download-limit",
    "max-overall-upload-limit",
    // The max-family seam-less no-op value faces (wired=false — row notes
    // in GLOBAL_PATCH_TABLE; each name cross-checked against the
    // reference prefs.cc `makePref` literals).
    "max-download-result",
    "max-file-not-found",
    "max-resume-failure-tries",
    "max-mmap-limit",
    "enable-dht",
    "enable-dht6",
    // The PEX gate (aria2 PREF_ENABLE_PEER_EXCHANGE; a typed hot-reload
    // row + echo, wired to EngineConfig.peer_exchange).
    "enable-peer-exchange",
    // The DHT startup group (entry-point/message-timeout — session fields
    // echoed + the CLI/conf face; no changeGlobal arm, capability bits
    // aligned with the reference).
    "dht-entry-point",
    "dht-message-timeout",
    // The DNS resolution shape switch (reference prefs.cc
    // `makePref("async-dns")`; accepted as a no-op value face — the
    // Motrix engine-supervisor actually sends it; taiji's resolver
    // behavior is fixed, no wiring seam; the value face echoes via the
    // GLOBAL_PATCH_TABLE no-op row).
    "async-dns",
    // The async-dns6 shape switch (reference prefs.cc same-name entry; on
    // the aria2 side it is wrapped by a DeprecatedOptionHandler —
    // OptionHandlerFactory.cc "TODO Deprecated". Accepted as a
    // no-op value face: taiji's resolver behavior is fixed, no v6
    // resolver switch seam; row note in GLOBAL_PATCH_TABLE).
    "enable-async-dns6",
    "bt-detach-seed-only",
    "listen-port",
    "bt-require-crypto",
    "bt-min-crypto-level",
    // The exclusion face for the globally imported tracker set (reference
    // prefs.cc `makePref("bt-exclude-tracker")`; accepted as a no-op
    // value face — the Motrix tracker-manager always sends an empty
    // string placeholder; taiji's global import has no exclusion face;
    // echoed via the GLOBAL_PATCH_TABLE no-op row).
    "bt-exclude-tracker",
    // The aria2 frozen name of the LSD switch (reference prefs.cc
    // `makePref("bt-enable-lpd")`; the acceptance half of the rename
    // declaration paired with bt-lsd — the Motrix applyEngineSettings
    // sends this name; the GLOBAL_PATCH_TABLE alias row writes the same
    // g.bt_lsd slot as bt-lsd, wired=true).
    "bt-enable-lpd",
    "save-session",
    "bt-tracker",
    "peer-id-prefix",
    "rpc-user",
    // Hook notification command family (echo face projected through
    // HookEvent::ALL, single source; each name cross-checked against
    // prefs.cc — consistency tests lock the two together).
    "on-download-start",
    "on-download-pause",
    "on-download-stop",
    "on-download-complete",
    "on-download-error",
    "on-bt-download-complete",
    // HTTP task face (addUri per-task / CLI `taiji http`).
    "checksum",
    "remote-time",
    "timeout",
    "connect-timeout",
    "max-tries",
    "retry-wait",
    "user-agent",
    "header",
    "http-user",
    "http-passwd",
    "all-proxy",
    // Domain 2 extension (accepted on the per-task HTTP runtime face):
    // the HTTPS-dedicated proxy slot (effect order = dedicated slot >
    // all-proxy > no proxy — the reqwest two-slot projection) + the
    // Referer header (RequestCtx.referer) + the transparent gzip
    // decompression switch. Effect semantics in the domain-2 entries of
    // the semantic diff declaration block.
    "https-proxy",
    "referer",
    "http-accept-gzip",
    "check-certificate",
    // Task-level CA face (accepted; same-name reference entry, prefs.cc
    // `makePref("ca-certificate")`) — PEM CA file; the task-level root
    // REPLACES the platform trust store (aria2 replace semantics, not
    // append); effective for both HTTPS and FTPS; when
    // `--check-certificate=false` is also set, the latter wins (aria2
    // same). Diff stance: the ca-certificate entry in
    // docs/design/core.md.
    "ca-certificate",
    "split",
    "min-split-size",
    "max-connection-per-server",
    // FTP family (names cross-checked one by one against reference
    // prefs.cc; semantic diffs in docs/design/core.md).
    "ftp-user",
    "ftp-passwd",
    "ftp-pasv",
    "ftp-reuse-connection",
    // metalink family (names cross-checked one by one against reference
    // prefs.cc; accepted via CLI `--metalink-file` + the legacy family
    // ignored-with-warning at the addMetalink seam — diff declaration in
    // docs/design/core.md).
    "metalink-file",
    "metalink-language",
    "metalink-location",
    "metalink-os",
    "metalink-version",
    "metalink-preferred-protocol",
    "metalink-enable-unique-protocol",
    // Resume switch (reference prefs.cc same-name entry; declared
    // inverted semantics — this build always resumes; false does not
    // discard progress and a warning discloses it. Accepted via the CLI
    // `--continue` flag +, since the Motrix alignment batch,
    // changeGlobalOption too (the Motrix engine-supervisor sends it
    // post-ready) — as a no-op value face: the value does not affect the
    // always-resume behavior; echoed via the GLOBAL_PATCH_TABLE no-op
    // row).
    "continue",
    // Cookie file ingestion gate (reference prefs.cc same-name entry,
    // `makePref("load-cookies")`): Netscape file path, aria2 same name
    // and meaning. Accepted via addUri per-task options (read directly in
    // add_uri) + changeGlobalOption global face
    // (GlobalOptions.load_cookies) + CLI `taiji http --load-cookies`;
    // effect = pre-filling the task CookieStore. Migrated out of
    // DECLARED_NON_ACCEPTED_OPTION_NAMES (diff declaration: the
    // load-cookies entry in docs/design/core.md).
    "load-cookies",
    // Periodic task summary log interval in seconds (reference prefs.cc
    // `makePref("summary-interval")`; default 60, domain 0..INT32_MAX,
    // 0 = disabled — anchored to `OptionHandlerFactory.cc`
    // `NumberOptionHandler(..., "60", 0, INT32_MAX)` to prevent invented
    // domains). Capability bits aligned with the reference: the factory
    // sets no setChangeOption/setChangeGlobalOption (the handler has no
    // change* capability calls), so changeOption/changeGlobalOption do
    // not accept it; effect = the CLI/session initial value
    // (startup-only option, takes effect on restart).
    "summary-interval",
    // Four tracker keys (names cross-checked one by one against
    // reference prefs.cc; domain/default anchors in the
    // GLOBAL_PATCH_TABLE row notes — tracker-interval default 0,
    // tracker-timeout/connect-timeout 60 with domain 1..=600,
    // stop-timeout 0).
    "bt-tracker-interval",
    "bt-tracker-timeout",
    "bt-tracker-connect-timeout",
    "bt-stop-timeout",
];

/// `--summary-interval` default (seconds; the reference
/// `OptionHandlerFactory.cc` third parameter "60", the single anchor).
pub const SUMMARY_INTERVAL_DEFAULT: u32 = 60;

/// `--summary-interval` domain upper bound (the reference
/// `OptionHandlerFactory.cc` fourth parameter INT32_MAX; lower bound 0 =
/// summary logging disabled).
pub const SUMMARY_INTERVAL_MAX: u32 = i32::MAX as u32;

/// `--dht-message-timeout` default (seconds; the reference
/// `OptionHandlerFactory.cc` handler third parameter "10", the single
/// anchor — the same value as the taiji-bt `DHT_MESSAGE_TIMEOUT`, so the
/// default is a zero change).
pub const DHT_MESSAGE_TIMEOUT_DEFAULT_SECS: u64 = 10;

/// `--dht-message-timeout` domain (the reference handler fourth/fifth
/// parameter 1..=60 anchors; no invented domains).
pub const DHT_MESSAGE_TIMEOUT_MIN_SECS: u64 = 1;
pub const DHT_MESSAGE_TIMEOUT_MAX_SECS: u64 = 60;

/// Option-face diff declaration list (**whitelist**; accepted/echoed
/// names not in [`ARIA2_OPTION_NAMES`] are declared here one by one;
/// grows only via PR + user approval). `(name, declaration basis)`.
/// Public export (single declaration source) — consumed directly by the
/// seam/CLI diff tests.
pub const DECLARED_OPTION_DIFFS: &[(&str, &str)] = &[
    // Renamed pair (an aria2 synonym option name).
    (
        "bt-lsd",
        "renamed: aria2 `--bt-enable-lpd` (prefs.cc) — carried over from the Phase A promised surface",
    ),
    // Per-task DHT flag: a libtorrent `torrent_flags::disable_dht`
    // capability-alignment extension (aria2 has no per-torrent DHT face —
    // the fork's DHTRegistry is a global singleton with no torrent_handle
    // flag face). bool value face, default follows the session
    // `enable-dht`; task-level override + live effect on active tasks
    // (engine SetDhtEnabled live arm + the existing changeOption restart
    // semantics as fallback). The private flag is not overridden (BEP27
    // hard gate; the engine's SetDhtEnabled refuses).
    (
        "bt-disable-dht",
        "extension: per-task DHT flags (no aria2 counterpart; aligned with the libtorrent capability —\
         torrent_flags::disable_dht, torrent.cpp)",
    ),
    // Per-task webseeding switch (the BEP19 url-list consumption gate):
    // aria2 has no such switch (url-list is always used, no switch face)
    // — a Motrix extension. bool value face, default true = the metainfo
    // url-list projection proceeds; false = clear the webseed set on
    // activation (BT-only shape, the url-list original is kept — lossless
    // to re-enable). Effective through the engine activation chain
    // (build_engine_config / the magnet upgrade chain clear at the same
    // point); already-active tasks take effect via the changeOption
    // restart re-activation.
    (
        "enable-http-seeding",
        "extension: BEP19 webseeding switch (no aria2 counterpart — url-list always applies;\
         off = clear the webseed set, the task stays on the BT face)",
    ),
    // bt-sequential-download: the aria2 same-name option is accepted,
    // but the semantics = a scheduling-policy projection (authority =
    // taiji.setSchedulerPolicy — true/false projects
    // sequential/rarest_first, with both entry points echoing
    // consistently; aria2 stores it as an independent option, taiji keeps
    // the policy as the single truth — projection-face diff declared).
    (
        "bt-sequential-download",
        "projection: the aria2-compatible option key for the sequential scheduler policy (authority = \
         taiji.setSchedulerPolicy; the echo projects from the task policy)",
    ),
    // Motrix/taiji extension entries (aria2 has no such option).
    (
        "bt-tracker-file",
        "extension: ngosang/trackerslist import (no aria2 option; Phase A promised surface)",
    ),
    (
        "bt-peer-connection-type",
        "extension (fork legacy name): MSE/connection-type value domain plain|arc4 family (no aria2 option name)",
    ),
    (
        "bt-enable-upnp",
        "extension: NAT provisioning face (aria2 has no UPnP; the libtorrent default-true comparison is noted)",
    ),
    (
        "bt-enable-nat-pmp",
        "extension: NAT provisioning face (aria2 has no NAT-PMP)",
    ),
    (
        "max-connection",
        "extension: Motrix UX alias onto the bt-max-peers slot (Phase A declared surface)",
    ),
    (
        "client-ban-prefixes",
        "extension: client-ban rule face (no aria2 counterpart)",
    ),
    (
        "bt-metadata-web-sources",
        "extension: magnet web-mirror template (no aria2 counterpart)",
    ),
    (
        "http-incomplete-suffix",
        "extension: configurable incomplete-name (aria2 always uses the `.aria2` control-file naming)",
    ),
    (
        "http-max-per-host",
        "extension: per-host connection cap (default 64 — benchmarked: cap 64 gave -38% on many-small,\
         -27%..-40% on injection, zero regression on tuned; promoted to default 2026-09-22;\
         no aria2 option). Two channels: session HostCap initialization\
         (GlobalOptions.http_max_per_host, injected via the CLI/global option face)\
         + a runtime addUri option adjustment (last-set-wins, the task-level override\
         wins over the initialization value)",
    ),
    (
        "http-stall-window",
        "extension: stall-steal detection window (default 15s, domain >=3s = \
         several heartbeat periods; no aria2 option — dynamic-scheduling extension)",
    ),
    (
        "http-scheduler",
        "extension: scheduler mode dynamic|static (default dynamic — guided \
         self-scheduling + AIMD; static = fixed-split comparison/fallback.\
         No aria2 scheduler-mode option — dynamic-scheduling extension)",
    ),
    (
        "http-block-size",
        "extension: block-grid granularity (default 4MiB; a power of two in 256KiB..16MiB,\
         immutable per task. No aria2 block-grid concept — dynamic-scheduling extension)",
    ),
    (
        "http-max-chunk",
        "extension: guided extent cap (default 32MiB; >= the effective block granularity.\
         No aria2 guided-extent concept — dynamic-scheduling extension)",
    ),
    (
        "http-protocol",
        "extension + experimental window: protocol form auto|h1|h2. auto (default) = the ruled current state:\
         plaintext h1 plus rustls ALPN negotiation with h2/h1 fallback on https — behavior unchanged;\
         h1 = http1_only, upgrade paths shut off; h2 = HTTP/2 prior knowledge, h2c on plaintext\
         endpoints, no Upgrade and no fallback, fails outright against h1-only peers —\
         experimental-window semantics. No aria2 protocol-selection option — capability extension)",
    ),
    (
        "http2-adaptive-window",
        "extension + experimental window: h2 adaptive flow-control window, default false = the static\
         engine default windows (8MiB per stream / 16MiB per connection) — the hyper crate defaults\
         (2MiB/5MiB) are reachable only via the programmatic None path; true = the window grows\
         dynamically from ping/BDP estimates, hedging the long-fat-pipe ~2MiB/RTT single-stream\
         ceiling. Takes effect on the h2 transport only. No aria2 window option — capability extension)",
    ),
    (
        "http2-stream-window",
        "extension + experimental window: h2 stream-level initial window in bytes,\
         domain 65535..=2^31-1 per the RFC 7540 §5.2.2 ceiling; default = the engine default 8MiB.\
         Single-stream throughput <= window/RTT. No aria2 window option — capability extension)",
    ),
    (
        "http2-connection-window",
        "extension + experimental window: h2 connection-level initial window, same domain,\
         shared across streams; default = the engine default 16MiB. Affects only the unthrottled\
         full-speed path — throttled backpressure semantics are unchanged.\
         No aria2 window option — capability extension)",
    ),
    (
        "http2-max-connections",
        "extension + experimental window: h2 per-origin connection cap, default 1 = the current\
         single-connection multiplexed state; domain 1..=8 — K independent transport instances\
         with round-robin request spread on the data plane, each counted toward --http-max-per-host;\
         inert when negotiation lands on h1. No aria2 counterpart — capability extension)",
    ),
    (
        "http2-keep-alive-interval",
        "extension + experimental window: h2 PING keepalive interval in seconds, default 0 = off =\
         the hyper status quo; domain 0..=3600 — liveness probes for pooled idle connections,\
         timeout = 2x the interval, guarding tail latency from silently-dropped dead connections\
         behind middleboxes. No aria2 counterpart — capability extension)",
    ),
    (
        "http-batch-budget",
        "extension: same-host transient batch-group connection budget (default 16, domain 2..=64,\
         unit = connections — an aggregate budget across files in the group. Three caps compose:\
         a single file's intent min(split, cap) is never amplified; with >=2 active files in the\
         group the group aggregate stays <= this budget (exception: work-conserving overflow when\
         the per-host cap has idle slots); batch-group connections count fully toward\
         --http-max-per-host (shared across tasks). No aria2 batch-group concept —\
         dynamic-scheduling extension)",
    ),
    (
        "ftp-ssl",
        "extension: FTPS TLS mode none|auth|implicit (aria2 \
         has no FTPS capability and no such option name — capability extension; the ftps://\
         scheme rejection shares the declaration)",
    ),
    (
        "ftp-pasv-address-check",
        "extension: PASV/EPSV data-connection address adjudication, three states peer|strict|off \
         (default peer = the SSRF-hardened aligned state, i.e. aria2 FtpNegotiationCommand.cc \
         preparePasvConnect's hard-wired behavior; strict = adopt the reply IP but refuse\
         private/loopback/link-local addresses that differ from the control peer; off = use the\
         227 reply verbatim as the dial target — the adjudication face is disabled wholesale,\
         opt-in for trusted networks only. No aria2 option name — capability extension)",
    ),
    (
        "metalink-enable-auto-discover",
        "accepted but treated as invalid (true = ignored with a warning): auto-converting an\
         HTTP response into a metalink is not done in 0.2 (absent from aria2 1.37.0 —\
         its semantic face is --follow-metalink, see the non-accepted declaration table)",
    ),
    (
        "metalink-force-protocol",
        "accepted and ignored with a warning: a legacy metalink-family inventory name;\
         absent from aria2 1.37.0 prefs.cc — a historical entry, re-verified against the\
         fork in the differential audit",
    ),
    // ---- Domain 5: metalink selector CLI face + behavior misc (the
    // taiji CLI seam; acceptance = the CLI top-level face / the
    // `taiji http` metalink shape — the RPC/session faces do not accept
    // them, so the addMetalink/changeGlobalOption seam semantics are
    // unchanged).
    (
        "metalink-servers",
        "extension: per-entry mirror count cap (accepted on the CLI \
         `taiji http` metalink shape — the entry `<url>` set is \
         pre-sorted by ascending priority and truncated to the first N. \
         aria2 1.37.0 has **no such option** (no makePref in prefs.cc; \
         only the usage_text.h TEXT_METALINK_SERVERS remnant) — the \
         historical `-C` name is accepted as a fork extension; the \
         RPC/session faces do not accept it)",
    ),
    (
        "stop",
        "accepted (the CLI top-level face): graceful shutdown after the \
         process has run for N minutes (the bare-run/download+RPC/idle \
         shapes share one face, 0 = disabled — aria2 same). **Unit \
         difference declared**: aria2 `--stop=SEC` (seconds, \
         usage_text.h TEXT_STOP); this build takes **minutes** (symmetric \
         with --seed-time)",
    ),
    (
        "hash-check-only",
        "accepted (the CLI top-level face, effective in the bare-run \
         download shape): fully re-check the on-disk pieces of existing \
         data before downloading (session::recheck_on_disk) and abort — \
         check only, no download; all pieces pass = exit 0, otherwise 1. \
         Together with `--enable-rpc` in the download shape = an explicit \
         rejection with exit 2 (the RPC pipeline has no per-task \
         pre-download recheck face; accepting it would violate the \
         \"no download\" promise — fail-closed); the idle daemon has no \
         task face and does not consume it. aria2 semantic anchor: \
         usage_text.h TEXT_HASH_CHECK_ONLY (the --check-integrity pair)",
    ),
    // ---- Media group (unified registration;
    // the P90-P93 flag family first-wired by their cards, mount-ready
    // parse faces; the values' single parse source = taiji-media's
    // option faces, the RPC/addMedia per-task subset consumes the same
    // tables) ----
    (
        "media-variant-policy",
        "extension: media variant selection policy highest|resolution=<H>|bandwidth=<B> (aria2 has no media face — capability extension; addMedia options project through the media-selector three-layer expression)",
    ),
    (
        "media-audio-lang",
        "extension: audio-track language policy, RFC 5646 prefix (match chain: prefix match -> DEFAULT -> en -> declaration order; aria2 has no media face — capability extension)",
    ),
    (
        "media-subtitles",
        "extension: subtitle face sidecar|none (default sidecar — the VTT sidecar product face; aria2 has no media face — capability extension)",
    ),
    (
        "media-segment-concurrency",
        "extension: per-task segment concurrency (default 8, domain 1..=64; aria2 has no media face — capability extension)",
    ),
    (
        "media-staging-quota-gib",
        "extension: staging quota in GiB (default 50, admission + watermark double-check; aria2 has no media face — capability extension)",
    ),
    (
        "media-staging-dir",
        "extension: staging root directory (default <dir>/.taiji-b on the same volume; aria2 has no media face — capability extension)",
    ),
    (
        "media-allow-private-key-url",
        "extension: SSRF defense private-network allowance (default false = deny; governs both key URIs and media segment/init URLs — a deliberately broadened scope; the name carries the early-draft era)",
    ),
    (
        "media-ffmpeg-path",
        "extension: ffmpeg discovery input auto|<dir>|path:<dir> (explicit PATH opt-in + warning; aria2 has no media face — capability extension)",
    ),
    (
        "media-archive",
        "extension: download-archive recording switch (default false; on = archive at Done with dual fingerprints + a dual-checkpoint duplicate-entry skip; cleared via the taiji.clearMediaArchive RPC / --media-archive-clear CLI; sensitivity = browsing-history-equivalent; no aria2 counterpart — taiji capability extension)",
    ),
    (
        "media-info-json",
        "extension: info.json whitelist export switch (default false; a field allowlist sharing the redact implementation, http_headers/cookies/token banned; --no-meta only disables the synthesis-embed face and is orthogonal to export; no aria2 counterpart — taiji capability extension)",
    ),
    // ---- Four-pool budget trio (the four-pool model, landed on the
    // acceptance/echo face; the internal fields + read-side accessors
    // predate this face — zero fields/accessors were added, the close-out
    // check held).
    // Row shape = max-concurrent-downloads: changeGlobalOption hot
    // reload, apply-side domain clamp, non-numeric = lenient ignore. ----
    (
        "max-concurrent-seeds",
        "extension: seeding-pool budget (the four-pool allocation model; default 16 [two-state\
         note — 0 = unlimited presumes the session-level connection budget; a temporary\
         convergence to 16 until it lands, then restored], domain 0..=4096, 0 = unlimited;\
         hot-reloadable via changeGlobalOption — widening reactivates parked seed_wait members\
         FIFO without ever routing through a download slot, and a narrowed budget never\
         preempts in-flight residents; no aria2 option — taiji capability extension)",
    ),
    (
        "max-concurrent-checks",
        "extension: verify-pool budget (the four-pool allocation model; default 2 = a conservative\
         pread+hash IO/CPU overlap value, domain 1..=16, no unlimited state; hot-reloadable via\
         changeGlobalOption — in-flight verification runs to completion, narrowing constrains\
         only subsequent admissions; no aria2 option — taiji capability extension)",
    ),
    (
        "media-synthesis-concurrency",
        "extension: media-synthesis-pool budget (the four-pool allocation model; default 2 = a\
         conservative ffmpeg-process weight, domain 1..=16, no unlimited state; layered with\
         media-segment-concurrency — that key governs the network phase, this one governs the\
         Processing/Verifying phases; hot-reloadable via changeGlobalOption — in-flight synthesis\
         runs to completion (a narrowed budget never preempts), and shares are not transferable;\
         no aria2 option — taiji capability extension)",
    ),
    (
        "peer-agent",
        "accepted but treated as invalid + a warning (the use-head \
         disclosure style): the BT client UA/ext-handshake `v` string is \
         pinned to a build constant in this build (taiji-bt \
         tracker::PEER_AGENT — PT risk control checks UA and peer id \
         against two independent whitelists; a configurable UA would \
         poison the identification face). **Not an alias of \
         --peer-id-prefix** (aria2 has two independent options in \
         OptionHandlerFactory.cc; this build keeps the same separation — \
         see the peer-id-prefix field note)",
    ),
];

/// Finalized declaration table of aria2 option names (reference
/// prefs.cc) that this crate does **not** accept — the per-option stance
/// list for the HTTP/metalink families (the in-repo anchor of the diff
/// declarations and one of the whitelist-check bases for the full diff).
/// `(name, declaration basis)`. Discipline:
/// - before any name enters the acceptance face it must first migrate
/// into [`ARIA2_OPTION_NAMES`]/[`DECLARED_OPTION_DIFFS`] with effect
/// semantics — "declared non-accepted yet accepted" is pinned red by
/// the diff tests (the two tables and the acceptance face are pairwise
/// disjoint);
/// - the table only holds aria2 reference names (literal prefs.cc
/// `makePref` names); taiji-named but unwired extensions live in
/// [`DECLARED_UNWIRED_OPTION_NAMES`].
pub const DECLARED_NON_ACCEPTED_OPTION_NAMES: &[(&str, &str)] = &[
    // Fixed HTTP transport behavior (keys not accepted — behavior stance
    // declarations). The three domain-2 names (referer/https-proxy/
    // http-accept-gzip) have migrated OUT of this table: they are accepted
    // on the per-task HTTP runtime face (registered in ARIA2_OPTION_NAMES;
    // effect semantics in the domain-2 entries of the semantic diff
    // declaration block above — their former "not accepted" stances are
    // retired with the migration).
    (
        "http-proxy",
        "not accepted: a single --all-proxy slot only (per-scheme proxy slots are out of scope for 0.2)",
    ),
    ("no-proxy", "not accepted: no per-host proxy exemption face"),
    (
        "http-proxy-user",
        "not accepted: proxy credentials ride the all-proxy URL userinfo",
    ),
    ("http-proxy-passwd", "not accepted: same as http-proxy-user"),
    ("https-proxy-user", "not accepted: same as http-proxy-user"),
    (
        "https-proxy-passwd",
        "not accepted: same as http-proxy-user",
    ),
    (
        "all-proxy-user",
        "not accepted: proxy credentials ride the URL userinfo",
    ),
    ("all-proxy-passwd", "not accepted: same as all-proxy-user"),
    (
        "proxy-method",
        "not accepted: the proxy request form is fixed (GET tunnel semantics)",
    ),
    // load-cookies has migrated to the accepted face (ARIA2_OPTION_NAMES;
    // effect semantics: the load-cookies entry in docs/design/core.md).
    (
        "save-cookies",
        "not accepted: out of scope for 0.2 (sqlite is the sole persistence source of truth; file export can be revisited on demand)",
    ),
    (
        "http-auth-challenge",
        "not accepted: auth behavior is fixed (Basic preemptive + Digest challenge-response always on)",
    ),
    (
        "http-no-cache",
        "not accepted: the cache-directive face is fixed",
    ),
    // The http-accept-gzip migration (accepted face = the per-task HTTP
    // runtime face) removed its former stance from this table.
    (
        "use-head",
        "not accepted: HEAD is not used as a probe method",
    ),
    (
        "enable-http-keep-alive",
        "not accepted: HTTP/1.1 keep-alive is always on (the connection pool is fixed)",
    ),
    (
        "enable-http-pipelining",
        "not accepted: no pipelining (superseded by the h1 connection pool + h2 multiplexing)",
    ),
    (
        "max-http-pipelining",
        "not accepted: same as enable-http-pipelining",
    ),
    (
        "allow-overwrite",
        "not accepted: always the false semantics (an existing target -> taiji.http.path_conflict, code 13)",
    ),
    (
        "auto-file-renaming",
        "not accepted: the key does not exist; engine-side creation always auto-renames (matching\
         the aria2 default true) — the aria2 false (fail on conflict) semantics is unreachable",
    ),
    (
        "lowest-speed-limit",
        "not accepted: a promised item left unwired in 0.2 — the dynamic-scheduling AIMD has no\
         per-source minimum-speed disconnect-and-reswitch semantics (the aria2 semantic =\
         disconnect below threshold); accepting it without effect would masquerade. It was\
         mistakenly registered on the acceptance face (zero consumers) and then migrated into\
         this table as the final stance, recorded in the differential audit",
    ),
    // Non-accepted metalink family names.
    (
        "follow-metalink",
        "not accepted: auto-converting an HTTP response into a metalink is not done (the taiji \
         face is --metalink-enable-auto-discover, accepted but treated as invalid — the seam-carry \
         declaration)",
    ),
    (
        "metalink-base-uri",
        "not accepted: no consumer for the relative-URI resolution base in 0.2",
    ),
    // DHT family non-accepted names (the max/proxy/dht/enable-family
    // adjudication: architectural difference declarations — not missed
    // wiring). Newly declared; the wording is intentionally English (a
    // newly ported declaration, not pre-existing data).
    (
        "dht-listen-port",
        "not accepted: taiji's DHT and BT listeners share one socket (a \
         single-port UDP demux face — the port semantics belong to \
         --listen-port); there is no seam for an independent DHT UDP port \
         range (accepting it would misrepresent the port face, so the \
         non-acceptance is declared instead)",
    ),
    (
        "dht-file-path",
        "not accepted: DHT routing-table persistence = the taiji.sqlite3 \
         dht_state table (the single primary store, the SPEC §8.2 \
         crash-recovery face); an independent dht.dat file has no \
         consumer",
    ),
    // Non-accepted FTP family names (kept in sync with the FTP diff
    // declaration in docs/design/core.md).
    ("ftp-type", "not accepted: TYPE I (binary) is constant"),
    (
        "ftp-proxy",
        "not accepted: FTP-over-HTTP proxy is a P2 item",
    ),
    ("ftp-proxy-user", "not accepted: same as ftp-proxy"),
    ("ftp-proxy-passwd", "not accepted: same as ftp-proxy"),
];

/// Declaration table for taiji-named extensions that are not yet wired
/// (keys are ignored as unknown — the reference's rule). Difference from
/// [`DECLARED_NON_ACCEPTED_OPTION_NAMES`]: these names are not aria2
/// reference names (no fork comparison stance, only a promise-face gap).
pub const DECLARED_UNWIRED_OPTION_NAMES: &[(&str, &str)] = &[(
    "http-min-chunk",
    "unwired: a named item (the effective min-chunk is always the block granularity, defaulting\
     to the same 4MiB) — the key is ignored like an unknown one; wiring grows with the\
     scheduling option face",
)];

/// Option diff-face registration helper: is the name on the aria2
/// reference face or in the acceptance whitelist (shared by the diff
/// tests and new-option acceptance).
pub fn option_name_declared(name: &str) -> bool {
    ARIA2_OPTION_NAMES.contains(&name) || DECLARED_OPTION_DIFFS.iter().any(|(n, _)| *n == name)
}

/// Is the name in any declaration table (acceptance whitelist ∪
/// non-acceptance declarations ∪ unwired declarations) — the total check
/// entry for "every face name has a declared stance" (consumed by the
/// CLI/seam diff tests).
pub fn option_name_has_declaration(name: &str) -> bool {
    option_name_declared(name)
        || DECLARED_NON_ACCEPTED_OPTION_NAMES
            .iter()
            .any(|(n, _)| *n == name)
        || DECLARED_UNWIRED_OPTION_NAMES
            .iter()
            .any(|(n, _)| *n == name)
}

// ---- Option declaration tables (row types and classification bits for
// table-driven parsing; new options register in one place) ----
//
// Each declaration-table entry = option name + classification bits
// ([`OptionFace`]) + a parse/validate write arm ([`OptionDecl::apply`]).
// Parse points (`parse_task_options`, `apply_global_patch`, and the three
// actor HTTP task-domain chains) only execute the tables — adding an
// option means adding a table row + the matching accepted-name mirror
// constant (cfg(test), governance tests pin the tables), not editing
// match arms in several places. Special options that cannot be
// table-driven per key keep an explicit arm but must register a manual
// arm row (`apply = None`; dynamic name-set rows also carry an
// [`OptionDecl::manual_match`] predicate); governance tests verify the
// registration is complete.

/// Classification bits of a declaration-table entry (the stance is
/// registered bit by bit; each field's doc describes its production and
/// consumption faces — governance tests verify each bit against the real
/// registration).
#[derive(Debug, Clone, Copy)]
pub(crate) struct OptionFace {
    /// Accepted bit: the row participates in parse execution (the
    /// table-driven arm / manual arm / explicit-rejection arm consumes
    /// the key). false = a registration-only row (declares a stance, the
    /// parse face skips it entirely; apply is always None).
    pub accepted: bool,
    /// Persist bit: the value persists with the task row (HTTP task
    /// domain = the persist parse-face dispatch bit; BT task domain = a
    /// stance registration on the task-creation payload, with no dispatch
    /// consumer in that domain).
    pub persist: bool,
    /// Runtime bit: the value belongs to the live runtime face and is not
    /// stored (HTTP task domain = the runtime parse-face dispatch bit;
    /// session global domain = the changeGlobalOption hot-reload dispatch
    /// bit — non-hot-reload registration rows are not accepted; the
    /// scheduler increment domain = changeable while running).
    pub runtime: bool,
    /// Echo bit: the key is registered on the getGlobalOption echo face
    /// (`global_option_echo` projects the value from this bit — `Some` =
    /// echoed and carrying the value-shape function; only session-global
    /// rows carry it, HTTP/BT rows are always None — the getOption
    /// projection face lives in the actor commands hand-written section,
    /// not in this bit).
    pub echo: Option<fn(&GlobalOptions) -> String>,
    /// Fold bit (HTTP task domain): consumed by `fold_imported_options` —
    /// import restores the key verbatim (dispatch bit; runtime rows fold
    /// into the request-identity domain, persist rows fold into the row
    /// payload).
    pub import_fold: bool,
    /// Cumulative bit (HTTP task domain, a subset of the fold bit): the
    /// same key with multiple values joins them in order with "\n" into
    /// one value (the aria2 multi-header value shape); false = the later
    /// value overwrites (scalar keys).
    pub cumulative: bool,
}

impl OptionFace {
    /// Base bits for the BT task-creation payload face (accepted; fixed
    /// with the task payload at add time).
    pub(crate) const fn task_payload() -> Self {
        OptionFace {
            accepted: true,
            persist: true,
            runtime: false,
            echo: None,
            import_fold: false,
            cumulative: false,
        }
    }

    /// Base bits for the session-global hot-reload face (accepted +
    /// changeGlobalOption hot-reload dispatch; the echo bit is layered on
    /// by [`Self::echoing`]).
    pub(crate) const fn session_runtime() -> Self {
        OptionFace {
            accepted: true,
            persist: false,
            runtime: true,
            echo: None,
            import_fold: false,
            cumulative: false,
        }
    }

    /// Base bits for the HTTP task persist face (accepted + persist
    /// parse-face dispatch).
    pub(crate) const fn http_persist() -> Self {
        OptionFace {
            accepted: true,
            persist: true,
            runtime: false,
            echo: None,
            import_fold: false,
            cumulative: false,
        }
    }

    /// Base bits for the HTTP task runtime face (accepted + runtime
    /// parse-face dispatch; not stored, recovery uses session defaults).
    pub(crate) const fn http_runtime() -> Self {
        OptionFace {
            accepted: true,
            persist: false,
            runtime: true,
            echo: None,
            import_fold: false,
            cumulative: false,
        }
    }

    /// Layer on the echo bit (value-shape function; consumed by the
    /// `global_option_echo` projection).
    pub(crate) const fn echoing(mut self, echo: fn(&GlobalOptions) -> String) -> Self {
        self.echo = Some(echo);
        self
    }

    /// Layer on the fold bit (consumed by the fold_imported_options
    /// dispatch; spans the runtime/persist faces — the dispatch follows
    /// the face).
    pub(crate) const fn folding(mut self) -> Self {
        self.import_fold = true;
        self
    }

    /// Layer on the cumulative bit (multiple values joined with "\n";
    /// consumed by the fold_imported_options join semantics).
    pub(crate) const fn accumulating(mut self) -> Self {
        self.cumulative = true;
        self
    }
}

/// A declaration-table entry (one row type across all domains; the
/// `apply` arm type is instantiated per domain — static tables drive the
/// parse points).
pub(crate) struct OptionDecl<A> {
    /// Option name (frozen kebab name; a dynamic name-set manual arm row
    /// carries a name-set description string).
    pub name: &'static str,
    /// Classification bits (field semantics in [`OptionFace`]).
    pub face: OptionFace,
    /// Table-driven parse write arm; `None` = a manual-arm registration
    /// row (the body lives in the explicit section of this domain's parse
    /// function — cross-key combination semantics or dynamic name sets
    /// cannot be table-driven per key).
    pub apply: Option<A>,
    /// Manual-arm dynamic-name match predicate (dynamic name-set rows
    /// only; static-name rows are always None).
    pub manual_match: Option<fn(&str) -> bool>,
}

impl<A> OptionDecl<A> {
    /// Table-driven arm row constructor (const — for static declaration
    /// table initialization).
    pub(crate) const fn table_row(name: &'static str, face: OptionFace, apply: A) -> Self {
        OptionDecl {
            name,
            face,
            apply: Some(apply),
            manual_match: None,
        }
    }

    /// Manual-arm registration row constructor (dynamic name set; the
    /// body lives in the parse function's explicit section — `apply` is
    /// always None, registration completeness is pinned by governance
    /// tests).
    pub(crate) const fn manual_row(
        name: &'static str,
        face: OptionFace,
        matches: fn(&str) -> bool,
    ) -> Self {
        OptionDecl {
            name,
            face,
            apply: None,
            manual_match: Some(matches),
        }
    }
}

/// Parse/write arm type for the task-patch domain (a declaration-table
/// instantiation alias).
type TaskPatchApply = fn(&mut TaskOptionPatch, &str);

/// Parse/write arm type for the session-global hot-reload domain (a
/// declaration-table instantiation alias).
type GlobalPatchApply = fn(&mut GlobalOptions, &str);

/// Per-task common option declaration table (parse point =
/// [`parse_task_options`], table-driven; each row = an accepted name +
/// task-creation payload bits + a parse write arm. Invalid values are
/// ignored inside the arm — the reference's "unacceptable options
/// ignored" rule, consistent with this domain having no error return).
/// Manual arm = the six hook command family (a dynamic name set via
/// `HookEvent::from_option_name`, single source, impossible to enumerate
/// statically — registered with [`OptionDecl::manual_row`], body in the
/// [`parse_task_options`] explicit section). Accepted-name mirror =
/// [`TASK_OPTION_NAMES`] (cfg(test); governance tests pin the table).
static TASK_OPTION_TABLE: &[OptionDecl<TaskPatchApply>] = &[
    OptionDecl::table_row("dir", OptionFace::task_payload(), |p, v| {
        p.dir = Some(PathBuf::from(v));
    }),
    // pause: invalid values are ignored and fall back to false (aria2's
    // initial-option default of not paused, same shape). **No CLI face by
    // design**: the CLI adds are immediate one-shot downloads (the bare
    // .torrent/magnet/URL/batch forms carry no "add paused" face); the
    // RPC add face (addUri/addTorrent per-task options) accepts per-task
    // values — aria2's own --pause only affects RPC-added downloads, the
    // same rule. The no-op changeGlobalOption value face is the
    // GLOBAL_PATCH_TABLE row (the Motrix guard sends it).
    OptionDecl::table_row("pause", OptionFace::task_payload(), |p, v| {
        p.pause = parse_bool(v).unwrap_or(false);
    }),
    OptionDecl::table_row("seed-ratio", OptionFace::task_payload(), |p, v| {
        if let Ok(r) = v.parse::<f64>() {
            if r.is_finite() && r >= 0.0 {
                p.seed_ratio = Some(r);
            }
        }
    }),
    // seed-time unit = minutes (aria2 same). Domain =
    // [0, MAX_SEED_TIME_MIN] (out-of-domain values are invalid and
    // ignored; the task face keeps its "unacceptable options ignored"
    // semantics; the bound rationale is in the constant's doc — guarding
    // the downstream minutes->seconds conversion against panic).
    OptionDecl::table_row("seed-time", OptionFace::task_payload(), |p, v| {
        if let Ok(m) = v.parse::<f64>() {
            if m.is_finite() && (0.0..=MAX_SEED_TIME_MIN).contains(&m) {
                p.seed_time_min = Some(m);
            }
        }
    }),
    // Three aliases of the bt-max-peers slot share one arm:
    // max-connection (a Motrix UX alias — declared in
    // DECLARED_OPTION_DIFFS) and max-connection-per-server (mapped to the
    // same slot on the BT option face, per the declaration tables).
    OptionDecl::table_row("bt-max-peers", OptionFace::task_payload(), |p, v| {
        if let Ok(n) = v.parse::<usize>() {
            p.bt_max_peers = Some(n);
        }
    }),
    OptionDecl::table_row("max-connection", OptionFace::task_payload(), |p, v| {
        if let Ok(n) = v.parse::<usize>() {
            p.bt_max_peers = Some(n);
        }
    }),
    OptionDecl::table_row(
        "max-connection-per-server",
        OptionFace::task_payload(),
        |p, v| {
            if let Ok(n) = v.parse::<usize>() {
                p.bt_max_peers = Some(n);
            }
        },
    ),
    // Rate-limit family: 0 = unlimited (parse_size semantics).
    OptionDecl::table_row("max-download-limit", OptionFace::task_payload(), |p, v| {
        p.max_download_limit = parse_size(v)
    }),
    OptionDecl::table_row("max-upload-limit", OptionFace::task_payload(), |p, v| {
        p.max_upload_limit = parse_size(v)
    }),
    // magnet family boolean arms (invalid values ignored = the slot
    // stays None = not given).
    OptionDecl::table_row("bt-save-metadata", OptionFace::task_payload(), |p, v| {
        p.bt_save_metadata = parse_bool(v)
    }),
    OptionDecl::table_row("bt-metadata-only", OptionFace::task_payload(), |p, v| {
        p.bt_metadata_only = parse_bool(v)
    }),
    OptionDecl::table_row("follow-torrent", OptionFace::task_payload(), |p, v| {
        p.follow_torrent = parse_bool(v)
    }),
    // pause-metadata: **No CLI face by design** — the CLI adds are
    // immediate one-shot downloads (no metadata-residence face to pause);
    // the RPC add face (addUri(magnet)/addTorrent per-task options)
    // accepts per-task values — aria2's own --pause-metadata only affects
    // RPC-added metadata downloads, the same rule. Invalid values are
    // ignored and fall back to false (the "unacceptable options ignored"
    // rule).
    OptionDecl::table_row("pause-metadata", OptionFace::task_payload(), |p, v| {
        p.pause_metadata = parse_bool(v)
    }),
    OptionDecl::table_row(
        "bt-load-saved-metadata",
        OptionFace::task_payload(),
        |p, v| p.bt_load_saved_metadata = parse_bool(v),
    ),
    // bt-tracker per-task (the aria2 frozen name, prefs.cc
    // `makePref("bt-tracker")`; accepted at the parse face: the Motrix
    // TrackerManager/TaskTrackerService actually sends per-task tracker
    // table edits via changeOption — parsed into the patch with the
    // split_bt_tracker common parsing). **No consume arm yet (wired=false,
    // a no-op)**: the actor change_option/add faces do not read this
    // field (the wiring lands with the actor per-task tracker face);
    // taiji's native equivalent face = taiji.addTracker/removeTracker
    // (task tracker table edits) and the changeGlobalOption `bt-tracker`
    // global import (the actor command arm). aria2 gives this key only
    // the changeReserved bit (no live changeOption bit), so this
    // acceptance is no narrower than the reference behavior face.
    OptionDecl::table_row("bt-tracker", OptionFace::task_payload(), |p, v| {
        p.bt_tracker = Some(split_bt_tracker(v));
    }),
    // select-file: the raw value enters the patch; syntax parsing +
    // 1-based->0-based conversion + range validation happen at the single
    // entry point (parse_select_file / select_file_range_error) — known
    // keys reject invalid values explicitly, not via the "unknown option
    // ignored" path.
    OptionDecl::table_row("select-file", OptionFace::task_payload(), |p, v| {
        p.select_file = Some(v.to_string());
    }),
    // bt-disable-dht: the per-task DHT flag (a libtorrent
    // torrent_flags::disable_dht capability-alignment extension). Invalid
    // values ignored.
    OptionDecl::table_row("bt-disable-dht", OptionFace::task_payload(), |p, v| {
        p.bt_disable_dht = parse_bool(v)
    }),
    // enable-http-seeding (BEP19): the webseeding switch (Motrix
    // extension).
    OptionDecl::table_row("enable-http-seeding", OptionFace::task_payload(), |p, v| {
        p.enable_http_seeding = parse_bool(v)
    }),
    // bt-enable-hook-after-hash-check: the hash-check gate (default
    // true, same as aria2 OptionHandlerFactory.cc).
    OptionDecl::table_row(
        "bt-enable-hook-after-hash-check",
        OptionFace::task_payload(),
        |p, v| p.hooks.bt_enable_hook_after_hash_check = parse_bool(v),
    ),
    // bt-sequential-download: the aria2-compatible projection of the
    // task's sequential scheduling policy (authority =
    // taiji.setSchedulerPolicy).
    OptionDecl::table_row(
        "bt-sequential-download",
        OptionFace::task_payload(),
        |p, v| p.bt_sequential_download = parse_bool(v),
    ),
    // bt-stop-timeout (seconds; 0 = no watchdog — the same value/domain
    // as the aria2 NumberOptionHandler default "0" min 0,
    // OptionHandlerFactory.cc): projected into the task policy in
    // seed_policy_from (consumed by the engine BtStopTimeoutWatch);
    // invalid values ignored (u64 rejects negatives/non-numbers).
    OptionDecl::table_row("bt-stop-timeout", OptionFace::task_payload(), |p, v| {
        if let Ok(n) = v.parse::<u64>() {
            p.bt_stop_timeout_secs = Some(n);
        }
    }),
    // Manual arm: the six hook command family (on-download-* — the name
    // set is projected via HookEvent::ALL; empty string = blank,
    // normalized in the explicit section; initial values fixed at add
    // time, non-persist bits).
    OptionDecl::manual_row(
        "on-download-* (six names, the HookEvent::ALL projection)",
        OptionFace {
            persist: false,
            ..OptionFace::task_payload()
        },
        |k| crate::hook::HookEvent::from_option_name(k).is_some(),
    ),
];

/// Per-task common option acceptance face (parse point =
/// [`parse_task_options`], table-driven; the hook family names come via
/// `HookEvent::from_option_name`, single source — registered in the
/// table as a manual arm row, not in this name mirror). Consistency with
/// the parse arms is pinned by tests (every name must have an observable
/// consumer).
#[cfg(test)]
pub(crate) const TASK_OPTION_NAMES: &[&str] = &[
    "dir",
    "pause",
    "seed-ratio",
    "seed-time",
    "bt-max-peers",
    "max-connection",
    "max-connection-per-server",
    "max-download-limit",
    "max-upload-limit",
    "bt-save-metadata",
    "bt-metadata-only",
    "follow-torrent",
    "pause-metadata",
    "bt-load-saved-metadata",
    // Per-task tracker table edit (accepted at the parse face — the
    // Motrix changeOption sends it; the no-op declaration is in the
    // TASK_OPTION_TABLE row note and TaskOptionPatch.bt_tracker).
    "bt-tracker",
    "select-file",
    // Per-task DHT flag (libtorrent torrent_flags::disable_dht
    // capability alignment — the new key entered the
    // DECLARED_OPTION_DIFFS whitelist; parse-arm consistency is locked by
    // task_option_table_matches_parser_arms).
    "bt-disable-dht",
    // Webseeding switch (BEP19; the Motrix extension key entered the
    // DECLARED_OPTION_DIFFS whitelist; parse-arm consistency locked as
    // above).
    "enable-http-seeding",
    "bt-enable-hook-after-hash-check",
    "bt-sequential-download",
    // bt-stop-timeout (the seeding-stall watchdog; registered on both
    // the task face and the session-global face; parse-arm consistency
    // locked by task_option_table_matches_parser_arms).
    "bt-stop-timeout",
];

/// changeGlobalOption acceptance-face declaration table (parse point =
/// [`apply_global_patch`], table-driven; the runtime hot-reload bit
/// dispatches — non-hot-reload registration rows are not accepted). The
/// echo bit is registered per row ([`OptionFace::echo`]);
/// `global_option_echo` projects from this table — a new global key
/// registers name + hot-reload arm + echo value shape in one place.
/// Accepted-name mirror = [`GLOBAL_PATCH_OPTION_NAMES`] (cfg(test);
/// governance tests pin the table).
///
/// No-op rows (**wired=false**, DEPRECATED semantics) are built by the
/// [`aria2_noop_row!`] macro: the value lands in
/// [`GlobalOptions::unwired_option_values`], the echo = the raw value
/// (unset = the empty string).
macro_rules! aria2_noop_row {
    ($name:literal) => {
        OptionDecl::table_row(
            $name,
            OptionFace::session_runtime().echoing(|g| {
                g.unwired_option_values
                    .get($name)
                    .cloned()
                    .unwrap_or_default()
            }),
            |g: &mut GlobalOptions, v: &str| {
                g.unwired_option_values
                    .insert($name.to_string(), v.to_string());
            },
        )
    };
}

static GLOBAL_PATCH_TABLE: &[OptionDecl<GlobalPatchApply>] = &[
    // ---- Media family (unified registration): changeGlobalOption
    // accepts the P90-P93 flag family (value validation through the
    // taiji-media parse faces — an invalid value ignores per the
    // gatherChangeableGlobalOption lenient rule here; the addMedia
    // per-task face is the strict one). Startup + hot-reload both land
    // in GlobalOptions; tasks activated afterwards consume them as
    // their defaults. ----
    OptionDecl::table_row(
        "media-variant-policy",
        OptionFace::session_runtime().echoing(|g| g.media_variant_policy.clone()),
        |g, v| {
            if taiji_media::VariantPolicy::parse(v).is_ok() {
                g.media_variant_policy = v.trim().to_string();
            }
        },
    ),
    OptionDecl::table_row(
        "media-audio-lang",
        OptionFace::session_runtime().echoing(|g| g.media_audio_lang.clone().unwrap_or_default()),
        |g, v| {
            if let Ok(Some(lang)) = taiji_media::parse_audio_lang(v) {
                g.media_audio_lang = Some(lang);
            }
        },
    ),
    OptionDecl::table_row(
        "media-subtitles",
        OptionFace::session_runtime().echoing(|g| g.media_subtitles.clone()),
        |g, v| {
            if taiji_media::parse_subtitles(v).is_ok() {
                g.media_subtitles = v.trim().to_string();
            }
        },
    ),
    OptionDecl::table_row(
        "media-segment-concurrency",
        OptionFace::session_runtime().echoing(|g| g.media_segment_concurrency.to_string()),
        |g, v| {
            if let Ok(n) = taiji_media::parse_segment_concurrency(v) {
                g.media_segment_concurrency = n;
            }
        },
    ),
    OptionDecl::table_row(
        "media-staging-quota-gib",
        OptionFace::session_runtime().echoing(|g| g.media_staging_quota_gib.to_string()),
        |g, v| {
            if let Ok(n) = taiji_media::parse_staging_quota_gib(v) {
                g.media_staging_quota_gib = n;
            }
        },
    ),
    OptionDecl::table_row(
        "media-staging-dir",
        OptionFace::session_runtime().echoing(|g| g.media_staging_dir.clone().unwrap_or_default()),
        |g, v| {
            if taiji_media::parse_staging_dir(v).is_ok() {
                g.media_staging_dir = Some(v.trim().to_string());
            }
        },
    ),
    OptionDecl::table_row(
        "media-allow-private-key-url",
        OptionFace::session_runtime().echoing(|g| g.media_allow_private_key_url.to_string()),
        |g, v| {
            if let Ok(b) = taiji_media::parse_allow_private_key_url(v) {
                g.media_allow_private_key_url = b;
            }
        },
    ),
    OptionDecl::table_row(
        "media-ffmpeg-path",
        OptionFace::session_runtime().echoing(|g| g.media_ffmpeg_path.clone()),
        |g, v| {
            if taiji_media::parse_ffmpeg_path(v).is_ok() {
                g.media_ffmpeg_path = v.trim().to_string();
            }
        },
    ),
    OptionDecl::table_row(
        "media-archive",
        OptionFace::session_runtime().echoing(|g| g.media_archive.to_string()),
        |g, v| {
            if let Ok(b) = taiji_media::parse_media_archive(v) {
                g.media_archive = b;
            }
        },
    ),
    OptionDecl::table_row(
        "media-info-json",
        OptionFace::session_runtime().echoing(|g| g.media_info_json.to_string()),
        |g, v| {
            if let Ok(b) = taiji_media::parse_media_info_json(v) {
                g.media_info_json = b;
            }
        },
    ),
    // max-concurrent-downloads clamped to [1,64] (the aria2 RANGE(1..)
    // lower-bound semantics + an upper bound: each concurrent task
    // multiplies the per-task wr_cache/arena/engine faces — closing the
    // memory amplification of pulling N arbitrarily high via RPC hot
    // reload; 64 is already extreme single-process concurrency and normal
    // configurations never touch the bound).
    OptionDecl::table_row(
        "max-concurrent-downloads",
        OptionFace::session_runtime().echoing(|g| g.max_concurrent_downloads.to_string()),
        |g, v| {
            if let Ok(n) = v.parse::<usize>() {
                g.max_concurrent_downloads = n.clamp(1, 64);
            }
        },
    ),
    // ---- The four-pool budget trio (the internal fields get their
    // accepted/echo faces; zero new fields or accessors — the close-out
    // check held). Row shape = the
    // max-concurrent-downloads precedent: apply-side value-domain clamp
    // (seeds [0,4096] / checks [1,16] / synthesis [1,16] — the same
    // domains the read-side accessors clamp), a non-numeric value
    // ignores per the gatherChangeableGlobalOption lenient rule (the
    // media-family row note above; zero new error codes). Hot reload =
    // the ChangeGlobalOption arm's trailing pump_all (I3): a narrowed
    // budget never preempts in-flight members, it only gates subsequent
    // admissions; a widened seed budget reactivates seed_wait members
    // FIFO without ever touching a download slot. CLI/conf faces live in
    // the taiji crate (conf.rs arms + the Cli flags; hard domain validation
    // there — the fail-fast conf shape — same domains). ----
    OptionDecl::table_row(
        "max-concurrent-seeds",
        OptionFace::session_runtime().echoing(|g| g.max_concurrent_seeds.to_string()),
        |g, v| {
            if let Ok(n) = v.parse::<usize>() {
                g.max_concurrent_seeds = n.clamp(0, 4096);
            }
        },
    ),
    OptionDecl::table_row(
        "max-concurrent-checks",
        OptionFace::session_runtime().echoing(|g| g.max_concurrent_checks.to_string()),
        |g, v| {
            if let Ok(n) = v.parse::<usize>() {
                g.max_concurrent_checks = n.clamp(1, 16);
            }
        },
    ),
    OptionDecl::table_row(
        "media-synthesis-concurrency",
        OptionFace::session_runtime().echoing(|g| g.media_synthesis_concurrency.to_string()),
        |g, v| {
            if let Ok(n) = v.parse::<usize>() {
                g.media_synthesis_concurrency = n.clamp(1, 16);
            }
        },
    ),
    OptionDecl::table_row(
        "max-overall-download-limit",
        OptionFace::session_runtime().echoing(|g| g.max_overall_download_limit.to_string()),
        |g, v| {
            if let Some(n) = parse_size(v) {
                g.max_overall_download_limit = n;
            }
        },
    ),
    OptionDecl::table_row(
        "max-overall-upload-limit",
        OptionFace::session_runtime().echoing(|g| g.max_overall_upload_limit.to_string()),
        |g, v| {
            if let Some(n) = parse_size(v) {
                g.max_overall_upload_limit = n;
            }
        },
    ),
    // Note: the per-download rate-limit defaults (max-download-limit/
    // max-upload-limit) have NO session-global hot-reload rows here — the
    // names are already accepted on the per-task option face
    // (TASK_OPTION_TABLE; consumed by the per_torrent bucket through the
    // add faces), and this build's add faces do not consume a
    // session-level default for them (aria2 carries the
    // setChangeGlobalOption bit for both; the session-default consume
    // seam would be a tasks.rs change, declared as a divergence gap).
    OptionDecl::table_row(
        "enable-dht",
        OptionFace::session_runtime().echoing(|g| g.enable_dht.to_string()),
        |g, v| {
            if let Some(b) = parse_bool(v) {
                g.enable_dht = b;
            }
        },
    ),
    OptionDecl::table_row(
        "enable-dht6",
        OptionFace::session_runtime().echoing(|g| g.enable_dht6.to_string()),
        |g, v| {
            if let Some(b) = parse_bool(v) {
                g.enable_dht6 = b;
            }
        },
    ),
    // enable-peer-exchange (the aria2 PREF_ENABLE_PEER_EXCHANGE
    // BooleanOptionHandler A2_V_TRUE default + the setChangeGlobalOption
    // bit, OptionHandlerFactory.cc). **wired=true**: the ut_pex
    // gate for tasks activated afterwards (consumed by the actor's
    // activation-time snapshot into EngineConfig.peer_exchange →
    // bt::pex::pex_offered; running tasks are not hot-changed —
    // per-download semantics, same rule as enable-dht).
    OptionDecl::table_row(
        "enable-peer-exchange",
        OptionFace::session_runtime().echoing(|g| g.enable_peer_exchange.to_string()),
        |g, v| {
            if let Some(b) = parse_bool(v) {
                g.enable_peer_exchange = b;
            }
        },
    ),
    // bt-lsd: the reference carries the setChangeGlobalOption bit
    // (OptionHandlerFactory.cc); effect = tasks activated afterwards.
    OptionDecl::table_row(
        "bt-lsd",
        OptionFace::session_runtime().echoing(|g| g.bt_lsd.to_string()),
        |g, v| {
            if let Some(b) = parse_bool(v) {
                g.bt_lsd = b;
            }
        },
    ),
    // client-ban-prefixes (a entry with the hot-reload
    // bit). The comma list replaces the whole table (trim + empty
    // segments skipped — split_bt_tracker's common parsing); an empty
    // string clears the list (back to the default of banning no client).
    // Pushing to running engines and persisting to kv is done by the
    // actor command arm.
    OptionDecl::table_row(
        "client-ban-prefixes",
        OptionFace::session_runtime().echoing(|g| g.client_ban_prefixes.join(",")),
        |g, v| g.client_ban_prefixes = split_bt_tracker(v),
    ),
    // Mirror template list replaces the whole table (split_bt_tracker
    // common parsing: trim + empty segments skipped); an empty string
    // clears it (back to the default-off shape). Template validity
    // (placeholder/protocol) is validated again on the magnet face
    // (parse_web_mirror_templates). Effect = magnet tasks created
    // afterwards (same rule as enable-dht).
    OptionDecl::table_row(
        "bt-metadata-web-sources",
        OptionFace::session_runtime().echoing(|g| g.bt_metadata_web_sources.join(",")),
        |g, v| g.bt_metadata_web_sources = split_bt_tracker(v),
    ),
    // bt-enable-hook-after-hash-check: aria2 gives this option
    // setChangeGlobalOption (OptionHandlerFactory.cc); the on-download-*
    // hook family is LocalFilePathOptionHandler with no
    // changeGlobalOption bit — no hot reload, only the initial
    // per-download/global value at add time takes effect (the reference
    // behaves the same).
    OptionDecl::table_row(
        "bt-enable-hook-after-hash-check",
        OptionFace::session_runtime()
            .echoing(|g| g.hooks.bt_enable_hook_after_hash_check.to_string()),
        |g, v| {
            if let Some(b) = parse_bool(v) {
                g.hooks.bt_enable_hook_after_hash_check = b;
            }
        },
    ),
    // load-cookies global face (accepted; the reference carries the
    // setChangeGlobalOption bit): whole-value path replacement, an empty
    // string = clear (back to "no session-level cookie source"). Effect =
    // tasks created afterwards (fail-closed loading happens at task
    // acceptance — this arm does no IO; the value face is the path
    // string).
    OptionDecl::table_row(
        "load-cookies",
        OptionFace::session_runtime().echoing(|g| {
            g.load_cookies
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        }),
        |g, v| {
            let trimmed = v.trim();
            g.load_cookies = if trimmed.is_empty() {
                None
            } else {
                Some(PathBuf::from(trimmed))
            };
        },
    ),
    // Four tracker keys (value domains cross-checked bit by bit against
    // the reference NumberOptionHandler entries in
    // OptionHandlerFactory.cc; all four carry the setChangeGlobalOption
    // bit — hot reload applies to tasks activated afterwards, same rule
    // as enable-dht; invalid values ignored, same as the reference):
    // - bt-tracker-interval (seconds; 0 = do not override the tracker
    // interval — the aria2 default is the same value): effective in the
    // engine tracker actor's announce client, a direct translation of
    // `apply_interval_settings` userDefinedInterval_.
    // - bt-tracker-timeout / bt-tracker-connect-timeout (seconds,
    // 1..=600, default 60): effective as the HTTP announce reqwest
    // timeout / connect_timeout (bt::tracker TrackerOptions).
    // Out-of-domain values are ignored (aria2 fails startup on
    // out-of-range values; this crate narrows to "unacceptable options
    // ignored", the same stance as the bt-max-peers arm).
    // - bt-stop-timeout (seconds; 0 = no watchdog — the aria2 default is
    // the same value): effective as the engine's seeding
    // BtStopTimeoutWatch (SeedPolicy.stop_timeout, a direct translation
    // of `BtSetup.cc`; consumed through the seed_policy_from
    // task-policy projection).
    OptionDecl::table_row(
        "bt-tracker-interval",
        OptionFace::session_runtime().echoing(|g| g.bt_tracker_interval.to_string()),
        |g, v| {
            if let Ok(n) = v.parse::<u64>() {
                g.bt_tracker_interval = n;
            }
        },
    ),
    OptionDecl::table_row(
        "bt-tracker-timeout",
        OptionFace::session_runtime().echoing(|g| g.bt_tracker_timeout_secs.to_string()),
        |g, v| {
            if let Ok(n) = v.parse::<u64>()
                && (1..=600).contains(&n)
            {
                g.bt_tracker_timeout_secs = n;
            }
        },
    ),
    OptionDecl::table_row(
        "bt-tracker-connect-timeout",
        OptionFace::session_runtime().echoing(|g| g.bt_tracker_connect_timeout_secs.to_string()),
        |g, v| {
            if let Ok(n) = v.parse::<u64>()
                && (1..=600).contains(&n)
            {
                g.bt_tracker_connect_timeout_secs = n;
            }
        },
    ),
    OptionDecl::table_row(
        "bt-stop-timeout",
        OptionFace::session_runtime().echoing(|g| g.bt_stop_timeout_secs.to_string()),
        |g, v| {
            if let Ok(n) = v.parse::<u64>() {
                g.bt_stop_timeout_secs = n;
            }
        },
    ),
    // ---- Motrix frontend alignment batch (changeGlobalOption keys the
    // frontend actually sends; extracted from the Motrix
    // src/core/engine/{engine-supervisor, aria2/completed-task-startup-guard}.ts
    // + src/core/tracker/tracker-manager.ts call sites): applySpeedLimits
    // (the limit family), applyAsyncDns (async-dns), applyDefaultSaveDir
    // (dir), applyEngineSettings (the 14 HOT_ENGINE_OPTIONS names),
    // writeGlobalProxyOptions (the 13 proxy-family names), the post-ready
    // continue seed, tracker-manager (bt-tracker/bt-exclude-tracker),
    // completed-task-startup-guard (pause). This segment = the sent keys
    // that were previously absent from the acceptance face; the
    // non-accepted proxy-family whitelist entries (http-proxy/no-proxy/
    // proxy-method/...) keep their existing declarations (ADR
    // discipline, DECLARED_NON_ACCEPTED_OPTION_NAMES untouched).
    //
    // wired=true rows (the values land in existing engine-consumed
    // fields): dir / seed-ratio / bt-enable-lpd. The bt-max-peers row is
    // a typed value face (the field has an echo; the engine does not
    // consume it — wired=false reality, row note). The no-op rows
    // (DEPRECATED semantics) land in
    // [`GlobalOptions::unwired_option_values`] via [`aria2_noop_row`].
    //
    // dir (reference prefs.cc `makePref("dir")`; the factory carries the
    // setChangeGlobalOption bit — the OptionHandlerFactory.cc DIR block;
    // the Motrix applyDefaultSaveDir sends it): the default download
    // directory for later tasks. Consume points = the add-face
    // `patch.dir.unwrap_or(global.dir)` family (session/actor/tasks.rs)
    // + the persist recovery face from the same source — **wired=true**.
    // An empty string = ignored (the blank semantics, same as the
    // load-cookies row).
    OptionDecl::table_row(
        "dir",
        OptionFace::session_runtime().echoing(|g| g.dir.display().to_string()),
        |g, v| {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                g.dir = PathBuf::from(trimmed);
            }
        },
    ),
    // seed-ratio (the factory changeGlobal bit; the Motrix
    // applyEngineSettings sends it): the seeding-ratio default for later
    // tasks. Consume point = the add face
    // `patch.seed_ratio.unwrap_or(global.seed_ratio)` (tasks.rs) + the
    // persist recovery face — **wired=true**. Domain = [`checked_seed_ratio`]
    // (finite >= 0); out-of-domain values are ignored (the reference's
    // "unacceptable options ignored" rule).
    OptionDecl::table_row(
        "seed-ratio",
        OptionFace::session_runtime().echoing(|g| format_seed_ratio(g.seed_ratio)),
        |g, v| {
            if let Ok(r) = v.parse::<f64>()
                && let Some(r) = checked_seed_ratio(r)
            {
                g.seed_ratio = r;
            }
        },
    ),
    // bt-max-peers (the factory carries both the changeGlobal/changeOption
    // bits; the Motrix applyEngineSettings sends it): hot-updates the
    // g.bt_max_peers value face (the echo key already exists — the
    // global_option_echo hand-written section has the same key, so the
    // table projection overwrites without drift). **wired=false
    // reality**: the engine peer-connection hard cap = a taiji-engine
    // constant (intentional divergence: "no CLI/RPC option face") — this
    // value does not reach the engine, echo only.
    OptionDecl::table_row(
        "bt-max-peers",
        OptionFace::session_runtime().echoing(|g| g.bt_max_peers.to_string()),
        |g, v| {
            if let Ok(n) = v.parse::<usize>() {
                g.bt_max_peers = n;
            }
        },
    ),
    // bt-enable-lpd (the aria2 frozen name, prefs.cc
    // `makePref("bt-enable-lpd")`; the factory changeGlobal bit; the
    // Motrix applyEngineSettings sends it): the acceptance half of the
    // rename declaration (the DECLARED_OPTION_DIFFS bt-lsd entry) —
    // writes the same g.bt_lsd slot as the bt-lsd row (the LSD service
    // gate consume points = the session/actor bootstrap + the commands.rs
    // task assembly); semantics = tasks activated afterwards (same rule
    // as enable-dht). **wired=true**; the echo key coexists with bt-lsd
    // at the same value. The CLI face pairs with this row since the
    // alias promotion: `--bt-enable-lpd` is a visible alias of
    // `--bt-lsd` folding into the same CLI field, and the conf key
    // `bt-enable-lpd` folds into the same field — one value face across
    // the CLI/conf/session surfaces.
    OptionDecl::table_row(
        "bt-enable-lpd",
        OptionFace::session_runtime().echoing(|g| g.bt_lsd.to_string()),
        |g, v| {
            if let Some(b) = parse_bool(v) {
                g.bt_lsd = b;
            }
        },
    ),
    // The no-op rows below (**wired=false**, DEPRECATED semantics —
    // accepted with the value face echoed, no engine behavior change):
    // the values land in [`GlobalOptions::unwired_option_values`].
    // Per-key non-wiring reasons:
    // - split / min-split-size / max-connection-per-server / user-agent /
    // connect-timeout / timeout / max-tries / retry-wait / remote-time:
    // already accepted per-task on the HTTP task face
    // (http_task_runtime_options / the persist face; the tightened
    // domains are semantic redefinitions declared in the diff block);
    // the global-default consume seam = the actor HttpTaskOpts::default
    // (outside this file) — the global face records the value face,
    // behavior unchanged.
    // - async-dns: taiji's resolver behavior is fixed (no async-dns
    // wiring seam — a declared limitation; the http transport stack
    // manages its own resolution).
    // - continue: the always-resume inverted-semantics declaration (the
    // same-name entry in the diff block) — true/false do not affect
    // behavior (aria2 false = discard progress and re-download,
    // unreachable here). This row is the key's core acceptance
    // reference face (the CLI_ONLY_ACCEPTED exemption in
    // accepted_option_faces_are_fully_declared is retired with it).
    // - pause: aria2 gives this key no changeGlobal capability bit
    // (factory-verified; the summary-interval precedent — the reference
    // ignores it too); the Motrix guard startup flow
    // (completed-task-startup-guard reconcile) sends it, so the value
    // face is recorded (taiji has no global pause template face; an
    // explicit add-face pause is already accepted).
    // - bt-exclude-tracker: the Motrix tracker-manager always sends an
    // empty string (a subscription-exclusion placeholder); taiji's
    // global tracker import has no exclusion face — recorded (the
    // value face stays empty), zero behavior.
    // - all-proxy: the proxy face = per-task all-proxy (accepted on the
    // HTTP runtime face, the URL-userinfo exception declared); the
    // global proxy default has no consume seam — the rest of the
    // Motrix writeGlobalProxyOptions proxy-family names keep the
    // non-accepted declarations.
    aria2_noop_row!("split"),
    aria2_noop_row!("min-split-size"),
    aria2_noop_row!("max-connection-per-server"),
    aria2_noop_row!("user-agent"),
    aria2_noop_row!("connect-timeout"),
    aria2_noop_row!("timeout"),
    aria2_noop_row!("max-tries"),
    aria2_noop_row!("retry-wait"),
    aria2_noop_row!("remote-time"),
    aria2_noop_row!("async-dns"),
    aria2_noop_row!("continue"),
    aria2_noop_row!("pause"),
    aria2_noop_row!("bt-exclude-tracker"),
    aria2_noop_row!("all-proxy"),
    // ---- The max-family seam-less keys + the async-dns6 no-op value
    // face (**wired=false** — accepted and echoed, no engine behavior
    // change; per-key reasons):
    // - max-download-result: the RPC stopped-result retention count
    // (aria2 default 1000) — the taiji RPC face has no result-retention
    // seam (the job bookkeeping is the truth; tellStopped reads the
    // queues directly).
    // - max-file-not-found: the 404-count switch-source threshold — the
    // taiji-http source probe eviction has no option-driven counter
    // seam (wiring lands with the HTTP retry face).
    // - max-resume-failure-tries: fall back to a full re-download after N
    // resume failures — the bitmap resume has no "fall back to zero"
    // seam (the bitmap is the resume truth).
    // - max-mmap-limit: the mmap loading threshold (the aria2 default
    // i64::MAX = never mmap) — the taiji store face has no mmap path
    // (taiji-store disk_policy); the value face is accepted with zero
    // behavior.
    // - enable-async-dns6: wrapped by an aria2 DeprecatedOptionHandler
    // (OptionHandlerFactory.cc "TODO Deprecated") — taiji's
    // resolver behavior is fixed (same as the async-dns row), no v6
    // resolver switch seam.
    aria2_noop_row!("max-download-result"),
    aria2_noop_row!("max-file-not-found"),
    aria2_noop_row!("max-resume-failure-tries"),
    aria2_noop_row!("max-mmap-limit"),
    aria2_noop_row!("enable-async-dns6"),
    // Domain 2: the https-proxy global no-op row (a name the Motrix
    // writeGlobalProxyOptions sends — same rule as the all-proxy row):
    // "the proxy face = the per-task https-proxy dedicated slot (accepted
    // on the HTTP runtime face, the URL-userinfo exception declared); the
    // global proxy default has no consume seam". Session-face effect
    // order = dedicated slot > all-proxy > no proxy.
    aria2_noop_row!("https-proxy"),
];

/// changeGlobalOption acceptance face (parse point =
/// [`apply_global_patch`]). The trailing alignment-batch segment =
/// the Motrix frontend's actually-sent subset: dir/seed-ratio/
/// bt-enable-lpd wired=true (engine-consumed fields); bt-max-peers a
/// typed value face (the engine cap is a constant seam — wired=false);
/// the rest = the no-op value face (DEPRECATED semantics, per-key
/// reasons in the [`GLOBAL_PATCH_TABLE`] row notes).
#[cfg(test)]
pub(crate) const GLOBAL_PATCH_OPTION_NAMES: &[&str] = &[
    // Media family (unified registration; mirrors the table's
    // leading rows position by position).
    "media-variant-policy",
    "media-audio-lang",
    "media-subtitles",
    "media-segment-concurrency",
    "media-staging-quota-gib",
    "media-staging-dir",
    "media-allow-private-key-url",
    "media-ffmpeg-path",
    "media-archive",
    "media-info-json",
    "max-concurrent-downloads",
    // The four-pool budget trio (mirrors the table rows position
    // by position — option_decl_tables_mirror_name_consts locks it).
    "max-concurrent-seeds",
    "max-concurrent-checks",
    "media-synthesis-concurrency",
    "max-overall-download-limit",
    "max-overall-upload-limit",
    "enable-dht",
    "enable-dht6",
    // The PEX gate typed row (mirrors the table row order position by
    // position — option_decl_tables_mirror_name_consts locks it).
    "enable-peer-exchange",
    "bt-lsd",
    "client-ban-prefixes",
    "bt-metadata-web-sources",
    "bt-enable-hook-after-hash-check",
    // Cookie file global face (the load-cookies value face = path
    // replacement; loading is fail-closed at task acceptance).
    "load-cookies",
    // Four tracker keys (the tracker announce client interval/timeout
    // pair + the seeding-stall watchdog — echoed via the table rows'
    // echo bits).
    "bt-tracker-interval",
    "bt-tracker-timeout",
    "bt-tracker-connect-timeout",
    "bt-stop-timeout",
    // ---- Motrix alignment batch (mirrors the table row order position
    // by position — option_decl_tables_mirror_name_consts locks it):
    // dir/seed-ratio/bt-max-peers/bt-enable-lpd typed rows + the no-op
    // value-face rows.
    "dir",
    "seed-ratio",
    "bt-max-peers",
    "bt-enable-lpd",
    "split",
    "min-split-size",
    "max-connection-per-server",
    "user-agent",
    "connect-timeout",
    "timeout",
    "max-tries",
    "retry-wait",
    "remote-time",
    "async-dns",
    "continue",
    "pause",
    "bt-exclude-tracker",
    "all-proxy",
    // ---- The max-family seam-less keys + the async-dns6 no-op rows
    // (mirroring the table tail order).
    "max-download-result",
    "max-file-not-found",
    "max-resume-failure-tries",
    "max-mmap-limit",
    "enable-async-dns6",
    // Domain 2: the https-proxy global no-op row (mirroring the table
    // tail order).
    "https-proxy",
];

/// HTTP task persist option face (parse point =
/// `session::actor::http_task_options`; valid values persist with the
/// task row at creation).
#[cfg(test)]
pub(crate) const HTTP_PERSIST_OPTION_NAMES: &[&str] =
    &["http-incomplete-suffix", "checksum", "remote-time"];

/// HTTP task runtime option face (parse point =
/// `session::actor::http_task_runtime_options`; not stored, recovery
/// uses the defaults).
#[cfg(test)]
pub(crate) const HTTP_RUNTIME_OPTION_NAMES: &[&str] = &[
    "timeout",
    "connect-timeout",
    "max-tries",
    "retry-wait",
    "user-agent",
    "header",
    "http-user",
    "http-passwd",
    "all-proxy",
    // Domain 2 (the HTTPS-dedicated slot / Referer / the transparent gzip
    // decompression switch).
    "https-proxy",
    "referer",
    "http-accept-gzip",
    "check-certificate",
    // Task-level CA face (PEM path; parse-time existence/PEM validation
    // — a bad path/bad PEM = taiji.option.invalid; the replace semantics
    // + check-certificate=false ordering: see the ca-certificate diff
    // declaration in docs/design/core.md).
    "ca-certificate",
    // Scheduling group (the option group wired; split/min-split-size are
    // semantic redefinitions, max-connection-per-server domain 1..=16
    // rejects out-of-range values).
    "split",
    "min-split-size",
    "max-connection-per-server",
    "http-stall-window",
    "http-scheduler",
    "http-block-size",
    "http-max-chunk",
    // Protocol shape (experimental: the h2c prior-knowledge plaintext
    // switch).
    "http-protocol",
    // h2 flow-control windows (experimental: adaptive windows +
    // per-stream/per-connection initial windows).
    "http2-adaptive-window",
    "http2-stream-window",
    "http2-connection-window",
    // h2 multi-connection + keep-alive (experimental: the per-origin
    // connection cap + the PING interval).
    "http2-max-connections",
    "http2-keep-alive-interval",
    // Batch-group budget (an aggregated cross-file connection budget for
    // transient same-host batch groups).
    "http-batch-budget",
    // FTP family (ftp-pasv is value-validation only — false is
    // explicitly rejected, active mode is not implemented;
    // ftp-pasv-address-check = the PASV/EPSV address-check tri-state,
    // default peer).
    "ftp-user",
    "ftp-passwd",
    "ftp-ssl",
    "ftp-pasv",
    "ftp-reuse-connection",
    "ftp-pasv-address-check",
];

/// Keys read directly by addUri (consumed directly in `session::actor`
/// add_uri, not via [`parse_task_options`]).
#[cfg(test)]
pub(crate) const ADD_URI_DIRECT_OPTION_NAMES: &[&str] =
    &["http-max-per-host", "out", "load-cookies"];

/// Mirror of the metalink seam's accepted names (the single facts live
/// in taiji-rpc
/// `metalink::{UNSUPPORTED_METALINK_OPTIONS, AUTO_DISCOVER_OPTION}` +
/// the taiji CLI `--metalink-file`). The core table is the
/// declaration single source; the subset check (seam face ⊆ declaration
/// table) lives in the taiji-rpc seam tests (mirror/seam drift turns
/// red).
#[cfg(test)]
pub(crate) const METALINK_ACCEPTED_SEAM_OPTION_NAMES: &[&str] = &[
    "metalink-file",
    "metalink-language",
    "metalink-location",
    "metalink-os",
    "metalink-version",
    "metalink-preferred-protocol",
    "metalink-force-protocol",
    "metalink-enable-unique-protocol",
    "metalink-enable-auto-discover",
];

/// Union of all accepted/direct-read face names (the total diff-check
/// face; hook option names join the echo face separately via the
/// HookEvent single source).
#[cfg(test)]
pub(crate) fn accepted_option_names() -> impl Iterator<Item = &'static str> {
    TASK_OPTION_NAMES
        .iter()
        .chain(GLOBAL_PATCH_OPTION_NAMES)
        .chain(HTTP_PERSIST_OPTION_NAMES)
        .chain(HTTP_RUNTIME_OPTION_NAMES)
        .chain(ADD_URI_DIRECT_OPTION_NAMES)
        .chain(METALINK_ACCEPTED_SEAM_OPTION_NAMES)
        .copied()
}

/// `CryptoLevel` option value parsing (unknown value = None -> the
/// caller ignores it, the reference's "unacceptable options ignored"
/// rule).
pub fn parse_crypto_level(s: &str) -> Option<taiji_bt::mse::CryptoLevel> {
    match s {
        "plain" => Some(taiji_bt::mse::CryptoLevel::Plain),
        "arc4" => Some(taiji_bt::mse::CryptoLevel::Arc4),
        _ => None,
    }
}

/// Option value strings for `PeerConnectionType` (SPEC §6.1/§11 domain
/// tcp|utp|prefer-utp|prefer-tcp). The implementation lives in the
/// engine subtree (`engine::transit` — the dial-observation labels share
/// this literal table with the echo face); re-exported here so the
/// existing `session::options` public path does not drift.
pub use crate::engine::peer_connection_type_str;

/// `PeerConnectionType` option value parsing (unknown value = None ->
/// the caller ignores it).
pub fn parse_peer_connection_type(s: &str) -> Option<taiji_bt::utp::PeerConnectionType> {
    use taiji_bt::utp::PeerConnectionType as P;
    match s {
        "tcp" => Some(P::Tcp),
        "utp" => Some(P::Utp),
        "prefer-utp" => Some(P::PreferUtp),
        "prefer-tcp" => Some(P::PreferTcp),
        _ => None,
    }
}

/// Numeric echo convention (shared by getGlobalOption/getOption — the
/// echo uses the f64's minimal digit form and never fabricates
/// precision; matches the rpc-api-diff.md §3 `seed-ratio` value-diff
/// entry).
pub(crate) fn format_seed_ratio(r: f64) -> String {
    // aria2 echoes numbers as-is (string); a fixed two-decimal format
    // would fabricate precision — trimming the fraction is enough.
    if r.fract() == 0.0 {
        format!("{}", r as i64)
    } else {
        format!("{r}")
    }
}

/// Minutes value echo convention (`--seed-time` unit = minutes; shared
/// by getGlobalOption/getOption — same format as
/// [`format_seed_ratio`]).
pub(crate) fn format_minutes(min: f64) -> String {
    if min.fract() == 0.0 {
        format!("{}", min as i64)
    } else {
        format!("{min}")
    }
}

/// aria2 size literal parsing: bare bytes or a k/K/m/M/g/G suffix (base
/// 1024). "0" = unlimited (the rate-limit family semantics, SPEC §11).
///
/// Reference: `Util.cc getRealSize` (K/M suffixes base 1024; negative/
/// overflow error out — this function also tightens the rate-limit
/// family to >= 0, invalid values = ignored, the caller-face semantics).
/// taiji extension: the g/G suffix (getRealSize only takes K/M; the
/// SizeOptionHandler family's large-size options share this parser, so
/// the superset keeps one consistent face).
pub fn parse_size(s: &str) -> Option<u64> {
    let (digits, mult) = match s.chars().last() {
        Some('k' | 'K') => (&s[..s.len() - 1], 1024u64),
        Some('m' | 'M') => (&s[..s.len() - 1], 1024 * 1024),
        Some('g' | 'G') => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        Some(_) => (s, 1),
        None => return None,
    };
    let n: u64 = digits.parse().ok()?;
    n.checked_mul(mult)
}

fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "true" | "1" => Some(true),
        "false" | "0" => Some(false),
        _ => None,
    }
}

/// Per-task option subset parse result (shared by addUri/addTorrent
/// options and changeOption; None = not given). Known options outside
/// the BT subset (e.g. the HTTP-only split) are ignored along with
/// unknown ones (RpcMethod.cc).
#[derive(Debug, Clone, Default)]
pub struct TaskOptionPatch {
    /// `dir` (per-add download directory; no effect on already-active
    /// tasks).
    pub dir: Option<PathBuf>,
    /// `pause`="true": pause immediately on enqueue (aria2's
    /// initial-option semantics).
    pub pause: bool,
    /// `seed-ratio`.
    pub seed_ratio: Option<f64>,
    /// `seed-time` (minutes).
    pub seed_time_min: Option<f64>,
    /// `bt-max-peers`; `max-connection` (a Motrix UX alias) maps to the
    /// same slot by design. Enforcement hangs off the engine connection
    /// management (currently the constant MIN_PEERS face); the value
    /// first lands in the option table.
    pub bt_max_peers: Option<usize>,
    /// `max-download-limit` (0 = unlimited; enforced by the per_torrent
    /// bucket).
    pub max_download_limit: Option<u64>,
    /// `max-upload-limit` (0 = unlimited; enforced by the per_torrent
    /// bucket).
    pub max_upload_limit: Option<u64>,
    /// magnet face options (a pass-through of MagnetOptions).
    pub bt_save_metadata: Option<bool>,
    pub bt_metadata_only: Option<bool>,
    pub follow_torrent: Option<bool>,
    pub pause_metadata: Option<bool>,
    pub bt_load_saved_metadata: Option<bool>,
    /// `select-file` raw value. **Not parsed here**: syntax parsing and
    /// 1-based->0-based conversion converge at the [`parse_select_file`]
    /// single point, executed by the entry points
    /// (addTorrent/addUri(magnet)/changeOption) together with the
    /// metadata-aware range validation — invalid values are explicitly
    /// rejected with `taiji.option.invalid` (the known-key tightening
    /// convention, not the "unknown option ignored" path).
    pub select_file: Option<String>,
    /// `bt-disable-dht` (bool; **None = not given = follow the session
    /// `enable-dht`**). Counterpart of libtorrent's
    /// `torrent_flags::disable_dht` per-torrent flag (src/torrent.cpp
    /// runtime flip) — the task-level value overrides the session value:
    /// Some(true) = DHT off for this task (even if the session has it
    /// on), Some(false) = DHT forced on for this task (even if the
    /// session has it off; private torrents are still held down by the
    /// BEP27 engine gate). Already-active tasks hot-apply it via the
    /// engine `SetDhtEnabled` (the changeOption live arm). aria2 has no
    /// per-torrent DHT option — a libtorrent capability-alignment
    /// extension (diff declaration in rpc-api-diff §3).
    pub bt_disable_dht: Option<bool>,
    /// `enable-http-seeding` (BEP19; bool; **None = not given = default
    /// true** — the metainfo url-list projection proceeds). false = clear
    /// this task's webseed set (BT-only shape; the url-list original
    /// stays in the metainfo, so re-enabling is lossless). aria2 has no
    /// such switch (url-list is always used) — a Motrix extension (diff
    /// declaration in DECLARED_OPTION_DIFFS). Effective through the
    /// activation chain (`build_engine_config` / the magnet upgrade chain
    /// call `webseeds.clear` at the same point); already-active tasks
    /// take effect via the changeOption restart re-activation (an engine
    /// hot-push face belongs to future webseeding engine integration).
    pub enable_http_seeding: Option<bool>,
    /// `bt-sequential-download`: the task-face projection of the aria2
    /// same-name option — **the authority is `taiji.setSchedulerPolicy`**:
    /// true = set the task policy to sequential, false = rarest_first;
    /// both entry points echo consistently. Accepted by
    /// addTorrent/addMagnet (projected into the `scheduler_policy`
    /// payload via patch_config); on the changeOption Reserved face,
    /// active tasks are explicitly rejected (restart semantics belong to
    /// the setSchedulerPolicy live face).
    pub bt_sequential_download: Option<bool>,
    /// Increment for the six hook commands (None = keep the global
    /// value. An empty-string value = blank = unset, normalized per the
    /// reference `option->blank` rule).
    pub hooks: crate::hook::HookPatch,
    /// `bt-tracker` per-task comma list (accepted at the parse face;
    /// parsed by [`split_bt_tracker`] — trim + empty segments skipped).
    /// **No consume arm yet (wired=false, a no-op)**: the actor
    /// change_option/add faces do not read this field (the wiring lands
    /// with the actor per-task tracker face — outside this file);
    /// taiji's native equivalent face = `taiji.addTracker`/
    /// `taiji.removeTracker` (task tracker table edits) and the
    /// changeGlobalOption `bt-tracker` global import (the actor command
    /// arm). aria2 gives this key only the changeReserved bit (no live
    /// changeOption bit), so this acceptance is no narrower than the
    /// reference behavior face.
    pub bt_tracker: Option<Vec<String>>,
    /// `bt-stop-timeout` (seconds; None = not given = fall back to the
    /// session-global `bt_stop_timeout_secs` — aria2's per-download
    /// precedence, same order). Effective through `seed_policy_from` ->
    /// `SeedPolicy.stop_timeout` (the engine's seeding
    /// BtStopTimeoutWatch).
    pub bt_stop_timeout_secs: Option<u64>,
}

/// Parses the per-task option subset (table-driven;
/// [`TASK_OPTION_TABLE`] executed key by key). Unknown/invalid-valued
/// options are ignored (no error — aria2 silently skips unknown options;
/// its handler.parse throws on invalid values, and this crate narrows
/// that to ignore, keeping explicitness by having callers validate the
/// keys they care about).
pub fn parse_task_options(opts: &BTreeMap<String, String>) -> TaskOptionPatch {
    let mut p = TaskOptionPatch::default();
    for (k, v) in opts {
        let key = k.as_str();
        // Table-driven arm: direct name lookup + entry parse write
        // (invalid values ignored inside the arm). Acceptance-bit
        // dispatch: registration-only rows (accepted = false) are skipped
        // by the parse face entirely.
        if let Some(decl) = TASK_OPTION_TABLE.iter().find(|d| d.name == key) {
            if decl.face.accepted
                && let Some(apply) = decl.apply
            {
                apply(&mut p, v);
                continue;
            }
        }
        // Manual arm (registered in the table via the
        // [`OptionDecl::manual_match`] dynamic name set): the six hook
        // command family — the name list comes via HookEvent, single
        // source; empty string = blank = unset (normalized per the
        // reference `option->blank` rule).
        if TASK_OPTION_TABLE
            .iter()
            .any(|d| d.manual_match.is_some_and(|m| m(key)))
            && let Some(ev) = crate::hook::HookEvent::from_option_name(key)
        {
            p.hooks.set_command(ev, non_empty(v));
        }
        // Everything else = unknown option, ignored (same as the
        // reference).
    }
    p
}

/// Normalizes an empty string to None (aria2 blank semantics:
/// `option->blank` = an empty string means unset).
fn non_empty(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// `select-file` option value parsing -> a 0-based selection face (the
/// **single point for the 1-based->0-based conversion**; the Motrix
/// frontend sends 1-based values, and an off-by-one here is the highest
/// risk, so it converges on this one function).
///
/// Reference cross-check (aria2 `IntegerRangeOptionHandler`,
/// `OptionHandlerFactory.cc`): **1-based**, comma-separated, `N-M`
/// **closed ranges** (parseIntSegments semantics, `Util.cc` —
/// `sgl.add(a, b+1)` makes it closed; incomplete ranges `-5`/`5-` raise
/// MSG_INCOMPLETE_RANGE in aria2 and are rejected here too); domain
/// 1..=1048576 (aria2 `1_m`).
///
/// taiji tightenings (diff declaration vs aria2 — the select-file entry
/// in docs/design/core.md): empty string/empty item, contains 0,
/// out-of-domain, duplicates, out-of-order, overlapping/inverted ranges,
/// non-decimal/whitespace/sign -> `Err` (the caller explicitly rejects
/// with `taiji.option.invalid`). aria2 only errors on non-numbers and
/// incomplete ranges — duplicates/out-of-order are absorbed by
/// `SegList::normalize`, and out-of-range indexes build a silently empty
/// filter via setFileFilter at group construction
/// (`download_helper.cc`). The strictly-increasing rule matches the
/// magnet `so=` parser (`taiji_bt::magnet::parse_so`; the same 0-based
/// data face).
pub fn parse_select_file(value: &str) -> Result<Vec<u32>, String> {
    /// aria2 handler domain upper bound (the C++ literal `1_m` =
    /// 1048576, OptionHandlerFactory.cc).
    const MAX_INDEX_1BASED: u64 = 1_048_576;
    let bad = |what: String| {
        format!(
            "taiji.option.invalid: --select-file {what} \
             (1-based, comma-separated closed ranges, e.g. \"1-3,5\")"
        )
    };
    if value.is_empty() {
        return Err(bad("value is empty".into()));
    }
    let mut out: Vec<u32> = Vec::new();
    for item in value.split(',') {
        if item.is_empty() {
            return Err(bad("has an empty segment".into()));
        }
        let (lo_raw, hi_raw) = match item.split_once('-') {
            None => (item, item),
            Some((l, r)) => {
                if l.is_empty() || r.is_empty() {
                    return Err(bad(format!("has an incomplete range {item:?}")));
                }
                (l, r)
            }
        };
        // u64::from_str only takes unsigned plain decimal — whitespace,
        // signs, and non-digits are all rejected (aria2's parseIntNoThrow
        // tolerates leading whitespace via strtol; this crate tightens).
        let lo: u64 = lo_raw
            .parse()
            .map_err(|_| bad(format!("has a non-numeric item {item:?}")))?;
        let hi: u64 = hi_raw
            .parse()
            .map_err(|_| bad(format!("has a non-numeric item {item:?}")))?;
        if lo == 0 || hi == 0 {
            return Err(bad("contains index 0 (indices are 1-based)".into()));
        }
        if lo > MAX_INDEX_1BASED || hi > MAX_INDEX_1BASED {
            return Err(bad(format!(
                "index exceeds domain 1..={MAX_INDEX_1BASED} (aria2 1_m)"
            )));
        }
        if hi < lo {
            return Err(bad(format!("has an inverted range {item:?}")));
        }
        for one_based in lo..=hi {
            // The expanded order must be strictly increasing: duplicates
            // (1,1), out-of-order (2,1), and overlaps (1-3,2 or 1-2,2-4)
            // are all rejected here.
            let zero_based = (one_based - 1) as u32;
            if out.last().is_some_and(|&prev| prev >= zero_based) {
                return Err(bad("segments must be strictly increasing \
                     (duplicate/overlap/out-of-order)"
                    .into()));
            }
            out.push(zero_based);
        }
    }
    Ok(out)
}

/// Range validation for the `select-file` 0-based selection face
/// (executed once the metadata is known; `file_count` = the **non-pad**
/// file count — the BEP53 client file list convention; BEP47 pad entries
/// are placeholder intervals, not file entries. Same anchor as the
/// magnet `so=` upgrade-chain validation in crate::magnet.rs). Out of
/// range -> `Some(error text)` (the caller explicitly rejects).
pub fn select_file_range_error(sel: &[u32], file_count: u32) -> Option<String> {
    sel.iter().find(|&&i| i >= file_count).map(|&bad| {
        format!(
            "taiji.option.invalid: --select-file index {} out of range \
             ({} files; 1-based client file list, padding files not counted)",
            bad + 1,
            file_count
        )
    })
}

/// select-file parsing + range validation for the metadata-known face
/// (one shared point for addTorrent and changeOption
/// Reserved(torrent); a magnet task with unknown metadata -> the caller
/// only runs the syntax check [`parse_select_file`] and defers range
/// validation to the upgrade chain — the same convention as `so=`).
/// None = the option was not given (select everything, zero behavior
/// change).
pub fn resolve_select_file_for_meta(
    patch: &TaskOptionPatch,
    meta: &TorrentMeta,
) -> Result<Option<Vec<u32>>, crate::session::SessionError> {
    let Some(raw) = &patch.select_file else {
        return Ok(None);
    };
    let sel = parse_select_file(raw).map_err(crate::session::SessionError::failed)?;
    let file_count = meta.files.iter().filter(|f| !f.padding).count() as u32;
    match select_file_range_error(&sel, file_count) {
        Some(err) => Err(crate::session::SessionError::failed(err)),
        None => Ok(Some(sel)),
    }
}

/// `--bt-tracker` comma-list parsing: split on commas, trim both sides,
/// skip empty segments. Reference: `bittorrent_helper.cc`
/// `util::split(..., ',', true)` (trimMerger = true skips empty
/// segments; whitespace tolerance aligns with the same file's
/// removeAnnounceUri per-entry comparison semantics).
pub fn split_bt_tracker(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Windows reserved device-name stems (case-insensitive). The classic
/// six + the full COM/LPT ranges; COM0/LPT0 included conservatively per
/// Microsoft's naming documentation ("reserved though not forbidden").
const WINDOWS_RESERVED_STEMS: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
    "COM8", "COM9", "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Whether a basename is unsafe in the Windows naming domain (rounding
/// out the `--out` domain):
///
/// - Reserved device-name stems: `CON` and `CON.iso` both match (stem =
/// the segment before the first `.`, case-insensitive) — the Win32
/// desktop API compatibility layer rejects/rewrites the extension
/// forms too;
/// - Trailing `.` or space: Win32 silently strips them on write -> an
/// accidental rename + a collision face for multiple tasks on the same
/// (dir,out).
///
/// Cross-platform consistent check (not cfg(windows)): names produced on
/// Linux/macOS and consumed on Windows are protected equally; the
/// metalink basename flattening gathers cross-document entries into the
/// same (dir,out), and explicit rejection beats silent rewriting at the
/// write face. Public export — the taiji-rpc metalink expansion face
/// consumes this for its out domain too (single source).
pub fn windows_unsafe_basename(name: &str) -> bool {
    if name.ends_with('.') || name.ends_with(' ') {
        return true;
    }
    let stem = name.split('.').next().unwrap_or(name);
    WINDOWS_RESERVED_STEMS
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
}

/// Task-level tracker tier cap (real v1 announce-lists are far smaller;
/// closes the unbounded cross-call accumulation of malicious RPC/global
/// imports).
pub const MAX_TRACKER_TIERS: usize = 256;

/// Global tracker set cap (the union-import cumulative face).
pub const MAX_GLOBAL_TRACKERS: usize = 1024;

/// Three-layer merge: per-torrent table (built-in announce-list ∪
/// per-torrent manual edits) ∪ the global import set = the engine's
/// effective table (effective_trackers).
///
/// Merge semantics (cross-checked against the read-only reference):
/// - the per-torrent table is kept wholesale at the front, tier
/// structure and order untouched — BEP12 tier order is priority order,
/// and built-in/manual entries outrank global supplements;
/// - global URLs each become an **independent tier** appended at the end
/// (aria2 `addAnnounceUri`, a direct translation of
/// `bittorrent_helper.cc`: each URI pushes back its own layer);
/// - union dedup: a global URL already present in any existing tier is
/// skipped (aria2 has no such step — its bt-tracker is not cumulative;
/// this is an explicit extension required by the union-import
/// semantics);
/// - an empty global set = the identity transform (returns a table
/// equivalent to the input; zero behavior change for existing
/// callers).
pub fn merge_global_trackers(
    per_torrent: &[(usize, String)],
    global: &[String],
) -> Vec<(usize, String)> {
    let mut tiers = per_torrent.to_vec();
    let mut next = tiers.iter().map(|(t, _)| *t).max().map_or(0, |m| m + 1);
    // Dedup via HashSet (removes the O(n·m) linear scan) + the
    // task-level tier cap (closes the unbounded cross-call accumulation;
    // the cap truncates silently — the caller records the total).
    let mut seen: std::collections::HashSet<String> =
        tiers.iter().map(|(_, u)| u.clone()).collect();
    for url in global {
        if url.is_empty() || !seen.insert(url.clone()) {
            continue;
        }
        if tiers.len() >= MAX_TRACKER_TIERS {
            break;
        }
        tiers.push((next, url.clone()));
        next += 1;
    }
    tiers
}

/// Tracker table transform for `taiji.addTracker` (a pure function
/// shared by the session arm and unit tests): each of `urls` becomes an
/// **independent tier** (BEP12, one layer per URL; aligns with the
/// global import semantics of [`merge_global_trackers`]):
/// - dedup: empty URLs and URLs already in the table are skipped (not
/// counted in added; same rule as union import — repeated adds are
/// idempotent);
/// - with `position`: insert at tier index `position` (0-based, clamped
/// to the table end; existing tiers shift down — BEP12 tier order is
/// priority order, so the insertion point is the priority position);
/// default = append at the end (tier numbers continue from max+1; an
/// isomorphic translation of aria2 `addAnnounceUri`,
/// `bittorrent_helper.cc`);
/// - returns (new table, added = the number actually inserted). The new
/// table's tier numbers are compacted (0..n), matching the magnet `tr`
/// order semantics (existing table invariants: one URL per layer,
/// tiers ascending).
pub fn add_trackers(
    tiers: &[(usize, String)],
    urls: &[String],
    position: Option<usize>,
) -> (Vec<(usize, String)>, u64) {
    // Existing URL order (stable by ascending tier — a table invariant;
    // defends against out-of-order shapes).
    let mut ordered: Vec<String> = {
        let mut sorted: Vec<&(usize, String)> = tiers.iter().collect();
        sorted.sort_by_key(|(t, _)| *t);
        sorted.into_iter().map(|(_, u)| u.clone()).collect()
    };
    let mut added: u64 = 0;
    // Insertion cursor: with position = the clamped start, advancing one
    // entry per URL to keep the urls list order; default = table end.
    let mut at = position.unwrap_or(ordered.len()).min(ordered.len());
    // Dedup via HashSet (removes O(n·m+m²)) + the task-level tier cap
    // (closes the unbounded RPC flood-add accumulation; entries past the
    // cap are skipped silently and under-counted in added).
    let mut seen: std::collections::HashSet<String> = ordered.iter().cloned().collect();
    for url in urls {
        if url.is_empty() || !seen.insert(url.clone()) {
            continue;
        }
        if ordered.len() >= MAX_TRACKER_TIERS {
            break;
        }
        at = at.min(ordered.len());
        ordered.insert(at, url.clone());
        added += 1;
        at += 1;
    }
    (ordered.into_iter().enumerate().collect(), added)
}

/// Tracker table transform for `taiji.removeTracker` (a pure function):
/// each of `urls` is exact-matched and **all** hit entries are removed
/// (the current table invariant of one URL per layer means removing a
/// URL removes its tier — the "announce-list tier cleanup" face; an
/// emptied table = the pure-DHT accepted shape, legal). Returns (new
/// table, removed = the number actually deleted), with tier numbers
/// compacted (0..n).
pub fn remove_trackers(tiers: &[(usize, String)], urls: &[String]) -> (Vec<(usize, String)>, u64) {
    let targets: std::collections::BTreeSet<&str> = urls.iter().map(|u| u.as_str()).collect();
    let mut removed: u64 = 0;
    let kept: Vec<(usize, String)> = {
        let mut sorted: Vec<&(usize, String)> = tiers.iter().collect();
        sorted.sort_by_key(|(t, _)| *t);
        sorted
            .into_iter()
            .filter(|(_, u)| {
                if targets.contains(u.as_str()) {
                    removed += 1;
                    false
                } else {
                    true
                }
            })
            .cloned()
            .collect()
    };
    (
        kept.into_iter()
            .enumerate()
            .map(|(i, (_, u))| (i, u))
            .collect(),
        removed,
    )
}

/// changeGlobalOption acceptance face (table-driven =
/// [`GLOBAL_PATCH_TABLE`]; rate limits / max-concurrent-downloads / the
/// dht family / bt-lsd (with the bt-enable-lpd alias) / the ban lists /
/// the hook gate / load-cookies + the four tracker keys + the Motrix
/// alignment segment — dir/seed-ratio/bt-max-peers wired value faces +
/// the no-op value-face segment). Keys outside the table are ignored
/// (gatherChangeableGlobalOption only collects the ChangeGlobalOption
/// capability bits, RpcMethod.cc). max-concurrent-downloads is clamped
/// to >= 1 (the aria2 RANGE(1..) validation semantics).
///
/// Table-driven: [`GLOBAL_PATCH_TABLE`] rows probe the payload one by
/// one (no cross-key dependencies between rows; invalid values are
/// ignored inside the arm — row order is irrelevant). `peer-id-prefix`
/// is **not accepted** (a startup-only option taking effect on restart —
/// no peer ID runtime hot-reload; listen-port/bt-enable-upnp follow the
/// same rule — none has a table row). Unknown keys fall through to
/// ignore; tests assert this explicitly.
pub fn apply_global_patch(g: &mut GlobalOptions, patch: &BTreeMap<String, String>) {
    for decl in GLOBAL_PATCH_TABLE {
        // Dispatch bits: the accepted bit + the runtime hot-reload bit
        // (non-hot-reload registration rows are not accepted — startup
        // options never reach this face).
        if !decl.face.accepted || !decl.face.runtime {
            continue;
        }
        let Some(apply) = decl.apply else {
            continue;
        };
        let Some(v) = patch.get(decl.name) else {
            continue;
        };
        apply(g, v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// `--summary-interval` cross-check test (name/default/domain/
    /// capability bits): the accepted name is registered in
    /// ARIA2_OPTION_NAMES (reference prefs.cc literal); default 60 and
    /// domain 0..=INT32_MAX anchor OptionHandlerFactory.cc (pinned, no
    /// invented values); the echo face is getGlobalOption; capability
    /// bits align with the reference — apply_global_patch has no arm for
    /// it (changeGlobalOption does not accept it).
    #[test]
    fn summary_interval_option_faces_match_aria2() {
        // Name: the reference literal + exactly one declared stance
        // (accepted, absent from the non-accepted/unwired tables).
        assert!(
            ARIA2_OPTION_NAMES.contains(&"summary-interval"),
            "an accepted name must be registered in ARIA2_OPTION_NAMES"
        );
        assert!(
            !DECLARED_NON_ACCEPTED_OPTION_NAMES
                .iter()
                .any(|(n, _)| *n == "summary-interval")
        );
        assert!(
            !DECLARED_UNWIRED_OPTION_NAMES
                .iter()
                .any(|(n, _)| *n == "summary-interval")
        );
        // Default 60 (the reference handler's third-parameter anchor).
        assert_eq!(SUMMARY_INTERVAL_DEFAULT, 60);
        // Domain 0..=INT32_MAX (the reference handler's fourth-parameter
        // anchor; 0 = disabled).
        assert_eq!(SUMMARY_INTERVAL_MAX, 2_147_483_647);
        // Echo: the default shape already contains the key, value =
        // decimal seconds string.
        let echo = global_option_echo(&GlobalOptions::default());
        assert_eq!(echo.get("summary-interval").map(String::as_str), Some("60"));
        // Capability bits: changeGlobalOption does not accept it — the
        // value stays after a patch (restart-only; the reference also has
        // it as non-changeable, the key is ignored as unknown).
        let mut g = GlobalOptions::default();
        let patch = BTreeMap::from([("summary-interval".to_string(), "5".to_string())]);
        apply_global_patch(&mut g, &patch);
        assert_eq!(
            g.summary_interval, SUMMARY_INTERVAL_DEFAULT,
            "changeGlobalOption does not accept summary-interval (capability bit aligned with aria2)"
        );
        // Echo unchanged (echo = the startup-time effective face).
        assert_eq!(
            global_option_echo(&g)
                .get("summary-interval")
                .map(String::as_str),
            Some("60")
        );
    }

    /// `--bt-tracker` comma-list parsing (trim + empty segments skipped)
    /// and the global-set echo shape (comma-joined; empty set = empty
    /// string — aria2's unset echo shape).
    #[test]
    fn bt_tracker_split_and_echo_shape() {
        assert_eq!(
            split_bt_tracker(" udp://a/announce , ,https://b/announce\n,"),
            vec!["udp://a/announce", "https://b/announce"]
        );
        assert_eq!(split_bt_tracker(""), Vec::<String>::new());
        assert_eq!(split_bt_tracker(","), Vec::<String>::new());
        let g = GlobalOptions {
            bt_tracker: vec!["udp://x/announce".into(), "udp://y/announce".into()],
            bt_tracker_file: Some(PathBuf::from("/list/all.txt")),
            ..Default::default()
        };
        let echo = global_option_echo(&g);
        assert_eq!(
            echo.get("bt-tracker").map(String::as_str),
            Some("udp://x/announce,udp://y/announce")
        );
        assert_eq!(
            echo.get("bt-tracker-file").map(String::as_str),
            Some("/list/all.txt")
        );
        let bare = global_option_echo(&GlobalOptions::default());
        assert_eq!(bare.get("bt-tracker").map(String::as_str), Some(""));
        assert_eq!(bare.get("bt-tracker-file").map(String::as_str), Some(""));
    }

    /// Three-layer merge semantics (acceptance criterion 3): union
    /// dedup, global URLs appended as independent tiers at the end (aria2
    /// bittorrent_helper.cc addAnnounceUri direct translation), the
    /// per-torrent table structure kept at the front, empty global set =
    /// identity.
    #[test]
    fn merge_global_trackers_union_dedups_and_appends_own_tiers() {
        // per-torrent: announce-list (two tiers) + a manual-edit product
        // shape.
        let per: Vec<(usize, String)> = vec![
            (0, "http://builtin1/announce".into()),
            (0, "http://builtin2/announce".into()),
            (1, "http://manual/announce".into()),
        ];
        // Empty global set = identity transform (zero change for
        // existing callers).
        assert_eq!(merge_global_trackers(&per, &[]), per);
        // Union append: duplicate URLs skipped (clashing with a tier-0
        // built-in and within the global set itself).
        let global = vec![
            "http://builtin2/announce".into(),
            "udp://g1:6969/announce".into(),
            "udp://g2:1337/announce".into(),
            "udp://g1:6969/announce".into(),
        ];
        let merged = merge_global_trackers(&per, &global);
        assert_eq!(
            merged,
            vec![
                (0, "http://builtin1/announce".to_string()),
                (0, "http://builtin2/announce".to_string()),
                (1, "http://manual/announce".to_string()),
                (2, "udp://g1:6969/announce".to_string()),
                (3, "udp://g2:1337/announce".to_string()),
            ],
            "global URLs append as their own tier at the table tail, built-in/manual entries stay in front, union-deduped"
        );
        // Tier numbers increase consecutively (from max+1); when the
        // announceList view groups by ascending tier (the group_tiers
        // consumer), global supplements sort after built-in/manual ones.
        // Empty per-torrent table (a task with no announce): the global
        // set is the whole table.
        let only_global =
            merge_global_trackers(&[], &["udp://g1:6969/announce".to_string(), String::new()]);
        assert_eq!(
            only_global,
            vec![(0, "udp://g1:6969/announce".to_string())],
            "with an empty per-torrent list the global set forms its own tier; empty URLs are skipped"
        );
    }

    /// `taiji.addTracker` table transform: per-URL independent tier
    /// append/insert, dedup idempotence, position clamping, and tier
    /// number compaction.
    #[test]
    fn add_trackers_appends_inserts_dedups_and_renumbers() {
        let base: Vec<(usize, String)> = vec![
            (0, "http://t0/announce".into()),
            (1, "http://t1/announce".into()),
        ];
        // Default = append at the end, one independent tier each (BEP12,
        // one URL per layer).
        let (t, added) = add_trackers(
            &base,
            &[
                "udp://a:6969/announce".to_string(),
                "udp://b:1337/announce".to_string(),
            ],
            None,
        );
        assert_eq!(added, 2);
        assert_eq!(
            t,
            vec![
                (0, "http://t0/announce".to_string()),
                (1, "http://t1/announce".to_string()),
                (2, "udp://a:6969/announce".to_string()),
                (3, "udp://b:1337/announce".to_string()),
            ]
        );
        // position insert: two entries at index 1, existing tiers shift +
        // numbers compact; the urls list order is kept (the insertion
        // cursor advances per entry).
        let (t, added) = add_trackers(
            &base,
            &[
                "udp://x/announce".to_string(),
                "udp://y/announce".to_string(),
            ],
            Some(1),
        );
        assert_eq!(added, 2);
        assert_eq!(
            t,
            vec![
                (0, "http://t0/announce".to_string()),
                (1, "udp://x/announce".to_string()),
                (2, "udp://y/announce".to_string()),
                (3, "http://t1/announce".to_string()),
            ]
        );
        // Dedup idempotence: existing URLs (across positions) and empty
        // strings do not count into added.
        let (t, added) = add_trackers(
            &t,
            &[
                "udp://x/announce".to_string(),
                String::new(),
                "udp://new/announce".to_string(),
            ],
            None,
        );
        assert_eq!(added, 1, "duplicate/empty URLs are skipped");
        assert_eq!(t.len(), 5);
        // Out-of-range position clamps to the table end.
        let (t, added) = add_trackers(&base, &["udp://z/announce".to_string()], Some(99));
        assert_eq!(added, 1);
        assert_eq!(t.last().map(|(_, u)| u.as_str()), Some("udp://z/announce"));
        // Empty URL list = identity (added=0; idempotent, replay-safe).
        assert_eq!(add_trackers(&base, &[], None), (base.clone(), 0));
    }

    /// `taiji.removeTracker` table transform: exact match removes all
    /// hits (tier cleanup), miss/empty-table idempotence, emptying the
    /// table = the pure-DHT face, number compaction.
    #[test]
    fn remove_trackers_exact_match_cleans_tiers_and_survives_empty() {
        let base: Vec<(usize, String)> = vec![
            (0, "http://t0/announce".into()),
            (1, "udp://t1:6969/announce".into()),
            (2, "http://t2/announce".into()),
        ];
        // One hit = tier cleanup + number compaction.
        let (t, removed) = remove_trackers(&base, &["udp://t1:6969/announce".to_string()]);
        assert_eq!(removed, 1);
        assert_eq!(
            t,
            vec![
                (0, "http://t0/announce".to_string()),
                (1, "http://t2/announce".to_string()),
            ],
            "tier renumbering is compacted after cleanup (0..n)"
        );
        // Missed URL and duplicate targets: removed counts only actual
        // deletions.
        let (t, removed) = remove_trackers(
            &base,
            &[
                "http://no-such/announce".to_string(),
                "http://t0/announce".to_string(),
                "http://t0/announce".to_string(),
            ],
        );
        assert_eq!(removed, 1);
        assert_eq!(t.len(), 2);
        // Emptying the table = the pure-DHT face (an accepted shape;
        // legal, not rejected).
        let (t, removed) = remove_trackers(
            &base,
            &[
                "http://t0/announce".to_string(),
                "udp://t1:6969/announce".to_string(),
                "http://t2/announce".to_string(),
            ],
        );
        assert_eq!((removed, t.len()), (3, 0));
        // Removing from an empty table = identity, idempotent.
        assert_eq!(
            remove_trackers(&[], &["http://x/announce".to_string()]),
            (Vec::new(), 0)
        );
    }

    #[test]
    fn global_echo_excludes_rpc_secret_and_uses_frozen_names() {
        let g = GlobalOptions {
            rpc_secret: Some("topsecret".into()),
            ..Default::default()
        };
        let echo = global_option_echo(&g);
        assert!(
            !echo.contains_key("rpc-secret"),
            "rpc-secret must never echo"
        );
        assert_eq!(
            echo.get("max-concurrent-downloads").map(String::as_str),
            Some("5")
        );
        assert_eq!(echo.get("seed-ratio").map(String::as_str), Some("1"));
        assert_eq!(echo.get("bt-max-peers").map(String::as_str), Some("55"));
        assert_eq!(echo.get("enable-dht").map(String::as_str), Some("true"));
    }

    /// rpc-user echoed when set (the reference only strips
    /// PREF_RPC_SECRET, RpcMethodImpl.cc); rpc-passwd is secret-class
    /// and never echoed.
    #[test]
    fn global_echo_covers_rpc_user_but_never_rpc_passwd() {
        let g = GlobalOptions {
            rpc_user: Some("motrix".into()),
            rpc_passwd: Some("topsecret".into()),
            ..Default::default()
        };
        let echo = global_option_echo(&g);
        assert_eq!(echo.get("rpc-user").map(String::as_str), Some("motrix"));
        assert!(
            !echo.contains_key("rpc-passwd"),
            "rpc-passwd must never echo: {echo:?}"
        );
        // Unset = the key is absent (the reference's `!defined ->
        // continue` rule).
        let bare = global_option_echo(&GlobalOptions::default());
        assert!(!bare.contains_key("rpc-user"));
    }

    #[test]
    fn size_literals_parse_with_1024_base() {
        assert_eq!(parse_size("0"), Some(0));
        assert_eq!(parse_size("10M"), Some(10 * 1024 * 1024));
        assert_eq!(parse_size("512K"), Some(512 * 1024));
        assert_eq!(parse_size("2G"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_size("abc"), None);
        assert_eq!(parse_size("M"), None);
    }

    /// Newly wired options: defaults (the SPEC §11 frozen defaults) and
    /// the getGlobalOption echo shape (aria2-compatible names; values =
    /// string faces).
    #[test]
    fn options_default_and_echo_with_frozen_names() {
        let g = GlobalOptions::default();
        assert_eq!(g.listen_port, 6881);
        assert!(!g.bt_require_crypto);
        assert_eq!(crypto_level_str(g.bt_min_crypto_level), "plain");
        assert_eq!(
            peer_connection_type_str(g.bt_peer_connection_type),
            "prefer-tcp"
        );
        let echo = global_option_echo(&g);
        assert_eq!(echo.get("listen-port").map(String::as_str), Some("6881"));
        assert_eq!(
            echo.get("bt-require-crypto").map(String::as_str),
            Some("false")
        );
        assert_eq!(
            echo.get("bt-min-crypto-level").map(String::as_str),
            Some("plain")
        );
        assert_eq!(
            echo.get("bt-peer-connection-type").map(String::as_str),
            Some("prefer-tcp")
        );
        // Echo of explicitly set values.
        let g2 = GlobalOptions {
            listen_port: 58013,
            bt_require_crypto: true,
            bt_min_crypto_level: parse_crypto_level("arc4").unwrap_or_else(|| panic!("arc4")),
            bt_peer_connection_type: parse_peer_connection_type("utp")
                .unwrap_or_else(|| panic!("utp")),
            ..Default::default()
        };
        let echo2 = global_option_echo(&g2);
        assert_eq!(echo2.get("listen-port").map(String::as_str), Some("58013"));
        assert_eq!(
            echo2.get("bt-require-crypto").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            echo2.get("bt-min-crypto-level").map(String::as_str),
            Some("arc4")
        );
        assert_eq!(
            echo2.get("bt-peer-connection-type").map(String::as_str),
            Some("utp")
        );
        // Parsers: out-of-domain values = None.
        assert_eq!(parse_crypto_level("aes"), None);
        assert_eq!(parse_peer_connection_type("quic"), None);
    }

    /// `--bt-lsd` default false (SPEC §11), the getGlobalOption echo,
    /// and changeGlobalOption acceptance (the reference
    /// setChangeGlobalOption bit, OptionHandlerFactory.cc).
    #[test]
    fn bt_lsd_default_echo_and_global_patch() {
        let g = GlobalOptions::default();
        assert!(!g.bt_lsd, "bt-lsd defaults to false (SPEC Â§11)");
        let echo = global_option_echo(&g);
        assert_eq!(echo.get("bt-lsd").map(String::as_str), Some("false"));
        let mut g2 = GlobalOptions {
            bt_lsd: true,
            ..Default::default()
        };
        assert_eq!(
            global_option_echo(&g2).get("bt-lsd").map(String::as_str),
            Some("true")
        );
        // changeGlobalOption: bool value face (aria2 "true"/"false");
        // invalid values ignored.
        let patch: BTreeMap<String, String> = [
            ("bt-lsd".to_string(), "false".to_string()),
            ("bt-lsd-typo".to_string(), "true".to_string()),
        ]
        .into_iter()
        .collect();
        apply_global_patch(&mut g2, &patch);
        assert!(!g2.bt_lsd);
    }

    #[test]
    fn global_patch_applies_subset_and_ignores_unknown() {
        let mut g = GlobalOptions::default();
        let patch: BTreeMap<String, String> = [
            ("max-concurrent-downloads".to_string(), "2".to_string()),
            ("max-overall-download-limit".to_string(), "1M".to_string()),
            ("enable-dht".to_string(), "false".to_string()),
            // dir accepted (the default download directory for later
            // tasks — consumed at the tasks.rs add faces via
            // patch.dir.unwrap_or(global.dir)); no longer the
            // "ignored" exemplar.
            ("dir".to_string(), "/elsewhere".to_string()),
            ("no-such-option".to_string(), "x".to_string()),
        ]
        .into_iter()
        .collect();
        apply_global_patch(&mut g, &patch);
        assert_eq!(g.max_concurrent_downloads, 2);
        assert_eq!(g.max_overall_download_limit, 1024 * 1024);
        assert!(!g.enable_dht);
        assert_eq!(g.dir, PathBuf::from("/elsewhere"), "dir must be accepted");
        // Clamp: 0 -> 1 (the aria2 RANGE(1..) semantics).
        let zero: BTreeMap<String, String> =
            [("max-concurrent-downloads".to_string(), "0".to_string())]
                .into_iter()
                .collect();
        apply_global_patch(&mut g, &zero);
        assert_eq!(g.max_concurrent_downloads, 1);
    }

    /// Hook option parsing (six names + the hash-check gate; empty
    /// string = blank = unset) and the getGlobalOption echo (the six
    /// names are always present, unset = empty string — aria2's echo
    /// shape).
    #[test]
    fn hook_options_parse_and_global_echo() {
        let opts: BTreeMap<String, String> = [
            (
                "on-download-start".to_string(),
                "/hooks/start.sh".to_string(),
            ),
            ("on-bt-download-complete".to_string(), String::new()), // blank → None
            (
                "bt-enable-hook-after-hash-check".to_string(),
                "false".to_string(),
            ),
            ("on-download-nope".to_string(), "/x".to_string()), // unknown name → ignored
        ]
        .into_iter()
        .collect();
        let p = parse_task_options(&opts);
        assert_eq!(
            p.hooks.on_download_start.as_deref(),
            Some("/hooks/start.sh")
        );
        assert_eq!(p.hooks.on_bt_download_complete, None);
        assert_eq!(p.hooks.bt_enable_hook_after_hash_check, Some(false));
        // Echo: the six hook names + the hash-check gate (default true,
        // aria2 same).
        let echo = global_option_echo(&GlobalOptions::default());
        for ev in crate::hook::HookEvent::ALL {
            assert_eq!(
                echo.get(ev.option_name()).map(String::as_str),
                Some(""),
                "{} must echo empty when unset",
                ev.option_name()
            );
        }
        assert_eq!(
            echo.get("bt-enable-hook-after-hash-check")
                .map(String::as_str),
            Some("true")
        );
        // changeGlobalOption: the hash-check gate is changeable (the
        // setChangeGlobalOption bit, OptionHandlerFactory.cc); the
        // on-download-* hook family is not hot-changeable.
        let mut g = GlobalOptions::default();
        let patch: BTreeMap<String, String> = [
            (
                "bt-enable-hook-after-hash-check".to_string(),
                "false".to_string(),
            ),
            ("on-download-start".to_string(), "/hot".to_string()),
        ]
        .into_iter()
        .collect();
        apply_global_patch(&mut g, &patch);
        assert!(!g.hooks.bt_enable_hook_after_hash_check);
        assert_eq!(
            g.hooks.command(crate::hook::HookEvent::Start),
            None,
            "hook commands are not runtime-changeable (aria2 same)"
        );
    }

    /// bt-metadata-web-sources (a entry) — default empty
    /// = feature off (zero HTTP outbound), changeGlobalOption replaces
    /// the whole list (empty string = clear), getGlobalOption echoes
    /// comma-joined.
    #[test]
    fn bt_metadata_web_sources_default_empty_patch_and_echo() {
        let g = GlobalOptions::default();
        assert!(g.bt_metadata_web_sources.is_empty(), "off by default");
        assert_eq!(
            global_option_echo(&g)
                .get("bt-metadata-web-sources")
                .map(String::as_str),
            Some("")
        );
        let mut g = GlobalOptions::default();
        let patch: BTreeMap<String, String> = [(
            "bt-metadata-web-sources".to_string(),
            " https://a.example/{INFOHASH} ,, https://b.example/{INFOHASH} ".to_string(),
        )]
        .into_iter()
        .collect();
        apply_global_patch(&mut g, &patch);
        assert_eq!(
            g.bt_metadata_web_sources,
            vec![
                "https://a.example/{INFOHASH}",
                "https://b.example/{INFOHASH}"
            ],
            "trimmed, empty segments skipped"
        );
        assert_eq!(
            global_option_echo(&g)
                .get("bt-metadata-web-sources")
                .map(String::as_str),
            Some("https://a.example/{INFOHASH},https://b.example/{INFOHASH}")
        );
        // Empty string = clear (back to the default-off shape).
        let clear: BTreeMap<String, String> =
            [("bt-metadata-web-sources".to_string(), String::new())]
                .into_iter()
                .collect();
        apply_global_patch(&mut g, &clear);
        assert!(g.bt_metadata_web_sources.is_empty());
    }

    #[test]
    fn task_patch_maps_max_connection_to_bt_max_peers() {
        let opts: BTreeMap<String, String> = [
            ("dir".to_string(), "/tmp/dl".to_string()),
            ("pause".to_string(), "true".to_string()),
            ("max-connection".to_string(), "80".to_string()),
            ("seed-ratio".to_string(), "3.5".to_string()),
            ("seed-time".to_string(), "30".to_string()),
            ("bt-save-metadata".to_string(), "true".to_string()),
            ("split".to_string(), "8".to_string()), // http-only key → ignored
        ]
        .into_iter()
        .collect();
        let p = parse_task_options(&opts);
        assert_eq!(p.dir, Some(PathBuf::from("/tmp/dl")));
        assert!(p.pause);
        assert_eq!(p.bt_max_peers, Some(80));
        assert_eq!(p.seed_ratio, Some(3.5));
        assert_eq!(p.seed_time_min, Some(30.0));
        assert_eq!(p.bt_save_metadata, Some(true));
    }

    /// seed-time parse-arm domain check. Extremes (1e30/inf/nan/
    /// negative) must not enter the patch — patch values convert through
    /// `Duration::from_secs_f64(m * 60.0)` (seed_policy_from/
    /// changeOption), and 1e30 minutes = 6e31 seconds overflows u64::MAX
    /// and panics: the session actor dies -> all RPC SessionClosed, and
    /// seed_time_min lands in config_json via patch_config -> bootstrap
    /// panics again on restart (persistent DoS). The upper bound =
    /// [`MAX_SEED_TIME_MIN`] (2^40 minutes); in-domain values are
    /// accepted normally.
    #[test]
    fn seed_time_patch_domain_extremes_rejected() {
        let patch_of = |v: &str| {
            parse_task_options(&BTreeMap::from([("seed-time".to_string(), v.to_string())]))
        };
        for bad in ["1e30", "inf", "-inf", "nan", "-1", "-0.001"] {
            assert_eq!(
                patch_of(bad).seed_time_min,
                None,
                "seed-time {bad:?} out of domain must not enter the patch"
            );
        }
        // Normal in-domain values (including the 2^40 =
        // 1099511627776-minute bound itself).
        assert_eq!(patch_of("0").seed_time_min, Some(0.0));
        assert_eq!(patch_of("60").seed_time_min, Some(60.0));
        assert_eq!(patch_of("5.5").seed_time_min, Some(5.5));
        assert_eq!(
            patch_of("1099511627776").seed_time_min,
            Some(1_099_511_627_776.0)
        );
        // Any finite value past the bound is rejected too (the domain
        // check is not only an inf guard).
        assert_eq!(patch_of("1099511627777").seed_time_min, None);
    }

    /// The minutes->Duration single conversion point contract. Before
    /// the fix, the five conversion sites' equivalent expression
    /// (`Duration::from_secs_f64(m * 60.0)`) panicked on 1e30 minutes
    /// ("cannot convert float seconds to Duration: value is either too
    /// big or NaN") — the session actor dies -> all RPC SessionClosed;
    /// now everything goes through [`seed_duration_from_minutes`] and
    /// out-of-domain values fold to None.
    #[test]
    fn seed_duration_from_minutes_bounds() {
        assert_eq!(seed_duration_from_minutes(0.0), Some(Duration::ZERO));
        assert_eq!(
            seed_duration_from_minutes(60.0),
            Some(Duration::from_secs(3600))
        );
        assert_eq!(
            seed_duration_from_minutes(5.5),
            Some(Duration::from_secs_f64(330.0))
        );
        // The bound itself is accepted (2^40 minutes; no precision gap
        // in-domain).
        assert_eq!(
            seed_duration_from_minutes(MAX_SEED_TIME_MIN),
            Some(Duration::from_secs(MAX_SEED_TIME_MIN as u64 * 60))
        );
        // Out of domain = None (1e30 minutes = 6e31 seconds > u64::MAX
        // ≈ 1.8e19, the old panic point); non-finite and negative values
        // are rejected likewise.
        for bad in [1e30, f64::INFINITY, f64::NEG_INFINITY, f64::NAN, -1.0] {
            assert_eq!(
                seed_duration_from_minutes(bad),
                None,
                "{bad:e} minutes must yield None, not panic/Some"
            );
        }
    }

    /// The seed-ratio domain-check single point contract. Domain =
    /// [0, ∞): 0 (a legal explicit "no criterion" value) and any finite
    /// positive value are accepted; negative/NaN/±inf are rejected
    /// (None) — a non-finite value persisted to the store projects to
    /// null via serde_json and poisons the recovery face, finite inf
    /// attaches an unsatisfiable ShareRatio criterion = seed forever. No
    /// upper bound (ratio semantics differ from the seed-time panic
    /// guard).
    #[test]
    fn checked_seed_ratio_bounds() {
        assert_eq!(checked_seed_ratio(0.0), Some(0.0));
        assert_eq!(checked_seed_ratio(1.5), Some(1.5));
        assert_eq!(checked_seed_ratio(1e300), Some(1e300));
        for bad in [
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::NAN,
            -1.0,
            -f64::MIN_POSITIVE,
        ] {
            assert_eq!(checked_seed_ratio(bad), None, "{bad:e} must yield None");
        }
    }

    /// `select-file` syntax/domain negative vectors (acceptance
    /// criterion 1): empty string, empty item, contains 0, out of domain
    /// (> 1_m), duplicates, out-of-order, overlapping ranges, inverted
    /// ranges, incomplete ranges, non-numeric, whitespace/sign — all
    /// explicitly rejected (the taiji tightening convention; aria2 only
    /// errors on non-numbers and incomplete ranges, absorbing duplicates/
    /// out-of-order via normalize and silently filtering out-of-range).
    #[test]
    fn select_file_syntax_negative_vectors() {
        let bad_cases = [
            "",
            "1,,2",
            "1,",
            ",1",
            "0",
            "1,0",
            "0-2",
            "1-0",
            "1048577",
            "1-1048577",
            "1,1",
            "2,1",
            "1-3,2",
            "1-3,3-5",
            "5-3",
            "-1",
            "1-",
            "-",
            "abc",
            "1,a",
            " 1",
            "1 ",
            "1.5",
            "0x2",
        ];
        for case in bad_cases {
            assert!(
                parse_select_file(case).is_err(),
                "negative vector {case:?} must be rejected"
            );
        }
        // Positive edge: the domain bound 1048576 (= aria2 1_m) is
        // accepted exactly; full-shape combinations.
        assert_eq!(
            parse_select_file("1048576").as_deref(),
            Ok(&[1_048_575u32][..])
        );
        assert_eq!(
            parse_select_file("1,3,5-6").as_deref(),
            Ok(&[0u32, 2, 4, 5][..])
        );
        // Error text face: the taiji.option.invalid code + the 1-based
        // syntax hint.
        let msg = match parse_select_file("0") {
            Err(m) => m,
            Ok(v) => panic!("a zero component must be rejected, got {v:?}"),
        };
        assert!(
            msg.starts_with("taiji.option.invalid: --select-file"),
            "{msg}"
        );
        assert!(msg.contains("1-based"), "{msg}");
    }

    /// The 1-based->0-based conversion single point + the range check's
    /// pad-does-not-count anchor (acceptance criterion 2): the conversion
    /// lives only in the parse function; the out-of-range anchor = the
    /// **non-pad** file count (the BEP53 client file list convention, the
    /// same anchor as the magnet so= upgrade chain).
    #[test]
    fn select_file_base_conversion_and_non_pad_anchor() {
        // 1<->0 base: aria2 "1-3,5" ≡ BEP53 so= "0-2,4" (the same
        // 0-based data face).
        assert_eq!(parse_select_file("1").as_deref(), Ok(&[0u32][..]));
        assert_eq!(
            parse_select_file("1-3,5").as_deref(),
            Ok(&[0u32, 1, 2, 4][..])
        );
        // Pad-does-not-count anchor: a 3-entry v1 list (a.bin + .pad +
        // b.bin) -> client file count = 2. 1-based "2" (= b.bin) is
        // legal; "3" (= the pad slot) is out of range.
        let file_count = 2u32;
        assert_eq!(select_file_range_error(&[1], file_count), None);
        let err = select_file_range_error(&[2], file_count)
            .unwrap_or_else(|| panic!("a pad slot must be out of bounds"));
        assert!(
            err.contains("index 3 out of range (2 files"),
            "the error echoes 1-based indexing and the non-pad count: {err}"
        );
        assert!(err.contains("padding files not counted"), "{err}");
        // An empty selection face is not a parse product (range
        // expansion is never empty); the range function is always None
        // for an empty set (defensive face).
        assert_eq!(select_file_range_error(&[], file_count), None);
    }

    /// client-ban-prefixes (a entry) — default empty list
    /// (no client banned), changeGlobalOption replaces the whole list
    /// (trim/empty segments skipped/empty string = clear), getGlobalOption
    /// echoes comma-joined.
    #[test]
    fn client_ban_prefixes_default_empty_patch_and_echo() {
        let g = GlobalOptions::default();
        assert!(
            g.client_ban_prefixes.is_empty(),
            "an empty default list bans no client (identification != banning)"
        );
        assert_eq!(
            global_option_echo(&g)
                .get("client-ban-prefixes")
                .map(String::as_str),
            Some("")
        );
        let mut g = GlobalOptions::default();
        let patch: BTreeMap<String, String> = [(
            "client-ban-prefixes".to_string(),
            " -XL , -QD ,,".to_string(),
        )]
        .into_iter()
        .collect();
        apply_global_patch(&mut g, &patch);
        assert_eq!(
            g.client_ban_prefixes,
            vec!["-XL", "-QD"],
            "trimmed, empty segments skipped"
        );
        assert_eq!(
            global_option_echo(&g)
                .get("client-ban-prefixes")
                .map(String::as_str),
            Some("-XL,-QD")
        );
        // Empty string = clear (back to the default shape).
        let clear: BTreeMap<String, String> = [("client-ban-prefixes".to_string(), String::new())]
            .into_iter()
            .collect();
        apply_global_patch(&mut g, &clear);
        assert!(g.client_ban_prefixes.is_empty());
    }

    /// `--peer-id-prefix`, three assertions — (1) default = `-TJ0001-`
    /// (byte-identical to the bt frozen constant = zero regression when
    /// unset); (2) the getGlobalOption echo (an aria2 option-table
    /// entry); (3) changeGlobalOption does not accept it (startup-only,
    /// effective on restart — no peer ID runtime hot-reload). Also: the
    /// bt `PEER_AGENT` (UA/ext-v identity string) equals this crate's
    /// `version_string` (the getVersion source) — the workspace
    /// `CARGO_PKG_VERSION` is the single version source.
    #[test]
    fn peer_id_prefix_default_echo_restart_only_and_agent_same_source() {
        let g = GlobalOptions::default();
        assert_eq!(
            g.peer_id_prefix.as_bytes(),
            taiji_bt::tracker::PEER_ID_PREFIX.as_bytes(),
            "the default prefix must match -TJ0001- byte for byte (zero regression)"
        );
        assert_eq!(g.peer_id_prefix, "-TJ0001-");
        // Echo face.
        let echo = global_option_echo(&g);
        assert_eq!(
            echo.get("peer-id-prefix").map(String::as_str),
            Some("-TJ0001-")
        );
        // Custom prefix echo (no truncation here — truncation happens at
        // the generation point generate_peer_id, aria2 erase(20) same
        // stance).
        let custom = GlobalOptions {
            peer_id_prefix: "-qB4550-".to_string(),
            ..Default::default()
        };
        assert_eq!(
            global_option_echo(&custom)
                .get("peer-id-prefix")
                .map(String::as_str),
            Some("-qB4550-")
        );
        // Startup-only option: changeGlobalOption does not accept it
        // (the unknown-key fallthrough ignores it).
        let mut g2 = GlobalOptions::default();
        let patch: BTreeMap<String, String> =
            [("peer-id-prefix".to_string(), "-HOTUPDATED-".to_string())]
                .into_iter()
                .collect();
        apply_global_patch(&mut g2, &patch);
        assert_eq!(
            g2.peer_id_prefix, "-TJ0001-",
            "not hot-reloadable (takes effect on restart)"
        );
        // The UA/ext-v string and the getVersion version string share
        // one source (the workspace version).
        assert_eq!(
            taiji_bt::tracker::PEER_AGENT,
            crate::version_string(),
            "PEER_AGENT must be the same string as the getVersion taiji/<semver>"
        );
    }

    /// `--bt-enable-upnp` / `--bt-enable-nat-pmp` — default false (zero
    /// behavior change by default: the pre-wiring nat: None shape;
    /// "defaults must not enable behavior". Upstream aria2 has no such
    /// option — verified by a full-history `git log -S` pickaxe — so
    /// there is no aria2 default to compare against; the libtorrent
    /// settings_pack.cpp default-true contrast is in the field docs);
    /// getGlobalOption echo, changeGlobalOption non-acceptance
    /// (startup-only, same rule as listen-port), and the NatConfig
    /// assembly face (override injection + boolean layering).
    #[test]
    fn nat_options_default_echo_and_config_build() {
        let g = GlobalOptions::default();
        assert!(!g.bt_enable_upnp, "false by default (zero behavior change)");
        assert!(
            !g.bt_enable_natpmp,
            "false by default (zero behavior change)"
        );
        assert!(
            !g.nat_enabled(),
            "all off = no provisioning (the nat: None shape)"
        );
        let echo = global_option_echo(&g);
        assert_eq!(
            echo.get("bt-enable-upnp").map(String::as_str),
            Some("false")
        );
        assert_eq!(
            echo.get("bt-enable-nat-pmp").map(String::as_str),
            Some("false")
        );
        // Explicitly on: the power gate (either on = powered) + echo.
        let on = GlobalOptions {
            bt_enable_upnp: true,
            ..Default::default()
        };
        assert_eq!(
            global_option_echo(&on)
                .get("bt-enable-upnp")
                .map(String::as_str),
            Some("true")
        );
        assert!(on.nat_enabled(), "a single switch on still provisions");
        // changeGlobalOption does not accept them (startup-only — same
        // rule as listen-port).
        let mut g2 = GlobalOptions {
            bt_enable_upnp: true,
            bt_enable_natpmp: true,
            ..Default::default()
        };
        let patch: BTreeMap<String, String> = [
            ("bt-enable-upnp".to_string(), "false".to_string()),
            ("bt-enable-nat-pmp".to_string(), "false".to_string()),
            ("no-such-option".to_string(), "x".to_string()),
        ]
        .into_iter()
        .collect();
        apply_global_patch(&mut g2, &patch);
        assert!(
            g2.bt_enable_upnp && g2.bt_enable_natpmp,
            "not hot-reloadable (takes effect on restart)"
        );
        // NatConfig assembly: the default booleans layer over the io
        // defaults; the injected override is the base with the booleans
        // on top (protocol switches inside the override do not escape the
        // option face).
        let cfg = g2.build_nat_config();
        assert!(cfg.enable_upnp && cfg.enable_natpmp);
        assert!(cfg.igd_device_url.is_none(), "no override = SSDP discovery");
        let overridden = taiji_io::nat::NatConfig {
            igd_device_url: Some("http://127.0.0.1:1/desc.xml".into()),
            lease: std::time::Duration::from_secs(2),
            enable_natpmp: true,
            ..Default::default()
        };
        let g3 = GlobalOptions {
            bt_enable_upnp: true,
            bt_enable_natpmp: false,
            nat_config_override: Some(overridden),
            ..Default::default()
        };
        let cfg = g3.build_nat_config();
        assert_eq!(
            cfg.igd_device_url.as_deref(),
            Some("http://127.0.0.1:1/desc.xml")
        );
        assert_eq!(cfg.lease, std::time::Duration::from_secs(2));
        assert!(cfg.enable_upnp);
        assert!(
            !cfg.enable_natpmp,
            "the boolean switches compose on top of the override (the option face is authoritative)"
        );
    }

    // ---- aria2 option diff face (per-option checks; whitelist
    // governance) ----

    /// getGlobalOption echo face, key-by-key check: every echo key must
    /// fall inside the declared universe (aria2 reference names ∪ the
    /// whitelist) — a new echo key without a declaration turns red
    /// (acceptance criterion 1: all diffs live in the declaration lists).
    /// Hook family names share one source in both places.
    #[test]
    fn global_option_echo_keys_are_fully_declared() {
        let echo = global_option_echo(&GlobalOptions::default());
        assert!(!echo.is_empty());
        for key in echo.keys() {
            assert!(
                option_name_declared(key),
                "echo key {key:?} is neither an aria2 name nor in the declared-difference whitelist —\
                 add it to DECLARED_OPTION_DIFFS (PR + approval) before echoing"
            );
        }
        // Hook option names, single source: each HookEvent-projected
        // name must be registered in the reference list (the aria2
        // same-name options, prefs.cc cross-check).
        for ev in crate::hook::HookEvent::ALL {
            assert!(
                ARIA2_OPTION_NAMES.contains(&ev.option_name()),
                "hook option name {} must be registered in ARIA2_OPTION_NAMES",
                ev.option_name()
            );
        }
    }

    /// Acceptance face, name-by-name check: all parse/direct-read tables
    /// ⊆ the declared universe; whitelist names must really be diffs (not
    /// in the reference list) and referenced by at least one acceptance
    /// face (no dead entries — bidirectional completeness of the
    /// per-option checks); every reference-list name must also have a
    /// real acceptance/echo face reference ("declared accepted but never
    /// consumed" turns red — lowest-speed-limit once slipped through:
    /// registered, marked accepted, zero consumers repo-wide).
    #[test]
    fn accepted_option_faces_are_fully_declared() {
        for name in accepted_option_names() {
            assert!(
                option_name_declared(name),
                "accepted name {name:?} is unregistered (ARIA2_OPTION_NAMES or DECLARED_OPTION_DIFFS)"
            );
        }
        // CLI-only accepted names (domain 5 onward): the acceptance face
        // = the taiji CLI top-level face / the `taiji http`
        // metalink shape (declaration entries in DECLARED_OPTION_DIFFS —
        // the unit/effect-face diffs are registered per name), while the
        // core session/RPC faces do not accept them (no parse arm, no
        // echo) — exempted from the "session acceptance/echo reference"
        // check (the mechanism stays; the list is the CLI-only registry).
        // - `metalink-servers`: per-entry mirror count cap (the
        // `taiji http` metalink shape; aria2 1.37.0 has no such name —
        // a fork extension);
        // - `stop`: the process shutdown time limit (the CLI top-level
        // face, three shapes; the unit diff is in the entry);
        // - `hash-check-only`: bare-run check-only (the CLI top-level
        // face);
        // - `peer-agent`: accepted + warning, no effect (the UA/v string
        // is pinned to the build constant).
        const CLI_ONLY_ACCEPTED: &[&str] =
            &["metalink-servers", "stop", "hash-check-only", "peer-agent"];
        for (name, _) in DECLARED_OPTION_DIFFS {
            assert!(
                !ARIA2_OPTION_NAMES.contains(name),
                "whitelist entry {name:?} is actually an aria2 option name — move it into ARIA2_OPTION_NAMES"
            );
            let referenced = accepted_option_names().any(|n| n == *name)
                || global_option_echo(&GlobalOptions::default()).contains_key(*name)
                || CLI_ONLY_ACCEPTED.contains(name);
            assert!(
                referenced,
                "whitelist entry {name:?} has no acceptance/echo face reference (dead declaration)"
            );
        }
        // The reference-list reverse-reference check (the same rule as
        // the whitelist half above): every name in the reference list
        // must really have an acceptance/echo-face reference ("declared
        // accepted yet zero-consumed" turns red — lowest-speed-limit once
        // slipped through: registered, marked accepted, zero consumers
        // repo-wide).
        let full_echo = global_option_echo(&GlobalOptions {
            rpc_user: Some("u".into()),
            save_session: Some(PathBuf::from("s")),
            ..Default::default()
        });
        for name in ARIA2_OPTION_NAMES {
            let referenced = accepted_option_names().any(|n| n == *name)
                || full_echo.contains_key(*name)
                || CLI_ONLY_ACCEPTED.contains(name);
            assert!(
                referenced,
                "aria2 name {name:?} has no acceptance/echo face reference (dead acceptance declaration —\
                 move into DECLARED_NON_ACCEPTED_OPTION_NAMES or wire it)"
            );
        }
        // The exemption list itself must not overlap the acceptance/echo
        // faces (drift narrows the exemption).
        for name in CLI_ONLY_ACCEPTED {
            assert!(
                !accepted_option_names().any(|n| n == *name) && !full_echo.contains_key(*name),
                "CLI exemption name {name:?} already has a core acceptance/echo face — remove it from the exemption list"
            );
        }
    }

    /// The HTTP base group + metalink group promised names (the total
    /// per-option stance check). Every promised name must be classified
    /// **exactly once** among "accepted (reference/whitelist), explicitly
    /// non-accepted, unwired" — a name with neither acceptance nor
    /// declaration turns red (all diffs live in the declaration lists).
    #[test]
    fn spec_b_http_metalink_promised_options_are_fully_classified() {
        let promised: &[&str] = &[
            // §7.4 HTTP base group (name by name).
            "http-scheduler",
            "http-block-size",
            "http-min-chunk",
            "http-max-chunk",
            "http-stall-window",
            "max-connection-per-server",
            "http-max-per-host",
            "split",
            "min-split-size",
            "lowest-speed-limit",
            "timeout",
            "connect-timeout",
            "max-tries",
            "retry-wait",
            "user-agent",
            "referer",
            "header",
            "load-cookies",
            "http-user",
            "http-passwd",
            "http-proxy",
            "https-proxy",
            "all-proxy",
            "no-proxy",
            "check-certificate",
            "ca-certificate",
            "checksum",
            "auto-file-renaming",
            "allow-overwrite",
            "remote-time",
            "http-incomplete-suffix",
            // §7.4 metalink group (legacy family names + group items).
            "metalink-file",
            "metalink-enable-auto-discover",
            "metalink-language",
            "metalink-location",
            "metalink-os",
            "metalink-version",
            "metalink-preferred-protocol",
            "metalink-force-protocol",
            "metalink-enable-unique-protocol",
        ];
        for name in promised {
            let accepted = option_name_declared(name);
            let declined = DECLARED_NON_ACCEPTED_OPTION_NAMES
                .iter()
                .any(|(n, _)| n == name);
            let unwired = DECLARED_UNWIRED_OPTION_NAMES.iter().any(|(n, _)| n == name);
            let votes = [accepted, declined, unwired].iter().filter(|v| **v).count();
            assert_eq!(
                votes, 1,
                "promised name {name:?} must hold exactly one stance (accepted={accepted} declined={declined} unwired={unwired})"
            );
        }
    }

    /// `--load-cookies` migrated acceptance face, four checks: exactly
    /// one declared stance (registered in ARIA2_OPTION_NAMES, removed
    /// from the two declaration tables — a targeted reinforcement of the
    /// three-tables-disjoint mechanism test); the global patch
    /// (whole-value path replacement + empty-string clear) and the echo
    /// (unset = empty string, the save-session shape).
    #[test]
    fn load_cookies_migration_acceptance_faces() {
        // Exactly one declared stance: the accepted name registered,
        // removed from the non-accepted/unwired tables.
        assert!(
            ARIA2_OPTION_NAMES.contains(&"load-cookies"),
            "an accepted name must be registered in ARIA2_OPTION_NAMES (an aria2 name, same literal as prefs.cc)"
        );
        assert!(
            !DECLARED_NON_ACCEPTED_OPTION_NAMES
                .iter()
                .any(|(n, _)| *n == "load-cookies"),
            "after migration it must not remain in the non-accepted table (dual stance = red)"
        );
        assert!(
            !DECLARED_UNWIRED_OPTION_NAMES
                .iter()
                .any(|(n, _)| *n == "load-cookies")
        );
        // Global patch: whole-value path replacement (trim) + empty
        // string = clear.
        let mut g = GlobalOptions::default();
        assert!(g.load_cookies.is_none(), "unset by default");
        let patch: BTreeMap<String, String> =
            [("load-cookies".to_string(), " /tmp/cookies.txt ".to_string())]
                .into_iter()
                .collect();
        apply_global_patch(&mut g, &patch);
        assert_eq!(
            g.load_cookies.as_deref(),
            Some(Path::new("/tmp/cookies.txt")),
            "whole-value replacement after trim"
        );
        let clear: BTreeMap<String, String> = [("load-cookies".to_string(), "  ".to_string())]
            .into_iter()
            .collect();
        apply_global_patch(&mut g, &clear);
        assert!(
            g.load_cookies.is_none(),
            "an empty string clears (restores the default shape)"
        );
        // Echo: unset = empty string; set = the path verbatim.
        let g2 = GlobalOptions {
            load_cookies: Some(Path::new("/home/u/cj.txt").to_path_buf()),
            ..Default::default()
        };
        let echo = global_option_echo(&g2);
        assert_eq!(
            echo.get("load-cookies").map(String::as_str),
            Some("/home/u/cj.txt")
        );
        assert_eq!(
            global_option_echo(&GlobalOptions::default())
                .get("load-cookies")
                .map(String::as_str),
            Some(""),
            "unset echoes as an empty string (the aria2 unset shape)"
        );
    }

    /// Guard for the non-accepted/unwired declaration tables: names in
    /// these tables never appear on any acceptance/echo face ("declared
    /// non-accepted yet accepted" = red — a name must migrate out of the
    /// table before acceptance); the three declaration tables are
    /// pairwise disjoint (the same name with two stances = red).
    #[test]
    fn non_accepted_and_unwired_tables_never_intersect_acceptance() {
        let echo = global_option_echo(&GlobalOptions::default());
        for (declared, table) in [
            (
                DECLARED_NON_ACCEPTED_OPTION_NAMES,
                "DECLARED_NON_ACCEPTED_OPTION_NAMES",
            ),
            (
                DECLARED_UNWIRED_OPTION_NAMES,
                "DECLARED_UNWIRED_OPTION_NAMES",
            ),
        ] {
            for (name, _) in declared {
                let name = *name;
                assert!(
                    !accepted_option_names().any(|n| n == name),
                    "{table} entry {name:?} appears on the acceptance face — move it into the acceptance whitelist before wiring"
                );
                assert!(
                    !echo.contains_key(name),
                    "{table} entry {name:?} appears on the echo face"
                );
                assert!(
                    !option_name_declared(name),
                    "{table} entry {name:?} is also on the acceptance whitelist (dual stance)"
                );
            }
        }
        // The reference list and the non-accepted table are disjoint (a
        // reference name that is truly not accepted = declared, and must
        // not also be registered as accepted).
        for (name, _) in DECLARED_NON_ACCEPTED_OPTION_NAMES {
            assert!(
                !ARIA2_OPTION_NAMES.contains(name),
                "{name:?} is registered both as an accepted aria2 name and in the non-accepted declaration (dual stance)"
            );
        }
    }

    /// TASK_OPTION_NAMES <-> parse_task_options parse-arm consistency:
    /// each name accepted alone with a legal value must have an
    /// observable consumer (table/arm drift turns red).
    #[test]
    fn task_option_table_matches_parser_arms() {
        let patch_of = |k: &str, v: &str| {
            parse_task_options(&BTreeMap::from([(k.to_string(), v.to_string())]))
        };
        for name in TASK_OPTION_NAMES {
            let consumed = match *name {
                "dir" => {
                    let p = patch_of(name, "/tmp/tb21-dir");
                    p.dir.is_some()
                }
                "pause" => patch_of(name, "true").pause,
                "seed-ratio" => patch_of(name, "1.5").seed_ratio == Some(1.5),
                "seed-time" => patch_of(name, "45").seed_time_min == Some(45.0),
                "bt-max-peers" => patch_of(name, "80").bt_max_peers == Some(80),
                "max-connection" => patch_of(name, "77").bt_max_peers == Some(77),
                "max-connection-per-server" => patch_of(name, "16").bt_max_peers == Some(16),
                "max-download-limit" => patch_of(name, "1M").max_download_limit.is_some(),
                "max-upload-limit" => patch_of(name, "2M").max_upload_limit.is_some(),
                "bt-save-metadata" => patch_of(name, "true").bt_save_metadata == Some(true),
                "bt-metadata-only" => patch_of(name, "true").bt_metadata_only == Some(true),
                "follow-torrent" => patch_of(name, "true").follow_torrent == Some(true),
                "pause-metadata" => patch_of(name, "true").pause_metadata == Some(true),
                "bt-load-saved-metadata" => {
                    patch_of(name, "true").bt_load_saved_metadata == Some(true)
                }
                // The per-task tracker table (accepted at the parse face;
                // the apply arm lives in the actor — declared wired=false).
                "bt-tracker" => {
                    patch_of(name, " udp://a/announce ,, ").bt_tracker
                        == Some(vec!["udp://a/announce".to_string()])
                }
                "select-file" => patch_of(name, "2").select_file.is_some(),
                // Per-task DHT flag: an observable parse-arm consumer.
                "bt-disable-dht" => patch_of(name, "true").bt_disable_dht == Some(true),
                // Webseeding switch (BEP19): an observable parse-arm
                // consumer.
                "enable-http-seeding" => patch_of(name, "false").enable_http_seeding == Some(false),
                // Sequential-download projection: an observable
                // parse-arm consumer.
                "bt-sequential-download" => {
                    patch_of(name, "true").bt_sequential_download == Some(true)
                }
                "bt-enable-hook-after-hash-check" => {
                    patch_of(name, "true").hooks.bt_enable_hook_after_hash_check == Some(true)
                }
                // Seeding-stall watchdog (seconds): an observable
                // parse-arm consumer.
                "bt-stop-timeout" => patch_of(name, "30").bt_stop_timeout_secs == Some(30),
                other => panic!("TASK_OPTION_NAMES has an unknown arm {other:?}"),
            };
            assert!(
                consumed,
                "accepted name {name:?} has no observable consumer (table/parse-arm drift)"
            );
        }
    }

    /// GLOBAL_PATCH_OPTION_NAMES <-> apply_global_patch parse-arm
    /// consistency (each name accepted alone must produce an observable
    /// state change; written independently of the defaults). The
    /// observation face = the concatenation of the observed fields
    /// (Vec<String> — bare tuples with more than 12 elements have no
    /// PartialEq/Debug).
    #[test]
    fn global_patch_table_matches_parser_arms() {
        fn observed(g: &GlobalOptions) -> Vec<String> {
            vec![
                g.max_concurrent_downloads.to_string(),
                // The four-pool budget trio.
                g.max_concurrent_seeds.to_string(),
                g.max_concurrent_checks.to_string(),
                g.media_synthesis_concurrency.to_string(),
                g.max_overall_download_limit.to_string(),
                g.max_overall_upload_limit.to_string(),
                g.enable_dht.to_string(),
                g.enable_dht6.to_string(),
                g.enable_peer_exchange.to_string(),
                g.bt_lsd.to_string(),
                g.client_ban_prefixes.join(","),
                g.bt_metadata_web_sources.join(","),
                g.hooks.bt_enable_hook_after_hash_check.to_string(),
                g.load_cookies
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default(),
                // The four tracker keys (interval/timeout pair/
                // stop-timeout).
                g.bt_tracker_interval.to_string(),
                g.bt_tracker_timeout_secs.to_string(),
                g.bt_tracker_connect_timeout_secs.to_string(),
                g.bt_stop_timeout_secs.to_string(),
                // The Motrix alignment segment (wired rows + the no-op
                // value face; the dht startup fields never change here —
                // startup-only, no patch rows).
                g.dir.display().to_string(),
                format_seed_ratio(g.seed_ratio),
                g.bt_max_peers.to_string(),
                g.dht_entry_point.as_ref().cloned().unwrap_or_default(),
                g.dht_message_timeout.to_string(),
                g.unwired_option_values
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(","),
                // The media family (unified registration) + the product faces.
                g.media_variant_policy.clone(),
                g.media_audio_lang.clone().unwrap_or_default(),
                g.media_subtitles.clone(),
                g.media_segment_concurrency.to_string(),
                g.media_staging_quota_gib.to_string(),
                g.media_staging_dir.clone().unwrap_or_default(),
                g.media_allow_private_key_url.to_string(),
                g.media_ffmpeg_path.clone(),
                g.media_archive.to_string(),
                g.media_info_json.to_string(),
            ]
        }
        for name in GLOBAL_PATCH_OPTION_NAMES {
            let mut g = GlobalOptions::default();
            let before = observed(&g);
            let value = match *name {
                // Media family: in-domain values that flip the observed
                // defaults.
                "media-variant-policy" => "resolution=720",
                "media-audio-lang" => "zh-Hans",
                "media-subtitles" => "none",
                "media-segment-concurrency" => "16",
                "media-staging-quota-gib" => "10",
                "media-staging-dir" => "/tmp/media-stage",
                "media-allow-private-key-url" => "true",
                "media-ffmpeg-path" => "path:/opt/ff",
                "media-archive" => "true",
                "media-info-json" => "true",
                "max-concurrent-downloads" => "7",
                // The four-pool budget trio (in-domain flips from the
                // defaults 16/2/2 — observable).
                "max-concurrent-seeds" => "20",
                "max-concurrent-checks" => "5",
                "media-synthesis-concurrency" => "5",
                "max-overall-download-limit" => "10M",
                "max-overall-upload-limit" => "20M",
 // Default-true switches flip to false, the rest flip to
 // true (guaranteeing an observable change).
                "enable-dht" | "bt-enable-hook-after-hash-check" | "enable-peer-exchange" => {
                    "false"
                }
                "enable-dht6" | "bt-lsd" | "bt-enable-lpd" => "true",
                "client-ban-prefixes" => "bad-client-",
                "bt-metadata-web-sources" => "https://mirror.example/{{infohash}}.torrent",
 // cookie file source path (None -> Some, observable).
                "load-cookies" => "/tmp/gc.txt",
 // The four tracker keys (in-domain values pass through —
 // interval/stop-timeout default 0 flip positive, the
 // timeout pair default 60 flips to 90, observable).
                "bt-tracker-interval" => "120",
                "bt-tracker-timeout" | "bt-tracker-connect-timeout" => "90",
                "bt-stop-timeout" => "45",
 // The Motrix alignment segment: typed rows flip their
 // defaults; the no-op rows land in the value-face map.
                "dir" => "/tmp/w3-dir",
                "seed-ratio" => "2.5",
                "bt-max-peers" => "80",
                "split" | "min-split-size" | "max-connection-per-server" | "user-agent"
                | "connect-timeout" | "timeout" | "max-tries" | "retry-wait" | "remote-time"
                | "async-dns" | "continue" | "pause" | "bt-exclude-tracker" | "all-proxy"
                | "https-proxy"
 // The max-family seam-less keys + the async-dns6 no-op
 // rows.
                | "max-download-result" | "max-file-not-found"
                | "max-resume-failure-tries" | "max-mmap-limit" | "enable-async-dns6" => {
                    "1"
                }
                other => panic!("unknown arm for GLOBAL_PATCH_OPTION_NAMES {other:?}"),
            };
            apply_global_patch(
                &mut g,
                &BTreeMap::from([(name.to_string(), value.to_string())]),
            );
            assert_ne!(
                observed(&g),
                before,
                "global accepted name {name:?} has no observable consume (table/parse-arm drift)"
            );
        }
    }

    /// Motrix alignment acceptance anchor: the full set of option names
    /// the Motrix frontend actually sends via changeGlobalOption /
    /// changeOption (extracted 2026-10 from the call sites —
    /// engine-supervisor applySpeedLimits/applyAsyncDns/
    /// applyDefaultSaveDir/applyEngineSettings(HOT_ENGINE_OPTIONS)/
    /// writeGlobalProxyOptions/post-ready continue;
    /// completed-task-startup-guard pause; tracker-manager
    /// bt-tracker/bt-exclude-tracker on both the global and per-task
    /// changeOption faces; set-selected-files select-file). Every name
    /// must land in exactly one of three classes: changeGlobalOption
    /// accepted ([`GLOBAL_PATCH_OPTION_NAMES`]) / a direct actor command
    /// arm (the bt-tracker/bt-tracker-file global import) / an explicit
    /// non-acceptance declaration ([`DECLARED_NON_ACCEPTED_OPTION_NAMES`]
    /// — the proxy-family and lowest-speed-limit ADR stances, untouched
    /// by this batch). An unclassified sent name = red (the
    /// "actually-sent subset 100% classified" bidirectional pin).
    #[test]
    fn motrix_sent_rpc_options_are_fully_classified() {
        let sent_global: &[&str] = &[
            // engine-supervisor.ts sends (including all 14
            // HOT_ENGINE_OPTIONS names).
            "max-overall-download-limit",
            "max-overall-upload-limit",
            "async-dns",
            "dir",
            "max-concurrent-downloads",
            "max-connection-per-server",
            "split",
            "min-split-size",
            "user-agent",
            "connect-timeout",
            "timeout",
            "max-tries",
            "retry-wait",
            "lowest-speed-limit",
            "bt-max-peers",
            "bt-enable-lpd",
            "seed-ratio",
            "remote-time",
            // writeGlobalProxyOptions, the 13 proxy-family names
            // (+ proxy-method).
            "all-proxy",
            "http-proxy",
            "http-proxy-user",
            "http-proxy-passwd",
            "https-proxy",
            "https-proxy-user",
            "https-proxy-passwd",
            "ftp-proxy",
            "ftp-proxy-user",
            "ftp-proxy-passwd",
            "all-proxy-user",
            "all-proxy-passwd",
            "no-proxy",
            "proxy-method",
            // The post-ready seed + the guard startup flow + the global
            // curated tracker hot update.
            "continue",
            "pause",
            "bt-tracker",
            "bt-exclude-tracker",
        ];
        // The direct actor command-arm face (outside apply_global_patch —
        // the commands.rs ChangeGlobalOption arm).
        const ACTOR_GLOBAL_ARMS: &[&str] = &["bt-tracker", "bt-tracker-file"];
        for name in sent_global {
            let accepted =
                GLOBAL_PATCH_OPTION_NAMES.contains(name) || ACTOR_GLOBAL_ARMS.contains(name);
            let declined = DECLARED_NON_ACCEPTED_OPTION_NAMES
                .iter()
                .any(|(n, _)| n == name);
            assert!(
                accepted || declined,
                "Motrix-sent changeGlobalOption name {name:?} is unclassified (needs an \
                 acceptance or an explicit non-acceptance declaration)"
            );
        }
        // The changeOption face: Motrix only sends bt-tracker /
        // select-file — both must sit on the per-task acceptance face.
        for name in ["bt-tracker", "select-file"] {
            assert!(
                TASK_OPTION_NAMES.contains(&name),
                "Motrix-sent changeOption name {name:?} is not on the per-task acceptance face"
            );
        }
    }

    /// The Motrix alignment wired-row anchor: the wired=true rows (the
    /// values land in existing engine-consumed fields — consume points
    /// noted) vs the no-op rows (wired=false — only the value-face map
    /// moves) boundary pin: dir/seed-ratio change the fields themselves,
    /// bt-enable-lpd shares the bt-lsd slot, and the no-op rows do not
    /// spill into any behavior field (zero mutation outside
    /// unwired_option_values).
    #[test]
    fn motrix_wired_rows_reach_consumed_fields_and_noop_rows_do_not() {
        // wired=true: dir (the later-tasks default directory consume
        // point).
        let mut g = GlobalOptions::default();
        apply_global_patch(
            &mut g,
            &BTreeMap::from([("dir".to_string(), "/w3/dir".to_string())]),
        );
        assert_eq!(g.dir, PathBuf::from("/w3/dir"));
        // wired=true: seed-ratio (the add-face seeding-criterion default
        // consume point).
        let mut g = GlobalOptions::default();
        apply_global_patch(
            &mut g,
            &BTreeMap::from([("seed-ratio".to_string(), "2.5".to_string())]),
        );
        assert_eq!(g.seed_ratio, 2.5);
        // Out-of-domain values are ignored (a negative ratio does not
        // enter).
        apply_global_patch(
            &mut g,
            &BTreeMap::from([("seed-ratio".to_string(), "-1".to_string())]),
        );
        assert_eq!(g.seed_ratio, 2.5);
        // wired=true: the bt-enable-lpd alias row shares the bt-lsd slot
        // (the LSD service gate consume field); both echo keys show the
        // same value.
        let mut g = GlobalOptions::default();
        apply_global_patch(
            &mut g,
            &BTreeMap::from([("bt-enable-lpd".to_string(), "true".to_string())]),
        );
        assert!(g.bt_lsd);
        let echo = global_option_echo(&g);
        assert_eq!(echo.get("bt-enable-lpd").map(String::as_str), Some("true"));
        assert_eq!(echo.get("bt-lsd").map(String::as_str), Some("true"));
        // wired=false: the no-op rows only move the value-face map (zero
        // mutation of the behavior fields — field-by-field against the
        // wired=true rows' reachable face). Nested 2-tuples: a bare tuple
        // with more than 12 elements has no PartialEq/Debug.
        let mut g = GlobalOptions::default();
        let snapshot = (
            (
                g.max_concurrent_downloads,
                g.max_overall_download_limit,
                g.max_overall_upload_limit,
                g.enable_dht,
                g.enable_dht6,
                g.enable_peer_exchange,
                g.bt_lsd,
                g.dir.clone(),
                g.seed_ratio,
                g.bt_max_peers,
            ),
            (
                g.load_cookies.clone(),
                g.dht_entry_point.clone(),
                g.dht_message_timeout,
            ),
        );
        apply_global_patch(
            &mut g,
            &BTreeMap::from([
                ("split".to_string(), "8".to_string()),
                ("user-agent".to_string(), "motrix-w3/1.0".to_string()),
                ("async-dns".to_string(), "false".to_string()),
                ("continue".to_string(), "true".to_string()),
                ("pause".to_string(), "false".to_string()),
                ("bt-exclude-tracker".to_string(), String::new()),
                ("all-proxy".to_string(), "http://127.0.0.1:7890".to_string()),
            ]),
        );
        assert_eq!(
            (
                (
                    g.max_concurrent_downloads,
                    g.max_overall_download_limit,
                    g.max_overall_upload_limit,
                    g.enable_dht,
                    g.enable_dht6,
                    g.enable_peer_exchange,
                    g.bt_lsd,
                    g.dir.clone(),
                    g.seed_ratio,
                    g.bt_max_peers,
                ),
                (
                    g.load_cookies.clone(),
                    g.dht_entry_point.clone(),
                    g.dht_message_timeout,
                ),
            ),
            snapshot,
            "no-op rows must not touch any behavior field"
        );
        // Value face: the raw value recorded + an unset key echoes the
        // empty string (the save-session unset shape).
        let echo = global_option_echo(&g);
        assert_eq!(
            echo.get("user-agent").map(String::as_str),
            Some("motrix-w3/1.0")
        );
        assert_eq!(echo.get("async-dns").map(String::as_str), Some("false"));
        assert_eq!(echo.get("bt-exclude-tracker").map(String::as_str), Some(""));
        assert_eq!(echo.get("timeout").map(String::as_str), Some(""));
        // An empty-string value = an recorded empty string (the value face
        // stores it directly — unlike load-cookies' "empty = clear"
        // semantics: a no-op row has no default to restore).
        assert_eq!(
            g.unwired_option_values.get("bt-exclude-tracker"),
            Some(&String::new())
        );
    }

    /// The max/dht/enable-family adjudication anchor (the aria2 1.37.0
    /// OptionHandlerFactory.cc capability-bit pins).
    ///
    /// (a) enable-peer-exchange: default true (A2_V_TRUE); a typed
    /// hot-reload row.
    /// (b) dht-entry-point/dht-message-timeout: startup-only session
    /// fields — unset/10s defaults; changeGlobalOption does not accept
    /// them (the reference has no change bit); the 1..=60 domain
    /// constants are pinned (no invented domains).
    /// (c) The no-op row family: max-download-result/max-file-not-found/
    /// max-resume-failure-tries/max-mmap-limit/enable-async-dns6 only
    /// enter the value-face map (zero behavior-field mutation);
    /// dht-listen-port/dht-file-path are declared non-accepted (on no
    /// acceptance/echo face).
    #[test]
    fn w3c_max_dht_enable_faces_match_reference() {
        // (a) enable-peer-exchange: default true (the aria2 A2_V_TRUE
        // default) + hot flip to false + echo.
        let g = GlobalOptions::default();
        assert!(g.enable_peer_exchange, "the aria2 A2_V_TRUE default");
        assert_eq!(
            global_option_echo(&g)
                .get("enable-peer-exchange")
                .map(String::as_str),
            Some("true")
        );
        let mut g = GlobalOptions::default();
        apply_global_patch(
            &mut g,
            &BTreeMap::from([("enable-peer-exchange".to_string(), "false".to_string())]),
        );
        assert!(!g.enable_peer_exchange);
        // (b) The DHT startup group: default shapes + changeGlobalOption
        // non-acceptance + the domain constant anchors.
        let g = GlobalOptions::default();
        assert_eq!(g.dht_entry_point, None);
        assert_eq!(g.dht_message_timeout, DHT_MESSAGE_TIMEOUT_DEFAULT_SECS);
        assert_eq!(DHT_MESSAGE_TIMEOUT_DEFAULT_SECS, 10);
        assert_eq!(DHT_MESSAGE_TIMEOUT_MIN_SECS, 1);
        assert_eq!(DHT_MESSAGE_TIMEOUT_MAX_SECS, 60);
        let echo = global_option_echo(&g);
        assert_eq!(echo.get("dht-entry-point").map(String::as_str), Some(""));
        assert_eq!(
            echo.get("dht-message-timeout").map(String::as_str),
            Some("10")
        );
        let mut g = GlobalOptions::default();
        apply_global_patch(
            &mut g,
            &BTreeMap::from([
                ("dht-entry-point".to_string(), "h:1".to_string()),
                ("dht-message-timeout".to_string(), "30".to_string()),
            ]),
        );
        assert_eq!(
            g.dht_entry_point, None,
            "dht-entry-point has no changeGlobal arm (the reference is equally non-changeable)"
        );
        assert_eq!(
            g.dht_message_timeout, DHT_MESSAGE_TIMEOUT_DEFAULT_SECS,
            "dht-message-timeout has no changeGlobal arm (the reference same)"
        );
        // Set values echo (the CLI/conf injection face).
        let g2 = GlobalOptions {
            dht_entry_point: Some("router.bittorrent.com:6881".to_string()),
            dht_message_timeout: 30,
            ..Default::default()
        };
        let echo2 = global_option_echo(&g2);
        assert_eq!(
            echo2.get("dht-entry-point").map(String::as_str),
            Some("router.bittorrent.com:6881")
        );
        assert_eq!(
            echo2.get("dht-message-timeout").map(String::as_str),
            Some("30")
        );
        // (c) The no-op row family: zero behavior-field mutation
        // (field-by-field — only the value-face map moves).
        let mut g = GlobalOptions::default();
        let snapshot = (
            g.enable_peer_exchange,
            g.dht_entry_point.clone(),
            g.dht_message_timeout,
        );
        apply_global_patch(
            &mut g,
            &BTreeMap::from([
                ("max-download-result".to_string(), "500".to_string()),
                ("max-file-not-found".to_string(), "5".to_string()),
                ("max-resume-failure-tries".to_string(), "3".to_string()),
                ("max-mmap-limit".to_string(), "16M".to_string()),
                ("enable-async-dns6".to_string(), "true".to_string()),
            ]),
        );
        assert_eq!(
            (
                g.enable_peer_exchange,
                g.dht_entry_point.clone(),
                g.dht_message_timeout,
            ),
            snapshot,
            "the no-op row family must not touch any behavior field"
        );
        let echo = global_option_echo(&g);
        assert_eq!(
            echo.get("max-download-result").map(String::as_str),
            Some("500")
        );
        assert_eq!(
            echo.get("enable-async-dns6").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            echo.get("max-mmap-limit").map(String::as_str),
            Some("16M"),
            "a no-op row echoes the last accepted raw value"
        );
        // An unset key echoes the empty string (the unset shape).
        assert_eq!(
            global_option_echo(&GlobalOptions::default())
                .get("max-file-not-found")
                .map(String::as_str),
            Some("")
        );
        // Non-accepted declared names never appear on the echo/acceptance
        // faces (the non_accepted-table discipline, pinned here for the
        // two DHT names).
        for name in ["dht-listen-port", "dht-file-path"] {
            assert!(
                !global_option_echo(&GlobalOptions::default()).contains_key(name),
                "{name} is declared non-accepted and must not echo"
            );
            assert!(
                !option_name_declared(name),
                "{name} must not enter the acceptance whitelist"
            );
        }
    }

    /// Value-domain table for the four tracker keys (ignored inside the
    /// changeGlobalOption arm — aria2's "unacceptable options ignored"
    /// rule): the tracker timeout pair domain 1..=600 (0/601 out of range
    /// = ignored, keeping the default 60), interval/stop-timeout accept
    /// the full u64 domain (0 = the default semantics), non-numbers are
    /// ignored.
    #[test]
    fn w3b_global_keys_domain_decision_table() {
        let patch_of = |k: &str, v: &str| {
            let mut g = GlobalOptions::default();
            apply_global_patch(&mut g, &BTreeMap::from([(k.to_string(), v.to_string())]));
            g
        };
        // tracker-timeout domain 1..=600: 0 out of domain ignored, 1 the
        // lower bound accepted, 600 the upper bound accepted, 601 out of
        // domain ignored, non-numeric ignored — the default 60 always
        // survives in the ignore arm.
        assert_eq!(
            patch_of("bt-tracker-timeout", "0").bt_tracker_timeout_secs,
            60
        );
        assert_eq!(
            patch_of("bt-tracker-timeout", "1").bt_tracker_timeout_secs,
            1
        );
        assert_eq!(
            patch_of("bt-tracker-timeout", "600").bt_tracker_timeout_secs,
            600
        );
        assert_eq!(
            patch_of("bt-tracker-timeout", "601").bt_tracker_timeout_secs,
            60
        );
        assert_eq!(
            patch_of("bt-tracker-timeout", "abc").bt_tracker_timeout_secs,
            60
        );
        // connect-timeout: same domain, same rule.
        assert_eq!(
            patch_of("bt-tracker-connect-timeout", "0").bt_tracker_connect_timeout_secs,
            60
        );
        assert_eq!(
            patch_of("bt-tracker-connect-timeout", "600").bt_tracker_connect_timeout_secs,
            600
        );
        assert_eq!(
            patch_of("bt-tracker-connect-timeout", "-1").bt_tracker_connect_timeout_secs,
            60
        );
        // interval/stop-timeout: 0 = the explicit default semantics (no
        // override / no watchdog), accepted.
        assert_eq!(patch_of("bt-tracker-interval", "0").bt_tracker_interval, 0);
        assert_eq!(
            patch_of("bt-tracker-interval", "900").bt_tracker_interval,
            900
        );
        assert_eq!(patch_of("bt-tracker-interval", "x").bt_tracker_interval, 0);
        assert_eq!(patch_of("bt-stop-timeout", "0").bt_stop_timeout_secs, 0);
        assert_eq!(patch_of("bt-stop-timeout", "75").bt_stop_timeout_secs, 75);
        // Task-face bt-stop-timeout: legal values enter the patch,
        // invalid values are ignored (None = not given = fall back to the
        // global value — the "unacceptable options ignored" rule).
        assert_eq!(
            parse_task_options(&BTreeMap::from([(
                "bt-stop-timeout".to_string(),
                "30".to_string()
            )]))
            .bt_stop_timeout_secs,
            Some(30)
        );
        assert_eq!(
            parse_task_options(&BTreeMap::from([(
                "bt-stop-timeout".to_string(),
                "-4".to_string()
            )]))
            .bt_stop_timeout_secs,
            None
        );
    }

    /// Echo projection for the four tracker keys: all four sit on the
    /// getGlobalOption echo face (the table rows' echo bits), value shape
    /// = decimal seconds strings (the aria2 getGlobalOption value shape);
    /// the default value shapes (0/60/60/0) match the aria2 defaults.
    #[test]
    fn w3b_global_keys_echo_faces() {
        let e = global_option_echo(&GlobalOptions::default());
        assert_eq!(e.get("bt-tracker-interval").map(String::as_str), Some("0"));
        assert_eq!(e.get("bt-tracker-timeout").map(String::as_str), Some("60"));
        assert_eq!(
            e.get("bt-tracker-connect-timeout").map(String::as_str),
            Some("60")
        );
        assert_eq!(e.get("bt-stop-timeout").map(String::as_str), Some("0"));
        // After a hot reload the echo follows (the echo-bit projection
        // reads the live value).
        let mut g = GlobalOptions::default();
        apply_global_patch(
            &mut g,
            &BTreeMap::from([
                ("bt-tracker-interval".to_string(), "120".to_string()),
                ("bt-stop-timeout".to_string(), "45".to_string()),
            ]),
        );
        let e = global_option_echo(&g);
        assert_eq!(
            e.get("bt-tracker-interval").map(String::as_str),
            Some("120")
        );
        assert_eq!(e.get("bt-stop-timeout").map(String::as_str), Some("45"));
    }

    /// Declaration tables <-> accepted-name mirror consistency (the
    /// registration-completeness axis of the table-driven rework): static
    /// row names and the cfg(test) name constants match **position by
    /// position** (missing a new option on either side turns red); row
    /// names are unique; task-table rows = task-creation payload bits,
    /// global-table rows = hot-reload + echo bits (the echo projection
    /// key set = the table row name set — global_option_echo projects
    /// from the table, and hand-written keys must not overlap it).
    #[test]
    fn option_decl_tables_mirror_name_consts() {
        // Task table: static-row (apply arm row) names match
        // TASK_OPTION_NAMES position by position; the manual arm row (the
        // hook family dynamic name set) does not enter the mirror (the
        // HookEvent single source).
        let task_static: Vec<&str> = TASK_OPTION_TABLE
            .iter()
            .filter(|d| d.apply.is_some())
            .map(|d| d.name)
            .collect();
        assert_eq!(task_static, TASK_OPTION_NAMES);
        // Row names unique (the precondition for find-driven direct
        // lookup).
        let mut names: Vec<&str> = TASK_OPTION_TABLE.iter().map(|d| d.name).collect();
        let n = names.len();
        names.dedup();
        assert_eq!(names.len(), n, "task-table row names must be unique");
        // Task-table row bit truthfulness: always accepted; apply rows =
        // task-creation payload bits; exactly one manual arm row
        // (apply = None + dynamic name match), bits = initial values
        // fixed at add time (non-persist).
        let manual_rows: Vec<_> = TASK_OPTION_TABLE
            .iter()
            .filter(|d| d.apply.is_none())
            .collect();
        assert_eq!(
            manual_rows.len(),
            1,
            "exactly one task-table manual-arm row (the hook family)"
        );
        for decl in TASK_OPTION_TABLE {
            assert!(
                decl.face.accepted,
                "task-table row {:?} must be accepted",
                decl.name
            );
            if decl.apply.is_some() {
                assert!(
                    decl.face.persist && !decl.face.runtime,
                    "task-table apply row {:?} sits on the task-creation payload face",
                    decl.name
                );
            }
        }
        assert!(
            !manual_rows[0].face.persist && !manual_rows[0].face.runtime,
            "the hook-family manual-arm row fixes the initial value at add time (not persisted, not hot-reloadable)"
        );

        // Global table: row names = GLOBAL_PATCH_OPTION_NAMES position
        // by position; all accepted + hot-reload bit + echo bit
        // registered; the echo projection key set = the table row name
        // set.
        let global_names: Vec<&str> = GLOBAL_PATCH_TABLE.iter().map(|d| d.name).collect();
        assert_eq!(global_names, GLOBAL_PATCH_OPTION_NAMES);
        let mut gnames = global_names.clone();
        gnames.dedup();
        assert_eq!(
            gnames.len(),
            global_names.len(),
            "global-table row names must be unique"
        );
        for decl in GLOBAL_PATCH_TABLE {
            assert!(
                decl.face.accepted && decl.face.runtime,
                "global-table row {:?} = accepted + changeGlobalOption hot-reload slot",
                decl.name
            );
            assert!(
                decl.face.echo.is_some(),
                "global-table row {:?} must be registered on the echo slot (the getGlobalOption face)",
                decl.name
            );
        }
        let echo = global_option_echo(&GlobalOptions::default());
        for name in GLOBAL_PATCH_OPTION_NAMES {
            assert!(
                echo.contains_key(*name),
                "the echo face is missing declaration-table row {name:?} (table-projection break)"
            );
        }
    }

    /// Task-table manual arm registration completeness (governance axis:
    /// "every explicit arm has a registration, every registration has an
    /// arm"): the dynamic name-set row's (hook family) predicate hit set
    /// = the HookEvent::ALL projected names — each consumed exactly by
    /// that row (zero overlap with static rows); the predicate never
    /// matches non-hook names among all declared-face names (accepted ∪
    /// non-accepted ∪ unwired) — an over-broad predicate would swallow
    /// unknown keys.
    #[test]
    fn task_table_manual_arm_registration_complete() {
        let manual: Vec<_> = TASK_OPTION_TABLE
            .iter()
            .filter(|d| d.manual_match.is_some())
            .collect();
        assert_eq!(
            manual.len(),
            1,
            "exactly one manual-arm row in the dynamic name set"
        );
        let manual = manual[0];
        assert!(
            manual.apply.is_none(),
            "the manual-arm row apply must be None"
        );
        let hook_names: Vec<&str> = crate::hook::HookEvent::ALL
            .iter()
            .map(|ev| ev.option_name())
            .collect();
        for name in &hook_names {
            let hits = TASK_OPTION_TABLE
                .iter()
                .filter(|d| d.name == *name || d.manual_match.is_some_and(|m| m(name)))
                .count();
            assert_eq!(
                hits, 1,
                "hook option name {name:?} must be consumed exclusively by the manual-arm row (zero static-row overlap)"
            );
        }
        // Predicate closure: the hit set = the hook name set
        // (declared-face non-hook names never match).
        for (name, _) in DECLARED_OPTION_DIFFS
            .iter()
            .chain(DECLARED_NON_ACCEPTED_OPTION_NAMES.iter())
            .chain(DECLARED_UNWIRED_OPTION_NAMES.iter())
        {
            assert!(
                !manual.manual_match.is_some_and(|m| m(name)) || hook_names.contains(name),
                "the manual-arm predicate swallowed a non-hook declaration name {name:?}"
            );
        }
        for name in ARIA2_OPTION_NAMES {
            assert!(
                !manual.manual_match.is_some_and(|m| m(name)) || hook_names.contains(name),
                "the manual-arm predicate swallowed a non-hook aria2 name {name:?}"
            );
        }
    }
}

/// Caps and dedup table: the two-level tracker caps + HashSet dedup
/// semantics.
#[test]
fn bt_caps_decision_table() {
    use super::*;
    // Cap values anchored.
    assert_eq!(MAX_TRACKER_TIERS, 256);
    assert_eq!(MAX_GLOBAL_TRACKERS, 1024);
    // add_trackers: 301 new URLs -> the table holds exactly 256;
    // added = 256 - existing.
    let (t, added) = add_trackers(
        &[],
        &(0..301)
            .map(|i| format!("http://t{i}/ann"))
            .collect::<Vec<_>>(),
        None,
    );
    assert_eq!(t.len(), 256, "per-task tier cap");
    assert_eq!(added, 256);
    // Dedup idempotence (HashSet semantics): adding the same URL again
    // adds nothing.
    let (t2, added2) = add_trackers(&t, &[t[0].1.clone()], None);
    assert_eq!(added2, 0);
    assert_eq!(t2.len(), 256);
    // merge_global_trackers: 250 existing + 100 new global -> truncated
    // at exactly 256.
    let base: Vec<(usize, String)> = (0..250).map(|i| (i, format!("http://b{i}/a"))).collect();
    let global: Vec<String> = (0..100).map(|i| format!("http://g{i}/a")).collect();
    let merged = merge_global_trackers(&base, &global);
    assert_eq!(merged.len(), 256, "truncated within the merge cap");
    // Existing content stays at the front.
    assert!(merged.iter().take(250).all(|(i, _)| *i < 250));
}
