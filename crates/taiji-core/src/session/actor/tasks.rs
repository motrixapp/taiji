//! Task face: activation (`activate`: full spawn chain for metainfo /
//! magnet / URL fetch), teardown dispatch (`handle_ended`: pause
//! requeue to front / restart / `DownloadResult`), the add/remove/pause/unpause
//! lifecycle, metadata upgrade (`upgrade_from_fetched` / paused residency),
//! and identity dedup.
//!
//! Owns the control flow from enqueue through activation to terminal
//! dispatch. Does not own command intake (commands), persistence payloads
//! (persist), or shutdown propagation (lifecycle).
//!
//! Upstream anchor mapping: docs/design/core.md

use super::*;
use crate::session::queue::RetireOutcome;

impl SessionActor {
    fn allocate_task_gid(
        &mut self,
        options: &BTreeMap<String, String>,
    ) -> Result<Gid, SessionError> {
        let Some(value) = options.get("gid") else {
            return Ok(self.gid.allocate());
        };
        if value.len() != 16 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(SessionError::failed(
                "gid must contain 16 hexadecimal characters",
            ));
        }
        let raw =
            u64::from_str_radix(value, 16).map_err(|_| SessionError::failed("invalid gid"))?;
        if raw == 0 || !self.gid.reserve_unique(raw) {
            return Err(SessionError::failed("gid is already in use or zero"));
        }
        Ok(Gid::from_u64(raw))
    }

    /// Activate a queue item: spawn the engine / magnet full chain /
    /// metadata fetch per payload.
    /// `reuse` is the existing task token carried over by the URL metadata
    /// upgrade path (`None` otherwise).
    pub(super) async fn activate(&mut self, gid: Gid, reuse: Option<CancellationToken>) {
        let token = reuse.unwrap_or_else(|| self.token.child_token());
        // Media activation consumes the token after the jobs-borrow
        // match (the other arms move it into RunningTask inline).
        let token_clone = token.clone();
        let events = self.events.clone();
        // LSD handle readiness face: when bt-lsd=true the first task
        // activation lazily spawns the session-level service (isomorphic to
        // aria2 building the receiver in BtSetup for the first BT download).
        // Taken before the mutable borrow of `jobs` to avoid overlapping
        // borrows.
        let lsd = self.lsd_ready().await;
        // Ban-face payload snapshot (identity rules + unexpired manual
        // bans); taken before the mutable borrow of `jobs` — pushed to the
        // engine after spawn via EngineHandle::set_ban_config, the same
        // point as the MagnetUpgraded notice arm in the activation path.
        let ban_config = self.ban_config_payload();
        // Recovery event relay closure (taken before the mutable borrow of
        // `jobs`, same reason as above; the torrent and magnet paths share
        // the same HookRunner mount point).
        let recovery_relay = self.recovery_relay(gid);
        // Startup recovery (task activation / upgrade face): read back the
        // recovered layers from the derived table, re-validate the admission
        // semantics, and merge them into the metadata — the engine is
        // assembled fully configured (missing-layer gating stays closed;
        // recovered layers survive restart). The read-back completes before
        // the mutable borrow of `jobs` (restore takes &self).
        let meta_restored = match self.jobs.get(&gid) {
            Some(Job::Torrent(tj)) => Some(self.restore_recovered_layers(gid, &tj.metainfo).await),
            _ => None,
        };
        let Some(job) = self.jobs.get_mut(&gid) else {
            self.queue.drop_active(gid);
            // Seed-side activations register in the seeding registry
            // before spawning (activate_seed); a vanished payload must
            // not leak the registry entry.
            self.queue.remove_seeding(gid);
            return;
        };
        // Media activation payload (hoisted out of the jobs borrow; the
        // arm below only stashes it).
        let mut media_pending: Option<crate::session::media::MediaRunConfig> = None;
        match job {
            Job::Torrent(tj) => {
                // EngineConfig assembly is pure CPU (metainfo layout /
                // vector builds); the main loop does zero disk IO (parses
                // over 1MiB never run on the main loop).
                // The metainfo takes its post-recovery-merge shape (no row /
                // not merged = the original).
                let meta = match meta_restored {
                    Some(m) => m,
                    None => Arc::clone(&tj.metainfo),
                };
                let dir = tj.dir.clone();
                let mut seed = tj.seed.clone();
                // Flag consumption: activation injects the global
                // bt-detach-seed-only into SeedPolicy → completion flips to
                // seed-only → engine end EngineEnd::Detached.
                seed.detach_seed_only = self.global.bt_detach_seed_only;
                // Effective DHT value: session `enable-dht` combined with
                // the task-level `bt-disable-dht` override (None = follow
                // the session; the private flag is separately suppressed by
                // the engine's BEP27 gate).
                let dht_enabled = self.global.enable_dht && !tj.bt_disable_dht.unwrap_or(false);
                // Effective webseeding value (BEP19): None = default true =
                // url-list projection unchanged; false = clear the webseed
                // set (the build_engine_config override point, same rule as
                // the bare CLI run).
                let webseeding_enabled = tj.enable_http_seeding.unwrap_or(true);
                // Rate-limit topology: global bucket (session-shared
                // instance) + this module's bucket (0 = unlimited).
                let limiter = self
                    .limits
                    .torrent_set(tj.max_download_limit, tj.max_upload_limit);
                // Task-final hook set (resolved at add time; fixed during
                // activation).
                let hook_set = Arc::clone(&tj.hooks);
                // Single generation point: the prefix comes from the session
                // option `--peer-id-prefix` (the default `-TJ0001-` is a
                // byte-exact regression anchor); this peer_id feeds both
                // tracker announce and peer handshake via EngineConfig (one
                // source, one value — the announce-side TrackerWiring.peer_id
                // and the handshake-side DialCtx.peer_id consume the same
                // field; assemble.rs wires the single source).
                let peer_id = generate_peer_id(self.global.peer_id_prefix.as_bytes(), rand::random);
                // Three-layer merge (the EngineConfig injection face):
                // effective = per-torrent table (built-in announce-list ∪
                // tracker edits via taiji.addTracker/removeTracker) ∪ the
                // global imported set. aria2's `adjustAnnounceUri` rewrites
                // the announce-list tiers in place (bittorrent_helper.cc);
                // the merge result is also written back to the job mirror
                // (same surface as tellStatus announceList / config_json
                // persistence). An empty global set is the identity
                // transform.
                let tiers = {
                    let global = self.global.bt_tracker.clone();
                    merge_global_trackers(&tj.tiers, &global)
                };
                tj.tiers = tiers.clone();
                // BEP53 selection-face snapshot (taken before the `jobs`
                // borrow ends; pushed after spawn).
                let selected_files = tj.selected_files.clone();
                // File multi-level priority snapshot, likewise pushed after
                // spawn (selection order takes effect before the first
                // dispatch round).
                let file_priorities = tj.file_priorities.clone();
                // ut_holepunch switch snapshot (taken before the `jobs`
                // borrow ends).
                let holepunch_enabled = tj.holepunch;
                // Scheduler policy snapshot (taken before the `jobs` borrow
                // ends; pushed after spawn when non-default — consumed
                // before announce/discovery connects).
                let scheduler_policy = tj.scheduler_policy.clone();
                // Disk tier override snapshot (taken before the `jobs`
                // borrow ends; injected into EngineConfig.disk_policy at
                // activation).
                let disk_tier = tj.disk_tier.clone();
                let total_len = tj.total_len;
                // listen-port + crypto policy injected from global options
                // (CryptoPolicy semantics per face in engine.rs: outbound,
                // inbound, announce).
                let listen_port = self.global.listen_port;
                let crypto = taiji_bt::mse::CryptoPolicy {
                    require_crypto: self.global.bt_require_crypto,
                    min_level: self.global.bt_min_crypto_level,
                };
                // NAT consumption snapshot (an engine clone of the session
                // singleton supervisor; None = both switches off — the
                // existing nat: None shape is unchanged). Field-disjoint
                // borrow, same discipline as self.global.
                let network = crate::nat::PeerNetworkBinding::new(rand::random());
                let nat_engine = Some(
                    network.observe(
                        self.nat
                            .as_ref()
                            .map(|s| s.engine())
                            .unwrap_or_else(|| network.engine()),
                    ),
                );
                // Announce client option snapshot (`--bt-tracker-interval`
                // / `--bt-tracker-timeout` / `--bt-tracker-connect-timeout`
                // injected from global options; taken before the
                // spawn_blocking closure's borrow ends).
                let tracker_options = taiji_bt::tracker::TrackerOptions {
                    bt_tracker_interval: self.global.bt_tracker_interval,
                    bt_tracker_timeout: Duration::from_secs(self.global.bt_tracker_timeout_secs),
                    bt_tracker_connect_timeout: Duration::from_secs(
                        self.global.bt_tracker_connect_timeout_secs,
                    ),
                    ..taiji_bt::tracker::TrackerOptions::default()
                };
                // PEX gate + DHT entry point / message timeout snapshotted
                // from the global options (activation-time injection — the
                // same point as build_engine_config; the bare-run CLI form
                // in main.rs mirrors it). dht-entry-point None = the
                // SPEC §6.7 router fallback constant default; message-timeout
                // default 10s = the frozen taiji-bt DHT_MESSAGE_TIMEOUT
                // default (zero change when unset).
                let peer_exchange = self.global.enable_peer_exchange;
                let dht_entry_point = self.global.dht_entry_point.clone();
                let dht_entry_point6 = self.global.dht_entry_point6.clone();
                let dht_message_timeout = self.global.dht_message_timeout;
                let built = tokio::task::spawn_blocking(move || {
                    build_engine_config(
                        meta,
                        dir,
                        peer_id,
                        seed,
                        dht_enabled,
                        listen_port,
                        crypto,
                        disk_tier,
                        webseeding_enabled,
                        tracker_options,
                    )
                })
                .await;
                let mut config = match built {
                    Ok(Ok(c)) => c,
                    Ok(Err(e)) => {
                        warn!(target: "taiji::core::session", gid = %gid, %e,
                            "engine config build failed; task recorded as error");
                        let entry =
                            self.build_result_entry(gid, StatusKind::Error, total_len, 0, None);
                        self.queue.retire_active(gid, entry);
                        self.jobs.remove(&gid);
                        return;
                    }
                    Err(e) => {
                        warn!(target: "taiji::core::session", gid = %gid, %e,
                            "engine config build join failed");
                        let entry =
                            self.build_result_entry(gid, StatusKind::Error, total_len, 0, None);
                        self.queue.retire_active(gid, entry);
                        self.jobs.remove(&gid);
                        return;
                    }
                };
                // Attach the rate-limit topology (shared global bucket +
                // this module's bucket).
                config.limiter = Some(Arc::clone(&limiter));
                // Hook runner (argv payload mirrors executeHookByOptName in
                // util.cc: firstFilename = first requested file path,
                // numFiles = requested file count; requested = non-padding
                // real files — BEP47 pad regions are placeholders, not file
                // entries). Shares one instance with the engine. The runner
                // is always attached (even with an empty command set) — it
                // also relays the event bus: the engine-side BtComplete
                // trigger (the notification half of aria2
                // DefaultPieceStorage.cc) comes back through here; spawning
                // with an empty command set still costs nothing.
                let bus = self.bus.clone();
                let notice_tx = self.events.clone();
                let notify: Arc<dyn Fn(HookEvent) + Send + Sync> = Arc::new(move |ev| {
                    // Relay BtComplete only: Start/Pause/Stop/Complete/Error
                    // are published directly by the actor (prevents double
                    // publishing).
                    if ev == HookEvent::BtComplete {
                        let _ = bus.send(SessionEvent {
                            gid,
                            kind: EventKind::BtComplete,
                        });
                        // Status snapshot cache invalidation notice (the
                        // invalidation half of the STATUS_CACHE_TTL read
                        // seam): BtComplete is not task teardown (the task
                        // stays resident seeding, no Ended notice), so the
                        // completion event must trigger invalidation itself
                        // — otherwise post-completion polls hit the
                        // pre-completion sample (a 0-byte snapshot). The
                        // closure runs in the engine thread's sync context:
                        // try_send degrades to the TTL fallback when full or
                        // closed, never blocking the engine thread; the
                        // notice is enqueued before the frontend can query
                        // after receiving the completion event (WS frame
                        // outbound + one RPC round trip), so the event arm
                        // digests it first.
                        let _ = notice_tx.try_send(TaskNotice::StatusDirty { gid });
                        // Seed-pool transfer trigger: the
                        // same completion-flips-to-seeding moment, the same
                        // relay, one more notice — zero new channel (the
                        // frozen engine protocol face's net addition). The
                        // actor arm is idempotent; a dropped notice under
                        // channel pressure degrades to the earlier shape
                        // (that one task seeds on the active face) —
                        // bounded by the same 64-slot budget that bounds
                        // StatusDirty.
                        let _ = notice_tx.try_send(TaskNotice::SeedingStarted { gid });
                    }
                });
                let files = config.layout.files();
                let num_files = files.iter().filter(|f| !f.padding).count();
                let first_filename = files
                    .iter()
                    .find(|f| !f.padding)
                    .map(|f| config.dest.join(&f.path).to_string_lossy().into_owned())
                    .unwrap_or_default();
                // Recovery event relay mounted in the same slot
                // (taiji.recovery* — engine-side missing-layer / upgrade
                // convergence points → extension event bus).
                let hook = Arc::new(
                    HookRunner::new(Arc::clone(&hook_set), gid, num_files, first_filename)
                        .with_notify(notify)
                        .with_recovery_notify(Arc::clone(&recovery_relay)),
                );
                config.hook = Some(Arc::clone(&hook));
                // Inject the session metrics counter face (the data source
                // for the engine tick/event/store pipeline feed points).
                config.stats = Some(Arc::clone(&self.metrics));
                // NAT consumption injection (same point as
                // build_engine_config; None = unpowered, zero change). The
                // engine triggers Map once listen-port is settled (TCP+UDP,
                // 60min renewal); external port changes flow through the 2s
                // tick into the DHT announce refresh (existing consumers in
                // assemble/tick). A mapping failure degrades without
                // blocking the download (assemble semantics).
                config.nat = nat_engine;
                // Options-face injection (→ EngineConfig): the PEX gate
                // (default true = the engine_config default — an explicit
                // override so an explicit false is honored); the DHT entry
                // point (Some = replaces the SPEC §6.7 router fallback
                // constant); the message timeout (default 10s, the frozen
                // bt::dht default — zero change when unset).
                config.peer_exchange = peer_exchange;
                if let Some(ep) = dht_entry_point {
                    config.dht.entry_points_v4 = vec![ep];
                }
                if let Some(ep) = dht_entry_point6 {
                    config.dht.entry_points_v6 = vec![ep];
                }
                config.dht.engine.message_timeout =
                    std::time::Duration::from_secs(dht_message_timeout);
                config.initial_selection = selected_files.clone();
                let (engine, join) = DownloadEngine::spawn_controlled(
                    config,
                    TrackerWireConfig {
                        tiers: tiers.clone(),
                        // Injected — tracker/progress/bitfield rows and
                        // recovery cardinality all flow through this handle
                        // (engine-side auto-save every 60s + terminal values
                        // at teardown).
                        persist: self.persist.as_ref().map(|h| (gid.to_string(), h.clone())),
                        guard: None,
                    },
                    &token,
                    // Outbound transport plan (--bt-peer-connection-type,
                    // four states).
                    self.global.bt_peer_connection_type,
                );
                // ut_holepunch internal switch load (default enabled = no
                // command sent; only the disable path pushes; effective for
                // new connections). A closed channel = engine already dead
                // (the join teardown path handles it); silently ignored
                // here.
                if !holepunch_enabled {
                    let _ = engine.disable_holepunch().await;
                }
                // Scheduler policy load (default rarest_first = no command
                // sent; only non-default values are pushed). An engine-side
                // validation rejection (e.g. a restored payload for a policy
                // this build does not implement) → the engine keeps its
                // default policy; warn, never silent, never kill the task.
                if scheduler_policy != crate::engine::SchedulerPolicy::default() {
                    if let Err(e) = engine.set_scheduler_policy(scheduler_policy.clone()).await {
                        warn!(target: "taiji::core::session", gid = %gid, %e,
                            "scheduler policy push skipped (engine keeps default)");
                    }
                }
                // Ban face pushed at activation (consumed by the engine
                // before announce/discovery connects — identity rules +
                // unexpired manual bans; local handle only, never holds
                // self across await).
                let (ban_clients, ban_manual) = ban_config.clone();
                if let Err(e) = engine.set_ban_config(ban_clients, ban_manual).await {
                    debug!(target: "taiji::core::session", gid = %gid, %e,
                        "ban config push skipped (engine already down)");
                }
                // BEP53: selection pushed at activation (consumed by the
                // engine before announce connects); an out-of-range or empty
                // selection = explicit failure → task recorded as error
                // (silently ignoring is forbidden by the BEP53 surface
                // design).
                if let Some(sel) = selected_files {
                    if let Err(e) = engine.set_file_selection(Arc::from(sel.as_slice())).await {
                        warn!(target: "taiji::core::session", gid = %gid, %e,
                            "file selection rejected; task recorded as error");
                        let entry =
                            self.build_result_entry(gid, StatusKind::Error, total_len, 0, None);
                        self.queue.retire_active(gid, entry);
                        self.jobs.remove(&gid);
                        return;
                    }
                }
                // Priority face pushed at activation (a projection
                // validation failure is handled like the selection face —
                // the restored payload already passed write-side validation,
                // so this is a defensive explicit failure, never silent).
                if let Some(pr) = file_priorities {
                    if let Err(e) = engine.set_file_priority(Arc::from(pr.as_slice())).await {
                        warn!(target: "taiji::core::session", gid = %gid, %e,
                            "file priority rejected; task recorded as error");
                        let entry =
                            self.build_result_entry(gid, StatusKind::Error, total_len, 0, None);
                        self.queue.retire_active(gid, entry);
                        self.jobs.remove(&gid);
                        return;
                    }
                }
                let abort = join.abort_handle();
                // Panic counter feed point (real panics only; abort /
                // teardown do not count).
                let panic_metrics = Arc::clone(&self.metrics);
                tokio::spawn(async move {
                    let outcome = match join.await {
                        Ok(end) => TaskOutcome::Engine(end),
                        Err(e) => {
                            if e.is_panic() {
                                panic_metrics.note_panic();
                            }
                            TaskOutcome::Engine(EngineEnd::Failed(format!(
                                "engine task aborted: {e}"
                            )))
                        }
                    };
                    let _ = events.send(TaskNotice::Ended { gid, outcome }).await;
                });
                self.running.insert(
                    gid,
                    RunningTask {
                        network: Some(network),
                        token,
                        backend: TaskBackend::Engine {
                            engine,
                            status_cache: None,
                        },
                        tiers,
                        total_len,
                        abort: Some(abort),
                        // Limiter handle shared with the engine: the
                        // changeOption live hot-reload point.
                        limiter: Some(limiter),
                        hook: Some(hook),
                    },
                );
                // bt-lsd announce face (BEP14). The gate mirrors aria2
                // BtSetup.cc: private torrents disabled (BEP27 disables
                // DHT/PEX/LSD); v2-only without a v1 infohash has no
                // announce carrier (the BEP14 payload is the 20B v1 hash;
                // the magnet.rs LSD branch follows the same rule). The
                // announce port is the NAT external port snapshot
                // (effective: TCP mapping preferred); with no mapping /
                // unpowered it falls back to the --listen-port option
                // (current behavior, zero change; if the engine binds a
                // fallback port the two may diverge — a known pre-existing
                // gap this module does not fix). At activation the mapping
                // usually has not completed yet (mapping triggers
                // asynchronously inside engine assemble) → the first
                // announce mostly reports the fallback value; once the
                // external port is ready, the main-loop watch arm refreshes
                // the bt::lsd port slot (effective on the next natural
                // announce cycle — no extra re-announce cadence is added;
                // see mod.rs run()).
                let lsd_ih = if tj.metainfo.private {
                    debug!(target: "taiji::core::session", gid = %gid,
                        "lsd announce skipped: private torrent (BEP27)");
                    None
                } else {
                    tj.metainfo.meta.identity.v1
                };
                if let Some(ih) = lsd_ih {
                    if let Some(h) = lsd.as_ref() {
                        let lsd_port = crate::nat::resolve_announce_port(
                            self.nat.as_ref().map(|s| s.engine().external_ports()),
                            listen_port,
                        );
                        match h.announce(ih, lsd_port).await {
                            Ok(()) => {
                                self.lsd_announced.insert(gid, ih);
                            }
                            Err(e) => warn!(target: "taiji::core::session", gid = %gid, %e,
                                "lsd announce failed"),
                        }
                    }
                }
                // Start trigger point (mirrors aria2 RequestGroupMan.cc at
                // group activation; restart/unpause re-activations hit the
                // same face). Hook first, event notice after (same order as
                // the reference).
                if let Some(h) = self.running.get(&gid).and_then(|t| t.hook.as_ref()) {
                    h.fire(HookEvent::Start);
                }
                self.publish(gid, EventKind::Start);
                // Activation → row state downloading (terminal dispatch
                // rewrites per flags); a seed-side activation (complete
                // content, the seed pool) writes the seeding residence
                // state instead.
                let state = if self.queue.contains_seeding(gid) {
                    TaskPhase::Seeding
                } else {
                    TaskPhase::Downloading
                };
                self.persist_transition(gid, state).await;
            }
            Job::Magnet(mj) => {
                // The metadata phase and the post-upgrade engine share one
                // limiter set (RunningTask holds the same Arc — the
                // changeOption live hot-reload point spans both phases).
                let limiter = self
                    .limits
                    .torrent_set(mj.max_download_limit, mj.max_upload_limit);
                // Hook runner — metadata phase = in-memory download
                // projection (numFiles=0 / firstFilename="", the
                // inMemoryDownload branch of util.cc); magnet.rs's in-place
                // upgrade re-mounts the real file payload via set_payload
                // and hands the upgraded engine across. The runner is always
                // attached — the upgraded engine's BtComplete relay (same as
                // the Torrent branch) returns through this same instance.
                let bus = self.bus.clone();
                let notice_tx = self.events.clone();
                let notify: Arc<dyn Fn(HookEvent) + Send + Sync> = Arc::new(move |ev| {
                    // Relay BtComplete only (prevents double publishing with
                    // the actor publish point).
                    if ev == HookEvent::BtComplete {
                        let _ = bus.send(SessionEvent {
                            gid,
                            kind: EventKind::BtComplete,
                        });
                        // Status snapshot cache invalidation notice (same
                        // point and rule as the Torrent branch; the metadata
                        // phase backend has no cache slot so invalidation is
                        // a no-op — only the post-upgrade engine shape holds
                        // an entry).
                        let _ = notice_tx.try_send(TaskNotice::StatusDirty { gid });
                        // Seed-pool transfer trigger (same point and rule as
                        // the Torrent branch — the upgraded engine's
                        // completion relay grows the same one notice).
                        let _ = notice_tx.try_send(TaskNotice::SeedingStarted { gid });
                    }
                });
                // The upgraded engine may lack layers (v2 metadata can have
                // no piece layers) — the recovery event relay mounts in the
                // same slot (same as the torrent path).
                let hook = Arc::new(
                    HookRunner::new(Arc::clone(&mj.hooks), gid, 0, String::new())
                        .with_notify(notify)
                        .with_recovery_notify(Arc::clone(&recovery_relay)),
                );
                // RunningTask and MagnetTaskConfig share the same runner
                // instance.
                let cfg_hook = hook.clone();
                // bt-lsd=true → the magnet metadata phase attaches the
                // session-level LSD subscription (PeerFound → ut_metadata
                // dial, consumed in magnet.rs; announce is also self-driven
                // through the handle in this phase, v1 face only). Magnets
                // have no private form (BEP27 always allows, same note in
                // magnet.rs). A lazy service spawn failure = None →
                // tracker/DHT discovery fallback (same rule as the reference
                // receiver init failure; no fake capability).
                let lsd_lease = lsd.as_ref().map(|h| {
                    let events = h.subscribe();
                    crate::magnet::LsdLease {
                        handle: h.clone(),
                        events,
                    }
                });
                // bt-enable-dht=true → the magnet metadata phase attaches a
                // dedicated DhtEngine (BEP42 derived node_id +
                // get_peers/announce → PeersFound → ut_metadata dial;
                // closes the tracker-only-zero-delivery pending-items gap).
                // Lease lifetime: consumed by the metadata phase, and the
                // demux keep-alive handle ends with the task token (see the
                // spawn_phase_dht module docs). Assembly failure = None →
                // tracker/LSD discovery fallback (no fake capability).
                // Effective DHT value: session value combined with the task
                // flag override (None = follow the session) — the metadata
                // phase lease and the upgraded engine agree.
                let task_dht_enabled =
                    self.global.enable_dht && !mj.bt_disable_dht.unwrap_or(false);
                let dht_lease = None;
                let tiers = merge_global_trackers(&mj.tiers, &self.global.bt_tracker);
                let (tracker_updates, tracker_receiver) =
                    tokio::sync::watch::channel(tiers.clone());
                let network = crate::nat::PeerNetworkBinding::new(rand::random());
                let nat_engine = network.observe(
                    self.nat
                        .as_ref()
                        .map(|s| s.engine())
                        .unwrap_or_else(|| network.engine()),
                );
                let cfg = MagnetTaskConfig {
                    services: Some(self.magnet_services.clone()),
                    dht_entry_point_v6_override: self.global.dht_entry_point6.clone(),
                    dht_message_timeout: Duration::from_secs(self.global.dht_message_timeout),
                    dht_ipv6_enabled: self.global.enable_dht6,
                    nat: Some(nat_engine),
                    tracker_updates: Some(tracker_receiver),
                    dht_entry_point_override: self.global.dht_entry_point.clone(),
                    gid,
                    magnet_uri: mj.magnet_uri.clone(),
                    dest: mj.dest.clone(),
                    // Single generation point: the same session prefix
                    // option (metadata-phase announce/handshake share one
                    // source and value — this config's single peer_id field
                    // serves both faces; the upgraded engine regenerates
                    // from the same option on the activation path).
                    peer_id: generate_peer_id(self.global.peer_id_prefix.as_bytes(), rand::random),
                    options: mj.options.clone(),
                    // Metadata-phase lease faces: LSD lease as above; DHT
                    // lease = the dedicated metadata-phase engine (above).
                    // Magnets have no private form (BEP27 always allows; the
                    // DhtTarget construction gate re-checks).
                    dht: dht_lease,
                    dht_entry_points: Vec::new(),
                    // Upgraded engine DHT switch (session global semantics
                    // combined with the task flag — the synthesis point; the
                    // torrent activation path injects at the same point in
                    // build_engine_config — without this injection the
                    // upgraded engine's DHT is always off).
                    dht_enabled: task_dht_enabled,
                    // Upgraded engine webseeding switch (BEP19; None =
                    // default on — url-list projection unchanged; false =
                    // clear the webseed set. The torrent activation path
                    // overrides at the same point in build_engine_config).
                    webseeding_enabled: mj.enable_http_seeding.unwrap_or(true),
                    lsd: lsd_lease,
                    // The metadata phase announces on the global
                    // --listen-port (previously always 0 = ephemeral port
                    // semantics, possibly inconsistent with the upgraded
                    // engine's actual bound port).
                    phase: crate::magnet::MetadataPhaseConfig {
                        listen_port: self.global.listen_port,
                        max_metadata_peers: if self.global.bt_max_peers == 0 {
                            32
                        } else {
                            self.global.bt_max_peers.min(32)
                        },
                        ..crate::magnet::MetadataPhaseConfig::default()
                    },
                    seed: mj.seed.clone(),
                    seed_after_complete: true,
                    // Post-upgrade engine row persistence injection (the
                    // metadata phase writes no rows — rows belong to the
                    // upgraded engine's session, same note in magnet.rs).
                    persist: self.persist.as_ref().map(|h| (gid.to_string(), h.clone())),
                    // select-file option value (0-based) handed across the
                    // upgrade chain (magnet.rs merges it with the URI so=
                    // value — the two sources are mutually exclusive; range
                    // validation is deferred until metadata is ready).
                    select_file: mj.selected_files.clone(),
                    limiter: Some(Arc::clone(&limiter)),
                    hook: Some(hook),
                    // Mirror template set snapshotted per task from the
                    // global option (hot reload applies to later tasks
                    // immediately); the health table is shared across tasks
                    // (a session field). An empty list / all invalid = None
                    // = the fourth source is off (zero HTTP egress).
                    web: if self.global.bt_metadata_web_sources.is_empty() {
                        None
                    } else {
                        Some(Arc::new(crate::magnet::WebMirrors::new(
                            crate::magnet::parse_web_mirror_templates(
                                &self.global.bt_metadata_web_sources,
                            ),
                            Arc::clone(&self.web_health),
                        )))
                    },
                    // Session metrics handed to the upgraded engine (the
                    // torrent activation path injects config.stats at the
                    // same point — without it the upgrade chain shows
                    // all-zero /metrics and a fake 0/0 announce face).
                    stats: Some(Arc::clone(&self.metrics)),
                    // Session-level IpGuard snapshot injection (a uniform
                    // ban gate for the metadata phase's four-way dialing;
                    // hot reload = re-stored snapshot at ban config change
                    // points, live tasks read the latest at each dial — the
                    // push_all_ban_configs extension).
                    ip_guard: Some(self.meta_guard.clone()),
                };
                // Controlled spawn — upgrade notification face (the upgraded
                // engine handle returns to the session, followedBy served as
                // given + live readings, SPEC §7.1).
                let (join, mut upgrade_rx) = MagnetEngine::spawn_with_upgrade_notify(cfg, &token);
                let abort = join.abort_handle();
                // Upgrade and teardown notifications merge into a single
                // per-task forwarder — on this FIFO event channel
                // MagnetUpgraded is always enqueued before Ended. Two
                // independent spawn tasks previously raced the enqueue
                // order; with a fast engine teardown
                // (Detached/SeedStopped/Failed/cancel) Ended could overtake,
                // the actor retired first and the late-arrival guard
                // silently dropped the upgrade notice, so the upgraded flag
                // never set and followedBy never appeared.
                let up_events = events.clone();
                let up_gid = gid;
                tokio::spawn(async move {
                    if let Some(handle) = upgrade_rx.recv().await {
                        let _ = up_events
                            .send(TaskNotice::MagnetUpgraded {
                                gid: up_gid,
                                handle,
                            })
                            .await;
                    }
                    // Wait for teardown only after the upgrade channel
                    // closes (no upgrade before teardown / notice already
                    // delivered) — Ended always follows the upgrade notice.
                    let outcome = match join.await {
                        Ok(end) => TaskOutcome::Magnet(end),
                        Err(e) => TaskOutcome::Engine(EngineEnd::Failed(format!(
                            "magnet task aborted: {e}"
                        ))),
                    };
                    let _ = up_events
                        .send(TaskNotice::Ended {
                            gid: up_gid,
                            outcome,
                        })
                        .await;
                });
                self.running.insert(
                    gid,
                    RunningTask {
                        network: Some(network),
                        token,
                        // The metadata phase has no live handle (the upgrade
                        // notification swaps in the Engine in place).
                        backend: TaskBackend::Metadata {
                            tracker_updates: Some(tracker_updates),
                        },
                        tiers,
                        total_len: 0,
                        abort: Some(abort),
                        limiter: Some(limiter),
                        // The magnet task runner is shared across phases
                        // (metadata → upgrade).
                        hook: Some(cfg_hook),
                    },
                );
                // Start trigger point (metadata phase activation hits the
                // same face; RequestGroupMan.cc). Hook first, notice after.
                if let Some(h) = self.running.get(&gid).and_then(|t| t.hook.as_ref()) {
                    h.fire(HookEvent::Start);
                }
                self.publish(gid, EventKind::Start);
            }
            Job::TorrentUrl { url, .. } => {
                let url = url.clone();
                let fetch_token = token.clone();
                // Fetch phase = in-memory projection runner (same as the
                // magnet metadata phase; util.cc).
                let hook = if let Some(Job::TorrentUrl { hooks, .. }) = self.jobs.get(&gid) {
                    if hooks.has_any_command() {
                        Some(Arc::new(HookRunner::new(
                            Arc::clone(hooks),
                            gid,
                            0,
                            String::new(),
                        )))
                    } else {
                        None
                    }
                } else {
                    None
                };
                tokio::spawn(async move {
                    let outcome = fetch_torrent_bytes(&url, &fetch_token).await;
                    let _ = events.send(TaskNotice::Ended { gid, outcome }).await;
                });
                self.running.insert(
                    gid,
                    RunningTask {
                        network: None,
                        token,
                        // The fetch phase has no live handle (the upgrade
                        // swaps in the Engine in place).
                        backend: TaskBackend::Metadata {
                            tracker_updates: None,
                        },
                        tiers: Vec::new(),
                        total_len: 0,
                        // A metadata fetch task has no engine to abort;
                        // cancellation goes through the token.
                        abort: None,
                        // No peer connections in the fetch phase; a new
                        // limiter set takes over after the upgrade.
                        limiter: None,
                        hook,
                    },
                );
                // Start trigger point (fetch phase activation hits the same
                // face; RequestGroupMan.cc). Hook first, notice after.
                if let Some(h) = self.running.get(&gid).and_then(|t| t.hook.as_ref()) {
                    h.fire(HookEvent::Start);
                }
                self.publish(gid, EventKind::Start);
            }
            Job::Http(hj) => {
                // HTTP task activation: the driver spawn carries the whole
                // Probing→Planning→Downloading chain (see the http_task
                // module docs). The rate limiter set matches BT tasks
                // (two-bucket topology).
                // Cookie reseed on reactivation (the in-session
                // reactivation face): cookies captured in the previous run were
                // persisted on the 2s write-back cadence, so reactivation
                // reads back the latest set — otherwise pause→resume
                // requests would only carry the bootstrap-time seeds. A read
                // failure / missing row keeps the existing seeds (degrade,
                // no fake).
                let load_t0 = std::time::Instant::now();
                if let Some(p) = self.persist.as_ref()
                    && let Ok(Some(snap)) = p.load_http_task(&gid.to_string()).await
                {
                    hj.cookies = snap.cookies;
                    // The durable set replaces intake seeds, not supplements them.
                    hj.cookie_seed.clear();
                }
                debug!(target: "taiji::core::session", gid = %gid,
                    load_us = load_t0.elapsed().as_micros() as u64,
                    "activate: http row load (persist round-trip)");
                let limiter = self
                    .limits
                    .torrent_set(hj.max_download_limit, hj.max_upload_limit);
                // Hook runner: session-side Start/stop-family trigger
                // points mounted the same way (in-memory projection shape —
                // the filename payload is unknown before Planning, so
                // numFiles=0 / firstFilename="", same rule as util.cc; HTTP
                // tasks have no engine-side BtComplete trigger).
                let hook = if hj.hooks.has_any_command() {
                    Some(Arc::new(HookRunner::new(
                        Arc::clone(&hj.hooks),
                        gid,
                        0,
                        String::new(),
                    )))
                } else {
                    None
                };
                // Per-task cap intent restoration — a task whose row carries
                // `host_cap` restores its cap via the same channel addUri
                // uses (HostCap::set_cap, last-set-wins) on (re)activation;
                // a task without this payload does nothing (no contamination
                // — no row write, no cap touch). The session HostCap
                // initialization semantics (CLI / global option) are
                // unchanged: restoration is the cross-restart continuation
                // of the runtime adjustment channel, not an initialization
                // rewrite; addUri's immediate set_cap keeps in-session
                // last-set-wins (the first activation after add replays the
                // same value idempotently; a resume activation's replay =
                // semantically a new last-set, the same as "a later addUri
                // overrides the earlier value" at runtime).
                if let Some(cap) = hj
                    .restore
                    .as_ref()
                    .and_then(|row| http_task::task_host_cap(&row.config_json))
                {
                    self.http_per_host.set_cap(cap);
                }
                // Copy the submission instant out first (Copy): decouples
                // the trailing self.row_seq() from hj's last use (NLL borrow
                // face).
                let submitted = hj.submitted;
                // Task cookie store prefill (injection seam): the injection
                // seeds (structured direct pass / load-cookies file load)
                // seed the driver-shared store; the cookie write-back loop
                // then persists them (snapshot ∪ baseline), and Set-Cookie
                // capture keeps absorbing into the same store.
                let task_cookies = taiji_http::cookies::CookieStore::new();
                task_cookies.seed(hj.cookie_seed.iter().cloned());
                let mut opts = hj.opts.clone();
                if hj.restore.as_ref().is_some_and(|row| {
                    let cfg = http_task::HttpPersistConfig::from_json(&row.config_json);
                    cfg.retain_request_context || cfg.origin_fork_key.is_some()
                }) {
                    opts.runtime_defaults = self
                        .global
                        .motrix_http_defaults
                        .iter()
                        .filter(|(key, _)| {
                            matches!(
                                key.as_str(),
                                "all-proxy"
                                    | "http-proxy"
                                    | "https-proxy"
                                    | "ftp-proxy"
                                    | "no-proxy"
                                    | "user-agent"
                            )
                        })
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect();
                }
                let run = http_task::HttpTaskRun {
                    notices: Some(events.clone()),
                    gid,
                    uris: hj.uris.clone(),
                    dir: hj.dir.clone(),
                    out: hj.out.clone(),
                    restore: hj.restore.clone(),
                    row_mirror: hj.mirror.clone(),
                    cookies: hj.cookies.clone(),
                    task_cookies,
                    opts,
                    per_host: self.http_per_host.clone(),
                    queue_pos: self.row_seq(),
                    persist: self.persist.clone(),
                    limiter: Some(Arc::clone(&limiter)),
                    token: token.clone(),
                    metrics: Arc::clone(&self.metrics),
                    trace: http_task::ChainTrace::with_origin(submitted),
                };
                let (live, mirror, pause, join) = http_task::spawn_http_task(run);
                if let Some(Job::Http(hj)) = self.jobs.get_mut(&gid) {
                    hj.mirror = Some(mirror.clone());
                }
                let abort = join.abort_handle();
                // Teardown watcher: DriveStop → TaskOutcome (same face as
                // the torrent engine watcher; a driver panic closes the task
                // as an error).
                let panic_metrics = Arc::clone(&self.metrics);
                tokio::spawn(async move {
                    let outcome = match join.await {
                        Ok(http_task::DriveStop::Done {
                            total_len,
                            completed_len,
                        }) => TaskOutcome::Http(http_task::HttpEnd {
                            total_len,
                            completed_len,
                            note: None,
                            error_engine: None,
                        }),
                        Ok(http_task::DriveStop::Cancelled) => TaskOutcome::Cancelled,
                        Ok(http_task::DriveStop::Failed { failure, message }) => {
                            TaskOutcome::Http(http_task::HttpEnd {
                                total_len: 0,
                                completed_len: 0,
                                note: Some(message),
                                error_engine: Some(failure),
                            })
                        }
                        // The 412 restart signal is consumed inside the
                        // drive loop's budget under normal operation — this
                        // is a defensive arm (invariant backstop): if it
                        // escapes, the driver is structurally broken; close
                        // as an explicit failure (never fake done/cancel).
                        Ok(http_task::DriveStop::ContentRestart) => {
                            TaskOutcome::Http(http_task::HttpEnd {
                                total_len: 0,
                                completed_len: 0,
                                note: Some(
                                    "taiji.http.bad_range: content restart escaped the \
                                     driver loop (invariant violation)"
                                        .into(),
                                ),
                                error_engine: Some(super::super::view::EngineFailure::bare(
                                    "taiji.http.bad_range",
                                )),
                            })
                        }
                        Err(e) => {
                            if e.is_panic() {
                                panic_metrics.note_panic();
                            }
                            TaskOutcome::Http(http_task::HttpEnd {
                                total_len: 0,
                                completed_len: 0,
                                note: Some(format!("http task aborted: {e}")),
                                error_engine: None,
                            })
                        }
                    };
                    let _ = events.send(TaskNotice::Ended { gid, outcome }).await;
                });
                self.running.insert(
                    gid,
                    RunningTask {
                        network: None,
                        token,
                        // The driver trio assembled at once (live readings /
                        // row mirror / pause flag — spawn_http_task returns
                        // them together).
                        backend: TaskBackend::Http {
                            live,
                            row: mirror,
                            pause,
                        },
                        tiers: Vec::new(),
                        total_len: 0,
                        abort: Some(abort),
                        limiter: Some(limiter),
                        hook,
                    },
                );
                // Start trigger point (RequestGroupMan.cc at activation;
                // restart/unpause re-activations hit the same face). Hook
                // first, event notice after.
                if let Some(h) = self.running.get(&gid).and_then(|t| t.hook.as_ref()) {
                    h.fire(HookEvent::Start);
                }
                self.publish(gid, EventKind::Start);
                // Row state progression belongs to the driver (probing/
                // planning/downloading are written to the http_task row by
                // the state machine); the torrent row transition face is not
                // involved.
            }
            Job::Media(mj) => {
                // Media task activation (the third task
                // family): the driver carries the whole Resolving →
                // Downloading → Processing/Verifying → Done chain (the
                // session::media module); the row lifecycle rides the
                // pipeline's own persist face. The cfg hoists out of
                // the jobs borrow (the spawn awaits — the arm completes
                // after the match).
                // Cookie reseed on activation (the
                // http arm's load-back counterpart): the unified table
                // is the single truth — restarts replay from the rows
                // (a fresh bootstrap's cfg.cookies is empty) and an
                // in-session re-activation picks up a setTaskCookies
                // replacement. A read failure keeps the existing pairs
                // (degrade, no fake).
                let mut cfg = mj.cfg.clone();
                if let Some(p) = self.persist.as_ref() {
                    match p.load_task_cookies(&gid.to_string()).await {
                        Ok(rows) => {
                            // Expired rows are not replayed (the
                            // cookies_from_specs rule — expired entries
                            // never enter the active store).
                            let now = now_epoch();
                            cfg.cookies = rows
                                .iter()
                                .filter(|c| !c.expires_utc.is_some_and(|exp| now >= exp))
                                .map(|c| (c.name.clone(), c.value.clone()))
                                .collect();
                        }
                        Err(e) => {
                            warn!(target: "taiji::core::session", gid = %gid, %e,
                                "media activation cookie read-back failed; \
                                 the in-memory seed stays");
                        }
                    }
                }
                media_pending = Some(cfg);
            }
        }
        // Media activation completion (outside the jobs borrow — the
        // spawn driver takes &self and awaits).
        if let Some(cfg) = media_pending.take() {
            let pause = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let (live, abort, gate_permit) = self
                .spawn_media_driver(gid, cfg, token_clone.clone(), Arc::clone(&pause))
                .await;
            // The gate permit end lands in the actor's map before any
            // notice processing (single-threaded actor: the driver's
            // SynthesisGate arrival — if it races here — sits in the
            // notice channel until this activation step completes).
            self.media_gate_tx.insert(gid, gate_permit);
            self.running.insert(
                gid,
                RunningTask {
                    network: None,
                    token: token_clone,
                    backend: TaskBackend::Media { live, pause },
                    tiers: Vec::new(),
                    total_len: 0,
                    abort: Some(abort),
                    limiter: None,
                    hook: None,
                },
            );
            // Start trigger point (the same face as the other
            // families; hook first, event notice after — media tasks
            // carry no hook face this card).
            self.publish(gid, EventKind::Start);
        }
    }

    /// Startup recovery: read back the recovered layers from the derived
    /// table, re-validate them with the admission semantics (count + root
    /// convergence, `session::persist::recovery::apply_recovered_layers`),
    /// and merge them into the task metadata — the engine assembles fully
    /// configured (missing-layer gating stays closed, recovered layers
    /// survive restart, no refetch; mirrors libtorrent's resume-data
    /// reingest in torrent.cpp and load_merkle_trees). Rows that fail
    /// re-validation (hand-edited / stale) are not merged — files keep
    /// their missing-layer gated state and refetch from the swarm; never
    /// serve a sick full-config. The return value is always usable: no
    /// persistence / no row / all rejected → the original.
    pub(super) async fn restore_recovered_layers(
        &self,
        gid: Gid,
        meta: &Arc<crate::metainfo::Metainfo>,
    ) -> Arc<crate::metainfo::Metainfo> {
        let Some(persist) = &self.persist else {
            return Arc::clone(meta);
        };
        let rows = match persist.load_recovered_layers(&gid.to_string()).await {
            Ok(rows) => rows,
            Err(e) => {
                warn!(target: "taiji::core::session", gid = %gid, %e,
                    "recovered layers load failed (missing-layer files stay gated)");
                return Arc::clone(meta);
            }
        };
        if rows.is_empty() {
            return Arc::clone(meta);
        }
        let mut patched = meta.as_ref().clone();
        let report =
            crate::session::persist::recovery::apply_recovered_layers(&mut patched.meta, &rows);
        for (file_index, reason) in &report.rejected {
            warn!(target: "taiji::core::session", gid = %gid, file_index, reason = %reason,
                "persisted recovered layer rejected at re-validation; file stays gated \
                 (swarm refetch, no sick full-config)");
        }
        if report.applied.is_empty() {
            return Arc::clone(meta);
        }
        info!(target: "taiji::core::session", gid = %gid,
            restored = report.applied.len(),
            "recovered layers restored from persistence (full-config takeover)");
        Arc::new(patched)
    }

    /// Running-task teardown (engine/magnet/fetch watcher events): dispatch
    /// per the recorded flags — pause → requeue at the front as paused;
    /// restart (changeOption) → requeue at the front and re-activate
    /// immediately; otherwise → DownloadResult + fillup. Teardown
    /// persistence (terminal rows / row deletion / requeue state rows)
    /// happens synchronously with the dispatch (persist_after_end).
    pub(super) async fn handle_ended(&mut self, gid: Gid, outcome: TaskOutcome) {
        // Task teardown always withdraws the LSD announce (covers pause
        // requeue / upgrade residency / natural terminal states;
        // re-activation re-announces per the gate).
        self.lsd_withdraw(gid).await;
        // URL metadata fetch success: in-place upgrade (SPEC §7.1 upgrade
        // linearization; same GID).
        if let TaskOutcome::Fetched(bytes) = outcome {
            self.upgrade_from_fetched(gid, bytes).await;
            return;
        }
        // pause-metadata upgrade residency — the upgrade product becomes a
        // paused task (queue head) with the same resume semantics as a
        // normal torrent row; no longer faked as an Error result.
        if let TaskOutcome::Magnet(MagnetEnd::UpgradedPaused { meta, torrent, .. }) = outcome {
            self.residency_upgraded_paused(gid, meta, torrent).await;
            return;
        }
        // Seeding-residence teardown: the engine of a
        // seed-slot resident ended — seed criteria met, a user
        // pause/remove, or a forceRecheck stop. The finalize works from
        // the seeding registry (never the active face — the download
        // slot was released at the transfer), both Ended-after-transfer
        // orders converging on the same terminal (§4.1.6).
        if self.queue.contains_seeding(gid) {
            self.handle_seeding_ended(gid, outcome).await;
            return;
        }
        // Synthesis-side teardown: the driver of a
        // gate-parked or synthesizing media task ended — Done/Failed
        // natural terminal, a user pause/remove, or a shutdown
        // cancellation. The finalize works from the synthesis faces
        // (never the active face — the download slot was released at
        // the gate; retire_and_fire's active-face path would silently
        // skip the result record).
        if self.queue.contains_synthesis(gid) {
            self.handle_synthesis_ended(gid, outcome).await;
            return;
        }
        // total takes the runtime backfill value; if the engine died early
        // (query failed while the upgrade notice was handled → no backfill)
        // and the result carries upgrade metadata, fall back to the
        // metadata ([`ended_total_len`] — closes the backfill race so
        // terminal entries no longer produce complete 0/0 views).
        let total_len = ended_total_len(
            self.running.get(&gid).map(|t| t.total_len).unwrap_or(0),
            &outcome,
        );
        let (status, completed, note) = ended_classification(&outcome, total_len);
        // The halt override (remove → Removed) is applied uniformly inside
        // retire_and_fire.
        // HTTP tasks: the row write face is the http_task table (the driver
        // already wrote the terminal/paused row); the torrent row teardown
        // persistence is not involved (independent tables, zero
        // coupling).
        let is_http = matches!(self.jobs.get(&gid), Some(Job::Http(_)));
        // The media family flag is taken before retire_and_fire (the
        // terminal branch of retire removes the job payload — a read
        // after it would always see nothing).
        let is_media = matches!(self.jobs.get(&gid), Some(Job::Media(_)));
        if let Some(note) = &note {
            warn!(target: "taiji::core::session", gid = %gid, note,
                "task ended with explicit failure/pending-seam note");
        }
        // Engine-side canonical code passthrough (HTTP error terminal;
        // numeric refinement lives in the taiji-rpc render layer — the
        // single mapping source).
        let engine_code = match &outcome {
            TaskOutcome::Http(end) => end.error_engine.clone(),
            _ => None,
        };
        // The magnet in-place upgrade event carries the upgrade product —
        // the row upgrades to a full torrent row (metadata BLOB / file rows
        // / identity); terminal dispatch rewrites on top.
        let upgraded = match &outcome {
            TaskOutcome::Magnet(MagnetEnd::Upgraded { meta, torrent, .. }) => {
                Some((Arc::clone(meta), torrent.clone()))
            }
            // (The media DirectLink arm below matches by reference;
            // the partial-move fix keeps `outcome` borrowable.)
            _ => None,
        };
        // Media DirectLink conversion (§4: a direct media file routes
        // to the existing HTTP family — zero new surface): rebuild a
        // Job::Http from the original addMedia payload (the cookies
        // seed rides the unified-cookie shape) and re-activate on the same
        // GID; no result-table entry, no media row exists yet (the
        // conversion happens inside Resolving, before any row write).
        if let TaskOutcome::Media(crate::session::media::MediaEnd::DirectLink) = &outcome {
            self.media_direct_link(gid).await;
            return;
        }
        let flags = self.queue.active_flags(gid);
        // Take the HTTP row mirror before retire (running/jobs are gone
        // after) + renamePending registration (the in-process registry for
        // closeout polling — a DriveStop::Done + pending task no longer has
        // a driver loop, so row facts are snapshotted here).
        let http_live = self
            .running
            .get(&gid)
            .and_then(|t| t.backend.http_live().cloned());
        let http_mirror = self
            .running
            .get(&gid)
            .and_then(|t| t.backend.http_row().cloned());
        // Error outcomes carry no counters. Project the durable checkpoint,
        // not zero, after the driver has flushed its retained failure row.
        let total_len = total_len.max(
            http_live
                .as_ref()
                .map(|live| live.total_len.load(std::sync::atomic::Ordering::Relaxed))
                .unwrap_or(0),
        );
        let completed = if is_http
            && status == StatusKind::Error
            && !engine_code
                .as_ref()
                .is_some_and(|failure| failure.code == "taiji.http.checksum_mismatch")
        {
            http_mirror
                .as_ref()
                .map(|mirror| crate::lock(mirror).total_done.max(0) as u64)
                .unwrap_or(completed)
        } else {
            completed
        };
        // Finalize-window pause race shield: for outcome=Done the user's
        // pause has no object left — the pause flag no longer flips the
        // teardown dispatch (requeue-paused would restart a completed task).
        let flags = if is_http && status == StatusKind::Complete {
            flags.map(|(_pause, remove, restart)| (false, remove, restart))
        } else {
            flags
        };
        // Seed-budget park consume: a completion that
        // arrived against a full seed budget was gracefully stopped and
        // marked `seed_wait_deferred` — its Ended must **not** enter
        // results; the task parks in the seed_wait FIFO instead (row
        // 'seeding', payload retained for the budget-gated
        // reactivation). User flags set inside the stop window win over
        // the park (remove → the normal halt dispatch; pause → the
        // normal requeue-paused on the active face — the later unpause
        // re-enters through the download-side activation and converges
        // onto the seed side at its SeedingStarted, the declared
        // assembly-window boundary §4.1.4).
        if self.seed_wait_deferred.remove(&gid)
            && !matches!(flags, Some((_, true, _)))
            && !matches!(flags, Some((true, _, _)))
        {
            self.queue.drop_active(gid);
            self.queue.push_seed_wait(gid);
            self.running.remove(&gid);
            self.persist_transition(gid, TaskPhase::Seeding).await;
            info!(target: "taiji::core::session", gid = %gid,
                "seed budget full: completed task parked in seed_wait (graceful stop)");
            // The download slot freed here backfills in the same tick.
            self.pump_all().await;
            return;
        }
        let outcome =
            self.retire_and_fire(gid, status, total_len, completed, note.clone(), engine_code);
        // The unpauseAll-superseded landing rewrites the row face: the
        // revoked pause must not write 'paused' back — borrow the
        // restart face (queued row), keeping remove authoritative.
        let flags = if matches!(outcome, RetireOutcome::RequeuedUnpauseSuperseded) {
            flags.map(|(_p, rm, _r)| (false, rm, true))
        } else {
            flags
        };
        if !is_http {
            self.persist_after_end(gid, status, note, flags, upgraded)
                .await;
        } else if matches!(flags, Some((_, true, _))) {
            // HTTP remove: delete the row (DeleteHttpTask; the paired
            // delete clears the cookie rows; not rebuilt on restart).
            self.http_remove_row(gid).await;
        }
        if is_media && matches!(flags, Some((_, true, _))) {
            // Media remove: delete the row (DeleteMediaTask; the FK
            // cascade clears track/segment/key/format rows + the paired
            // cookie clear) + the staging tree (the media remove face).
            self.media_remove_row(gid).await;
        }
        // Terminal cookie close-out: the full
        // terminal set clears the task's unified-table cookie rows —
        // done and error, http and media alike. The old resident/one-
        // shot distinction is retired (an error-terminal task's
        // cookies no longer wait for a 24h GC / shutdown sweep; an
        // Error→unpause retry re-supplies credentials via
        // setTaskCookies — the tightened cookie semantics). The
        // error clear publishes the bypass alert. Placed after
        // the dispatch above so a remove-flagged task's paired
        // row-delete is not raced (the close-out is idempotent either
        // way); the driver/write-back loops have fully exited before
        // the Ended notice arrives (no concurrent cookie writer).
        if (is_http || is_media) && matches!(status, StatusKind::Complete | StatusKind::Error) {
            let kind = if is_http {
                taiji_store::persist::TASK_KIND_HTTP
            } else {
                taiji_store::persist::TASK_KIND_MEDIA
            };
            self.terminal_cookie_closeout(gid, kind, status == StatusKind::Error)
                .await;
        }
        // Whole-key rewrite after requeue-to-front: pause/restart teardown
        // push_front (queue.rs, the ProcessStoppedRequestGroup face of
        // RequestGroupMan.cc) already rewrites the reserved FIFO order —
        // previously only changePosition renumbered (commands.rs
        // change_position), so with max-concurrent≥2 and two active tasks
        // pausing in turn the stored keys kept the stale activation order,
        // and the restart restore order differed from the shutdown run
        // order. Placed before pump: the restart branch takes its new key
        // before re-activation — if shutdown lands just before activation,
        // row state queued + new key reflects the requeue-front fact; after
        // re-activation the key stays with the row (converging on the next
        // requeue/reorder). Placed after persist_after_end: state rows
        // (paused/queued) are written first and the rewrite only touches
        // queue_pos (single-writer serial; full-row comparison absorbs
        // duplicates).
        // Active-domain forceRecheck teardown seam: once the requeue lands,
        // move to checking and spawn the recheck (a remove override = the
        // mark is voided). Placed before pump — a requeued paused item is
        // not picked up by fillup, so dequeuing into checking has no race.
        let requeued_paused = match outcome {
            RetireOutcome::Requeued { paused } => Some(paused),
            RetireOutcome::RequeuedUnpauseSuperseded => Some(false),
            RetireOutcome::Result => None,
        };
        self.begin_deferred_recheck(gid, requeued_paused).await;
        if !matches!(outcome, RetireOutcome::Result) {
            self.persist_queue_renumber().await;
        }
        self.pump_all().await;
    }

    // ---- seed pool ----

    /// SeedingStarted consume: the active → seeding transfer. Queue
    /// accounting only — `running` keeps the engine handle, token and
    /// status cache untouched; the download slot is released at the
    /// transfer and backfilled by the trailing `pump_all` in the same
    /// tick (release-then-backfill, no idle beat). Idempotent: a
    /// gid that is not a current active resident (duplicate arrival,
    /// or the Ended-first race where the task already finalized) is a
    /// silent no-op. Seed budget full (a finite value): the graceful
    /// stop + `seed_wait_deferred` mark instead — the park consume at
    /// `Ended` moves the task into the seed_wait FIFO without entering
    /// results (§4.1.2).
    pub(super) async fn on_seeding_started(&mut self, gid: Gid) {
        if !self.queue.contains_active(gid) || !self.running.contains_key(&gid) {
            // Duplicate SeedingStarted / late arrival after Ended /
            // unknown gid — idempotent no-op (both §4.1.6 orders
            // converge on the same terminal).
            return;
        }
        let budget = self.global.seed_budget();
        if budget > 0 && self.queue.seeding_len() >= budget {
            // Budget full: gracefully stop the engine (the token is the
            // unified pause face — the same stop the active-domain pause
            // uses; the engine runs its stopped-announce teardown) and
            // mark for the park consume at Ended. No user pause flag is
            // set: a user pause/remove arriving inside the stop window
            // stays distinguishable and wins at the consume.
            self.seed_wait_deferred.insert(gid);
            // Row truth: the download is complete and the task belongs
            // to the seed side ('seeding' covers residence and waiting
            // alike, the 'checking' precedent).
            self.persist_transition(gid, TaskPhase::Seeding).await;
            if let Some(t) = self.running.get(&gid) {
                t.token.cancel();
            }
            info!(target: "taiji::core::session", gid = %gid,
                seeding = self.queue.seeding_len(), budget,
                "seed budget full: graceful stop, parking into seed_wait at Ended");
            // No pump here: the download slot frees when the stop lands
            // (the Ended consume pumps).
            return;
        }
        self.queue.begin_seeding(gid);
        self.persist_transition(gid, TaskPhase::Seeding).await;
        info!(target: "taiji::core::session", gid = %gid,
            seeding = self.queue.seeding_len(),
            "download complete: task transferred to the seed pool (download slot released)");
        self.pump_all().await;
    }

    // ---- synthesis pool ----

    /// SynthesisGate consume: the active → proc_wait transfer (the
    /// driver reached the Downloading → Processing boundary). Queue
    /// accounting only — `running` keeps the driver live handle/token
    /// untouched; the download slot is released at the transfer and
    /// backfilled by the trailing `pump_all` in the same tick
    /// (release-then-backfill, no idle beat). The permit itself fires
    /// from pump_all's synthesis segment (budget-gated FIFO: proc_wait
    /// → processing). Idempotent: a gid that is not a current active
    /// resident (duplicate notice, or the remove/Ended-first race
    /// where the task already finalized — the gate await then loses
    /// the token race and the teardown lands through the normal
    /// paths) is a silent no-op.
    pub(super) async fn on_synthesis_gate(&mut self, gid: Gid) {
        if !self.queue.contains_active(gid) || !self.running.contains_key(&gid) {
            // Duplicate SynthesisGate / late arrival after Ended or
            // remove / unknown gid — idempotent no-op.
            return;
        }
        if self.queue.begin_synthesis_park(gid) {
            info!(target: "taiji::core::session", gid = %gid,
                processing = self.queue.processing_len(),
                parked = self.queue.proc_wait_gids().len(),
                "media task reached the synthesis gate (download slot released, \
                 parked into proc_wait)");
            self.pump_all().await;
        }
    }

    /// Synthesis-side teardown (the `Ended` consume for a gid on the
    /// synthesis faces — processing registry or proc_wait FIFO): the
    /// driver of a gate-parked or synthesizing media task ended. The
    /// finalize works from the synthesis faces (never the active face
    /// — the download slot was released at the gate), the synthesis
    /// twin of `handle_ended` + `retire_and_fire`. Dispatch per the
    /// record flags (carried over from the active face at the gate
    /// transfer, so a pause/remove racing the arrival keeps its halt
    /// semantics):
    /// - pause → requeue to the front paused (the teardown already
    ///   wrote the paused row with the §3.2 phase memory —
    ///   `MediaEnd::Paused{memory: Processing}` for both the gate hang
    ///   and the true synthesis);
    /// - remove → Removed result + media row/staging deletion;
    /// - natural terminal (Done/Failed — the driver's own outcome
    ///   classification) → DownloadResult + the terminal cookie
    ///   close-out.
    ///
    /// Every branch releases the synthesis slot/position and pumps
    /// (release-then-backfill — a parked member promotes in this
    /// same tick when the budget freed).
    pub(super) async fn handle_synthesis_ended(&mut self, gid: Gid, outcome: TaskOutcome) {
        let flags = self.queue.synthesis_flags(gid);
        let total_len = self
            .running
            .get(&gid)
            .map(|t| t.total_len)
            .unwrap_or_default();
        let (status, completed, note) = ended_classification(&outcome, total_len);
        if let Some(note) = &note {
            warn!(target: "taiji::core::session", gid = %gid, note,
                "synthesis-side task ended with explicit failure note");
        }
        let mut entry = self.build_result_entry(gid, status, total_len, completed, note.clone());
        // Halt semantics (the same override as retire_and_fire /
        // handle_seeding_ended): a user remove wins over every other
        // terminal.
        if flags.is_some_and(|(_, rm)| rm) {
            entry.status = StatusKind::Removed;
        }
        let retired_status = entry.status;
        let requeued = self.queue.retire_synthesis(gid, entry);
        // The permit end dies with the driver (an un-granted permit
        // must never outlive its gate — the grant after this point
        // would fire into a dropped receiver).
        self.media_gate_tx.remove(&gid);
        self.running.remove(&gid);
        match requeued {
            // Requeued to the front paused: payload retained; the
            // unpause re-enters through the download-side activation
            // and converges back onto the gate (no activation-phase
            // special case — the idempotent re-walk, §4.3).
            Some(true) => {
                // Media tasks carry no hook face.
                self.publish(gid, EventKind::Pause);
            }
            Some(false) => {}
            None => {
                if retired_status == StatusKind::Complete {
                    self.metrics.note_task_completed();
                }
                // Media tasks carry no hook face (fire_stop_family on
                // None is a no-op — kept for the dispatch shape).
                fire_stop_family(None, retired_status);
                if let Some(kind) = stop_family_kind(retired_status) {
                    self.publish(gid, kind);
                }
                self.jobs.remove(&gid);
            }
        }
        // Row dispatch: the driver wrote the terminal/paused row
        // already (the media_task table is its face). Remove → delete
        // the row + staging (the paired cookie clear rides the delete
        // face); the done/error terminals clear the cookies (the
        // full-terminal-set close-out, both families).
        if flags.is_some_and(|(_, rm)| rm) {
            self.media_remove_row(gid).await;
        }
        if matches!(retired_status, StatusKind::Complete | StatusKind::Error) {
            self.terminal_cookie_closeout(
                gid,
                taiji_store::persist::TASK_KIND_MEDIA,
                retired_status == StatusKind::Error,
            )
            .await;
        }
        // A synthesis slot freed (or a requeue rewrote the reserved
        // order): promote proc_wait members within this tick.
        self.pump_all().await;
    }

    /// Seeding-residence teardown (the `Ended` consume for a gid in the
    /// seeding registry): the seed-domain twin of `handle_ended` +
    /// `retire_and_fire`. Dispatch per the record flags:
    /// - forceRecheck deferred mark → consume straight into checking
    ///   (the stop was the recheck's own; no results, no requeue);
    /// - pause → requeue to the front paused (the seed_parked
    ///   provenance routes the later unpause back to the seed side);
    /// - remove → Removed result + row deletion;
    /// - natural terminal (seed criteria met: Detached / SeedStopped,
    ///   or any other classification) → DownloadResult with the same
    ///   `ended_classification` mapping as the active domain (Complete
    ///   for the seed-stop family — §4.1.5).
    pub(super) async fn handle_seeding_ended(&mut self, gid: Gid, outcome: TaskOutcome) {
        let flags = self.queue.seeding_flags(gid);
        // forceRecheck-on-seeding stop landing: consume into checking
        // unless a remove override voids the mark (the same voiding
        // rule as the active-domain deferred recheck).
        if self.checking_deferred.contains(&gid) && !flags.is_some_and(|(_, rm)| rm) {
            self.consume_seeding_recheck(gid).await;
            return;
        }
        if flags.is_some_and(|(_, rm)| rm) {
            self.checking_deferred.remove(&gid);
        }
        let total_len = ended_total_len(
            self.running.get(&gid).map(|t| t.total_len).unwrap_or(0),
            &outcome,
        );
        let (status, completed, note) = ended_classification(&outcome, total_len);
        if let Some(note) = &note {
            warn!(target: "taiji::core::session", gid = %gid, note,
                "seeding task ended with explicit failure note");
        }
        let hook = self.running.get(&gid).and_then(|t| t.hook.clone());
        let mut entry = self.build_result_entry(gid, status, total_len, completed, note.clone());
        // Halt semantics (the same override as retire_and_fire).
        if flags.is_some_and(|(_, rm)| rm) {
            entry.status = StatusKind::Removed;
        }
        let retired_status = entry.status;
        let requeued = self.queue.retire_seeding(gid, entry);
        self.running.remove(&gid);
        match requeued {
            // Requeued to the front paused: payload retained; the
            // provenance mark routes the unpause back to the seed side.
            // (Requeued{paused:false} is unreachable — the seeding
            // record has no restart face; the arm keeps the shape of
            // the active domain's dispatch.)
            RetireOutcome::Requeued { paused: true } => {
                if let Some(h) = &hook {
                    h.fire(HookEvent::Pause);
                }
                self.publish(gid, EventKind::Pause);
                self.seed_parked.insert(gid);
            }
            RetireOutcome::Requeued { paused: false } => {}
            // The revoked in-flight pause lands unpaused on the waiting
            // face (no seed_parked mark — the download-side fillup
            // reactivation is the correct next step).
            RetireOutcome::RequeuedUnpauseSuperseded => {}
            RetireOutcome::Result => {
                if retired_status == StatusKind::Complete {
                    self.metrics.note_task_completed();
                }
                fire_stop_family(hook.as_ref(), retired_status);
                if let Some(kind) = stop_family_kind(retired_status) {
                    self.publish(gid, kind);
                }
                self.jobs.remove(&gid);
                self.seed_parked.remove(&gid);
            }
        }
        // Row dispatch through the shared face (remove → delete; pause
        // → paused row; natural terminal → done/error result row). A
        // superseded pause lands the queued state instead (the restart
        // row face — never resurrect 'paused').
        let flags = if matches!(requeued, RetireOutcome::RequeuedUnpauseSuperseded) {
            flags.map(|(_p, r)| (false, r, true))
        } else {
            flags.map(|(p, r)| (p, r, false))
        };
        self.persist_after_end(gid, retired_status, note, flags, None)
            .await;
        if !matches!(requeued, RetireOutcome::Result) {
            self.persist_queue_renumber().await;
        }
        // A seed slot freed (or a requeue rewrote the reserved order):
        // promote seed_wait members within this tick.
        self.pump_all().await;
    }

    /// The forceRecheck-Seeding stop landing (the seed-domain twin of
    /// [`Self::begin_deferred_recheck`]): move the task into the check
    /// pool's waiting FIFO. The seed slot was already released at
    /// request time (`release_seed_slot`); the registry entry and
    /// `running` go here. The paused intent is always false — force
    /// semantics: verify, then continue (the same stance as the
    /// active-domain arm). War 2: the recheck itself is budget-gated
    /// (park_check promotes within max-concurrent-checks; the trailing
    /// pump is the registration trigger — seeding→checking's seat swap
    /// backfills in the same tick).
    async fn consume_seeding_recheck(&mut self, gid: Gid) {
        if !self.checking_deferred.remove(&gid) {
            return;
        }
        self.queue.remove_seeding(gid);
        self.running.remove(&gid);
        self.seed_parked.remove(&gid);
        if !self.jobs.contains_key(&gid) {
            return;
        }
        self.park_check(gid, false).await;
        info!(target: "taiji::core::session", gid = %gid,
            "forceRecheck scheduled (seeding task stopped; parked in check_pending)");
    }

    /// Seed-side activation (the seed_wait promotion / restart routing
    /// executor, §4.1.2): register in the seeding registry (occupying
    /// the seed slot) **before** spawning, then run the shared
    /// activation pipeline. The engine assembly (complete bitmap) and
    /// the eventual SeedingStarted confirmation — the resume-complete
    /// path does not fire the BtComplete hook, so the confirmation may
    /// never arrive; the registration is authoritative either way —
    /// happen inside the seed slot; the download side (fillup /
    /// reserved) is never touched. A magnet payload is rebuilt into a
    /// torrent job from the row mirror's metadata BLOB first (the same
    /// rebuild bootstrap does); when that is impossible (no persisted
    /// metadata — a no-persistence session), an honest degradation
    /// re-enters through the download-side queue (the pre-war
    /// behavior). Does **not** pump: callers (pump_all's seed segment /
    /// unpause) own the trailing fillup.
    pub(super) async fn activate_seed(&mut self, gid: Gid) {
        if !self.rebuild_magnet_for_seed(gid).await {
            // Degradation: no metadata to seed from — route through the
            // waiting queue; the caller's trailing fillup activates it
            // within the download budget (the pre-war path).
            self.queue
                .insert_reserved(ReservedEntry { gid, paused: false }, Some(0));
            warn!(target: "taiji::core::session", gid = %gid,
                "seed reactivation without persisted metadata: degraded to the download side");
            return;
        }
        self.queue.insert_seeding(gid);
        self.activate(gid, None).await;
        if !self.running.contains_key(&gid) && self.queue.remove_seeding(gid) {
            // The shared pipeline failed after the registry insert
            // (engine config build / selection rejection — it already
            // recorded the error result on the active face, a no-op
            // here): record the error from the seed face so the task
            // neither leaks the registry nor vanishes silently.
            let entry = self.build_result_entry(gid, StatusKind::Error, 0, 0, None);
            self.queue.record_result(entry);
            self.persist_after_end(
                gid,
                StatusKind::Error,
                None,
                Some((false, false, false)),
                None,
            )
            .await;
            self.jobs.remove(&gid);
            self.seed_parked.remove(&gid);
            warn!(target: "taiji::core::session", gid = %gid,
                "seed-side activation failed; task recorded as error");
        }
    }

    /// Upgrade an upgraded-magnet job into a torrent job for seed-side
    /// reactivation (the in-session twin of bootstrap's rebuild: the
    /// row mirror's metadata BLOB is authoritative). Returns false only
    /// for a magnet payload whose metadata cannot be rebuilt (nothing
    /// persisted / unparseable) — the caller degrades to the download
    /// side. Non-magnet payloads are a trivial true.
    async fn rebuild_magnet_for_seed(&mut self, gid: Gid) -> bool {
        let Some(Job::Magnet(mj)) = self.jobs.get(&gid) else {
            return true;
        };
        let Some((row, _files)) = self.rows.get(&gid.to_string()).cloned() else {
            return false;
        };
        let Some(blob) = row.metadata.clone() else {
            return false;
        };
        let parsed = tokio::task::spawn_blocking(move || Metainfo::parse(&blob)).await;
        let Ok(Ok(meta)) = parsed else {
            return false;
        };
        // Job construction mirrors the paused-upgrade residency face
        // (residency_upgraded_paused) — the same payload a restart
        // rebuilds.
        let cfg = self.job_config(&gid);
        let total_len = meta.meta.total_len();
        let tiers = tiers_from_metainfo(&meta);
        let attrs_top = torrent_top_attrs(&row.metadata.clone().unwrap_or_default());
        let (dest, seed, down, up, hooks, selected_files, flag_dht, flag_webseed) = (
            mj.dest.clone(),
            mj.seed.clone(),
            mj.max_download_limit,
            mj.max_upload_limit,
            Arc::clone(&mj.hooks),
            effective_magnet_selection(mj),
            mj.bt_disable_dht,
            mj.enable_http_seeding,
        );
        self.jobs.insert(
            gid,
            Job::Torrent(Box::new(TorrentJob {
                metainfo: Arc::new(meta),
                tiers,
                dir: dest,
                seed,
                total_len,
                attrs_top,
                max_download_limit: down,
                max_upload_limit: up,
                hooks,
                selected_files,
                file_priorities: cfg.file_priorities.clone(),
                holepunch: cfg.holepunch,
                scheduler_policy: cfg.scheduler_policy.unwrap_or_default(),
                disk_tier: cfg.disk_tier.clone(),
                bt_disable_dht: flag_dht,
                enable_http_seeding: flag_webseed,
            })),
        );
        info!(target: "taiji::core::session", gid = %gid,
            "seed reactivation: upgraded magnet rebuilt as a torrent job (row metadata)");
        true
    }

    /// pause-metadata upgrade residency — the upgrade product becomes a
    /// real paused task (queue head; the same semantics as aria2's
    /// setPauseRequested follow-up group residency), persisted as a full
    /// torrent row (paused) with normal-task resume semantics.
    pub(super) async fn residency_upgraded_paused(
        &mut self,
        gid: Gid,
        meta: Arc<Metainfo>,
        torrent: Vec<u8>,
    ) {
        // Re-run the queued dual budget with real values before magnet
        // pause-upgrade residency (magnet intake was est=0) — prevents a
        // pause-metadata flood from bypassing the byte budget through the
        // intake arm (residency + persisted reingest face). Over budget =
        // the task becomes an error terminal (same shape as the
        // fetch-upgrade arm): no residency, no row.
        if let Err(e) = self.check_queue_admission(meta.resident_estimate_bytes()) {
            let total = meta.meta.total_len();
            let entry = self.build_result_entry(gid, StatusKind::Error, total, 0, None);
            let _ = self.queue.retire_active(gid, entry);
            self.jobs.remove(&gid);
            self.running.remove(&gid);
            warn!(target: "taiji::core::session", gid = %gid, err = %e,
                "magnet paused-upgrade exceeds queued budget; task recorded as error");
            self.pump_all().await;
            return;
        }
        let (dir, seed, down, up, hooks, selected_files, flag_disable_dht, flag_http_seeding) =
            match self.jobs.get(&gid) {
                Some(Job::Magnet(mj)) => (
                    mj.dest.clone(),
                    mj.seed.clone(),
                    mj.max_download_limit,
                    mj.max_upload_limit,
                    Arc::clone(&mj.hooks),
                    // BEP53: selection rides the upgrade residency (merge
                    // single point = effective_magnet_selection — the
                    // select-file option value wins, falling back to a
                    // re-parse of the magnet URI so=; the upgrade chain
                    // reuses the same rule).
                    effective_magnet_selection(mj),
                    // The per-task DHT flag rides the upgrade.
                    mj.bt_disable_dht,
                    // The webseeding switch rides the upgrade (BEP19).
                    mj.enable_http_seeding,
                ),
                // Late / missing payload (defensive): global hook set +
                // default dir.
                _ => (
                    self.global.dir.clone(),
                    SeedPolicy::default(),
                    0,
                    0,
                    resolve_hook_set(&self.global, &TaskOptionPatch::default()),
                    None,
                    None,
                    None,
                ),
            };
        self.running.remove(&gid);
        self.queue.drop_active(gid);
        let cfg = self.job_config(&gid);
        let mut row = super::super::persist::torrent_row(
            &gid.to_string(),
            TaskPhase::Paused,
            self.row_seq(),
            &derive_name(&meta.meta),
            &cfg,
        );
        super::super::persist::fill_torrent_identity(&mut row, &meta, torrent.clone());
        let files = file_rows(&row.gid, &meta.meta.files);
        self.persist_row(row, files).await;
        let total_len = meta.meta.total_len();
        let tiers = tiers_from_metainfo(&meta);
        let attrs_top = torrent_top_attrs(&torrent);
        self.jobs.insert(
            gid,
            Job::Torrent(Box::new(TorrentJob {
                metainfo: Arc::clone(&meta),
                tiers,
                dir,
                seed,
                total_len,
                attrs_top,
                max_download_limit: down,
                max_upload_limit: up,
                hooks,
                selected_files,
                // The upgrade face has no file-priority input (established
                // via taiji.setFilePriority on the add face).
                file_priorities: None,
                // The magnet metadata-upgrade config_json payload
                // (job_config defaults to true).
                holepunch: cfg.holepunch,
                // The magnet upgrade-face policy (job_config defaults to
                // rarest_first).
                scheduler_policy: cfg.scheduler_policy.unwrap_or_default(),
                // The disk tier belongs to torrent tasks (magnet upgrades
                // are always default).
                disk_tier: None,
                // The per-task DHT flag rides the upgrade.
                bt_disable_dht: flag_disable_dht,
                // The webseeding switch rides the residency (BEP19).
                enable_http_seeding: flag_http_seeding,
            })),
        );
        self.queue
            .insert_reserved(ReservedEntry { gid, paused: true }, Some(0));
        info!(target: "taiji::core::session", gid = %gid,
            "upgraded metadata task parked as paused (bt-pause-metadata residency)");
    }

    /// Teardown bookkeeping + stop-family hook triggers + event bus publish
    /// (shared by handle_ended and shutdown_routine; pump is decided by the
    /// caller based on shutdown state).
    ///
    /// Hook dispatch and notice publishing mirror executeStopHook
    /// (RequestGroupMan.cc) plus the notifyDownloadEvent call sites:
    /// - requeue-to-front paused (pause teardown) → on-download-pause hook +
    ///   `EventKind::Pause`;
    /// - requeue-to-front unpaused (restart) → NO pause hook and no Pause
    ///   event (same as aria2);
    /// - terminal: FINISHED → on-download-complete/`Complete`, error →
    ///   on-download-error/`Error`, everything else (REMOVED/IN_PROGRESS,
    ///   including remove and shutdown interruption) → on-download-stop/
    ///   `Stop` — hooks fire before event notices (same order as the
    ///   reference; bus wiring).
    ///
    /// Orphan-event guard: after forceRemove detaches immediately, the
    /// watcher still delivers one late Failed teardown (abort race) — the
    /// active record is already gone and the result already recorded;
    /// publishing again would fabricate an Error event, so only a real
    /// teardown (the active record present before teardown) publishes.
    ///
    /// Returns the requeue flag (same value as [`QueueMan::retire_active`]):
    /// `Some(_)` = pause/restart requeued to the front — the reserved FIFO
    /// order was rewritten by push_front, so the caller must trigger
    /// [`Self::persist_queue_renumber`] to rewrite the stored keys (restore
    /// reads by `ORDER BY queue_pos`; without the rewrite the restore order
    /// would differ from the shutdown run order); `None` = terminal
    /// teardown, the row leaves the queue and key order is unchanged.
    pub(super) fn retire_and_fire(
        &mut self,
        gid: Gid,
        status: StatusKind,
        total_len: u64,
        completed: u64,
        note: Option<String>,
        error_engine: Option<super::super::view::EngineFailure>,
    ) -> RetireOutcome {
        self.queue.finalizing.remove(&gid);
        let hook = self.running.get(&gid).and_then(|t| t.hook.clone());
        let was_active = self.queue.contains_active(gid);
        // Terminal display snapshot (files/bitfield/piece faces/bt dict)
        // into the entry.
        let mut entry = self.build_result_entry(gid, status, total_len, completed, note);
        entry.error_engine = error_engine;
        // Halt semantics (aria2 ProcessStoppedRequestGroup): a user-remove
        // teardown always records Removed — natural terminal states
        // (complete/seeding) are overridden by the removal (errorCode=31).
        let entry = if self.queue.is_removing(gid) {
            let mut e = entry;
            e.status = StatusKind::Removed;
            e
        } else {
            entry
        };
        // Terminal completion counting (only real terminals enter the
        // DownloadResult table; the pause-requeue Some(_) branch does not —
        // the same decision face as num_stopped_total).
        let retired_status = entry.status;
        // The requeue flag is handed to the caller (the stored-key renumber
        // trigger; see the function docs).
        let requeued = self.queue.retire_active(gid, entry);
        match requeued {
            // Requeued to the front: payload retained (pause/restart tasks
            // are not final).
            RetireOutcome::Requeued { paused: true } => {
                if let Some(h) = &hook {
                    h.fire(HookEvent::Pause);
                }
                // Pause notice (hook first).
                self.publish(gid, EventKind::Pause);
            }
            RetireOutcome::Requeued { paused: false } => {}
            // A late teardown whose pause request an unpauseAll already
            // revoked: land silent and unpaused (the row rewrite is the
            // caller's flags face — see the call site).
            RetireOutcome::RequeuedUnpauseSuperseded => {}
            RetireOutcome::Result => {
                if was_active {
                    if retired_status == StatusKind::Complete {
                        self.metrics.note_task_completed();
                    }
                    fire_stop_family(hook.as_ref(), retired_status);
                    // Stop-family notices (the notice half of the
                    // executeStopHook three branches, same mapping as the
                    // hooks).
                    if let Some(kind) = stop_family_kind(retired_status) {
                        self.publish(gid, kind);
                    }
                }
                self.jobs.remove(&gid);
            }
        }
        self.running.remove(&gid);
        requeued
    }

    /// .torrent URL metadata fetch success: parse + duplicate checks +
    /// in-place upgrade into a real task (keeps the active slot and the
    /// same GID; the engine continues on the same token; isomorphic to the
    /// SPEC §7.1 magnet in-place upgrade chain, with followedBy synthesized
    /// in the RPC view layer).
    pub(super) async fn upgrade_from_fetched(&mut self, gid: Gid, bytes: Vec<u8>) {
        let (dir, seed, down, up, hooks, select_file, flag_disable_dht, flag_http_seeding) =
            match self.jobs.get(&gid) {
                Some(Job::TorrentUrl {
                    dir,
                    seed,
                    max_download_limit,
                    max_upload_limit,
                    hooks,
                    select_file,
                    bt_disable_dht,
                    enable_http_seeding,
                    ..
                }) => (
                    dir.clone(),
                    seed.clone(),
                    *max_download_limit,
                    *max_upload_limit,
                    Arc::clone(hooks),
                    select_file.clone(),
                    *bt_disable_dht,
                    *enable_http_seeding,
                ),
                _ => {
                    // The task was already removed (a late event from remove
                    // racing the fetch).
                    self.queue.drop_active(gid);
                    self.jobs.remove(&gid);
                    self.running.remove(&gid);
                    return;
                }
            };
        // Capture the top-level attrs before bytes moves into the parse
        // task (the bittorrent dict source). The raw bytes are the metadata
        // BLOB; the parse task consumes a clone.
        let attrs_top = torrent_top_attrs(&bytes);
        let parsed = {
            let raw = bytes.clone();
            tokio::task::spawn_blocking(move || Metainfo::parse(&raw)).await
        };
        let meta = match parsed {
            Ok(Ok(m)) => m,
            Ok(Err(e)) => {
                let entry = self.build_result_entry(gid, StatusKind::Error, 0, 0, None);
                let _ = self.queue.retire_active(gid, entry);
                self.jobs.remove(&gid);
                self.running.remove(&gid);
                warn!(target: "taiji::core::session", gid = %gid, %e,
                    "fetched metadata is not a valid metainfo; task recorded as error");
                self.pump_all().await;
                return;
            }
            Err(e) => {
                self.queue.drop_active(gid);
                self.jobs.remove(&gid);
                self.running.remove(&gid);
                warn!(target: "taiji::core::session", gid = %gid, %e,
                    "metadata parse join failed");
                self.pump_all().await;
                return;
            }
        };
        // Intake gate (flipped): a .torrent fetched from a URL passes the
        // same gate as addTorrent direct-add — no tracker and DHT off =
        // accept + WARN (guidance: enable DHT at runtime / add trackers /
        // restart; after hot-enabling DHT this task revives via the
        // engine's SetDhtEnabled — the reject face is gone;
        // `Metainfo::check_intake`'s doc is the source of record).
        if let Some(w) = meta.check_intake(self.global.enable_dht) {
            warn!(target: "taiji::core::session", gid = %gid, "{w}");
        }
        // The fetch-upgrade arm re-checks the queued budget with real
        // values (the .torrent URL intake pre-check used the 30MiB worst
        // case; the metadata is now in hand — over budget = the task
        // becomes an error terminal with no residency, the same error shape
        // as existing upgrade failures).
        if let Err(e) = self.check_queue_admission(meta.resident_estimate_bytes()) {
            let total = meta.meta.total_len();
            let entry = self.build_result_entry(gid, StatusKind::Error, total, 0, None);
            let _ = self.queue.retire_active(gid, entry);
            self.jobs.remove(&gid);
            self.running.remove(&gid);
            warn!(target: "taiji::core::session", gid = %gid, err = %e,
                "fetched metadata exceeds queued budget; task recorded as error");
            self.pump_all().await;
            return;
        }
        if self.identity_is_duplicate(&meta.meta.identity, gid) {
            let total = meta.meta.total_len();
            let entry = self.build_result_entry(gid, StatusKind::Error, total, 0, None);
            let _ = self.queue.retire_active(gid, entry);
            self.jobs.remove(&gid);
            self.running.remove(&gid);
            warn!(target: "taiji::core::session", gid = %gid,
                "fetched metadata duplicates an existing task; recorded as error");
            self.pump_all().await;
            return;
        }
        // The upgrade product shares a dest (dir+name) with an existing
        // task = both write the same data file — closed the same way as an
        // identity duplicate (at the upgrade accept point the task already
        // occupies a slot; rejection = record an error terminal, never
        // reach the engine).
        {
            let name = derive_name(&meta.meta);
            if self.torrent_dest_is_occupied(&dir, &name, gid) {
                let total = meta.meta.total_len();
                let entry = self.build_result_entry(gid, StatusKind::Error, total, 0, None);
                let _ = self.queue.retire_active(gid, entry);
                self.jobs.remove(&gid);
                self.running.remove(&gid);
                warn!(target: "taiji::core::session", gid = %gid,
                    dest = %dir.join(&name).display(),
                    "fetched metadata dest conflicts with an active BT task; \
                     recorded as error (taiji.bt.path_conflict)");
                self.pump_all().await;
                return;
            }
        }
        let total_len = meta.meta.total_len();
        let tiers = tiers_from_metainfo(&meta);
        let meta = Arc::new(meta);
        // The upgrade product is a real task → the torrent row upgrades to
        // full form (raw bytes into the metadata BLOB, the file row set,
        // identity columns); row state queued (awaiting activation).
        let cfg = self.job_config(&gid);
        let mut row = super::super::persist::torrent_row(
            &gid.to_string(),
            TaskPhase::Queued,
            self.row_seq(),
            &derive_name(&meta.meta),
            &cfg,
        );
        super::super::persist::fill_torrent_identity(&mut row, &meta, bytes.clone());
        let files = file_rows(&row.gid, &meta.meta.files);
        self.persist_row(row, files).await;
        self.jobs.insert(
            gid,
            Job::Torrent(Box::new(TorrentJob {
                metainfo: Arc::clone(&meta),
                tiers: tiers.clone(),
                dir,
                seed,
                total_len,
                attrs_top,
                // Upgrade payload passthrough (per-task rate limits
                // continue with the task).
                max_download_limit: down,
                max_upload_limit: up,
                // The hook set continues with the task (the runner is
                // assembled at upgrade activation).
                hooks,
                // A URL metadata upgrade has no magnet so= selection face;
                // the select-file option face rides the task (None = select
                // all, zero change).
                selected_files: select_file,
                file_priorities: None,
                // URL upgrade payload (patch_config defaults to true).
                holepunch: cfg.holepunch,
                // URL upgrade-face policy (job_config defaults to
                // rarest_first).
                scheduler_policy: cfg.scheduler_policy.unwrap_or_default(),
                // The disk tier belongs to torrent tasks (URL upgrades are
                // always default).
                disk_tier: None,
                // The per-task DHT flag rides the upgrade.
                bt_disable_dht: flag_disable_dht,
                // The webseeding switch rides the upgrade (BEP19).
                enable_http_seeding: flag_http_seeding,
            })),
        );
        let Some(token) = self.running.get(&gid).map(|t| t.token.clone()) else {
            return;
        };
        self.running.remove(&gid);
        self.activate(gid, Some(token)).await;
        info!(target: "taiji::core::session", gid = %gid,
            "fetched .torrent metadata upgraded in place (same GID, SPEC §7.1)");
    }

    /// Same-torrent-already-registered check (a hit in either the active or
    /// the waiting map; the explicit duplicate-error source shared by
    /// addTorrent/addUri and the metadata upgrade path).
    pub(super) fn identity_is_duplicate(&self, identity: &TorrentIdentity, skip: Gid) -> bool {
        self.jobs
            .iter()
            .any(|(gid, job)| *gid != skip && identities_overlap(&job_identity(job), identity))
    }

    /// BT task dest occupancy check (a plain dir+name match): any
    /// non-terminal torrent task in jobs at the same `(dir, name)` =
    /// occupied. When two tasks with different infohashes point at one path
    /// (multi-file = the same content root `<dir>/<name>/`, single-file =
    /// the same data file `<dir>/<name>`), both VerifiedWriters would
    /// pwrite their own torrent's verified bytes to the same data file —
    /// real data corruption (the same race on the HTTP face is closed by
    /// the `.part` claim table, `taiji.http.path_conflict`). The name+dir
    /// text match does no path normalization (actor main-loop zero-disk-IO
    /// discipline; alias shapes are backstopped by the spill-side lock).
    /// Occupancy includes waiting/paused tasks (the same scope as identity
    /// dedup: a paused task still holds its dest when re-activated).
    pub(super) fn torrent_dest_is_occupied(&self, dir: &Path, name: &str, skip: Gid) -> bool {
        self.jobs.iter().any(|(gid, job)| {
            if *gid == skip {
                return false;
            }
            match job {
                Job::Torrent(tj) => tj.dir == dir && derive_name(&tj.metainfo.meta) == name,
                // magnet/URL metadata tasks have an unknown name (only
                // revealed at upgrade), and HTTP tasks' file face is
                // arbitrated by their own claim table — none participate
                // in this check.
                Job::Magnet(_) | Job::TorrentUrl { .. } | Job::Http(_) | Job::Media(_) => false,
            }
        })
    }

    /// BT dest conflict error (`taiji.bt.path_conflict` — the error shape
    /// is aligned with the HTTP-face `taiji.http.path_conflict` semantics:
    /// explicit rejection + path info).
    pub(super) fn dest_conflict_error(dir: &Path, name: &str) -> SessionError {
        SessionError::failed(format!(
            "taiji.bt.path_conflict: dest {} conflicts with an active BT task \
             (same dir+name; remove it first)",
            dir.join(name).display()
        ))
    }

    // ---- add ----

    /// taiji.addMedia: the media task's add
    /// face. Classification is **not** synchronous — Resolving does it
    /// (a direct media file converts to the HTTP family there, the
    /// zero-new-surface rule; a non-media entry fails with
    /// `not_media`). The probe-token face consumes the server-side
    /// snapshot here (unknown/expired/mismatched token = the explicit
    /// `probe_expired` error, §4's anti-forgery posture).
    pub(super) async fn add_media(
        &mut self,
        url: String,
        options: BTreeMap<String, String>,
        cookies: Vec<TaskCookieSpec>,
        position: Option<usize>,
    ) -> Result<CommandReply, SessionError> {
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err(SessionError::failed(
                "taiji.option.invalid: media entries are http(s) URLs",
            ));
        }
        let pause_add = options
            .get("pause")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        let mut cfg = media_task::media_cfg_from_options(&url, &options, &cookies, &self.global)?;
        if let Some(token) = options
            .get("probe-token")
            .map(|t| t.trim())
            .filter(|t| !t.is_empty())
        {
            let snap = self
                .probe_face
                .consume(token, &url)
                .map_err(|e| SessionError::failed(e.to_string()))?;
            cfg.probe_snapshot = Some(snap);
        }
        // The media payload is lightweight (no metadata fetch at add
        // time — Resolving owns the network); the queued budget uses
        // est=0 (the magnet precedent; the staging quota governs the
        // disk face at admission).
        self.check_queue_admission(0)?;
        let gid = self.allocate_task_gid(&options)?;
        cfg.gid = gid.to_string();
        // Structured cookies land in the unified table at creation
        // (persist-first): task_kind=media, the whole
        // set in one write. The media_task row itself first lands
        // inside Resolving (the media row lifecycle), so the cookie
        // write deliberately **precedes** it — the single-writer
        // serialization keeps the order durable, and a task whose row
        // never materialized (crash inside Resolving / not_media) is an
        // orphan the startup GC clears. A persist failure fails the
        // add (the setTaskCookies persist-first rule — never accept a
        // cookie payload that is not durable). No cookies = no write.
        if !cookies.is_empty() {
            let Some(p) = self.persist.as_ref() else {
                return Err(SessionError::failed(
                    "taiji.option.invalid: media task cookies require session storage",
                ));
            };
            let entries = cookies_from_specs(&cookies);
            let now = now_epoch();
            let rows: Vec<taiji_store::persist::TaskCookieRow> = entries
                .iter()
                .map(|c| taiji_store::persist::TaskCookieRow {
                    gid: gid.to_string(),
                    task_kind: taiji_store::persist::TASK_KIND_MEDIA.to_string(),
                    name: c.name.clone(),
                    domain: c.domain.clone(),
                    path: c.path.clone(),
                    value: c.value.clone(),
                    expires_utc: c.expires,
                    secure: c.secure,
                    host_only: c.host_only,
                    creation_utc: now,
                })
                .collect();
            p.upsert_task_cookies(
                &gid.to_string(),
                taiji_store::persist::TASK_KIND_MEDIA,
                rows,
            )
            .await
            .map_err(|e| SessionError::failed(format!("addMedia cookie persist failed: {e}")))?;
        }
        self.jobs.insert(
            gid,
            Job::Media(Box::new(media_task::MediaJob {
                cfg,
                cookie_specs: cookies,
            })),
        );
        self.enqueue(gid, pause_add, position);
        Ok(CommandReply::Gid(gid))
    }

    pub(super) async fn add_uri(
        &mut self,
        uris: Vec<String>,
        options: BTreeMap<String, String>,
        position: Option<usize>,
    ) -> Result<CommandReply, SessionError> {
        self.add_uri_inner(uris, options, position, Vec::new())
            .await
    }

    /// addUriWithCookies actor arm (fork AddUriWithCookiesRpcMethod,
    /// RpcMethodImpl.cc): structured cookies are converted via
    /// [`Self::cookies_from_specs`] (expired entries dropped, same rule as
    /// the fork's RpcCookie.cc) and then enter the same assembly face as
    /// addUri ("task orchestration always rides existing paths"; the task
    /// storage is the same CookieStore face as `--load-cookies`, the seed
    /// injection seam).
    ///
    /// Scheme gate (defensive): all URIs must be http/https — the fork's
    /// verbatim text "Task cookies require HTTP or HTTPS URIs." (the RPC
    /// layer already gates the same way, RpcMethodImpl.cc; this covers
    /// direct SessionCommand callers).
    /// `.torrent` URLs are rejected outright: they classify into the
    /// metadata fetch face (TorrentUrl), which has no cookie consumption
    /// point — accepting would be a fake; prefer rejection (a declared
    /// difference).
    pub(super) async fn add_uri_with_cookies(
        &mut self,
        uris: Vec<String>,
        cookies: Vec<crate::session::command::TaskCookieSpec>,
        mut options: BTreeMap<String, String>,
        position: Option<usize>,
    ) -> Result<CommandReply, SessionError> {
        if uris.is_empty() {
            return Err(SessionError::failed("URI is not provided."));
        }
        if uris
            .iter()
            .any(|u| !u.starts_with("http://") && !u.starts_with("https://"))
        {
            return Err(SessionError::failed(
                "Task cookies require HTTP or HTTPS URIs.",
            ));
        }
        if uris.iter().any(|u| is_torrent_url(u)) {
            return Err(SessionError::failed(
                "taiji.option.invalid: cookies apply to HTTP download tasks only \
                 (metadata fetch face not covered)",
            ));
        }
        let seed = cookies_from_specs(&cookies);
        options.insert("motrix-task-cookie-scope".into(), "true".into());
        self.add_uri_inner(uris, options, position, seed).await
    }

    async fn add_uri_inner(
        &mut self,
        uris: Vec<String>,
        mut options: BTreeMap<String, String>,
        position: Option<usize>,
        cookie_seed: Vec<taiji_http::cookies::NetscapeCookie>,
    ) -> Result<CommandReply, SessionError> {
        let explicit_options: std::collections::BTreeSet<_> = options.keys().cloned().collect();
        for (key, value) in &self.global.motrix_http_defaults {
            options.entry(key.clone()).or_insert_with(|| value.clone());
        }
        if uris.is_empty() {
            return Err(SessionError::failed("URI is not provided."));
        }
        let patch = parse_task_options(&options);
        // Classification (the addUri always-on face): the first magnet wins
        // (aria2 createRequestGroupForUri magnet grouping semantics); next,
        // an http(s) `.torrent` URL → the metadata download path (Phase A
        // semantics preserved); everything else http(s)/ftp(s) → an HTTP
        // download task (multi-source = all URIs of the same family, aria2
        // URI priority semantics).
        if let Some(uri) = uris.iter().find(|u| u.starts_with("magnet:")) {
            let parsed = taiji_bt::magnet::parse(uri)
                .map_err(|e| SessionError::failed(format!("magnet URI parse failed: {e}")))?;
            // magnet intake uses est=0 (a MagnetJob is lightweight; the
            // upgrade arm re-checks the byte budget once metadata is ready).
            self.check_queue_admission(0)?;
            // select-file: syntax/conversion validation + rejection when it
            // coexists with the magnet `so=` (a single selection-source
            // rule — the error names both source keys; aria2 has no so=
            // face, no upstream counterpart). Metadata unknown → range
            // validation deferred to the upgrade chain (the same rule as
            // so=: anchored on the non-pad file count).
            let select_file_sel = if let Some(raw) = &patch.select_file {
                if parsed.so.is_some() {
                    return Err(SessionError::failed(
                        "taiji.option.invalid: both magnet URI 'so=' and option \
                         'select-file' are present (single selection source; remove one)",
                    ));
                }
                Some(parse_select_file(raw).map_err(SessionError::failed)?)
            } else {
                None
            };
            if self.identity_is_duplicate(
                &TorrentIdentity {
                    v1: parsed.btih,
                    v2: parsed.btmh,
                },
                Gid::from_u64(0),
            ) {
                return Err(SessionError::failed(
                    "duplicate download: magnet identity already registered",
                ));
            }
            let gid = self.allocate_task_gid(&options)?;
            let tr_tiers: Vec<(usize, String)> = parsed
                .tr
                .iter()
                .enumerate()
                .map(|(i, t)| (i, String::from_utf8_lossy(t).into_owned()))
                .collect();
            let tr_tiers =
                merge_global_trackers(&tr_tiers, patch.bt_tracker.as_deref().unwrap_or(&[]));
            // Task-final hook set (global + per-task overrides, fixed at
            // add time).
            let hooks = resolve_hook_set(&self.global, &patch);
            // Task registration row (metadata BLOB NULL → restore returns
            // to the metadata state, SPEC §5.4; the identity column carries
            // the magnet's dual identities).
            let mut cfg = self.patch_config(&patch);
            cfg.holepunch = options
                .get("motrix-metadata-holepunch")
                .is_none_or(|value| value != "false");
            cfg.magnet_uri = Some(uri.clone());
            cfg.selection_pending = match options.get("motrix-await-selection").map(String::as_str)
            {
                None | Some("false") => false,
                Some("true") => true,
                _ => return Err(SessionError::failed("invalid selection barrier")),
            };
            let mut metadata_options = MagnetOptions {
                holepunch: cfg.holepunch,
                ..magnet_options_from_patch(&patch, self.global.bt_peer_connection_type)
            };
            if cfg.selection_pending {
                metadata_options.pause_metadata = true;
                metadata_options.bt_metadata_only = false;
                metadata_options.follow_torrent = true;
            }
            cfg.magnet_flags = Some(crate::session::persist::PersistedMagnetFlags::from(
                &metadata_options,
            ));
            cfg.tiers = tr_tiers.clone();
            // BEP53: selection persisted with config_json (pushed to the
            // engine via SetFileSelection at activation/restore). The
            // select-file option value (0-based, mutually exclusive with
            // so= — rejected above) merges into the same data face.
            cfg.selected_files = parsed.so.clone().or(select_file_sel.clone());
            let name = parsed
                .dn
                .as_ref()
                .map(|d| String::from_utf8_lossy(d).into_owned())
                .unwrap_or_else(|| {
                    let id = parsed
                        .btih
                        .map(|b| b.to_vec())
                        .unwrap_or_else(|| parsed.btmh.map(|b| b.to_vec()).unwrap_or_default());
                    id.iter().map(|b| format!("{b:02x}")).collect()
                });
            let mut row = super::super::persist::torrent_row(
                &gid.to_string(),
                if patch.pause {
                    TaskPhase::Paused
                } else {
                    TaskPhase::Metadata
                },
                self.row_seq(),
                &name,
                &cfg,
            );
            row.v1_infohash = parsed.btih.map(|b| b.to_vec());
            row.v2_infohash = parsed.btmh.map(|b| b.to_vec());
            self.persist_row(row, Vec::new()).await;
            self.jobs.insert(
                gid,
                Job::Magnet(Box::new(MagnetJob {
                    magnet_uri: uri.clone(),
                    dest: patch.dir.clone().unwrap_or_else(|| self.global.dir.clone()),
                    options: metadata_options,
                    seed: self.seed_policy_from(&patch),
                    btih: parsed.btih,
                    btmh: parsed.btmh,
                    tiers: tr_tiers,
                    // select-file option value (0-based; mutually exclusive
                    // with the URI so= — rejected above; the merge single
                    // point = magnet::effective_magnet_selection).
                    selected_files: select_file_sel,
                    // Scheduler policy (a projection of the
                    // bt-sequential-download option; the upgrade chain
                    // carries it via job_config).
                    scheduler_policy: match patch.bt_sequential_download {
                        Some(true) => crate::engine::SchedulerPolicy::sequential(),
                        _ => crate::engine::SchedulerPolicy::default(),
                    },
                    // Per-task rate limits (0 = unlimited default, SPEC §11).
                    max_download_limit: patch.max_download_limit.unwrap_or(0),
                    max_upload_limit: patch.max_upload_limit.unwrap_or(0),
                    hooks,
                    upgraded: false,
                    // Per-task DHT flag (None = follow the session).
                    bt_disable_dht: patch.bt_disable_dht,
                    // Webseeding switch (BEP19; None = default on, consumed
                    // by the upgrade chain).
                    enable_http_seeding: patch.enable_http_seeding,
                })),
            );
            self.enqueue(gid, patch.pause, position);
            return Ok(CommandReply::Gid(gid));
        }
        let http_like: Vec<String> = uris
            .iter()
            .filter(|u| is_download_uri(u))
            .cloned()
            .collect();
        // `.torrent` URL metadata path (Phase A semantics): a single-URL
        // placeholder task, upgraded in place to a torrent after fetch.
        if let Some(url) = http_like.iter().find(|u| is_torrent_url(u))
            && patch.follow_torrent != Some(false)
            && patch.bt_metadata_only != Some(true)
        {
            // select-file: 1-based syntax parse + 0-based conversion at a
            // single point (same as the magnet arm; metadata unknown →
            // range validation deferred to the upgrade chain — the same
            // rule as magnet). Invalid values reject the whole add.
            let select_file_sel = match &patch.select_file {
                Some(raw) => Some(parse_select_file(raw).map_err(SessionError::failed)?),
                None => None,
            };
            // The .torrent URL arm — pre-check the queued budget with the
            // fetch cap (30MiB) as the worst case before fetching; the
            // upgrade arm re-checks with real values.
            self.check_queue_admission(taiji_bt::tracker::http::TORRENT_FETCH_MAX_BODY_BYTES)?;
            let gid = self.allocate_task_gid(&options)?;
            // Task-final hook set (global + per-task overrides, fixed at
            // add time).
            let hooks = resolve_hook_set(&self.global, &patch);
            // URL metadata task registration row (metadata BLOB NULL;
            // completed at upgrade).
            let mut cfg = self.patch_config(&patch);
            cfg.torrent_url = Some(url.clone());
            // Selection persisted with config_json (pushed to the engine as
            // a projection mask via SetFileSelection at upgrade activation
            // — same source as TorrentJob.selected_files).
            cfg.selected_files = select_file_sel.clone();
            let row = super::super::persist::torrent_row(
                &gid.to_string(),
                if patch.pause {
                    TaskPhase::Paused
                } else {
                    TaskPhase::Queued
                },
                self.row_seq(),
                url,
                &cfg,
            );
            self.persist_row(row, Vec::new()).await;
            self.jobs.insert(
                gid,
                Job::TorrentUrl {
                    url: url.clone(),
                    dir: patch.dir.clone().unwrap_or_else(|| self.global.dir.clone()),
                    seed: self.seed_policy_from(&patch),
                    // Upgrade payload passthrough (per-task rate limits).
                    max_download_limit: patch.max_download_limit.unwrap_or(0),
                    max_upload_limit: patch.max_upload_limit.unwrap_or(0),
                    hooks,
                    // The select-file option face rides the upgrade product
                    // (same source as TorrentJob.selected_files — the same
                    // rule as aria2's addUri .torrent URL face,
                    // download_helper.cc).
                    select_file: select_file_sel,
                    // The per-task DHT flag rides the upgrade product (same
                    // source).
                    bt_disable_dht: patch.bt_disable_dht,
                    // Webseeding switch (BEP19; rides the upgrade product).
                    enable_http_seeding: patch.enable_http_seeding,
                },
            );
            self.enqueue(gid, patch.pause, position);
            return Ok(CommandReply::Gid(gid));
        }
        // HTTP download task (always on): multi-source = all
        // http(s)/ftp(s) URIs; `--out` is read straight from the raw option
        // face (a standard per-add item).
        // SFTP deferred (final): a `sftp://` scheme is explicitly rejected
        // with error code `taiji.sftp.deferred` (the SFTP transport face is
        // a declared difference delivered by a separate effort; never
        // silently ignored — accepting without effect would be a fake). A
        // hit in any source rejects the whole addUri (partial acceptance is
        // unreachable under the multi-URI-same-file mirror semantics).
        if uris.iter().any(|u| u.starts_with("sftp://")) {
            return Err(SessionError::failed(
                "taiji.sftp.deferred: SFTP transport is deferred in this build \
                 (declared difference; supported schemes: magnet:, http(s)/ftp(s))",
            ));
        }
        let Some(first) = http_like.first().cloned() else {
            return Err(SessionError::failed(
                "URI scheme not supported: accept magnet:, http(s)/ftp(s) downloads \
                 and http(s) .torrent URLs",
            ));
        };
        let gid = self.allocate_task_gid(&options)?;
        let hooks = resolve_hook_set(&self.global, &patch);
        // Submission instant (the ChainTrace t0 anchor): the start of the
        // queued/activation segment.
        let submitted = std::time::Instant::now();
        // Cookie intake gate: priority = structured direct pass
        // (addUriWithCookies — the cookie argument is the only source, file
        // sources are not stacked) > per-task `load-cookies` >
        // session-level `load-cookies` (GlobalOptions.load_cookies, aria2's
        // per-download precedence over global). File loading is fail-closed
        // at a single point (missing/unreadable/oversized = task rejected,
        // [`load_cookie_seed`]); the combination semantics (manual Cookie
        // header stripping) live in [`cookie_intake_active`]. The
        // fail-closed decision precedes the row write — a rejected call
        // leaves zero mutations (the same discipline as out sanitization /
        // host_cap).
        let structured_seed = cookie_seed;
        let cookie_seed = if !structured_seed.is_empty()
            || options
                .get("motrix-task-cookie-scope")
                .is_some_and(|value| value == "true")
        {
            structured_seed
        } else if let Some(path) = options.get("load-cookies").filter(|v| !v.trim().is_empty()) {
            load_cookie_seed(path.trim()).await?
        } else if let Some(path) = &self.global.load_cookies {
            load_cookie_seed(&path.display().to_string()).await?
        } else {
            Vec::new()
        };
        let mut options = options;
        if cookie_intake_active(
            self.global.load_cookies.as_deref(),
            &options,
            cookie_seed.len(),
        ) {
            strip_manual_cookie_headers(&mut options);
        }
        // Per-task option face (`--checksum` / `--http-incomplete-suffix` /
        // `--remote-time`): invalid values reject the add
        // (taiji.option.invalid); valid values persist with row creation
        // (the driver's completion-time verdict / resume share the same
        // source). The add-path baseline is the defaults (a new task has no
        // prior payload to merge).
        let mut http_cfg = http_task_options(&options, &http_task::HttpPersistConfig::default())?;
        if options
            .get("http-resume-context")
            .is_some_and(|value| value == "true")
        {
            http_cfg.retain_request_context = true;
            http_cfg.imported_options = Some(
                options
                    .iter()
                    .filter(|(key, _)| {
                        explicit_options.contains(*key)
                            && super::HTTP_TASK_OPTION_TABLE
                                .iter()
                                .any(|decl| decl.face.import_fold && decl.name == key.as_str())
                    })
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
            );
        }
        // Runtime option face: timeouts / credentials / proxy / UA / header
        // / certificate faces.
        let http_opts = http_task_runtime_options(&options, &http_task::HttpTaskOpts::default())?;
        // `--out` sanitization: basename-only domain — path separators,
        // absolute paths, and parent-directory components escaping `--dir`
        // (the out-of-dir write red line) and option-injection shapes
        // (a leading `-`) all reject the task.
        let out = match options.get("out").map(|v| sanitize_out_option(v)) {
            Some(Ok(name)) => Some(name),
            Some(Err(e)) => return Err(e),
            None => None,
        };
        // Per-host connection cap: adjusts the session registry's effective
        // value (last-set-wins — the convergence semantics of a shared
        // cap). Parsing stays in the rejection zone (an invalid value = task
        // rejection, no row written — the original order); the effect moves
        // after all rejection faces (after the row is persisted) — before
        // the fix, set_cap ran before out sanitization, so a rejected
        // addUri left a global side effect (HostCap is a single field
        // effective for all hosts: invalid out + valid cap → the task was
        // rejected while the cap mutated).
        let host_cap_patch = match options
            .get("http-max-per-host")
            .filter(|v| !v.trim().is_empty())
        {
            // The same value domain as the CLI face, explicitly rejected —
            // the CLI uses `value_parser!(u32).range(1..)` (the u32
            // domain); the RPC/addUri face adds the same-domain check after
            // parsing: > 2^32-1 is always a `taiji.option.invalid` task
            // rejection (before the fix parse_u64_domain accepted any u64
            // and the effect-side set_cap silently clamped to u32::MAX —
            // accepting without effect is a fake).
            Some(v) => {
                let cap = parse_u64_domain(v, "--http-max-per-host", 1)?;
                if cap > u32::MAX as u64 {
                    return Err(SessionError::failed(format!(
                        "taiji.option.invalid: --http-max-per-host {v:?} exceeds u32 \
                         domain (want unsigned integer in 1..=4294967295)"
                    )));
                }
                Some(cap)
            }
            None => None,
        };
        // Row registration (the http_task table; pause intent persisted
        // with the row — writing `queued` for an add with pause=true would
        // auto-start the task after restart, so the row state and the queue
        // bookkeeping both write paused from the same source).
        let row = taiji_store::persist::HttpTaskRow {
            gid: gid.to_string(),
            url: first.clone(),
            final_url: String::new(),
            // Multi-source manifest (the addUri multi-URI array carried
            // through): more than one source persists with the row and
            // restart restore expands the same source set (the
            // uris_from_mirrors inverse); for a single source the url
            // column is the truth, no redundant payload.
            mirrors_json: http_task::mirrors_json_of(&http_like),
            state: if patch.pause {
                TaskPhase::Paused
            } else {
                TaskPhase::Queued
            }
            .as_v1_str()
            .into(),
            queue_pos: self.row_seq(),
            dir: patch
                .dir
                .clone()
                .unwrap_or_else(|| self.global.dir.clone())
                .display()
                .to_string(),
            out: out.clone().unwrap_or_default(),
            // Concurrency intent fixed with the row: the add-effective
            // split/cap values enter the store — a kill -9 bootstrap replay
            // restores from this face and reactivation assembles the same
            // starting concurrency (`AimdConfig::with_start` + 5ms source
            // rotation waves), never degrading to a single connection with
            // the session default (cap 1). Cap intent rides the row: the
            // addUri `http-max-per-host` adjustment enters `host_cap` —
            // restart/resume activation restores that task's cap intent via
            // the addUri channel.
            config_json: {
                let mut cfg = http_cfg;
                cfg.concurrency = Some(http_task::HttpConcurrencyPersist::of(&http_opts));
                cfg.host_cap = host_cap_patch.map(|c| c as u32);
                cfg.to_json()
            },
            probe_json: None,
            validator_digest: None,
            // Block granularity fixed at creation (--http-block-size
            // wiring; the row value is the resume truth — the driver treats
            // a non-zero row value as authoritative, 0 = legacy rows fall
            // back to the default granularity).
            block_size: http_opts.block_size as i64,
            block_bitmap: None,
            block_count: None,
            total_done: 0,
            error_code: None,
            error_msg: None,
            created_at: now_epoch(),
            updated_at: now_epoch(),
        };
        self.persist_http_row(&row).await;
        // Persist initial cookies before admission. A fast failure or a paused
        // task may never reach the periodic cookie write-back tick.
        if !cookie_seed.is_empty() {
            if let Some(persist) = &self.persist {
                let rows = cookie_seed
                    .iter()
                    .map(|c| taiji_store::persist::TaskCookieRow {
                        gid: gid.to_string(),
                        task_kind: taiji_store::persist::TASK_KIND_HTTP.into(),
                        name: c.name.clone(),
                        domain: c.domain.clone(),
                        path: c.path.clone(),
                        value: c.value.clone(),
                        expires_utc: c.expires,
                        secure: c.secure,
                        host_only: c.host_only,
                        creation_utc: now_epoch(),
                    })
                    .collect();
                if let Err(error) = persist
                    .upsert_task_cookies(
                        &gid.to_string(),
                        taiji_store::persist::TASK_KIND_HTTP,
                        rows,
                    )
                    .await
                {
                    let _ = persist.delete_http_task(&gid.to_string()).await;
                    return Err(SessionError::failed(format!(
                        "HTTP cookie persist failed: {error}"
                    )));
                }
            }
        }
        // Cap effect face: the session registry mutates only after all
        // rejection faces pass and the row is persisted. The value domain
        // is pinned ≤ u32::MAX at parse time (a CLI-same-domain explicit
        // rejection) — the silent clamp exit is gone.
        if let Some(cap) = host_cap_patch {
            self.http_per_host.set_cap(cap as u32);
        }
        self.jobs.insert(
            gid,
            Job::Http(Box::new(HttpJob {
                uris: http_like,
                dir: patch.dir.clone().unwrap_or_else(|| self.global.dir.clone()),
                out,
                // Per-task rate limits (0 = unlimited default, SPEC §11).
                max_download_limit: patch.max_download_limit.unwrap_or(0),
                max_upload_limit: patch.max_upload_limit.unwrap_or(0),
                hooks,
                opts: http_opts,
                restore: Some(row),
                mirror: None,
                cookies: Vec::new(),
                // Cookie injection seeds: structured direct pass /
                // load-cookies file load — seeds the task store at
                // activation, then persists via the cookie write-back loop
                // (restart replay rides the cookie row face).
                cookie_seed,
                submitted,
            })),
        );
        self.enqueue(gid, patch.pause, position);
        Ok(CommandReply::Gid(gid))
    }

    /// Queued-face dual budget (shared by every intake arm — addTorrent /
    /// the addUri magnet arm / the .torrent URL arm / the fetch-upgrade
    /// arm; bootstrap restore trusts its own persisted face and is not
    /// capped). `est` is this task's estimated resident Metainfo bytes (0
    /// during magnet intake; the upgrade arm re-checks).
    pub(super) fn check_queue_admission(&self, est: usize) -> Result<(), SessionError> {
        let q = self.queue.reserved_entries();
        if q.len() >= super::super::queue::MAX_RESERVED_QUEUE_ENTRIES {
            return Err(SessionError::failed(format!(
                "download queue full: {} waiting entries (max {})",
                q.len(),
                super::super::queue::MAX_RESERVED_QUEUE_ENTRIES
            )));
        }
        let held: usize = q
            .iter()
            .filter_map(|e| match self.jobs.get(&e.gid) {
                Some(Job::Torrent(t)) => Some(t.metainfo.resident_estimate_bytes()),
                _ => None,
            })
            .sum();
        if held + est > super::super::queue::MAX_QUEUED_METAINFO_BYTES {
            return Err(SessionError::failed(format!(
                "queued metadata budget exceeded: held {held} + this {est} > {} bytes",
                super::super::queue::MAX_QUEUED_METAINFO_BYTES
            )));
        }
        Ok(())
    }

    pub(super) async fn add_torrent(
        &mut self,
        torrent: Vec<u8>,
        options: BTreeMap<String, String>,
        position: Option<usize>,
    ) -> Result<CommandReply, SessionError> {
        // Metainfo parsing stays off the main loop; top-level attrs are
        // captured before the move (the bittorrent dict source). The raw
        // bytes are the metadata BLOB.
        let attrs_top = torrent_top_attrs(&torrent);
        let parsed = {
            let raw = torrent.clone();
            tokio::task::spawn_blocking(move || Metainfo::parse(&raw)).await
        };
        let mut meta = parsed
            .map_err(|e| SessionError::failed(format!("metainfo parse join failed: {e}")))?
            .map_err(|e| SessionError::failed(format!("BitTorrent metainfo parse failed: {e}")))?;
        // Intake gate (flipped): no tracker and DHT off = accept + WARN
        // (guidance rides the warn text; the bare CLI run shares the gate —
        // both entries agree; upstream contrast: aria2 RequestGroup.cc only
        // NOTICEs and libtorrent never rejects — see the
        // `Metainfo::check_intake` doc).
        // After hot-enabling DHT this task revives via the engine's
        // SetDhtEnabled (no restart).
        if let Some(w) = meta.check_intake(self.global.enable_dht) {
            warn!(target: "taiji::core::session", "{w}");
        }
        if self.identity_is_duplicate(&meta.meta.identity, Gid::from_u64(0)) {
            return Err(SessionError::failed(
                "duplicate download: torrent identity already registered",
            ));
        }
        let patch = parse_task_options(&options);
        let output_paths = super::output_paths::parse(&options, meta.meta.files.len())?;
        super::output_paths::apply(&mut meta, &output_paths)?;
        // select-file (accepted on aria2's INITIAL face): 1-based syntax
        // parse + 0-based conversion at one point (options::
        // parse_select_file) → metadata known → range validation immediate
        // (anchored on the non-pad file count, the BEP53 client file list;
        // aria2's setFileFilter silently drops out-of-range values during
        // group creation — tightened to explicit rejection, a declared
        // difference). Invalid values reject the whole add with no row
        // written (accepting without effect is a fake); valid values enter
        // cfg.selected_files (the same data face / persistence channel as
        // so=) and are pushed to the engine via SetFileSelection at
        // activation.
        let selected_files = resolve_select_file_for_meta(&patch, &meta.meta)?;
        // Same-dest (dir+name) BT tasks are exclusive — two tasks with
        // different infohashes landing on one path would have both
        // VerifiedWriters pwrite their own torrent's verified bytes to the
        // same data file = real corruption, and the shared `<task>/face<N>`
        // spill pieces would delete each other's in-flight pieces. Rejected
        // explicitly at the accept point
        // ([`Self::torrent_dest_is_occupied`]; the error shape is aligned
        // with the HTTP face's path_conflict semantics). Ordered after
        // option validation: user input errors (immediately fixable)
        // surface before resource conflicts (state errors).
        let dir = patch.dir.clone().unwrap_or_else(|| self.global.dir.clone());
        let dest_name = derive_name(&meta.meta);
        if self.torrent_dest_is_occupied(&dir, &dest_name, Gid::from_u64(0)) {
            return Err(Self::dest_conflict_error(&dir, &dest_name));
        }
        // Queued-face dual budget (the .torrent intake arm; est = the
        // parsed Metainfo's resident estimate).
        self.check_queue_admission(meta.resident_estimate_bytes())?;
        let total_len = meta.meta.total_len();
        let tiers = tiers_from_metainfo(&meta);
        let gid = self.allocate_task_gid(&options)?;
        // Task-final hook set (global + per-task overrides, fixed at add
        // time).
        let hooks = resolve_hook_set(&self.global, &patch);
        // Task registration row (metadata BLOB = the raw .torrent bytes —
        // the raw info-section envelope; file rows ride the row).
        let mut cfg = self.patch_config(&patch);
        // BEP53 selection persisted with config_json (the restore chain
        // backfills TorrentJob.selected_files via lifecycle::bootstrap).
        cfg.selected_files = selected_files.clone();
        cfg.output_paths = output_paths;
        let meta = Arc::new(meta);
        let mut row = super::super::persist::torrent_row(
            &gid.to_string(),
            if patch.pause {
                TaskPhase::Paused
            } else {
                TaskPhase::Queued
            },
            self.row_seq(),
            &derive_name(&meta.meta),
            &cfg,
        );
        super::super::persist::fill_torrent_identity(&mut row, &meta, torrent.clone());
        let files = file_rows(&row.gid, &meta.meta.files);
        self.persist_row(row, files).await;
        self.jobs.insert(
            gid,
            Job::Torrent(Box::new(TorrentJob {
                metainfo: Arc::clone(&meta),
                tiers,
                dir: dir.clone(),
                seed: self.seed_policy_from(&patch),
                total_len,
                attrs_top,
                // Per-task rate limits (0 = unlimited default, SPEC §11).
                max_download_limit: patch.max_download_limit.unwrap_or(0),
                max_upload_limit: patch.max_upload_limit.unwrap_or(0),
                hooks,
                // select-file option value (0-based; addTorrent direct-add
                // previously had no selection entry — the second entry
                // besides magnet so=).
                selected_files,
                // No file-priority input on the add face (established via
                // taiji.setFilePriority or the restore chain).
                file_priorities: None,
                // The add face defaults to enabled (the patch_config
                // default).
                holepunch: cfg.holepunch,
                // The add-face default policy (the patch_config default
                // None = rarest_first).
                scheduler_policy: cfg.scheduler_policy.unwrap_or_default(),
                // No RPC option on the add face — an internal config_json
                // face, default None.
                disk_tier: None,
                // Per-task DHT flag (None = follow the session).
                bt_disable_dht: patch.bt_disable_dht,
                // Webseeding switch (BEP19; None = default on).
                enable_http_seeding: patch.enable_http_seeding,
            })),
        );
        // Explicit integrity checks apply to paused intake as well: Motrix
        // registers ownership before unpausing, and existing bytes must be
        // verified before the first payload download. Preserve the caller's
        // pause intent throughout the check and subsequent seed admission.
        let check_integrity = options.get("check-integrity").is_some_and(|v| v == "true");
        if self.persist.is_some()
            && total_len > 0
            && (check_integrity || (!patch.pause && Self::payload_complete(&dir, &meta.meta)))
        {
            self.park_check(gid, patch.pause).await;
        } else {
            self.enqueue(gid, patch.pause, position);
        }
        Ok(CommandReply::Gid(gid))
    }

    pub(super) fn enqueue(&mut self, gid: Gid, paused: bool, position: Option<usize>) {
        self.queue
            .insert_reserved(ReservedEntry { gid, paused }, position);
    }

    // ---- on-disk recheck scheduling ----

    /// Park a recheck into the check pool's waiting FIFO (the pool's
    /// shared admission face of the four former direct-spawn
    /// points: addTorrent complete payload / forceRecheck reserved arm /
    /// begin_deferred_recheck (the Active-deferred consume) /
    /// consume_seeding_recheck (the Seeding-deferred consume), plus
    /// bootstrap's 'checking' rows). Row truth 'checking' + FIFO
    /// parking; the spawn itself is **budget-gated** — pump_all's check
    /// segment promotes within max-concurrent-checks (the trailing pump
    /// here is the registration promotion trigger: an admission with budget
    /// room promotes in the same tick). The parked member occupies no
    /// running slot of any pool and registers no checking_progress
    /// sample (the ⟺ in-flight invariant stays on spawn_recheck).
    /// `paused` = the post-recheck requeue intent (the reserved arm
    /// preserves the waiting entry's pause state; the other three
    /// admissions are force semantics — false).
    async fn park_check(&mut self, gid: Gid, paused: bool) {
        // Complete-content provenance never crosses a checking entry
        // (the measured bitmap at RecheckDone re-routes; the mark would
        // only mislead the waiting face in between).
        self.seed_parked.remove(&gid);
        self.persist_transition(gid, TaskPhase::Checking).await;
        self.queue.insert_check_pending(gid, paused);
        info!(target: "taiji::core::session", gid = %gid, parked =
            self.queue.check_pending_gids().len(),
            "recheck scheduled: parked in check_pending \
             (max-concurrent-checks gated promotion)");
        self.pump_all().await;
    }

    /// Payload completeness probe (the gate for addTorrent's initial
    /// recheck): every non-pad real file in the dir exists with a per-file
    /// length match (zero-length files always count as matched — they may
    /// legitimately be absent). No content hashing (hashing is recheck's
    /// own job); stat only.
    fn payload_complete(dir: &Path, meta: &TorrentMeta) -> bool {
        meta.files.iter().filter(|f| !f.padding).all(|f| {
            f.length == 0
                || std::fs::metadata(dir.join(&f.path))
                    .map(|m| m.is_file() && m.len() == f.length)
                    .unwrap_or(false)
        })
    }

    /// Spawn an on-disk recheck (does not block the actor main loop; the
    /// `spawn_blocking` core + completion reported via
    /// [`TaskNotice::RecheckDone`] — the admission semantics are shared
    /// by every check-pool member: runtime forceRecheck / addTorrent
    /// initial verification / bootstrap-recovered rows alike, all
    /// promoted here by pump_check's budget gate since the check pool
    /// landed).
    /// Precondition: the gid is already in checking bookkeeping (the
    /// promotion moved it out of check_pending). pub(super): the
    /// pump_check segment (actor/mod.rs) is the promotion executor.
    pub(super) fn spawn_recheck(&mut self, gid: Gid, meta: Arc<Metainfo>) {
        let dir = match self.jobs.get(&gid) {
            Some(Job::Torrent(tj)) => tj.dir.clone(),
            _ => return,
        };
        // Persist handle resolved before the checking_progress registration:
        // the entry's only cleaner is the spawned task's RecheckDone notice,
        // so an entry registered before an early return here would leak
        // (stale fake checking-progress projection in the status views).
        // Invariant localized to this function's boundary: an entry in
        // checking_progress ⟺ a recheck is in flight for it.
        let persist = match self.persist.clone() {
            Some(p) => p,
            None => return,
        };
        let sink = Arc::new(std::sync::atomic::AtomicU64::new(0));
        self.checking_progress.insert(gid, Arc::clone(&sink));
        let events = self.events.clone();
        let gid_hex = gid.to_string();
        tokio::spawn(async move {
            // Recovered-layer read-back (keeps forceRecheck semantics
            // consistent for v2 missing-layer tasks — a read failure
            // degrades to suspended boundaries, same as the bootstrap
            // recovery path).
            let recovered: Vec<super::super::recheck::RecoveredFileLayer> =
                match persist.load_recovered_layers(&gid_hex).await {
                    Ok(rows) => rows
                        .into_iter()
                        .map(|r| super::super::recheck::RecoveredFileLayer {
                            file_index: r.file_index.max(0) as u32,
                            layer: r.layer,
                        })
                        .collect(),
                    Err(e) => {
                        warn!(target: "taiji::core::session", gid = %gid_hex, %e,
                            "recheck: recovered layers load failed (missing-layer \
                             files suspend)");
                        Vec::new()
                    }
                };
            let outcome = {
                let sink = Arc::clone(&sink);
                tokio::task::spawn_blocking(move || {
                    super::super::recheck::recheck_on_disk_recovering_with_progress(
                        &meta,
                        &dir,
                        &recovered,
                        Some(sink.as_ref()),
                    )
                })
                .await
                .unwrap_or_else(|e| Err(format!("recheck join failed: {e}")))
            };
            info!(target: "taiji::core::session", gid = %gid_hex,
                verified_pieces = sink.load(std::sync::atomic::Ordering::Relaxed),
                "recheck finished; writing bitfield back");
            let _ = events
                .send(TaskNotice::RecheckDone {
                    gid,
                    outcome: Box::new(outcome),
                })
                .await;
        });
    }

    /// Recheck completion (the [`TaskNotice::RecheckDone`] arm): write the
    /// verified bitfield back to the progress row (suspensions preserved,
    /// merged like the bootstrap recovery path) → route per the **measured
    /// bitmap** (the two-branch routing table) → pump. A task
    /// removed during the recheck (absent from jobs) = a late receipt
    /// silently absorbed (its row was already deleted by remove).
    ///
    /// Routing table (the transfer edges checking→seeding /
    /// checking→reserved; every arm ends in pump_all):
    /// - **full** (`recheck_outcome_complete`) and not pause-intent →
    ///   release the check slot and enter the **seed side** direct: the
    ///   seed slot (activate_seed — engine assembly inside the seed slot)
    ///   or, budget full, the seed_wait FIFO — never the reserved
    ///   download-slot detour (the same measured-bitmap routing as the
    ///   restart path, §4.1.4 isomorph);
    /// - **full** with the pause intent set → the user pause wins over
    ///   auto-seeding: requeue paused at the head with the complete-content
    ///   provenance mark (seed_parked — the later unpause reactivates on
    ///   the seed side, never a download slot);
    /// - **not full** (or the recheck errored: verifier build failure =
    ///   bitmap cleared = download from scratch) → requeue reserved at
    ///   the head, pause intent preserved (the existing path).
    ///
    /// The gid already left the checking registry at the function head
    /// (early return = stranded until restart — the defense below
    /// predates the routing and is preserved verbatim: every routing arm
    /// re-registers the gid somewhere).
    pub(super) async fn finish_recheck(
        &mut self,
        gid: Gid,
        outcome: Result<super::super::recheck::RecheckOutcome, String>,
    ) {
        self.checking_progress.remove(&gid);
        let paused = self.queue.remove_checking(gid).unwrap_or(false);
        let Some(Job::Torrent(tj)) = self.jobs.get(&gid) else {
            return;
        };
        let gid_hex = gid.to_string();
        let piece_len = tj.metainfo.meta.piece_length;
        // Routing predicate, computed before the write-back below
        // consumes the outcome's bitmap fields (Err = verifier build
        // failure = not complete).
        let measured_complete = match &outcome {
            Ok(o) => super::super::recheck::recheck_outcome_complete(&tj.metainfo.meta, o),
            Err(_) => false,
        };
        // Progress row write-back (count history preserved, only the
        // bitfield/piece_length overwritten — same as the bootstrap recovery
        // path's write-back; no
        // row = a new row). A read failure degrades to "no row to write"
        // (the count history is unknowable, so writing a fabricated fresh
        // row would destroy it) — the lifecycle requeue below is
        // unconditional: the gid already left the checking registry at the
        // head of this function, so an early return here would strand the
        // task outside queue/known_gids/resolve_gid until restart.
        if let Some(persist) = self.persist.clone() {
            let progress: Option<TorrentProgressRow> =
                match persist.load_torrent_progress(&gid_hex).await {
                    Ok(Some(p)) => Some(p),
                    Ok(None) => Some(TorrentProgressRow {
                        gid: gid_hex.clone(),
                        piece_length: i64::from(piece_len),
                        v1_bitfield: None,
                        v2_file_bits: None,
                        upload_at_startup: 0,
                        downloaded_total: 0,
                        uploaded_total: 0,
                        active_time_s: 0,
                        seed_time_s: 0,
                    }),
                    Err(e) => {
                        warn!(target: "taiji::core::session", gid = %gid_hex, %e,
                            "recheck: progress row load failed; bitfield write skipped");
                        None
                    }
                };
            if let Some(mut progress) = progress {
                match outcome {
                    Ok(mut o) => {
                        super::super::recheck::preserve_suspended_v2_bits(
                            &mut o.v2_file_bits,
                            progress.v2_file_bits.as_deref(),
                            &o.suspended_files,
                        );
                        info!(target: "taiji::core::session", gid = %gid_hex,
                            verified = o.verified, total = o.total,
                            suspended = o.suspended_files.len(),
                            "recheck complete: verified pieces kept, others cleared");
                        progress.piece_length = i64::from(piece_len);
                        progress.v1_bitfield = o.v1_bitfield;
                        progress.v2_file_bits = o.v2_file_bits;
                    }
                    Err(e) => {
                        // Validator build failure = the bitfield cleared
                        // (download from scratch — the importer's
                        // degrade-semantic floor, same as the bootstrap recovery path).
                        warn!(target: "taiji::core::session", gid = %gid_hex, %e,
                            "recheck failed; bitfield cleared (download from scratch)");
                        progress.piece_length = i64::from(piece_len);
                        progress.v1_bitfield = None;
                        progress.v2_file_bits = None;
                    }
                }
                if let Err(e) = persist.upsert_torrent_progress(progress).await {
                    warn!(target: "taiji::core::session", gid = %gid_hex, %e,
                        "recheck progress row write failed");
                }
            }
        }
        // Measured-bitmap routing (the two-branch table in this
        // function's doc). Row-state advance rides each arm: the seed
        // arms write 'seeding' (the seed-pool row truth: complete content
        // belongs to the seed side — residence and seed_wait alike),
        // the reserved arm writes queued/paused per the intent.
        if measured_complete && paused {
            // User pause intent wins over auto-seeding: requeue paused
            // at the head with the complete-content provenance (the
            // unpause face reactivates on the seed side — seed_parked,
            // §4.1.3).
            self.seed_parked.insert(gid);
            self.persist_transition(gid, TaskPhase::Paused).await;
            self.queue
                .insert_reserved(ReservedEntry { gid, paused: true }, Some(0));
            info!(target: "taiji::core::session", gid = %gid,
                "recheck complete (bitmap full): requeued paused with seed \
                 provenance (pause intent preserved)");
        } else if measured_complete {
            let budget = self.global.seed_budget();
            if budget > 0 && self.queue.seeding_len() >= budget {
                // Seed budget full: park (no running slot of any pool;
                // pump_all's seed segment promotes on the next release).
                self.queue.push_seed_wait(gid);
                self.persist_transition(gid, TaskPhase::Seeding).await;
                info!(target: "taiji::core::session", gid = %gid, budget,
                    "recheck complete (bitmap full): seed budget full, \
                     parked in seed_wait");
            } else {
                // Direct seed-side transfer: the engine assembles inside
                // the seed slot (activate_seed), never a download slot.
                self.persist_transition(gid, TaskPhase::Seeding).await;
                info!(target: "taiji::core::session", gid = %gid,
                    "recheck complete (bitmap full): transfer to the seed pool \
                     (check slot released)");
                self.activate_seed(gid).await;
            }
        } else {
            // Not full (or the recheck errored): requeue reserved at the
            // head — the existing path, pause intent preserved (the
            // acceptance face of pausing mid-recheck).
            let state = if paused {
                TaskPhase::Paused
            } else {
                TaskPhase::Queued
            };
            self.persist_transition(gid, state).await;
            self.queue
                .insert_reserved(ReservedEntry { gid, paused }, Some(0));
        }
        self.pump_all().await;
    }

    /// forceRecheck: schedule an on-disk recheck for a torrent task.
    ///
    /// Per domain:
    /// - **Reserved/ReservedPaused**: dequeue into the check pool's
    ///   waiting FIFO (row state 'checking'); the recheck spawns within
    ///   max-concurrent-checks (park_check + pump); requeue at the head
    ///   on completion (paused intent preserved).
    /// - **Active**: stop first (pause teardown semantics —
    ///   `retire_and_fire` requeues paused without taking an activation
    ///   slot); once the teardown event lands, the `checking_deferred` mark
    ///   parks the task into check_pending (consumed by `handle_ended`) —
    ///   the recheck must wait for engine exit to prevent an in-flight bitfield
    ///   overwrite (engine auto-save / terminal flush would clobber the
    ///   recheck write-back).
    /// - **Checking** (in flight **or parked**): already rechecking =
    ///   explicit Err (idempotent re-entry not accepted).
    /// - **Result/metadata tasks**: explicit Err (no faking).
    pub(super) async fn force_recheck(
        &mut self,
        raw_gid: String,
    ) -> Result<CommandReply, SessionError> {
        let gid = self.resolve_gid(&raw_gid)?;
        if self.persist.is_none() {
            return Err(SessionError::failed(
                "forceRecheck: session storage is not enabled",
            ));
        }
        // The family face rejects non-torrent jobs before Location
        // dispatch — the synthesis locations are
        // structurally unreachable here (media tasks have no recheck
        // face), so no Synthesizing/SynthesisWaiting arms exist in the
        // match below; the `_` arm would answer them, but no media gid
        // can reach it.
        match self.jobs.get(&gid) {
            Some(Job::Torrent(_)) => {}
            Some(_) => {
                return Err(SessionError::failed(format!(
                    "forceRecheck: GID#{gid} is not a torrent task"
                )));
            }
            None => {
                return Err(SessionError::failed(format!(
                    "Cannot re-check GID#{gid} now"
                )));
            }
        }
        match self.queue.find(gid) {
            Some(Location::Reserved | Location::ReservedPaused) => {
                let paused = self
                    .queue
                    .reserved_entry(gid)
                    .map(|e| e.paused)
                    .unwrap_or(false);
                self.queue.remove_reserved(gid);
                // War 2: park into check_pending (the spawn is
                // budget-gated — park_check's trailing pump promotes
                // within max-concurrent-checks; the pause intent rides
                // the entry to the post-recheck requeue).
                self.park_check(gid, paused).await;
                info!(target: "taiji::core::session", gid = %gid,
                    "forceRecheck scheduled (reserved task, recheck first)");
                Ok(CommandReply::Gid(gid))
            }
            Some(Location::Active) => {
                // Stop + deferred registration: move into checking after the
                // teardown event (handle_ended) lands. The pause flag =
                // requeue at the head paused (does not occupy an activation
                // slot).
                if !self.queue.request_pause(gid) {
                    return Err(SessionError::failed(format!(
                        "GID#{gid} cannot be re-checked now"
                    )));
                }
                self.checking_deferred.insert(gid);
                if let Some(t) = self.running.get(&gid) {
                    t.token.cancel();
                }
                info!(target: "taiji::core::session", gid = %gid,
                    "forceRecheck scheduled (active task: graceful stop, \
                     recheck after engine end)");
                Ok(CommandReply::Gid(gid))
            }
            // Already in the check pool (in flight **or parked** — find
            // locates both faces as Checking since the check pool
            // landed) = explicit Err
            // (idempotent re-entry not accepted; a parked member is
            // already scheduled for the check).
            Some(Location::Checking | Location::CheckingPaused) => Err(SessionError::failed(
                format!("GID#{gid} is already being re-checked"),
            )),
            // Seeding residence (the pool revision): isomorphic to the
            // Active-deferred arm — graceful stop + the checking_deferred
            // mark; the seed slot releases from the budget **immediately**
            // (the registry entry stays operable for find/pause/remove
            // until the Ended consume clears it); the Ended is swallowed
            // by the deferred consume (no results) and the task enters
            // checking directly (consume_seeding_recheck — the
            // seed-domain twin of begin_deferred_recheck's direct
            // spawn_recheck path).
            Some(Location::Seeding) => {
                if !self.queue.request_seed_pause(gid) {
                    return Err(SessionError::failed(format!(
                        "GID#{gid} cannot be re-checked now"
                    )));
                }
                self.checking_deferred.insert(gid);
                self.queue.release_seed_slot(gid);
                if let Some(t) = self.running.get(&gid) {
                    t.token.cancel();
                }
                info!(target: "taiji::core::session", gid = %gid,
                    "forceRecheck scheduled (seeding task: graceful stop, seed slot released, \
                     recheck after engine end)");
                Ok(CommandReply::Gid(gid))
            }
            _ => Err(SessionError::failed(format!(
                "Cannot re-check GID#{gid} now"
            ))),
        }
    }

    /// The teardown seam for active-domain forceRecheck (consumed by
    /// `handle_ended`): after the engine-exit event lands (requeued
    /// paused), move into checking and spawn the recheck. A remove override
    /// (teardown REMOVED, not requeued) = the mark is silently voided. The
    /// paused intent is **always false** — the paused requeue is
    /// forceRecheck's own stop semantics (pause_requested), and the task
    /// resumes after the recheck (force semantics: verify, then continue);
    /// a user pause during the recheck goes through pause()'s checking arm,
    /// which updates the bookkeeping separately.
    pub(super) async fn begin_deferred_recheck(&mut self, gid: Gid, requeued: Option<bool>) {
        if !self.checking_deferred.remove(&gid) {
            return;
        }
        if requeued.is_none() || !self.jobs.contains_key(&gid) {
            return;
        }
        self.queue.remove_reserved(gid);
        // War 2: park (budget-gated promotion). The paused intent is
        // always false — the paused requeue was forceRecheck's own stop
        // semantics, and the task resumes after the recheck. The
        // park's trailing pump is harmless mid-handle_ended (the
        // requeued-paused entry is skipped by fillup; this caller's own
        // trailing pump follows) and a no-op during shutdown (token
        // cancelled — the parked member persists as a 'checking' row
        // and re-enters at the next bootstrap).
        self.park_check(gid, false).await;
    }

    pub(super) fn seed_policy_from(&self, patch: &TaskOptionPatch) -> SeedPolicy {
        // An out-of-domain seed-time (the parse face already blocks
        // 1e30-scale extremes; this backstops side channels like
        // config_json) = skip the time condition (Duration::ZERO, the same
        // as "unset"), never panic (from_secs_f64 panics on out-of-range
        // values and would kill the actor).
        let seed_minutes = patch.seed_time_min.unwrap_or(self.global.seed_time_min);
        SeedPolicy {
            // No super-seeding option on the add face (aria2 has no such
            // option and no RPC/CLI name is promised — the only entry is
            // the internal config_json face).
            super_seeding: false,
            seed_ratio: patch.seed_ratio.unwrap_or(self.global.seed_ratio),
            seed_time: seed_duration_from_minutes(seed_minutes).unwrap_or_else(|| {
                warn!(target: "taiji::core::session",
                    "seed-time {seed_minutes:e} min out of range; seed time condition dropped");
                Duration::ZERO
            }),
            // bt-stop-timeout: an explicit per-task value wins, falling
            // back to the session global (aria2's per-download precedence);
            // 0 = no BtStopTimeoutWatch attached (the same as aria2's
            // default). u64 secs → Duration cannot overflow (from_secs is
            // valid over the whole domain).
            stop_timeout: Duration::from_secs(
                patch
                    .bt_stop_timeout_secs
                    .unwrap_or(self.global.bt_stop_timeout_secs),
            ),
            detach_seed_only: self.global.bt_detach_seed_only,
        }
    }

    // ---- lifecycle ----

    /// pause/forcePause. The two are equivalent in this model (aria2's
    /// force distinction concerns the halt/pause combination state —
    /// `pauseRequestGroup`, RpcMethodImpl.cc; a task already pausing or
    /// removing is rejected for both). Success persists the row state
    /// paused.
    pub(super) async fn pause(&mut self, gid: Gid) -> Result<CommandReply, SessionError> {
        if let Some(resume) = self.queue.startup_held.get_mut(&gid) {
            *resume = false;
        }
        match self.queue.find(gid) {
            Some(Location::Active) => {
                if self.queue.request_pause(gid) {
                    if let Some(t) = self.running.get(&gid) {
                        // HTTP tasks: pause sets the cancel-source flag (the
                        // driver teardown writes the http_task row as paused
                        // — restart returns it to the paused queue).
                        if let Some(p) = t.backend.http_pause() {
                            p.store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                        // Media tasks: the same cancel-source flag shape
                        // (the pipeline teardown writes the paused row
                        // with the §3.2 phase memory).
                        if let Some(p) = t.backend.media_pause() {
                            p.store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                        t.token.cancel();
                    }
                    // Row state paused (the teardown event rewrites the same
                    // value when requeueing by the pause flag; skip-write
                    // semantics absorb the duplicate).
                    self.persist_transition(gid, TaskPhase::Paused).await;
                    Ok(CommandReply::Gid(gid))
                } else {
                    Err(SessionError::failed(format!(
                        "GID#{gid} cannot be paused now"
                    )))
                }
            }
            Some(Location::Reserved) => {
                if let Some(e) = self.queue.reserved_entry_mut(gid) {
                    e.paused = true;
                }
                // HTTP tasks: pause intent persisted with the http_task row
                // (previously a reserved pause was a no-op on the http row,
                // so the task auto-started after restart).
                self.http_reserved_transition(gid, TaskPhase::Paused).await;
                self.media_reserved_transition(gid, TaskPhase::Paused).await;
                self.persist_transition(gid, TaskPhase::Paused).await;
                Ok(CommandReply::Gid(gid))
            }
            // Check pool (in flight or parked — find locates both):
            // record the pause intent on whichever face holds the gid
            // (the task stays paused after the recheck requeues); row
            // state stays 'checking' — crash recovery's check-pending
            // re-admission must not lose the pause intent (the requeue
            // face closes on the bookkeeping).
            Some(Location::Checking | Location::CheckingPaused) => {
                self.queue.set_check_paused(gid, true);
                Ok(CommandReply::Gid(gid))
            }
            // Seeding residence (§4.1.3): graceful stop →
            // the Ended consume requeues to the front paused (the
            // existing pause path, only the registry source differs —
            // the seeding record's flag instead of the active record's).
            Some(Location::Seeding) => {
                if self.queue.request_seed_pause(gid) {
                    if let Some(t) = self.running.get(&gid) {
                        t.token.cancel();
                    }
                    self.persist_transition(gid, TaskPhase::Paused).await;
                    Ok(CommandReply::Gid(gid))
                } else {
                    Err(SessionError::failed(format!(
                        "GID#{gid} cannot be paused now"
                    )))
                }
            }
            // Parked in the seed FIFO: leave seed_wait and enter the
            // waiting queue paused at the front, with the seed_parked
            // provenance so the later unpause reactivates on the seed
            // side (never a download slot).
            Some(Location::SeedWaiting) => {
                self.queue.remove_seed_wait(gid);
                self.queue
                    .insert_reserved(ReservedEntry { gid, paused: true }, Some(0));
                self.seed_parked.insert(gid);
                self.persist_transition(gid, TaskPhase::Paused).await;
                Ok(CommandReply::Gid(gid))
            }
            // Synthesis pool (§4.3): a gate-hung or
            // synthesizing media task pauses like the active face —
            // the flag lands on whichever synthesis face holds the
            // gid, the token cancel races the gate await / the
            // synthesis, and the teardown lands
            // `MediaEnd::Paused{memory: Processing}` (the §3.2 phase
            // memory — the driver writes the paused row; media rows
            // have no torrent mirror, so no persist_transition here).
            // The Ended consume requeues to the front paused; the
            // unpause re-enters via the download-side activation and
            // converges back onto the gate (no special case).
            Some(Location::Synthesizing | Location::SynthesisWaiting) => {
                if !self.queue.request_synthesis_pause(gid) {
                    return Err(SessionError::failed(format!(
                        "GID#{gid} cannot be paused now"
                    )));
                }
                if let Some(t) = self.running.get(&gid) {
                    if let Some(p) = t.backend.media_pause() {
                        p.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    t.token.cancel();
                }
                Ok(CommandReply::Gid(gid))
            }
            // Already paused / result table / unknown → the same aria2
            // failure face.
            _ => Err(SessionError::failed(format!(
                "GID#{gid} cannot be paused now"
            ))),
        }
    }

    /// unpause. ReservedPaused → normal resume (back to the waiting
    /// queue); the Result face = the §7.1 Error→unpause re-probe transition
    /// arm (a failed task may re-enter the probe queue; previously a failed
    /// task could only be deleted and re-added).
    pub(super) async fn unpause(&mut self, gid: Gid) -> Result<CommandReply, SessionError> {
        if self.awaiting_torrent_selection(gid) {
            return Err(SessionError::failed(
                "torrent file selection is awaiting confirmation",
            ));
        }
        if self.queue.startup_held.remove(&gid).is_some()
            && !matches!(
                self.queue.find(gid),
                Some(Location::ReservedPaused | Location::CheckingPaused)
            )
        {
            return Ok(CommandReply::Gid(gid));
        }
        if self.queue.find(gid).is_none() {
            if let Some(persist) = &self.persist {
                if let Some(snapshot) = persist
                    .load_http_task(&gid.to_string())
                    .await
                    .map_err(|error| SessionError::failed(error.to_string()))?
                {
                    if snapshot.row.state == "error"
                        && http_task::HttpPersistConfig::from_json(&snapshot.row.config_json)
                            .retain_request_context
                    {
                        return self.unpause_http_result(gid).await;
                    }
                }
            }
            return Err(SessionError::failed(format!("GID {gid} is not found")));
        }
        match self.queue.find(gid) {
            // Complete-content provenance (§4.1.3 — the
            // park/unpark round trip): a paused task whose measured
            // content is complete reactivates on the **seed side** —
            // the reactivation occupies a seed slot (or parks back into
            // seed_wait when the budget is full), never a download
            // slot. The download-slot count is untouched throughout.
            Some(Location::ReservedPaused) if self.seed_parked.contains(&gid) => {
                self.queue.remove_reserved(gid);
                self.seed_parked.remove(&gid);
                let budget = self.global.seed_budget();
                if budget == 0 || self.queue.seeding_len() < budget {
                    self.persist_transition(gid, TaskPhase::Seeding).await;
                    self.activate_seed(gid).await;
                } else {
                    self.queue.push_seed_wait(gid);
                    self.persist_transition(gid, TaskPhase::Seeding).await;
                    info!(target: "taiji::core::session", gid = %gid,
                        "seed budget full: unparked task re-queued into seed_wait");
                }
                Ok(CommandReply::Gid(gid))
            }
            Some(Location::ReservedPaused) => {
                if let Some(e) = self.queue.reserved_entry_mut(gid) {
                    e.paused = false;
                }
                // HTTP task row back to queued (the http_task table is the
                // source of truth).
                self.http_reserved_transition(gid, TaskPhase::Queued).await;
                self.media_reserved_transition(gid, TaskPhase::Queued).await;
                let state = self.reserved_state(gid);
                self.persist_transition(gid, state).await;
                Ok(CommandReply::Gid(gid))
            }
            // Check pool in flight/parked + pause intent: clear the
            // pause intent only (the recheck continues / the promotion
            // order is untouched; the task is activatable right after
            // requeueing); row state stays 'checking'.
            Some(Location::CheckingPaused) => {
                self.queue.set_check_paused(gid, false);
                Ok(CommandReply::Gid(gid))
            }
            Some(Location::Result) => {
                // The Error→unpause re-entry: HTTP tasks re-probe;
                // media tasks re-resolve (§3.2's same-semantics arm).
                // The family decision is row-driven (the jobs table is
                // empty at the Result state — the teardown removed the
                // payload): a media_task row decides the media arm.
                let media_row = match self.persist.as_ref() {
                    Some(p) => matches!(p.load_media_task(&gid.to_string()).await, Ok(Some(_))),
                    None => false,
                };
                if media_row {
                    self.unpause_media_result(gid).await
                } else {
                    self.unpause_http_result(gid).await
                }
            }
            _ => Err(SessionError::failed(format!(
                "GID#{gid} cannot be unpaused now"
            ))),
        }
    }

    /// Error→unpause re-probe transition arm (HTTP tasks only — the §7.1
    /// state machine's `Error(re-probe via unpause)`; a torrent failure's
    /// bitfield re-verification belongs to the recheck face, not this arm):
    /// read the error row → the row goes back to queued (error fields
    /// cleared, cookies kept for replay) → rebuild Job::Http into the
    /// waiting queue. A reopen write failure rejects the unpause (no Job
    /// rebuild, no queue bookkeeping change, zero DB writes) — rebuilding
    /// anyway while the row is stuck in an error terminal would make the
    /// terminal-degrade guard reject every subsequent non-terminal row
    /// write, leaving the session/DB divergence unresolvable and the task's
    /// cross-restart self-recovery gone.
    async fn unpause_http_result(&mut self, gid: Gid) -> Result<CommandReply, SessionError> {
        let Some(persist) = self.persist.clone() else {
            return Err(SessionError::failed(format!(
                "GID#{gid} cannot be unpaused now"
            )));
        };
        let snap = match persist.load_http_task(&gid.to_string()).await {
            Ok(Some(s)) => s,
            Ok(None) => {
                return Err(SessionError::failed(format!(
                    "GID#{gid} cannot be unpaused now"
                )));
            }
            Err(e) => {
                warn!(target: "taiji::core::session", gid = %gid, %e,
                    "unpause: http row load failed");
                return Err(SessionError::failed(format!(
                    "GID#{gid} cannot be unpaused now"
                )));
            }
        };
        // Terminal escape uses the explicit reopen (the single writer's
        // terminal-degrade guard refuses non-terminal overwrites — a normal
        // upsert would be skip-written); progress/summary/cookies are
        // preserved as-is by the UPDATE. The failure arm rejects the
        // unpause: the row keeps its error terminal, in-memory stays in
        // Result bookkeeping, both sides consistent (retries left to the
        // user).
        if let Err(e) = persist.reopen_http_task(&gid.to_string()).await {
            warn!(target: "taiji::core::session", gid = %gid, %e,
                "unpause: http row reopen persist failed; unpause rejected");
            return Err(SessionError::failed(format!(
                "GID#{gid} cannot be unpaused now"
            )));
        }
        let mut row = snap.row;
        row.state = TaskPhase::Queued.as_v1_str().into();
        row.error_code = None;
        row.error_msg = None;
        row.updated_at = now_epoch();
        // Clear own stale claims before the rerun: re-entering a
        // done+renamePending row re-occupies the runtime, so the part+final
        // claims transferred at the previous finalize yield (an error row
        // has no claims; an idempotent no-op).
        http_task::release_output_claims(&gid.to_string(), &row.config_json);
        self.jobs.insert(
            gid,
            Job::Http(Box::new(HttpJob {
                uris: vec![row.url.clone()],
                dir: PathBuf::from(&row.dir),
                out: (!row.out.is_empty()).then(|| row.out.clone()),
                max_download_limit: 0,
                max_upload_limit: 0,
                hooks: Arc::new(self.global.hooks.clone()),
                opts: http_task::HttpTaskOpts::default(),
                restore: Some(row),
                mirror: None,
                cookies: snap.cookies,
                // Bootstrap rebuild = empty seeds: file sources are not
                // re-read across restarts (aria2 also loads once at task
                // creation); the restore face replays from persisted cookie
                // rows.
                cookie_seed: Vec::new(),
                submitted: std::time::Instant::now(),
            })),
        );
        self.queue.remove_result(gid);
        self.queue
            .insert_reserved(ReservedEntry { gid, paused: false }, None);
        info!(target: "taiji::core::session", gid = %gid,
            "error task unpaused; re-probe requeued (state machine Error→Probing)");
        Ok(CommandReply::Gid(gid))
    }

    /// Row-state transition for waiting HTTP tasks (the reserved
    /// pause/unpause face): the row payload comes from the mirror
    /// (activated) or the registration row (not yet activated); the state
    /// arrives as the unified vocabulary's enum and serializes through
    /// its canonical table, the whole row is rewritten; `restore` is
    /// updated in sync (the next activation before the mirror takes over
    /// does not carry a stale row state). No-op for non-HTTP tasks.
    pub(super) async fn http_reserved_transition(&mut self, gid: Gid, phase: TaskPhase) {
        let Some(Job::Http(hj)) = self.jobs.get_mut(&gid) else {
            return;
        };
        let mut row = match hj.mirror.as_ref() {
            Some(m) => crate::lock(m).clone(),
            None => match hj.restore.as_ref() {
                Some(r) => r.clone(),
                None => return,
            },
        };
        row.state = phase.as_v1_str().to_string();
        row.updated_at = now_epoch();
        hj.restore = Some(row.clone());
        self.persist_http_row(&row).await;
    }

    // ---- Media task lifecycle helpers ----

    /// The DirectLink conversion (§4): rebuild a Job::Http from the
    /// media job's original payload (dir/out/cookies) and re-activate
    /// on the same GID — the entry runs as an ordinary HTTP task from
    /// here (the zero-new-surface rule; the probe face already told
    /// the client the same thing).
    async fn media_direct_link(&mut self, gid: Gid) {
        let Some(Job::Media(mj)) = self.jobs.get(&gid) else {
            return;
        };
        let url = mj.cfg.url.clone();
        let dir = mj.cfg.output_dir.clone();
        let out = mj.cfg.out.clone();
        let cookie_specs = mj.cookie_specs.clone();
        let cookie_seed: Vec<taiji_http::cookies::NetscapeCookie> =
            cookies_from_specs(&cookie_specs);
        let hooks = Arc::new(self.global.hooks.clone());
        self.jobs.insert(
            gid,
            Job::Http(Box::new(HttpJob {
                uris: vec![url],
                dir,
                out,
                max_download_limit: 0,
                max_upload_limit: 0,
                hooks,
                opts: http_task::HttpTaskOpts::default(),
                restore: None,
                mirror: None,
                cookies: Vec::new(),
                cookie_seed,
                submitted: std::time::Instant::now(),
            })),
        );
        // The active slot carries over: re-activate inline (the same
        // face as a restart requeue).
        let token = self.token.child_token();
        self.activate(gid, Some(token)).await;
        info!(target: "taiji::core::session", gid = %gid,
            "media entry classified as a direct file; converted to the HTTP task family");
    }

    /// Media remove: delete the row (the FK cascade clears track/
    /// segment/key/format children; the delete face pairs its own
    /// cookie clear) + the staging tree (the media remove face) + an
    /// **unconditional idempotent** cookie clear — a waiting media
    /// task's creation-time cookie rows exist **without** a
    /// media_task row (the row first lands inside Resolving), and
    /// delete_media_task's paired clear only runs when the row was
    /// actually deleted, so the row-less form is cleared here (every
    /// remove path funnels through this face: the graceful teardown
    /// arm, the active-force arm, and the reserved remove arms).
    async fn media_remove_row(&mut self, gid: Gid) {
        if let Some(p) = self.persist.as_ref() {
            let _ = p.delete_media_task(&gid.to_string()).await;
            let _ = p.clear_task_cookies(&gid.to_string()).await;
        }
        if let Some(Job::Media(mj)) = self.jobs.get(&gid) {
            let gid_dir = mj.cfg.staging_gid_dir();
            let _ = taiji_media::remove_staging(&gid_dir);
        }
    }

    /// Terminal cookie close-out (the full
    /// terminal set done|error clears, both families): clear the gid's
    /// unified-table cookie rows; on the **error** form publish the
    /// bypass alert (`taiji.task.cookiesClearedOnError`,
    /// payload = gid/task_kind/cleared count — never a cookie value).
    /// The count is read before the clear (load-then-clear through the
    /// single writer; low frequency — only error terminals of tasks
    /// that held cookies). A clear failure only warns: the startup GC
    /// backstops the residue (the crash window is exactly its (b)
    /// class), and the alert is skipped when the clear itself failed
    /// (never claim a clear that did not happen).
    pub(super) async fn terminal_cookie_closeout(
        &mut self,
        gid: Gid,
        task_kind: &'static str,
        error_form: bool,
    ) {
        let Some(p) = self.persist.clone() else {
            return;
        };
        if error_form && task_kind == "http" {
            if let Ok(Some(snapshot)) = p.load_http_task(&gid.to_string()).await {
                if http_task::HttpPersistConfig::from_json(&snapshot.row.config_json)
                    .retain_request_context
                {
                    return;
                }
            }
        }
        let count = if error_form {
            match p.load_task_cookies(&gid.to_string()).await {
                Ok(rows) => rows.len() as u64,
                Err(e) => {
                    warn!(target: "taiji::core::session", gid = %gid, %e,
                        "terminal cookie count read failed; clearing without the alert");
                    // Fall through to the clear (0 = no alert payload).
                    0
                }
            }
        } else {
            0
        };
        match p.clear_task_cookies(&gid.to_string()).await {
            Ok(_) => {
                if error_form && count > 0 {
                    let _ = self
                        .cookie_bus
                        .send(crate::session::events::TaskCookieEvent {
                            gid,
                            task_kind,
                            count,
                        });
                    info!(target: "taiji::core::session", gid = %gid,
                        task_kind, count,
                        "task cookies cleared at the error terminal");
                }
            }
            Err(e) => {
                warn!(target: "taiji::core::session", gid = %gid, %e,
                    "terminal cookie clear failed (startup GC backstops the residue)");
            }
        }
    }

    /// Row-state transition for waiting media tasks (the reserved
    /// pause/unpause face; the phase arrives as the unified vocabulary's
    /// enum and serializes through its canonical table): `paused` writes
    /// through the upsert (non-terminal→terminal); `queued` — the exit
    /// from `paused` — routes through the explicit unpause job (the
    /// upsert's terminal-degrade guard refuses the plain non-terminal
    /// overwrite; the job also clears the §3.2 phase memory). No-op
    /// for non-media tasks.
    pub(super) async fn media_reserved_transition(&mut self, gid: Gid, phase: TaskPhase) {
        let Some(Job::Media(mj)) = self.jobs.get_mut(&gid) else {
            return;
        };
        let Some(mut row) = mj.cfg.restore.clone() else {
            return;
        };
        let Some(p) = self.persist.as_ref() else {
            return;
        };
        if phase == TaskPhase::Queued {
            let _ = p.unpause_media_task(&gid.to_string()).await;
            if let Ok(Some(fresh)) = p.load_media_task(&gid.to_string()).await {
                row = fresh;
            }
        } else {
            let _ = p.upsert_media_task(row.clone()).await;
        }
        row.state = phase.as_v1_str().to_string();
        row.updated_at = now_epoch();
        mj.cfg.restore = Some(row);
    }

    /// Media Error→unpause re-resolve arm (§3.2: Error --unpause-->
    /// Resolving re-resolution): reopen the row (error fields cleared, state
    /// `resolving`) → rebuild Job::Media into the waiting queue. A
    /// reopen failure rejects the unpause (zero DB writes, the row
    /// keeps its terminal — the http face's discipline).
    async fn unpause_media_result(&mut self, gid: Gid) -> Result<CommandReply, SessionError> {
        let Some(persist) = self.persist.clone() else {
            return Err(SessionError::failed(format!(
                "GID#{gid} cannot be unpaused now"
            )));
        };
        let row = match persist.load_media_task(&gid.to_string()).await {
            Ok(Some(r)) => r,
            _ => {
                return Err(SessionError::failed(format!(
                    "GID#{gid} cannot be unpaused now"
                )));
            }
        };
        if let Err(e) = persist.reopen_media_task(&gid.to_string()).await {
            warn!(target: "taiji::core::session", gid = %gid, %e,
                "unpause: media row reopen persist failed; unpause rejected");
            return Err(SessionError::failed(format!(
                "GID#{gid} cannot be unpaused now"
            )));
        }
        let mut cfg = crate::session::media::media_config_from_row(&row);
        cfg.gid = gid.to_string();
        cfg.persist = self.persist.clone();
        self.jobs.insert(
            gid,
            Job::Media(Box::new(media_task::MediaJob {
                cfg,
                cookie_specs: Vec::new(),
            })),
        );
        self.queue.remove_result(gid);
        self.queue
            .insert_reserved(ReservedEntry { gid, paused: false }, None);
        info!(target: "taiji::core::session", gid = %gid,
            "error media task unpaused; re-resolve requeued (state machine Error→Resolving)");
        Ok(CommandReply::Gid(gid))
    }

    /// Media bootstrap (the §8 recovery face): active rows read back →
    /// Job::Media rebuild + GID reserve + enqueue (paused rows stay
    /// paused; the rest re-enter by phase — the pipeline's download
    /// resume is the track-ledger face, Processing is the idempotent
    /// re-run). Also the staging startup GC (orphan gids, the
    /// liveness fix): the liveness set = **every** media_task
    /// row, any state — a staging tree without a row is an orphan by
    /// definition, a tree **with** a row (error/done included) never
    /// is (the media spec keeps an errored task's staging for the
    /// Error→unpause re-run).
    pub(super) async fn bootstrap_media(&mut self) -> Vec<(i64, Gid, bool)> {
        let Some(persist) = self.persist.clone() else {
            return Vec::new();
        };
        let rows = match persist.load_media_tasks_at_startup().await {
            Ok(rows) => rows,
            Err(e) => {
                warn!(target: "taiji::core::session", %e,
                    "startup media task load failed (treated as fresh set)");
                return Vec::new();
            }
        };
        // Staging GC: the liveness set = **every** row, any
        // state (a true orphan = a gid directory with no media_task
        // row at all). Terminal rows are not re-enqueued, but their
        // staged trees stay — the media spec keeps an errored task's
        // staging (the Error→unpause re-run's resume face); `done`
        // residue belongs to the success-cleanup face, not the GC.
        // Roots = the distinct staging parents over the same all-row
        // set (an error-only history still puts its root on the radar
        // so genuine orphans next to it are swept).
        let mut swept = 0usize;
        if !self.global.motrix_startup_hold {
            match persist.load_media_task_gc_refs().await {
                Ok(gc_refs) => {
                    let mut roots: std::collections::BTreeSet<PathBuf> =
                        std::collections::BTreeSet::new();
                    let live_gids: Vec<&str> =
                        gc_refs.iter().map(|(gid, _)| gid.as_str()).collect();
                    for (_, staging_dir) in &gc_refs {
                        if let Some(parent) = PathBuf::from(staging_dir).parent() {
                            roots.insert(parent.to_path_buf());
                        }
                    }
                    for root in &roots {
                        let orphans = taiji_media::gc_orphan_gids(root, &live_gids);
                        swept += orphans.len();
                    }
                    if swept > 0 {
                        info!(target: "taiji::core::session", swept,
                        "media staging startup GC: orphan gid directories removed");
                    }
                }
                Err(e) => {
                    // Fail-closed the safe way: sweep nothing (deleting a
                    // live task's staging on a read error is the §7 bug in
                    // another coat).
                    warn!(target: "taiji::core::session", %e,
                    "staging GC liveness read failed; startup GC skipped");
                }
            }
        }
        let mut reserved: Vec<(i64, Gid, bool)> = Vec::new();
        for (pos, row) in rows.into_iter().enumerate() {
            let Ok(raw_gid) = u64::from_str_radix(&row.gid, 16) else {
                warn!(target: "taiji::core::session", gid = %row.gid,
                    "startup media row has malformed gid; skipped");
                continue;
            };
            let gid = Gid::from_u64(raw_gid);
            self.gid.reserve(raw_gid);
            // Pause judgment through the unified vocabulary's parse face
            // (the startup read face already filters rows to the active
            // word set; a parse failure is defensive-only — warn and take
            // the not-paused active face, the store write face's
            // poisoned-row posture, the row repairs on the next phase
            // write).
            let paused = match TaskPhase::parse_v1(&row.state) {
                Ok(phase) => phase == TaskPhase::Paused,
                Err(e) => {
                    warn!(target: "taiji::core::session", gid = %row.gid, %e,
                        "startup media row state outside the unified vocabulary; \
                         restored as the not-paused active face (row repairs on the \
                         next phase write)");
                    false
                }
            };
            if self.global.motrix_startup_hold {
                self.queue.startup_held.insert(gid, !paused);
            }
            let mut cfg = crate::session::media::media_config_from_row(&row);
            cfg.gid = gid.to_string();
            cfg.persist = self.persist.clone();
            self.jobs.insert(
                gid,
                Job::Media(Box::new(media_task::MediaJob {
                    cfg,
                    cookie_specs: Vec::new(),
                })),
            );
            // media rows carry no queue_pos — the created_at order is
            // the stable restore key (pos keeps the relative order
            // inside the merged reserved set).
            reserved.push((pos as i64, gid, paused));
        }
        if !reserved.is_empty() {
            info!(target: "taiji::core::session", restored = reserved.len(),
                "session bootstrap: active media tasks restored (GID reserved)");
        }
        reserved
    }

    /// remove (the graceful entry; see [`Self::remove_inner`] for the
    /// shared semantics): graceful shutdown, the teardown event drives
    /// the result recording.
    ///
    /// Notices: both remove paths ultimately end in a REMOVED terminal →
    /// the `Stop` event (the REMOVED branch of aria2 executeStopHook) —
    /// force publishes directly here; the normal path publishes in the
    /// teardown's retire_and_fire. The aborted watcher's late Failed
    /// teardown is absorbed by retire_and_fire's orphan guard (no
    /// fabricated Error event).
    ///
    /// Persistence decision: SPEC §5.3's state set has no `removed`, and
    /// aria2's session save also does not persist removed tasks
    /// (SessionSerializer.cc: FINISHED/REMOVED need --force-save) →
    /// **remove = DeleteTorrent** (row-level FK cascade clears the child
    /// tables); force deletes here immediately, a normal remove deletes via
    /// the teardown event's remove-flag dispatch (persist_after_end).
    /// HTTP tasks: the row write face is **DeleteHttpTask** (the previous
    /// tombstone write face was a no-op when the mirror was absent — a
    /// reserved task / already removed — so "add then remove, and the task
    /// resurrects after restart"; deleting the row also FK-cascades the
    /// task cookies away, the delete-clears backstop half).
    pub(super) async fn remove(&mut self, gid: Gid) -> Result<CommandReply, SessionError> {
        self.remove_inner(gid, false).await
    }

    /// forceRemove: abort the engine task immediately (skipping the
    /// stopped announce budget) + record the result at once (see
    /// [`Self::remove_inner`] for the shared remove semantics).
    pub(super) async fn force_remove(&mut self, gid: Gid) -> Result<CommandReply, SessionError> {
        self.remove_inner(gid, true).await
    }

    /// Shared body of the remove/forceRemove pair (the `force` fact is
    /// crate-private; no call site passes a positional bool). The two
    /// public entries are [`Self::remove`] (graceful) and
    /// [`Self::force_remove`] (immediate abort).
    async fn remove_inner(&mut self, gid: Gid, force: bool) -> Result<CommandReply, SessionError> {
        match self.queue.find(gid) {
            Some(Location::Active) => {
                if !self.queue.request_remove(gid) {
                    return Err(SessionError::failed(format!(
                        "Active Download not found for GID#{gid}"
                    )));
                }
                if force {
                    // A filesystem call cannot be aborted. Drain publication
                    // before acknowledging removal or releasing its claims.
                    let publication_gate = self.running.get(&gid).and_then(|t| {
                        t.backend.http_live().map(|live| {
                            t.token.cancel();
                            live.output.io_gate.clone()
                        })
                    });
                    let _publication_drain = match publication_gate {
                        Some(gate) => Some(gate.lock_owned().await),
                        None => None,
                    };
                    let total = self
                        .running
                        .get(&gid)
                        .map(|t| t.total_len)
                        .unwrap_or_default();
                    // Claim-domain closeout: release the final/part claims
                    // with the removal. Only runs when the live
                    // rename_pending flag is set (= finalize already
                    // returned RenamePending and the claims were transferred
                    // to the polling bookkeeping) — an in-flight driver's
                    // active claims are released by its lease/credentials on
                    // future drop; stealing them early would widen a dying
                    // driver's mutual-exclusion window. Row facts are taken
                    // first (the mirror is unreachable after running.remove
                    // below).
                    let persisted_pending = self
                        .running
                        .get(&gid)
                        .and_then(|t| t.backend.http_live().cloned())
                        .is_some_and(|l| {
                            l.rename_pending.load(std::sync::atomic::Ordering::Relaxed)
                        });
                    if persisted_pending
                        && let Some(mirror) = self
                            .running
                            .get(&gid)
                            .and_then(|t| t.backend.http_row().cloned())
                    {
                        let cfg_json = crate::lock(&mirror).config_json.clone();
                        http_task::release_output_claims(&gid.to_string(), &cfg_json);
                    }
                    if let Some(t) = self.running.get(&gid) {
                        // token.cancel before the hard abort — the batch-path
                        // driver cancel branch (batch.abort + leave) and the
                        // worker pickup loop's cancel face both source from
                        // the token; aborting without cancelling drops the
                        // driver future outright and leaving the group falls
                        // back to the Drop guard alone (cancelling first
                        // lets in-flight workers exit in order at select
                        // points, so the teardown face deterministically
                        // runs).
                        t.token.cancel();
                        if let Some(abort) = &t.abort {
                            abort.abort();
                        }
                    }
                    self.running.remove(&gid);
                    // forceRemove's immediate detach has no window before an
                    // Ended notice is enqueued, so the announce face is
                    // withdrawn synchronously here (the late notice's
                    // withdraw is idempotent).
                    self.lsd_withdraw(gid).await;
                    let entry = self.build_result_entry(gid, StatusKind::Removed, total, 0, None);
                    let _ = self.queue.retire_active(gid, entry);
                    // Media force-remove: delete the row (the paired
                    // cookie clear rides the delete face) + the staging
                    // tree BEFORE the job payload goes (media_remove_row
                    // reads the staging dir off the job) — the force
                    // path has no teardown event, nothing else would.
                    if matches!(self.jobs.get(&gid), Some(Job::Media(_))) {
                        self.media_remove_row(gid).await;
                    }
                    self.jobs.remove(&gid);
                    self.publish(gid, EventKind::Stop);
                    // Row deletion (FK cascade clears file/progress/tracker
                    // rows) + HTTP row deletion (the paired delete clears
                    // the cookie rows) + closeout registry removal.
                    self.persist_remove_row(gid).await;
                    self.http_remove_row(gid).await;
                } else if let Some(t) = self.running.get(&gid) {
                    t.token.cancel();
                }
                Ok(CommandReply::Gid(gid))
            }
            Some(Location::Reserved) | Some(Location::ReservedPaused) => {
                self.queue.remove_reserved(gid);
                // Media remove on the reserved arms (waiting/paused):
                // delete the row + staging and clear the cookie rows —
                // BEFORE the job payload goes (media_remove_row reads
                // the staging dir off the job). The unconditional
                // clear covers the never-activated waiting form whose
                // creation-time cookie rows have no media_task row
                // (delete_media_task's paired clear is row-scoped);
                // for the paused-after-activation form the row delete
                // also closes the restart-resurrection face.
                if matches!(self.jobs.get(&gid), Some(Job::Media(_))) {
                    self.media_remove_row(gid).await;
                }
                self.jobs.remove(&gid);
                self.persist_remove_row(gid).await;
                self.http_remove_row(gid).await;
                Ok(CommandReply::Gid(gid))
            }
            // Check pool (in flight or parked): cancel the recheck (the
            // in-flight spawn_blocking cannot be interrupted — a late
            // RecheckDone receipt is silently absorbed by the gid's
            // absence from jobs), dequeue from both check faces, task
            // teardown + row deletion. The same direction as aria2
            // allowing group removal during verification.
            Some(Location::Checking | Location::CheckingPaused) => {
                self.queue.remove_checking(gid);
                self.queue.remove_check_pending(gid);
                self.checking_progress.remove(&gid);
                self.jobs.remove(&gid);
                self.persist_remove_row(gid).await;
                info!(target: "taiji::core::session", gid = %gid,
                    "task removed during recheck (recheck cancelled)");
                Ok(CommandReply::Gid(gid))
            }
            // Seeding residence: remove as usual — graceful
            // stop, the Ended consume records Removed + deletes the row
            // (the halt override on the seeding record); force =
            // immediate abort detach (the active-domain force shape,
            // sourced from the seeding registry).
            Some(Location::Seeding) => {
                if !self.queue.request_seed_remove(gid) {
                    return Err(SessionError::failed(format!(
                        "Active Download not found for GID#{gid}"
                    )));
                }
                if force {
                    let total = self
                        .running
                        .get(&gid)
                        .map(|t| t.total_len)
                        .unwrap_or_default();
                    if let Some(t) = self.running.get(&gid) {
                        t.token.cancel();
                        if let Some(abort) = &t.abort {
                            abort.abort();
                        }
                    }
                    self.running.remove(&gid);
                    self.lsd_withdraw(gid).await;
                    self.queue.remove_seeding(gid);
                    self.checking_deferred.remove(&gid);
                    self.seed_wait_deferred.remove(&gid);
                    self.seed_parked.remove(&gid);
                    let entry = self.build_result_entry(gid, StatusKind::Removed, total, 0, None);
                    self.queue.record_result(entry);
                    self.jobs.remove(&gid);
                    self.publish(gid, EventKind::Stop);
                    self.persist_remove_row(gid).await;
                } else if let Some(t) = self.running.get(&gid) {
                    t.token.cancel();
                }
                Ok(CommandReply::Gid(gid))
            }
            // Parked in the seed FIFO: dequeue + row deletion (the
            // waiting-remove shape — no result entry, same as
            // removeReservedGroup).
            Some(Location::SeedWaiting) => {
                self.queue.remove_seed_wait(gid);
                self.jobs.remove(&gid);
                self.seed_parked.remove(&gid);
                self.persist_remove_row(gid).await;
                Ok(CommandReply::Gid(gid))
            }
            // Synthesis pool: remove as usual — graceful =
            // the remove flag + token cancel (the gate await / the
            // synthesis loses the race), the Ended consume records
            // Removed + deletes the row (the halt override on the
            // synthesis faces); force = immediate abort detach (the
            // active-domain force shape, sourced from the synthesis
            // faces).
            Some(Location::Synthesizing | Location::SynthesisWaiting) => {
                if !self.queue.request_synthesis_remove(gid) {
                    return Err(SessionError::failed(format!(
                        "Active Download not found for GID#{gid}"
                    )));
                }
                if force {
                    let total = self
                        .running
                        .get(&gid)
                        .map(|t| t.total_len)
                        .unwrap_or_default();
                    if let Some(t) = self.running.get(&gid) {
                        t.token.cancel();
                        if let Some(abort) = &t.abort {
                            abort.abort();
                        }
                    }
                    self.running.remove(&gid);
                    self.queue.remove_synthesis(gid);
                    self.media_gate_tx.remove(&gid);
                    let entry = self.build_result_entry(gid, StatusKind::Removed, total, 0, None);
                    self.queue.record_result(entry);
                    self.jobs.remove(&gid);
                    self.publish(gid, EventKind::Stop);
                    self.media_remove_row(gid).await;
                    // The force detach released the synthesis slot (and
                    // possibly a requeue order): the parked members
                    // backfill in this command's own pump
                    // (release-then-backfill, no idle beat).
                    self.pump_all().await;
                } else if let Some(t) = self.running.get(&gid) {
                    t.token.cancel();
                }
                Ok(CommandReply::Gid(gid))
            }
            _ => Err(SessionError::failed(format!(
                "Active Download not found for GID#{gid}"
            ))),
        }
    }

    /// HTTP row deletion (the remove/forceRemove closeout; a normal
    /// remove's deletion funnels here after the teardown path's is_http
    /// split — idempotent at both call sites). DeleteHttpTask deletes the
    /// row by gid in one message, no mirror needed (structurally removes
    /// the old ordering defect); the paired delete clears the cookie
    /// rows (no FK on the unified table). No-op for non-HTTP
    /// tasks (independent tables).
    pub(super) async fn http_remove_row(&mut self, gid: Gid) {
        let Some(p) = self.persist.as_ref() else {
            return;
        };
        if let Err(e) = p.delete_http_task(&gid.to_string()).await {
            warn!(target: "taiji::core::session", gid = %gid, %e,
                "http task row delete failed");
        }
    }
}

/// Terminal-entry total selection: the runtime backfill value (backfilled
/// by the MagnetUpgraded notice arm via the engine query seam) wins; when
/// the backfill is 0 and the result carries upgrade metadata (the engine
/// died early = the query failed, the notice arm gave up backfilling — the
/// race window), fall back to `meta.meta.total_len()` — an upgraded task's
/// total is fully derivable offline, so the runtime query is not a
/// necessary dependency. Other result shapes (non-upgrade tasks) are
/// unaffected.
pub(super) fn ended_total_len(running_total: u64, outcome: &TaskOutcome) -> u64 {
    // HTTP tasks: the total rides the teardown payload (the
    // probe-authoritative total / what EOF actually received); the runtime
    // backfill face does not apply (no engine query seam).
    if let TaskOutcome::Http(end) = outcome {
        return end.total_len;
    }
    if running_total > 0 {
        return running_total;
    }
    match outcome {
        TaskOutcome::Magnet(MagnetEnd::Upgraded { meta, .. }) => meta.meta.total_len(),
        _ => 0,
    }
}

/// Teardown event → (result status, completed, explicit note).
pub(super) fn ended_classification(
    outcome: &TaskOutcome,
    total: u64,
) -> (StatusKind, u64, Option<String>) {
    match outcome {
        // Fetched is dispatched at handle_ended entry (the in-place upgrade
        // path); defensive completeness.
        TaskOutcome::Fetched(_) => (StatusKind::Complete, 0, None),
        // Consumers: Detached = the teardown of a completion flipping to
        // seed-only (releases the concurrency slot), a complete-state
        // result alongside SeedStopped.
        TaskOutcome::Engine(EngineEnd::Completed)
        | TaskOutcome::Engine(EngineEnd::SeedStopped)
        | TaskOutcome::Engine(EngineEnd::Detached) => (StatusKind::Complete, total, None),
        TaskOutcome::Engine(EngineEnd::Cancelled) | TaskOutcome::Cancelled => {
            (StatusKind::Removed, 0, None)
        }
        TaskOutcome::Engine(EngineEnd::Failed(msg)) => (StatusKind::Error, 0, Some(msg.clone())),
        // HTTP task teardown: note = Some means a task-level error; Done
        // (including renamePending — the terminal completion where the file
        // is only reachable with the suffix) → Complete.
        TaskOutcome::Http(end) => match &end.note {
            Some(msg) => (StatusKind::Error, 0, Some(msg.clone())),
            None => (StatusKind::Complete, end.completed_len, None),
        },
        TaskOutcome::Magnet(MagnetEnd::MetadataFetched { .. })
        | TaskOutcome::Magnet(MagnetEnd::NotFollowed { .. }) => (StatusKind::Complete, total, None),
        TaskOutcome::Magnet(MagnetEnd::Upgraded { end, .. }) => match end {
            EngineEnd::Completed | EngineEnd::SeedStopped | EngineEnd::Detached => {
                (StatusKind::Complete, total, None)
            }
            EngineEnd::Cancelled => (StatusKind::Removed, 0, None),
            EngineEnd::Failed(msg) => (StatusKind::Error, 0, Some(msg.clone())),
        },
        TaskOutcome::Magnet(MagnetEnd::Failed(msg)) => (StatusKind::Error, 0, Some(msg.clone())),
        TaskOutcome::FetchFailed(msg) => (StatusKind::Error, 0, Some(msg.clone())),
        // Media teardown: Done → Complete (bytes = the product size);
        // Failed → Error (the note carries the canonical code + the
        // redacted message); Paused/Cancelled → the pause/requeue
        // faces (retire_and_fire's flags dispatch — a pause requeues
        // as paused, a remove records Removed, a shutdown cancels).
        TaskOutcome::Media(crate::session::media::MediaEnd::Done { bytes }) => {
            (StatusKind::Complete, *bytes, None)
        }
        TaskOutcome::Media(crate::session::media::MediaEnd::Failed { code, message }) => {
            (StatusKind::Error, 0, Some(format!("{code}: {message}")))
        }
        TaskOutcome::Media(crate::session::media::MediaEnd::Paused { .. })
        | TaskOutcome::Media(crate::session::media::MediaEnd::Cancelled { .. }) => {
            (StatusKind::Removed, 0, None)
        }
        TaskOutcome::Media(crate::session::media::MediaEnd::DirectLink) => {
            // The DirectLink conversion is dispatched at handle_ended
            // entry (before this classification); defensive arm.
            (StatusKind::Removed, 0, None)
        }
        // The archive duplicate skip: Done-shaped — Complete with
        // zero downloaded bytes (nothing was fetched; the warning rode
        // the bypass and the done row already landed).
        TaskOutcome::Media(crate::session::media::MediaEnd::ArchiveHit { .. }) => {
            (StatusKind::Complete, 0, None)
        }
        // This module never passes pause-metadata through (see
        // magnet_options_from_patch); a defensive branch: the residency
        // shape records an explicit error (never faked as a resumable
        // pause).
        TaskOutcome::Magnet(MagnetEnd::UpgradedPaused { .. }) => (
            StatusKind::Error,
            0,
            Some("pause-metadata upgrade residency lands with (crash recovery seam)".into()),
        ),
    }
}

/// Global options + per-task patch → the task-final hook set (per-task
/// overrides global, fixed at add time, unchanged during activation —
/// aria2's per-download option ownership semantics).
pub(super) fn resolve_hook_set(
    global: &super::super::options::GlobalOptions,
    patch: &TaskOptionPatch,
) -> Arc<HookSet> {
    let mut set = global.hooks.clone();
    set.overlay(&patch.hooks);
    Arc::new(set)
}

/// metainfo → EngineConfig (pure CPU; runs inside spawn_blocking).
/// listen_port comes from `--listen-port` (default 6881): it was previously
/// always 0 (an OS ephemeral port), which broke port-mapping / firewall
/// scenarios. Multi-task port conflicts converge via the engine's
/// per-range fallback (engine.rs bind_listen_with_fallback, same as aria2
/// BtSetup.cc); aria2's global shared single listener converges with the
/// session-shared listener wiring (at which point the per-task independent
/// listener is withdrawn).
#[expect(
    clippy::too_many_arguments,
    reason = "per-task engine knobs are passed explicitly; a config struct is a later phase"
)]
pub(super) fn build_engine_config(
    meta: Arc<Metainfo>,
    dir: PathBuf,
    peer_id: [u8; 20],
    seed: SeedPolicy,
    dht_enabled: bool,
    listen_port: u16,
    crypto: taiji_bt::mse::CryptoPolicy,
    disk_tier: Option<String>,
    webseeding_enabled: bool,
    tracker_options: taiji_bt::tracker::TrackerOptions,
) -> Result<crate::engine::EngineConfig, crate::metainfo::MetainfoError> {
    let mut cfg = crate::engine::engine_config(
        &meta,
        dir,
        listen_port,
        peer_id,
        crate::engine::CompletionMode::Seed,
    )?;
    cfg.seed = seed;
    cfg.dht.enabled = dht_enabled;
    cfg.crypto = crypto;
    // Announce client options (interval + both timeouts) injected —
    // consumed when the engine's tracker actor spawns (defaults = aria2's
    // values, zero behavior delta).
    cfg.tracker_options = tracker_options;
    // BEP19 webseeding switch (--enable-http-seeding / the per-task option
    // key, default true): false = clear the url-list projection's webseed
    // set (a BT-only shape; the metainfo url_list original is not lost —
    // toggling is lossless). The bare CLI run (main.rs run_download)
    // overrides with the same rule.
    if !webseeding_enabled {
        cfg.webseeds.clear();
    }
    // Per-torrent disk tier override (a config_json `disk_tier` internal
    // face; None / unknown name = the throughput default tier; an unknown
    // name warns observably on the resolve side).
    cfg.disk_policy = taiji_store::disk_policy::DiskPolicy::resolve(disk_tier.as_deref());
    Ok(cfg)
}

/// .torrent byte fetch (reuses the tracker HTTP client, SPEC §8.2 addUri
/// semantics); token cancel → [`TaskOutcome::Cancelled`]. The cap is the
/// 30MiB fetch tier (decision A: a complete metainfo can legitimately
/// exceed the 4MiB announce tier; the value aligns with libtorrent
/// settings_pack.cpp's 30MiB default; the source and tier invariants live
/// at `taiji_bt::tracker::http::TORRENT_FETCH_MAX_BODY_BYTES`).
pub(super) async fn fetch_torrent_bytes(url: &str, token: &CancellationToken) -> TaskOutcome {
    let client = HttpAnnounce::new(&TrackerOptions::default());
    let fetch = async {
        match client {
            Ok(c) => match c
                .get_body_capped(url, taiji_bt::tracker::http::TORRENT_FETCH_MAX_BODY_BYTES)
                .await
            {
                Ok(bytes) => TaskOutcome::Fetched(bytes),
                Err(e) => TaskOutcome::FetchFailed(format!("metadata fetch failed: {e}")),
            },
            Err(e) => TaskOutcome::FetchFailed(format!("http client build failed: {e}")),
        }
    };
    tokio::select! {
        _ = token.cancelled() => TaskOutcome::Cancelled,
        outcome = fetch => outcome,
    }
}

pub(super) fn job_identity(job: &Job) -> TorrentIdentity {
    match job {
        Job::Torrent(tj) => tj.metainfo.meta.identity,
        Job::Magnet(mj) => TorrentIdentity {
            v1: mj.btih,
            v2: mj.btmh,
        },
        // URL metadata / HTTP tasks have no torrent identity (the HTTP
        // multi-source dedup face is out of scope — aria2 likewise does not
        // dedup HTTP downloads by content).
        Job::TorrentUrl { .. } | Job::Http(_) | Job::Media(_) => {
            TorrentIdentity { v1: None, v2: None }
        }
    }
}

/// BEP12 full tier ingestion: the metainfo announce face → the session
/// tracker table `Vec<(tier, url)>` (tiers dense 0..n, order preserved
/// within a tier; an empty table = no trackers, the pure DHT intake shape).
/// All three .torrent intake faces (addTorrent / URL fetch upgrade /
/// pause-metadata upgrade residency) share this single point; the magnet
/// `tr=` path does not (one tier per tr, carried by the magnet itself —
/// the BEP12 tier structure does not exist in a magnet URI).
fn tiers_from_metainfo(meta: &Metainfo) -> Vec<(usize, String)> {
    meta.announce_tiers
        .iter()
        .enumerate()
        .flat_map(|(tier, urls)| urls.iter().map(move |u| (tier, u.clone())))
        .collect()
}

/// Dual-identity overlap: any side non-None and equal = the same torrent
/// (a v1 sha1 or v2 sha256 hit means duplicate).
pub(super) fn identities_overlap(a: &TorrentIdentity, b: &TorrentIdentity) -> bool {
    matches!((a.v1, b.v1), (Some(x), Some(y)) if x == y)
        || matches!((a.v2, b.v2), (Some(x), Some(y)) if x == y)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::magnet::MetadataChain;
    use crate::metainfo::MetaFile;
    use taiji_bt::filetree::SwarmKind;

    /// Minimal v1 metadata model (the total_len test anchor; skips bencode
    /// parsing — this face only consumes `meta.total_len()`).
    fn upgraded_meta(total: u64) -> Arc<Metainfo> {
        Arc::new(Metainfo {
            meta: TorrentMeta {
                identity: TorrentIdentity {
                    v1: Some([0x11; 20]),
                    v2: None,
                },
                kind: SwarmKind::V1Only,
                piece_length: 16 * 1024,
                files: vec![MetaFile {
                    path: PathBuf::from("f.bin"),
                    length: total,
                    padding: false,
                    pieces_root: None,
                    piece_layer: None,
                    v1_offset: Some(0),
                }],
            },
            announce: String::new(),
            announce_tiers: Vec::new(),
            url_list: Vec::new(),
            v1_pieces: Vec::new(),
            private: false,
            name: Some("f".into()),
            multi_file: false,
            info_bytes: bytes::Bytes::new(),
        })
    }

    fn upgraded_outcome(meta: Arc<Metainfo>, end: EngineEnd) -> TaskOutcome {
        TaskOutcome::Magnet(MagnetEnd::Upgraded {
            end,
            chain: MetadataChain {
                metadata_gid: Gid::from_u64(0x8000_0000_0000_0001),
                task_gid: Gid::from_u64(0x8000_0000_0000_0001),
                metadata_uri: "magnet:?xt=urn:btih:1111111111111111111111111111111111111111".into(),
                paused: false,
            },
            meta,
            torrent: Vec::new(),
        })
    }

    /// Regression for the total backfill race: in the
    /// late-upgrade-notice race window (the engine died early →
    /// `query_status` failed → `running.total_len` stays 0), the terminal
    /// total falls back to the metadata carried by the result —
    /// `ended_classification` receives total > 0 and terminal entries no
    /// longer produce complete 0/0. Table-driven: row 1 = the race scenario
    /// (backfill 0 + Upgraded{Completed}) → the metadata total; row 2 =
    /// the backfill present → the backfill wins (zero semantic change);
    /// row 3 = backfill 0 + a non-upgrade result (Cancelled / Engine
    /// terminal) → 0 (other shapes unaffected by the fallback).
    #[test]
    fn ended_total_len_falls_back_to_upgrade_metadata() {
        let meta = upgraded_meta(12991 * 16 * 1024);

        // Row 1: the engine-died-early race window — backfill 0, metadata
        // fallback.
        let total = ended_total_len(
            0,
            &upgraded_outcome(Arc::clone(&meta), EngineEnd::Completed),
        );
        assert_eq!(
            total,
            meta.meta.total_len(),
            "the upgraded metadata backfills a missing total (terminal entries no longer report complete 0/0)"
        );
        // The fallback joined with classification: Complete + completed =
        // total.
        let (status, completed, _) = ended_classification(
            &upgraded_outcome(Arc::clone(&meta), EngineEnd::Completed),
            total,
        );
        assert_eq!(status, StatusKind::Complete);
        assert_eq!(completed, meta.meta.total_len(), "completed = total > 0");

        // Row 2: the backfill present — the backfill wins, metadata does
        // not override.
        assert_eq!(
            ended_total_len(
                777,
                &upgraded_outcome(Arc::clone(&meta), EngineEnd::Completed)
            ),
            777,
            "the runtime backfill value wins (semantics unchanged)"
        );

        // Row 3: non-upgrade result shapes unaffected by the fallback.
        assert_eq!(ended_total_len(0, &TaskOutcome::Cancelled), 0);
        assert_eq!(
            ended_total_len(0, &TaskOutcome::Engine(EngineEnd::Completed)),
            0,
            "non-upgraded Completed has no metadata to fall back on (torrent tasks source total elsewhere)"
        );
        assert_eq!(
            ended_total_len(0, &TaskOutcome::Magnet(MagnetEnd::Failed("timeout".into()))),
            0
        );
    }

    // ===== .torrent fetch tier: 30MiB =====

    /// A synthetic v1 single-file .torrent: the piece hash string dominates
    /// the size (20B per entry × `pieces` entries), pushing the metainfo
    /// past the 4MiB announce tier; structurally legal — piece_len × count
    /// = total_len and the hash string length matches the piece count
    /// exactly (the parse face has no size cap).
    fn synthetic_v1_torrent(pieces: usize) -> Vec<u8> {
        const PIECE_LEN: u64 = 16 * 1024;
        let n = pieces * 20;
        let total = pieces as u64 * PIECE_LEN;
        let mut b = Vec::with_capacity(n + 128);
        // info keys in raw byte ascending order (length < name < piece
        // length < pieces; the parse face strictly validates key order).
        b.extend_from_slice(b"d8:announce31:http://example.invalid/announce4:infod");
        b.extend_from_slice(b"6:lengthi");
        b.extend_from_slice(total.to_string().as_bytes());
        b.extend_from_slice(b"e4:name12:big-pack.bin12:piece lengthi16384e6:pieces");
        b.extend_from_slice(format!("{n}:").as_bytes());
        b.extend((0..n).map(|i| (i % 251) as u8));
        b.extend_from_slice(b"ee");
        b
    }

    /// Regression: a structurally legal ~4.6MiB .torrent — the parse face
    /// accepts it (a legal input class); under a uniform 4MiB transfer cap
    /// the fetch would deterministically FetchFailed(max-size), but via
    /// fetch_torrent_bytes's 30MiB fetch tier it round-trips byte-exact.
    #[tokio::test]
    async fn fetch_torrent_bytes_recovers_over_4mib_legal_torrent() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        // The same input class: past the 4MiB announce tier, within the
        // 30MiB fetch tier.
        let torrent = synthetic_v1_torrent(235_930);
        assert!(
            torrent.len() > taiji_bt::tracker::http::MAX_BODY_BYTES,
            "input must exceed announce tier: {}",
            torrent.len()
        );
        assert!(
            torrent.len() < taiji_bt::tracker::http::TORRENT_FETCH_MAX_BODY_BYTES,
            "input must fit fetch tier: {}",
            torrent.len()
        );
        // Input-class legality: the parse face has no size cap.
        let meta = Metainfo::parse(&torrent).unwrap_or_else(|e| panic!("parse: {e}"));
        assert_eq!(meta.meta.piece_length, 16 * 1024);
        // Loopback origin: 200 + Content-Length + the full body.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
        let served = torrent.clone();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap_or_else(|e| panic!("{e}"));
            let mut req = Vec::new();
            let mut buf = [0u8; 512];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = sock.read(&mut buf).await.unwrap_or_else(|e| panic!("{e}"));
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
            }
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                served.len()
            );
            sock.write_all(head.as_bytes())
                .await
                .unwrap_or_else(|e| panic!("{e}"));
            sock.write_all(&served)
                .await
                .unwrap_or_else(|e| panic!("{e}"));
        });
        // Assertion: the fetch succeeds byte-exact (before the fix =
        // FetchFailed(max-size)).
        let outcome = fetch_torrent_bytes(
            &format!("http://{addr}/big.torrent"),
            &CancellationToken::new(),
        )
        .await;
        match outcome {
            TaskOutcome::Fetched(bytes) => assert_eq!(bytes, torrent, "bytes must round-trip"),
            TaskOutcome::FetchFailed(m) => panic!("FetchFailed: {m}"),
            TaskOutcome::Cancelled => panic!("unexpected cancel"),
            TaskOutcome::Engine(_)
            | TaskOutcome::Magnet(_)
            | TaskOutcome::Http(_)
            | TaskOutcome::Media(_) => panic!("wrong outcome kind"),
        }
        let _ = server.await;
    }
}
