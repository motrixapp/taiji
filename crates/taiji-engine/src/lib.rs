//! `taiji-engine` — the single-torrent BT executor (`DownloadEngine`).
//!
//! Crate positioning: the execution layer under core{session};
//! dependencies point downward only — domain (the shared vocabulary
//! layer: domain models / recovery event vocabulary / method-face
//! contracts) and the bt/http/io/store companion crates. It must not
//! depend on core/rpc/cli (enforced by Cargo: a dependency cycle is a
//! compile error; the boundary is additionally swept by the
//! `boundary_sweep` test as a belt-and-braces source scan). core
//! re-exports via `pub use taiji_engine as engine`, so the existing
//! `taiji_core::engine::*` public paths are unchanged.
//!
//! DownloadEngine: the single-torrent, multi-face download loop.
//!
//! Data flow: TrackerActor announce (bt::tracker::actor, one actor per
//! swarm face; tier state machine / dual-tier fallback / stop sequence
//! cross-checked against TrackerWatcherCommand; UDP carried over the
//! UdpDemux tracker channel) + DHT (bt::dht::engine, one per family;
//! announce/PeersFound/PORT/dht_state cross-checked against DHTSetup)
//! -> connect + crypto negotiation + handshake (require-crypto ->
//! `bt::mse::connect`, otherwise plaintext `bt::peer::
//! handshake_exchange`; inbound always sniffs via
//! `bt::mse::accept_any`) -> PeerTask (bt::peer) -> PieceData
//! aggregation -> VerifiedWriter (store::verified, verify then write)
//! -> all pieces complete: stay seeding or return
//! [`EngineEnd::Completed`].
//!
//! # tracker wiring
//!
//! - One [`taiji_bt::tracker::actor::spawn_tracker_actor`] per face:
//!   the actor drives the announce cycle (started -> downloading ->
//!   completed -> stopped, the aria2 event order), tier fallback and
//!   reset, interval/min-interval, scrape; the engine only consumes
//!   events (Peers -> dial; IntervalUpdated/AnnounceFailed/
//!   ScrapeResult -> tracker table rows). The old "single URL announce
//!   per tick" face is removed; `EngineConfig::announce` degraded to
//!   the tiers default source (the call sites unchanged).
//! - Event -> row attribution: actor events carry no tier/success URL
//!   (a frozen protocol face), so the engine holds a **mirror
//!   instance** of the same frozen state machine
//!   (`bt::tracker::AnnounceList`) for attribution
//!   ([`tracker::TrackerMirror`]) — failure events carry the url,
//!   success events are IntervalUpdated (HTTP always sends; UDP with
//!   interval=0 sends none), Stop/completed are flipped by the engine's
//!   own actions/snapshot, in lockstep with the actor; attribution =
//!   the mirror's `get_announce()`, scrape attributes to the most
//!   recent successful row.
//! - Shutdown sequence (token-stop paths only): Stop -> the actor
//!   drives the stopped event sequence -> noMoreAnnounce -> Halted
//!   (`TrackerWatcherCommand.cc`); peers/store are torn down only
//!   after every face reports Halted (budget
//!   [`tracker::STOPPED_ANNOUNCE_BUDGET`], timed-out faces exit
//!   degraded). Completed/Failed paths do not drive the stopped
//!   sequence (TorrentTask takes over the RPC pause/remove semantics;
//!   the actor ends when the command channel drops at engine exit).
//!
//! # MSE/DHT/UDP wiring
//!
//! - **MSE**: inbound listener streams -> [`taiji_bt::mse::accept_any`]
//!   (first-byte sniffing splits legacy/MSE,
//!   `ReceiverMSEHandshakeCommand.cc`; require-crypto rejects legacy);
//!   outbound follows [`taiji_bt::mse::CryptoPolicy`] three ways (see
//!   `transit::outbound_crypto_shape`) — require-crypto MUST MSE
//!   (`bt::mse::connect`, no silent plaintext fallback);
//!   min-crypto-level=arc4 is MSE-first with a fresh-connection legacy
//!   fallback (`InitiatorMSEHandshakeCommand.cc`); the default plain
//!   dials a legacy handshake directly. Announce crypto parameter bits
//!   via `mse::announce_crypto_param` (`DefaultBtAnnounce.cc`).
//! - **UDP**: [`taiji_io::udp_demux::spawn`] both families (v4 main;
//!   v6 best-effort bind) takes over the listen-port UDP face on a
//!   shared socket — DHT consumes the dht channel, the tracker actor's
//!   router/dispatcher tasks carry the tracker channel; the µTP
//!   channel -> the `io::utp` listener (accept merged into the main
//!   loop on the same path as TCP inbound; outbound dials follow the
//!   `--bt-peer-connection-type` four-state plan).
//! - **DHT** (`EngineConfig::dht`; the default constructor is disabled
//!   — existing tests unchanged. Production injection: the CLI download
//!   mode `--enable-dht` (default true) or the idle-mode session option
//!   `enable_dht`): one `spawn_dht_engine` per family; the restored
//!   state = `dht_state` rows ([`load_dht_restore_state`]); bootstrap =
//!   `--dht-entry-point[-6]` + the router fallback (v4); TorrentTask
//!   announce via `DhtHandle::announce` (target = sha1 | truncated
//!   sha256, private torrents BEP27 disabled); `PeersFound` -> dedup
//!   then dial; PORT after the handshake (the peer reserved DHT bit &&
//!   local enabled) + on receiving PORT -> `AddPortNode`
//!   (BtPortMessage.cc); `Persist` -> UpsertDhtState (autosave 30min +
//!   halt-save).
//!
//! # swarm faces (BEP52 "Upgrade Path")
//!
//! BEP52: "Implementations supporting both formats can join both
//! swarms by calculating the new and old infohashes" (dual swarm in
//! parallel); "When initiating a connection and sending the sha1
//! infohash of such a hybrid torrent a peer can set the 4th most
//! significant bit in the last byte of the reserved bitfield"
//! (reserved[7] & 0x10). The shapes:
//!
//! - **v1-only**: a single v1 face (Flat addressing);
//! - **v2-only**: a single v2 face
//!   ([`taiji_bt::piece_id::Addressing::PerFile`], wire index =
//!   file-aligned base + in-piece offset, the BEP52 `piece length`
//!   section; the on-disk layout is compact with file-boundary gaps
//!   between pieces -> each piece's disk offset is precomputed by
//!   `Layout::v2_piece_offset`);
//! - **hybrid**: two faces in parallel — v1 (the v1 sha1 identity) +
//!   v2 (the truncated sha256 identity). The BEP52 alignment makes the
//!   **v1 piece index and the v2 wire index identical** (pad only
//!   fills the real last-piece remainder, never a whole piece), so both
//!   faces share one piece space: independent verification (v1 =
//!   whole-piece SHA-1 including the pad zeros; v2 = content-prefix
//!   merkle recompute of the piece root), independent persistence (the
//!   same bytes write the same file ranges; pad is never written),
//!   completion propagated across faces (one face verifying piece k
//!   marks it complete on the other, avoiding duplicate downloads).
//!   BEP52: "they must also verify that pieces match both piece hash
//!   formats" — both faces attach a
//!   [`taiji_store::verified::CrossRule`] dual check; a mismatch =
//!   metadata contradiction -> torrent-level failure (BEP52 allows
//!   "abort or fall back"; this implementation aborts).
//!
//! # seeding operation
//!
//! - **Stop conditions** (`taiji_domain::seed`): seed-ratio
//!   (ShareRatioSeedCriteria), seed-time (TimeSeedCriteria, timed from
//!   the download-complete moment); either stops seeding (Union);
//!   assembly cross-checked against BtSetup.cc. A satisfied criterion
//!   ends seeding and returns [`EngineEnd::SeedStopped`].
//! - **bt-stop-timeout** (BtStopDownloadCommand): a 1s tick (the
//!   dedicated [`seed_ticker`] cadence); a download speed > 0 (the
//!   SpeedCalc 10s sliding window) resets the checkpoint, on timeout
//!   the engine force-stops (`EngineEnd::Failed` with the
//!   `--bt-stop-timeout` message); download period only.
//! - **Counter persistence**: session up/down = PeerConfig-injected
//!   counters (piece-payload scope, counted at BtPieceMessage.cc),
//!   autosaved via `UpsertTorrentProgress` (60s, the
//!   --auto-save-interval default) + final values at teardown; the
//!   `upload_at_startup` base is read back at engine start via
//!   `LoadTorrentProgress` (the .aria2 control-file uploadLength
//!   semantics).
//! - **bt-detach-seed-only**: the complete-to-seed-only decision
//!   (RequestGroup.cc) + distinct return paths (Detached vs
//!   SeedStopped).
//!
//! # scope (honesty)
//!
//! - TorrentTask/SessionActor RPC integration lives outside this
//!   crate; this module is the bare CLI shape.
//! - hash exchange **requester**: the v2 face lazily fetches the base
//!   layer covering a file before requesting its blocks (the
//!   [`taiji_domain::hash_fetch`] planner, a length<=512 cap), verifies
//!   the response up to the piece root into the HashTreeCache; the
//!   store pipeline compares leaf hashes per block directly (a failure
//!   refetches only that 16KiB). Exhausted lazy retries -> a
//!   whole-piece buffering fallback (an explicit warn, not a silent
//!   default). The responder side (hash request replies) is delivered.
//! - Inbound connections are served already-written pieces before full
//!   completion (unwritten pieces are rejected — the gate checks the
//!   written bits; hash-pass advertising and serving stay distinct).
//! - Choking: completed faces use the seeder path, unchoking
//!   interested peers; the download face uses the leecher path:
//!   LeecherChoke decides every 10s round (3 regular slots + a planned
//!   optimistic rotation), tit-for-tat upload served via
//!   PartialFaceSource.
//! - Client-identity bans: identity rules are judged on
//!   session-activated engines (download/seed) at handshake completion
//!   (`ban::client_violation`, outbound TCP/µTP + inbound TCP/µTP, four
//!   points); re-judged once when the ext handshake `v` field arrives
//!   (`ban::client_v_deny_check` injected into PeerTask; a hit is a
//!   `ClientBanned` violation disconnect — both dimensions share the
//!   same persistence/disconnect face). Known gaps (stated honestly):
//!   magnet metadata-phase direct dials (taiji_core::magnet's
//!   dial_metadata_peer — assembled core-side, with no ledger/snapshot
//!   wiring across crates); and the bare CLI shape (no session) has no
//!   ban-list feed point, so the empty-list semantics (ban no clients)
//!   holds naturally.
//!
//! Concurrency discipline: the main loop does zero disk IO / zero
//! hashing — each face has its own store pipeline task with blocking
//! work inside its `spawn_blocking`; progress returns to the main loop
//! over bounded channels.

/// Engine command-face errors (owned by the engine subtree: the engine
/// never references the session namespace back; the session side
/// converts variant by variant via `From<EngineError> for
/// SessionError`, so error copy and match classification stay in sync).
mod error;
/// Metrics counting implementation (the session::metrics module
/// re-exports pointing back here — the engine never references the
/// session namespace; the feed-point table is in the module docs).
pub mod metrics;
/// Engine recovery face (engine -> session recovery event relay
/// payloads + recovered-layer persistence row assembly — types and pure
/// functions belong to the shared vocabulary layer
/// taiji-domain::recovery; both producer and consumer reach them via
/// this re-export; the session side's events/persist re-exports keep
/// the existing public paths).
pub use taiji_domain::recovery;

/// Block-data bypass master switch: `BH_BLOCK_BYPASS`, default `1` =
/// the direct path (peer read loop -> face-level sink feeding the
/// pipeline directly, eliminating the attach forward-task hop);
/// `0`/`off`/`false` = the old path (`data_tx` -> the attach forward
/// task). Read at assembly (the `FaceState::block_sink_for` factory,
/// evaluated when outbound DialJobs / inbound accepts are built),
/// OnceLock parsed once per process — **env vars are never read on the
/// block hot path**; a `None` sink makes the bt side fall back to the
/// old path automatically. Same pattern as the `BH_VERIFY_WORKERS`
/// seam. Parse registry: `taiji_io::knobs` (process-level OnceLock).
pub(crate) fn block_bypass_enabled() -> bool {
    taiji_io::knobs::block_bypass_enabled()
}

/// Return-path batching switch: `BH_BLOCK_BATCH_ACK`, defaults to the
/// master switch [`block_bypass_enabled`]; an explicit
/// `0`/`off`/`false` turns off only the batching, keeping the direct
/// path, with acknowledgements back to per-block `BlockSettled` — an
/// independent fallback granularity for the two orthogonal hops (the
/// middle state for "direct path stable, batching timing in question").
pub(crate) fn block_batch_ack_enabled() -> bool {
    taiji_io::knobs::block_batch_ack_enabled()
}

/// Lean-swarm three-face telemetry switch: `BH_LEAN_TELEMETRY`, default
/// off = zero logs, zero behaviour (telemetry only observes; see the 1s
/// per-peer snapshot row in `run::tick::handle_seed_tick`). on = one
/// per-face per-peer snapshot row per 1s tick — supply depth (the BDP
/// target window / in-flight / 30s window rate, the lock-free
/// RequestBook mirror), reciprocity level (whether the peer chokes us —
/// unchoke/choke edges differenced per cuid), transport mix (per-peer
/// transport kind + face-level TCP/µTP cumulative supply bytes,
/// [`faces::face_transport_supply`]). OnceLock parsed once per process
/// — never read on the hot path (the [`block_bypass_enabled`]
/// pattern). Parse registry: `taiji_io::knobs` (process-level
/// OnceLock).
pub(crate) fn lean_telemetry_enabled() -> bool {
    taiji_io::knobs::lean_telemetry_enabled()
}

/// Discovery-source address hygiene: the single-point v4-mapped
/// normalization + bogon filter; reused by every discovery-source entry
/// (the classification list and RFC/libtorrent cross-references are in
/// the module docs).
pub mod addr_hygiene;
mod ban;
/// Piece bitmap (bit-compressed rows): the shared structure of the
/// peer_avail advertisement rows and the written_bits gate bitmap.
mod bitmap;
/// Capability discovery (taiji.getCapabilities): the declarative view
/// of the engine's policy/feature registry (a single source of truth;
/// the session actor assembles, RPC renders the schema JSON).
pub mod capabilities;
mod choke;
mod command;
mod config;
mod dht;
mod dispatch;
mod faces;
mod pipeline;
mod progress;
mod query;
mod redial;
mod run;
mod strategy;
mod superseed;
mod tracker;
mod transit;
mod upload;
mod verify_pool;
/// BEP19 webseeding engine face: pseudo-peer duplex wire responder +
/// piece prefetch cache (assembly orchestration in
/// `run::dial::attach_webseeds` — EngineLoop/DialCtx belong to the run
/// tree).
mod webseed;

/// Lock-poisoning policy (batch-wide decision): a poisoned `std::sync::Mutex`
/// means a panic happened mid-critical-section and an invariant may be lost —
/// recovery via `into_inner` is not permitted. The `expect` is fatal by
/// policy: the process teardown is carried to its terminal state by the
/// existing panic-watcher, so failing loudly here is the intended behavior.
///
/// All non-test lock acquisitions in this crate must go through this helper.
#[expect(
    clippy::expect_used,
    reason = "lock poisoning is fatal by policy; terminal state handled by the panic-watcher"
)]
pub(crate) fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock()
        .expect("lock poisoned: invariant lost, fail loudly")
}

/// RwLock read side of the same poison policy (see [`lock`]).
#[expect(
    clippy::expect_used,
    reason = "lock poisoning is fatal by policy; terminal state handled by the panic-watcher"
)]
pub(crate) fn lock_read<T>(m: &std::sync::RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    m.read()
        .expect("lock poisoned: invariant lost, fail loudly")
}

/// RwLock write side of the same poison policy (see [`lock`]).
#[expect(
    clippy::expect_used,
    reason = "lock poisoning is fatal by policy; terminal state handled by the panic-watcher"
)]
pub(crate) fn lock_write<T>(m: &std::sync::RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    m.write()
        .expect("lock poisoned: invariant lost, fail loudly")
}

/// Connection leave reason: the crate-level re-export of
/// `transit::LeaveKind` — the session metrics face
/// (`SessionMetrics::note_peer_leave`) and the engine arms share the
/// same closed five-variant set; the /metrics rendering label contract
/// is in the session::MetricsSnapshot field docs.
pub(crate) use transit::LeaveKind;

#[cfg(test)]
#[rustfmt::skip]
mod tests;
#[cfg(test)]
/// Behaviour tests for the metainfo -> EngineConfig assembly face
/// (moved up alongside the assembly function from the domain module's
/// inline tests; the test bodies are kept verbatim).
mod config_tests;
#[cfg(test)]
mod recovery_tests;

// ---- Public facade (every existing `taiji_core::engine::*` path
// resolves) ----
pub use command::{EngineCommand, EngineHandle};
// The engine command error type (returned by the EngineHandle methods;
// the session side converts via From).
pub use error::EngineError;
// PeerConnectionType option-value strings (the transit observability
// label and the session option echo share one literal table —
// re-exported on the session options side; a second match is
// forbidden).
pub use config::{
    CompletionMode, DhtWireConfig, EngineConfig, FaceConfig, FaceKind, PresetProgress,
    TrackerWireConfig, WriterFactory, engine_config,
};
pub use dht::load_dht_restore_state;
pub use progress::{EngineEnd, Progress};
pub use query::{EnginePeerSnapshot, EngineStatusSnapshot};
pub use run::DownloadEngine;
pub use transit::peer_connection_type_str;
// Scheduling policy configuration face (the session mirror + RPC
// params/receipts + the config_json payload).
pub use strategy::SchedulerPolicy;
// disk_tier RPC face: tier configuration (RPC set validation/receipts)
// and live readings (QueryDiskPolicy receipts), re-exported across
// crates (rpc depends only on core).
pub use capabilities::{CapabilitiesView, FeatureCapability, FeatureToggles};
pub use taiji_store::disk_policy::{DiskTier, LivePolicy};

/// Engine boundary governance sweep. Three invariants:
///
/// 1. The engine subtree (doc comments and test code included) must
///    not contain crate paths pointing at session — the engine never
///    referencing the session namespace back is the hard prerequisite
///    of the crate split; a regression breaks the split's feasibility.
/// 2. The engine's companion-crate coupling is capped by the
///    COMPANION_WHITELIST registry: a `taiji_*` reference outside the
///    list would be a reference back to core/rpc/cli, which is already
///    a Cargo-level dependency-cycle error (the compiler owns
///    cross-crate boundaries after the split); the source scan keeps
///    the registry honest as belt-and-braces — violations turn red in
///    `cargo test -p taiji-engine`.
/// 3. This crate's manifest must not declare a dependency on
///    taiji-core — the compile-level boundary pinned explicitly at the
///    manifest layer (a dependency-table regression surfaces before
///    compilation).
///
/// Scan scope: source text + assertions (the same convention as the
/// taiji-core lib.rs allow_lint_sweep); the scanned face = every .rs
/// under this crate's `src`. Invariant 1 matches the full text (docs
/// and tests alike); invariant 2 counts only compile-time dependency
/// edges — whole-line comments (`//`, incl. `///`/`//!`) are skipped
/// and inline trailing comments are not split (conservative:
/// over-report, never miss). Grouped use forms (a brace right after
/// the path prefix) are invisible to substring matching, so a
/// brace-balanced full-text scan runs as well (segments may span
/// lines). Known gaps (recorded, not closed): aliased path shapes and
/// `super::` relative shapes are outside the spec. This module is
/// inside its own scan face: needles are assembled via concat! and the
/// comment wording avoids the forbidden literals/prefixes, so
/// self-scanning never false-reds.
#[cfg(test)]
mod boundary_sweep {
    /// Companion crates the engine may couple to (the capped registry).
    /// New coupling = an explicit decision editing this list (the
    /// registration is the record). The order is the dependency
    /// direction (see the root Cargo.toml layering comment): domain is
    /// the shared vocabulary layer, bt/http/io/store are execution
    /// companion crates; `segment` registered 2026-10-30:
    /// the segment vocabulary crate — the verbatim lift of the three
    /// segmentation traits out of taiji-http; webseed.rs consumes
    /// `taiji_segment::traits::RequestCtx` directly per the
    /// named redirection in the protocol-extension map (a bottom
    /// vocabulary layer in
    /// the domain direction, not an upper crate — the first name
    /// outside the list would still be taiji_core — the engine must
    /// not reference the orchestration layer.
    const COMPANION_WHITELIST: &[&str] = &["domain", "bt", "http", "io", "store", "segment"];

    /// Scanned-file count floor: below this the crate layout drifted
    /// and the scan face is wrong (a no-op walk makes the assertion
    /// vacuously true) — fix the paths before governing.
    const MIN_SCANNED_FILES: usize = 30;

    /// Invariant 1 match substring (not whole-word, full text):
    /// assembled via concat! to avoid self-matching this file.
    const NEEDLE_SESSION: &str = concat!("crate", "::", "session");

    /// Grouped-use prefix (the grouped-form match anchor of invariant
    /// 1).
    const NEEDLE_GROUP: &str = concat!("crate", "::", "{");

    /// Invariant 3 match substring (whole manifest): concat! guards
    /// against source self-matching.
    const NEEDLE_CORE_MANIFEST: &str = concat!("taiji", "-", "core");

    /// Companion-crate prefix for diagnostics (assembled to dodge the
    /// self-scan anchor).
    const TAIJI_PREFIX: &str = "taiji_";

    /// Grouped-segment decision word: a lowercase identifier inside a
    /// segment equal to this means the segment points at session.
    const SESSION_WORD: &str = "session";

    /// Invariant 1: the engine subtree's full text (docs and tests
    /// alike) must not contain a session-pointing path substring; the
    /// grouped use form is covered by the grouped-segment scan.
    #[test]
    fn no_session_path_in_engine_subtree() {
        let sources = engine_sources();
        let mut offenders: Vec<String> = Vec::new();
        for (rel, text) in &sources {
            for (i, line) in text.lines().enumerate() {
                if line.contains(NEEDLE_SESSION) {
                    offenders.push(format!("{rel}:{}", i + 1));
                }
            }
            for (line, words) in grouped_use_segments(text) {
                if words.iter().any(|w| w == SESSION_WORD) {
                    offenders.push(format!("{rel}:{line} (grouped use form)"));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "session-pointing path references found in the engine subtree ({} \
             occurrences) — the engine must not reference back into the \
             session namespace (hard prerequisite of the crate split, \
             retrospective semantics):\n{}",
            offenders.len(),
            offenders.join("\n")
        );
    }

    /// Invariant 2: non-comment companion-crate references must fall
    /// within COMPANION_WHITELIST. Referencing an upper crate
    /// (core/rpc/cli) is a dependency-cycle error at compile time; this
    /// assertion makes the list a test-protected registry rather than a
    /// comment.
    #[test]
    fn companion_couplings_within_whitelist() {
        let sources = engine_sources();
        let mut offenders: Vec<String> = Vec::new();
        for (rel, text) in &sources {
            for (i, line) in text.lines().enumerate() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                for id in companion_crate_idents(line) {
                    if !COMPANION_WHITELIST.contains(&id.as_str()) {
                        offenders.push(format!("{rel}:{} {}{id}", i + 1, TAIJI_PREFIX));
                    }
                }
            }
            for (line, words) in grouped_use_segments(text) {
                for w in &words {
                    let Some(suffix) = w.strip_prefix(TAIJI_PREFIX) else {
                        continue;
                    };
                    if !COMPANION_WHITELIST.contains(&suffix) {
                        offenders.push(format!(
                            "{rel}:{line} {}{w} (grouped use form)",
                            TAIJI_PREFIX
                        ));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "companion-crate references outside the whitelist found in the \
             engine ({} occurrences) — a new coupling = an explicit decision \
             to amend COMPANION_WHITELIST (each entry requires a rationale; \
             an upper crate referencing back is a dependency cycle at the \
             Cargo layer and must not be registered):\n{}",
            offenders.len(),
            offenders.join("\n")
        );
    }

    /// Invariant 3: the manifest dependency table must not declare
    /// taiji-core. The compile-level boundary (dependency cycle =
    /// compile error) pinned explicitly at the manifest text layer — a
    /// regression turns red here before compilation.
    #[test]
    fn core_absent_from_engine_manifest() {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let text = match std::fs::read_to_string(&manifest) {
            Ok(t) => t,
            Err(e) => panic!("failed to read manifest {}: {e}", manifest.display()),
        };
        assert!(
            !text.contains(NEEDLE_CORE_MANIFEST),
            "dependency declaration on {} found in the engine manifest — the \
             engine must not depend on the orchestration layer \
             (crate layering: core -> engine; the reverse is a dependency \
             cycle)",
            NEEDLE_CORE_MANIFEST
        );
    }

    /// Collect (relative src/ path, full text) of every .rs in this
    /// crate's `src`, sorted for deterministic diagnostics; the floor
    /// gate (see MIN_SCANNED_FILES).
    fn engine_sources() -> Vec<(String, String)> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut out: Vec<(String, String)> = Vec::new();
        walk_rs(&root, &root, &mut out);
        out.sort();
        let scanned = out.len();
        assert!(
            scanned >= MIN_SCANNED_FILES,
            "scan surface distorted: only {scanned} .rs files in the engine \
             subtree (floor {MIN_SCANNED_FILES}); has the directory layout drifted?"
        );
        out
    }

    /// Recursively collect .rs texts (relative paths for path:line
    /// diagnostics).
    fn walk_rs(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<(String, String)>) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => panic!("failed to read directory {}: {e}", dir.display()),
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk_rs(root, &path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = match std::fs::read_to_string(&path) {
                    Ok(t) => t,
                    Err(e) => panic!("failed to read file {}: {e}", path.display()),
                };
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .display()
                    .to_string();
                out.push((rel, text));
            }
        }
    }

    /// Extract inline companion-crate reference names (taiji_-prefixed
    /// identifiers). The function name avoids that prefix's lowercase
    /// form — this file is inside the scan face; a self-match would be
    /// a false red.
    fn companion_crate_idents(line: &str) -> Vec<String> {
        let mut idents: Vec<String> = Vec::new();
        let mut from = 0usize;
        while let Some(pos) = line[from..].find(TAIJI_PREFIX) {
            let rest = &line[from + pos + TAIJI_PREFIX.len()..];
            let id: String = rest
                .chars()
                .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_')
                .collect();
            if !id.is_empty() {
                idents.push(id);
            }
            from += pos + TAIJI_PREFIX.len();
        }
        idents
    }

    /// Grouped-use segment walk: scan the full text for each grouped
    /// prefix anchor, take the segment with brace balancing (supports
    /// nested `a::{b}`, segments may span lines), and produce (line,
    /// lowercase identifier set). Callers decide: invariant 1 only
    /// checks whether the segment contains the session decision word;
    /// invariant 2 checks the companion-list membership of
    /// taiji_-prefixed words.
    fn grouped_use_segments(text: &str) -> Vec<(usize, Vec<String>)> {
        let bytes = text.as_bytes();
        let mut segs: Vec<(usize, Vec<String>)> = Vec::new();
        let mut from = 0usize;
        while let Some(pos) = text[from..].find(NEEDLE_GROUP) {
            let seg_start = from + pos + NEEDLE_GROUP.len();
            let mut depth = 1usize;
            let mut i = seg_start;
            while i < bytes.len() && depth > 0 {
                match bytes[i] {
                    b'{' => depth += 1,
                    b'}' => depth -= 1,
                    _ => {}
                }
                i += 1;
            }
            let seg = &text[seg_start..i.saturating_sub(1)];
            let words: Vec<String> = seg
                .split(|c: char| !c.is_ascii_lowercase() && c != '_')
                .filter(|w| !w.is_empty())
                .map(str::to_string)
                .collect();
            let line = text[..seg_start].matches('\n').count() + 1;
            segs.push((line, words));
            from = i;
        }
        segs
    }
}
