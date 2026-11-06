//! Peer-ban bookkeeping and failure-attribution take-out: `BanBook`
//! (IpGuard snapshot hot-update + persistence + same-IP disconnection),
//! `disconnect_ip`/`violation_of`, and block-sender/dispatch-target
//! bookkeeping take-outs (`take_block_sender(s)`/
//! `take_piece_dispatch_targets`). Also `set_ban_config` (session-pushed
//! manual ban ranges + client identity rules), `client_violation`
//! (handshake-time identity judgment), and `disconnect_ranges` (range
//! disconnection).
//!
//! Scope: the ban-enforcement surface and the bookkeeping consumption of
//! failure attribution. IpGuard snapshot internals live in
//! taiji_domain::peer_guard.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use tracing::{debug, info, warn};

use taiji_bt::peer::{PeerEnd, PeerHandle as _};
use taiji_bt::peer_policy::{FilterRule, IpGuardHandle, Violation};
use taiji_store::persist::PersistOutcome;

use crate::metrics::SessionMetrics;
use taiji_domain::peer_guard::{
    BanLedger, HashFailureDecision, ManualBanRule, REASON_CLIENT_BAN_PREFIX, refresh_guard_full,
};

use crate::faces::FaceState;
use crate::tracker::{TrackerPersistShared, epoch_secs};
/// Violation event channel capacity (Violation mpsc(64) -> core
/// bookkeeping; violations are low-frequency, and a full channel applies
/// backpressure on the attach forwarder — never dropped, a dropped event
/// = a missed ban).
pub(super) const VIOLATION_CHANNEL_CAPACITY: usize = 64;

/// smart_ban master switch env (`BH_SMART_BAN=0` turns the whole surface
/// off; default/any other value = on — the evidence-based ban surface can
/// exit independently; the fallback does not touch the sliding-window
/// semantics).
pub(super) const SMART_BAN_SWITCH_ENV: &str = "BH_SMART_BAN";
/// Independent switch env for the parole gate (`BH_SMART_BAN_PAROLE=0`
/// disables only the dispatch-suspicion gate — evidence registration,
/// trust, and contradiction bans are unaffected).
pub(super) const SMART_BAN_PAROLE_SWITCH_ENV: &str = "BH_SMART_BAN_PAROLE";
/// smart_ban ban reason prefix (peer_ban.reason column; distinguishable
/// from the sliding-window reason `REASON_HASH_FAILURES` — observation
/// splits the two defenses' activity by prefix).
pub(super) const SMART_BAN_REASON_PREFIX: &str = "smart-ban:";

/// trust_points penalty per hash failure (libtorrent `torrent.cpp`
/// parole chain verbatim: on hash fail the downloader's trust_points
/// -2).
pub(super) const SMART_BAN_TRUST_FAIL_PENALTY: i32 = 2;
/// trust_points reward per piece pass (same upstream surface: +1 on
/// pass; asymmetric penalty/reward).
pub(super) const SMART_BAN_TRUST_PASS_REWARD: i32 = 1;
/// trust_points ban threshold (<= -7 bans; the upstream "trust <= -7
/// bans directly"). Reward capping at 0 is a local policy (upstream has
/// no positive-accumulation cap — locally positive credit does not
/// accumulate, preventing a peer from farming good-piece credit to buy
/// bad-piece allowance; the point of asymmetric penalty/reward is that
/// bad evidence is only diluted over time by good evidence, never
/// offset).
pub(super) const SMART_BAN_TRUST_BAN_THRESHOLD: i32 = 7;

/// Failed-piece per-block evidence capacity bound (in blocks; a local
/// policy — memory bound = this x (8B key + 20B digest + 8B cuid) ~
/// 300KiB, guarding the evidence table against unbounded growth under a
/// never-converging piece that keeps getting refetched. When full, new
/// evidence is NOT recorded (conservative: no new evidence, existing
/// evidence still consumed) — libtorrent has no such bound (its block
/// hash table is reclaimed with the piece's lifetime; locally a failed
/// piece may never converge, so a bound must be self-imposed).
pub(super) const SMART_BAN_FAILED_BLOCK_CAP: usize = 4096;
/// trust accounting IP capacity bound (a local policy; neutral/positive
/// entries are reclaimed by [`BanBook::sweep`] on the 1h cadence, keeping
/// only negative IPs — adversarial IP counts are naturally bounded; when
/// full, new IPs do not enter the books (conservative: no trust
/// accounting, the existing ban surface unaffected)).
pub(super) const SMART_BAN_TRUST_MAP_CAP: usize = 4096;

/// Env switch reading (`=0` off, default/anything else = on; the same
/// pattern as `BH_VERIFY_WORKERS` — a process-level seam, read once and
/// living with the ledger).
fn switch_on(env: &str) -> bool {
    match std::env::var(env) {
        Ok(s) => s.trim() != "0",
        Err(_) => true,
    }
}

/// smart_ban ledger (a pure structure; owned by the main loop, no shared
/// locks — evidence converges on the main loop via `PieceDropped`/
/// `PieceVerified` events and is processed in order; time is supplied by
/// callers — the structure itself makes no timing decisions).
///
/// # Evidence self-certification (after libtorrent `smart_ban.cpp`)
///
/// The classic v1 problem "many peers co-write one piece; a hash failure
/// cannot be attributed": the only attribution surface of a failed piece
/// is piece-level aggregation. smart_ban's answer is to let evidence
/// certify itself:
///
/// 1. On piece failure, record per-block `{block -> (peer, digest)}`
/// (locally the verify worker produces per-block SHA-1 before the
/// job's cell is destroyed — [`taiji_store::verified::
/// PieceJob::failed_block_digests`]; the upstream reference reads back
/// from disk — an intentional divergence: upstream persists data
/// first so it reads disk, while here verification precedes writing
/// and failed-piece data lives only in the in-memory cell; the
/// evidence is equivalent with one less disk IO);
/// 2. The same peer giving two different digests for the same block
/// (each failure records its own) => at least one is bad — ban +
/// disconnect immediately (`smart_ban.cpp`);
/// 3. When the piece later passes, compare per block — a peer whose
/// recorded digest mismatches the good data is the bad-data source;
/// ban + disconnect.
///
/// Division of labor with the sliding-window ban (coexisting, not
/// alternatives): the window treats repeated failure (a count dimension,
/// unable to pin block or source); trust/contradiction self-certification
/// treats single severe events (an evidence dimension, pinning block and
/// source). Gate: `BH_SMART_BAN=0` disables the whole surface.
pub(super) struct SmartBanLedger {
    enabled: bool,
    parole_enabled: bool,
    /// trust_points (IP-keyed — the same key surface as [`BanLedger`]'s
    /// bans, not reset on reconnect; asymmetric penalty/reward, see the
    /// module docs).
    trust: HashMap<IpAddr, i32>,
    /// Failed-piece per-block evidence: (piece, begin) -> [(cuid,
    /// digest)]. Multiple peers on one block each keep an entry (the
    /// attribution input for the co-written-piece scenario); the same
    /// peer repeating the same digest on the same block is not
    /// re-recorded (a deterministic corruption replay is not contradiction
    /// evidence).
    failed: FailedBlockMap,
    /// Occupancy count against [`SMART_BAN_FAILED_BLOCK_CAP`].
    stored_blocks: usize,
}

impl std::fmt::Debug for SmartBanLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmartBanLedger")
            .field("enabled", &self.enabled)
            .field("parole_enabled", &self.parole_enabled)
            .field("trust", &self.trust.len())
            .field("failed_blocks", &self.stored_blocks)
            .finish()
    }
}

/// A failed-piece evidence entry (begin, delivering cuid, the block's
/// SHA-1).
pub(super) type FailedBlockEntry = (u32, u64, [u8; 20]);
/// Failed-piece evidence table type ((piece, begin) -> [(cuid, digest)];
/// a readability alias).
type FailedBlockMap = HashMap<(u64, u32), Vec<(u64, [u8; 20])>>;

impl SmartBanLedger {
    /// Reads the process-level switches
    /// ([`SMART_BAN_SWITCH_ENV`] / [`SMART_BAN_PAROLE_SWITCH_ENV`]).
    pub(super) fn from_env() -> SmartBanLedger {
        SmartBanLedger {
            enabled: switch_on(SMART_BAN_SWITCH_ENV),
            parole_enabled: switch_on(SMART_BAN_PAROLE_SWITCH_ENV),
            trust: HashMap::new(),
            failed: HashMap::new(),
            stored_blocks: 0,
        }
    }

    pub(super) fn enabled(&self) -> bool {
        self.enabled
    }

    pub(super) fn parole_enabled(&self) -> bool {
        self.enabled && self.parole_enabled
    }

    /// Whether the piece has any recorded failure evidence (a zero-cost
    /// precondition for the pass-arm read-back comparison).
    pub(super) fn has_failed_records(&self, piece: u64) -> bool {
        self.failed.keys().any(|&(p, _)| p == piece)
    }

    /// Piece failure: record evidence + same-peer-same-block contradiction
    /// decision (two different digests => at least one bad, immediate ban
    /// — the `smart_ban.cpp` semantics). Returns contradiction ban
    /// candidate cuids (deduplicated). When full, new evidence is not
    /// recorded (existing evidence still decided).
    pub(super) fn note_piece_failed(
        &mut self,
        piece: u64,
        entries: &[FailedBlockEntry],
    ) -> Vec<u64> {
        let mut contradictions: Vec<u64> = Vec::new();
        for &(begin, cuid, digest) in entries {
            let slot = self.failed.entry((piece, begin)).or_default();
            // Contradiction check: the same peer already has a different
            // digest on record for this block.
            if slot.iter().any(|(c, d)| *c == cuid && *d != digest)
                && !contradictions.contains(&cuid)
            {
                contradictions.push(cuid);
            }
            // Deduplicated recording (same peer + same digest is
            // idempotent; the capacity gate only blocks new evidence).
            let room = self.stored_blocks < SMART_BAN_FAILED_BLOCK_CAP;
            if room && !slot.iter().any(|(c, d)| *c == cuid && *d == digest) {
                slot.push((cuid, digest));
                self.stored_blocks += 1;
            }
        }
        // Reclaim empty slots (a recording attempt while full can leave an
        // empty entry — `has_failed_records` keys on key existence, so an
        // empty slot would cause a false read-back trigger).
        self.failed.retain(|_, slot| !slot.is_empty());
        contradictions
    }

    /// Piece pass: per-block comparison of recorded failure evidence
    /// against the good-data digests (index = in-piece block order).
    /// Returns bad-data sources (cuid, begin) — those whose digest
    /// mismatches the good data (the bytes they delivered in the failed
    /// cycle differ from the bytes that finally passed verification: the
    /// bad-block source).
    pub(super) fn pass_compare(&self, piece: u64, good: &[[u8; 20]]) -> Vec<(u64, u32)> {
        let mut out = Vec::new();
        for (&(p, begin), slot) in &self.failed {
            if p != piece {
                continue;
            }
            let idx = (begin / taiji_store::merkle::BLOCK_SIZE) as usize;
            let Some(&good_digest) = good.get(idx) else {
                continue;
            };
            for &(cuid, digest) in slot {
                if digest != good_digest {
                    out.push((cuid, begin));
                }
            }
        }
        out
    }

    /// Clear all recorded evidence for the piece (a piece's evidence
    /// lifecycle ends when it settles; the failed-read-back path also
    /// clears — conservatively producing no evidence, preventing stale
    /// evidence drifting across piece cycles into a wrong ban).
    pub(super) fn clear_piece(&mut self, piece: u64) {
        self.failed.retain(|&(p, _), slot| {
            if p == piece {
                self.stored_blocks -= slot.len();
                false
            } else {
                true
            }
        });
    }

    /// trust penalty (hash failure): returns true = crossed the ban
    /// threshold (<= -7).
    pub(super) fn trust_penalize(&mut self, ip: IpAddr) -> bool {
        // Capacity gate: when full, reclaim neutral/positive entries
        // first; if still full (all negative), a new IP does not enter the
        // books (conservative: no trust accounting = no new bans, the
        // existing surface unaffected).
        if !self.trust.contains_key(&ip) && self.trust.len() >= SMART_BAN_TRUST_MAP_CAP {
            self.prune_neutral();
            if self.trust.len() >= SMART_BAN_TRUST_MAP_CAP {
                return false;
            }
        }
        let e = self.trust.entry(ip).or_insert(0);
        *e -= SMART_BAN_TRUST_FAIL_PENALTY;
        *e <= -SMART_BAN_TRUST_BAN_THRESHOLD
    }

    /// trust reward (piece pass; capped at 0 — positive credit does not
    /// accumulate, see the constant note).
    pub(super) fn trust_reward(&mut self, ip: IpAddr) {
        if let Some(e) = self.trust.get_mut(&ip) {
            *e = (*e + SMART_BAN_TRUST_PASS_REWARD).min(0);
        }
    }

    /// Reclaim neutral/positive entries (piggybacked on `BanBook::sweep`'s
    /// 1h cadence — only negative IPs need cross-tick memory). Returns the
    /// number reclaimed.
    pub(super) fn prune_neutral(&mut self) -> usize {
        let before = self.trust.len();
        self.trust.retain(|_, &mut v| v < 0);
        before - self.trust.len()
    }
}
/// Peer-ban bookkeeping context (owned by the main loop, no shared locks
/// — events converge on the main loop via the violation channel / progress
/// events and are processed in order).
pub(super) struct BanBook {
    /// IpGuard shared snapshot (arc-swap; read by accept/dial filter
    /// points, written by this structure).
    pub(super) guard: IpGuardHandle,
    /// ipfilter static rules (read back at startup; immutable while the
    /// engine runs — import hot-updates belong to the external session
    /// surface).
    pub(super) static_rules: Vec<FilterRule>,
    pub(super) ledger: BanLedger,
    /// Client identity rules (`client_ban_prefixes`; pushed in full by the
    /// session — SetBanConfig replaces wholesale + hot-updates the
    /// snapshot. Default empty = ban no client).
    pub(super) client_deny: Vec<String>,
    /// Manual ban ranges (`taiji.banAddr`; pushed in full by the session —
    /// same source as persisted peer_ban reason=manual; unexpired ones
    /// enter the snapshot).
    pub(super) manual: Vec<ManualBanRule>,
    /// Ban-enforcement counter feed (None = no feeding).
    pub(super) metrics: Option<Arc<SessionMetrics>>,
    /// smart_ban ledger (the evidence-based ban surface; coexists with the
    /// sliding-window ledger — division of labor in [`SmartBanLedger`]).
    pub(super) smart_ban: SmartBanLedger,
    /// smart_ban pass-piece read-back gate (1 concurrent piece per torrent
    /// — a disk read-back budget; read-back uses the pooled
    /// `TorrentReader` (handle pool + merged reads); this only bounds
    /// concurrency).
    pub(super) smart_ban_read_gate: Arc<tokio::sync::Semaphore>,
}

impl BanBook {
    /// Rebuild the effective-ban snapshot (static rules + active bans +
    /// manual ranges + identity rules).
    pub(super) fn refresh(&self, now: i64) {
        refresh_guard_full(
            &self.guard,
            &self.static_rules,
            &self.ledger,
            &self.manual,
            &self.client_deny,
            now,
        );
    }

    /// Session-pushed config surface (the EngineCommand::SetBanConfig
    /// body): replace identity rules and manual bans wholesale ->
    /// hot-update the snapshot -> immediately disconnect online connections
    /// inside unexpired manual ranges (the same enforcement surface as
    /// automatic bans; bans are never silent).
    pub(super) fn set_ban_config(
        &mut self,
        client_deny: Vec<String>,
        manual: Vec<ManualBanRule>,
        faces: &mut [FaceState],
    ) {
        self.client_deny = client_deny;
        self.manual = manual;
        let now = epoch_secs();
        self.refresh(now);
        let live: Vec<(IpAddr, IpAddr)> = self
            .manual
            .iter()
            .filter(|r| r.until > now)
            .map(|r| (r.start, r.end))
            .collect();
        let dropped = disconnect_ranges(faces, &live);
        if dropped > 0 {
            info!(target: "taiji::core::engine", dropped, ranges = live.len(),
                "connected peers inside manual ban ranges disconnecting");
        }
    }

    /// Expired-ban sweep (the 1h cadence gate lives inside the ledger; the
    /// snapshot hot-updates only when something was swept).
    pub(super) fn sweep(&mut self, now: i64) {
        let removed = self.ledger.sweep_if_due(now);
        // smart_ban trust accounting reclaims neutral/positive entries on
        // the same cadence (negatives kept — trust's memory belongs only
        // to rejected peers).
        let pruned = self.smart_ban.prune_neutral();
        if removed > 0 || pruned > 0 {
            info!(target: "taiji::core::engine", removed, pruned,
                "expired peer bans / neutral trust entries swept");
            self.refresh(now);
        }
    }

    /// Ban enforcement (bans are never silent): log with ip+reason+until
    /// -> snapshot hot-update -> persist the peer_ban row (failure warns
    /// only — filtering is hardening, it does not block downloads) ->
    /// immediately disconnect online connections of that IP (the
    /// message-level filter point).
    pub(super) async fn enact(
        &mut self,
        ip: IpAddr,
        reason: &str,
        until: i64,
        faces: &mut [FaceState],
        persist: Option<&TrackerPersistShared>,
    ) {
        warn!(target: "taiji::core::engine", %ip, reason, until,
            "peer banned (SPEC §13 reactive rule / identity rule)");
        // Ban-enforcement counter (the same enforcement point as the log
        // and the persist).
        if let Some(m) = self.metrics.as_ref() {
            m.note_peer_ban();
        }
        self.refresh(epoch_secs());
        if let Some(p) = persist {
            let row = taiji_store::persist::PeerBanRow {
                ip: ip.to_string(),
                reason: reason.to_string(),
                until,
            };
            match p.handle.upsert_peer_ban(row).await {
                Ok(PersistOutcome::Written) => {}
                Ok(PersistOutcome::SkippedUnchanged) => {}
                Err(e) => {
                    warn!(target: "taiji::core::engine", %ip, %e,
                        "peer ban persist failed")
                }
            }
        }
        let dropped = disconnect_ip(faces, ip);
        if dropped > 0 {
            debug!(target: "taiji::core::engine", %ip, dropped,
                "connected peers of banned ip disconnecting");
        }
    }

    /// Hash-verification failure bookkeeping (sliding window 10min /
    /// threshold 3; reaching the threshold bans).
    pub(super) async fn hash_failure(
        &mut self,
        ip: IpAddr,
        faces: &mut [FaceState],
        persist: Option<&TrackerPersistShared>,
    ) {
        let now = epoch_secs();
        match self.ledger.record_hash_failure(ip, now) {
            HashFailureDecision::Counted { failures } => {
                debug!(target: "taiji::core::engine", %ip, failures,
                    "hash check failure counted (window 10min, threshold 3)");
            }
            HashFailureDecision::Banned => {
                let until = self
                    .ledger
                    .is_banned(ip, now)
                    .map(|r| r.until)
                    .unwrap_or_else(|| unreachable!("just banned"));
                self.enact(
                    ip,
                    taiji_domain::peer_guard::REASON_HASH_FAILURES,
                    until,
                    faces,
                    persist,
                )
                .await;
            }
        }
    }

    /// Protocol violation bookkeeping (immediate ban; repeated violations
    /// are idempotent — the first until is kept; an already-banned IP's
    /// online connections were disconnected at the first ban and new
    /// connections are filtered by the snapshot).
    pub(super) async fn violation(
        &mut self,
        v: Violation,
        faces: &mut [FaceState],
        persist: Option<&TrackerPersistShared>,
    ) {
        let now = epoch_secs();
        if self.ledger.record_violation(v.ip, &v.reason, now) {
            let until = self
                .ledger
                .is_banned(v.ip, now)
                .map(|r| r.until)
                .unwrap_or_else(|| unreachable!("just banned"));
            self.enact(v.ip, &v.reason, until, faces, persist).await;
        }
    }
}

/// Disconnect all online connections of one IP (the message-level filter
/// point, event-driven; returns the disconnect count). After the PeerTask
/// exits, the attach forwarder sends leave for the regular removal
/// (availability retraction).
pub(super) fn disconnect_ip(faces: &mut [FaceState], ip: IpAddr) -> usize {
    let mut n = 0;
    for f in faces.iter_mut() {
        let targets: Vec<u64> = f
            .peer_state
            .iter()
            .filter(|(_, ps)| ps.ip == Some(ip))
            .map(|(c, _)| *c)
            .collect();
        for cuid in targets {
            if let Some(pos) = f.peer_cuids.iter().position(|c| *c == cuid) {
                if let Some(p) = f.peers.get(pos) {
                    warn!(target: "taiji::core::engine", %ip, cuid,
                        "connected peer banned -> disconnecting");
                    p.shutdown();
                    n += 1;
                }
            }
        }
    }
    n
}

/// Disconnect all online connections whose IP falls in any closed range
/// `[start, end]` (same-family comparison; the manual-ban enforcement
/// surface; few ranges x bounded online connections per engine = a
/// pairwise scan).
pub(super) fn disconnect_ranges(faces: &mut [FaceState], ranges: &[(IpAddr, IpAddr)]) -> usize {
    let mut n = 0;
    for f in faces.iter_mut() {
        let targets: Vec<u64> = f
            .peer_state
            .iter()
            .filter(|(_, ps)| {
                let Some(ip) = ps.ip else {
                    return false;
                };
                ranges.iter().any(|(s, e)| {
                    ip >= *s && ip <= *e && std::mem::discriminant(&ip) == std::mem::discriminant(s)
                })
            })
            .map(|(c, _)| *c)
            .collect();
        for cuid in targets {
            if let Some(pos) = f.peer_cuids.iter().position(|c| *c == cuid) {
                if let Some(p) = f.peers.get(pos) {
                    debug!(target: "taiji::core::engine", cuid,
                        "connected peer inside manual ban range -> disconnecting");
                    p.shutdown();
                    n += 1;
                }
            }
        }
    }
    n
}

/// Identity judgment at handshake completion (shared by outbound/inbound;
/// peer_id only becomes available at this point). A snapshot identity-rule
/// hit -> a Violation event (reason = `client-ban: <matched>`), flowing
/// through the existing violation channel into persistence + the unified
/// same-IP disconnection enforcement surface. The `v` field only arrives
/// after the ext handshake, so it is always None here (this judgment is
/// peer_id-only — the gap is noted in the [`crate`] module docs).
pub(super) fn client_violation(
    guard: &IpGuardHandle,
    peer_id: &[u8; 20],
    ip: IpAddr,
) -> Option<Violation> {
    let hit = guard.load().client_blocks(Some(peer_id), None)?;
    Some(Violation {
        ip,
        reason: format!("{REASON_CLIENT_BAN_PREFIX}{hit}"),
    })
}

/// Identity re-check callback for the ext handshake `v` field (injected
/// into every PeerTask; delivers the second matching dimension promised
/// by the options.rs `client_ban_prefixes` docs — "a peer_id byte prefix
/// OR a case-insensitive substring of the v field"). A hit =
/// `Some(client-ban:<matched>)`, the same reason shape as
/// [`client_violation`]; the PeerTask disconnects with
/// `PeerEnd::Violation(ClientBanned)` and flows through the existing
/// violation channel into persistence + the unified same-IP
/// disconnection enforcement surface (runtime hot-updates apply
/// naturally: every call reads the latest arc-swap snapshot).
pub(super) fn client_v_deny_check(guard: &IpGuardHandle) -> taiji_bt::peer::ClientDenyCheck {
    let guard = guard.clone();
    Arc::new(move |v: &str| {
        guard
            .load()
            .client_blocks(None, Some(v))
            .map(|hit| format!("{REASON_CLIENT_BAN_PREFIX}{hit}"))
    })
}

/// PeerEnd -> Violation event (protocol violations / flooding; other ends
/// are not violations).
pub(super) fn violation_of(end: PeerEnd, ip: IpAddr) -> Option<Violation> {
    match end {
        PeerEnd::Violation(e) => Some(Violation {
            ip,
            reason: e.to_string(),
        }),
        PeerEnd::Flooded => Some(Violation {
            ip,
            reason: "message flooding".to_string(),
        }),
        _ => None,
    }
}

/// Take and clear one block's sender (v2 block-level precise-coordinate
/// attribution).
pub(super) fn take_block_sender(
    faces: &mut [FaceState],
    fi: usize,
    index: u32,
    begin: u32,
) -> Option<u64> {
    let face = faces.get_mut(fi)?;
    let mut senders = crate::lock(&face.block_senders);
    senders.remove(&(index, begin))
}

/// Take and clear a piece's dispatch-target bookkeeping (the forensics
/// surface; invalidated and cleared once the piece settles or fails).
/// Returns a begin -> cuid snapshot for the pre-ban check "did we ever
/// request this block from them". Ownership: dispatch targets live inside
/// [`crate::dispatch::PieceSentLedger`] rows as the owner (a peer_cuids
/// index) — this take-out REMOVES the piece's `blocks_sent` row and
/// collects all its ownership (fused: the caller's old order — remove the
/// blocks_sent row, then take from the separate block_dispatch table — is
/// done in one step here; ownership dies with the row = the old separate
/// table's take-and-clear, semantically equivalent; the PieceDropped/
/// PieceEvicted arm call order is noted in `crate::run::arms`). Slots
/// without ownership (no owner / peer already gone) produce no entry
/// (in the old cuid form: the lookup table simply has no such coordinate —
/// conservatively unattributed).
pub(super) fn take_piece_dispatch_targets(
    face: &mut FaceState,
    index: u64,
) -> std::collections::HashMap<u32, u64> {
    let mut out = std::collections::HashMap::new();
    let Some(ledger) = face.blocks_sent.remove(&index) else {
        return out;
    };
    let block = u64::from(taiji_store::merkle::BLOCK_SIZE);
    for (bi, slot) in ledger.slots().iter().enumerate() {
        if slot.owner == crate::dispatch::NO_OWNER {
            continue;
        }
        if let Some(&cuid) = face.peer_cuids.get(slot.owner as usize) {
            out.insert((bi as u64 * block) as u32, cuid);
        }
    }
    out
}

/// Take and clear a piece's per-block sender bookkeeping (the smart_ban
/// attribution input): a begin -> cuid snapshot (re-reception at the same
/// coordinate still overwrites — the last arriver is recorded). The old
/// [`take_block_sender`] (v2 single-block attribution) and piece-level
/// dedup-view consumption shapes are all derived from this table's range;
/// smart ban needs per-block pairing of digest and deliverer.
pub(super) fn take_block_sender_map(
    faces: &mut [FaceState],
    fi: usize,
    index: u64,
) -> std::collections::HashMap<u32, u64> {
    let Some(face) = faces.get_mut(fi) else {
        return std::collections::HashMap::new();
    };
    let mut senders = crate::lock(&face.block_senders);
    let idx = index as u32;
    let mut out = std::collections::HashMap::new();
    senders.retain(|&(p, b), cuid| {
        if p == idx {
            out.insert(b, *cuid);
            false
        } else {
            true
        }
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(oct: [u8; 4]) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::from(oct))
    }

    fn d(seed: u8) -> [u8; 20] {
        let mut h = [0u8; 20];
        h[0] = seed;
        h
    }

    fn ledger() -> SmartBanLedger {
        SmartBanLedger {
            enabled: true,
            parole_enabled: true,
            trust: HashMap::new(),
            failed: HashMap::new(),
            stored_blocks: 0,
        }
    }

    /// Criterion (evidence self-certification, smart_ban.cpp): the same
    /// peer giving two different digests for the same block => the
    /// contradiction holds and bans; different peers each telling their
    /// own story does not; the same peer replaying the same value
    /// (deterministic corruption) is not a contradiction.
    #[test]
    fn contradiction_requires_same_peer_two_distinct_digests() {
        let mut l = ledger();
        let p = 7u64;
        // Cycle 1: P delivers block 0 (d1), Q delivers block 1 (d2) — the
        // piece fails.
        assert!(
            l.note_piece_failed(p, &[(0, 11, d(1)), (16384, 22, d(2))])
                .is_empty()
        );
        // Cycle 2 (a different peer): Q delivers block 0 again with a
        // digest differing from P's — different peers do not form a
        // contradiction (the bad one cannot be pinned).
        assert!(l.note_piece_failed(p, &[(0, 33, d(9))]).is_empty());
        // Cycle 3: P gives block 0 a d(3) differing from the recorded d(1)
        // -> contradiction => ban P.
        assert_eq!(l.note_piece_failed(p, &[(0, 11, d(3))]), vec![11]);
        // Same peer, same value replay: idempotent recording, no
        // contradiction.
        let mut l2 = ledger();
        assert!(l2.note_piece_failed(p, &[(0, 11, d(1))]).is_empty());
        assert!(l2.note_piece_failed(p, &[(0, 11, d(1))]).is_empty());
    }

    /// Criterion (on_piece_pass comparison, smart_ban.cpp): a peer whose
    /// recorded failure-cycle digest != the good-data digest is the
    /// bad-block source; equal digests are innocent; after comparison the
    /// piece's evidence is consumed (cleared).
    #[test]
    fn pass_compare_flags_only_mismatched_records_and_clears() {
        let mut l = ledger();
        let p = 3u64;
        // Failure cycle: block 0 delivered by P (a bad digest), block 1 by
        // Q (exactly the digest of the future good data).
        let _ = l.note_piece_failed(p, &[(0, 11, d(1)), (16384, 22, d(2))]);
        let good = vec![d(9), d(2)];
        let mut flagged = l.pass_compare(p, &good);
        flagged.sort();
        // P's recorded digest != good data -> bad-block source; Q's
        // recorded digest == good data -> innocent (zero false bans).
        assert_eq!(flagged, vec![(11, 0)]);
        // Evidence consumption: no residue after clearing (a second pass
        // of the same piece re-decides nothing).
        l.clear_piece(p);
        assert!(!l.has_failed_records(p));
        assert!(l.pass_compare(p, &good).is_empty());
    }

    /// Mixed-swarm decision table (good peers get zero false bans): a good
    /// peer's per-cycle block digests always equal the good data, so
    /// neither the contradiction decision nor the pass comparison may
    /// produce a ban candidate for it; the bad peer is pinned within <= 2
    /// piece cycles (the contradiction fires in cycle 2).
    #[test]
    fn mixed_swarm_decision_table_good_peer_never_flagged() {
        let mut l = ledger();
        let p = 1u64;
        let good0 = d(100);
        let good1 = d(200);
        // Cycle 1 (failure): good peer G delivers block 0 = good0; bad
        // peer B delivers block 1 = d(1) (bad).
        assert!(
            l.note_piece_failed(p, &[(0, 1, good0), (16384, 2, d(1))])
                .is_empty(),
            "no contradiction in the first cycle"
        );
        // Cycle 2 (failure again): G still delivers good0 (same value,
        // idempotent); B switches to bad data d(2) — B's contradiction
        // holds, G never enters the contradiction set.
        assert_eq!(
            l.note_piece_failed(p, &[(0, 1, good0), (16384, 2, d(2))]),
            vec![2]
        );
        // Cycle 3 (pass): good data = [good0, good1]. The pass comparison
        // flags only B (both its failure-cycle digests != good1); G's
        // good0 == the good data, zero false bans.
        let flagged = l.pass_compare(p, &[good0, good1]);
        assert!(
            flagged.iter().all(|&(c, _)| c == 2),
            "only the bad peer flagged: {flagged:?}"
        );
        assert!(flagged.contains(&(2, 16384)));
    }

    /// trust asymmetric penalty/reward (torrent.cpp): -2 per failure,
    /// +1 per pass capped at 0; a cumulative <= -7 decides the ban; a
    /// reward with no penalty history is a no-op (positive credit never
    /// appears from nothing).
    #[test]
    fn trust_asymmetric_penalty_reward_and_threshold() {
        let mut l = ledger();
        let a = ip([192, 0, 2, 1]);
        // 3 penalties = -6, below the threshold; the 4th = -8 <= -7 ->
        // ban.
        assert!(!l.trust_penalize(a));
        assert!(!l.trust_penalize(a));
        assert!(!l.trust_penalize(a));
        assert!(l.trust_penalize(a), "4 x -2 = -8 crosses the threshold");
        // The reward only recovers within the negative range, capped at 0.
        l.trust_reward(a);
        assert_eq!(l.trust[&a], -7);
        // A never-penalized peer: the reward is a no-op (no positive
        // account).
        let b = ip([192, 0, 2, 2]);
        l.trust_reward(b);
        assert!(!l.trust.contains_key(&b));
        // -6 -> +1 -> -5: never crosses 0.
        let c = ip([192, 0, 2, 3]);
        assert!(!l.trust_penalize(c));
        assert!(!l.trust_penalize(c));
        assert!(!l.trust_penalize(c)); // -6 (not yet -7)
        l.trust_reward(c);
        assert_eq!(l.trust[&c], -5);
    }

    /// Capacity bound (a local policy, see the SMART_BAN_FAILED_BLOCK_CAP
    /// note): once the evidence table is full, new evidence is not
    /// recorded (conservatively producing none); existing evidence is
    /// still decided and consumed as usual.
    #[test]
    fn failed_block_cap_refuses_new_evidence_when_full() {
        let mut l = ledger();
        // Fill it (4096 blocks, all distinct blocks of one piece).
        let piece = 0u64;
        let entries: Vec<FailedBlockEntry> = (0..SMART_BAN_FAILED_BLOCK_CAP as u32)
            .map(|b| (b * 16384, 9u64, d((b % 251) as u8 + 1)))
            .collect();
        assert!(l.note_piece_failed(piece, &entries).is_empty());
        assert_eq!(l.stored_blocks, SMART_BAN_FAILED_BLOCK_CAP);
        // When full, new evidence is not recorded.
        l.note_piece_failed(piece, &[(999 * 16384, 10, d(7))]);
        assert_eq!(
            l.stored_blocks, SMART_BAN_FAILED_BLOCK_CAP,
            "no growth once full"
        );
        // Existing evidence is still consumed.
        l.clear_piece(piece);
        assert_eq!(l.stored_blocks, 0);
    }

    /// trust accounting reclamation: neutral/positive entries are
    /// reclaimed on the cadence, negatives kept (memory belongs only to
    /// rejected peers).
    #[test]
    fn prune_neutral_keeps_only_penalized_ips() {
        let mut l = ledger();
        let a = ip([10, 0, 0, 1]);
        let b = ip([10, 0, 0, 2]);
        let _ = l.trust_penalize(a); // -2
        l.trust.insert(b, 0);
        assert_eq!(l.prune_neutral(), 1, "neutral entry reclaimed");
        assert!(l.trust.contains_key(&a), "negative score kept");
        assert!(!l.trust.contains_key(&b));
    }

    /// clear_piece only clears the target piece (other pieces' evidence is
    /// untouched — the concurrent multi-piece failure shape).
    #[test]
    fn clear_piece_is_piece_scoped() {
        let mut l = ledger();
        let _ = l.note_piece_failed(1, &[(0, 5, d(1))]);
        let _ = l.note_piece_failed(2, &[(0, 6, d(2))]);
        l.clear_piece(1);
        assert!(!l.has_failed_records(1));
        assert!(l.has_failed_records(2), "other piece's evidence kept");
    }
}
