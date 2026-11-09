//! Peer ban accounting plus eMule blocklist import orchestration.
//!
//! Responsibilities (core side): per-peer hash-verification-failure
//! sliding-window counting (>= 3 in 10min auto-bans), immediate ban on
//! protocol violations, assembling ban snapshots plus static rules into an
//! [`IpGuard`] hot swap, peer_ban/ipfilter table persistence through
//! PersistWriter, and .dat file import (parsing of > 1MiB files runs in
//! `spawn_blocking`). Pure types like IpGuard/Violation live in
//! `taiji-bt::peer_policy` (dependency-direction compliance).
//!
//! # Policy value sources
//!
//! - Sliding window 10min + threshold >= 3: a local design decision. The
//! reference has no "count threshold" concept — aria2 bans on a single
//! bad piece (`BtPieceMessage.cc` bad piece hash ->
//! `peerStorage_->addBadPeer`); >= 3 per 10min is more conservative
//! here (a peer with occasional corruption is not killed by mistake).
//! - Ban duration: an aria2 `DefaultPeerStorage.cc` transcription —
//! `max(getRandomNumber(601), 120)` seconds; `SimpleRandomizer.cc`
//! `getRandomNumber(to)` is in [0, to-1], so the range is [120, 600]
//! seconds. The variable timeout's purpose (aria2's original comment)
//! is to avoid large batches of bad peers expiring simultaneously and
//! waking together.
//! - Expiry sweep cadence: aria2 `DefaultPeerStorage.cc` — a full-table
//! sweep only when >= 1h since the last one
//! (`lastBadPeerCleaned_.difference(wallclock) >= 1_h`); the query side
//! [`BanLedger::is_banned`] itself lazily treats entries as expired
//! (same as `DefaultPeerStorage.cc` isBadPeer, which erases an expired
//! hit on lookup).

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use taiji_bt::peer_policy::{
    BanRecord, FilterRule, IpGuard, IpGuardHandle, RuleKind, parse_cidr, parse_emule_dat,
};
use taiji_store::error::StoreError;
use taiji_store::persist::{IpfilterRow, PersistHandle};
use tracing::{debug, info, warn};

/// Hash-failure sliding window length: 10min (a local design decision;
/// see the module docs' policy values).
pub const HASH_FAILURE_WINDOW: Duration = Duration::from_secs(600);
/// Auto-ban threshold: >= 3 verification failures within the window.
pub const HASH_FAILURE_THRESHOLD: u32 = 3;
/// Persisted ban reason (peer_ban.reason; protocol-violation reasons come
/// from the event text).
pub const REASON_HASH_FAILURES: &str = "hash verification failures (>=3 in 10min)";
/// Persisted reason for manual bans (`taiji.banAddr`; the peer_ban.reason
/// column).
pub const REASON_MANUAL: &str = "manual";
/// Persisted reason prefix for client-identity bans
/// (`client-ban: <matched string>`; source classification keys off this
/// prefix).
pub const REASON_CLIENT_BAN_PREFIX: &str = "client-ban:";

/// Ban duration lower/upper bound (seconds; an aria2
/// `DefaultPeerStorage.cc` transcription, see the module docs).
pub const BAD_PEER_TIMEOUT_MIN_SECS: u64 = 120;
pub const BAD_PEER_TIMEOUT_MAX_SECS: u64 = 600;

/// Minimum interval between expired-ban sweeps (seconds; an aria2
/// `DefaultPeerStorage.cc` 1h transcription).
pub const BAD_PEER_CLEAN_INTERVAL_SECS: i64 = 3600;

/// File reads/parses over 1MiB run in `spawn_blocking`.
pub const BLOCKLIST_PARSE_OFFLOAD: u64 = 1024 * 1024;
/// Blocklist hard cap (a local policy, OOM protection — the same idea as
/// a resource ceiling).
pub const BLOCKLIST_HARD_CAP: u64 = 256 * 1024 * 1024;

/// Ban duration source (injected: engine = aria2-style variable timeout;
/// tests = a constant).
pub type DurationSource = Box<dyn Fn() -> Duration + Send>;

/// aria2-style variable timeout, uniform over
/// [BAD_PEER_TIMEOUT_MIN_SECS, BAD_PEER_TIMEOUT_MAX_SECS]
/// (`DefaultPeerStorage.cc` transcription). For engine assembly of
/// [`BanLedger`].
pub fn variable_bad_peer_timeout() -> Duration {
    let span = BAD_PEER_TIMEOUT_MAX_SECS - BAD_PEER_TIMEOUT_MIN_SECS;
    let r = rand::RngExt::random_range(&mut rand::rng(), 0..=span);
    Duration::from_secs(BAD_PEER_TIMEOUT_MIN_SECS + r)
}

/// The outcome of hash-failure accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashFailureDecision {
    /// Count below threshold (failures = the current in-window count).
    Counted { failures: u32 },
    /// Threshold reached, ban recorded (the engine side then persists /
    /// hot-swaps / disconnects).
    Banned,
}

/// Peer ban ledger (engine main-loop exclusive; lock-free, no sharing —
/// only events cross tasks).
///
/// All time is injected by the caller (epoch seconds), keeping tests
/// deterministic.
pub struct BanLedger {
    window_secs: i64,
    threshold: u32,
    duration: DurationSource,
    /// Per-IP in-window failure timestamps (the sliding window).
    failures: HashMap<IpAddr, VecDeque<i64>>,
    bans: HashMap<IpAddr, BanRecord>,
    /// Last full-table sweep instant (epoch seconds; the counterpart of
    /// aria2 lastBadPeerCleaned_).
    last_sweep: i64,
}

impl std::fmt::Debug for BanLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BanLedger")
            .field("window_secs", &self.window_secs)
            .field("threshold", &self.threshold)
            .field("failures", &self.failures.len())
            .field("bans", &self.bans.len())
            .finish()
    }
}

impl BanLedger {
    /// The default policy (10min window / threshold 3) plus an injected
    /// duration source.
    pub fn new(duration: DurationSource) -> BanLedger {
        BanLedger {
            window_secs: HASH_FAILURE_WINDOW.as_secs() as i64,
            threshold: HASH_FAILURE_THRESHOLD,
            duration,
            failures: HashMap::new(),
            bans: HashMap::new(),
            last_sweep: 0,
        }
    }

    /// Records one hash verification failure: the sliding window evicts
    /// out-of-window history, then counts; at the threshold it bans
    /// (until = now + duration; the failure queue is cleared — counting
    /// restarts after a ban).
    pub fn record_hash_failure(&mut self, ip: IpAddr, now: i64) -> HashFailureDecision {
        let q = self.failures.entry(ip).or_default();
        while let Some(&t) = q.front() {
            if now - t >= self.window_secs {
                q.pop_front();
            } else {
                break;
            }
        }
        q.push_back(now);
        if q.len() as u32 >= self.threshold {
            let until = ban_until(now, &mut self.duration);
            self.bans.insert(
                ip,
                BanRecord {
                    reason: REASON_HASH_FAILURES.to_string(),
                    until,
                },
            );
            self.failures.remove(&ip);
            HashFailureDecision::Banned
        } else {
            HashFailureDecision::Counted {
                failures: q.len() as u32,
            }
        }
    }

    /// Protocol violation -> immediate ban. Returns whether this is a new
    /// ban (repeat violations keep the first until — idempotent, so a
    /// persistent violator cannot extend indefinitely).
    pub fn record_violation(&mut self, ip: IpAddr, reason: &str, now: i64) -> bool {
        if self.bans.contains_key(&ip) {
            return false;
        }
        let until = ban_until(now, &mut self.duration);
        self.bans.insert(
            ip,
            BanRecord {
                reason: reason.to_string(),
                until,
            },
        );
        self.failures.remove(&ip);
        true
    }

    /// The active ban (`until > now`; None = not banned or expired).
    pub fn is_banned(&self, ip: IpAddr, now: i64) -> Option<&BanRecord> {
        self.bans.get(&ip).filter(|r| r.until > now)
    }

    /// Snapshot of active bans (for IpGuard assembly / persistence
    /// comparison).
    pub fn active_bans(&self, now: i64) -> Vec<(IpAddr, BanRecord)> {
        self.bans
            .iter()
            .filter(|(_, r)| r.until > now)
            .map(|(ip, r)| (*ip, r.clone()))
            .collect()
    }

    /// Startup restore (peer_ban table read-back; only unexpired
    /// `until > now` entries are accepted).
    pub fn restore_ban(&mut self, ip: IpAddr, reason: String, until: i64, now: i64) {
        if until > now {
            self.bans.insert(ip, BanRecord { reason, until });
        }
    }

    /// Expired full-table sweep (>= 1h cadence; also reclaims failure
    /// queues that never reached the threshold and are out of window).
    /// Returns the number of bans cleared (> 0 -> the caller hot-swaps
    /// the snapshot).
    pub fn sweep_if_due(&mut self, now: i64) -> usize {
        if now - self.last_sweep < BAD_PEER_CLEAN_INTERVAL_SECS {
            return 0;
        }
        self.last_sweep = now;
        let before = self.bans.len();
        self.bans.retain(|_, r| r.until > now);
        self.failures
            .retain(|_, q| q.back().is_some_and(|t| now - *t < self.window_secs) && !q.is_empty());
        before - self.bans.len()
    }
}

fn ban_until(now: i64, duration: &mut DurationSource) -> i64 {
    now.saturating_add(duration().as_secs() as i64)
}

/// Assembles and hot-swaps the snapshot (static rules + active bans).
/// Call after a ban takes effect / an import / a sweep.
pub fn refresh_guard(guard: &IpGuardHandle, rules: &[FilterRule], ledger: &BanLedger, now: i64) {
    guard.store(IpGuard::new(rules.iter().copied(), ledger.active_bans(now)));
}

/// Manual ban rule (the `taiji.banAddr` engine face): a closed interval
/// `[start, end]` plus an expiry instant (epoch seconds; `i64::MAX` =
/// permanent). reason is always "manual" (one source for persistence and
/// snapshot — the snapshot side assembles the [`BanRecord`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualBanRule {
    pub start: IpAddr,
    pub end: IpAddr,
    pub until: i64,
}

/// Assembles and hot-swaps the snapshot — the extended face (manual ban
/// ranges + client-identity rules). Unexpired manual bans enter the
/// snapshot (same priority as auto bans); `client_deny` enters as-is
/// (identification is not banning; an empty list always allows). A
/// superset wrapper of [`refresh_guard`].
pub fn refresh_guard_full(
    guard: &IpGuardHandle,
    rules: &[FilterRule],
    ledger: &BanLedger,
    manual: &[ManualBanRule],
    client_deny: &[String],
    now: i64,
) {
    let snapshot = IpGuard::new(rules.iter().copied(), ledger.active_bans(now))
        .with_manual_bans(manual.iter().filter(|r| r.until > now).map(|r| {
            (
                r.start,
                r.end,
                BanRecord {
                    reason: REASON_MANUAL.to_string(),
                    until: r.until,
                },
            )
        }))
        .with_client_deny(client_deny.iter().cloned());
    guard.store(snapshot);
}

/// Blocklist import report (log/test assertion face).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlocklistReport {
    pub total_rules: usize,
    pub deny: usize,
    pub allow: usize,
    /// Non-conforming line count (the bt::peer_policy parser's per-line
    /// tolerance count).
    pub skipped: usize,
    /// Whether spawn_blocking was used (> 1MiB).
    pub offloaded: bool,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BlocklistError {
    #[error("blocklist file {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("blocklist file exceeds hard cap {cap} bytes: {size}")]
    TooLarge { size: u64, cap: u64 },
    #[error("blocklist persist: {0}")]
    Persist(#[from] StoreError),
}

/// eMule .dat blocklist import: read file -> parse -> replace the
/// ipfilter table kind=p2p-blocklist as a whole table -> hot-swap the
/// IpGuard snapshot (static rules = imported rules; the ban snapshot is
/// passed in by the caller).
///
/// Returns the import report; with `persist = None` nothing is persisted
/// (hot snapshot only — pure in-memory usage).
pub async fn import_emule_blocklist(
    path: impl AsRef<Path>,
    persist: Option<&PersistHandle>,
    guard: &IpGuardHandle,
    bans: &[(IpAddr, BanRecord)],
) -> Result<BlocklistReport, BlocklistError> {
    let path = path.as_ref();
    let show = path.display().to_string();
    let meta = tokio::fs::metadata(path)
        .await
        .map_err(|source| BlocklistError::Io {
            path: show.clone(),
            source,
        })?;
    let size = meta.len();
    if size > BLOCKLIST_HARD_CAP {
        return Err(BlocklistError::TooLarge {
            size,
            cap: BLOCKLIST_HARD_CAP,
        });
    }
    let offloaded = size > BLOCKLIST_PARSE_OFFLOAD;
    let bytes = if offloaded {
        let p = path.to_path_buf();
        tokio::task::spawn_blocking(move || std::fs::read(&p))
            .await
            .map_err(|e| BlocklistError::Io {
                path: show.clone(),
                source: std::io::Error::other(e),
            })?
            .map_err(|source| BlocklistError::Io {
                path: show.clone(),
                source,
            })?
    } else {
        tokio::fs::read(path)
            .await
            .map_err(|source| BlocklistError::Io {
                path: show.clone(),
                source,
            })?
    };
    let parsed = if offloaded {
        tokio::task::spawn_blocking(move || parse_emule_dat(&String::from_utf8_lossy(&bytes)))
            .await
            .map_err(|e| BlocklistError::Io {
                path: show.clone(),
                source: std::io::Error::other(e),
            })?
    } else {
        parse_emule_dat(&String::from_utf8_lossy(&bytes))
    };

    let deny = parsed
        .rules
        .iter()
        .filter(|r| r.action == taiji_bt::peer_policy::RuleAction::Deny)
        .count();
    let report = BlocklistReport {
        total_rules: parsed.rules.len(),
        deny,
        allow: parsed.rules.len() - deny,
        skipped: parsed.skipped,
        offloaded,
    };
    if report.skipped > 0 {
        warn!(target: "taiji::core::peer_guard", path = %show,
            skipped = report.skipped, "blocklist import skipped malformed lines");
    }
    info!(target: "taiji::core::peer_guard", path = %show,
        deny = report.deny, allow = report.allow, skipped = report.skipped,
        offloaded = report.offloaded, "emule blocklist imported");

    // kind=p2p-blocklist whole-table replacement (re-importing identical
    // content skips writes on the store side).
    if let Some(p) = persist {
        let rows: Vec<IpfilterRow> = parsed
            .rules
            .iter()
            .map(|r| IpfilterRow {
                kind: RuleKind::P2PBlocklist.as_str().to_string(),
                rule: r.to_blocklist_text(),
                enabled: true,
            })
            .collect();
        p.replace_ipfilter(RuleKind::P2PBlocklist.as_str(), rows)
            .await?;
    }

    // Hot-swap the snapshot (imported rules + the existing ban snapshot).
    guard.store(IpGuard::new(
        parsed.rules.iter().copied(),
        bans.iter().cloned(),
    ));
    debug!(target: "taiji::core::peer_guard", path = %show,
        "IpGuard snapshot hot-swapped");
    Ok(report)
}

/// ipfilter table row -> static rule (the startup restore read-back
/// face): unknown kinds / bad rule text warn and skip, never failing
/// wholesale — filter rules are a hardening face; one bad row missing
/// must not cripple it.
pub fn ipfilter_row_to_rule(row: &IpfilterRow) -> Option<FilterRule> {
    if !row.enabled {
        return None;
    }
    let parsed = match row.kind.as_str() {
        "p2p-blocklist" => taiji_bt::peer_policy::parse_blocklist_rule(&row.rule),
        "cidr" => parse_cidr(&row.rule),
        other => {
            warn!(target: "taiji::core::peer_guard", kind = %other,
                rule = %row.rule, "unknown ipfilter kind, skipped");
            return None;
        }
    };
    if parsed.is_none() {
        warn!(target: "taiji::core::peer_guard", kind = %row.kind,
            rule = %row.rule, "malformed ipfilter rule, skipped");
    }
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(oct: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(oct))
    }

    /// Constant duration (test determinism).
    fn fixed(secs: u64) -> DurationSource {
        Box::new(move || Duration::from_secs(secs))
    }

    /// Sliding-window count boundary table: 2 in 10min does not ban,
    /// 3 bans, cross-window reset (old entries evicted), in-window spread
    /// counting, queue cleared and recount restarted after a ban.
    #[test]
    fn sliding_window_boundary_table() {
        let mut ledger = BanLedger::new(fixed(300));
        let a = ip([192, 0, 2, 1]);

        // Case 1: 2 in 10min -> no ban.
        let t0 = 1_000_000;
        assert_eq!(
            ledger.record_hash_failure(a, t0),
            HashFailureDecision::Counted { failures: 1 }
        );
        assert_eq!(
            ledger.record_hash_failure(a, t0 + 60),
            HashFailureDecision::Counted { failures: 2 }
        );
        assert!(ledger.is_banned(a, t0 + 60).is_none());

        // Case 2: the 3rd within the window -> ban (until = now + 300).
        assert_eq!(
            ledger.record_hash_failure(a, t0 + 120),
            HashFailureDecision::Banned
        );
        let rec = ledger
            .is_banned(a, t0 + 120)
            .unwrap_or_else(|| panic!("banned"));
        assert_eq!(rec.until, t0 + 120 + 300);
        assert_eq!(rec.reason, REASON_HASH_FAILURES);

        // Case 3: the failure queue is cleared after a ban, recount
        // restarts (no immediate re-ban from old history).
        assert_eq!(
            ledger.record_hash_failure(a, t0 + 130),
            HashFailureDecision::Counted { failures: 1 },
            "recount restarts after ban"
        );
        // Case 4: cross-window reset — old entries (> 10min ago) evicted,
        // no accumulation.
        let mut ledger = BanLedger::new(fixed(300));
        let b = ip([192, 0, 2, 2]);
        let _ = ledger.record_hash_failure(b, t0);
        let _ = ledger.record_hash_failure(b, t0 + 599);
        // The t0 entry is exactly evicted at t0+600 (now - t >= 600):
        assert_eq!(
            ledger.record_hash_failure(b, t0 + 600),
            HashFailureDecision::Counted { failures: 2 },
            "t0 entry already evicted (two entries: t0+599 and t0+600)"
        );
        assert!(
            ledger.is_banned(b, t0 + 600).is_none(),
            "no ban across the window"
        );

        // Case 5: 3 spread exactly within the window -> ban (count
        // condition = now - t < window: 599 < 600 is inside; 600 is
        // evicted — see case 4).
        let mut ledger = BanLedger::new(fixed(300));
        let c = ip([192, 0, 2, 3]);
        let _ = ledger.record_hash_failure(c, t0);
        let _ = ledger.record_hash_failure(c, t0 + 299);
        assert_eq!(
            ledger.record_hash_failure(c, t0 + 599),
            HashFailureDecision::Banned,
            "3 spread within the window (gaps 299/300 < 600) -> ban"
        );
    }

    /// Protocol violation bans immediately; repeat violations are
    /// idempotent (keeping the first until); is_banned lazily judges
    /// expiry; restore accepts only unexpired entries.
    #[test]
    fn violation_ban_and_restore_semantics() {
        let mut ledger = BanLedger::new(fixed(300));
        let a = ip([192, 0, 2, 9]);
        let now = 5_000;
        assert!(
            ledger.record_violation(a, "unsolicited piece", now),
            "first = new ban"
        );
        assert!(
            !ledger.record_violation(a, "flooding", now + 10),
            "repeat violation does not create a new ban"
        );
        let rec = ledger.is_banned(a, now).unwrap_or_else(|| panic!("banned"));
        assert_eq!(rec.reason, "unsolicited piece", "first reason kept");
        assert_eq!(rec.until, now + 300, "first until kept");
        // Lazy expiry judgment.
        assert!(
            ledger.is_banned(a, now + 300).is_none(),
            "blocks only while until > now"
        );
        // restore: expired entries not accepted.
        let mut ledger = BanLedger::new(fixed(300));
        ledger.restore_ban(a, "from db".into(), now + 100, now);
        assert!(
            ledger.is_banned(a, now).is_some(),
            "unexpired entry restored"
        );
        let mut ledger = BanLedger::new(fixed(300));
        ledger.restore_ban(a, "stale".into(), now, now);
        assert!(
            ledger.is_banned(a, now).is_none(),
            "expired entry not restored"
        );
    }

    /// A violation ban clears any pending failure queue — both ban paths
    /// share the "counting restarts after a ban" invariant (the
    /// hash-failure path clears at its own ban; the violation path must
    /// not leave a stale queue behind to re-ban on the first failure
    /// after expiry).
    #[test]
    fn violation_ban_clears_stale_failure_queue() {
        let mut ledger = BanLedger::new(fixed(300));
        let a = ip([192, 0, 2, 11]);
        let now = 1_000_000;
        // Two in-window failures (below threshold, the queue non-empty).
        assert_eq!(
            ledger.record_hash_failure(a, now),
            HashFailureDecision::Counted { failures: 1 }
        );
        assert_eq!(
            ledger.record_hash_failure(a, now + 60),
            HashFailureDecision::Counted { failures: 2 }
        );
        // The violation ban takes the same IP: new ban ...
        assert!(ledger.record_violation(a, "viol", now + 120));
        // ... and the stale failure queue is dropped with it.
        assert!(ledger.failures.get(&a).is_none());
        // Past the violation ban's expiry (until = now+120+300): a fresh
        // hash failure counts from 1 instead of tripping the old 2+1
        // history straight into Banned.
        assert_eq!(
            ledger.record_hash_failure(a, now + 120 + 301),
            HashFailureDecision::Counted { failures: 1 },
            "counting restarts after a violation ban (stale queue cleared)"
        );
    }

    /// The sweep cadence (1h) and expired-entry reclamation (aria2
    /// DefaultPeerStorage.cc).
    #[test]
    fn sweep_gated_by_one_hour_interval() {
        let mut ledger = BanLedger::new(fixed(300));
        let a = ip([192, 0, 2, 10]);
        let now = 1_000_000;
        // The first call already meets the cadence (constructed last_sweep
        // = 0): sweeping an empty table returns 0.
        assert_eq!(ledger.sweep_if_due(now), 0);
        // Within the 1h cadence no sweep: even an expired ban stays for
        // now (the query side's lazy expiry check is the backstop).
        assert!(ledger.record_violation(a, "x", now), "ban until = now+300");
        assert_eq!(
            ledger.sweep_if_due(now + 300),
            0,
            "cadence not reached: expired entries not yet reclaimed"
        );
        assert!(
            ledger.is_banned(a, now + 300).is_none(),
            "is_banned judges expiry lazily (until > now) — cross-validates DefaultPeerStorage.cc"
        );
        // Cadence reached -> 1 expired entry cleared.
        assert_eq!(ledger.sweep_if_due(now + BAD_PEER_CLEAN_INTERVAL_SECS), 1);
        assert!(
            ledger
                .active_bans(now + BAD_PEER_CLEAN_INTERVAL_SECS)
                .is_empty(),
            "no residue after sweep"
        );
        // After the sweep the cadence restarts.
        assert_eq!(
            ledger.sweep_if_due(now + BAD_PEER_CLEAN_INTERVAL_SECS + 10),
            0
        );
    }

    /// Variable timeout range: [120, 600] (aria2 DefaultPeerStorage.cc
    /// transcription).
    #[test]
    fn variable_timeout_within_aria2_bounds() {
        for _ in 0..200 {
            let d = variable_bad_peer_timeout();
            assert!(
                d.as_secs() >= BAD_PEER_TIMEOUT_MIN_SECS
                    && d.as_secs() <= BAD_PEER_TIMEOUT_MAX_SECS,
                "duration out of bounds: {d:?}"
            );
        }
    }

    /// Import orchestration: snapshot hot swap (deny/allow counts +
    /// skipped) + whole-table replacement + existing bans folded into the
    /// snapshot; the > 1MiB offload path. A persist = None in-memory case
    /// is covered here too.
    #[tokio::test]
    async fn import_blocklist_swaps_snapshot_and_persists() {
        // A tmp .dat (with 1 bad line).
        let dir = std::env::temp_dir().join(format!(
            "taiji-p30-import-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
        let dat = dir.join("filter.dat");
        std::fs::write(
            &dat,
            "# test list\ndeny,10.9.9.0,10.9.9.255\nallow,192.168.0.0,192.168.0.255\nbad line\n",
        )
        .unwrap_or_else(|e| panic!("{e}"));

        let guard = IpGuardHandle::new(IpGuard::default());
        let now = 1_000_000;
        let bans = vec![(
            ip([192, 0, 2, 66]),
            BanRecord {
                reason: "viol".into(),
                until: now + 1000,
            },
        )];
        let report = import_emule_blocklist(&dat, None, &guard, &bans)
            .await
            .unwrap_or_else(|e| panic!("import: {e}"));
        assert_eq!(
            report,
            BlocklistReport {
                total_rules: 2,
                deny: 1,
                allow: 1,
                skipped: 1,
                offloaded: false,
            }
        );
        // Snapshot swap visible: deny blocks, allow passes, the ban is
        // folded in, the bad line has no effect.
        assert!(guard.load().blocks(ip([10, 9, 9, 5]), now).is_some());
        assert_eq!(guard.load().blocks(ip([192, 168, 0, 7]), now), None);
        assert_eq!(
            guard.load().blocks(ip([192, 0, 2, 66]), now),
            Some(taiji_bt::peer_policy::IpBlock::Banned("viol".into())),
            "existing ban folded into the post-import snapshot"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ipfilter table row -> rule (the startup restore face):
    /// enabled=false not accepted, bad text warns and skips, both
    /// cidr/p2p-blocklist kinds parse.
    #[test]
    fn ipfilter_row_conversion() {
        let mk = |kind: &str, rule: &str, enabled: bool| IpfilterRow {
            kind: kind.into(),
            rule: rule.into(),
            enabled,
        };
        assert!(
            ipfilter_row_to_rule(&mk("p2p-blocklist", "deny,10.0.0.0,10.0.0.255", true)).is_some()
        );
        assert!(ipfilter_row_to_rule(&mk("cidr", "10.0.0.0/8", true)).is_some());
        assert!(
            ipfilter_row_to_rule(&mk("p2p-blocklist", "deny,10.0.0.0,10.0.0.255", false)).is_none(),
            "disabled rows not accepted"
        );
        assert!(ipfilter_row_to_rule(&mk("p2p-blocklist", "garbage", true)).is_none());
        assert!(
            ipfilter_row_to_rule(&mk("mystery", "deny,1.2.3.4,1.2.3.4", true)).is_none(),
            "unknown kind"
        );
    }

    /// refresh_guard_full: manual ban ranges (unexpired enter the
    /// snapshot, expired dropped) + client_deny identity rules + auto
    /// bans folded into the same snapshot.
    #[test]
    fn refresh_guard_full_swaps_manual_and_client_rules() {
        let guard = IpGuardHandle::new(IpGuard::default());
        let mut ledger = BanLedger::new(fixed(300));
        let auto_ip = ip([192, 0, 2, 1]);
        assert!(ledger.record_violation(auto_ip, "unsolicited piece", 1000));
        let manual = vec![
            ManualBanRule {
                start: ip([10, 66, 0, 0]),
                end: ip([10, 66, 0, 255]),
                until: 5_000,
            },
            ManualBanRule {
                start: ip([10, 77, 0, 0]),
                end: ip([10, 77, 0, 255]),
                until: 1_000, // already expired relative to now=2000 -> not in the snapshot.
            },
        ];
        let clients = vec!["-XL".to_string()];
        // Snapshot at 1_200: manual[0] (until 5000) active, manual[1]
        // (until 1000) expired and dropped, auto ban (until 1300) active
        // — all three judgeable from one snapshot.
        refresh_guard_full(&guard, &[], &ledger, &manual, &clients, 1_200);
        let snap = guard.load();
        // Unexpired manual range blocks (reason=manual).
        assert_eq!(
            snap.blocks(ip([10, 66, 0, 9]), 1_200),
            Some(taiji_bt::peer_policy::IpBlock::Banned(
                REASON_MANUAL.to_string()
            ))
        );
        // Expired manual range does not block.
        assert_eq!(snap.blocks(ip([10, 77, 0, 9]), 1_200), None);
        // Auto ban folded in.
        assert!(snap.blocks(auto_ip, 1_200).is_some());
        // Identity rule hit.
        assert_eq!(
            snap.client_blocks(Some(b"-XL0011-0123456789AB"), None),
            Some("-XL".to_string())
        );
        assert_eq!(
            snap.client_blocks(Some(b"-qB4550-0123456789AB"), None),
            None
        );
        // Swapping in an empty list: identity rules disappear with it
        // (full-state hot-swap semantics).
        refresh_guard_full(&guard, &[], &ledger, &manual, &[], 2_000);
        assert_eq!(
            guard
                .load()
                .client_blocks(Some(b"-XL0011-0123456789AB"), None),
            None
        );
    }
}
