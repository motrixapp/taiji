//! Disk-protection tier policy: a three-tier parameter table drives the
//! write-merge window, flush cadence, IO ops/s quota, read-serving merge
//! parameters, and the preallocation mode.
//!
//! # Tier table (default = throughput, zero behavior change)
//!
//! | Parameter | throughput (default) | ssd-protect | hdd-sequential |
//! |---|---|---|---|
//! | Preallocation mode | trunc (existing) | falloc | prealloc (full zero-fill) |
//! | Write-merge cap | 0 (per-cell writes = existing) | 1 MiB | 4 MiB |
//! | Flush cadence | none (flush at completion only) | 30s | 60s |
//! | IO ops/s quota | 0 (unlimited) | 4096 | 512 |
//! | Read-merge cap | 0 (1:1 reads = existing) | 256 KiB | 1 MiB |
//! | Read-merge max ranges | 0 | 16 | 64 |
//!
//! # Platform capability (real preallocation fast path)
//!
//! Neither Linux `fallocate(2)` nor macOS `fcntl(F_PREALLOCATE)` has a safe
//! std wrapper (raw libc fcntl/fallocate is unsafe — the workspace
//! `unsafe_code = forbid` vetoes it; a safe-wrapper crate would be a new
//! dependency, barred by policy). [`AllocationMode::Falloc`] is stubbed in
//! [`crate::disk::DiskWriter::allocate`] and by design falls back to trunc
//! (logged, never silently faked); [`AllocationMode::Prealloc`] is
//! implemented with plain std zero-fill (direct translation of aria2
//! `SingleFileAllocationIterator`) and really preallocates on every
//! platform. Landing the fast path awaits a safe fcntl wrapper (same seam
//! as F_NOCACHE).
//!
//! Upstream anchor mapping: docs/design/store.md

use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tracing::warn;

use crate::lock;

/// Preallocation mode (cross-checked against aria2 `--file-allocation`:
/// trunc|falloc|prealloc; `none` is not a tier — allocation always happens
/// at task creation, with trunc as the default semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AllocationMode {
    /// Sparse ftruncate (the existing behavior; reserves no disk space,
    /// allocated on demand as writes land).
    Trunc,
    /// Real preallocation fast path (Linux fallocate / macOS F_PREALLOCATE;
    /// currently stubbed on every platform — see the module docs: falls
    /// back to trunc at runtime and says so).
    Falloc,
    /// Full preallocation: write zeros segment by segment (direct
    /// translation of aria2 `SingleFileAllocationIterator`; real
    /// allocation on every platform, prevents HDD fragmentation).
    Prealloc,
}

/// Disk-protection tier (three tiers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiskTier {
    /// Default tier: every parameter keeps the existing behavior (zero
    /// change).
    Throughput,
    /// SSD protection: falloc intent + write merging to cut write
    /// amplification + a moderate cadence.
    SsdProtect,
    /// HDD sequencing: full preallocation against fragmentation + large
    /// merged sequential writes/reads + a low ops quota.
    HddSequential,
}

impl DiskTier {
    /// All tier names (the declarative source for the
    /// `diskPolicy.available` capability face and RPC set-parameter
    /// validation; same value domain as the [`FromStr`] parse — a
    /// roundtrip test locks them together).
    pub const NAMES: &'static [&'static str] = &["throughput", "ssd-protect", "hdd-sequential"];

    /// Canonical tier name (value domain of the config_json `disk_tier`
    /// payload).
    pub fn name(&self) -> &'static str {
        match self {
            DiskTier::Throughput => "throughput",
            DiskTier::SsdProtect => "ssd-protect",
            DiskTier::HddSequential => "hdd-sequential",
        }
    }

    /// Tier parameter table (the single table-driven source; tests assert
    /// each cell).
    pub fn policy(&self) -> DiskPolicy {
        let (allocation, write_merge, flush, ops, read_bytes, read_ranges) = match self {
            // Default tier = the existing behavior verbatim (the
            // zero-change rule).
            DiskTier::Throughput => (AllocationMode::Trunc, 0, None, 0, 0, 0),
            DiskTier::SsdProtect => (
                AllocationMode::Falloc,
                1024 * 1024,
                Some(Duration::from_secs(30)),
                4096,
                256 * 1024,
                16,
            ),
            DiskTier::HddSequential => (
                AllocationMode::Prealloc,
                4 * 1024 * 1024,
                Some(Duration::from_secs(60)),
                512,
                1024 * 1024,
                64,
            ),
        };
        DiskPolicy {
            tier: *self,
            allocation,
            write_merge_max_bytes: write_merge,
            flush_interval: flush,
            io_ops_per_sec: ops,
            read_merge_max_bytes: read_bytes,
            read_merge_max_ranges: read_ranges,
        }
    }
}

/// Unknown disk-tier name (the [`FromStr`] error face; carries the
/// rejected input verbatim so callers can echo it in diagnostics).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown disk tier: `{0}`")]
pub struct UnknownTierName(pub String);

// Parse a tier name (case-insensitive; the `Err` carries the rejected
// name verbatim — the caller decides between an explicit error and the
// default-tier fallback).
impl FromStr for DiskTier {
    type Err = UnknownTierName;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "throughput" => Ok(DiskTier::Throughput),
            "ssd-protect" => Ok(DiskTier::SsdProtect),
            "hdd-sequential" => Ok(DiskTier::HddSequential),
            _ => Err(UnknownTierName(s.to_string())),
        }
    }
}

/// Disk-policy parameters (the expanded form of the tier table; consumed
/// by the pipeline and the writers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskPolicy {
    /// Owning tier (for observation/logging).
    pub tier: DiskTier,
    /// Preallocation mode for newly created tasks.
    pub allocation: AllocationMode,
    /// Write-merge window cap (max bytes merged into one `write_at`;
    /// 0 = no merging, per-cell writes = the existing behavior).
    pub write_merge_max_bytes: usize,
    /// Flush cadence (periodic fsync; None = no periodic fsync, the
    /// completion path only, as before).
    pub flush_interval: Option<Duration>,
    /// IO ops/s token-bucket quota (shared by read serving and write
    /// flushes; 0 = unlimited).
    pub io_ops_per_sec: u32,
    /// Read-serving merge: max bytes per merged IO (0 = no merging).
    pub read_merge_max_bytes: usize,
    /// Read-serving merge: max read ranges one merge may absorb
    /// (0 = no merging).
    pub read_merge_max_ranges: usize,
}

impl Default for DiskPolicy {
    fn default() -> DiskPolicy {
        DiskTier::Throughput.policy()
    }
}

impl DiskPolicy {
    /// Resolve a per-task override (the config_json `disk_tier` internal
    /// face): None = default tier; an unknown name logs a warn and falls
    /// back to the default tier (the downgrade is observable, never
    /// silent).
    pub fn resolve(override_tier: Option<&str>) -> DiskPolicy {
        match override_tier.map(|name| name.parse::<DiskTier>()) {
            None => DiskPolicy::default(),
            Some(Ok(tier)) => tier.policy(),
            Some(Err(err)) => {
                warn!(target: "taiji::store::disk_policy",
                    override = override_tier.unwrap_or(""),
                    %err,
                    "unknown disk_tier override: falling back to throughput (default)");
                DiskPolicy::default()
            }
        }
    }
}

/// IO ops/s token bucket: the shared quota face of read serving and write
/// flushing (IO fairness).
///
/// - Capacity = 1s of quota (a full bucket never accumulates across
///   seconds — the burst ceiling is exactly `io_ops_per_sec`).
/// - `try_acquire` is deterministic under injected time;
///   [`IoGate::acquire`] is the async wrapper (sleep-and-retry; no lock
///   held across an await — the std Mutex only guards the state
///   read/update).
/// - Fairness = **quota** (reads and writes share one bucket; neither
///   side can hold a burst larger than 1s of quota) + **staggered
///   cadence** (flushes are periodic events, naturally offset from read
///   requests). No per-request round-robin: BT read traffic is naturally
///   bursty, and queueing buys less than its complexity costs.
#[derive(Debug)]
pub struct IoGate {
    /// None = unlimited (zero-overhead passthrough for the throughput
    /// tier). One Mutex carries the whole None<->Some state so
    /// [`Self::set_rate`] can retarget live — the ticket path takes the
    /// lock once per call as before, and the no-lock-across-await
    /// discipline is unchanged.
    state: Mutex<Option<GateState>>,
}

#[derive(Debug)]
struct GateState {
    /// Remaining tokens (1/1000-op granularity).
    tokens_milli: u64,
    /// Instant of the last ticket (anchor for incremental refill).
    last: Instant,
    rate: u32,
}

impl IoGate {
    /// `ops_per_sec` = 0 -> unlimited (throughput tier); > 0 -> a token
    /// bucket with 1s capacity.
    pub fn new(ops_per_sec: u32) -> IoGate {
        if ops_per_sec == 0 {
            return IoGate {
                state: Mutex::new(None),
            };
        }
        IoGate {
            state: Mutex::new(Some(GateState {
                tokens_milli: u64::from(ops_per_sec) * 1000,
                last: Instant::now(),
                rate: ops_per_sec,
            })),
        }
    }

    /// The unlimited form (explicit; equivalent to `new(0)`, for tests
    /// and passthrough paths).
    pub fn unlimited() -> IoGate {
        IoGate {
            state: Mutex::new(None),
        }
    }

    /// Whether the gate is unlimited (tests/logging).
    pub fn is_unlimited(&self) -> bool {
        lock(&self.state).is_none()
    }

    /// Live retarget (the live face of the disk_tier RPC): change the
    /// quota while running. `0` = switch to unlimited; a new non-zero
    /// rate resets to a full bucket of that rate (1s of quota — a switch
    /// starts a fresh metering window; leftover tokens from the old rate
    /// are not prorated across rates; simple and testable); re-entering
    /// the same rate is a no-op.
    pub fn set_rate(&self, ops_per_sec: u32) {
        let mut state = lock(&self.state);
        if state.as_ref().map(|s| s.rate) == Some(ops_per_sec) {
            return;
        }
        *state = (ops_per_sec != 0).then(|| GateState {
            tokens_milli: u64::from(ops_per_sec) * 1000,
            last: Instant::now(),
            rate: ops_per_sec,
        });
    }

    /// Non-blocking ticket: `Ok(())` = admitted within quota;
    /// `Err(wait)` = quota exhausted, retry after `wait` (`wait` <= 1s —
    /// the bucket holds at most 1s of quota, which bounds the wait).
    pub fn try_acquire(&self, ops: u32) -> Result<(), Duration> {
        self.try_acquire_at(ops, Instant::now())
    }

    /// Time-injected form of [`Self::try_acquire`] (test determinism;
    /// production goes through
    /// `try_acquire`/`acquire`/`acquire_blocking`).
    fn try_acquire_at(&self, ops: u32, now: Instant) -> Result<(), Duration> {
        let mut state = lock(&self.state);
        let Some(st) = state.as_ref() else {
            return Ok(());
        };
        let elapsed_ms = now.saturating_duration_since(st.last).as_millis() as u64;
        let rate = st.rate;
        let tokens_milli = st.tokens_milli;
        // Incremental refill (1/1000 op per ms per op/s), truncated at
        // bucket capacity.
        let capacity = u64::from(rate) * 1000;
        let tokens_milli = capacity.saturating_sub(
            capacity
                .saturating_sub(tokens_milli)
                .saturating_sub(elapsed_ms.saturating_mul(u64::from(rate))),
        );
        let want = u64::from(ops.max(1)) * 1000;
        if tokens_milli >= want {
            let st = state.as_mut().unwrap_or_else(|| unreachable!("Some above"));
            st.tokens_milli = tokens_milli - want;
            st.last = now;
            Ok(())
        } else {
            // Wait until enough tokens refill; a sub-millisecond
            // remainder floors at 1ms (spin defense).
            let shortage = want - tokens_milli;
            let wait_ms = (shortage / u64::from(rate)).max(1);
            let st = state.as_mut().unwrap_or_else(|| unreachable!("Some above"));
            st.tokens_milli = tokens_milli;
            st.last = now;
            Err(Duration::from_millis(wait_ms.min(1000)))
        }
    }

    /// Blocking ticket (async: on Err(wait), sleep(wait) and retry).
    pub async fn acquire(&self, ops: u32) {
        loop {
            match self.try_acquire(ops) {
                Ok(()) => return,
                Err(wait) => tokio::time::sleep(wait).await,
            }
        }
    }

    /// Synchronously blocking ticket (**blocking contexts only**: this
    /// method sleeps the thread internally, so callers must run inside
    /// `spawn_blocking`/on a blocking thread; async contexts use
    /// [`IoGate::acquire`]). Lets synchronous IO primitives
    /// ([`crate::torrent_writer::TorrentReader::read_coalesced`]) and
    /// write flushes share the same quota bucket.
    pub fn acquire_blocking(&self, ops: u32) {
        loop {
            match self.try_acquire(ops) {
                Ok(()) => return,
                Err(wait) => std::thread::sleep(wait),
            }
        }
    }
}

/// Live reading of the **effective** disk policy (the applied-policy
/// observability face): a snapshot taken after the store pipeline applies
/// a tier. Carries only the three parameters the pipeline can retarget at
/// runtime (quota/cadence/write-merge window) — allocation mode is a
/// construction-time one-shot (`StoreJob::allocate`) with no runtime
/// state. `flush_interval` keeps Option semantics (None = no cadence);
/// `tier` is omitted (tier -> parameters is a many-to-one expansion; the
/// parameters are the effective fact).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LivePolicy {
    /// Current IoGate quota (0 = unlimited).
    pub io_ops_per_sec: u32,
    /// Flush cadence (None = no periodic fsync).
    pub flush_interval: Option<Duration>,
    /// Write-merge window cap (0 = per-cell writes).
    pub write_merge_max_bytes: usize,
}

/// Shared atomic cell for [`LivePolicy`] (handed out via Arc: the
/// pipeline writes, engine command arms read — a lock-free observability
/// face; the data source for `QueryDiskPolicy` replies, not a config
/// mirror).
#[derive(Debug)]
pub struct LivePolicyCell {
    io_ops_per_sec: std::sync::atomic::AtomicU32,
    /// Second granularity; 0 = no cadence (atomic projection of None).
    flush_interval_secs: std::sync::atomic::AtomicU64,
    write_merge_max_bytes: std::sync::atomic::AtomicU64,
}

impl LivePolicyCell {
    /// Build the cell from an initial policy (called once at pipeline
    /// construction; the initial value is the construction-time policy).
    pub fn new(policy: DiskPolicy) -> LivePolicyCell {
        let cell = LivePolicyCell {
            io_ops_per_sec: std::sync::atomic::AtomicU32::new(0),
            flush_interval_secs: std::sync::atomic::AtomicU64::new(0),
            write_merge_max_bytes: std::sync::atomic::AtomicU64::new(0),
        };
        cell.store(&policy);
        cell
    }

    /// Written after the pipeline applies a tier (idempotent;
    /// sub-single-atomic-word races are harmless — the reading is only an
    /// observability face).
    pub fn store(&self, policy: &DiskPolicy) {
        use std::sync::atomic::Ordering::Relaxed;
        self.io_ops_per_sec.store(policy.io_ops_per_sec, Relaxed);
        self.flush_interval_secs.store(
            policy.flush_interval.map(|d| d.as_secs()).unwrap_or(0),
            Relaxed,
        );
        self.write_merge_max_bytes
            .store(policy.write_merge_max_bytes as u64, Relaxed);
    }

    /// Current effective reading (engine `QueryDiskPolicy` reply).
    pub fn get(&self) -> LivePolicy {
        use std::sync::atomic::Ordering::Relaxed;
        LivePolicy {
            io_ops_per_sec: self.io_ops_per_sec.load(Relaxed),
            flush_interval: match self.flush_interval_secs.load(Relaxed) {
                0 => None,
                secs => Some(Duration::from_secs(secs)),
            },
            write_merge_max_bytes: self.write_merge_max_bytes.load(Relaxed) as usize,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Tier parameter table (all three tiers table-driven; dedicated
    // default zero-change checks).
    // ------------------------------------------------------------------

    /// Table-driven: assert every cell of all three tiers (the single
    /// parameter source is `DiskTier::policy`).
    #[test]
    fn tier_parameter_table_is_complete() {
        // throughput: every parameter = the existing behavior (trunc
        // allocation, no merging, no cadence, unlimited, 1:1 reads).
        let t = DiskTier::Throughput.policy();
        assert_eq!(t.tier, DiskTier::Throughput);
        assert_eq!(
            t.allocation,
            AllocationMode::Trunc,
            "the default tier allocates = trunc"
        );
        assert_eq!(
            t.write_merge_max_bytes, 0,
            "the default tier merges no writes (per cell = existing)"
        );
        assert_eq!(
            t.flush_interval, None,
            "the default tier has no periodic fsync (existing behavior)"
        );
        assert_eq!(t.io_ops_per_sec, 0, "the default tier is unlimited");
        assert_eq!(
            t.read_merge_max_bytes, 0,
            "the default tier reads 1:1 (existing)"
        );
        assert_eq!(t.read_merge_max_ranges, 0);

        let s = DiskTier::SsdProtect.policy();
        assert_eq!(s.tier, DiskTier::SsdProtect);
        assert_eq!(
            s.allocation,
            AllocationMode::Falloc,
            "the SSD tier intends falloc"
        );
        assert!(
            s.write_merge_max_bytes > 0,
            "the SSD tier enables write merging (less write amplification)"
        );
        assert!(
            s.flush_interval.is_some(),
            "the SSD tier has a flush cadence"
        );
        assert!(s.io_ops_per_sec > 0, "the SSD tier has an ops quota");
        assert!(s.read_merge_max_bytes > 0 && s.read_merge_max_ranges > 0);

        let h = DiskTier::HddSequential.policy();
        assert_eq!(h.tier, DiskTier::HddSequential);
        assert_eq!(
            h.allocation,
            AllocationMode::Prealloc,
            "the HDD tier preallocates fully to avoid fragmentation"
        );
        assert!(
            h.write_merge_max_bytes > s.write_merge_max_bytes,
            "HDD merges more (sequentializing)"
        );
        assert_eq!(
            h.flush_interval,
            Some(Duration::from_secs(60)),
            "60s cross-validation: aria2 auto-save-interval default"
        );
        assert!(
            h.io_ops_per_sec < s.io_ops_per_sec,
            "the HDD quota is tighter (low physical IOPS)"
        );
        assert!(
            h.read_merge_max_bytes > s.read_merge_max_bytes,
            "HDD read merging is larger (seek avoidance)"
        );
        assert!(h.read_merge_max_ranges > s.read_merge_max_ranges);
    }

    /// Dedicated zero-change check: default = throughput and every
    /// parameter equals the existing behavior exactly (the parameter-face
    /// definition of zero change; the behavior face is backed by path
    /// tests via 0 write/read merge caps + trunc allocation + no cadence).
    #[test]
    fn default_policy_is_throughput_and_frozen() {
        assert_eq!(DiskPolicy::default(), DiskTier::Throughput.policy());
        assert_eq!(DiskPolicy::default().tier, DiskTier::Throughput);
        assert_eq!(DiskPolicy::default().allocation, AllocationMode::Trunc);
        assert_eq!(DiskPolicy::default().write_merge_max_bytes, 0);
        assert_eq!(DiskPolicy::default().flush_interval, None);
        assert_eq!(DiskPolicy::default().io_ops_per_sec, 0);
        assert_eq!(DiskPolicy::default().read_merge_max_bytes, 0);
        assert_eq!(DiskPolicy::default().read_merge_max_ranges, 0);
    }

    /// Tier-name roundtrip + unknown-name rejection (the config_json
    /// internal-face value domain; the `Err` carries the rejected name).
    #[test]
    fn tier_name_roundtrip_and_unknown_fallback() {
        for tier in [
            DiskTier::Throughput,
            DiskTier::SsdProtect,
            DiskTier::HddSequential,
        ] {
            assert_eq!(tier.name().parse::<DiskTier>(), Ok(tier));
        }
        // Case/whitespace tolerance.
        assert_eq!(
            " SSD-Protect ".parse::<DiskTier>(),
            Ok(DiskTier::SsdProtect)
        );
        // Unknown name -> Err carrying the name verbatim -> resolve falls
        // back to the default tier (an observable warn).
        assert_eq!(
            "turbo".parse::<DiskTier>(),
            Err(UnknownTierName("turbo".to_string()))
        );
        assert_eq!(DiskPolicy::resolve(Some("turbo")), DiskPolicy::default());
    }

    /// resolve over all states: None -> default tier; Some(valid) -> that
    /// tier; Some(invalid) -> default tier.
    #[test]
    fn resolve_override_matrix() {
        assert_eq!(DiskPolicy::resolve(None), DiskTier::Throughput.policy());
        assert_eq!(
            DiskPolicy::resolve(Some("hdd-sequential")),
            DiskTier::HddSequential.policy()
        );
        assert_eq!(
            DiskPolicy::resolve(Some("ssd-protect")),
            DiskTier::SsdProtect.policy()
        );
    }

    // ------------------------------------------------------------------
    // IoGate (the quota face; deterministic via injected time).
    // ------------------------------------------------------------------

    /// A 0 quota = unlimited passthrough (zero overhead for the default
    /// tier).
    #[test]
    fn gate_zero_rate_is_unlimited_passthrough() {
        let gate = IoGate::new(0);
        assert!(gate.is_unlimited());
        for _ in 0..10_000 {
            assert!(gate.try_acquire(1).is_ok(), "unlimited always admits");
        }
        assert!(IoGate::unlimited().is_unlimited());
    }

    /// Initial bucket = 1s of quota: a full bucket drains in one take; an
    /// immediate follow-up must wait (the burst ceiling).
    #[test]
    fn gate_full_bucket_drains_then_throttles() {
        let gate = IoGate::new(100);
        let t0 = Instant::now();
        // Full bucket = 100 ops.
        assert!(
            gate.try_acquire_at(100, t0).is_ok(),
            "a full bucket takes the whole 1s quota at once"
        );
        // Quota exhausted -> an immediate take must throttle (wait <= 1s
        // capacity bound).
        match gate.try_acquire_at(1, t0) {
            Err(wait) => {
                assert_eq!(wait, Duration::from_millis(10), "1 op @100/s = 10ms");
            }
            Ok(()) => panic!("must throttle once the quota is exhausted"),
        }
    }

    /// Refill rate = quota: at 100 ops/s, 10ms after exhaustion exactly
    /// 1 op has refilled (deterministic).
    #[test]
    fn gate_refill_rate_matches_quota() {
        let gate = IoGate::new(100);
        let t0 = Instant::now();
        assert!(gate.try_acquire_at(100, t0).is_ok());
        // After 10ms: 1 op refilled -> 1 more admissible.
        assert!(
            gate.try_acquire_at(1, t0 + Duration::from_millis(10))
                .is_ok()
        );
        // Taking again at the same instant: empty again -> the wait is
        // back at the 10ms scale.
        match gate.try_acquire_at(1, t0 + Duration::from_millis(10)) {
            Err(wait) => assert_eq!(wait, Duration::from_millis(10)),
            Ok(()) => panic!("must throttle"),
        }
    }

    /// IO fairness (quota face): after a read burst drains the bucket,
    /// the write flush's wait is **bounded** and it can acquire again;
    /// the read side is limited by the same token — neither side can
    /// starve the other permanently.
    #[test]
    fn gate_quota_bounds_starvation_for_both_sides() {
        let gate = IoGate::new(512);
        let t0 = Instant::now();
        // The "read server" burst drains the whole bucket.
        assert!(gate.try_acquire_at(512, t0).is_ok());
        // The "write flush" (1 op) must wait: 512 ops/s -> ~2ms, bounded.
        let write_wait = match gate.try_acquire_at(1, t0) {
            Err(w) => w,
            Ok(()) => panic!("flush must throttle once the bucket is empty"),
        };
        assert!(
            write_wait <= Duration::from_secs(1),
            "the flush wait is bounded"
        );
        // The "read" side is limited too (quota binds both sides; no
        // one-sided privilege).
        assert!(
            gate.try_acquire_at(1, t0).is_err(),
            "the read side is limited too — quota fairness"
        );
        // After the refill window both sides admit again (no permanent
        // starvation).
        let t1 = t0 + write_wait + Duration::from_millis(1);
        assert!(gate.try_acquire_at(1, t1).is_ok(), "flush recovers");
        if let Err(w) = gate.try_acquire_at(1, t1) {
            assert!(w <= Duration::from_secs(1), "the read side waits boundedly");
        }
    }

    /// Capacity truncation: no accumulation across seconds (capacity = 1s
    /// of quota). After 10s idle at 50 ops/s the bucket holds at most 50
    /// (truncated), never an accumulated 550.
    #[test]
    fn gate_capacity_is_one_second_worth() {
        let gate = IoGate::new(50);
        let t0 = Instant::now();
        assert!(
            gate.try_acquire_at(50, t0).is_ok(),
            "the initial bucket is full"
        );
        // Idle 10s (refill far beyond capacity) -> truncation caps the
        // bucket back at 50.
        assert!(
            gate.try_acquire_at(51, t0 + Duration::from_secs(10))
                .is_err(),
            "a take beyond capacity must be refused (the truncation face)"
        );
        assert!(
            gate.try_acquire_at(50, t0 + Duration::from_secs(10))
                .is_ok(),
            "after truncation exactly the 1s quota is takeable"
        );
    }

    // ------------------------------------------------------------------
    // Live retargeting (the store half of the live disk_tier RPC face).
    // ------------------------------------------------------------------

    /// set_rate: limited -> unlimited -> limited roundtrip; same-rate
    /// re-entry is a no-op; a switch = a full bucket of the new rate
    /// (leftover tokens from the old rate are not prorated across rates —
    /// documented semantics).
    #[test]
    fn gate_set_rate_retargets_live() {
        let gate = IoGate::new(100);
        assert!(!gate.is_unlimited());
        // Drain the whole bucket (100 @100/s).
        let t0 = Instant::now();
        assert!(gate.try_acquire_at(100, t0).is_ok());
        // While throttled -> switch to 0 = unlimited: tickets always
        // pass.
        gate.set_rate(0);
        assert!(gate.is_unlimited());
        for _ in 0..1000 {
            assert!(
                gate.try_acquire_at(1, t0).is_ok(),
                "unlimited passes straight through"
            );
        }
        // Switch back to 512: full bucket = 1s of quota (512); an
        // immediate take is limited.
        gate.set_rate(512);
        assert!(!gate.is_unlimited());
        let t1 = Instant::now();
        assert!(
            gate.try_acquire_at(512, t1).is_ok(),
            "retargeting = a full bucket of the new rate"
        );
        assert!(
            gate.try_acquire_at(1, t1).is_err(),
            "takes are limited once full (the retarget reset took effect)"
        );
        // Same-rate re-entry = no-op (the bucket is not reset — an empty
        // bucket still limits).
        gate.set_rate(512);
        assert!(
            gate.try_acquire_at(1, t1).is_err(),
            "re-entry does not reset the bucket"
        );
    }

    /// LivePolicyCell: initial/store/get roundtrip (None cadence <->
    /// 0-second projection).
    #[test]
    fn live_policy_cell_roundtrip() {
        let cell = LivePolicyCell::new(DiskTier::Throughput.policy());
        assert_eq!(
            cell.get(),
            LivePolicy {
                io_ops_per_sec: 0,
                flush_interval: None,
                write_merge_max_bytes: 0,
            },
            "initial = throughput (the zero-change tier)"
        );
        cell.store(&DiskTier::HddSequential.policy());
        assert_eq!(
            cell.get(),
            LivePolicy {
                io_ops_per_sec: 512,
                flush_interval: Some(Duration::from_secs(60)),
                write_merge_max_bytes: 4 * 1024 * 1024,
            },
            "reads follow after storing hdd-sequential"
        );
    }

    /// The NAMES registry and the FromStr value domain are the same
    /// source (single source of truth locked for capability discovery /
    /// parameter validation).
    #[test]
    fn tier_names_registry_matches_from_str() {
        assert_eq!(DiskTier::NAMES.len(), 3);
        for name in DiskTier::NAMES {
            let tier: DiskTier = name.parse().unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(tier.name(), *name, "{name} roundtrip");
        }
        // Unknown names are not in the registry.
        assert!(!DiskTier::NAMES.contains(&"turbo"));
    }
}
