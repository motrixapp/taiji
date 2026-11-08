//! Process-wide unverified-byte ledger.
//!
//! The wr_cache / block_arena unverified-byte budgets are sized **per
//! face** (`max(16MiB, 2×peer_max×piece_len)`, the single pipeline.rs
//! formula); a hybrid torrent doubles it and ×max-concurrent-downloads
//! multiplies again — 5 default tasks already reach 600MiB-1.2GiB, and
//! RPC `changeGlobalOption` can raise concurrency without bound. This
//! module puts a total ceiling on the unverified bytes **resident across
//! all in-process WrDiskCaches**:
//!
//! - Admission point = `taiji_store::cache::WrDiskCache::update_min_loss`
//!   (a second, global gate on top of each face's existing LRU eviction:
//!   a face over the global cap **evicts its own data** to make room and
//!   never touches other faces); release points = negative deltas /
//!   eviction / detachment / Drop.
//! - When a claim fails and the claimer has nothing of its own to evict,
//!   the claim is **forced** (the bytes have already arrived in RAM and
//!   cannot be dropped) — so the total ceiling = cap + one increment
//!   (cell granularity): soft-cap semantics.
//! - Default 384MiB: 5 default concurrent single-face tasks (5×60MiB =
//!   300MiB) always fit inside the cap with **zero behavior change**;
//!   hybrid / higher concurrency tightens gently from inside the cap
//!   (evicting an over-cap face amplifies wire re-fetch — the cap is
//!   deliberately wider than the default load).
//! - Knob `BH_SESSION_UNVERIFIED_BYTES` (u64 bytes, default 384MiB,
//!   clamped [128MiB, 4GiB] — the lower bound keeps the knob from
//!   starving unverified buffering, the upper bound keeps the OOM guard
//!   from being inflated back; registry in `knobs`).
//!
//! block_arena is not accounted: pool rentals are already strictly
//! budgeted by the face-level `cap_bytes` (`claim_budget` rolls claims
//! back), and the direct-allocation fallback is a **transient** decode
//! buffer (lifetime = one block send/receive, bounded by the Σ in-flight
//! window) — a demand-driven working set, not a resident multiplication
//! face.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicI64, Ordering};

/// Default cap (384MiB; sizing rationale in the module docs).
pub const DEFAULT_SESSION_UNVERIFIED_BYTES: usize = 384 * 1024 * 1024;
/// Knob lower bound.
pub const MIN_SESSION_UNVERIFIED_BYTES: usize = 128 * 1024 * 1024;
/// Knob upper bound.
pub const MAX_SESSION_UNVERIFIED_BYTES: usize = 4 * 1024 * 1024 * 1024;

static USED: AtomicI64 = AtomicI64::new(0);
static CAP: OnceLock<usize> = OnceLock::new();

fn cap() -> usize {
    *CAP.get_or_init(crate::knobs::session_unverified_bytes)
}

/// Cap value (parsed once and cached; observation/test face).
pub fn cap_value() -> usize {
    cap()
}

/// Claim `bytes`; deny and roll back when over cap (`Err` carries a
/// (post-claim use, cap) snapshot).
pub fn claim(bytes: usize) -> Result<(), (i64, usize)> {
    let b = bytes as i64;
    let prev = USED.fetch_add(b, Ordering::Relaxed);
    if prev + b <= cap() as i64 {
        Ok(())
    } else {
        USED.fetch_sub(b, Ordering::Relaxed);
        Err((prev + b, cap()))
    }
}

/// Forced claim (the bytes are already in RAM and cannot be dropped —
/// the soft cap's bounded-overshoot path).
pub fn force_claim(bytes: usize) {
    if bytes > 0 {
        USED.fetch_add(bytes as i64, Ordering::Relaxed);
    }
}

/// Release (saturating, defending against underflow).
pub fn release(bytes: usize) {
    if bytes > 0 {
        let prev = USED.fetch_sub(bytes as i64, Ordering::Relaxed);
        debug_assert!(
            prev >= bytes as i64,
            "ledger underflow: releasing {bytes} > on-ledger {prev}"
        );
        let _ = prev;
    }
}

/// On-ledger byte snapshot (observation/test face).
pub fn used() -> i64 {
    USED.load(Ordering::Relaxed)
}

/// Test seam: change the cap (valid only before the first
/// `cap_value`/`claim` — ignored once the OnceLock has been filled;
/// parallel tests must not depend on changing the cap, see the cache
/// decision-table unit-test convention).
#[doc(hidden)]
pub fn set_cap_for_tests(cap: usize) -> bool {
    CAP.set(cap).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decision table: claim / deny / force / release / clamp primitives.
    #[test]
    fn claim_deny_force_release_primitives() {
        let base = used();
        // Claim within the cap.
        claim(1024).unwrap_or_else(|_| panic!("a claim within the cap must succeed"));
        assert_eq!(used(), base + 1024);
        // Fill to cap-1 -> a 2B claim is denied and rolled back.
        let fill = cap_value() as i64 - 1 - (used() - base);
        assert!(fill > 0);
        force_claim(fill as usize);
        let denied = match claim(2) {
            Err(d) => d,
            Ok(()) => panic!("over-cap must be denied"),
        };
        assert_eq!(denied.1, cap_value(), "Err carries a cap snapshot");
        assert_eq!(used(), base + cap_value() as i64 - 1, "denial rolls back");
        // 1B exactly fits the cap; the next 1B is denied.
        claim(1).unwrap_or_else(|_| panic!("a claim exactly filling the cap must succeed"));
        assert!(
            claim(1).is_err(),
            "a claim against a full cap must be denied"
        );
        // Forced claim (soft-cap overshoot) -> release back to baseline.
        force_claim(7);
        release(fill as usize + 1024 + 1 + 7);
        assert_eq!(used(), base, "release returns to baseline");
    }

    /// Knob default/clamp anchors (cap value and default constants).
    #[test]
    fn defaults_and_clamps_anchored() {
        assert_eq!(DEFAULT_SESSION_UNVERIFIED_BYTES, 384 * 1024 * 1024);
        assert_eq!(MIN_SESSION_UNVERIFIED_BYTES, 128 * 1024 * 1024);
        assert_eq!(MAX_SESSION_UNVERIFIED_BYTES, 4 * 1024 * 1024 * 1024);
        // No env var -> cap = default (test processes never set
        // BH_SESSION_UNVERIFIED_BYTES).
        assert_eq!(cap_value(), DEFAULT_SESSION_UNVERIFIED_BYTES);
    }
}
