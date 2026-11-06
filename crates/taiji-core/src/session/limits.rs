//! The session rate-limit execution face (SPEC §3.3/§7.3): the global
//! bucket (shared across tasks) + the global quota snapshot (arc-swap
//! hot-update publication) + per-torrent chained-set assembly.
//!
//! - Execution face: [`taiji_io::rate_limit`] (io-layer token buckets);
//! this module is the session side's **assembly and hot-update
//! handle**.
//! - Hot-update chain: changeGlobalOption ->
//! [`SpeedLimits::set_overall`] (snapshot arc-swap store + atomic
//! bucket rate change — the direct translation of RpcMethodImpl.cc's
//! setMaxOverallDownload/UploadSpeedLimit) -> takes effect
//! immediately for all running engines' `Throttled` streams through
//! the shared bucket; changeOption's per-task limits
//! (max-download-limit/max-upload-limit) apply live via the
//! `set_rate` of [`LimiterSet`]'s per_torrent bucket.
//! - `0 = unlimited` (the SPEC §11 frozen default): a bucket-level
//! short circuit; a session cold-starts with all-default limits of 0
//! -> zero overhead.
//! - The snapshot read side is lock-free (arc-swap `load`); the write
//! side is only the session actor (single writer).

use std::sync::Arc;

use arc_swap::ArcSwap;

use taiji_io::rate_limit::{LimiterPair, LimiterSet, TokenBucket};

/// The global (overall) quota snapshot (bytes/sec; 0 = unlimited).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverallLimits {
    /// `--max-overall-download-limit`.
    pub download: u64,
    /// `--max-overall-upload-limit`.
    pub upload: u64,
}

/// The session-level rate-limit handle: the global bucket pair (shared
/// instances across tasks) + the global quota snapshot.
///
/// Clone = the same execution face (the bucket Arcs are shared); the
/// session actor holds one, and each engine mounts the shared global
/// buckets into the task's chained set via [`SpeedLimits::torrent_set`]
/// at assembly time.
#[derive(Clone)]
pub struct SpeedLimits {
    snap: Arc<ArcSwap<OverallLimits>>,
    /// The global download bucket (shared across tasks; a hot update on
    /// this instance reaches every task).
    global_down: Arc<TokenBucket>,
    /// The global upload bucket.
    global_up: Arc<TokenBucket>,
}

impl SpeedLimits {
    /// Build from the initial global quotas (`0 = unlimited`).
    pub fn new(overall_down: u64, overall_up: u64) -> SpeedLimits {
        SpeedLimits {
            snap: Arc::new(ArcSwap::from_pointee(OverallLimits {
                download: overall_down,
                upload: overall_up,
            })),
            global_down: Arc::new(TokenBucket::new(overall_down)),
            global_up: Arc::new(TokenBucket::new(overall_up)),
        }
    }

    /// The current global quota snapshot (lock-free arc-swap read
    /// side).
    pub fn overall(&self) -> OverallLimits {
        **self.snap.load()
    }

    /// changeGlobalOption hot update: snapshot store + atomic bucket
    /// rate change (waiters wake and re-evaluate) — takes effect
    /// immediately for all running engines.
    pub fn set_overall(&self, overall_down: u64, overall_up: u64) {
        self.snap.store(Arc::new(OverallLimits {
            download: overall_down,
            upload: overall_up,
        }));
        self.global_down.set_rate(overall_down);
        self.global_up.set_rate(overall_up);
    }

    /// The global bucket pair (Arc-shared; engine-side [`LimiterSet`]
    /// assembly).
    pub fn global_pair(&self) -> LimiterPair {
        LimiterPair {
            down: Arc::clone(&self.global_down),
            up: Arc::clone(&self.global_up),
        }
    }

    /// Assemble the per-torrent chained set: the global pair = the
    /// session-shared instances (Arc clones); the per_torrent pair =
    /// this module's independent buckets (`0 = unlimited`).
    pub fn torrent_set(&self, per_down: u64, per_up: u64) -> Arc<LimiterSet> {
        Arc::new(LimiterSet {
            global: self.global_pair(),
            per_torrent: LimiterPair::new(per_down, per_up),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Topology sharing: torrent_set's global pair is the same instance
    /// as the handle's buckets (the hot-update sharing face);
    /// per_torrent is independent.
    #[test]
    fn torrent_set_shares_global_buckets_and_isolates_torrent_pair() {
        let limits = SpeedLimits::new(0, 0);
        let a = limits.torrent_set(1000, 2000);
        let b = limits.torrent_set(3000, 4000);
        assert!(
            Arc::ptr_eq(&a.global.down, &b.global.down),
            "global bucket must be shared across tasks"
        );
        assert!(
            !Arc::ptr_eq(&a.per_torrent.down, &b.per_torrent.down),
            "per-torrent buckets must be independent"
        );
        assert_eq!(a.per_torrent.down.rate(), 1000);
        assert_eq!(b.per_torrent.down.rate(), 3000);
    }

    /// set_overall hot update: the snapshot + shared buckets visible
    /// immediately (including 0 -> finite and finite -> 0).
    #[test]
    fn set_overall_hot_updates_snapshot_and_shared_buckets() {
        let limits = SpeedLimits::new(0, 0);
        let set = limits.torrent_set(0, 0);
        assert!(set.global.down.is_unlimited());
        limits.set_overall(1024 * 1024, 512 * 1024);
        let overall = limits.overall();
        assert_eq!(overall.download, 1024 * 1024);
        assert_eq!(overall.upload, 512 * 1024);
        // The existing chained set (same shared buckets) takes effect
        // immediately.
        assert_eq!(set.global.down.rate(), 1024 * 1024);
        assert!(!set.global.down.is_unlimited());
        assert_eq!(set.global.up.rate(), 512 * 1024);
        // Back to unlimited: the short circuit resumes.
        limits.set_overall(0, 0);
        assert!(set.global.down.is_unlimited());
        assert_eq!(
            limits.overall(),
            OverallLimits {
                download: 0,
                upload: 0
            }
        );
    }
}
