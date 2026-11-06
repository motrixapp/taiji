//! The three synthesis prechecks (the media spec's synthesis line —
//! the adopted precheck faces + the both-channels
//! terminal state).
//!
//! ① **Disk precheck** ([`disk_precheck`]) — before entering
//! Processing: merge/mux keeps the staged tracks **and** the
//! product side by side, peak ≈ 2× product + margin. The product
//! estimate is Σ staged archive bytes (remux, `-c copy` family —
//! no re-encode growth). A precheck that cannot be obtained
//! (network mount, stat failure, non-unix without a face) is an
//! **optimistic pass** — ENOSPC during synthesis surfaces through
//! the existing error face (`taiji.media.staging` on the write).
//!
//! ② **Both-channels-failed terminal state** — owned by the pipeline
//! ([`crate::synth`]): native + ffmpeg both failed → task **Error**
//! (the compound error keeps the last channel's inherited code and
//! names both failures in its text — no new error code here),
//! staged tracks and staging **retained** (Processing
//! idempotent re-run = the retry), warning recorded in the report
//! for the session's event emission face.
//!
//! ③ **Sidecar start precheck** ([`sidecar_start_precheck`]) — when
//! the task's form **may trigger the fallback channel**, check the
//! discovery/assertion face **before the first segment is
//! fetched** (no wasted whole-track traffic): fallback-required
//! form + no usable pair → `taiji.media.ffmpeg_missing` at start;
//! fallback-optional form + no pair → proceed native-only with a
//! degraded-dual-channel warning. The decision function
//! ([`FallbackNeed`]) and the precheck action live here;
//! task-activation-chain wiring is the session's.

use std::path::Path;

use crate::error::MediaError;

/// Headroom added on top of the 2×-product peak (the recorded
/// margin form; 64 MiB — covers moov tables, sidecars and
/// filesystem overhead).
pub const PRECHECK_MARGIN_BYTES: u64 = 64 * 1024 * 1024;

/// Whether a form needs the ffmpeg channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FallbackNeed {
    /// Native unsupported (TS-source line pre-0.4, MKV output, matrix
    /// degraded item, user-explicit) → the ffmpeg channel is the only
    /// path: a missing pair is `ffmpeg_missing` at start.
    Required { reason: String },
    /// Native primary with ffmpeg as the safety net: a missing pair
    /// degrades to native-only (warning), never blocks start.
    Optional,
    /// Pure-native form: the sidecar face is irrelevant.
    None,
}

/// Disk precheck verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiskVerdict {
    /// Free space covers 2× product + margin.
    Pass,
    /// Insufficient: refuse to enter Processing (task error, staging
    /// retained — the degraded face; the pipeline maps this to the staging
    /// error family).
    Insufficient { need: u64, free: u64 },
    /// Free space unobtainable (network mount/stat failure/no
    /// platform face) → optimistic pass.
    UnknownOptimistic,
}

/// The peak-need formula (pure; the exported seam the tests pin):
/// `2 × product + margin`.
pub fn peak_need(product_estimate_bytes: u64) -> u64 {
    product_estimate_bytes
        .saturating_mul(2)
        .saturating_add(PRECHECK_MARGIN_BYTES)
}

/// Run the disk precheck for an explicitly-known free byte count.
pub fn disk_precheck(free_bytes: Option<u64>, product_estimate_bytes: u64) -> DiskVerdict {
    let need = peak_need(product_estimate_bytes);
    match free_bytes {
        Some(free) if free >= need => DiskVerdict::Pass,
        Some(free) => DiskVerdict::Insufficient { need, free },
        None => DiskVerdict::UnknownOptimistic,
    }
}

/// Query the free bytes of the volume holding `path` (unix: statfs
/// through rustix's safe wrapper — no out-param, no unsafe; other
/// platforms: no face — the optimistic path, documented). A stat
/// failure is also `None` (optimistic), never a task error at
/// precheck time.
pub fn volume_free_bytes(path: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        match rustix::fs::statfs(path) {
            Ok(stat) => {
                // `f_bsize` is u32 on darwin but signed `c_long`
                // (i64) on linux/musl — only the fallible conversion
                // covers both faces (f_bsize is non-negative in
                // practice; the 0 arm is defensive only). Darwin
                // clippy flags the try_from as unnecessary_fallible;
                // the allow is scoped to this arm, not the workspace.
                #[allow(clippy::unnecessary_fallible_conversions)]
                let bsize = u64::try_from(stat.f_bsize).unwrap_or(0);
                Some(stat.f_bavail * bsize)
            }
            Err(_) => None,
        }
    }
    #[cfg(not(unix))]
    {
        // No statfs face without a Windows dependency; the
        // optimistic path carries this platform (documented in
        // docs/design/media-synthesis.md).
        let _ = path;
        None
    }
}

/// Sidecar start precheck verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartVerdict {
    /// Proceed.
    Proceed,
    /// Fallback-required form with no usable pair: `ffmpeg_missing`
    /// at start — **zero segment traffic** (the caller asserts by
    /// never starting the download; the error carries the reason).
    FfmpegMissing(MediaError),
    /// Native-only with the dual-channel safety net absent (warning
    /// text for the report; the verdict-table degraded form).
    NativeOnlyWarning(String),
}

/// The start precheck (③). `pair_present` = a discovered, asserted
/// ffmpeg pair exists. Absent-but-needed → the error; absent-but-
/// optional → the warning.
pub fn sidecar_start_precheck(need: &FallbackNeed, pair_present: bool) -> StartVerdict {
    match need {
        FallbackNeed::None => StartVerdict::Proceed,
        FallbackNeed::Optional if pair_present => StartVerdict::Proceed,
        FallbackNeed::Optional => StartVerdict::NativeOnlyWarning(
            "ffmpeg fallback unavailable (not found/asserted); \
             native channel only"
                .to_string(),
        ),
        FallbackNeed::Required { .. } if pair_present => StartVerdict::Proceed,
        FallbackNeed::Required { reason } => {
            StartVerdict::FfmpegMissing(MediaError::Missing(format!(
                "task form requires the ffmpeg channel ({reason}) but no \
                 usable pair was discovered — refusing before any segment \
                 traffic"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ① Disk precheck: pass / insufficient / optimistic, with the
    /// 2× + margin formula.
    #[test]
    fn disk_precheck_faces() {
        let product = 1000;
        let need = peak_need(product);
        assert_eq!(need, 2000 + PRECHECK_MARGIN_BYTES);
        assert_eq!(disk_precheck(Some(need), product), DiskVerdict::Pass);
        let DiskVerdict::Insufficient { need: n, free: f } = disk_precheck(Some(need - 1), product)
        else {
            panic!("insufficient shape");
        };
        assert_eq!(n, need);
        assert_eq!(f, need - 1);
        assert_eq!(disk_precheck(None, product), DiskVerdict::UnknownOptimistic);
        // Zero product: only the margin is needed.
        assert_eq!(
            disk_precheck(Some(PRECHECK_MARGIN_BYTES), 0),
            DiskVerdict::Pass
        );
        // Saturating on absurd estimates.
        assert_eq!(peak_need(u64::MAX), u64::MAX);
    }

    /// Real volume query returns Some on unix dev machines (the
    /// optimistic path stays for stat failures).
    #[test]
    fn volume_free_bytes_real() {
        let free = volume_free_bytes(std::env::temp_dir().as_path());
        #[cfg(unix)]
        {
            match free {
                Some(f) => assert!(f > 0, "statfs reports a positive free figure"),
                None => panic!("temp dir statfs must answer on unix"),
            }
        }
        #[cfg(not(unix))]
        {
            assert_eq!(free, None, "no face off unix — optimistic");
        }
    }

    /// ③ Start precheck: required/optional/none × pair present/absent.
    #[test]
    fn start_precheck_matrix() {
        let none = FallbackNeed::None;
        assert_eq!(sidecar_start_precheck(&none, false), StartVerdict::Proceed);
        let optional = FallbackNeed::Optional;
        assert_eq!(
            sidecar_start_precheck(&optional, true),
            StartVerdict::Proceed
        );
        match sidecar_start_precheck(&optional, false) {
            StartVerdict::NativeOnlyWarning(w) => assert!(w.contains("native")),
            other => panic!("unexpected {other:?}"),
        }
        let required = FallbackNeed::Required {
            reason: "mkv output".to_string(),
        };
        assert_eq!(
            sidecar_start_precheck(&required, true),
            StartVerdict::Proceed
        );
        match sidecar_start_precheck(&required, false) {
            StartVerdict::FfmpegMissing(e) => {
                assert_eq!(e.code(), "taiji.media.ffmpeg_missing");
                assert!(e.to_string().contains("mkv output"));
                assert!(e.to_string().contains("segment traffic"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
