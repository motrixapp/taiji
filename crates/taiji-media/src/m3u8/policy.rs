//! Variant selection policy.
//!
//! Pure function face of the `--media-variant-policy` CLI flag
//! (`highest|resolution=<H>|bandwidth=<B>`; the flag
//! itself registers on the unified option surface).
//!
//! Semantics (documented ruling — the spec names the forms, not the
//! tie-breaks):
//!
//! * `highest` (default): maximum BANDWIDTH; ties broken by
//!   resolution, then declaration order;
//! * `resolution=<H>`: among variants whose RESOLUTION height is
//!   **≤ H**, the same ordering as `highest` (a cap, matching the
//!   SPEC-Media selector predicate family `res<=`); variants without
//!   a RESOLUTION attribute are ineligible — an unmeasurable cap
//!   candidate is never guessed;
//! * `bandwidth=<B>`: maximum BANDWIDTH **≤ B**; an exact B match is
//!   not required;
//! * an empty candidate set is an explicit `variant_policy` error,
//!   never a silent fallback to a different variant;
//! * `EXT-X-I-FRAME-STREAM-INF` renditions are excluded from every
//!   policy (trick-play only, RFC 8216 §4.3.4.3) — an i-frame playlist
//!   selected by hand fails later as `iframes_unsupported` at its own
//!   media-playlist parse.

use super::model::{MasterPlaylist, Variant};
use crate::error::MediaError;

/// Variant selection policy value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum VariantPolicy {
    /// `highest` — maximum bandwidth (default).
    #[default]
    Highest,
    /// `resolution=<H>` — best variant with height ≤ H.
    Resolution { height: u32 },
    /// `bandwidth=<B>` — best variant with bandwidth ≤ B.
    Bandwidth { bits_per_second: u64 },
}

impl VariantPolicy {
    /// Parse the flag value (`highest`, `resolution=720`,
    /// `bandwidth=5000000`). Whitespace-tolerant; anything else is a
    /// `variant_policy` error.
    pub fn parse(input: &str) -> Result<Self, MediaError> {
        let input = input.trim();
        if input.eq_ignore_ascii_case("highest") {
            return Ok(Self::Highest);
        }
        if let Some(h) = input.strip_prefix("resolution=") {
            let height = h
                .trim()
                .parse::<u32>()
                .map_err(|_| bad_policy(input, "resolution must be a height in pixels"))?;
            return Ok(Self::Resolution { height });
        }
        if let Some(b) = input.strip_prefix("bandwidth=") {
            let bits_per_second = b
                .trim()
                .parse::<u64>()
                .map_err(|_| bad_policy(input, "bandwidth must be bits per second"))?;
            return Ok(Self::Bandwidth { bits_per_second });
        }
        Err(bad_policy(
            input,
            "expected highest, resolution=<H> or bandwidth=<B>",
        ))
    }
}

fn bad_policy(input: &str, why: &str) -> MediaError {
    MediaError::VariantPolicy(format!("--media-variant-policy {input:?}: {why}"))
}

/// Select the variant row the policy names.
pub fn select_variant<'a>(
    master: &'a MasterPlaylist,
    policy: &VariantPolicy,
) -> Result<&'a Variant, MediaError> {
    let candidates: Vec<&Variant> = match *policy {
        VariantPolicy::Highest => master.variants.iter().collect(),
        VariantPolicy::Resolution { height } => master
            .variants
            .iter()
            .filter(|v| v.resolution.is_some_and(|(_, h)| h <= height))
            .collect(),
        VariantPolicy::Bandwidth {
            bits_per_second: cap,
        } => master
            .variants
            .iter()
            .filter(|v| v.bandwidth <= cap)
            .collect(),
    };
    // min_by with a reversed comparator: min_by keeps the FIRST of
    // equal elements, so the declaration-order tiebreak holds (max_by
    // would keep the last).
    let Some(best) = candidates
        .into_iter()
        .min_by(|a, b| variant_rank(b).cmp(&variant_rank(a)))
    else {
        return Err(MediaError::VariantPolicy(match *policy {
            VariantPolicy::Highest => {
                "master playlist declares no EXT-X-STREAM-INF variant".to_owned()
            }
            VariantPolicy::Resolution { .. } => {
                "no variant satisfies the resolution cap".to_owned()
            }
            VariantPolicy::Bandwidth { .. } => "no variant satisfies the bandwidth cap".to_owned(),
        }));
    };
    Ok(best)
}

/// Ordering key: bandwidth, then resolution height.
fn variant_rank(v: &Variant) -> (u64, u32) {
    (v.bandwidth, v.resolution.map_or(0, |(_, h)| h))
}
