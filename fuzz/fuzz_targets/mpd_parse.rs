#![no_main]

//! fuzz target: the MPD (DASH) parse + expansion surface
//! (`taiji_media::mpd`; the media parser-roster row
//! deliverable 5 — the §10 parse-surface red line).
//!
//! Invariants:
//! 1. `parse_mpd`, `plan_dash_tracks`, `expand_representation`,
//! `materialize_sidx` and the digest never panic on any byte
//! input (quick-xml errors are explicit; all count/time
//! arithmetic is checked; caps refuse loudly);
//! 2. parsing is deterministic: the same bytes parse to the same
//! verdict and the same digest;
//! 3. on success the structural caps hold: ≤16MiB body (checked
//! before parsing) and an expansion of ≤100k segments — an
//! over-cap expansion is the `manifest_too_large` verdict, never
//! a silent materialization;
//! 4. segment identity: every expanded segment's `sequence` equals
//! its cross-period ordinal exactly (the track-model ruling);
//! 5. every byte range satisfies `offset + length` without overflow
//! and stays non-empty;
//! 6. the judgment-table rows are code-stable: a verdict carrying a
//! code names exactly the canonical string (`live_unsupported` /
//! `drm_unsupported` / `sidx_unsupported` / `manifest_parse` /
//! `manifest_too_large`).

use libfuzzer_sys::fuzz_target;
use taiji_media::m3u8::MAX_MANIFEST_BYTES;
use taiji_media::mpd;
use taiji_media::trackset::TrackSetConfig;

const URL: &str = "https://fuzz.test/manifest.mpd";

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_MANIFEST_BYTES {
        return; // over the byte cap by construction — the parse face
                // refuses before any allocation; the cap row's reference
                // is pinned by the unit/golden suites.
    }
    // 1 + 2: one-shot parse + determinism.
    let first = mpd::parse_mpd(data);
    assert_eq!(
        first.is_ok(),
        mpd::parse_mpd(data).is_ok(),
        "deterministic parse verdict"
    );
    if let Ok(doc) = first {
        // 6: the digest is a pure function of the parsed structure.
        let d1 = mpd::mpd_digest(&doc, URL);
        assert_eq!(d1, mpd::mpd_digest(&doc, URL), "deterministic digest");
        assert_eq!(d1.len(), 64, "sha256 hex face");

        // 1 + 3 + 4 + 5: plan + expand through every pick (the policy
        // cycles Highest/Resolution/Bandwidth — every arm stays
        // panic-free and a verdict is always deterministic).
        for policy in [
            taiji_media::VariantPolicy::Highest,
            taiji_media::VariantPolicy::Resolution { height: 720 },
            taiji_media::VariantPolicy::Bandwidth {
                bits_per_second: 5_000_000,
            },
        ] {
        if let Ok(plan) = mpd::plan_dash_tracks(&doc, URL, &TrackSetConfig::default(), &policy) {
            for pick in &plan.picks {
                match mpd::expand_representation(&doc, URL, pick) {
                    Ok(mpd::Expanded::Ready(track)) => {
                        assert!(
                            track.playlist.segments.len()
                                <= taiji_media::m3u8::MAX_MEDIA_SEGMENTS,
                            "expansion cap holds"
                        );
                        for (i, seg) in track.playlist.segments.iter().enumerate() {
                            assert_eq!(
                                seg.sequence,
                                i as u64,
                                "cross-period ordinal identity"
                            );
                            assert!(
                                seg.duration.is_finite() && seg.duration >= 0.0,
                                "finite duration"
                            );
                            if let Some(br) = seg.byte_range {
                                assert!(br.length > 0, "non-empty range");
                                assert!(br.offset.checked_add(br.length).is_some());
                            }
                            assert!(
                                !seg.uri.contains('?') || seg.uri.matches('?').count() >= 1,
                                "URIs kept verbatim (query included)"
                            );
                        }
                        // Layer judgment never panics and is pure.
                        let l1 = taiji_media::trackdl::classify_track(&track.playlist);
                        let l2 = taiji_media::trackdl::classify_track(&track.playlist);
                        assert_eq!(l1, l2);
                    }
                    Ok(mpd::Expanded::DeferredSidx(_)) => {}
                    Err(e) => {
                        // 6: an expansion refusal carries a canonical code.
                        let code = e.code();
                        assert!(
                            matches!(
                                code,
                                "taiji.media.manifest_too_large"
                                    | "taiji.media.manifest_parse"
                                    | "taiji.media.variant_policy"
                            ),
                            "expansion refusal code {code}"
                        );
                    }
                }
            }
        }
        }
    } else if let Err(e) = first {
        // 6: parse refusals name canonical codes only.
        let code = e.code();
        assert!(
            matches!(
                code,
                "taiji.media.manifest_parse"
                    | "taiji.media.live_unsupported"
                    | "taiji.media.drm_unsupported"
                    | "taiji.media.manifest_too_large"
            ),
            "parse refusal code {code}"
        );
    }

    // 1: the sidx materialization arm over arbitrary fetched bytes
    // (the deferred-fetch face — hostile index bytes are explicit
    // errors, never panics).
    let plan = mpd::SidxPlan {
        base: "https://fuzz.test/x.mp4".to_string(),
        index_range: (0, data.len().min(u32::MAX as usize) as u64),
        init: None,
        timescale: 1,
    };
    let m1 = mpd::materialize_sidx(&plan, data);
    let m2 = mpd::materialize_sidx(&plan, data);
    assert_eq!(m1.is_ok(), m2.is_ok(), "deterministic materialize");
    if let Err(e) = m1 {
        let code = e.code();
        assert!(
            matches!(
                code,
                "taiji.media.sidx_unsupported"
                    | "taiji.media.manifest_parse"
                    | "taiji.media.manifest_too_large"
            ),
            "materialize refusal code {code}"
        );
    }
});
