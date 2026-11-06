#![no_main]

//! fuzz target: the m3u8 manifest parser + sniffer + selection /
//! digest faces (`taiji_media::m3u8`; the media parser-roster row).
//!
//! Invariants (media parse posture):
//! 1. `sniff` and `parse_manifest` never panic on any byte input
//! (lossy UTF-8; all range/sequence arithmetic checked);
//! 2. parsing is deterministic: the same bytes parse to the same
//! structure;
//! 3. on success the structural caps hold: ≤100k media segments and
//! the ≤16MiB body cap (the latter is checked before parsing, so
//! every input reaching a structure is under it);
//! 4. segment identity: `segments[i].sequence == media_sequence + i`
//! exactly, with no u64 overflow (parse-time checked arithmetic);
//! 5. every resolved byte range satisfies `offset + length ≤ u64::MAX`
//! (checked at parse, asserted here);
//! 6. every media playlist that parses carries ENDLIST (its absence
//! is the `live_unsupported` refusal);
//! 7. query-stripping is complete: no normalized URI or digest input
//! contains a '?' after `strip_query`;
//! 8. merge runs stay within the ≤8-segment cap and never overflow
//! their byte span;
//! 9. `VariantPolicy::parse` never panics on any string (first 64
//! bytes of the input, lossily decoded), and a successful parse
//! always names a selectable variant or errors.

use libfuzzer_sys::fuzz_target;
use taiji_media::m3u8::{
    MAX_MEDIA_SEGMENTS, Playlist, VariantPolicy, byterange_runs, master_playlist_digest,
    media_playlist_digest, parse_manifest, select_variant, sniff, strip_query,
};

fuzz_target!(|data: &[u8]| {
    // 1. Sniff never panics, on any combination of signals.
    let _ = sniff(Some(data), Some("x.m3u8"), Some("application/x-mpegurl"));
    let _ = sniff(Some(data), None, None);
    let _ = sniff(None, Some("list.m3u8"), None);

    // 9. Policy parsing never panics.
    let head = String::from_utf8_lossy(&data[..data.len().min(64)]);
    if let Ok(policy) = VariantPolicy::parse(&head) {
        let _ = policy;
    }

    // 1/2. One-shot parse + determinism.
    let first = parse_manifest(data);
    if let Ok(playlist) = first.clone() {
        assert_eq!(parse_manifest(data).ok(), Some(playlist.clone()));
        match playlist {
            Playlist::Media(m) => {
                // 3. Caps.
                assert!(m.segments.len() <= MAX_MEDIA_SEGMENTS);
                // 4. Identity arithmetic.
                for (i, seg) in m.segments.iter().enumerate() {
                    assert_eq!(
                        u128::from(seg.sequence),
                        u128::from(m.media_sequence) + u128::from(i as u64)
                    );
                    // 5. Checked range arithmetic.
                    if let Some(br) = seg.byte_range {
                        assert!(br.offset.checked_add(br.length).is_some());
                        assert!(br.length > 0);
                    }
                    assert!(seg.duration.is_finite() && seg.duration >= 0.0);
                    // 7. Normalization face.
                    assert!(!strip_query(&seg.uri).contains('?'));
                }
                // 6. ENDLIST invariant.
                assert!(m.endlist);
                // 8. Merge runs.
                for run in byterange_runs(&m) {
                    assert!(run.segments >= 1 && run.segments <= 8);
                    assert!(run.offset.checked_add(run.length).is_some());
                }
                // 2. Digest determinism rides the structure clone.
                let _ = media_playlist_digest(&m);
            }
            Playlist::Master(m) => {
                let _ = master_playlist_digest(&m);
                // 9. Selection never panics, error or variant.
                if let Ok(policy) = VariantPolicy::parse(&head) {
                    let _ = select_variant(&m, &policy);
                }
            }
        }
    }
});
