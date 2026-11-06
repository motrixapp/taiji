#![no_main]

//! fuzz target: the ISO-BMFF read surface (`taiji_media::bmff` —
//! Parse-surface red line: hostile bytes are explicit
//! errors, never panics; the target was added after the
//! box-end integer-wraparound finding).
//!
//! Invariants:
//! 1. every entry point (`iter_boxes`, `read_moof`, `parse_init`,
//! `fold_track`) terminates on any byte input with Ok/Err — no
//! panic (the wraparound shape `largesize = 2^64 - k` is the seed
//! of record);
//! 2. on success every box lies inside the input slice (bounds hold
//! absolutely, including the largesize escape);
//! 3. verdicts are deterministic across repeated calls on the same
//! input (pure functions of the bytes).

use libfuzzer_sys::fuzz_target;
use taiji_media::bmff;

fuzz_target!(|data: &[u8]| {
    // 1 + 2: box iteration.
    if let Ok(boxes) = bmff::iter_boxes(data) {
        for b in &boxes {
            assert!(b.start <= b.end, "box span ordered");
            assert!(
                b.end <= data.len() as u64,
                "box end {} inside the {}-byte input",
                b.end,
                data.len()
            );
            let header_len = (b.end - b.start) - b.payload.len() as u64;
            assert!(
                header_len == 8 || header_len == 16,
                "header length {header_len}"
            );
        }
        // read_moof over any moof found: explicit error or trafs.
        if let Some(moof) = boxes.iter().find(|b| b.typ == *b"moof") {
            if let Ok(trafs) = bmff::read_moof(moof.payload) {
                for traf in &trafs {
                    assert!(traf.track_id != 0, "read_traf guarantees a track_id");
                }
            }
        }
    }
    // 1: the init parse face.
    let _ = bmff::parse_init(data);
    // 1 + 3: the fold face (same bytes as init and archive; an empty
    // span set forces the moof-outside-every-span refusal on any
    // archive carrying a moof — still an explicit error, never a
    // panic).
    let a = bmff::fold_track(data, data, &[]);
    let b = bmff::fold_track(data, data, &[]);
    assert_eq!(a.is_ok(), b.is_ok(), "deterministic verdict");
    // Determinism of the plain iteration face too.
    assert_eq!(
        bmff::iter_boxes(data).is_ok(),
        bmff::iter_boxes(data).is_ok()
    );

    // the multi-track entry points (the muxed
    // A/V faces the single-trak convenience pair above never reaches):
    // parse_init_tracks (every trak) + fold_track_for (the
    // selected-track fold) + select_init_track (handler pick).
    if let Ok(tracks) = bmff::parse_init_tracks(data) {
        assert!(
            !tracks.is_empty(),
            "parse_init_tracks never returns zero traks"
        );
        // The handler pick never panics for either kind and only
        // yields a track from the parsed set.
        for kind in ["video", "audio"] {
            if let Some(picked) = bmff::select_init_track(&tracks, kind) {
                assert!(
                    tracks.iter().any(|t| t.track_id == picked.track_id),
                    "the picked track comes from the parsed set"
                );
            }
        }
        // The selected-track fold over each parsed description (an
        // empty span set keeps the moof-outside-every-span refusal
        // path armed; deterministic verdicts).
        for desc in &tracks {
            let a = bmff::fold_track_for(desc, data, &[]);
            let b = bmff::fold_track_for(desc, data, &[]);
            assert_eq!(a.is_ok(), b.is_ok(), "deterministic fold_track_for");
        }
    }
    // parse_init_tracks determinism.
    assert_eq!(
        bmff::parse_init_tracks(data).is_ok(),
        bmff::parse_init_tracks(data).is_ok(),
        "deterministic parse_init_tracks"
    );

    // the sidx arm (the DASH SegmentBase addressing face):
    // read_sidx over any sidx-shaped payload is an explicit verdict,
    // never a panic; determinism holds; on success the reference
    // table is exactly reference_count long and every row's size is
    // the 31-bit reference_size domain.
    if let Ok(boxes) = bmff::iter_boxes(data)
        && let Some(sidx) = boxes.iter().find(|b| b.typ == *b"sidx")
    {
        let a = bmff::read_sidx(sidx.payload);
        let b = bmff::read_sidx(sidx.payload);
        assert_eq!(a.is_ok(), b.is_ok(), "deterministic read_sidx");
        if let Ok(info) = a {
            for r in &info.references {
                assert!(r.reference_size <= 0x7FFF_FFFF, "31-bit domain");
                assert!(r.sap_type <= 7, "raw 3-bit SAP domain");
            }
            assert_eq!(info.has_nested_sidx(), info.references.iter().any(|r| r.reference_type));
        }
    }
});

