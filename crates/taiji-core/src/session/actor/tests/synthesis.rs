// ---- Synthesis pool ----
//
// Actor-level unit faces for the synthesis budget (the default + the
// read-side clamp, the seed_budget/check_budget read-side shape) — the
// e2e slices (slot release/backfill, gate-hang remove/pause races, the
// park/unpark round trip, restart non-persistence, the tellWaiting
// visibility projection) live in the taiji-core integration suite
// (`tests/media_synthesis_gate.rs`), which drives the full mock-HLS
// pipeline. Assertion shapes are meter/registry counts — no wall-clock
// ratio assertions (an earlier suite's flake precedent; banned here).

/// The default + the read-side [1,16] clamp (§2's synthesis ruling:
/// an ffmpeg process is heavy — stream-copy light, transcode/burn-in
/// heavy; the media-segment-concurrency network knob is a different
/// layer and is NOT governed by this budget). No parse/RPC face until
/// No parse/RPC face: a direct construction feeding an out-of-domain value clamps
/// at the single consumption point, never panics; no "unlimited" state
/// (the lower clamp 1; shares are non-transferable — the value is this pool's alone).
#[test]
fn synthesis_budget_default_domain_and_clamp() {
    let g = GlobalOptions::default();
    assert_eq!(
        g.media_synthesis_concurrency, 2,
        "default 2 (an ffmpeg process is heavy: stream-copy light, transcode/burn-in heavy)"
    );
    assert_eq!(g.synthesis_budget(), 2);
    let zero = GlobalOptions {
        media_synthesis_concurrency: 0,
        ..Default::default()
    };
    assert_eq!(
        zero.synthesis_budget(),
        1,
        "below the domain clamps to 1 (no unlimited state)"
    );
    let over = GlobalOptions {
        media_synthesis_concurrency: 999,
        ..Default::default()
    };
    assert_eq!(over.synthesis_budget(), 16, "the domain ceiling 16 clamps");
}
