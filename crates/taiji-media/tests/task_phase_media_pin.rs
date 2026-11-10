//! Cross-crate single-source pin for the media task-state domain.
//!
//! `MediaPhase` (this crate) stays the single source of the
//! `media_task.state` domain; `TaskPhase` (taiji-store — the unified
//! vocabulary over the three persisted `state` columns) carries the
//! same ten strings as its media subset without referencing this crate
//! (the dependency direction forbids it: taiji-media depends on
//! taiji-store, never the reverse). Two independent declarations of one
//! domain is drift debt the moment it lands — this test is the one
//! place both tables are in view, so editing either alone fails here.
//! Widening either side is a schema event (the state columns have no
//! CHECK by design; the domains are anchored in declarations exactly
//! like this pair).

use taiji_media::phase::MediaPhase;
use taiji_store::persist::writer::{TaskFamily, TaskPhase};

/// The two declarations of the media domain are member-identical:
/// `MediaPhase::ALL`'s `as_str` table == `TaskPhase`'s media-family
/// subset's `as_v1_str` table (ten words each, order-insensitive —
/// the tables have different orderings by design: MediaPhase's table
/// order is its own frozen domain order, TaskPhase's is the unified
/// variant table order).
#[test]
fn media_phase_table_matches_task_phase_media_subset() {
    let mut media: Vec<&str> = MediaPhase::ALL.iter().map(|p| p.as_str()).collect();
    let mut subset: Vec<&str> = TaskPhase::ALL
        .iter()
        .filter(|p| p.applies_to(TaskFamily::Media))
        .map(|p| p.as_v1_str())
        .collect();
    media.sort_unstable();
    subset.sort_unstable();
    assert_eq!(
        subset, media,
        "the media_task.state domain is declared twice (MediaPhase here, TaskPhase's \
         media subset in taiji-store); they must stay member-identical — edit both or \
         neither, and treat any widening as a schema event"
    );
    assert_eq!(
        media.len(),
        10,
        "the media domain is the full ten-state set (queued|resolving|downloading|\
         recording|processing|verifying|finalizing|paused|error|done)"
    );
}
