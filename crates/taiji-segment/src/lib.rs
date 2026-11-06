//! `taiji-segment` — the segment download vocabulary: the three
//! segmentation traits and their supporting types (the
//! frozen core abstraction), plus the signature closure that came
//! along in the verbatim lift: the per-task cookie face
//! ([`cookies`]) and the engine error face ([`error`]) that the trait
//! signatures reference.
//!
//! Topology position (the protocol-extension map):
//! vocabulary at the bottom, engines as siblings, session on top —
//! sibling engines (taiji-http today; ed2k/iroh when their own
//! projects land) depend on this crate and never on each other.
//! `taiji-http` re-exports [`traits`]/[`cookies`]/[`error`] as its
//! path-stable transition face; new consumers should depend on
//! taiji-segment directly.
//!
//! Hard invariant (compile-time guarded): this crate depends
//! on neither taiji-http, taiji-core, nor taiji-store — disk writes
//! stay injected through the `SegmentSink` trait.
//!
//! Upstream anchor mapping: docs/design/http.md

pub mod cookies;
pub mod error;
pub mod traits;
