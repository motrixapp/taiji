//! The shared fixture face = the `taiji_media::testkit` module (moved
//! out of tests/ so the cross-crate integration tests
//! consume the identical builders; re-exported here so the existing
//! test paths stay unchanged) + the VOD fixture generator
//! (`fixturegen`, test-support only).

pub mod ffmpeg_lab;
pub mod fixturegen;
pub mod ledger;
pub mod origin;

// The legacy glob keeps the pre-existing test binaries' paths
// (`common::build_init` …) working; binaries that consume none of it
// (the fixture suites import ledger/fixturegen directly) would warn.
#[allow(unused_imports)]
pub use taiji_media::testkit::*;
