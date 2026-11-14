//! The aria2 v1 adapter layer (L3a): the only place in this crate (and
//! the repo) where aria2 wire strings are produced.
//!
//! Excision semantics: deleting this directory must leave the kernel
//! crates (taiji-store/core/engine/bt/http/media/segment/io/domain/
//! metalink) compiling with zero source changes — the kernel carries
//! only enums and semantics, never the wire words. That property is
//! pinned by `scripts/ci/excision_check.sh` (a cold `cargo check` of
//! the kernel ten with `crates/taiji-rpc/src/aria2/` removed from a
//! throwaway copy of the tree).
//!
//! Layer rules (the protocol/internal split plan):
//!
//! - R2 — wire strings are produced only through the tables in this
//!   module: table-driven, exhaustive `match`, frozen by literal
//!   tests. A new value must enter the deviations ledger
//!   (`docs/compat/aria2-v1-deviations.yaml`) before it can appear
//!   here.
//!
//! - R5 — internal error types map onto aria2 error codes only in
//!   [`error`].
//!
//! - The tables render kernel enums one-to-one; folds between kernel
//!   concepts (e.g. `HttpSourceState` → `ServerStatus`) stay in the
//!   kernel projection (L2), never here.
//!
//! Module map:
//!
//! - [`status`]: every status-shaped field's word table.
//!
//! - [`error`]: the repo-wide single error-mapping source (migrated
//!   whole from the former `src/error.rs`).
//!
//! - [`event`]: the six-event notification name tables (both faces) +
//!   the extension-event registry.
//!
//! - [`option`]: the metalink seam name tables, the option-name
//!   classification gate, and the echo serialization gate.

pub mod error;
pub mod event;
pub mod option;
pub mod status;
