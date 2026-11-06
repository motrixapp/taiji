//! GID type vocabulary.
//!
//! Engine-allocated GIDs are always `random u64 | 0x8000_0000_0000_0000`,
//! rendered as 16 lowercase hex digits. Setting the high bit keeps this
//! engine's GID space disjoint from the aria2 fork's (high bit = 0); this is
//! the foundation of a frozen compatibility surface: the frontend routes
//! between the two engines by GID prefix, so clients are unaffected.
//!
//! Scope: this module carries only the type and constant vocabulary (the GID
//! shape is a frozen public surface shared by core session/engine/hook and
//! the RPC layer). The allocator (`GidAllocator`, random draw with duplicate
//! check) is session execution semantics and lives in taiji-core's `gid`
//! module; this vocabulary layer must not gain execution semantics or its
//! dependency edges.

/// Mask for the GID high bit.
pub const GID_HIGH_BIT: u64 = 0x8000_0000_0000_0000;

/// A download task identifier for this engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Gid(u64);

impl Gid {
    /// Builds from a raw u64 (persistence/restore paths only; the caller
    /// must guarantee the high bit is already set).
    pub fn from_u64(raw: u64) -> Self {
        Gid(raw)
    }

    /// Raw value (for persistence serialization).
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for Gid {
    /// Renders as 16 lowercase hex digits (RPC-layer GIDs are always
    /// 16-digit lowercase hex).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}
