//! Data-source abstractions for seeding / hash-request serving (defined in
//! bt, provided by core/store): the [`PieceSource`] block-read surface
//! (BEP47 pad zero-fill is the implementer's job) and the [`HashSource`]
//! BEP-52 hash-request serving surface. Pure traits, no IO orchestration.
/// Hash-request serving source (BEP-52; core implements it via the
/// metadata piece layer plus on-disk data). `Err` = cannot serve; the
/// caller replies with a hash reject — a legal answer, since a hash
/// request MUST be answered.
pub trait HashSource: Send + Sync {
    /// Serve a hash request: return base-layer hashes plus proof hashes;
    /// the canonical count is length + max(0, proof - (log2(length)-1))
    /// (BEP-52 omission rule). Only base = leaf layer (0) and piece layer
    /// support is required (BEP-52).
    fn serve(
        &self,
        root: &[u8; 32],
        base: u32,
        index: u32,
        length: u32,
        proof: u32,
    ) -> Result<Vec<[u8; 32]>, String>;
}

/// Seeding data source (defined in bt, provided by core/store).
pub trait PieceSource: Send + Sync {
    /// Read one block: `(wire index, begin)` into `buf`. The implementer
    /// owns the addressing map (v1: index*piece_len+begin; hybrid: v1
    /// layout offset plus pad zero-fill, BEP47). A short read at EOF is
    /// legal (the caller rejects on that basis).
    fn read_block(&self, index: u32, begin: u32, buf: &mut [u8]) -> Result<usize, String>;
    fn total_len(&self) -> u64;

    /// Batched read: `reqs[i] = (index, begin)` pairs with `bufs[i]`
    /// (its length is that request's byte count); returns one result per
    /// request, in `reqs` order (read_block semantics unchanged: Ok =
    /// bytes filled / Err = unservable -> reject). The default
    /// implementation loops read_block (semantically identical; any
    /// implementation inherits it unchanged); the store full source (core
    /// FaceSource) overrides it with merged reads of adjacent requests —
    /// libtorrent `docs/manual.rst` "coalesce the small bittorrent
    /// requests" (the store `coalesce_reads` pure function is the same
    /// reference). A batch-wide IO error (e.g. a missing file) may fail
    /// the whole batch: rejecting any request at any time is legal (BEP3),
    /// and the caller (peer::read_pool) replies with per-request rejects.
    fn read_batch(
        &self,
        reqs: &[(u32, u32)],
        bufs: &mut [&mut [u8]],
    ) -> Vec<Result<usize, String>> {
        debug_assert_eq!(reqs.len(), bufs.len());
        reqs.iter()
            .zip(bufs.iter_mut())
            .map(|(&(index, begin), buf)| self.read_block(index, begin, buf))
            .collect()
    }
}
