//! Write-path tee face for `--checksum` streaming digests (streaming
//! verification at full-file completion): finalization moves from
//! "post-completion full re-read" to "incremental feeding during the
//! download". This module only provides the write-byte callback seam
//! ([`TeeSink`]); the digester itself and the out-of-order-write →
//! ordered-consumption coordination live core-side. Tee position:
//! inside the rate gate (`ThrottledSink(TeeSink(FileSink))`), so fed
//! bytes already hold a rate permit and match the final disk bytes.
//!
//! Upstream anchor mapping: docs/design/http.md

use std::sync::Arc;

use bytes::Bytes;
use futures::future::BoxFuture;

use crate::error::Result;
use crate::traits::{SegId, SegmentSink};

/// Write-byte callback seam (the digester is held core-side;
/// `Fn(&[u8])` fed in disk-write order).
pub type ByteFeed = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// Shared digest tee: every disk-bound byte on the write path is fed
/// to the callback synchronously (sequential streaming form).
///
/// Feeding precedes the inner write: the callback content = the final
/// on-disk bytes (tee and inner write keep the same order; an inner
/// write failure fails the task and the digest is never consumed — a
/// failed task has no finalization face).
pub struct TeeSink {
    inner: Arc<dyn SegmentSink>,
    feed: Option<ByteFeed>,
}

impl TeeSink {
    /// Assemble (`None` feed = zero-cost pass-through — without
    /// `--checksum` the assembly behaves byte-identically to the
    /// existing sink chain).
    pub fn new(inner: Arc<dyn SegmentSink>, feed: Option<ByteFeed>) -> Self {
        TeeSink { inner, feed }
    }
}

impl SegmentSink for TeeSink {
    fn write_at(&self, seg: SegId, off: u64, bytes: Bytes) -> BoxFuture<'_, Result<()>> {
        if let Some(feed) = self.feed.as_ref() {
            feed(&bytes);
        }
        Box::pin(self.inner.write_at(seg, off, bytes))
    }

    fn complete_block(&self, block: u64) -> BoxFuture<'_, Result<()>> {
        Box::pin(self.inner.complete_block(block))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// All bytes reach the callback in write order (the sequential
    /// feeding contract); a None feed passes through.
    #[tokio::test]
    async fn bytes_reach_feed_in_write_order() {
        let seen: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_t = Arc::clone(&seen);
        let feed: ByteFeed = Arc::new(move |b: &[u8]| {
            seen_t
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend_from_slice(b);
        });
        let sink = Arc::new(RecordSink(Arc::new(Mutex::new(Vec::new()))));
        let tee = TeeSink::new(
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            Some(Arc::clone(&feed)),
        );
        let seg = SegId {
            source: 0,
            extent: 0,
        };
        tee.write_at(seg, 0, Bytes::from_static(b"abc"))
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        tee.write_at(seg, 3, Bytes::from_static(b"de"))
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(*seen.lock().unwrap_or_else(|e| e.into_inner()), b"abcde");
        assert_eq!(
            sink.0.lock().unwrap_or_else(|e| e.into_inner()).as_slice(),
            b"abcde",
            "tee pass-through of the inner write"
        );

        // None feed: pass-through (zero behavior change when disabled).
        let plain = TeeSink::new(sink as Arc<dyn SegmentSink>, None);
        plain
            .write_at(seg, 5, Bytes::from_static(b"f"))
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(*seen.lock().unwrap_or_else(|e| e.into_inner()), b"abcde");
    }

    /// Inner sink recorder.
    struct RecordSink(Arc<Mutex<Vec<u8>>>);

    impl SegmentSink for RecordSink {
        fn write_at(&self, _seg: SegId, _off: u64, bytes: Bytes) -> BoxFuture<'_, Result<()>> {
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend_from_slice(&bytes);
            Box::pin(std::future::ready(Ok(())))
        }
        fn complete_block(&self, _block: u64) -> BoxFuture<'_, Result<()>> {
            Box::pin(std::future::ready(Ok(())))
        }
    }
}
