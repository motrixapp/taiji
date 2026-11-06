//! Worker-side execution ring for stall stealing — the per-extent
//! byte-heartbeat producer and write-right cancellation consumer
//! facing the [`crate::coordinator`] decision face.
//!
//! One [`ExtentHeartbeat`] is assembled per extent fetch: the ticker
//! beats once per [`HEARTBEAT_INTERVAL`], the write path catches up a
//! beat after a pause (only growing beats advance that baseline), a
//! [`HeartbeatAck::Cancelled`] reply flips the cancel bit and wakes
//! the fetch watchdog, and every block fully written and fully inside
//! the extent domain is reported as written. The ticker holds only a
//! [`std::sync::Weak`] to the host and is aborted by
//! [`Drop for ExtentHeartbeat`] on the last host handle — a hung or
//! aborted worker cannot leak a live ticker.
//!
//! Upstream anchor mapping: docs/design/http.md

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bytes::Bytes;
use futures::future::BoxFuture;
use tokio::sync::watch;

use crate::coordinator::{CoordinatorHandle, HEARTBEAT_INTERVAL, HeartbeatAck};
use crate::error::{HttpError, Result};
use crate::traits::{SegId, SegmentSink};

/// The abort error message used by [`SegmentSink::write_at`] when the
/// write right is lost (the transport passes sink errors out of the
/// fetch; callers attribute via [`ExtentHeartbeat::is_cancelled`] — the
/// text is diagnostic only).
const WRITE_RIGHT_LOST: &str = "extent write right lost (stolen); stopping at block boundary";

/// Heartbeat outcome (the shared verdict of the ticker and the pause
/// catch-up).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Beat {
    /// The write right is still ours (or the coordinator has stopped —
    /// closeout belongs to the next call site in the worker loop; no
    /// fake cancellation here).
    Live,
    /// The write right has been transferred: set the cancel bit and
    /// wake the watchdog.
    Cancelled,
}

/// Shared state (the entity behind [`ExtentHeartbeat`]'s cheap clones;
/// the ticker task holds a clone).
struct Shared {
    coord: CoordinatorHandle,
    /// Reporting source number (the write-right reconciliation domain).
    source: u32,
    /// In-flight extent number (the allocated `SegId.extent`, echoed
    /// back as-is).
    extent: u64,
    /// Block size (the boundary arithmetic of report-as-written).
    bs: u64,
    /// Inner sink (the rate/attribution chain passes through unchanged
    /// — this module only adds heartbeat and accounting, never changing
    /// write semantics).
    sink: Arc<dyn SegmentSink>,
    /// Cumulative bytes written within the extent (`fetch_add` on the
    /// write path; the source of truth for heartbeat deltas).
    written: AtomicU64,
    /// Report-as-written cursor (the next block number to report;
    /// initial value = the first block fully inside the extent domain =
    /// ceil(extent_start/bs) — under byte-granular leases the start
    /// block's head belongs to the predecessor lease and is not in this
    /// domain; its completion is closed by the coordinator's
    /// watermark-full decision). The cursor advances only when a fully
    /// in-domain block is written — each block reports exactly once.
    /// One writer per fetch, so Relaxed suffices.
    edge_cursor: AtomicU64,
    /// The byte watermark already reported by a heartbeat (delta =
    /// current total − watermark; shared by both producers, `fetch_max`
    /// consumption prevents double counting).
    beat_cursor: AtomicU64,
    /// Time of the last **growing** heartbeat (the pause catch-up's
    /// timing baseline; zero-growth beats never refresh it — otherwise
    /// the ticker's zero-growth beats during a write pause would keep
    /// advancing the baseline, the catch-up condition would be
    /// permanently false, and the resumed first write could not learn
    /// of the lost write right in time). The lock is never held across
    /// an await (read and release).
    last_beat: Mutex<Instant>,
    /// Fast cancel bit (a channel-free check on the write path).
    cancelled: AtomicBool,
    /// Cancel wakeup face (where the watchdog's `cancelled().await`
    /// parks).
    notify_tx: watch::Sender<bool>,
    /// Ticker reaping face ([`ExtentHeartbeat::spawn_ticker`] registers
    /// its [`tokio::task::AbortHandle`]; [`Drop for ExtentHeartbeat`]
    /// aborts them all when the last host handle drops). The assembly
    /// contract is one ticker per extent; the vector only defends
    /// against duplicate spawns on the same handle (repeated
    /// registrations do not overwrite each other).
    tickers: Mutex<Vec<tokio::task::AbortHandle>>,
}

impl Shared {
    fn set_cancelled(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        // `send_replace` (not `send`): the value lands even with no
        // receiver — the watchdog (`cancelled()`) subscribes lazily, so
        // a cancel at any time after construction must be readable.
        self.notify_tx.send_replace(true);
    }

    /// Send one heartbeat (shared by the ticker and the pause
    /// catch-up): delta = total − watermark; a Cancelled reply sets the
    /// cancel bit. A stopped coordinator does not fake cancellation
    /// (the next call site in the worker loop closes out).
    ///
    /// The catch-up baseline (`last_beat`) advances only on **growing**
    /// heartbeats: zero-growth beats (the ticker's normal output during
    /// a write pause) never rewrite it — otherwise the baseline would
    /// keep refreshing through the pause, the write-path catch-up
    /// condition would be permanently false, and the resumed first
    /// write could not learn of the lost write right in time (the
    /// stolen first block would stop only at the next beat; megabytes
    /// of duplicate transfer on a fast connection).
    async fn beat(&self) -> Beat {
        let cur = self.written.load(Ordering::Relaxed);
        let prev = self.beat_cursor.fetch_max(cur, Ordering::Relaxed);
        let delta = cur.saturating_sub(prev);
        let out = match self.coord.heartbeat(self.source, self.extent, delta).await {
            Ok(HeartbeatAck::Continue) => Beat::Live,
            Ok(HeartbeatAck::Cancelled) => {
                self.set_cancelled();
                Beat::Cancelled
            }
            Err(_) => Beat::Live,
        };
        if delta > 0 {
            *crate::lock(&self.last_beat) = Instant::now();
        }
        out
    }
}

/// Per-extent heartbeat ring (one assembled per extent fetch; cheap to
/// clone).
///
/// The type itself implements [`SegmentSink`]: the worker swaps the
/// transport's sink for it (passing through to the inner sink) and
/// gains heartbeat production, cancellation consumption, and
/// report-as-written block completion.
pub struct ExtentHeartbeat {
    shared: Arc<Shared>,
}

impl ExtentHeartbeat {
    /// Assemble (`coord`/`source`/`extent` = the write-right
    /// reconciliation triple; `extent_start` = the extent's starting
    /// byte — the domain of the "fully in-domain" report criterion;
    /// `bs` = block size; `sink` = the inner sink chain).
    pub fn new(
        coord: CoordinatorHandle,
        source: u32,
        extent: u64,
        extent_start: u64,
        bs: u64,
        sink: Arc<dyn SegmentSink>,
    ) -> Self {
        let first_full_block = extent_start.div_ceil(bs);
        let (notify_tx, _) = watch::channel(false);
        ExtentHeartbeat {
            shared: Arc::new(Shared {
                coord,
                source,
                extent,
                bs,
                sink,
                written: AtomicU64::new(0),
                edge_cursor: AtomicU64::new(first_full_block),
                beat_cursor: AtomicU64::new(0),
                last_beat: Mutex::new(Instant::now()),
                cancelled: AtomicBool::new(false),
                notify_tx,
                tickers: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Spawn the ticker (one per extent): one beat per
    /// [`HEARTBEAT_INTERVAL`]. The first beat fires immediately —
    /// extent allocation establishes the stall-evidence baseline.
    ///
    /// Reaping: the ticker holds only a host [`std::sync::Weak`] — once
    /// all host handles are gone a failed `upgrade` self-detects and
    /// exits (the backstop); before returning it registers its
    /// [`tokio::task::AbortHandle`], and [`Drop for ExtentHeartbeat`]
    /// aborts it when the last host handle drops (the main closure, no
    /// wait for the next beat). The caller's explicit `abort()` at the
    /// fetch closeout line remains the timely normal-path closeout
    /// (ahead of the handle drop) and coexists with this guard.
    pub fn spawn_ticker(&self) -> tokio::task::JoinHandle<()> {
        let host = Arc::downgrade(&self.shared);
        let handle = tokio::spawn(async move {
            let mut tick = tokio::time::interval(HEARTBEAT_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                // Host-death self-detection (Weak): a zero strong count
                // = every host handle dropped (the wholesale
                // worker-future abort shape) — stop beating and exit.
                let Some(this) = host.upgrade() else {
                    return;
                };
                if this.cancelled.load(Ordering::SeqCst) {
                    return;
                }
                match this.beat().await {
                    Beat::Live => {}
                    Beat::Cancelled => return,
                }
            }
        });
        crate::lock(&self.shared.tickers).push(handle.abort_handle());
        handle
    }

    /// Write-right-lost verdict (the fast bit; shared by the write-path
    /// entry and fetch closeout attribution).
    pub fn is_cancelled(&self) -> bool {
        self.shared.cancelled.load(Ordering::SeqCst)
    }

    /// Cumulative bytes written for this extent (the wave-phase verdict
    /// feeding the AIMD Reset wiring: a zero-byte failure is
    /// connect-phase noise — accept-queue race RSTs — and must not
    /// trigger a multiplicative decrease; >0 means a transfer was under
    /// way and the interruption counts as steady-state congestion. An
    /// observational read, no synchronization semantics).
    pub fn written_bytes(&self) -> u64 {
        self.shared.written.load(Ordering::Relaxed)
    }

    /// Final flush (call after a successful fetch): immediately report
    /// written bytes not yet covered by the ticker/catch-up cadence
    /// (keeps the block watermark-full decision timely — tail/shared
    /// block completion and the task closeout chain do not wait for the
    /// next beat).
    pub async fn flush(&self) {
        let _ = self.shared.beat().await;
    }

    /// Wait for write-right loss (the fetch watchdog): returns once the
    /// cancel bit is set. Heartbeat replies set it via the ticker/pause
    /// catch-up.
    pub async fn cancelled(&self) {
        let mut rx = self.shared.notify_tx.subscribe();
        loop {
            if *rx.borrow_and_update() {
                return;
            }
            // The sender dies with the ring = the fetch is already
            // closing out (the guard lifetime matches the fetch); the
            // wait face is gone — return and leave attribution to
            // closeout.
            if rx.changed().await.is_err() {
                return;
            }
        }
    }

    /// Pause catch-up check + execution: send only if at least one
    /// interval has passed since the last **growing** beat (steady
    /// streaming writes are covered by the ticker at zero incremental
    /// cost; zero-growth beats during a pause never advance the
    /// baseline, so this fires exactly on the first write after a
    /// pause). Returns `false` = the catch-up got Cancelled (the write
    /// right is gone; the caller must reject this write).
    async fn refresh_beat(&self) -> bool {
        let due = {
            let last = crate::lock(&self.shared.last_beat);
            last.elapsed() >= HEARTBEAT_INTERVAL
        };
        if due {
            let _ = self.shared.beat().await;
        }
        !self.is_cancelled()
    }
}

impl Clone for ExtentHeartbeat {
    fn clone(&self) -> Self {
        ExtentHeartbeat {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl Drop for ExtentHeartbeat {
    fn drop(&mut self) {
        // Drop-guard reaping (the main leak closure): this drop is the
        // last host handle (strong count 1 — the ticker holds only a
        // Weak) -> registered tickers are reaped along the way (abort
        // is a no-op on an already-exited task). On paths where the
        // worker future is aborted wholesale between assembly and the
        // closeout line (cancel/shutdown parent selects, task abort,
        // panic) the closeout line's explicit abort is unreachable —
        // this guard is the along-the-way backstop.
        if Arc::strong_count(&self.shared) == 1 {
            let mut tickers = crate::lock(&self.shared.tickers);
            for handle in tickers.drain(..) {
                handle.abort();
            }
        }
    }
}

impl SegmentSink for ExtentHeartbeat {
    fn write_at(&self, seg: SegId, off: u64, bytes: Bytes) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            // Pre-write gates: the cancel bit, then the pause catch-up.
            // Either hit rejects this write (the fetch aborts via the
            // sink error) — zero new writes into the stolen region.
            if self.is_cancelled() {
                return Err(HttpError::Transport(WRITE_RIGHT_LOST.into()));
            }
            if !self.refresh_beat().await {
                return Err(HttpError::Transport(WRITE_RIGHT_LOST.into()));
            }
            let n = bytes.len() as u64;
            self.shared.sink.write_at(seg, off, bytes).await?;
            self.shared.written.fetch_add(n, Ordering::Relaxed);
            // Report-as-written (the watermark cursor): every block
            // whose end the cumulative write has covered **and that lies
            // fully inside the extent domain** reports exactly once
            // (first arrival wins, idempotent; the start block's head
            // belongs to the predecessor lease — not this domain, its
            // completion is closed by the coordinator's per-block
            // watermark-full decision). Blocks doubled by the
            // fetch-final flush are absorbed by the decision face.
            let bs = self.shared.bs;
            let covered_end = off + n;
            let mut cursor = self.shared.edge_cursor.load(Ordering::Relaxed);
            while (cursor + 1) * bs <= covered_end {
                self.shared.coord.complete_block(cursor).await?;
                cursor += 1;
            }
            self.shared.edge_cursor.store(cursor, Ordering::Relaxed);
            Ok(())
        })
    }

    fn complete_block(&self, block: u64) -> BoxFuture<'_, Result<()>> {
        // The only accounting entry is the decision face (the
        // coordinator's single point); the inner sink's complete_block
        // is consumed by the decision face itself (the worker never
        // touches it directly). This implementation does not pass
        // through — test transports calling complete_block directly
        // never cross the production sink chain.
        Box::pin(self.shared.coord.complete_block(block))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::StealVerdict;
    use crate::grid::{BlockGrid, MIN_BLOCK_SIZE};
    use crate::scheduler::{GuidedConfig, GuidedPlan};
    use crate::traits::Extent;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    /// Seeded rate book (EWMA established so the rate lease term is
    /// active): the fixture that lets the owner claim a multi-block
    /// extent — the cold-start block-granule lease semantics are pinned
    /// by the scheduler's tests; these tests focus on the heartbeat/
    /// steal ring.
    fn seeded_rates() -> crate::rate::SourceRateBook {
        crate::rate::SourceRateBook::seed_established(&[(0, 64.0 * MIN_BLOCK_SIZE as f64)])
    }

    /// Accounting/overlap observation sink: records the set of writers
    /// per block (overlap = blocks written by >= 2 distinct sources) and
    /// the completion order (duplicates visible). Written bytes are
    /// discarded.
    struct WatchSink {
        bs: u64,
        writers: StdMutex<BTreeMap<u64, BTreeSet<u32>>>,
        completions: StdMutex<Vec<u64>>,
        blocks_done: AtomicU64,
    }

    impl WatchSink {
        fn new(bs: u64) -> Self {
            WatchSink {
                bs,
                writers: StdMutex::new(BTreeMap::new()),
                completions: StdMutex::new(Vec::new()),
                blocks_done: AtomicU64::new(0),
            }
        }

        fn overlap_blocks(&self) -> Vec<u64> {
            self.writers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .filter(|(_, srcs)| srcs.len() > 1)
                .map(|(b, _)| *b)
                .collect()
        }

        fn completions(&self) -> Vec<u64> {
            self.completions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    impl SegmentSink for WatchSink {
        fn write_at(&self, seg: SegId, off: u64, _bytes: Bytes) -> BoxFuture<'_, Result<()>> {
            let block = off / self.bs;
            self.writers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .entry(block)
                .or_default()
                .insert(seg.source);
            Box::pin(std::future::ready(Ok(())))
        }

        fn complete_block(&self, block: u64) -> BoxFuture<'_, Result<()>> {
            self.completions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(block);
            self.blocks_done.fetch_add(1, Ordering::Relaxed);
            Box::pin(std::future::ready(Ok(())))
        }
    }

    /// Block-aligned grid parameters (block = test granularity;
    /// min-chunk = block — the extent floor is 1 block, max-chunk
    /// relaxed per scenario).
    fn fixture(bs: u64, blocks: u64, max_blocks: u64) -> (BlockGrid, GuidedPlan) {
        let total = blocks * bs;
        let grid = BlockGrid::new(bs, total).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan = GuidedPlan::build(
            total,
            &GuidedConfig {
                block_size: bs,
                max_chunk: max_blocks * bs,
            },
            &|b| grid.is_recorded(b),
        )
        .unwrap_or_else(|e| panic!("plan: {e}"));
        (grid, plan)
    }

    /// Pre-digest the head block (the same shape as the pressure ring):
    /// block 0 is claimed and reported complete — with the in-flight
    /// ledger empty, W=1 pure guided hands the owner a multi-block
    /// extent.
    async fn drain_head(handle: &CoordinatorHandle) {
        let head = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire head: {e}"))
            .unwrap_or_else(|| panic!("head alloc"));
        assert_eq!(head.extent.start, 0, "head block first");
        handle
            .complete_block(0)
            .await
            .unwrap_or_else(|e| panic!("head report: {e}"));
    }

    /// Heartbeat sink write loop (simulated streaming): writes the
    /// extent in `chunk` steps.
    async fn pump_seg(hb: &ExtentHeartbeat, seg: SegId, extent: &Extent, chunk: u64) -> Result<()> {
        let mut off = extent.start;
        while off < extent.end() {
            let n = chunk.min(extent.end() - off);
            hb.write_at(seg, off, bytes_of(n)).await?;
            off += n;
        }
        Ok(())
    }

    fn bytes_of(n: u64) -> Bytes {
        Bytes::from(vec![0u8; n as usize])
    }

    fn seg_of(source: u32, extent: u64) -> SegId {
        SegId { source, extent }
    }

    /// Pause catch-up closure (the key face of overlap = 0): the steal
    /// grant lands inside a write pause; the resumed first write learns
    /// Cancelled via the catch-up before touching disk — zero new owner
    /// writes in the stolen region and the fetch aborts with the
    /// write-right-lost error.
    #[tokio::test]
    async fn first_write_after_lull_observes_cancel_before_disk() {
        let bs = MIN_BLOCK_SIZE;
        let (grid, plan) = fixture(bs, 8, 8);
        let sink = Arc::new(WatchSink::new(bs));
        let (handle, actor) = crate::coordinator::spawn_dynamic_with_rates(
            "8000000000003301",
            grid,
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            2,
            // Decision window >= several heartbeat intervals (as in
            // production): the growing heartbeat matures before the
            // evidence — the owner's written blocks are booked first (a
            // real last_acked watermark), the grant starts at the hung
            // block, and overlap = 0 is decidable.
            Duration::from_millis(2500),
            crate::aimd::AimdConfig::new(1),
            seeded_rates(),
        );
        drain_head(&handle).await;
        // W=1 pure guided: 7 blocks remain -> a 3.5-block extent
        // ([bs, 4.5bs); the sub-block domain no longer clamps back to
        // block alignment).
        let alloc = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("alloc"));
        assert_eq!(
            alloc.extent.len,
            7 * bs / 2,
            "W=1 guided multi-block extent"
        );
        let alloc_extent_start = alloc.extent.start;
        let hb = ExtentHeartbeat::new(
            handle.clone(),
            0,
            alloc.seg.extent,
            alloc_extent_start,
            bs,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
        );
        // The owner writes 1 block (advancing last_acked to a block
        // boundary), then pauses >= the window.
        let head = Extent {
            start: alloc.extent.start,
            len: bs,
        };
        pump_seg(&hb, alloc.seg, &head, bs / 4)
            .await
            .unwrap_or_else(|e| panic!("head write: {e}"));
        hb.flush().await;
        // Fence (the FIFO query face): the report-as-written has been
        // serially consumed by the actor.
        let _ = handle.runtime_stats().await;
        assert!(
            sink.completions().contains(&1),
            "report-as-written of the head block (write watermark advancing): {:?}",
            sink.completions()
        );
        tokio::time::sleep(Duration::from_millis(2600)).await;

        // The steal grant is [write watermark, extent end) = from
        // block 2.
        let grant = loop {
            match handle
                .request_steal(1)
                .await
                .unwrap_or_else(|e| panic!("steal: {e}"))
            {
                StealVerdict::Approved(a) => break a,
                StealVerdict::DeniedNoStallEvidence => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                other => panic!("expected grant, got {other:?}"),
            }
        };
        assert_eq!(
            grant.extent.start,
            alloc.extent.start + bs,
            "grant start = last_acked+1 block"
        );

        // First write after the resume: pause >= one beat -> the
        // catch-up gets Cancelled -> the write is rejected before disk.
        tokio::time::sleep(HEARTBEAT_INTERVAL).await;
        let res = hb
            .write_at(
                seg_of(0, alloc.seg.extent),
                grant.extent.start,
                bytes_of(64),
            )
            .await;
        assert!(
            res.is_err(),
            "the first write into the stolen region must be rejected"
        );
        assert!(hb.is_cancelled(), "catch-up cancel bit set");
        assert!(
            sink.writers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&(grant.extent.start / bs))
                .is_none_or(|srcs| !srcs.contains(&0)),
            "the stolen first block must have no owner writes"
        );
        // Watchdog face: the cancel bit is set, the wait returns
        // immediately.
        tokio::time::timeout(Duration::from_millis(100), hb.cancelled())
            .await
            .unwrap_or_else(|_| panic!("watchdog must resolve once cancelled"));

        // The heartbeat ring holds a handle clone — release it before
        // actor closeout (a closed channel = the actor drains and exits;
        // the test face has no abort, explicit drop is the closeout
        // order).
        drop(hb);
        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
    }

    /// Ticker running + owner resume after a stall (the combined
    /// shape): the steal grant lands inside a write pause while the
    /// ticker's zero-growth beats keep arriving — the resumed **first
    /// write** must learn Cancelled through the pause catch-up
    /// (zero-growth beats never refresh the catch-up baseline). If they
    /// did refresh it, the catch-up condition would be permanently
    /// false while the ticker lives (dead code): the first write would
    /// only see the local cancel bit (set at the next beat) and the
    /// stolen first block would already be on disk — megabytes of
    /// duplicate transfer on a fast connection, breaking overlap = 0.
    #[tokio::test]
    async fn resumed_write_with_live_ticker_observes_cancel_before_disk() {
        let bs = MIN_BLOCK_SIZE;
        let (grid, plan) = fixture(bs, 8, 8);
        let sink = Arc::new(WatchSink::new(bs));
        let (handle, actor) = crate::coordinator::spawn_dynamic_with_rates(
            "8000000000003304",
            grid,
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            2,
            // Decision window >= several heartbeat intervals (as in
            // production).
            Duration::from_millis(2500),
            crate::aimd::AimdConfig::new(1),
            seeded_rates(),
        );
        drain_head(&handle).await;
        // W=1 pure guided: 7 blocks remain -> a 3.5-block extent
        // ([bs, 4.5bs); the sub-block domain no longer clamps back to
        // block alignment).
        let alloc = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("alloc"));
        assert_eq!(
            alloc.extent.len,
            7 * bs / 2,
            "W=1 guided multi-block extent"
        );
        let alloc_extent_start = alloc.extent.start;
        let hb = ExtentHeartbeat::new(
            handle.clone(),
            0,
            alloc.seg.extent,
            alloc_extent_start,
            bs,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
        );
        // The ticker runs throughout (the production shape; the other
        // tests cover no-ticker and permanently hung shapes — this one
        // completes the running-ticker + resume combination).
        let ticker = hb.spawn_ticker();
        // The owner writes 1 block (a growing heartbeat sets the
        // baseline), then pauses >= the window — during the pause the
        // ticker's zero-growth beats keep arriving (they must not
        // advance the catch-up baseline).
        let head = Extent {
            start: alloc.extent.start,
            len: bs,
        };
        pump_seg(&hb, alloc.seg, &head, bs / 4)
            .await
            .unwrap_or_else(|e| panic!("head write: {e}"));
        hb.flush().await;
        let _ = handle.runtime_stats().await;
        assert!(
            sink.completions().contains(&1),
            "report-as-written of the head block (last_acked watermark advancing): {:?}",
            sink.completions()
        );
        tokio::time::sleep(Duration::from_millis(2600)).await;

        // The steal grant is [last_acked+1, extent end) = blocks
        // 2..=3.
        let grant = loop {
            match handle
                .request_steal(1)
                .await
                .unwrap_or_else(|e| panic!("steal: {e}"))
            {
                StealVerdict::Approved(a) => break a,
                StealVerdict::DeniedNoStallEvidence => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                other => panic!("expected grant, got {other:?}"),
            }
        };
        assert_eq!(
            grant.extent.start,
            alloc.extent.start + bs,
            "grant start = last_acked+1 block"
        );

        // Resumed write (ticker alive): the first write must learn of
        // the cancel via the catch-up before disk — it cannot wait for
        // the next beat (the local cancel bit is not yet set; the
        // catch-up is the only immediate face).
        let res = hb
            .write_at(
                seg_of(0, alloc.seg.extent),
                grant.extent.start,
                bytes_of(64),
            )
            .await;
        assert!(
            res.is_err(),
            "the resumed first write must be rejected (catch-up before disk)"
        );
        assert!(hb.is_cancelled(), "catch-up cancel bit set");
        assert!(
            sink.writers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&(grant.extent.start / bs))
                .is_none_or(|srcs| !srcs.contains(&0)),
            "the stolen first block must have no owner writes"
        );

        ticker.abort();
        drop(hb);
        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
    }

    /// Ticker-to-watchdog cancel e2e (the hung-transport shape) + thief
    /// takeover: the owner writes to a block boundary and hangs (no
    /// writes, no catch-up); after the grant the thief finishes the
    /// tail with its own heartbeat sink; the owner's zero-growth beats
    /// deliver Cancelled to the watchdog — the hung fetch aborts
    /// (closeout is not blocked by a hung worker). The stolen first
    /// block gets zero owner writes (overlap = 0) and the steal grant
    /// counter really increments.
    #[tokio::test]
    async fn ticker_delivers_cancel_to_hung_fetch_and_thief_finishes() {
        let bs = MIN_BLOCK_SIZE;
        let (grid, plan) = fixture(bs, 8, 8);
        let sink = Arc::new(WatchSink::new(bs));
        let (handle, actor) = crate::coordinator::spawn_dynamic_with_rates(
            "8000000000003302",
            grid,
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            2,
            // Decision window >= several heartbeat intervals: the
            // growing heartbeat (first beat after the write) matures
            // before the evidence, the grant must land past the hung
            // block (overlap = 0 decidable).
            Duration::from_millis(2500),
            crate::aimd::AimdConfig::new(1),
            seeded_rates(),
        );
        drain_head(&handle).await;
        let alloc = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("alloc"));
        let alloc_extent_start = alloc.extent.start;
        let hb = ExtentHeartbeat::new(
            handle.clone(),
            0,
            alloc.seg.extent,
            alloc_extent_start,
            bs,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
        );
        let ticker = hb.spawn_ticker();
        // Write 1 block, then hang (the block-boundary shape — the hung
        // block unwritten, no catch-up).
        let head = Extent {
            start: alloc.extent.start,
            len: bs,
        };
        pump_seg(&hb, alloc.seg, &head, bs / 4)
            .await
            .unwrap_or_else(|e| panic!("head write: {e}"));

        // The thief (source 1): window elapses -> grant -> finish the
        // tail with a heartbeat sink.
        let thief = {
            let handle = handle.clone();
            let sink = Arc::clone(&sink);
            async move {
                let grant = loop {
                    match handle
                        .request_steal(1)
                        .await
                        .unwrap_or_else(|e| panic!("steal: {e}"))
                    {
                        StealVerdict::Approved(a) => break a,
                        StealVerdict::DeniedNoStallEvidence => {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                        other => panic!("expected grant, got {other:?}"),
                    }
                };
                let thb = ExtentHeartbeat::new(
                    handle.clone(),
                    1,
                    grant.seg.extent,
                    alloc_extent_start,
                    bs,
                    Arc::clone(&sink) as Arc<dyn SegmentSink>,
                );
                let _thief_ticker = thb.spawn_ticker();
                pump_seg(&thb, grant.seg, &grant.extent, bs / 4)
                    .await
                    .unwrap_or_else(|e| panic!("thief write: {e}"));
                grant
            }
        };
        let grant = tokio::time::timeout(Duration::from_secs(5), thief)
            .await
            .unwrap_or_else(|_| panic!("thief timed out"));

        // The hung owner's watchdog: zero-growth beats deliver the
        // cancel.
        tokio::time::timeout(Duration::from_secs(5), hb.cancelled())
            .await
            .unwrap_or_else(|_| panic!("hung owner watchdog never fired"));
        assert!(hb.is_cancelled());
        ticker.abort();

        // Invariant recheck: zero owner writes in the stolen first
        // block, overlap = 0, grant count >= 1, every extent block
        // reachable by the accounting face (first arrival wins).
        assert!(
            sink.writers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&(grant.extent.start / bs))
                .is_none_or(|srcs| !srcs.contains(&0)),
            "the stolen first block must have no owner writes"
        );
        assert_eq!(
            sink.overlap_blocks(),
            Vec::<u64>::new(),
            "sink write-range overlap must be 0"
        );
        let stats = handle
            .runtime_stats()
            .await
            .unwrap_or_else(|e| panic!("stats: {e}"));
        assert!(
            stats.steals_granted >= 1,
            "steal grants must actually happen: {stats:?}"
        );

        drop(hb);
        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
    }

    /// Leak regression: the worker future is aborted wholesale between
    /// the assembly point and the closeout line — on cancel/shutdown
    /// parent-select and task-abort paths the host handle
    /// ([`ExtentHeartbeat`]) leaves the stack and the closeout line (an
    /// explicit `ticker.abort()`) is unreachable. The ticker must be
    /// reaped along the way: after the host dies no beat reaches the
    /// coordinator (`heartbeats_total` freezes). The old form held a
    /// strong host clone and beat forever (the `interval` never ends
    /// and a stopped coordinator maps to `Beat::Live`) — beats survived
    /// host death; this test is its regression.
    #[tokio::test]
    async fn ticker_is_reaped_when_host_dropped_without_abort() {
        let bs = MIN_BLOCK_SIZE;
        let (grid, plan) = fixture(bs, 8, 8);
        let sink = Arc::new(WatchSink::new(bs));
        let (handle, actor) = crate::coordinator::spawn_dynamic_with_rates(
            "8000000000003306",
            grid,
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            1,
            Duration::from_secs(15),
            crate::aimd::AimdConfig::new(1),
            seeded_rates(),
        );
        drain_head(&handle).await;
        let alloc = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("alloc"));
        let alloc_extent_start = alloc.extent.start;
        let hb = ExtentHeartbeat::new(
            handle.clone(),
            0,
            alloc.seg.extent,
            alloc_extent_start,
            bs,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
        );
        let ticker = hb.spawn_ticker();
        // While the ticker lives: at least one beat has arrived and been
        // booked (runtime_stats shares the heartbeat channel FIFO — the
        // reading fences all prior beats).
        let drain = 2 * HEARTBEAT_INTERVAL + Duration::from_millis(300);
        tokio::time::sleep(drain).await;
        let seen = handle
            .runtime_stats()
            .await
            .unwrap_or_else(|e| panic!("stats: {e}"))
            .heartbeats_total;
        assert!(
            seen >= 1,
            "at least one beat arrives while the ticker lives: {seen}"
        );

        // The wholesale worker-future abort shape: the host handle
        // leaves the stack, the closeout line unreachable (dropping a
        // JoinHandle = detach — no wait, no abort; simulates the leak).
        drop(hb);
        drop(ticker);
        // A drain window for in-flight beats (the host-drop vs upgrade
        // race costs at most one more beat), then two consecutive
        // windows assert the count froze — zero beats arrive afterward.
        tokio::time::sleep(drain).await;
        let mid = handle
            .runtime_stats()
            .await
            .unwrap_or_else(|e| panic!("stats: {e}"))
            .heartbeats_total;
        tokio::time::sleep(drain).await;
        let after = handle
            .runtime_stats()
            .await
            .unwrap_or_else(|e| panic!("stats: {e}"))
            .heartbeats_total;
        assert_eq!(
            mid, after,
            "beat count must freeze after host death (no more beats arrive): \
             seen={seen} mid={mid} after={after}"
        );

        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
    }

    /// The boundary arithmetic of report-as-written: a write crossing a
    /// boundary reports exactly the fully covered blocks (partial
    /// blocks and the start block's leading edge are not reported); the
    /// closeout bulk report (the existing worker face) overlapping
    /// report-as-written is absorbed by the decision face's idempotence
    /// (first arrival wins).
    #[tokio::test]
    async fn boundary_reports_track_write_watermark() {
        let bs = MIN_BLOCK_SIZE;
        let (grid, plan) = fixture(bs, 6, 8);
        let sink = Arc::new(WatchSink::new(bs));
        let (handle, actor) = crate::coordinator::spawn_dynamic_with_rates(
            "8000000000003303",
            grid,
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            1,
            Duration::from_secs(15),
            crate::aimd::AimdConfig::new(1),
            seeded_rates(),
        );
        drain_head(&handle).await;
        // W=1: 5 blocks remain -> a 2.5-block extent ([bs, 3.5bs), the
        // sub-block domain).
        let alloc = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("alloc"));
        assert_eq!(alloc.extent.len, 5 * bs / 2);
        let alloc_extent_start = alloc.extent.start;
        let hb = ExtentHeartbeat::new(
            handle.clone(),
            0,
            alloc.seg.extent,
            alloc_extent_start,
            bs,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
        );
        let seg = alloc.seg;

        // First 1.5 blocks: block 1 complete (reported), block 2
        // partial (not).
        hb.write_at(seg, alloc.extent.start, bytes_of(bs + bs / 2))
            .await
            .unwrap_or_else(|e| panic!("write: {e}"));
        // Fence (the FIFO query face): the report-as-written has been
        // serially consumed; completions include block 0 booked by
        // drain_head through the decision face (the sink is the
        // persistence face — the decision's first report reaches it).
        let _ = handle.runtime_stats().await;
        assert_eq!(
            sink.completions(),
            vec![0, 1],
            "reports exactly the first completed block"
        );

        // One more block (crossing block 2's boundary, landing inside
        // the extent's outer edge): exactly block 2 reports.
        hb.write_at(seg, alloc.extent.start + bs + bs / 2, bytes_of(bs / 2))
            .await
            .unwrap_or_else(|e| panic!("write: {e}"));
        let _ = handle.runtime_stats().await;
        assert_eq!(
            sink.completions(),
            vec![0, 1, 2],
            "report-as-written advances block by block"
        );

        // The closeout bulk report (the existing face) re-reports: the
        // decision face keeps first arrival (no double accounting).
        for b in [1u64, 2] {
            handle
                .complete_block(b)
                .await
                .unwrap_or_else(|e| panic!("bulk report: {e}"));
        }
        // Fence (FIFO): the bulk report has been serially consumed.
        let stats = handle
            .runtime_stats()
            .await
            .unwrap_or_else(|e| panic!("stats: {e}"));
        assert!(
            stats.aimd_connections.is_empty(),
            "no rate observation -> AIMD absent"
        );

        drop(hb);
        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
        assert_eq!(
            sink.blocks_done.load(Ordering::Relaxed),
            3,
            "each block reaches the persistence face at most once \
             (duplicate late reports are absorbed by the decision face's \
             first-arrival-wins; late reports never reach the sink)"
        );
    }
}
