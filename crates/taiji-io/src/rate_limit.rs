//! Token-bucket rate limiting: pure token buckets chained as a global and
//! per-torrent pair, exposed as rate-limited streams.
//!
//! Global and per-torrent sides each hold a (down, up) bucket pair, and
//! permits are acquired in series (global first, then per torrent). The
//! peer read/write paths `await` these permits, which naturally pushes
//! back on the TCP/uTP windows.
//!
//! Implementation parameters:
//! - Capacity = rate x 1s (burst <= 1s of bandwidth); cold-start tokens
//! are 0 (no initial burst; a long idle accumulates at most 1s of
//! bandwidth).
//! - Refill = rate x elapsed, settled lazily on demand: pure arithmetic
//! in a short critical section; the std Mutex never spans an await —
//! waiting is driven by runtime timers, never by sleeping with the
//! lock held.
//! - `0 = unlimited` (aria2 option semantics) short-circuits at both the
//! bucket and stream level: the unlimited path is one atomic read plus
//! a branch (no lock, no future, no timer).
//! - Concurrency fairness: FIFO ticket-order grants (first come, first
//! served). Waiters estimate their deadline from the token deficit and
//! re-check when a runtime timer fires; once a grant completes, the new
//! queue head is woken immediately.
//! - Rate hot-update ([`TokenBucket::set_rate`]) is an atomic store plus
//! waking all waiters to re-estimate; it applies to in-flight streams
//! immediately.
//!
//! Upstream anchors: aria2 RequestGroupMan.cc (static quota limiting; no
//! token bucket in aria2), RpcMethodImpl.cc setMaxDownloadSpeedLimit (the
//! hot-update surface). Long-form notes: docs/design/io.md
//!
//! Testability: the deterministic core [`TokenBucket::refill_at`] /
//! [`TokenBucket::try_acquire_at`] takes an injected clock and is covered
//! table-driven for refill, chaining, and 0 = unlimited; async paths are
//! thin real-clock wrappers, and stream-level limiting has an end-to-end
//! synthetic-traffic test (loopback TCP, throughput <= limit x tolerance).
//!
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker, ready};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

/// Per-read staging chunk cap (= BT block size, 16 KiB): the copy
/// granularity of the gated read path; also caps how much data can be
/// be in flight while a permit is pending (one chunk).
const READ_CHUNK: usize = 16 * 1024;

/// Token bucket: an atomic `rate` (bytes/sec) plus bucket state ([`BucketState`]).
///
/// Capacity = rate x 1s; rate = 0 means unlimited (all permit paths short-circuit).
pub struct TokenBucket {
    /// Current rate (bytes/sec); 0 = unlimited. Hot-updated via an atomic
    /// store ([`Self::set_rate`]); applies immediately to queued waiters
    /// and existing [`Acquire`] futures.
    rate: AtomicU64,
    /// Bucket state (short critical section; never spans an await; see module docs).
    state: Mutex<BucketState>,
}

impl std::fmt::Debug for TokenBucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written (the `state` mutex holds live wait tickets and
        // refill arithmetic — Debug must not lock, and the queue is not
        // diagnostics payload): the hot rate renders, the bucket state
        // is redacted.
        f.debug_struct("TokenBucket")
            .field(
                "rate",
                &self.rate.load(std::sync::atomic::Ordering::Relaxed),
            )
            .field("state", &"<redacted>")
            .finish()
    }
}

struct BucketState {
    /// Current tokens (bytes; f64 carries sub-byte precision of continuous refill).
    tokens: f64,
    /// Last refill settlement instant (monotonic clock).
    last: Instant,
    /// FIFO wait queue (ticket-order grants; [`Acquire`] cancellation
    /// removes its entry via `Drop`).
    waiters: VecDeque<Waiter>,
    /// Ticket allocator (monotonically increasing; backs the FIFO fair order).
    next_ticket: u64,
}

struct Waiter {
    ticket: u64,
    /// Demand in bytes captured at enqueue (input to the deficit estimate;
    /// re-clamped to capacity at grant time).
    demand: u64,
    waker: Waker,
}

/// Capacity in bytes = rate x 1s (burst <= 1s of bandwidth).
fn capacity_of(rate: u64) -> f64 {
    rate as f64
}

/// Clamp a single demand to the capacity (rate x 1s): guarantees a permit is
/// reachable at any positive rate (otherwise requests with n > capacity could
/// never be satisfied).
fn clamp_demand(n: u64, rate: u64) -> u64 {
    n.min(rate)
}

impl TokenBucket {
    /// New bucket at `bps` bytes/sec; tokens refill from 0 (no initial burst).
    pub fn new(bps: u64) -> TokenBucket {
        TokenBucket {
            rate: AtomicU64::new(bps),
            state: Mutex::new(BucketState {
                tokens: 0.0,
                last: Instant::now(),
                waiters: VecDeque::new(),
                next_ticket: 0,
            }),
        }
    }

    /// Current rate (bytes/sec; 0 = unlimited).
    pub fn rate(&self) -> u64 {
        self.rate.load(Ordering::Relaxed)
    }

    /// Unlimited (rate = 0) test: the first short-circuit point on every permit path.
    pub fn is_unlimited(&self) -> bool {
        self.rate() == 0
    }

    /// Hot-update the rate (atomic store) and wake all waiters to
    /// re-estimate: a raise grants earlier and a drop to 0 (unlimited)
    /// releases immediately. Applies at once to live [`Throttled`] streams
    /// (shared bucket).
    pub fn set_rate(&self, bps: u64) {
        self.rate.store(bps, Ordering::Relaxed);
        let wakers: Vec<Waker> = {
            let mut st = self.lock_state();
            // New capacity = new rate x 1s: excess tokens truncated (a rate cut keeps no burst).
            st.tokens = st.tokens.min(capacity_of(bps));
            st.waiters.iter().map(|w| w.waker.clone()).collect()
        };
        for w in wakers {
            w.wake();
        }
    }

    /// Lazy refill settlement (deterministic core with an injected clock;
    /// table-driven test surface). Returns the token count after settling.
    /// An unlimited bucket returns positive infinity (no numeric meaning).
    pub fn refill_at(&self, now: Instant) -> f64 {
        let rate = self.rate();
        if rate == 0 {
            return f64::INFINITY;
        }
        let mut st = self.lock_state();
        st.refill(now, rate);
        st.tokens
    }

    /// Deterministic permit attempt (injected clock; no queueing — a
    /// single-threaded table-driven test surface). `Ok(())` = deducted;
    /// `Err(wait)` = out of tokens, with the earliest satisfiable wait.
    pub fn try_acquire_at(&self, n: u64, now: Instant) -> Result<(), Duration> {
        let rate = self.rate();
        if rate == 0 || n == 0 {
            return Ok(());
        }
        let mut st = self.lock_state();
        st.refill(now, rate);
        let want = clamp_demand(n, rate);
        if st.tokens >= want as f64 {
            st.tokens -= want as f64;
            Ok(())
        } else {
            let deficit = want as f64 - st.tokens;
            Err(Duration::from_secs_f64(deficit / rate as f64))
        }
    }

    /// Async permit (owned future: holds the bucket `Arc`, stored in the
    /// [`Throttled`] gate state).
    ///
    /// With 0 = unlimited the future is `Ready` on first poll (no lock, no timer).
    pub fn acquire(self: &Arc<Self>, n: u64) -> Acquire {
        Acquire {
            bucket: Arc::clone(self),
            n,
            ticket: None,
            timer: None,
        }
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, BucketState> {
        crate::lock(&self.state)
    }
}

impl BucketState {
    /// Refill settlement: `tokens += rate x elapsed`, clamped to capacity; advances `last`.
    fn refill(&mut self, now: Instant, rate: u64) {
        if rate == 0 {
            return;
        }
        let elapsed = now.duration_since(self.last);
        if elapsed.is_zero() {
            return;
        }
        self.last = now;
        let gain = elapsed.as_secs_f64() * rate as f64;
        self.tokens = (self.tokens + gain).min(capacity_of(rate));
    }
}

/// Permit future for [`TokenBucket::acquire`]: FIFO ticket queueing with
/// runtime-timer-driven re-checks; cancellation-safe ([`Drop`] removes the
/// queue entry, leaving no ghost waiters).
#[must_use = "futures do nothing unless polled/awaited"]
#[derive(Debug)]
pub struct Acquire {
    bucket: Arc<TokenBucket>,
    /// Demand in bytes (clamped to capacity at grant time).
    n: u64,
    /// Queued ticket (None = not yet enqueued).
    ticket: Option<u64>,
    /// Expiry timer for the re-check (at the estimated deficit time; a stale timer is replaced).
    timer: Option<Pin<Box<Sleep>>>,
}

impl Acquire {
    /// Deficit estimate: queued demand ahead of this ticket, plus this
    /// demand, minus current tokens, converted to time at the current rate
    /// (with continuous refill this estimates when the ticket is served).
    fn estimate_wait(st: &BucketState, ticket: Option<u64>, want: u64, rate: u64) -> Duration {
        if rate == 0 {
            return Duration::ZERO;
        }
        let ahead: f64 = match ticket {
            Some(t) => st
                .waiters
                .iter()
                .take_while(|w| w.ticket != t)
                .map(|w| w.demand as f64)
                .sum(),
            None => 0.0,
        };
        let deficit = (ahead + want as f64 - st.tokens).max(0.0);
        Duration::from_secs_f64(deficit / rate as f64)
    }
}

impl Future for Acquire {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = &mut *self;
        loop {
            // 0 = unlimited short-circuit: a single atomic read returns.
            let rate = this.bucket.rate();
            if rate == 0 {
                return Poll::Ready(());
            }
            let mut st = this.bucket.lock_state();
            st.refill(Instant::now(), rate);
            let want = clamp_demand(this.n, rate);
            let granted = match this.ticket {
                None => {
                    // Fast path: empty queue and enough tokens -> take directly.
                    if st.waiters.is_empty() && st.tokens >= want as f64 {
                        st.tokens -= want as f64;
                        true
                    } else {
                        let ticket = st.next_ticket;
                        st.next_ticket += 1;
                        st.waiters.push_back(Waiter {
                            ticket,
                            demand: want,
                            waker: cx.waker().clone(),
                        });
                        this.ticket = Some(ticket);
                        false
                    }
                }
                Some(ticket) => {
                    // FIFO: only the queue head may be granted.
                    let is_head = matches!(
                        st.waiters.front(),
                        Some(Waiter { ticket: t, .. }) if *t == ticket,
                    );
                    if is_head && st.tokens >= want as f64 {
                        st.waiters.pop_front();
                        st.tokens -= want as f64;
                        true
                    } else {
                        false
                    }
                }
            };
            if granted {
                // Wake the new queue head: it slept on a more conservative
                // deficit and may be serviceable before its own timer fires.
                let next = st.waiters.front().map(|w| w.waker.clone());
                drop(st);
                if let Some(w) = next {
                    w.wake();
                }
                return Poll::Ready(());
            }
            let wait = Self::estimate_wait(&st, this.ticket, want, rate);
            drop(st);
            // 1ms floor: estimate can hit zero before the head gets polled; avoid spinning.
            let wait = wait.max(Duration::from_millis(1));
            let deadline = tokio::time::Instant::from_std(Instant::now() + wait);
            match this.timer.as_mut() {
                Some(t) if t.deadline() <= deadline => {}
                _ => this.timer = Some(Box::pin(tokio::time::sleep_until(deadline))),
            }
            let timer = match this.timer.as_mut() {
                Some(t) => t.as_mut(),
                // Unreachable (the step above always arms it); defensively re-poll now.
                None => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            };
            match timer.poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => continue, // timer fired: re-check in the loop
            }
        }
    }
}

impl Drop for Acquire {
    fn drop(&mut self) {
        // Cancellation safety: drop the queue entry (a ghost waiter would block FIFO forever).
        let Some(ticket) = self.ticket else { return };
        let next = {
            let mut st = self.bucket.lock_state();
            st.waiters.retain(|w| w.ticket != ticket);
            st.waiters.front().map(|w| w.waker.clone())
        };
        if let Some(w) = next {
            w.wake();
        }
    }
}

/// A pair of directional buckets (down = download/read, up = upload/write).
#[derive(Debug)]
pub struct LimiterPair {
    /// Download-direction bucket.
    pub down: Arc<TokenBucket>,
    /// Upload-direction bucket.
    pub up: Arc<TokenBucket>,
}

impl LimiterPair {
    /// New pair (`0 = unlimited`).
    pub fn new(down_bps: u64, up_bps: u64) -> LimiterPair {
        LimiterPair {
            down: Arc::new(TokenBucket::new(down_bps)),
            up: Arc::new(TokenBucket::new(up_bps)),
        }
    }
}

/// Rate-limit topology: a global pair plus a per-torrent pair, chained in
/// series (global first, then the task). `global` shares one bucket
/// instance across tasks (Arc clones); `per_torrent` is per task, so a
/// global limit change only touches the shared bucket.
#[derive(Debug)]
pub struct LimiterSet {
    /// Global (overall) pair: shared session-wide.
    pub global: LimiterPair,
    /// Per-torrent pair: independent per task.
    pub per_torrent: LimiterPair,
}

impl LimiterSet {
    /// Download permit through the chain: global first, then per torrent;
    /// unlimited buckets short-circuit.
    pub async fn acquire_down(&self, n: u64) {
        self.global.down.acquire(n).await;
        self.per_torrent.down.acquire(n).await;
    }

    /// Upload permit through the chain (same order as [`Self::acquire_down`]).
    pub async fn acquire_up(&self, n: u64) {
        self.global.up.acquire(n).await;
        self.per_torrent.up.acquire(n).await;
    }
}

/// Gate state (shared by read and write): idle -> global-bucket permit ->
/// per-torrent-bucket permit. The chain order is fixed, so waits can never
/// form a cycle across buckets.
#[derive(Debug, Default)]
enum Gate {
    #[default]
    Idle,
    /// Waiting on the global bucket.
    Global,
    /// Global passed; waiting on the per-torrent bucket.
    Torrent,
}

/// Rate-limited stream wrapper: the read (download) and write (upload)
/// paths each acquire permits through the chained bucket pair.
///
/// - `limits = None` (or both buckets unlimited) short-circuits with zero
/// overhead: one branch, then straight to the inner stream
/// ([`Throttled::maybe`] with `None` is the bare CLI form).
/// - Read path: read into an internal staging buffer of at most 16 KiB
/// first (never past the permit), then hand the data over with one copy
/// once granted. The socket is untouched while waiting, so the TCP/uTP
/// window is pushed back; the burst upper bound is one chunk.
/// - Write path: write to the inner stream first (at most one wire message
/// in flight) and report completion to the caller only after the permit,
/// so back-pressure propagates up the write half to the message loop.
/// - The permit future is owned by this struct (with the bucket Arc);
/// dropping clears its queue entry (see [`Acquire`]).
pub struct Throttled<S> {
    inner: S,
    limits: Option<Arc<LimiterSet>>,
    read_gate: Gate,
    read_permit: Option<Acquire>,
    /// Read staging buffer (stages data before the gate; reused to
    /// avoid a per-read allocation). Lazily allocated: construction
    /// and the whole passthrough path (unmounted / both buckets
    /// unlimited, read path short-circuits before the gate) are
    /// allocation-free (construction used to pre-pay 16 KiB per
    /// connection); the first gated read builds the chunk via
    /// `get_or_insert_with` ([`empty_read_stage`])
    /// and reuses it.
    read_stage: Option<Box<[u8; READ_CHUNK]>>,
    /// Valid staged byte count (handed over once the permit clears).
    read_staged: usize,
    write_gate: Gate,
    write_permit: Option<Acquire>,
    /// Write-gate bytes in flight (written to the inner stream, permit still pending).
    write_bytes: usize,
}

impl<S> std::fmt::Debug for Throttled<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written (stateful wrapper): the staged buffers carry
        // payload bytes and are shown as counts only; the inner stream
        // is omitted (no `S: Debug` bound is imposed).
        f.debug_struct("Throttled")
            .field("limits", &self.limits)
            .field("read_gate", &self.read_gate)
            .field("read_permit_active", &self.read_permit.is_some())
            .field("read_staged", &self.read_staged)
            .field("write_gate", &self.write_gate)
            .field("write_permit_active", &self.write_permit.is_some())
            .field("write_bytes", &self.write_bytes)
            .finish()
    }
}

impl<S> Throttled<S> {
    /// Attach a rate-limit topology.
    pub fn new(inner: S, limits: Arc<LimiterSet>) -> Throttled<S> {
        Throttled::maybe(inner, Some(limits))
    }

    /// Conditional attach: `None` = pure passthrough (zero-overhead form).
    pub fn maybe(inner: S, limits: Option<Arc<LimiterSet>>) -> Throttled<S> {
        Throttled {
            inner,
            limits,
            read_gate: Gate::Idle,
            read_permit: None,
            read_stage: None,
            read_staged: 0,
            write_gate: Gate::Idle,
            write_permit: None,
            write_bytes: 0,
        }
    }

    /// Unwrap (returns the inner stream; limiting comes off with it).
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Build a staging chunk (lazy-alloc closure): `vec!` places the zeroed
    /// pages straight on the heap without materializing 16 KiB on the
    /// stack (also avoiding the stack materialization of `Box::new([0;
    /// 16KiB])`); `try_into` only fails on a length mismatch, which `vec!`
    /// with the same argument makes impossible.
    fn empty_read_stage() -> Box<[u8; READ_CHUNK]> {
        vec![0u8; READ_CHUNK]
            .try_into()
            .unwrap_or_else(|_| unreachable!("vec length == READ_CHUNK"))
    }

    /// Staged slice (delivery surface once the gate is past Idle): the
    /// chunk is always filled before leaving Idle (the Idle arm builds it
    /// with `get_or_insert_with` before switching gates); same
    /// unreachable! rationale as read_pool `PooledBlock`.
    fn staged(&self, n: usize) -> &[u8] {
        match self.read_stage.as_deref() {
            Some(stage) => &stage[..n],
            None => unreachable!("read_stage filled before leaving Idle gate"),
        }
    }
}

impl<S> Throttled<S>
where
    S: AsyncRead + Unpin,
{
    /// Both buckets unlimited (or unmounted): read-path passthrough test.
    fn read_passthrough(&self) -> bool {
        match &self.limits {
            None => true,
            Some(l) => l.global.down.is_unlimited() && l.per_torrent.down.is_unlimited(),
        }
    }

    /// Read-gate advance: `Idle` stages a read and builds a permit;
    /// `Global`/`Torrent` hand the data over once past the gate.
    fn poll_read_gated(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            match self.read_gate {
                Gate::Idle => {
                    if out.remaining() == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    // Staging read: at most one chunk per poll (the burst
                    // in flight while a permit pends is one chunk). The
                    // staging buffer is built lazily on the first gated
                    // read, then reused; passthrough streams never build it.
                    let cap = out.remaining().min(READ_CHUNK);
                    let mut buf = ReadBuf::new(
                        &mut self.read_stage.get_or_insert_with(Self::empty_read_stage)[..cap],
                    );
                    ready!(Pin::new(&mut self.inner).poll_read(cx, &mut buf))?;
                    let n = buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(())); // EOF
                    }
                    self.read_staged = n;
                    let Some(limits) = self.limits.clone() else {
                        // Defensive ungated passthrough (passthrough test already filtered this).
                        out.put_slice(self.staged(n));
                        self.read_staged = 0;
                        return Poll::Ready(Ok(()));
                    };
                    // Permit chain: global first, then per torrent; skip unlimited buckets.
                    if !limits.global.down.is_unlimited() {
                        self.read_permit = Some(limits.global.down.acquire(n as u64));
                        self.read_gate = Gate::Global;
                    } else {
                        self.read_permit = Some(limits.per_torrent.down.acquire(n as u64));
                        self.read_gate = Gate::Torrent;
                    }
                }
                Gate::Global => {
                    let Some(permit) = self.read_permit.as_mut() else {
                        self.read_gate = Gate::Idle; // defensive: gate-state invariant
                        continue;
                    };
                    ready!(Pin::new(permit).poll(cx));
                    let Some(limits) = self.limits.clone() else {
                        self.read_gate = Gate::Idle;
                        continue;
                    };
                    if limits.per_torrent.down.is_unlimited() {
                        self.read_permit = None;
                        self.read_gate = Gate::Idle;
                        let n = self.read_staged;
                        self.read_staged = 0;
                        out.put_slice(self.staged(n));
                        return Poll::Ready(Ok(()));
                    }
                    let n = self.read_staged;
                    self.read_permit = Some(limits.per_torrent.down.acquire(n as u64));
                    self.read_gate = Gate::Torrent;
                }
                Gate::Torrent => {
                    let Some(permit) = self.read_permit.as_mut() else {
                        self.read_gate = Gate::Idle;
                        continue;
                    };
                    ready!(Pin::new(permit).poll(cx));
                    self.read_permit = None;
                    self.read_gate = Gate::Idle;
                    let n = self.read_staged;
                    self.read_staged = 0;
                    out.put_slice(self.staged(n));
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S> AsyncRead for Throttled<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.read_passthrough() {
            // Zero-overhead short-circuit: one test, then passthrough (no copy, lock, or future).
            return Pin::new(&mut this.inner).poll_read(cx, out);
        }
        this.poll_read_gated(cx, out)
    }
}

impl<S> Throttled<S>
where
    S: AsyncWrite + Unpin,
{
    /// Both buckets unlimited (or unmounted): write-path passthrough test.
    fn write_passthrough(&self) -> bool {
        match &self.limits {
            None => true,
            Some(l) => l.global.up.is_unlimited() && l.per_torrent.up.is_unlimited(),
        }
    }
}

impl<S> AsyncWrite for Throttled<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.write_passthrough() {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        loop {
            match this.write_gate {
                Gate::Idle => {
                    let n = ready!(Pin::new(&mut this.inner).poll_write(cx, buf))?;
                    if n == 0 {
                        return Poll::Ready(Ok(0));
                    }
                    let Some(limits) = this.limits.clone() else {
                        return Poll::Ready(Ok(n));
                    };
                    this.write_bytes = n;
                    // Permit chain: global first, then per torrent; skip unlimited buckets.
                    if !limits.global.up.is_unlimited() {
                        this.write_permit = Some(limits.global.up.acquire(n as u64));
                        this.write_gate = Gate::Global;
                    } else {
                        this.write_permit = Some(limits.per_torrent.up.acquire(n as u64));
                        this.write_gate = Gate::Torrent;
                    }
                }
                Gate::Global => {
                    let Some(permit) = this.write_permit.as_mut() else {
                        this.write_gate = Gate::Idle; // defensive: gate-state invariant
                        continue;
                    };
                    ready!(Pin::new(permit).poll(cx));
                    let Some(limits) = this.limits.clone() else {
                        this.write_gate = Gate::Idle;
                        continue;
                    };
                    if limits.per_torrent.up.is_unlimited() {
                        this.write_permit = None;
                        this.write_gate = Gate::Idle;
                        return Poll::Ready(Ok(this.write_bytes));
                    }
                    let n = this.write_bytes;
                    this.write_permit = Some(limits.per_torrent.up.acquire(n as u64));
                    this.write_gate = Gate::Torrent;
                }
                Gate::Torrent => {
                    let Some(permit) = this.write_permit.as_mut() else {
                        this.write_gate = Gate::Idle;
                        continue;
                    };
                    ready!(Pin::new(permit).poll(cx));
                    this.write_permit = None;
                    this.write_gate = Gate::Idle;
                    return Poll::Ready(Ok(this.write_bytes));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    /// Table step: `(relative time ms, request bytes, expected Err wait ms | Ok)`.
    type Step = (u64, u64, Result<(), u64>);

    /// Deterministic timeline driver: runs [`TokenBucket::try_acquire_at`] step by step from `t0`.
    fn run_table(bucket: &TokenBucket, t0: Instant, table: &[Step]) {
        for (ms, n, want) in table {
            let got = bucket.try_acquire_at(*n, t0 + Duration::from_millis(*ms));
            match (*want, got) {
                (Ok(()), Ok(())) => {}
                (Err(want_ms), Err(wait)) => {
                    let got_ms = wait.as_secs_f64() * 1000.0;
                    // Tolerance for deficit-to-time conversion: sub-ms rounding.
                    assert!(
                        (got_ms - want_ms as f64).abs() <= 1.5,
                        "at {ms}ms acquire({n}): want {want_ms}ms wait, got {got_ms:.3}ms"
                    );
                }
                (want, got) => panic!("at {ms}ms acquire({n}): want {want:?}, got {got:?}"),
            }
        }
    }

    #[test]
    fn refill_accumulates_at_rate_and_caps_capacity() {
        let b = TokenBucket::new(1000);
        let t0 = Instant::now();
        // Idle 2s: refill clamped to capacity = rate x 1s = 1000 (burst <= 1s of bandwidth).
        let tokens = b.refill_at(t0 + Duration::from_secs(2));
        assert!(
            (tokens - 1000.0).abs() < 1.0,
            "capped at capacity, got {tokens}"
        );
        // Half a second refills only 500.
        let b2 = TokenBucket::new(1000);
        let tokens = b2.refill_at(t0 + Duration::from_millis(500));
        assert!((tokens - 500.0).abs() < 1.0, "got {tokens}");
        // Unlimited buckets have no numeric meaning.
        let free = TokenBucket::new(0);
        assert_eq!(free.refill_at(t0), f64::INFINITY);
    }

    #[test]
    fn acquire_deducts_and_reports_deficit_wait() {
        let b = TokenBucket::new(1000);
        let t0 = Instant::now();
        run_table(
            &b,
            t0,
            &[
                (0, 400, Err(400)),   // cold start at 0 tokens; 400B @1000B/s = 0.4s
                (0, 400, Err(400)),   // same-instant retry: no time passes, no refill
                (400, 700, Err(300)), // +400 refilled; 700 needs 0.3s more
                (700, 700, Ok(())),   // refill caught up
            ],
        );
    }

    #[test]
    fn zero_rate_is_unlimited_short_circuit() {
        let b = TokenBucket::new(0);
        let t0 = Instant::now();
        // Huge over-capacity requests pass at once (short-circuit, not queueing).
        let start = Instant::now();
        for _ in 0..1000 {
            assert!(b.try_acquire_at(u64::MAX / 2, t0).is_ok(), "unlimited");
        }
        assert!(
            start.elapsed() < Duration::from_millis(50),
            "unlimited path must be near-zero cost"
        );
        assert!(b.is_unlimited());
    }

    #[test]
    fn chained_dual_buckets_gate_in_series() {
        // Global 2000B/s + per torrent 1000B/s: chained effective rate = min = 1000.
        let set = LimiterSet {
            global: LimiterPair::new(2000, 0),
            per_torrent: LimiterPair::new(1000, 0),
        };
        let t0 = Instant::now();
        // Global debited first: 1200B -> global at 0 (0.6s deficit).
        run_table(
            &set.global.down,
            t0,
            &[(0, 1200, Err(600)), (600, 500, Ok(()))],
        );
        // The torrent bucket accounts independently: the global debit does
        // not touch torrent tokens (600ms refills 600; take 500, 100 left;
        // another 300 needs 200ms more).
        run_table(
            &set.per_torrent.down,
            t0,
            &[(600, 500, Ok(())), (600, 300, Err(200))],
        );
        // Unlimited buckets short-circuit in the chain: global unlimited -> only torrent acts.
        let set2 = LimiterSet {
            global: LimiterPair::new(0, 0),
            per_torrent: LimiterPair::new(1000, 0),
        };
        // Over-capacity demand clamped to rate: 10KB @1000B/s -> 1KB permit -> wait 1s.
        run_table(&set2.per_torrent.down, t0, &[(0, 10_000, Err(1000))]);
        assert!(set2.global.down.is_unlimited());
    }

    #[test]
    fn request_above_capacity_is_clamped_and_served() {
        let b = TokenBucket::new(1000);
        let t0 = Instant::now();
        // A 10KB request > capacity (1KB) is clamped to capacity; from an
        // empty bucket the first permit waits 1s — reachable at any
        // positive rate (never hangs).
        let Err(wait) = b.try_acquire_at(10_000, t0) else {
            panic!("empty bucket must defer");
        };
        assert!((wait.as_secs_f64() - 1.0).abs() < 0.01);
    }

    /// Concurrency fairness: FIFO ticket-order grants (first come, first served; no starvation).
    #[tokio::test]
    async fn concurrent_acquire_is_fifo_fair() {
        let bucket = Arc::new(TokenBucket::new(200_000));
        let order = Arc::new(Mutex::new(Vec::<usize>::new()));
        let mut tasks = Vec::new();
        for i in 0..3usize {
            let bucket = Arc::clone(&bucket);
            let order = Arc::clone(&order);
            tasks.push(tokio::spawn(async move {
                // Stagger enqueue: larger i polls later, so ticket order = arrival order.
                tokio::time::sleep(Duration::from_millis(30 * i as u64)).await;
                bucket.acquire(120_000).await;
                order.lock().unwrap_or_else(|e| e.into_inner()).push(i);
            }));
        }
        // 3x120KB @200KB/s = 1.8s total deficit; generous bound for CI jitter.
        tokio::time::timeout(Duration::from_secs(15), futures_all(tasks))
            .await
            .unwrap_or_else(|_| panic!("acquirers must complete (no starvation)"));
        let order = order.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(&*order, &[0usize, 1, 2], "FIFO ticket order must hold");
    }

    async fn futures_all(tasks: Vec<tokio::task::JoinHandle<()>>) {
        for t in tasks {
            t.await.unwrap_or_else(|e| panic!("task join: {e}"));
        }
    }

    #[tokio::test]
    async fn set_rate_hot_update_releases_waiters_immediately() {
        let bucket = Arc::new(TokenBucket::new(1_000));
        let slow = Arc::clone(&bucket);
        let slow_task = tokio::spawn(async move {
            // 100KB @1KB/s = 100s (infeasible at the old rate); must be <2s after the update.
            slow.acquire(100_000).await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await; // enqueue
        bucket.set_rate(1_000_000); // hot update: x1000
        tokio::time::timeout(Duration::from_secs(2), slow_task)
            .await
            .unwrap_or_else(|_| panic!("hot rate update must take effect immediately"))
            .unwrap_or_else(|e| panic!("join: {e}"));
        assert_eq!(bucket.rate(), 1_000_000);
    }

    /// Loopback TCP synthetic traffic: gated read throughput <= limit x tolerance (end to end).
    #[tokio::test]
    async fn throttled_read_limits_loopback_throughput() {
        const TOTAL: usize = 48 * 1024;
        const RATE: u64 = 16 * 1024; // 48KB @16KB/s ~ 3s
        let (mut writer, reader) = tokio::io::duplex(READ_CHUNK);
        let limits = Arc::new(LimiterSet {
            global: LimiterPair::new(0, 0),
            per_torrent: LimiterPair::new(RATE, 0),
        });
        let pump = tokio::spawn(async move {
            let payload = vec![7u8; TOTAL];
            writer
                .write_all(&payload)
                .await
                .unwrap_or_else(|e| panic!("pump write: {e}"));
        });
        let mut throttled = Throttled::new(reader, limits);
        let mut got = Vec::new();
        let started = Instant::now();
        tokio::time::timeout(Duration::from_secs(30), async {
            throttled
                .read_to_end(&mut got)
                .await
                .unwrap_or_else(|e| panic!("read ok: {e}"));
        })
        .await
        .unwrap_or_else(|e| panic!("read must complete (no starvation): {e}"));
        let elapsed = started.elapsed();
        pump.await.unwrap_or_else(|e| panic!("pump join: {e}"));
        assert_eq!(got.len(), TOTAL);
        assert!(got.iter().all(|&b| b == 7));
        // Lower bound = total/rate x 0.8 (staging and first in-flight chunk tolerance).
        let theoretical = TOTAL as f64 / RATE as f64;
        assert!(
            elapsed.as_secs_f64() >= theoretical * 0.8,
            "throughput exceeded limit: {elapsed:?} < {theoretical}s"
        );
        assert!(
            elapsed.as_secs_f64() <= theoretical * 3.0,
            "pathologically slow: {elapsed:?}"
        );
    }

    /// Loopback TCP synthetic traffic: gated write throughput <= limit x tolerance (end to end).
    #[tokio::test]
    async fn throttled_write_limits_loopback_throughput() {
        const TOTAL: usize = 48 * 1024;
        const RATE: u64 = 16 * 1024;
        let (client, mut server) = tokio::io::duplex(READ_CHUNK);
        let limits = Arc::new(LimiterSet {
            global: LimiterPair::new(0, 0),
            per_torrent: LimiterPair::new(0, RATE),
        });
        let mut throttled = Throttled::new(client, limits);
        let payload = vec![9u8; TOTAL];
        // Concurrent reads on the receiver (if the peer never reads, the
        // duplex buffer fills and the writer goes Pending — the
        // back-pressure semantics itself; the test drains concurrently).
        let sink = tokio::spawn(async move {
            let mut got = Vec::new();
            server
                .read_to_end(&mut got)
                .await
                .unwrap_or_else(|e| panic!("read ok: {e}"));
            got
        });
        let started = Instant::now();
        tokio::time::timeout(Duration::from_secs(30), async {
            throttled
                .write_all(&payload)
                .await
                .unwrap_or_else(|e| panic!("write ok: {e}"));
            throttled
                .flush()
                .await
                .unwrap_or_else(|e| panic!("flush ok: {e}"));
        })
        .await
        .unwrap_or_else(|e| panic!("write must complete (no starvation): {e}"));
        let elapsed = started.elapsed();
        throttled
            .shutdown()
            .await
            .unwrap_or_else(|e| panic!("shutdown ok: {e}"));
        let got = sink.await.unwrap_or_else(|e| panic!("sink join: {e}"));
        assert_eq!(got.len(), TOTAL);
        assert!(got.iter().all(|&b| b == 9));
        let theoretical = TOTAL as f64 / RATE as f64;
        assert!(
            elapsed.as_secs_f64() >= theoretical * 0.8,
            "throughput exceeded limit: {elapsed:?} < {theoretical}s"
        );
        assert!(elapsed.as_secs_f64() <= theoretical * 3.0);
    }

    #[tokio::test]
    async fn unlimited_set_and_none_limits_are_passthrough() {
        // Both buckets unlimited + 1MiB: near-instant (zero-overhead short-circuit).
        let payload = vec![1u8; 1024 * 1024];
        let expected = payload.len();
        let (mut tx, rx) = tokio::io::duplex(READ_CHUNK);
        let limits = Arc::new(LimiterSet {
            global: LimiterPair::new(0, 0),
            per_torrent: LimiterPair::new(0, 0),
        });
        let mut reader = Throttled::new(rx, limits);
        let write = tokio::spawn(async move {
            tx.write_all(&payload)
                .await
                .unwrap_or_else(|e| panic!("write: {e}"));
        });
        let started = Instant::now();
        let mut got = Vec::new();
        reader
            .read_to_end(&mut got)
            .await
            .unwrap_or_else(|e| panic!("read: {e}"));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "unlimited passthrough"
        );
        assert_eq!(got.len(), expected);
        write.await.unwrap_or_else(|e| panic!("join: {e}"));

        // limits = None: passthrough on the same surface.
        let payload = vec![1u8; 1024 * 1024];
        let (tx, rx) = tokio::io::duplex(READ_CHUNK);
        let mut reader = Throttled::maybe(rx, None);
        let write = tokio::spawn(async move {
            let mut tx = tx;
            tx.write_all(&payload)
                .await
                .unwrap_or_else(|e| panic!("write: {e}"));
        });
        let mut got = Vec::new();
        reader
            .read_to_end(&mut got)
            .await
            .unwrap_or_else(|e| panic!("read: {e}"));
        assert_eq!(got.len(), expected);
        write.await.unwrap_or_else(|e| panic!("join: {e}"));
        let _inner = reader.into_inner();
    }

    /// Staging-buffer lazy allocation: passthrough (unmounted / both
    /// buckets unlimited) construction and reads allocate nothing
    /// (construction used to pre-pay 16 KiB per connection); gated
    /// construction is also allocation-free, and only the first gated read
    /// builds the chunk (a full 16 KiB).
    #[tokio::test]
    async fn read_stage_lazy_allocated_only_for_gated_reads() {
        // Unmounted (None = bare CLI form): construction allocates nothing.
        let (mut tx, rx) = tokio::io::duplex(READ_CHUNK);
        let mut passthrough = Throttled::maybe(rx, None);
        assert!(
            passthrough.read_stage.is_none(),
            "no allocation at construction"
        );
        tx.write_all(&[1, 2, 3])
            .await
            .unwrap_or_else(|e| panic!("write: {e}"));
        let mut buf = [0u8; 3];
        passthrough
            .read_exact(&mut buf)
            .await
            .unwrap_or_else(|e| panic!("read: {e}"));
        assert_eq!(
            &buf,
            &[1, 2, 3],
            "passthrough data skips the staging buffer"
        );
        assert!(
            passthrough.read_stage.is_none(),
            "passthrough reads never build the chunk"
        );

        // Both buckets unlimited: topology attached, same short-circuit, no construction alloc.
        let limits = Arc::new(LimiterSet {
            global: LimiterPair::new(0, 0),
            per_torrent: LimiterPair::new(0, 0),
        });
        let (_tx, rx) = tokio::io::duplex(READ_CHUNK);
        let unlimited = Throttled::new(rx, limits);
        assert!(
            unlimited.read_stage.is_none(),
            "unlimited buckets allocate nothing at construction"
        );

        // Gated (finite torrent bucket): no construction alloc; first gated read builds it.
        let limits = Arc::new(LimiterSet {
            global: LimiterPair::new(0, 0),
            per_torrent: LimiterPair::new(1 << 20, 0),
        });
        let (mut tx, rx) = tokio::io::duplex(READ_CHUNK);
        let mut gated = Throttled::new(rx, limits);
        assert!(
            gated.read_stage.is_none(),
            "gated construction is likewise allocation-free"
        );
        tx.write_all(&[4, 5, 6])
            .await
            .unwrap_or_else(|e| panic!("write: {e}"));
        let mut buf = [0u8; 3];
        gated
            .read_exact(&mut buf)
            .await
            .unwrap_or_else(|e| panic!("read: {e}"));
        let stage = gated
            .read_stage
            .as_deref()
            .unwrap_or_else(|| panic!("the first gated read must build the chunk"));
        assert_eq!(stage.len(), READ_CHUNK, "a full 16KiB chunk");
        assert_eq!(
            &buf,
            &[4, 5, 6],
            "data delivered through the staging buffer"
        );
    }
}
