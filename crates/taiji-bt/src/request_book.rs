//! RequestBook: per-peer request bookkeeping plus adaptive windowing
//! (the peer-wire request rules). Outstanding request slots per peer; window sizes in
//! blocks; all time caller-injected for deterministic tests. Window
//! modes: BDP rate-driven (default,
//! `clamp(3s x rate EWMA / 16KiB, floor, cap)` with slow start) or the
//! legacy doubling fallback. Adaptive per-peer request timeout
//! (mean + 4 x avg deviation, capped by the configured timeout, floored
//! at 2s). Timed-out/cancelled slots enter a late-delivery grace registry
//! (redelivery counts as redundancy, not unsolicited). Lock-free mirrors
//! publish engine-facing values from single authoritative fields. Also
//! houses the flood guard and the HAVE advertiser.
//!
//! Upstream anchor mapping and divergence notes: docs/design/request-window.md
//!
//! # Relation to the v2 request semantics
//!
//! A piece that matches no outstanding slot in `on_piece` is an
//! unsolicited piece: the caller must disconnect (the peer-wire rule). Slot keys
//! are [`crate::piece_id::PieceId`]; a bare global piece index is
//! forbidden.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::piece_id::PieceId;

/// Initial window (aria2 `BtConstants.h` anchor). No longer the knob
/// default: the initial window comes from `taiji_io::knobs::req_window_init`
/// (default 16); an explicit `BH_REQ_WINDOW_INIT=6` restores this constant
/// bit-for-bit (knob surface in [`initial_window_from_env`]).
pub const DEFAULT_MAX_OUTSTANDING_REQUEST: usize = 6;
/// Window cap (aria2 `BtConstants.h`).
pub const UB_MAX_OUTSTANDING_REQUEST: usize = 256;
/// Default value of `--bt-request-timeout` (aria2 `OptionHandlerFactory.cc`;
/// configured range 1..=600).
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Flood-check interval (aria2 `DefaultBtInteractive.cc`
/// `FLOODING_CHECK_INTERVAL`).
pub const FLOODING_CHECK_INTERVAL: Duration = Duration::from_secs(5);
/// Flood threshold (keepalive dimension; aria2 `DefaultBtInteractive.cc`
/// original value 2): 2+ keepalives within one 5s check window disconnect.
/// aria2's own keepalive interval is 120s (`--bt-keep-alive-interval`,
/// `OptionHandlerFactory.cc`), so 2 per 5s can only be abuse. For the
/// choke/unchoke flip dimension see [`FLOODING_CHOKE_FLIP_THRESHOLD`];
/// this constant now covers keepalive only (value unchanged).
pub const FLOODING_THRESHOLD: u32 = 2;
/// Flood threshold (choke/unchoke flip dimension): 2 -> 20.
///
/// Safety argument: BEP 3 makes choking a routine, high-frequency signal
/// (tit-for-tat plus optimistic rotation requires frequent flips), and
/// libtorrent neither rate-limits nor disconnects on them
/// (`incoming_choke` / `incoming_unchoke` only update state,
/// `peer_connection.cpp`). aria2's original 2 (`DefaultBtInteractive.cc`)
/// is oversensitive on real swarms, where legitimate rotation was observed
/// up to ~5 flips/window; 20 = that bound x 4 margin, still catching
/// sustained 4+ flips/second. Mechanism unchanged.
pub const FLOODING_CHOKE_FLIP_THRESHOLD: u32 = 20;
/// Grace after we send a Choke frame during which the peer may still send
/// requests: within the grace they are answered with reject (BEP 3
/// choking semantics); past it, a request is a protocol violation and
/// disconnects ([`crate::peer::PeerError::RequestsWhileChoked`]).
/// libtorrent `peer_connection.cpp`: after choke, inbound requests are
/// rejected with reject_request, and it will "allow peers to send request
/// up to 2 seconds after getting choke, then disconnect them"
/// (`too_many_requests_when_choked`). Intentional divergence: libtorrent's
/// `m_last_choke` clock also covers the initially-choked phase; here the
/// clock starts only when a Choke frame is actually sent, so requests in
/// that phase are rejected but never disconnect (pipelining tolerance).
pub const CHOKE_REQUEST_GRACE: Duration = Duration::from_secs(2);
/// HAVE advertisement expiry (aria2 `HaveEraseCommand.cc`: entries older
/// than now - 5s are dropped).
pub const HAVE_EXPIRY: Duration = Duration::from_secs(5);

/// Adaptive-timeout lower bound (libtorrent `peer_connection.cpp`:
/// "timeouts should never be less than 2 seconds. The granularity is
/// whole seconds, and only checked once per second. 2 is the minimum to
/// avoid being considered timed out instantly").
pub const MIN_ADAPTIVE_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// BDP target-window lower bound (libtorrent `peer_connection.cpp`
/// `min_request_queue = 2`, the fallback arm of
/// `update_desired_queue_size`).
pub const MIN_REQUEST_WINDOW: usize = 2;

/// BDP target-window real-network floor. A peer's supply rate responds
/// causally to our request depth (peers schedule by rotating through the
/// request queue): a low rate sample collapses the BDP target to 2-4
/// blocks, the peer schedules us less often, the rate drops further — a
/// self-locking loop; in controlled high-throughput settings the floor
/// never binds. Intentional divergence from libtorrent
/// `min_request_queue = 2`: the floor defaults to 64 blocks (1 MiB in
/// flight per peer, ~19 MiB worst case at 50 peers; bounded block pool);
/// `BH_REQ_WINDOW_FLOOR=2` restores libtorrent bit-for-bit, `=24` the
/// earlier floor. Never exceeds the cap; snub/timeout handling is not
/// protected by the floor.
fn bdp_window_floor() -> usize {
    taiji_io::knobs::req_window_floor(MIN_REQUEST_WINDOW)
}

/// BDP window time factor (libtorrent `settings_pack.cpp`
/// `request_queue_time`, default 3 seconds; consumed in
/// `peer_connection.cpp`).
pub const REQUEST_QUEUE_TIME: Duration = Duration::from_secs(3);

/// Request block granularity, 16 KiB (BEP 3 convention, 2^14; the
/// reference notes "16 kB is the size of each request",
/// libtorrent `peer_connection.cpp`). Same value as
/// `taiji_store::merkle::BLOCK_SIZE`; the bt layer does not depend on the
/// store, so the shared literal is duplicated — the BDP denominator.
pub const REQUEST_BLOCK_SIZE: u64 = 16 * 1024;

/// Rate window granularity, 1s (reference `stat_channel::second_tick`
/// ticks once per second, `stat.cpp`; locally the lazy-settle gate: settle
/// only once the window is at least this old).
const RATE_WINDOW: Duration = Duration::from_secs(1);

/// Rate EWMA inverse gain (reference `stat.cpp`:
/// `m_5_sec_average = m_5_sec_average * 4/5 + sample / 5`).
const RATE_EWMA_INVERTED_GAIN: i64 = 5;

/// Rate EWMA long-window inverse gain (jitter adaptation): enabled after
/// slow-start exit (alpha 1/10, ten 1s rate windows = ~10s smoothing).
/// Stand-in alignment with aria2's rate smoothing window
/// `SPEED_WINDOW = 10_s` (`SpeedCalc.cc`); the reference alpha 1/5
/// (`stat.cpp`) remains for slow start and fallback. Intentional
/// divergence: libtorrent has no longer rate window (`m_5_sec_average`
/// only). `BH_RATE_EWMA_LONG=0` restores the reference bit-for-bit.
const RATE_EWMA_LONG_INVERTED_GAIN: i64 = 10;

/// BDP window hysteresis low-gate numerator (shrink only when the new
/// target < current window x 7/10). No libtorrent counterpart
/// (intentional divergence); `BH_BDP_WINDOW_HYSTERESIS=0` restores
/// direct assignment.
const WINDOW_HYSTERESIS_LOW_NUM: u64 = 7;
/// BDP window hysteresis high-gate numerator (grow only when the new
/// target > current window x 13/10; inside the band the window holds).
/// Same source as [`WINDOW_HYSTERESIS_LOW_NUM`].
const WINDOW_HYSTERESIS_HIGH_NUM: u64 = 13;
/// Common denominator of the hysteresis gates (ratios 7/10 and 13/10).
const WINDOW_HYSTERESIS_DEN: u64 = 10;

/// Request-window mode: BDP rate-driven (default) or the legacy doubling
/// heuristic (fallback path).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WindowMode {
    /// BDP-driven (default): target window =
    /// `clamp(3s x payload rate EWMA / 16KiB, 2, cap)`, +1 per received
    /// block during slow start (libtorrent `peer_connection.cpp`).
    #[default]
    Bdp,
    /// Legacy constant-heuristic fallback: double 6->256 once a quarter of
    /// the round completes (aria2 `DefaultBtInteractive.cc`). Selected by
    /// `BH_REQUEST_WINDOW_BDP=0`.
    LegacyDoubling,
}

impl WindowMode {
    /// Environment default: `BH_REQUEST_WINDOW_BDP=0` selects the doubling
    /// fallback; unset or any other value selects BDP. Evaluated on every
    /// [`RequestBook`] construction (process-level switch, not hot-reload);
    /// deterministic tests pin it via [`RequestBook::with_window_mode`].
    /// Parsing and read timing are registered in `taiji_io::knobs`.
    pub fn from_env() -> WindowMode {
        if taiji_io::knobs::request_window_bdp_enabled() {
            WindowMode::Bdp
        } else {
            WindowMode::LegacyDoubling
        }
    }
}

/// Rate EWMA long-window environment default: only `BH_RATE_EWMA_LONG=0`
/// disables it (restoring reference alpha 1/5 bit-for-bit); unset or any
/// other value means on. Evaluated on every [`RequestBook`] construction
/// (process-level switch; same pattern as [`WindowMode::from_env`]).
/// Parsing is registered in `taiji_io::knobs`.
fn rate_ewma_long_from_env() -> bool {
    taiji_io::knobs::rate_ewma_long_enabled()
}

/// BDP window hysteresis environment default: only
/// `BH_BDP_WINDOW_HYSTERESIS=0` disables it (restoring direct recompute-
/// and-assignment bit-for-bit); unset or any other value means on. Same
/// pattern as above. Parsing is registered in `taiji_io::knobs`.
fn window_hysteresis_from_env() -> bool {
    taiji_io::knobs::bdp_window_hysteresis_enabled()
}

/// Initial request-window depth (slow-start start) environment
/// default: `BH_REQ_WINDOW_INIT` falls back to 16 when unset or
/// unparseable — decoupled from [`DEFAULT_MAX_OUTSTANDING_REQUEST`] (the
/// aria2 anchor); an explicit `=6` restores that anchor exactly.
/// Clamped to [2, 256] ([`MIN_REQUEST_WINDOW`] /
/// [`UB_MAX_OUTSTANDING_REQUEST`]). Evaluated on every [`RequestBook`]
/// construction (same pattern as [`bdp_window_floor`]; no caching).
fn initial_window_from_env() -> usize {
    taiji_io::knobs::req_window_init()
}

/// Peer download payload-rate EWMA (libtorrent `stat.cpp`
/// `stat_channel::second_tick`, plus a first-sample-seeding divergence;
/// source chain: docs/design/request-window.md). Integer arithmetic
/// (reference-shaped integer division); time is injected by the caller.
/// Settlement: once the window is at least [`RATE_WINDOW`] old,
/// `sample = acc x 1000 / elapsed_ms` (B/s); `value` is seeded directly
/// on the first window, afterwards `value x (g-1)/g + sample / g` (g =
/// inverse gain, chosen per slow-start/fallback state); an idle window
/// decays the reading toward 0 by 1/g.
#[derive(Debug)]
struct RateEwma {
    /// EWMA reading (B/s; reference `m_5_sec_average`).
    value: i64,
    /// Unsettled-window payload byte accumulator (reference `m_counter`).
    acc: u64,
    /// Unsettled-window start (None = no payload seen yet: the window is
    /// established by the first sample, so the idle span before the first
    /// block cannot crush the reading).
    window_start: Option<Instant>,
    /// First sample seeded (one-shot switch for the first-sample arm).
    seeded: bool,
}

impl RateEwma {
    fn new() -> RateEwma {
        RateEwma {
            value: 0,
            acc: 0,
            window_start: None,
            seeded: false,
        }
    }

    /// Record payload bytes (no settlement; the window starts at the
    /// first sample).
    fn add(&mut self, bytes: u64, now: Instant) {
        self.acc += bytes;
        if self.window_start.is_none() {
            self.window_start = Some(now);
        }
    }

    /// Lazy settlement: once the window is at least [`RATE_WINDOW`] old,
    /// settle and open a new window; returns whether settlement happened.
    /// `inverted_gain` = EWMA inverse gain (reference-shaped
    /// `x(g-1)/g + sample/g`; the first-sample arm does not consume the
    /// gain). A backwards clock (now < start) defensively does not settle.
    fn settle(&mut self, now: Instant, inverted_gain: i64) -> bool {
        let Some(start) = self.window_start else {
            return false;
        };
        let Some(elapsed) = now.checked_duration_since(start) else {
            return false;
        };
        if elapsed < RATE_WINDOW {
            return false;
        }
        let ms = i64::try_from(elapsed.as_millis())
            .unwrap_or(i64::MAX)
            .max(1);
        let sample = i64::try_from(self.acc).unwrap_or(i64::MAX) * 1000 / ms;
        self.value = if self.seeded {
            // Reference formula (stat.cpp): x(g-1)/g + sample/g (integer
            // division).
            self.value * (inverted_gain - 1) / inverted_gain + sample / inverted_gain
        } else {
            // First sample seeds directly (divergence: slow start covers
            // only the no-sample period, so the first rate evidence must
            // be immediately usable).
            self.seeded = true;
            sample
        };
        self.acc = 0;
        self.window_start = Some(now);
        true
    }
}

/// Request-response RTT sliding statistics: EWMA mean + avg deviation.
/// Port of libtorrent `sliding_average<int, 20>`: fixed point x64
/// ([`Self::FIXED_POINT`]), gain 20 ([`Self::INVERTED_GAIN`] — at most 20
/// samples counted, an equivalent sliding window); `avg_deviation` lags
/// the mean by one sample (non-zero from 2+ samples on). Samples are
/// milliseconds (the reference samples `total_milliseconds` at the
/// incoming-piece point, `peer_connection.cpp`).
///
/// The carrier is i64; the reference uses i32 with an overflow-clamp
/// branch at `s >= Int::MAX/64/4`. Locally samples top out at
/// 600x10^3 ms x64 = 3.8x10^7 — that branch is unreachable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RttSamples {
    mean_fp: i64,
    avg_dev_fp: i64,
    num_samples: i32,
}

impl RttSamples {
    /// Fixed-point multiplier (reference `fixed_point = 64`).
    const FIXED_POINT: i64 = 64;
    /// Inverse gain (reference `inverted_gain = 20`, `peer_connection.hpp`).
    const INVERTED_GAIN: i32 = 20;

    /// Sample in milliseconds (same shape as reference
    /// `sliding_average::add_sample`: the deviation lags one sample; mean
    /// and deviation each smooth over their own sample count).
    pub fn add_sample(&mut self, sample_ms: i64) {
        let s = sample_ms * Self::FIXED_POINT;
        let deviation = if self.num_samples > 0 {
            (self.mean_fp - s).abs()
        } else {
            0
        };
        if self.num_samples < Self::INVERTED_GAIN {
            self.num_samples += 1;
        }
        self.mean_fp += (s - self.mean_fp) / i64::from(self.num_samples);
        if self.num_samples > 1 {
            self.avg_dev_fp += (deviation - self.avg_dev_fp) / i64::from(self.num_samples - 1);
        }
    }

    /// Mean in milliseconds (reference `mean()`: `(m_mean + 32) / 64`
    /// rounding).
    pub fn mean(&self) -> i64 {
        if self.num_samples > 0 {
            (self.mean_fp + 32) / Self::FIXED_POINT
        } else {
            0
        }
    }

    /// Average deviation in milliseconds (reference `avg_deviation()`:
    /// non-zero only with 2+ samples).
    pub fn avg_deviation(&self) -> i64 {
        if self.num_samples > 1 {
            (self.avg_dev_fp + 32) / Self::FIXED_POINT
        } else {
            0
        }
    }

    /// Samples taken (capped at [`Self::INVERTED_GAIN`]; reference
    /// `num_samples()`).
    pub fn num_samples(&self) -> i32 {
        self.num_samples
    }
}

/// One outstanding request slot (a v2-first shape of aria2 `RequestSlot`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slot {
    pub id: PieceId,
    pub begin: u32,
    pub length: u32,
    pub dispatched: Instant,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DispatchError {
    #[error("outstanding window full: {outstanding}/{window}")]
    WindowFull { window: usize, outstanding: usize },
    #[error("duplicate request slot {id:?}+{begin}+{length}")]
    Duplicate {
        id: PieceId,
        begin: u32,
        length: u32,
    },
    #[error("piece id not representable on the wire for this addressing")]
    BadPieceId,
    #[error("frame write failed: {0}")]
    Io(String),
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PieceError {
    /// Unsolicited piece (or length mismatch): must disconnect (the peer-wire rule).
    #[error("unsolicited piece {id:?}+{begin}+{length}")]
    Unsolicited {
        id: PieceId,
        begin: u32,
        length: u32,
    },
}

/// Per-peer request bookkeeping. All time is caller-injected
/// (deterministically testable).
#[derive(Debug)]
pub struct RequestBook {
    window: usize,
    slots: Vec<Slot>,
    /// Grace registry of timed-out slots: `(id, begin, length) -> retired
    /// at`. A late same-coordinate delivery (slow link / race with our
    /// cancel) within the grace window is accepted, not judged
    /// unsolicited. libtorrent cross-check: timed-out blocks stay in
    /// `m_download_queue` (`queued_block::timed_out`) and late delivery
    /// counts as `waste_reason::piece_timed_out` redundant bytes, never a
    /// disconnect (`peer_connection.cpp`). Locally `request_timeout`
    /// bounds the grace (libtorrent keeps entries until close; a
    /// deliberate divergence to bound bookkeeping).
    expired: std::collections::HashMap<(PieceId, u32, u32), Instant>,
    request_timeout: Duration,
    round_start_outstanding: usize,
    snubbed: bool,
    /// Lock-free in-flight mirror (observability seam; None = zero change
    /// to existing behavior): every slot-set change stores the current
    /// outstanding count via [`Self::sync_in_flight`].
    /// Single-point discipline — the sole authority for per-peer
    /// in-flight is [`Self::slots`]; all changes happen inside this
    /// struct's methods and the mirror syncs as each method closes.
    in_flight: Option<Arc<AtomicU64>>,
    /// Request-response RTT statistics ([`RttSamples`]; reference
    /// `m_request_time`, `peer_connection.hpp`). Sampled on the
    /// slot-matched arm of [`Self::on_piece`]; consumed by
    /// [`Self::adaptive_timeout`].
    rtt: RttSamples,
    /// Lock-free adaptive-timeout mirror (None = not published by default,
    /// zero change to existing construction): every sample stores the
    /// current adaptive value (ms) via [`Self::publish_timeout`].
    /// Single-point discipline mirrors [`Self::in_flight`] — the sole
    /// authority is [`Self::rtt`]; changes happen only at the sampling
    /// point; consumers (the engine's reissue window) read lock-free.
    timeout_mirror: Option<Arc<AtomicU64>>,
    /// Window cap (the local `bt-max-out-request-queue` analog): defaults
    /// to [`UB_MAX_OUTSTANDING_REQUEST`] (256, the aria2 `BtConstants.h`
    /// value; the libtorrent default of 500 kept as reference),
    /// configurable via `PeerConfig::max_out_request_queue`; shared by
    /// both modes.
    max_window: usize,
    /// Window mode: defaults to [`WindowMode::from_env`];
    /// [`Self::with_window_mode`] pins it explicitly (deterministic-test
    /// surface).
    mode: WindowMode,
    /// Peer download payload-rate EWMA ([`RateEwma`]; shaped after the
    /// reference `stat_channel` `m_5_sec_average`). Accumulated on the
    /// slot-matched arm of [`Self::on_piece`]; settled lazily in
    /// [`Self::refresh_window`] (triggered from every `now`-injecting
    /// entry point); consumed by the BDP target-window recompute there.
    rate: RateEwma,
    /// Slow-start flag (reference `m_slow_start`, `peer_connection.hpp`):
    /// while no rate evidence exists, each received block grows the window
    /// by 1 (`peer_connection.cpp`); the first rate-window settlement or a
    /// snub exits it.
    slow_start: bool,
    /// Lock-free target-window mirror (None = not published by default,
    /// zero change to existing construction): every window change stores
    /// the current value (blocks) via [`Self::sync_window`]. Same
    /// single-point discipline as the other mirrors — the sole authority
    /// is `self.window`; changes happen only at slow-start +1, BDP
    /// recompute, and fallback doubling; consumers (the engine's supply
    /// cap) read lock-free.
    window_mirror: Option<Arc<AtomicU64>>,
    /// Rate EWMA long-window flag: after slow-start exit the gain goes
    /// alpha 1/5 -> 1/10 (source and divergence notes in
    /// docs/design/request-window.md). Defaults from the environment
    /// (`BH_RATE_EWMA_LONG=0` falls back); [`Self::with_rate_ewma_long`]
    /// pins it explicitly (deterministic-test surface).
    rate_ewma_long: bool,
    /// BDP window hysteresis flag: after slow-start exit, hold steady
    /// inside the `[0.7w, 1.3w]` band (source and divergence notes in
    /// docs/design/request-window.md). Defaults from the environment
    /// (`BH_BDP_WINDOW_HYSTERESIS=0` falls back),
    /// [`Self::with_window_hysteresis`] pins it explicitly
    /// (deterministic-test surface).
    window_hysteresis: bool,
    /// BDP target-window real-network floor: absolute lower bound against
    /// target-window collapse in low-rate regimes (the causal-loop
    /// rationale is in the [`bdp_window_floor`] docs; inert in controlled
    /// high-throughput regimes). Defaults from the environment
    /// (`BH_REQ_WINDOW_FLOOR`, default 64; `=24` the earlier floor, `=2`
    /// the libtorrent behavior); [`Self::with_window_floor`] pins it
    /// explicitly (deterministic tests).
    window_floor: usize,
    /// Endgame-tail window-floor override (engine -> book
    /// direction, the reverse of the three mirrors above): the engine's
    /// dispatch round raises a holder peer's floor to cover the tail's
    /// missing block volume (`min(k x missing blocks, 256)`,
    /// `BH_ENDGAME_TAIL_WINDOW`); 0 / detached = no effect (the floor is
    /// a `max`, relax-only). Applied only inside [`Self::refresh_window`]
    /// (BDP mode, post-slow-start), so the cap / hysteresis / fallback
    /// mode semantics are untouched.
    endgame_floor: Option<Arc<AtomicU64>>,
}

impl RequestBook {
    pub fn new(request_timeout: Duration) -> RequestBook {
        RequestBook {
            // The initial window (slow-start start) is environment-
            // configurable: `BH_REQ_WINDOW_INIT` defaults to 16; an
            // explicit `=6` restores the aria2 `BtConstants.h` anchor (see
            // [`DEFAULT_MAX_OUTSTANDING_REQUEST`]).
            window: initial_window_from_env(),
            slots: Vec::new(),
            expired: std::collections::HashMap::new(),
            request_timeout,
            round_start_outstanding: 0,
            snubbed: false,
            // No mirrors by default = zero change to existing construction
            // (seams attach explicitly via
            // [`Self::with_in_flight_mirror`]).
            in_flight: None,
            rtt: RttSamples::default(),
            // Timeout mirror likewise
            // ([`Self::with_adaptive_timeout_mirror`]).
            timeout_mirror: None,
            // Cap defaults to 256 (the aria2 UB value); mode from the
            // environment default (`BH_REQUEST_WINDOW_BDP=0` falls back to
            // doubling); slow start starts true (reference
            // `m_slow_start(true)`, `peer_connection.cpp`); the rate EWMA
            // starts at zero; mirrors attach on demand.
            max_window: UB_MAX_OUTSTANDING_REQUEST,
            mode: WindowMode::from_env(),
            rate: RateEwma::new(),
            slow_start: true,
            window_mirror: None,
            // Both jitter-adaptation surfaces default on (see
            // docs/design/request-window.md); the env switches fall back
            // individually (same pattern as `WindowMode::from_env`).
            rate_ewma_long: rate_ewma_long_from_env(),
            window_hysteresis: window_hysteresis_from_env(),
            window_floor: bdp_window_floor(),
            endgame_floor: None,
        }
    }

    /// Pin the window mode (deterministic-test surface); production always
    /// takes the environment default from [`Self::new`]
    /// ([`WindowMode::from_env`]).
    pub fn with_window_mode(mut self, mode: WindowMode) -> RequestBook {
        self.mode = mode;
        self
    }

    /// Pin the rate EWMA long window (deterministic-test surface):
    /// `false` = reference alpha 1/5 bit-for-bit (the construction-time
    /// equivalent of `BH_RATE_EWMA_LONG=0`).
    ///
    /// The `bool` stays deliberately (documented divergence from the
    /// enum-per-flag convention): this setter mirrors the binary env knob
    /// `BH_RATE_EWMA_LONG` 1:1 — the knob's whole value domain is {0,
    /// non-zero}, the field feeds a boolean gain gate in
    /// [`Self::refresh_window`], and the sole callers (in-file tests)
    /// pin `false` to freeze the reference behavior. A wrapper enum
    /// would be constructed and destructured inside this one file
    /// without removing a decision from any call site.
    pub fn with_rate_ewma_long(mut self, long: bool) -> RequestBook {
        self.rate_ewma_long = long;
        self
    }

    /// Pin BDP window hysteresis (deterministic-test surface): `false` =
    /// direct recompute-and-assign bit-for-bit (the construction-time
    /// equivalent of `BH_BDP_WINDOW_HYSTERESIS=0`).
    ///
    /// The `bool` stays deliberately (same rationale as
    /// [`Self::with_rate_ewma_long`]): the setter mirrors the binary env
    /// knob `BH_BDP_WINDOW_HYSTERESIS` 1:1, the field feeds a boolean
    /// band gate in [`Self::refresh_window`], and the only callers are
    /// in-file tests pinning `false`.
    pub fn with_window_hysteresis(mut self, hysteresis: bool) -> RequestBook {
        self.window_hysteresis = hysteresis;
        self
    }

    /// Pin the BDP target-window floor explicitly (test injection;
    /// production uses the [`bdp_window_floor`] environment default).
    pub fn with_window_floor(mut self, floor: usize) -> RequestBook {
        self.window_floor = floor.max(MIN_REQUEST_WINDOW);
        self
    }

    /// Attach the endgame-tail window-floor override (the
    /// engine -> book seam, reverse direction of the three read mirrors):
    /// the engine writes the tail's missing-block volume (blocks; 0 = no
    /// override) when the torrent enters its endgame tail and this peer
    /// advertises a missing piece; [`Self::refresh_window`] lifts the
    /// effective floor to `max(generic floor, override)` — relax-only,
    /// never above `max_window`, inert in fallback mode and during slow
    /// start. No publish on attach (0 = the no-op default; the window
    /// itself is unchanged until the engine raises the value and a
    /// refresh runs).
    pub fn with_endgame_window_floor(mut self, floor: Arc<AtomicU64>) -> RequestBook {
        self.endgame_floor = Some(floor);
        self
    }

    /// Effective endgame-tail floor reading (blocks): the attached
    /// override's current value, saturating-cast to usize; detached /
    /// 0 = no lift.
    fn endgame_floor_blocks(&self) -> usize {
        self.endgame_floor
            .as_ref()
            .map(|f| usize::try_from(f.load(Ordering::Relaxed)).unwrap_or(usize::MAX))
            .unwrap_or(0)
    }

    /// Pin the initial request-window depth (test injection; production
    /// uses the [`initial_window_from_env`] environment default,
    /// `BH_REQ_WINDOW_INIT`): clamped to [2, 256] and never above the
    /// configured cap (the same `min` as
    /// [`Self::with_max_out_request_queue`]; chain order does not matter).
    /// The mirror is not synced here (attaching publishes the value).
    pub fn with_initial_window(mut self, initial: usize) -> RequestBook {
        self.window = initial
            .clamp(MIN_REQUEST_WINDOW, UB_MAX_OUTSTANDING_REQUEST)
            .min(self.max_window);
        self
    }

    /// Configure the window cap (the `bt-max-out-request-queue` analog):
    /// defensively clamped below by [`MIN_REQUEST_WINDOW`]; the current
    /// window converges immediately (a tighter cap takes effect at once,
    /// both modes).
    pub fn with_max_out_request_queue(mut self, cap: usize) -> RequestBook {
        self.max_window = cap.max(MIN_REQUEST_WINDOW);
        self.window = self.window.min(self.max_window);
        self
    }

    /// Attach the lock-free target-window mirror: attaching publishes the
    /// current value immediately (a published-0 state is never exposed),
    /// then updates on every window change ([`Self::sync_window`]).
    /// Consumer: the engine dispatch-round supply cap `min(target - in
    /// flight, command-channel headroom)` (`dispatch::supply_cap` reading
    /// lock-free via PeerTaskHandle).
    pub fn with_target_window_mirror(mut self, mirror: Arc<AtomicU64>) -> RequestBook {
        mirror.store(
            u64::try_from(self.window).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        self.window_mirror = Some(mirror);
        self
    }

    /// Target-window mirror sync (single choke point): every change point
    /// of `window` (slow-start +1 / BDP recompute / fallback doubling /
    /// cap convergence) stores the mirror through this method. Relaxed
    /// single-variable projection, same discipline as the other mirrors.
    fn sync_window(&self) {
        if let Some(m) = &self.window_mirror {
            m.store(
                u64::try_from(self.window).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        }
    }

    /// BDP target-window refresh (libtorrent `update_desired_queue_size`,
    /// `peer_connection.cpp`; source chain: docs/design/request-window.md):
    ///
    /// 1. Lazily settle the rate window ([`RateEwma::settle`], one settle
    ///    per 1s+). Gain by state: slow start exited and long window on ->
    ///    alpha 1/10 (stand-in `SpeedCalc.cc` alignment), otherwise
    ///    reference alpha 1/5 (`stat.cpp`). Any rate evidence
    ///    ([`RateEwma::seeded`]) exits slow start — the check is
    ///    idempotent; settlement and recompute may be driven by different
    ///    entry points.
    /// 2. During slow start: clamp only, never recompute (the window grows
    ///    by +1 per block; here only the bounds clamp). Otherwise
    ///    `clamp(3s x rate / 16KiB, 2, cap)` (cap first, then floor).
    /// 3. Hysteresis (default on): a target inside the `[0.7w, 1.3w]` band
    ///    holds the window steady (local policy, an intentional
    ///    divergence); disabled, the recompute assigns directly
    ///    (reference bit-for-bit).
    /// 4. Fallback mode is untouched — the window belongs to
    ///    [`Self::end_receive_round`].
    ///
    /// Called from every `now`-injecting entry point (dispatch / the
    /// on_piece slot-matched arm / expire_timed_out): supply, delivery,
    /// and tick all advance rate settlement; idle readings decay via the
    /// tick arm (same shape as the reference's per-second tick).
    fn refresh_window(&mut self, now: Instant) {
        if self.mode != WindowMode::Bdp {
            return;
        }
        // Gain selection: the first settlement window is the direct-seed
        // arm (gain unused), so the long window takes effect from the
        // second rate sample — "not applicable during slow start" holds
        // structurally (slow-start exit = the first rate-window
        // settlement).
        let gain = if self.rate_ewma_long && !self.slow_start {
            RATE_EWMA_LONG_INVERTED_GAIN
        } else {
            RATE_EWMA_INVERTED_GAIN
        };
        self.rate.settle(now, gain);
        if self.rate.seeded {
            self.slow_start = false;
        }
        if self.slow_start {
            self.sync_window();
            return;
        }
        // target = request_queue_time x rate / 16KiB (reference formula;
        // the seconds factor comes from REQUEST_QUEUE_TIME; the rate is a
        // non-negative i64 bounded by the settle sample rule, so the i64
        // multiply cannot overflow).
        let secs = i64::try_from(REQUEST_QUEUE_TIME.as_secs()).unwrap_or(3);
        let target = secs * self.rate.value / i64::try_from(REQUEST_BLOCK_SIZE).unwrap_or(1);
        let target_us = usize::try_from(target).unwrap_or(usize::MAX);
        // Cap first, then floor (reference order — the cap binds first;
        // the floor can never punch through the cap:
        // with_max_out_request_queue already guarantees max_window >= 2).
        // The floor is the real-network floor in BDP mode
        // ([`bdp_window_floor`]; `BH_REQ_WINDOW_FLOOR=2` restores the
        // reference bit-for-bit), lifted by the endgame-tail override
        // (`max` = relax-only — a detached seam / 0 keeps the
        // generic floor, and the `min(max_window)` keeps even a huge
        // override under the configured cap).
        let tail_floor = self.endgame_floor_blocks();
        let floor = self
            .max_window
            .min(self.window_floor.max(tail_floor))
            .max(MIN_REQUEST_WINDOW);
        let capped = target_us.min(self.max_window).max(floor);
        // Hysteresis (default on): hold steady inside the band — the
        // window does not shrink on transient rate dips (this protects the
        // long window's slower-response cost; saturating u64 math defends
        // extreme configured caps, unreachable for normal <=256 domains).
        // This assignment is the pre-override formula verbatim (the generic
        // floor keeps its soft role: a slow-start-exit window held below
        // the generic floor by the band stays below it — the documented
        // "snub/timeout handling is not protected by the floor" semantics,
        // [`bdp_window_floor`] docs; review-blocker fix: the earlier
        // unconditional trailing `.max(floor)` wrongly lifted such windows
        // even with no override attached — non-endgame drift).
        self.window = if self.window_hysteresis {
            let w = u64::try_from(self.window).unwrap_or(u64::MAX);
            let c = u64::try_from(capped).unwrap_or(u64::MAX);
            let below_floor = c.saturating_mul(WINDOW_HYSTERESIS_DEN)
                < w.saturating_mul(WINDOW_HYSTERESIS_LOW_NUM);
            let above_ceiling = c.saturating_mul(WINDOW_HYSTERESIS_DEN)
                > w.saturating_mul(WINDOW_HYSTERESIS_HIGH_NUM);
            if below_floor || above_ceiling {
                capped
            } else {
                self.window
            }
        } else {
            capped
        };
        // Endgame-tail floor lift, applied ONLY on the
        // override's component beyond the generic floor: the lift is a
        // hard lower bound (immediate, not holdable by the band — the
        // hold arm could otherwise park the window just below a freshly
        // raised floor: capped=80 vs w=64 sits inside [0.7w, 1.3w]).
        // With no override (detached / 0 / at or below the generic floor)
        // this clamp does not run at all and the expression above is the
        // old formula bit-for-bit — the frozen seam (non-endgame zero
        // change) holds; the clamp value itself is capped at
        // `max_window` (the lift never punches the configured cap) and
        // floored at [`MIN_REQUEST_WINDOW`] (a malformed 1-block
        // override never shrinks anything — `max` is monotone here).
        if tail_floor > self.window_floor {
            let lift_floor = self.max_window.min(tail_floor).max(MIN_REQUEST_WINDOW);
            self.window = self.window.max(lift_floor);
        }
        self.sync_window();
    }

    /// Attach the lock-free in-flight mirror (observability seam): synced
    /// with every slot-set change of this book ([`Self::sync_in_flight`]);
    /// consumers (the engine's 1s tick via PeerTaskHandle) read lock-free.
    pub fn with_in_flight_mirror(mut self, mirror: Arc<AtomicU64>) -> RequestBook {
        mirror.store(0, Ordering::Relaxed);
        self.in_flight = Some(mirror);
        self
    }

    /// Attach the lock-free adaptive-timeout mirror: attaching publishes
    /// the current value (no samples = configured cap, zero change vs the
    /// fixed-timeout behavior), then updates on every sample
    /// ([`Self::publish_timeout`]). Consumer: the read side of the engine
    /// reissue window (`dispatch::reissue_window`).
    pub fn with_adaptive_timeout_mirror(mut self, mirror: Arc<AtomicU64>) -> RequestBook {
        mirror.store(
            u64::try_from(self.adaptive_timeout().as_millis()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        self.timeout_mirror = Some(mirror);
        self
    }

    /// Adaptive-timeout publish (lock-free mirror choke point): the value
    /// changes only at the sampling point ([`Self::on_piece`]), so only
    /// the sampling arm calls this.
    fn publish_timeout(&self) {
        if let Some(m) = &self.timeout_mirror {
            m.store(
                u64::try_from(self.adaptive_timeout().as_millis()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        }
    }

    /// Per-peer adaptive request timeout (libtorrent `request_timeout()`,
    /// `peer_connection.cpp`; source chain: docs/design/request-window.md):
    ///
    /// - 0 samples -> configured cap (the `--bt-request-timeout` analog;
    ///   the reference likewise returns `settings_pack::request_timeout`)
    ///   — no evidence, no behavior change;
    /// - 1 sample -> `mean + mean/5` (+20%); 2+ -> `mean + 4 x
    /// avg_deviation`;
    /// - ceil to whole seconds -> `min(configured cap)` -> `max(2s)` floor
    ///   (reference order: cap before floor, so a cap below 2s still
    ///   yields the 2s floor).
    pub fn adaptive_timeout(&self) -> Duration {
        let (avg, dev, n) = (
            self.rtt.mean(),
            self.rtt.avg_deviation(),
            self.rtt.num_samples(),
        );
        if n == 0 {
            return self.request_timeout;
        }
        let ret_ms = if n == 1 { avg + avg / 5 } else { avg + dev * 4 };
        // Configured range 1..=600s (aria2 `OptionHandlerFactory.cc`), so
        // cap_secs >= 1; no i64 overflow (ret_ms <= 6x10^5 + 4x6x10^5).
        // The floor is [`MIN_ADAPTIVE_REQUEST_TIMEOUT`] (2s). Ceil to
        // seconds = reference `(ret + 999) / 1000` (ret_ms >= 0).
        let cap_secs = i64::try_from(self.request_timeout.as_secs()).unwrap_or(i64::MAX);
        let secs = ((ret_ms + 999) / 1000).min(cap_secs).max(2);
        Duration::from_secs(u64::try_from(secs).unwrap_or(u64::MAX))
    }

    /// In-flight mirror sync (single choke point): `slots` is the sole
    /// authority for per-peer outstanding requests; called after all five
    /// change points (dispatch/on_piece/expire_timed_out/on_choke/cancel).
    /// Relaxed single-variable projection, same discipline as the other
    /// lock-free mirrors.
    fn sync_in_flight(&self) {
        if let Some(m) = &self.in_flight {
            m.store(self.slots.len() as u64, Ordering::Relaxed);
        }
    }

    pub fn window(&self) -> usize {
        self.window
    }

    pub fn outstanding(&self) -> usize {
        self.slots.len()
    }

    pub fn slots(&self) -> impl Iterator<Item = &Slot> {
        self.slots.iter()
    }

    pub fn is_snubbed(&self) -> bool {
        self.snubbed
    }

    /// Requests still dispatchable this round (aria2
    /// `DefaultBtInteractive.cc`).
    pub fn budget(&self) -> usize {
        self.window - self.outstanding().min(self.window)
    }

    /// Register an outstanding slot; rejects on a full window or a
    /// duplicate slot (duplicate dispatch is a caller bug). The entry
    /// refreshes the BDP target window first: supply itself is a
    /// rate-settlement driver (a continuously supplied but
    /// non-delivering slow peer still converges the reading toward its
    /// true rate via lazy settlement, keeping the window fresh).
    pub fn dispatch(
        &mut self,
        id: PieceId,
        begin: u32,
        length: u32,
        now: Instant,
    ) -> Result<(), DispatchError> {
        self.refresh_window(now);
        if self.outstanding() >= self.window {
            return Err(DispatchError::WindowFull {
                window: self.window,
                outstanding: self.outstanding(),
            });
        }
        if self
            .slots
            .iter()
            .any(|s| s.id == id && s.begin == begin && s.length == length)
        {
            return Err(DispatchError::Duplicate { id, begin, length });
        }
        self.slots.push(Slot {
            id,
            begin,
            length,
            dispatched: now,
        });
        self.sync_in_flight();
        Ok(())
    }

    /// A bulk receive round begins: snapshot outstanding (aria2
    /// `DefaultBtInteractive.cc` `countOldOutstandingRequest`).
    pub fn begin_receive_round(&mut self) {
        self.round_start_outstanding = self.slots.len();
    }

    /// A round ends: in fallback mode, double with cap when
    /// `completed*4 >= window` (aria2 `DefaultBtInteractive.cc`). No growth
    /// during endgame; endgame detection lives in TorrentTask, and this
    /// layer treats rounds as non-endgame. Returns whether the window
    /// doubled. In BDP mode (default) this heuristic is off (always
    /// false) — the window is rate-driven ([`Self::refresh_window`]);
    /// `BH_REQUEST_WINDOW_BDP=0` restores this path.
    pub fn end_receive_round(&mut self) -> bool {
        if self.mode != WindowMode::LegacyDoubling {
            return false;
        }
        let completed = self
            .round_start_outstanding
            .saturating_sub(self.slots.len());
        if completed > 0 && completed * 4 >= self.window && self.window < UB_MAX_OUTSTANDING_REQUEST
        {
            self.window = (self.window * 2).min(UB_MAX_OUTSTANDING_REQUEST);
            self.sync_window();
            true
        } else {
            false
        }
    }

    /// A piece arrived: match and remove the outstanding slot; on no
    /// match, consult the timeout-grace registry (slots retired within
    /// `request_timeout` still accept a same-coordinate delivery);
    /// neither means unsolicited (the disconnect signal). `now` is
    /// injected (same pattern as dispatch/expire): the slot-matched arm
    /// samples request-response RTT (same shape as the reference
    /// `now - requested` in `peer_connection.cpp`), publishes the
    /// adaptive-timeout mirror, accumulates the payload-rate sample by
    /// block length, and advances slow start / the BDP window refresh.
    /// The grace arm does not sample: the slot timestamp is consumed at
    /// retirement, and late bytes stay out of the rate window (they would
    /// drag a fast peer's reading down at alpha 1/5).
    pub fn on_piece(
        &mut self,
        id: PieceId,
        begin: u32,
        length: u32,
        now: Instant,
    ) -> Result<(), PieceError> {
        match self
            .slots
            .iter()
            .position(|s| s.id == id && s.begin == begin && s.length == length)
        {
            Some(i) => {
                let slot = self.slots.remove(i);
                // Request-response sample (ms; a backwards clock
                // defensively yields 0 — "answered instantly").
                let elapsed = now
                    .checked_duration_since(slot.dispatched)
                    .unwrap_or_default();
                let ms = i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX);
                self.rtt.add_sample(ms);
                // Payload sample (a matched delivery is this peer's
                // effective payload) + slow-start growth (reference
                // `peer_connection.cpp`: +1 per received block during slow
                // start, clamped at the cap) + BDP refresh (including the
                // first rate-window settlement — exits slow start).
                if self.mode == WindowMode::Bdp {
                    self.rate.add(u64::from(length), now);
                    if self.slow_start {
                        self.window = (self.window + 1).min(self.max_window);
                    }
                    self.refresh_window(now);
                }
                self.publish_timeout();
                self.snubbed = false;
                self.sync_in_flight();
                Ok(())
            }
            None => {
                // Timeout grace: libtorrent never disconnects on late
                // delivery of a timed-out block (`peer_connection.cpp`).
                // The grace window waits one more `request_timeout`, then
                // the entry is dropped (bounded bookkeeping).
                let key = (id, begin, length);
                match self.expired.get(&key).copied() {
                    Some(t) if t.elapsed() <= self.request_timeout => {
                        self.expired.remove(&key);
                        Ok(())
                    }
                    _ => {
                        self.expired.remove(&key);
                        Err(PieceError::Unsolicited { id, begin, length })
                    }
                }
            }
        }
    }

    /// Remove timed-out slots and return them (the caller sends a snub
    /// event to TorrentTask and decides on reissue). Any timeout sets
    /// snubbed (aria2 `DefaultBtMessageDispatcher.cc`); receiving a piece
    /// clears it (`BtPieceMessage.cc`). The "block already obtained from
    /// disk -> send Cancel" branch belongs to the disk integration layer.
    /// Retired slots enter the timeout-grace registry ([`Self::on_piece`]).
    /// The judgment uses the adaptive timeout (fast peers retire their
    /// slots sooner, slow peers are not killed early); the grace registry
    /// still uses the configured cap (must not tighten with sample
    /// jitter). A timeout (snub) exits slow start; the window is then
    /// left to [`Self::refresh_window`] to decide from seen rates (no
    /// samples = the 2 floor, so slow/dead peers do not accumulate
    /// in-flight requests). This entry point is also the tick-face
    /// rate-settlement driver (idle readings decay toward 0).
    pub fn expire_timed_out(&mut self, now: Instant) -> Vec<Slot> {
        let timeout = self.adaptive_timeout();
        let mut expired = Vec::new();
        self.slots.retain(|s| {
            // RequestSlot.cc: now - dispatched >= t means timed out
            // (equality included).
            let timed_out = now
                .checked_duration_since(s.dispatched)
                .is_some_and(|d| d >= timeout);
            if timed_out {
                expired.push(s.clone());
            }
            !timed_out
        });
        if !expired.is_empty() {
            self.snubbed = true;
            if self.mode == WindowMode::Bdp && self.slow_start {
                self.slow_start = false;
            }
            for s in &expired {
                self.expired.insert((s.id, s.begin, s.length), now);
            }
            // Grace-registry bound (defensive): stale entries beyond the
            // window size converge naturally via the insert-overwrite
            // semantics in on_piece/here; sweeping expired entries again
            // prevents unbounded growth on long-lived connections. Grace
            // = configured cap (not the adaptive value — bound stability
            // first).
            let grace = self.request_timeout;
            self.expired.retain(|_, t| t.elapsed() <= grace * 2);
        }
        // BDP refresh (tick-face rate-settlement driver; fallback mode
        // untouched).
        self.refresh_window(now);
        self.sync_in_flight();
        expired
    }

    /// Choke received: clear outstanding slots (keeping those where `keep`
    /// says true, e.g. covered by allowed-fast, aria2
    /// `DefaultBtMessageDispatcher.cc`) and return the cleared slots
    /// (to be rejected when the fast extension is on).
    pub fn on_choke(&mut self, keep: impl Fn(&Slot) -> bool) -> Vec<Slot> {
        let mut dropped = Vec::new();
        self.slots.retain(|s| {
            if keep(s) {
                true
            } else {
                dropped.push(s.clone());
                false
            }
        });
        self.sync_in_flight();
        dropped
    }
    /// Explicit cancel: remove the matching slot (returns whether it
    /// existed); the caller sends the wire cancel.
    pub fn cancel(&mut self, id: PieceId, begin: u32, length: u32) -> bool {
        match self
            .slots
            .iter()
            .position(|s| s.id == id && s.begin == begin && s.length == length)
        {
            Some(i) => {
                self.slots.remove(i);
                self.sync_in_flight();
                true
            }
            None => false,
        }
    }

    /// Cancel and register a late-delivery grace ("cancel on reassignment"
    /// support). When the engine-level reissue window (2s) takes over a
    /// slow peer's outstanding blocks it sends Cancel to the original
    /// holder — but a Cancel frame races piece frames already in flight on
    /// TCP/uTP; judging such a late delivery unsolicited by
    /// [`Self::on_piece`]'s no-slot rule (the peer-wire rule) would kill the slow
    /// peer the reassignment is meant to help. The cancelled slot
    /// therefore enters the same grace registry as
    /// [`Self::expire_timed_out`] (a same-coordinate delivery within
    /// `request_timeout` counts as redundancy). libtorrent points the
    /// same way: late delivery of timed-out/cancelled blocks counts as
    /// `waste_reason` redundancy, never a disconnect
    /// (`peer_connection.cpp`). The registry is bounded (the same sweep
    /// rule as [`Self::expire_timed_out`]).
    pub fn cancel_with_grace(
        &mut self,
        id: PieceId,
        begin: u32,
        length: u32,
        now: Instant,
    ) -> bool {
        if !self.cancel(id, begin, length) {
            return false;
        }
        self.expired.insert((id, begin, length), now);
        let grace = self.request_timeout;
        self.expired.retain(|_, t| t.elapsed() <= grace * 2);
        true
    }
}

/// Flood detector (aria2 `DefaultBtInteractive.cc`). Checks once per
/// fixed [`FLOODING_CHECK_INTERVAL`] (not a sliding window); a
/// choke/unchoke **flip** count or a keepalive count at or above the
/// threshold disconnects; below it, counters reset.
#[derive(Debug)]
pub struct FloodGuard {
    interval: Duration,
    choke_unchoke_count: u32,
    keep_alive_count: u32,
    /// None = the peer's choke state not yet observed (the first
    /// choke/unchoke is not a flip; aria2 judges from the
    /// `peer_->peerChoking()` initial value false — equivalent).
    prev_choke: Option<bool>,
    last_check: Instant,
}

impl FloodGuard {
    /// `now` injects the first check point (aria2 sets
    /// `floodingTimer_ = wallclock` at construction,
    /// `DefaultBtInteractive.cc`; the injected clock keeps tests
    /// deterministic).
    pub fn new(interval: Duration, now: Instant) -> FloodGuard {
        FloodGuard {
            interval,
            choke_unchoke_count: 0,
            keep_alive_count: 0,
            prev_choke: None,
            last_check: now,
        }
    }

    /// Choke message received: one flip if previously unchoked
    /// (aria2 `DefaultBtInteractive.cc`).
    pub fn observe_choke(&mut self) {
        if self.prev_choke == Some(false) {
            self.choke_unchoke_count += 1;
        }
        self.prev_choke = Some(true);
    }

    /// Unchoke message received: one flip if previously choked
    /// (aria2 `DefaultBtInteractive.cc`).
    pub fn observe_unchoke(&mut self) {
        if self.prev_choke == Some(true) {
            self.choke_unchoke_count += 1;
        }
        self.prev_choke = Some(false);
    }

    /// Keepalive received (aria2 `DefaultBtInteractive.cc`).
    pub fn observe_keepalive(&mut self) {
        self.keep_alive_count += 1;
    }

    /// Periodic check: on reaching the interval, judge and reset;
    /// true = disconnect. Per-dimension thresholds: keepalive keeps the
    /// aria2 original [`FLOODING_THRESHOLD`]; choke/unchoke flips use the
    /// recalibrated [`FLOODING_CHOKE_FLIP_THRESHOLD`] (rationale in the
    /// constant docs).
    pub fn check(&mut self, now: Instant) -> bool {
        if now.checked_duration_since(self.last_check) < Some(self.interval) {
            return false;
        }
        let flood = self.choke_unchoke_count >= FLOODING_CHOKE_FLIP_THRESHOLD
            || self.keep_alive_count >= FLOODING_THRESHOLD;
        self.choke_unchoke_count = 0;
        self.keep_alive_count = 0;
        self.last_check = now;
        flood
    }

    /// Trigger-dimension readings (observability only): `(choke/unchoke
    /// flip count, keepalive count)` — read at the check point so
    /// disconnect logs can carry the triggering dimension (aria2
    /// disconnects without it; a local enhancement).
    pub fn trigger_counts(&self) -> (u32, u32) {
        (self.choke_unchoke_count, self.keep_alive_count)
    }
}

/// HAVE advertisement ledger: monotonic cursor + time-based expiry
/// (aria2 `DefaultPieceStorage.cc` + `HaveEraseCommand.cc`). In aria2 the
/// ledger is global (piece storage) and the cursor per-connection
/// (`lastHaveIndex_`); here it exists as a per-connection instance — when
/// swarm wiring lands, TorrentTask will hold the ledger and PeerTask the
/// cursor; the API is split accordingly.
#[derive(Debug)]
pub struct HaveAdvertiser {
    entries: Vec<HaveEntry>,
    next_have_index: u64,
    /// have_index this connection has been advertised up to (cursor,
    /// `DefaultPieceStorage.cc`).
    sent_cursor: u64,
}

#[derive(Debug)]
struct HaveEntry {
    have_index: u64,
    id: PieceId,
    registered: Instant,
}

impl HaveAdvertiser {
    /// have_index starts at 1: a cursor initial value of 0 means "nothing
    /// sent yet", so the cursor semantics cannot swallow the first entry
    /// (same handling and comment as aria2 `DefaultPieceStorage.cc`).
    pub fn new() -> HaveAdvertiser {
        HaveAdvertiser {
            entries: Vec::new(),
            next_have_index: 1,
            sent_cursor: 0,
        }
    }

    /// Register an advertisement after a piece completes (aria2
    /// `DefaultPieceStorage.cc`).
    pub fn advertise(&mut self, id: PieceId, now: Instant) {
        let have_index = self.next_have_index;
        self.next_have_index += 1;
        self.entries.push(HaveEntry {
            have_index,
            id,
            registered: now,
        });
    }

    /// Take all pending pieces after the cursor (the cursor itself
    /// excluded) and advance it (aria2 `DefaultPieceStorage.cc`,
    /// upper_bound semantics: start at the first entry with
    /// `have_index > cursor`). Entries grow monotonically by have_index
    /// (append order), so a straight scan suffices.
    pub fn drain_since_cursor(&mut self) -> (Vec<PieceId>, u64) {
        let mut ids = Vec::new();
        let mut new_cursor = self.sent_cursor;
        for e in &self.entries {
            if e.have_index > new_cursor {
                ids.push(e.id);
                new_cursor = e.have_index;
            }
        }
        self.sent_cursor = new_cursor;
        (ids, new_cursor)
    }

    /// Drop expired entries (`HaveEraseCommand.cc`: delete older than
    /// now-5s; entries a slow peer has not consumed are never re-sent —
    /// same as aria2's global deletion semantics).
    pub fn remove_expired(&mut self, now: Instant) {
        self.entries.retain(|e| {
            e.registered
                .checked_add(HAVE_EXPIRY)
                .is_some_and(|t| t > now)
        });
    }

    /// Bitfield vs per-piece have choice: use a bitfield when
    /// `5 + bitfield_len <= n_haves * 9` (aria2
    /// `DefaultBtInteractive.cc`).
    pub fn prefer_bitfield(bitfield_len: usize, n_haves: usize) -> bool {
        5 + bitfield_len <= n_haves * 9
    }
}

impl Default for HaveAdvertiser {
    fn default() -> Self {
        HaveAdvertiser::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::piece_id::PieceId;

    /// t0 anchors test instants (Instant is monotonic; relative arithmetic
    /// stays deterministic).
    fn t0() -> Instant {
        Instant::now()
    }

    const ID: PieceId = PieceId::V1(1);

    /// Window starts at 16 (the current default), budget = window -
    /// outstanding, dispatch rejected when the window is full.
    #[test]
    fn window_budget_and_full_rejection() {
        let mut book = RequestBook::new(DEFAULT_REQUEST_TIMEOUT);
        assert_eq!(book.window(), 16);
        assert_eq!(book.budget(), 16);
        let now = t0();
        for i in 0..16 {
            assert!(book.dispatch(ID, i * 16384, 16384, now).is_ok(), "i={i}");
        }
        assert_eq!(book.outstanding(), 16);
        assert_eq!(book.budget(), 0);
        assert!(matches!(
            book.dispatch(ID, 100_000, 16384, now),
            Err(DispatchError::WindowFull {
                window: 16,
                outstanding: 16
            })
        ));
    }

    /// Duplicate slot rejected (duplicate dispatch is a caller bug; the
    /// bookkeeping layer enforces the invariant).
    #[test]
    fn duplicate_dispatch_rejected() {
        let mut book = RequestBook::new(DEFAULT_REQUEST_TIMEOUT);
        let now = t0();
        assert!(book.dispatch(ID, 0, 16384, now).is_ok());
        assert!(matches!(
            book.dispatch(ID, 0, 16384, now),
            Err(DispatchError::Duplicate {
                id: ID,
                begin: 0,
                length: 16384
            })
        ));
    }

    /// Adaptive-window table (fallback-path regression lock): under
    /// `BH_REQUEST_WINDOW_BDP=0` semantics, `completed*4 >= window` doubles
    /// the window up to the 256 cap (aria2 `DefaultBtInteractive.cc`).
    /// Since doubling retirement this path survives only in
    /// [`WindowMode::LegacyDoubling`] (the default-mode BDP decision table
    /// is [`Self::bdp_window_decision_table`]). The initial value is
    /// pinned to 6 = the aria2 anchor (the default is 16).
    #[test]
    fn adaptive_window_doubling_table() {
        let mut book = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_window_mode(WindowMode::LegacyDoubling)
            .with_initial_window(6);
        let now = t0();
        // Window 6: complete 2 (2*4=8 >= 6) -> 12; complete 1 (4 < 6) ->
        // unchanged.
        for i in 0..6 {
            let _ = book.dispatch(ID, i * 100, 100, now);
        }
        book.begin_receive_round();
        for i in 0..2 {
            let _ = book.on_piece(ID, i * 100, 100, now);
        }
        assert!(book.end_receive_round(), "completed 2/6 must double");
        assert_eq!(book.window(), 12);

        // Each round counts separately: only 1 completed this round
        // (4 < 12) -> no doubling.
        book.begin_receive_round();
        for i in 2..4 {
            let _ = book.on_piece(ID, i * 100, 100, now);
            assert!(!book.end_receive_round(), "completed 1/12 must not double");
            book.begin_receive_round();
        }

        // Double all the way to the 256 cap:
        // 12->24->48->96->192->384->min(384,256)=256.
        let mut expected = 24u64;
        while book.window() < UB_MAX_OUTSTANDING_REQUEST {
            let w = book.window();
            for i in 0..w {
                let _ = book.dispatch(PieceId::V1(i as u32 + 1000), 0, 1, now);
            }
            book.begin_receive_round();
            let quarter = (w / 4).max(1);
            for i in 0..quarter {
                let _ = book.on_piece(PieceId::V1(i as u32 + 1000), 0, 1, now);
            }
            assert!(book.end_receive_round(), "window {w} must double");
            assert_eq!(book.window() as u64, expected.min(256), "window growth");
            expected *= 2;
        }
        assert_eq!(book.window(), 256);
        // No growth after the cap.
        for i in 0..64 {
            let _ = book.dispatch(PieceId::V1(i as u32 + 9000), 0, 1, now);
        }
        book.begin_receive_round();
        for i in 0..64 {
            let _ = book.on_piece(PieceId::V1(i as u32 + 9000), 0, 1, now);
        }
        assert!(!book.end_receive_round(), "capped window must stay");
        assert_eq!(book.window(), 256);
    }

    /// Exact-match piece removes the slot; no match = unsolicited (the
    /// disconnect signal).
    #[test]
    fn piece_matching_and_unsolicited() {
        let mut book = RequestBook::new(DEFAULT_REQUEST_TIMEOUT);
        let now = t0();
        let _ = book.dispatch(ID, 16384, 16384, now);
        // begin mismatch.
        assert!(matches!(
            book.on_piece(ID, 0, 16384, now),
            Err(PieceError::Unsolicited {
                id: ID,
                begin: 0,
                length: 16384
            })
        ));
        // id mismatch.
        assert!(book.on_piece(PieceId::V1(99), 16384, 16384, now).is_err());
        // Exact match -> remove + clear snub.
        assert!(book.on_piece(ID, 16384, 16384, now).is_ok());
        assert_eq!(book.outstanding(), 0);
        assert!(!book.is_snubbed());
    }

    /// Slot timeout: dispatched + t <= now means timed out
    /// (`RequestSlot.cc`) and sets snub; the boundary (exactly t) counts
    /// as timed out (>= semantics).
    #[test]
    fn slot_timeout_and_snub() {
        let timeout = Duration::from_secs(60);
        let mut book = RequestBook::new(timeout);
        let now = t0();
        let _ = book.dispatch(ID, 0, 16384, now);
        // 59s: not timed out.
        assert!(
            book.expire_timed_out(now + Duration::from_secs(59))
                .is_empty()
        );
        assert!(!book.is_snubbed());
        // 60s (boundary, >= semantics): timeout -> remove + snub.
        let expired = book.expire_timed_out(now + Duration::from_secs(60));
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].id, ID);
        assert_eq!(expired[0].begin, 0);
        assert!(book.is_snubbed());
        assert_eq!(book.outstanding(), 0);
        // Receiving a piece clears snub (`BtPieceMessage.cc`).
        let _ = book.dispatch(PieceId::V1(2), 0, 16384, now);
        assert!(book.on_piece(PieceId::V1(2), 0, 16384, now).is_ok());
        assert!(!book.is_snubbed());
    }

    /// Choke clears slots: all cleared by default; allowed-fast-covered
    /// slots are kept (`DefaultBtMessageDispatcher.cc`); cleared slots must
    /// be rejected.
    #[test]
    fn choke_cleanup_keeps_allowed_fast() {
        let mut book = RequestBook::new(DEFAULT_REQUEST_TIMEOUT);
        let now = t0();
        let _ = book.dispatch(PieceId::V1(1), 0, 16384, now);
        let _ = book.dispatch(PieceId::V1(2), 0, 16384, now);
        let dropped = book.on_choke(|s| s.id == PieceId::V1(2)); // 2 is allowed-fast
        assert_eq!(dropped.len(), 1);
        assert_eq!(
            dropped[0].id,
            PieceId::V1(1),
            "cleared slots need a reject (fast-ext)"
        );
        assert_eq!(book.outstanding(), 1);
    }

    /// Lock-free in-flight mirror: synced at all five change points —
    /// dispatch increments; on_piece/expire_timed_out/on_choke/cancel
    /// decrement; the mirror always equals [`RequestBook::outstanding`];
    /// no mirror attached (default construction) = zero side effects.
    #[test]
    fn in_flight_mirror_tracks_outstanding() {
        let mirror = Arc::new(AtomicU64::new(0));
        let mut book =
            RequestBook::new(DEFAULT_REQUEST_TIMEOUT).with_in_flight_mirror(Arc::clone(&mirror));
        assert_eq!(mirror.load(Ordering::Relaxed), 0, "zero at attach time");
        let now = t0();
        // dispatch x2 -> mirror 2.
        assert!(book.dispatch(ID, 0, 16384, now).is_ok());
        assert!(book.dispatch(PieceId::V1(2), 0, 16384, now).is_ok());
        assert_eq!(mirror.load(Ordering::Relaxed), 2);
        assert_eq!(mirror.load(Ordering::Relaxed), book.outstanding() as u64);
        // Matched piece retires -> 1.
        assert!(book.on_piece(ID, 0, 16384, now).is_ok());
        assert_eq!(mirror.load(Ordering::Relaxed), 1);
        // Explicit cancel -> 0.
        assert!(book.cancel(PieceId::V1(2), 0, 16384));
        assert_eq!(mirror.load(Ordering::Relaxed), 0);
        // Slot timeout retirement -> mirror converges via retain.
        assert!(book.dispatch(PieceId::V1(3), 0, 16384, now).is_ok());
        assert_eq!(mirror.load(Ordering::Relaxed), 1);
        let expired = book.expire_timed_out(now + DEFAULT_REQUEST_TIMEOUT);
        assert_eq!(expired.len(), 1);
        assert_eq!(mirror.load(Ordering::Relaxed), 0);
        // Choke clears slots -> mirror converges.
        assert!(book.dispatch(PieceId::V1(4), 0, 16384, now).is_ok());
        assert!(book.dispatch(PieceId::V1(5), 0, 16384, now).is_ok());
        assert_eq!(mirror.load(Ordering::Relaxed), 2);
        let dropped = book.on_choke(|_| false);
        assert_eq!(dropped.len(), 2);
        assert_eq!(mirror.load(Ordering::Relaxed), 0);
        // Duplicate dispatch rejected (slot set unchanged) -> mirror
        // unmoved.
        assert!(book.dispatch(ID, 0, 1, now).is_ok());
        assert!(book.dispatch(ID, 0, 1, now).is_err());
        assert_eq!(mirror.load(Ordering::Relaxed), 1);

        // Default construction (no mirror): zero side effects on all
        // paths; outstanding semantics unchanged.
        let mut plain = RequestBook::new(DEFAULT_REQUEST_TIMEOUT);
        assert!(plain.dispatch(ID, 0, 16384, now).is_ok());
        assert_eq!(plain.outstanding(), 1);
        assert!(plain.on_piece(ID, 0, 16384, now).is_ok());
        assert_eq!(plain.outstanding(), 0);
    }

    /// Flooding: fixed 5s-interval check; per-dimension thresholds;
    /// counters reset when under threshold (`DefaultBtInteractive.cc`).
    /// Recalibration note (constant change, mechanism unchanged): keepalive
    /// keeps 2 (the aria2 original); choke/unchoke flips 2 -> 20 (rationale
    /// in the [`FLOODING_CHOKE_FLIP_THRESHOLD`] docs).
    #[test]
    fn flood_guard_thresholds() {
        let interval = FLOODING_CHECK_INTERVAL;
        let start = t0();
        let mut guard = FloodGuard::new(interval, start);

        // First choke is not a flip (no prior state).
        guard.observe_choke();
        assert!(!guard.check(start + interval));
        // Exact flip sequence: unchoke establishes the prior state (not a
        // flip); each alternating frame after that flips exactly once
        // (observe_unchoke: prev==true flips; observe_choke:
        // prev==false flips).
        fn flips(guard: &mut FloodGuard, n: u32) {
            guard.observe_unchoke(); // establish prior state (not a flip)
            for i in 1..=n {
                if i % 2 == 1 {
                    guard.observe_choke();
                } else {
                    guard.observe_unchoke();
                }
            }
        }
        // unchoke -> flip 1; choke -> flip 2 -> below the flip threshold
        // (20), no disconnect (2 flips/window is legitimate peer churn).
        let mut guard = FloodGuard::new(interval, start);
        flips(&mut guard, 2);
        assert!(
            !guard.check(start + 2 * interval),
            "2 flips in one window is legitimate peer churn "
        );

        // Flip threshold reached (20/window) -> disconnect (same
        // mechanism, recalibrated threshold).
        let mut guard = FloodGuard::new(interval, start);
        flips(&mut guard, 20);
        assert!(
            guard.check(start + interval),
            "20 flips in one window must disconnect"
        );
        // 19/window: no disconnect (boundary).
        let mut guard = FloodGuard::new(interval, start);
        flips(&mut guard, 19);
        assert!(!guard.check(start + interval), "19 flips must not");

        // Flips reset at the check point; nothing carries into the next
        // window.
        let mut guard = FloodGuard::new(interval, start);
        guard.observe_choke();
        guard.observe_unchoke(); // 1 flip
        assert!(!guard.check(start + interval));
        guard.observe_keepalive(); // 1 keepalive
        assert!(
            !guard.check(start + 2 * interval),
            "1+1 across windows must not"
        );

        // 2 keepalives -> disconnect (the keepalive threshold stays 2, the
        // aria2 original).
        let mut guard = FloodGuard::new(interval, start);
        guard.observe_keepalive();
        guard.observe_keepalive();
        assert!(guard.check(start + interval));

        // Before the check interval: no verdict.
        let mut guard = FloodGuard::new(interval, start);
        guard.observe_choke();
        guard.observe_unchoke();
        guard.observe_choke();
        assert!(!guard.check(start), "before interval no verdict");
    }

    /// Timed-out slot grace (libtorrent `peer_connection.cpp`): a slot
    /// retired by timeout accepts a same-coordinate late delivery within
    /// the grace window instead of judging it unsolicited; beyond grace
    /// it stays unsolicited.
    #[test]
    fn expired_slot_grace_accepts_late_delivery() {
        let timeout = Duration::from_millis(30);
        let mut book = RequestBook::new(timeout);
        let now = t0();
        let _ = book.dispatch(ID, 0, 16384, now);
        // Timeout retirement (>= semantics).
        let expired = book.expire_timed_out(now + timeout);
        assert_eq!(expired.len(), 1);
        // Within grace (< timeout since retirement) late delivery:
        // accepted, registry consumed.
        std::thread::sleep(Duration::from_millis(10));
        assert!(
            book.on_piece(ID, 0, 16384, now).is_ok(),
            "grace accepts late"
        );
        assert!(
            book.on_piece(ID, 0, 16384, now).is_err(),
            "second is unsolicited"
        );

        // Beyond grace: still unsolicited (violation semantics not
        // relaxed).
        let mut book = RequestBook::new(timeout);
        let now = t0();
        let _ = book.dispatch(ID, 0, 16384, now);
        let _ = book.expire_timed_out(now + timeout);
        std::thread::sleep(timeout * 3);
        assert!(
            book.on_piece(ID, 0, 16384, now).is_err(),
            "beyond grace window stays unsolicited"
        );
    }

    /// Reassignment-cancel late-delivery grace
    /// ([`RequestBook::cancel_with_grace`]): row 1 — a cancelled slot
    /// accepts a same-coordinate late delivery within the grace window
    /// (redundant, not unsolicited — reassignment must not kill slow
    /// peers); row 2 — a second delivery is still unsolicited (the grace
    /// entry is consumed once); row 3 — cancelling a non-existent slot
    /// returns false and registers no grace.
    #[test]
    fn cancel_with_grace_accepts_late_delivery() {
        let timeout = Duration::from_millis(30);
        let mut book = RequestBook::new(timeout);
        let now = t0();
        let _ = book.dispatch(ID, 0, 16384, now);
        // Row 1: cancel -> late delivery within grace accepted.
        assert!(book.cancel_with_grace(ID, 0, 16384, now));
        assert_eq!(book.outstanding(), 0);
        std::thread::sleep(Duration::from_millis(10));
        assert!(
            book.on_piece(ID, 0, 16384, now).is_ok(),
            "grace accepts delivery racing the cancel"
        );
        // Row 2: the grace entry is one-shot — another same-coordinate
        // delivery is unsolicited.
        assert!(book.on_piece(ID, 0, 16384, now).is_err());
        // Row 3: cancelling a non-existent slot = false, no grace entry.
        let mut book = RequestBook::new(timeout);
        let now = t0();
        assert!(!book.cancel_with_grace(ID, 0, 16384, now));
        assert!(book.on_piece(ID, 0, 16384, now).is_err(), "no ghost grace");
    }

    // proptest: bookkeeping invariants under arbitrary operation sequences
    // (both modes driven the same way — default BDP and fallback
    // doubling): outstanding <= 256, window lower bound per mode (BDP in
    // [2, 256] per libtorrent `min_request_queue`; fallback in [6, 256]
    // per the aria2 initial value), no duplicate slots.
    fn drive_random_op(
        book: &mut RequestBook,
        op: u8,
        id: PieceId,
        begin: u32,
        length: u32,
        now: Instant,
        min_window: usize,
    ) {
        match op {
            0 => {
                let _ = book.dispatch(id, begin % 4096, length % 16384 + 1, now);
            }
            1 => {
                let _ = book.on_piece(id, begin % 4096, length % 16384 + 1, now);
            }
            2 => {
                let _ = book.expire_timed_out(now + Duration::from_secs(120));
            }
            _ => {
                let _ = book.on_choke(|_| false);
            }
        }
        // Invariants: outstanding within the cap; window bounded below per
        // mode and capped at 256; slots pairwise distinct.
        assert!(book.outstanding() <= UB_MAX_OUTSTANDING_REQUEST);
        assert!(
            book.window() >= min_window,
            "window {} below floor {min_window}",
            book.window()
        );
        assert!(book.window() <= UB_MAX_OUTSTANDING_REQUEST);
        let mut keys: Vec<_> = book.slots().map(|s| (s.id, s.begin, s.length)).collect();
        keys.sort();
        assert!(
            keys.windows(2).all(|w| w[0] != w[1]),
            "duplicate slots under random ops (mode fenestration invariant)"
        );
        book.begin_receive_round();
        let _ = book.end_receive_round();
        assert!(book.window() <= UB_MAX_OUTSTANDING_REQUEST);
    }

    proptest::proptest! {
        #[test]
        fn invariants_hold_under_random_operations(ops in proptest::prelude::prop::collection::vec(
            (0u8..4, proptest::prelude::any::<u32>(), 0u32..40_000u32, 1u32..65_536u32),
            0..128,
        )) {
            let mut bdp = RequestBook::new(Duration::from_secs(60))
                .with_window_mode(WindowMode::Bdp);
            let mut legacy = RequestBook::new(Duration::from_secs(60))
                .with_window_mode(WindowMode::LegacyDoubling);
            let now = t0();
            for (op, idx, begin, length) in ops {
                let id = PieceId::V1(idx % 8);
                drive_random_op(&mut bdp, op, id, begin, length, now, MIN_REQUEST_WINDOW);
                drive_random_op(
                    &mut legacy,
                    op,
                    id,
                    begin,
                    length,
                    now,
                    DEFAULT_MAX_OUTSTANDING_REQUEST,
                );
            }
        }
    }

    /// HAVE cursor: monotonic, no resends, the cursor itself excluded;
    /// expiry cleanup; the bitfield-vs-have choice
    /// (`DefaultBtInteractive.cc`).
    #[test]
    fn have_advertiser_cursor_and_expiry() {
        let start = t0();
        let mut adv = HaveAdvertiser::new();
        adv.advertise(PieceId::V1(1), start);
        adv.advertise(PieceId::V1(2), start);
        let (ids, cursor) = adv.drain_since_cursor();
        assert_eq!(ids, vec![PieceId::V1(1), PieceId::V1(2)]);
        assert_eq!(
            cursor, 2,
            "have_index starts at 1; after two entries cursor=2"
        );
        // No new advertisements: re-drain is empty and the cursor never
        // regresses.
        let (ids, cursor2) = adv.drain_since_cursor();
        assert!(ids.is_empty());
        assert_eq!(cursor2, 2);

        // New advertisements send only the delta.
        adv.advertise(PieceId::V1(3), start);
        let (ids, cursor3) = adv.drain_since_cursor();
        assert_eq!(ids, vec![PieceId::V1(3)]);
        assert_eq!(cursor3, 3);

        // Expiry cleanup: entries older than 5s dropped
        // (`HaveEraseCommand.cc`).
        adv.remove_expired(start + HAVE_EXPIRY + Duration::from_secs(1));
        adv.advertise(PieceId::V1(4), start + HAVE_EXPIRY + Duration::from_secs(1));
        let (ids, _) = adv.drain_since_cursor();
        assert_eq!(
            ids,
            vec![PieceId::V1(4)],
            "stale entries expired; only the new one is sent"
        );

        // Choice: 5 + bitfield_len <= n_haves * 9.
        assert!(
            !HaveAdvertiser::prefer_bitfield(10, 1),
            "11 > 9 -> individual haves"
        );
        assert!(
            HaveAdvertiser::prefer_bitfield(10, 2),
            "11 <= 18 → bitfield"
        );
    }

    /// EWMA estimator fixed-point arithmetic (numeric lock of libtorrent
    /// `sliding_average<int,20>` in `sliding_average.hpp`): the first
    /// sample lands directly; the deviation lags one sample (dev input
    /// exists from the second sample on); the smoothing denominators are
    /// `n` / `n-1` respectively; readings round via `(fp + 32) / 64`; the
    /// sample count is capped at 20.
    #[test]
    fn rtt_samples_ewma_fixed_point_table() {
        let mut r = RttSamples::default();
        assert_eq!((r.mean(), r.avg_deviation(), r.num_samples()), (0, 0, 0));
        r.add_sample(100);
        assert_eq!((r.mean(), r.avg_deviation(), r.num_samples()), (100, 0, 1));
        r.add_sample(100);
        assert_eq!((r.mean(), r.avg_deviation(), r.num_samples()), (100, 0, 2));
        // Third sample 300: dev input = |6400-19200| = 12800fp -> smoothed
        // to 6400fp (/2); mean = 6400 + (19200-6400)/3 = 10666fp ->
        // reading 167/100.
        r.add_sample(300);
        assert_eq!(
            (r.mean(), r.avg_deviation(), r.num_samples()),
            (167, 100, 3)
        );
        // Sample count capped at 20 (inverted_gain).
        for _ in 0..40 {
            r.add_sample(200);
        }
        assert_eq!(r.num_samples(), 20, "sample count capped = inverted_gain");
    }

    /// Adaptive-timeout decision table (the three shapes of libtorrent
    /// `request_timeout()`, `peer_connection.cpp`):
    /// row 1, no samples -> configured cap (the reference returns the
    /// settings default 60s — no evidence, no behavior change); row 2, a
    /// single 500ms sample -> `mean+mean/5` = 600ms -> ceil to 1s -> the
    /// 2s floor wins; row 3, a fast peer (constant 8ms) -> the 2s floor;
    /// row 4, a slow peer (100,100,900,900,900ms -> mean 580 + 4xdev 433
    /// = 2312ms) -> 3s; row 5, cap (book configured to 10s; samples
    /// 100/9900ms -> 45s -> min(45,10) = 10s); row 6, floor order
    /// (min before max).
    #[test]
    fn adaptive_timeout_decision_table() {
        // Row 1: no samples = configured cap (60s default — zero behavior
        // change).
        let mut book = RequestBook::new(DEFAULT_REQUEST_TIMEOUT);
        assert_eq!(book.adaptive_timeout(), DEFAULT_REQUEST_TIMEOUT);
        // Row 2: single sample +20%, then whole-second ceil, then floor.
        book.rtt.add_sample(500);
        assert_eq!(book.adaptive_timeout(), Duration::from_secs(2));
        // Row 3: fast peer at a constant 8ms -> the 2s floor (not 1s — the
        // floor prevents instant death).
        let mut book = RequestBook::new(DEFAULT_REQUEST_TIMEOUT);
        for _ in 0..5 {
            book.rtt.add_sample(8);
        }
        assert_eq!(book.adaptive_timeout(), MIN_ADAPTIVE_REQUEST_TIMEOUT);
        // Row 4: slow peer (high jitter) -> mean + 4 sigma = 2312ms -> 3s.
        let mut book = RequestBook::new(DEFAULT_REQUEST_TIMEOUT);
        for s in [100i64, 100, 900, 900, 900] {
            book.rtt.add_sample(s);
        }
        assert_eq!(
            book.rtt.mean(),
            580,
            "row 4 premise: mean fixed-point reading"
        );
        assert_eq!(
            book.rtt.avg_deviation(),
            433,
            "row 4 premise: deviation fixed-point reading"
        );
        assert_eq!(book.adaptive_timeout(), Duration::from_secs(3));
        // Row 5: cap = configured limit (10s configuration).
        let mut book = RequestBook::new(Duration::from_secs(10));
        book.rtt.add_sample(100);
        book.rtt.add_sample(9900);
        assert_eq!(book.adaptive_timeout(), Duration::from_secs(10));
        // Row 6: cap before floor (the reference `min` precedes `max`):
        // configured 1s, no samples -> configured value returned directly;
        // with a 1ms sample -> capped to 1s, then the 2s floor wins.
        let mut book = RequestBook::new(Duration::from_secs(1));
        assert_eq!(
            book.adaptive_timeout(),
            Duration::from_secs(1),
            "no samples"
        );
        book.rtt.add_sample(1);
        book.rtt.add_sample(1);
        assert_eq!(book.adaptive_timeout(), MIN_ADAPTIVE_REQUEST_TIMEOUT);
    }

    /// Snub timing under the adaptive timeout: a slow peer's slot
    /// (adaptive 3s) times out at 3s and sets snub (2.9s does not); a
    /// no-sample peer keeps the existing 60s boundary (the judgment uses
    /// the adaptive value); the grace registry still uses the configured
    /// cap (does not tighten with the adaptive value): a 10s-stale entry
    /// survives the 2x60s=120s sweep bound (an adaptive bound would clear
    /// it at 6s); late delivery of a retired slot is still accepted
    /// (the reference likewise never disconnects on late delivery,
    /// `peer_connection.cpp`).
    #[test]
    fn adaptive_timeout_snub_timing_and_grace_bound() {
        let mut book = RequestBook::new(DEFAULT_REQUEST_TIMEOUT);
        let now = t0();
        for s in [100i64, 100, 900, 900, 900] {
            book.rtt.add_sample(s);
        }
        assert_eq!(book.adaptive_timeout(), Duration::from_secs(3));
        let _ = book.dispatch(ID, 0, 16384, now);
        // 2.9s: below the adaptive timeout, no verdict.
        assert!(
            book.expire_timed_out(now + Duration::from_millis(2900))
                .is_empty(),
            "2.9s < the 3s adaptive value: no timeout verdict"
        );
        assert!(!book.is_snubbed());
        // Direct check that the grace-registry bound = configured cap (not
        // the adaptive value): pre-seed a 10s-stale entry; it survives the
        // timeout-triggered sweep (an adaptive bound of 2x3s=6s would
        // clear it).
        let stale_key = (PieceId::V1(42), 0, 1);
        book.expired
            .insert(stale_key, Instant::now() - Duration::from_secs(10));
        // 3.0s (boundary >=): timeout + snub (the sweep runs in the same
        // round).
        let expired = book.expire_timed_out(now + Duration::from_secs(3));
        assert_eq!(expired.len(), 1, "the 3s adaptive-value boundary times out");
        assert!(book.is_snubbed());
        assert!(
            book.expired.contains_key(&stale_key),
            "the grace-sweep bound = 2x the configured cap (120s), not the adaptive 6s"
        );
        // Late delivery of a retired slot is still accepted (the grace
        // entry is consumed; under saturated-clock semantics it arrives
        // immediately).
        std::thread::sleep(Duration::from_millis(10));
        assert!(
            book.on_piece(ID, 0, 16384, Instant::now()).is_ok(),
            "grace = the configured cap; it does not tighten with the adaptive value"
        );
        // No-sample shape: the 60s boundary is unchanged (regression
        // lock).
        let mut book = RequestBook::new(DEFAULT_REQUEST_TIMEOUT);
        let now = t0();
        let _ = book.dispatch(ID, 0, 16384, now);
        assert!(
            book.expire_timed_out(now + Duration::from_secs(59))
                .is_empty(),
            "no samples: 59s is not a timeout"
        );
        assert_eq!(
            book.expire_timed_out(now + Duration::from_secs(60)).len(),
            1,
            "no samples: the 60s boundary times out (zero change to existing behavior)"
        );
    }

    /// Adaptive-timeout mirror: attaching publishes the current value (no
    /// samples = configured cap -> 60000ms); sampling updates it (3000ms
    /// after the slow-peer samples); default construction (no mirror) has
    /// zero side effects on all paths.
    #[test]
    fn adaptive_timeout_mirror_publishes_on_sample() {
        let mirror = Arc::new(AtomicU64::new(0));
        let mut book = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_adaptive_timeout_mirror(Arc::clone(&mirror));
        assert_eq!(
            mirror.load(Ordering::Relaxed),
            60_000,
            "published at attach: no samples = the configured cap (milliseconds)"
        );
        let now = t0();
        // Slot-matched delivery sampling (slow-peer shape, each delay a
        // sample) -> the mirror updates to 3000ms with the sampling.
        for (i, delay) in [100u64, 100, 900, 900, 900].iter().enumerate() {
            let begin = (i as u32 + 1) * 16384;
            let _ = book.dispatch(ID, begin, 16384, now);
            assert!(
                book.on_piece(ID, begin, 16384, now + Duration::from_millis(*delay))
                    .is_ok()
            );
        }
        assert_eq!(book.adaptive_timeout(), Duration::from_secs(3));
        assert_eq!(
            mirror.load(Ordering::Relaxed),
            3_000,
            "published on sample: the mirror = the current adaptive value"
        );
        // Default construction (no mirror): sampling/timeout/delivery all
        // side-effect free.
        let mut plain = RequestBook::new(DEFAULT_REQUEST_TIMEOUT);
        let _ = plain.dispatch(ID, 0, 16384, now);
        assert!(plain.on_piece(ID, 0, 16384, now).is_ok());
        assert!(
            plain
                .expire_timed_out(now + DEFAULT_REQUEST_TIMEOUT)
                .is_empty()
        );
    }

    /// Doubling decision unchanged while samples exist (fallback path):
    /// with RTT samples present, the `end_receive_round` doubling verdict
    /// is bit-identical (aria2 `DefaultBtInteractive.cc`). The BDP-mode
    /// counterpart is [`Self::bdp_window_unaffected_by_rtt_samples`]. The
    /// initial value is pinned to 6 = the aria2 anchor (the default is 16).
    #[test]
    fn window_doubling_unaffected_by_rtt_samples() {
        let mut book = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_window_mode(WindowMode::LegacyDoubling)
            .with_initial_window(6);
        let now = t0();
        // First build slow-peer samples (adaptive 3s).
        for s in [100i64, 100, 900, 900, 900] {
            book.rtt.add_sample(s);
        }
        assert_eq!(book.adaptive_timeout(), Duration::from_secs(3));
        // Window 6: complete 2 (2*4=8 >= 6) -> 12 (the verdict is
        // identical to the no-sample state).
        for i in 0..6u32 {
            let _ = book.dispatch(ID, i * 100, 100, now);
        }
        book.begin_receive_round();
        for i in 0..2u32 {
            let _ = book.on_piece(ID, i * 100, 100, now + Duration::from_millis(300));
        }
        assert!(
            book.end_receive_round(),
            "with samples present the doubling verdict is unchanged"
        );
        assert_eq!(book.window(), 12);
    }

    /// BDP rate EWMA fixed-point table (libtorrent `stat.cpp` integer
    /// arithmetic plus the first-sample-seeding divergence): the settle
    /// rule is `sample = acc x 1000 / elapsed_ms`, `value = value x 4/5 +
    /// sample/5` (alpha 1/5 — the caller passes the gain per
    /// slow-start/fallback state); the first sample seeds directly; an
    /// idle window (sample 0) decays toward 0.
    #[test]
    fn bdp_rate_ewma_settle_table() {
        let mut r = RateEwma::new();
        let t = t0();
        // No samples yet: settle does nothing (the window starts at the
        // first sample — the idle span before the first block cannot
        // produce a crushing zero sample).
        assert!(!r.settle(t + RATE_WINDOW, RATE_EWMA_INVERTED_GAIN));
        assert_eq!(r.value, 0);
        // First window: 100B/1s -> sample 100, seeded directly (divergence
        // arm, gain unused).
        r.add(100, t);
        assert!(r.settle(t + RATE_WINDOW, RATE_EWMA_INVERTED_GAIN));
        assert_eq!(r.value, 100);
        // Idle window: 0B/1s -> sample 0 -> 100x4/5 + 0 = 80 (reference
        // integer division).
        assert!(r.settle(t + 2 * RATE_WINDOW, RATE_EWMA_INVERTED_GAIN));
        assert_eq!(r.value, 80);
        // Next window: 50B/1s -> 80x4/5 + 50/5 = 64 + 10 = 74.
        r.add(50, t + 2 * RATE_WINDOW);
        assert!(r.settle(t + 3 * RATE_WINDOW, RATE_EWMA_INVERTED_GAIN));
        assert_eq!(r.value, 74);
        // Sub-window granularity (<1s) does not settle.
        r.add(1000, t + 3 * RATE_WINDOW);
        assert!(!r.settle(
            t + 3 * RATE_WINDOW + Duration::from_millis(999),
            RATE_EWMA_INVERTED_GAIN
        ));
        // Multi-second single settle: 1000B/2s -> sample 500 -> 74x4/5 +
        // 500/5 = 59 + 100 = 159.
        assert!(r.settle(t + 5 * RATE_WINDOW, RATE_EWMA_INVERTED_GAIN));
        assert_eq!(r.value, 159);
        // Backwards-clock defense: no settle, no negative samples.
        assert!(!r.settle(t, RATE_EWMA_INVERTED_GAIN));
        assert_eq!(r.value, 159);
    }

    /// Rate EWMA long-window fixed-point table: gain alpha 1/10 (aligned
    /// with the stand-in `SpeedCalc.cc` 10s smoothing; effective after
    /// slow-start exit — the first-sample arm likewise skips the gain).
    /// For the same input sequence the readings move at exactly half the
    /// granularity of the alpha-1/5 table (90/86/127 vs 80/74/159) —
    /// denoising under high jitter, halved idle decay, pinned numerically.
    #[test]
    fn bt_rate_ewma_long_settle_table() {
        let mut r = RateEwma::new();
        let t = t0();
        assert!(!r.settle(t + RATE_WINDOW, RATE_EWMA_LONG_INVERTED_GAIN));
        // First window seeds directly (gain unused).
        r.add(100, t);
        assert!(r.settle(t + RATE_WINDOW, RATE_EWMA_LONG_INVERTED_GAIN));
        assert_eq!(r.value, 100);
        // Idle window: 100x9/10 + 0 = 90 (the alpha-1/5 table yields 80 —
        // decay halved).
        assert!(r.settle(t + 2 * RATE_WINDOW, RATE_EWMA_LONG_INVERTED_GAIN));
        assert_eq!(r.value, 90);
        // Next window: 90x9/10 + 50/10 = 81 + 5 = 86 (alpha-1/5
        // counterpart 74).
        r.add(50, t + 2 * RATE_WINDOW);
        assert!(r.settle(t + 3 * RATE_WINDOW, RATE_EWMA_LONG_INVERTED_GAIN));
        assert_eq!(r.value, 86);
        // Multi-second single settle: 86x9/10 + 500/10 = 77 + 50 = 127
        // (alpha-1/5 counterpart 159 — the single 500-sample jolt is
        // halved by the 9/10 history weight).
        r.add(1000, t + 3 * RATE_WINDOW);
        assert!(r.settle(t + 5 * RATE_WINDOW, RATE_EWMA_LONG_INVERTED_GAIN));
        assert_eq!(r.value, 127);
    }

    /// BDP target-window decision table (libtorrent `peer_connection.cpp`
    /// behavior + "slow start = +1 per completed block during the
    /// no-sample period") — the reference-bit-for-bit face: alpha 1/5 with
    /// direct assignment (pin the `BH_RATE_EWMA_LONG=0` x
    /// `BH_BDP_WINDOW_HYSTERESIS=0` equivalents via the builders); the
    /// initial value is pinned to 6 = the aria2 anchor (the default is
    /// 16); the default (jitter adaptation on) decision table is
    /// [`Self::bt_jitter_window_decision_table`].
    /// Row 1, slow-start growth (no rate evidence): +1 per received block,
    /// 6->9 (on_piece-driven); row 2, first rate-window settlement: exits
    /// slow start, window = `3s x 81920B/s / 16KiB = 15` (the first sample
    /// seeds directly); row 3, next windows EWMA alpha 1/5: `81920x4/5 +
    /// 49152/5 = 65536 + 9830 = 75366` -> `3x75366/16384 = 13`; row 4,
    /// slow peer: 1638B/s -> target 0 -> the 2 floor (reference
    /// `min_request_queue`); row 5, fast peer: 16MB/s -> target 3000 ->
    /// the 256 cap; row 6, configurable cap: with cap 8 the fast peer
    /// caps at 8; row 7, idle decay: sample 0 -> reading x4/5 = 60292 ->
    /// window 11; row 8, snub exits slow start: no evidence + timeout ->
    /// the window floors at 2. Rows 2-7 drive rate.add/settle +
    /// refresh_window directly; the on_piece supply arm is covered by
    /// rows 1/8 and the mirror/supply tests.
    #[test]
    fn bdp_window_decision_table() {
        let now = t0();
        // Row 1: slow-start +1/block (all at the same instant — <1s, no
        // rate-window settle).
        let mut book = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_window_mode(WindowMode::Bdp)
            .with_initial_window(6)
            .with_rate_ewma_long(false)
            .with_window_hysteresis(false)
            .with_window_floor(2);
        assert_eq!(
            book.window(),
            6,
            "explicit initial value 6 (the aria2 fallback arm; the default 16 is locked by its own table)"
        );
        for i in 0..3u32 {
            let _ = book.dispatch(ID, i * 16384, 16384, now);
            assert!(book.on_piece(ID, i * 16384, 16384, now).is_ok());
        }
        assert_eq!(book.window(), 9, "slow start 6 + 3 blocks = 9");
        assert!(book.slow_start, "still in slow start without rate evidence");

        // Row 2: first rate-window settle (+1s), first sample seeds
        // directly: 5 blocks x 16KiB / 1s = 81920 B/s -> 3x81920/16384 =
        // 15, slow start exits.
        let mut book = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_window_mode(WindowMode::Bdp)
            .with_initial_window(6)
            .with_rate_ewma_long(false)
            .with_window_hysteresis(false)
            .with_window_floor(2);
        book.rate.add(5 * 16384, now);
        assert!(
            book.rate.settle(now + RATE_WINDOW, RATE_EWMA_INVERTED_GAIN),
            "first settlement window"
        );
        book.refresh_window(now + RATE_WINDOW);
        assert!(
            !book.slow_start,
            "rate evidence present -> slow start exits"
        );
        assert_eq!(book.window(), 15, "3s × 81920B/s / 16KiB = 15");

        // Row 3: next-window EWMA (3 blocks x 16KiB / 1s = 49152B/s):
        // 81920x4/5 + 49152/5 = 65536 + 9830 = 75366 -> 3x75366/16384 =
        // 13.
        book.rate.add(3 * 16384, now + RATE_WINDOW);
        assert!(
            book.rate
                .settle(now + 2 * RATE_WINDOW, RATE_EWMA_INVERTED_GAIN)
        );
        book.refresh_window(now + 2 * RATE_WINDOW);
        assert_eq!(book.rate.value, 75366, "EWMA alpha=1/5 fixed-point reading");
        assert_eq!(
            book.window(),
            13,
            "3 x 75366 / 16384 = 13 (integer division)"
        );

        // Row 4: slow peer floors. The rate window starts at the first
        // block delivery: two 16KiB blocks delivered 10s apart -> sample
        // = 2x16384x1000/10000 = 3276 B/s -> target 0 -> 2. (Window start
        // = first block delivery — idle time before the first request
        // stays out of the rate window.)
        let mut slow = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_window_mode(WindowMode::Bdp)
            .with_initial_window(6)
            .with_rate_ewma_long(false)
            .with_window_hysteresis(false)
            .with_window_floor(2);
        let _ = slow.dispatch(ID, 0, 16384, now);
        let _ = slow.dispatch(ID, 16384, 16384, now);
        assert!(slow.on_piece(ID, 0, 16384, now).is_ok());
        assert_eq!(
            slow.window(),
            7,
            "still slow start at first-block delivery (+1, no rate evidence)"
        );
        assert!(
            slow.on_piece(ID, 16384, 16384, now + Duration::from_secs(10))
                .is_ok()
        );
        assert_eq!(
            slow.window(),
            2,
            "3276B/s -> min_request_queue floor (reference :80)"
        );

        // Row 5: fast peer cap. 1000 blocks x 16KiB / 1s = 16MiB/s ->
        // target 3000 -> 256 (default cap).
        let mut fast = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_window_mode(WindowMode::Bdp)
            .with_initial_window(6)
            .with_rate_ewma_long(false)
            .with_window_hysteresis(false)
            .with_window_floor(2);
        fast.rate.add(1000 * 16384, now);
        assert!(fast.rate.settle(now + RATE_WINDOW, RATE_EWMA_INVERTED_GAIN));
        fast.refresh_window(now + RATE_WINDOW);
        assert!(!fast.slow_start);
        assert_eq!(fast.window(), 256, "fast peer capped = the default cap");

        // Row 6: configurable cap. The same rate with cap 8 -> capped at 8
        // (bt-max-out-request-queue).
        let mut capped = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_window_mode(WindowMode::Bdp)
            .with_max_out_request_queue(8)
            .with_initial_window(6)
            .with_rate_ewma_long(false)
            .with_window_hysteresis(false)
            .with_window_floor(2);
        capped.rate.add(1000 * 16384, now);
        assert!(
            capped
                .rate
                .settle(now + RATE_WINDOW, RATE_EWMA_INVERTED_GAIN)
        );
        capped.refresh_window(now + RATE_WINDOW);
        assert!(!capped.slow_start);
        assert_eq!(capped.window(), 8, "capped by the configurable cap of 8");

        // Row 7: idle decay. From row 3's end state (75366), a zero-byte
        // window: 75366x4/5 = 60292 -> 3x60292/16384 = 11.
        book.rate.add(0, now + 2 * RATE_WINDOW);
        assert!(
            book.rate
                .settle(now + 3 * RATE_WINDOW, RATE_EWMA_INVERTED_GAIN)
        );
        book.refresh_window(now + 3 * RATE_WINDOW);
        assert_eq!(book.rate.value, 60292, "idle-window sample 0, reading x4/5");
        assert_eq!(book.window(), 11, "3 × 60292 / 16384 = 11");

        // Row 8: snub exits slow start. No rate evidence + slot timeout ->
        // the window floors at 2 (no evidence means target = 0 -> floor).
        let mut snubbed_book = RequestBook::new(Duration::from_secs(1))
            .with_window_mode(WindowMode::Bdp)
            .with_initial_window(6)
            .with_rate_ewma_long(false)
            .with_window_hysteresis(false)
            .with_window_floor(2);
        let _ = snubbed_book.dispatch(ID, 0, 16384, now);
        assert!(snubbed_book.slow_start);
        let expired = snubbed_book.expire_timed_out(now + Duration::from_secs(1));
        assert_eq!(
            expired.len(),
            1,
            "slot timeout (the 1s configured-cap boundary)"
        );
        assert!(snubbed_book.is_snubbed());
        assert!(!snubbed_book.slow_start, "snub exits slow start");
        assert_eq!(
            snubbed_book.window(),
            2,
            "no rate evidence -> the floor of 2 (no pile-up)"
        );
    }

    /// Endgame-tail window-floor override table: the attached
    /// engine→book override lifts the effective BDP floor
    /// `max(generic, override)` — relax-only, never above the configured
    /// cap, immediate past the hysteresis hold band (the floor is a hard
    /// bound, not a rate target), inert during slow start and in fallback
    /// mode; detached / 0 = the generic floor bit-for-bit.
    #[test]
    fn endgame_window_floor_override_table() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicU64;

        let now = t0();
        // A settled slow-rate book (post-slow-start, generic floor 64):
        // 2 blocks / 10s -> 3276B/s -> target 0 -> generic floor 64.
        let mk = || {
            let mut b = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
                .with_window_mode(WindowMode::Bdp)
                .with_initial_window(6)
                .with_rate_ewma_long(false)
                .with_window_floor(64);
            b.rate.add(2 * 16384, now);
            assert!(
                b.rate
                    .settle(now + Duration::from_secs(10), RATE_EWMA_INVERTED_GAIN)
            );
            b.refresh_window(now + Duration::from_secs(10));
            assert!(!b.slow_start);
            b
        };

        // Row 1: detached / override 0 = the generic floor (hysteresis on,
        // the default face): 64.
        let mut b = mk();
        assert_eq!(b.window(), 64, "no override = the generic floor");
        let zero = Arc::new(AtomicU64::new(0));
        b = mk().with_endgame_window_floor(Arc::clone(&zero));
        b.refresh_window(now + Duration::from_secs(11));
        assert_eq!(b.window(), 64, "override 0 = the generic floor bit-for-bit");

        // Row 2: override 80 lifts through the hysteresis hold band
        // (capped=80 vs w=64 sits inside [0.7w, 1.3w] — the plain hold
        // arm would park at 64; the floor is a hard bound -> 80).
        let o = Arc::new(AtomicU64::new(80));
        let mut b = mk().with_endgame_window_floor(Arc::clone(&o));
        assert_eq!(b.window(), 64, "attach does not publish immediately");
        b.refresh_window(now + Duration::from_secs(11));
        assert_eq!(
            b.window(),
            80,
            "override 80 pierces the hold band immediately"
        );

        // Row 3: a huge override stays under the configured cap (256
        // default; the min(max_window) clamp).
        let big = Arc::new(AtomicU64::new(u64::MAX));
        let mut b = mk().with_endgame_window_floor(Arc::clone(&big));
        b.refresh_window(now + Duration::from_secs(11));
        assert_eq!(b.window(), 256, "the override does not pierce the cap");
        // ... and a tighter configured cap binds first (cap 8).
        let mut b = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_window_mode(WindowMode::Bdp)
            .with_max_out_request_queue(8)
            .with_initial_window(6)
            .with_rate_ewma_long(false)
            .with_window_floor(2)
            .with_endgame_window_floor(Arc::new(AtomicU64::new(80)));
        b.rate.add(2 * 16384, now);
        assert!(
            b.rate
                .settle(now + Duration::from_secs(10), RATE_EWMA_INVERTED_GAIN)
        );
        b.refresh_window(now + Duration::from_secs(10));
        b.refresh_window(now + Duration::from_secs(11));
        assert_eq!(
            b.window(),
            8,
            "the configurable cap of 8 binds before the override"
        );

        // Row 4: relax-only — an override below the generic floor never
        // lowers the window (16 < 64 keeps 64).
        let small = Arc::new(AtomicU64::new(16));
        let mut b = mk().with_endgame_window_floor(Arc::clone(&small));
        b.refresh_window(now + Duration::from_secs(11));
        assert_eq!(b.window(), 64, "the override only raises, never lowers");

        // Row 5: dropping the override back to 0 leaves the window held
        // at 80 inside the band (the hold arm; capped=64 >= 0.7x80 keeps
        // 80 — bounded by the 256 cap, harmless depth for a holder).
        let lift = Arc::new(AtomicU64::new(80));
        let mut b = mk().with_endgame_window_floor(Arc::clone(&lift));
        b.refresh_window(now + Duration::from_secs(11));
        assert_eq!(b.window(), 80, "80 after the lift");
        lift.store(0, Ordering::Relaxed);
        b.refresh_window(now + Duration::from_secs(12));
        assert_eq!(
            b.window(),
            80,
            "after the override drops to 0, held inside the band"
        );

        // Row 6: slow start is untouched (no rate evidence — the override
        // applies only in the post-slow-start recompute): +1/block growth
        // continues, window stays 6.
        let mut b = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_window_mode(WindowMode::Bdp)
            .with_initial_window(6)
            .with_rate_ewma_long(false)
            .with_window_floor(2)
            .with_endgame_window_floor(Arc::new(AtomicU64::new(200)));
        let _ = b.dispatch(ID, 0, 16384, now);
        assert!(b.on_piece(ID, 0, 16384, now).is_ok());
        assert_eq!(
            b.window(),
            7,
            "the slow-start path is unaffected by the override"
        );
        assert!(b.slow_start);

        // Row 7: fallback mode is untouched (the window belongs to the
        // doubling heuristic; refresh_window early-returns).
        let mut b = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_window_mode(WindowMode::LegacyDoubling)
            .with_initial_window(6)
            .with_endgame_window_floor(Arc::new(AtomicU64::new(200)));
        b.rate.add(2 * 16384, now);
        assert!(
            b.rate
                .settle(now + Duration::from_secs(10), RATE_EWMA_INVERTED_GAIN)
        );
        b.refresh_window(now + Duration::from_secs(10));
        assert_eq!(b.window(), 6, "fallback mode ignores the override");
    }

    /// Frozen-seam regression lock (review-blocker fix): the
    /// endgame-tail floor lift must be inert with no override — the
    /// generic floor keeps its pre-fix **soft** role. Reproduction
    /// shape (the review probe, deterministic): slow start grows
    /// 6 -> 50 via 44 same-instant deliveries (no rate window settles
    /// inside the growth); one outstanding slot then snubs out
    /// (`expire_timed_out` at +3s; the adaptive timeout floors at 2s),
    /// the first settled rate reading (44 blocks / 3s = 240298 B/s)
    /// gives target 44 -> capped = generic floor 64, which sits INSIDE
    /// the hold band [0.7x50, 1.3x50] = [35, 65] -> the hold arm keeps
    /// w=50 BELOW the generic floor. The unconditional trailing
    /// `.max(floor)` lifted this to 64 (dev-vs-branch probe delta 55->64
    /// class) — non-endgame drift; the fixed clamp runs only on the
    /// override's component beyond the generic floor.
    #[test]
    fn endgame_floor_seam_frozen_slow_start_exit_hold() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicU64;

        let now = t0();
        let mk = || {
            let mut b = RequestBook::new(Duration::from_secs(1))
                .with_window_mode(WindowMode::Bdp)
                .with_initial_window(6)
                .with_window_floor(64);
            // 44 same-instant matched deliveries: slow-start +1 each
            // (6 -> 50), zero rate settlement inside the growth burst.
            for i in 0..44u32 {
                let _ = b.dispatch(ID, i * 100, 100, now);
                assert!(b.on_piece(ID, i * 100, 100, now).is_ok());
            }
            assert_eq!(b.window(), 50, "slow start 6 + 44 blocks = 50");
            assert!(b.slow_start);
            b
        };
        // One still-outstanding slot times out at +3s (adaptive floors at
        // 2s; request_timeout 1s caps below the floor -> 2s): snub exits
        // slow start, the same refresh settles the first rate window
        // (44x100B / 3s -> target far below the floor -> capped = 64,
        // inside the hold band) -> the pre-change formula HOLDS 50.
        let mk_and_snub = |b: &mut RequestBook| {
            let _ = b.dispatch(ID, 100_000, 100, now);
            let expired = b.expire_timed_out(now + Duration::from_secs(3));
            assert_eq!(expired.len(), 1, "slot timeout (snub)");
            assert!(!b.slow_start, "snub exits slow start");
        };

        // Row 1 (the seam): detached seam — the hold arm keeps w=50 below
        // the generic floor (bit-for-bit pre-fix; the buggy
        // unconditional clamp lifted this to 64).
        let mut b = mk();
        mk_and_snub(&mut b);
        assert_eq!(
            b.window(),
            50,
            "no override: w=50 kept inside the hold band (< the generic floor 64) bit-for-bit"
        );
        // A second settled window (idle, reading x4/5) still holds 50.
        b.refresh_window(now + Duration::from_secs(4));
        assert_eq!(
            b.window(),
            50,
            "the second settlement window still holds (the seam stays frozen)"
        );

        // Row 2: override 0 — identical (the no-op default value).
        let mut b = mk();
        b = b.with_endgame_window_floor(Arc::new(AtomicU64::new(0)));
        assert_eq!(
            b.window(),
            50,
            "the window is unchanged before attach (the constructor-clamp shape)"
        );
        mk_and_snub(&mut b);
        assert_eq!(b.window(), 50, "override 0 = the seam frozen bit-for-bit");

        // Row 3: override == generic floor (64, not ">") — no lift
        // component, the clamp does not run.
        let mut b = mk();
        b = b.with_endgame_window_floor(Arc::new(AtomicU64::new(64)));
        mk_and_snub(&mut b);
        assert_eq!(
            b.window(),
            50,
            "override == the generic floor: no lift component, no clamp"
        );

        // Row 4: override 80 > 64 — the lift component clamps to 80
        // immediately (the tail face's intended hard bound).
        let mut b = mk();
        b = b.with_endgame_window_floor(Arc::new(AtomicU64::new(80)));
        mk_and_snub(&mut b);
        assert_eq!(
            b.window(),
            80,
            "override 80 > the generic floor: the lift component takes effect immediately"
        );
    }

    /// Jitter-adaptation window decision table (the default face: long
    /// window alpha 1/10 + hysteresis both on; each row drives the
    /// [`Self::refresh_window`] production path). The initial value is
    /// pinned to 6 = the aria2 anchor (the default is 16); row A's 1.3x6
    /// growth band and row G's pre-collapse 6 both scale from it.
    /// Row A: first sample seeds directly + upward growth (6->15);
    /// row B: holds inside the band (target 14 in [0.7x15, 1.3x15] ->
    /// window unmoved; the direct face with the same input -> 13, locked
    /// by pinned table row 3 — the hold divergence is observable);
    /// rows C/D: idle decay holds inside the band (targets 12/11 still in
    /// band; the direct face would be at 11); row E: the fourth idle
    /// window targets 10 < 0.7x15 -> shrink; row F: upward growth
    /// (target 105 > 1.3x10); row G: genuine collapse is not damped by
    /// the band (6->2, same as the direct face); row H: hysteresis off =
    /// direct-assignment divergence lock (15->14); row I: long window off
    /// = reference gain + hysteresis on (reading 75366 at alpha 1/5,
    /// window holds 15 — switch independence); row J: the mirror holds
    /// with zero jitter.
    #[test]
    fn bt_jitter_window_decision_table() {
        let now = t0();
        // Row A: first rate-window settle (seed 81920B/s -> target 15 >
        // 1.3x6 -> grow).
        let mut book = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_window_mode(WindowMode::Bdp)
            .with_initial_window(6)
            .with_window_floor(2);
        book.rate.add(5 * 16384, now);
        book.refresh_window(now + RATE_WINDOW);
        assert!(
            !book.slow_start,
            "slow start exits at the first settlement window"
        );
        assert_eq!(book.window(), 15, "direct fill 81920 -> 15, upward growth");

        // Row B: second window (49152B/s) -> 81920x9/10 + 49152/10 =
        // 73728 + 4915 = 78643 -> target 14 in band -> hold 15 (the
        // direct face would be 13 — the divergence row).
        book.rate.add(3 * 16384, now + RATE_WINDOW);
        book.refresh_window(now + 2 * RATE_WINDOW);
        assert_eq!(book.rate.value, 78643, "alpha=1/10 fixed-point reading");
        assert_eq!(book.window(), 15, "target 14 in [10.5, 19.5] -> hold");

        // Rows C/D: idle windows x2 (sample 0) -> 78643x9/10 = 70778
        // (target 12), x9/10 = 63700 (target 11) — both hold in band (the
        // direct face would be down to 11 by now).
        book.refresh_window(now + 3 * RATE_WINDOW);
        assert_eq!(
            book.rate.value, 70778,
            "idle decay -10%/window (alpha=1/5 would be -20%)"
        );
        assert_eq!(book.window(), 15, "target 12 in band -> hold");
        book.refresh_window(now + 4 * RATE_WINDOW);
        assert_eq!(book.rate.value, 63700, "second idle-window beat");
        assert_eq!(book.window(), 15, "target 11 in band -> hold");

        // Row E: third idle window -> 57330 (target 10) < 0.7x15 = 10.5
        // -> shrink.
        book.refresh_window(now + 5 * RATE_WINDOW);
        assert_eq!(book.rate.value, 57330, "third idle-window beat");
        assert_eq!(book.window(), 10, "target 10 < 0.7x15 -> downward shrink");

        // Row F: upward growth. 320 blocks/window -> sample 5242880 ->
        // 57330x9/10 + 524288 = 51597 + 524288 = 575885 -> target 105 >
        // 1.3x10 -> grow.
        book.rate.add(320 * 16384, now + 5 * RATE_WINDOW);
        book.refresh_window(now + 6 * RATE_WINDOW);
        assert_eq!(
            book.rate.value, 575885,
            "a single-sample jolt moves only 1/10 (observable denoising)"
        );
        assert_eq!(book.window(), 105, "target 105 > 1.3x10 -> upward growth");

        // Row G: a genuine slow-peer collapse is not damped by the band.
        // 16384B/10s = 1638B/s -> target 0 -> floor 2 < 0.7x6 = 4.2 ->
        // shrink (the same verdict as the direct face).
        let mut slow = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_window_mode(WindowMode::Bdp)
            .with_initial_window(6)
            .with_window_floor(2);
        slow.rate.add(16384, now);
        slow.refresh_window(now + Duration::from_secs(10));
        assert_eq!(
            slow.window(),
            2,
            "a genuine collapse is judged straight to the floor (hysteresis does not damp the downward cross)"
        );

        // Row H: hysteresis off = direct-assignment divergence lock (the
        // `BH_BDP_WINDOW_HYSTERESIS=0` construction-time equivalent):
        // same input as rows A/B -> 15->14 assigned directly (long window
        // on).
        let mut direct = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_window_mode(WindowMode::Bdp)
            .with_initial_window(6)
            .with_window_hysteresis(false)
            .with_window_floor(2);
        direct.rate.add(5 * 16384, now);
        direct.refresh_window(now + RATE_WINDOW);
        assert_eq!(
            direct.window(),
            15,
            "row A judged the same on the direct face"
        );
        direct.rate.add(3 * 16384, now + RATE_WINDOW);
        direct.refresh_window(now + 2 * RATE_WINDOW);
        assert_eq!(
            direct.rate.value, 78643,
            "the long-window reading is the same (switch independence)"
        );
        assert_eq!(
            direct.window(),
            14,
            "hysteresis off -> target assigned directly (the divergence row)"
        );

        // Row I: long window off (the `BH_RATE_EWMA_LONG=0`
        // construction-time equivalent) = reference alpha 1/5 + hysteresis
        // on: reading 75366 (alpha-1/5 fixed point) -> target 13 in band
        // -> hold 15 (the pinned reference face with the same input -> 13
        // — hysteresis acts independently).
        let mut reference_gain = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_window_mode(WindowMode::Bdp)
            .with_initial_window(6)
            .with_rate_ewma_long(false)
            .with_window_floor(2);
        reference_gain.rate.add(5 * 16384, now);
        reference_gain.refresh_window(now + RATE_WINDOW);
        assert_eq!(
            reference_gain.window(),
            15,
            "row A judged the same (the gain does not participate in direct fill)"
        );
        reference_gain.rate.add(3 * 16384, now + RATE_WINDOW);
        reference_gain.refresh_window(now + 2 * RATE_WINDOW);
        assert_eq!(
            reference_gain.rate.value, 75366,
            "alpha=1/5 fixed-point reading (long window off)"
        );
        assert_eq!(reference_gain.window(), 15, "target 13 in band -> hold");

        // Row J: the mirror follows + holds with zero jitter (in-band
        // recomputes produce no mirror flips).
        let mirror = Arc::new(AtomicU64::new(0));
        let mut mirrored = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_window_mode(WindowMode::Bdp)
            .with_initial_window(6)
            .with_target_window_mirror(Arc::clone(&mirror))
            .with_window_floor(2);
        mirrored.rate.add(5 * 16384, now);
        mirrored.refresh_window(now + RATE_WINDOW);
        assert_eq!(mirror.load(Ordering::Relaxed), 15, "follows the growth");
        mirrored.rate.add(3 * 16384, now + RATE_WINDOW);
        mirrored.refresh_window(now + 2 * RATE_WINDOW);
        assert_eq!(mirrored.window(), 15, "held inside the band");
        assert_eq!(
            mirror.load(Ordering::Relaxed),
            15,
            "zero mirror jitter while held"
        );
    }

    /// BDP supply rhythm (`budget()` = target window - in flight): during
    /// slow start the budget widens block by block (window 9, 3 in flight
    /// -> budget 6); when the window shrinks (slow peer floors at 2) the
    /// budget saturates at 0 (`window - min(outstanding, window)`, no
    /// negative budget) and over-window dispatch is rejected (WindowFull
    /// carries the shrunk window). Floor check: under a low-rate sample
    /// the target window does not collapse to the reference floor of 2
    /// but is lifted to the floor (24 injected explicitly; the default
    /// today is 64, explicit `=24`/`=2` remain the fallback seams). The
    /// floor never punches through the cap.
    #[test]
    fn bt_window_floor_lifts_collapsed_target() {
        let mut book = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_window_mode(WindowMode::Bdp)
            .with_window_floor(24);
        let now = t0();
        // Exit slow start: one block received + a first rate sample (low
        // rate 1638B/s).
        let _ = book.dispatch(ID, 0, 16384, now);
        let _ = book.on_piece(ID, 0, 16384, now);
        book.rate.add(16384, now);
        assert!(
            book.rate
                .settle(now + Duration::from_secs(10), RATE_EWMA_INVERTED_GAIN)
        );
        book.refresh_window(now + Duration::from_secs(10));
        // Reference behavior here: target=0 -> floor 2; with the floor: 24.
        assert_eq!(book.window(), 24, "the floor lifts the collapsed target");
        // Tightened cap: with max_window=8 the floor does not exceed the
        // cap.
        let mut capped = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_window_mode(WindowMode::Bdp)
            .with_window_floor(24)
            .with_window_hysteresis(false)
            .with_max_out_request_queue(8);
        let _ = capped.dispatch(ID, 0, 16384, now);
        let _ = capped.on_piece(ID, 0, 16384, now);
        capped.rate.add(16384, now);
        assert!(
            capped
                .rate
                .settle(now + Duration::from_secs(10), RATE_EWMA_INVERTED_GAIN)
        );
        capped.refresh_window(now + Duration::from_secs(10));
        assert_eq!(capped.window(), 8, "the floor does not exceed the cap");
    }

    /// Initial request-window depth pinning (the default is 16 via
    /// `BH_REQ_WINDOW_INIT`; `=6` restores the aria2 `BtConstants.h`
    /// anchor). The A/B arms 16/24 are injected via
    /// [`RequestBook::with_initial_window`] (a test process cannot mutate
    /// env — edition 2024 has no set_var; production goes through
    /// [`RequestBook::new`]'s environment default). Row 1: the default
    /// construction window is 16; row 2: injected 16/24 initial windows
    /// are honored, slow-start +1/block unchanged, the explicit `=6`
    /// fallback arm works; row 3: after a BDP refresh, floor/max clamps
    /// are independent of the initial value (same verdicts as the
    /// initial-6 tables); row 4: the initial value never exceeds the
    /// configured cap; the builder clamps out-of-range to [2, 256].
    #[test]
    fn bt_initial_window_knob() {
        let now = t0();
        // Row 1: default construction window = 16 (both modes); the aria2
        // anchor 6 is now the explicit fallback arm.
        let book = RequestBook::new(DEFAULT_REQUEST_TIMEOUT);
        assert_eq!(
            book.window(),
            16,
            "the default initial value is 16 (BH_REQ_WINDOW_INIT unset)"
        );

        // Row 2: A/B arms injected 16/24 — initial window honored,
        // slow-start +1/block unchanged (block-by-block growth during the
        // no-evidence period, all at the same instant <1s, no settle);
        // explicit 6 = the fallback arm (the `BH_REQ_WINDOW_INIT=6`
        // construction-time equivalent = the aria2 anchor value).
        let mut w16 = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_window_mode(WindowMode::Bdp)
            .with_window_floor(2)
            .with_initial_window(16);
        assert_eq!(
            w16.window(),
            16,
            "arm A initial value 16 (= the new default)"
        );
        for i in 0..3u32 {
            let _ = w16.dispatch(ID, i * 16384, 16384, now);
            assert!(w16.on_piece(ID, i * 16384, 16384, now).is_ok());
        }
        assert_eq!(
            w16.window(),
            19,
            "slow start 16 + 3 blocks = 19 (+1/block unchanged)"
        );
        assert!(w16.slow_start, "still slow start without rate evidence");
        let w24 = RequestBook::new(DEFAULT_REQUEST_TIMEOUT).with_initial_window(24);
        assert_eq!(w24.window(), 24, "arm B initial value 24");
        let w6 = RequestBook::new(DEFAULT_REQUEST_TIMEOUT).with_initial_window(6);
        assert_eq!(
            w6.window(),
            6,
            "fallback-arm initial value 6 (aria2 BtConstants.h direct translation)"
        );

        // Row 3: after a BDP refresh, floor/max clamps are independent of
        // the initial value. The collapsed shape (1638B/s -> target 0 ->
        // floor 24, hysteresis upward growth identical) matches the
        // initial-6 table; the fast peer (16MiB/s -> target 3000) caps at
        // 256 just like BDP decision-table row 5 (initial 6).
        let mut collapsed = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_window_mode(WindowMode::Bdp)
            .with_window_floor(24)
            .with_initial_window(16);
        let _ = collapsed.dispatch(ID, 0, 16384, now);
        let _ = collapsed.on_piece(ID, 0, 16384, now);
        collapsed.rate.add(16384, now);
        assert!(
            collapsed
                .rate
                .settle(now + Duration::from_secs(10), RATE_EWMA_INVERTED_GAIN)
        );
        collapsed.refresh_window(now + Duration::from_secs(10));
        assert_eq!(
            collapsed.window(),
            24,
            "the initial-16 collapse is judged to floor 24 just the same (no difference from initial 6)"
        );

        let mut capped = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_window_mode(WindowMode::Bdp)
            .with_rate_ewma_long(false)
            .with_window_hysteresis(false)
            .with_window_floor(2)
            .with_initial_window(24);
        capped.rate.add(1000 * 16384, now);
        assert!(
            capped
                .rate
                .settle(now + RATE_WINDOW, RATE_EWMA_INVERTED_GAIN)
        );
        capped.refresh_window(now + RATE_WINDOW);
        assert_eq!(
            capped.window(),
            256,
            "initial 24 caps the fast peer at 256 just the same (no difference from initial 6)"
        );

        // Row 4: the initial value never exceeds the configured cap (the
        // same `min` as with_max_out_request_queue, order-insensitive
        // within the chain); the builder clamps out-of-range values to
        // [2, 256] (same bounds as the knob accessor — the
        // req_window_init parse surface is locked by its own decision
        // table).
        let pre_cap = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_initial_window(16)
            .with_max_out_request_queue(8);
        assert_eq!(
            pre_cap.window(),
            8,
            "initial value first, cap second: the min clamps to 8"
        );
        let post_cap = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_max_out_request_queue(8)
            .with_initial_window(16);
        assert_eq!(
            post_cap.window(),
            8,
            "cap first, initial value second: the min clamps to 8 (order-insensitive)"
        );
        assert_eq!(
            RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
                .with_initial_window(1024)
                .window(),
            256,
            "the builder clamps the upper out-of-range to 256"
        );
        assert_eq!(
            RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
                .with_initial_window(1)
                .window(),
            2,
            "the builder clamps the lower out-of-range to 2"
        );
    }

    #[test]
    fn bdp_supply_rhythm_budget() {
        // The initial value is pinned to 6 = the aria2 anchor fallback arm
        // (the default is 16), so the "window 6, 3 in flight" numbers
        // stay locked.
        let mut book = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_window_mode(WindowMode::Bdp)
            .with_initial_window(6)
            .with_window_floor(2);
        let now = t0();
        for i in 0..3u32 {
            let _ = book.dispatch(ID, i * 16384, 16384, now);
        }
        assert_eq!(book.budget(), 3, "window 6 with 3 in flight");
        for i in 0..3u32 {
            assert!(book.on_piece(ID, i * 16384, 16384, now).is_ok());
        }
        assert_eq!(book.window(), 9, "slow-start growth");
        assert_eq!(
            book.budget(),
            9,
            "after in-flight zeroes, budget = the whole window"
        );
        // Slow-peer shape: 16384B/10s = 1638B/s -> the window shrinks to 2
        // (the first sample seeds 1638 -> target 0 -> floor). With the
        // default face (hysteresis on), 2 < 0.7x9 triggers the shrink the
        // same way — both behaviors agree (the first settlement window
        // seeds directly).
        book.rate.add(16384, now);
        assert!(
            book.rate
                .settle(now + Duration::from_secs(10), RATE_EWMA_INVERTED_GAIN)
        );
        book.refresh_window(now + Duration::from_secs(10));
        assert!(!book.slow_start);
        assert_eq!(book.window(), 2, "1638B/s -> floored at 2");
        // Supply after the shrink: 2 slots fill the window -> budget 0 ->
        // the 3rd slot is rejected (WindowFull carries 2).
        assert!(
            book.dispatch(ID, 100 * 16384, 16384, now + Duration::from_secs(10))
                .is_ok()
        );
        assert!(
            book.dispatch(ID, 101 * 16384, 16384, now + Duration::from_secs(10))
                .is_ok()
        );
        assert_eq!(
            book.budget(),
            0,
            "in-flight = window: the budget saturates at 0"
        );
        assert!(matches!(
            book.dispatch(ID, 200 * 16384, 16384, now + Duration::from_secs(10)),
            Err(DispatchError::WindowFull {
                window: 2,
                outstanding: 2
            })
        ));
    }

    /// BDP window decoupled from RTT samples (the BDP counterpart of the
    /// doubling regression): with RTT samples present (slow-peer shape)
    /// the window is still driven only by rate/slow start;
    /// `end_receive_round` is always false (doubling retired). The initial
    /// value is pinned to 6 = the aria2 anchor (the default is 16), so the
    /// 6->9 slow-start numbers stay locked.
    #[test]
    fn bdp_window_unaffected_by_rtt_samples() {
        let mut book = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_window_mode(WindowMode::Bdp)
            .with_initial_window(6);
        let now = t0();
        // First build slow-peer RTT samples (adaptive 3s).
        for s in [100i64, 100, 900, 900, 900] {
            book.rtt.add_sample(s);
        }
        assert_eq!(book.adaptive_timeout(), Duration::from_secs(3));
        // 3 blocks delivered matched at the same instant -> slow start
        // 6->9 (identical to the no-RTT-sample state).
        for i in 0..3u32 {
            let _ = book.dispatch(ID, i * 100, 100, now);
            assert!(
                book.on_piece(ID, i * 100, 100, now + Duration::from_millis(300))
                    .is_ok()
            );
        }
        assert_eq!(
            book.window(),
            9,
            "the BDP window is independent of RTT samples"
        );
        assert!(
            !book.end_receive_round(),
            "doubling is retired in BDP mode (always false)"
        );
        assert_eq!(
            book.window(),
            9,
            "a round settlement does not change the window"
        );
    }

    /// Fallback-mode isolation (`BH_REQUEST_WINDOW_BDP=0` semantics):
    /// under LegacyDoubling, on_piece does not grow the window (slow-start
    /// +1 disabled, rate not sampled) while round-end doubling still works
    /// (2*4 >= 6 -> 12) — the old path bit-faithful. The initial value is
    /// pinned to 6 = the aria2 anchor fallback arm (the default is 16).
    #[test]
    fn legacy_fallback_mode_isolated_from_bdp() {
        let mut book = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_window_mode(WindowMode::LegacyDoubling)
            .with_initial_window(6);
        let now = t0();
        for i in 0..6u32 {
            let _ = book.dispatch(ID, i * 100, 100, now);
        }
        // 2 blocks matched and delivered (same timing as the slow-peer RTT
        // shape): the window must stay 6 (no slow-start +1); the rate
        // window stays idle (settle not driven — on_piece returns early).
        book.begin_receive_round();
        for i in 0..2u32 {
            assert!(
                book.on_piece(ID, i * 100, 100, now + Duration::from_millis(300))
                    .is_ok()
            );
        }
        assert_eq!(book.window(), 6, "fallback mode has no slow-start growth");
        assert_eq!(book.rate.value, 0, "fallback mode does not sample the rate");
        assert!(book.end_receive_round(), "doubling as before (2*4 >= 6)");
        assert_eq!(book.window(), 12);
        // Even operations spanning 1s+ do not settle the rate window
        // (refresh_window returns immediately).
        let _ = book.dispatch(ID, 1000, 1, now + 5 * RATE_WINDOW);
        assert_eq!(book.rate.value, 0, "fallback mode settles at zero rate");
    }

    /// Target-window mirror: attaching publishes the initial value (6);
    /// slow-start +1, rate-window settlement, and fallback doubling all
    /// follow; default construction (no mirror) has zero side effects on
    /// all paths. The initial value is pinned to 6 = the aria2 anchor
    /// (the default is 16).
    #[test]
    fn target_window_mirror_publishes_on_change() {
        let mirror = Arc::new(AtomicU64::new(0));
        let mut book = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_window_mode(WindowMode::Bdp)
            .with_initial_window(6)
            .with_window_floor(2)
            .with_target_window_mirror(Arc::clone(&mirror));
        assert_eq!(
            mirror.load(Ordering::Relaxed),
            6,
            "published at attach (the initial value)"
        );
        let now = t0();
        for i in 0..2u32 {
            let _ = book.dispatch(ID, i * 16384, 16384, now);
            assert!(book.on_piece(ID, i * 16384, 16384, now).is_ok());
        }
        assert_eq!(
            mirror.load(Ordering::Relaxed),
            8,
            "slow-start +1/block follows"
        );
        assert_eq!(mirror.load(Ordering::Relaxed), book.window() as u64);
        // Rate-window settlement -> the mirror follows the recompute.
        // acc = 2 blocks (sampled by on_piece) + 5 added directly =
        // 7x16KiB / 1s = 114688B/s -> 3x114688/16384 = 21 (the first
        // settlement window seeds directly; with the default face 21 >
        // 1.3x8 grows the same way).
        book.rate.add(5 * 16384, now);
        assert!(book.rate.settle(now + RATE_WINDOW, RATE_EWMA_INVERTED_GAIN));
        book.refresh_window(now + RATE_WINDOW);
        assert!(!book.slow_start);
        assert_eq!(book.window(), 21, "3s x 114688B/s / 16KiB = 21");
        assert_eq!(
            mirror.load(Ordering::Relaxed),
            21,
            "follows the BDP recompute"
        );

        // Fallback mode: the mirror follows the doubling.
        let legacy_mirror = Arc::new(AtomicU64::new(0));
        let mut legacy = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_window_mode(WindowMode::LegacyDoubling)
            .with_initial_window(6)
            .with_target_window_mirror(Arc::clone(&legacy_mirror));
        assert_eq!(legacy_mirror.load(Ordering::Relaxed), 6);
        for i in 0..6u32 {
            let _ = legacy.dispatch(ID, i * 100, 100, now);
        }
        legacy.begin_receive_round();
        for i in 0..2u32 {
            let _ = legacy.on_piece(ID, i * 100, 100, now);
        }
        assert!(legacy.end_receive_round());
        assert_eq!(
            legacy_mirror.load(Ordering::Relaxed),
            12,
            "follows the doubling"
        );

        // Default construction (no mirror): sampling/delivery/settlement
        // all side-effect free.
        let mut plain = RequestBook::new(DEFAULT_REQUEST_TIMEOUT)
            .with_window_mode(WindowMode::Bdp)
            .with_window_floor(2);
        let _ = plain.dispatch(ID, 0, 16384, now);
        assert!(plain.on_piece(ID, 0, 16384, now).is_ok());
        assert!(
            plain
                .rate
                .settle(now + RATE_WINDOW, RATE_EWMA_INVERTED_GAIN)
        );
        plain.refresh_window(now + RATE_WINDOW);
        assert_eq!(
            plain.window(),
            3,
            "default construction, same semantics (16KiB/1s -> 3 blocks)"
        );
    }
}
