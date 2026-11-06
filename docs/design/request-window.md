# Request window design

Surface summary of the window and timeout machinery in
`crates/taiji-bt/src/request_book.rs` (the `RequestBook`, `RateEwma`,
`RttSamples`, `FloodGuard`, and `HaveAdvertiser` types), the upstream rules
it borrows, and the deliberate divergences.

| Surface | Default | Fallback knob |
|---|---|---|
| Window mode | BDP rate-driven | `BH_REQUEST_WINDOW_BDP=0` -> legacy doubling |
| Initial window (slow-start start) | 16 | `BH_REQ_WINDOW_INIT` (`=6` restores the aria2 anchor) |
| Window cap | 256 | `PeerConfig::max_out_request_queue` (the `bt-max-out-request-queue` analog) |
| BDP target floor | 64 blocks (1 MiB/peer) | `BH_REQ_WINDOW_FLOOR=24` earlier, `=2` libtorrent |
| Rate EWMA gain | 1/5, then 1/10 after slow start | `BH_RATE_EWMA_LONG=0` pins 1/5 |
| Window hysteresis | on: hold inside [0.7w, 1.3w] | `BH_BDP_WINDOW_HYSTERESIS=0` assigns directly |
| Request-timeout cap | 60 s | constructor arg of `RequestBook::new`; aria2 range 1..=600 |
| Adaptive-timeout floor | 2 s | `MIN_ADAPTIVE_REQUEST_TIMEOUT` constant |
| Rate window | 1 s, lazily settled | `RATE_WINDOW` constant |
| Flood: keepalive threshold | 2 per 5 s window | `FLOODING_THRESHOLD` constant |
| Flood: choke-flip threshold | 20 per 5 s window | `FLOODING_CHOKE_FLIP_THRESHOLD` constant |
| Choke request grace | 2 s | `CHOKE_REQUEST_GRACE` constant |
| HAVE advertisement expiry | 5 s | `HAVE_EXPIRY` constant |
| Command channel capacity | 64 (was 8) | `peer/conn.rs` `COMMAND_CHANNEL_CAPACITY` |

## aria2 rules

- Window initial value 6 / cap 256: `BtConstants.h`
  (`DEFAULT_MAX_OUTSTANDING_REQUEST = 6`, `UB_MAX_OUTSTANDING_REQUEST = 256`).
- Doubling after a receive round (`DefaultBtInteractive.cc`): non-endgame,
  the round's outstanding count decreased, and `completed * 4 >= window`
  implies `window = min(256, window*2)`. Endgame detection belongs to
  TorrentTask; this layer treats rounds as non-endgame.
- Send budget (`DefaultBtInteractive.cc`): `window - outstanding` (0 once
  outstanding >= window).
- Slot timeout (`RequestSlot.cc`): `dispatchedTime + t <= now` cancels the
  block and sets `peer_->snubbing(true)` (`DefaultBtMessageDispatcher.cc`).
  The timeout option `--bt-request-timeout` defaults to 60 s, range
  1..=600 (`OptionHandlerFactory.cc`).
- Choke clears pending slots, allowed-fast kept (`BtChokeMessage.cc` +
  `DefaultBtMessageDispatcher.cc`).
- Flooding (`DefaultBtInteractive.cc`): a check every
  `FLOODING_CHECK_INTERVAL` (5 s, a fixed interval, not a sliding window);
  2+ keepalives in one window disconnect. aria2's own keepalive interval
  is 120 s (`--bt-keep-alive-interval`, `OptionHandlerFactory.cc`), so 2
  per 5 s can only be abuse.

## libtorrent adaptive timeout (mean + 4 sigma)

libtorrent (`peer_connection.cpp` unless noted):

- `request_timeout()`: 0 samples -> `settings_pack::request_timeout`
  (default 60 s, `settings_pack.cpp`); 1 sample -> `avg + avg/5`; 2+
  samples -> `avg + 4 x avg_deviation`. Round up to whole seconds, then
  the `min(settings)` cap, then the `max(2s)` floor. libtorrent:
  "timeouts should never be less than 2 seconds. The granularity is whole
  seconds, and only checked once per second. 2 is the minimum to avoid
  being considered timed out instantly." Locally
  `settings_pack::request_timeout` corresponds to the configured
  request-timeout cap (the `RequestBook::new` argument); its semantics
  narrow from "fixed timeout" to "cap", default unchanged.
- Sample surface: request-response latency, sampled when `incoming_piece`
  matches a slot (milliseconds). Estimator: `sliding_average<int, 20>`
  (`peer_connection.hpp`, implemented in `aux_/sliding_average.hpp`):
  fixed point x64, gain 20 — a sliding window of at most 20 samples;
  `avg_deviation` lags the mean by one sample. Local type: `RttSamples`.
- Divergence: libtorrent's timed-out-block late-delivery arm samples
  inter-block intervals (`m_requested` resets after each completed block);
  the port samples only the slot-matched arm (now minus the slot's
  dispatched time). Grace-window late deliveries are not sampled (the
  slot timestamp is consumed at retirement).

## libtorrent BDP window (3 s x rate, clamped 2..cap)

libtorrent (`peer_connection.cpp` + `request_blocks.cpp`):

- Target depth (`update_desired_queue_size`):
  `desired_queue_size = request_queue_time (3 s) x download_payload_rate /
  block_size (16 KiB)` — "16 kB is the size of each request" — capped by
  `max_out_request_queue` first, then floored by `min_request_queue = 2`.
  `max_out_request_queue` defaults to 500 (`settings_pack.cpp`); the
  local cap defaults to 256 (the aria2 `BtConstants.h` UB value),
  configurable via `PeerConfig::max_out_request_queue`.
- Deficit consumption (`request_blocks.cpp`):
  `num_requests = desired_queue_size - |download_queue| - |request_queue|`.
  The local counterpart is `RequestBook::budget` plus the engine-side
  `dispatch::supply_cap` (`min(target - in flight, command-channel
  headroom)`).
- Rate statistics (`stat.cpp`, `stat_channel::second_tick`): one tick per
  second, `sample = counter x 1000 / tick_interval_ms`,
  `m_5_sec_average = m_5_sec_average x 4/5 + sample / 5` (EWMA gain 1/5).
  Local type: `RateEwma`, settled lazily — any `now`-injecting entry point
  (dispatch / on_piece slot-matched arm / expire_timed_out) settles once
  the window is 1 s old (the lazy shape of the reference's per-second
  tick; idle seconds settle through the tick entry point).
- Divergence, first sample seeds directly: the reference EWMA ramps up
  from 0 (its first window reads sample/5), and its slow start happens to
  cover the ramp. Locally slow start covers only the no-sample period, so
  the first rate window must be immediately usable: the first sample
  seeds `value = sample`; later windows use the reference formula with
  alpha = 1/5.
- Slow start: initial `m_desired_queue_size = 4` (`peer_connection.hpp`);
  `+= 1` per completed block mid-round (`peer_connection.cpp`);
  `update_desired_queue_size` only clamps. Reference exits: rate plateau
  (next-second download up 5 KB over the previous second), loss of
  interest, snub. Local: the initial value is the configurable initial
  window (default 16; `=6` restores the aria2 anchor), +1 per received
  block on the slot-matched arm, exit on the first rate-window settlement
  or a snub; the "rate plateau" exit is merged into the "first sample
  immediately usable" rule.
- Divergence: a snubbed peer gets `desired_queue_size = 1` in libtorrent;
  not adopted (the local formula clamps at 2, and the snubbed state is
  handled by choke decisions).
- Whole-piece preference (`whole_pieces_threshold` 20 s): the local
  dispatch round picks one piece per peer per round, already a whole-piece
  supply rhythm; no separate switch.
- Doubling retirement: in BDP mode the round-end doubling branch is off
  (the aria2 anchor is kept as reference); `BH_REQUEST_WINDOW_BDP=0`
  restores the old path.
- Real-network floor: a peer's supply rate responds causally to our
  request depth (peers schedule by rotating through the request queue), so
  a low rate sample can collapse the BDP target to 2-4 blocks, reduce how
  often the peer schedules us, and lower the rate further — a self-locking
  loop. In controlled high-throughput settings the window stays pinned at
  the cap and a floor never binds. The BDP mode therefore floors at 64
  blocks (1 MiB in flight per peer; about 19 MiB total across 50 peers
  worst case; the block pool is bounded). For scale, librqbit runs a
  constant `DEFAULT_PEER_REQUEST_WINDOW = 128` (`live/mod.rs`) with no
  warmup.

## Jitter adaptation (BDP windows under variable RTT)

With loss handled separately, the residual gap is attributed to +/-50 ms
jitter. Two parameter-surface changes, default on, each with an
independent fallback knob:

1. Longer rate EWMA window (`BH_RATE_EWMA_LONG=0` restores the reference
   bit-for-bit): after slow-start exit the gain goes alpha 1/5 -> 1/10
   (ten 1 s rate windows, ~10 s of smoothing). The reference `stat.cpp`
   (alpha 1/5) remains in force during slow start and as the fallback
   tier. The 10 s window is a stand-in alignment with aria2's rate
   smoothing window `SPEED_WINDOW = 10_s` (`SpeedCalc.cc`), whose readings
   stay flat under jitter. Intentional divergence: libtorrent has no
   longer rate window (`stat` only keeps `m_5_sec_average`), so alpha
   1/10 is stand-in alignment, not a port. The cost — slower response to
   real rate changes — is protected by the hysteresis floor below, and the
   long window does not apply during slow start (structurally: the first
   settlement window exits slow start and seeds directly, so the long
   window takes effect from the second rate sample).
2. BDP window hysteresis (`BH_BDP_WINDOW_HYSTERESIS=0` restores direct
   assignment bit-for-bit): after slow-start exit, a recomputed target
   inside the `[0.7w, 1.3w]` band holds the window steady — no shrink on
   transient rate dips (shrink only below 0.7x the current window, grow
   only above 1.3x). Local policy constants with no libtorrent
   counterpart: `update_desired_queue_size` recomputes and assigns
   directly every time.

The timeout surface is intentionally untouched: the mean+4 sigma adaptive
timeout is already ported, and a wider timeout means fewer reissues
without lowering throughput by itself.

## Divergences at a glance

- Initial window default 16 vs aria2's 6; `BH_REQ_WINDOW_INIT=6` restores
  the anchor bit-for-bit.
- BDP mode is the default; aria2 doubling is the fallback
  (`BH_REQUEST_WINDOW_BDP=0`).
- Window cap 256 (aria2 UB value) vs libtorrent's `max_out_request_queue`
  default of 500.
- BDP floor 64 (earlier 24) vs libtorrent `min_request_queue = 2`;
  `BH_REQ_WINDOW_FLOOR=24` and `=2` step back through the history.
- First rate sample seeds the EWMA directly; libtorrent ramps from 0.
- Slow start means the no-sample period only and exits on the first rate
  settlement or a snub; libtorrent also exits on a rate plateau or loss
  of interest, and drops the target to 1 on snub (not adopted).
- Rate EWMA alpha 1/10 after slow start; libtorrent only has alpha 1/5
  (`BH_RATE_EWMA_LONG=0` restores).
- Window hysteresis `[0.7w, 1.3w]` has no libtorrent counterpart
  (`BH_BDP_WINDOW_HYSTERESIS=0` restores direct assignment).
- Grace registry for timed-out and cancelled slots is bounded by
  `request_timeout`; libtorrent keeps timed-out blocks until connection
  close. The registry bound always uses the configured cap, not the
  adaptive value, so the bound stays stable under sample jitter.
- Choke grace clock starts when the Choke frame is actually sent;
  libtorrent's `m_last_choke` clock also covers the initially-choked
  phase, where the port only rejects and never disconnects (more lenient
  by one notch, for optimistic-pipelining interoperability).
- Choke-flip flood threshold 20 vs aria2's 2 (rationale: BEP 3 makes
  choking routine; libtorrent neither rate-limits nor disconnects on
  flips; legitimate rotation was observed up to ~5 flips per window, and
  20 still catches sustained 4+ flips per second). The keepalive
  dimension keeps aria2's 2, and disconnect logs carry the triggering
  dimension (aria2 disconnects without it).
