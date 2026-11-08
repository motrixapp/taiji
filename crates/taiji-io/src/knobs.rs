//! Central registry of the `BH_*` environment knobs (the only `BH_*` env
//! read face in the tree; production code must go through this module's
//! accessor functions — never scatter `std::env::var("BH_…")` reads).
//!
//! # Registry
//!
//! Parse/fallback forms mirror the read points exactly; each accessor's
//! doc below carries the full rule plus its read timing.
//!
//! | Knob | Default | Parse / fallback |
//! |---|---|---|
//! | `BH_PARALLEL_WRITES` | off | trim+lc "1"/"on"/"true" = on; else (incl. unset) off |
//! | `BH_WRITE_COALESCE` | on | trim "0"/"off"/"false" = off; else on (case-sensitive) |
//! | `BH_REQUEST_COALESCE` | on | exactly `"0"` = off; else on (no trim) |
//! | `BH_CHOKE_ARIA2` | libtorrent | exactly `"1"` = aria2-port choke; else libtorrent |
//! | `BH_UNCHOKE_SLOTS` | 8 | usize (no trim), fail->8, clamp [3,128]; =8 = libtorrent default |
//! | `BH_UNCHOKE_BUDGET_SLOTS` | off | exactly `"1"` = on (budget-derived slots); else off |
//! | `BH_UNCHOKE_PER_PEER_FLOOR_BPS` | 16384 | u64 (no trim), fail->16384, clamp [4096,65536] |
//! | `BH_REQ_WINDOW_FLOOR` | 64 | usize (no trim), fail->64; =24 -> prior default |
//! | `BH_REQ_WINDOW_INIT` | 16 | usize (no trim), fail->16, clamp [2,256]; =6 -> aria2 anchor |
//! | `BH_REISSUE_CEIL_SECS` | 5 | u64 (no trim), fail->5, clamp [2,300]; =5 = current ceiling |
//! | `BH_REQUEST_WINDOW_BDP` | BDP | exactly `"0"` = old doubling heuristic; else BDP |
//! | `BH_RATE_EWMA_LONG` | on | exactly `"0"` = off (α=1/5); else on (α=1/10) |
//! | `BH_BDP_WINDOW_HYSTERESIS` | on | exactly `"0"` = off (direct recompute); else on |
//! | `BH_FAST_RECONNECT` | on | exactly `"0"` = off; else on |
//! | `BH_BLOCK_BYPASS` | on | trim+lc "0"/"off"/"false" = off; else on |
//! | `BH_BLOCK_BATCH_ACK` | w/ master | trim+lc "0"/"off"/"false" = batch off only; AND bypass |
//! | `BH_LEAN_TELEMETRY` | off | trim+lc "1"/"on"/"true" = on; else off |
//! | `BH_ENDGAME_STRICT` | on | exactly `"0"` = off; else on (no trim) |
//! | `BH_TWO_PHASE_LEDGER` | on | exactly `"0"` = off; else on (no trim) |
//! | `BH_MULTI_PIECE_SUPPLY` | on | exactly `"0"` = off; else on (no trim) |
//! | `BH_MULTI_PIECE_SUPPLY_MAX` | 16 | u64 (no trim), fail/0->16; =8 -> earlier cap |
//! | `BH_MULTI_PIECE_BUDGET_FLOOR` | 4 | u64 (no trim), fail->4, clamp [0,8]; =0 -> old pace |
//! | `BH_ENDGAME_LASTMILE` | 4 | u64 (no trim), fail->4; 0 = gate off (strict) |
//! | `BH_VERIFY_WORKERS` | auto | usize after trim, fail/<1 = no override (core-count floor) |
//! | `BH_WEBSEED` | on | exactly `"0"` = off; else on |
//! | `BH_WEBSEED_MAX` | 8 | usize after trim, fail/0->default |
//! | `BH_BLOCK_ARENA` | on | trim, exactly `"0"` = off (chain -> direct alloc); else on |
//! | `BH_BLOCK_ARENA_BYTES` | cache value | u64 after trim, fail/<min->default; caller max()es |
//! | `BH_WR_CACHE_BYTES` | cache value | usize after trim, fail/<min->default; caller max()es |
//! | `BH_SESSION_UNVERIFIED_BYTES` | 384MiB | u64 (no trim), fail->384MiB, clamp [128MiB,4GiB] |
//! | `BH_SPILL_UNVERIFIED` | on | trim "0"/"off"/"false" = off; else on (case-sensitive) |
//! | `BH_SPILL_BYTES` | formula value | usize after trim, fail/0->default (formula) |
//! | `BH_SPILL_FIXED` | off | trim "1"/"on"/"true" = on (fixed, bypasses formula); else off |
//! | `BH_V2_HASH_PRECOMPUTE` | on | trim "0"/"off"/"false" = off; else on (case-sensitive) |
//! | `BH_HOLEPUNCH_MODE` | on | exactly `"0"` = off; else on |
//! | `BH_CONNECT_SPEED` | adaptive | u32 after trim, >=1 pins speed; fail/0 = no override |
//! | `BH_V6_PREF` | on | exactly `"0"` = off; else on |
//! | `BH_CONNECT_SPEED_HOLD` | on | exactly `"0"` = off; else on |
//! | `BH_CONN_FILL_POOL` | on | exactly `"0"` = off (candidate table back to 1024); else on |
//! | `BH_CONN_FILL_RETRY` | on | exactly `"0"` = off; else on |
//! | `BH_CONN_FILL_DHT` | on | exactly `"0"` = off; else on |
//! | `BH_DHT_RAMP_INTERVAL_SECS` | 30 | u64 (no trim), fail->30; 0 = previous cadence (was 60) |
//! | `BH_DHT_RAMP_MIN_PEERS` | target reading | usize after trim, fail/0->caller default |
//! | `BH_TRACKER_MIN_PEERS` | target reading | usize after trim, fail/0->caller default |
//! | `BH_DHT_FRONTIER_K` | 16 | usize after trim, fail/0->caller constant; =8 -> aria2 width |
//! | `BH_UTP_MUTE` | on | exactly `"0"` = off; else on |
//! | `BH_SLOW_PEER_CHURN` | on | exactly `"0"` = off; else on |
//! | `BH_SLOW_PEER_FRAC` | 100 | u64 (no trim), fail->100 (%) |
//! | `BH_SLOW_PEER_K_PCT` | 10 | u64 (no trim), fail->10 (%) |
//! | `BH_SLOW_PEER_MIN_AGE_SECS` | 45 | u64 (no trim), fail->45; 0 = no observation window |
//! | `BH_SLOW_CHURN_RARITY_EXEMPT` | off | exactly `"1"` = on (sole-holder exempt); else off |
//! | `BH_PEX_IMMEDIATE` | on | exactly `"0"` = off; else on |
//! | `BH_PEER_MAX` | 120 | usize after trim, fail/0->default |
//! | `BH_PEER_TARGET` | 100 | usize after trim, fail/0->default; caller min()es cap |
//! | `BH_UTP_DIAL_TIMEOUT_SECS` | 10 | u64 (no trim), fail->10; 0 = unlimited (caller maps) |
//! | `BH_DIAL_DEAD_TCP_ONLY` | off | exactly `"1"` = on (trim µTP arm); else off |
//! | `BH_DIAL_PREFER_UTP` | off | exactly `"1"` = on ([Tcp,Utp] -> [Utp,Tcp]); else off |
//! | `BH_QUIET_PIECE_LOG` | on | trim+lc "0"/"off"/"false" = off (old INFO); else on (debug!) |
//! | `BH_CHECKOUT_SOFT_ACCOUNTING` | on | trim+lc "0"/"off"/"false" = off (old count); else on |
//! | `BH_ENDGAME_FAST_BUSY_K` | 2 | u64 (no trim), fail->2, clamp [0,8]; =0 -> strict busy gate |
//! | `BH_ADJACENT_SKIP_N` | 2 | u64 (no trim), fail->2, clamp [0,8]; =0 -> old chain break |
//! | `BH_SERVE_PENDING_CAP` | 256 | u64 (no trim), fail->256, clamp [32,1024] |
//! | `BH_DIAL_BACKOFF` | on | exactly `"0"` = off (dial decay + dead-addr TTL legacy); else on |
//! | `BH_SEED_PASSIVE_DHT` | off | exactly `"1"` = on (completed-state passive DHT); else off |
//! | `BH_READ_BUF_SHRINK` | on | after trim exactly `"0"` = off (per-connection Framed read/write idle buffers keep the old never-shrink behavior); else on |
//! | `BH_THREAD_STACK_KB` | 1024 | `usize` after trim, fail/<256 -> 1024, clamp [256, 8192]; =2048 restores the tokio 2MiB default |
//! | `BH_ENDGAME_TAIL_PCT` | 5 | u64 (no trim), fail->5, clamp [0,100]; 0 = endgame-tail supply face off |
//! | `BH_ENDGAME_PIECE_DEADLINE_SECS` | 30 | u64 (no trim), fail->30, clamp [0,600]; 0 = per-piece deadline off |
//! | `BH_ENDGAME_TAIL_WINDOW` | 1 | u64 (no trim), fail->1, clamp [0,8]; 0 = tail window floor off; k>=1 = k x missing blocks |
//! | `BH_ENDGAME_UNCHOKE_HOLDER` | on | exactly `"0"` = off (tail holder choke priority); else on |
//!
//! # Read-timing classes (zero-behavior-change invariant)
//!
//! - **Process-level OnceLock**: the read point is a process-lazy cache
//!   filled once; the accessor keeps its [`std::sync::OnceLock`] as-is —
//!   bit-for-bit equivalent while env is process-constant.
//! - **Construction**: the read point evaluates at the construction /
//!   assembly site and the caller holds the value (struct field or
//!   local). Accessors do **not** cache — every construction re-reads
//!   env; switching to OnceLock would silently turn per-construction
//!   evaluation into first-construction evaluation. Behavior change,
//!   forbidden.
//! - **Per-round / per-event**: the read point reads env at every tick /
//!   dispatch round / event arm. Accessors do **not** cache.
//!
//! # CLI override seam (not env knobs)
//!
//! Two in-process override statics ([`set_peer_max_override`] /
//! [`set_peer_request_speed_limit_override`]) are injected once from CLI
//! main() at startup, before any engine spawns; read priority: CLI
//! override > env knob > caller default constant. Consumers: `peer_max`
//! (`--bt-max-peers` explicit value beats env and the built-in 120) and
//! `peer_request_speed_limit` (the engine admission health check;
//! `PEER_REQUEST_SPEED_LIMIT` 50K default equals the aria2 default — no
//! behavior change when unset). Decision tables drive the `_of_parts`
//! pure functions directly (process statics stay out of parallel tests).
//!
//! Numeric knobs whose defaults belong to consumers (taiji_store
//! write-cache sizing, taiji-core connection/webseed caps, the bt
//! request-window floor) receive the default as a parameter — this crate
//! must not depend on other workspace crates. Parsing and filtering stay
//! centralized here; callers only compose (`max` demand scaling, `min`
//! cap, enum mapping).
//!
//! Upstream anchor mapping: docs/design/io.md

/// `BH_PARALLEL_WRITES` (registry in the module docs): explicit
/// "1"/"on"/"true" after trim + lowercase = on; anything else (including
/// unset) = off.
///
/// Read timing: **construction** — the caller evaluates at the shared
/// write-handle construction point and holds the value locally.
pub fn parallel_writes_enabled() -> bool {
    match std::env::var("BH_PARALLEL_WRITES") {
        Ok(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "on" | "true"),
        Err(_) => false,
    }
}

/// `BH_WRITE_COALESCE` (registry in the module docs): explicit
/// "0"/"off"/"false" (trim, case-sensitive) = off; anything else
/// (including unset) = on.
///
/// Read timing: **construction** — evaluated at the pipeline / write-face
/// assembly point and held by the caller.
pub fn write_coalesce_enabled() -> bool {
    match std::env::var("BH_WRITE_COALESCE") {
        Ok(s) => !matches!(s.trim(), "0" | "off" | "false"),
        Err(_) => true,
    }
}

/// `BH_REQUEST_COALESCE` (registry in the module docs): exactly `"0"` =
/// off; anything else (including unset) = on.
///
/// Read timing: **construction** — evaluated once per connection at
/// `peer_loop` assembly.
pub fn request_coalesce_enabled() -> bool {
    std::env::var("BH_REQUEST_COALESCE").as_deref() != Ok("0")
}

/// `BH_CHOKE_ARIA2` (registry in the module docs): exactly `"1"` = the
/// aria2-port choke mode; anything else (including unset) = libtorrent
/// semantics.
///
/// Read timing: **construction** — evaluated at choke-object construction
/// / engine assembly.
pub fn choke_aria2_enabled() -> bool {
    std::env::var("BH_CHOKE_ARIA2").as_deref() == Ok("1")
}

/// `BH_UNCHOKE_SLOTS` (registry in the module docs): `usize` parse (no
/// trim); parse failure/unset -> default 8 (total leecher slots including
/// optimistic = the libtorrent `unchoke_slots_limit` default in
/// `settings_pack.cpp`; optimistic slots auto-scale as max(1, N/5), the
/// runtime form of `OPTIMISTIC_SLOTS_AUTO`); effective value clamped to
/// [3, 128] (lower bound 3 = the minimum split of 2 regular + 1
/// optimistic; upper bound guards the runaway surface). The aria2
/// fallback branch (`BH_CHOKE_ARIA2=1`) does not read this knob.
///
/// Read timing: **read every round** — evaluated in the choke decision
/// round (15s cadence, low read frequency); not cached.
pub fn unchoke_slots() -> usize {
    unchoke_slots_of_raw(std::env::var("BH_UNCHOKE_SLOTS").ok().as_deref())
}

/// Pure parse function for the above (decision-table tested).
fn unchoke_slots_of_raw(raw: Option<&str>) -> usize {
    raw.and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(8)
        .clamp(3, 128)
}

/// `BH_UNCHOKE_BUDGET_SLOTS` (registry in the module docs): exactly `"1"`
/// = on (budget-derived unchoke slots: total leecher slots
/// N = clamp(upload budget / per-peer floor, 4, 32); with upload not
/// rate-limited (=0, unlimited) fall back to static [`unchoke_slots`] —
/// never guess when the budget face is absent), anything else (including
/// unset) = off (opt-in, default off, zero behavior change).
///
/// The pure decision function is `taiji_bt::choke::budget_unchoke_slots`
/// (bt crate, decision-table tested); the consumer is the engine's
/// `choke::budget_derived_slots` (limiter -> choke decision face; the
/// engine computes N and passes it in).
///
/// Read timing: **read every round** — evaluated in the choke decision
/// round (15s cadence), same shape as [`unchoke_slots`]; not cached.
pub fn unchoke_budget_slots_enabled() -> bool {
    unchoke_budget_slots_of_raw(std::env::var("BH_UNCHOKE_BUDGET_SLOTS").ok().as_deref())
}

/// Pure parse function for the above (decision-table tested; the
/// exact-"1" convention matches `BH_DIAL_DEAD_TCP_ONLY`).
fn unchoke_budget_slots_of_raw(raw: Option<&str>) -> bool {
    raw == Some("1")
}

/// `BH_UNCHOKE_PER_PEER_FLOOR_BPS` (registry in the module docs): `u64`
/// parse (no trim); parse failure/unset -> default 16384 (= 16KiB/s —
/// the minimum "meaningful rate" for a single unchoked peer: below it a
/// peer gets no non-trivial throughput, so the slot wastes reciprocity);
/// effective value clamped to [4096, 65536] (4KiB/s = dial-up-era lower
/// anchor; 64KiB/s = the absurd upper bound where one peer saturates a
/// whole ADSL upstream). Consumed only while `BH_UNCHOKE_BUDGET_SLOTS`
/// is on (as the divisor input).
///
/// Read timing: **read every round** — evaluated in the choke decision
/// round (same point and shape as [`unchoke_budget_slots_enabled`]); not
/// cached.
pub fn unchoke_per_peer_floor_bps() -> u64 {
    unchoke_per_peer_floor_bps_of_raw(
        std::env::var("BH_UNCHOKE_PER_PEER_FLOOR_BPS")
            .ok()
            .as_deref(),
    )
}

/// Pure parse function for the above (decision-table tested).
fn unchoke_per_peer_floor_bps_of_raw(raw: Option<&str>) -> u64 {
    raw.and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(16384)
        .clamp(4096, 65536)
}

/// `BH_REQ_WINDOW_FLOOR` (registry in the module docs): `usize` parse
/// (no trim); parse failure/unset -> default 64 (default raised from the
/// earlier 24; `=24` restores the earlier behavior, `=2` restores the
/// libtorrent reference `min_request_queue` bit-for-bit); the caller
/// clamps the effective value to at least the floor passed via
/// `min_floor`.
///
/// Read timing: **construction** — evaluated at `RequestBook`
/// construction and held locally.
pub fn req_window_floor(min_floor: usize) -> usize {
    let v = std::env::var("BH_REQ_WINDOW_FLOOR")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(64);
    v.max(min_floor)
}

/// `BH_REQ_WINDOW_INIT` (registry in the module docs): `usize` parse
/// (no trim); parse failure/unset -> default 16 (the initial request
/// window doubles as the slow-start starting point; default raised from
/// 6 = the aria2 `BtConstants.h` value, so `=6` restores the aria2 value
/// bit-for-bit); effective value clamped to [2, 256].
///
/// Read timing: **construction** — evaluated at `RequestBook`
/// construction and held locally (same shape as [`req_window_floor`]);
/// not cached.
pub fn req_window_init() -> usize {
    req_window_init_of_raw(std::env::var("BH_REQ_WINDOW_INIT").ok().as_deref())
}

/// Pure parse function for the above (decision-table tested).
fn req_window_init_of_raw(raw: Option<&str>) -> usize {
    raw.and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(16)
        .clamp(2, 256)
}

/// `BH_REISSUE_CEIL_SECS` (registry in the module docs): `u64` seconds
/// parse (no trim); parse failure/unset -> default 5 (restores the
/// taiji-engine `dispatch.rs` `REISSUE_WINDOW_CEIL` 5s ceiling
/// bit-for-bit); effective value clamped to [2, 300] (lower bound 2 =
/// the engine's reissue-window floor — a ceiling below the floor makes
/// the knob a dead value; upper bound 300 = defense against runaway
/// recovery latency on stalled storage).
///
/// A short reissue window and deep queues are mutually exclusive: once a
/// tail block's age exceeds the window another peer takes the block over
/// via reissue and cancels the original holder, voiding the queue. rqbit
/// has no per-block reissue — in-flight is reclaimed only when a peer
/// dies (librqbit live/mod.rs `mark_chunk_requests_canceled`) — so deep
/// queues stay undisturbed there. This knob makes the ceiling
/// configurable.
///
/// Read timing: **process-level OnceLock** — consumed block by block in
/// the dispatch round (same discipline as `BH_MULTI_PIECE_BUDGET_FLOOR`
/// — quasi-static configuration; no env reads on the hot path).
pub fn reissue_ceil_secs() -> u64 {
    static CEIL: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *CEIL.get_or_init(|| {
        reissue_ceil_secs_of_raw(std::env::var("BH_REISSUE_CEIL_SECS").ok().as_deref())
    })
}

/// Pure parse function for the above (decision-table tested).
fn reissue_ceil_secs_of_raw(raw: Option<&str>) -> u64 {
    raw.and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(5)
        .clamp(2, 300)
}

/// `BH_REQUEST_WINDOW_BDP` (registry in the module docs): exactly `"0"` =
/// restore the old doubling heuristic; anything else (including unset) =
/// BDP-driven.
///
/// Read timing: **construction** — evaluated on every `RequestBook`
/// construction.
pub fn request_window_bdp_enabled() -> bool {
    std::env::var("BH_REQUEST_WINDOW_BDP").as_deref() != Ok("0")
}

/// `BH_RATE_EWMA_LONG` (registry in the module docs): exactly `"0"` =
/// off (restore α=1/5); anything else (including unset) = on (α=1/10).
///
/// Read timing: **construction** — evaluated on every `RequestBook`
/// construction.
pub fn rate_ewma_long_enabled() -> bool {
    std::env::var("BH_RATE_EWMA_LONG").as_deref() != Ok("0")
}

/// `BH_BDP_WINDOW_HYSTERESIS` (registry in the module docs): exactly
/// `"0"` = off (restore direct reassignment); anything else (including
/// unset) = on.
///
/// Read timing: **construction** — evaluated on every `RequestBook`
/// construction.
pub fn bdp_window_hysteresis_enabled() -> bool {
    std::env::var("BH_BDP_WINDOW_HYSTERESIS").as_deref() != Ok("0")
}

/// `BH_FAST_RECONNECT` (registry in the module docs): exactly `"0"` = off
/// (restore the current backoff ladder); anything else (including unset)
/// = on.
///
/// Read timing: **construction** — evaluated once at `RedialPool`
/// construction and held locally.
pub fn fast_reconnect_enabled() -> bool {
    std::env::var("BH_FAST_RECONNECT").as_deref() != Ok("0")
}

/// `BH_BLOCK_BYPASS` (registry in the module docs): "0"/"off"/"false"
/// after trim + lowercase = off (the old attach-forwarding path);
/// anything else (including unset) = on (the direct path).
///
/// Read timing: **process-level OnceLock** (kept as-is) — evaluated at
/// the assembly-time factory; no env reads on the block hot path.
pub fn block_bypass_enabled() -> bool {
    static BYPASS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *BYPASS.get_or_init(|| {
        !matches!(
            std::env::var("BH_BLOCK_BYPASS")
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
                .as_str(),
            "0" | "off" | "false"
        )
    })
}

/// `BH_BLOCK_BATCH_ACK` (registry in the module docs): "0"/"off"/"false"
/// after trim + lowercase = turn batching off only (direct path kept);
/// defaults to following [`block_bypass_enabled`].
///
/// Read timing: **process-level OnceLock** (kept as-is) — same
/// discipline as the master switch.
pub fn block_batch_ack_enabled() -> bool {
    static BATCH: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *BATCH.get_or_init(|| {
        !matches!(
            std::env::var("BH_BLOCK_BATCH_ACK")
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
                .as_str(),
            "0" | "off" | "false"
        ) && block_bypass_enabled()
    })
}

/// `BH_LEAN_TELEMETRY` (registry in the module docs): "1"/"on"/"true"
/// after trim + lowercase = on (1s tick telemetry snapshot); anything
/// else (including unset) = off (zero logging, zero behavior change).
///
/// Read timing: **process-level OnceLock** (kept as-is) — no env reads
/// on the hot path.
pub fn lean_telemetry_enabled() -> bool {
    static TELEMETRY: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *TELEMETRY.get_or_init(|| {
        matches!(
            std::env::var("BH_LEAN_TELEMETRY")
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
                .as_str(),
            "1" | "on" | "true"
        )
    })
}

/// `BH_ENDGAME_STRICT` (registry in the module docs): exactly `"0"` = off
/// (endgame cursor restoration at ×2); anything else (including unset) =
/// on.
///
/// Read timing: **process-level OnceLock** (kept as-is) — a process-lazy
/// cache read once per round.
pub fn endgame_strict_enabled() -> bool {
    static MODE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *MODE.get_or_init(|| {
        std::env::var("BH_ENDGAME_STRICT")
            .map(|v| v != "0")
            .unwrap_or(true)
    })
}

/// `BH_TWO_PHASE_LEDGER` (registry in the module docs): exactly `"0"` =
/// off (the whole face reverts to single-state bookkeeping); anything
/// else (including unset) = on.
///
/// Read timing: **process-level OnceLock** (kept as-is).
pub fn two_phase_ledger_enabled() -> bool {
    static MODE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *MODE.get_or_init(|| {
        std::env::var("BH_TWO_PHASE_LEDGER")
            .map(|v| v != "0")
            .unwrap_or(true)
    })
}

/// `BH_MULTI_PIECE_SUPPLY` (registry in the module docs): exactly `"0"` =
/// off (the whole face reverts to single-piece cadence); anything else
/// (including unset) = on.
///
/// Read timing: **process-level OnceLock** (kept as-is).
pub fn multi_piece_supply_enabled() -> bool {
    static MODE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *MODE.get_or_init(|| {
        std::env::var("BH_MULTI_PIECE_SUPPLY")
            .map(|v| v != "0")
            .unwrap_or(true)
    })
}

/// `BH_MULTI_PIECE_SUPPLY_MAX` (registry in the module docs): `u64`
/// parse (no trim); parse failure/0 -> default 16 (lower-bound defense —
/// 0 would bypass the adjacent-piece arm entirely; `=8` restores the
/// earlier cap bit-for-bit).
///
/// 8 pieces ≈ 2MiB of in-flight bytes per peer; the cap sits inside the
/// 16-piece domain bounded by the 256-block BDP window ceiling (4MiB /
/// 256KiB pieces = 16 pieces). With soft checkout accounting on, this
/// cap is the only depth bound left for fast peers (the window dimension
/// is still clamped block-by-block by supply_cap): cap 8 × 16 blocks =
/// 128 blocks ceiling sat below the request window, while 16 × 16 = 256
/// ≥ window removes that sawtooth ceiling. No upper clamp (the consumer
/// budget/spill formulas track the value via [`multi_piece_checkout_cap`]
/// as a single source).
///
/// Read timing: **process-level OnceLock** (kept as-is).
pub fn multi_piece_supply_max() -> u64 {
    static CAP: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *CAP.get_or_init(|| {
        multi_piece_supply_max_of_raw(std::env::var("BH_MULTI_PIECE_SUPPLY_MAX").ok().as_deref())
    })
}

/// Pure parse function for the above (decision-table tested; the env
/// read shell stays out of the table).
fn multi_piece_supply_max_of_raw(raw: Option<&str>) -> u64 {
    raw.and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v >= 1)
        .unwrap_or(16)
}

/// `BH_MULTI_PIECE_BUDGET_FLOOR` (registry in the module docs): `u64`
/// parse (no trim); parse failure/unset -> default 4 (default raised
/// from the earlier 0 = off); effective value clamped to [0, 8] (the
/// upper bound is the historical bound tied to the supply cap — after
/// [`multi_piece_supply_max`] rose to 16, 8 stays ≤ cap, preserving the
/// budget-under-cap semantics; `=0` explicitly disables the cross-piece
/// budget, restoring the earlier single-piece cadence bit-for-bit).
///
/// Read timing: **process-level OnceLock** — consumed per peer in the
/// dispatch round (same discipline as `BH_MULTI_PIECE_SUPPLY_MAX` —
/// quasi-static configuration; no env reads on the hot path).
pub fn multi_piece_budget_floor() -> u64 {
    static FLOOR: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *FLOOR.get_or_init(|| {
        multi_piece_budget_floor_of_raw(
            std::env::var("BH_MULTI_PIECE_BUDGET_FLOOR").ok().as_deref(),
        )
    })
}

/// Pure parse function for the above (decision-table tested).
fn multi_piece_budget_floor_of_raw(raw: Option<&str>) -> u64 {
    raw.and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(4)
        .clamp(0, 8)
}

/// `BH_ENDGAME_LASTMILE` (registry in the module docs): `u64` parse (no
/// trim); parse failure -> default 4; 0 = last-mile gate off (strict
/// semantics bit-for-bit).
///
/// Read timing: **read every round** — evaluated each endgame dispatch
/// round (a numeric parameter, not OnceLock); not cached.
pub fn endgame_lastmile_pieces() -> u64 {
    std::env::var("BH_ENDGAME_LASTMILE")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(4)
}

/// `BH_VERIFY_WORKERS` (registry in the module docs): `usize` parse
/// after trim; parse failure/<1 = `None` (no override; fall back to the
/// core-count floor).
///
/// Read timing: **construction** — evaluated at verify-pool configuration
/// construction.
pub fn verify_workers_override() -> Option<usize> {
    match std::env::var("BH_VERIFY_WORKERS") {
        Ok(s) => s.trim().parse::<usize>().ok().filter(|&n| n >= 1),
        Err(_) => None,
    }
}

/// `BH_WEBSEED` (registry in the module docs): exactly `"0"` = off (the
/// assembly face spawns no fake peers); anything else (including unset)
/// = on.
///
/// Read timing: **construction** — evaluated at the webseed assembly
/// decision point.
pub fn webseed_enabled() -> bool {
    std::env::var("BH_WEBSEED").as_deref() != Ok("0")
}

/// `BH_WEBSEED_MAX` (registry in the module docs): `usize` parse after
/// trim; parse failure/0 -> default (the caller-supplied assembly cap
/// constant).
///
/// Read timing: **construction** — evaluated at the webseed assembly
/// point.
pub fn webseed_max(default_max: usize) -> usize {
    std::env::var("BH_WEBSEED_MAX")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&v| v >= 1)
        .unwrap_or(default_max)
}

/// `BH_BLOCK_ARENA` (registry in the module docs): after trim, exactly
/// `"0"` = off (the whole chain reverts to direct allocation); anything
/// else (including unset) = on.
///
/// Read timing: **construction** — evaluated at storage pipeline
/// assembly.
pub fn block_arena_enabled() -> bool {
    match std::env::var("BH_BLOCK_ARENA") {
        Ok(v) => v.trim() != "0",
        Err(_) => true,
    }
}

/// `BH_BLOCK_ARENA_BYTES` (registry in the module docs): `u64` parse
/// after trim; parse failure/< lower bound -> default (lower bound and
/// default passed in by the caller per the write-cache constants); the
/// `max` scaling against demand stays with the caller.
///
/// Read timing: **construction** — evaluated at storage pipeline
/// assembly.
pub fn block_arena_bytes(min_bytes: u64, default_bytes: u64) -> u64 {
    match std::env::var("BH_BLOCK_ARENA_BYTES") {
        Ok(s) => s
            .trim()
            .parse::<u64>()
            .ok()
            .filter(|&n| n >= min_bytes)
            .unwrap_or(default_bytes),
        Err(_) => default_bytes,
    }
}

/// `BH_SESSION_UNVERIFIED_BYTES` (registry in the module docs): `u64`
/// byte parse (no trim); parse failure/unset -> default 384MiB (default
/// 5 concurrent single-face tasks at 300MiB + headroom — the default
/// load always stays inside the cap with zero behavior change);
/// effective value clamped to [128MiB, 4GiB]. Consumer = the taiji-store
/// `WrDiskCache` admission face (`taiji_io::unverified_budget`, lazily
/// read once at construction).
pub fn session_unverified_bytes() -> usize {
    match std::env::var("BH_SESSION_UNVERIFIED_BYTES") {
        Ok(s) => s
            .trim()
            .parse::<u64>()
            .ok()
            .map(|n| n as usize)
            .unwrap_or(super::unverified_budget::DEFAULT_SESSION_UNVERIFIED_BYTES)
            .clamp(
                super::unverified_budget::MIN_SESSION_UNVERIFIED_BYTES,
                super::unverified_budget::MAX_SESSION_UNVERIFIED_BYTES,
            ),
        Err(_) => super::unverified_budget::DEFAULT_SESSION_UNVERIFIED_BYTES,
    }
}
/// `BH_WR_CACHE_BYTES` (registry in the module docs): `usize` parse
/// after trim; parse failure/< lower bound -> default (lower bound and
/// default passed in by the caller per the write-cache constants); the
/// `max` scaling against demand stays with the caller.
///
/// Read timing: **construction** — evaluated at the write-cache sizing
/// point.
pub fn wr_cache_bytes(min_bytes: usize, default_bytes: usize) -> usize {
    match std::env::var("BH_WR_CACHE_BYTES") {
        Ok(s) => s
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|&n| n >= min_bytes)
            .unwrap_or(default_bytes),
        Err(_) => default_bytes,
    }
}

/// `BH_SPILL_UNVERIFIED` (registry in the module docs): after trim,
/// "0"/"off"/"false" = off; anything else (including unset) = on
/// (case-sensitive).
///
/// Read timing: **construction** — evaluated at the spill-area mount
/// decision point.
pub fn spill_unverified_enabled() -> bool {
    match std::env::var("BH_SPILL_UNVERIFIED") {
        Ok(s) => !matches!(s.trim(), "0" | "off" | "false"),
        Err(_) => true,
    }
}

/// `BH_SPILL_BYTES` (registry in the module docs): `usize` parse after
/// trim; parse failure/0 -> default (the formula value passed in by the
/// caller).
///
/// Read timing: **construction** — evaluated at the spill budget point.
pub fn spill_bytes(default_limit: usize) -> usize {
    match std::env::var("BH_SPILL_BYTES") {
        Ok(s) => s
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|&n| n > 0)
            .unwrap_or(default_limit),
        Err(_) => default_limit,
    }
}

/// `BH_SPILL_FIXED` (registry in the module docs): after trim,
/// "1"/"on"/"true" = on (fixed budget, bypassing the formula entirely);
/// anything else (including unset) = off.
///
/// Read timing: **construction** — evaluated at the spill budget floor
/// formula point.
pub fn spill_fixed_enabled() -> bool {
    match std::env::var("BH_SPILL_FIXED") {
        Ok(s) => matches!(s.trim(), "1" | "on" | "true"),
        Err(_) => false,
    }
}

/// `BH_V2_HASH_PRECOMPUTE` (registry in the module docs): after trim,
/// "0"/"off"/"false" = off; anything else (including unset) = on
/// (case-sensitive); the "v2 pieces present" precondition gate stays
/// with the caller.
///
/// Read timing: **construction** — evaluated at the lookup-table mount
/// decision point.
pub fn v2_hash_precompute_enabled() -> bool {
    match std::env::var("BH_V2_HASH_PRECOMPUTE") {
        Ok(s) => !matches!(s.trim(), "0" | "off" | "false"),
        Err(_) => true,
    }
}

/// `BH_HOLEPUNCH_MODE` (registry in the module docs): exactly `"0"` = off
/// (holepunch dialing reverts to the current behavior); anything else
/// (including unset) = on.
///
/// Read timing: **event-level** — evaluated during DialJob assembly (no
/// env reads inside dial tasks).
pub fn holepunch_mode_enabled() -> bool {
    std::env::var("BH_HOLEPUNCH_MODE").as_deref() != Ok("0")
}

/// `BH_CONNECT_SPEED` (registry in the module docs): `u32` parse after
/// trim; ≥1 pins the speed (adaptive disabled); parse failure/0 =
/// `None` (no override; 0 treated as unset).
///
/// Read timing: **construction** — evaluated once at dial budget
/// assembly.
pub fn connect_speed_override() -> Option<u32> {
    match std::env::var("BH_CONNECT_SPEED") {
        Ok(raw) => raw.trim().parse::<u32>().ok().filter(|v| *v >= 1),
        Err(_) => None,
    }
}

/// `BH_V6_PREF` (registry in the module docs): exactly `"0"` = off (the
/// v6 sort key is always false); anything else (including unset) = on.
///
/// Read timing: **read every round** — evaluated each 250ms drain round
/// (tick-level env read, not hot path); not cached.
pub fn v6_pref_enabled() -> bool {
    std::env::var("BH_V6_PREF").as_deref() != Ok("0")
}

/// `BH_CONNECT_SPEED_HOLD` (registry in the module docs): exactly `"0"` =
/// off (insufficient samples revert to the base gear and gear changes do
/// not re-anchor); anything else (including unset) = on.
///
/// Read timing: **read every round** — evaluated each 250ms drain round;
/// not cached.
pub fn connect_speed_hold_enabled() -> bool {
    std::env::var("BH_CONNECT_SPEED_HOLD").as_deref() != Ok("0")
}

/// `BH_DIAL_BACKOFF` (registry in the module docs): exactly `"0"` = off
/// (the dial-decay ladder and the failed-address dedup window extension
/// both revert to their legacy shapes — adaptive base/hostile gearing
/// only, flat 10min dedup window); anything else (including
/// unset) = on.
///
/// Read timing: **read every round** (the decay decision at the 250ms
/// drain round) and **event-level** (the failed-window mark at each
/// dial-outcome report); not cached.
pub fn dial_backoff_enabled() -> bool {
    std::env::var("BH_DIAL_BACKOFF").as_deref() != Ok("0")
}

/// `BH_SEED_PASSIVE_DHT` (registry in the module docs): exactly `"1"` = on
/// (once every face is complete, the engine stops re-issuing DHT
/// announce/get_peers rounds — the node keeps answering inbound queries
/// and maintaining its table, but no longer actively crawls for new
/// download peers); anything else (including unset) = off (the current
/// always-active behavior). Opt-in by design: a behavior change, default
/// off, left for the NS line to adjudicate.
///
/// Service-face degradation disclosure (wording carried over from the
/// original task card — the "(=1)" state is the non-default opt-in above,
/// the default stays off):
///
/// > When on (=1), the DHT seed visibility of a completed torrent drops
/// > to zero within 30min (the bt engine's PeerAnnounceCheck clears the
/// > registry every 30min) -> remote downloaders can no longer find this
/// > seed via DHT -> upload supply falls; the tracker face is unaffected;
/// > new download tasks immediately resume active announce
///
/// Read timing: **read every round** — evaluated each 2s slow tick; not
/// cached.
pub fn seed_passive_dht_enabled() -> bool {
    std::env::var("BH_SEED_PASSIVE_DHT").as_deref() == Ok("1")
}

/// `BH_CONN_FILL_POOL` (registry in the module docs): exactly `"0"` = off
/// (candidate table capacity reverts to the current 1024); anything else
/// (including unset) = on.
///
/// Read timing: **construction** — evaluated once at candidate pool
/// assembly.
pub fn conn_fill_pool_enabled() -> bool {
    std::env::var("BH_CONN_FILL_POOL").as_deref() != Ok("0")
}

/// `BH_READ_BUF_SHRINK` (registry in the module docs): after trim, exactly
/// `"0"` = off (each connection's FramedRead/FramedWrite internal buffers
/// keep the never-shrink behavior — capacity high-water stays resident for
/// the connection's life); anything else (including unset) = on (a
/// connection idle past the peer-layer threshold swaps its buffers down to
/// zero capacity; the codec's one-shot exact reservation regrows them on
/// the next inbound frame — a buffer-shrink knob item).
///
/// Read timing: **construction** — evaluated at each peer-loop assembly
/// (per connection, same shape as `BH_REQUEST_COALESCE`).
pub fn read_buf_shrink_enabled() -> bool {
    match std::env::var("BH_READ_BUF_SHRINK") {
        Ok(v) => v.trim() != "0",
        Err(_) => true,
    }
}

/// `BH_THREAD_STACK_KB` (registry in the module docs): `usize` KiB parse
/// after trim; parse failure/unset -> 1024 (tokio default 2048 halved: the
/// runtime's worker + blocking threads on the 2-core target need nowhere
/// near 2MiB of stack — async task frames are heap-allocated, the OS stack
/// only carries the reactor loop and `spawn_blocking` closures); effective
/// value clamped to [256, 8192] (=2048 restores the tokio default
/// bit-for-bit; 256 guards against starvation-prone tiny stacks). Consumer
/// = the taiji CLI runtime builder (`thread_stack_size`; stack mapping
/// preallocation only — scheduling semantics untouched).
///
/// Read timing: **construction** — read once at process start before the
/// runtime is built.
pub fn thread_stack_kb() -> usize {
    thread_stack_kb_of_raw(std::env::var("BH_THREAD_STACK_KB").ok().as_deref())
}

/// Pure parse function for the above (decision-table tested).
fn thread_stack_kb_of_raw(raw: Option<&str>) -> usize {
    raw.and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(1024)
        .clamp(256, 8192)
}

/// `BH_CONN_FILL_RETRY` (registry in the module docs): exactly `"0"` =
/// off (failed endpoints do not return to the candidate table); anything
/// else (including unset) = on.
///
/// Read timing: **event-level** — evaluated per dial-outcome report
/// event; not cached.
pub fn conn_fill_retry_enabled() -> bool {
    std::env::var("BH_CONN_FILL_RETRY").as_deref() != Ok("0")
}

/// `BH_CONN_FILL_DHT` (registry in the module docs): exactly `"0"` = off
/// (the announce re-send cadence reverts to the current fast-gear
/// criterion); anything else (including unset) = on.
///
/// Read timing: **read every round** — evaluated on each 2s slow tick;
/// not cached.
pub fn conn_fill_dht_enabled() -> bool {
    std::env::var("BH_CONN_FILL_DHT").as_deref() != Ok("0")
}

/// `BH_DHT_RAMP_INTERVAL_SECS` (registry in the module docs): `u64`
/// parse (no trim); parse failure -> default 30; 0 = restore the
/// previous cadence (the fallback mapping stays with the caller).
/// Default lowered 60 -> 30 (DHT supply ramp cadence doubled; combined
/// with the wider candidate frontier `BH_DHT_FRONTIER_K` this gives
/// roughly 4× node contacts per minute).
///
/// Read timing: **read every round** — evaluated per tick; not cached.
pub fn dht_ramp_interval_secs() -> u64 {
    dht_ramp_interval_secs_of_raw(std::env::var("BH_DHT_RAMP_INTERVAL_SECS").ok().as_deref())
}

/// Pure parse function for the above (decision-table tested;
/// `BH_UTP_DIAL_TIMEOUT_SECS` follows the same discipline).
fn dht_ramp_interval_secs_of_raw(raw: Option<&str>) -> u64 {
    raw.and_then(|v| v.parse::<u64>().ok()).unwrap_or(30)
}

/// `BH_DHT_RAMP_MIN_PEERS` (registry in the module docs): `usize` parse
/// after trim; parse failure/0 -> default (the caller-supplied threshold
/// — the core side passes the outbound target
/// [`peer_connections_target`] projection); `=50` explicitly restores
/// the libtorrent port's old threshold (torrent.cpp `num_peers < 50`).
///
/// Read timing: **read every round** — evaluated on each 2s slow tick
/// (same point and discipline as `BH_CONN_FILL_DHT`); not cached.
pub fn dht_ramp_min_peers(default: usize) -> usize {
    dht_ramp_min_peers_of_raw(
        std::env::var("BH_DHT_RAMP_MIN_PEERS").ok().as_deref(),
        default,
    )
}

/// Pure parse function for the above (decision-table tested; the env
/// read shell stays out of the table).
fn dht_ramp_min_peers_of_raw(raw: Option<&str>, default: usize) -> usize {
    raw.and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&v| v >= 1)
        .unwrap_or(default)
}

/// `BH_TRACKER_MIN_PEERS` (registry in the module docs): `usize` parse
/// after trim; parse failure/0 -> default (the caller-supplied threshold
/// — the core side passes the outbound target
/// [`peer_connections_target`] projection); `=40` explicitly restores
/// the aria2 port's old threshold (`BtRuntime.h` DEFAULT_MIN_PEERS = 40).
///
/// Read timing: **process-level OnceLock** (same shape as
/// `BH_PEER_MAX`/`BH_PEER_TARGET` — a gate threshold is quasi-static
/// configuration read at the low-frequency announce decision).
pub fn tracker_min_peers(default: usize) -> usize {
    static MIN: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *MIN.get_or_init(|| {
        tracker_min_peers_of_raw(
            std::env::var("BH_TRACKER_MIN_PEERS").ok().as_deref(),
            default,
        )
    })
}

/// Pure parse function for the above (decision-table tested).
fn tracker_min_peers_of_raw(raw: Option<&str>, default: usize) -> usize {
    raw.and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&v| v >= 1)
        .unwrap_or(default)
}

/// `BH_DHT_FRONTIER_K` (registry in the module docs): `usize` parse
/// after trim; parse failure/0 -> default (the caller-supplied frontier
/// width constant); `=8` explicitly restores the aria2
/// `DHTAbstractNodeLookupTask` port's old width (candidate table
/// truncation K).
///
/// Read timing: **construction** — evaluated per lookup-task construction
/// (lookups are low frequency: announce / bucket-refresh driven, not hot
/// path); not cached (same shape as the `BH_CHOKE_ARIA2` construction-
/// time precedent in choke.rs).
pub fn dht_frontier_k(default_k: usize) -> usize {
    dht_frontier_k_of_raw(
        std::env::var("BH_DHT_FRONTIER_K").ok().as_deref(),
        default_k,
    )
}

/// Pure parse function for the above (decision-table tested).
fn dht_frontier_k_of_raw(raw: Option<&str>, default_k: usize) -> usize {
    raw.and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&v| v >= 1)
        .unwrap_or(default_k)
}

/// `BH_UTP_MUTE` (registry in the module docs): exactly `"0"` = off
/// (zero-throughput µTP connections are no longer disconnected);
/// anything else (including unset) = on.
///
/// Read timing: **read every round** — read once per tick; not cached.
pub fn utp_mute_enabled() -> bool {
    std::env::var("BH_UTP_MUTE").as_deref() != Ok("0")
}

/// `BH_SLOW_PEER_CHURN` (registry in the module docs): exactly `"0"` =
/// off (the whole face reverts to current behavior); anything else
/// (including unset) = on.
///
/// Read timing: **read every round** — tick-level env read; not cached.
pub fn slow_peer_churn_enabled() -> bool {
    std::env::var("BH_SLOW_PEER_CHURN").as_deref() != Ok("0")
}

/// `BH_SLOW_PEER_FRAC` (registry in the module docs): `u64` parse (no
/// trim); parse failure -> default 100 (churn line = pool median rate ×
/// frac%).
///
/// Read timing: **read every round** — evaluated at tick assembly (env
/// stays out of the pure function); not cached.
pub fn slow_peer_frac_pct() -> u64 {
    std::env::var("BH_SLOW_PEER_FRAC")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(100)
}

/// `BH_SLOW_PEER_K_PCT` (registry in the module docs): `u64` parse (no
/// trim); parse failure -> default 10 (per-round K = max(1, n×k%)).
///
/// Read timing: **read every round** — evaluated at tick assembly; not
/// cached.
pub fn slow_peer_k_pct() -> u64 {
    std::env::var("BH_SLOW_PEER_K_PCT")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(10)
}

/// `BH_SLOW_PEER_MIN_AGE_SECS` (registry in the module docs): `u64`
/// parse (no trim); parse failure -> default 45; 0 = explicitly disable
/// the observation window (the seconds -> duration conversion stays with
/// the caller).
///
/// Read timing: **read every round** — evaluated at tick assembly; not
/// cached.
pub fn slow_peer_min_age_secs() -> u64 {
    std::env::var("BH_SLOW_PEER_MIN_AGE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(45)
}

/// `BH_SLOW_CHURN_RARITY_EXEMPT` (registry in the module docs): exactly
/// `"1"` = on (before eviction, exempt the "sole connected holder of any
/// unfinished piece" — a patch for the rarity blindness of slow-peer
/// churn); anything else (including unset) = off (the eviction predicate
/// restored to current behavior bit-for-bit).
///
/// Read timing: **read every round** — evaluated at slow_churn tick
/// assembly (30s cadence, low read frequency); not cached.
pub fn slow_churn_rarity_exempt_enabled() -> bool {
    std::env::var("BH_SLOW_CHURN_RARITY_EXEMPT").as_deref() == Ok("1")
}

/// `BH_PEX_IMMEDIATE` (registry in the module docs): exactly `"0"` = off
/// (PEX candidates wait for the regular drain round); anything else
/// (including unset) = on.
///
/// Read timing: **event-level** — evaluated per PEX event (frame cadence
/// ≥60s per peer, not hot path); not cached.
pub fn pex_immediate_enabled() -> bool {
    std::env::var("BH_PEX_IMMEDIATE").as_deref() != Ok("0")
}

/// `BH_PEER_MAX` (registry in the module docs): `usize` parse after
/// trim; parse failure/0 -> default (the caller-supplied connection
/// hard-cap constant). The CLI override seam wins when set
/// ([`PEER_MAX_CLI_OVERRIDE`], injected at startup via `--bt-max-peers`
/// — the highest priority above the env knob; the in-process injection
/// form required because edition 2024 has no `set_var`).
///
/// Read timing: **process-level OnceLock** (kept as-is) — runtime
/// override seam.
pub fn peer_max(default_max: usize) -> usize {
    let o = PEER_MAX_CLI_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed);
    if o >= 1 {
        return o;
    }
    static MAX: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *MAX.get_or_init(|| {
        peer_max_of_parts(0, std::env::var("BH_PEER_MAX").ok().as_deref(), default_max)
    })
}

/// `BH_PEER_TARGET` (registry in the module docs): `usize` parse after
/// trim; parse failure/0 -> default (the caller-supplied outbound target
/// constant); the `min` cap against the hard limit stays with the
/// caller.
///
/// Read timing: **process-level OnceLock** (kept as-is) — runtime
/// override seam.
pub fn peer_target(default_target: usize) -> usize {
    static TARGET: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *TARGET.get_or_init(|| {
        std::env::var("BH_PEER_TARGET")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|&v| v >= 1)
            .unwrap_or(default_target)
    })
}

// ---- CLI override seam (startup-option injection face; the highest
// priority above the `BH_*` env knobs) ----
//
// Convention: the `BH_*` env knobs face load tests and rollbacks (env is
// process-immutable; edition 2024 forbids unsafe and offers no
// `set_var`). CLI flags (`--bt-max-peers` /
// `--bt-request-peer-speed-limit`, the aria2-compatible face) need
// in-process injection: override statics as atomics plus an `_of_parts`
// pure-function layer (decision-table tests drive the pure functions
// directly; process statics untouched — parallel-test hygiene, same as
// the env knobs). Priority: CLI override > env knob > caller default
// constant. Injection happens once in CLI main() at startup (before any
// engine spawn; constant for the rest of the process — startup-option
// semantics).

/// `--bt-max-peers` CLI override (0 = not overridden; valid values ≥ 1).
static PEER_MAX_CLI_OVERRIDE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Inject the `--bt-max-peers` CLI override (effective for v ≥ 1; 0 = no
/// override). Injected once in main() at startup, before any engine
/// spawn — the `peer_max` read point (engine connection hard cap)
/// consumes it from the first admission round on.
pub fn set_peer_max_override(v: usize) {
    PEER_MAX_CLI_OVERRIDE.store(v, std::sync::atomic::Ordering::Relaxed);
}

/// `peer_max` decision-table pure function (CLI override > env knob >
/// default; test-driven; touches no statics/env).
fn peer_max_of_parts(override_v: usize, env_raw: Option<&str>, default_max: usize) -> usize {
    if override_v >= 1 {
        return override_v;
    }
    env_raw
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&v| v >= 1)
        .unwrap_or(default_max)
}

/// `--bt-request-peer-speed-limit` CLI override (`UNSET` = not
/// overridden). The sentinel is `u64::MAX` rather than 0: the value
/// range includes 0 (aria2 NumberOptionHandler min 0; a threshold of 0
/// makes the rate check always "healthy" -> the rescue arm disabled —
/// a legal explicit value with semantics different from "not
/// overridden").
static PEER_REQ_SPEED_CLI_OVERRIDE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(u64::MAX);

/// Unset sentinel for `--bt-request-peer-speed-limit`.
pub const PEER_REQ_SPEED_UNSET: u64 = u64::MAX;

/// Inject the `--bt-request-peer-speed-limit` CLI override (bytes/sec,
/// including 0). Injected once in main() at startup, before any engine
/// spawn — consumer = the download-health check in engine connection
/// admission (taiji-engine run::state, 10s sliding-window rate reading).
pub fn set_peer_request_speed_limit_override(v: u64) {
    PEER_REQ_SPEED_CLI_OVERRIDE.store(v, std::sync::atomic::Ordering::Relaxed);
}

/// Effective supply-threshold decision-table pure function (CLI override >
/// caller default constant; test-driven).
fn peer_request_speed_limit_of_parts(override_v: u64, default: u64) -> u64 {
    if override_v != PEER_REQ_SPEED_UNSET {
        return override_v;
    }
    default
}

/// Effective supply threshold (bytes/sec; consumed by engine admission —
/// the `--bt-request-peer-speed-limit` wiring: not overridden = the
/// caller default constant (taiji-engine `PEER_REQUEST_SPEED_LIMIT` 50K,
/// same as the aria2 default — zero behavior change by default).
pub fn peer_request_speed_limit(default: u64) -> u64 {
    peer_request_speed_limit_of_parts(
        PEER_REQ_SPEED_CLI_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed),
        default,
    )
}

/// `BH_UTP_DIAL_TIMEOUT_SECS` (registry in the module docs): `u64` parse
/// (no trim); parse failure -> default 10; 0 = unlimited (the emergency
/// fallback seam bypassing the µTP dial budget entirely; the 0 -> `None`
/// mapping stays with the core-side caller).
///
/// Read timing: **event-level** — evaluated per µTP dial arm (dialing is
/// low frequency: announce / DHT driven, not hot path); not cached.
pub fn utp_dial_timeout_secs() -> u64 {
    utp_dial_timeout_secs_of_raw(std::env::var("BH_UTP_DIAL_TIMEOUT_SECS").ok().as_deref())
}

/// Pure parse function for the above (decision-table tested; env reads
/// stay out of the pure function — same discipline as
/// `BH_SLOW_PEER_FRAC`).
fn utp_dial_timeout_secs_of_raw(raw: Option<&str>) -> u64 {
    raw.and_then(|v| v.parse::<u64>().ok()).unwrap_or(10)
}

/// `BH_DIAL_DEAD_TCP_ONLY` (registry in the module docs): exactly `"1"` =
/// on (trim the µTP arm for addresses with ≥ 1 failure); anything else
/// (including unset) = off (the dial plan keeps the µTP arm). The
/// default stays off: paired same-window wall times on the real swarm
/// showed no improvement when on, so the trim remains opt-in
/// (`BH_DIAL_DEAD_TCP_ONLY=1`) and is layered separately from the
/// timeout fix (which triggers only on hangs; the healthy path is
/// unchanged).
///
/// Read timing: **event-level** — evaluated per dial in the dial-plan
/// loop (low frequency, not hot path); not cached.
pub fn dial_dead_tcp_only_enabled() -> bool {
    std::env::var("BH_DIAL_DEAD_TCP_ONLY").as_deref() == Ok("1")
}

/// `BH_DIAL_PREFER_UTP` (registry in the module docs): exactly `"1"` =
/// on (the outbound dial transport plan flips `[Tcp, Utp]` to
/// `[Utp, Tcp]` — the µTP fallback arm becomes primary; outbound
/// connections run under BEP-29 LEDBAT congestion control and yield to
/// user traffic — an ADSL uplink guard), anything else (including unset)
/// = off. Opt-in, default off, zero behavior change. **Inbound is
/// unaffected** (peers choose; the accept face takes both transports);
/// orthogonal to `BH_DIAL_DEAD_TCP_ONLY` (that trims the arm, this
/// reorders it). The plan-flip decision face is the engine
/// `transit::outbound_dial_plan` pure function (decision-table tested
/// for both arms).
///
/// Read timing: **event-level** — evaluated per dial in the dial-plan
/// loop (low frequency, not hot path), same shape as
/// [`dial_dead_tcp_only_enabled`]; not cached.
pub fn dial_prefer_utp_enabled() -> bool {
    std::env::var("BH_DIAL_PREFER_UTP").as_deref() == Ok("1")
}

/// `BH_QUIET_PIECE_LOG` (registry in the module docs): "0"/"off"/"false"
/// after trim + lowercase = off (per-piece `piece verified` lines back
/// to the old INFO behavior); anything else (including unset) = on (the
/// same field set demoted to `debug!` — under an INFO filter the tracing
/// macro arguments are not evaluated, so the per-piece ~150B write
/// amplification and formatting cost drop to zero).
///
/// Forensics dependency (the reason the `=0` fallback arm exists):
/// tooling that aggregates `piece verified` lines per second needs
/// `BH_QUIET_PIECE_LOG=0` explicitly. Other log lines (download
/// complete, pool curves, lean, endgame entered/exited, ...) are not
/// governed by this knob.
///
/// Read timing: **process-level OnceLock** — consumed per piece-verified
/// event (quasi-static configuration; no env reads on the event path;
/// same discipline as `BH_LEAN_TELEMETRY`).
pub fn quiet_piece_log() -> bool {
    static QUIET: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *QUIET
        .get_or_init(|| quiet_piece_log_of_raw(std::env::var("BH_QUIET_PIECE_LOG").ok().as_deref()))
}

/// Pure parse function for the above (decision-table tested; the env
/// read shell stays out of the table).
fn quiet_piece_log_of_raw(raw: Option<&str>) -> bool {
    !matches!(
        raw.unwrap_or_default().trim().to_ascii_lowercase().as_str(),
        "0" | "off" | "false"
    )
}

/// `BH_CHECKOUT_SOFT_ACCOUNTING` (registry in the module docs): after
/// trim + lowercase, explicit `"0"/"off"/"false"` = off (whole-piece
/// counting, old behavior bit-for-bit); anything else (including unset)
/// = on (soft accounting of checkout slots on the adjacent-piece arm).
/// Default on (previously opt-in off).
///
/// Mechanism: the dispatch `supply_adjacent_pieces` arm counts
/// `checked_out = 1 + continuable.len()` in whole pieces (cap =
/// [`multi_piece_supply_max`]), and a slot is released only once all
/// blocks of the piece have **arrived** (`own_piece_continuable` still
/// requires in-flight-family blocks) — under uniform seeder service the
/// checked-out pieces complete near-simultaneously, so in-flight drops
/// 128 -> 0 and refills in one batch (sawtooth). On = secondary-piece
/// occupancy is weighted `ceil(Σ pending blocks / blocks per piece)`
/// (pending = in-flight-family blocks; piece complete/arrived -> weight
/// 0, fully released) — slots refill block by block, append eligibility
/// comes earlier, and the cap dimension flows continuously.
///
/// rqbit anchor: no piece-level checkout; a constant 128-deep request
/// window refills per block (librqbit live/mod.rs). This switch moves
/// the cap dimension toward that semantic while keeping the whole-piece
/// checkout bookkeeping structure.
///
/// Fallback: `=0` (off/false equivalent) = whole-piece counting, old
/// behavior bit-for-bit. **Invariant**: soft accounting relaxes only the
/// "cap" dimension (pieces checked out per peer), never the "window"
/// dimension (total in-flight is still clamped by supply_cap = target
/// window − in flight); `own_piece_continuable` / continuation arm /
/// claimed / peer_piece checkout bookkeeping semantics unchanged.
///
/// Read timing: **process-level OnceLock** — consumed per peer in the
/// dispatch round (same discipline as `BH_MULTI_PIECE_SUPPLY_MAX` /
/// `BH_MULTI_PIECE_BUDGET_FLOOR` — quasi-static configuration; no env
/// reads on the hot path).
pub fn checkout_soft_accounting_enabled() -> bool {
    static SOFT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SOFT.get_or_init(|| {
        checkout_soft_accounting_of_raw(
            std::env::var("BH_CHECKOUT_SOFT_ACCOUNTING").ok().as_deref(),
        )
    })
}

/// Pure parse function for the above (decision-table tested; the env
/// read shell stays out of the table).
fn checkout_soft_accounting_of_raw(raw: Option<&str>) -> bool {
    !matches!(
        raw.unwrap_or_default().trim().to_ascii_lowercase().as_str(),
        "0" | "off" | "false"
    )
}

/// `BH_ENDGAME_FAST_BUSY_K` (registry in the module docs): `u64` parse
/// (no trim); parse failure/unset -> default 2 (default raised from the
/// earlier 0 = off; `=0` explicitly restores the strict busy gate
/// bit-for-bit); effective value clamped to [0, 8] (K ≥ 1 on — a
/// fast-tier peer may hold at most K busy pieces at once).
///
/// Mechanism: the strict busy gate (one busy piece per peer at a time —
/// the `request_blocks.cpp` port) clamps a fast peer's endgame
/// parallelism to one-piece-at-a-time serial. For K ≥ 1, peers
/// "significantly faster than the swarm body" (30s rate ≥ 2× the
/// peer-rate median ∧ ≥ 100KiB/s floor — the adaptive criterion avoids
/// absolute thresholds misfiring on heterogeneous swarms; the floor
/// avoids a false fast tier when the median ≈ 0 on an all-dead swarm)
/// may hold up to K busy pieces at once; the slow tier stays strict.
///
/// Invariants: the replica cap ×2 (`ENDGAME_MAX_COPIES`) and the
/// last-mile boundary (`BH_ENDGAME_LASTMILE`) are untouched — K only
/// affects the "busy pieces per peer" dimension of the strict segment
/// (the anti-pileup gate stays as-is). Fallback: `=0` explicitly = the
/// old two-tier gate bit-for-bit (the K=0 tier function is equivalent to
/// the old gate — pinned by the decision table; parse failure/unset fall
/// back to default 2, never 0).
///
/// Read timing: **process-level OnceLock** — consumed per peer in the
/// endgame branch of the dispatch round (same discipline as
/// `BH_MULTI_PIECE_BUDGET_FLOOR` — quasi-static configuration; no env
/// reads on the hot path).
pub fn endgame_fast_busy_k() -> u64 {
    static K: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *K.get_or_init(|| {
        endgame_fast_busy_k_of_raw(std::env::var("BH_ENDGAME_FAST_BUSY_K").ok().as_deref())
    })
}

/// Pure parse function for the above (decision-table tested; the env
/// read shell stays out of the table).
fn endgame_fast_busy_k_of_raw(raw: Option<&str>) -> u64 {
    raw.and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(2)
        .clamp(0, 8)
}

/// `BH_ADJACENT_SKIP_N` (registry in the module docs): `u64` parse (no
/// trim); parse failure/unset -> default 2 (default raised from the
/// earlier 0 = off; `=0` explicitly restores the old break-at-first-
/// soft-breakpoint behavior bit-for-bit); effective value clamped to
/// [0, 8] (N ≥ 1 on — skip up to N pieces at soft breakpoints to
/// continue the chain).
///
/// Mechanism: in claim-dense regions (round-robin claims interleaved
/// across peers) adjacent chains often break at the first piece, which
/// degrades the chain back to single-piece cadence and zeroes the
/// seeder sequential-read benefit of goff-contiguous spans. Soft
/// breakpoints (completed / claimed / unadvertised while goff stays
/// contiguous) may be skipped, up to N pieces, pushing the chain
/// frontier to the next dispatchable piece — span semantics preserved
/// (hard breakpoints = goff non-contiguous still break the chain).
///
/// Invariants: selection-side only — checkout bookkeeping
/// (`peer_extra_pieces` / `own_piece_continuable`), the window-dimension
/// `supply_cap` block clamp, and claim/spread exclusion semantics are
/// unchanged; skipped pieces are not dispatched, not claimed, and do not
/// count against checkout occupancy (skipping pieces claimed by others
/// is exactly the mechanism's intent); at most N total skips per round.
/// Fallback: `=0` explicitly = the old chain-break behavior bit-for-bit
/// (max_skip = 0 makes the skip function identical to the old one —
/// pinned by the decision table; parse failure/unset fall back to
/// default 2, never 0).
///
/// Read timing: **process-level OnceLock** — consumed per peer in the
/// adjacent-piece arm of the dispatch round (same discipline as
/// `BH_MULTI_PIECE_SUPPLY_MAX` — quasi-static configuration).
pub fn adjacent_skip_n() -> u64 {
    static N: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *N.get_or_init(|| adjacent_skip_n_of_raw(std::env::var("BH_ADJACENT_SKIP_N").ok().as_deref()))
}

/// Pure parse function for the above (decision-table tested; the env
/// read shell stays out of the table).
fn adjacent_skip_n_of_raw(raw: Option<&str>) -> u64 {
    raw.and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(2)
        .clamp(0, 8)
}

/// `BH_ENDGAME_TAIL_PCT` (registry in the module docs): `u64` parse (no
/// trim); parse failure/unset -> default 5; effective value clamped to
/// [0, 100]. 0 = the whole endgame-tail supply face off (every
/// tail-scoped policy — the per-piece deadline, the holder window floor,
/// the holder unchoke priority — reverts to non-tail behavior
/// bit-for-bit).
///
/// Mechanism: the tail band = missing pieces <= pct% of the
/// torrent's piece count (and > 0). Bench evidence (ext-server multi-round,
/// per the earlier perf review): the wall of the slow rounds is dominated by the
/// last-1-5-pieces supply wait (~70s zero-speed tail), not cold-start —
/// the band keys the endgame-specific supply policies to exactly that
/// regime. 5% of a 3003-piece torrent = 150 pieces; the deep tail
/// (1-5 pieces) is additionally covered by the narrower existing faces
/// (last-mile `BH_ENDGAME_LASTMILE` = 4, the last-8 observation window).
///
/// Read timing: **read every round** — evaluated each dispatch round /
/// choke round (a numeric parameter, not OnceLock; the
/// `BH_ENDGAME_LASTMILE` shape); not cached.
pub fn endgame_tail_pct() -> u64 {
    endgame_tail_pct_of_raw(std::env::var("BH_ENDGAME_TAIL_PCT").ok().as_deref())
}

/// Pure parse function for the above (decision-table tested; the env
/// read shell stays out of the table).
fn endgame_tail_pct_of_raw(raw: Option<&str>) -> u64 {
    raw.and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(5)
        .clamp(0, 100)
}

/// `BH_ENDGAME_PIECE_DEADLINE_SECS` (registry in the module docs):
/// `u64` parse (no trim); parse failure/unset -> default 30; effective
/// value clamped to [0, 600]. 0 = the per-piece deadline face off.
///
/// Mechanism: during the endgame tail each busy missing
/// piece carries a deadline (anchored at its first tail-round dispatch
/// observation; re-armed on each deadline-driven re-dispatch). A piece
/// whose deadline expires is "overdue": its whole network-phase
/// in-flight set becomes takeover candidates in the next dispatch round
/// (bypassing the per-block reissue-window freshness reading) — the
/// piece-level shared timestamp approximation
/// (`PieceSentLedger::dispatched_at`, refreshed by every dispatch write)
/// can otherwise mask per-block staleness indefinitely under a re-dispatch
/// trickle, stalling the piece far past the per-block 2-5s windows with
/// no re-issue. Local policy value (libtorrent/aria2 have no per-piece
/// deadline: libtorrent's reissue is per-block `request_timeout()`;
/// 30s = one order of magnitude above the reissue ceiling default 5s,
/// sized so the deadline only fires on structurally stuck pieces, not on
/// slow-but-alive ones).
///
/// Read timing: **read every round** — evaluated each dispatch round (a
/// numeric parameter, not OnceLock); not cached.
pub fn endgame_piece_deadline_secs() -> u64 {
    endgame_piece_deadline_secs_of_raw(
        std::env::var("BH_ENDGAME_PIECE_DEADLINE_SECS")
            .ok()
            .as_deref(),
    )
}

/// Pure parse function for the above (decision-table tested; the env
/// read shell stays out of the table).
fn endgame_piece_deadline_secs_of_raw(raw: Option<&str>) -> u64 {
    raw.and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30)
        .clamp(0, 600)
}

/// `BH_ENDGAME_TAIL_WINDOW` (registry in the module docs): `u64` parse
/// (no trim); parse failure/unset -> default 1; effective value clamped
/// to [0, 8]. 0 = the tail window-floor face off (holders keep the
/// generic BDP floor bit-for-bit); k >= 1 = the multiplier over the
/// tail's missing block count (the consumer clamps the product to the
/// 256-block UB; default k=1 = "a holder's outstanding-request window
/// should at least cover every remaining tail block once").
///
/// Mechanism: during the endgame tail, peers advertising a
/// missing piece get their RequestBook window floor raised to
/// `min(k x missing_blocks, 256)` — the generic BDP floor (64 blocks)
/// sits below the tail block volume of a 5%-band tail (e.g. 150 pieces x
/// 16 blocks = 2400), so a holder's outstanding-request pipeline is
/// clamped below what the tail can supply; the floor is relax-only (a
/// lower product never lowers the generic floor) and never exceeds the
/// configured window cap.
///
/// Read timing: **process-level OnceLock** — consumed per peer in the
/// dispatch round (same discipline as `BH_MULTI_PIECE_BUDGET_FLOOR` —
/// quasi-static configuration; no env reads on the hot path).
pub fn endgame_tail_window() -> u64 {
    static W: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *W.get_or_init(|| {
        endgame_tail_window_of_raw(std::env::var("BH_ENDGAME_TAIL_WINDOW").ok().as_deref())
    })
}

/// Pure parse function for the above (decision-table tested; the env
/// read shell stays out of the table).
fn endgame_tail_window_of_raw(raw: Option<&str>) -> u64 {
    raw.and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(1)
        .clamp(0, 8)
}

/// `BH_ENDGAME_UNCHOKE_HOLDER` (registry in the module docs): exactly
/// `"0"` = off (the choke sort keeps the existing keys bit-for-bit);
/// anything else (including unset) = on.
///
/// Mechanism: during the endgame tail, interested peers
/// that advertise at least one still-missing piece sort first in the
/// leecher regular-unchoke key (ahead of the keep-position partition):
/// in the deep tail the tit-for-tat rate key has collapsed to zero for
/// exactly the peers whose last pieces we need (a holder we never
/// downloaded from has no rate credit), so the regular slots can evict
/// every holder and the tail then waits on the peer-side optimistic
/// unchoke cadence (~30-60s — the observed ~70s tail shape). Outside
/// the tail every peer's flag is false and the sort is unchanged.
///
/// Read timing: **read every round** — evaluated once per choke round
/// (15s/10s by mode; a switch parameter, not OnceLock); not cached.
pub fn endgame_unchoke_holder_enabled() -> bool {
    endgame_unchoke_holder_of_raw(std::env::var("BH_ENDGAME_UNCHOKE_HOLDER").ok().as_deref())
}

/// Pure parse function for the above (decision-table tested; the env
/// read shell stays out of the table).
fn endgame_unchoke_holder_of_raw(raw: Option<&str>) -> bool {
    raw != Some("0")
}

/// `BH_SERVE_PENDING_CAP` (registry in the module docs): `u64` parse
/// (no trim); parse failure/unset -> default 256 (≈ the peer target
/// window ceiling — anchored by the aria2 `BtConstants.h`
/// `UB_MAX_OUTSTANDING_REQUEST` and the doubling adaptive ceiling alike:
/// under normal pipelining a peer has ≤ 256 outstanding requests; more
/// than that means a window violation or a stalled completion drain, and
/// further queueing only grows tail memory); effective value clamped to
/// [32, 1024] (the OOM guard must not be inflated back by the knob).
/// Consumer = the bt `read_pool::ServeQueue` (at cap: BEP-6 Reject
/// Request instead of enqueueing).
///
/// Read timing: **construction** — evaluated once per connection at
/// `ServeQueue` construction and held locally (same shape as
/// `BH_REQUEST_COALESCE` — peer_loop assembly level, not hot path); not
/// cached.
pub fn serve_pending_cap() -> u64 {
    serve_pending_cap_of_raw(std::env::var("BH_SERVE_PENDING_CAP").ok().as_deref())
}

/// Pure parse function for the above (decision-table tested).
fn serve_pending_cap_of_raw(raw: Option<&str>) -> u64 {
    raw.and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(256)
        .clamp(32, 1024)
}

/// Knob parse decision tables (table-driven; env is process-immutable —
/// edition 2024 forbids unsafe and tests have no `set_var` — so the
/// parse faces are driven via the `_of_raw` pure functions; the env read
/// shells stay out of the tables).
#[cfg(test)]
mod tests {
    use super::*;

    /// `BH_THREAD_STACK_KB` parse table: default/invalid -> 1024 (half the
    /// tokio 2MiB default); legal values pass through after clamp; "2048"
    /// = the tokio default fallback arm.
    #[test]
    fn thread_stack_kb_parse_table() {
        // Default (unset) = 1024.
        assert_eq!(thread_stack_kb_of_raw(None), 1024);
        // Invalid (non-numeric / empty / negative) = default.
        assert_eq!(thread_stack_kb_of_raw(Some("abc")), 1024);
        assert_eq!(thread_stack_kb_of_raw(Some("")), 1024);
        assert_eq!(thread_stack_kb_of_raw(Some("-1")), 1024);
        // Legal values pass through (trim tolerated).
        assert_eq!(thread_stack_kb_of_raw(Some("512")), 512);
        assert_eq!(thread_stack_kb_of_raw(Some(" 2048 ")), 2048);
        // Clamps: below floor -> 256, above ceiling -> 8192.
        assert_eq!(thread_stack_kb_of_raw(Some("0")), 256);
        assert_eq!(thread_stack_kb_of_raw(Some("64")), 256);
        assert_eq!(thread_stack_kb_of_raw(Some("99999")), 8192);
    }

    /// `BH_UTP_DIAL_TIMEOUT_SECS` parse table: default/invalid -> 10; legal
    /// values pass through; "0" passes through (the 0 -> `None` unlimited
    /// mapping lives on the core side `utp_dial_budget`; this table locks
    /// parsing only).
    #[test]
    fn utp_dial_timeout_secs_parse_table() {
        // Default (unset) = 10 (same magnitude as MSE_HANDSHAKE_TIMEOUT).
        assert_eq!(utp_dial_timeout_secs_of_raw(None), 10);
        // Invalid (non-numeric / negative sign / empty) = default.
        assert_eq!(utp_dial_timeout_secs_of_raw(Some("abc")), 10);
        assert_eq!(utp_dial_timeout_secs_of_raw(Some("-1")), 10);
        assert_eq!(utp_dial_timeout_secs_of_raw(Some("")), 10);
        // Legal value passes through.
        assert_eq!(utp_dial_timeout_secs_of_raw(Some("25")), 25);
        // 0 = unlimited fallback seam (value passes through; semantic
        // mapping stays with the caller).
        assert_eq!(utp_dial_timeout_secs_of_raw(Some("0")), 0);
    }

    /// `BH_DHT_RAMP_INTERVAL_SECS` parse table: default/invalid -> 30
    /// (lowered from 60); legal values pass through; "0" passes through
    /// (the 0 -> 1/3-cadence fallback mapping lives on the core side
    /// `dht_ramp_interval`; this table locks parsing only).
    #[test]
    fn dht_ramp_interval_secs_parse_table() {
        // Default (unset) = 30 (previous value 60).
        assert_eq!(dht_ramp_interval_secs_of_raw(None), 30);
        // Invalid (non-numeric / empty) = default.
        assert_eq!(dht_ramp_interval_secs_of_raw(Some("abc")), 30);
        assert_eq!(dht_ramp_interval_secs_of_raw(Some("")), 30);
        // Legal values pass through (including explicit 60 = old cadence).
        assert_eq!(dht_ramp_interval_secs_of_raw(Some("60")), 60);
        // 0 = fallback seam (value passes through; mapping stays with the
        // caller).
        assert_eq!(dht_ramp_interval_secs_of_raw(Some("0")), 0);
    }

    /// `BH_DHT_RAMP_MIN_PEERS` parse table: default/invalid/0 -> the caller
    /// default (= target reading); "50" passes through = the libtorrent
    /// port's old-threshold fallback arm.
    #[test]
    fn dht_ramp_min_peers_parse_table() {
        const DEFAULT: usize = 100;
        // Default (unset) = the outbound target reading (caller-supplied).
        assert_eq!(dht_ramp_min_peers_of_raw(None, DEFAULT), DEFAULT);
        // Invalid/0 = default (0 treated as unset; no "threshold 0"
        // semantic).
        assert_eq!(dht_ramp_min_peers_of_raw(Some("abc"), DEFAULT), DEFAULT);
        assert_eq!(dht_ramp_min_peers_of_raw(Some("0"), DEFAULT), DEFAULT);
        assert_eq!(dht_ramp_min_peers_of_raw(Some(""), DEFAULT), DEFAULT);
        // "50" passes through = fallback arm (torrent.cpp old threshold).
        assert_eq!(dht_ramp_min_peers_of_raw(Some("50"), DEFAULT), 50);
    }

    /// `BH_TRACKER_MIN_PEERS` parse table: default/invalid/0 -> the caller
    /// default (= target reading); "40" passes through = the aria2 port's
    /// old-threshold fallback arm.
    #[test]
    fn tracker_min_peers_parse_table() {
        const DEFAULT: usize = 100;
        assert_eq!(tracker_min_peers_of_raw(None, DEFAULT), DEFAULT);
        assert_eq!(tracker_min_peers_of_raw(Some("abc"), DEFAULT), DEFAULT);
        assert_eq!(tracker_min_peers_of_raw(Some("0"), DEFAULT), DEFAULT);
        // "40" passes through = fallback arm (BtRuntime.h DEFAULT_MIN_PEERS).
        assert_eq!(tracker_min_peers_of_raw(Some("40"), DEFAULT), 40);
    }

    /// `BH_DHT_FRONTIER_K` parse table: default/invalid/0 -> the caller
    /// default (= frontier constant 16); "8" passes through = the aria2
    /// port's old-width fallback arm.
    #[test]
    fn dht_frontier_k_parse_table() {
        const DEFAULT_K: usize = 16;
        assert_eq!(dht_frontier_k_of_raw(None, DEFAULT_K), DEFAULT_K);
        assert_eq!(dht_frontier_k_of_raw(Some("abc"), DEFAULT_K), DEFAULT_K);
        assert_eq!(dht_frontier_k_of_raw(Some("0"), DEFAULT_K), DEFAULT_K);
        // "8" passes through = fallback arm (candidate truncation K, old width).
        assert_eq!(dht_frontier_k_of_raw(Some("8"), DEFAULT_K), 8);
    }

    /// `BH_REQ_WINDOW_INIT` parse table (default raised 6 -> 16):
    /// default/invalid -> 16 (new default); legal values pass through
    /// (explicit `=6` = the aria2 `BtConstants.h` fallback arm); out of
    /// range clamped to [2, 256].
    #[test]
    fn req_window_init_parse_table() {
        // Default (unset) = 16 (previous value 6).
        assert_eq!(req_window_init_of_raw(None), 16);
        // Invalid (non-numeric / negative sign / empty) = default.
        assert_eq!(req_window_init_of_raw(Some("abc")), 16);
        assert_eq!(req_window_init_of_raw(Some("-1")), 16);
        assert_eq!(req_window_init_of_raw(Some("")), 16);
        // Legal values pass through (16 = new default; 24 = legacy arm;
        // explicit 6 = aria2 port fallback — the BtConstants.h old value).
        assert_eq!(req_window_init_of_raw(Some("16")), 16);
        assert_eq!(req_window_init_of_raw(Some("24")), 24);
        assert_eq!(req_window_init_of_raw(Some("6")), 6);
        // Clamped to [2, 256] (0/1 -> 2; >256 -> 256).
        assert_eq!(req_window_init_of_raw(Some("0")), 2);
        assert_eq!(req_window_init_of_raw(Some("1")), 2);
        assert_eq!(req_window_init_of_raw(Some("1024")), 256);
    }

    /// `BH_REISSUE_CEIL_SECS` parse table: default/invalid -> 5 (the
    /// current 5s reissue-window ceiling restored bit-for-bit); legal
    /// values pass through; out of range clamped to [2, 300].
    #[test]
    fn reissue_ceil_secs_parse_table() {
        // Default (unset) = 5 (the ported old value).
        assert_eq!(reissue_ceil_secs_of_raw(None), 5);
        // Invalid (non-numeric / negative sign / empty) = default.
        assert_eq!(reissue_ceil_secs_of_raw(Some("abc")), 5);
        assert_eq!(reissue_ceil_secs_of_raw(Some("-1")), 5);
        assert_eq!(reissue_ceil_secs_of_raw(Some("")), 5);
        // Legal values pass through (explicit 5 = fallback arm).
        assert_eq!(reissue_ceil_secs_of_raw(Some("5")), 5);
        assert_eq!(reissue_ceil_secs_of_raw(Some("15")), 15);
        assert_eq!(reissue_ceil_secs_of_raw(Some("30")), 30);
        // Clamped to [2, 300] (0/1 -> 2 = the engine reissue-window floor,
        // so the ceiling never sinks below the floor; >300 -> 300 =
        // runaway recovery-latency defense).
        assert_eq!(reissue_ceil_secs_of_raw(Some("0")), 2);
        assert_eq!(reissue_ceil_secs_of_raw(Some("1")), 2);
        assert_eq!(reissue_ceil_secs_of_raw(Some("1024")), 300);
    }

    /// `BH_UNCHOKE_SLOTS` parse table: default/invalid -> 8 (the libtorrent
    /// `settings_pack.cpp` fallback arm); legal values pass through; out
    /// of range clamped to [3, 128].
    #[test]
    fn unchoke_slots_parse_table() {
        // Default (unset) = 8 (the ported old value).
        assert_eq!(unchoke_slots_of_raw(None), 8);
        // Invalid (non-numeric / negative sign / empty) = default.
        assert_eq!(unchoke_slots_of_raw(Some("abc")), 8);
        assert_eq!(unchoke_slots_of_raw(Some("-1")), 8);
        assert_eq!(unchoke_slots_of_raw(Some("")), 8);
        // Legal values pass through (explicit 8 = fallback arm).
        assert_eq!(unchoke_slots_of_raw(Some("8")), 8);
        assert_eq!(unchoke_slots_of_raw(Some("16")), 16);
        assert_eq!(unchoke_slots_of_raw(Some("64")), 64);
        // Clamped to [3, 128] (0/1/2 -> 3 = the minimum split of 2 regular
        // + 1 optimistic; >128 -> 128).
        assert_eq!(unchoke_slots_of_raw(Some("0")), 3);
        assert_eq!(unchoke_slots_of_raw(Some("2")), 3);
        assert_eq!(unchoke_slots_of_raw(Some("1024")), 128);
    }

    /// `BH_UNCHOKE_BUDGET_SLOTS` parse table: exactly `"1"` = on
    /// (budget-derived slots); everything else — unset, `"0"`, `"on"`
    /// variants — = off (default off, zero behavior change; same
    /// convention as `BH_DIAL_DEAD_TCP_ONLY`).
    #[test]
    fn unchoke_budget_slots_parse_table() {
        // Default (unset) = off.
        assert!(!unchoke_budget_slots_of_raw(None));
        // The only on-value is exactly "1".
        assert!(unchoke_budget_slots_of_raw(Some("1")));
        // Everything else = off (explicit 0 = the off arm; "on"/"true"/
        // trim variants do not fold — the exact-match convention ignores
        // them).
        assert!(!unchoke_budget_slots_of_raw(Some("0")));
        assert!(!unchoke_budget_slots_of_raw(Some("on")));
        assert!(!unchoke_budget_slots_of_raw(Some("true")));
        assert!(!unchoke_budget_slots_of_raw(Some(" 1 ")));
        assert!(!unchoke_budget_slots_of_raw(Some("")));
        assert!(!unchoke_budget_slots_of_raw(Some("abc")));
    }

    /// `BH_UNCHOKE_PER_PEER_FLOOR_BPS` parse table: default/invalid ->
    /// 16384 (16KiB/s meaningful-rate floor); legal values pass through;
    /// out of range clamped to [4096, 65536].
    #[test]
    fn unchoke_per_peer_floor_bps_parse_table() {
        // Default (unset) = 16384 (16KiB/s).
        assert_eq!(unchoke_per_peer_floor_bps_of_raw(None), 16384);
        // Invalid (non-numeric / negative sign / empty) = default.
        assert_eq!(unchoke_per_peer_floor_bps_of_raw(Some("abc")), 16384);
        assert_eq!(unchoke_per_peer_floor_bps_of_raw(Some("-1")), 16384);
        assert_eq!(unchoke_per_peer_floor_bps_of_raw(Some("")), 16384);
        // Legal values pass through (explicit 16384 = the default arm).
        assert_eq!(unchoke_per_peer_floor_bps_of_raw(Some("16384")), 16384);
        assert_eq!(unchoke_per_peer_floor_bps_of_raw(Some("8192")), 8192);
        assert_eq!(unchoke_per_peer_floor_bps_of_raw(Some("32768")), 32768);
        assert_eq!(unchoke_per_peer_floor_bps_of_raw(Some("65536")), 65536);
        // Clamped to [4096, 65536] (0/1000 -> 4096 lower bound; >65536 ->
        // 65536 upper bound; 1024 lands on the lower side).
        assert_eq!(unchoke_per_peer_floor_bps_of_raw(Some("0")), 4096);
        assert_eq!(unchoke_per_peer_floor_bps_of_raw(Some("1000")), 4096);
        assert_eq!(unchoke_per_peer_floor_bps_of_raw(Some("1024")), 4096);
        assert_eq!(unchoke_per_peer_floor_bps_of_raw(Some("131072")), 65536);
        assert_eq!(unchoke_per_peer_floor_bps_of_raw(Some("999999999")), 65536);
    }

    /// `BH_QUIET_PIECE_LOG` parse table: default (unset) = quiet on
    /// (per-piece `piece verified` demoted to `debug!`); "0"/"off"/
    /// "false" = off (old INFO behavior restored — the forensics recovery
    /// arm); "1"/"on"/"true" and trim/case variants = quiet on.
    #[test]
    fn quiet_piece_log_parse_table() {
        // Default (unset) = quiet on.
        assert!(quiet_piece_log_of_raw(None));
        // Off = old INFO behavior (explicit =0 is the forensics recovery arm).
        assert!(!quiet_piece_log_of_raw(Some("0")));
        assert!(!quiet_piece_log_of_raw(Some("off")));
        assert!(!quiet_piece_log_of_raw(Some("false")));
        // Trim + lowercase variants judged the same (BH_LEAN_TELEMETRY style).
        assert!(!quiet_piece_log_of_raw(Some("  FALSE  ")));
        assert!(!quiet_piece_log_of_raw(Some("Off")));
        // Explicit on (any other value, including unset, = on).
        assert!(quiet_piece_log_of_raw(Some("1")));
        assert!(quiet_piece_log_of_raw(Some("on")));
        assert!(quiet_piece_log_of_raw(Some("true")));
        assert!(quiet_piece_log_of_raw(Some("True")));
        assert!(quiet_piece_log_of_raw(Some("abc")));
        assert!(quiet_piece_log_of_raw(Some("")));
    }

    /// `BH_MULTI_PIECE_BUDGET_FLOOR` parse table (default raised 0 -> 4):
    /// default/invalid -> 4 (the slow-peer cross-piece budget floor on by
    /// default); legal values pass through (explicit `=0` = the fallback
    /// arm — the earlier single-piece cadence bit-for-bit); clamped to
    /// [0, 8] (upper bound tied to the supply cap — after the cap rose to
    /// 16, 8 stays <= cap).
    #[test]
    fn multi_piece_budget_floor_parse_table() {
        // Default (unset) = 4 (previous value 0 = off).
        assert_eq!(multi_piece_budget_floor_of_raw(None), 4);
        // Invalid (non-numeric / negative sign / empty) = default 4.
        assert_eq!(multi_piece_budget_floor_of_raw(Some("abc")), 4);
        assert_eq!(multi_piece_budget_floor_of_raw(Some("-1")), 4);
        assert_eq!(multi_piece_budget_floor_of_raw(Some("")), 4);
        // Legal values pass through (explicit 0 = fallback arm — the
        // earlier single-piece cadence bit-for-bit; 2 = legacy arm value).
        assert_eq!(multi_piece_budget_floor_of_raw(Some("0")), 0);
        assert_eq!(multi_piece_budget_floor_of_raw(Some("2")), 2);
        assert_eq!(multi_piece_budget_floor_of_raw(Some("4")), 4);
        // Upper clamp 8 (the historical bound tied to the supply cap; after
        // the cap rose to 16, 8 stays <= cap, preserving under-cap
        // semantics).
        assert_eq!(multi_piece_budget_floor_of_raw(Some("12")), 8);
        assert_eq!(multi_piece_budget_floor_of_raw(Some("1024")), 8);
    }

    /// `BH_MULTI_PIECE_SUPPLY_MAX` parse table (default raised 8 -> 16):
    /// default/invalid/0 -> 16 (lower-bound defense — 0 would bypass the
    /// adjacent-piece arm entirely); legal values pass through (explicit
    /// `=8` = the fallback arm — the old cap bit-for-bit); no trim
    /// (`" 8"` fails to parse -> default, mirroring the read point).
    #[test]
    fn multi_piece_supply_max_parse_table() {
        // Default (unset) = 16 (previous value 8).
        assert_eq!(multi_piece_supply_max_of_raw(None), 16);
        // Invalid (non-numeric / negative sign / empty) = default 16.
        assert_eq!(multi_piece_supply_max_of_raw(Some("abc")), 16);
        assert_eq!(multi_piece_supply_max_of_raw(Some("-1")), 16);
        assert_eq!(multi_piece_supply_max_of_raw(Some("")), 16);
        // 0 = lower-bound defense -> default (whole-arm bypass belongs to
        // the on/off switch, not this knob).
        assert_eq!(multi_piece_supply_max_of_raw(Some("0")), 16);
        // Legal values pass through (explicit 8 = fallback arm — old cap;
        // 16 = new default).
        assert_eq!(multi_piece_supply_max_of_raw(Some("8")), 8);
        assert_eq!(multi_piece_supply_max_of_raw(Some("16")), 16);
        assert_eq!(multi_piece_supply_max_of_raw(Some("32")), 32);
        // No trim (whitespace-wrapped fails to parse -> default — mirrors
        // the read point).
        assert_eq!(multi_piece_supply_max_of_raw(Some(" 8")), 16);
    }

    /// `BH_CHECKOUT_SOFT_ACCOUNTING` parse table (default flipped to on,
    /// parse arm flipped with it): default (unset) = on (soft accounting
    /// on by default); explicit `=0`/off/false (trim + lowercase) = off
    /// (whole-piece counting, old behavior bit-for-bit fallback arm);
    /// any other value = on.
    #[test]
    fn checkout_soft_accounting_parse_table() {
        // Default (unset) = on (previously opt-in off).
        assert!(checkout_soft_accounting_of_raw(None));
        // Off = old whole-piece counting (explicit =0 is the fallback arm).
        assert!(!checkout_soft_accounting_of_raw(Some("0")));
        assert!(!checkout_soft_accounting_of_raw(Some("off")));
        assert!(!checkout_soft_accounting_of_raw(Some("false")));
        // Trim + lowercase variants judged the same (BH_QUIET_PIECE_LOG style).
        assert!(!checkout_soft_accounting_of_raw(Some("  FALSE  ")));
        assert!(!checkout_soft_accounting_of_raw(Some("Off")));
        // Explicit on (any other value, including unset, = on).
        assert!(checkout_soft_accounting_of_raw(Some("1")));
        assert!(checkout_soft_accounting_of_raw(Some("on")));
        assert!(checkout_soft_accounting_of_raw(Some("true")));
        assert!(checkout_soft_accounting_of_raw(Some("True")));
        assert!(checkout_soft_accounting_of_raw(Some("abc")));
        assert!(checkout_soft_accounting_of_raw(Some("")));
    }

    /// `BH_ENDGAME_FAST_BUSY_K` parse table (default raised 0 -> 2):
    /// default/invalid -> 2 (new default — fast-tier busy-piece tiering
    /// on); legal values pass through (explicit `=0` = the strict busy
    /// gate restored bit-for-bit — the pre-change default); clamped to
    /// [0, 8]; no trim (`" 8"` fails to parse -> default, mirroring the
    /// read point).
    #[test]
    fn endgame_fast_busy_k_parse_table() {
        // Default (unset) = 2 (previous value 0).
        assert_eq!(endgame_fast_busy_k_of_raw(None), 2);
        // Invalid (non-numeric / negative sign / empty) = default 2.
        assert_eq!(endgame_fast_busy_k_of_raw(Some("abc")), 2);
        assert_eq!(endgame_fast_busy_k_of_raw(Some("-1")), 2);
        assert_eq!(endgame_fast_busy_k_of_raw(Some("")), 2);
        // "0" passes through = explicit off (strict busy gate fallback arm).
        assert_eq!(endgame_fast_busy_k_of_raw(Some("0")), 0);
        // Legal values pass through (2 = new default; 8 = clamp upper bound).
        assert_eq!(endgame_fast_busy_k_of_raw(Some("2")), 2);
        assert_eq!(endgame_fast_busy_k_of_raw(Some("8")), 8);
        // Upper clamp 8 (9/1024 -> 8).
        assert_eq!(endgame_fast_busy_k_of_raw(Some("9")), 8);
        assert_eq!(endgame_fast_busy_k_of_raw(Some("1024")), 8);
        // No trim (whitespace-wrapped fails to parse -> default — numeric
        // knobs mirror the read point).
        assert_eq!(endgame_fast_busy_k_of_raw(Some(" 8")), 2);
    }

    /// `BH_ADJACENT_SKIP_N` parse table (default raised 0 -> 2; same
    /// shape as `endgame_fast_busy_k_parse_table`): default/invalid -> 2
    /// (new default — soft-breakpoint chain skipping on); legal values
    /// pass through (explicit `=0` = the old break-at-first-soft-
    /// breakpoint behavior restored bit-for-bit — the pre-change
    /// default); clamped to [0, 8]; no trim.
    #[test]
    fn adjacent_skip_n_parse_table() {
        // Default (unset) = 2 (previous value 0).
        assert_eq!(adjacent_skip_n_of_raw(None), 2);
        // Invalid (non-numeric / negative sign / empty) = default 2.
        assert_eq!(adjacent_skip_n_of_raw(Some("abc")), 2);
        assert_eq!(adjacent_skip_n_of_raw(Some("-1")), 2);
        assert_eq!(adjacent_skip_n_of_raw(Some("")), 2);
        // "0" passes through = explicit off (old chain-break fallback arm).
        assert_eq!(adjacent_skip_n_of_raw(Some("0")), 0);
        // Legal values pass through (2 = new default; 1 = legacy arm value;
        // 8 = clamp upper bound).
        assert_eq!(adjacent_skip_n_of_raw(Some("1")), 1);
        assert_eq!(adjacent_skip_n_of_raw(Some("2")), 2);
        assert_eq!(adjacent_skip_n_of_raw(Some("8")), 8);
        // Upper clamp 8 (9/1024 -> 8).
        assert_eq!(adjacent_skip_n_of_raw(Some("9")), 8);
        assert_eq!(adjacent_skip_n_of_raw(Some("1024")), 8);
        // No trim.
        assert_eq!(adjacent_skip_n_of_raw(Some(" 2")), 2);
    }

    /// `BH_SERVE_PENDING_CAP` parse table: default/invalid -> 256 (≈ the
    /// peer target-window ceiling, the `UB_MAX_OUTSTANDING_REQUEST`
    /// anchor); legal values pass through (explicit 256 = the default
    /// fallback arm); clamped to [32, 1024]; no trim.
    #[test]
    fn serve_pending_cap_parse_table() {
        // Default (unset) = 256.
        assert_eq!(serve_pending_cap_of_raw(None), 256);
        // Invalid (non-numeric / negative sign / empty) = default.
        assert_eq!(serve_pending_cap_of_raw(Some("abc")), 256);
        assert_eq!(serve_pending_cap_of_raw(Some("-1")), 256);
        assert_eq!(serve_pending_cap_of_raw(Some("")), 256);
        // Legal values pass through (explicit 256 = the default fallback arm).
        assert_eq!(serve_pending_cap_of_raw(Some("256")), 256);
        assert_eq!(serve_pending_cap_of_raw(Some("512")), 512);
        // Clamped to [32, 1024] (0/16 -> 32 lower bound = minimum pipelining
        // depth defense; >1024 -> 1024 upper bound = the OOM guard must not
        // be inflated back by the knob).
        assert_eq!(serve_pending_cap_of_raw(Some("0")), 32);
        assert_eq!(serve_pending_cap_of_raw(Some("16")), 32);
        assert_eq!(serve_pending_cap_of_raw(Some("2048")), 1024);
        // No trim (whitespace-wrapped fails to parse -> default — numeric
        // knobs mirror the read point).
        assert_eq!(serve_pending_cap_of_raw(Some(" 256")), 256);
    }

    /// `BH_ENDGAME_TAIL_PCT` parse table: default/invalid -> 5;
    /// legal values pass through (explicit `=0` = the whole endgame-tail
    /// supply face off); clamped to [0, 100]; no trim.
    #[test]
    fn endgame_tail_pct_parse_table() {
        // Default (unset) = 5.
        assert_eq!(endgame_tail_pct_of_raw(None), 5);
        // Invalid (non-numeric / negative sign / empty) = default 5.
        assert_eq!(endgame_tail_pct_of_raw(Some("abc")), 5);
        assert_eq!(endgame_tail_pct_of_raw(Some("-1")), 5);
        assert_eq!(endgame_tail_pct_of_raw(Some("")), 5);
        // "0" passes through = explicit off (tail supply face fallback arm).
        assert_eq!(endgame_tail_pct_of_raw(Some("0")), 0);
        // Legal values pass through (5 = default; 1 = deep-tail-only band;
        // 100 = clamp upper bound).
        assert_eq!(endgame_tail_pct_of_raw(Some("5")), 5);
        assert_eq!(endgame_tail_pct_of_raw(Some("1")), 1);
        assert_eq!(endgame_tail_pct_of_raw(Some("100")), 100);
        // Upper clamp 100 (101/1024 -> 100).
        assert_eq!(endgame_tail_pct_of_raw(Some("101")), 100);
        assert_eq!(endgame_tail_pct_of_raw(Some("1024")), 100);
        // No trim.
        assert_eq!(endgame_tail_pct_of_raw(Some(" 5")), 5);
    }

    /// `BH_ENDGAME_PIECE_DEADLINE_SECS` parse table:
    /// default/invalid -> 30; legal values pass through (explicit `=0` =
    /// per-piece deadline off); clamped to [0, 600]; no trim.
    #[test]
    fn endgame_piece_deadline_secs_parse_table() {
        // Default (unset) = 30.
        assert_eq!(endgame_piece_deadline_secs_of_raw(None), 30);
        // Invalid (non-numeric / negative sign / empty) = default 30.
        assert_eq!(endgame_piece_deadline_secs_of_raw(Some("abc")), 30);
        assert_eq!(endgame_piece_deadline_secs_of_raw(Some("-1")), 30);
        assert_eq!(endgame_piece_deadline_secs_of_raw(Some("")), 30);
        // "0" passes through = explicit off (deadline face fallback arm).
        assert_eq!(endgame_piece_deadline_secs_of_raw(Some("0")), 0);
        // Legal values pass through (30 = default; 600 = clamp upper bound).
        assert_eq!(endgame_piece_deadline_secs_of_raw(Some("30")), 30);
        assert_eq!(endgame_piece_deadline_secs_of_raw(Some("60")), 60);
        assert_eq!(endgame_piece_deadline_secs_of_raw(Some("600")), 600);
        // Upper clamp 600 (601/1024 -> 600).
        assert_eq!(endgame_piece_deadline_secs_of_raw(Some("601")), 600);
        assert_eq!(endgame_piece_deadline_secs_of_raw(Some("1024")), 600);
        // No trim.
        assert_eq!(endgame_piece_deadline_secs_of_raw(Some(" 30")), 30);
    }

    /// `BH_ENDGAME_TAIL_WINDOW` parse table: default/invalid
    /// -> 1; legal values pass through (explicit `=0` = tail window floor
    /// off — holders keep the generic BDP floor); clamped to [0, 8]; no
    /// trim.
    #[test]
    fn endgame_tail_window_parse_table() {
        // Default (unset) = 1 (k x missing blocks, k=1).
        assert_eq!(endgame_tail_window_of_raw(None), 1);
        // Invalid (non-numeric / negative sign / empty) = default 1.
        assert_eq!(endgame_tail_window_of_raw(Some("abc")), 1);
        assert_eq!(endgame_tail_window_of_raw(Some("-1")), 1);
        assert_eq!(endgame_tail_window_of_raw(Some("")), 1);
        // "0" passes through = explicit off (window-floor fallback arm).
        assert_eq!(endgame_tail_window_of_raw(Some("0")), 0);
        // Legal values pass through (1 = default; 8 = clamp upper bound).
        assert_eq!(endgame_tail_window_of_raw(Some("1")), 1);
        assert_eq!(endgame_tail_window_of_raw(Some("2")), 2);
        assert_eq!(endgame_tail_window_of_raw(Some("8")), 8);
        // Upper clamp 8 (9/1024 -> 8).
        assert_eq!(endgame_tail_window_of_raw(Some("9")), 8);
        assert_eq!(endgame_tail_window_of_raw(Some("1024")), 8);
        // No trim.
        assert_eq!(endgame_tail_window_of_raw(Some(" 1")), 1);
    }

    /// `BH_ENDGAME_UNCHOKE_HOLDER` parse table: exactly "0" =
    /// off; everything else (including unset/empty/whitespace) = on (the
    /// `BH_ENDGAME_STRICT` no-trim switch shape).
    #[test]
    fn endgame_unchoke_holder_parse_table() {
        // Unset = on (default).
        assert!(endgame_unchoke_holder_of_raw(None));
        // Exactly "0" = off (the explicit fallback arm).
        assert!(!endgame_unchoke_holder_of_raw(Some("0")));
        // Any other value = on.
        assert!(endgame_unchoke_holder_of_raw(Some("1")));
        assert!(endgame_unchoke_holder_of_raw(Some("off")));
        assert!(endgame_unchoke_holder_of_raw(Some("")));
        assert!(endgame_unchoke_holder_of_raw(Some(" 0")));
    }

    /// `peer_max` decision table (CLI override > env knob > default; the
    /// `--bt-max-peers` wiring): a registered CLI override (>= 1) always
    /// beats env and default; when not overridden the env parse arms
    /// apply (legal/failure/0 -> default, identical to the old OnceLock
    /// body).
    #[test]
    fn peer_max_of_parts_decision_table() {
        // CLI override registered: always wins (env is not read even if legal).
        assert_eq!(peer_max_of_parts(55, Some("120"), 120), 55);
        assert_eq!(peer_max_of_parts(1, None, 120), 1);
        assert_eq!(peer_max_of_parts(usize::MAX, Some("0"), 120), usize::MAX);
        // Not overridden (0): legal env value passes through.
        assert_eq!(peer_max_of_parts(0, Some("64"), 120), 64);
        // Not overridden: invalid env/0 -> default (old body bit-for-bit).
        assert_eq!(peer_max_of_parts(0, None, 120), 120);
        assert_eq!(peer_max_of_parts(0, Some("abc"), 120), 120);
        assert_eq!(peer_max_of_parts(0, Some("0"), 120), 120);
        // Trim convention preserved.
        assert_eq!(peer_max_of_parts(0, Some(" 64 "), 120), 64);
    }

    /// Effective supply-threshold decision table (CLI override > default;
    /// the `--bt-request-peer-speed-limit` wiring): the sentinel means
    /// not overridden (u64::MAX can never be a legal aria2 injection —
    /// the range min is 0 and the CLI-side u64 ceiling is unreachable);
    /// 0 = a legal explicit threshold (rate check always healthy ->
    /// rescue arm disabled; same-domain semantics as aria2 min 0).
    #[test]
    fn peer_request_speed_limit_of_parts_decision_table() {
        // Not overridden = caller default constant (taiji-engine
        // PEER_REQUEST_SPEED_LIMIT 50K, same as the aria2 default — zero
        // behavior change by default).
        assert_eq!(
            peer_request_speed_limit_of_parts(u64::MAX, 50 * 1024),
            50 * 1024
        );
        // Explicit override passes through: 0 = rescue arm off (aria2
        // threshold 0, same domain), 50K, upper bound.
        assert_eq!(peer_request_speed_limit_of_parts(0, 50 * 1024), 0);
        assert_eq!(
            peer_request_speed_limit_of_parts(50 * 1024, 50 * 1024),
            50 * 1024
        );
        assert_eq!(peer_request_speed_limit_of_parts(1, 50 * 1024), 1);
    }
}
