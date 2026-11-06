//! Choking policy (libtorrent semantics by default; the aria2 port kept as
//! a fallback via `BH_CHOKE_ARIA2=1`).
//!
//! `LeecherChoke`/`SeederChoke` produce per-round `ChokeDecision`s from
//! `PeerStat` snapshots, dispatched by [`ChokeMode`]. Slots: 8 total
//! (optimistic included, auto ratio max(1, N/5)), 15s regular rounds, 30s
//! optimistic reselection; the aria2 fallback uses 3(+1) slots, 10s rounds
//! and planned/shuffled optimism. Wire rules and deliberate divergences:
//! docs/design/peer-protocol.md.

use std::time::{Duration, Instant};

// ---- Constants (default = libtorrent; aria2 values kept for the fallback mode) ----

/// Choke regular round interval: libtorrent 15s (`session_impl.cpp`).
/// Deliberate divergence: the aria2 port uses 10s (`DefaultPeerStorage.cc`);
/// the fallback mode takes [`ARIA2_CHOKE_ROUND_INTERVAL`].
pub const CHOKE_ROUND_INTERVAL: Duration = Duration::from_secs(15);

/// aria2 fallback round interval (`DefaultPeerStorage.cc`
/// `CHOKE_ROUND_INTERVAL = 10_s`; taken when BH_CHOKE_ARIA2=1).
pub const ARIA2_CHOKE_ROUND_INTERVAL: Duration = Duration::from_secs(10);

/// Optimistic unchoke rotation period: libtorrent
/// `optimistic_unchoke_interval` 30s (`session_impl.cpp`). This side shares
/// the cadence with regular rounds (phase aligned; see the module docs).
pub const OPTIMISTIC_UNCHOKE_INTERVAL: Duration = Duration::from_secs(30);

/// Const-context max (`Ord::max` is not const-callable).
const fn cmax(a: usize, b: usize) -> usize {
    if a >= b { a } else { b }
}

/// Regular rounds per optimistic reselection = 30s / 15s = 2 (phase-aligned
/// division; max(1) guards against inverted round spacing). libtorrent has
/// no equivalent (independent timer).
pub const OPTIMISTIC_ROUND_EVERY: u32 = cmax(
    (OPTIMISTIC_UNCHOKE_INTERVAL.as_secs() / CHOKE_ROUND_INTERVAL.as_secs()) as usize,
    1,
) as u32;

/// Total regular unchoke slots: libtorrent `unchoke_slots_limit` default 8
/// (`settings_pack.cpp`). Deliberate divergence: the aria2 port uses 3
/// (`BtLeecherStateChoke.cc` `int count = 3;`; seeder
/// `BtSeederStateChoke.cc` round != 2); the fallback mode takes
/// [`ARIA2_UNCHOKE_SLOTS`]. Optimistic slots count against this budget
/// (`unchoke_slots_limit` is the total unchoke cap; leecher face = 8-1
/// regular + 1 optimistic, seeder face all regular).
///
/// Knob: the leecher total can be overridden at runtime via
/// `BH_UNCHOKE_SLOTS` (default 8 = this constant; clamped to [3, 128],
/// optimistic ratio max(1, N/5) scales with N), consumed by
/// `LeecherChoke::select_libtorrent`. The aria2 fallback branch and the
/// seeder face do not read the knob (they use this constant).
pub const UNCHOKE_SLOTS: usize = 8;

/// aria2 fallback regular slots (`BtLeecherStateChoke.cc` /
/// `BtSeederStateChoke.cc` round != 2).
pub const ARIA2_UNCHOKE_SLOTS: usize = 3;

/// Optimistic slot auto ratio: `max(1, total/5)` (libtorrent
/// `num_optimistic_unchoke_slots` default 0 = auto; `session_impl.cpp`;
/// same integer division). 8 slots -> 1.
pub const OPTIMISTIC_SLOTS_AUTO: usize = cmax(UNCHOKE_SLOTS / 5, 1);

/// aria2 seeder optimistic round slot count (`BtSeederStateChoke.cc`
/// round == 2; fallback mode).
pub const ARIA2_SEEDER_OPTIMISTIC_SLOTS: usize = 4;

/// Budget-derived unchoke slots (pure function): the leecher total scales
/// with the upload budget — a large budget opens more slots (every
/// unchoke'd peer still gets a meaningful rate), a small budget tightens
/// slots to concentrate reciprocity.
///
/// - `budget_bps = 0` (upload unlimited) or `floor_bps = 0` (division
/// guard) -> `static_n`: a missing budget face is never guessed — fall
/// back to the existing static slots (`BH_UNCHOKE_SLOTS`, default 8 =
/// [`UNCHOKE_SLOTS`]);
/// - N = `budget_bps / floor_bps` clamped to [4, 32] (lower bound 4 = the
/// generosity floor of budget-derived mode, still wider than the aria2
/// fallback 3; upper bound 32 = runaway defense). Optimistic ratio
/// max(1, N/5) scales with N (same formula as
/// [`LeecherChoke::select_libtorrent`]).
///
/// Consumed by the engine's choke assembly: the limiter lives on the
/// engine-side `DialCtx`, out of this crate's reach, so the engine
/// computes N and passes it through [`LeecherChoke::select_with_slots`]'s
/// `total_slots` parameter.
pub fn budget_unchoke_slots(budget_bps: u64, floor_bps: u64, static_n: usize) -> usize {
    if budget_bps == 0 || floor_bps == 0 {
        return static_n;
    }
    (budget_bps / floor_bps).clamp(4, 32) as usize
}

/// Rate/last-unchoke observation window (aria2 fallback sort-key window;
/// `TIME_FRAME = 20_s` in both `BtLeecherStateChoke.cc` and
/// `BtSeederStateChoke.cc`). The libtorrent-mode leecher sort window is
/// the engine-side `down_windows` (30s design window); this constant is
/// not read there.
pub const TIME_FRAME: Duration = Duration::from_secs(20);

/// Round phase count (aria2 fallback: leecher/seeder both wrap at 3).
const ROUND_PHASES: u32 = 3;

/// Choke face semantics mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChokeMode {
    /// libtorrent semantics (default): 8 slots (optimistic 1 included) /
    /// engine-side preemptive unchoke / seeding fastest_upload /
    /// optimistic waits longest / 15s+30s rounds.
    #[default]
    Libtorrent,
    /// aria2 port (fallback switch `BH_CHOKE_ARIA2=1`): 3+1 slots /
    /// planned optimistic shuffle / seeder 3/3/4 rotation / 10s rounds /
    /// no preemptive.
    Aria2,
}

/// Fallback switch parse (`BH_CHOKE_ARIA2=1` -> the aria2 port; read at
/// construction time). Reading goes through `taiji_io::knobs` (read at
/// construction, not cached).
pub fn choke_mode_from_env() -> ChokeMode {
    if taiji_io::knobs::choke_aria2_enabled() {
        ChokeMode::Aria2
    } else {
        ChokeMode::Libtorrent
    }
}

/// Round interval (per mode; the engine ticker assembly and choke object
/// construction read the same switch — timing consistency via
/// [`choke_mode_from_env`]).
pub fn round_interval(mode: ChokeMode) -> Duration {
    match mode {
        ChokeMode::Libtorrent => CHOKE_ROUND_INTERVAL,
        ChokeMode::Aria2 => ARIA2_CHOKE_ROUND_INTERVAL,
    }
}

/// Seeding sort policy registry (libtorrent `seed_choking_algorithm`
/// policies, `choker.cpp`). Same registry style as the engine's
/// `SchedulerPolicy` (`NAMES`/`from_name`/`name`); no RPC config surface
/// (an internal default change does not alter capabilities).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SeedingPolicy {
    /// round_robin (libtorrent default; registration stub, not implemented).
    RoundRobin,
    /// fastest_upload: descending by our upload rate to the peer over the
    /// last round (`choker.cpp`). Implemented; this repo's default.
    #[default]
    FastestUpload,
    /// anti_leech: V-shaped scoring (`choker.cpp`; registration stub, not
    /// implemented).
    AntiLeech,
}

impl SeedingPolicy {
    /// All policy names (registry source; same value domain as
    /// [`Self::from_name`] — roundtrip tests lock this in sync).
    pub const NAMES: &'static [&'static str] = &["round_robin", "fastest_upload", "anti_leech"];

    /// Policy name (for logs; mirrors [`Self::from_name`]).
    pub fn name(self) -> &'static str {
        match self {
            SeedingPolicy::RoundRobin => "round_robin",
            SeedingPolicy::FastestUpload => "fastest_upload",
            SeedingPolicy::AntiLeech => "anti_leech",
        }
    }

    /// Policy name -> config (unknown name = None). All three policies are
    /// nameable (registry stubs); see [`Self::is_implemented`] for what is
    /// executable.
    pub fn from_name(name: &str) -> Option<SeedingPolicy> {
        match name.trim() {
            "round_robin" => Some(SeedingPolicy::RoundRobin),
            "fastest_upload" => Some(SeedingPolicy::FastestUpload),
            "anti_leech" => Some(SeedingPolicy::AntiLeech),
            _ => None,
        }
    }

    /// Implemented (executable) face: only fastest_upload. round_robin /
    /// anti_leech are registration stubs — [`SeederChoke::try_with`]
    /// rejects them at construction time, and the permissive
    /// [`SeederChoke::with`] face hits the explicit `unimplemented!` in
    /// `select` rather than silently falling back.
    pub fn is_implemented(self) -> bool {
        matches!(self, SeedingPolicy::FastestUpload)
    }
}

/// Input to one choke decision (per-peer stats snapshot).
#[derive(Debug, Clone)]
pub struct PeerStat {
    /// Stable identifier (the caller maps it back to the connection).
    pub id: u64,
    pub interested: bool,
    /// Snubbed: slot timed out without delivery (RequestBook); the leecher
    /// excludes these outright (aria2 `executeChoke`).
    pub snubbed: bool,
    /// Whether we have an unfinished upload to that peer (seeder sort first
    /// key).
    pub outstanding_upload: bool,
    /// Last time we unchoke'd that peer (seeder second key).
    pub last_am_unchoking: Option<Instant>,
    /// Peer's download rate to us within the observation window (leecher
    /// sort key; B/s).
    pub download_speed: f64,
    /// Our upload rate to that peer within the observation window (seeder
    /// third key / libtorrent fastest_upload primary key; B/s).
    pub upload_speed: f64,
    /// Regular unchoke last round (leecher keep-slot partition key).
    pub regular_unchoker: bool,
    /// Optimistic unchoke last round (leecher fast-handoff key).
    pub opt_unchoked: bool,
    /// Last optimistic unchoke of that peer (libtorrent optimistic choice
    /// key `last_optimistically_unchoked` ascending; None = never = waited
    /// longest, sorts first. The aria2 fallback does not read this key —
    /// planned optimism shuffles instead).
    pub last_optimistically_unchoked: Option<Instant>,
    /// Endgame-tail holder priority: true = the peer currently
    /// advertises at least one still-missing piece while the torrent is in
    /// its endgame tail. In the leecher regular-unchoke sort this flag is
    /// the **first** key (ahead of the keep-position partition and the
    /// rate key) — in the deep tail the tit-for-tat rate key has collapsed
    /// to zero for exactly the holders (no download credit without
    /// supply), so without the boost the regular slots can evict every
    /// holder and the tail then waits on the peer-side optimistic unchoke
    /// cadence. Default false for every peer outside the tail: the key
    /// never flips an ordering and both sort arms stay bit-for-bit (local
    /// policy — libtorrent's choker has no endgame face; the rationale is
    /// the symmetric counterpart of its download-side
    /// `strict_end_game_mode` supply prioritization).
    pub endgame_holder: bool,
}

/// Decision output: `regular` = this round's regular slots; `optimistic` =
/// this round's optimistic slots.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChokeDecision {
    pub regular: Vec<u64>,
    pub optimistic: Vec<u64>,
}

/// Shuffle step source (`next(n) -> [0, n)`); tests inject identity/fixed
/// order. Consumed only by the aria2 fallback (planned optimistic shuffle);
/// libtorrent-mode optimistic choice is deterministic (waits longest
/// first) and does not read this.
pub type Rng = dyn FnMut(usize) -> usize;

/// `std::nth_element` partial-sort port (`choker.cpp`): only the top k are
/// guaranteed ordered by `cmp`, O(n) amortized. k >= len degrades to a full
/// sort (same semantics); k = 0 is a no-op.
fn partial_top_k<T>(v: &mut [T], k: usize, mut cmp: impl FnMut(&T, &T) -> std::cmp::Ordering) {
    if k == 0 || v.len() <= 1 {
        return;
    }
    if k >= v.len() {
        v.sort_by(|a, b| cmp(a, b));
        return;
    }
    let _ = v.select_nth_unstable_by(k - 1, |a, b| cmp(a, b));
    let (head, _) = v.split_at_mut(k);
    head.sort_by(|a, b| cmp(a, b));
}

/// Leecher state choke (aria2 `BtLeecherStateChoke` port plus the
/// libtorrent face, dispatched by [`ChokeMode`]).
#[derive(Debug)]
pub struct LeecherChoke {
    mode: ChokeMode,
    round: u32,
    /// Optimistic unchoke holder (kept across rounds until reselection or
    /// disqualification).
    opt_holder: Option<u64>,
}

impl LeecherChoke {
    /// Construct (mode from the fallback switch, resolved once at assembly).
    pub fn new() -> LeecherChoke {
        Self::with_mode(choke_mode_from_env())
    }

    /// Explicit-mode constructor (tests / fallback mode).
    pub fn with_mode(mode: ChokeMode) -> LeecherChoke {
        LeecherChoke {
            mode,
            round: 0,
            opt_holder: None,
        }
    }

    /// Constructed mode (read by the engine's preemptive path).
    pub fn mode(&self) -> ChokeMode {
        self.mode
    }

    pub fn round(&self) -> u32 {
        self.round
    }

    /// One round of decisions (dispatched by mode).
    ///
    /// The libtorrent arm reads its slot count from `BH_UNCHOKE_SLOTS`
    /// (one read per 15s round; default 8 = [`UNCHOKE_SLOTS`]). The aria2
    /// fallback branch (3 slots) does not read the knob.
    pub fn select(&mut self, peers: &mut [PeerStat], rng: &mut Rng) -> ChokeDecision {
        self.select_with_slots(peers, rng, None)
    }

    /// Slot-parameter variant of [`Self::select`] (budget-derived slots):
    /// `slots = Some(N)` gives the libtorrent arm N total slots — the
    /// engine's choke assembly derives N from the upload budget and passes
    /// it in ([`budget_unchoke_slots`]; the limiter lives on the engine's
    /// `DialCtx`, out of the decision's reach). `None` = the existing
    /// static `BH_UNCHOKE_SLOTS` path, unchanged. The aria2 fallback arm
    /// ignores the override (locked to 3 slots).
    pub fn select_with_slots(
        &mut self,
        peers: &mut [PeerStat],
        rng: &mut Rng,
        slots: Option<usize>,
    ) -> ChokeDecision {
        match self.mode {
            ChokeMode::Aria2 => self.select_aria2(peers, rng),
            ChokeMode::Libtorrent => {
                self.select_libtorrent(peers, slots.unwrap_or_else(taiji_io::knobs::unchoke_slots))
            }
        }
    }

    /// aria2 fallback mode (aria2 `executeChoke` port, semantics preserved).
    fn select_aria2(&mut self, peers: &mut [PeerStat], rng: &mut Rng) -> ChokeDecision {
        // snubbed peers are excluded.
        let mut cands: Vec<&PeerStat> = peers.iter().filter(|p| !p.snubbed).collect();

        let mut decision = ChokeDecision::default();
        // Planned optimistic (round == 0, aria2 plannedOptimisticUnchoke):
        // pool = interested and not the current holder; shuffle and pick
        // one.
        if self.round == 0 {
            let pool: Vec<u64> = cands
                .iter()
                .filter(|p| p.interested && Some(p.id) != self.opt_holder)
                .map(|p| p.id)
                .collect();
            if !pool.is_empty() {
                let j = rng(pool.len());
                if let Some(pick) = pool.get(j.min(pool.len() - 1)) {
                    self.opt_holder = Some(*pick);
                }
            } else {
                self.opt_holder = None;
            }
        }
        if let Some(h) = self.opt_holder {
            decision.optimistic.push(h);
        }

        // Regular slots: keep-position partition (regular_unchoker first)
        // -> endgame-holder priority (first key inside the
        // sort — all-false outside the endgame tail keeps the ordering
        // bit-for-bit) -> download speed descending -> take 3 from the
        // interested.
        cands.sort_by(|a, b| {
            b.endgame_holder
                .cmp(&a.endgame_holder)
                .then(b.regular_unchoker.cmp(&a.regular_unchoker))
                .then(b.download_speed.total_cmp(&a.download_speed))
        });
        let mut fast_opt_transferred = false;
        for p in cands.iter() {
            if decision.regular.len() >= ARIA2_UNCHOKE_SLOTS {
                break;
            }
            if !p.interested {
                continue;
            }
            decision.regular.push(p.id);
            // Fast optimistic handoff: the regular slots absorbed the
            // holder -> the flag transfers to the first remaining
            // interested peer.
            if self.opt_holder == Some(p.id) {
                fast_opt_transferred = true;
                self.opt_holder = None;
                decision.optimistic.clear();
            }
        }
        if fast_opt_transferred
            && let Some(next) = cands
                .iter()
                .find(|p| p.interested && !decision.regular.contains(&p.id))
                .map(|p| p.id)
        {
            self.opt_holder = Some(next);
            decision.optimistic.push(next);
        }

        // Round phase wraps after 3.
        self.round = (self.round + 1) % ROUND_PHASES;
        decision
    }

    /// libtorrent mode:
    ///
    /// - Regular slots = `total_slots` minus this round's optimistic count
    /// (optimistic counts against the total budget); candidates =
    /// interested, not snubbed, not the optimistic holder (optimistic and
    /// regular slots never overlap — overlap would crowd the budget;
    /// libtorrent accounts the optimistic set independently,
    /// `session_impl.cpp`). Sort keys follow the aria2 port (keep-position
    /// partition + download speed descending), via [`partial_top_k`]
    /// partial sort (nth_element port);
    /// - Optimistic: reselected every [`OPTIMISTIC_ROUND_EVERY`] rounds
    /// (phase aligned). Candidates sort by `last_optimistically_unchoked`
    /// ascending (None = never = waited longest first); the holder
    /// participates with its own timestamp and is kept if still in the top
    /// N. On non-reselection rounds the holder is kept but loses the slot
    /// when interested/snub changes.
    ///
    /// `total_slots`: leecher total slots (optimistic included). Production
    /// path = `BH_UNCHOKE_SLOTS` (default 8 = [`UNCHOKE_SLOTS`], see
    /// [`Self::select`]); optimistic slots = max(1, N/5) (same formula as
    /// [`OPTIMISTIC_SLOTS_AUTO`], scaling with N). The pure decision
    /// function reads no env.
    fn select_libtorrent(&mut self, peers: &mut [PeerStat], total_slots: usize) -> ChokeDecision {
        // Optimistic slot auto ratio: max(1, N/5) (same integer division;
        // 8 -> 1, 16 -> 3, 64 -> 12).
        let optimistic_slots = cmax(total_slots / 5, 1);
        let mut decision = ChokeDecision::default();

        if self.round % OPTIMISTIC_ROUND_EVERY == 0 {
            // Reselection round: waits-longest first (None first, then
            // earliest timestamp; stable sort keeps input order as the
            // last key).
            let mut pool: Vec<&PeerStat> = peers
                .iter()
                .filter(|p| p.interested && !p.snubbed)
                .collect();
            pool.sort_by(|a, b| {
                a.last_optimistically_unchoked
                    .cmp(&b.last_optimistically_unchoked)
            });
            decision.optimistic = pool.iter().take(optimistic_slots).map(|p| p.id).collect();
        } else if let Some(h) = self.opt_holder
            && peers
                .iter()
                .any(|p| p.id == h && p.interested && !p.snubbed)
        {
            // Non-reselection round: the holder is kept (disqualified by
            // losing interested or becoming snubbed).
            decision.optimistic.push(h);
        }
        self.opt_holder = decision.optimistic.first().copied();

        let regular_slots = total_slots.saturating_sub(decision.optimistic.len());
        let mut cands: Vec<&PeerStat> = peers
            .iter()
            .filter(|p| p.interested && !p.snubbed && !decision.optimistic.contains(&p.id))
            .collect();
        partial_top_k(&mut cands, regular_slots, |a, b| {
            b.endgame_holder
                .cmp(&a.endgame_holder)
                .then(b.regular_unchoker.cmp(&a.regular_unchoker))
                .then(b.download_speed.total_cmp(&a.download_speed))
        });
        decision.regular = cands.iter().take(regular_slots).map(|p| p.id).collect();

        self.round = self.round.wrapping_add(1);
        decision
    }
}

impl Default for LeecherChoke {
    fn default() -> Self {
        Self::new()
    }
}

/// Seeder state choke (aria2 `BtSeederStateChoke` port plus the libtorrent
/// `seed_choking_algorithm`, dispatched by [`ChokeMode`]).
#[derive(Debug)]
pub struct SeederChoke {
    mode: ChokeMode,
    policy: SeedingPolicy,
    round: u32,
}

impl SeederChoke {
    /// Construct (mode from the fallback switch; policy = the default
    /// fastest_upload).
    pub fn new() -> SeederChoke {
        Self::with(choke_mode_from_env(), SeedingPolicy::default())
    }

    /// Explicit mode/policy constructor (tests / fallback mode). Permissive
    /// by design: an unexecutable (Libtorrent, stub-policy) combination is
    /// not rejected here — [`Self::select`] keeps its registration-stub
    /// `unimplemented!` as the loud failure (the `#[should_panic]` port
    /// lock leans on it); validating construction goes through
    /// [`Self::try_with`].
    pub fn with(mode: ChokeMode, policy: SeedingPolicy) -> SeederChoke {
        SeederChoke {
            mode,
            policy,
            round: 0,
        }
    }

    /// Validating constructor: rejects up front the combinations
    /// [`Self::select`] cannot execute — the libtorrent face paired with a
    /// registration-stub policy (round_robin / anti_leech, `choker.cpp`
    /// registry entries without an implementation here) — returning the
    /// offending policy as `Err` instead of deferring the failure to a
    /// mid-session `unimplemented!`. The aria2 face does not read the
    /// policy (its sort order is policy-independent), so every policy is
    /// accepted there.
    pub fn try_with(mode: ChokeMode, policy: SeedingPolicy) -> Result<Self, SeedingPolicy> {
        if mode == ChokeMode::Libtorrent && !policy.is_implemented() {
            return Err(policy);
        }
        Ok(Self::with(mode, policy))
    }

    /// Constructed mode (read by the engine's preemptive path).
    pub fn mode(&self) -> ChokeMode {
        self.mode
    }

    /// Constructed policy (observation face).
    pub fn policy(&self) -> SeedingPolicy {
        self.policy
    }

    pub fn round(&self) -> u32 {
        self.round
    }

    /// One round of decisions (dispatched by mode).
    pub fn select(&mut self, peers: &mut [PeerStat], now: Instant) -> ChokeDecision {
        match self.mode {
            ChokeMode::Aria2 => self.select_aria2(peers, now),
            ChokeMode::Libtorrent => self.select_libtorrent(peers),
        }
    }

    /// Seeder sort comparison (aria2 `BtSeederStateChoke.cc` port):
    /// outstanding upload first -> most recently unchoke'd within 20s
    /// first (newer timestamp wins) -> upload speed descending.
    fn less(a: &PeerStat, b: &PeerStat, now: Instant) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        if a.outstanding_upload && !b.outstanding_upload {
            return Ordering::Less;
        }
        if !a.outstanding_upload && b.outstanding_upload {
            return Ordering::Greater;
        }
        let a_recent = a.last_am_unchoking.is_some_and(|t| {
            now.checked_duration_since(t)
                .is_some_and(|d| d <= TIME_FRAME)
        });
        let b_recent = b.last_am_unchoking.is_some_and(|t| {
            now.checked_duration_since(t)
                .is_some_and(|d| d <= TIME_FRAME)
        });
        if a_recent && b_recent {
            // Both recent: the newer lastAmUnchoking wins (aria2 only
            // compares inside its this.recent branch; implemented
            // equivalently here).
            return b
                .last_am_unchoking
                .cmp(&a.last_am_unchoking)
                .then(b.upload_speed.total_cmp(&a.upload_speed));
        }
        if a_recent {
            return Ordering::Less;
        }
        if b_recent {
            return Ordering::Greater;
        }
        b.upload_speed.total_cmp(&a.upload_speed)
    }

    /// aria2 fallback mode (unchoke + round-wrap port, semantics
    /// preserved). Interested filtering is the caller's job (non-interested
    /// peers occupy no slot).
    fn select_aria2(&mut self, peers: &mut [PeerStat], now: Instant) -> ChokeDecision {
        let count = if self.round == 2 {
            ARIA2_SEEDER_OPTIMISTIC_SLOTS
        } else {
            ARIA2_UNCHOKE_SLOTS
        };
        let mut cands: Vec<&PeerStat> = peers.iter().filter(|p| p.interested).collect();
        cands.sort_by(|a, b| Self::less(a, b, now));
        let decision = ChokeDecision {
            regular: cands.iter().take(count).map(|p| p.id).collect(),
            optimistic: Vec::new(),
        };
        self.round = (self.round + 1) % ROUND_PHASES;
        decision
    }

    /// libtorrent mode: fastest_upload (`choker.cpp`) — descending by our
    /// upload rate to the peer over the last round, top-[`UNCHOKE_SLOTS`]
    /// partial sort (nth_element port).
    ///
    /// # Deliberate divergences
    ///
    /// - Sort key input is the engine's `peer_rates.up` 10s sliding-window
    /// rate (fed at 1s ticks); libtorrent uses per-round (~15s) delta
    /// bytes / measured unchoke interval — same direction (the faster a
    /// peer receives from us, the more it keeps its slot);
    /// - Session-level optimistic-slot allocation across faces is not
    /// modeled (`session_impl.cpp` candidate eligibility spans download and
    /// seeding torrents) — the seeding face uses 8 all-regular slots;
    /// - libtorrent's `compare_peers` common prefix comparator (peer class
    /// priority -> the peer's last-round download to us, `choker.cpp`) has
    /// no peer-class equivalent here and is not modeled.
    fn select_libtorrent(&mut self, peers: &mut [PeerStat]) -> ChokeDecision {
        match self.policy {
            SeedingPolicy::FastestUpload => {}
            other => unimplemented!(
                "seeding choke policy '{}' is a registration stub; \
                 unreachable: engine constructs fastest_upload only",
                other.name()
            ),
        }
        let mut cands: Vec<&PeerStat> = peers.iter().filter(|p| p.interested).collect();
        partial_top_k(&mut cands, UNCHOKE_SLOTS, |a, b| {
            b.upload_speed.total_cmp(&a.upload_speed)
        });
        self.round = self.round.wrapping_add(1);
        ChokeDecision {
            regular: cands.iter().take(UNCHOKE_SLOTS).map(|p| p.id).collect(),
            optimistic: Vec::new(),
        }
    }
}

impl Default for SeederChoke {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat(id: u64) -> PeerStat {
        PeerStat {
            id,
            interested: true,
            snubbed: false,
            outstanding_upload: false,
            last_am_unchoking: None,
            download_speed: 0.0,
            upload_speed: 0.0,
            regular_unchoker: false,
            opt_unchoked: false,
            last_optimistically_unchoked: None,
            endgame_holder: false,
        }
    }

    fn t(secs: u64) -> Instant {
        Instant::now() - Duration::from_secs(100) + Duration::from_secs(secs)
    }

    fn aria2_rng() -> impl FnMut(usize) -> usize {
        |_n: usize| 0usize // always pool head
    }

    // ==== aria2 fallback decision table (port lock, semantics unchanged) ====

    /// Seeder ordering table (BtSeederStateChoke.cc):
    /// outstanding > recent(20s, newer first) > upload speed descending.
    #[test]
    fn seeder_ordering_decision_table() {
        let now = t(100);
        let mut peers = vec![
            stat(0), // slow
            stat(1), // fast
        ];
        peers[0].upload_speed = 10.0;
        peers[1].upload_speed = 100.0;
        let mut choke = SeederChoke::with(ChokeMode::Aria2, SeedingPolicy::FastestUpload);
        let d = choke.select(&mut peers, now);
        assert_eq!(d.regular, vec![1, 0], "speed descending");

        // recent(20s) beats speed: 0 was unchoke'd within 20s -> 0 first.
        peers[0].last_am_unchoking = Some(t(95));
        let mut choke = SeederChoke::with(ChokeMode::Aria2, SeedingPolicy::FastestUpload);
        let d = choke.select(&mut peers, now);
        assert_eq!(d.regular[0], 0, "recent-unchoke first");

        // both recent: the newer timestamp first.
        peers[1].last_am_unchoking = Some(t(99));
        let mut choke = SeederChoke::with(ChokeMode::Aria2, SeedingPolicy::FastestUpload);
        let d = choke.select(&mut peers, now);
        assert_eq!(
            d.regular,
            vec![1, 0],
            "within recent, the newer instant wins"
        );

        // outstanding beats everything.
        peers[0].outstanding_upload = true;
        peers[0].last_am_unchoking = None;
        let mut choke = SeederChoke::with(ChokeMode::Aria2, SeedingPolicy::FastestUpload);
        let d = choke.select(&mut peers, now);
        assert_eq!(d.regular[0], 0, "outstanding highest priority");

        // recent expired (>20s) no longer first.
        peers[0].outstanding_upload = false;
        peers[1].last_am_unchoking = None;
        peers[0].last_am_unchoking = Some(t(80)); // exactly 20s ago: still inside the window (<=)
        let mut choke = SeederChoke::with(ChokeMode::Aria2, SeedingPolicy::FastestUpload);
        let d = choke.select(&mut peers, now);
        assert_eq!(d.regular[0], 0, "TIME_FRAME boundary (<= 20s)");
        peers[0].last_am_unchoking = Some(t(79)); // 21s ago: expired
        let mut choke = SeederChoke::with(ChokeMode::Aria2, SeedingPolicy::FastestUpload);
        let d = choke.select(&mut peers, now);
        assert_eq!(d.regular, vec![1, 0], "back to speed order once expired");
    }

    /// Seeder slots 3/3/4 with round wrap; non-interested peers occupy no
    /// slot.
    #[test]
    fn seeder_slots_and_rotation() {
        let peers: Vec<PeerStat> = (0..10).map(stat).collect();
        let mut choke = SeederChoke::with(ChokeMode::Aria2, SeedingPolicy::FastestUpload);
        let d = choke.select(&mut peers.clone(), t(100));
        assert_eq!(d.regular.len(), 3, "round 0");
        let d = choke.select(&mut peers.clone(), t(100));
        assert_eq!(d.regular.len(), 3, "round 1");
        let d = choke.select(&mut peers.clone(), t(100));
        assert_eq!(d.regular.len(), 4, "round 2 optimistic round");
        let d = choke.select(&mut peers.clone(), t(100));
        assert_eq!(d.regular.len(), 3, "round wrap");
        // All-zero speeds: sort is stable = input order (same rank keeps
        // input order).
        let mut two: Vec<PeerStat> = vec![stat(7), stat(3)];
        let mut choke = SeederChoke::with(ChokeMode::Aria2, SeedingPolicy::FastestUpload);
        let d = choke.select(&mut two, t(100));
        assert_eq!(d.regular, vec![7, 3]);
        // Non-interested peers occupy no slot.
        let mut mixed = vec![stat(0), stat(1)];
        mixed[0].interested = false;
        let mut choke = SeederChoke::with(ChokeMode::Aria2, SeedingPolicy::FastestUpload);
        let d = choke.select(&mut mixed, t(100));
        assert_eq!(d.regular, vec![1]);
    }

    /// Leecher: 3 regular slots (interested, not snubbed, speed
    /// descending) + round==0 planned optimistic + fast optimistic handoff
    /// (BtLeecherStateChoke).
    #[test]
    fn leecher_regular_slots_optimistic_and_fast_transfer() {
        let mut rng = aria2_rng();
        let mut peers: Vec<PeerStat> = (0..5).map(stat).collect();
        peers[0].download_speed = 5.0;
        peers[1].download_speed = 50.0;
        peers[2].download_speed = 20.0;
        // 3 stays interested (low speed): the fast-handoff transfer target.
        peers[3].download_speed = 0.5;
        peers[4].snubbed = true;
        let mut choke = LeecherChoke::with_mode(ChokeMode::Aria2);
        let d = choke.select(&mut peers, &mut rng);
        // round 0: planned optimistic (pool {0,1,2,3}, rng always 0 -> 0);
        // regular = interested by speed desc 1(50),2(20),0(5) -> holder 0
        // absorbed -> fast handoff: first remaining interested = 3.
        assert_eq!(d.regular, vec![1, 2, 0]);
        assert_eq!(d.optimistic, vec![3]);

        // Fast handoff + round 1 no reselection: holder 0 tops the speeds
        // and enters the regular slots -> handed to the first interested
        // outside them (3).
        peers[0].download_speed = 100.0;
        let mut choke2 = LeecherChoke::with_mode(ChokeMode::Aria2);
        let d1 = choke2.select(&mut peers, &mut rng);
        assert_eq!(d1.optimistic, vec![3], "round 0 planned optimistic");
        let d2 = choke2.select(&mut peers, &mut rng);
        assert!(
            d2.regular.contains(&0),
            "0 has the top speed and enters the regular slots"
        );
        assert_eq!(
            d2.optimistic,
            vec![3],
            "holder absorbed by the regular slots -> handed to the first interested outside them"
        );
    }

    /// Snubbed peers fully excluded; round phase wraps at 3.
    #[test]
    fn snubbed_excluded_and_round_wraps() {
        let mut rng = aria2_rng();
        let mut peers: Vec<PeerStat> = (0..4).map(stat).collect();
        peers[0].snubbed = true;
        let mut choke = LeecherChoke::with_mode(ChokeMode::Aria2);
        let d = choke.select(&mut peers, &mut rng);
        assert!(
            !d.regular.contains(&0) && !d.optimistic.contains(&0),
            "snubbed excluded"
        );
        assert_eq!(choke.round(), 1);
        let _ = choke.select(&mut peers, &mut rng);
        assert_eq!(choke.round(), 2);
        let _ = choke.select(&mut peers, &mut rng);
        assert_eq!(choke.round(), 0, "round wrap");
        // round 0 planned optimistic reselection: pool = interested not
        // snubbed = {1,2,3} (0 excluded by snub), rng always 0 -> holder=1;
        // but 1/2/3 all fill the 3 regular slots -> the holder is absorbed
        // and no outside candidate exists -> optimistic empty (aria2: no
        // optimistic slot when no handoff target exists).
        let d = choke.select(&mut peers, &mut rng);
        assert!(d.optimistic.is_empty(), "got {:?}", d.optimistic);
    }

    // ==== libtorrent mode decision table ====

    /// Constant surface: 8 slots / optimistic auto 1 / 15s + 30s / aria2
    /// fallback values kept. Changing a constant changes behavior; locked
    /// here against drift.
    #[test]
    fn constant_surface_locked() {
        assert_eq!(UNCHOKE_SLOTS, 8, "unchoke_slots_limit (settings_pack.cpp)");
        assert_eq!(OPTIMISTIC_SLOTS_AUTO, 1, "max(1, 8/5) (session_impl.cpp)");
        assert_eq!(OPTIMISTIC_ROUND_EVERY, 2, "30s/15s phase alignment");
        assert_eq!(
            CHOKE_ROUND_INTERVAL,
            Duration::from_secs(15),
            "session_impl.cpp"
        );
        assert_eq!(
            OPTIMISTIC_UNCHOKE_INTERVAL,
            Duration::from_secs(30),
            "session_impl.cpp"
        );
        assert_eq!(
            ARIA2_UNCHOKE_SLOTS, 3,
            "BtLeecherStateChoke.cc fallback value"
        );
        assert_eq!(
            ARIA2_SEEDER_OPTIMISTIC_SLOTS, 4,
            "BtSeederStateChoke.cc fallback value"
        );
        assert_eq!(
            ARIA2_CHOKE_ROUND_INTERVAL,
            Duration::from_secs(10),
            "DefaultPeerStorage.cc fallback value"
        );
        assert_eq!(
            round_interval(ChokeMode::Libtorrent),
            CHOKE_ROUND_INTERVAL,
            "per-mode round-interval dispatch"
        );
        assert_eq!(round_interval(ChokeMode::Aria2), ARIA2_CHOKE_ROUND_INTERVAL);
        // Environment default (no BH_CHOKE_ARIA2) = libtorrent mode.
        assert_eq!(choke_mode_from_env(), ChokeMode::Libtorrent);
    }

    /// Slot table: 9 interested with distinct speeds -> regular 7 +
    /// optimistic 1 = 8 (the optimistic holder takes no regular slot —
    /// slots are disjoint), the slowest loses; snubbed excluded from both
    /// pools; ties stay in input order.
    #[test]
    fn libtorrent_leecher_eight_slot_table() {
        // Input order = id order; speeds all distinct. Peer 0 fastest (and
        // the optimistic first pick — None waited longest + stable order),
        // peer 8 slowest (the only loser).
        let mut peers: Vec<PeerStat> = (0..9).map(stat).collect();
        for (i, p) in peers.iter_mut().enumerate() {
            p.download_speed = 100.0 - i as f64;
        }
        let mut choke = LeecherChoke::with_mode(ChokeMode::Libtorrent);
        let d = choke.select(&mut peers, &mut aria2_rng());
        assert_eq!(
            d.optimistic,
            vec![0],
            "optimistic = waiting longest (None), stable first"
        );
        assert_eq!(
            d.regular.len(),
            7,
            "regular 7 (the optimistic holder counts inside the 8-slot budget)"
        );
        assert_eq!(
            d.regular,
            vec![1, 2, 3, 4, 5, 6, 7],
            "regular = speed-descending top-7 after removing optimistic"
        );
        assert!(!d.regular.contains(&8), "the slowest loses");
        assert_eq!(
            d.regular.len() + d.optimistic.len(),
            UNCHOKE_SLOTS,
            "total slots = 8"
        );

        // snubbed excluded from both pools (optimistic + regular).
        let mut peers: Vec<PeerStat> = (0..4).map(stat).collect();
        peers[0].snubbed = true;
        let mut choke = LeecherChoke::with_mode(ChokeMode::Libtorrent);
        let d = choke.select(&mut peers, &mut aria2_rng());
        assert!(
            !d.optimistic.contains(&0) && !d.regular.contains(&0),
            "snubbed excluded"
        );

        // Same rank (all-zero speeds) stable = input order; all accepted
        // when candidates are short.
        let mut peers: Vec<PeerStat> = (0..3).map(stat).collect();
        let mut choke = LeecherChoke::with_mode(ChokeMode::Libtorrent);
        let d = choke.select(&mut peers, &mut aria2_rng());
        assert_eq!(d.optimistic, vec![0]);
        assert_eq!(
            d.regular,
            vec![1, 2],
            "fewer candidates than slots: all taken, stable order"
        );
    }

    /// Slot scaling table (knob `BH_UNCHOKE_SLOTS`; drives the pure
    /// `select_libtorrent` face — the production env default 8 is covered
    /// bit-for-bit by `libtorrent_leecher_eight_slot_table`): split is
    /// regular = N - optimistic, optimistic = max(1, N/5) (16 -> 3,
    /// 64 -> 12); sort keys do not change with N (optimistic = waits
    /// longest first; regular = speed-descending top-(N-optimistic) after
    /// removing optimistic).
    #[test]
    fn libtorrent_leecher_slots_scaling_table() {
        // slots=16 (30 interested, distinct speeds, input order = id order,
        // id 0 fastest): optimistic = max(1, 16/5) = 3 (None waits longest,
        // stable first 3 = 0,1,2); regular = 16 - 3 = 13 (speed-descending
        // 3..=15 after removing the optimistic).
        let mut peers: Vec<PeerStat> = (0..30).map(stat).collect();
        for (i, p) in peers.iter_mut().enumerate() {
            p.download_speed = 1000.0 - i as f64;
        }
        let mut choke = LeecherChoke::with_mode(ChokeMode::Libtorrent);
        let d = choke.select_libtorrent(&mut peers, 16);
        assert_eq!(
            d.optimistic,
            vec![0, 1, 2],
            "optimistic = the 3 waiting longest"
        );
        assert_eq!(d.regular.len(), 13, "regular = 16 - 3");
        assert_eq!(
            d.regular,
            (3..16).collect::<Vec<_>>(),
            "regular = speed-descending top-13 after removing optimistic"
        );
        assert_eq!(d.regular.len() + d.optimistic.len(), 16, "total slots = 16");

        // slots=64 (70 interested): optimistic = max(1, 64/5) = 12; regular
        // = 52; total 64, slowest 6 (64..=69) lose.
        let mut peers: Vec<PeerStat> = (0..70).map(stat).collect();
        for (i, p) in peers.iter_mut().enumerate() {
            p.download_speed = 1000.0 - i as f64;
        }
        let mut choke = LeecherChoke::with_mode(ChokeMode::Libtorrent);
        let d = choke.select_libtorrent(&mut peers, 64);
        assert_eq!(d.optimistic, (0..12).collect::<Vec<_>>(), "optimistic 12");
        assert_eq!(
            d.regular,
            (12..64).collect::<Vec<_>>(),
            "regular = speed-descending top-52 after removing optimistic"
        );
        assert!(!d.regular.contains(&69), "the slowest loses");
        assert_eq!(d.regular.len() + d.optimistic.len(), 64, "total slots = 64");

        // Lower bound 3 (parse clamp floor): optimistic = max(1, 0) = 1,
        // regular = 2.
        let mut peers: Vec<PeerStat> = (0..6).map(stat).collect();
        for (i, p) in peers.iter_mut().enumerate() {
            p.download_speed = 100.0 - i as f64;
        }
        let mut choke = LeecherChoke::with_mode(ChokeMode::Libtorrent);
        let d = choke.select_libtorrent(&mut peers, 3);
        assert_eq!(d.optimistic, vec![0]);
        assert_eq!(
            d.regular,
            vec![1, 2],
            "minimal split = regular 2 + optimistic 1"
        );
        assert_eq!(d.regular.len() + d.optimistic.len(), 3);
    }

    /// Budget-derived slot table ([`budget_unchoke_slots`] pure function):
    /// 0/unlimited falls back to static (missing budget is never guessed);
    /// division guard (floor=0 falls back to static); quotient clamped to
    /// [4, 32]; huge values do not overflow.
    #[test]
    fn budget_unchoke_slots_decision_table() {
        // Unlimited (budget=0) falls back to static: static_n passed
        // through (8 default / 16 explicit).
        assert_eq!(budget_unchoke_slots(0, 16384, 8), 8);
        assert_eq!(budget_unchoke_slots(0, 16384, 16), 16);
        // Division guard (floor=0 also falls back to static — never guess
        // the divisor).
        assert_eq!(budget_unchoke_slots(1_000_000, 0, 8), 8);
        assert_eq!(budget_unchoke_slots(0, 0, 8), 8);
        // Quotient < 4 -> clamped to 4 (1/2/3 all land on 4: even a
        // 16KiB/s budget keeps the 4-slot generosity floor, still wider
        // than the aria2 fallback 3).
        assert_eq!(budget_unchoke_slots(16384, 16384, 8), 4); // quotient 1
        assert_eq!(budget_unchoke_slots(32768, 16384, 8), 4); // quotient 2
        assert_eq!(budget_unchoke_slots(65535, 16384, 8), 4); // quotient 3
        // Quotient exactly at the floor: 64KiB/s / 16KiB/s = 4.
        assert_eq!(budget_unchoke_slots(65536, 16384, 8), 4);
        // Mid-range pass-through: 10 slots (160KiB/s / 16KiB/s).
        assert_eq!(budget_unchoke_slots(163_840, 16384, 8), 10);
        assert_eq!(
            budget_unchoke_slots(163_840, 8192, 8),
            20,
            "halving the floor knob doubles the slots"
        );
        // Quotient exactly at the cap and beyond clamps to 32 (512KiB/s /
        // 16KiB/s = 32; 1MiB/s gives 64, still 32 — runaway defense).
        assert_eq!(budget_unchoke_slots(524_288, 16384, 8), 32);
        assert_eq!(budget_unchoke_slots(1_048_576, 16384, 8), 32);
        // Huge value guard: u64::MAX does not overflow (safe division,
        // clamped to 32).
        assert_eq!(budget_unchoke_slots(u64::MAX, 4096, 8), 32);
        assert_eq!(
            budget_unchoke_slots(u64::MAX, u64::MAX, 8),
            4,
            "quotient 1 clamps to the floor"
        );
    }

    /// Two-arm table for [`LeecherChoke::select_with_slots`]: the None arm
    /// equals the existing [`Self::select`] static path (default 8); the
    /// Some(N) arm splits N slots (optimistic max(1, N/5) scaling with N);
    /// the aria2 fallback arm ignores the override (locked to 3 slots).
    #[test]
    fn select_with_slots_two_arm_table() {
        // 9 interested, distinct speeds (same input as
        // `libtorrent_leecher_eight_slot_table`: id 0 fastest and the
        // optimistic first pick, id 8 slowest).
        let mk_peers = || {
            let mut peers: Vec<PeerStat> = (0..9).map(stat).collect();
            for (i, p) in peers.iter_mut().enumerate() {
                p.download_speed = 100.0 - i as f64;
            }
            peers
        };
        // Off arm (None = production default path): static 8 slots,
        // bit-identical to `select()`.
        let mut a = LeecherChoke::with_mode(ChokeMode::Libtorrent);
        let mut b = LeecherChoke::with_mode(ChokeMode::Libtorrent);
        let d_static = a.select(&mut mk_peers(), &mut aria2_rng());
        let d_none = b.select_with_slots(&mut mk_peers(), &mut aria2_rng(), None);
        assert_eq!(
            d_none, d_static,
            "the None arm equals the static path bit-for-bit"
        );
        assert_eq!(d_none.regular.len() + d_none.optimistic.len(), 8);

        // On arm Some(4) (the budget-derived value of 64KiB/s / 16KiB/s):
        // optimistic = max(1, 4/5) = 1 (id 0), regular = 3 (speed
        // desc 1..=3 after removing it), 4..=8 lose to the tightening.
        let mut choke = LeecherChoke::with_mode(ChokeMode::Libtorrent);
        let d = choke.select_with_slots(&mut mk_peers(), &mut aria2_rng(), Some(4));
        assert_eq!(
            d.optimistic,
            vec![0],
            "optimistic = waiting longest (None), stable first"
        );
        assert_eq!(d.regular, vec![1, 2, 3], "regular = 4 - 1 = 3");
        assert!(
            !d.regular.contains(&8),
            "the slowest loses after the budget tightens"
        );
        assert_eq!(d.regular.len() + d.optimistic.len(), 4, "total slots = 4");

        // On arm Some(32) (the cap): 12 interested -> all fit (12 < 32),
        // optimistic = max(1, 32/5) = 6, regular = 6.
        let mut peers: Vec<PeerStat> = (0..12).map(stat).collect();
        for (i, p) in peers.iter_mut().enumerate() {
            p.download_speed = 100.0 - i as f64;
        }
        let mut choke = LeecherChoke::with_mode(ChokeMode::Libtorrent);
        let d = choke.select_with_slots(&mut peers, &mut aria2_rng(), Some(32));
        assert_eq!(d.optimistic.len(), 6, "optimistic = max(1, 32/5)");
        assert_eq!(d.regular.len(), 6, "fewer candidates than slots: all taken");
        assert_eq!(d.regular.len() + d.optimistic.len(), 12);

        // aria2 fallback arm ignores the override: still 3 regular +
        // planned optimistic under Some(32) (the override is silently
        // dropped — budget mode never touches the fallback face).
        let mut peers: Vec<PeerStat> = (0..5).map(stat).collect();
        peers[4].snubbed = true;
        let mut choke = LeecherChoke::with_mode(ChokeMode::Aria2);
        let d = choke.select_with_slots(&mut peers, &mut aria2_rng(), Some(32));
        assert_eq!(
            d.regular.len(),
            ARIA2_UNCHOKE_SLOTS,
            "the aria2 arm keeps 3 slots (direct translation) and ignores the override"
        );
    }

    /// Optimistic rotation table: waits-longest first
    /// (`last_optimistically_unchoked` ascending, None first) + holder kept
    /// (non-reselection rounds; joins with its timestamp on reselection
    /// rounds) + disqualification (losing interested / becoming snubbed) +
    /// 30s phase (reselect every 2 rounds).
    #[test]
    fn libtorrent_optimistic_wait_longest_table() {
        let mut peers = vec![stat(10), stat(20), stat(30)];
        // Wait order: 30 (None = never) > 10 (early) > 20 (late).
        peers[0].last_optimistically_unchoked = Some(t(80));
        peers[1].last_optimistically_unchoked = Some(t(90));
        let mut choke = LeecherChoke::with_mode(ChokeMode::Libtorrent);
        let d = choke.select(&mut peers, &mut aria2_rng());
        assert_eq!(
            d.optimistic,
            vec![30],
            "row 1: never optimistically unchoked ranks first"
        );

        // Row 2 (non-reselection round): the holder is kept — even though
        // 30's timestamp is newer than 10/20.
        peers[2].last_optimistically_unchoked = Some(t(99));
        let d = choke.select(&mut peers, &mut aria2_rng());
        assert_eq!(
            d.optimistic,
            vec![30],
            "row 2: the holder is kept in a non-reselection round"
        );

        // Row 3 (reselection round, round 2): joins with timestamps — 30
        // (t99, newest) last, waits-longest 10 (t80) wins.
        let d = choke.select(&mut peers, &mut aria2_rng());
        assert_eq!(
            d.optimistic,
            vec![10],
            "row 3: in a reselection round the waiting-longest (10, t80) wins"
        );

        // Row 4 (non-reselection round): holder 10 kept.
        let d = choke.select(&mut peers, &mut aria2_rng());
        assert_eq!(d.optimistic, vec![10], "row 4: kept");

        // Row 5 (reselection round): 10 joins with t80 and still leads
        // (20=t90, 30=t99 later) -> kept for another round.
        let d = choke.select(&mut peers, &mut aria2_rng());
        assert_eq!(
            d.optimistic,
            vec![10],
            "row 5: the holder still waits longest -> kept"
        );

        // Row 6: the holder loses interested -> disqualified
        // (non-reselection round).
        peers[0].interested = false;
        let d = choke.select(&mut peers, &mut aria2_rng());
        assert!(
            d.optimistic.is_empty(),
            "row 6: the holder lost interest -> optimistic empty"
        );
        assert!(
            !d.regular.contains(&0),
            "row 6: losing interest also excludes from regular slots"
        );
    }

    /// Seeding fastest_upload table + policy registry (SchedulerPolicy
    /// style: NAMES/from_name/name/is_implemented).
    #[test]
    fn libtorrent_seeder_fastest_upload_table() {
        // Registry: all three policies nameable, roundtrip stable;
        // fastest_upload is the only implemented one.
        assert_eq!(SeedingPolicy::NAMES.len(), 3);
        for &name in SeedingPolicy::NAMES {
            let p = SeedingPolicy::from_name(name).unwrap_or_else(|| panic!("{name}"));
            assert_eq!(p.name(), name, "{name} roundtrip");
            assert_eq!(SeedingPolicy::from_name(p.name()), Some(p));
        }
        assert_eq!(
            SeedingPolicy::from_name("bogus"),
            None,
            "unknown name -> None"
        );
        assert_eq!(
            SeedingPolicy::default(),
            SeedingPolicy::FastestUpload,
            "our default"
        );
        assert!(SeedingPolicy::FastestUpload.is_implemented());
        assert!(!SeedingPolicy::RoundRobin.is_implemented(), "registry stub");
        assert!(!SeedingPolicy::AntiLeech.is_implemented(), "registry stub");

        // fastest_upload: upload-speed descending top-8 (9 choose 8,
        // slowest loses).
        let mut peers: Vec<PeerStat> = (0..9).map(stat).collect();
        for (i, p) in peers.iter_mut().enumerate() {
            p.upload_speed = 10.0 + i as f64; // id 8 fastest ... id 0 slowest
        }
        let mut choke = SeederChoke::with(ChokeMode::Libtorrent, SeedingPolicy::FastestUpload);
        let d = choke.select(&mut peers, t(100));
        assert_eq!(
            d.regular,
            vec![8, 7, 6, 5, 4, 3, 2, 1],
            "fastest_upload descending top-8 (choker.cpp)"
        );
        assert!(!d.regular.contains(&0), "the slowest loses");
        assert!(
            d.optimistic.is_empty(),
            "the seeding face has no separate optimistic slot (divergence note)"
        );

        // Non-interested occupy no slot; all accepted when candidates are
        // short (stable order).
        let mut two = vec![stat(7), stat(3)];
        two[0].interested = false;
        let mut choke = SeederChoke::with(ChokeMode::Libtorrent, SeedingPolicy::FastestUpload);
        let d = choke.select(&mut two, t(100));
        assert_eq!(d.regular, vec![3]);
    }

    /// Registration-stub policies are explicitly unreachable (no silent
    /// fallback).
    #[test]
    #[should_panic(expected = "registration stub")]
    fn seeding_stub_policy_is_unreachable() {
        let mut peers = vec![stat(0)];
        let mut choke = SeederChoke::with(ChokeMode::Libtorrent, SeedingPolicy::RoundRobin);
        let _ = choke.select(&mut peers, t(100));
    }

    /// Construction-time rejection ([`SeederChoke::try_with`]): the stub
    /// policies under the libtorrent face are rejected up front (the `Err`
    /// payload is the offending policy) instead of surfacing as a
    /// mid-session `unimplemented!`; the implemented combination and the
    /// whole aria2 face (the port never reads the policy) construct and
    /// run.
    #[test]
    fn seeding_try_with_rejects_stub_policy_at_construction() {
        // The two stub policies, each rejected with itself as the payload.
        assert!(
            matches!(
                SeederChoke::try_with(ChokeMode::Libtorrent, SeedingPolicy::RoundRobin),
                Err(SeedingPolicy::RoundRobin)
            ),
            "libtorrent + round_robin rejected, payload = the policy"
        );
        assert!(matches!(
            SeederChoke::try_with(ChokeMode::Libtorrent, SeedingPolicy::AntiLeech),
            Err(SeedingPolicy::AntiLeech)
        ));
        // Implemented face constructs, reports its shape, and decides.
        let mut choke = SeederChoke::try_with(ChokeMode::Libtorrent, SeedingPolicy::FastestUpload)
            .unwrap_or_else(|p| panic!("fastest_upload must construct, got {p:?}"));
        assert_eq!(choke.mode(), ChokeMode::Libtorrent);
        assert_eq!(choke.policy(), SeedingPolicy::FastestUpload);
        let mut peers = vec![stat(0)];
        let _ = choke.select(&mut peers, t(100));
        // The aria2 face never reads the policy: all three construct.
        for &name in SeedingPolicy::NAMES {
            let policy = SeedingPolicy::from_name(name).unwrap_or_else(|| panic!("{name}"));
            assert!(
                SeederChoke::try_with(ChokeMode::Aria2, policy).is_ok(),
                "aria2 face accepts {name}"
            );
        }
    }

    /// Endgame-holder priority table (both leecher arms):
    /// `endgame_holder` is the first regular-sort key — a holder with zero
    /// rate beats a fast non-holder AND a keep-position incumbent
    /// non-holder; among holders the existing keys (keep-position, then
    /// rate) keep their order; the all-false arm is the pre-change
    /// ordering bit-for-bit (the key never flips when no peer holds a
    /// missing piece — non-tail = zero behavior change).
    #[test]
    fn endgame_holder_priority_table() {
        // libtorrent arm, 9 peers distinct speeds (id 0 fastest): the
        // slowest peer (8) flips to a holder -> it enters the regular top
        // and the slowest remaining non-holder (7) drops out.
        let mut peers: Vec<PeerStat> = (0..9).map(stat).collect();
        for (i, p) in peers.iter_mut().enumerate() {
            p.download_speed = 100.0 - i as f64;
        }
        peers[8].endgame_holder = true;
        let mut choke = LeecherChoke::with_mode(ChokeMode::Libtorrent);
        let d = choke.select(&mut peers, &mut aria2_rng());
        assert!(
            d.regular.contains(&8),
            "a holder with zero rate still enters the regular slots"
        );
        assert!(
            !d.regular.contains(&7),
            "the slowest non-holder yields its slot"
        );
        assert_eq!(d.regular.len() + d.optimistic.len(), UNCHOKE_SLOTS);

        // Holder beats the keep-position incumbent: 0-7 held regular
        // slots last round (rate order, all keep-position), the incumbent
        // tail (7) loses to a holder (8) despite keep-position (the
        // optimistic slot takes id 0 = waits-longest stable first).
        let mut peers: Vec<PeerStat> = (0..9).map(stat).collect();
        for (i, p) in peers.iter_mut().enumerate() {
            p.download_speed = 100.0 - i as f64;
            p.regular_unchoker = i <= 7; // incumbents
        }
        peers[8].endgame_holder = true;
        let mut choke = LeecherChoke::with_mode(ChokeMode::Libtorrent);
        let d = choke.select(&mut peers, &mut aria2_rng());
        assert!(
            d.regular.contains(&8),
            "the holder wins ahead of the keep-position key"
        );
        assert!(!d.regular.contains(&7), "the incumbent non-holder is out");

        // Among holders the old keys keep their relative order (and a
        // holder still beats a faster non-holder): holders 1 (rate 40)
        // and 2 (rate 20) line up rate-descending ahead of the faster
        // non-holder 3 (rate 50→ taken by optimistic? no — optimistic
        // takes the stable pool head 0); regular = holder rate order,
        // then non-holders.
        let mut peers: Vec<PeerStat> = (0..5).map(stat).collect();
        peers[0].download_speed = 60.0; // non-holder, optimistic pick (None first)
        peers[1].download_speed = 40.0; // holder
        peers[2].download_speed = 20.0; // holder
        peers[3].download_speed = 50.0; // non-holder, faster than holder 2
        peers[4].download_speed = 10.0; // non-holder
        peers[1].endgame_holder = true;
        peers[2].endgame_holder = true;
        let mut choke = LeecherChoke::with_mode(ChokeMode::Libtorrent);
        let d = choke.select(&mut peers, &mut aria2_rng());
        assert_eq!(d.optimistic, vec![0]);
        assert_eq!(
            d.regular,
            vec![1, 2, 3, 4],
            "holders keep their speed order among themselves and beat the faster non-holder (3)"
        );

        // All-false arm = the pre-change ordering bit-for-bit (pinned by
        // `libtorrent_leecher_eight_slot_table`; re-derived here with the
        // flag explicitly defaulted).
        let mut peers: Vec<PeerStat> = (0..9).map(stat).collect();
        for (i, p) in peers.iter_mut().enumerate() {
            p.download_speed = 100.0 - i as f64;
            p.endgame_holder = false;
        }
        let mut choke = LeecherChoke::with_mode(ChokeMode::Libtorrent);
        let d = choke.select(&mut peers, &mut aria2_rng());
        assert_eq!(
            d.regular,
            vec![1, 2, 3, 4, 5, 6, 7],
            "all false = the old order bit-for-bit"
        );

        // aria2 fallback arm: same key insertion — the holder (2, slowest)
        // enters the 3 regular slots, the slowest non-holder (1) drops.
        let mut peers: Vec<PeerStat> = (0..3).map(stat).collect();
        for (i, p) in peers.iter_mut().enumerate() {
            p.download_speed = 30.0 - i as f64;
        }
        peers[2].endgame_holder = true;
        let mut choke = LeecherChoke::with_mode(ChokeMode::Aria2);
        let d = choke.select(&mut peers, &mut aria2_rng());
        assert!(
            d.regular.contains(&2),
            "the aria2 arm also prioritizes holders"
        );
        assert!(d.regular.contains(&0), "the fast non-holder is kept");
        assert_eq!(d.regular.len(), ARIA2_UNCHOKE_SLOTS);

        // The optimistic pool does not consume the flag (waits-longest
        // unchanged): a never-optimistically-unchoked non-holder still
        // wins the optimistic slot over a recently-unchoke'd holder.
        let mut peers = vec![stat(10), stat(20)];
        peers[0].last_optimistically_unchoked = Some(t(90));
        peers[1].endgame_holder = true;
        let mut choke = LeecherChoke::with_mode(ChokeMode::Libtorrent);
        let d = choke.select(&mut peers, &mut aria2_rng());
        assert_eq!(
            d.optimistic,
            vec![20],
            "the optimistic pool ignores the holder flag (None waited longest)"
        );
    }
}
