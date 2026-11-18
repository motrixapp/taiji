//! Driver determinism seams: the injected clock and RNG handles
//! (SPEC G6, docs/spec.md: "Determinism where affordable: injected
//! clocks in the engine core ... so behavior is testable without
//! sleeping").
//!
//! Shape: one injection point per concern, carried on
//! [`crate::config::EngineConfig`] (the engine's established assembly
//! injection surface) and stored once on the loop state
//! ([`crate::run::state::EngineLoop`]) and each face state
//! ([`crate::faces::FaceState`]); every former direct
//! `Instant::now()` read in the driver paths (dispatch rounds, choke
//! rounds, run ticks, timeout and backoff scheduling) reads
//! `clock.now()` instead. Default construction is bit-for-bit the
//! current behavior: [`Clock::default`] calls `Instant::now()` with
//! zero indirection (a discriminant match on the `Real` arm), and
//! [`Rng::default`] draws OS entropy exactly like the scattered
//! `rand::random` calls it collects. Tests and the future
//! multi-peer simulation harness pin a [`ManualClock`] / a
//! fixed-seed [`Rng`] through the same public surface and drive the
//! engine from outside.
//!
//! Explicitly NOT covered (by design, mirroring the upstream
//! divergence from libtorrent's `TORRENT_BUILD_SIMULATOR`
//! compile-time wholesale swap):
//! - taiji-io transports (µTP/DNS/NAT): µTP keeps its own
//!   microsecond clock (`taiji_io::utp` now_us); the simulation layer
//!   plugs in through the existing duplex wire, not through a clock
//!   swap.
//! - The tokio timer wheel (`tokio::time::Instant` / sleep / tick):
//!   virtualizing the runtime clock is the harness's job (paused
//!   time), not the engine's.
//! - Wall-clock (`SystemTime`) reads (tracker timestamps, log
//!   formatting) and OS randomness inside taiji-bt (the DHT and
//!   tracker actors own internal generators; frozen zone).

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::time::Duration;
use std::time::Instant;

/// Monotonic-now injection handle: `now()` returns the current
/// instant of whatever clock this handle carries.
///
/// - [`Clock::default`] / [`Clock::real`]: the process monotonic
///   clock — exactly `Instant::now()`, no indirection (the production
///   path keeps today's behavior and cost).
/// - [`Clock::custom`]: an arbitrary now-function (one `Arc` deref +
///   one call per read). [`ManualClock`] is the ready-made driver for
///   tests and the simulation harness.
///
/// Clone is cheap (an `Arc` clone when custom); the handle is
/// `Send + Sync` so a face state, the loop state, and spawned plumbing
/// can share one clock.
#[derive(Clone, Default)]
pub struct Clock(ClockInner);

#[derive(Clone, Default)]
enum ClockInner {
    /// The real monotonic clock (the default; zero indirection).
    #[default]
    Real,
    /// An injected now-function.
    Custom(Arc<dyn Fn() -> Instant + Send + Sync>),
}

impl Clock {
    /// The real process monotonic clock (the default construction).
    pub fn real() -> Self {
        Self(ClockInner::Real)
    }

    /// An injected clock source. Read cost = one `Arc` deref + one
    /// call; per-read allocation: none.
    pub fn custom(source: Arc<dyn Fn() -> Instant + Send + Sync>) -> Self {
        Self(ClockInner::Custom(source))
    }

    /// The current instant of this clock. On the default (real)
    /// construction this is `Instant::now()` itself — the production
    /// paths read the same monotonic clock semantics as before the
    /// seam existed.
    pub fn now(&self) -> Instant {
        match &self.0 {
            ClockInner::Real => Instant::now(),
            ClockInner::Custom(source) => source(),
        }
    }
}

// Presence-only Debug (the custom arm carries an opaque closure).
impl std::fmt::Debug for Clock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            ClockInner::Real => f.write_str("Clock(real)"),
            ClockInner::Custom(_) => f.write_str("Clock(custom)"),
        }
    }
}

/// A shareable manual clock (the test/simulation driver for
/// [`Clock`]): `clock()` hands out handles whose `now()` reads the
/// shared instant; `advance()` moves it. Deterministic — no real
/// sleeping; time moves only when the driver says so.
///
/// Locking: one `std::sync::Mutex` around the instant; the critical
/// sections are a copy and an add (never held across `await`).
#[derive(Debug, Clone)]
pub struct ManualClock {
    cell: Arc<Mutex<Instant>>,
}

impl ManualClock {
    /// A manual clock starting at `start`.
    pub fn new(start: Instant) -> Self {
        Self {
            cell: Arc::new(Mutex::new(start)),
        }
    }

    /// A new [`Clock`] handle reading this manual clock (every handle
    /// observes `advance` moves immediately — one shared instant).
    pub fn clock(&self) -> Clock {
        let cell = Arc::clone(&self.cell);
        Clock::custom(Arc::new(move || {
            // Poisoning is impossible in practice (the lock body is a
            // copy that cannot panic); recovering the value keeps a
            // panicked sibling thread from stalling the clock.
            *cell.lock().unwrap_or_else(PoisonError::into_inner)
        }))
    }

    /// The current manual instant.
    pub fn now(&self) -> Instant {
        *self.cell.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Advance the manual clock by `step`; returns the new instant.
    pub fn advance(&self, step: Duration) -> Instant {
        let mut now = self.cell.lock().unwrap_or_else(PoisonError::into_inner);
        *now += step;
        *now
    }
}

/// Randomness injection handle: one seam behind the OS-random calls
/// of the engine/core driver layer (peer-id generation, GID
/// allocation, NAT binding owners, RPC session ids).
///
/// - [`Rng::default`]: OS entropy per call — the collected call sites
///   behave exactly like their former scattered `rand::random` reads.
/// - [`Rng::from_seed`]: a pinned deterministic source (tests pin the
///   seed; two constructions from one seed produce identical
///   sequences). [`Rng::seed`] reports the pinned seed so callers that
///   derive per-engine deterministic generators (the engine's startup
///   shuffle / choke shuffles) can do so without consuming draw
///   order.
///
/// The engine's in-loop generators (`XorShift`) stay deterministic
/// fixed constants by default — this seam only re-seeds them when a
/// seed is pinned (see `run::assemble`).
#[derive(Clone, Default)]
pub struct Rng(RngInner);

#[derive(Clone, Default)]
enum RngInner {
    /// OS entropy per call (the default; identical distribution to
    /// the former `rand::random` reads).
    #[default]
    Os,
    /// A pinned deterministic generator.
    Seeded(Arc<SeededRng>),
}

struct SeededRng {
    seed: u64,
    // The lock body is a fixed-size draw that cannot panic; a
    // poisoned lock recovers the generator (no invariant to lose).
    core: Mutex<rand::rngs::StdRng>,
}

impl Rng {
    /// OS entropy (the default construction).
    pub fn os() -> Self {
        Self(RngInner::Os)
    }

    /// A pinned deterministic source: identical sequences across two
    /// constructions from the same seed, different from any other
    /// seed. The seed is retained for [`Rng::seed`].
    pub fn from_seed(seed: u64) -> Self {
        use rand::SeedableRng as _;
        Self(RngInner::Seeded(Arc::new(SeededRng {
            seed,
            core: Mutex::new(rand::rngs::StdRng::seed_from_u64(seed)),
        })))
    }

    /// The pinned seed (`Some` only for [`Rng::from_seed`]
    /// constructions; `None` = the OS default — callers keep their
    /// frozen constants). Reading this never consumes draw order.
    pub fn seed(&self) -> Option<u64> {
        match &self.0 {
            RngInner::Os => None,
            RngInner::Seeded(s) => Some(s.seed),
        }
    }

    /// One uniform `u64`.
    pub fn next_u64(&self) -> u64 {
        match &self.0 {
            RngInner::Os => rand::random::<u64>(),
            RngInner::Seeded(s) => {
                use rand::RngExt as _;
                s.core
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .random()
            }
        }
    }

    /// One uniform byte (the peer-id generation byte source; the OS
    /// arm matches `rand::random::<u8>()` exactly).
    pub fn byte(&self) -> u8 {
        match &self.0 {
            RngInner::Os => rand::random::<u8>(),
            RngInner::Seeded(s) => {
                use rand::RngExt as _;
                s.core
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .random()
            }
        }
    }

    /// Uniform bytes into `buf` (the RPC session-id source).
    pub fn fill_bytes(&self, buf: &mut [u8]) {
        match &self.0 {
            RngInner::Os => rand::fill(buf),
            RngInner::Seeded(s) => {
                use rand::RngExt as _;
                s.core
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .fill(buf);
            }
        }
    }
}

// Presence-only Debug (the seeded arm carries a generator; the pinned
// seed is the interesting surface and prints inline).
impl std::fmt::Debug for Rng {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            RngInner::Os => f.write_str("Rng(os)"),
            RngInner::Seeded(s) => write!(f, "Rng(seeded {:016x})", s.seed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default clock is the real monotonic clock: non-decreasing
    /// reads advancing with wall time (two consecutive reads ordered,
    /// a busy-wait span observed positive — bounded so the test never
    /// hangs on a stalled clock).
    #[test]
    fn default_clock_reads_the_real_monotonic_clock() {
        let clock = Clock::default();
        let a = clock.now();
        let mut b = a;
        for _ in 0..100_000 {
            b = clock.now();
            if b > a {
                break;
            }
        }
        assert!(b >= a, "monotonic clock reads must not go backwards");
        assert!(b > a, "two real-clock reads a busy loop apart must advance");
    }

    /// Manual-clock handles share one instant: every handle observes
    /// `advance` immediately, `now()` matches, and nothing moves
    /// without an explicit advance (the determinism contract).
    #[test]
    fn manual_clock_handles_share_one_advanceable_instant() {
        let start = Instant::now();
        let manual = ManualClock::new(start);
        let c1 = manual.clock();
        let c2 = manual.clock();
        assert_eq!(c1.now(), start);
        assert_eq!(c2.now(), start, "handles read the same shared instant");

        let t1 = manual.advance(Duration::from_secs(30));
        assert_eq!(t1, start + Duration::from_secs(30));
        assert_eq!(c1.now(), t1);
        assert_eq!(c2.now(), t1, "a handle observes the advance at once");

        // No advance, no motion.
        assert_eq!(c1.now(), t1);
    }

    /// Fixed-seed determinism: two `from_seed` constructions produce
    /// identical draw sequences across every draw face; a different
    /// seed diverges (the replay/pin contract of the seam).
    #[test]
    fn fixed_seed_rng_sequences_are_identical_and_seed_sensitive() {
        let draw = |rng: &Rng| {
            let mut bytes = [0u8; 16];
            rng.fill_bytes(&mut bytes);
            (
                [rng.next_u64(), rng.next_u64()],
                [rng.byte(), rng.byte(), rng.byte()],
                bytes,
            )
        };
        let a = Rng::from_seed(0x5EED_0000_0000_0001);
        let b = Rng::from_seed(0x5EED_0000_0000_0001);
        assert_eq!(draw(&a), draw(&b), "same seed must replay identically");

        let c = Rng::from_seed(0x5EED_0000_0000_0002);
        assert_ne!(draw(&a), draw(&c), "a different seed must diverge");

        // The pinned seed is observable without consuming draw order.
        assert_eq!(a.seed(), Some(0x5EED_0000_0000_0001));
        assert_eq!(
            Rng::default().seed(),
            None,
            "the OS default carries no seed"
        );
    }

    /// The OS default draws without panic across every draw face (the
    /// distribution itself is not assertable; this pins the wiring).
    #[test]
    fn os_default_rng_draws_on_every_face() {
        let rng = Rng::default();
        let mut buf = [0u8; 16];
        rng.fill_bytes(&mut buf);
        let _ = rng.next_u64();
        let _ = rng.byte();
    }
}
