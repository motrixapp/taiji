//! The unified task-phase vocabulary over the three persisted task
//! `state` columns: `torrent.state`, `http_task.state` and
//! `media_task.state`. One enum = the union of the three declared value
//! domains (15 distinct row-state strings) plus the two ledger-registered
//! fold sub-phases (19 variants — see [`TaskPhase`]).
//!
//! # Why this crate (the landing decision)
//!
//! The three value domains are anchored in this crate's own row
//! declarations (the `rows` module's field docs and the media write
//! face's constants) — this enum is their unified anchor, and the store
//! is the pure data face. `taiji-domain` already depends on
//! `taiji-store` (workspace dependency direction), so the reverse
//! placement would be a dependency cycle. Visibility today:
//! core/engine/bt/domain depend on `taiji-store` in production and see
//! this type as-is; taiji-media reaches it dev-only (its store edge is
//! a dev-dependency — the production assembly belongs to the media
//! orchestration crate), which is exactly what the cross-pin test
//! rides; a production-face use inside taiji-media (e.g. converting
//! against `MediaPhase` outside tests) would need a new,
//! topology-governed dependency edge.
//!
//! # Fold semantics (exactly the two ledger entries)
//!
//! The persisted row word is coarser than the engine's phase in exactly
//! two places, both registered in the ledger
//! (`docs/compat/aria2-v1-deviations.yaml`):
//! - **checking-fold**: the row word `checking` covers the pending and
//!   the in-flight recheck alike (the pre-war precedent; the row keeps
//!   `checking` through the check_pending FIFO stay — see the session
//!   actor's lifecycle comments);
//! - **seeding-fold**: the row word `seeding` covers seeding residence
//!   and seed_wait waiting alike (the `checking` precedent).
//!
//! The fine variants ([`TaskPhase::CheckingPending`] /
//! [`TaskPhase::CheckingInflight`], [`TaskPhase::SeedingResident`] /
//! [`TaskPhase::SeedingWait`]) exist so in-memory classification can be
//! expressed in the same vocabulary; they have **no row word of their
//! own** ([`as_v1_str`](TaskPhase::as_v1_str) folds them onto the coarse
//! word). The fold is lossy one way only: `parse_v1` of a folded row
//! word returns the coarse variant and cannot recover the sub-phase —
//! the row never recorded it. The invariant
//! `parse_v1(p.as_v1_str()) == p.coarse()` holds over all of
//! [`TaskPhase::ALL`] and is pinned by tests.
//!
//! # Parse policy ([`parse_v1`])
//!
//! Accepts exactly the 15-string union of the three declared domains,
//! byte for byte, case-sensitive. Unknown strings — including case
//! drift (`Paused`), true prefixes of a domain word (`check`), and the
//! online projection words (`active`/`waiting`/`complete`/`removed`,
//! which are `StatusKind` wire values, not row states) — are an
//! explicit error carrying the original string: a hand-edited row never
//! silently maps to a live phase. Family-blind: any family's string
//! parses (a `metadata` string
//! presented as an http row is the caller's validation problem, not the
//! vocabulary's — the family-limited entry point is deferred until a
//! real caller exists).
//!
//! # Vocabulary-caliber note (two tables, one domain set)
//!
//! The rpc governance table `STATUS_WORDS`
//! (`taiji-rpc/tests/rpc_boundary_guard.rs`) lists 14 of this module's
//! 15 strings; `error` is excluded there because it is aria2's own wire
//! word (outside the fork-extended vocabulary under governance), yet it
//! is a persisted terminal state of all three families and therefore a
//! member here. 15 = 14 + `error`.
//!
//! # Relationship to the existing types (B1 touches none of them)
//!
//! - `taiji_media::phase::MediaPhase` stays the single source of the
//!   `media_task.state` domain. `TaskPhase`'s media subset repeats the
//!   same ten strings without referencing taiji-media (the dependency
//!   direction forbids it); the single-source discipline is enforced by
//!   a cross-crate pin test landed in taiji-media (the one crate where
//!   both tables are in view).
//! - `StatusKind` (the online projection face) is untouched: its
//!   `active`/`waiting`/`complete`/`removed` words are projection
//!   words, not row states, and are rejected by `parse_v1`.
//! - The five state-set constants that once lived beside this enum (the
//!   three active sets in the `rows`/`write_media` modules, the http
//!   terminal set, the media guarded set) are **dissolved**: every
//!   write/read face now consumes the derivation face here —
//!   [`TaskPhase::active_words`] (family filter + terminal filter),
//!   [`TaskPhase::terminal_words`], [`TaskPhase::guarded_words`] —
//!   which reproduced each body exactly, word for word
//!   (9−2=7, 6−2=4, 10−2=8 active members; membership was pinned, the
//!   constants' declared-doc sequence was not — every consumer is an
//!   order-insensitive contains-check or IN-list), before the swap.
//!   The dissolution anchors are the frozen tables in this file's
//!   tests (the per-family domain lists plus the frozen emission
//!   orders), so the derivation cannot drift now that no constant
//!   body remains to compare against. The derivations add no bare
//!   word of their own: they walk [`TaskPhase::ALL`] × `applies_to` ×
//!   `is_terminal` / `is_guarded` × `as_v1_str` inside this
//!   (exempted) file.
//!
//! # Leak-baseline disposition
//!
//! The 15-string table lives in this module's production face as
//! exactly one bare literal per domain word (the grouped
//! [`as_v1_str`](TaskPhase::as_v1_str) arms; `parse_v1` derives from it
//! — there is no second literal table; 14 of the 15 are governed words,
//! the floor this API permits). At the B1 landing the rpc leak counter
//! was a purely lexical count with zero headroom, so this module alone
//! took it 125 → 139 red until a same-batch disposition landed. The
//! disposition that landed is the single-source-table exemption: the
//! guard's `CANONICAL_V1_TABLES` list (in the rpc crate's
//! `rpc_boundary_guard.rs` test) names this file, the whole table body
//! rides outside the counted face, and the baseline ratchets down as
//! the write faces migrate onto the derivation face (the five
//! state-set constants dissolved onto it — see the relationship note
//! above). Raising the baseline remains forbidden by the guard's own
//! module doc.
//!
//! # Variant line (no more, no fewer)
//!
//! Declared persisted domains ∪ the two ledger fold pairs. Excluded on
//! purpose: `planning` (http runtime-only phase, never enters the
//! persisted payload — it folds onto `probing`), the in-memory FIFO /
//! deferred flags (check_pending / seed_wait residence is *expressed* by
//! the fine variants; the flags themselves are not persisted
//! vocabulary), and every projection-only fold (active-covering,
//! waiting duals, numeric error codes) — the ledger has no fold entry
//! for them, and this enum mirrors the ledger.

/// The persisted task-state phase vocabulary, unified across the three
/// task families. Variant table order is the [`TaskPhase::ALL`] order;
/// a coarse variant precedes its fine siblings (the `parse_v1` scan
/// face relies on it, pinned by tests).
///
/// No `Default`: all three families share `Queued`, but no variant is a
/// natural "absence" value — a default would silently manufacture a
/// live bookkeeping state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskPhase {
    /// Three-family queued bookkeeping state: the torrent normal initial
    /// row and the restart flag's terminal landing, the http initial row
    /// and its one terminal exit (reopen), the media unpause exit
    /// (paused→queued). A magnet task's initial row is `metadata` or
    /// `queued` (the reserved-state decision at write time).
    Queued,
    /// Torrent magnet metadata phase (the pre-infohash residence);
    /// a magnet upgrade keeps the row state it finds (no drift).
    Metadata,
    /// Coarse checking phase — the parse target for the row word
    /// `checking` (the ledger checking-fold: the word covers pending and
    /// in-flight alike; the sub-phase is unrecoverable from the row).
    Checking,
    /// Fine: recheck admitted but budget-gated — parked in the
    /// check_pending FIFO, occupying no running slot. The row word stays
    /// `checking` (the fold's left element, with
    /// [`TaskPhase::CheckingInflight`]).
    CheckingPending,
    /// Fine: recheck in-flight — occupying a max-concurrent-checks slot.
    /// The row word stays `checking`; the online projection reads
    /// active-semantics for the in-flight leg.
    CheckingInflight,
    /// Declared-domain member (the torrent row doc and active-set
    /// constant both carry it) with no current producer in this tree —
    /// carried per the declared domain; removing it is a value-domain
    /// event (row docs, the rpc governance word list and this enum all
    /// move together), not a silent drop.
    Allocating,
    /// Three-family live download phase.
    Downloading,
    /// Coarse seeding phase — the parse target for the row word
    /// `seeding` (the ledger seeding-fold: the word covers residence and
    /// waiting alike). The recovery-side rewrite seeding→queued for
    /// progress-incomplete rows is a read-path behavior, not a
    /// vocabulary entry.
    Seeding,
    /// Fine: seeding resident — engine running, occupying a seed slot.
    /// Unified projection reports both residence and waiting as
    /// `seeding`.
    SeedingResident,
    /// Fine: seed_wait FIFO — content complete, waiting for a seed
    /// budget slot, occupying no running slot; under budget pressure the
    /// row is written `seeding` first, then the task stops gracefully.
    SeedingWait,
    /// Three-family pause bookkeeping state. Media pauses carry the
    /// interrupted phase in the `phase_detail` column (a column-level
    /// fact this enum deliberately does not model); media lists `paused`
    /// in BOTH the active read set and the upsert guard's refuse set.
    Paused,
    /// Terminal. All three families' terminal sets agree
    /// {`done`, `error`}; the only exit is the explicit reopen face.
    Error,
    /// Terminal, same contract as [`TaskPhase::Error`].
    Done,
    /// http probe phase. The runtime-only `planning` phase folds onto
    /// this word and never enters the persisted payload — hence no
    /// `Planning` variant.
    Probing,
    /// media resolve phase; the reopen exit (error|done→resolving, with
    /// the error fields cleared and the phase memory reset) lands here.
    Resolving,
    /// LIVE-only (0.4) phase, unreachable in the 0.3 pipeline — carried
    /// from day one so the persisted domain never widens later (the
    /// media mount's posture, mirrored here).
    Recording,
    /// media synthesis phase; pauses land with phase memory.
    Processing,
    /// media synthesis verification phase; pauses land with phase
    /// memory.
    Verifying,
    /// LIVE-only (0.4) graceful-stop finalization; pauses land with
    /// phase memory.
    Finalizing,
}

/// The persisted task family: which of the three `state` columns a
/// phase word belongs to ([`TaskPhase::applies_to`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskFamily {
    /// `torrent.state` (9 declared row words).
    Torrent,
    /// `http_task.state` (6 declared row words).
    Http,
    /// `media_task.state` (the full ten-state domain).
    Media,
}

/// [`parse_v1`](TaskPhase::parse_v1) failure: the input string is
/// outside the unified 15-string domain. The original value rides the
/// error so callers can report the exact offending row content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TaskPhaseError {
    /// Unknown persisted-state string (case drift, projection words,
    /// typos, empty input — anything not byte-equal to a domain word).
    #[error("task phase: unknown persisted state {value:?} (outside the unified domain)")]
    Unknown {
        /// The rejected input, verbatim.
        value: String,
    },
}

impl TaskPhase {
    /// The full variant set, table order (19 = the 15 distinct row
    /// words + the two ledger fold pairs' fine variants). A coarse
    /// variant precedes its fine siblings — the `parse_v1` scan face
    /// resolves a folded word to the coarse variant through this order.
    pub const ALL: [TaskPhase; 19] = [
        TaskPhase::Queued,
        TaskPhase::Metadata,
        TaskPhase::Checking,
        TaskPhase::CheckingPending,
        TaskPhase::CheckingInflight,
        TaskPhase::Allocating,
        TaskPhase::Downloading,
        TaskPhase::Seeding,
        TaskPhase::SeedingResident,
        TaskPhase::SeedingWait,
        TaskPhase::Paused,
        TaskPhase::Error,
        TaskPhase::Done,
        TaskPhase::Probing,
        TaskPhase::Resolving,
        TaskPhase::Recording,
        TaskPhase::Processing,
        TaskPhase::Verifying,
        TaskPhase::Finalizing,
    ];

    /// The persisted v1 row-state string. Exactly 15 distinct strings
    /// over the 19 variants: the checking fold emits one word for three
    /// variants, likewise the seeding fold — the grouped arms below are
    /// the single literal table for the whole vocabulary (see the
    /// module doc's leak-baseline note; `parse_v1` derives from this
    /// table, adding none of its own).
    pub fn as_v1_str(self) -> &'static str {
        match self {
            TaskPhase::Queued => "queued",
            TaskPhase::Metadata => "metadata",
            // The checking fold: one row word covers the pending and the
            // in-flight recheck alike (the ledger's checking-fold entry).
            TaskPhase::Checking | TaskPhase::CheckingPending | TaskPhase::CheckingInflight => {
                "checking"
            }
            TaskPhase::Allocating => "allocating",
            TaskPhase::Downloading => "downloading",
            // The seeding fold: one row word covers residence and
            // waiting alike (the ledger's seeding-fold entry, the
            // `checking` precedent).
            TaskPhase::Seeding | TaskPhase::SeedingResident | TaskPhase::SeedingWait => "seeding",
            TaskPhase::Paused => "paused",
            TaskPhase::Error => "error",
            TaskPhase::Done => "done",
            TaskPhase::Probing => "probing",
            TaskPhase::Resolving => "resolving",
            TaskPhase::Recording => "recording",
            TaskPhase::Processing => "processing",
            TaskPhase::Verifying => "verifying",
            TaskPhase::Finalizing => "finalizing",
        }
    }

    /// Parse a persisted v1 row-state string. Accepts exactly the
    /// 15-string union of the three declared domains, byte for byte,
    /// case-sensitive and family-blind; a folded word resolves to its
    /// coarse variant (the sub-phase is unrecoverable from the row).
    ///
    /// The scan walks [`Self::ALL`] against [`Self::as_v1_str`] — the
    /// single literal table — so the parse face cannot drift from the
    /// emission face; the coarse-before-fine table order is what routes
    /// `checking`/`seeding` to [`TaskPhase::Checking`] /
    /// [`TaskPhase::Seeding`] (pinned by tests).
    ///
    /// Unknown strings (including case drift and the `StatusKind`
    /// projection words) are [`TaskPhaseError::Unknown`] carrying the
    /// original input — a hand-edited row never silently maps to a live
    /// phase.
    pub fn parse_v1(s: &str) -> Result<TaskPhase, TaskPhaseError> {
        Self::ALL
            .into_iter()
            .find(|p| p.as_v1_str() == s)
            .ok_or_else(|| TaskPhaseError::Unknown {
                value: s.to_owned(),
            })
    }

    /// Normalize onto the coarse phase: the two ledger fold pairs map
    /// onto their coarse variants ([`TaskPhase::CheckingPending`] and
    /// [`TaskPhase::CheckingInflight`] → [`TaskPhase::Checking`];
    /// [`TaskPhase::SeedingResident`] and [`TaskPhase::SeedingWait`] →
    /// [`TaskPhase::Seeding`]); every other variant is its own coarse
    /// phase (the function is idempotent and the identity on coarse
    /// variants).
    pub fn coarse(self) -> TaskPhase {
        match self {
            TaskPhase::CheckingPending | TaskPhase::CheckingInflight => TaskPhase::Checking,
            TaskPhase::SeedingResident | TaskPhase::SeedingWait => TaskPhase::Seeding,
            other => other,
        }
    }

    /// The terminal phases ([`TaskPhase::Error`] and
    /// [`TaskPhase::Done`]). All three families' terminal sets agree
    /// {`done`, `error`} (the torrent terminal write face, the http
    /// terminal constant, the media schema pin); leaving a terminal
    /// state goes only through the explicit reopen faces.
    pub fn is_terminal(self) -> bool {
        matches!(self, TaskPhase::Error | TaskPhase::Done)
    }

    /// The guarded phases ([`TaskPhase::Paused`], [`TaskPhase::Error`],
    /// [`TaskPhase::Done`]) — the media upsert guard's refuse set, word
    /// body {`paused`, `error`, `done`} (once the guarded-state
    /// constant in write_media; the derivation face
    /// [`Self::guarded_words`] now owns it). Guarded is NOT terminal:
    /// a paused task is parked,
    /// not finished — the two terminal members are guarded AND
    /// terminal, `paused` is guarded only (it stays in the active read
    /// set because restart recovery resumes it; the deliberate
    /// double-listing is pinned by tests below). Leaving the guarded
    /// set goes only through the explicit faces (unpause paused→queued,
    /// reopen error|done→resolving).
    ///
    /// Family note: today only the media write face consumes a guarded
    /// word set, but the classification itself is family-blind
    /// vocabulary — `paused` parks the same way in all three families
    /// — so the predicate carries no family parameter and
    /// [`Self::guarded_words`] derives from it without per-family arms.
    pub fn is_guarded(self) -> bool {
        matches!(self, TaskPhase::Paused | TaskPhase::Error | TaskPhase::Done)
    }

    /// Does this phase word belong to the family's declared value
    /// domain? (Torrent 9, http 6, media 10 row words; the shared words
    /// — queued/downloading/paused/error/done — belong to all three.)
    pub fn applies_to(self, family: TaskFamily) -> bool {
        match family {
            TaskFamily::Torrent => matches!(
                self,
                TaskPhase::Queued
                    | TaskPhase::Metadata
                    | TaskPhase::Checking
                    | TaskPhase::CheckingPending
                    | TaskPhase::CheckingInflight
                    | TaskPhase::Allocating
                    | TaskPhase::Downloading
                    | TaskPhase::Seeding
                    | TaskPhase::SeedingResident
                    | TaskPhase::SeedingWait
                    | TaskPhase::Paused
                    | TaskPhase::Error
                    | TaskPhase::Done
            ),
            TaskFamily::Http => matches!(
                self,
                TaskPhase::Queued
                    | TaskPhase::Probing
                    | TaskPhase::Downloading
                    | TaskPhase::Paused
                    | TaskPhase::Error
                    | TaskPhase::Done
            ),
            TaskFamily::Media => matches!(
                self,
                TaskPhase::Queued
                    | TaskPhase::Resolving
                    | TaskPhase::Downloading
                    | TaskPhase::Recording
                    | TaskPhase::Processing
                    | TaskPhase::Verifying
                    | TaskPhase::Finalizing
                    | TaskPhase::Paused
                    | TaskPhase::Error
                    | TaskPhase::Done
            ),
        }
    }

    /// Shared derivation walk behind the word-set faces:
    /// [`Self::ALL`] in table order → `keep` filter → [`Self::as_v1_str`]
    /// → first occurrence kept (the checking/seeding fold groups emit
    /// their one row word once each). Zero bare words in any derivation
    /// body — every string below this line comes from the
    /// [`Self::as_v1_str`] table — so the whole derivation face rides
    /// this file's canonical-table exemption and never widens the leak
    /// baseline.
    fn words_matching(keep: impl Fn(TaskPhase) -> bool) -> Vec<&'static str> {
        let mut words: Vec<&'static str> = Vec::new();
        for phase in Self::ALL {
            if !keep(phase) {
                continue;
            }
            let word = phase.as_v1_str();
            if !words.contains(&word) {
                words.push(word);
            }
        }
        words
    }

    /// The family's active-state words: every non-terminal member of
    /// the family's declared domain (family filter + terminal filter),
    /// emitted in [`Self::ALL`] table order (torrent 9−2=7, http 6−2=4,
    /// media 10−2=8 members). Pinned word for word — as a SET — against
    /// the frozen active-set tables in the tests below (the anchors
    /// that stood as the write-face constants before their
    /// dissolution), so the derivation cannot drift. The frozen tables
    /// spell each family's declared doc order (the http and media
    /// bodies are lifecycle-ordered), the derivation emits ALL-table
    /// order; membership is what is pinned, not sequence — every
    /// consumer (startup recovery IN-lists, path-conflict probes,
    /// guard contains-checks) is order-insensitive.
    pub fn active_words(family: TaskFamily) -> Vec<&'static str> {
        Self::words_matching(|phase| phase.applies_to(family) && !phase.is_terminal())
    }

    /// The terminal-state words {`error`, `done`}: derivation =
    /// [`Self::ALL`] filtered by [`Self::is_terminal`]. All three
    /// families' terminal sets agree; returned in ALL order (`error`
    /// precedes `done`; set-equal, and the consumers are
    /// contains-checks and IN-lists, both order-insensitive).
    pub fn terminal_words() -> Vec<&'static str> {
        Self::words_matching(Self::is_terminal)
    }

    /// The guarded-state words {`paused`, `error`, `done`}: derivation =
    /// [`Self::ALL`] filtered by [`Self::is_guarded`] (the terminals
    /// plus `paused`) — the media upsert guard's refuse set, word set
    /// AND order (the ALL walk visits Paused, then Error, then Done).
    /// The paused double-listing (active AND guarded) survives the
    /// derivation because `active_words` never filters on `is_guarded`.
    pub fn guarded_words() -> Vec<&'static str> {
        Self::words_matching(Self::is_guarded)
    }
}

#[cfg(test)]
mod tests {
    use super::{TaskFamily, TaskPhase, TaskPhaseError};
    use std::collections::HashSet;

    /// The frozen 15-string union of the three declared domains, sorted.
    const FROZEN_V1_DOMAIN: &[&str] = &[
        "allocating",
        "checking",
        "done",
        "downloading",
        "error",
        "finalizing",
        "metadata",
        "paused",
        "processing",
        "probing",
        "queued",
        "recording",
        "resolving",
        "seeding",
        "verifying",
    ];

    /// Sorted family faces of the declared domains (torrent 9 / http 6 /
    /// media 10 — the row-doc declarations this enum unifies).
    const FROZEN_TORRENT: &[&str] = &[
        "allocating",
        "checking",
        "done",
        "downloading",
        "error",
        "metadata",
        "paused",
        "queued",
        "seeding",
    ];
    const FROZEN_HTTP: &[&str] = &[
        "done",
        "downloading",
        "error",
        "paused",
        "probing",
        "queued",
    ];
    const FROZEN_MEDIA: &[&str] = &[
        "done",
        "downloading",
        "error",
        "finalizing",
        "paused",
        "processing",
        "queued",
        "recording",
        "resolving",
        "verifying",
    ];

    /// Sorted distinct `as_v1_str` outputs over [`TaskPhase::ALL`].
    fn sorted_v1_strings() -> Vec<&'static str> {
        let mut v: Vec<&str> = TaskPhase::ALL
            .into_iter()
            .map(TaskPhase::as_v1_str)
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// Sorted family-filtered row words (terminal included).
    fn sorted_family_strings(family: TaskFamily) -> Vec<&'static str> {
        let mut v: Vec<&str> = TaskPhase::ALL
            .into_iter()
            .filter(|p| p.applies_to(family))
            .map(TaskPhase::as_v1_str)
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// Sorted family-filtered row words minus the terminals.
    fn sorted_family_active_strings(family: TaskFamily) -> Vec<&'static str> {
        let mut v: Vec<&str> = TaskPhase::ALL
            .into_iter()
            .filter(|p| p.applies_to(family) && !p.is_terminal())
            .map(TaskPhase::as_v1_str)
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// The expected active-set body for a family, anchored on the
    /// frozen domain list (the state-set constants the derivation face
    /// replaced are gone; the frozen tables here are the dissolution
    /// anchors — family domain minus the two terminal words).
    fn frozen_family_active(family: TaskFamily) -> Vec<&'static str> {
        let domain: &[&str] = match family {
            TaskFamily::Torrent => FROZEN_TORRENT,
            TaskFamily::Http => FROZEN_HTTP,
            TaskFamily::Media => FROZEN_MEDIA,
        };
        let terminal = TaskPhase::terminal_words();
        let mut v: Vec<&str> = domain.to_vec();
        v.retain(|w| !terminal.contains(w));
        v
    }

    fn sorted<'a>(words: &[&'a str]) -> Vec<&'a str> {
        let mut v = words.to_vec();
        v.sort_unstable();
        v
    }

    /// Variant-count pin + the frozen 15-string emission table: 19
    /// variants (the 15 row words + the two fold pairs' fine variants),
    /// every emission inside the frozen domain, nothing else emitted.
    #[test]
    fn variant_count_and_v1_string_table_are_frozen() {
        assert_eq!(
            TaskPhase::ALL.len(),
            19,
            "19 = 15 distinct row words + 2 checking fold variants + 2 seeding fold \
             variants; changing this count is a value-domain event"
        );
        assert_eq!(
            sorted_v1_strings(),
            sorted(FROZEN_V1_DOMAIN),
            "the emission face must be exactly the frozen 15-string union"
        );
    }

    /// Per-variant identity pins (review finding: the set-level pins
    /// above cannot see a same-class swap). Two faces, both driven
    /// variant by variant:
    /// - the (variant, row word) pairs fix the emission face member for
    ///   member — swapping two same-family words (Queued↔Downloading,
    ///   Resolving↔Processing) or re-pointing any arm fails here even
    ///   though every set-level comparison still passes;
    /// - the pair table's variant set == [`TaskPhase::ALL`] as a set
    ///   (deduplicated, both length 19) pins ALL's "full variant set"
    ///   promise: a duplicated member (SeedingWait → a second Seeding)
    ///   keeps the length, the emission set and even the per-word
    ///   producer counts, and only the set identity catches it.
    #[test]
    fn variant_string_pairs_and_all_membership_are_pinned_per_variant() {
        const PAIRS: [(TaskPhase, &str); 19] = [
            (TaskPhase::Queued, "queued"),
            (TaskPhase::Metadata, "metadata"),
            (TaskPhase::Checking, "checking"),
            (TaskPhase::CheckingPending, "checking"),
            (TaskPhase::CheckingInflight, "checking"),
            (TaskPhase::Allocating, "allocating"),
            (TaskPhase::Downloading, "downloading"),
            (TaskPhase::Seeding, "seeding"),
            (TaskPhase::SeedingResident, "seeding"),
            (TaskPhase::SeedingWait, "seeding"),
            (TaskPhase::Paused, "paused"),
            (TaskPhase::Error, "error"),
            (TaskPhase::Done, "done"),
            (TaskPhase::Probing, "probing"),
            (TaskPhase::Resolving, "resolving"),
            (TaskPhase::Recording, "recording"),
            (TaskPhase::Processing, "processing"),
            (TaskPhase::Verifying, "verifying"),
            (TaskPhase::Finalizing, "finalizing"),
        ];
        for (variant, word) in PAIRS {
            assert_eq!(
                variant.as_v1_str(),
                word,
                "{:?} must emit {word} (the variant-word identity, not just set membership)",
                variant
            );
            let occurrences = TaskPhase::ALL.into_iter().filter(|q| *q == variant).count();
            assert_eq!(
                occurrences, 1,
                "{:?} must appear in ALL exactly once (no dropped, no duplicated member)",
                variant
            );
        }
        // Set identity both ways: ALL has no unlisted member and no
        // duplicate (a duplicate shrinks the deduplicated set below 19
        // even though ALL.len() and the emission set stay unchanged).
        let all_set: HashSet<TaskPhase> = TaskPhase::ALL.into_iter().collect();
        let table_set: HashSet<TaskPhase> = PAIRS.iter().map(|(v, _)| *v).collect();
        assert_eq!(all_set.len(), 19, "ALL must have 19 distinct members");
        assert_eq!(
            all_set, table_set,
            "the pin table and ALL must be the same member set"
        );
    }

    /// Per-variant family membership pins (review finding: the family
    /// filter tests compare deduped word sets, so deleting a fold-group
    /// member from `applies_to` — the coarse Checking/Seeding lines
    /// among them — left every set-level comparison green, silently
    /// stripping the coarse variants of their family qualification).
    /// The table fixes each variant's (torrent, http, media) membership
    /// triple member for member; the set identity closes the table
    /// against ALL (no unlisted variant, none missing).
    #[test]
    fn family_membership_is_pinned_per_variant() {
        const FAMILIES: [(TaskPhase, bool, bool, bool); 19] = [
            (TaskPhase::Queued, true, true, true),
            (TaskPhase::Metadata, true, false, false),
            // The fold group rides the torrent family as three full
            // members — the coarse variants included.
            (TaskPhase::Checking, true, false, false),
            (TaskPhase::CheckingPending, true, false, false),
            (TaskPhase::CheckingInflight, true, false, false),
            (TaskPhase::Allocating, true, false, false),
            (TaskPhase::Downloading, true, true, true),
            (TaskPhase::Seeding, true, false, false),
            (TaskPhase::SeedingResident, true, false, false),
            (TaskPhase::SeedingWait, true, false, false),
            (TaskPhase::Paused, true, true, true),
            (TaskPhase::Error, true, true, true),
            (TaskPhase::Done, true, true, true),
            (TaskPhase::Probing, false, true, false),
            (TaskPhase::Resolving, false, false, true),
            (TaskPhase::Recording, false, false, true),
            (TaskPhase::Processing, false, false, true),
            (TaskPhase::Verifying, false, false, true),
            (TaskPhase::Finalizing, false, false, true),
        ];
        for (variant, torrent, http, media) in FAMILIES {
            assert_eq!(
                variant.applies_to(TaskFamily::Torrent),
                torrent,
                "{:?} torrent membership",
                variant
            );
            assert_eq!(
                variant.applies_to(TaskFamily::Http),
                http,
                "{:?} http membership",
                variant
            );
            assert_eq!(
                variant.applies_to(TaskFamily::Media),
                media,
                "{:?} media membership",
                variant
            );
        }
        let all_set: HashSet<TaskPhase> = TaskPhase::ALL.into_iter().collect();
        let table_set: HashSet<TaskPhase> = FAMILIES.iter().map(|(v, _, _, _)| *v).collect();
        assert_eq!(
            all_set, table_set,
            "the family table must cover ALL exactly (no unlisted variant, none missing)"
        );
    }

    /// Per-variant round-trip through the coarse phase — the parse
    /// invariant `parse_v1(p.as_v1_str()) == p.coarse()` over ALL of
    /// [`TaskPhase::ALL`]: a coarse variant round-trips to itself, a
    /// fine variant round-trips to its coarse variant (the fold is
    /// lossy exactly one way).
    #[test]
    fn every_variant_round_trips_through_its_coarse_phase() {
        for p in TaskPhase::ALL {
            assert_eq!(
                TaskPhase::parse_v1(p.as_v1_str()).ok(),
                Some(p.coarse()),
                "round-trip failed for {:?} (row word {})",
                p,
                p.as_v1_str()
            );
        }
        // The coarse variants themselves are fixed points.
        for p in [TaskPhase::Checking, TaskPhase::Seeding] {
            assert_eq!(TaskPhase::parse_v1(p.as_v1_str()).ok(), Some(p));
            assert_eq!(p.coarse(), p, "coarse is the identity on {:?}", p);
        }
    }

    /// The fold rules, pinned entry for entry against the ledger's
    /// exactly-two fold entries: checking-fold (pending + in-flight →
    /// the one row word) and seeding-fold (residence + waiting → the
    /// one row word); no other word has more than one producing
    /// variant, and `coarse` maps exactly the fold pairs.
    #[test]
    fn fold_rules_are_pinned_two_entries_exactly() {
        // checking-fold: all three variants emit the same row word.
        for p in [
            TaskPhase::Checking,
            TaskPhase::CheckingPending,
            TaskPhase::CheckingInflight,
        ] {
            assert_eq!(p.as_v1_str(), "checking", "{:?} rides the fold", p);
            assert_eq!(p.coarse(), TaskPhase::Checking, "{:?}", p);
        }
        // seeding-fold: likewise.
        for p in [
            TaskPhase::Seeding,
            TaskPhase::SeedingResident,
            TaskPhase::SeedingWait,
        ] {
            assert_eq!(p.as_v1_str(), "seeding", "{:?} rides the fold", p);
            assert_eq!(p.coarse(), TaskPhase::Seeding, "{:?}", p);
        }
        // No third fold: every other row word has exactly one producing
        // variant (13 words x 1 + 2 words x 3 = 19).
        for word in FROZEN_V1_DOMAIN {
            let producers = TaskPhase::ALL
                .into_iter()
                .filter(|p| p.as_v1_str() == *word)
                .count();
            let want = match *word {
                "checking" | "seeding" => 3,
                _ => 1,
            };
            assert_eq!(
                producers, want,
                "row word {word} must have exactly {want} producing variant(s)"
            );
        }
        // coarse is idempotent over the whole table.
        for p in TaskPhase::ALL {
            assert_eq!(p.coarse().coarse(), p.coarse(), "{:?}", p);
        }
    }

    /// Unknown strings are rejected with the original value carried:
    /// case drift, the StatusKind projection words (they are online
    /// projection words, not row states), runtime-only phase names,
    /// FIFO names, empty and padded input. The words that are BOTH row
    /// states and StatusKind wire values (`paused`/`seeding`/`checking`
    /// /`error`) must keep parsing.
    #[test]
    fn unknown_and_projection_strings_are_rejected_with_the_original_value() {
        for bad in [
            "Paused",
            "QUEUED",
            "Metadata",
            "checking ",
            "",
            "active",
            "waiting",
            "complete",
            "removed",
            "planning",
            "check_pending",
            "seed_wait",
            "allocating\n",
        ] {
            let err = match TaskPhase::parse_v1(bad) {
                Ok(p) => panic!("must not parse: {bad:?} -> {:?}", p),
                Err(e) => e,
            };
            assert_eq!(
                err,
                TaskPhaseError::Unknown {
                    value: bad.to_owned()
                },
                "the error must carry the original input {bad:?}"
            );
        }
        // Row states that double as StatusKind wire words stay accepted.
        for (word, want) in [
            ("paused", TaskPhase::Paused),
            ("seeding", TaskPhase::Seeding),
            ("checking", TaskPhase::Checking),
            ("error", TaskPhase::Error),
        ] {
            assert_eq!(TaskPhase::parse_v1(word).ok(), Some(want));
        }
    }

    /// parse is family-blind: every family's declared words parse from
    /// any context (family restriction is the caller's / a later
    /// phase's duty, not the vocabulary's).
    #[test]
    fn parse_v1_is_family_blind() {
        assert_eq!(
            TaskPhase::parse_v1("metadata").ok(),
            Some(TaskPhase::Metadata),
            "a torrent-only word parses"
        );
        assert_eq!(
            TaskPhase::parse_v1("probing").ok(),
            Some(TaskPhase::Probing),
            "an http-only word parses"
        );
        assert_eq!(
            TaskPhase::parse_v1("recording").ok(),
            Some(TaskPhase::Recording),
            "a media-only word parses"
        );
    }

    /// The acceptance face is full-word byte equality, not prefix
    /// matching: a true prefix of a domain word (`check`, `q`, `do`, …)
    /// is an unknown string. This pins the half of the "byte for byte"
    /// contract the round-trip tests cannot — weakening `parse_v1`'s
    /// comparison to a `starts_with` form keeps every round-trip green
    /// (the round-trip only ever feeds full words) and must fail HERE.
    #[test]
    fn true_prefixes_of_domain_words_are_rejected() {
        for bad in [
            "check", "checkin", "q", "qu", "do", "don", "seed", "meta", "paus", "down", "pro",
            "reso", "rec", "proc", "ver", "fin", "allo", "err",
        ] {
            assert!(
                TaskPhase::parse_v1(bad).is_err(),
                "a true prefix of a domain word must not parse: {bad:?}"
            );
        }
        // The full words themselves still parse (the prefix set above is
        // drawn from exactly these domains).
        for good in ["checking", "queued", "done", "seeding"] {
            assert!(
                TaskPhase::parse_v1(good).is_ok(),
                "the full word must keep parsing: {good:?}"
            );
        }
    }

    /// The family filters reproduce the three declared domains exactly
    /// (9/6/10), and — the derivation face the write/read consumers
    /// rely on — family filter + terminal filter reproduces the three
    /// active-set bodies member for member (9−2=7, 6−2=4, 10−2=8;
    /// the frozen tables here are the anchors since the write-face
    /// constants dissolved).
    #[test]
    fn family_filters_reproduce_the_declared_domains_and_active_sets() {
        // Declared domains.
        assert_eq!(
            sorted_family_strings(TaskFamily::Torrent),
            sorted(FROZEN_TORRENT)
        );
        assert_eq!(sorted_family_strings(TaskFamily::Http), sorted(FROZEN_HTTP));
        assert_eq!(
            sorted_family_strings(TaskFamily::Media),
            sorted(FROZEN_MEDIA)
        );
        // Active sets: family filter + non-terminal filter == the
        // frozen bodies (family domain minus the two terminals).
        assert_eq!(
            sorted_family_active_strings(TaskFamily::Torrent),
            sorted(&frozen_family_active(TaskFamily::Torrent)),
            "torrent: 9 declared words - 2 terminals = the 7-member active set"
        );
        assert_eq!(
            sorted_family_active_strings(TaskFamily::Http),
            sorted(&frozen_family_active(TaskFamily::Http)),
            "http: 6 declared words - 2 terminals = the 4-member active set"
        );
        assert_eq!(
            sorted_family_active_strings(TaskFamily::Media),
            sorted(&frozen_family_active(TaskFamily::Media)),
            "media: 10 declared words - 2 terminals = the 8-member active set"
        );
    }

    /// Terminal classification: exactly Error|Done, agreeing with the
    /// per-family filter view and the guarded derivation's terminal
    /// members; `paused` deliberately double-lists on the media face
    /// (active AND guarded) — pinned here so the derivation face keeps
    /// that shape.
    #[test]
    fn terminal_classification_matches_the_write_faces() {
        for p in TaskPhase::ALL {
            assert_eq!(
                p.is_terminal(),
                matches!(p, TaskPhase::Error | TaskPhase::Done),
                "{:?}",
                p
            );
        }
        // The family-filter view and the classification view agree: the
        // http family's terminal members (family filter + terminal
        // retain) == the terminal derivation, and the frozen terminal
        // body is exactly the two words.
        let terminal = TaskPhase::terminal_words();
        let mut derived_terminals = sorted_family_strings(TaskFamily::Http);
        derived_terminals.retain(|w| terminal.contains(w));
        let mut frozen_terminal = vec!["done", "error"];
        frozen_terminal.sort_unstable();
        assert_eq!(
            derived_terminals,
            sorted(&terminal),
            "the http family's terminal members == the terminal derivation"
        );
        assert_eq!(
            sorted(&terminal),
            frozen_terminal,
            "the terminal body is exactly {{done, error}}"
        );
        // The media guarded derivation = terminals + paused (the
        // deliberate double listing of paused: active because restart
        // recovery resumes it, guarded because the teardown row must
        // survive a late detached phase write). Derived from the full
        // media domain, not the active set — the terminals are exactly
        // what the active set excludes.
        let mut derived_guarded = sorted_family_strings(TaskFamily::Media);
        derived_guarded.retain(|w| terminal.contains(w));
        derived_guarded.push("paused");
        derived_guarded.sort_unstable();
        assert_eq!(
            derived_guarded,
            sorted(&TaskPhase::guarded_words()),
            "media guarded = the family terminals + paused"
        );
    }

    /// The public derivation face vs the frozen active-set bodies,
    /// WORD FOR WORD — the complement of the sorted-set pin above: that
    /// pin rides a test-local reimplementation of the filter chain,
    /// this one exercises the production face the write consumers
    /// actually call, so a drift between the two fails here even when
    /// the local helper still agrees. Membership is pinned as a set
    /// against the frozen tables (the write-face constants the
    /// derivation replaced are dissolved; these arrays are the
    /// standing anchors). The derived sequences are separately frozen
    /// below as the documented emission order (a reorder of ALL
    /// silently reshaping the IN-lists deserves a red test, not a
    /// shrug).
    #[test]
    fn active_words_derivation_is_frozen_word_for_word() {
        let torrent = TaskPhase::active_words(TaskFamily::Torrent);
        let http = TaskPhase::active_words(TaskFamily::Http);
        let media = TaskPhase::active_words(TaskFamily::Media);
        // Word-for-word membership against the frozen bodies.
        assert_eq!(
            sorted(&torrent),
            sorted(&frozen_family_active(TaskFamily::Torrent)),
            "torrent: the 7-member body, fold words once each"
        );
        assert_eq!(
            sorted(&http),
            sorted(&frozen_family_active(TaskFamily::Http)),
            "http: the 4-member body"
        );
        assert_eq!(
            sorted(&media),
            sorted(&frozen_family_active(TaskFamily::Media)),
            "media: the 8-member body"
        );
        // Member counts as independent pins (a frozen-body edit that
        // keeps set equality but changes the count cannot slip through).
        assert_eq!(torrent.len(), 7, "torrent: 9 declared - 2 terminals");
        assert_eq!(http.len(), 4, "http: 6 declared - 2 terminals");
        assert_eq!(media.len(), 8, "media: 10 declared - 2 terminals");
        // Fold collapse: the checking/seeding groups contribute their one
        // row word exactly once each (no duplicates anywhere).
        for words in [&torrent, &http, &media] {
            let mut uniq = words.to_vec();
            uniq.sort_unstable();
            uniq.dedup();
            assert_eq!(uniq.len(), words.len(), "no folded duplicate: {words:?}");
        }
        // The frozen emission order (ALL-table walk, first occurrence
        // kept). Torrent happens to coincide with its frozen body's
        // sorted-ish spelling; http/media do not — both facts are
        // pinned as-is.
        assert_eq!(
            torrent,
            [
                "queued",
                "metadata",
                "checking",
                "allocating",
                "downloading",
                "seeding",
                "paused",
            ]
        );
        assert_eq!(http, ["queued", "downloading", "paused", "probing"]);
        assert_eq!(
            media,
            [
                "queued",
                "downloading",
                "paused",
                "resolving",
                "recording",
                "processing",
                "verifying",
                "finalizing",
            ]
        );
    }

    /// terminal/guarded derivations vs the frozen bodies: terminal ==
    /// {`done`, `error`} (set-equal; the ALL walk emits `error` first —
    /// consumers are contains-checks/IN-lists, order-insensitive),
    /// guarded == {`paused`, `error`, `done`} WORD FOR WORD in ALL-table
    /// order, guarded == terminal ∪ {`paused`}, and the paused
    /// double-listing (active AND guarded on the media face) belongs to
    /// `paused` alone.
    #[test]
    fn terminal_and_guarded_words_match_the_write_face_bodies() {
        let terminal = TaskPhase::terminal_words();
        let guarded = TaskPhase::guarded_words();
        // Terminal: set-pinned against the frozen two-word body.
        assert_eq!(terminal.len(), 2, "exactly the two terminal words");
        let mut frozen_terminal = vec!["done", "error"];
        frozen_terminal.sort_unstable();
        assert_eq!(
            sorted(&terminal),
            frozen_terminal,
            "terminal set == {{done, error}}"
        );
        // Guarded: the frozen refuse-set body, order included.
        assert_eq!(
            guarded,
            ["paused", "error", "done"],
            "guarded == {{paused, error, done}}, ALL-table order"
        );
        // Algebra: guarded = terminal + paused (the double listing).
        let mut terminal_plus_paused = terminal.clone();
        terminal_plus_paused.push("paused");
        terminal_plus_paused.sort_unstable();
        assert_eq!(
            sorted(&guarded),
            terminal_plus_paused,
            "guarded == terminal ∪ {{paused}}"
        );
        // The double listing is paused's alone: within the media family,
        // every guarded member sits in the active set exactly when it is
        // `paused` (restart recovery resumes it; error/done are excluded
        // from the active read face).
        let media_active = TaskPhase::active_words(TaskFamily::Media);
        for word in &guarded {
            assert_eq!(
                media_active.contains(word),
                *word == "paused",
                "only paused double-lists (active AND guarded): {word}"
            );
        }
    }

    /// Per-variant guarded classification (the same per-variant caliber
    /// as the family membership pin): `is_guarded` == Paused|Error|Done
    /// over the whole table, and `is_guarded` == `is_terminal` || Paused
    /// — the classification algebra [`TaskPhase::guarded_words`] and
    /// [`TaskPhase::active_words`] ride, so a re-pointed predicate arm
    /// fails here even when the word-set comparisons above still pass.
    #[test]
    fn guarded_classification_is_pinned_per_variant() {
        for phase in TaskPhase::ALL {
            assert_eq!(
                phase.is_guarded(),
                matches!(
                    phase,
                    TaskPhase::Paused | TaskPhase::Error | TaskPhase::Done
                ),
                "guarded body pin for {phase:?}"
            );
            assert_eq!(
                phase.is_guarded(),
                phase.is_terminal() || phase == TaskPhase::Paused,
                "guarded == terminal || paused for {phase:?}"
            );
        }
    }
}
