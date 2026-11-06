//! `taiji-core` — the orchestration layer (SPEC §3.2, §7).
//!
//! Responsibilities:
//! - SessionActor: queue scheduling (FIFO + max-concurrent), GID
//! allocation (top bit set), task lifecycle command entry, the
//! DownloadResult table, global-config ArcSwap hot updates;
//! - TorrentTask: the single-torrent orchestration state machine
//! (Queued -> MetadataPending -> Checking -> Allocating -> Downloading
//! <=> Seeding);
//! - the event bus (six events aligned with aria2 notifications) and
//! hook execution;
//! - rate limiting and statistics (a direct translation of the SpeedCalc
//! 10s sliding window);
//! - the migration importer (read-only aria2 fork sqlite / `.aria2`).
//!
//! Status: scaffolding. Implementation tasks live in `docs/`; the actor
//! concurrency discipline is in SPEC §2.5 (across actors pass only
//! messages/`Bytes`; locks must not be held across `await`; unbounded
//! channels are banned).
//!
//! Dependency direction: may depend on `taiji-bt` / `taiji-store` /
//! `taiji-io` / `taiji-domain` (the shared vocabulary layer) /
//! `taiji-engine` (the execution layer, below this crate — engine must
//! not depend back on core).

/// Seed-creation exposure shared facade: an explicit on-disk path ->
/// bt::creator generation -> the .torrent written to disk (the shared
/// parameter face of RPC `taiji.createTorrent` / CLI `create-torrent`;
/// the normalized entry point for taiji.* error semantics).
pub mod create;

/// The engine execution layer (DownloadEngine) — the implementation
/// lives in the `taiji-engine` crate (dependency direction core ->
/// engine; engine must not reference back to core, enforced by Cargo).
/// The whole crate is re-exported under an alias:
/// `taiji_core::engine::*` / `crate::engine::*` — every existing public
/// path unchanged (the subtree moved out of core).
pub use taiji_io::redact;

pub use taiji_engine as engine;

pub mod gid;
pub use taiji_domain::hash_fetch;
pub use taiji_domain::hash_source;

/// Hook subset execution model (SPEC §7.4; corrections in the module
/// doc — the reference passes argv, util.cc, with no placeholder
/// substitution).
pub use taiji_domain::hook;
pub mod magnet;
pub use taiji_domain::metainfo;

/// NAT assembly (SPEC §3.2 single-instance NatActor + §6.8): a
/// single-instance supervisor + the engine consumption face + external
/// port watching.
pub use taiji_domain::nat;

/// Peer ban accounting + eMule blocklist import orchestration (SPEC
/// §13).
pub use taiji_domain::peer_guard;
pub use taiji_domain::progress;

/// Peer redial pool (libtorrent min_reconnect_time semantics; see the
/// module doc).
pub use taiji_domain::redial;

pub use taiji_domain::seed;
pub mod session;
/// The silent-abandon failure ledger for endpoints (libtorrent
/// max_failcount/failcount semantics; see the module doc).
pub use taiji_domain::silent;
pub mod torrent;

/// Lock-poisoning policy (batch-wide decision): a poisoned `std::sync::Mutex`
/// means a panic happened mid-critical-section and an invariant may be lost —
/// recovery via `into_inner` is not permitted. The `expect` is fatal by
/// policy: the process teardown is carried to its terminal state by the
/// existing panic-watcher, so failing loudly here is the intended behavior.
///
/// All non-test lock acquisitions in this crate must go through this helper.
#[expect(
    clippy::expect_used,
    reason = "lock poisoning is fatal by policy; terminal state handled by the panic-watcher"
)]
pub(crate) fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock()
        .expect("lock poisoned: invariant lost, fail loudly")
}

/// Engine version (semver).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The full version string returned by RPC `getVersion` (SPEC §8.2:
/// Motrix recognizes the dual engines by the `taiji/` prefix; this
/// format is a frozen compatibility face and must not be changed).
pub fn version_string() -> String {
    format!("taiji/{VERSION}")
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_string_uses_frozen_prefix() {
        let s = super::version_string();
        assert!(s.starts_with("taiji/"), "frozen prefix violated: {s}");
    }

    /// Lock policy pin: a poisoned mutex is fatal — the helper must not
    /// recover the inner value (`into_inner`); it panics, and the
    /// panic-watcher owns the terminal state from there.
    #[test]
    #[should_panic(expected = "lock poisoned: invariant lost")]
    fn poisoned_lock_is_fatal_by_policy() {
        let m = std::sync::Arc::new(std::sync::Mutex::new(0u32));
        let poisoner = std::sync::Arc::clone(&m);
        // Poison: panic while holding the guard. The join error is the
        // poisoning thread's expected outcome, not the assertion.
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.lock().unwrap_or_else(|e| e.into_inner());
            panic!("poisoning thread");
        })
        .join();
        assert!(m.is_poisoned(), "precondition: the mutex must be poisoned");
        let _guard = super::lock(&m);
    }
}

/// A repo-wide governance sweep of `unused_imports` allow attributes:
/// scans workspace `crates/*/src` production code (excluding `tests`
/// directories — test code may keep a local exemption; whether its
/// imports are self-sustaining is not dependency-edge evidence) and
/// asserts the suppression-attribute count == 0.
///
/// Invariant: dead imports are deleted outright; names consumed only by
/// doc intra-doc links are rewritten as fully qualified paths (e.g.
/// `[`wire::MAX_PEER_RECORD_KEYS`]); names consumed only by tests via
/// glob are imported by the tests themselves — an allow suppression
/// masks a real dependency edge, and glob consumption is already
/// witnessed by unused_imports in the lib build, so the suppression has
/// no reason to exist. The exemption list takes only exceptions with a
/// written reason, and an entry must point at a real file (guards
/// against stale entries). This module is inside its own scan face:
/// NEEDLE is assembled via concat! and the doc wording avoids the
/// matched substring, so this file contains no violating literal (the
/// self-scan must not go false-red).
#[cfg(test)]
mod allow_lint_sweep {
    /// The exemption list (paths relative to the workspace root).
    /// Currently empty: all remnants (5 in session/actor/mod.rs, 18 in
    /// dht/engine/mod.rs) were cleared per the invariants above. New
    /// entries need a reason and a removal plan; asymptomatic
    /// accumulation is not allowed.
    const EXEMPT: &[&str] = &[];

    /// Scan file-count floor: below this, directory-layout drift has
    /// distorted the scan face (an idling walk makes the assertion
    /// vacuously true); fix the paths before governing.
    const MIN_SCANNED_FILES: usize = 200;

    /// The matched substring (not whole-word): covers the single-lint
    /// form, the multi-lint combined form, and inner attributes (the #!
    /// whole-file suppression form, the most important to catch).
    /// concat! assembly prevents this file from self-matching.
    const NEEDLE: &str = concat!("allow(", "unused_imports");

    #[test]
    fn no_unused_import_allow_in_production_code() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace = manifest_dir.join("..").join("..");
        let crates_dir = workspace.join("crates");

        let mut scanned = 0usize;
        let mut offenders: Vec<String> = Vec::new();
        let crates = match std::fs::read_dir(&crates_dir) {
            Ok(c) => c,
            Err(e) => panic!("failed to read crates dir {}: {e}", crates_dir.display()),
        };
        for entry in crates.flatten() {
            let src = entry.path().join("src");
            if !src.is_dir() {
                continue;
            }
            walk_rs(&src, &mut scanned, &mut offenders);
        }

        assert!(
            scanned >= MIN_SCANNED_FILES,
            "scan surface distorted: only {scanned} .rs files (floor {MIN_SCANNED_FILES}); did the directory layout drift?"
        );
        for path in EXEMPT {
            assert!(
                workspace.join(path).is_file(),
                "exempt entry points at a nonexistent file (stale entries must be removed): {path}"
            );
        }
        let exempted = |p: &str| EXEMPT.iter().any(|e| p.ends_with(e));
        let real: Vec<&str> = offenders
            .iter()
            .map(String::as_str)
            .filter(|o| !exempted(o))
            .collect();
        assert!(
            real.is_empty(),
            "unused_imports allow-suppression in production code ({} sites) — \
             delete dead imports / fully qualify doc links / let tests import themselves, \
             or register an exemption with a justification:\n{}",
            real.len(),
            real.join("\n")
        );
    }

    /// Recursively collect violations in .rs files (path:line); the
    /// `tests` directory is pruned whole.
    fn walk_rs(dir: &std::path::Path, scanned: &mut usize, offenders: &mut Vec<String>) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => panic!("failed to read dir {}: {e}", dir.display()),
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "tests") {
                    continue;
                }
                walk_rs(&path, scanned, offenders);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = match std::fs::read_to_string(&path) {
                    Ok(t) => t,
                    Err(e) => panic!("failed to read file {}: {e}", path.display()),
                };
                *scanned += 1;
                let rel = path.display().to_string();
                for (i, line) in text.lines().enumerate() {
                    if line.contains(NEEDLE) {
                        offenders.push(format!("{}:{}", rel, i + 1));
                    }
                }
            }
        }
    }
}

/// A format-governance sweep for the include! domain files of
/// `session/actor/tests/`.
///
/// The directory (11 domain files + the mod.rs facade) is mounted into
/// `mod tests` via include!, which cargo fmt does not follow — drift
/// would otherwise go unnoticed unless someone remembers to run rustfmt
/// directly — so this sweep guards the gate: it runs
/// `rustfmt --edition 2024 --check` on every .rs in the directory and
/// goes red with a per-file diff tail plus remediation guidance (run
/// `rustfmt --edition 2024 <file>` directly).
///
/// Precondition: the repo gate and dev machines already require the
/// rustfmt component; if missing from PATH, fall back to probing next
/// to `$CARGO` (the common CI-container layout where rustfmt shares
/// bin/ with cargo); if still unavailable, hard-fail — repo discipline
/// rejects silent skips / false greens, and a missing environment piece
/// must not neuter the format gate. The file-count floor guards against
/// an emptied directory idling green.
#[cfg(test)]
mod include_fmt_sweep {
    /// Scan file-count floor (11 domain files + the mod.rs facade):
    /// below this the directory was emptied or renamed and the scan
    /// face is distorted (idling always green); fix the paths first.
    const MIN_FILES: usize = 10;

    /// Tail lines shown of each file's drift diff: the full diff of a
    /// large file like http.rs can reach hundreds of lines; the tail
    /// suffices to locate and remediate, and full output would drown
    /// the point.
    const DIFF_TAIL_LINES: usize = 20;

    #[test]
    fn actor_tests_domain_files_stay_rustfmt_clean() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/session/actor/tests");
        let entries = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) => panic!("failed to read tests facade dir {}: {e}", dir.display()),
        };
        let mut files: Vec<std::path::PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "rs"))
            .collect();
        files.sort();
        assert!(
            files.len() >= MIN_FILES,
            "scan surface distorted: only {} .rs files (floor {MIN_FILES}); directory emptied or moved?",
            files.len()
        );

        let rustfmt = resolve_rustfmt();
        let mut offenders: Vec<String> = Vec::new();
        for path in &files {
            let output = match std::process::Command::new(&rustfmt)
                .args(["--edition", "2024", "--check"])
                .arg(path)
                .output()
            {
                Ok(o) => o,
                Err(e) => panic!(
                    "rustfmt failed to start {}: {e} (this sweep refuses to silently skip; \
                     fix the environment before running the gate)",
                    rustfmt.display()
                ),
            };
            if output.status.success() {
                continue;
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stdout.contains("Diff in") {
                let mut tail: Vec<&str> = stdout.lines().rev().take(DIFF_TAIL_LINES).collect();
                tail.reverse();
                offenders.push(format!(
                    "{} (last {} lines of drift diff):\n{}",
                    path.display(),
                    tail.len(),
                    tail.join("\n")
                ));
            } else {
                offenders.push(format!(
                    "{} (rustfmt error, not format drift; fix the syntax first):\n{}",
                    path.display(),
                    stderr.trim_end()
                ));
            }
        }

        assert!(
            offenders.is_empty(),
            "rustfmt drift in the session/actor/tests/ include! domain files ({} files) — \
             cargo fmt does not follow include!, so remediate by running \
             rustfmt --edition 2024 <file> directly on each:\n\n{}",
            offenders.len(),
            offenders.join("\n\n")
        );
    }

    /// Resolve the rustfmt executable: probe PATH first; if
    /// unavailable, fall back to `$CARGO`'s directory (in CI containers
    /// rustfmt shares bin/ with cargo and PATH may not include it); if
    /// neither works, panic — a missing component hard-fails,
    /// forbidding silent skips / false greens.
    fn resolve_rustfmt() -> std::path::PathBuf {
        if probe(std::path::Path::new("rustfmt")) {
            return std::path::PathBuf::from("rustfmt");
        }
        if let Ok(cargo) = std::env::var("CARGO") {
            if let Some(bin_dir) = std::path::Path::new(&cargo).parent() {
                let candidate = bin_dir.join("rustfmt");
                if probe(&candidate) {
                    return candidate;
                }
            }
        }
        panic!(
            "no usable rustfmt found (neither PATH nor $CARGO's directory probed alive) — \
             repo discipline: the gate and dev machines require the rustfmt component \
             (rustup component add rustfmt); this sweep refuses silent skips / false greens"
        );
    }

    /// Probe: a runnable `--version` with a successful exit counts as
    /// available.
    fn probe(bin: &std::path::Path) -> bool {
        std::process::Command::new(bin)
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    }
}
