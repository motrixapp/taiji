//! `taiji --print-completions <bash|zsh|fish>` — the minimal completion
//! script generator (zero third-party dependencies: no clap_complete,
//! hand-built word lists).
//!
//! Discipline: [`LONG_FLAGS`] / [`SUBCOMMANDS`] are hardcoded ledgers
//! that must mirror the clap metadata of the `Cli` struct in `main.rs`
//! verbatim (the `#[arg(long …)]` / `long = "…"` derive names + visible
//! aliases + the `Command` subcommand names). Every time a flag is added
//! to `Cli` or a subcommand to `Command`, the ledger here must be
//! updated — the sync is not enforced by comments but pinned by tests:
//! [`tests::long_flags_sync_with_clap_metadata`] /
//! [`tests::subcommands_sync_with_clap_metadata`] derive the expected
//! surface live from clap `Command` introspection, so ledger drift goes
//! red (the same seal-the-registration-hole pattern as conf.rs'
//! `conf_key_surface_matches_cli_long_options`).
//!
//! Scope (minimal by design): completes long flag names (no values) and
//! subcommand names; flag value domains/hints, short flags, and
//! in-subcommand options are out of scope. Each shell gets one minimal
//! snippet: bash a `complete -W` word list, zsh `compdef` + `_arguments`,
//! fish one `complete -c taiji -l` line per flag. Output goes to stdout
//! and the process exits (meta-flag semantics; see the `main.rs`
//! consumption point).
//!
//! Upstream anchor mapping: docs/design/cli.md

/// Shell domain for generation (the Cli `--print-completions`
/// PossibleValuesParser references this same table — a single source;
/// out-of-domain values never reach [`script`]).
pub(crate) const SHELLS: &[&str] = &["bash", "zsh", "fish"];

/// Long-flag ledger (hardcoded, mirrors the `Cli` clap metadata; sync
/// discipline in the module docs). Excludes `help`/`version` (clap
/// auto-generated, see [`AUTO_LONG_FLAGS`]) and hidden aliases
/// (`rpc-port` — a derive `alias` is hidden, help does not show it, and
/// the completion surface follows the help surface; `bt-enable-lpd` is
/// a visible alias and IS listed).
const LONG_FLAGS: &[&str] = &[
    // Base face (dir/listen-port/the input-file batch list — domain A).
    "dir",
    "input-file",
    "listen-port",
    // BT face: encryption/connection types + LSD/sequential download +
    // integrity + DHT/webseed.
    "bt-require-crypto",
    "bt-min-crypto-level",
    "bt-peer-connection-type",
    "bt-lsd",
    // The aria2 original name (a visible alias of bt-lsd; the
    // completion surface follows the help surface).
    "bt-enable-lpd",
    "bt-sequential-download",
    "check-integrity",
    "enable-dht",
    "enable-http-seeding",
    // NAT face.
    "bt-enable-upnp",
    "bt-enable-nat-pmp",
    // Rate-limit face.
    "max-concurrent-downloads",
    // The four-pool budget trio (taiji capability extensions).
    "max-concurrent-seeds",
    "max-concurrent-checks",
    "media-synthesis-concurrency",
    "max-download-limit",
    "max-upload-limit",
    "max-overall-download-limit",
    "max-overall-upload-limit",
    // The peer-exchange / DHT family (the ut_pex gate + the DHT v4/v6
    // startup-time group).
    "enable-peer-exchange",
    "enable-dht6",
    "dht-entry-point",
    "dht-message-timeout",
    // RPC face.
    "enable-rpc",
    "rpc-listen-port",
    "rpc-listen-all",
    "rpc-secret",
    "rpc-user",
    "rpc-passwd",
    "rpc-allow-origin-all",
    "rpc-max-request-size",
    "rpc-aria2-compat",
    // RPC over TLS family (domain B: --rpc-secure/certificate/private-key).
    "rpc-secure",
    "rpc-certificate",
    "rpc-private-key",
    // TLS/certificate family (domain B: the top-level CA/mTLS/minimum version).
    "ca-certificate",
    "certificate",
    "private-key",
    "min-tls-version",
    // Session/persistence.
    "sqlite3-db-path",
    "bt-detach-seed-only",
    // Tracker face.
    "bt-tracker",
    "bt-tracker-file",
    // High-frequency BT family.
    "bt-max-peers",
    "bt-request-peer-speed-limit",
    "bt-stop-timeout",
    "bt-tracker-interval",
    "bt-tracker-timeout",
    "bt-tracker-connect-timeout",
    "bt-hash-check-seed",
    "bt-save-metadata",
    "bt-metadata-only",
    "bt-load-saved-metadata",
    "bt-enable-hook-after-hash-check",
    // The hook command family (`--on-*`, SPEC §7.4).
    "on-download-start",
    "on-download-pause",
    "on-download-stop",
    "on-download-complete",
    "on-download-error",
    "on-bt-download-complete",
    // Misc (peer id / per-host caps / summary interval).
    "peer-id-prefix",
    "peer-agent",
    "http-max-per-host",
    "summary-interval",
    // The domain 5 behavior family (the task/selection face + the
    // process shutdown deadline + the verify-only gate).
    "select-file",
    "seed-time",
    // The seeding-ratio threshold (the engine SeedPolicy / session
    // GlobalOptions surface).
    "seed-ratio",
    "stop",
    "hash-check-only",
    // The acceptance-disclosure family (accepted at the session/RPC
    // faces as no-op value faces; the CLI faces warn once —
    // accepted-but-not-effective, never masquerading).
    "async-dns",
    "enable-async-dns6",
    "bt-exclude-tracker",
    "max-download-result",
    "max-file-not-found",
    "max-mmap-limit",
    "max-resume-failure-tries",
    // The domain C misc family (cookies/session/interface).
    "load-cookies",
    "save-cookies",
    "save-session",
    "save-session-interval",
    "auto-save-interval",
    "interface",
    "disable-ipv6",
    "dht-entry-point6",
    "ftp-type",
    "netrc-path",
    "no-netrc",
    "gid",
    "dry-run",
    "show-files",
    // Observability/logging face.
    "log-format",
    "log-level",
    "console-log-level",
    "log",
    "stderr",
    "human-readable",
    "enable-color",
    "quiet",
    "verbose",
    "debug",
    "log-verbatim-urls",
    // Config face.
    "conf-path",
    // Meta-flags (this generator's own entry point).
    "print-completions",
];

/// clap auto-generated names (`-h/--help`, `-V/--version`) — not derived
/// Cli fields, so the generator appends them separately (`--he<TAB>` is
/// the most common completion; leaving it out would feel broken).
const AUTO_LONG_FLAGS: &[&str] = &["help", "version"];

/// Subcommand ledger (mirrors the `Command` enum variants; sync
/// discipline in the module docs).
const SUBCOMMANDS: &[&str] = &["import", "create-torrent", "http", "media"];

/// Generate the completion script (consumed from stdout). The `shell`
/// domain is frozen by the clap PossibleValuesParser ([`SHELLS`]);
/// out-of-domain values never get here — the unknown-arm panic is an
/// invariant sentinel, not error handling.
pub(crate) fn script(shell: &str) -> String {
    match shell {
        "bash" => bash_script(),
        "zsh" => zsh_script(),
        "fish" => fish_script(),
        other => {
            panic!("unreachable: the shell domain is frozen by clap ({SHELLS:?}), got {other:?}")
        }
    }
}

/// Minimal bash completion: one `complete -W` word list (flags and
/// subcommands mixed — compgen's prefix filtering naturally splits them:
/// `--` prefixes hit flags, bare words hit subcommands). `-o filenames`
/// backs up filename completion for out-of-list input (.torrent paths
/// are the main positional form; without this fallback path completion
/// would be dead).
fn bash_script() -> String {
    let mut words: Vec<String> = LONG_FLAGS.iter().map(|f| format!("--{f}")).collect();
    words.extend(AUTO_LONG_FLAGS.iter().map(|f| format!("--{f}")));
    words.extend(SUBCOMMANDS.iter().map(|s| (*s).to_string()));
    format!(
        "# taiji bash completion (minimal word-list form, generated by \
         `taiji --print-completions bash`)\n\
         # Install: source <(taiji --print-completions bash) (add to ~/.bashrc)\n\
         # The flag list is a hardcoded ledger (sync discipline: see the\n\
         # completions.rs module docs).\n\
         complete -o filenames -W \"{}\" taiji\n",
        words.join(" ")
    )
}

/// Minimal zsh completion: a `#compdef` header + `_arguments` per-flag
/// specs (bare flag names — no description text; semantics live in
/// `--help`) + a first-positional `_alternative` with two sources (the
/// subcommand word list ∪ filename completion — .torrent paths are the
/// main positional form and must not be crowded out by the subcommand
/// list); the trailing `compdef` line finishes registration (the script
/// is loaded via `source`, where an autoload registration in the header
/// comment form does not take effect — the trailing line is the only
/// hook point).
fn zsh_script() -> String {
    let mut specs = String::new();
    for f in LONG_FLAGS.iter().chain(AUTO_LONG_FLAGS.iter()) {
        specs.push_str(&format!("    '--{f}' \\\n"));
    }
    format!(
        "#compdef taiji\n\
         # taiji zsh completion (minimal _arguments form, generated by \
         `taiji --print-completions zsh`)\n\
         # Install: source <(taiji --print-completions zsh) (add to ~/.zshrc)\n\
         # flag-ledger sync discipline lives in the completions.rs module docs;\n\
         # scope of this generator (minimal form).\n\
         _taiji() {{\n\
         \x20 _arguments \\\n\
         {specs}\
         \x20   '1: :_alternative \"cmds:subcommand:(({cmds}))\" \"files:torrent file:_files\"' \\\n\
         \x20   '*: :_files'\n\
         }}\n\
         compdef _taiji taiji\n",
        specs = specs,
        cmds = SUBCOMMANDS.join(" "),
    )
}

/// Minimal fish completion: one `complete -c taiji -l <flag>` line per
/// flag (the idiomatic fish per-line form) + one subcommand line gated
/// by `-n '__fish_is_first_arg'` (only offered at the first argument
/// position, avoiding noise after flags; the helper is built into fish
/// 3.2+ — without it subcommand completion silently never fires, flag
/// completion is unaffected).
fn fish_script() -> String {
    let mut lines = String::from(
        "# taiji fish completion (minimal form, generated by \
         `taiji --print-completions fish`)\n\
         # Install: taiji --print-completions fish > ~/.config/fish/completions/taiji.fish\n\
         # Long flags (flag-name completion only; value hints are out of\n\
         # scope for this generator -- minimal form).\n",
    );
    for f in LONG_FLAGS.iter().chain(AUTO_LONG_FLAGS.iter()) {
        lines.push_str(&format!("complete -c taiji -l {f}\n"));
    }
    lines.push_str("# Subcommands (first argument position only; in-subcommand\n");
    lines.push_str("# options are out of scope for this generator).\n");
    lines.push_str(&format!(
        "complete -c taiji -n '__fish_is_first_arg' -a '{}'\n",
        SUBCOMMANDS.join(" ")
    ));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ledger sync test (the mechanical enforcer of the discipline, the
    /// first rule of the module docs): LONG_FLAGS == the
    /// clap-introspected long-name surface (long + visible aliases; the
    /// auto-generated help/version names excluded — they are registered
    /// separately in AUTO_LONG_FLAGS). A new Cli flag without a ledger
    /// entry goes red; a ledger entry without a flag (a ghost line) also
    /// goes red.
    #[test]
    fn long_flags_sync_with_clap_metadata() {
        use crate::Cli;
        use clap::CommandFactory;
        let mut expected: Vec<String> = Cli::command()
            .get_arguments()
            .filter_map(|a| a.get_long_and_visible_aliases().map(|ls| ls.to_vec()))
            .flatten()
            .filter(|n| *n != "help" && *n != "version")
            .map(str::to_string)
            .collect();
        expected.sort();
        let mut actual: Vec<&str> = LONG_FLAGS.to_vec();
        actual.sort();
        assert_eq!(
            actual, expected,
            "LONG_FLAGS ledger drifted from the Cli clap metadata — add/remove flags in both (discipline: module docs)"
        );
    }

    /// Subcommand ledger sync: SUBCOMMANDS == the clap-introspected
    /// subcommand names (minus the hidden auto help subcommand). A new
    /// `Command` variant without a ledger entry goes red.
    #[test]
    fn subcommands_sync_with_clap_metadata() {
        use crate::Cli;
        use clap::CommandFactory;
        let mut expected: Vec<String> = Cli::command()
            .get_subcommands()
            .filter(|c| !c.is_hide_set())
            .map(|c| c.get_name().to_string())
            .filter(|n| n != "help")
            .collect();
        expected.sort();
        let mut actual: Vec<&str> = SUBCOMMANDS.to_vec();
        actual.sort();
        assert_eq!(
            actual, expected,
            "SUBCOMMANDS ledger drifted from the Command enum"
        );
    }

    /// Domain freeze (single-source face): `--print-completions` accepts
    /// exactly the three [`SHELLS`] values and fills the field;
    /// out-of-domain values (tcsh) and a missing value are refused by
    /// clap.
    #[test]
    fn shell_domain_frozen_by_cli_parser() {
        use crate::Cli;
        use clap::{CommandFactory, FromArgMatches};
        for shell in SHELLS {
            let m = Cli::command()
                .try_get_matches_from(["taiji", "--print-completions", shell])
                .unwrap_or_else(|e| panic!("shell {shell:?} must parse: {e}"));
            let cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(cli.print_completions.as_deref(), Some(*shell));
        }
        assert!(
            Cli::command()
                .try_get_matches_from(["taiji", "--print-completions", "tcsh"])
                .is_err(),
            "out-of-domain shell must be rejected"
        );
        assert!(
            Cli::command()
                .try_get_matches_from(["taiji", "--print-completions"])
                .is_err(),
            "missing value must be rejected"
        );
    }

    /// bash generation: a single `complete -W` line + the word list with
    /// every flag (`--` prefixed) and subcommand + the `-o filenames`
    /// fallback in place.
    #[test]
    fn bash_script_lists_every_flag_and_subcommand() {
        let s = bash_script();
        assert!(s.contains("complete -o filenames -W \""), "{s}");
        assert!(
            s.trim_end().ends_with("taiji"),
            "word list must end with the command name: {s}"
        );
        for f in LONG_FLAGS.iter().chain(AUTO_LONG_FLAGS.iter()) {
            assert!(
                s.contains(&format!("--{f}")),
                "bash word list is missing --{f}"
            );
        }
        for c in SUBCOMMANDS {
            assert!(s.contains(c), "bash word list is missing subcommand {c}");
        }
    }

    /// zsh generation: the `#compdef` header + the `compdef _taiji
    /// taiji` registration trailer + `_arguments` per-flag specs + the
    /// first-positional `_alternative` (subcommand list + `_files` dual
    /// source).
    #[test]
    fn zsh_script_has_compdef_arguments_and_every_flag() {
        let s = zsh_script();
        assert!(s.starts_with("#compdef taiji\n"), "{s}");
        assert!(s.contains("compdef _taiji taiji"), "{s}");
        assert!(s.contains("_arguments \\"), "{s}");
        assert!(s.contains("_alternative"), "{s}");
        assert!(s.contains("_files"), "{s}");
        assert!(
            s.contains(&format!("(({}))", SUBCOMMANDS.join(" "))),
            "subcommand word list must appear verbatim inside _alternative: {s}"
        );
        for f in LONG_FLAGS.iter().chain(AUTO_LONG_FLAGS.iter()) {
            assert!(
                s.contains(&format!("    '--{f}' \\")),
                "zsh spec is missing --{f}"
            );
        }
    }

    /// fish generation: one `complete -c taiji -l <flag>` line per flag
    /// (line counting — fish has no word-list form, a missing line is a
    /// missing completion) + the subcommand line with the
    /// `__fish_is_first_arg` gate.
    #[test]
    fn fish_script_has_complete_line_per_flag_and_subcommand() {
        let s = fish_script();
        for f in LONG_FLAGS.iter().chain(AUTO_LONG_FLAGS.iter()) {
            let line = format!("complete -c taiji -l {f}\n");
            assert!(s.contains(&line), "fish is missing line: {line:?}");
        }
        assert!(s.contains("__fish_is_first_arg"), "{s}");
        assert!(
            s.contains(&format!("-a '{}'\n", SUBCOMMANDS.join(" "))),
            "fish subcommand line is missing the word list: {s}"
        );
    }
}
