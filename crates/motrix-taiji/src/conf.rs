//! `--conf-path` configuration-file layer (the aria2 conf form).
//!
//! Parses `key=value` lines: the first `=` splits (inner `=` stays in the
//! value), `#` comment lines and blank lines are skipped, a head UTF-8
//! BOM is tolerated, whitespace is trimmed. Unknown keys and
//! missing/unreadable files fail fast (exit 2); nothing is loaded
//! implicitly — no `--conf-path` means zero file IO. Conf keys are taiji
//! CLI long-option names without `--`; that surface is locked against
//! clap introspection by `conf_key_surface_matches_cli_long_options` — a
//! new flag without a parse arm turns red. Priority: defaults < conf <
//! explicit CLI flags (clap `value_source == CommandLine`), with one
//! fail-closed exception: conf-provided `enable-rpc=true` hard-errors in
//! download mode.
//!
//! Upstream anchor mapping: docs/design/cli.md

use std::path::{Path, PathBuf};

use crate::Cli;

/// Registry of conf key names (mirrors the match arms in [`apply_entry`];
/// shared by the unknown-key check and the key-surface lock test — the
/// same table in both places; a missing same-name arm in `apply_entry` is
/// pinned red by `conf_keys_all_have_value_arms`).
const CONF_KEYS: &[&str] = &[
    "conf-path",
    "dir",
    "input-file",
    "listen-port",
    "bt-require-crypto",
    "bt-min-crypto-level",
    "bt-peer-connection-type",
    "bt-lsd",
    "bt-sequential-download",
    "check-integrity",
    "enable-dht",
    "enable-http-seeding",
    "bt-enable-upnp",
    "bt-enable-nat-pmp",
    "max-download-limit",
    "max-upload-limit",
    "enable-rpc",
    "rpc-listen-port",
    "rpc-listen-all",
    "rpc-secret",
    "rpc-user",
    "rpc-passwd",
    "rpc-allow-origin-all",
    "rpc-max-request-size",
    "rpc-aria2-compat",
    "sqlite3-db-path",
    "bt-detach-seed-only",
    "bt-tracker",
    "bt-tracker-file",
    "peer-id-prefix",
    // Behavior-misc family (same face as the CLI flags; the value-domain
    // arms share the CLI value_parser / parser single points — the
    // conf-key surface vs CLI long-option surface correspondence is
    // locked by conf_key_surface_matches_cli_long_options).
    "select-file",
    "seed-time",
    "stop",
    "hash-check-only",
    "peer-agent",
    "http-max-per-host",
    "summary-interval",
    // bt high-frequency family (same face as the CLI flags; bt-enable-lpd
    // is the visible CLI alias of bt-lsd and folds into the same slot —
    // the key-surface lock test covers visible aliases; hidden aliases
    // stay out).
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
    // The six hook command family (`--on-*`, SPEC §7.4; the raw
    // single-value command — the same face as aria2
    // LocalFilePathOptionHandler PATH_TO_COMMAND, no domain validation).
    "on-download-start",
    "on-download-pause",
    "on-download-stop",
    "on-download-complete",
    "on-download-error",
    "on-bt-download-complete",
    // Limits/dht/enable family (value domains share the CLI value_parser
    // domains — sizes go through parse_aria2_size, bools through
    // conf_bool; the parser single points are reused).
    "max-concurrent-downloads",
    // The four-pool budget trio (taiji capability extensions; value
    // domains = the RPC face's same-source domains —
    // seeds 0..=4096 / checks 1..=16 / synthesis 1..=16 — validated at
    // the arms).
    "max-concurrent-seeds",
    "max-concurrent-checks",
    "media-synthesis-concurrency",
    "max-overall-download-limit",
    "max-overall-upload-limit",
    "enable-peer-exchange",
    "enable-dht6",
    "dht-entry-point",
    "dht-message-timeout",
    "log-format",
    "log-level",
    // Console/log family (the `--console-log-level` visible alias joins
    // the key surface — it folds into the
    // same log-level slot; hidden aliases stay out of the primary-name
    // surface; see the module docs on the key-name face).
    "log",
    "stderr",
    "human-readable",
    "enable-color",
    "quiet",
    "verbose",
    "debug",
    "log-verbatim-urls",
    // Domain B TLS/certificate family (the same face as the CLI flags):
    // the client CA/mTLS/version trio + the RPC TLS trio. Value domains
    // live in the parse arms.
    "ca-certificate",
    "certificate",
    "private-key",
    "min-tls-version",
    "rpc-secure",
    "rpc-certificate",
    "rpc-private-key",
    // Domain C misc family (the same face as the CLI flags): the two
    // cookie session keys + the three save-session pieces + the three
    // interface/ipv6/dht6 pieces + the four ftp/netrc pieces + gid/
    // dry-run/show-files. Value domains live in the parse arms.
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
    // The seed-ratio/alias/disclosure family (the same face as the CLI
    // flags): the
    // seed-ratio wiring key + the visible-alias keys (bt-enable-lpd folds
    // into the bt-lsd slot; console-log-level into the log-level slot —
    // visible aliases are CLI long-option names, the key-surface lock
    // test covers them) + the seven acceptance-disclosure keys (the
    // GLOBAL_PATCH_TABLE no-op names; the CLI/conf faces accept + warn,
    // no consumption seam — per-key reasons in the Cli field docs /
    // options.rs row notes). Value domains live in the parse arms.
    "seed-ratio",
    "bt-enable-lpd",
    "console-log-level",
    "async-dns",
    "enable-async-dns6",
    "bt-exclude-tracker",
    "max-download-result",
    "max-file-not-found",
    "max-mmap-limit",
    "max-resume-failure-tries",
];

/// aria2 conf form parser: text -> an ordered `((1-based line, key,
/// value))` table — the line number travels with the entry so fail-fast
/// messages can point at the line. BOM tolerance looks only at the file
/// head (a mid-file U+FEFF is body content, not stripped).
fn parse_conf_entries(text: &str) -> Vec<(usize, String, String)> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut entries = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Split on the first `=`; lines without `=` or with an empty key
        // side are skipped (same shape as aria2 — an `=` inside the value
        // belongs to the value, preserved verbatim for URL queries and
        // the like).
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        entries.push((idx + 1, key.to_string(), value.trim().to_string()));
    }
    entries
}

/// bool value domain (same face as the CLI flags + the aria2
/// BooleanOptionHandler domain: only the `true`/`false` literals, no
/// 1/0/yes — intentionally unlike the core session-side parse_bool's
/// 1/0 tolerance; conf follows the flag surface).
fn conf_bool(value: &str) -> Option<bool> {
    match value {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// Assembly entry: read from disk (Windows long paths go through the
/// taiji-io choke point to the OS; error messages use the original path —
/// the winpath "no prefix on user-visible paths" contract) -> parse ->
/// apply overrides. No `--conf-path` = zero file IO (nothing is loaded
/// implicitly; see the module docs).
pub(crate) fn load_and_apply(matches: &clap::ArgMatches, cli: &mut Cli) -> Result<(), String> {
    let Some(path) = cli.conf_path.clone() else {
        return Ok(());
    };
    let text = std::fs::read_to_string(taiji_io::winpath::to_fs_path(&path))
        .map_err(|e| format!("error: cannot read conf file {}: {e}", path.display()))?;
    let entries = parse_conf_entries(&text);
    apply_conf_overrides(matches, cli, &path, &entries)
}

/// Apply entries in order (same-name keys: later values override earlier);
/// return on the first error (fail-fast).
fn apply_conf_overrides(
    matches: &clap::ArgMatches,
    cli: &mut Cli,
    path: &Path,
    entries: &[(usize, String, String)],
) -> Result<(), String> {
    for (line_no, key, value) in entries {
        apply_entry(matches, cli, path, *line_no, key, value)?;
    }
    Ok(())
}

/// One conf entry -> Cli field. Order: unknown keys rejected -> explicit
/// CLI flags win (the entry is dead, not consumed) -> domain validation ->
/// write.
fn apply_entry(
    matches: &clap::ArgMatches,
    cli: &mut Cli,
    path: &Path,
    line_no: usize,
    key: &str,
    value: &str,
) -> Result<(), String> {
    if !CONF_KEYS.contains(&key) {
        return Err(format!(
            "error: {}:{line_no}: unknown conf option: {key} \
             (conf keys are taiji CLI long option names without `--`; see `taiji --help`)",
            path.display()
        ));
    }
    // Explicit CLI flags always win (priority defaults < conf < CLI): the
    // conf entry is not consumed. Criterion = clap value_source
    // CommandLine (same criterion as rpc_group_conflict; defaults and conf
    // values are both non-command-line sources).
    macro_rules! cli_wins {
        ($id:literal) => {
            if matches.value_source($id) == Some(clap::parser::ValueSource::CommandLine) {
                return Ok(());
            }
        };
    }
    // Domain-error text (line-numbered; the `--key` form matches CLI
    // naming).
    let invalid = |expected: &str| {
        format!(
            "error: {}:{line_no}: invalid value for --{key}: {value:?} (expected {expected})",
            path.display()
        )
    };
    match key {
        // Recognized but no-op: no nested loading (single deterministic
        // assembly; see the module docs).
        "conf-path" => {}
        "dir" => {
            cli_wins!("dir");
            cli.dir = PathBuf::from(value);
        }
        // Domain A (the --input-file batch list): the value = the list
        // path verbatim (existence/cap validation lives on the
        // run_input_file read face — missing/over-limit = exit 2; the
        // list is the primary workload and does not take the "warn and
        // degrade" face). The mutual exclusion with the positional arg
        // is enforced by the main runtime recheck arm (a conf source
        // bypasses the clap conflict declaration — noted in main).
        "input-file" => {
            cli_wins!("input_file");
            cli.input_file = Some(PathBuf::from(value));
        }
        "listen-port" => {
            cli_wins!("listen_port");
            cli.listen_port = value.parse().map_err(|_| invalid("u16 port"))?;
        }
        "bt-require-crypto" => {
            cli_wins!("bt_require_crypto");
            cli.bt_require_crypto = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        "bt-min-crypto-level" => {
            cli_wins!("bt_min_crypto_level");
            // Enum domain = the core option parse surface (run consumes
            // the same parser).
            if taiji_core::session::parse_crypto_level(value).is_none() {
                return Err(invalid("plain|arc4"));
            }
            cli.bt_min_crypto_level = value.to_string();
        }
        "bt-peer-connection-type" => {
            cli_wins!("bt_peer_connection_type");
            if taiji_core::session::parse_peer_connection_type(value).is_none() {
                return Err(invalid("tcp|utp|prefer-utp|prefer-tcp"));
            }
            cli.bt_peer_connection_type = value.to_string();
        }
        "bt-lsd" => {
            cli_wins!("bt_lsd");
            cli.bt_lsd = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        // The visible-alias key (`--bt-enable-lpd`, the aria2 original
        // name): folds into the same bt_lsd slot as the primary name —
        // the CLI field, this conf arm, and the session face's
        // GLOBAL_PATCH_TABLE alias row all write one value face.
        "bt-enable-lpd" => {
            cli_wins!("bt_lsd");
            cli.bt_lsd = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        "bt-sequential-download" => {
            cli_wins!("bt_sequential_download");
            cli.bt_sequential_download = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        // The conf face of --check-integrity (bare-download rescan switch;
        // default false, the same value as the CLI flag).
        "check-integrity" => {
            cli_wins!("check_integrity");
            cli.check_integrity = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        "enable-dht" => {
            cli_wins!("enable_dht");
            cli.enable_dht = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        "enable-http-seeding" => {
            cli_wins!("enable_http_seeding");
            cli.enable_http_seeding = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        "bt-enable-upnp" => {
            cli_wins!("bt_enable_upnp");
            cli.bt_enable_upnp = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        "bt-enable-nat-pmp" => {
            cli_wins!("bt_enable_natpmp");
            cli.bt_enable_natpmp = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        "max-download-limit" => {
            cli_wins!("max_download_limit");
            // The same function as the clap `--max-download-limit`
            // value_parser (K/M/G suffixes, 1024-based; 0 = unlimited).
            cli.max_download_limit =
                crate::parse_aria2_size(value).map_err(|_| invalid("<n>[k|m|g] size"))?;
        }
        "max-upload-limit" => {
            cli_wins!("max_upload_limit");
            // Same as `max-download-limit`.
            cli.max_upload_limit =
                crate::parse_aria2_size(value).map_err(|_| invalid("<n>[k|m|g] size"))?;
        }
        "enable-rpc" => {
            cli_wins!("enable_rpc");
            cli.enable_rpc = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        "rpc-listen-port" => {
            cli_wins!("rpc_listen_port");
            cli.rpc_listen_port = value.parse().map_err(|_| invalid("u16 port"))?;
        }
        "rpc-listen-all" => {
            cli_wins!("rpc_listen_all");
            cli.rpc_listen_all = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        "rpc-secret" => {
            cli_wins!("rpc_secret");
            // Blank values (the parse layer already trims line values, so
            // pure whitespace lands the same) normalize to unset — the
            // same normalize single point as the CLI ingest; aria2's empty
            // string = unset.
            cli.rpc_secret = taiji_rpc::normalize_secret(Some(value.to_string()));
        }
        "rpc-user" => {
            cli_wins!("rpc_user");
            cli.rpc_user = Some(value.to_string());
        }
        "rpc-passwd" => {
            cli_wins!("rpc_passwd");
            cli.rpc_passwd = Some(value.to_string());
        }
        "rpc-allow-origin-all" => {
            cli_wins!("rpc_allow_origin_all");
            cli.rpc_allow_origin_all = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        "rpc-max-request-size" => {
            cli_wins!("rpc_max_request_size");
            // The same function as the clap `--rpc-max-request-size`
            // value_parser (K/M/G suffixes, 1024-based).
            cli.rpc_max_request_size =
                crate::parse_aria2_size(value).map_err(|_| invalid("<n>[k|m|g] size"))?;
        }
        "rpc-aria2-compat" => {
            cli_wins!("rpc_aria2_compat");
            cli.rpc_aria2_compat = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        "sqlite3-db-path" => {
            cli_wins!("sqlite3_db_path");
            cli.sqlite3_db_path = PathBuf::from(value);
        }
        "bt-detach-seed-only" => {
            cli_wins!("bt_detach_seed_only");
            cli.bt_detach_seed_only = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        "bt-tracker" => {
            cli_wins!("bt_tracker");
            // The comma-list syntax (empty-segment/whitespace tolerance) is
            // validated at the split_bt_tracker single point, the same gate
            // as the CLI/session faces — the whole value is passed through
            // here.
            cli.bt_tracker = value.to_string();
        }
        "bt-tracker-file" => {
            cli_wins!("bt_tracker_file");
            cli.bt_tracker_file = Some(PathBuf::from(value));
        }
        "peer-id-prefix" => {
            cli_wins!("peer_id_prefix");
            // No charset validation, no over-20-byte truncation here — the
            // semantics live at the generation point (same rule as the
            // CLI).
            cli.peer_id_prefix = Some(value.to_string());
        }
        // Behavior-misc family: the value-domain arms share the CLI
        // parser single points (select-file goes through the session
        // parse_select_file gate — syntax rejected on the spot;
        // seed-time/stop minute domains = finite and >= 0, the same
        // fail-fast direction as the CLI face; bool two-state =
        // conf_bool; peer-agent is a pass-through string — its effect
        // stance is accept + warn-not-effective, semantics live on the
        // flag/declaration face).
        "select-file" => {
            cli_wins!("select_file");
            if let Err(msg) = taiji_core::session::parse_select_file(value) {
                return Err(invalid(&msg));
            }
            cli.select_file = Some(value.to_string());
        }
        "seed-time" => {
            cli_wins!("seed_time");
            let m: f64 = value.parse().map_err(|_| invalid("minutes >= 0"))?;
            if !m.is_finite() || m < 0.0 {
                return Err(invalid("minutes >= 0"));
            }
            cli.seed_time = Some(m);
        }
        "stop" => {
            cli_wins!("stop");
            let m: f64 = value.parse().map_err(|_| invalid("minutes >= 0"))?;
            if !m.is_finite() || m < 0.0 {
                return Err(invalid("minutes >= 0"));
            }
            cli.stop = Some(m);
        }
        "hash-check-only" => {
            cli_wins!("hash_check_only");
            cli.hash_check_only = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        "peer-agent" => {
            cli_wins!("peer_agent");
            cli.peer_agent = Some(value.to_string());
        }
        "http-max-per-host" => {
            cli_wins!("http_max_per_host");
            let n: u32 = value.parse().map_err(|_| invalid("u32 >= 1"))?;
            if n < 1 {
                return Err(invalid("u32 >= 1"));
            }
            cli.http_max_per_host = Some(n);
        }
        "summary-interval" => {
            cli_wins!("summary_interval");
            let n: u32 = value
                .parse()
                .map_err(|_| invalid("u32 in 0..=2147483647"))?;
            if n > taiji_core::session::SUMMARY_INTERVAL_MAX {
                return Err(invalid("u32 in 0..=2147483647"));
            }
            cli.summary_interval = n;
        }
        // bt high-frequency family (domains = the clap value_parser
        // domains; the conf injection of the two knob-override-seam keys
        // happens here — the cli_wins yield rule guarantees a command-line
        // injection always writes last; the echo face reaches session
        // assembly via the Cli fields).
        "bt-max-peers" => {
            cli_wins!("bt_max_peers");
            let n: u64 = value.parse().map_err(|_| invalid("u64 >= 0"))?;
            cli.bt_max_peers = n;
            match crate::bt_max_peers_override_of(n, true) {
                Some(v) => taiji_io::knobs::set_peer_max_override(v),
                None => {
                    // aria2's 0 = unlimited peers — the taiji engine always
                    // has a hard cap and cannot express it (the same note
                    // as the Cli field docs): no override injected, the
                    // value is still recorded.
                    eprintln!(
                        "warning: {}:{line_no}: bt-max-peers=0 (unlimited) is not \
                         expressible; keeping built-in peer cap",
                        path.display()
                    );
                }
            }
        }
        "bt-request-peer-speed-limit" => {
            cli_wins!("bt_request_peer_speed_limit");
            let n = crate::parse_aria2_size(value).map_err(|_| invalid("<n>[k|m|g] size"))?;
            cli.bt_request_peer_speed_limit = n;
            taiji_io::knobs::set_peer_request_speed_limit_override(n);
        }
        "bt-stop-timeout" => {
            cli_wins!("bt_stop_timeout");
            cli.bt_stop_timeout = value.parse().map_err(|_| invalid("u64 >= 0"))?;
        }
        "bt-tracker-interval" => {
            cli_wins!("bt_tracker_interval");
            cli.bt_tracker_interval = value.parse().map_err(|_| invalid("u64 >= 0"))?;
        }
        "bt-tracker-timeout" => {
            cli_wins!("bt_tracker_timeout");
            let n: u64 = value.parse().map_err(|_| invalid("u64 in 1..=600"))?;
            if !(1..=600).contains(&n) {
                return Err(invalid("u64 in 1..=600"));
            }
            cli.bt_tracker_timeout = n;
        }
        "bt-tracker-connect-timeout" => {
            cli_wins!("bt_tracker_connect_timeout");
            let n: u64 = value.parse().map_err(|_| invalid("u64 in 1..=600"))?;
            if !(1..=600).contains(&n) {
                return Err(invalid("u64 in 1..=600"));
            }
            cli.bt_tracker_connect_timeout = n;
        }
        "bt-hash-check-seed" => {
            cli_wins!("bt_hash_check_seed");
            cli.bt_hash_check_seed = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        "bt-save-metadata" => {
            cli_wins!("bt_save_metadata");
            cli.bt_save_metadata = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        "bt-metadata-only" => {
            cli_wins!("bt_metadata_only");
            cli.bt_metadata_only = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        "bt-load-saved-metadata" => {
            cli_wins!("bt_load_saved_metadata");
            cli.bt_load_saved_metadata = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        "bt-enable-hook-after-hash-check" => {
            cli_wins!("bt_enable_hook_after_hash_check");
            cli.bt_enable_hook_after_hash_check =
                conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        // The six hook command family (`--on-*`, SPEC §7.4): the raw
        // single-value command is stored verbatim (the same face as the
        // aria2 LocalFilePathOptionHandler PATH_TO_COMMAND — no value
        // domain validation, no comma-separated multi-command semantics;
        // a bare name is looked up via PATH, the argv passes through
        // without a shell). An empty string is not normalized here — the
        // blank = unset normalization single point lives at the assembly
        // site hook_set_from_cli (the CLI/conf sources through the same
        // gate).
        "on-download-start" => {
            cli_wins!("on_download_start");
            cli.on_download_start = Some(value.to_string());
        }
        "on-download-pause" => {
            cli_wins!("on_download_pause");
            cli.on_download_pause = Some(value.to_string());
        }
        "on-download-stop" => {
            cli_wins!("on_download_stop");
            cli.on_download_stop = Some(value.to_string());
        }
        "on-download-complete" => {
            cli_wins!("on_download_complete");
            cli.on_download_complete = Some(value.to_string());
        }
        "on-download-error" => {
            cli_wins!("on_download_error");
            cli.on_download_error = Some(value.to_string());
        }
        "on-bt-download-complete" => {
            cli_wins!("on_bt_download_complete");
            cli.on_bt_download_complete = Some(value.to_string());
        }
        // Limits/dht/enable family (value domains share the CLI
        // value_parser domains — sizes go through parse_aria2_size, bools
        // through conf_bool; the parser single points are reused).
        "max-concurrent-downloads" => {
            cli_wins!("max_concurrent_downloads");
            // The [1,64] domain — the RPC apply-side
            // clamp's upper bound now enforced fail-fast here too
            // (the budget trio's shape; a conf-pulled N > 64 must not
            // slip past startup).
            let n: u32 = value.parse().map_err(|_| invalid("u32 in 1..=64"))?;
            if !(1..=64).contains(&n) {
                return Err(invalid("u32 in 1..=64"));
            }
            cli.max_concurrent_downloads = n;
        }
        // The four-pool budget trio: hard domain
        // validation at the conf face (the fail-fast conf shape — the
        // max-concurrent-downloads arm precedent), value domains =
        // the RPC face's same-source domains (the RPC accepted-key rows
        // clamp 0..=4096 / 1..=16 / 1..=16; the CLI value_parsers take
        // the same ranges).
        "max-concurrent-seeds" => {
            cli_wins!("max_concurrent_seeds");
            let n: u32 = value.parse().map_err(|_| invalid("u32 in 0..=4096"))?;
            if n > 4096 {
                return Err(invalid("u32 in 0..=4096"));
            }
            cli.max_concurrent_seeds = n;
        }
        "max-concurrent-checks" => {
            cli_wins!("max_concurrent_checks");
            let n: u32 = value.parse().map_err(|_| invalid("u32 in 1..=16"))?;
            if !(1..=16).contains(&n) {
                return Err(invalid("u32 in 1..=16"));
            }
            cli.max_concurrent_checks = n;
        }
        "media-synthesis-concurrency" => {
            cli_wins!("media_synthesis_concurrency");
            let n: u32 = value.parse().map_err(|_| invalid("u32 in 1..=16"))?;
            if !(1..=16).contains(&n) {
                return Err(invalid("u32 in 1..=16"));
            }
            cli.media_synthesis_concurrency = n;
        }
        "max-overall-download-limit" => {
            cli_wins!("max_overall_download_limit");
            cli.max_overall_download_limit =
                crate::parse_aria2_size(value).map_err(|_| invalid("<n>[k|m|g] size"))?;
        }
        "max-overall-upload-limit" => {
            cli_wins!("max_overall_upload_limit");
            cli.max_overall_upload_limit =
                crate::parse_aria2_size(value).map_err(|_| invalid("<n>[k|m|g] size"))?;
        }
        "enable-peer-exchange" => {
            cli_wins!("enable_peer_exchange");
            cli.enable_peer_exchange = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        "enable-dht6" => {
            cli_wins!("enable_dht6");
            cli.enable_dht6 = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        "dht-entry-point" => {
            cli_wins!("dht_entry_point");
            // HOST:PORT syntax is validated at the same CLI parser single
            // point (DNS resolution lives in the engine bootstrap — only
            // the shape is pinned here).
            cli.dht_entry_point =
                Some(crate::parse_dht_entry_point(value).map_err(|_| invalid("HOST:PORT"))?);
        }
        "dht-message-timeout" => {
            cli_wins!("dht_message_timeout");
            let n: u64 = value.parse().map_err(|_| invalid("u64 in 1..=60"))?;
            // The 1..=60 domain is the core session DHT message-timeout
            // anchor (DHT_MESSAGE_TIMEOUT_MIN_SECS/MAX_SECS = 1/60 —
            // pinned as literals here so the conf face does not depend on
            // the session re-export surface).
            if !(1..=60).contains(&n) {
                return Err(invalid("u64 in 1..=60"));
            }
            cli.dht_message_timeout = n;
        }
        "log-format" => {
            cli_wins!("log_format");
            if !matches!(value, "text" | "json") {
                return Err(invalid("text|json"));
            }
            cli.log_format = value.to_string();
        }
        "log-level" => {
            cli_wins!("log_level");
            if !matches!(value, "debug" | "info" | "notice" | "warn" | "error") {
                return Err(invalid("debug|info|notice|warn|error"));
            }
            cli.log_level = Some(value.to_string());
        }
        // The visible-alias key (`--console-log-level`): folds into the
        // same log_level slot as the primary name (a single log stream —
        // the alias rationale is in the Cli field doc).
        "console-log-level" => {
            cli_wins!("log_level");
            if !matches!(value, "debug" | "info" | "notice" | "warn" | "error") {
                return Err(invalid("debug|info|notice|warn|error"));
            }
            cli.log_level = Some(value.to_string());
        }
        // Console/log family: log/stderr (a single stream with two
        // targets — the same explicit mutual exclusion as the CLI face's
        // clap conflicts_with is backed by the open_log_target fail-fast;
        // the per-key write-backs here do not see each other);
        // human-readable/enable-color (bool domains via conf_bool,
        // default true — same as the flag face).
        "log" => {
            cli_wins!("log");
            cli.log = Some(PathBuf::from(value));
        }
        "stderr" => {
            cli_wins!("stderr");
            cli.stderr = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        "human-readable" => {
            cli_wins!("human_readable");
            cli.human_readable = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        "enable-color" => {
            cli_wins!("enable_color");
            cli.enable_color = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        "verbose" => {
            cli_wins!("verbose");
            cli.verbose = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        "quiet" => {
            cli_wins!("quiet");
            cli.quiet = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        "debug" => {
            cli_wins!("debug");
            cli.debug = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        "log-verbatim-urls" => {
            cli_wins!("log_verbatim_urls");
            cli.log_verbatim_urls = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        // ---- domain B TLS/certificate family ----
        // `ca-certificate`: the path is stored verbatim (the validation
        // source = the session addUri parse arm's single point — a bad
        // path/bad PEM = task rejected `taiji.option.invalid`, the same
        // gate as the CLI flag/http subcommand; the conf value does not
        // pre-read the disk). The effective face per form is in the Cli
        // field doc (URL positional direct mapping / input-file WebUri
        // line injection / the session forms' no-global-face warning
        // disclosure).
        "ca-certificate" => {
            cli_wins!("ca_certificate");
            cli.ca_certificate = Some(value.to_string());
        }
        // `certificate`/`private-key` (the client mTLS pair): the paths
        // are stored verbatim. The acceptance-disclosure face is the
        // same as the CLI (transport face wired, session projection face
        // absent — accepted but not effective, one explicit warning at
        // the run single point).
        "certificate" => {
            cli_wins!("certificate");
            cli.certificate = Some(PathBuf::from(value));
        }
        "private-key" => {
            cli_wins!("private_key");
            cli.private_key = Some(PathBuf::from(value));
        }
        // `min-tls-version`: value domain `tls1.2|tls1.3` (the same
        // domain as the clap value_parser — the two literals frozen;
        // taiji-http `MinTlsVersion::from_value` is the domain's
        // semantic source, motrix-taiji has no such dependency edge so
        // the literals are mirrored here. The aria2 domain has one more
        // member TLSv1.1 — rustls 0.23 supports only 1.2/1.3, the
        // narrowing declaration is in the Cli field doc).
        "min-tls-version" => {
            cli_wins!("min_tls_version");
            if !matches!(value, "tls1.2" | "tls1.3") {
                return Err(invalid("tls1.2|tls1.3"));
            }
            cli.min_tls_version = Some(value.to_string());
        }
        // `rpc-secure` (the RPC over TLS switch): the bool value domain
        // matches the CLI flag; pair validation (certificate/private key
        // missing one, a certificate without secure) belongs to the
        // serve assembly point fail-closed (the taiji-rpc guard's single
        // source — the conf/CLI sources through the same gate).
        "rpc-secure" => {
            cli_wins!("rpc_secure");
            cli.rpc_secure = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        "rpc-certificate" => {
            cli_wins!("rpc_certificate");
            cli.rpc_certificate = Some(PathBuf::from(value));
        }
        "rpc-private-key" => {
            cli_wins!("rpc_private_key");
            cli.rpc_private_key = Some(PathBuf::from(value));
        }
        // ---- domain C misc family ----
        // `load-cookies`: the Netscape cookie file path is stored
        // verbatim (the loading/validation source = the session's
        // fail-closed single point at task acceptance — a bad path =
        // task rejected `taiji.option.invalid`, the same gate as the
        // CLI flag/http subcommand; the conf value does not pre-read the
        // disk).
        "load-cookies" => {
            cli_wins!("load_cookies");
            cli.load_cookies = Some(PathBuf::from(value));
        }
        // `save-cookies`: the path is stored verbatim (an
        // acceptance-disclosure face — the consumption face is absent,
        // one explicit warning at the run single point, the same gate
        // as the CLI flag).
        "save-cookies" => {
            cli_wins!("save_cookies");
            cli.save_cookies = Some(PathBuf::from(value));
        }
        // `save-session`: the exit text export path (consumed by the
        // session shutdown save_session; a directory-face failure = a
        // shutdown-time warning, not pre-validated).
        "save-session" => {
            cli_wins!("save_session");
            cli.save_session = Some(PathBuf::from(value));
        }
        // `save-session-interval`: the seconds domain >= 0 (the same
        // domain as the clap value_parser; 0 = disabled — aria2
        // default anchor, consumed by the actor's periodic save tick).
        "save-session-interval" => {
            cli_wins!("save_session_interval");
            cli.save_session_interval = value.parse().map_err(|_| invalid("u64 >= 0"))?;
        }
        // `auto-save-interval`: the seconds domain 0..=600 (the same
        // domain as aria2 NumberOptionHandler(…, "60", 0, 600));
        // an acceptance-disclosure face (the consumption face is absent
        // — continuous commits, one explicit warning at the run single
        // point).
        "auto-save-interval" => {
            cli_wins!("auto_save_interval");
            let n: u64 = value.parse().map_err(|_| invalid("u64 in 0..=600"))?;
            if n > 600 {
                return Err(invalid("u64 in 0..=600"));
            }
            cli.auto_save_interval = Some(n);
        }
        // `interface`: the bind name/IP is stored verbatim (an
        // acceptance-disclosure face — the connection layer has no
        // local_addr binding seam, one explicit warning at the run
        // single point).
        "interface" => {
            cli_wins!("interface");
            cli.interface = Some(value.to_string());
        }
        // `disable-ipv6`: the bool value domain matches the CLI flag
        // (an acceptance-disclosure face — the resolution/dial faces
        // have no consumption point, one explicit warning at the run
        // single point).
        "disable-ipv6" => {
            cli_wins!("disable_ipv6");
            cli.disable_ipv6 = Some(conf_bool(value).ok_or_else(|| invalid("true|false"))?);
        }
        // `dht-entry-point6`: the HOST:PORT domain (the same parse
        // single point = [`crate::parse_dht_entry_point6`], the same
        // gate as the CLI flag value_parser — the v6 literal bracket
        // form / port 1..=65535).
        "dht-entry-point6" => {
            cli_wins!("dht_entry_point6");
            crate::parse_dht_entry_point6(value).map_err(|_| invalid("HOST:PORT"))?;
            cli.dht_entry_point6 = Some(value.to_string());
        }
        // `ftp-type`: the value domain ascii|binary (the same domain as
        // the clap PossibleValuesParser); binary = zero change to the
        // status quo, ascii = an acceptance-disclosure face (one
        // explicit warning at the run single point — TYPE I is
        // constant).
        "ftp-type" => {
            cli_wins!("ftp_type");
            if !matches!(value, "ascii" | "binary") {
                return Err(invalid("ascii|binary"));
            }
            cli.ftp_type = Some(value.to_string());
        }
        // `netrc-path`/`no-netrc`: the path/bool stored verbatim (an
        // acceptance-disclosure face — the netrc consumption face is
        // absent, one explicit warning at the run single point).
        "netrc-path" => {
            cli_wins!("netrc_path");
            cli.netrc_path = Some(PathBuf::from(value));
        }
        "no-netrc" => {
            cli_wins!("no_netrc");
            cli.no_netrc = Some(conf_bool(value).ok_or_else(|| invalid("true|false"))?);
        }
        // `gid`: the 16-digit hex domain (the same parse single point =
        // [`crate::parse_cli_gid`] — the high-bit mask normalization,
        // the aria2 GID form).
        "gid" => {
            cli_wins!("gid");
            cli.gid = Some(crate::parse_cli_gid(value).map_err(|_| invalid("16-hex GID"))?);
        }
        // `dry-run`: the bool value domain matches the CLI flag
        // (consumed by the bare-run .torrent arm; the other forms warn
        // once at the run/per-form single point).
        "dry-run" => {
            cli_wins!("dry_run");
            cli.dry_run = Some(conf_bool(value).ok_or_else(|| invalid("true|false"))?);
        }
        // `show-files`: the bool value domain (a meta flag — true
        // prints the listing and exits; the conf face goes through the
        // same gate as the CLI flag).
        "show-files" => {
            cli_wins!("show_files");
            cli.show_files = conf_bool(value).ok_or_else(|| invalid("true|false"))?;
        }
        // ---- The seed-ratio/alias/disclosure family ----
        // `seed-ratio`: the minutes-face template (seed-time) value
        // domain — finite >= 0, the same fail-fast direction as the CLI
        // face (0.0 = the ratio criterion disabled, decided by the
        // consumption face via the SeedCheck::build rule).
        "seed-ratio" => {
            cli_wins!("seed_ratio");
            let r: f64 = value.parse().map_err(|_| invalid("ratio >= 0"))?;
            if !r.is_finite() || r < 0.0 {
                return Err(invalid("ratio >= 0"));
            }
            cli.seed_ratio = Some(r);
        }
        // The seven acceptance-disclosure keys (the GLOBAL_PATCH_TABLE
        // no-op names; the value domains share the CLI flag faces): the
        // value is recorded on the Cli fields, the consumption faces are
        // absent — one explicit warning at the run single point
        // (warn_deferred_d_tier), the same gate as the CLI flag.
        "async-dns" => {
            cli_wins!("async_dns");
            cli.async_dns = Some(conf_bool(value).ok_or_else(|| invalid("true|false"))?);
        }
        "enable-async-dns6" => {
            cli_wins!("enable_async_dns6");
            cli.enable_async_dns6 = Some(conf_bool(value).ok_or_else(|| invalid("true|false"))?);
        }
        // `bt-exclude-tracker`: the comma multi-value string stored
        // verbatim (the same face as the CLI flag; the exclusion
        // consumption face is absent).
        "bt-exclude-tracker" => {
            cli_wins!("bt_exclude_tracker");
            cli.bt_exclude_tracker = Some(value.to_string());
        }
        // The four max-* numerics: the integer face pass-through
        // (negative sentinels tolerated — the values are never consumed,
        // no domain pinning beyond the integer face).
        "max-download-result" => {
            cli_wins!("max_download_result");
            cli.max_download_result = Some(value.parse::<i64>().map_err(|_| invalid("integer"))?);
        }
        "max-file-not-found" => {
            cli_wins!("max_file_not_found");
            cli.max_file_not_found = Some(value.parse::<i64>().map_err(|_| invalid("integer"))?);
        }
        "max-mmap-limit" => {
            cli_wins!("max_mmap_limit");
            cli.max_mmap_limit = Some(value.parse::<i64>().map_err(|_| invalid("integer"))?);
        }
        "max-resume-failure-tries" => {
            cli_wins!("max_resume_failure_tries");
            cli.max_resume_failure_tries =
                Some(value.parse::<i64>().map_err(|_| invalid("integer"))?);
        }
        // Exhaustiveness of the CONF_KEYS registry is pinned by
        // `conf_keys_all_have_value_arms` (every name has a walkable dummy
        // arm). This arm is unreachable for registered names (the unknown
        // check runs first); if names/arms ever drift, degrade to the same
        // unknown error face instead of panicking — startup rejection is
        // the backstop, no crash path is introduced.
        _ => {
            return Err(format!(
                "error: {}:{line_no}: unknown conf option: {key} \
                 (conf keys are taiji CLI long option names without `--`; see `taiji --help`)",
                path.display()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, FromArgMatches};
    use std::path::Path;

    /// Empty conf face: no `--conf-path` = zero file IO (nothing loaded
    /// implicitly — pins the module docs' intentional-safety behavior).
    #[test]
    fn no_conf_path_means_no_file_io() {
        let m = Cli::command()
            .try_get_matches_from(["taiji"])
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
        cli.conf_path = None;
        load_and_apply(&m, &mut cli).unwrap_or_else(|e| panic!("no-op must be Ok: {e}"));
    }

    /// Parse form: head BOM tolerance, `#` comment lines, blank lines
    /// skipped, leading/trailing whitespace trimmed, first-`=` split
    /// (inner `=` verbatim), `=`-less lines skipped, 1-based locatable
    /// line numbers.
    #[test]
    fn conf_parse_tolerates_bom_comments_blanks_and_whitespace() {
        let text = "\u{feff}# taiji conf\n\n   \ndir=/tmp/dl\nlisten-port=58013\nbt-tracker=udp://a:1/announce?x=1&y=2\nno_equals_line\n  peer-id-prefix = -TJ0001-  \n  # indented comment\n=\n";
        let entries = parse_conf_entries(text);
        assert_eq!(
            entries,
            vec![
                (4, "dir".to_string(), "/tmp/dl".to_string()),
                (5, "listen-port".to_string(), "58013".to_string()),
                (
                    6,
                    "bt-tracker".to_string(),
                    "udp://a:1/announce?x=1&y=2".to_string()
                ),
                (8, "peer-id-prefix".to_string(), "-TJ0001-".to_string()),
            ],
            "BOM/comments/whitespace/no-= lines/bare = lines all skipped; \
             line numbers travel with the entries"
        );
    }

    /// Unknown keys fail fast: the message carries file:line + the key
    /// name + acceptance guidance; registered keys with bad values take
    /// the same face (the domain message carries the expected domain).
    #[test]
    fn conf_unknown_key_fails_fast_with_location() {
        let m = Cli::command()
            .try_get_matches_from(["taiji"])
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
        let path = Path::new("/tmp/t.conf");
        let entries = parse_conf_entries("enable-dht=false\nbt-Lsd=true\n");
        let Err(err) = apply_conf_overrides(&m, &mut cli, path, &entries) else {
            panic!("unknown key must fail fast");
        };
        assert!(err.contains("/tmp/t.conf:2"), "{err}");
        assert!(err.contains("bt-Lsd"), "{err}");
        assert!(err.contains("unknown conf option"), "{err}");
    }

    /// Missing/unreadable file fails fast (the same exit-2 face as
    /// unknown keys; the load_and_apply read arm — the message carries
    /// the original path).
    #[test]
    fn conf_unreadable_file_fails_fast() {
        let m = Cli::command()
            .try_get_matches_from(["taiji"])
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
        cli.conf_path = Some(PathBuf::from("/nonexistent/taiji/definitely-absent.conf"));
        let Err(err) = load_and_apply(&m, &mut cli) else {
            panic!("missing file must fail fast (same shape as the aria2 explicit path)");
        };
        assert!(err.contains("cannot read conf file"), "{err}");
        assert!(
            err.contains("/nonexistent/taiji/definitely-absent.conf"),
            "{err}"
        );
    }

    /// Priority matrix: defaults < conf < explicit CLI flags.
    #[test]
    fn conf_priority_defaults_below_conf_below_cli() {
        let entries = parse_conf_entries(
            "listen-port=58013\nenable-dht=false\ndir=/from/conf\nbt-lsd=true\nlisten-port=58014\n",
        );
        // defaults < conf: with no flags the conf applies (including
        // later-value-wins on same-name keys).
        let m = Cli::command()
            .try_get_matches_from(["taiji"])
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
        apply_conf_overrides(&m, &mut cli, Path::new("/tmp/t.conf"), &entries)
            .unwrap_or_else(|e| panic!("valid conf rejected: {e}"));
        assert_eq!(
            cli.listen_port, 58014,
            "later conf value overrides the earlier one"
        );
        assert!(!cli.enable_dht, "conf overrides the default true");
        assert_eq!(cli.dir, PathBuf::from("/from/conf"));
        assert!(cli.bt_lsd, "conf overrides the default false");

        // conf < explicit CLI flags (both the space and `=` explicit
        // forms; both bool forms).
        let m = Cli::command()
            .try_get_matches_from([
                "taiji",
                "--listen-port",
                "7001",
                "--enable-dht",
                "--dir=/from/cli",
            ])
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
        apply_conf_overrides(&m, &mut cli, Path::new("/tmp/t.conf"), &entries)
            .unwrap_or_else(|e| panic!("valid conf rejected: {e}"));
        assert_eq!(cli.listen_port, 7001, "explicit CLI wins over conf");
        assert!(
            cli.enable_dht,
            "bare flag = explicit; conf =false does not override"
        );
        assert_eq!(
            cli.dir,
            PathBuf::from("/from/cli"),
            "the `=` form is explicit too"
        );
        assert!(cli.bt_lsd, "CLI not given = conf takes effect");
    }

    /// Domain validation reuses existing parsers: enums via the core
    /// parsers, the bool domain true|false, size/port/number domains
    /// matching the clap value_parsers — out-of-domain values fail fast.
    #[test]
    fn conf_value_domain_reuses_existing_parsers() {
        let verdict = |conf_text: &str| {
            let m = Cli::command()
                .try_get_matches_from(["taiji"])
                .unwrap_or_else(|e| panic!("must parse: {e}"));
            let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
            let entries = parse_conf_entries(conf_text);
            apply_conf_overrides(&m, &mut cli, Path::new("/tmp/t.conf"), &entries).map(|_| cli)
        };
        // Enums = the core option parse surface.
        assert!(verdict("bt-min-crypto-level=arc4\n").is_ok());
        assert!(
            verdict("bt-min-crypto-level=AES\n").is_err(),
            "out-of-domain core value rejected"
        );
        assert!(verdict("bt-peer-connection-type=utp\n").is_ok());
        assert!(verdict("bt-peer-connection-type=quic\n").is_err());
        // bool domain = true|false (no yes/1 — same domain as the flag
        // face).
        assert!(verdict("enable-dht=yes\n").is_err());
        assert!(verdict("bt-lsd=1\n").is_err());
        assert!(
            !verdict("enable-dht=false\n")
                .unwrap_or_else(|e| panic!("{e}"))
                .enable_dht
        );
        // Size = parse_aria2_size (the same function as
        // --rpc-max-request-size).
        assert_eq!(
            verdict("rpc-max-request-size=1M\n")
                .unwrap_or_else(|e| panic!("{e}"))
                .rpc_max_request_size,
            1024 * 1024
        );
        assert!(verdict("rpc-max-request-size=abc\n").is_err());
        // Port domain = u16.
        assert!(verdict("listen-port=70000\n").is_err());
        assert_eq!(
            verdict("rpc-listen-port=6900\n")
                .unwrap_or_else(|e| panic!("{e}"))
                .rpc_listen_port,
            6900
        );
        // summary-interval domain = 0..=SUMMARY_INTERVAL_MAX (same as
        // clap).
        assert_eq!(
            verdict("summary-interval=0\n")
                .unwrap_or_else(|e| panic!("{e}"))
                .summary_interval,
            0
        );
        assert!(
            verdict("summary-interval=2147483648\n").is_err(),
            "> i32::MAX rejected"
        );
        // http-max-per-host domain = >= 1 (same as clap range(1..)).
        assert!(verdict("http-max-per-host=0\n").is_err());
        assert_eq!(
            verdict("http-max-per-host=8\n")
                .unwrap_or_else(|e| panic!("{e}"))
                .http_max_per_host,
            Some(8)
        );
        // log-format domain = text|json (same as clap
        // PossibleValuesParser).
        assert!(verdict("log-format=json\n").is_ok());
        assert!(verdict("log-format=xml\n").is_err());
        // The hook family = the raw single-value command stored
        // verbatim (the same face as aria2
        // LocalFilePathOptionHandler PATH_TO_COMMAND — no domain
        // validation, no comma-split semantics; a literal containing a
        // comma stays a single value; the blank normalization lives at
        // the assembly point hook_set_from_cli, the same gate as the CLI
        // source).
        assert_eq!(
            verdict("on-download-complete=/bin/x,extra\n")
                .unwrap_or_else(|e| panic!("{e}"))
                .on_download_complete
                .as_deref(),
            Some("/bin/x,extra"),
            "hook value stored verbatim (single-value command surface, no comma splitting)"
        );
        assert_eq!(
            verdict("on-bt-download-complete=  \n")
                .unwrap_or_else(|e| panic!("{e}"))
                .on_bt_download_complete
                .as_deref(),
            Some(""),
            "whitespace-only value trims to the empty string at the parse layer \
             and is stored verbatim; the blank = unset normalization single point \
             lives at the assembly-point hook_set_from_cli (CLI/conf same gate)"
        );
        // The seed-ratio/alias/disclosure family: the value domains share the CLI
        // flag faces (the seed-ratio float domain mirrors the CLI
        // parse_seed_ratio_option rule; the alias keys share the primary
        // slots' domains; the disclosure family = the bool/verbatim
        // string/integer faces).
        assert_eq!(
            verdict("seed-ratio=2.5\n")
                .unwrap_or_else(|e| panic!("{e}"))
                .seed_ratio,
            Some(2.5)
        );
        assert!(
            verdict("seed-ratio=0\n")
                .unwrap_or_else(|e| panic!("{e}"))
                .seed_ratio
                == Some(0.0),
            "0.0 = the criterion disabled (the CLI same rule)"
        );
        assert!(
            verdict("seed-ratio=-1\n").is_err(),
            "out-of-domain rejected (ratio >= 0)"
        );
        assert!(verdict("seed-ratio=abc\n").is_err());
        assert!(
            verdict("bt-enable-lpd=true\n")
                .unwrap_or_else(|e| panic!("{e}"))
                .bt_lsd,
            "the alias key folds into the same bt-lsd slot"
        );
        assert!(verdict("bt-enable-lpd=1\n").is_err());
        assert_eq!(
            verdict("console-log-level=notice\n")
                .unwrap_or_else(|e| panic!("{e}"))
                .log_level
                .as_deref(),
            Some("notice"),
            "the alias key folds into the same log-level slot"
        );
        assert!(verdict("console-log-level=loud\n").is_err());
        assert!(
            !verdict("async-dns=false\n")
                .unwrap_or_else(|e| panic!("{e}"))
                .async_dns
                .unwrap_or(true)
        );
        assert!(verdict("async-dns=yes\n").is_err());
        assert_eq!(
            verdict("max-download-result=-1\n")
                .unwrap_or_else(|e| panic!("{e}"))
                .max_download_result,
            Some(-1),
            "the integer face tolerates the negative sentinel (never consumed)"
        );
        assert!(verdict("max-download-result=abc\n").is_err());
        assert_eq!(
            verdict("bt-exclude-tracker=udp://a:1/announce,udp://b:1/announce\n")
                .unwrap_or_else(|e| panic!("{e}"))
                .bt_exclude_tracker
                .as_deref(),
            Some("udp://a:1/announce,udp://b:1/announce"),
            "the comma multi-value string passes through verbatim"
        );
    }

    /// The four-pool budget trio: the conf value domains are
    /// the RPC face's same-source domains (seeds 0..=4096, checks
    /// 1..=16, synthesis 1..=16), hard-validated fail-fast (the
    /// max-concurrent-downloads arm shape — the RPC accepted-key rows
    /// clamp, the CLI/conf faces reject), and the projection lands in
    /// the Cli fields the session assembly injects.
    #[test]
    fn conf_budget_keys_domains_and_projection() {
        let verdict = |conf_text: &str| -> Result<Cli, String> {
            let m = Cli::command()
                .try_get_matches_from(["taiji"])
                .unwrap_or_else(|e| panic!("must parse: {e}"));
            let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
            let entries = parse_conf_entries(conf_text);
            apply_conf_overrides(&m, &mut cli, Path::new("/tmp/t.conf"), &entries)?;
            Ok(cli)
        };
        // In-domain values project (and the defaults match the
        // GlobalOptions defaults: 16/2/2 — the two-state seed note).
        let cli = verdict(
            "max-concurrent-seeds=24\nmax-concurrent-checks=3\nmedia-synthesis-concurrency=4\n",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(cli.max_concurrent_seeds, 24);
        assert_eq!(cli.max_concurrent_checks, 3);
        assert_eq!(cli.media_synthesis_concurrency, 4);
        let plain = Cli::command()
            .try_get_matches_from(["taiji"])
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        let plain = Cli::from_arg_matches(&plain).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            (
                plain.max_concurrent_seeds,
                plain.max_concurrent_checks,
                plain.media_synthesis_concurrency
            ),
            (16, 2, 2),
            "defaults 16/2/2 (the seed-budget two-state note = the not-yet-merged state)"
        );
        // seeds: 0 = unlimited passes; > 4096 rejected.
        assert_eq!(
            verdict("max-concurrent-seeds=0\n")
                .unwrap_or_else(|e| panic!("{e}"))
                .max_concurrent_seeds,
            0,
            "0 = unlimited passes through"
        );
        assert!(verdict("max-concurrent-seeds=4097\n").is_err());
        assert!(verdict("max-concurrent-seeds=-1\n").is_err());
        assert!(verdict("max-concurrent-seeds=abc\n").is_err());
        // checks: 1..=16 (no unlimited state).
        assert_eq!(
            verdict("max-concurrent-checks=1\n")
                .unwrap_or_else(|e| panic!("{e}"))
                .max_concurrent_checks,
            1
        );
        assert_eq!(
            verdict("max-concurrent-checks=16\n")
                .unwrap_or_else(|e| panic!("{e}"))
                .max_concurrent_checks,
            16
        );
        assert!(verdict("max-concurrent-checks=0\n").is_err());
        assert!(verdict("max-concurrent-checks=17\n").is_err());
        // synthesis: the same [1,16] domain.
        assert_eq!(
            verdict("media-synthesis-concurrency=16\n")
                .unwrap_or_else(|e| panic!("{e}"))
                .media_synthesis_concurrency,
            16
        );
        assert!(verdict("media-synthesis-concurrency=0\n").is_err());
        assert!(verdict("media-synthesis-concurrency=17\n").is_err());
        // cli_wins: an explicit CLI flag beats the conf entry (the
        // priority discipline).
        let m = Cli::command()
            .try_get_matches_from(["taiji", "--max-concurrent-seeds", "8"])
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
        let entries = parse_conf_entries("max-concurrent-seeds=24\n");
        apply_conf_overrides(&m, &mut cli, Path::new("/tmp/t.conf"), &entries)
            .unwrap_or_else(|e| panic!("valid conf rejected: {e}"));
        assert_eq!(cli.max_concurrent_seeds, 8, "explicit CLI wins over conf");
    }

    /// The conf face carries the RPC apply-side clamp's
    /// upper bound for max-concurrent-downloads ([1,64] — the memory
    /// amplification close; the budget trio's hard fail-fast shape,
    /// now including the downloads arm). Pre-fix the arm accepted any
    /// n >= 1, so a conf-pulled 128 slipped past startup and only the
    /// later changeGlobalOption path clamped.
    #[test]
    fn conf_max_concurrent_downloads_upper_bound() {
        let verdict = |conf_text: &str| -> Result<Cli, String> {
            let m = Cli::command()
                .try_get_matches_from(["taiji"])
                .unwrap_or_else(|e| panic!("must parse: {e}"));
            let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
            let entries = parse_conf_entries(conf_text);
            apply_conf_overrides(&m, &mut cli, Path::new("/tmp/t.conf"), &entries)?;
            Ok(cli)
        };
        assert_eq!(
            verdict("max-concurrent-downloads=64\n")
                .unwrap_or_else(|e| panic!("{e}"))
                .max_concurrent_downloads,
            64,
            "the bound itself accepts"
        );
        assert!(
            verdict("max-concurrent-downloads=65\n").is_err(),
            "n > 64 rejected at the conf face"
        );
        assert!(
            verdict("max-concurrent-downloads=0\n").is_err(),
            "n < 1 rejected at the conf face"
        );
    }

    /// The conf-path key: recognized but no-op (no nested loading — it
    /// does not change this process's conf_path and does not trigger a
    /// second read).
    #[test]
    fn conf_path_key_is_recognized_noop() {
        let m = Cli::command()
            .try_get_matches_from(["taiji"])
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
        let entries = parse_conf_entries("conf-path=/etc/another.conf\n");
        apply_conf_overrides(&m, &mut cli, Path::new("/tmp/t.conf"), &entries)
            .unwrap_or_else(|e| panic!("recognized key must be Ok: {e}"));
        assert!(cli.conf_path.is_none(), "no-op: no nested loading");
    }

    /// Registered key surface == clap-introspected long-name surface
    /// (long names + visible aliases; excluding the auto-generated
    /// help/version names and the `print-completions` meta flag — CLI
    /// plumbing: it writes a completion script to stdout and exits, no
    /// conf semantics; hidden aliases stay out too — the help face does
    /// not show them and the conf key face follows the help face) — a
    /// new Cli flag without a parse arm turns red (the
    /// missed-registration hole is closed; the same discipline as
    /// http.rs cli_long_options_all_have_declaration_or_are_cli_plumbing).
    /// Visible aliases join the surface
    /// (`bt-enable-lpd` folds into the bt-lsd slot, `console-log-level`
    /// into log-level — a visible alias is a CLI long-option name on the
    /// help face).
    #[test]
    fn conf_key_surface_matches_cli_long_options() {
        use clap::CommandFactory;
        let mut clap_longs: Vec<String> = Cli::command()
            .get_arguments()
            .filter_map(|a| a.get_long_and_visible_aliases().map(|ls| ls.to_vec()))
            .flatten()
            .map(str::to_string)
            .filter(|n| n != "help" && n != "version" && n != "print-completions")
            .collect();
        clap_longs.sort();
        let mut table: Vec<&str> = CONF_KEYS.to_vec();
        table.sort();
        assert_eq!(
            table, clap_longs,
            "the conf key surface must match the CLI long-option surface one to one"
        );
        // Hidden aliases stay out (the help face does not show them):
        // every alias name not in the visible set must be absent from
        // CONF_KEYS (the rpc-port precedent).
        for a in Cli::command().get_arguments() {
            let visible = a.get_visible_aliases().unwrap_or_default();
            for alias in a.get_aliases().unwrap_or_default().iter() {
                if !visible.contains(alias) {
                    assert!(
                        !CONF_KEYS.contains(alias),
                        "hidden alias {alias} must stay out of the conf key surface"
                    );
                }
            }
        }
    }

    /// Every CONF_KEYS name has a value arm: a registered name with a
    /// legal dummy value must walk through (otherwise it falls to the
    /// unknown/unreachable arm — table/arm drift turns red). The dummy
    /// table covers CONF_KEYS exhaustively; a new key without a dummy
    /// makes compilation infeasible (a non-exhaustive match).
    #[test]
    fn conf_keys_all_have_value_arms() {
        for key in CONF_KEYS {
            let m = Cli::command()
                .try_get_matches_from(["taiji"])
                .unwrap_or_else(|e| panic!("must parse: {e}"));
            let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
            let entries = vec![(
                1usize,
                (*key).to_string(),
                conf_dummy_value(key).to_string(),
            )];
            apply_conf_overrides(&m, &mut cli, Path::new("/tmp/t.conf"), &entries).unwrap_or_else(
                |e| panic!("registered key {key} must have a walkable value-domain arm: {e}"),
            );
        }
    }

    /// Legal dummy values for the registered keys (consumed by
    /// conf_keys_all_have_value_arms; each key takes any legal literal in
    /// its domain).
    fn conf_dummy_value(key: &str) -> &'static str {
        match key {
            "conf-path" => "/tmp/another.conf",
            "dir" | "sqlite3-db-path" | "bt-tracker-file" | "input-file" => "/tmp/x",
 // Domain B TLS/certificate path-face dummy values (stored
 // verbatim, no disk read — any path literal).
            "ca-certificate" | "certificate" | "private-key" | "rpc-certificate"
            | "rpc-private-key" => "/tmp/x",
            "listen-port" | "rpc-listen-port" => "6800",
            "bt-min-crypto-level" => "plain",
            "bt-peer-connection-type" => "tcp",
            "log-format" => "text",
            "log-level" => "debug",
 // Console/log family dummy values (legal literals in each
 // domain).
            "log" => "/tmp/taiji.log",
            "stderr" => "false",
            "human-readable" | "enable-color" => "true",
            "quiet" | "verbose" | "debug" | "log-verbatim-urls" => "true",
            "rpc-max-request-size" => "1M",
            "max-download-limit" | "max-upload-limit" => "2M",
            "summary-interval" => "60",
            "http-max-per-host" => "8",
 // bt-family dummy values (legal literals in each domain;
 // bt-max-peers takes >= 1 to stay clear of the "0 = unlimited
 // not expressible" warning arm).
            "bt-max-peers" => "55",
            "bt-request-peer-speed-limit" => "64K",
            "bt-stop-timeout" | "bt-tracker-interval" => "0",
            "bt-tracker-timeout" | "bt-tracker-connect-timeout" => "60",
            "rpc-secret" | "rpc-user" | "rpc-passwd" | "bt-tracker" | "peer-id-prefix" => "x",
 // The six hook command family dummy values (the raw
 // single-value face, no domain validation — any non-empty
 // literal).
            "on-download-start"
            | "on-download-pause"
            | "on-download-stop"
            | "on-download-complete"
            | "on-download-error"
            | "on-bt-download-complete" => "/bin/true",
 // Limits/dht/enable family dummy values (legal literals in
 // each domain).
            "max-concurrent-downloads" => "5",
            // The four-pool budget trio (legal literals in each domain;
            // the seeds dummy takes the merged 16 default).
            "max-concurrent-seeds" => "16",
            "max-concurrent-checks" | "media-synthesis-concurrency" => "2",
            "max-overall-download-limit" | "max-overall-upload-limit" => "1M",
            "dht-entry-point" => "router.bittorrent.com:6881",
            "dht-message-timeout" => "10",
 // Behavior-misc family dummy values (legal literals in each
 // domain: select-file a 1-based index, minute values, bool
 // two-state, string face).
            "select-file" => "1",
            "seed-time" | "stop" => "30",
            "hash-check-only" => "false",
            "peer-agent" => "x",
            "bt-require-crypto"
            | "bt-lsd"
            | "bt-sequential-download"
            | "check-integrity"
            | "enable-dht"
            | "enable-http-seeding"
            | "bt-enable-upnp"
            | "bt-enable-nat-pmp"
            | "enable-rpc"
            | "rpc-listen-all"
            | "rpc-allow-origin-all"
            | "rpc-aria2-compat"
            | "rpc-secure"
            | "bt-detach-seed-only"
            | "bt-hash-check-seed"
            | "bt-save-metadata"
            | "bt-metadata-only"
            | "bt-load-saved-metadata"
            | "bt-enable-hook-after-hash-check"
 // Limits/dht/enable family: PEX defaults true, dht6 defaults
 // false — the dummy takes "true" either way (any legal literal
 // in the domain walks the value arm).
            | "enable-peer-exchange"
            | "enable-dht6" => "true",
 // Domain B: the min-tls-version value-domain dummy (the
 // tls1.2|tls1.3 two-literal domain).
            "min-tls-version" => "tls1.2",
 // Domain C misc-family dummy values (legal literals in each
 // domain; the path pieces take the verbatim face,
 // auto-save-interval takes the in-domain 60, gid takes the
 // 16-hex-digit form).
            "load-cookies" | "save-cookies" | "save-session" | "netrc-path" => "/tmp/x",
            "save-session-interval" => "0",
            "auto-save-interval" => "60",
            "interface" => "eth0",
            "disable-ipv6" | "no-netrc" | "dry-run" | "show-files" => "true",
            "dht-entry-point6" => "router6.example.com:6881",
            "ftp-type" => "binary",
            "gid" => "1234567890abcdef",
// Seed-ratio/alias/disclosure family dummy values (legal literals in each
// domain: the seed-ratio float face, the visible-alias keys sharing
// their primary slots' domains, the disclosure family's bool /
// multi-value-string / integer faces).
            "seed-ratio" => "1.0",
            "bt-enable-lpd" => "true",
            "console-log-level" => "notice",
            "async-dns" | "enable-async-dns6" => "true",
            "bt-exclude-tracker" => "x",
            "max-download-result" | "max-file-not-found" | "max-mmap-limit"
            | "max-resume-failure-tries" => "0",
 // Every CONF_KEYS name needs a legal dummy — a new key without
 // an arm turns this panic red (a &str match has no compile-time
 // exhaustiveness; pinned at run time).
            other => panic!("new CONF_KEYS key {other} lacks a test dummy -- add conf_dummy_value"),
        }
    }

    /// Layered semantics of conf-provided enable-rpc against the two
    /// startup gates. Function layer: conf setting enable-rpc=true
    /// releases the `rpc_group_conflict` conflict arm (on that function's
    /// input fields a conf value ranks equal to a CLI value); without
    /// conf the arm fires as usual; the conf value alone does not trigger
    /// the arm (criterion = command-line source; see the module docs).
    /// Startup layer: `conf_enable_rpc_download_conflict` hard-errors
    /// first in download mode (mode restriction), so the released conflict
    /// arm cannot reach run in download mode.
    #[test]
    fn conf_enable_rpc_satisfies_rpc_group_conflict() {
        let m = Cli::command()
            .try_get_matches_from(["taiji", "x.torrent", "--rpc-listen-port", "16801"])
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
        // Before the conf overlay: download mode + an explicit RPC-group
        // option + enable-rpc default false -> the conflict arm fires
        // (the same truth table as main.rs).
        assert_eq!(
            crate::rpc_group_conflict(cli.torrent.is_some(), cli.enable_rpc, &m),
            Some(vec!["--rpc-listen-port"])
        );
        let entries = parse_conf_entries("enable-rpc=true\n");
        apply_conf_overrides(&m, &mut cli, Path::new("/tmp/t.conf"), &entries)
            .unwrap_or_else(|e| panic!("valid conf rejected: {e}"));
        assert!(cli.enable_rpc, "conf value writes the Cli field");
        assert_eq!(
            crate::rpc_group_conflict(cli.torrent.is_some(), cli.enable_rpc, &m),
            None,
            "conf-provided enable-rpc makes the RPC group options legal -- \
             the function-layer conflict arm is released"
        );
        assert!(
            crate::conf_enable_rpc_download_conflict(cli.torrent.is_some(), cli.enable_rpc, &m),
            "the startup-layer mode restriction fires first: in download mode \
             this exits 2 here, so the released arm cannot reach run()"
        );
    }

    /// Mode restriction (fail-closed): download mode + conf
    /// enable-rpc=true -> hard error (main exits 2 on the verdict). Both
    /// arm boundaries: with explicit CLI rpc-group options and conf
    /// enable-rpc=true, the function-layer conflict arm is released and
    /// this startup-layer arm is the only interception; an explicit CLI
    /// `--enable-rpc=false` overrides conf =true (the entry is not
    /// consumed) -> back to bare download, unrestricted.
    #[test]
    fn conf_enable_rpc_true_in_download_mode_fails_closed() {
        let entries = parse_conf_entries("enable-rpc=true\n");

        // Bare download args + conf enable-rpc=true: the default false is
        // raised to true with a non-command-line source -> rejected.
        let m = Cli::command()
            .try_get_matches_from(["taiji", "x.torrent"])
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
        apply_conf_overrides(&m, &mut cli, Path::new("/tmp/t.conf"), &entries)
            .unwrap_or_else(|e| panic!("valid conf rejected: {e}"));
        assert!(cli.enable_rpc, "conf value writes the Cli field");
        assert!(
            crate::conf_enable_rpc_download_conflict(cli.torrent.is_some(), cli.enable_rpc, &m),
            "download mode + conf enable-rpc=true must fail closed (the exit-2 surface)"
        );

        // Explicit CLI rpc-group options + conf enable-rpc=true:
        // rpc_group_conflict stays released (enable_rpc=true regardless
        // of source); the startup-layer arm fires first.
        let m = Cli::command()
            .try_get_matches_from(["taiji", "x.torrent", "--rpc-listen-port", "16801"])
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
        apply_conf_overrides(&m, &mut cli, Path::new("/tmp/t.conf"), &entries)
            .unwrap_or_else(|e| panic!("valid conf rejected: {e}"));
        assert_eq!(
            crate::rpc_group_conflict(cli.torrent.is_some(), cli.enable_rpc, &m),
            None,
            "the function-layer conflict arm is released (enable_rpc=true regardless of source)"
        );
        assert!(
            crate::conf_enable_rpc_download_conflict(cli.torrent.is_some(), cli.enable_rpc, &m),
            "in download mode this arm is the only interception surface for the conf RPC switch"
        );

        // An explicit CLI --enable-rpc=false always wins (the conf entry
        // is dead): bare download is unchanged.
        let m = Cli::command()
            .try_get_matches_from(["taiji", "x.torrent", "--enable-rpc=false"])
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
        apply_conf_overrides(&m, &mut cli, Path::new("/tmp/t.conf"), &entries)
            .unwrap_or_else(|e| panic!("valid conf rejected: {e}"));
        assert!(
            !cli.enable_rpc,
            "an explicit CLI flag always wins: the conf entry is not consumed"
        );
        assert!(
            !crate::conf_enable_rpc_download_conflict(cli.torrent.is_some(), cli.enable_rpc, &m),
            "bare download mode (RPC off) is not subject to the mode restriction"
        );
    }

    /// Mode restriction, second face: command-line explicit --enable-rpc
    /// plus conf tuning values (rpc-secret / rpc-listen-port) -> both
    /// gates pass and download+rpc assembles normally (conf tuning values
    /// are legal — the restriction targets only the conf-provided switch
    /// itself, it does not spill over to the other rpc-group items).
    #[test]
    fn cli_enable_rpc_with_conf_rpc_tuning_assembles_download_rpc() {
        let m = Cli::command()
            .try_get_matches_from(["taiji", "x.torrent", "--enable-rpc"])
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
        let entries = parse_conf_entries("rpc-secret=s3cr3t\nrpc-listen-port=16801\n");
        apply_conf_overrides(&m, &mut cli, Path::new("/tmp/t.conf"), &entries)
            .unwrap_or_else(|e| panic!("valid conf rejected: {e}"));
        assert_eq!(
            cli.rpc_secret.as_deref(),
            Some("s3cr3t"),
            "conf tuning values take effect"
        );
        assert_eq!(cli.rpc_listen_port, 16801, "conf tuning values take effect");
        assert!(
            !crate::conf_enable_rpc_download_conflict(cli.torrent.is_some(), cli.enable_rpc, &m),
            "a command-line-explicit --enable-rpc (source = command line) \
             is not subject to the mode restriction"
        );
        assert_eq!(
            crate::rpc_group_conflict(cli.torrent.is_some(), cli.enable_rpc, &m),
            None,
            "enable-rpc on -> the rpc group options are legal, \
             the download+rpc arm assembles normally"
        );
    }

    /// Mode restriction, third face: idle daemon + conf enable-rpc=true
    /// is unaffected (idle is the daemon form, RPC always on — a conf
    /// value ranks with the default, no unplanned listening surface).
    #[test]
    fn idle_daemon_conf_enable_rpc_unaffected() {
        let m = Cli::command()
            .try_get_matches_from(["taiji"])
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
        let entries = parse_conf_entries("enable-rpc=true\n");
        apply_conf_overrides(&m, &mut cli, Path::new("/tmp/t.conf"), &entries)
            .unwrap_or_else(|e| panic!("valid conf rejected: {e}"));
        assert!(cli.enable_rpc, "conf value writes the Cli field");
        assert!(
            !crate::conf_enable_rpc_download_conflict(cli.torrent.is_some(), cli.enable_rpc, &m),
            "idle mode (no positional args) is not subject to the conf enable-rpc mode restriction"
        );
    }

    /// Assembly parity across both forms: the same set of values injected
    /// via the CLI flag face and via the conf face produces
    /// indistinguishable session options at the shared assembly single
    /// point (build_idle_options -> IdleOptions::to_session_options,
    /// shared by run_idle and run_download_with_rpc) (GlobalOptions
    /// derive(Debug) full-field equality — including the echo projection
    /// source and the never-echoed rpc-secret).
    #[test]
    fn conf_and_cli_faces_are_indistinguishable_at_session_assembly() {
        // Assembly-point projection (isomorphic to the pre-run
        // derivation in run: crypto/conn_type -> build_idle_options ->
        // to_session_options).
        let project = |cli: &Cli| {
            let min_level = taiji_core::session::parse_crypto_level(&cli.bt_min_crypto_level)
                .unwrap_or_else(|| panic!("crypto level must parse"));
            let conn_type =
                taiji_core::session::parse_peer_connection_type(&cli.bt_peer_connection_type)
                    .unwrap_or_else(|| panic!("conn type must parse"));
            let crypto = taiji_bt::mse::CryptoPolicy {
                require_crypto: cli.bt_require_crypto,
                min_level,
            };
            let opts = crate::build_idle_options(cli, crypto, conn_type);
            opts.to_session_options(&crate::rpc_config_from_cli(cli))
        };

        // CLI face: all explicit flags.
        let m_cli = Cli::command()
            .try_get_matches_from([
                "taiji",
                "--dir",
                "/tmp/face",
                "--listen-port",
                "12345",
                "--enable-dht=false",
                "--bt-lsd",
                // ArgAction::Set requires a value (sidecar spawn contract;
                // no bare form).
                "--bt-detach-seed-only=true",
                "--rpc-secret",
                "s3cr3t",
                "--http-max-per-host",
                "8",
                "--summary-interval",
                "30",
                "--bt-tracker",
                "udp://a:1/announce",
                "--peer-id-prefix=-ZZ-",
                "--bt-enable-upnp",
                "--on-download-complete=/bin/on-complete",
                "--on-bt-download-complete",
                "/bin/bt-complete",
            ])
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        let cli_flag = Cli::from_arg_matches(&m_cli).unwrap_or_else(|e| panic!("{e}"));

        // conf face: the same values via conf (all CLI defaults — conf is
        // the only source).
        let m_conf = Cli::command()
            .try_get_matches_from(["taiji"])
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        let mut cli_conf = Cli::from_arg_matches(&m_conf).unwrap_or_else(|e| panic!("{e}"));
        let entries = parse_conf_entries(
            "dir=/tmp/face\nlisten-port=12345\nenable-dht=false\nbt-lsd=true\n\
             bt-detach-seed-only=true\nrpc-secret=s3cr3t\nhttp-max-per-host=8\n\
             summary-interval=30\nbt-tracker=udp://a:1/announce\npeer-id-prefix=-ZZ-\n\
             bt-enable-upnp=true\non-download-complete=/bin/on-complete\n\
             on-bt-download-complete=/bin/bt-complete\n",
        );
        apply_conf_overrides(&m_conf, &mut cli_conf, Path::new("/tmp/t.conf"), &entries)
            .unwrap_or_else(|e| panic!("valid conf rejected: {e}"));

        let so_flag = project(&cli_flag);
        let so_conf = project(&cli_conf);
        // GlobalOptions has no PartialEq — the derived Debug full-field
        // form is the single assertion surface for structural equality
        // (session-assembly global options + RPC credentials + echo
        // projection source).
        assert_eq!(
            format!("{:?}", so_flag.global),
            format!("{:?}", so_conf.global),
            "conf values and CLI values must be indistinguishable at the session \
             assembly point (GlobalOptions full-field)"
        );
    }

    /// conf rpc-secret blank normalization: `rpc-secret=` (and pure
    /// whitespace — the parse layer already trims line values, so the arm
    /// sees "") = unset (the aria2 empty-string = unset semantics; the
    /// same normalize single point as the CLI). Later-value-wins is
    /// unchanged.
    #[test]
    fn conf_rpc_secret_blank_value_normalizes_to_unset() {
        let m = Cli::command()
            .try_get_matches_from(["taiji"])
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
        let entries = parse_conf_entries("rpc-secret=\nrpc-secret=   \n");
        apply_conf_overrides(&m, &mut cli, Path::new("/tmp/t.conf"), &entries)
            .unwrap_or_else(|e| panic!("valid conf rejected: {e}"));
        assert_eq!(
            cli.rpc_secret, None,
            "a blank value normalizes to unset (later-value-wins unchanged)"
        );
    }

    /// Domain A: the `input-file` conf key face — the path is stored
    /// verbatim (existence/1MiB-cap validation lives on the
    /// run_input_file read face); an explicit CLI flag always wins (the
    /// conf entry is dead).
    #[test]
    fn conf_input_file_key_sets_batch_list_path() {
        let entries = parse_conf_entries("input-file=/tmp/urls.txt\n");
        let m = Cli::command()
            .try_get_matches_from(["taiji"])
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
        apply_conf_overrides(&m, &mut cli, Path::new("/tmp/t.conf"), &entries)
            .unwrap_or_else(|e| panic!("valid conf rejected: {e}"));
        assert_eq!(cli.input_file, Some(PathBuf::from("/tmp/urls.txt")));
        // An explicit CLI flag always wins: the conf entry is not
        // consumed.
        let m = Cli::command()
            .try_get_matches_from(["taiji", "--input-file=/from/cli.txt"])
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
        apply_conf_overrides(&m, &mut cli, Path::new("/tmp/t.conf"), &entries)
            .unwrap_or_else(|e| panic!("valid conf rejected: {e}"));
        assert_eq!(
            cli.input_file,
            Some(PathBuf::from("/from/cli.txt")),
            "an explicit CLI flag always wins (conf < CLI)"
        );
    }

    /// Domain A: the --input-file batch form is subject to the same
    /// conf enable-rpc mode restriction ([`crate::download_mode_given`]
    /// criterion covers the batch list — conf sets true with a
    /// non-command-line source = the hard-error face, the same gate as
    /// the positional-arg download form; the batch-list variant of
    /// conf_enable_rpc_true_in_download_mode_fails_closed).
    #[test]
    fn conf_enable_rpc_true_in_input_file_batch_fails_closed() {
        let entries = parse_conf_entries("enable-rpc=true\n");
        let m = Cli::command()
            .try_get_matches_from(["taiji", "--input-file", "u.txt"])
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
        apply_conf_overrides(&m, &mut cli, Path::new("/tmp/t.conf"), &entries)
            .unwrap_or_else(|e| panic!("valid conf rejected: {e}"));
        assert!(cli.enable_rpc, "conf value writes the Cli field");
        assert!(
            crate::conf_enable_rpc_download_conflict(
                crate::download_mode_given(&cli),
                cli.enable_rpc,
                &m
            ),
            "the batch form + conf enable-rpc=true must fail closed (the exit-2 surface)"
        );
    }

    /// Domain B decision table: the conf-face writes of the TLS/
    /// certificate family's seven keys (defaults < conf layer) — the
    /// three path pieces / ca-certificate stored verbatim, the rpc-secure
    /// bool, the min-tls version domain, the rpc TLS path pair.
    #[test]
    fn conf_tls_certificate_family_keys_write_fields() {
        let entries = parse_conf_entries(
            "ca-certificate=/etc/ca.pem\n\
             certificate=/etc/client.pem\n\
             private-key=/etc/client.key\n\
             min-tls-version=tls1.3\n\
             rpc-secure=true\n\
             rpc-certificate=/etc/rpc.pem\n\
             rpc-private-key=/etc/rpc.key\n",
        );
        let m = Cli::command()
            .try_get_matches_from(["taiji"])
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
        apply_conf_overrides(&m, &mut cli, Path::new("/tmp/t.conf"), &entries)
            .unwrap_or_else(|e| panic!("valid conf rejected: {e}"));
        assert_eq!(
            cli.ca_certificate.as_deref(),
            Some("/etc/ca.pem"),
            "ca-certificate stored verbatim (validation belongs to the session-resolution arm)"
        );
        assert_eq!(cli.certificate, Some(PathBuf::from("/etc/client.pem")));
        assert_eq!(cli.private_key, Some(PathBuf::from("/etc/client.key")));
        assert_eq!(cli.min_tls_version.as_deref(), Some("tls1.3"));
        assert!(cli.rpc_secure, "rpc-secure bool surface write");
        assert_eq!(cli.rpc_certificate, Some(PathBuf::from("/etc/rpc.pem")));
        assert_eq!(cli.rpc_private_key, Some(PathBuf::from("/etc/rpc.key")));
    }

    /// Domain B: an explicit CLI flag always wins (the conf entry is a
    /// dead value, not consumed — the domain B face check of the
    /// priority defaults < conf < CLI; spot-checks one path piece and
    /// one bool/version domain each).
    #[test]
    fn conf_tls_keys_yield_to_explicit_cli_flags() {
        let entries = parse_conf_entries(
            "ca-certificate=/from/conf.pem\n\
             min-tls-version=tls1.2\n\
             rpc-secure=true\n",
        );
        let m = Cli::command()
            .try_get_matches_from([
                "taiji",
                "--ca-certificate=/from/cli.pem",
                "--min-tls-version=tls1.3",
                "--rpc-secure=false",
            ])
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
        apply_conf_overrides(&m, &mut cli, Path::new("/tmp/t.conf"), &entries)
            .unwrap_or_else(|e| panic!("valid conf rejected: {e}"));
        assert_eq!(
            cli.ca_certificate.as_deref(),
            Some("/from/cli.pem"),
            "explicit CLI always wins"
        );
        assert_eq!(
            cli.min_tls_version.as_deref(),
            Some("tls1.3"),
            "explicit CLI always wins"
        );
        assert!(
            !cli.rpc_secure,
            "explicit --rpc-secure=false suppresses conf true"
        );
    }

    /// Domain B: value-domain fail-fast — a min-tls-version
    /// out-of-domain value / an rpc-secure non-bool literal (bad conf =
    /// rejected, the same policy as unknown keys).
    #[test]
    fn conf_tls_keys_reject_out_of_domain_values() {
        for bad in [
            "min-tls-version=tls1.1",
            "min-tls-version=TLSv1.2",
            "rpc-secure=yes",
        ] {
            let entries = parse_conf_entries(&format!("{bad}\n"));
            let m = Cli::command()
                .try_get_matches_from(["taiji"])
                .unwrap_or_else(|e| panic!("must parse: {e}"));
            let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
            let err = apply_conf_overrides(&m, &mut cli, Path::new("/tmp/t.conf"), &entries);
            assert!(err.is_err(), "{bad} must be rejected");
        }
    }

    /// Domain C decision table: the conf-face writes of the misc
    /// family's fourteen keys (defaults < conf layer) — the path pieces
    /// stored verbatim, the interval domains, the bool family, the
    /// HOST:PORT domain, the GID high-bit normalization, the ftp-type
    /// two-literal domain.
    #[test]
    fn conf_domain_c_keys_write_fields() {
        let entries = parse_conf_entries(
            "load-cookies=/etc/cookies.txt\n\
             save-cookies=/etc/save-cookies.txt\n\
             save-session=/etc/session.txt\n\
             save-session-interval=90\n\
             auto-save-interval=60\n\
             interface=eth1\n\
             disable-ipv6=true\n\
             dht-entry-point6=[2001:db8::1]:6881\n\
             ftp-type=ascii\n\
             netrc-path=/home/u/.netrc\n\
             no-netrc=true\n\
             gid=1234567890abcdef\n\
             dry-run=true\n\
             show-files=false\n",
        );
        let m = Cli::command()
            .try_get_matches_from(["taiji"])
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
        apply_conf_overrides(&m, &mut cli, Path::new("/tmp/t.conf"), &entries)
            .unwrap_or_else(|e| panic!("valid conf rejected: {e}"));
        assert_eq!(
            cli.load_cookies.as_deref().map(Path::new),
            Some(Path::new("/etc/cookies.txt"))
        );
        assert_eq!(
            cli.save_cookies.as_deref().map(Path::new),
            Some(Path::new("/etc/save-cookies.txt"))
        );
        assert_eq!(
            cli.save_session.as_deref().map(Path::new),
            Some(Path::new("/etc/session.txt"))
        );
        assert_eq!(cli.save_session_interval, 90);
        assert_eq!(cli.auto_save_interval, Some(60));
        assert_eq!(cli.interface.as_deref(), Some("eth1"));
        assert_eq!(cli.disable_ipv6, Some(true));
        assert_eq!(
            cli.dht_entry_point6.as_deref(),
            Some("[2001:db8::1]:6881"),
            "HOST:PORT passes through verbatim (the bracketed v6 form)"
        );
        assert_eq!(cli.ftp_type.as_deref(), Some("ascii"));
        assert_eq!(
            cli.netrc_path.as_deref().map(Path::new),
            Some(Path::new("/home/u/.netrc"))
        );
        assert_eq!(cli.no_netrc, Some(true));
        assert!(
            cli.gid.is_some(),
            "16-hex-digit pass-through (high-bit normalization)"
        );
        assert_eq!(cli.dry_run, Some(true));
        assert!(!cli.show_files);
    }

    /// Domain C: an explicit CLI flag always wins (the conf entry is a
    /// dead value, not consumed — the domain C face check of the
    /// priority defaults < conf < CLI; spot-checks one path piece / one
    /// bool piece / one domain piece each).
    #[test]
    fn conf_domain_c_keys_yield_to_explicit_cli_flags() {
        let entries = parse_conf_entries(
            "load-cookies=/from/conf.txt\n\
             save-session-interval=999\n\
             disable-ipv6=true\n",
        );
        let m = Cli::command()
            .try_get_matches_from([
                "taiji",
                "--load-cookies=/from/cli.txt",
                "--save-session-interval=5",
                "--disable-ipv6=false",
            ])
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
        apply_conf_overrides(&m, &mut cli, Path::new("/tmp/t.conf"), &entries)
            .unwrap_or_else(|e| panic!("valid conf rejected: {e}"));
        assert_eq!(
            cli.load_cookies.as_deref().map(Path::new),
            Some(Path::new("/from/cli.txt")),
            "explicit CLI always wins"
        );
        assert_eq!(cli.save_session_interval, 5, "explicit CLI always wins");
        assert_eq!(
            cli.disable_ipv6,
            Some(false),
            "explicit false suppresses conf true"
        );
    }

    /// Domain C: value-domain fail-fast — auto-save-interval over the
    /// upper bound / an out-of-domain ftp-type / a malformed gid / a
    /// bare-colon v6 dht-entry-point6 / non-literal bools (bad conf =
    /// rejected, the same policy as unknown keys).
    #[test]
    fn conf_domain_c_keys_reject_out_of_domain_values() {
        for bad in [
            "auto-save-interval=601",
            "ftp-type=quic",
            "gid=short",
            "dht-entry-point6=2001:db8::1:6881",
            "disable-ipv6=yes",
            "dry-run=1",
        ] {
            let entries = parse_conf_entries(&format!("{bad}\n"));
            let m = Cli::command()
                .try_get_matches_from(["taiji"])
                .unwrap_or_else(|e| panic!("must parse: {e}"));
            let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
            let err = apply_conf_overrides(&m, &mut cli, Path::new("/tmp/t.conf"), &entries);
            assert!(err.is_err(), "{bad} must be rejected");
        }
    }

    /// Console/log family conf face: the log/stderr/human-readable/
    /// enable-color registered keys write back to the Cli fields (log =
    /// a PathBuf; the rest = the conf_bool true|false domain, rejected
    /// out of domain); an explicit CLI flag always wins (the same
    /// cli_wins rule); the single-stream/two-target combination (log and
    /// stderr together) writes back per key here and is rejected by the
    /// main-side open_log_target fail-fast (never silently picking one —
    /// only the field face is pinned here).
    #[test]
    fn conf_log_family_keys_apply() {
        let apply = |conf_text: &str| {
            let m = Cli::command()
                .try_get_matches_from(["taiji"])
                .unwrap_or_else(|e| panic!("must parse: {e}"));
            let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
            let entries = parse_conf_entries(conf_text);
            apply_conf_overrides(&m, &mut cli, Path::new("/tmp/t.conf"), &entries).map(|_| cli)
        };
        let cli = apply(
            "log=/var/log/taiji.log\nstderr=true\nhuman-readable=false\nenable-color=false\n",
        )
        .unwrap_or_else(|e| panic!("valid conf rejected: {e}"));
        assert_eq!(
            cli.log,
            Some(PathBuf::from("/var/log/taiji.log")),
            "log key writes back to the Cli field"
        );
        assert!(cli.stderr, "stderr key writes back to the Cli field");
        assert!(!cli.human_readable, "human-readable=false writes back");
        assert!(!cli.enable_color, "enable-color=false writes back");
        // The bool domain = true|false (out-of-domain rejected — the same
        // domain as the flag face).
        assert!(apply("stderr=1\n").is_err());
        assert!(apply("enable-color=yes\n").is_err());
        // An explicit CLI flag always wins: an explicit --log overrides
        // the conf log entry (the entry is not consumed).
        let m = Cli::command()
            .try_get_matches_from(["taiji", "--log", "/from/cli.log"])
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        let mut cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
        let entries = parse_conf_entries("log=/from/conf.log\n");
        apply_conf_overrides(&m, &mut cli, Path::new("/tmp/t.conf"), &entries)
            .unwrap_or_else(|e| panic!("valid conf rejected: {e}"));
        assert_eq!(
            cli.log,
            Some(PathBuf::from("/from/cli.log")),
            "explicit CLI flag wins (the conf entry is not consumed)"
        );
    }
}
