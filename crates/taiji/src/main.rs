//! `taiji` — the binary entry point (crates/taiji).
//!
//! Modes (mirrors the upstream three-state assembly, ):
//! - **Download mode** (a .torrent positional arg is given): parse the
//!   metainfo -> DownloadEngine download -> once all pieces complete,
//!   stay resident seeding; Ctrl-C/SIGTERM exits gracefully
//!   (part 3c; the M0 deliverable "command-line `taiji <torrent> -d dir`
//!   downloads a public-swarm torrent to completion and seeds it");
//! - **Download + RPC co-residence** (download mode + `--enable-rpc`):
//!   an RPC server starts in the same process — the engine path goes
//!   through the SessionActor pipeline (shared with idle) and the
//!   torrent is injected directly via the AddTorrent session command
//!   ([`run_download_with_rpc`] mirrors the third state of the
//!   `DownloadEngineFactory.cc` three-state assembly);
//! - **Idle mode** (no positional arg): actor topology bootstrap + RPC
//!   service (axum `POST/GET /jsonrpc`, token/Basic auth, six methods) +
//!   signal/RPC dual-driven graceful shutdown (1s budget, SPEC
//!   §8.1);
//! - **Migration import mode** (`import` subcommand: SPEC §10 —
//!   read-only import from a fork sqlite / `.aria2` file plus an aria2
//!   dereg list, see [`import`]);
//! - **HTTP one-shot download** (`http` subcommand: SessionActor-driven
//!   with session-db bitmap resume, see [`http`]);
//! - **Batch download** (`--input-file <FILE>`, domain A: the aria2
//!   `-i` counterpart — list lines are classified one by one into the
//!   same session pipeline, exit code summarized once all tasks reach a
//!   terminal state, see [`run_input_file`]);
//! - **Completion script generation** (the
//!   `--print-completions <bash|zsh|fish>` meta flag, :
//!   prints the minimal completion script to stdout and exits — enters
//!   no download/session mode, see [`completions`]).
//!
//! Option naming freeze: `--dir`/`--listen-port`/`--rpc-*` are
//! aria2-compatible names. aria2's `--listen-port` accepts a port range
//! and tries the ports one by one; the M0 bare form takes a single
//! value (range/per-port fallback lands with the Session option panel
//! in M1+).
//!
//! # Exit-code system ( audit doc — records the current
//! state and divergences only, no behavior change)
//!
//! **Common baseline** ([`main`] entry layer, shared by the three
//! modes, applied before mode dispatch):
//! - `2` = usage/startup hard error: clap parse failure (value-domain
//!   rejection/missing arg), `--conf-path` fail-fast (unknown key /
//!   unreadable file), download-mode RPC group option conflict
//!   ([`rpc_group_conflict`]), conf-provided enable-rpc
//!   ([`conf_enable_rpc_download_conflict`]),
//!   `--bt-min-crypto-level`/`--bt-peer-connection-type` value-domain
//!   rejection;
//! - `1` = process infrastructure failure: tokio runtime build failure.
//!
//! Three-mode comparison (per code; the `http` column covers both the
//! top-level URL positional delegation form and the `http` subcommand —
//! same pipeline, same mapping; bare = a .torrent positional arg,
//! [`run_download`]; idle = no positional arg, [`run_idle`]):
//!
//! - `0` — bare: download complete / seeding stopped / Ctrl-C·SIGTERM
//!   graceful shutdown (signal = 0); http: task Complete (signal = 1,
//!   see divergence ①); idle: signal or RPC shutdown graceful stop
//!   (still 0 beyond the 1s budget, see divergence ②).
//! - `1` — bare: torrent read/parse/engine-config failure, engine
//!   Failed/panic, shutdown over the 1s budget; http: task
//!   error/removed, signal interrupt, concurrent session lock held,
//!   attach refused / in-flight row read failure / malformed gid,
//!   non-value-domain session command error; idle: RPC bind failure
//!   (the only 1 face).
//! - `2` — bare: none (common baseline only); http: session command
//!   value-domain rejection (`taiji.option.invalid` prefix,
//!   `http::exit_code_of`), lock-file filesystem failure, missing URL,
//!   metalink document failure (read/over-cap/parse/zero entries);
//!   idle: none (common baseline only).
//!
//! Documented divergences ( discipline: record faithfully, no
//! behavior change):
//! ① **Signal interrupt**: the BT modes (bare/magnet one-shot/
//! download+rpc) and idle finish gracefully on Ctrl-C/SIGTERM = 0;
//! the http pipeline's signal interrupt = 1 (http.rs terminal-state
//! poll `break 1`).
//! ② **Shutdown over the 1s budget**: bare = 1 (the engine did not stop
//! within the budget, the main.rs shutdown select arm); idle = 0
//! ([`shutdown_session_and_server`] logs an error beyond the budget
//! but does not report failure back).
//! ③ **Startup input-error grading**: bare torrent read/parse failure =
//! 1; the http counterparts (option value domain / lock IO /
//! document failure) = 2 — the error-grading granularity differs
//! and is not unified.
//! ④ **Magnet positional one-shot** ([`run_one_shot_magnet`], no RPC):
//! the lock face is shared with http (held = 1 / lock IO = 2,
//! `http::acquire_db_lock`), signal exit = 0, task Error = 1; the
//! download+rpc form ([`run_download_with_rpc`]) maps like the bare
//! family (intake/injection/bind failure = 1, graceful shutdown =
//! 0).
//! ⑤ **Subcommand face**: `import`/`create-torrent` only 0/1 (0 =
//! success, 1 = failure), no in-mode 2 face.
//! ⑥ **Domain A batch form** (`--input-file`, [`run_input_file`]):
//! 0 = all tasks Complete; 1 = any line failed (task terminal
//! Error/Removed, creation refused, malformed list line, .torrent
//! read failure) or a signal interrupt — summarized binary; the
//! single-task forms' value-domain-rejection 2 face
//! (`taiji.option.invalid`) folds into 1 on the batch face (the ask
//! contract "any failure = 1"); 2 = file-face startup hard error
//! (list missing/unreadable/over the 1MiB cap/non-UTF-8/zero valid
//! lines) and `--input-file` given together with a positional arg
//! (the clap conflict arm, same code).

mod completions;
mod conf;
mod create_torrent;
mod db_lock;
mod http;
mod import;
mod media;

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use taiji_bt::tracker;
use taiji_core::engine::{DownloadEngine, EngineEnd};
use taiji_core::metainfo::{Metainfo, MetainfoError};

/// Total graceful-shutdown budget: exit within 1s of Ctrl-C.
const SHUTDOWN_BUDGET: Duration = Duration::from_secs(1);

/// Budget for the NAT teardown (unmap + pump stop) on the bare-download
/// exit path; same value as the `taiji-core` session actor's
/// NAT_SHUTDOWN_BUDGET (250ms). The delete request is advisory (RFC 6886
/// §3.1 — the 3600s lifetime expiry reclaims the mapping gateway-side as
/// a backstop); a slow or malicious IGD can stall DeletePortMapping up to
/// HTTP-timeout scale (~10s per protocol), so an unbounded wait would eat
/// into the SHUTDOWN_BUDGET exit contract. On expiry the wait is
/// abandoned; the exit code is unchanged.
const NAT_SHUTDOWN_BUDGET: Duration = Duration::from_millis(250);

/// Subcommand surface (coexists with the positional arg / idle mode: a
/// first token matching a subcommand name dispatches there).
#[derive(Subcommand, Debug)]
enum Command {
    /// Migration importer: read-only import from a fork sqlite / `.aria2`
    /// file plus an aria2 dereg list.
    Import(import::ImportArgs),
    /// Torrent creator: explicit file list -> .torrent (same facade and
    /// argument surface as the RPC `taiji.createTorrent` method).
    CreateTorrent(create_torrent::CreateTorrentArgs),
    /// HTTP(S)/FTP(S) one-shot download (SessionActor-driven with
    /// session-db bitmap resume; see [`http::HttpArgs`]).
    Http(Box<http::HttpArgs>),
    /// Media face (M0: `media doctor` — ffmpeg/ffprobe health check,
    /// see [`media::MediaArgs`]).
    Media(Box<media::MediaArgs>),
}

/// Top-level positional dispatch: a `magnet:` or `http(s)|ftp(s)://`
/// prefix routes to a session-pipeline one-shot download; anything else
/// is a `.torrent` file path (the existing direct-engine path is
/// unchanged). Scheme matching is case-insensitive (RFC 3986); `ftps://`
/// is not accepted (same rule as the http subcommand: FTPS = `ftp://` +
/// `--ftp-ssl`).
enum PositionalInput {
    /// `.torrent` file path (the existing surface for both the bare
    /// direct-engine path and download+rpc injection).
    TorrentFile(PathBuf),
    /// `magnet:` URI — session-pipeline one-shot (AddUri, then wait for a
    /// terminal state).
    MagnetUri(String),
    /// `http(s)|ftp(s)://` URL — delegated to the http subcommand
    /// pipeline (attach, resume, and exit-code mapping fully reused).
    WebUri(String),
}

fn classify_positional(raw: &std::ffi::OsStr) -> PositionalInput {
    let lower = raw.to_string_lossy().to_ascii_lowercase();
    if lower.starts_with("magnet:") {
        return PositionalInput::MagnetUri(raw.to_string_lossy().into_owned());
    }
    if lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("ftp://")
    {
        return PositionalInput::WebUri(raw.to_string_lossy().into_owned());
    }
    PositionalInput::TorrentFile(PathBuf::from(raw))
}

/// `--help` tail examples (clap `after_help`). Two alignment facts: the
/// checksum value uses the `sha-256=<hex>` hyphen form (the http.rs value
/// domain is `md5|sha-1|sha-224|sha-256|sha-384|sha-512=<hex>`); and the
/// daemon example must carry credentials — `--rpc-listen-all` without
/// credentials is a fail-closed startup refusal (exit 2), so the examples
/// only show runnable commands.
const EXAMPLES_AFTER_HELP: &str = "\
EXAMPLES:
  # Download a .torrent (seeds in place after completion; Ctrl-C exits gracefully)
  taiji file.torrent -d ~/downloads

  # One-shot magnet download (session pipeline: metadata -> payload)
  taiji 'magnet:?xt=urn:btih:<infohash>'

  # HTTP(S)/FTP(S) one-shot download (session-db bitmap resume; a rerun \
after an interruption resumes)
  taiji https://example.com/file.iso

  # http subcommand + completion-phase checksum (mismatch = task error, exit code 1)
  taiji http https://example.com/file.iso --checksum sha-256=<hex>

  # Long-running RPC daemon (--rpc-listen-all requires credentials -- \
without them startup fail-closed refuses)
  taiji --enable-rpc --rpc-listen-all --rpc-secret <token>
";

#[derive(Parser, Debug)]
#[command(
    name = "taiji",
    about = "Motrix next-gen download engine sidecar: BT/HTTP(S)/FTP(S)/metalink/magnet one-shot downloads + RPC daemon (aria2-compatible option surface)",
    after_help = EXAMPLES_AFTER_HELP,
 // Subcommands (import/create-torrent) are mutually exclusive with the
 // top-level [TORRENT] positional: without this declaration clap would
 // misroute a subcommand's first positional arg to [TORRENT].
    args_conflicts_with_subcommands = true
)]
struct Cli {
    /// Subcommand (`import`).
    #[command(subcommand)]
    command: Option<Command>,
    /// .torrent file path (given = download mode: seed after completion
    /// until Ctrl-C).
    torrent: Option<PathBuf>,
    /// Batch download list (aria2-compatible name `--input-file`,
    /// domain A; aria2 prefs.cc `PREF_INPUT_FILE`, consumption
    /// points Context.cc / download_helper.cc
    /// `createRequestGroupForUriList`). One URI per line
    /// (magnet:/http(s)/ftp(s)) or a local `.torrent` path; blank lines
    /// and `#` comment lines are skipped (same rule as aria2
    /// UriListParser.cc); in-line tab-separated per-task options
    /// (`uri\tout=x\tmax-download-limit=5M` — the aria2 uri\toption
    /// in-line syntax; the single key-domain parse point = the session
    /// `parse_task_options` — unknown keys are ignored like aria2
    /// `RpcMethod.cc`, the CLI keeps no second key-domain
    /// verdict). aria2's "option lines follow the URI line" multi-line
    /// syntax is not in this form (only the in-line tab form is
    /// supported — a follow line would be accepted as a .torrent path
    /// and fail explicitly at the read face, not silently). Multiple
    /// lines = multiple tasks into one session (concurrency clamped by
    /// `--max-concurrent-downloads` — the existing session face); once
    /// all tasks reach a terminal state the exit code is summarized:
    /// any line failed (including task creation refused / malformed
    /// list line / read failure) = 1, all passed = 0; file
    /// missing/unreadable/over the 1MiB cap/non-UTF-8/zero valid lines
    /// = 2. Mutually exclusive with the [TORRENT] positional (clap
    /// `conflicts_with` + the runtime recheck arm for conf-origin
    /// values — main). Disk reads via spawn_blocking + the 1MiB cap
    /// (pre-read precheck + post-read recheck, same shape as
    /// bt-tracker-file — the cap is also the memory-face anchor: a
    /// realistic 100k-line list of full-length URIs far exceeds 1MiB,
    /// over-cap = refused, so the input text is always <= 1MiB).
    /// Boundary disclosure: a task with in-line `pause=true` stays in
    /// Paused (not a terminal state) — the batch face "wait for all
    /// terminal states" keeps waiting on that task until a signal
    /// winds things down; use with care in batch scenarios.
    #[arg(long, value_name = "FILE", conflicts_with = "torrent")]
    input_file: Option<PathBuf>,
    /// Download directory (aria2-compatible name `--dir`; default: the
    /// current directory).
    #[arg(short, long, default_value = ".")]
    dir: PathBuf,
    /// BT listen port (aria2-compatible name `--listen-port`; single
    /// value).
    #[arg(long, default_value_t = 6881)]
    listen_port: u16,
    /// Reject unencrypted BT connections (aria2-compatible name
    /// `--bt-require-crypto`; default false = encryption optional). true =
    /// outbound connections must start with MSE (no plaintext fallback),
    /// legacy inbound is refused, and announce carries `requirecrypto=1`.
    /// Both the bare flag and the `=true|=false` value forms are accepted
    /// (aria2 bool-option dual form).
    #[arg(
        long,
        default_value_t = false,
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    bt_require_crypto: bool,
    /// Minimum MSE crypto level (aria2-compatible name
    /// `--bt-min-crypto-level`; domain plain|arc4, default plain).
    #[arg(long, default_value = "plain", value_parser = clap::builder::PossibleValuesParser::new(["plain", "arc4"]))]
    bt_min_crypto_level: String,
    /// Outbound peer connection type (aria2-compatible name
    /// `--bt-peer-connection-type`; domain tcp|utp|prefer-utp|prefer-tcp,
    /// default prefer-tcp). All four states feed the engine's outbound
    /// dial plan (prefer-* retries once over the other transport; pure
    /// types do not downgrade); inbound always accepts both TCP and µTP.
    /// Injected identically in download and idle mode (idle via the
    /// session option table, download via controlled spawn parameters).
    #[arg(
        long,
        default_value = "prefer-tcp",
        value_parser = clap::builder::PossibleValuesParser::new([
            "tcp", "utp", "prefer-utp", "prefer-tcp"
        ])
    )]
    bt_peer_connection_type: String,
    /// LSD switch (aria2-compatible name `--bt-lsd`; default **false**,
    /// same rule as aria2 `PREF_BT_ENABLE_LPD`). true = the engine spawns
    /// the LSD multicast send/receive service at startup
    /// (239.192.152.143:6771, BEP14) — idle mode goes through the session
    /// option surface (torrent announce/withdraw + discovery consumption
    /// in the magnet metadata phase); bare download mode is announce-only.
    /// Disabled for private torrents (BEP27; aria2 BtSetup.cc same rule).
    /// Both the bare flag and the `=true|=false` value forms are accepted.
    /// Alias: `--bt-enable-lpd` is the aria2 original name (prefs.cc
    /// `PREF_BT_ENABLE_LPD`; a **visible** alias — the help and completion
    /// faces list it) folding into the same slot end to end: the CLI
    /// field here, the conf key `bt-enable-lpd`, and the session face
    /// (the GLOBAL_PATCH_TABLE pairs the names onto the same `g.bt_lsd`
    /// slot).
    #[arg(
        long,
        visible_alias = "bt-enable-lpd",
        default_value_t = false,
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    bt_lsd: bool,
    /// Sequential download switch (aria2-compatible name
    /// `--bt-sequential-download`; default **false**, same rule as aria2
    /// `PREF_BT_SEQUENTIAL_DOWNLOAD`). Bare mode pushes the sequential
    /// policy via SetSchedulerPolicy after spawn; download+rpc mode
    /// injects the `bt-sequential-download=true` AddTorrent option (the
    /// session side projects it onto scheduler_policy).
    #[arg(
        long,
        default_value_t = false,
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    bt_sequential_download: bool,
    /// File integrity check switch (aria2-compatible name
    /// `--check-integrity`; default **false**, same rule as aria2
    /// `PREF_CHECK_INTEGRITY`, so the bare default changes nothing).
    /// true = before engine spawn, rehash existing files in the target
    /// directory piece by piece (the same entry point as `session::recheck`
    /// and checking-state re-entry — v1 full SHA-1 / v2 piece root, with
    /// progress logged on a 1s cadence); the verified bitmap feeds
    /// `EngineConfig.preset_progress` as the engine's bitmap resume point:
    /// verified pieces skip re-download (serviceable/seeding right away),
    /// full completion goes straight to seeding, and missing files are
    /// still created (allocate path untouched). A failed rescan warns and
    /// downloads from scratch (same tolerance as a session-side recheck
    /// failure; no exit). Both the bare flag and the `=true|=false` value
    /// forms are accepted (aria2 bool-option dual form).
    #[arg(
        long,
        default_value_t = false,
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    check_integrity: bool,
    /// DHT switch (aria2-compatible name `--enable-dht`; default
    /// **true**, same rule as aria2 `PREF_ENABLE_DHT`). Download (bare)
    /// mode injects `DhtWireConfig::enabled` (per-family DHT engine +
    /// handshake DHT bit/PORT + UDP demux dht channel + torrent announce);
    /// idle mode injects the session global option `enable_dht` (consumed
    /// at engine spawn via `cfg.dht.enabled`). Both the bare flag and the
    /// `=true|=false` value forms are accepted.
    #[arg(
        long,
        default_value_t = true,
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    enable_dht: bool,
    /// HTTP webseeding switch (taiji extension option
    /// `--enable-http-seeding`; aria2 has no such switch — url-list is
    /// always used; the difference is declared in the session option
    /// surface DECLARED_OPTION_DIFFS). Default **true**: the .torrent
    /// top-level `url-list` (BEP19, both single-string and list forms)
    /// projects onto the engine webseed set; false discards it
    /// (`c.webseeds.clear` — BT-only mode; the original url-list stays
    /// in the metainfo, so re-enabling is lossless). Bare download mode
    /// overwrites after engine assembly; download+rpc mode injects the
    /// AddTorrent task option `enable-http-seeding=false` (cleared at the
    /// same point of the session activation chain). Both the bare flag
    /// and the `=true|=false` value forms are accepted (aria2 bool-option
    /// dual form).
    #[arg(
        long,
        default_value_t = true,
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    enable_http_seeding: bool,
    /// UPnP IGD port-mapping switch (aria2-compatible name
    /// `--bt-enable-upnp`; default **false**). Provenance note: aria2
    /// upstream has no such option (no aria2 default to mirror); the
    /// contrast libtorrent RC_2_0 `settings_pack.cpp` `enable_upnp`
    /// defaults to true. Keeping it off here preserves default-zero
    /// behavior change, and NAT mapping is an inline wait point — a slow
    /// IGD can take minutes for a single-protocol mapping, so defaulting
    /// on would delay announce/download start; users opt in explicitly.
    /// true = idle mode powers the NAT singleton actor via session
    /// options (UPnP IGD + NAT-PMP mapping of listen-port + external-port
    /// watch feeding DHT announce); bare download mode powers a
    /// single-task supervisor on the same surface. Mapping failure
    /// degrades without blocking the download. Both the bare flag and the
    /// `=true|=false` value forms are accepted. Startup-time option
    /// (applies on restart).
    #[arg(
        long = "bt-enable-upnp",
        default_value_t = false,
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    bt_enable_upnp: bool,
    /// NAT-PMP port-mapping switch (aria2-compatible name
    /// `--bt-enable-nat-pmp`; default **false** — a contrast note:
    /// libtorrent `settings_pack.cpp` `enable_natpmp` defaults to true;
    /// otherwise the same rules as `--bt-enable-upnp`). Startup-time
    /// option (applies on restart).
    #[arg(
        long = "bt-enable-nat-pmp",
        default_value_t = false,
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    bt_enable_natpmp: bool,
    /// Per-task download rate limit (aria2-compatible name
    /// `--max-download-limit`; bytes/s, `0 = unlimited` — the frozen
    /// aria2 default is the same; size literals `2M`/`500K` are
    /// 1024-based, parsed by [`parse_aria2_size`], the same parser as
    /// `--rpc-max-request-size`). Download (bare) mode assembles
    /// `EngineConfig.limiter` via [`build_session_limiter`] (all four
    /// values 0 = None, keeping the existing pass-through with zero
    /// behavior change; this pair fills the per_torrent bucket and the
    /// `--max-overall-*` pair fills the global bucket). The RPC key
    /// `max-download-limit` has the same name and
    /// semantics (existing session surface; this entry only fills the CLI
    /// bare-mode gap). Startup-time option (applies on restart; session
    /// modes hot-reload via changeGlobalOption/changeOption instead).
    #[arg(
        long = "max-download-limit",
        default_value = "0",
        value_parser = parse_aria2_size
    )]
    max_download_limit: u64,
    /// Per-task upload rate limit (aria2-compatible name
    /// `--max-upload-limit`; semantics/parsing as `--max-download-limit`
    /// — `0 = unlimited`, 1024-based size literals; same wiring: bare
    /// mode throttles each peer stream's wire rate, the guard for small
    /// uplink connections). Startup-time option (applies on restart).
    #[arg(
        long = "max-upload-limit",
        default_value = "0",
        value_parser = parse_aria2_size
    )]
    max_upload_limit: u64,
    /// RPC co-residence switch (aria2-compatible name `--enable-rpc`;
    /// default **false**, same rule as `OptionHandlerFactory.cc`
    /// A2_V_FALSE). Mirrors the upstream three-state assembly in
    /// `DownloadEngineFactory.cc`: pure download / pure daemon /
    /// download+RPC in one process. In download mode this starts an RPC
    /// server in the same process — the engine path goes through the
    /// SessionActor pipeline (shared with idle) and the torrent is
    /// injected directly via the AddTorrent session command (no RPC
    /// self-call — bypasses the write gate and credential requirement);
    /// task lifecycle matches bare mode (seeding residence) and the
    /// process stays up until a signal / RPC shutdown. In idle mode this
    /// option has no effect (idle is the daemon form; RPC is always on —
    /// semantics unchanged). Both the bare flag and the `=true|=false`
    /// value forms are accepted (aria2 bool-option dual form).
    /// Invariant (require_equals): a boolean flag must not swallow a
    /// positional argument — the value may only be passed via `=`
    /// (`x.torrent` in `--enable-rpc x.torrent` always stays the
    /// positional); the bare form behaves as before
    /// (default_missing_value semantics unchanged) and the aria2 `=value`
    /// form is preserved. Startup-time option.
    #[arg(
        long,
        default_value_t = false,
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    enable_rpc: bool,
    /// RPC listen port (aria2-compatible name `--rpc-listen-port`;
    /// default 6800).
    #[arg(long, alias = "rpc-port", default_value_t = 6800)]
    rpc_listen_port: u16,
    /// RPC all-interface listen switch (aria2-compatible name
    /// `--rpc-listen-all`; default **false**, same rule as
    /// `OptionHandlerFactory.cc` A2_V_FALSE). Binding axis: true binds
    /// 0.0.0.0 (all interfaces); false binds 127.0.0.1 only (usage_text.h
    /// "If false is given, listen only on local loopback interface").
    /// Decoupled from credentials: secret/Basic only gate authentication
    /// and never widen the bind surface — setting `--rpc-secret` keeps
    /// the bind surface at loopback. Controlled divergence (fail-closed):
    /// listen_all with no credential at all refuses to start (aria2 only
    /// WARNs and listens anyway on this combination,
    /// DownloadEngineFactory.cc) — set `--rpc-secret` (recommended) or
    /// `--rpc-user/--rpc-passwd`, or drop this switch. Both the bare flag
    /// and the `=true|=false` value forms are accepted.
    #[arg(
        long,
        default_value_t = false,
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    rpc_listen_all: bool,
    /// RPC secret token (aria2-compatible name `--rpc-secret`;
    /// authentication gate only — never part of the bind decision, which
    /// only looks at `--rpc-listen-all`; the two axes are decoupled). A
    /// startup warning fires when no credential is set at all.
    #[arg(long)]
    rpc_secret: Option<String>,
    /// Basic auth user (aria2-compatible name `--rpc-user`; deprecated
    /// upstream but still compatible, OptionHandlerFactory.cc).
    /// Independent of `--rpc-secret`: Basic only looks at user/passwd,
    /// token auth only at the secret — the reference has the same shape.
    #[arg(long)]
    rpc_user: Option<String>,
    /// Basic auth password (aria2-compatible name `--rpc-passwd`; unset =
    /// the password is not checked).
    #[arg(long)]
    rpc_passwd: Option<String>,
    /// Allow CORS from all origins (aria2-compatible name
    /// `--rpc-allow-origin-all`).
    #[arg(long, default_value_t = false)]
    rpc_allow_origin_all: bool,
    /// RPC request body cap (aria2-compatible name
    /// `--rpc-max-request-size`; K/M/G suffixes are 1024-based, default
    /// 10M).
    #[arg(long, default_value = "10M", value_parser = parse_aria2_size)]
    rpc_max_request_size: u64,
    /// RPC over TLS switch (aria2-compatible name `--rpc-secure`,
    /// domain B; aria2 OptionHandlerFactory.cc
    /// `PREF_RPC_SECURE`, default false = zero change to the plaintext
    /// HTTP/WS status quo). true = the RPC listener switches to TLS
    /// (a tokio-rustls TlsAcceptor wrapping the TCP listener + the
    /// hyper-util service ring — the WS upgrade face / Basic+token
    /// auth gate / binding axis / all middleware are unchanged across
    /// the transport). The assembly pair = [`Self::rpc_certificate`] +
    /// [`Self::rpc_private_key`] (either missing = refused, fail-closed
    /// at the serve assembly point — io::Error -> exit 1, same flow as
    /// a bind failure). Both the bare flag and the `=true|=false` value
    /// forms are accepted (the aria2 bool dual form). RPC group option
    /// ( conflict arm): explicitly given in download mode
    /// without `--enable-rpc` = hard error.
    #[arg(
        long,
        default_value_t = false,
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    rpc_secure: bool,
    /// RPC TLS server certificate (aria2-compatible name
    /// `--rpc-certificate`, domain B; aria2 prefs.cc
    /// `makePref("rpc-certificate")`; a PEM `CERTIFICATE` section, a
    /// multi-section certificate chain allowed). Consumed only when
    /// [`Self::rpc_secure`] = true; given one-sided (no secure, or no
    /// [`Self::rpc_private_key`]) = startup refused (explicitness —
    /// silently ignoring a security piece violates the fail-closed
    /// discipline; the aria2 docs require `--rpc-secure` alongside,
    /// made a hard error here).
    #[arg(long = "rpc-certificate", value_name = "FILE")]
    rpc_certificate: Option<PathBuf>,
    /// RPC TLS server private key (aria2-compatible name
    /// `--rpc-private-key`, domain B; aria2 prefs.cc
    /// `makePref("rpc-private-key")`; PEM — a PKCS#8/RSA/EC private-key
    /// section, any of them). Consumed in pairs with
    /// [`Self::rpc_certificate`]; a certificate without a private key =
    /// refused at the serve assembly point. Nothing outside the private
    /// key path ever enters a log.
    #[arg(long = "rpc-private-key", value_name = "FILE")]
    rpc_private_key: Option<PathBuf>,
    /// aria2 alias mode (taiji extension option `--rpc-aria2-compat`;
    /// default false, session-level startup option). On = the methods
    /// additionally accept `aria2.*` aliases, the six events are pushed
    /// as `aria2.onXxx`, and system.listMethods/listNotifications present
    /// the aria2 face (for full aria2-fork diffing and drop-in use by
    /// external aria2 frontends); off = the single canonical `taiji.*`
    /// face. **Only one API face exists at a time; dual emission is
    /// forbidden**; the `system.*` introspection family and the `taiji.*`
    /// extension methods/events keep the same names across the two
    /// states. Both the bare flag and the `=true|=false` value forms are
    /// accepted (aria2 bool-option dual form).
    #[arg(
        long = "rpc-aria2-compat",
        default_value_t = false,
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    rpc_aria2_compat: bool,
    /// Session database path (aria2-compatible name `--sqlite3-db-path`;
    /// default taiji.sqlite3). Idle mode (RPC service) persists through
    /// PersistWriter: torrent rows, bitmap/counters, tracker rows,
    /// dht_state (the primary crash-recovery store). An open failure
    /// warns and runs without persistence (same as bootstrap; no
    /// masquerading).
    #[arg(long, default_value = "taiji.sqlite3")]
    sqlite3_db_path: PathBuf,
    /// Seed-only tasks do not occupy a concurrency slot
    /// (aria2-compatible name `--bt-detach-seed-only`; default false).
    /// The sidecar spawn contract passes it explicitly in the
    /// `--bt-detach-seed-only=false` value form, so this uses
    /// ArgAction::Set (value required) rather than a switch where mere
    /// presence implies true.
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    bt_detach_seed_only: bool,
    /// Global tracker comma list (aria2-compatible name `--bt-tracker`).
    /// Initial source of the global import set: idle mode injects it into
    /// the session and persists it to the taiji.sqlite3 `global_tracker`
    /// table (union accumulation, restored across restarts); download
    /// mode merges it into this module's effective list (each entry
    /// appended as its own tier, mirroring aria2 bittorrent_helper.cc
    /// addAnnounceUri).
    #[arg(long, default_value = "")]
    bt_tracker: String,
    /// ngosang/trackerslist file (`--bt-tracker-file`, taiji extension;
    /// aria2 has no such option). One URL per line; `#` comments and
    /// blank lines are skipped; capped at 1MiB (parsed by
    /// `taiji_bt::tracker::trackerslist`, disk reads via
    /// spawn_blocking). Idle mode imports the global set and persists it;
    /// download mode merges it into this module's effective list. A
    /// missing/oversized file warns and degrades without blocking
    /// startup.
    #[arg(long)]
    bt_tracker_file: Option<PathBuf>,
    /// Per-torrent peer cap (aria2-compatible name `--bt-max-peers`;
    /// default **55**, domain >= 0 — aria2
    /// `NumberOptionHandler(PREF_BT_MAX_PEERS, …, "55", 0)` anchor
    /// OptionHandlerFactory.cc; 0 = unlimited). Wiring (knob-override
    /// seam): when given explicitly (command line; conf values enter via
    /// the same surface), feeds `taiji_io::knobs::set_peer_max_override`
    /// — the engine's hard connection cap applies from the first
    /// admission round (built-in cap 120, mirroring `BH_PEER_MAX`;
    /// built-in outbound target 100 is defensively clamped via
    /// min(hard cap), keeping the "target < cap" ordering invariant).
    /// Documented divergences: (1) aria2's 0 = unlimited is not
    /// expressible here — the engine always enforces a cap, so an
    /// explicit 0 warns and keeps the built-in default (the same
    /// "0 falls back to default" rule as the BH_ family); (2) the default
    /// applies no override (built-ins 120/100 stay — the
    /// default-zero-behavior rule; the divergence from aria2's
    /// per-torrent 55 default is a deliberate taiji-engine choice), an
    /// explicit `--bt-max-peers 55` converges to 55. The session echo
    /// surface is GlobalOptions.bt_max_peers (value default 55,
    /// aria2-consistent; this flag reaches the idle-session echo via
    /// injection).
    #[arg(long, default_value_t = 55, value_parser = clap::value_parser!(u64).range(0..))]
    bt_max_peers: u64,
    /// Outbound dial supply threshold (aria2-compatible name
    /// `--bt-request-peer-speed-limit`; default **50K** = aria2
    /// `UnitNumberOptionHandler(…, "50K", 0)` anchor
    /// OptionHandlerFactory.cc; bytes/s, K/M/G size literals are
    /// 1024-based via [`parse_aria2_size`]; domain >= 0; 0 makes the rate
    /// test always "healthy", disabling the admission rescue arm — the
    /// same domain semantics as aria2's min 0). Wiring: when given
    /// explicitly, feeds
    /// `taiji_io::knobs::set_peer_request_speed_limit_override` — the
    /// download-health reading of the engine's connection-admission
    /// decision (slow => the rescue arm admits, mirroring
    /// `PeerReceiveHandshakeCommand.cc`). The default applies no override
    /// (built-in 50K, same as aria2 — zero behavior difference).
    #[arg(
        long = "bt-request-peer-speed-limit",
        default_value = "50K",
        value_parser = parse_aria2_size
    )]
    bt_request_peer_speed_limit: u64,
    /// Seeding-stall watchdog (aria2-compatible name `--bt-stop-timeout`;
    /// seconds, default **0** = not armed — aria2
    /// `NumberOptionHandler(…, "0", 0)` anchor OptionHandlerFactory.cc).
    /// Wiring: bare mode injects `EngineConfig.seed.stop_timeout`
    /// (BtStopTimeoutWatch: N consecutive seconds of zero throughput
    /// after completion wind down and exit, ported from BtSetup.cc); the
    /// session modes inject via the task option key `bt-stop-timeout` /
    /// changeGlobalOption (per-task explicit value wins, otherwise the
    /// global default). The magnet one-shot form forwards it via AddUri
    /// options (the key is written only when > 0).
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u64).range(0..))]
    bt_stop_timeout: u64,
    /// Tracker re-announce interval override (aria2-compatible name
    /// `--bt-tracker-interval`; seconds, default **0** = no override,
    /// follow the tracker's returned interval — the same aria2 default,
    /// anchor OptionHandlerFactory.cc). Wiring: the engine tracker
    /// actor's announce client (`TrackerOptions.bt_tracker_interval` ->
    /// `apply_interval_settings` userDefinedInterval_,
    /// DefaultBtAnnounce.cc); the session modes inject via GlobalOptions
    /// (accepted by changeGlobalOption, applying to subsequently
    /// activated tasks). Scope note: the magnet metadata-phase announce
    /// and the .torrent byte fetch do not go through this value
    /// (existing `TrackerOptions::default` behavior — a declared
    /// divergence, also noted on EngineConfig.tracker_options).
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u64).range(0..))]
    bt_tracker_interval: u64,
    /// HTTP announce total timeout (aria2-compatible name
    /// `--bt-tracker-timeout`; seconds, default **60**, domain 1..=600 —
    /// aria2 `NumberOptionHandler(…, "60", 1, 600)` anchor
    /// OptionHandlerFactory.cc). Wiring: reqwest timeout (bt::tracker
    /// `TrackerOptions.bt_tracker_timeout`); the session modes inject
    /// via GlobalOptions. UDP announce has no per-request timeout concept
    /// (its transaction retransmit cadence is its own); only the HTTP
    /// carrier consumes this value (same as the reference).
    #[arg(
        long,
        default_value_t = 60,
        value_parser = clap::value_parser!(u64).range(1..=600)
    )]
    bt_tracker_timeout: u64,
    /// HTTP announce connect timeout (aria2-compatible name
    /// `--bt-tracker-connect-timeout`; seconds, default **60**, domain
    /// 1..=600 — aria2 `NumberOptionHandler(…, "60", 1, 600)` anchor
    /// OptionHandlerFactory.cc). Wiring: reqwest connect_timeout; the
    /// UDP carrier does not consume it (same as the reference).
    #[arg(
        long,
        default_value_t = 60,
        value_parser = clap::value_parser!(u64).range(1..=600)
    )]
    bt_tracker_connect_timeout: u64,
    /// Post-hash-check seeding gate (aria2-compatible name
    /// `--bt-hash-check-seed`; default **true**, same rule as aria2
    /// `A2_V_TRUE`, OptionHandlerFactory.cc). Combined with
    /// `--check-integrity` in bare mode: true = a fully verified recheck
    /// goes straight to seeding residence (existing behavior); false =
    /// `EngineConfig.seed_after_complete = false` — exit after
    /// recheck/repair without seeding (aria2 "check file and download it
    /// only when it is damaged" semantics). Without `--check-integrity`
    /// this flag has no effect (aria2-consistent — the gate only belongs
    /// to the post-check seeding point). Both the bare flag and the
    /// `=true|=false` value forms are accepted.
    #[arg(
        long,
        default_value_t = true,
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    bt_hash_check_seed: bool,
    /// Magnet metadata save switch (aria2-compatible name
    /// `--bt-save-metadata`; default **false**, same rule as aria2
    /// `A2_V_FALSE`, OptionHandlerFactory.cc). true = after the metadata
    /// download completes, write `<hex infohash>.torrent` into the
    /// `--dir` directory — both magnet arms (one-shot and magnet+rpc)
    /// forward it via the AddUri option `bt-save-metadata` (existing
    /// consumer in the session magnet chain). No effect for
    /// torrent-file/HTTP input (aria2 "only when Magnet URI is used"
    /// rule). Both the bare flag and the `=true|=false` value forms are
    /// accepted.
    #[arg(
        long,
        default_value_t = false,
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    bt_save_metadata: bool,
    /// Metadata-only switch (aria2-compatible name `--bt-metadata-only`;
    /// default **false**, aria2-consistent, OptionHandlerFactory.cc).
    /// true = the task reaches a terminal state once metadata is complete
    /// (payload files are not downloaded) — both magnet arms forward it
    /// via the AddUri option `bt-metadata-only` (existing consumer in the
    /// session magnet chain). Both the bare flag and the `=true|=false`
    /// value forms are accepted.
    #[arg(
        long,
        default_value_t = false,
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    bt_metadata_only: bool,
    /// Magnet metadata local pre-read switch (aria2-compatible name
    /// `--bt-load-saved-metadata`; default **false**, aria2-consistent,
    /// OptionHandlerFactory.cc). true = before fetching metadata, read an
    /// existing `<hex infohash>.torrent` (written by
    /// `--bt-save-metadata`) from `--dir` and skip the network fetch on a
    /// hit — both magnet arms forward it via AddUri options (existing
    /// consumer in the session magnet chain). Both the bare flag and the
    /// `=true|=false` value forms are accepted.
    #[arg(
        long,
        default_value_t = false,
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    bt_load_saved_metadata: bool,
    /// Post-hash-check hook gate (aria2-compatible name
    /// `--bt-enable-hook-after-hash-check`; default **true** — the same
    /// rule as the aria2 `A2_V_TRUE` at OptionHandlerFactory.cc-
    /// 1476). **Wiring (-B, both session forms)**: injects the
    /// `GlobalOptions.hooks` gate slot (an existing session global
    /// option: the hook gate at the recheck-completed trigger point, a
    /// literal port of `BtCheckIntegrityEntry.cc` — the normal
    /// completion path carries no gate, same as aria2). The bare
    /// form injects alongside `hook_set_from_cli` and carries it via
    /// `EngineConfig.hook` (the gate slot's consumption point = the
    /// session recheck trigger; the bare form has no such trigger point
    /// — declared as-is, the normal completion path carries no gate,
    /// same as aria2). Both the bare flag and the `=true|=false`
    /// value forms are accepted; changeGlobalOption hot-reload follows
    /// the existing session face (aria2 setChangeGlobalOption
    /// slot, same rule).
    #[arg(
        long,
        default_value_t = true,
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    bt_enable_hook_after_hash_check: bool,
    /// Task-start hook (aria2-compatible name `--on-download-start`,
    /// SPEC §7.4). Trigger point = group activation time (a literal
    /// port of `RequestGroupMan.cc`; the semantics source is the
    /// `taiji_core::hook` module docs). Value face = **a single value,
    /// the raw command passed through** (aria2
    /// `LocalFilePathOptionHandler(…, PATH_TO_COMMAND)` single-value
    /// face, `OptionHandlerFactory.cc` — no comma-separated
    /// multi-command semantics; a bare name is looked up via PATH);
    /// execution = argv payload `[command, gidHex16, numFiles,
    /// firstFilename]`, **no shell, no placeholder substitution** (a
    /// literal port of aria2 `util.cc` executeHook; an
    /// explicitly forbidden design item). Empty value = unset (blank
    /// normalization, same rule as aria2 `option->blank`).
    /// **Wiring**: the two session forms (idle/download+rpc) inject
    /// into `GlobalOptions.hooks` via [`IdleOptions`]; bare/magnet
    /// one-shot inject via the session globals or `EngineConfig.hook`.
    /// The hook family is a startup-time option (aria2
    /// LocalFilePathOptionHandler has no changeGlobalOption slot —
    /// changeGlobalOption does not accept it, the session face follows
    /// the same rule).
    #[arg(long = "on-download-start")]
    on_download_start: Option<String>,
    /// Task-pause hook (aria2-compatible name `--on-download-pause`,
    /// SPEC §7.4). Trigger point = a pause winds down back to the queue
    /// head and is not a restart (`RequestGroupMan.cc`; the restart
    /// branch does not trigger, `:451-453` — semantics source
    /// `taiji_core::hook`). Value face / execution model / wiring face
    /// as [`Self::on_download_start`].
    #[arg(long = "on-download-pause")]
    on_download_pause: Option<String>,
    /// Task-stop hook (aria2-compatible name `--on-download-stop`,
    /// SPEC §7.4). Trigger point = the remaining arms of the wind-down
    /// three-branch split (including REMOVED/IN_PROGRESS —
    /// `RequestGroupMan.cc` executeStopHook; FINISHED goes to
    /// complete and errors go to error, the rest go here).
    /// Value face / execution model / wiring face as
    /// [`Self::on_download_start`].
    #[arg(long = "on-download-stop")]
    on_download_stop: Option<String>,
    /// Task-complete hook (aria2-compatible name
    /// `--on-download-complete`, SPEC §7.4). Trigger point = the
    /// FINISHED arm of the wind-down three-branch split
    /// (`RequestGroupMan.cc`; covers stop — a BT task that
    /// winds down after the `--on-bt-download-complete` trigger point
    /// fires here as well, aria2 event order from the same
    /// source). Value face / execution model / wiring face as
    /// [`Self::on_download_start`].
    #[arg(long = "on-download-complete")]
    on_download_complete: Option<String>,
    /// Task-failure hook (aria2-compatible name `--on-download-error`,
    /// SPEC §7.4). Trigger point = the error arm of the wind-down
    /// three-branch split (an error terminal state that is not
    /// IN_PROGRESS/REMOVED — `RequestGroupMan.cc`, covers
    /// stop). Value face / execution model / wiring face as
    /// [`Self::on_download_start`].
    #[arg(long = "on-download-error")]
    on_download_error: Option<String>,
    /// BT-task-complete hook (aria2-compatible name
    /// `--on-bt-download-complete`, SPEC §7.4). Trigger point = the
    /// moment a BT download completes and turns to seeding
    /// (`DefaultPieceStorage.cc`, no option gate; fires twice
    /// with `--on-download-complete` — this point first, per the
    /// RequestGroupMan.cc event order). Value face / execution
    /// model / wiring face as [`Self::on_download_start`].
    #[arg(long = "on-bt-download-complete")]
    on_bt_download_complete: Option<String>,
    /// Peer ID prefix (aria2-compatible name `--peer-id-prefix`; default
    /// `-TJ0001-` = byte-identical to the previous behavior when unset).
    /// Semantics match aria2 (bittorrent_helper.cc + usage_text.h):
    /// prefix padded with random bytes to 20B; **over 20B is truncated to
    /// the first 20B (not rejected)**; no charset validation. The tracker
    /// announce and the peer handshake consume the same value from the
    /// single generation point (bt `generate_peer_id`). Startup-time
    /// option (applies on restart, no hot reload). Independent of the
    /// UA/ext-handshake `v` string (aria2 `--peer-agent` is also a
    /// separate option, OptionHandlerFactory.cc).
    #[arg(long)]
    peer_id_prefix: Option<String>,
    /// BEP 53 file selection (aria2-compatible name `--select-file`; a
    /// **1-based** comma-separated closed-range list, e.g. `1-3,5` —
    /// usage_text.h "Set file to download by specifying its index").
    /// Parsing/conversion goes through the session single point
    /// `taiji_core::session::parse_select_file` (the only source of the
    /// 1-based -> 0-based conversion; strictly increasing, domain
    /// 1..=1048576 = the aria2 `1_m` cap). Effective face per form: bare
    /// download = range validation once the metainfo is known
    /// (`select_file_range_error`, over non-pad files) + a
    /// `SetFileSelection` push after the engine spawns (consumed before
    /// announce connects, the same slot as `--bt-sequential-download`);
    /// download+rpc = injected as the AddTorrent task option (the same
    /// session point for parse/range check/error face); the idle daemon
    /// has no task face and does not consume it (the same rule as
    /// `--bt-sequential-download`).
    #[arg(long = "select-file")]
    select_file: Option<String>,
    /// Seeding time limit (aria2-compatible name `--seed-time`;
    /// **minutes**, fractional values allowed — the same unit as
    /// usage_text.h "Specify seeding time in (fractional) minutes").
    /// Effective face per form: bare download = the engine seed policy
    /// mounts TimeSeedCriteria (the SeedCheck latch timer **starts at
    /// the download-completion moment**, the `BtSetup.cc` same rule;
    /// `SeedPolicy.seed_time`), seeding stops gracefully when it
    /// elapses; download+rpc/idle = injected as the session global
    /// default (`GlobalOptions.seed_time_min` — tasks whose add payload
    /// carries no seed-time fall back to this value, getGlobalOption
    /// echo). 0 = no time limit (the aria2 `SeedCheck::build`
    /// `seed_time > 0` same rule — the bare default stays resident
    /// seeding until a signal, so this value's default changes nothing).
    /// Domain >= 0; negative / non-finite / beyond the Duration domain =
    /// startup refusal exit 2.
    #[arg(long = "seed-time", allow_negative_numbers = true)]
    seed_time: Option<f64>,
    /// Seeding ratio threshold (aria2-compatible name `--seed-ratio`;
    /// prefs.cc `makePref("seed-ratio")`, the OptionHandlerFactory.cc
    /// NumberOptionHandler "1.0" default — the same value as the engine
    /// `SeedPolicy` default and the session `GlobalOptions.seed_ratio`
    /// default). Effective face per form: bare download = the engine seed
    /// policy mounts ShareRatioSeedCriteria (`SeedCheck::build`, the
    /// `seed_ratio > 0.0` rule — seeding stops gracefully when the
    /// upload/completed ratio reaches N); **`0.0` disables the ratio
    /// criterion** (the aria2 "If 0 is given, this feature is disabled"
    /// same rule — the task seeds until a signal or the seed-time
    /// criterion); idle/download+rpc inject the session global default
    /// (`GlobalOptions.seed_ratio` — tasks whose add payload carries no
    /// seed-ratio fall back to this value, getGlobalOption echo).
    /// Unset = the standing 1.0 default everywhere (zero change). Scope
    /// note: the magnet one-shot / input-file batch / URL positional
    /// forms keep the built-in default (the same scope as `--seed-time`
    /// — their one-shot session globals do not carry this face).
    /// Value domain: finite >= 0 (mirrors the core `checked_seed_ratio`
    /// rule; negative/non-finite = startup refusal exit 2; the aria2
    /// `0.0|RATIO` float face).
    #[arg(long = "seed-ratio", allow_negative_numbers = true)]
    seed_ratio: Option<f64>,
    /// Process shutdown deadline (aria2-compatible name `--stop`).
    /// **Declared unit divergence**: aria2 `--stop=SEC` (seconds,
    /// usage_text.h TEXT_STOP) vs **minutes here** — symmetric with
    /// `--seed-time` (the declared-diffs table `stop` entry). Semantics
    /// = graceful shutdown after the process has run for N minutes (the
    /// aria2 "Stop application after SEC seconds has passed" same rule —
    /// wall clock from process start): bare = the same path as the
    /// shutdown signal (cancel + in-budget engine wind-down);
    /// download+rpc/idle = the RPC shutdown path (token cancel + actor
    /// drain). 0 = disabled (aria2 same rule). Domain >= 0 (negative /
    /// non-finite = startup refusal exit 2).
    #[arg(long = "stop", allow_negative_numbers = true)]
    stop: Option<f64>,
    /// Verify only, no download (aria2-compatible name
    /// `--hash-check-only`; both the bare flag and the `=true|=false`
    /// value forms are accepted — the BooleanOptionHandler same shape).
    /// **Effective in the bare download form**: after the metainfo
    /// parses, recheck all pieces of the on-disk content
    /// (`session::recheck::recheck_on_disk`, the single verification
    /// source — the same function as the session forceRecheck/bootstrap;
    /// v1 full-piece SHA-1 / v2 Merkle; v2 files missing the piece layer
    /// are reported honestly as suspended), **no engine spawn, no
    /// download**: all pieces verified (nothing suspended) = exit 0,
    /// otherwise exit 1. Combined with `--enable-rpc` in the download
    /// form = explicit refusal exit 2 (the RPC pipeline has no per-task
    /// pre-download verification face; accepting it would break the
    /// "no download" promise — fail-closed, declared-diffs entry); the
    /// idle daemon has no task face = accepted + a not-effective
    /// warning. The aria2 semantic anchor = the `--check-integrity`
    /// pairing (usage_text.h TEXT_HASH_CHECK_ONLY).
    #[arg(
        long,
        default_value_t = false,
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    hash_check_only: bool,
    /// BT client UA / ext-handshake `v` string (aria2-compatible name
    /// `--peer-agent`, OptionHandlerFactory.cc "Set client
    /// reported during Extended torrent handshakes"). **Accepted but
    /// treated as not effective + one warning** (the same disclosure
    /// style as `--use-head` — no masquerading): this build pins the
    /// string to the build constant (taiji-bt `tracker::PEER_AGENT` —
    /// private-tracker risk control checks UA and peer id **both**, two
    /// independent allow-lists; a configurable UA would pollute the
    /// identification face). **Not an alias of `--peer-id-prefix`**: the
    /// two are separate aria2 options and this build keeps them
    /// structurally separate (see the peer-id-prefix field doc — the
    /// alias stance is the cross-check conclusion of this doc and the
    /// declared-diffs entry).
    #[arg(long = "peer-agent")]
    peer_agent: Option<String>,
    /// Per-host connection cap (taiji extension option
    /// `--http-max-per-host`, default 64; unit = connections, a shared
    /// hard cap across tasks). Idle (RPC service) mode injects it into
    /// the session HostCap initialization (previously the only effective
    /// channel was the addUri option); an addUri task-level override
    /// (last-set-wins) wins over this value. Startup-time option
    /// (applies on restart; changeGlobalOption does not accept it).
    /// Domain >= 1 (0 is refused at startup, in the same direction as the
    /// addUri `taiji.option.invalid` face).
    #[arg(long = "http-max-per-host", value_parser = clap::value_parser!(u32).range(1..))]
    http_max_per_host: Option<u32>,
    /// Per-task CA certificate file (aria2-compatible name
    /// `--ca-certificate`, domain B top level; aria2 prefs.cc
    /// `makePref("ca-certificate")`, already accepted on the
    /// session face — this flag fills the CLI top level + conf + bare
    /// faces). PEM format; non-empty **replaces** the platform trust
    /// roots (aria2 replace semantics, not append). **Wiring face (per
    /// form)**: the URL positional form maps directly onto the http
    /// pipeline's addUri option via [`http::delegate_positional`]
    /// (single source at the session parse arm — a bad path/bad PEM =
    /// task rejected `taiji.option.invalid`, the same gate as
    /// `taiji http --ca-certificate`, no clap value domain); the
    /// `--input-file` batch face injects into WebUri lines only
    /// (magnet/.torrent lines have no HTTPS download client, not
    /// injected — a bad path does not reject unrelated tasks, the same
    /// way aria2 global options have no effect on BT tasks); the two
    /// session forms idle/download+rpc have **no global injection
    /// face** (the session `ca-certificate` is a per-task option, the
    /// RPC addUri/changeOption faces remain usable) — an explicit
    /// warning discloses this, never silent. With
    /// `--check-certificate=false` given alongside, the latter wins
    /// (verification off, the CA file's effective face is ignored —
    /// same rule as aria2; the effective order closes at the session
    /// projection point).
    #[arg(long = "ca-certificate", value_name = "FILE")]
    ca_certificate: Option<String>,
    /// Client mTLS certificate (aria2-compatible name `--certificate`,
    /// domain B; a PEM `CERTIFICATE` section). **Acceptance
    /// disclosure** (CLI face): the transport face is wired
    /// (taiji-http `ClientConfig::identity_cert_path` -> reqwest
    /// `Identity::from_pem` — locked by the `tests/mtls_mock.rs` wire
    /// matrix) but the session task-option projection face (the
    /// taiji-core option table) is absent — this flag is accepted but
    /// **not effective**, one explicit warning (the same disclosure
    /// style as `--use-head`, no masquerading). Consumed in
    /// pairs with [`Self::private_key`] (one-sided = refused, already
    /// implemented on the assembly side — a half-missing TLS client
    /// identity would fail the handshake anyway, surfaced early at
    /// build time).
    #[arg(long = "certificate", value_name = "FILE")]
    certificate: Option<PathBuf>,
    /// Client private key (aria2-compatible name `--private-key`,
    /// domain B; PEM — a PKCS#8 `PRIVATE KEY` / RSA / EC private-key
    /// section, any of them). Consumed in pairs with
    /// [`Self::certificate`]. **Acceptance disclosure** as
    /// [`Self::certificate`] (transport face wired, session projection
    /// face absent — accepted but not effective, one explicit warning).
    /// Nothing outside the private key path ever enters a log.
    #[arg(long = "private-key", value_name = "FILE")]
    private_key: Option<PathBuf>,
    /// Minimum TLS protocol version (aria2-compatible name
    /// `--min-tls-version`, domain B; aria2 prefs.cc +
    /// OptionHandlerFactory.cc ParameterOptionHandler — the
    /// aria2 domain {TLSv1.1,TLSv1.2,TLSv1.3} defaults TLSv1.2; this
    /// domain tls1.2|tls1.3 = the de-`v` lowercase form + **narrowed by
    /// one**: the workspace rustls 0.23 protocol stack supports only
    /// 1.2/1.3, tls1.1 is not expressible (a declared divergence, not
    /// an omission). **Acceptance disclosure** (CLI face): the
    /// transport face is wired (taiji-http `ClientConfig::
    /// min_tls_version` -> reqwest `ClientBuilder::tls_version_min` —
    /// the non-deprecated name in 0.13; the `mtls_mock` version-floor
    /// wire matrix locks it) but the session task-option projection
    /// face is absent — accepted but **not effective**, one explicit
    /// warning. tls1.3 = TLS1.3-only negotiation (fails outright
    /// against a TLS1.2-only peer); tls1.2 = rejects 1.0/1.1 (the
    /// workspace rustls "tls12" feature is on, 1.2 is expressible).
    #[arg(
        long = "min-tls-version",
        value_parser = clap::builder::PossibleValuesParser::new(["tls1.2", "tls1.3"])
    )]
    min_tls_version: Option<String>,
    // ---- domain C: cookies/session/interface misc family ----
    /// Cookie ingestion session-level default source (aria2-compatible
    /// name `--load-cookies`, domain C; aria2 prefs.cc
    /// `PREF_LOAD_COOKIES`). Path of a Netscape cookie file; effective
    /// face = the session-level global default source
    /// (`GlobalOptions.load_cookies`, the acceptance face):
    /// HTTP tasks created later fall back to this value when addUri
    /// carries no per-task `load-cookies`; loading fails closed at task
    /// acceptance (missing/unreadable/over 1MiB = task rejected
    /// `taiji.option.invalid`). Injection face per form:
    /// idle/download+rpc (session global default source), the URL
    /// positional (direct addUri option mapping — the same gate as
    /// `taiji http --load-cookies`), `--input-file` WebUri lines
    /// (direct addUri option mapping; magnet/.torrent lines have no
    /// HTTPS download client, not injected). BT tasks have no cookie
    /// face (same as aria2).
    #[arg(long = "load-cookies", value_name = "FILE")]
    load_cookies: Option<PathBuf>,
    /// Cookie wind-down export (aria2-compatible name `--save-cookies`,
    /// domain C; aria2 prefs.cc). **Acceptance disclosure**: in
    /// this build cookie persistence is the sqlite single
    /// source of truth (captured rows written back); the taiji-http
    /// CookieJar has no Netscape serialization export face and the
    /// session shutdown has no jar snapshot seam — given explicitly =
    /// one warning, not effective (in step with the session option
    /// face's DECLARED_NON_ACCEPTED `save-cookies` stance: file export
    /// deferred until needed).
    #[arg(long = "save-cookies", value_name = "FILE")]
    save_cookies: Option<PathBuf>,
    /// Session text export at exit (aria2-compatible name
    /// `--save-session`, domain C; the session face
    /// `GlobalOptions.save_session` already exists — after the graceful
    /// shutdown persists everything it writes the same input-file
    /// compatible text on the same path, `__temp`+rename atomic write +
    /// 0600). This flag adds the CLI top-level injection (the only
    /// previous entry was RPC saveSession). Effective in the four
    /// download forms: idle/download+rpc (session globals), the magnet
    /// one-shot, `--input-file` batch (the same gate on the exit path).
    /// Export failure (missing directory etc.) = a warning during
    /// shutdown, the exit code is unchanged (the existing save_session
    /// failure-face semantics).
    #[arg(long = "save-session", value_name = "FILE")]
    save_session: Option<PathBuf>,
    /// Session auto-save interval in seconds (aria2-compatible name
    /// `--save-session-interval`, domain C; aria2
    /// `OptionHandlerFactory.cc` default **0** = disabled,
    /// domain >= 0). Effective face = the session periodic tick fully
    /// flushes to disk every N seconds (task/HTTP row flush + the
    /// `--save-session` text export + WAL checkpoint — the same
    /// save_session entry as graceful shutdown); when the db open
    /// degrades (no persistence layer) the tick is not assembled.
    /// Divergence note: aria2's interval drives periodic `.aria2`
    /// control-file writes; here sqlite persistence writes continuously
    /// and the tick carries the flush/text-export/checkpoint closing
    /// (a startup-time option — applies on restart).
    #[arg(
        long = "save-session-interval",
        default_value_t = 0,
        value_parser = clap::value_parser!(u64).range(0..)
    )]
    save_session_interval: u64,
    /// sqlite auto-save interval in seconds (aria2-compatible name
    /// `--auto-save-interval`, domain C; aria2
    /// `OptionHandlerFactory.cc` `NumberOptionHandler(…, "60",
    /// 0, 600)` default 60, domain 0..=600). **Acceptance disclosure**:
    /// persistence here = continuous PersistWriter commits (per-event —
    /// bitmap/counters/row writes commit immediately), permanently
    /// subsuming aria2's "write the control file every N seconds"
    /// semantics; given explicitly = one warning, not effective
    /// (declared difference).
    #[arg(
        long = "auto-save-interval",
        value_parser = clap::value_parser!(u64).range(0..=600)
    )]
    auto_save_interval: Option<u64>,
    /// Bound interface/IP (aria2-compatible name `--interface`, domain
    /// C; aria2 `OptionHandlerFactory.cc`). **Acceptance
    /// disclosure** (connection-layer check findings, stated as-is):
    /// reqwest 0.13 `ClientBuilder::local_address` exists, but
    /// taiji-http `ClientConfig`/build_transport has no such field (the
    /// transport assembly face is absent); the taiji-io UDP/TCP bind
    /// face likewise has no interface-binding seam — no consumption
    /// point for either protocol family. Given explicitly = one
    /// warning, not effective.
    #[arg(long = "interface", value_name = "NAME")]
    interface: Option<String>,
    /// IPv6 switch (aria2-compatible name `--disable-ipv6`, domain C;
    /// aria2 `OptionHandlerFactory.cc` Boolean, default false).
    /// **Acceptance disclosure**: the taiji-http DNS resolution adapter
    /// has no AAAA filter seam (SharedDns returns both families) and
    /// the BT dial face's `BH_V6_PREF` knob is a v6 preference order,
    /// not a disable — no consumption point. Given explicitly = one
    /// warning, not effective (default false = zero change to the
    /// status quo).
    #[arg(
        long = "disable-ipv6",
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    disable_ipv6: Option<bool>,
    /// IPv6 DHT bootstrap entry (aria2-compatible name
    /// `--dht-entry-point6`, domain C; aria2
    /// `OptionHandlerFactory.cc` HostPortOptionHandler).
    /// Value domain `HOST:PORT` (a v6 literal host requires the
    /// `[...]` bracket form; a bare-colon v6 or a missing port / 0 /
    /// 65536+ = startup refusal — [`parse_dht_entry_point6`]).
    /// **Wiring (bare-run arm)**: injects
    /// `EngineConfig.dht.entry_points_v6` (consumed by the engine/dht.rs
    /// V6-family bootstrap; default empty = the SPEC §6.7 v6 router
    /// fallback constant — zero change to the existing form). The
    /// session forms (idle/download+rpc/magnet/input-file) hard-code
    /// the default engine entry — accepted but not effective, one
    /// explicit warning.
    #[arg(
        long = "dht-entry-point6",
        value_name = "HOST:PORT",
        value_parser = parse_dht_entry_point6
    )]
    dht_entry_point6: Option<String>,
    /// FTP transfer mode (aria2-compatible name `--ftp-type`, domain
    /// C; aria2 `OptionHandlerFactory.cc` ParameterOptionHandler
    /// domain {binary, ascii} default binary). **Acceptance
    /// disclosure**: the FTP data connection here is always TYPE I
    /// (binary) — the taiji-http ftp transport face hard-wires
    /// `transfer_type(FileType::Binary)` and the session option face's
    /// `ftp-type` takes the same stance, not accepted
    /// (DECLARED_NON_ACCEPTED: TYPE I constant). binary = zero change
    /// to the status quo; **ascii = one explicit warning, not
    /// effective**.
    #[arg(
        long = "ftp-type",
        value_parser = clap::builder::PossibleValuesParser::new(["ascii", "binary"])
    )]
    ftp_type: Option<String>,
    /// netrc credentials file path (aria2-compatible name
    /// `--netrc-path`, domain C; aria2 prefs.cc, the aria2 default
    /// `$HOME/.netrc`). **Acceptance disclosure**: there is no netrc
    /// parse/consumption face here (confirmed by a repo-wide search —
    /// credentials go through the `--http-user`/`--ftp-user` option
    /// chain) and aria2's "read ~/.netrc by default" behavior does not
    /// exist here (declared difference). Given explicitly = one
    /// warning, not effective.
    #[arg(long = "netrc-path", value_name = "FILE")]
    netrc_path: Option<PathBuf>,
    /// Disable netrc (aria2-compatible name `--no-netrc`, domain C;
    /// aria2 `OptionHandlerFactory.cc` Boolean, default false).
    /// **Acceptance disclosure**: same as [`Self::netrc_path`] — this
    /// build never reads a netrc (the aria2 no-netrc=true semantics are
    /// already the status quo). Given explicitly = one warning, not
    /// effective.
    #[arg(
        long = "no-netrc",
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    no_netrc: Option<bool>,
    /// Pin the task GID (aria2-compatible name `--gid`, domain C;
    /// aria2 `OptionHandlerFactory.cc` DefaultOptionHandler).
    /// Value domain = a 16-digit hex string (the aria2 GID form;
    /// out-of-domain = startup refusal — [`parse_cli_gid`]).
    /// Normalization = set the high bit (the taiji GID space mask —
    /// fork GIDs with a zero high bit are normalized into the
    /// taiji space; our own exports round-trip losslessly).
    /// **Wiring (bare-run arm)**: the task GID is pinned to this value
    /// (consumed by the hook argv payload and the startup log —
    /// `Gid::from_u64`; bare mode has no session allocator,
    /// [`GidAllocator::reserve`] is the session-form counterpart seam).
    /// In the session forms (idle/download+rpc/magnet/input-file) the
    /// allocator lives in the SessionActor — accepted but not
    /// effective, one explicit warning.
    #[arg(long, value_name = "GID", value_parser = parse_cli_gid)]
    gid: Option<taiji_core::gid::Gid>,
    /// Dry-run switch (aria2-compatible name `--dry-run`, domain C;
    /// aria2 `OptionHandlerFactory.cc` Boolean, default false).
    /// **Wiring (bare-run .torrent arm)**: true = parse the metainfo,
    /// print the download plan (torrent/dir/listen-port/name/file
    /// count/total length/announce) and exit (exit 0), the engine is
    /// not spawned. The other download forms (URL/magnet/input-file/
    /// download+rpc) have no probe seam — an explicit true warns once
    /// and downloads as usual (aria2 treats HTTP/FTP as "probe
    /// availability only, no download", a declared semantic
    /// difference; aria2 cancels outright for BT).
    #[arg(
        long = "dry-run",
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    dry_run: Option<bool>,
    /// Show the torrent file listing and exit (aria2-compatible name
    /// `--show-files` / `-S`, domain C; aria2
    /// `OptionHandlerFactory.cc` Boolean, default false; the
    /// aria2 behavior = `Context.cc` showTorrentFile +
    /// `bittorrent_helper.h` print: print the torrent info
    /// block + the file list, then exit 0). **Wiring (meta flag)**:
    /// with a `.torrent` positional = parse, print (info block +
    /// per-file path/length, pad placeholder entries excluded) and
    /// exit 0; no positional or a non-torrent positional (magnet/URL) =
    /// exit 2 (a usage error — aria2 prints a not-torrent line and
    /// carries on for non-torrent input, refused explicitly here,
    /// declared difference). The info block is bounded by the existing
    /// Metainfo extraction face (comment/creation date/created
    /// by/magnet lines are absent — the extraction face lacks them,
    /// declared as-is); the metalink document listing face is not in
    /// this form.
    #[arg(long, default_value_t = false)]
    show_files: bool,
    // ---- Acceptance-disclosure family (the session/RPC
    // faces already accept these names as no-op value faces — the
    // GLOBAL_PATCH_TABLE no-op rows; the CLI face here closes the
    // "accepted at the session face but missing a CLI face" gap). Each
    // flag is typed where aria2 types it and warns once on an explicit
    // given ([`warn_deferred_d_tier`]) — accepted-but-not-effective,
    // never masquerading. The per-flag non-wiring reasons live in the
    // GLOBAL_PATCH_TABLE row notes (options.rs) and are mirrored in the
    // field docs below.
    /// DNS shape switch (aria2-compatible name `--async-dns`; prefs.cc
    /// `makePref("async-dns")`; aria2 Boolean face, default true).
    /// **Acceptance disclosure**: taiji's resolver behavior is fixed —
    /// the http transport stack manages its own resolution and there is
    /// no async-dns wiring seam (the session face records the value via
    /// the GLOBAL_PATCH_TABLE no-op row, zero behavior). Given
    /// explicitly = one warning, not effective. Both the bare flag and
    /// the `=true|=false` value forms are accepted.
    #[arg(
        long = "async-dns",
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    async_dns: Option<bool>,
    /// IPv6 async-DNS shape switch (aria2-compatible name
    /// `--enable-async-dns6`; prefs.cc same-name entry — wrapped by an
    /// aria2 DeprecatedOptionHandler, OptionHandlerFactory.cc "TODO
    /// Deprecated"). **Acceptance disclosure**: taiji's resolver
    /// behavior is fixed (same as `--async-dns`), no v6 resolver switch
    /// seam (the session face records the value via the no-op row).
    /// Given explicitly = one warning, not effective. Both the bare
    /// flag and the `=true|=false` value forms are accepted.
    #[arg(
        long = "enable-async-dns6",
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    enable_async_dns6: Option<bool>,
    /// Global tracker exclusion list (aria2-compatible name
    /// `--bt-exclude-tracker`; prefs.cc same-name entry; a
    /// comma-separated multi-value string). **Acceptance disclosure**:
    /// taiji's global tracker import has no exclusion face — the import
    /// set is union-cumulative and the exclusion half of the aria2
    /// tracker face is absent (the session face records the value via
    /// the no-op row; the Motrix tracker-manager sends an empty
    /// placeholder). Given explicitly = one warning, not effective.
    #[arg(long = "bt-exclude-tracker", value_name = "URI,...")]
    bt_exclude_tracker: Option<String>,
    /// RPC stopped-result retention count (aria2-compatible name
    /// `--max-download-result`; prefs.cc same-name entry; numeric
    /// face). **Acceptance disclosure**: the taiji RPC face has no
    /// result-retention seam — job bookkeeping is the truth and
    /// tellStopped reads the queues directly (the session face records
    /// the value via the no-op row). Given explicitly = one warning,
    /// not effective.
    #[arg(long = "max-download-result", value_name = "NUM")]
    max_download_result: Option<i64>,
    /// Source-switch 404-count threshold (aria2-compatible name
    /// `--max-file-not-found`; prefs.cc same-name entry; numeric face).
    /// **Acceptance disclosure**: the taiji-http source probe eviction
    /// has no option-driven counter seam (the session face records the
    /// value via the no-op row). Given explicitly = one warning, not
    /// effective.
    #[arg(long = "max-file-not-found", value_name = "NUM")]
    max_file_not_found: Option<i64>,
    /// mmap loading threshold (aria2-compatible name `--max-mmap-limit`;
    /// prefs.cc same-name entry; numeric face). **Acceptance
    /// disclosure**: the taiji store face has no mmap path
    /// (taiji-store disk_policy decides the IO shape) — the value has
    /// nothing to threshold (the session face records the value via the
    /// no-op row). Given explicitly = one warning, not effective.
    #[arg(long = "max-mmap-limit", value_name = "SIZE")]
    max_mmap_limit: Option<i64>,
    /// Resume-failure fallback count (aria2-compatible name
    /// `--max-resume-failure-tries`; prefs.cc same-name entry; numeric
    /// face — the fall-back-to-full-redownload count). **Acceptance
    /// disclosure**: the bitmap resume has no "fall back to zero" seam
    /// — the bitmap is the resume truth (the session face records the
    /// value via the no-op row). Given explicitly = one warning, not
    /// effective.
    #[arg(long = "max-resume-failure-tries", value_name = "NUM")]
    max_resume_failure_tries: Option<i64>,
    /// Periodic task summary log interval in seconds (aria2-compatible
    /// name `--summary-interval`, prefs.cc; default 60, domain
    /// 0..=INT32_MAX, 0 = disabled — OptionHandlerFactory.cc anchor).
    /// Consumed by the session's periodic INFO summary
    /// (gid/speed/progress/connection count, target
    /// `taiji::core::summary`). Startup-time option: changeGlobalOption
    /// does not accept it (capability parity with the reference);
    /// applies on restart.
    #[arg(
        long,
        default_value_t = taiji_core::session::SUMMARY_INTERVAL_DEFAULT,
        value_parser = clap::value_parser!(u32).range(0..=taiji_core::session::SUMMARY_INTERVAL_MAX as i64)
    )]
    summary_interval: u32,
    /// Max concurrent downloads (aria2-compatible name
    /// `--max-concurrent-downloads`, the `-j` family; default 5 — the
    /// OptionHandlerFactory.cc "5" anchor; domain 1..=64, the aria2
    /// RANGE(1..) lower bound + the upper bound the RPC apply-side
    /// clamp already enforces — each concurrent task multiplies the
    /// per-task wr_cache/arena/engine faces, so the memory
    /// amplification of pulling N arbitrarily high is closed at every
    /// face). Session-wide concurrency cap (an existing
    /// GlobalOptions field — consumed by the SessionActor queue
    /// bookkeeping). **Startup-time option**: CLI/conf inject the
    /// session initial value; the changeGlobalOption hot reload
    /// already exists (clamped to [1,64]).
    #[arg(
        long = "max-concurrent-downloads",
        default_value_t = 5,
        value_parser = clap::value_parser!(u32).range(1..=64)
    )]
    max_concurrent_downloads: u32,
    /// Seed-pool budget (taiji extension `--max-concurrent-seeds`,
    /// four-pool model; aria2 has no such option).
    /// Max concurrently **seeding-resident** BT tasks; domain 0..=4096,
    /// 0 = unlimited. **Two-state default**: 16 while the session-level
    /// connection budget (the unlimited default's
    /// aggregate precondition) is unmerged; that card flips the
    /// default back to 0. Session-wide initial value (an existing
    /// GlobalOptions field): CLI/conf inject the startup value; the
    /// changeGlobalOption hot reload (RPC accepted key of the same
    /// name, apply-side clamp 0..=4096) reactivates parked seed_wait
    /// members FIFO without a download slot; narrowing never preempts
    /// in-flight residents.
    #[arg(
        long = "max-concurrent-seeds",
        default_value_t = 16,
        value_parser = clap::value_parser!(u32).range(0..=4096)
    )]
    max_concurrent_seeds: u32,
    /// Check-pool budget (taiji extension `--max-concurrent-checks`,
    /// four-pool model; aria2 has no such option).
    /// Max concurrently **in-flight** on-disk rechecks; domain 1..=16
    /// (no unlimited state; the lower bound keeps at least one recheck
    /// admitted). Default 2 = the pread+hash IO/CPU overlap conservative
    /// value. Session-wide initial value: CLI/conf inject the startup
    /// value; the changeGlobalOption hot reload narrows only subsequent
    /// admissions (in-flight rechecks run to completion — narrowing never preempts).
    #[arg(
        long = "max-concurrent-checks",
        default_value_t = 2,
        value_parser = clap::value_parser!(u32).range(1..=16)
    )]
    max_concurrent_checks: u32,
    /// Synthesis-pool budget (taiji extension
    /// `--media-synthesis-concurrency`, four-pool model; aria2 has no
    /// such option). Max concurrently
    /// **synthesizing** media tasks; domain 1..=16, default 2 (an
    /// ffmpeg process is heavy — stream-copy light, transcode/burn-in
    /// heavy; the layered counterpart of `--media-segment-concurrency`,
    /// which governs the network phase and is NOT this budget).
    /// Session-wide initial value: CLI/conf inject the startup value;
    /// the changeGlobalOption hot reload narrows only subsequent permit
    /// grants (narrowing never preempts; permits are not transferable).
    #[arg(
        long = "media-synthesis-concurrency",
        default_value_t = 2,
        value_parser = clap::value_parser!(u32).range(1..=16)
    )]
    media_synthesis_concurrency: u32,
    /// Overall download rate limit (aria2-compatible name
    /// `--max-overall-download-limit`; 0 = unlimited). **Bare download
    /// mode** = the global shared bucket; idle mode injects the session
    /// (the SpeedLimits global bucket, changeGlobalOption hot reload).
    #[arg(long = "max-overall-download-limit", default_value = "0", value_parser = parse_aria2_size)]
    max_overall_download_limit: u64,
    /// Overall upload rate limit (aria2-compatible name
    /// `--max-overall-upload-limit`; 0 = unlimited; same semantics as
    /// above).
    #[arg(long = "max-overall-upload-limit", default_value = "0", value_parser = parse_aria2_size)]
    max_overall_upload_limit: u64,
    /// Peer exchange switch (aria2-compatible name
    /// `--enable-peer-exchange`; default **true** — the aria2
    /// `PREF_ENABLE_PEER_EXCHANGE` A2_V_TRUE same rule). **Wiring**: the
    /// ut_pex advertise/consume gate (EngineConfig.peer_exchange ->
    /// bt::pex::pex_offered; private torrents always disable it, BEP27).
    /// Bare mode injects the engine; idle mode injects the session
    /// (changeGlobalOption hot reload — applies to subsequently activated
    /// tasks). Both the bare flag and the `=true|=false` value forms are
    /// accepted.
    #[arg(
        long = "enable-peer-exchange",
        default_value_t = true,
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    enable_peer_exchange: bool,
    /// DHTv6 switch (aria2-compatible name `--enable-dht6`; default
    /// **false** — the aria2 A2_V_FALSE same rule). **Value-face
    /// acceptance**: there is no independent v6 DHT gate here — the v6
    /// DHT face follows the `--enable-dht` master gate plus the IPv6
    /// connectivity gate (probe); this key does not change engine wiring
    /// (the divergence is declared in the session option surface
    /// enable_dht6 field doc). Idle mode injects the session
    /// (getGlobalOption echo). Both the bare flag and the `=true|=false`
    /// value forms are accepted. Startup-time option.
    #[arg(
        long = "enable-dht6",
        default_value_t = false,
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    enable_dht6: bool,
    /// DHT bootstrap entry (aria2-compatible name `--dht-entry-point`,
    /// v4; `HOST:PORT`, no default — the aria2 HostPortOptionHandler
    /// same form). **Wiring**: Some = replaces the SPEC §6.7 router
    /// fallback constants (DhtWireConfig.entry_points_v4 direct map —
    /// the engine resolves + pings each entry, converging on the first
    /// success). Startup-time option (applies on restart; aria2 likewise
    /// has no change slot). Both hostnames and v6 literals are accepted
    /// (the `[::1]:6881` form).
    #[arg(long = "dht-entry-point", value_parser = parse_dht_entry_point)]
    dht_entry_point: Option<String>,
    /// DHT transaction timeout in seconds (aria2-compatible name
    /// `--dht-message-timeout`; default 10, domain 1..=60 — the
    /// OptionHandlerFactory.cc handler domain anchor). **Wiring**:
    /// DhtEngineConfig.message_timeout (the same value as the frozen
    /// taiji-bt default 10s — zero change by default). Startup-time
    /// option (applies on restart).
    #[arg(
        long = "dht-message-timeout",
        default_value_t = 10,
        value_parser = clap::value_parser!(u64).range(1..=60)
    )]
    dht_message_timeout: u64,
    /// Log output format (taiji extension option `--log-format`; default
    /// text = the existing human format, unchanged). json =
    /// tracing-subscriber structured JSON (timestamp/level/target/fields,
    /// one valid JSON object per line; for log collection and tooling
    /// consumption); in text mode ANSI coloring applies only when stdout
    /// is a direct terminal (TTY) — redirects/pipelines stay clean
    /// automatically, and a set `NO_COLOR` disables it entirely.
    /// Startup-time option.
    #[arg(
        long = "log-format",
        default_value = "text",
        value_parser = clap::builder::PossibleValuesParser::new(["text", "json"])
    )]
    log_format: String,
    /// Log level (aria2-compatible name and domain
    /// `debug|info|notice|warn|error`). notice->info mapping note:
    /// tracing has no notice level, and aria2's notice-level notable
    /// events are carried by info. When RUST_LOG is set explicitly, this
    /// flag and --verbose/--debug all yield (existing RUST_LOG
    /// precedence). Startup-time option.
    /// `--console-log-level` = a visible alias of this flag (rationale:
    /// a single log stream — there is no separate console level to
    /// split; aria2's dual levels, log-level for the file and
    /// console-log-level for the console, merge under `--log`'s
    /// single-stream model). The alias shares the arg id and the value
    /// domain; the conf precedence check's value_source("log_level")
    /// hits alias-provided values the same way.
    #[arg(
        long = "log-level",
        visible_alias = "console-log-level",
        value_parser = clap::builder::PossibleValuesParser::new([
            "debug", "info", "notice", "warn", "error"
        ])
    )]
    log_level: Option<String>,
    /// Quiet tier (taiji extension; the lowest tier of the wget/curl `-q`
    /// style quietness ladder) = warn level: only warnings and errors.
    /// Semantic difference from aria2 `--quiet` (which suppresses console
    /// readouts): here it maps to a log-level tier; disabling the task
    /// summary is done via `--summary-interval=0`. Startup-time option.
    #[arg(long)]
    quiet: bool,
    /// Convenience level: = --log-level debug (taiji extension; does not
    /// take the `-v` short name, keeping zero conflict with aria2's
    /// single-letter surface). URL logs remain redacted (see
    /// --log-verbatim-urls for the full form). Startup-time option.
    #[arg(long)]
    verbose: bool,
    /// Deep-diagnostics level: trace (taiji extension; deeper than aria2
    /// debug: per-frame/per-block detail). Takes precedence over
    /// --verbose/--log-level. Startup-time option.
    #[arg(long)]
    debug: bool,
    /// Verbatim URL logging (taiji extension; default off). On =
    /// tracker/webseed URLs are logged with the full query (including
    /// passkey/token credentials) — for local deep diagnosis only;
    /// **scrub credentials before sharing logs**. Off = stripped at all
    /// levels (scheme://authority/path). Orthogonal to the level flags.
    /// Startup-time option.
    #[arg(long = "log-verbatim-urls")]
    log_verbatim_urls: bool,
    /// Log file (aria2-compatible name `--log`; **no default** — when
    /// absent the log stream stays on stdout, zero change). When given =
    /// the global log stream is redirected to the file (a single-point
    /// switch of the tracing fmt writer; the existing `std::fs::File`
    /// `MakeWriter` impl writes directly — no new tracing-appender
    /// third-party face, zero lock change; append+create, restarts keep
    /// appending without truncation, the same shape as the aria2 --log
    /// plain file, no rotation). The file sink is always ANSI-clean
    /// (collection-face purity — the same rule as redirection).
    /// Mutually exclusive with --stderr (a single log stream: a hard
    /// clap conflict = usage exit 2; both keys given via conf are
    /// refused by the open_log_target fail-fast — never silently picking
    /// one). File open failure = exit 2 (the same face as an unreadable
    /// conf). Startup-time option.
    #[arg(long, conflicts_with = "stderr")]
    log: Option<PathBuf>,
    /// Console output to stderr (aria2-compatible name `--stderr`;
    /// default **false** = the stdout log stream, zero change). The
    /// aria2 semantics = redirecting all console output
    /// (option_processing.cc `redirectStdoutToStderr`); here the single
    /// log stream = the writer switches to stderr (the ANSI TTY probe
    /// follows onto stderr). Both the bare flag and the `=true|=false`
    /// value forms are accepted (the aria2 bool dual form). Mutually
    /// exclusive with --log (as above). Startup-time option.
    #[arg(
        long,
        default_value_t = false,
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    stderr: bool,
    /// Observability format switch (aria2-compatible name
    /// `--human-readable`; default **true** = zero change). The aria2
    /// semantics = human-readable abbreviations for console readouts
    /// (MiB/s forms); there is no console readout here — the summary
    /// line's byte fields stay machine-first (the golden anchor,
    /// taiji-core summary.rs, outside this flag), so the switch lands on
    /// the observability log format: **false = the machine-readable
    /// face** (`--log-format json`), true = the format face keeps the
    /// given value. An explicit `--log-format` (command-line source)
    /// always wins — the more specific flag takes precedence (the
    /// value_source criterion, same as rpc_group_conflict; a conf-provided
    /// log-format is a non-command-line source and gets overridden by
    /// false — the CLI > conf precedence, same rule). Both the bare flag
    /// and the `=true|=false` value forms are accepted. Startup-time
    /// option.
    #[arg(
        long = "human-readable",
        default_value_t = true,
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    human_readable: bool,
    /// Color switch (aria2-compatible name `--enable-color`; default
    /// **true** = zero change — the TTY x NO_COLOR dual condition is
    /// unchanged). **false = force ANSI off** (the same rule for
    /// redirects/collection); true = the existing verdict, and a non-TTY
    /// stays clean without forcing color on — a setup divergence: aria2
    /// colors whenever enabled (no TTY probe), while the
    /// redirect-auto-clean discipline wins here, so the switch is only a
    /// disable arm. Both the bare flag and the `=true|=false` value
    /// forms are accepted. Startup-time option.
    #[arg(
        long = "enable-color",
        default_value_t = true,
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    enable_color: bool,
    /// Config file path (aria2-compatible name `--conf-path`; **no
    /// default**). A deliberate safety divergence from aria2: no path is
    /// loaded implicitly (aria2 reads `$HOME/.aria2/aria2.conf` by
    /// default) — without this flag there is zero file IO. The parse
    /// form/priority (defaults < conf < explicit CLI flags), unknown-key
    /// and unreadable-file fail-fast (exit 2) semantics are documented in
    /// the `conf` module; a `conf-path` key inside a conf file is
    /// recognized but a no-op (no nested loading).
    #[arg(long)]
    conf_path: Option<PathBuf>,
    /// Completion script generator (meta flag; taiji extension). When
    /// given, print the minimal completion script for the requested
    /// shell (bash/zsh/fish — long flag names without values +
    /// subcommand names) to stdout and exit 0 — the meta mode runs
    /// before conf loading, tracing initialization, and the RPC group
    /// conflict check, and all other arguments under the same flag are
    /// ignored (no conf semantics, not in the conf key surface). The
    /// value domain is frozen by clap; the flag-ledger sync discipline
    /// with the `Cli` metadata is documented in the [`completions`]
    /// module (the sync is pinned by tests, not by comment discipline).
    #[arg(
        long = "print-completions",
        value_parser = clap::builder::PossibleValuesParser::new(completions::SHELLS.iter().copied())
    )]
    print_completions: Option<String>,
}

/// aria2 size literal parsing: bare byte count or a k/K/m/M/g/G suffix
/// (1024-based, matching the aria2 OptionHandler size family; shared by
/// the `--rpc-max-request-size` default 10M and the
/// `create-torrent --piece-length` default 16k).
pub(crate) fn parse_aria2_size(s: &str) -> Result<u64, String> {
    let (digits, mult) = match s.chars().last() {
        Some('k' | 'K') => (&s[..s.len() - 1], 1024u64),
        Some('m' | 'M') => (&s[..s.len() - 1], 1024u64 * 1024),
        Some('g' | 'G') => (&s[..s.len() - 1], 1024u64 * 1024 * 1024),
        Some(_) => (s, 1u64),
        None => return Err("empty size".to_string()),
    };
    let n: u64 = digits
        .parse()
        .map_err(|_| format!("invalid size literal: {s} (expected <n>[k|m|G])"))?;
    n.checked_mul(mult)
        .ok_or_else(|| format!("size overflow: {s}"))
}

/// `--gid` value-domain parse (domain C; a single point shared by the
/// CLI and conf faces): a 16-digit hex string (the aria2 GID form; both
/// cases accepted — `u64::from_str_radix` semantics), out-of-domain
/// (length != 16 / non-hex / empty) = refused. Normalization = set the
/// high bit (`GID_HIGH_BIT`, the taiji GID space mask): our own
/// exported GIDs round-trip losslessly (taiji-allocated values always
/// carry the high bit); fork GIDs with a zero high bit are normalized
/// into the taiji space — this satisfies the "caller guarantees the
/// high bit is set" precondition of
/// [`taiji_core::gid::Gid::from_u64`].
pub(crate) fn parse_cli_gid(s: &str) -> Result<taiji_core::gid::Gid, String> {
    if s.len() != 16 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "invalid GID: {s:?} (expected 16 hex digits, aria2 GID form)"
        ));
    }
    let raw =
        u64::from_str_radix(s, 16).map_err(|_| format!("invalid GID: {s:?} (hex parse failed)"))?;
    Ok(taiji_core::gid::Gid::from_u64(
        raw | taiji_core::gid::GID_HIGH_BIT,
    ))
}

/// `--dht-entry-point6` value-domain parse (domain C; a single point
/// shared by the CLI and conf faces): `HOST:PORT` (the aria2
/// HostPortOptionHandler form). The host segment must be non-empty and
/// contain no bare `:` (a v6 literal host must use the `[...]` bracket
/// form — a bare colon is ambiguous against the host:port colon split,
/// refused explicitly); port 1..=65535. Returns the original text (the
/// validated face — the consumption point
/// `DhtWireConfig.entry_points_v6` is a host:port text vector).
pub(crate) fn parse_dht_entry_point6(s: &str) -> Result<String, String> {
    let invalid = || {
        format!(
            "invalid DHT entry point: {s:?} (expected HOST:PORT; \
                 IPv6 literal host requires [..] brackets, port 1..=65535)"
        )
    };
    // Host segment: a v6 literal = the `[...]` bracket form (non-empty
    // after stripping the brackets — an inner `:` is legal); anything
    // else = non-empty and without `:` (a bare v6 is ambiguous against
    // the split, refused explicitly).
    let (host, port_str) = s.rsplit_once(':').ok_or_else(invalid)?;
    let host_ok = if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        !inner.is_empty()
    } else {
        !host.is_empty() && !host.contains(':')
    };
    if !host_ok {
        return Err(invalid());
    }
    let port: u16 = port_str.parse().map_err(|_| invalid())?;
    if port == 0 {
        return Err(invalid());
    }
    Ok(s.to_string())
}

/// `--dht-entry-point` value parse (the v4 counterpart of
/// [`parse_dht_entry_point6`]): the `HOST:PORT` form (the aria2
/// HostPortOptionHandler `PREF_DHT_ENTRY_POINT` same form — host + a
/// u16 port, an explicit startup error, never silent). Hostnames /
/// IPv4 / bracketed IPv6 literals are all accepted (the DNS resolution
/// face lives in the engine bootstrap — taiji-engine `resolve_entry`).
/// The conf face reuses the same parser (a single value-domain point).
/// Returns the original text (the consumption point
/// `DhtWireConfig.entry_points_v4` is a host:port text vector).
pub(crate) fn parse_dht_entry_point(s: &str) -> Result<String, String> {
    let bad = || {
        format!(
            "invalid --dht-entry-point value: {s} (expected HOST:PORT, \
             e.g. router.bittorrent.com:6881)"
        )
    };
    let Some((host, port)) = s.rsplit_once(':') else {
        return Err(bad());
    };
    if host.is_empty() || port.parse::<u16>().is_err() {
        return Err(bad());
    }
    Ok(s.to_string())
}

/// RPC group option set (the conflict-arm verdict face; the
/// base enumeration is five items — listen-port / secret / user /
/// passwd / aria2-compat — extended with three TLS-family items from
/// domain B: secure / certificate / private-key). The tuple =
/// (clap arg id = the derive field name, the CLI long name used in
/// error text).
const RPC_GROUP_OPTIONS: [(&str, &str); 8] = [
    ("rpc_listen_port", "--rpc-listen-port"),
    ("rpc_secret", "--rpc-secret"),
    ("rpc_user", "--rpc-user"),
    ("rpc_passwd", "--rpc-passwd"),
    ("rpc_aria2_compat", "--rpc-aria2-compat"),
    ("rpc_secure", "--rpc-secure"),
    ("rpc_certificate", "--rpc-certificate"),
    ("rpc_private_key", "--rpc-private-key"),
];

/// Silent no-op elimination verdict : download mode (a
/// positional arg or an `--input-file` batch list is given —
/// [`download_mode_given`]) and the RPC group options are **explicitly
/// given** and `--enable-rpc` is not on -> Some(the explicit items'
/// long names).
///
/// "Explicitly given" = the clap `value_source` is the command line —
/// defaults never trigger (`--rpc-listen-port` always has the default
/// 6800, and clap `conflicts_with` cannot express "a default value is
/// not a conflict", hence the hand-written arm instead of a declarative
/// conflict). An explicit `--enable-rpc=false` also counts as off (the
/// RPC group options would still be ignored by the bare branch — no
/// silence). Idle mode (no positional and no --input-file) is
/// unrestricted: idle is the daemon form, RPC is always on, the RPC
/// group options naturally apply.
fn rpc_group_conflict(
    download_mode_given: bool,
    enable_rpc: bool,
    matches: &clap::ArgMatches,
) -> Option<Vec<&'static str>> {
    if !download_mode_given || enable_rpc {
        return None;
    }
    let given: Vec<&'static str> = RPC_GROUP_OPTIONS
        .iter()
        .filter(|(id, _)| matches.value_source(id) == Some(clap::parser::ValueSource::CommandLine))
        .map(|(_, long)| *long)
        .collect();
    if given.is_empty() { None } else { Some(given) }
}

/// Mode restriction for conf-provided enable-rpc (the fail-closed hard
/// error verdict): download mode ([`download_mode_given`]) and RPC on
/// and the switch source is not the command line (= conf-provided) ->
/// true; main exits 2 on it.
///
/// Invariant: download + RPC in one process adds a listen surface, so
/// entering that form requires an explicit command-line `--enable-rpc`
/// — a conf value and the default are both non-command-line sources;
/// letting them through would silently start an RPC listener from
/// "positional arg + conf tuning file" (the criterion and error face
/// share the value_source mechanism of `rpc_group_conflict`). Idle mode
/// is unrestricted: idle is the daemon form, RPC is always on, a conf
/// enable-rpc ranks with the default.
fn conf_enable_rpc_download_conflict(
    download_mode_given: bool,
    enable_rpc: bool,
    matches: &clap::ArgMatches,
) -> bool {
    download_mode_given
        && enable_rpc
        && matches.value_source("enable_rpc") != Some(clap::parser::ValueSource::CommandLine)
}

/// Download-mode verdict (the single shared criterion of both RPC
/// gates): a positional arg is given (.torrent path / magnet / URL all
/// count) or an `--input-file` batch list is given — both are
/// "run the tasks and exit" one-shot downloads where the RPC group
/// options have no effective face (explicitly given = hard error, no
/// silence; an explicit `--enable-rpc` disarms the group-option
/// conflict arm, and within the batch form a warning then discloses
/// that no RPC listener starts — [`run_input_file`]).
fn download_mode_given(cli: &Cli) -> bool {
    cli.torrent.is_some() || cli.input_file.is_some()
}

/// Pure decision function for the `--bt-max-peers` override injection
/// (decision-table tested; the side effect lives in main): explicit
/// (command line/conf, each judged in its own arm) and >= 1 gives
/// Some(override); not explicit (default 55) gives None (no override —
/// built-ins 120/100 stay, default-zero-behavior); explicit 0 (aria2
/// unlimited semantics) gives None (the always-enforced cap cannot
/// express unlimited — back to the default plus a warning).
fn bt_max_peers_override_of(cli_value: u64, explicit: bool) -> Option<usize> {
    if explicit && cli_value >= 1 {
        Some(usize::try_from(cli_value).unwrap_or(usize::MAX))
    } else {
        None
    }
}

fn main() {
    // Media exec-shim hook (the media spec §8.6): a child spawned by
    // taiji-media's orchestrator re-enters this executable with the
    // `__taiji-media-exec` marker argv; the shim applies the child
    // resource limits and runs the real ffmpeg/ffprobe (see
    // taiji_media::exec_shim). Must run before any runtime/clap work —
    // the marker argv is not a legal CLI shape.
    if let Some(code) = taiji_media::exec_shim::maybe_run_shim() {
        std::process::exit(code);
    }

    // Version string uses the frozen taiji/<semver> format; clap needs
    // a &'static str and the process starts once, so leaking it is
    // fine.
    let version: &'static str = Box::leak(taiji_core::version_string().into_boxed_str());
    let matches = Cli::command().version(version).get_matches();
    let mut cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());

    // Completion script generation (meta flag — runs before conf
    // loading, tracing initialization, and the RPC group conflict check:
    // prints to stdout and exits 0; all other arguments under the same
    // flag are ignored). The value domain is frozen by clap
    // (bash|zsh|fish); the script generation lives in [`completions`].
    // tracing is not yet initialized, so the output stream carries no
    // log noise (redirect consumers get a clean script from
    // `taiji --print-completions bash > …`).
    if let Some(shell) = cli.print_completions.as_deref() {
        print!("{}", completions::script(shell));
        let _ = std::io::Write::flush(&mut std::io::stdout());
        return;
    }

    // --conf-path config layer (parse form/priority/fail-fast semantics
    // in the conf module docs): consumed before tracing initialization
    // and the RPC group conflict check — conf-provided log-format /
    // enable-rpc carries the same standing as CLI providers (priority:
    // defaults < conf < explicit CLI flags; unknown keys / unreadable
    // files = exit 2 hard error).
    if let Err(msg) = conf::load_and_apply(&matches, &mut cli) {
        eprintln!("{msg}");
        std::process::exit(2);
    }

    // Domain A: the runtime recheck arm for the --input-file vs
    // positional-arg mutual exclusion. clap `conflicts_with` only
    // covers both args being command-line sourced; conf-provided
    // input-file + a CLI positional arg does not go through the clap
    // conflict declaration (the conf layer only overwrites fields), so
    // this intercepts — a silent bias (one side ignored) violates
    // explicitness, exit 2 like the clap conflict code.
    if cli.input_file.is_some() && cli.torrent.is_some() {
        eprintln!(
            "error: --input-file and the [TORRENT] positional argument are mutually exclusive"
        );
        std::process::exit(2);
    }

    // The URL verbatim switch is set before subscriber initialization
    // (a one-time process-level global ahead of init_tracing — the
    // taiji_io::redact gate reads it; BT/HTTP surfaces share the
    // source).
    taiji_io::redact::set_url_log_verbatim(cli.log_verbatim_urls);
    // Domain 3 console/log family assembly (finalized once, before the
    // subscriber initialization): the --human-readable observability
    // format landing point (an explicit --log-format command-line source
    // always wins — the value_source criterion, same as
    // rpc_group_conflict; a conf value is a non-command-line source)
    // -> the --log/--stderr single-stream assembly (a dual target / an
    // unopenable file = exit 2 fail-fast, the same face as an unreadable
    // conf) -> init_tracing.
    let log_format = resolve_log_format(
        &cli.log_format,
        cli.human_readable,
        matches.value_source("log_format") == Some(clap::parser::ValueSource::CommandLine),
    );
    let log_target = match open_log_target(cli.stderr, cli.log.as_deref()) {
        Ok(target) => target,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(2);
        }
    };
    init_tracing(
        &log_format,
        cli.verbose,
        cli.debug,
        cli.log_level.as_deref(),
        cli.quiet,
        cli.enable_color,
        log_target,
    );

    // Mode restriction for conf-provided enable-rpc (fail-closed):
    // download mode + RPC on + switch source not the command line (=
    // conf-provided) refuses to start. Invariant: download + RPC in one
    // process adds a listen surface out of nowhere, so entering
    // requires an explicit command-line `--enable-rpc`; letting a conf
    // value through would silently start a listener from "positional
    // arg + conf file". Runs before rpc_group_conflict: when
    // enable_rpc=true (any source) that function's conflict arm is
    // always disarmed, so this is the only interception surface for a
    // conf RPC switch in download mode.
    if conf_enable_rpc_download_conflict(download_mode_given(&cli), cli.enable_rpc, &matches) {
        eprintln!("error: conf-provided enable-rpc has no effect in download mode");
        eprintln!(
            "       download + RPC in the same process requires an explicit \
             command-line --enable-rpc"
        );
        std::process::exit(2);
    }

    // silent no-op elimination (the hard-error conflict
    // arm): download mode (positional arg or --input-file batch list)
    // receiving RPC group options while `--enable-rpc` is not in effect
    // -> refuse to start (previously silently ignored — measured:
    // `--rpc-listen-port` in the bare branch had no listener and no
    // warning, violating explicitness). Output face = stderr (the same
    // stream and code as a clap usage error — usage errors do not enter
    // the tracing log stream); the text guides toward adding
    // `--enable-rpc`.
    if let Some(given) = rpc_group_conflict(download_mode_given(&cli), cli.enable_rpc, &matches) {
        eprintln!(
            "error: the following options have no effect in download mode without --enable-rpc: {}",
            given.join(" ")
        );
        eprintln!(
            "       add --enable-rpc to run the RPC server alongside the download, \
             or remove these options"
        );
        std::process::exit(2);
    }

    // Knob-override injection (`--bt-max-peers` /
    // `--bt-request-peer-speed-limit`): explicit command-line values
    // (same value_source test as the RPC group; conf providers inject
    // inside the conf arm — the cli_wins rule guarantees command-line
    // injection is written last and always wins) go to in-process
    // override statics (taiji-io knobs, the highest priority above env
    // knobs; the no-set_var injection form for edition 2024). Defaults
    // do not inject — built-in cap 120 / target 100 and threshold 50K
    // stay (the default-zero-behavior rule; the aria2 default
    // divergence is noted in the Cli field docs).
    if matches.value_source("bt_max_peers") == Some(clap::parser::ValueSource::CommandLine) {
        match bt_max_peers_override_of(cli.bt_max_peers, true) {
            Some(v) => {
                taiji_io::knobs::set_peer_max_override(v);
                info!(target: "taiji::cli", bt_max_peers = cli.bt_max_peers,
                    "bt-max-peers override armed (engine peer cap; outbound target auto-clamped)");
            }
            None => {
                warn!(target: "taiji::cli",
                    "--bt-max-peers=0 (unlimited) is not expressible: taiji always enforces a peer cap; keeping built-in default");
            }
        }
    }
    if matches.value_source("bt_request_peer_speed_limit")
        == Some(clap::parser::ValueSource::CommandLine)
    {
        taiji_io::knobs::set_peer_request_speed_limit_override(cli.bt_request_peer_speed_limit);
        info!(target: "taiji::cli", bps = cli.bt_request_peer_speed_limit,
            "bt-request-peer-speed-limit override armed (bytes/s, 0 = rescue arm closed)");
    }

    // worker_threads = min(4, nproc).
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(4);
    // Worker + blocking thread stack preallocation: tokio
    // defaults every runtime thread to a 2MiB stack mapping; on the
    // 2-core target the reactor loops and `spawn_blocking` closures use
    // nowhere near that (async task frames are heap-allocated — this
    // touches only the OS stack mapping, never scheduling semantics).
    // Default 1MiB, `BH_THREAD_STACK_KB` clamped to [256, 8192]
    // (=2048 restores the tokio default bit-for-bit). No log line here:
    // the tracing subscriber initializes inside `run`, after the runtime
    // exists — the effective value is observable from the process's
    // thread-stack mappings (/proc/<pid>/maps anon sizes).
    let stack_kb = taiji_io::knobs::thread_stack_kb();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .thread_stack_size(stack_kb * 1024)
        .enable_all()
        .build();
    let rt = match rt {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(target: "taiji::cli", error = %e, "failed to start tokio runtime");
            std::process::exit(1);
        }
    };

    let code = rt.block_on(run(cli));
    if code != 0 {
        std::process::exit(code);
    }
}

async fn run(cli: Cli) -> i32 {
    // Subcommand dispatch (import / create-torrent / http); the
    // existing download/idle modes are unaffected.
    if let Some(Command::Import(args)) = cli.command {
        return import::run(args).await;
    }
    if let Some(Command::CreateTorrent(args)) = cli.command {
        return create_torrent::run(args).await;
    }
    if let Some(Command::Http(args)) = cli.command {
        return http::run(*args).await;
    }
    if let Some(Command::Media(args)) = cli.command {
        return media::run(*args).await;
    }
    // Domain C meta mode: --show-files (the aria2 `-S` counterpart) —
    // print the torrent info block + file list and exit (exit 0),
    // before any download-mode assembly (the meta-flag style, same as
    // `--print-completions`).
    if cli.show_files {
        return run_show_files(&cli);
    }
    // Domain B acceptance disclosure (explicitly not effective, no
    // silence — the same style as --use-head): the transport
    // face of the three client mTLS/minimum-TLS-version flags is wired
    // in taiji-http (`ClientConfig::identity_cert_path`/
    // `identity_key_path`/`min_tls_version` -> build_transport), but
    // the session task-option projection face (the taiji-core option
    // table) is absent — no CLI form in this build can reach the
    // transport face, so the three flags warn once on acceptance (the
    // value domain is frozen by clap: tls1.2|tls1.3).
    if cli.certificate.is_some() || cli.private_key.is_some() || cli.min_tls_version.is_some() {
        warn!(target: "taiji::cli",
            "--certificate/--private-key/--min-tls-version accepted but NOT effective \
             in this build: the taiji-http transport face is wired, the session \
             task-option projection is pending (declared difference)");
    }
    // Domain C acceptance disclosure (explicitly not effective, no
    // silence — the same style as domain B): the six flags' consumption
    // faces are absent in this build; given explicitly, each warns
    // once. The check findings are recorded faithfully in each Cli
    // field doc (interface connection layer / disable-ipv6 resolution
    // face / auto-save-interval persistence face / netrc face / cookie
    // export face / FTP TYPE face).
    warn_deferred_domain_c(&cli);
    // Acceptance disclosure (explicitly not effective, no
    // silence — the same style as domain C): the seven flags' names are
    // already accepted on the session/RPC faces as no-op value faces
    // (the GLOBAL_PATCH_TABLE no-op rows); the CLI face accepts the
    // value and warns once — the value has no consumption seam in this
    // build (the per-flag reasons are in the field docs / row notes).
    warn_deferred_d_tier(&cli);
    // Crypto options -> CryptoPolicy (invalid values exit with an
    // explicit error instead of silently falling back to defaults —
    // the same rule as aria2 SizeOptionHandler/ChoiceOptionHandler
    // failing startup on parse errors).
    let min_level =
        taiji_core::session::parse_crypto_level(&cli.bt_min_crypto_level).ok_or_else(|| {
            format!(
                "invalid --bt-min-crypto-level value: {} (plain|arc4)",
                cli.bt_min_crypto_level
            )
        });
    let min_level = match min_level {
        Ok(v) => v,
        Err(msg) => {
            error!(target: "taiji::cli", "{msg}");
            return 2;
        }
    };
    let conn_type = taiji_core::session::parse_peer_connection_type(&cli.bt_peer_connection_type)
        .ok_or_else(|| {
            format!(
                "invalid --bt-peer-connection-type value: {} (tcp|utp|prefer-utp|prefer-tcp)",
                cli.bt_peer_connection_type
            )
        });
    let conn_type = match conn_type {
        Ok(v) => v,
        Err(msg) => {
            error!(target: "taiji::cli", "{msg}");
            return 2;
        }
    };
    // The µTP engine dial/accept surface is wired — non-default values
    // no longer warn (the wiring-status notice was removed with the
    // wiring; effective in the download/idle modes below).
    let crypto = taiji_bt::mse::CryptoPolicy {
        require_crypto: cli.bt_require_crypto,
        min_level,
    };
    // Domain 5 behavior flags, shared resolution (a single CLI
    // value-domain point; out of domain = explicit exit 2 refusal — the
    // same direction as the aria2 NumberOptionHandler).
    let seed_time = match parse_minutes_option(cli.seed_time, "seed-time") {
        Ok(v) => v,
        Err(msg) => {
            error!(target: "taiji::cli", "{msg}");
            return 2;
        }
    };
    // Wiring: the --seed-ratio value domain (the
    // checked_seed_ratio rule — finite >= 0; 0.0 = the criterion
    // disabled; out-of-domain = explicit exit 2, the aria2
    // NumberOptionHandler direction).
    let seed_ratio = match parse_seed_ratio_option(cli.seed_ratio) {
        Ok(v) => v,
        Err(msg) => {
            error!(target: "taiji::cli", "{msg}");
            return 2;
        }
    };
    let stop_after = match parse_minutes_option(cli.stop, "stop") {
        Ok(v) => v,
        Err(msg) => {
            error!(target: "taiji::cli", "{msg}");
            return 2;
        }
    };
    // Domain 5: the --select-file syntax parse (the session single point
    // `parse_select_file`; the only source of the 1-based -> 0-based
    // conversion). Range validation is deferred until the metainfo is
    // known — bare in [`run_download`] (over non-pad files), the rpc
    // form at the same session addTorrent point (the error face = the
    // session's explicit refusal).
    let select_file = match &cli.select_file {
        Some(raw) => match taiji_core::session::parse_select_file(raw) {
            Ok(sel) => Some(sel),
            Err(msg) => {
                error!(target: "taiji::cli", "{msg}");
                return 2;
            }
        },
        None => None,
    };
    // Domain 5: the --hash-check-only mode restriction (fail-closed):
    // effective only in the bare .torrent download form — the RPC
    // pipeline (and the domain A batch pipeline alike) has no per-task
    // pre-download verification face; accepting it there would break the
    // "no download" promise; the idle daemon has no task face = accepted
    // + a not-effective warning (the same disclosure style as
    // --use-head).
    if cli.hash_check_only && hash_check_only_mode_conflict(cli.torrent.is_some(), cli.enable_rpc) {
        error!(
            target: "taiji::cli",
            "--hash-check-only cannot be combined with --enable-rpc in this build: \
             the RPC pipeline has no per-task pre-download verify face; use bare \
             download mode (drop --enable-rpc)"
        );
        return 2;
    }
    if cli.hash_check_only && cli.input_file.is_some() {
        error!(
            target: "taiji::cli",
            "--hash-check-only cannot be combined with --input-file in this build: \
             the batch pipeline has no per-task pre-download verify face; use bare \
             download mode (drop --input-file)"
        );
        return 2;
    }
    if cli.hash_check_only && cli.torrent.is_none() {
        warn!(
            target: "taiji::cli",
            "--hash-check-only accepted but NOT effective without a .torrent \
             positional: no task verification face in this form (declared \
             difference; the consumption face is the bare-run .torrent arm)"
        );
    }
    // Domain 5: the --peer-agent acceptance disclosure (the same style
    // as --use-head; the alias stance is in the flag's field doc — NOT
    // an alias of --peer-id-prefix, the UA/v string stays pinned to the
    // build constant).
    if cli.peer_agent.is_some() {
        warn!(
            target: "taiji::cli",
            "--peer-agent accepted but NOT effective in this build: the client UA / \
             extended-handshake v string is pinned to the build constant (declared \
             difference). It is NOT an alias of --peer-id-prefix (separate surfaces)"
        );
    }
    // Download (bare) mode's initial global import sources = the
    // --bt-tracker comma list + --bt-tracker-file (ngosang parsing;
    // disk read via spawn_blocking). Failure = warn and degrade (the
    // same policy as the idle-mode bootstrap). Since only
    // the bare arm consumes this (the --enable-rpc arm's import face
    // goes through the session bootstrap, same rule as idle; a pre-read
    // here would change idle's historical log face — hence gated by
    // mode); the domain A batch form (--input-file) consumes the same
    // face (its own session GlobalOptions.bt_tracker — the batch
    // session does not go through the bootstrap import path).
    let seed_trackers = if (cli.torrent.is_some() && !cli.enable_rpc) || cli.input_file.is_some() {
        let mut seed = taiji_core::session::split_bt_tracker(&cli.bt_tracker);
        if let Some(f) = &cli.bt_tracker_file {
            let f = f.clone();
            match tokio::task::spawn_blocking(move || {
                taiji_bt::tracker::trackerslist::read_trackerslist(&f)
            })
            .await
            {
                Ok(Ok(urls)) => seed.extend(urls),
                Ok(Err(e)) => {
                    warn!(target: "taiji::cli", %e, "bt-tracker-file import failed; continuing without it");
                }
                Err(e) => {
                    warn!(target: "taiji::cli", %e, "bt-tracker-file parse join failed; continuing without it");
                }
            }
        }
        seed
    } else {
        Vec::new()
    };
    // Domain A: the --input-file batch form (a one-shot session
    // pipeline; the RPC face is disclosed with a warning inside the
    // form — batch tasks run and exit, no RPC listener assembly).
    if let Some(path) = cli.input_file.clone() {
        return run_input_file(path, &cli, crypto, conn_type, seed_trackers).await;
    }
    // Three-state assembly (mirrors the upstream
    // `DownloadEngineFactory.cc` enable-rpc branch + CLI URI
    // co-residence): pure download (--enable-rpc=false default, the
    // bare path unchanged) / pure daemon (no positional = idle) /
    // download+RPC in one process (the enable_rpc arm — session actor
    // pipeline end to end). Both session arms share the
    // [`rpc_config_from_cli`] + [`build_idle_options`] assembly points —
    // values from CLI and conf enter through the same Cli fields. The
    // torrent is cloned before matching: both arms assemble through a
    // whole-struct `&cli` borrow, and partially moving the positional
    // would invalidate that borrow (E0382); one PathBuf copy at
    // startup.
    let torrent = cli.torrent.clone();
    match torrent {
        Some(arg) => match classify_positional(arg.as_os_str()) {
            PositionalInput::MagnetUri(uri) if cli.enable_rpc => {
                warn_ca_certificate_no_global_face(&cli);
                warn_bare_run_only_flags(&cli, "magnet+rpc");
                let cfg = rpc_config_from_cli(&cli);
                let mut opts = build_idle_options(&cli, crypto, conn_type);
                // Domain 5: the --stop shutdown deadline rides the
                // session form (parsed in run; the RPC shutdown path).
                opts.stop_after = stop_after;
                run_download_with_rpc(DownloadWithRpc::Magnet(uri), cfg, opts).await
            }
            PositionalInput::WebUri(url) => {
                // The URI positional form does not co-reside with RPC
                // (the http subcommand pipeline has no server assembly)
                // — warn explicitly instead of silently ignoring.
                if cli.enable_rpc {
                    warn!(target: "taiji::cli",
                        "--enable-rpc is not yet effective in the URI positional form \
                         (the torrent-file form supports co-residence); continuing the one-shot download");
                }
                // Note: the top-level `--summary-interval` flag is
                // injected into the URL positional form (previously
                // hard-coded SUMMARY_INTERVAL_DEFAULT — the flag was
                // silently ineffective in that form). Domain validation
                // is already done by the clap value_parser.
                // Domain B: the top-level `--ca-certificate` is injected
                // the same way (direct addUri option mapping — a single
                // source at the session parse arm, a bad path = task
                // rejected).
                // Domain C: the top-level `--load-cookies` maps the same
                // way (the same gate as `taiji http --load-cookies`);
                // `--gid`/`--dry-run` have bare-run-only consumption
                // faces that are absent in this form — disclosed
                // explicitly.
                warn_bare_run_only_flags(&cli, "URL positional");
                http::delegate_positional(
                    url,
                    cli.dir.clone(),
                    cli.summary_interval,
                    cli.ca_certificate.clone(),
                    cli.load_cookies.as_ref().map(|p| p.display().to_string()),
                )
                .await
            }
            PositionalInput::MagnetUri(uri) => {
                warn_bare_run_only_flags(&cli, "magnet one-shot");
                run_one_shot_magnet(uri, &cli, crypto, conn_type, seed_trackers).await
            }
            PositionalInput::TorrentFile(path) if cli.enable_rpc => {
                warn_ca_certificate_no_global_face(&cli);
                warn_bare_run_only_flags(&cli, "torrent+rpc");
                let cfg = rpc_config_from_cli(&cli);
                let mut opts = build_idle_options(&cli, crypto, conn_type);
                // Domain 5: task-face flags flow through IdleOptions with
                // the form (select-file = the AddTorrent injection, set
                // inside build_idle_options; --stop = the shutdown
                // deadline, parsed in run).
                opts.stop_after = stop_after;
                run_download_with_rpc(DownloadWithRpc::TorrentFile(path), cfg, opts).await
            }
            PositionalInput::TorrentFile(path) => {
                // Domain C: --dry-run (the bare-run .torrent arm) —
                // parse + print the download plan and exit, the engine
                // is not spawned (aria2 cancels for BT; here it "shows
                // what would happen" — noted as a divergence in the
                // flag docs).
                if cli.dry_run == Some(true) {
                    return run_dry_run_torrent(&path, &cli);
                }
                run_download(
                    path,
                    cli.dir.clone(),
                    cli.listen_port,
                    crypto,
                    conn_type,
                    DownloadOptions {
                        bt_lsd: cli.bt_lsd,
                        // --bt-sequential-download: bare mode
                        // pushes SetSchedulerPolicy after spawn.
                        bt_sequential_download: cli.bt_sequential_download,
                        // --enable-dht injects the download-mode
                        // DhtWireConfig (SPEC §11 default true; the same
                        // option face as idle mode).
                        enable_dht: cli.enable_dht,
                        // --enable-http-seeding injects the download-mode
                        // webseed set (BEP19 default true; false = cleared
                        // after assembly).
                        enable_http_seeding: cli.enable_http_seeding,
                        // --bt-enable-upnp/--bt-enable-nat-pmp inject the
                        // bare NAT power face (the same option face as idle
                        // mode).
                        bt_enable_upnp: cli.bt_enable_upnp,
                        bt_enable_natpmp: cli.bt_enable_natpmp,
                        seed_trackers,
                        // Peer ID prefix (consumed by the single generation
                        // point of announce and handshake).
                        peer_id_prefix: peer_id_prefix_or_default(&cli.peer_id_prefix),
                        // --max-download-limit/--max-upload-limit
                        // both 0 = None keeps the existing pass-through with
                        // zero behavior change).
                        max_download_limit: cli.max_download_limit,
                        max_upload_limit: cli.max_upload_limit,
                        // batch C: the overall rate-limit pair (the
                        // global bucket; 0 = unlimited, the same option
                        // face as idle mode).
                        max_overall_download_limit: cli.max_overall_download_limit,
                        max_overall_upload_limit: cli.max_overall_upload_limit,
                        // batch C: the ut_pex advertise/consume gate
                        // (the same option face as idle mode).
                        enable_peer_exchange: cli.enable_peer_exchange,
                        // batch C: the DHT startup-time group (the v4
                        // bootstrap entry + the transaction timeout; the
                        // same option face as idle mode).
                        dht_entry_point: cli.dht_entry_point.clone(),
                        dht_message_timeout: cli.dht_message_timeout,
                        // --check-integrity: a pre-spawn disk
                        // rescan feeds the preset_progress bitmap.
                        check_integrity: cli.check_integrity,
                        // -B: the post-check seeding gate + the
                        // seeding-stall watchdog + the tracker announce
                        // client knobs (the bare injection face; all
                        // defaults = zero behavior change).
                        bt_hash_check_seed: cli.bt_hash_check_seed,
                        bt_stop_timeout_secs: cli.bt_stop_timeout,
                        bt_tracker_interval: cli.bt_tracker_interval,
                        bt_tracker_timeout_secs: cli.bt_tracker_timeout,
                        bt_tracker_connect_timeout_secs: cli.bt_tracker_connect_timeout,
                        // The six hook commands + the gate (the `--on-*`
                        // family, SPEC §7.4): bare mode injects
                        // EngineConfig.hook (consumed by run_download).
                        hooks: hook_set_from_cli(&cli),
                        // Domain C: --dht-entry-point6 injects the engine's
                        // V6-family bootstrap (consumed by engine/dht.rs;
                        // None = the default empty = the SPEC §6.7 v6 router
                        // fallback constant, zero change to the existing
                        // form).
                        dht_entry_point6: cli.dht_entry_point6.clone(),
                        // Domain C: --gid pins the task GID (consumed by the
                        // hook argv payload + the startup log; None = a
                        // random allocator value — the existing form).
                        task_gid: cli.gid,
                        // Domain 5 behavior flags (the bare-form
                        // consumption face; parse in run — the value
                        // domain exits there).
                        select_file,
                        seed_time,
                        // Wiring: the bare-form
                        // consumption face (Some = the EngineConfig.seed
                        // seed_ratio override; None = the standing 1.0
                        // engine default, zero change).
                        seed_ratio,
                        stop_after,
                        hash_check_only: cli.hash_check_only,
                    },
                )
                .await
            }
        },
        None => {
            warn_ca_certificate_no_global_face(&cli);
            warn_bare_run_only_flags(&cli, "idle daemon");
            let cfg = rpc_config_from_cli(&cli);
            let mut opts = build_idle_options(&cli, crypto, conn_type);
            // Domain 5: the --stop shutdown deadline (parsed in run;
            // select-file/hash-check-only have no task face here and are
            // not consumed — the declared face in their field docs;
            // --seed-time rides build_idle_options as the session global
            // default).
            opts.stop_after = stop_after;
            run_idle(cfg, opts).await
        }
    }
}

/// Frozen peer-id-prefix default (unset = `-TJ0001-`, byte-identical
/// to the previous behavior); one option surface for the bare
/// download and session assembly arms.
fn peer_id_prefix_or_default(peer_id_prefix: &Option<String>) -> String {
    peer_id_prefix
        .clone()
        .unwrap_or_else(|| taiji_bt::tracker::PEER_ID_PREFIX.to_string())
}

/// Domain B: the `--ca-certificate` session-form disclosure (shared by
/// the idle and download+rpc arms). The session `ca-certificate` is a
/// per-task option (; accepted on the addUri/changeOption
/// faces) — the daemon form has no global injection face (the
/// taiji-core GlobalOptions has no such key), so given explicitly = one
/// warning: pushing it per task over RPC remains available and the
/// platform trust roots keep backing HTTPS. Not refused (aria2 global
/// options likewise have no effect on BT tasks — an acceptance
/// disclosure, not an acceptance refusal).
fn warn_ca_certificate_no_global_face(cli: &Cli) {
    if cli.ca_certificate.is_some() {
        warn!(target: "taiji::cli",
            "--ca-certificate accepted but has no global injection face in session forms \
             (the session option is per-task via addUri/changeOption); HTTPS tasks use \
             platform trust roots unless the option is passed per task");
    }
}

/// Domain C acceptance disclosure (a single point in run; a per-flag
/// warning each — only on explicit givens, zero noise on defaults).
/// The per-item check findings live in the corresponding Cli field
/// docs; the warning text itself carries the facts (the concrete
/// location of the absent consumption face), never masquerading as
/// effective.
fn warn_deferred_domain_c(cli: &Cli) {
    if cli.save_cookies.is_some() {
        warn!(target: "taiji::cli",
            "--save-cookies accepted but NOT effective in this build: cookie \
             persistence is sqlite-only, the CookieJar has no Netscape \
             export face (declared difference)");
    }
    if cli.auto_save_interval.is_some() {
        warn!(target: "taiji::cli",
            "--auto-save-interval accepted but NOT effective: sqlite persistence \
             is continuous (PersistWriter commits every event), the periodic \
             control-file write semantics are permanently subsumed (declared \
             difference; --save-session-interval drives the periodic flush face)");
    }
    if cli.interface.is_some() {
        warn!(target: "taiji::cli",
            "--interface accepted but NOT effective in this build: no consumption \
             point exists (reqwest local_address is available but the taiji-http \
             ClientConfig/build_transport face is absent; the taiji-io UDP/TCP \
             bind face has no interface binding) (declared difference)");
    }
    if cli.disable_ipv6.is_some() {
        warn!(target: "taiji::cli",
            "--disable-ipv6 accepted but NOT effective in this build: the DNS \
             adapter has no AAAA filter face and the BT dial face BH_V6_PREF knob \
             is an ordering preference, not a disable switch (declared difference)");
    }
    if cli.netrc_path.is_some() {
        warn!(target: "taiji::cli",
            "--netrc-path accepted but NOT effective in this build: no netrc \
             parsing/consumption face exists; credentials come from \
             --http-user/--ftp-user options (aria2 reads ~/.netrc by default — \
             taiji never does, declared difference)");
    }
    if cli.no_netrc.is_some() {
        warn!(target: "taiji::cli",
            "--no-netrc accepted but NOT effective: taiji never reads a netrc file \
             (aria2 no-netrc=true semantics are already the standing behavior) \
             (declared difference)");
    }
    if cli.ftp_type.as_deref() == Some("ascii") {
        warn!(target: "taiji::cli",
            "--ftp-type=ascii accepted but NOT effective: the FTP data connection \
             is always TYPE I (binary) in this build (declared difference; binary \
             is the aria2 default and matches standing behavior)");
    }
}

/// Acceptance disclosure (a sibling of
/// [`warn_deferred_domain_c`], the same single-point-in-run shape; a
/// per-flag warning each — only on explicit givens, zero noise on
/// defaults). The seven names are already accepted on the session/RPC
/// faces as no-op value faces (the GLOBAL_PATCH_TABLE no-op rows, the
/// value echoed verbatim); the CLI face here accepts + warns — the
/// consumption seams are absent in this build, and the warning text
/// carries each row note's reason (never masquerading as effective).
fn warn_deferred_d_tier(cli: &Cli) {
    if cli.async_dns.is_some() {
        warn!(target: "taiji::cli",
            "--async-dns accepted but NOT effective in this build: taiji's resolver \
             behavior is fixed (the http transport stack manages its own resolution; \
             no async-dns wiring seam) (declared difference)");
    }
    if cli.enable_async_dns6.is_some() {
        warn!(target: "taiji::cli",
            "--enable-async-dns6 accepted but NOT effective in this build: taiji's \
             resolver behavior is fixed, no v6 resolver switch seam (aria2 wraps the \
             option in a DeprecatedOptionHandler) (declared difference)");
    }
    if cli.bt_exclude_tracker.is_some() {
        warn!(target: "taiji::cli",
            "--bt-exclude-tracker accepted but NOT effective in this build: the global \
             tracker import has no exclusion face (union-cumulative import; the \
             exclusion half of the aria2 tracker face is absent) (declared difference)");
    }
    if cli.max_download_result.is_some() {
        warn!(target: "taiji::cli",
            "--max-download-result accepted but NOT effective in this build: the RPC \
             face has no result-retention seam (job bookkeeping is the truth; \
             tellStopped reads the queues directly) (declared difference)");
    }
    if cli.max_file_not_found.is_some() {
        warn!(target: "taiji::cli",
            "--max-file-not-found accepted but NOT effective in this build: the \
             taiji-http source probe eviction has no option-driven counter seam \
             (declared difference)");
    }
    if cli.max_mmap_limit.is_some() {
        warn!(target: "taiji::cli",
            "--max-mmap-limit accepted but NOT effective in this build: the store face \
             has no mmap path (disk_policy decides the IO shape; the value has nothing \
             to threshold) (declared difference)");
    }
    if cli.max_resume_failure_tries.is_some() {
        warn!(target: "taiji::cli",
            "--max-resume-failure-tries accepted but NOT effective in this build: the \
             bitmap resume has no fall-back-to-zero seam (the bitmap is the resume \
             truth) (declared difference)");
    }
}

/// Domain C bare-run-only flag disclosure in the session forms
/// (`--gid`/`--dry-run`: their consumption face is the bare-run
/// .torrent arm — the session pipeline allocates GIDs via the
/// SessionActor and the HTTP/magnet forms have no dry-run probe seam;
/// given explicitly = one warning, execution proceeds as usual).
/// `form` names the form the warning fires in (idle daemon / magnet
/// one-shot / input-file batch / URL positional / torrent+rpc /
/// magnet+rpc).
fn warn_bare_run_only_flags(cli: &Cli, form: &str) {
    if cli.gid.is_some() {
        warn!(target: "taiji::cli", form,
            "--gid accepted but NOT effective in this form: task GIDs are \
             allocated by the SessionActor (bare-run .torrent face only)");
    }
    if cli.dry_run == Some(true) {
        warn!(target: "taiji::cli", form,
            "--dry-run=true accepted but NOT effective in this form: \
             proceeding with the download (bare-run .torrent face only)");
    }
}

/// Minutes-value flag domain parse (a single point shared by
/// `--seed-time`/`--stop`; f64 minutes -> Duration): negative /
/// non-finite / beyond the Duration domain = Err (the caller exits 2 —
/// the same direction as the aria2 NumberOptionHandler failing startup
/// out of domain). `Duration::ZERO` = 0 minutes = the disabled
/// semantics (the aria2 "If 0 is given, this feature is disabled" same
/// rule), decided by the consumption face.
fn parse_minutes_option(value: Option<f64>, flag: &str) -> Result<Option<Duration>, String> {
    let Some(m) = value else {
        return Ok(None);
    };
    if !m.is_finite() || m < 0.0 {
        return Err(format!(
            "invalid --{flag} value: {m} (expected minutes >= 0)"
        ));
    }
    Duration::try_from_secs_f64(m * 60.0)
        .map(Some)
        .map_err(|_| format!("invalid --{flag} value: {m} (out of duration domain)"))
}

/// `--seed-ratio` value-domain parse (a single point; the CLI face of
/// the core `checked_seed_ratio` rule — finite and >= 0; `0.0` = the
/// ratio criterion disabled, decided by the consumption face via the
/// `SeedCheck::build` `seed_ratio > 0.0` rule). Err = the caller exits 2
/// (the same direction as [`parse_minutes_option`] — the aria2
/// NumberOptionHandler failing startup out of domain).
fn parse_seed_ratio_option(value: Option<f64>) -> Result<Option<f64>, String> {
    match value {
        None => Ok(None),
        Some(r) if r.is_finite() && r >= 0.0 => Ok(Some(r)),
        Some(r) => Err(format!(
            "invalid --seed-ratio value: {r} (expected ratio >= 0)"
        )),
    }
}

/// The `--stop` deadline future (None/0 = never fires — a pending
/// identity; a positive duration = a wall-clock sleep). The shutdown
/// select's shared arm across the three forms.
async fn stop_timer(after: Option<Duration>) {
    match after {
        Some(d) if d > Duration::ZERO => tokio::time::sleep(d).await,
        _ => std::future::pending::<()>().await,
    }
}

/// The `--hash-check-only` mode-restriction verdict (parameterized for
/// the truth-table unit test): the download form with `--enable-rpc`
/// also given = true (the exit 2 refusal arm — the RPC pipeline has no
/// per-task pre-download verification face; accepting it would break
/// the "no download" promise). Bare (enable_rpc=false) and idle (no
/// torrent) = false (the former is the effective arm, the latter the
/// not-effective warning arm — neither belongs to this verdict). The
/// caller composes the full refusal arm as `cli.hash_check_only &&`
/// this verdict.
fn hash_check_only_mode_conflict(torrent_given: bool, enable_rpc: bool) -> bool {
    torrent_given && enable_rpc
}

/// Human-readable byte-size abbreviation (the same shape as the aria2
/// `util::abbrevSize` — 1024-based, one decimal, KiB/MiB/GiB; below
/// 1KiB the raw byte count).
fn abbrev_size(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    let b = bytes as f64;
    if b >= GIB {
        format!("{:.1}GiB", b / GIB)
    } else if b >= MIB {
        format!("{:.1}MiB", b / MIB)
    } else if b >= KIB {
        format!("{:.1}KiB", b / KIB)
    } else {
        format!("{bytes}B")
    }
}

/// Lowercase hex of a byte string (the single info-hash render point).
fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Torrent info block + file list rendering (the `--show-files` output
/// face; a pure function for easy decision-table unit tests. Styled
/// after aria2 `bittorrent_helper.h` print: info block +
/// file list; fields are bounded by the existing Metainfo extraction
/// face — comment/creation date/created by/magnet lines are outside
/// the extraction face, omitted as-is). Pad placeholder entries (BEP47)
/// are excluded — they are never written to disk and stay out of the
/// "files that would be written" list.
fn format_torrent_listing(meta: &Metainfo) -> String {
    let mut out = String::new();
    out.push_str("*** BitTorrent File Information ***\n");
    out.push_str(&format!(
        "Mode: {}\n",
        if meta.multi_file { "multi" } else { "single" }
    ));
    if !meta.announce.is_empty() {
        out.push_str("Announce:\n");
        out.push_str(&format!(" {}\n", meta.announce));
    }
    // Info hash: the v1 40-hex-digit form first, falling back to the
    // 64-digit form for v2-only (both hashes are over the raw info
    // slice — the Metainfo::parse fact face).
    let info_hash = match meta.meta.identity.v1 {
        Some(v1) => hex_lower(&v1),
        None => meta
            .meta
            .identity
            .v2
            .map(|v2| hex_lower(&v2))
            .unwrap_or_default(),
    };
    out.push_str(&format!("Info Hash: {info_hash}\n"));
    out.push_str(&format!("Piece Length: {}B\n", meta.meta.piece_length));
    out.push_str(&format!("The Number of Pieces: {}\n", meta.v1_pieces.len()));
    let total = meta.meta.total_len();
    out.push_str(&format!(
        "Total Length: {} ({total} bytes)\n",
        abbrev_size(total)
    ));
    if !meta.url_list.is_empty() {
        out.push_str("URL List:\n");
        for u in &meta.url_list {
            out.push_str(&format!(" {u}\n"));
        }
    }
    if let Some(name) = &meta.name {
        out.push_str(&format!("Name: {name}\n"));
    }
    // File list: the disk view (disk_layout — multi-file carries the
    // name prefix); if layout planning fails (malformed v1 offsets
    // etc.) fall back to listing the wire view verbatim.
    let entries: Vec<(std::path::PathBuf, u64)> = match meta.disk_layout() {
        Ok(layout) => layout
            .files()
            .iter()
            .filter(|f| !f.padding)
            .map(|f| (f.path.clone(), f.length))
            .collect(),
        Err(_) => meta
            .meta
            .files
            .iter()
            .filter(|f| !f.padding)
            .map(|f| (f.path.clone(), f.length))
            .collect(),
    };
    out.push_str("Files:\n");
    for (idx, (path, len)) in entries.iter().enumerate() {
        out.push_str(&format!(
            "{}. {} ({} bytes)\n",
            idx + 1,
            path.display(),
            len
        ));
    }
    out
}

/// Domain C meta mode: `--show-files` (the aria2 `-S` counterpart;
/// styled after aria2 `Context.cc` showTorrentFile). Parse
/// the `.torrent` positional -> print the info block + file list to
/// stdout -> exit 0 (a meta flag — before any download-mode assembly,
/// neither the engine nor RPC starts). Exit codes: read/parse failure
/// = 1 (the same gate as bare); no positional or a non-torrent
/// positional = 2 (a usage error — aria2 prints a not-torrent line and
/// carries on for non-torrent input, refused explicitly here, a
/// declared divergence in the flag docs).
fn run_show_files(cli: &Cli) -> i32 {
    let Some(path) = cli.torrent.clone() else {
        eprintln!("error: --show-files requires a .torrent file positional argument");
        return 2;
    };
    if !matches!(
        classify_positional(path.as_os_str()),
        PositionalInput::TorrentFile(_)
    ) {
        eprintln!(
            "error: --show-files requires a .torrent file positional argument \
             (magnet/URL given; metalink listing is not supported in this build)"
        );
        return 2;
    }
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            error!(target: "taiji::cli", path = %path.display(), %e, "cannot read torrent file");
            return 1;
        }
    };
    let meta = match Metainfo::parse(&bytes) {
        Ok(m) => m,
        Err(e) => {
            error!(target: "taiji::cli", path = %path.display(), %e, "invalid metainfo");
            return 1;
        }
    };
    print!("{}", format_torrent_listing(&meta));
    let _ = std::io::Write::flush(&mut std::io::stdout());
    0
}

/// Domain C: the `--dry-run=true` bare-run .torrent arm (the
/// consumption point; aria2 cancels outright for BT, here = "show what
/// would happen" then exit — noted as a divergence in the flag docs).
/// Parse the metainfo -> print the download plan to stdout -> exit 0;
/// neither the engine nor RPC starts. Read/parse failure = 1 (the same
/// gate as bare — a dry run also refuses a bad torrent).
fn run_dry_run_torrent(path: &std::path::Path, cli: &Cli) -> i32 {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            error!(target: "taiji::cli", path = %path.display(), %e, "cannot read torrent file");
            return 1;
        }
    };
    let meta = match Metainfo::parse(&bytes) {
        Ok(m) => m,
        Err(e) => {
            error!(target: "taiji::cli", path = %path.display(), %e, "invalid metainfo");
            return 1;
        }
    };
    let files = meta.meta.files.iter().filter(|f| !f.padding).count();
    println!("dry-run: engine not spawned; planned download");
    println!("  torrent: {}", path.display());
    println!("  dir: {}", cli.dir.display());
    println!("  listen-port: {}", cli.listen_port);
    if let Some(name) = &meta.name {
        println!("  name: {name}");
    }
    println!("  files: {files}");
    println!(
        "  total: {} bytes ({})",
        meta.meta.total_len(),
        abbrev_size(meta.meta.total_len())
    );
    if meta.announce.is_empty() {
        println!("  announce: (none — DHT only)");
    } else {
        println!("  announce: {}", meta.announce);
    }
    println!(
        "  dht: {}",
        if cli.enable_dht {
            "enabled"
        } else {
            "disabled"
        }
    );
    let _ = std::io::Write::flush(&mut std::io::stdout());
    0
}

/// recheck outcome -> preset bitmap mapping (a single point; bitmap
/// columns map field-for-field, shaped like the torrent_progress
/// rows). Entries for suspended files (missing piece-layer v2) come
/// out of the outcome as all-zero bits = re-download — bare mode has
/// no previous-session values to preserve, so the
/// `preserve_suspended_v2_bits` row-merge surface does not apply; map
/// verbatim.
fn preset_progress_from_outcome(
    outcome: &taiji_core::session::RecheckOutcome,
) -> taiji_core::engine::PresetProgress {
    taiji_core::engine::PresetProgress {
        v1_bitfield: outcome.v1_bitfield.clone(),
        v2_file_bits: outcome.v2_file_bits.clone(),
    }
}

/// RPC listen-surface assembly (shared by the idle and download+rpc
/// branches — their construction literals were previously identical,
/// collapsed into one function; values from CLI and conf enter
/// through the same Cli fields). --rpc-listen-all feeds the binding
/// axis (decoupled from credentials). rpc-secret is normalized via
/// [`taiji_rpc::normalize_secret`] (empty/whitespace-only = unset, the
/// aria2 empty-string semantics — one shared point for CLI and conf).
fn rpc_config_from_cli(cli: &Cli) -> taiji_rpc::RpcConfig {
    taiji_rpc::RpcConfig {
        port: cli.rpc_listen_port,
        listen_all: cli.rpc_listen_all,
        secret: taiji_rpc::normalize_secret(cli.rpc_secret.clone()),
        rpc_user: cli.rpc_user.clone(),
        rpc_passwd: cli.rpc_passwd.clone(),
        allow_origin_all: cli.rpc_allow_origin_all,
        max_request_size: usize::try_from(cli.rpc_max_request_size).unwrap_or(usize::MAX),
        aria2_compat: cli.rpc_aria2_compat,
        // Domain B TLS family (--rpc-secure/certificate/private-key):
        // mapped straight to the serve assembly point — pair validation
        // and PEM loading fail closed in serve_with_guards (either
        // missing / bad PEM / a certificate without secure = io::Error,
        // refused to start).
        secure: cli.rpc_secure,
        certificate: cli.rpc_certificate.clone(),
        private_key: cli.rpc_private_key.clone(),
    }
}

/// The six hook commands + the post-hash-check gate -> the session
/// [`taiji_core::hook::HookSet`] (the single CLI injection point: the
/// two session forms go via [`IdleOptions`] -> `GlobalOptions.hooks`,
/// bare via `EngineConfig.hook`, magnet one-shot via the session
/// globals — three faces share this constructor to prevent multi-point
/// construction drift). Empty values normalize to unset (blank = None,
/// same rule as aria2 `option->blank` — the same normalization as the
/// RPC option face's `non_empty`; conf values arrive trimmed and take
/// the same shape).
fn hook_set_from_cli(cli: &Cli) -> taiji_core::hook::HookSet {
    let blank_to_none = |v: &Option<String>| v.clone().filter(|c| !c.is_empty());
    taiji_core::hook::HookSet {
        on_download_start: blank_to_none(&cli.on_download_start),
        on_download_pause: blank_to_none(&cli.on_download_pause),
        on_download_stop: blank_to_none(&cli.on_download_stop),
        on_download_complete: blank_to_none(&cli.on_download_complete),
        on_download_error: blank_to_none(&cli.on_download_error),
        on_bt_download_complete: blank_to_none(&cli.on_bt_download_complete),
        bt_enable_hook_after_hash_check: cli.bt_enable_hook_after_hash_check,
    }
}

/// Session option-bundle assembly point (the idle and download+rpc
/// branches' construction literals were previously identical,
/// collapsed into one function): values from CLI and conf enter
/// through the same Cli fields and project via
/// [`IdleOptions::to_session_options`] — the two forms are
/// indistinguishable at the session assembly point. crypto/conn_type
/// are derived values parsed up front in run (errors surface at
/// the parse point; not re-validated here).
fn build_idle_options(
    cli: &Cli,
    crypto: taiji_bt::mse::CryptoPolicy,
    conn_type: taiji_bt::utp::PeerConnectionType,
) -> IdleOptions {
    IdleOptions {
        dir: cli.dir.clone(),
        db_path: cli.sqlite3_db_path.clone(),
        bt_detach_seed_only: cli.bt_detach_seed_only,
        listen_port: cli.listen_port,
        crypto,
        conn_type,
        bt_lsd: cli.bt_lsd,
        // --enable-dht explicit injection (semantics = the existing
        // session option surface; default true matches
        // GlobalOptions::default, made explicit so =false is accepted).
        enable_dht: cli.enable_dht,
        // --bt-enable-upnp/--bt-enable-nat-pmp inject into the session
        // (bootstrap powers the NAT singleton; getGlobalOption echo;
        // see the Cli field docs).
        bt_enable_upnp: cli.bt_enable_upnp,
        bt_enable_natpmp: cli.bt_enable_natpmp,
        // Global import sources into the session option table —
        // bootstrap import/restore + union persistence (global_tracker
        // table); the bt-tracker-file path is resolved by the session
        // inside bootstrap (spawn_blocking).
        bt_tracker: taiji_core::session::split_bt_tracker(&cli.bt_tracker),
        bt_tracker_file: cli.bt_tracker_file.clone(),
        // peer-id-prefix into the session (consumed by the single peer
        // ID generation point at torrent activation / the magnet
        // metadata phase; getGlobalOption echo; startup-time option).
        peer_id_prefix: peer_id_prefix_or_default(&cli.peer_id_prefix),
        // --seed-time as the session global default (minutes; the value
        // domain was validated in run — this is a direct map onto the
        // f64 minutes face; tasks whose add payload carries no seed-time
        // fall back to this value, getGlobalOption echo). 0 = no time
        // limit (zero change by default).
        seed_time_min: cli.seed_time.unwrap_or(0.0),
        // --seed-ratio as the session global default (the same face as
        // seed-time; tasks whose add payload carries no seed-ratio fall
        // back to this value, getGlobalOption echo). Unset = the standing
        // 1.0 default (= GlobalOptions::default, zero change by default).
        seed_ratio: cli.seed_ratio.unwrap_or(1.0),
        // --select-file raw value (the download+rpc form injects it via
        // the AddTorrent task option — parse/range-check/error face at
        // the session single point; idle has no task face and does not
        // consume it).
        select_file: cli.select_file.clone(),
        // --http-max-per-host into the session HostCap initialization
        // (unset = the default 64; an addUri task-level override,
        // last-set-wins, wins).
        http_max_per_host: cli.http_max_per_host,
        // --summary-interval into the session (periodic task summary;
        // 0 = disabled).
        summary_interval: cli.summary_interval,
        // -B injections (the bt-max-peers echo face / stop-timeout /
        // the three tracker knobs — defaults match
        // GlobalOptions::default, made explicit so non-defaults are
        // accepted).
        bt_max_peers: cli.bt_max_peers,
        bt_stop_timeout_secs: cli.bt_stop_timeout,
        bt_tracker_interval: cli.bt_tracker_interval,
        bt_tracker_timeout_secs: cli.bt_tracker_timeout,
        bt_tracker_connect_timeout_secs: cli.bt_tracker_connect_timeout,
        // The six hook commands + the post-hash-check gate (the
        // `--on-*` family + the gate), injected via the single-point
        // constructor (to_session_options projects
        // `GlobalOptions.hooks` — the existing consumption face where
        // the session actor triggers Start/Pause/Stop/Complete/Error
        // and the engine triggers BtComplete).
        hooks: hook_set_from_cli(cli),
        // The magnet option family (forwarded via the magnet injection
        // arm's add_options; idle has no task face and does not consume
        // them).
        bt_save_metadata: cli.bt_save_metadata,
        bt_metadata_only: cli.bt_metadata_only,
        bt_load_saved_metadata: cli.bt_load_saved_metadata,
        // Task-face options (download+rpc injects via AddTorrent; idle
        // has no task face and does not consume them).
        bt_sequential_download: cli.bt_sequential_download,
        enable_http_seeding: cli.enable_http_seeding,
        // The three domain C keys (the cookie session-level default
        // source / the exit text export / the periodic save interval —
        // to_session_options projects the same-named GlobalOptions
        // fields; defaults match GlobalOptions::default, zero behavior
        // change).
        load_cookies: cli.load_cookies.clone(),
        save_session: cli.save_session.clone(),
        save_session_interval_secs: cli.save_session_interval,
        // batch C: the max/dht/enable family (session global options —
        // the concurrency cap / the overall rate defaults / the PEX gate /
        // the DHT startup-time group; field semantics in the Cli flag
        // docs). The per-task `--max-download-limit`/`--max-upload-limit`
        // pair is a task option face (no session global slot here) — the
        // bare form consumes it via the engine limiter topology.
        max_concurrent_downloads: cli.max_concurrent_downloads,
        // The four-pool budget trio: the session
        // initial values (the changeGlobalOption hot reload takes over
        // at runtime; the defaults match GlobalOptions::default — the
        // seed two-state note rides the GlobalOptions field doc).
        max_concurrent_seeds: cli.max_concurrent_seeds,
        max_concurrent_checks: cli.max_concurrent_checks,
        media_synthesis_concurrency: cli.media_synthesis_concurrency,
        max_overall_download_limit: cli.max_overall_download_limit,
        max_overall_upload_limit: cli.max_overall_upload_limit,
        enable_peer_exchange: cli.enable_peer_exchange,
        enable_dht6: cli.enable_dht6,
        dht_entry_point: cli.dht_entry_point.clone(),
        dht_entry_point6: cli.dht_entry_point6.clone(),
        dht_message_timeout: cli.dht_message_timeout,
        // The --stop shutdown deadline (the Duration parsed in run;
        // the three-form shutdown select shares the arm — None here, the
        // run arms inject per form).
        stop_after: None,
    }
}

/// Session option bundle (shared by idle mode and download+RPC;
/// grouping the growing flag set sidesteps the clippy
/// too_many_arguments gate in place of `#[allow]`; fields map
/// directly from the frozen CLI names).
struct IdleOptions {
    dir: PathBuf,
    db_path: PathBuf,
    bt_detach_seed_only: bool,
    listen_port: u16,
    crypto: taiji_bt::mse::CryptoPolicy,
    conn_type: taiji_bt::utp::PeerConnectionType,
    bt_lsd: bool,
    /// `--enable-dht` (default true; injected as a session global
    /// option).
    enable_dht: bool,
    /// `--bt-tracker` parse result (initial source of the global
    /// import set).
    bt_tracker: Vec<String>,
    /// `--bt-tracker-file` (parsed and imported inside the session
    /// bootstrap).
    bt_tracker_file: Option<PathBuf>,
    /// `--peer-id-prefix` (session peer ID generation prefix; default
    /// `-TJ0001-`).
    peer_id_prefix: String,
    /// `--seed-time` (minutes, the session global default face; 0 = no
    /// time limit). `to_session_options` projects
    /// `GlobalOptions.seed_time_min` — tasks whose add payload carries
    /// no seed-time fall back to this value; getGlobalOption echo.
    seed_time_min: f64,
    /// `--seed-ratio` (the session global default face; unset = the
    /// standing 1.0). `to_session_options` projects
    /// `GlobalOptions.seed_ratio` — tasks whose add payload carries no
    /// seed-ratio fall back to this value; getGlobalOption echo.
    seed_ratio: f64,
    /// `--select-file` raw value (the download+rpc form injects via
    /// AddTorrent; idle has no task face and does not consume it).
    select_file: Option<String>,
    /// `--stop` shutdown deadline (parsed in run; None/ZERO = never
    /// fires).
    stop_after: Option<Duration>,
    /// `--bt-enable-upnp` (session NAT power surface; default false).
    bt_enable_upnp: bool,
    /// `--bt-enable-nat-pmp` (default false).
    bt_enable_natpmp: bool,
    /// `--http-max-per-host` (taiji extension; injected into the
    /// session HostCap initialization; None = the default 64).
    /// Startup-time option — applies on restart, changeGlobalOption
    /// does not accept it; an addUri task-level override
    /// (last-set-wins) wins.
    http_max_per_host: Option<u32>,
    /// `--summary-interval` (session periodic summary interval
    /// seconds; 0 = disabled).
    summary_interval: u32,
    /// `--bt-max-peers` (the session echo value — the engine knob
    /// override is injected in main; this field carries the
    /// getGlobalOption echo and the existing value surface).
    bt_max_peers: u64,
    /// `--bt-stop-timeout` (seconds, 0 = not armed — session global
    /// injection, consumed by the seed_policy_from task-policy
    /// projection).
    bt_stop_timeout_secs: u64,
    /// `--bt-tracker-interval` (seconds, 0 = no override — session
    /// global injection, consumed by the engine tracker actor
    /// announce client).
    bt_tracker_interval: u64,
    /// `--bt-tracker-timeout` (seconds — session global injection, as
    /// above).
    bt_tracker_timeout_secs: u64,
    /// `--bt-tracker-connect-timeout` (seconds — session global
    /// injection, as above).
    bt_tracker_connect_timeout_secs: u64,
    /// The six hook commands + the `--bt-enable-hook-after-hash-check`
    /// gate (the `--on-*` family, SPEC §7.4) — the session HookSet
    /// built by the [`hook_set_from_cli`] single point;
    /// `to_session_options` projects `GlobalOptions.hooks` (the
    /// existing consumption face where the session actor triggers
    /// Start/Pause/Stop/Complete/Error and the engine triggers
    /// BtComplete; the getGlobalOption echo face projects with the
    /// `global_option_echo` HookEvent::ALL).
    hooks: taiji_core::hook::HookSet,
    /// `--bt-save-metadata` (forwarded via the magnet injection arm's
    /// add_options — idle has no task face and does not consume it).
    bt_save_metadata: bool,
    /// `--bt-metadata-only` (same as above).
    bt_metadata_only: bool,
    /// `--bt-load-saved-metadata` (same as above).
    bt_load_saved_metadata: bool,
    /// `--bt-sequential-download` (download+rpc injects via the
    /// AddTorrent option — idle has no task face and does not consume
    /// it).
    bt_sequential_download: bool,
    /// `--enable-http-seeding` (BEP19; download+rpc injects via the
    /// AddTorrent option, only when explicitly false — idle has no
    /// task face and does not consume it).
    enable_http_seeding: bool,
    /// `--load-cookies` (domain C; injected as the session-level
    /// default source — HTTP tasks fall back to this when addUri
    /// carries no per-task value; loading fails closed at task
    /// acceptance).
    load_cookies: Option<PathBuf>,
    /// `--save-session` (domain C; the graceful-shutdown text export
    /// path — an existing session-face consumption point).
    save_session: Option<PathBuf>,
    /// `--save-session-interval` (domain C; seconds, 0 = disabled —
    /// injected as the session periodic save tick, consumed actor-side).
    save_session_interval_secs: u64,
    // ---- batch C: the max/dht/enable family (session global option
    // injection; the field semantics map straight from the Cli flag
    // docs).
    /// `--max-concurrent-downloads` (the session concurrency cap
    /// initial value; default 5).
    max_concurrent_downloads: u32,
    /// `--max-concurrent-seeds` (the seed-pool budget initial value;
    /// default 16 = the two-state note while the connection-budget card
    /// is unmerged).
    max_concurrent_seeds: u32,
    /// `--max-concurrent-checks` (the check-pool budget initial value;
    /// default 2).
    max_concurrent_checks: u32,
    /// `--media-synthesis-concurrency` (the synthesis-pool budget
    /// initial value; default 2).
    media_synthesis_concurrency: u32,
    /// `--max-overall-download-limit` (the SpeedLimits global bucket
    /// initial value; 0 = unlimited).
    max_overall_download_limit: u64,
    /// `--max-overall-upload-limit` (0 = unlimited).
    max_overall_upload_limit: u64,
    /// `--enable-peer-exchange` (the ut_pex gate; default true).
    enable_peer_exchange: bool,
    /// `--enable-dht6` (the value face; default false).
    enable_dht6: bool,
    /// `--dht-entry-point` (None = the SPEC §6.7 router fallback
    /// constants).
    dht_entry_point: Option<String>,
    dht_entry_point6: Option<String>,
    /// `--dht-message-timeout` (the DHT transaction timeout seconds;
    /// default 10).
    dht_message_timeout: u64,
}

impl IdleOptions {
    /// -> SessionActor session options (the single injection point
    /// shared by idle and download+rpc — download+rpc reuses idle's
    /// existing construction so "the engine path is shared with idle"
    /// holds literally).
    ///
    /// rpc-secret/rpc-user/rpc-passwd go into the Session option table
    /// (the getGlobalOption echo explicitly omits the secret — same
    /// rule as RpcMethodImpl.cc). --dir is injected on the same surface
    /// (idle previously ignored it and GlobalOptions was always ".").
    fn to_session_options(
        &self,
        cfg: &taiji_rpc::RpcConfig,
    ) -> taiji_core::session::SessionOptions {
        taiji_core::session::SessionOptions {
            global: taiji_core::session::GlobalOptions {
                motrix_startup_hold: std::env::var("MOTRIX_TAIJI_STARTUP_HOLD").as_deref()
                    == Ok("1"),
                dir: self.dir.clone(),
                rpc_secret: cfg.secret.clone(),
                rpc_user: cfg.rpc_user.clone(),
                rpc_passwd: cfg.rpc_passwd.clone(),
                bt_detach_seed_only: self.bt_detach_seed_only,
                // --listen-port + the crypto/connection-type options
                // into the session (consumed at engine spawn and the
                // magnet metadata phase; getGlobalOption echo).
                listen_port: self.listen_port,
                bt_require_crypto: self.crypto.require_crypto,
                bt_min_crypto_level: self.crypto.min_level,
                bt_peer_connection_type: self.conn_type,
                // bt-lsd into the session (the LSD service is lazily
                // spawned at engine/task activation + announce/withdraw
                // lifecycle + magnet metadata-phase discovery;
                // getGlobalOption echo).
                bt_lsd: self.bt_lsd,
                // --enable-dht explicit injection (default true
                // matches GlobalOptions::default, made explicit so
                // =false is accepted).
                enable_dht: self.enable_dht,
                // --bt-enable-upnp/--bt-enable-nat-pmp into the
                // session (bootstrap powers the NAT singleton;
                // getGlobalOption echo; provenance in the Cli field
                // docs).
                bt_enable_upnp: self.bt_enable_upnp,
                bt_enable_natpmp: self.bt_enable_natpmp,
                // Initial sources of the global import set (the
                // bt-tracker comma list + bt-tracker-file path; session
                // bootstrap import/restore + union persistence).
                bt_tracker: self.bt_tracker.clone(),
                bt_tracker_file: self.bt_tracker_file.clone(),
                // peer-id-prefix (session peer ID generation prefix;
                // getGlobalOption echo; startup-time option — applies
                // on restart).
                peer_id_prefix: self.peer_id_prefix.clone(),
                // --seed-time session global default (a direct map onto
                // the minutes face; 0 = no time limit).
                seed_time_min: self.seed_time_min,
                // --seed-ratio session global default (the same face;
                // the standing default 1.0 = GlobalOptions::default —
                // zero change by default).
                seed_ratio: self.seed_ratio,
                // --http-max-per-host: the session HostCap
                // initialization value — the global entry point for idle
                // (RPC service) mode (the only previous channel was the
                // addUri option, not configurable before running). Unset
                // = the default 64.
                http_max_per_host: self
                    .http_max_per_host
                    .unwrap_or(taiji_core::session::DEFAULT_MAX_PER_HOST),
                // --summary-interval (periodic task summary; 0 =
                // disabled; startup-time option).
                summary_interval: self.summary_interval,
                // -B: bt-max-peers (the session value/echo face — the
                // engine knob override is injected at startup in
                // main; two independent faces on one flag);
                // stop-timeout and the three tracker knobs (consumed at
                // engine spawn).
                // Defaults match GlobalOptions::default — zero behavior
                // change by default.
                bt_max_peers: usize::try_from(self.bt_max_peers).unwrap_or(usize::MAX),
                bt_stop_timeout_secs: self.bt_stop_timeout_secs,
                bt_tracker_interval: self.bt_tracker_interval,
                bt_tracker_timeout_secs: self.bt_tracker_timeout_secs,
                bt_tracker_connect_timeout_secs: self.bt_tracker_connect_timeout_secs,
                // The six hook commands + the post-hash-check gate (the
                // `--on-*` family injected whole — the existing
                // consumption face: the session actor triggers the five
                // events + the engine BtComplete; an empty set has the
                // same shape as HookSet::default, zero behavior
                // change).
                hooks: self.hooks.clone(),
                // The three domain C keys (the cookie session-level
                // default source / the exit text export path / the
                // periodic save interval seconds — session-side
                // consumption points: cookie loading at task
                // acceptance, the shutdown save_session text export,
                // the actor's periodic save tick; defaults match
                // GlobalOptions::default, zero behavior change).
                load_cookies: self.load_cookies.clone(),
                save_session: self.save_session.clone(),
                save_session_interval_secs: self.save_session_interval_secs,
                // batch C: the max/dht/enable family injection (the
                // consumption faces: the concurrency cap = the session
                // queue bookkeeping; the overall limits = the SpeedLimits
                // global bucket initial values; PEX = the engine
                // activation injection; the dht group = the engine
                // activation injection + echo; enable-dht6 = the value
                // face). The per-task `--max-download-limit`/
                // `--max-upload-limit` pair has no session global slot
                // (a task-option face only).
                max_concurrent_downloads: self.max_concurrent_downloads as usize,
                // The four-pool budget trio injection (the
                // consumption faces: the seed/check/synthesis pools'
                // pump_all promotion gates + the getGlobalOption echo).
                max_concurrent_seeds: self.max_concurrent_seeds as usize,
                max_concurrent_checks: self.max_concurrent_checks as usize,
                media_synthesis_concurrency: self.media_synthesis_concurrency as usize,
                max_overall_download_limit: self.max_overall_download_limit,
                max_overall_upload_limit: self.max_overall_upload_limit,
                enable_peer_exchange: self.enable_peer_exchange,
                enable_dht6: self.enable_dht6,
                dht_entry_point: self.dht_entry_point.clone(),
                dht_entry_point6: self.dht_entry_point6.clone(),
                dht_message_timeout: self.dht_message_timeout,
                ..Default::default()
            },
        }
    }
}

/// Download-mode option bundle (grouping sidesteps the clippy
/// too_many_arguments gate, as in IdleOptions, in place of
/// `#[allow]`; fields map directly from the frozen CLI names).
struct DownloadOptions {
    bt_lsd: bool,
    /// `--bt-sequential-download` (bare = a SetSchedulerPolicy push
    /// after spawn; download+rpc = AddTorrent option injection).
    bt_sequential_download: bool,
    /// `--enable-dht` (default true; download mode injects
    /// `DhtWireConfig::enabled`, the same option surface as idle).
    enable_dht: bool,
    /// `--enable-http-seeding` (BEP19, default true; false clears the
    /// webseed set after bare assembly).
    enable_http_seeding: bool,
    /// Initial global import set (`--bt-tracker` comma list +
    /// `--bt-tracker-file` parse results, merged in `run`).
    seed_trackers: Vec<String>,
    /// `--peer-id-prefix` (bare peer ID generation prefix; default
    /// `-TJ0001-`).
    peer_id_prefix: String,
    /// `--bt-enable-upnp` (bare NAT power surface; default false).
    bt_enable_upnp: bool,
    /// `--bt-enable-nat-pmp` (default false).
    bt_enable_natpmp: bool,
    /// `--check-integrity` (bare = a pre-spawn disk recheck into
    /// `EngineConfig.preset_progress`; default false, zero behavior
    /// change).
    check_integrity: bool,
    /// `--max-download-limit` (bytes/s, 0 = unlimited; both this and
    /// `max_upload_limit` 0 keeps the per-task pair at zero — the
    /// limiter mounts only when any of the four values is non-zero).
    max_download_limit: u64,
    /// `--max-upload-limit` (same semantics as `max_download_limit`).
    max_upload_limit: u64,
    /// `--bt-hash-check-seed` (default true, zero behavior change):
    /// combined with `--check-integrity` — false = exit after
    /// recheck/repair without seeding.
    bt_hash_check_seed: bool,
    /// `--bt-stop-timeout` (seconds, 0 = not armed — zero behavior
    /// change by default).
    bt_stop_timeout_secs: u64,
    /// `--bt-tracker-interval` (seconds, 0 = no override — zero
    /// behavior change by default).
    bt_tracker_interval: u64,
    /// `--bt-tracker-timeout` (seconds, default 60 = zero behavior
    /// change).
    bt_tracker_timeout_secs: u64,
    /// `--bt-tracker-connect-timeout` (seconds, default 60, same as
    /// above).
    bt_tracker_connect_timeout_secs: u64,
    /// The six hook commands + the post-hash-check gate (the `--on-*`
    /// family, SPEC §7.4) — built at the [`hook_set_from_cli`] single
    /// point; bare mode injects `EngineConfig.hook` (the engine-side
    /// trigger face = the BtComplete seeding-turn point; an empty set =
    /// no runner, a zero-overhead pass-through).
    hooks: taiji_core::hook::HookSet,
    /// `--dht-entry-point6` (domain C; the bare-run arm): injects
    /// `EngineConfig.dht.entry_points_v6` (consumed by the
    /// engine/dht.rs V6-family bootstrap). None = the default empty
    /// list (the SPEC §6.7 v6 router fallback constant — zero change to
    /// the existing form).
    dht_entry_point6: Option<String>,
    /// `--gid` (domain C; the bare-run arm): the pinned task GID value
    /// (consumed by the hook argv payload and the startup log). None =
    /// a random allocator value — zero change to the existing form.
    task_gid: Option<taiji_core::gid::Gid>,
    // ---- batch C: the max/dht/enable family, bare injection (the
    // field semantics map straight from the Cli flag docs; the assembly
    // point is the [`run_download`] cfg overwrite block).
    /// `--max-overall-download-limit` (the global bucket; 0 = unlimited).
    max_overall_download_limit: u64,
    /// `--max-overall-upload-limit` (0 = unlimited).
    max_overall_upload_limit: u64,
    /// `--enable-peer-exchange` (the ut_pex gate; default true).
    enable_peer_exchange: bool,
    /// `--dht-entry-point` (None = the SPEC §6.7 router fallback
    /// constants).
    dht_entry_point: Option<String>,
    /// `--dht-message-timeout` (the DHT transaction timeout seconds;
    /// default 10).
    dht_message_timeout: u64,
    // ---- Domain 5 behavior flags (the bare-form consumption face; the
    // assembly point is [`run_download`]).
    /// `--select-file` (the 0-based selection face, syntax-parsed in
    /// run; range validation once the metainfo is known, the push
    /// after the engine spawns).
    select_file: Option<Vec<u32>>,
    /// `--seed-time` (None = not given; ZERO = no time limit — the
    /// engine seed policy mounts TimeSeedCriteria, its timer starting at
    /// the download-completion moment).
    seed_time: Option<Duration>,
    /// `--seed-ratio` (None = not given — the standing 1.0 engine
    /// default, zero change; Some = the ShareRatioSeedCriteria threshold,
    /// `0.0` = the ratio criterion disabled via the `SeedCheck::build`
    /// `seed_ratio > 0.0` rule).
    seed_ratio: Option<f64>,
    /// `--stop` (None/ZERO = never fires; the wall-clock shutdown
    /// deadline from process start).
    stop_after: Option<Duration>,
    /// `--hash-check-only` (true = recheck the on-disk content and
    /// abort, no engine spawn).
    hash_check_only: bool,
}

/// Bare-mode rate-limit topology assembly: all four 0 -> None (zero
/// behavior change — `EngineConfig.limiter` stays None, per-stream
/// pass-through with no overhead); any non-0 ->
/// `SpeedLimits::new(overall_down, overall_up).torrent_set(per_down,
/// per_up)` (assembled like the session actor activation chain's
/// SpeedLimits::new point). The overall pair = `--max-overall-*` (the
/// global bucket), the per-task pair = `--max-download-limit`/
/// `--max-upload-limit` (the RPC keys share the names and semantics
/// with the existing session option surface). Pure function, for
/// truth-table unit tests.
fn build_session_limiter(
    overall_down: u64,
    overall_up: u64,
    per_down: u64,
    per_up: u64,
) -> Option<Arc<taiji_io::rate_limit::LimiterSet>> {
    (overall_down != 0 || overall_up != 0 || per_down != 0 || per_up != 0).then(|| {
        taiji_core::session::SpeedLimits::new(overall_down, overall_up)
            .torrent_set(per_down, per_up)
    })
}

/// Intake parse gate: `Metainfo::parse` plus a conditional stall
/// notice.
///
/// No tracker and DHT off -> **accept + WARN** (guidance: hot-enable
/// DHT via RPC / add trackers / restart; bare mode has no RPC face,
/// so restart is the main path — the text carries the full
/// guidance); no tracker and DHT on -> accept with pure DHT discovery
/// (no notice). The bare download entry and the session
/// addTorrent/URL-fetch upgrade share the same gate
/// (`Metainfo::check_intake`), keeping the two entries naturally
/// uniform.
fn parse_metainfo_intake(bytes: &[u8], enable_dht: bool) -> Result<Metainfo, MetainfoError> {
    let meta = Metainfo::parse(bytes)?;
    if let Some(w) = meta.check_intake(enable_dht) {
        warn!(target: "taiji::cli", "{w}");
    }
    Ok(meta)
}

/// Shutdown-tail instrumentation (shared by the bare and download+rpc
/// forms): a block-stage histogram summary (count/mean/p50/p90/p99,
/// with the duplicate-block drop count alongside), bytes supplied per
/// transport, and endgame economics (trigger duration / duplicate and
/// buffered blocks during the trigger window + two tail-convergence
/// readings). metrics = None (stats not injected) skips the whole
/// block; when Some, both families are always logged — field-for-field
/// isomorphic to the two forms' original branches. The holepunch
/// observation family is held only by the bare form and is not part
/// of this shared surface (the two forms' log faces must stay
/// byte-identical — the line text is an e2e/bench log assertion
/// anchor).
fn emit_tail_instrumentation(metrics: Option<&taiji_core::session::metrics::SessionMetrics>) {
    let Some(m) = metrics else { return };
    if let Some(summary) = m.block_stage_log_summary() {
        info!(target: "taiji::cli", summary,
            dup_blocks = m.duplicate_blocks_dropped(),
            late_blocks = m.late_blocks_verified(),
            "block stage histogram (stage count/mean/p50/p90/p99)");
    }
    let (tcp, utp) = m.transport_supply_bytes();
    let (eg_secs, eg_dup, eg_buf, lm_secs, l8_secs) = m.endgame_economics();
    // Write locality (appended fields, existing fields unchanged): a
    // piece write landing at index±1 counts as adjacent (write_adj)
    // vs isolated (write_iso).
    let (write_adj, write_iso) = m.write_locality();
    info!(target: "taiji::cli", down_tcp = tcp, down_utp = utp,
        endgame_secs = format!("{eg_secs:.1}"), endgame_dup = eg_dup,
        endgame_buffered = eg_buf,
        last_mile_secs = format!("{lm_secs:.1}"),
        last8_pieces_secs = format!("{l8_secs:.1}"),
        write_adj = write_adj, write_iso = write_iso,
        "supply bytes by transport + endgame economics");
}

/// Download mode: metainfo -> engine -> seeding residence -> shutdown
/// signal.
///
/// With `bt_lsd` = true this builds an LSD announce face for the bare
/// form (BEP14 multicast; private torrents disabled per BEP27, and
/// v2-only torrents have no v1 infohash to carry); the gates match the
/// session face. The receive face runs on the same socket — the
/// discovery-to-dial consumption lives at the engine seam (not
/// wired), so events with no subscriber are dropped (announce-only
/// form; see the lsd.rs docs). The service follows the engine
/// lifecycle: shutdown token cancel -> process teardown -> handle
/// drop -> loop exit.
async fn run_download(
    torrent_path: PathBuf,
    dir: PathBuf,
    listen_port: u16,
    crypto: taiji_bt::mse::CryptoPolicy,
    conn_type: taiji_bt::utp::PeerConnectionType,
    opts: DownloadOptions,
) -> i32 {
    let DownloadOptions {
        bt_lsd,
        bt_sequential_download,
        enable_dht,
        enable_http_seeding,
        seed_trackers,
        bt_enable_upnp,
        bt_enable_natpmp,
        peer_id_prefix,
        max_download_limit,
        max_upload_limit,
        max_overall_download_limit,
        max_overall_upload_limit,
        enable_peer_exchange,
        dht_entry_point,
        dht_message_timeout,
        select_file,
        seed_time,
        seed_ratio,
        stop_after,
        hash_check_only,
        check_integrity,
        bt_hash_check_seed,
        bt_stop_timeout_secs,
        bt_tracker_interval,
        bt_tracker_timeout_secs,
        bt_tracker_connect_timeout_secs,
        hooks,
        dht_entry_point6,
        task_gid,
    } = opts;
    let bytes = match std::fs::read(&torrent_path) {
        Ok(b) => b,
        Err(e) => {
            error!(target: "taiji::cli", path = %torrent_path.display(), %e, "cannot read torrent file");
            return 1;
        }
    };
    let meta = match parse_metainfo_intake(&bytes, enable_dht) {
        Ok(m) => m,
        Err(e) => {
            error!(target: "taiji::cli", path = %torrent_path.display(), %e, "invalid metainfo");
            return 1;
        }
    };
    // --hash-check-only: recheck the on-disk content and abort
    // (verify only, no download — no engine spawn; the same meaning as
    // the aria2 "abort download whether or not download is completed").
    // The verification source = the session recheck single point
    // (`recheck_on_disk_recovering_with_progress` with no recovery rows —
    // the same entry the session forceRecheck/bootstrap and the
    // `--check-integrity` face use); the blocking face rides
    // spawn_blocking. Verdict: verified == total with no suspended file
    // = exit 0, otherwise exit 1 (the suspended face = v2 files missing
    // the piece layer — neither passed nor failed, reported honestly).
    if hash_check_only {
        let outcome = tokio::task::spawn_blocking(move || {
            taiji_core::session::recheck_on_disk_recovering_with_progress(&meta, &dir, &[], None)
        })
        .await;
        match outcome {
            Ok(Ok(o)) => {
                let passed = o.verified == o.total && o.suspended_files.is_empty();
                info!(
                    target: "taiji::cli",
                    verified = o.verified,
                    total = o.total,
                    suspended_files = o.suspended_files.len(),
                    "hash check only: disk recheck {}",
                    if passed { "passed; aborting without download" } else { "incomplete/failed; aborting without download" }
                );
                return if passed { 0 } else { 1 };
            }
            Ok(Err(e)) => {
                error!(target: "taiji::cli", %e, "hash check only: recheck failed to build layout");
                return 1;
            }
            Err(e) => {
                error!(target: "taiji::cli", %e, "hash check only: recheck join failed");
                return 1;
            }
        }
    }
    // --select-file range validation (the metainfo is known; over
    // non-pad files — the range face of the session single point; the
    // syntax was parsed in run, this adds the range verdict —
    // out of range = explicit exit 2 refusal pre-spawn, the same
    // direction as tightening aria2's silent empty filter; the engine
    // push re-validates as the second gate).
    let selection = match &select_file {
        Some(sel) => {
            let file_count = meta.meta.files.iter().filter(|f| !f.padding).count() as u32;
            if sel.is_empty() || sel.iter().any(|&f| f >= file_count) {
                error!(target: "taiji::cli",
                    "--select-file out of range: {} file(s) selected, {} non-pad file(s) in torrent (indexes are 0-based after conversion)",
                    sel.len(), file_count);
                return 2;
            }
            Some(sel.clone())
        }
        None => None,
    };
    // Single generation point: the bare form uses the same generator
    // and the same CLI prefix option (this peer_id feeds both announce
    // and handshake via the single engine_config field).
    let peer_id = tracker::generate_peer_id(peer_id_prefix.as_bytes(), rand::random);
    info!(
        target: "taiji::cli",
        torrent = %torrent_path.display(),
        dir = %dir.display(),
        listen_port = listen_port,
        announce = %meta.announce,
        pieces = meta.v1_pieces.len(),
        total_bytes = meta.meta.total_len(),
        "download mode: engine loop"
    );
    // Domain C: the --gid pin log (when no hook is attached, this line
    // is the value's only observable consumption face — the bare engine
    // does not report the GID back, so the startup log is the factual
    // record).
    if let Some(g) = task_gid {
        info!(target: "taiji::cli", gid = %g, "task gid pinned via --gid");
    }

    let root = tokio_util::sync::CancellationToken::new();
    let mut cfg = match taiji_core::engine::engine_config(
        &meta,
        dir.clone(),
        listen_port,
        peer_id,
        taiji_core::engine::CompletionMode::Seed,
    ) {
        Ok(mut c) => {
            // CLI crypto option injection (the same option surface
            // as idle mode).
            c.crypto = crypto;
            // --enable-dht injection (download mode was previously
            // always disabled — the DhtWire default; with
            // tracker-only torrents there is no redundant discovery
            // source).
            c.dht.enabled = enable_dht;
            // Domain C: --dht-entry-point6 injects the V6-family
            // bootstrap entry (consumed by engine/dht.rs
            // DhtFamily::V6; None = the default empty list = the
            // SPEC §6.7 v6 router fallback constant, zero change to
            // the existing form).
            if let Some(ep) = dht_entry_point6 {
                info!(target: "taiji::cli", entry = %ep, "dht-entry-point6 armed (V6 bootstrap)");
                c.dht.entry_points_v6 = vec![ep];
            }
            // batch C injection (the option face -> EngineConfig, the
            // same option face as idle mode): the PEX gate (default true
            // = the engine_config default — the explicit overwrite makes
            // =false acceptable); the DHT v4 entry (Some = replaces the
            // SPEC §6.7 router fallback constants); the transaction
            // timeout (the default 10s matches the frozen bt::dht
            // default — zero change by default).
            c.peer_exchange = enable_peer_exchange;
            if let Some(ep) = &dht_entry_point {
                info!(target: "taiji::cli", entry = %ep, "dht-entry-point armed (V4 bootstrap)");
                c.dht.entry_points_v4 = vec![ep.clone()];
            }
            c.dht.engine.message_timeout = Duration::from_secs(dht_message_timeout);
            // --seed-time: the engine seed policy mounts TimeSeedCriteria
            // (the SeedCheck latch timer starts at the download-completion
            // moment, the `BtSetup.cc` same rule; ZERO = not mounted —
            // zero change by default). Seeding stops gracefully via the
            // engine halt -> SeedStopped when the time elapses.
            c.seed.seed_time = seed_time.unwrap_or_default();
            // --seed-ratio: the engine seed policy mounts
            // ShareRatioSeedCriteria (the `SeedCheck::build`
            // `seed_ratio > 0.0` rule — N > 0 = seeding stops gracefully
            // at the share ratio N; `0.0` = the criterion disabled, the
            // aria2 "If 0 is given, this feature is disabled" same rule).
            // Unset = the standing SeedPolicy default 1.0 (zero change —
            // the aria2 NumberOptionHandler default "1.0" is the same
            // value).
            if let Some(r) = seed_ratio {
                info!(target: "taiji::cli", seed_ratio = r, "seed-ratio armed (bare seed policy)");
                c.seed.seed_ratio = r;
            }
            // --enable-http-seeding=false: drop the metainfo
            // url-list projection (BEP19 webseed set; BT-only form —
            // true keeps the projection, the same overwrite point as
            // the session activation chain's build_engine_config).
            if !enable_http_seeding {
                c.webseeds.clear();
            }
            // Observation carrier: the bare form previously had
            // stats=None — instrumentation families like
            // `taiji_block_stage_seconds` stayed at zero (CLI
            // download mode has no /metrics surface). Inject
            // process-level session metrics; at shutdown
            // `block_stage_log_summary` logs the block-stage
            // histogram summary.
            c.stats = Some(std::sync::Arc::new(
                taiji_core::session::metrics::SessionMetrics::new(),
            ));
            // Rate-limit topology ( batch C: the `--max-overall-*`
            // global bucket + the `--max-*` per-task per_torrent bucket;
            // the aria2 UnitNumberOptionHandler "0 = unlimited" same rule
            // — the TokenBucket 0 tier short-circuits straight through).
            // Mounted only when any value is non-zero (all-zero = None —
            // the existing bare limiter default, zero change).
            c.limiter = build_session_limiter(
                max_overall_download_limit,
                max_overall_upload_limit,
                max_download_limit,
                max_upload_limit,
            );
            if c.limiter.is_some() {
                info!(target: "taiji::cli",
                        down = max_download_limit, up = max_upload_limit,
                        overall_down = max_overall_download_limit,
                        overall_up = max_overall_upload_limit,
                        "rate limits armed (bytes/s, 0 = unlimited)");
            }
            // --bt-hash-check-seed=false + --check-integrity
            // together = exit after recheck/repair without seeding
            // (the aria2 post-check seeding gate,
            // BtCheckIntegrityEntry semantics; default true =
            // existing behavior; without --check-integrity this gate
            // has no effect — aria2-consistent).
            if check_integrity && !bt_hash_check_seed {
                c.seed_after_complete = false;
            }
            // --bt-stop-timeout (seconds; 0 = BtStopTimeoutWatch
            // not armed — zero behavior change by default; N
            // consecutive seconds of zero throughput while seeding ->
            // wind down and exit, ported from BtSetup.cc).
            c.seed.stop_timeout = Duration::from_secs(bt_stop_timeout_secs);
            // Tracker announce client knobs (interval + both
            // timeouts; defaults match, zero behavior change. The
            // magnet metadata phase and the .torrent fetch bypass
            // this surface — see the EngineConfig.tracker_options
            // scope note).
            c.tracker_options = taiji_bt::tracker::TrackerOptions {
                bt_tracker_interval,
                bt_tracker_timeout: Duration::from_secs(bt_tracker_timeout_secs),
                bt_tracker_connect_timeout: Duration::from_secs(bt_tracker_connect_timeout_secs),
                ..taiji_bt::tracker::TrackerOptions::default()
            };
            c
        }
        Err(e) => {
            error!(target: "taiji::cli", %e, "cannot build engine config");
            return 1;
        }
    };
    // The six hook commands injected (the `--on-*` family, SPEC §7.4):
    // the bare form attaches `EngineConfig.hook` — the existing
    // engine-side trigger face = the BtComplete seeding-turn point (a
    // literal port of DefaultPieceStorage.cc, consumed by the
    // arms.rs all_done arm); the Start/Pause/Stop/Complete/Error
    // trigger points live in the session actor (RequestGroupMan.cc:
    // 265-281/580 — bare mode has no actor, so those commands travel
    // with the HookSet but do not fire, declared as-is; the full face
    // is the download+rpc form). The argv payload is a literal port
    // (util.cc): gidHex16 / numFiles in decimal / the first
    // file path (the same projection as the session torrent activation
    // chain — a non-pad real file).
    // An empty command set = no runner attached (None = a zero-overhead
    // pass-through, zero change to the existing form); the gid is
    // allocated independently for this task (the high-bit mask
    // form; bare mode has no session allocator — a local one-shot
    // GidAllocator allocation).
    if hooks.has_any_command() {
        // Domain C: --gid pins the task GID (consumed by the hook argv
        // payload; None = a random allocator value — the existing form.
        // Bare mode has no session allocator; the counterpart of the
        // reserve face = adopting the given value directly).
        let gid = task_gid.unwrap_or_else(|| taiji_core::gid::GidAllocator::new().allocate());
        let files = cfg.layout.files();
        let num_files = files.iter().filter(|f| !f.padding).count();
        let first_filename = files
            .iter()
            .find(|f| !f.padding)
            .map(|f| cfg.dest.join(&f.path).to_string_lossy().into_owned())
            .unwrap_or_default();
        info!(target: "taiji::cli", %gid, hooks = "on-*", "hook commands armed (engine trigger: bt-download-complete)");
        cfg.hook = Some(Arc::new(taiji_core::hook::HookRunner::new(
            Arc::new(hooks),
            gid,
            num_files,
            first_filename,
        )));
    }
    // Bare-mode NAT power (--bt-enable-upnp/--bt-enable-nat-pmp; the
    // same option surface and defaults as idle mode). Single-task
    // singleton supervisor: the engine clone goes into
    // EngineConfig.nat — once the listen port is set the engine
    // triggers Map (TCP+UDP), and the external-port watch feeds DHT
    // announce (existing assemble/tick consumers); the exit path
    // unmaps and stops the pump (same as the session shutdown_routine).
    // All off = None, zero overhead. Keep a read-only metrics handle
    // for the shutdown log summary.
    let perf05_metrics = cfg.stats.clone();
    let nat_opts = taiji_core::session::GlobalOptions {
        bt_enable_upnp,
        bt_enable_natpmp,
        ..Default::default()
    };
    let nat_sup = nat_opts
        .nat_enabled()
        .then(|| taiji_core::nat::spawn_supervisor(nat_opts.build_nat_config()));
    if let Some(sup) = &nat_sup {
        cfg.nat = Some(sup.engine());
    }
    // --check-integrity: after cfg is built and before spawn, recheck
    // the target directory on disk (the bare counterpart of aria2
    // CheckIntegrityEntry; re-enters the same `session::recheck` entry
    // as the session checking state — the face construction / expected
    // hashes share the download surface, so there is no second
    // accounting). The verified bitmap feeds cfg.preset_progress: with
    // no persist row on the engine side it is the bitmap resume point
    // (verified pieces skip re-download / full completion goes straight
    // to seeding). Red line = never touch resume_existing (the
    // allocate path is untouched, missing files are still created,
    // existing bytes are preserved). Failure = warn + download from
    // scratch (same tolerance as a session recheck failure; no exit).
    // Progress: a 1s-cadence poll of an AtomicU64 sink (piece count,
    // the same observation surface as recheck).
    if check_integrity {
        let check_total = cfg.faces.first().map_or(0, |f| f.piece_count() as u64);
        let sink = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let poll_sink = Arc::clone(&sink);
        let progress_task = tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                let verified = poll_sink.load(std::sync::atomic::Ordering::Relaxed);
                info!(target: "taiji::cli", verified, total = check_total,
                    "integrity check: {verified}/{check_total} pieces");
                if verified >= check_total {
                    break;
                }
            }
        });
        let scan_meta = meta.clone();
        let scan_dir = dir.clone();
        let scan_sink = Arc::clone(&sink);
        let outcome = tokio::task::spawn_blocking(move || {
            taiji_core::session::recheck_on_disk_recovering_with_progress(
                &scan_meta,
                &scan_dir,
                // Bare mode has no session db: no recovery layer to
                // merge (suspended missing-v2 files -> all-zero bitmap
                // rows = re-download, repaired by the swarm).
                &[],
                Some(&scan_sink),
            )
        })
        .await;
        // The scan result is authoritative: the progress task ends by
        // abort (no cleanup face; the final line is covered by the
        // complete log below, so fast scans emit no noise row).
        progress_task.abort();
        match outcome {
            Ok(Ok(out)) => {
                info!(target: "taiji::cli", verified = out.verified, total = out.total,
                    "integrity check complete");
                cfg.preset_progress = Some(preset_progress_from_outcome(&out));
            }
            Ok(Err(e)) => {
                warn!(target: "taiji::cli", %e,
                    "recheck failed; downloading from scratch");
            }
            Err(e) => {
                warn!(target: "taiji::cli", %e,
                    "recheck task join failed; downloading from scratch");
            }
        }
    }
    // Controlled spawn carries --bt-peer-connection-type (the same
    // surface as idle mode; this form does not consume the command
    // handle — it is reclaimed with the engine lifecycle). Tracker
    // table = the built-in announce union the global import set
    // (merged; an empty set is the identity, falling back to the
    // existing single tier-0 EngineConfig::announce behavior for empty
    // TrackerWireConfig tiers).
    let tiers = {
        let base: Vec<(usize, String)> = if meta.announce.is_empty() {
            Vec::new()
        } else {
            vec![(0, meta.announce.clone())]
        };
        taiji_core::session::merge_global_trackers(&base, &seed_trackers)
    };
    let (engine_handle, mut engine) = DownloadEngine::spawn_controlled(
        cfg,
        taiji_core::engine::TrackerWireConfig {
            tiers,
            ..Default::default()
        },
        &root,
        conn_type,
    );
    // --bt-sequential-download: the bare form pushes the sequential
    // policy via engine SetSchedulerPolicy (the session form injects
    // via the AddTorrent option; the authoritative surface is
    // taiji.setSchedulerPolicy). Consumed before announce connects (the
    // bounded command channel orders it before dispatch).
    if bt_sequential_download {
        if let Ok(seq) = "sequential".parse::<taiji_core::engine::SchedulerPolicy>() {
            if let Err(e) = engine_handle.set_scheduler_policy(seq).await {
                warn!(target: "taiji::cli", %e, "sequential policy push skipped");
            } else {
                info!(target: "taiji::cli", "sequential download policy applied");
            }
        }
    }
    // --select-file: the BEP 53 selection push (range already validated;
    // consumed after spawn and before announce connects — the same slot
    // as SetSchedulerPolicy. The session form applies it at the same
    // point via the AddTorrent option). A second engine-side refusal
    // (empty/out-of-range) = an explicit failure, never silent.
    if let Some(sel) = &selection {
        let files: std::sync::Arc<[u32]> = sel.as_slice().into();
        if let Err(e) = engine_handle.set_file_selection(files).await {
            error!(target: "taiji::cli", %e, "select-file push failed");
            root.cancel();
            let _ = tokio::time::timeout(SHUTDOWN_BUDGET, &mut engine).await;
            return 1;
        }
        info!(target: "taiji::cli", files = sel.len(), "select-file applied (BEP53 selection)");
    }
    // bt-lsd announce face (bare form; announce after engine spawn —
    // the port semantics = the --listen-port option, same as
    // idle/session).
    let _lsd_keep: Option<taiji_bt::lsd::LsdHandle> = if bt_lsd {
        let lsd_cfg = taiji_bt::lsd::LsdConfig {
            enabled: true,
            ..taiji_bt::lsd::LsdConfig::default()
        };
        match taiji_bt::lsd::spawn(&lsd_cfg).await {
            Ok(Some((h, addr, _join))) => {
                info!(target: "taiji::cli", bind = %addr,
                    "lsd service up (BEP14 multicast 239.192.152.143:6771)");
                let ih = if meta.private {
                    info!(target: "taiji::cli", "lsd announce skipped: private torrent (BEP27)");
                    None
                } else {
                    meta.meta.identity.v1
                };
                if let Some(ih) = ih
                    && let Err(e) = h.announce(ih, listen_port).await
                {
                    warn!(target: "taiji::cli", %e, "lsd announce failed");
                }
                Some(h)
            }
            Ok(None) => None,
            Err(e) => {
                warn!(target: "taiji::cli", %e,
                    "lsd service init failed; running WITHOUT lsd (aria2 BtSetup.cc, same)");
                None
            }
        }
    } else {
        None
    };
    let t0 = Instant::now();

    // After completion the engine stays resident seeding; the shutdown
    // signal is a normal exit path (SeedStopped). The exit code
    // converges into a variable: NAT teardown (unmap + pump stop) runs
    // uniformly before returning.
    // --stop: the third shutdown driver (the deadline future; None/ZERO
    // never fires) — the signal and the deadline share the
    // [`stop_bare_engine`] arm (the same cancel + in-budget wind-down
    // path).
    let exit_code = tokio::select! {
        _ = wait_shutdown_signal() => {
            stop_bare_engine(&mut engine, &root, &t0,
                "shutdown signal received: stopping engine/seeding").await
        }
        _ = stop_timer(stop_after) => {
            stop_bare_engine(&mut engine, &root, &t0,
                "--stop deadline reached: stopping engine/seeding").await
        }
        end = &mut engine => {
            match end {
                Ok(EngineEnd::Completed) => {
                    info!(target: "taiji::cli", "download complete");
                    0
                }
                Ok(EngineEnd::SeedStopped) => {
                    info!(target: "taiji::cli", "download complete; seeding stopped");
                    0
                }
                Ok(EngineEnd::Detached) => {
                    info!(target: "taiji::cli",
                        "download complete; seeding stopped (detached seed-only task)");
                    0
                }
                Ok(EngineEnd::Cancelled) => 0,
                Ok(EngineEnd::Failed(msg)) => {
                    error!(target: "taiji::cli", %msg, "engine failed");
                    1
                }
                Err(e) => {
                    error!(target: "taiji::cli", %e, "engine task panicked");
                    1
                }
            }
        }
    };
    // Observation carrier: CLI download mode has no /metrics surface —
    // on shutdown (SIGTERM) or completion exit, the block-stage
    // histogram summary and the transport-supply/endgame readings go
    // to the log via [`emit_tail_instrumentation`] (shared with
    // download+rpc).
    emit_tail_instrumentation(perf05_metrics.as_deref());
    // Holepunch observation family wrap-up: the seven holepunch
    // counters log their session totals (CLI download mode has no
    // /metrics surface — the shutdown summary is the only read-out for
    // live-swarm rounds, accumulated via the tick bridge).
    // Zero-activity rounds still log zeros (honest denominator
    // evidence for the practical punch rate). Bare-form only
    // (download+rpc lacks this family — the shared instrumentation
    // point does not include it).
    if let Some(m) = perf05_metrics.as_deref() {
        let s = m.snapshot();
        info!(target: "taiji::cli",
            hp_rendezvous_sent = s.holepunch_rendezvous_sent_total,
            hp_relayed_connects = s.holepunch_relayed_connects_total,
            hp_punch_dials = s.holepunch_punch_dials_total,
            hp_punch_established = s.holepunch_punch_established_total,
            hp_introducer_hits = s.holepunch_introducer_hits_total,
            hp_no_introducer = s.holepunch_no_introducer_total,
            hp_punch_failed_nat = s.holepunch_punch_failed_nat_total,
            "holepunch observation family (session totals)");
    }
    // NAT singleton teardown (best-effort unmap + event-pump stop; the
    // delete request is advisory — RFC 6886 §3.1, failure does not
    // change the exit code). None = not powered, zero overhead. The
    // teardown is bounded by the 250ms budget (same as the session
    // face) — a slow gateway / malicious IGD must not stall the bare
    // exit.
    if let Some(sup) = nat_sup {
        let _ = tokio::time::timeout(NAT_SHUTDOWN_BUDGET, sup.shutdown()).await;
    }
    exit_code
}

/// The bare-run shutdown acceptance path (the shared arm of the signal
/// and the `--stop` deadline): cancel + wait for the engine wind-down
/// within the budget (peer teardown is fast, but the 1s budget still
/// applies). Returns the exit code. The log line text is byte-identical
/// to the original signal arm (the elapsed anchor unchanged) — only the
/// acceptance-source text follows `msg`.
async fn stop_bare_engine(
    engine: &mut tokio::task::JoinHandle<EngineEnd>,
    root: &CancellationToken,
    t0: &Instant,
    msg: &str,
) -> i32 {
    info!(target: "taiji::cli", "{msg}");
    root.cancel();
    match tokio::time::timeout(SHUTDOWN_BUDGET, &mut *engine).await {
        Ok(Ok(EngineEnd::SeedStopped)) => {
            info!(target: "taiji::cli", elapsed = ?t0.elapsed(), "seeding stopped cleanly");
            0
        }
        Ok(Ok(end)) => {
            info!(target: "taiji::cli", ?end, elapsed = ?t0.elapsed(), "engine ended");
            0
        }
        Ok(Err(e)) => {
            error!(target: "taiji::cli", %e, "engine task panicked on shutdown");
            1
        }
        Err(_) => {
            error!(target: "taiji::cli", "engine did not stop within shutdown budget");
            1
        }
    }
}

/// Idle mode: actor topology + RPC service online; graceful shutdown
/// is driven by either a signal or RPC shutdown, with a total 1s
/// budget (actor drain and server exit awaited concurrently).
///
/// Persistence wiring: PersistWriter (the sole writer) is opened
/// before the SessionActor and injected — torrent rows,
/// bitmap/counters, tracker rows, and dht_state all go through this
/// handle, giving crash recovery its primary store. (Earlier idle
/// wiring never attached a database, so RPC-created tasks wrote
/// nothing to disk.)
async fn run_idle(cfg: taiji_rpc::RpcConfig, opts: IdleOptions) -> i32 {
    // Session option injection point
    // ([`IdleOptions::to_session_options`]; field-level notes live on
    // that method; download+rpc shares the same construction).
    let session_options = opts.to_session_options(&cfg);
    let IdleOptions {
        db_path,
        stop_after,
        ..
    } = opts;
    // Open PersistWriter (shared by both download forms; see
    // [`open_persist_writer`]).
    let (persist, persist_join) = open_persist_writer(db_path).await;
    let (session, actor_join) =
        taiji_core::session::SessionActor::spawn_with_persist(session_options, persist.clone());
    let session = Arc::new(session);
    let shutdown = CancellationToken::new();
    let secret_set = cfg.secret.is_some();
    let server = match taiji_rpc::serve(cfg, session.clone(), shutdown.clone()).await {
        Ok(h) => h,
        Err(e) => {
            error!(target: "taiji::cli", %e, "cannot bind rpc listener");
            return 1;
        }
    };
    info!(
        target: "taiji::cli",
        addr = %server.local_addr,
        secret_set,
        "taiji up: SessionActor -> TorrentTask -> PeerTask + JSON-RPC (POST/GET /jsonrpc)"
    );

    tokio::select! {
           _ = wait_shutdown_signal() => {
               info!(target: "taiji::cli", "shutdown signal received: propagating through SessionActor");
    // Both channels: the signal path previously drove only the
    // SessionActor, leaving the RPC server's shutdown token
    // dangling so with_graceful_shutdown never fired and
    // server.join hit the full 1s timeout. Cancel runs
    // concurrently with the actor drain, mirroring the RPC
    // shutdown path (dispatch.rs cancels the same token on
    // acceptance).
               shutdown.cancel();
               session.shutdown().await;
           }
    // The --stop deadline arm (None/ZERO = never fires): the same
    // path as an RPC shutdown (token cancel + actor drain) — a
    // graceful stop after the process has run for N minutes.
           _ = stop_timer(stop_after) => {
               info!(target: "taiji::cli", "--stop deadline reached: propagating through SessionActor");
               shutdown.cancel();
               session.shutdown().await;
           }
    // RPC shutdown/forceShutdown cancels the same token on
    // acceptance (dispatch.rs): the SessionActor is already winding
    // down, so just wait for the actor drain.
           _ = shutdown.cancelled() => {
               info!(target: "taiji::cli", "rpc shutdown accepted: SessionActor already draining");
           }
       }

    // Budget accounting: t0 starts at shutdown acceptance; the
    // actor/server join budgets = the remaining share (previously each
    // held the full 1s, so stacked awaits could exceed the total). The
    // timeout itself enforces the budget — success only requires both
    // joins to finish within it, no extra elapsed check
    // (sub-millisecond scheduling jitter would cause false negatives).
    // The teardown logic lives in [`shutdown_session_and_server`]
    // (shared with download+rpc; zero semantic change).
    shutdown_session_and_server(session, actor_join, server).await;

    // Persistence wrap-up (both download forms share
    // [`drain_persist_writer`]: release the last handle -> drain the
    // queue -> wait for the thread).
    drain_persist_writer(persist, persist_join).await;
    0
}

/// Session + RPC server shutdown teardown (shared by idle and
/// download+rpc; zero semantic change): t0 starts at shutdown
/// acceptance; the actor/server join budgets = the remaining share of
/// SHUTDOWN_BUDGET; both joins finishing within the budget = graceful
/// shutdown, a timeout is only logged (budget enforcement — success
/// is not faked; the exit code is the caller's policy). drop(session)
/// closes the command channel: recv-None is the actor's second exit
/// path (drop semantics).
async fn shutdown_session_and_server(
    session: Arc<taiji_core::session::SessionHandle>,
    actor_join: tokio::task::JoinHandle<()>,
    server: taiji_rpc::ServerHandle,
) {
    let t0 = Instant::now();
    drop(session);
    let remaining = SHUTDOWN_BUDGET.saturating_sub(t0.elapsed());
    let (actor_done, server_done) = tokio::join!(
        tokio::time::timeout(remaining, actor_join),
        tokio::time::timeout(remaining, server.join()),
    );
    let elapsed = t0.elapsed();
    if actor_done.is_ok() && server_done.is_ok() {
        info!(
            target: "taiji::cli",
            elapsed = ?elapsed,
            "graceful shutdown complete within 1s budget"
        );
    } else {
        error!(
            target: "taiji::cli",
            elapsed = ?elapsed,
            actor_done = actor_done.is_ok(),
            server_done = server_done.is_ok(),
            "graceful shutdown exceeded 1s budget"
        );
    }
}

/// Open PersistWriter (the shared assembly point for idle and
/// download+rpc; with the metrics callback wired to the writer thread
/// — the process registry's persistence family). Open failure = warn
/// and run without persistence (the actor bootstrap treats read
/// failures the same way, "treated as fresh session" — no
/// masquerading). The caller holds the returned handle until shutdown
/// teardown: after a clone is injected into the actor, the caller's
/// copy is the last drop (the anchor of the writer close ordering;
/// see [`drain_persist_writer`]).
async fn open_persist_writer(
    db_path: PathBuf,
) -> (
    Option<taiji_core::session::persist::PersistHandle>,
    Option<tokio::task::JoinHandle<()>>,
) {
    match taiji_core::session::persist::import::open_session_writer_with_metrics(db_path).await {
        Ok((h, j)) => (Some(h), Some(j)),
        Err(e) => {
            error!(target: "taiji::cli", %e, "cannot open session db; running WITHOUT persistence");
            std::process::exit(1);
        }
    }
}

/// PersistWriter wrap-up (paired with [`open_persist_writer`]; shared
/// by both download forms): after actor/engine are fully stopped the
/// caller releases the last handle (drop closes the writer; with no
/// producers left the queue drains and exits) -> only the thread join
/// remains. A 2s grace wait beyond the budget; a timeout only warns —
/// row writes are transactional and consistency is unaffected (the
/// final flush already happened within the actor budget).
async fn drain_persist_writer(
    persist: Option<taiji_core::session::persist::PersistHandle>,
    persist_join: Option<tokio::task::JoinHandle<()>>,
) {
    drop(persist);
    if let Some(j) = persist_join
        && tokio::time::timeout(Duration::from_secs(2), j)
            .await
            .is_err()
    {
        warn!(target: "taiji::cli", "persist writer drain exceeded 2s (exiting anyway)");
    }
}

/// Download + RPC co-residence mode (entered instead of the bare
/// branch when `--enable-rpc` is set).
///
/// Three-state assembly mirroring upstream (`DownloadEngineFactory.cc`:
/// `--enable-rpc` coexisting with a CLI torrent — the RPC listen
/// assembly does not depend on a URI being present, the download loop
/// runs as usual). The engine path is shared with idle: the existing
/// SessionActor (persistence injected) -> TorrentTask -> PeerTask
/// pipeline, so persistence / fast resume / crash recovery come for
/// free; the torrent is injected directly via
/// [`taiji_core::session::SessionCommand::AddTorrent`] (no RPC
/// self-call — bypasses the write gate and credential requirement,
/// mirroring the upstream engine-phase direct RequestGroup wiring).
/// Order: intake gate first (same gate and error surface as bare) ->
/// start the RPC server (bind failure fails fast, no half-open
/// session) -> inject -> reside. Task lifecycle = session seed policy
/// seeding residence; the process stays up until a signal / RPC
/// shutdown (aria2 RPC-mode downloads do not exit on completion
/// either). The bare path with `--enable-rpc=false`
/// ([`run_download`]) is unchanged — this function is only entered
/// when explicitly enabled.
///
/// Bare magnet one-shot: session pipeline AddUri -> poll for a
/// terminal state -> map the exit code from the status
/// (Complete/Removed -> 0; Error -> 1). Ctrl-C graceful finish = 0.
/// The session option `one_shot: true` (an error terminal state
/// clears the cookie); BT tasks have no cookie face, but the one-shot
/// semantics follow the flag uniformly.
async fn run_one_shot_magnet(
    uri: String,
    cli: &Cli,
    crypto: taiji_bt::mse::CryptoPolicy,
    conn_type: taiji_bt::utp::PeerConnectionType,
    seed_trackers: Vec<String>,
) -> i32 {
    // Single-session guard + session db (same as the http subcommand:
    // lock before db).
    let _db_lock = match http::acquire_db_lock(&cli.sqlite3_db_path).await {
        Ok(l) => l,
        Err(code) => return code,
    };
    let (persist, persist_join) =
        match taiji_core::session::persist::import::open_session_writer_with_metrics(
            cli.sqlite3_db_path.clone(),
        )
        .await
        {
            Ok((h, j)) => (Some(h), Some(j)),
            Err(e) => {
                warn!(target: "taiji::cli", %e, "cannot open session db; running WITHOUT persistence");
                (None, None)
            }
        };
    let global = taiji_core::session::GlobalOptions {
        dir: cli.dir.clone(),
        one_shot: true,
        enable_dht: cli.enable_dht,
        listen_port: cli.listen_port,
        bt_require_crypto: crypto.require_crypto,
        bt_min_crypto_level: crypto.min_level,
        bt_peer_connection_type: conn_type,
        bt_tracker: seed_trackers,
        // Domain C: the exit text export + the cookie session-level
        // default source (the magnet one-shot goes through the session
        // pipeline — the same gate as the shutdown save_session; the
        // cookie source has no consumption face for magnet tasks,
        // recorded for parity with idle).
        save_session: cli.save_session.clone(),
        load_cookies: cli.load_cookies.clone(),
        // The six hook commands + the gate (the `--on-*` family,
        // SPEC §7.4): the magnet one-shot goes through the session
        // pipeline — the session actor triggers the five events + the
        // engine BtComplete full consumption face (built at the
        // hook_set_from_cli single point, same source as
        // idle/download+rpc).
        hooks: hook_set_from_cli(cli),
        // Four-key forwarding (stop-timeout also goes per-task via the
        // add_options key — the global value is the fallback; the
        // tracker knobs are consumed by the engine spawn's tracker actor
        // announce client).
        bt_tracker_interval: cli.bt_tracker_interval,
        bt_tracker_timeout_secs: cli.bt_tracker_timeout,
        bt_tracker_connect_timeout_secs: cli.bt_tracker_connect_timeout,
        bt_stop_timeout_secs: cli.bt_stop_timeout,
        ..Default::default()
    };
    let (session, actor_join) = taiji_core::session::SessionActor::spawn_with_persist(
        taiji_core::session::SessionOptions { global },
        persist.clone(),
    );
    // Rate-limit option forwarding (0 = key not written = unlimited).
    let mut add_options = std::collections::BTreeMap::new();
    if cli.max_download_limit > 0 {
        add_options.insert(
            "max-download-limit".to_string(),
            cli.max_download_limit.to_string(),
        );
    }
    if cli.max_upload_limit > 0 {
        add_options.insert(
            "max-upload-limit".to_string(),
            cli.max_upload_limit.to_string(),
        );
    }
    // Magnet-form option forwarding (aria2 "only when Magnet URI is
    // used" rule; stop-timeout 0 = key not written).
    if cli.bt_save_metadata {
        add_options.insert("bt-save-metadata".to_string(), "true".to_string());
    }
    if cli.bt_metadata_only {
        add_options.insert("bt-metadata-only".to_string(), "true".to_string());
    }
    if cli.bt_load_saved_metadata {
        add_options.insert("bt-load-saved-metadata".to_string(), "true".to_string());
    }
    if cli.bt_stop_timeout > 0 {
        add_options.insert(
            "bt-stop-timeout".to_string(),
            cli.bt_stop_timeout.to_string(),
        );
    }
    let gid = match session
        .call(taiji_core::session::SessionCommand::AddUri {
            uris: vec![uri],
            options: add_options,
            position: None,
        })
        .await
    {
        Ok(taiji_core::session::CommandReply::Gid(g)) => g,
        other => {
            error!(target: "taiji::cli", reply = ?other, "magnet intake failed");
            session.shutdown().await;
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), actor_join).await;
            drain_persist_writer(persist, persist_join).await;
            return 1;
        }
    };
    info!(target = "taiji::cli", gid = %gid, "magnet one-shot task accepted");
    // Wait for a terminal state (300ms TellStatus polling; Ctrl-C
    // shuts down gracefully concurrently).
    let mut code = 0;
    tokio::select! {
        changed = wait_magnet_terminal(&session, gid) => { code = changed; }
        _ = wait_shutdown_signal() => {
            info!(target = "taiji::cli", "shutdown signal received");
        }
    }
    session.shutdown().await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), actor_join).await;
    drain_persist_writer(persist, persist_join).await;
    code
}

/// Magnet terminal-state polling: Complete/Removed -> 0; Error -> 1
/// (with an error log).
async fn wait_magnet_terminal(
    session: &taiji_core::session::SessionHandle,
    gid: taiji_core::gid::Gid,
) -> i32 {
    loop {
        if let Ok(taiji_core::session::CommandReply::TorrentStatus(v)) = session
            .call(taiji_core::session::SessionCommand::TellStatus {
                gid: gid.to_string(),
                keys: Vec::new(),
            })
            .await
        {
            match v.status {
                taiji_core::session::StatusKind::Complete
                | taiji_core::session::StatusKind::Removed => return 0,
                taiji_core::session::StatusKind::Error => {
                    error!(
                        target = "taiji::cli",
                        gid = %gid,
                        code = ?v.error_code,
                        msg = %v.error_message.clone().unwrap_or_default(),
                        "magnet one-shot task failed"
                    );
                    return 1;
                }
                _ => {}
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }
}

// ---- domain A: the --input-file batch download (the aria2 `-i`
// counterpart) ----
//
// Line-by-line processing mirrors aria2 `UriListParser::parseNext`
// (UriListParser.cc; consumption points download_helper.cc
// createRequestGroupForUriList): `#` comment lines are skipped, URI
// lines are tab-split (first token = the target, the rest = `key=value`
// per-task options). taiji-side divergence declared: aria2's "option
// lines follow the URI line" multi-line syntax is not in this form
// (only the in-line tab form is supported).

/// The per-file byte cap of an input-file list: 1 MiB (the same shape
/// as bt-tracker-file — a pre-read precheck + a post-read recheck,
/// double refusal; over the limit errors explicitly instead of
/// truncating). **Memory-face anchor**: this cap pins the list text to
/// <= 1MiB; the line-parse output is <= the input byte count and the
/// gid table is ~24B per line — an extreme list (e.g. 100k lines) can
/// only fit under the cap with ~10B lines, while a realistic-URI-length
/// (>= 30B) 100k-line list starts at ~3MB and is refused over the cap
/// (exit 2); the session's in-flight task-queue memory face is pinned
/// indirectly by the same cap (the line-count bound = the number of
/// lines under the cap).
const INPUT_FILE_MAX_BYTES: usize = 1024 * 1024;

/// A parsed input-file list line (the line-level output of the pure
/// function [`parse_input_file_lines`]; malformed lines keep their line
/// number and reason — a per-line failure does not abort the batch).
#[derive(Debug, Clone, PartialEq)]
enum InputFileLine {
    /// A valid task line: the target (a URI or a .torrent path) + the
    /// in-line tab option table.
    Task {
        line_no: usize,
        target: String,
        options: std::collections::BTreeMap<String, String>,
    },
    /// A malformed line (a tab option token missing `=` or with an empty
    /// key) — no task is created, the failure bit is recorded.
    Malformed { line_no: usize, reason: String },
}

/// input-file list text parsing (a pure function; mirrors aria2
/// UriListParser.cc line semantics + taiji-side whitespace
/// hardening): strip a leading BOM (a common browser-download artifact;
/// the same rule as the conf/trackerslist parse faces) -> trim each
/// line -> skip blank lines and `#` comment lines (line-leading
/// comments — a URI fragment `#x` is unaffected, the trackerslist rule)
/// -> tab split: the first token trimmed = the target, the remaining
/// tokens are each `key=value` (split on the first `=`, an inner `=`
/// stays verbatim — the checksum=`sha-256=<hex>` case); a token missing
/// `=` or with an empty key = the line is malformed (the reason is kept
/// explicitly, the token is not silently dropped). Line numbers are
/// 1-based (the fail-fast/warning localization face).
fn parse_input_file_lines(text: &str) -> Vec<InputFileLine> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut out = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut tokens = line.split('\t');
        let target = tokens.next().unwrap_or("").trim().to_string();
        let mut options = std::collections::BTreeMap::new();
        let mut reason: Option<String> = None;
        for token in tokens {
            let token = token.trim();
            match token.split_once('=') {
                Some((k, v)) if !k.trim().is_empty() => {
                    options.insert(k.trim().to_string(), v.trim().to_string());
                }
                _ => {
                    reason = Some(format!(
                        "malformed per-task option token {token:?} (expected key=value)"
                    ));
                    break;
                }
            }
        }
        match reason {
            Some(reason) => out.push(InputFileLine::Malformed { line_no, reason }),
            None => out.push(InputFileLine::Task {
                line_no,
                target,
                options,
            }),
        }
    }
    out
}

/// input-file disk read (blocking disk IO — the caller must run it
/// inside spawn_blocking/an async wrapper): the 1 MiB cap **pre-read
/// precheck** (the metadata len, the same shape as the metalink
/// document read) + a post-read recheck (a TOCTOU-window backstop) —
/// over the limit is refused explicitly, never truncated.
#[derive(Debug)]
enum InputFileReadError {
    /// The open/stat/read IO face (including the normalized form of a
    /// blocking-task join failure).
    Io(std::io::Error),
    /// Cap hit (got = the byte count measured by the precheck/recheck).
    Oversize { got: u64, limit: u64 },
}

async fn read_input_file_bounded(path: PathBuf) -> Result<Vec<u8>, InputFileReadError> {
    tokio::task::spawn_blocking(move || {
        let limit = INPUT_FILE_MAX_BYTES as u64;
        let len = std::fs::metadata(taiji_io::winpath::to_fs_path(&path))
            .map_err(InputFileReadError::Io)?
            .len();
        if len > limit {
            return Err(InputFileReadError::Oversize { got: len, limit });
        }
        let bytes =
            std::fs::read(taiji_io::winpath::to_fs_path(&path)).map_err(InputFileReadError::Io)?;
        if bytes.len() as u64 > limit {
            return Err(InputFileReadError::Oversize {
                got: bytes.len() as u64,
                limit,
            });
        }
        Ok(bytes)
    })
    .await
    .map_err(|e| InputFileReadError::Io(std::io::Error::other(e.to_string())))?
}

/// The batch face's shared task options (frozen CLI names -> the
/// addUri/addTorrent task-face keys; a pure function driven directly by
/// decision-table unit tests): the three rate-limit/watchdog knob
/// families are injected only when explicitly non-zero (0 = the default
/// writes no key — the same rule as the magnet one-shot form, zero
/// behavior change by default). An in-line tab option sharing a name
/// with this table overrides the CLI value (the [`run_input_file`]
/// merge order).
fn cli_shared_task_options(cli: &Cli) -> std::collections::BTreeMap<String, String> {
    let mut o = std::collections::BTreeMap::new();
    if cli.max_download_limit > 0 {
        o.insert(
            "max-download-limit".to_string(),
            cli.max_download_limit.to_string(),
        );
    }
    if cli.max_upload_limit > 0 {
        o.insert(
            "max-upload-limit".to_string(),
            cli.max_upload_limit.to_string(),
        );
    }
    if cli.bt_stop_timeout > 0 {
        o.insert(
            "bt-stop-timeout".to_string(),
            cli.bt_stop_timeout.to_string(),
        );
    }
    o
}

/// Task-option deltas driven by the line-target classification (a pure
/// function; slotted by kind — the aria2 "only when Magnet URI is used"
/// rule): magnet lines = the -B three families
/// (bt-save-metadata/bt-metadata-only/bt-load-saved-metadata, the key
/// is written only when set); .torrent lines = the sequential
/// download (key written only when set) + the BEP19 webseed shutdown
/// (key written only on explicit false); WebUri lines have no kind
/// delta (the HTTP task face, the key domain belongs to the session
/// parse_task_options). These keys only enter their own family's tasks —
/// the session side "unacceptable options ignored" for out-of-domain
/// keys (aria2 rule), but the CLI does not pre-project out-of-domain
/// keys, keeping the payload consistent with the task family.
fn kind_extra_task_options(
    cli: &Cli,
    kind: &PositionalInput,
) -> std::collections::BTreeMap<String, String> {
    let mut o = std::collections::BTreeMap::new();
    match kind {
        PositionalInput::MagnetUri(_) => {
            if cli.bt_save_metadata {
                o.insert("bt-save-metadata".to_string(), "true".to_string());
            }
            if cli.bt_metadata_only {
                o.insert("bt-metadata-only".to_string(), "true".to_string());
            }
            if cli.bt_load_saved_metadata {
                o.insert("bt-load-saved-metadata".to_string(), "true".to_string());
            }
        }
        PositionalInput::TorrentFile(_) => {
            if cli.bt_sequential_download {
                o.insert("bt-sequential-download".to_string(), "true".to_string());
            }
            if !cli.enable_http_seeding {
                o.insert("enable-http-seeding".to_string(), "false".to_string());
            }
        }
        PositionalInput::WebUri(_) => {}
    }
    o
}

/// The domain A summarized exit code (driven directly by decision-table
/// unit tests): any line failed = 1; all passed = 0 (the ask contract
/// "any failure = exit 1, all passed = 0"; a signal interrupt does not
/// go through this function — the polling select arm breaks with 1
/// directly, the same rule as the http multi-task metalink form).
fn input_file_exit_code(any_failed: bool) -> i32 {
    if any_failed { 1 } else { 0 }
}

/// The domain A batch form (`--input-file <FILE>`; the aria2 `-i`
/// counterpart): read the list, parse and classify line by line, create
/// tasks one by one in the same session (the magnet one-shot's same
/// base: the mutex + persistence + SessionActor, `one_shot: true`),
/// poll all tasks to a terminal state, summarize the exit code.
///
/// - **Task creation face**: line targets are classified via
///   [`classify_positional`] — magnet/http(s)/ftp(s) = AddUri (scheme
///   dispatch belongs to the session: a magnet task / an HTTP task / a
///   .torrent-URL metadata download); a `.torrent` path = spawn_blocking
///   read -> AddTorrent. Task options = the CLI shared knobs
///   ([`cli_shared_task_options`]) + the kind delta
///   ([`kind_extra_task_options`]) + the in-line tab options (written
///   later, per-line override semantics); the key-domain parse point =
///   the session `parse_task_options` (unknown keys ignored, aria2
///   rule). A refused/malformed/read-failed line = the failure bit is
///   recorded and the remaining lines continue (a per-line failure does
///   not abort the batch).
/// - **Concurrency face**: multiple tasks enter the same session wait
///   queue; actual concurrency is clamped by the session-global
///   `--max-concurrent-downloads` (default 5) — the existing session
///   face, no new CLI knob.
/// - **Exit code**: [`input_file_exit_code`] (any failure = 1, all
///   passed = 0; a signal interrupt = 1 — the same rule as the http
///   multi-task metalink form); a file-face startup hard error
///   (missing/unreadable/over-cap/non-UTF-8/zero valid lines) = 2.
/// - **RPC face**: the batch form does not assemble an RPC listener (a
///   one-shot session pipeline — an explicit `--enable-rpc` is
///   disclosed with a warning, never silent; the RPC group options
///   already hard-error at the main gate without `--enable-rpc` —
///   [`rpc_group_conflict`]).
async fn run_input_file(
    path: PathBuf,
    cli: &Cli,
    crypto: taiji_bt::mse::CryptoPolicy,
    conn_type: taiji_bt::utp::PeerConnectionType,
    seed_trackers: Vec<String>,
) -> i32 {
    if cli.enable_rpc {
        warn!(target: "taiji::cli",
            "--enable-rpc is not yet effective in the --input-file batch form \
             (the session pipeline runs a one-shot download, no RPC listener); \
             continuing the batch download");
    }
    // Domain C: the --gid/--dry-run bare-run-only consumption faces are
    // absent in the batch form — disclosed explicitly.
    warn_bare_run_only_flags(cli, "input-file batch");
    // List disk read (the blocking face wrapped async; the 1 MiB cap
    // pre-read precheck + post-read recheck).
    let bytes = match read_input_file_bounded(path.clone()).await {
        Ok(b) => b,
        Err(InputFileReadError::Oversize { got, limit }) => {
            error!(target: "taiji::cli", path = %path.display(), got, limit,
                "input file exceeds the size limit");
            return 2;
        }
        Err(InputFileReadError::Io(e)) => {
            error!(target: "taiji::cli", path = %path.display(), %e,
                "cannot read input file");
            return 2;
        }
    };
    let text = match std::str::from_utf8(&bytes) {
        Ok(t) => t,
        Err(_) => {
            error!(target: "taiji::cli", path = %path.display(),
                "input file is not valid UTF-8");
            return 2;
        }
    };
    let lines = parse_input_file_lines(text);
    // Malformed lines record the failure bit first (a per-line warn —
    // line-number localized, the batch is not aborted).
    let mut failed = 0usize;
    for line in &lines {
        if let InputFileLine::Malformed { line_no, reason } = line {
            warn!(target: "taiji::cli", path = %path.display(), line_no, reason,
                "input-file line rejected");
            failed += 1;
        }
    }
    let task_count = lines
        .iter()
        .filter(|l| matches!(l, InputFileLine::Task { .. }))
        .count();
    if task_count == 0 {
        error!(target: "taiji::cli", path = %path.display(),
            "input file has no downloadable entries (only blank/comment/malformed lines)");
        return 2;
    }
    info!(target: "taiji::cli", path = %path.display(),
        lines = task_count, dir = %cli.dir.display(),
        "input-file batch: session pipeline (concurrency clamped by --max-concurrent-downloads)");

    // Single-session guard + session db + actor (the magnet one-shot's
    // same base: lock before db).
    let _db_lock = match http::acquire_db_lock(&cli.sqlite3_db_path).await {
        Ok(l) => l,
        Err(code) => return code,
    };
    let (persist, persist_join) =
        match taiji_core::session::persist::import::open_session_writer_with_metrics(
            cli.sqlite3_db_path.clone(),
        )
        .await
        {
            Ok((h, j)) => (Some(h), Some(j)),
            Err(e) => {
                warn!(target: "taiji::cli", %e, "cannot open session db; running WITHOUT persistence");
                (None, None)
            }
        };
    let global = taiji_core::session::GlobalOptions {
        dir: cli.dir.clone(),
        one_shot: true,
        enable_dht: cli.enable_dht,
        listen_port: cli.listen_port,
        bt_require_crypto: crypto.require_crypto,
        bt_min_crypto_level: crypto.min_level,
        bt_peer_connection_type: conn_type,
        bt_tracker: seed_trackers,
        // Domain C: the exit text export + the cookie session-level
        // default source (the batch face goes through the session
        // pipeline — the same gate as the shutdown save_session; the
        // cookie default source covers WebUri lines without a per-task
        // load-cookies, a line-level explicit value wins).
        save_session: cli.save_session.clone(),
        load_cookies: cli.load_cookies.clone(),
        // The six hook commands + the gate (the `--on-*` family,
        // SPEC §7.4): the batch face goes through the session pipeline
        // — the actor's five events + the engine BtComplete full
        // consumption face (built at the hook_set_from_cli single
        // point, same source as idle/download+rpc/magnet one-shot).
        hooks: hook_set_from_cli(cli),
        bt_tracker_interval: cli.bt_tracker_interval,
        bt_tracker_timeout_secs: cli.bt_tracker_timeout,
        bt_tracker_connect_timeout_secs: cli.bt_tracker_connect_timeout,
        bt_stop_timeout_secs: cli.bt_stop_timeout,
        // The HTTP task face (HostCap initialization + the periodic
        // summary — the same rule as the metalink form).
        http_max_per_host: cli
            .http_max_per_host
            .unwrap_or(taiji_core::session::DEFAULT_MAX_PER_HOST),
        summary_interval: cli.summary_interval,
        ..Default::default()
    };
    let (session, actor_join) = taiji_core::session::SessionActor::spawn_with_persist(
        taiji_core::session::SessionOptions { global },
        persist.clone(),
    );
    let session = std::sync::Arc::new(session);

    // Create tasks line by line (list order; in-line tab options are
    // written later and override the CLI shared/kind deltas).
    let shared = cli_shared_task_options(cli);
    let mut gids: std::collections::VecDeque<String> = std::collections::VecDeque::new();
    for line in &lines {
        let InputFileLine::Task {
            line_no,
            target,
            options,
        } = line
        else {
            continue;
        };
        let classified = classify_positional(std::ffi::OsStr::new(target));
        let mut add_options = kind_extra_task_options(cli, &classified);
        // Domain B: the top-level `--ca-certificate` batch-face
        // injection — **WebUri lines only** (magnet/.torrent lines have
        // no HTTPS download client, not injected — a bad path does not
        // reject unrelated tasks, the same way aria2 global options have
        // no effect on BT tasks). The key maps directly onto the session
        // addUri option (a single source at the parse arm: a bad
        // path/bad PEM = that line's task rejected
        // `taiji.option.invalid` — a line-level failure does not abort
        // the batch). Before the in-line options extend — an in-line
        // `ca-certificate=...` overrides the CLI value (the same merge
        // order rule).
        if matches!(classified, PositionalInput::WebUri(_)) {
            if let Some(ca) = cli
                .ca_certificate
                .as_deref()
                .filter(|v| !v.trim().is_empty())
            {
                add_options.insert("ca-certificate".to_string(), ca.to_string());
            }
            // Domain C: the top-level `--load-cookies` batch-face
            // injection — the same WebUri-line gate as ca-certificate
            // (magnet/.torrent lines have no HTTPS download client);
            // the session global default source (global.load_cookies)
            // backs it up at the same time, a line-level explicit value
            // wins over the global (the aria2 per-download precedence
            // order).
            if let Some(lc) = cli
                .load_cookies
                .as_deref()
                .filter(|p| !p.as_os_str().is_empty())
            {
                add_options.insert("load-cookies".to_string(), lc.display().to_string());
            }
        }
        add_options.extend(shared.iter().map(|(k, v)| (k.clone(), v.clone())));
        add_options.extend(options.iter().map(|(k, v)| (k.clone(), v.clone())));
        let reply = match classified {
            PositionalInput::TorrentFile(torrent_path) => {
                // .torrent line: read from disk (the blocking face via
                // spawn_blocking) -> inject the bytes via AddTorrent. A
                // read failure = that line failed (the same face
                // semantics as the bare form — "cannot read torrent
                // file"), the batch is not aborted.
                match tokio::task::spawn_blocking(move || std::fs::read(&torrent_path)).await {
                    Ok(Ok(bytes)) => {
                        session
                            .call(taiji_core::session::SessionCommand::AddTorrent {
                                torrent: bytes,
                                options: add_options,
                                position: None,
                            })
                            .await
                    }
                    Ok(Err(e)) => {
                        warn!(target: "taiji::cli", path = %target, %e, line_no,
                            "input-file line failed: cannot read torrent file");
                        failed += 1;
                        continue;
                    }
                    Err(e) => {
                        warn!(target: "taiji::cli", path = %target, %e, line_no,
                            "input-file line failed: torrent read join error");
                        failed += 1;
                        continue;
                    }
                }
            }
            PositionalInput::MagnetUri(_) | PositionalInput::WebUri(_) => {
                // magnet/http(s)/ftp(s) lines: injected via AddUri
                // (scheme dispatch belongs to the session — a magnet
                // task / an HTTP task / a .torrent-URL metadata
                // download, the session classification face).
                session
                    .call(taiji_core::session::SessionCommand::AddUri {
                        uris: vec![target.clone()],
                        options: add_options,
                        position: None,
                    })
                    .await
            }
        };
        match reply {
            Ok(taiji_core::session::CommandReply::Gid(g)) => {
                info!(target: "taiji::cli", gid = %g, line_no, target = %target,
                    "input-file task accepted");
                gids.push_back(g.to_string());
            }
            Ok(other) => {
                warn!(target: "taiji::cli", reply = ?other, line_no, target = %target,
                    "input-file task creation: unexpected reply");
                failed += 1;
            }
            Err(e) => {
                warn!(target: "taiji::cli", error = %e, line_no, target = %target,
                    "input-file task rejected");
                failed += 1;
            }
        }
    }

    // All-task terminal-state polling (the same cadence as the metalink
    // multi-task form; the difference = a failure does not break — wait
    // for all terminal states then summarize; the ask contract "any
    // failure = 1" is the final verdict, not a first-error short
    // circuit).
    let mut ticks = 0u32;
    let mut shutdown = std::pin::pin!(crate::wait_shutdown_signal());
    let code = loop {
        let Some(gid) = gids.front().cloned() else {
            break input_file_exit_code(failed > 0);
        };
        tokio::select! {
            _ = &mut shutdown => {
                info!(target: "taiji::cli", gid = %gid, "interrupted: stopping session");
                break 1;
            }
            r = session.call(taiji_core::session::SessionCommand::TellStatus {
                gid: gid.clone(),
                keys: Vec::new(),
            }) => {
                match r {
                    Ok(taiji_core::session::CommandReply::TorrentStatus(v)) => match v.status {
                        taiji_core::session::StatusKind::Complete => {
                            info!(target: "taiji::cli", gid = %gid,
                                total = v.total_length, "task complete");
                            gids.pop_front();
                        }
                        taiji_core::session::StatusKind::Error
                        | taiji_core::session::StatusKind::Removed => {
                            error!(target: "taiji::cli", gid = %gid,
                                code = ?v.error_code, message = ?v.error_message,
                                "input-file task failed");
                            failed += 1;
                            gids.pop_front();
                        }
                        _ => {
                            ticks += 1;
                            if ticks.is_multiple_of(http::PROGRESS_EVERY) {
                                info!(target: "taiji::cli", gid = %gid,
                                    done = v.completed_length, total = v.total_length,
                                    speed = v.download_speed,
                                    remaining = gids.len(),
                                    "downloading input-file tasks");
                            }
                            tokio::time::sleep(http::STATUS_POLL).await;
                        }
                    },
                    Ok(other) => {
                        error!(target: "taiji::cli", reply = ?other, gid = %gid,
                            "unexpected tellStatus reply");
                        failed += 1;
                        gids.pop_front();
                    }
                    Err(e) => {
                        error!(target: "taiji::cli", %e, gid = %gid, "tellStatus failed");
                        failed += 1;
                        gids.pop_front();
                    }
                }
            }
        }
    };
    http::unwind(session, actor_join, persist_join, code).await
}

/// Injection input for download+rpc: a torrent file (existing) or a
/// magnet URI (injected via session AddUri, same residence
/// semantics).
enum DownloadWithRpc {
    TorrentFile(PathBuf),
    Magnet(String),
}

/// Injection command payload (torrent bytes / magnet URI -> AddUri).
enum Injection {
    Torrent { bytes: Vec<u8> },
    Magnet { uri: String },
}

async fn run_download_with_rpc(
    input: DownloadWithRpc,
    cfg: taiji_rpc::RpcConfig,
    opts: IdleOptions,
) -> i32 {
    // Intake gate first (the same gate and error surface as bare; the
    // magnet arm is the same skeleton with AddUri injection — no file
    // read/parse gate).
    let injection = match &input {
        DownloadWithRpc::TorrentFile(torrent_path) => {
            let bytes = match std::fs::read(torrent_path) {
                Ok(b) => b,
                Err(e) => {
                    error!(target: "taiji::cli", path = %torrent_path.display(), %e, "cannot read torrent file");
                    return 1;
                }
            };
            let meta = match parse_metainfo_intake(&bytes, opts.enable_dht) {
                Ok(m) => m,
                Err(e) => {
                    error!(target: "taiji::cli", path = %torrent_path.display(), %e, "invalid metainfo");
                    return 1;
                }
            };
            info!(
                target = "taiji::cli",
                torrent = %torrent_path.display(),
                dir = %opts.dir.display(),
                listen_port = opts.listen_port,
                announce = %meta.announce,
                pieces = meta.v1_pieces.len(),
                total_bytes = meta.meta.total_len(),
                "download mode: rpc co-resident (SessionActor pipeline)"
            );
            Injection::Torrent { bytes }
        }
        DownloadWithRpc::Magnet(uri) => {
            info!(
                target = "taiji::cli",
                magnet = %uri,
                dir = %opts.dir.display(),
                listen_port = opts.listen_port,
                "download mode (magnet): rpc co-resident (SessionActor pipeline)"
            );
            Injection::Magnet { uri: uri.clone() }
        }
    };
    let session_options = opts.to_session_options(&cfg);
    // Snapshot the magnet family + stop-timeout before the destructure
    // borrow ends — the injection arms forward them via add_options
    // (`opts` is unavailable after the destructure). Domain 5:
    // select-file (the AddTorrent raw-value injection) and --stop (the
    // shutdown deadline) ride the same destructure.
    let IdleOptions {
        db_path,
        bt_save_metadata,
        bt_metadata_only,
        bt_load_saved_metadata,
        bt_stop_timeout_secs,
        bt_sequential_download,
        enable_http_seeding,
        select_file,
        stop_after,
        ..
    } = opts;
    // Open PersistWriter (same as idle; both download forms share
    // [`open_persist_writer`]).
    let (persist, persist_join) = open_persist_writer(db_path).await;
    let (session, actor_join) =
        taiji_core::session::SessionActor::spawn_with_persist(session_options, persist.clone());
    let session = Arc::new(session);
    let shutdown = CancellationToken::new();
    let secret_set = cfg.secret.is_some();
    let server = match taiji_rpc::serve(cfg, session.clone(), shutdown.clone()).await {
        Ok(h) => h,
        Err(e) => {
            error!(target: "taiji::cli", %e, "cannot bind rpc listener");
            return 1;
        }
    };
    info!(
        target: "taiji::cli",
        addr = %server.local_addr,
        secret_set,
        "taiji up (download+rpc): SessionActor -> TorrentTask -> PeerTask + JSON-RPC (POST/GET /jsonrpc)"
    );

    // Direct injection via the AddTorrent session command (no RPC
    // self-call — bypasses the write gate and credential requirement;
    // no task-level dir override = the session-global --dir is the
    // single source). Task-face options = --bt-sequential-download +
    // --enable-http-seeding (BEP19, injected only when explicitly
    // false — the default true writes no key) + --bt-stop-timeout
    // (written only when > 0 — 0 = the global default, watchdog not
    // armed) + --select-file (domain 5: the raw-value injection —
    // parse/range-check/error face at the session addTorrent single
    // point; an invalid value = the session's explicit refusal, the
    // taiji.option.invalid error face).
    let mut add_options = std::collections::BTreeMap::new();
    if bt_sequential_download {
        add_options.insert("bt-sequential-download".to_string(), "true".to_string());
    }
    if !enable_http_seeding {
        add_options.insert("enable-http-seeding".to_string(), "false".to_string());
    }
    let mut add_options = std::collections::BTreeMap::new();
    if bt_sequential_download {
        add_options.insert("bt-sequential-download".to_string(), "true".to_string());
    }
    if !enable_http_seeding {
        add_options.insert("enable-http-seeding".to_string(), "false".to_string());
    }
    if let Some(raw) = select_file {
        add_options.insert("select-file".to_string(), raw);
    }
    if bt_stop_timeout_secs > 0 {
        add_options.insert(
            "bt-stop-timeout".to_string(),
            bt_stop_timeout_secs.to_string(),
        );
    }
    let injected = match injection {
        Injection::Torrent { bytes } => {
            session
                .call(taiji_core::session::SessionCommand::AddTorrent {
                    torrent: bytes,
                    options: add_options,
                    position: None,
                })
                .await
        }
        Injection::Magnet { uri } => {
            // The magnet family (bt-save-metadata / bt-metadata-only /
            // bt-load-saved-metadata — aria2 "only when Magnet URI is
            // used" rule; the torrent injection arm writes no keys).
            if bt_save_metadata {
                add_options.insert("bt-save-metadata".to_string(), "true".to_string());
            }
            if bt_metadata_only {
                add_options.insert("bt-metadata-only".to_string(), "true".to_string());
            }
            if bt_load_saved_metadata {
                add_options.insert("bt-load-saved-metadata".to_string(), "true".to_string());
            }
            session
                .call(taiji_core::session::SessionCommand::AddUri {
                    uris: vec![uri],
                    options: add_options,
                    position: None,
                })
                .await
        }
    };
    match injected {
        Ok(taiji_core::session::CommandReply::Gid(gid)) => {
            info!(
                target = "taiji::cli",
                gid = %gid,
                "download injected via session command (bypasses rpc write gate)"
            );
        }
        Ok(other) => {
            error!(target: "taiji::cli", reply = ?other, "unexpected addTorrent reply");
            shutdown.cancel();
            shutdown_session_and_server(session, actor_join, server).await;
            return 1;
        }
        Err(e) => {
            error!(target: "taiji::cli", %e, "download injection failed");
            shutdown.cancel();
            shutdown_session_and_server(session, actor_join, server).await;
            return 1;
        }
    }

    // Residence: three-driven by signal / RPC shutdown / the --stop
    // deadline (the same wiring as run_idle — cancel concurrent with the
    // actor drain; after RPC shutdown is accepted the SessionActor is
    // already winding down). The --stop arm = the RPC shutdown path
    // (token cancel + drain).
    tokio::select! {
        _ = wait_shutdown_signal() => {
            info!(target: "taiji::cli", "shutdown signal received: propagating through SessionActor");
            shutdown.cancel();
            session.shutdown().await;
        }
        _ = stop_timer(stop_after) => {
            info!(target: "taiji::cli", "--stop deadline reached: propagating through SessionActor");
            shutdown.cancel();
            session.shutdown().await;
        }
        _ = shutdown.cancelled() => {
            info!(target: "taiji::cli", "rpc shutdown accepted: SessionActor already draining");
        }
    }
    // Tail instrumentation shares the bare path's
    // [`emit_tail_instrumentation`] point. Clone the handle first — the
    // metrics counters freeze once the SessionActor winds down, and the
    // read happens after shutdown_session_and_server consumes the
    // session.
    let perf05_metrics = session.metrics().clone();
    shutdown_session_and_server(session, actor_join, server).await;
    emit_tail_instrumentation(Some(&*perf05_metrics));
    // Persistence wrap-up (same as idle; both download forms share
    // [`drain_persist_writer`]).
    drain_persist_writer(persist, persist_join).await;
    0
}

pub(crate) async fn wait_shutdown_signal() {
    tokio::select! {
        _ = wait_os_shutdown_signal() => {},
        _ = wait_parent_stdin() => {},
    }
}

async fn wait_parent_stdin() {
    if std::env::var("MOTRIX_TAIJI_PARENT_PIPE").as_deref() != Ok("1") {
        std::future::pending::<()>().await;
        return;
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    // A detached OS thread avoids Tokio's non-cancellable blocking-stdin
    // runtime shutdown. Closing the parent-owned pipe is the crash fence.
    std::thread::spawn(move || {
        use std::io::Read;
        let mut input = std::io::stdin().lock();
        let mut byte = [0u8; 1];
        while matches!(input.read(&mut byte), Ok(n) if n > 0) {}
        let _ = tx.send(());
    });
    let _ = rx.await;
}

async fn wait_os_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}   // Ctrl-C (SIGINT)
                    _ = term.recv() => {}               // SIGTERM (the sidecar stop path)
                }
            }
            // If the SIGTERM handle is unavailable, degrade to Ctrl-C
            // only, without blocking startup.
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// ANSI color decision for text mode: keep color for TTY interaction
/// (stdout is a direct terminal); redirects/pipes/journal capture
/// stay clean automatically (ANSI used to be always on, littering
/// redirected files with `\x1b[2m` and embedded codes). A set
/// `NO_COLOR` environment variable always disables (no-color.org —
/// implemented literally as "is set", so an empty value still
/// counts). Both conditions must hold; either failing turns it off.
/// Both factors are parameters for four-state unit tests (a real
/// is_terminal and process environment cannot be constructed stably
/// in tests).
fn ansi_enabled(is_terminal: bool, no_color: Option<&std::ffi::OsStr>) -> bool {
    is_terminal && no_color.is_none()
}

/// The ANSI master gate (the `--enable-color` landing point): the
/// existing TTY x NO_COLOR dual condition ([`ansi_enabled`]) ANDed with
/// the explicit switch. Default true = an identity on the existing
/// verdict (zero change); false = force off (true does not force on —
/// the non-TTY stays-clean discipline is unchanged; the aria2 divergence
/// note is in the flag doc). Parameterized for the truth-table unit test
/// (a real is_terminal and process environment cannot be constructed
/// stably in tests, same as ansi_enabled).
fn ansi_final(is_terminal: bool, no_color: Option<&std::ffi::OsStr>, enable_color: bool) -> bool {
    ansi_enabled(is_terminal, no_color) && enable_color
}

/// The global log stream target (the `--log`/`--stderr` assembly
/// product; the default [`LogTarget::Stdout`] = the existing writer,
/// zero change). The single log stream is three-state exclusive: the
/// CLI face refuses via the clap `conflicts_with` (usage exit 2); both
/// keys given via conf = the [`open_log_target`] fail-fast — a dual
/// target on one stream is refused explicitly, never silently picking
/// one. derive(Debug): the test face's expect_err needs the Ok arm to
/// be Debug.
#[derive(Debug)]
pub(crate) enum LogTarget {
    /// Default: stdout (the existing writer, unchanged form).
    Stdout,
    /// `--stderr`: the global log stream rewritten to stderr (the
    /// aria2 redirectStdoutToStderr equivalent).
    Stderr,
    /// `--log FILE`: the file sink (append+create direct writes; always
    /// ANSI-clean).
    File(std::fs::File),
}

/// Log stream assembly (the only main call): opens the `--log` file
/// (append+create — restarts keep appending without truncation, the
/// aria2 `--log` plain-file form) -> [`LogTarget`]; `--log` absent =
/// `--stderr` ? Stderr : Stdout. `--log` and `--stderr` both given
/// (reachable via conf — the CLI face is refused earlier by the clap
/// conflicts_with) = Err; file open failure = Err (main exits 2, the
/// same face as an unreadable conf; the error text carries the original
/// path — the winpath "no prefix on user-visible paths" contract).
pub(crate) fn open_log_target(stderr: bool, log: Option<&Path>) -> Result<LogTarget, String> {
    let Some(path) = log else {
        return Ok(if stderr {
            LogTarget::Stderr
        } else {
            LogTarget::Stdout
        });
    };
    if stderr {
        return Err(
            "error: --log and --stderr are mutually exclusive (single log stream)".to_string(),
        );
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(taiji_io::winpath::to_fs_path(path))
        .map(LogTarget::File)
        .map_err(|e| format!("error: cannot open log file {}: {e}", path.display()))
}

/// The `--human-readable` landing point (observability format
/// resolution, the only main call): false = the machine-readable face
/// (`--log-format json`); true = the format face keeps the given value.
/// An explicit `--log-format` (command-line source) always wins — the
/// more specific flag takes precedence (the value_source criterion, same
/// as rpc_group_conflict; a conf-provided log-format is a non-command-
/// line source and gets overridden by false — the CLI > conf precedence,
/// same rule). A pure function face, consumed by the decision-table unit
/// test.
fn resolve_log_format(log_format: &str, human_readable: bool, log_format_explicit: bool) -> String {
    if human_readable || log_format_explicit {
        log_format.to_string()
    } else {
        "json".to_string()
    }
}

/// Level flags -> EnvFilter directive (a pure decision function; does
/// not touch the global subscriber). Quietness ladder (the
/// wget/curl/aria2 four tiers + explicit level): `--quiet`(warn) <
/// default info < `--verbose`(debug) < `--debug`(trace). Precedence
/// (higher verbosity wins): `--debug` > `--verbose` > `--log-level` >
/// `--quiet` > default info; with RUST_LOG set the flags all yield
/// (read in init_tracing). aria2 `notice` maps to info (tracing has
/// no notice level; see the flag docs). The global subscriber is a
/// single point, so the ladder applies to all protocol faces
/// (BT/HTTP/FTP) at once; the `log` crate bridge (suppaftp/reqwest
/// dependencies) rides tracing-subscriber's default feature.
fn log_level_directive(
    debug: bool,
    verbose: bool,
    log_level: Option<&str>,
    quiet: bool,
) -> &'static str {
    if debug {
        "trace"
    } else if verbose {
        "debug"
    } else if let Some(level) = log_level {
        match level {
            "debug" => "debug",
            "warn" => "warn",
            "error" => "error",
            // notice/info both land on info (the notice-mapping note).
            _ => "info",
        }
    } else if quiet {
        "warn"
    } else {
        "info"
    }
}

/// Global subscriber initialization point (called only from main;
/// every other `tracing_subscriber::fmt` in the repo is a
/// test-local set_default/MakeWriter capture, not this path).
/// `--log-format` dispatches by value: json = tracing-subscriber's
/// default JSON form (timestamp/level/target/fields/span ctx) with
/// ANSI always off (no escape noise in the machine-readable face);
/// text = the existing human form with ANSI per [`ansi_final`]. The
/// value domain is frozen by clap's PossibleValuesParser (text|json),
/// so out-of-domain values never reach here. Level: explicit
/// RUST_LOG has full authority (the per-module tuning escape hatch);
/// otherwise the quietness ladder ([`log_level_directive`]).
/// The writer is three-state (the domain 3 enhancement; the default
/// stdout form is unchanged): File = the `--log` file sink (the
/// existing `std::fs::File` `MakeWriter` impl — every event writes
/// straight to the OS, no in-process buffer backlog); Stderr =
/// `--stderr`; Stdout = the existing default.
fn init_tracing(
    log_format: &str,
    verbose: bool,
    debug: bool,
    log_level: Option<&str>,
    quiet: bool,
    enable_color: bool,
    log_target: LogTarget,
) {
    use tracing_subscriber::EnvFilter;
    // RUST_LOG takes precedence (explicitly set = full authority; the
    // per-module tuning escape hatch, standard tracing practice);
    // otherwise the quietness ladder order.
    let filter = if std::env::var_os("RUST_LOG").is_some() {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    } else {
        EnvFilter::new(log_level_directive(debug, verbose, log_level, quiet))
    };
    // The ANSI probe follows the writer: the default probes stdout
    // (the existing verdict); --stderr probes the stderr TTY; the --log
    // file sink is always clean (collection-face purity — the same rule
    // as redirection).
    let no_color_env = std::env::var_os("NO_COLOR");
    let no_color = no_color_env.as_deref();
    let ansi = match log_target {
        LogTarget::File(_) => false,
        LogTarget::Stderr => ansi_final(std::io::stderr().is_terminal(), no_color, enable_color),
        LogTarget::Stdout => ansi_final(std::io::stdout().is_terminal(), no_color, enable_color),
    };
    if log_format == "json" {
        let fmt = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .with_ansi(false);
        match log_target {
            LogTarget::File(f) => fmt.with_writer(f).init(),
            LogTarget::Stderr => fmt.with_writer(std::io::stderr).init(),
            LogTarget::Stdout => fmt.init(),
        }
    } else {
        let fmt = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(ansi);
        match log_target {
            LogTarget::File(f) => fmt.with_writer(f).init(),
            LogTarget::Stderr => fmt.with_writer(std::io::stderr).init(),
            LogTarget::Stdout => fmt.init(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decision table: positional prefix dispatch —
    /// magnet/http(s)/ftp(s) (scheme case-insensitive) go to the
    /// session pipeline; everything else (.torrent paths, relative
    /// paths, dotted strings without a scheme) = torrent file path;
    /// `ftps://` is not accepted (same rule as the http subcommand:
    /// FTPS = ftp:// + --ftp-ssl).
    #[test]
    fn classify_positional_decision_table() {
        let is_magnet = |s: &str| {
            matches!(
                classify_positional(std::ffi::OsStr::new(s)),
                PositionalInput::MagnetUri(_)
            )
        };
        let is_web = |s: &str| {
            matches!(
                classify_positional(std::ffi::OsStr::new(s)),
                PositionalInput::WebUri(_)
            )
        };
        let is_file = |s: &str| {
            matches!(
                classify_positional(std::ffi::OsStr::new(s)),
                PositionalInput::TorrentFile(_)
            )
        };
        assert!(is_magnet(
            "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567"
        ));
        assert!(
            is_magnet("MAGNET:?xt=urn:btih:abc"),
            "scheme matching is case-insensitive"
        );
        assert!(is_web("http://example.com/f.bin"));
        assert!(is_web("HTTPS://example.com/f.bin"));
        assert!(is_web("ftp://example.com/f.bin"));
        assert!(
            is_file("ftps://example.com/f.bin"),
            "ftps is not accepted (same rule as the http subcommand)"
        );
        assert!(is_file("/abs/path/x.torrent"));
        assert!(is_file("rel/x.torrent"));
        assert!(is_file("plain.torrent"));
        assert!(is_file("no-scheme.dots"));
        // WebUri/Magnet content fidelity (original string unchanged).
        match classify_positional(std::ffi::OsStr::new("magnet:?dn=a b")) {
            PositionalInput::MagnetUri(u) => assert_eq!(u, "magnet:?dn=a b"),
            _ => panic!("expected the magnet form"),
        }
    }

    /// Locks the bare-exit-path NAT teardown budget: 250ms (same value
    /// as the session actor's NAT_SHUTDOWN_BUDGET) and strictly below
    /// the graceful-shutdown total budget (the 1s contract is not
    /// eroded by NAT unmap).
    #[test]
    fn nat_shutdown_budget_is_bounded_below_total_budget() {
        assert_eq!(NAT_SHUTDOWN_BUDGET, Duration::from_millis(250));
        assert!(
            NAT_SHUTDOWN_BUDGET < SHUTDOWN_BUDGET,
            "nat unwind budget ({NAT_SHUTDOWN_BUDGET:?}) must stay within the \
             graceful shutdown budget ({SHUTDOWN_BUDGET:?})"
        );
    }

    // ---- bt option family (CLI surface: domains + aliases + session
    // projection) ----

    /// Cli parsing helper (argv-style first argument).
    fn cli_of(args: &[&str]) -> Cli {
        let m = Cli::command()
            .try_get_matches_from(args)
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"))
    }

    /// Acceptance-domain decision table (the clap value_parser mirrors
    /// the aria2 value domains bit for bit; anchors in the Cli field
    /// docs):
    /// - defaults = aria2 defaults (55/50K/0/0/60/60) plus gate
    ///   defaults (hash-check-seed true / hook gate true / magnet
    ///   family false);
    /// - bt-max-peers: 0 accepted (aria2 min 0; the non-expressible
    ///   semantics live in the injection arm), negatives rejected;
    /// - tracker timeouts: 1..=600 (0/601 rejected — the aria2
    ///   NumberOptionHandler(…, "60", 1, 600) domain verbatim);
    /// - request-peer-speed-limit: 1024-based size literals (64K =
    ///   65536, parse_aria2_size single parser);
    /// - stop-timeout/interval: the full non-negative integer domain.
    #[test]
    fn w3b_bt_option_cli_domain_decision_table() {
        // Defaults (aria2 defaults verbatim).
        let c = cli_of(&["taiji"]);
        assert_eq!(c.bt_max_peers, 55);
        assert_eq!(c.bt_request_peer_speed_limit, 50 * 1024);
        assert_eq!(c.bt_stop_timeout, 0);
        assert_eq!(c.bt_tracker_interval, 0);
        assert_eq!(c.bt_tracker_timeout, 60);
        assert_eq!(c.bt_tracker_connect_timeout, 60);
        assert!(
            c.bt_hash_check_seed,
            "default true (the aria2 A2_V_TRUE rule)"
        );
        assert!(c.bt_enable_hook_after_hash_check, "default true, same rule");
        assert!(!c.bt_save_metadata && !c.bt_metadata_only && !c.bt_load_saved_metadata);
        // bt-max-peers: 0 accepted (domain min 0); valid values pass
        // through.
        let c = cli_of(&["taiji", "--bt-max-peers", "0"]);
        assert_eq!(c.bt_max_peers, 0);
        let c = cli_of(&["taiji", "--bt-max-peers", "80"]);
        assert_eq!(c.bt_max_peers, 80);
        // Negatives rejected (clap u64 range(0..)).
        assert!(
            Cli::command()
                .try_get_matches_from(["taiji", "--bt-max-peers", "-1"])
                .is_err()
        );
        // Tracker dual-timeout domain 1..=600: boundaries accepted,
        // out-of-range rejected.
        let c = cli_of(&[
            "taiji",
            "--bt-tracker-timeout",
            "1",
            "--bt-tracker-connect-timeout",
            "600",
        ]);
        assert_eq!(
            (c.bt_tracker_timeout, c.bt_tracker_connect_timeout),
            (1, 600)
        );
        assert!(
            Cli::command()
                .try_get_matches_from(["taiji", "--bt-tracker-timeout", "0"])
                .is_err()
        );
        assert!(
            Cli::command()
                .try_get_matches_from(["taiji", "--bt-tracker-timeout", "601"])
                .is_err()
        );
        assert!(
            Cli::command()
                .try_get_matches_from(["taiji", "--bt-tracker-connect-timeout", "601"])
                .is_err()
        );
        // request-peer-speed-limit: size literal parsing (1024 base) +
        // 0 accepted.
        let c = cli_of(&["taiji", "--bt-request-peer-speed-limit", "64K"]);
        assert_eq!(c.bt_request_peer_speed_limit, 65536);
        let c = cli_of(&["taiji", "--bt-request-peer-speed-limit", "0"]);
        assert_eq!(c.bt_request_peer_speed_limit, 0);
        // stop-timeout / tracker-interval: the full non-negative domain
        // passes through.
        let c = cli_of(&[
            "taiji",
            "--bt-stop-timeout",
            "90",
            "--bt-tracker-interval",
            "120",
        ]);
        assert_eq!((c.bt_stop_timeout, c.bt_tracker_interval), (90, 120));
        assert!(
            Cli::command()
                .try_get_matches_from(["taiji", "--bt-stop-timeout", "-1"])
                .is_err()
        );
    }

    /// Alias and bool dual forms: `--bt-enable-lpd` is the aria2
    /// original name, sharing the `--bt-lsd` slot (the rename is
    /// declared in DECLARED_OPTION_DIFFS); the bare flag = true,
    /// `=false` explicitly suppresses (require_equals dual form, the
    /// aria2 bool-option rule).
    #[test]
    fn w3b_bt_lpd_alias_and_bool_double_forms() {
        // Alias and primary name share the slot.
        assert!(cli_of(&["taiji", "--bt-enable-lpd"]).bt_lsd);
        assert!(cli_of(&["taiji", "--bt-lsd"]).bt_lsd);
        assert!(!cli_of(&["taiji"]).bt_lsd);
        // =true/=false value forms (same for the alias).
        assert!(!cli_of(&["taiji", "--bt-enable-lpd=false"]).bt_lsd);
        // Bare-flag dual-form spot checks (magnet family + two gates).
        assert!(cli_of(&["taiji", "--bt-save-metadata"]).bt_save_metadata);
        assert!(!cli_of(&["taiji", "--bt-save-metadata=false"]).bt_save_metadata);
        assert!(cli_of(&["taiji", "--bt-metadata-only"]).bt_metadata_only);
        assert!(cli_of(&["taiji", "--bt-load-saved-metadata"]).bt_load_saved_metadata);
        assert!(!cli_of(&["taiji", "--bt-hash-check-seed=false"]).bt_hash_check_seed);
        assert!(
            !cli_of(&["taiji", "--bt-enable-hook-after-hash-check=false"])
                .bt_enable_hook_after_hash_check
        );
    }

    /// Decision table for the injection pure function
    /// (`--bt-max-peers` knob-override seam): explicit >= 1 -> Some;
    /// not explicit (default 55) -> None (built-ins 120/100 stay);
    /// explicit 0 -> None (unlimited not expressible, warning arm).
    #[test]
    fn w3b_bt_max_peers_override_decision_table() {
        assert_eq!(bt_max_peers_override_of(80, true), Some(80));
        assert_eq!(
            bt_max_peers_override_of(55, true),
            Some(55),
            "an explicit 55 also overrides (converges to 55)"
        );
        assert_eq!(
            bt_max_peers_override_of(55, false),
            None,
            "the default does not override"
        );
        assert_eq!(
            bt_max_peers_override_of(0, true),
            None,
            "0 = unlimited, not expressible"
        );
        assert_eq!(bt_max_peers_override_of(u64::MAX, true), Some(usize::MAX));
    }

    /// Session projection (the assembly point shared by idle /
    /// download+rpc): Cli -> build_idle_options -> to_session_options
    /// maps the keys straight onto GlobalOptions (the getGlobalOption
    /// echo face projects from here; defaults match
    /// GlobalOptions::default = zero behavior change by default).
    #[test]
    fn w3b_idle_options_project_to_session_globals() {
        let project = |args: &[&str]| {
            let cli = cli_of(args);
            let opts = build_idle_options(
                &cli,
                taiji_bt::mse::CryptoPolicy::optional(),
                taiji_bt::utp::PeerConnectionType::default(),
            );
            opts.to_session_options(&taiji_rpc::RpcConfig {
                port: 6800,
                listen_all: false,
                secret: None,
                rpc_user: None,
                rpc_passwd: None,
                allow_origin_all: false,
                max_request_size: 10 * 1024 * 1024,
                aria2_compat: false,
                secure: false,
                certificate: None,
                private_key: None,
            })
            .global
        };
        // Defaults = GlobalOptions::default values (zero behavior
        // change).
        let g = project(&["taiji"]);
        assert_eq!(
            g.bt_max_peers,
            taiji_core::session::GlobalOptions::default().bt_max_peers
        );
        assert_eq!(g.bt_stop_timeout_secs, 0);
        assert_eq!(g.bt_tracker_interval, 0);
        assert_eq!(g.bt_tracker_timeout_secs, 60);
        assert_eq!(g.bt_tracker_connect_timeout_secs, 60);
        assert!(g.hooks.bt_enable_hook_after_hash_check);
        // Explicit values map straight through (echo face follows).
        let g = project(&[
            "taiji",
            "--bt-max-peers",
            "80",
            "--bt-stop-timeout",
            "45",
            "--bt-tracker-interval",
            "120",
            "--bt-tracker-timeout",
            "90",
            "--bt-tracker-connect-timeout",
            "30",
            "--bt-enable-hook-after-hash-check=false",
        ]);
        assert_eq!(g.bt_max_peers, 80);
        assert_eq!(g.bt_stop_timeout_secs, 45);
        assert_eq!(g.bt_tracker_interval, 120);
        assert_eq!(g.bt_tracker_timeout_secs, 90);
        assert_eq!(g.bt_tracker_connect_timeout_secs, 30);
        assert!(!g.hooks.bt_enable_hook_after_hash_check);
    }

    // ---- the hook family's six items (`--on-*`, SPEC §7.4: the CLI
    // face -> the HookSet single point) ----

    /// The hook-family decision table (the six `--on-*` flags -> the
    /// [`hook_set_from_cli`] single point -> the session
    /// `GlobalOptions.hooks` projection; the same source across the
    /// idle/download+rpc/magnet one-shot/bare faces):
    /// - default face = all six slots unset (`has_any_command` false —
    ///   the bare form attaches no runner, a zero-overhead pass-through) +
    ///   the post-hash-check gate defaults true;
    /// - explicit face = each flag enters its `HookEvent` slot (the
    ///   name-face alignment is checked bit for bit via the
    ///   `HookEvent::option_name` single source, drift-proof); both the
    ///   space and `=` value forms are accepted;
    /// - blank face = an empty-string value normalizes to unset (same
    ///   rule as aria2 `option->blank` — the same shape as the RPC
    ///   option face's non_empty, the conf source through the same
    ///   gate);
    /// - projection face = after to_session_options each `g.hooks` slot
    ///   holds the same value (the echo face projects with the existing
    ///   session `global_option_echo` HookEvent::ALL — already tested
    ///   on the taiji-core side, not repeated here).
    #[test]
    fn hook_on_flags_cli_to_hookset_decision_table() {
        use taiji_core::hook::HookEvent;
        // Flag <-> event name-face table (the clap long name = the
        // frozen HookEvent name, checked bit for bit).
        let expect: [(&str, HookEvent, &str); 6] = [
            ("--on-download-start", HookEvent::Start, "/bin/start"),
            ("--on-download-pause", HookEvent::Pause, "/bin/pause"),
            ("--on-download-stop", HookEvent::Stop, "/bin/stop"),
            (
                "--on-download-complete",
                HookEvent::Complete,
                "/bin/complete",
            ),
            ("--on-download-error", HookEvent::Error, "/bin/error"),
            (
                "--on-bt-download-complete",
                HookEvent::BtComplete,
                "/bin/bt-complete",
            ),
        ];
        for (flag, ev, _) in &expect {
            assert_eq!(
                flag.trim_start_matches('-'),
                ev.option_name(),
                "the name surface is frozen"
            );
        }

        // Default face: all unset + the gate true.
        let set = hook_set_from_cli(&cli_of(&["taiji"]));
        assert!(!set.has_any_command(), "the default has no active command");
        for (_, ev, _) in &expect {
            assert_eq!(set.command(*ev), None);
        }
        assert!(
            set.bt_enable_hook_after_hash_check,
            "the gate defaults true, same rule"
        );

        // Explicit face: all six flags given (the `=` and space value
        // forms coexist) -> each slot holds the same value.
        let args: Vec<String> = expect
            .iter()
            .enumerate()
            .map(|(i, (flag, _, cmd))| {
                if i % 2 == 0 {
                    format!("{flag}={cmd}")
                } else {
                    format!("{flag} {cmd}")
                }
            })
            .collect();
        let argv: Vec<&str> = std::iter::once("taiji")
            .chain(args.iter().flat_map(|a| a.split(' ')))
            .collect();
        let set = hook_set_from_cli(&cli_of(&argv));
        assert!(set.has_any_command());
        for (flag, ev, cmd) in &expect {
            assert_eq!(set.command(*ev), Some(*cmd), "{flag} enters its slot");
        }

        // Session projection face (the two forms' assembly single
        // point): each GlobalOptions.hooks slot holds the same value +
        // the echo face projects with the frozen names.
        let cli = cli_of(&argv);
        let opts = build_idle_options(
            &cli,
            taiji_bt::mse::CryptoPolicy::optional(),
            taiji_bt::utp::PeerConnectionType::default(),
        );
        let g = opts
            .to_session_options(&taiji_rpc::RpcConfig {
                port: 6800,
                listen_all: false,
                secret: None,
                rpc_user: None,
                rpc_passwd: None,
                allow_origin_all: false,
                max_request_size: 10 * 1024 * 1024,
                aria2_compat: false,
                secure: false,
                certificate: None,
                private_key: None,
            })
            .global;
        for (flag, ev, cmd) in &expect {
            assert_eq!(g.hooks.command(*ev), Some(*cmd), "{flag} projects");
        }

        // Blank face: an empty-string value normalizes to unset (no
        // runner attached).
        let set = hook_set_from_cli(&cli_of(&["taiji", "--on-download-complete", ""]));
        assert_eq!(
            set.on_download_complete, None,
            "an empty string normalizes to unset"
        );
        assert!(!set.has_any_command());
    }

    #[test]
    fn aria2_size_literals_parse_with_1024_base() {
        assert_eq!(parse_aria2_size("10M"), Ok(10 * 1024 * 1024));
        assert_eq!(parse_aria2_size("1k"), Ok(1024));
        assert_eq!(parse_aria2_size("2G"), Ok(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_aria2_size("512"), Ok(512));
        assert!(parse_aria2_size("abc").is_err());
        assert!(parse_aria2_size("").is_err());
        assert!(parse_aria2_size("M").is_err());
    }

    /// Bare limiter assembly truth table — all four 0 -> None (existing
    /// pass-through, zero change); any non-0 -> Some (the overall pair =
    /// the global bucket, the per-task pair = the per_torrent bucket; an
    /// unset axis's 0 = an unlimited bucket short-circuit).
    #[test]
    fn build_session_limiter_truth_table() {
        // All four 0 = None (default form: no limiting, zero-overhead
        // pass-through).
        assert!(build_session_limiter(0, 0, 0, 0).is_none());
        // Per-task upload-only limit: the download buckets stay
        // unlimited (both levels).
        let set =
            build_session_limiter(0, 0, 0, 2_097_152).unwrap_or_else(|| panic!("up-only must arm"));
        assert!(set.global.down.is_unlimited());
        assert!(set.global.up.is_unlimited());
        assert!(set.per_torrent.down.is_unlimited());
        assert_eq!(set.per_torrent.up.rate(), 2_097_152);
        // Overall download-only limit ( batch C: the global bucket
        // arms on the overall pair alone; the per-task buckets stay
        // unlimited).
        let set = build_session_limiter(512 * 1024, 0, 0, 0)
            .unwrap_or_else(|| panic!("down-only must arm"));
        assert_eq!(set.global.down.rate(), 512 * 1024);
        assert!(set.global.up.is_unlimited());
        assert!(set.per_torrent.down.is_unlimited());
        assert!(set.per_torrent.up.is_unlimited());
        // The overall + per-task pairs land in their own buckets.
        let set = build_session_limiter(1024, 2048, 512, 256)
            .unwrap_or_else(|| panic!("both pairs must arm"));
        assert_eq!(set.global.down.rate(), 1024);
        assert_eq!(set.global.up.rate(), 2048);
        assert_eq!(set.per_torrent.down.rate(), 512);
        assert_eq!(set.per_torrent.up.rate(), 256);
    }

    /// `--max-download-limit`/`--max-upload-limit` frozen names +
    /// aria2 size literals (`2M` = 2_097_152, 1024 base —
    /// parse_aria2_size is the single parser; this test only pins the
    /// CLI wiring); default 0 = unlimited; both space and `=` value
    /// forms accepted; invalid literals = clap domain rejection.
    #[test]
    fn max_download_upload_limit_args_parse_aria2_size_literals() {
        let parse = |args: &[&str]| match Cli::command().try_get_matches_from(args) {
            Ok(m) => match Cli::from_arg_matches(&m) {
                Ok(cli) => (cli.max_download_limit, cli.max_upload_limit),
                Err(e) => panic!("valid matches rejected: {e}"),
            },
            Err(e) => panic!("flag must parse: {e}"),
        };
        // Default both 0 = unlimited (aria2's frozen default).
        assert_eq!(parse(vec!["taiji"].as_slice()), (0, 0));
        // Space value form: 2M = 2 * 1024 * 1024.
        assert_eq!(
            parse(vec!["taiji", "--max-upload-limit", "2M"].as_slice()),
            (0, 2_097_152)
        );
        // `=` value form + K suffix + explicit 0.
        assert_eq!(
            parse(vec!["taiji", "--max-download-limit=500K", "--max-upload-limit=0",].as_slice()),
            (500 * 1024, 0)
        );
        // Invalid literal = clap rejection (no silent default fallback).
        assert!(
            Cli::command()
                .try_get_matches_from(vec!["taiji", "--max-download-limit", "fast"].as_slice())
                .is_err()
        );
    }

    /// Sidecar spawn contract: the aria2 `=` value form
    /// `--bt-detach-seed-only=false` must be accepted by the CLI (the
    /// spawn argument set includes it, so a CLI refusal breaks sidecar
    /// startup).
    #[test]
    fn bt_detach_seed_only_accepts_aria2_eq_form() {
        let parse = |args: &[&str]| match Cli::command().try_get_matches_from(args) {
            Ok(m) => match Cli::from_arg_matches(&m) {
                Ok(cli) => cli.bt_detach_seed_only,
                Err(e) => panic!("valid matches rejected: {e}"),
            },
            Err(e) => panic!("spawn-contract flag must parse: {e}"),
        };
        assert!(!parse(
            vec!["taiji", "--bt-detach-seed-only=false"].as_slice()
        ));
        assert!(parse(
            vec!["taiji", "--bt-detach-seed-only=true"].as_slice()
        ));
        // Default (no flag) = false (frozen default).
        assert!(!parse(vec!["taiji"].as_slice()));
    }

    /// `--log-format` default and value domain — default text (no
    /// change); both the space and `=` value forms accepted;
    /// out-of-domain values rejected at startup by clap
    /// (PossibleValuesParser freezes the domain).
    #[test]
    fn log_format_defaults_to_text_and_freezes_value_domain() {
        let parse = |args: &[&str]| {
            Cli::from_arg_matches(
                &Cli::command()
                    .try_get_matches_from(args)
                    .unwrap_or_else(|e| panic!("valid matches rejected: {e}")),
            )
            .unwrap_or_else(|e| panic!("matches to cli: {e}"))
            .log_format
        };
        // Default (no flag) = text.
        assert_eq!(parse(vec!["taiji"].as_slice()), "text");
        assert_eq!(
            parse(vec!["taiji", "--log-format", "json"].as_slice()),
            "json"
        );
        assert_eq!(parse(vec!["taiji", "--log-format=json"].as_slice()), "json");
        assert!(
            Cli::command()
                .try_get_matches_from(vec!["taiji", "--log-format", "xml"])
                .is_err(),
            "out-of-domain value must be rejected"
        );
    }

    /// Level flags + verbatim flag — frozen value domain (notice
    /// accepted, out-of-domain rejected), boolean forms (including the
    /// --quiet tier), and the log_level_directive quietness-ladder
    /// decision table (--debug(trace) > --verbose(debug) >
    /// --log-level > --quiet(warn) > default info; notice -> info
    /// mapping).
    #[test]
    fn log_level_flags_and_directive_decision_table() {
        let parse_cli = |args: &[&str]| {
            Cli::from_arg_matches(
                &Cli::command()
                    .try_get_matches_from(args)
                    .unwrap_or_else(|e| panic!("valid matches rejected: {e}")),
            )
            .unwrap_or_else(|e| panic!("matches to cli: {e}"))
        };
        // Frozen domain: notice is inside the aria2 domain;
        // out-of-domain values rejected at startup.
        assert_eq!(
            parse_cli(vec!["taiji", "--log-level", "notice"].as_slice()).log_level,
            Some("notice".to_string())
        );
        assert!(
            Cli::command()
                .try_get_matches_from(vec!["taiji", "--log-level", "verbose"])
                .is_err(),
            "out-of-domain value must be rejected"
        );
        // Boolean flag forms (all off by default = zero behavior
        // change).
        let flags_of = |args: &[&str]| {
            let c = parse_cli(args);
            (c.quiet, c.verbose, c.debug, c.log_verbatim_urls)
        };
        assert_eq!(
            flags_of(vec!["taiji"].as_slice()),
            (false, false, false, false)
        );
        assert_eq!(
            flags_of(vec!["taiji", "--quiet"].as_slice()),
            (true, false, false, false)
        );
        assert_eq!(
            flags_of(vec!["taiji", "--verbose"].as_slice()),
            (false, true, false, false)
        );
        assert_eq!(
            flags_of(vec!["taiji", "--debug"].as_slice()),
            (false, false, true, false)
        );
        assert_eq!(
            flags_of(vec!["taiji", "--log-verbatim-urls"].as_slice()),
            (false, false, false, true)
        );
        // Quietness-ladder decision table.
        assert_eq!(log_level_directive(false, false, None, false), "info");
        assert_eq!(
            log_level_directive(false, false, Some("notice"), false),
            "info"
        );
        assert_eq!(
            log_level_directive(false, false, Some("info"), false),
            "info"
        );
        assert_eq!(
            log_level_directive(false, false, Some("debug"), false),
            "debug"
        );
        assert_eq!(
            log_level_directive(false, false, Some("warn"), false),
            "warn"
        );
        assert_eq!(
            log_level_directive(false, false, Some("error"), false),
            "error"
        );
        // quiet after an explicit level (yields when --log-level is
        // explicit).
        assert_eq!(
            log_level_directive(false, false, Some("info"), true),
            "info"
        );
        assert_eq!(log_level_directive(false, false, None, true), "warn");
        // verbose/debug beat quiet (higher verbosity wins).
        assert_eq!(log_level_directive(false, true, None, true), "debug");
        assert_eq!(log_level_directive(true, false, None, true), "trace");
        assert_eq!(
            log_level_directive(false, true, Some("warn"), false),
            "debug"
        );
        assert_eq!(log_level_directive(true, true, Some("warn"), true), "trace");
    }

    /// ANSI decision four-state truth table (TTY x NO_COLOR) — direct
    /// terminal and NO_COLOR unset = on (interactive color kept); the
    /// other three states (NO_COLOR set / non-TTY redirect / neither)
    /// always off (clean redirect/capture faces). An empty-string set
    /// also disables (the literal "is set" reading, no exemption).
    #[test]
    fn ansi_enabled_truth_table() {
        use std::ffi::OsStr;
        let set = Some(OsStr::new("1"));
        assert!(ansi_enabled(true, None), "tty + no NO_COLOR = colored");
        assert!(!ansi_enabled(true, set), "NO_COLOR must disable ansi");
        assert!(
            !ansi_enabled(false, None),
            "non-tty (redirect/pipe) output must be ansi-clean"
        );
        assert!(!ansi_enabled(false, set));
        assert!(
            !ansi_enabled(true, Some(OsStr::new(""))),
            "NO_COLOR set disables color (empty string is not exempt)"
        );
    }

    /// Domain 3: the `--console-log-level` alias face — the same arg id
    /// (`log_level`), the same value domain (the PossibleValuesParser
    /// gate: notice accepted, out-of-domain refused), and the same id
    /// for the command-line source verdict (the conf cli_wins
    /// value_source("log_level") check hits alias-provided values the
    /// same way — an alias value outranks conf by the same rule).
    #[test]
    fn console_log_level_alias_shares_log_level_face() {
        let alias_of = |args: &[&str]| {
            let m = Cli::command()
                .try_get_matches_from(args)
                .unwrap_or_else(|e| panic!("must parse: {e}"));
            let cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
            (cli.log_level, m.value_source("log_level"))
        };
        // The alias is accepted and the value lands in the primary field.
        let (level, source) = alias_of(vec!["taiji", "--console-log-level", "notice"].as_slice());
        assert_eq!(
            level.as_deref(),
            Some("notice"),
            "alias value lands in log_level"
        );
        assert_eq!(
            source,
            Some(clap::parser::ValueSource::CommandLine),
            "alias = command-line source (the conf precedence check shares the gate)"
        );
        // The `=` value form is accepted the same way.
        let (level, _) = alias_of(vec!["taiji", "--console-log-level=warn"].as_slice());
        assert_eq!(level.as_deref(), Some("warn"));
        // The same value-domain gate: out-of-domain values are refused
        // through the alias too.
        assert!(
            Cli::command()
                .try_get_matches_from(vec!["taiji", "--console-log-level", "verbose"])
                .is_err(),
            "alias must share the frozen value domain"
        );
        // Default (no flag) = None (the alias introduces zero behavior
        // change).
        let (level, _) = alias_of(vec!["taiji"].as_slice());
        assert_eq!(level, None);
    }

    /// Domain 3: `--log`/`--stderr` parsing and mutual exclusion — the
    /// bare and `=` dual forms accepted, defaults unchanged (None/false),
    /// the hard clap conflict (a usage refusal).
    #[test]
    fn log_and_stderr_flags_parse_and_conflict() {
        let parse = |args: &[&str]| {
            Cli::from_arg_matches(
                &Cli::command()
                    .try_get_matches_from(args)
                    .unwrap_or_else(|e| panic!("valid matches rejected: {e}")),
            )
            .unwrap_or_else(|e| panic!("matches to cli: {e}"))
        };
        // Defaults = no file, stderr off (zero change).
        let bare = parse(vec!["taiji"].as_slice());
        assert_eq!(bare.log, None);
        assert!(!bare.stderr);
        // --log: the path is accepted.
        let with_log = parse(vec!["taiji", "--log", "/tmp/t.log"].as_slice());
        assert_eq!(with_log.log, Some(PathBuf::from("/tmp/t.log")));
        // --stderr: the bare and `=` dual forms (the aria2 bool rule).
        assert!(parse(vec!["taiji", "--stderr"].as_slice()).stderr);
        assert!(parse(vec!["taiji", "--stderr=true"].as_slice()).stderr);
        assert!(!parse(vec!["taiji", "--stderr=false"].as_slice()).stderr);
        // Mutual exclusion: a dual target on the single log stream = a
        // hard clap conflict (the usage face, never silently picking
        // one).
        assert!(
            Cli::command()
                .try_get_matches_from(vec!["taiji", "--log", "/tmp/t.log", "--stderr"])
                .is_err(),
            "--log + --stderr must be a hard conflict"
        );
    }

    /// Domain 3: log stream assembly — the default Stdout / `--stderr` /
    /// the `--log` append+create file sink / the dual-target fail-fast /
    /// the unopenable-path fail-fast (the text carries the original
    /// path).
    #[test]
    fn log_target_assembly_and_fail_fast() {
        // The default and stderr arms (zero IO).
        assert!(matches!(
            open_log_target(false, None),
            Ok(LogTarget::Stdout)
        ));
        assert!(matches!(open_log_target(true, None), Ok(LogTarget::Stderr)));
        // The file arm: append+create — existing content preserved,
        // writes continue after it.
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "taiji-log-target-test-{}-{:?}.log",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
        ));
        std::fs::write(&path, b"pre\n").unwrap_or_else(|e| panic!("seed file: {e}"));
        use std::io::Write;
        let mut target = open_log_target(false, Some(&path)).unwrap_or_else(|e| panic!("{e}"));
        let LogTarget::File(f) = &mut target else {
            panic!("file path must assemble LogTarget::File");
        };
        f.write_all(b"post\n")
            .unwrap_or_else(|e| panic!("append write: {e}"));
        assert_eq!(
            std::fs::read(&path).unwrap_or_else(|e| panic!("read back: {e}")),
            b"pre\npost\n",
            "append+create keeps existing content and appends"
        );
        std::fs::remove_file(&path).unwrap_or_else(|e| panic!("cleanup: {e}"));
        // The dual target (reachable via conf; the CLI face is refused
        // up front by the clap conflicts_with).
        let Err(err) = open_log_target(true, Some(Path::new("/tmp/t.log"))) else {
            panic!("dual target must fail fast");
        };
        assert!(err.contains("mutually exclusive"), "{err}");
        // An unopenable path (a directory / a permission shape) = Err
        // and the text carries the original path.
        let Err(err) = open_log_target(false, Some(Path::new("/nonexistent-dir-taiji/t.log")))
        else {
            panic!("unopenable path must fail fast");
        };
        assert!(
            err.contains("/nonexistent-dir-taiji/t.log"),
            "error text carries the original path: {err}"
        );
    }

    /// Domain 3: the `--human-readable` observability format decision
    /// table — true (the default) = the format is kept; false = the
    /// machine-readable json face; an explicit `--log-format`
    /// (command-line source) always wins (the more specific flag takes
    /// precedence); a conf-provided log-format (a non-command-line
    /// source) is overridden by false.
    #[test]
    fn human_readable_resolves_observability_format() {
        let resolve = resolve_log_format;
        // The default true = zero change (text/json pass through).
        assert_eq!(resolve("text", true, false), "text");
        assert_eq!(resolve("json", true, false), "json");
        // false = the machine-readable face.
        assert_eq!(resolve("text", false, false), "json");
        // An explicit --log-format always wins (both directions).
        assert_eq!(resolve("text", false, true), "text");
        assert_eq!(resolve("json", true, true), "json");
    }

    /// Domain 3: the `--enable-color` switch — the parsing dual forms +
    /// the [`ansi_final`] truth table (default true = an identity on the
    /// existing TTY x NO_COLOR verdict; false = forced off; true does
    /// not force on — the non-TTY stays-clean discipline is unchanged).
    #[test]
    fn enable_color_switch_and_ansi_gate() {
        let parse = |args: &[&str]| {
            Cli::from_arg_matches(
                &Cli::command()
                    .try_get_matches_from(args)
                    .unwrap_or_else(|e| panic!("valid matches rejected: {e}")),
            )
            .unwrap_or_else(|e| panic!("matches to cli: {e}"))
        };
        // Default true (zero change) + the dual forms.
        assert!(parse(vec!["taiji"].as_slice()).enable_color);
        assert!(!parse(vec!["taiji", "--enable-color=false"].as_slice()).enable_color);
        assert!(parse(vec!["taiji", "--enable-color"].as_slice()).enable_color);
        // Truth table: the true arm = an identity on ansi_enabled; the
        // false arm is always off (even on a TTY).
        let set = Some(std::ffi::OsStr::new("1"));
        for &(tty, nc) in &[(true, None), (true, set), (false, None), (false, set)] {
            assert_eq!(
                ansi_final(tty, nc, true),
                ansi_enabled(tty, nc),
                "enable-color=true must be identity on tty={tty}"
            );
            assert!(
                !ansi_final(tty, nc, false),
                "enable-color=false must force ansi off (tty={tty})"
            );
        }
    }

    /// The domain 3 card-face pin (the verdict: the console UI
    /// family waits for the TUI crate split): `--daemon` (the libc fork
    /// face) / `--show-console-readout` / `--truncate-console-readout`
    /// stay out of the CLI acceptance face — unknown-option errors.
    /// Future wiring migrates this test first (making the acceptance-face
    /// change explicit).
    #[test]
    fn console_ui_family_cards_stay_out_of_cli_face() {
        for flag in [
            "--daemon",
            "--show-console-readout",
            "--truncate-console-readout",
        ] {
            assert!(
                Cli::command()
                    .try_get_matches_from(vec!["taiji", flag])
                    .is_err(),
                "{flag} must stay out of the CLI acceptance face"
            );
        }
    }

    /// crypto/µTP option surface — the bare flag and the `=` value
    /// forms (the sidecar spawn contract uses the `=` form); domains
    /// parsed from the frozen names.
    #[test]
    fn bt_crypto_and_connection_type_flags_parse() {
        let parse = |args: &[&str]| match Cli::command().try_get_matches_from(args) {
            Ok(m) => match Cli::from_arg_matches(&m) {
                Ok(cli) => (
                    cli.bt_require_crypto,
                    cli.bt_min_crypto_level,
                    cli.bt_peer_connection_type,
                ),
                Err(e) => panic!("valid matches rejected: {e}"),
            },
            Err(e) => panic!("flag must parse: {e}"),
        };
        // Defaults: false / plain / prefer-tcp.
        assert_eq!(
            parse(vec!["taiji"].as_slice()),
            (false, "plain".into(), "prefer-tcp".into())
        );
        // bare flag = true (aria2 bool-option dual form).
        assert!(parse(vec!["taiji", "--bt-require-crypto"].as_slice()).0);
        // `=` value forms.
        let (req, lvl, conn) = parse(
            vec![
                "taiji",
                "--bt-require-crypto=true",
                "--bt-min-crypto-level=arc4",
                "--bt-peer-connection-type=utp",
            ]
            .as_slice(),
        );
        assert!(req);
        assert_eq!(lvl, "arc4");
        assert_eq!(conn, "utp");
        // Invalid values = clap domain rejection (no silent default
        // fallback).
        assert!(
            Cli::command()
                .try_get_matches_from(vec!["taiji", "--bt-min-crypto-level=AES"].as_slice())
                .is_err()
        );
        assert!(
            Cli::command()
                .try_get_matches_from(vec!["taiji", "--bt-peer-connection-type=quic"].as_slice())
                .is_err()
        );
    }

    /// `--bt-lsd` dual-form acceptance (bare flag = true; `=` value
    /// form = the sidecar spawn contract); default false (frozen
    /// default).
    #[test]
    fn bt_lsd_accepts_bare_flag_and_eq_value_form() {
        let parse = |args: &[&str]| match Cli::command().try_get_matches_from(args) {
            Ok(m) => match Cli::from_arg_matches(&m) {
                Ok(cli) => cli.bt_lsd,
                Err(e) => panic!("valid matches rejected: {e}"),
            },
            Err(e) => panic!("flag must parse: {e}"),
        };
        assert!(!parse(vec!["taiji"].as_slice()), "default false (SPEC §11)");
        assert!(parse(vec!["taiji", "--bt-lsd"].as_slice()));
        assert!(parse(vec!["taiji", "--bt-lsd=true"].as_slice()));
        assert!(!parse(vec!["taiji", "--bt-lsd=false"].as_slice()));
        assert!(
            Cli::command()
                .try_get_matches_from(vec!["taiji", "--bt-lsd=yes"].as_slice())
                .is_err()
        );
    }

    /// `--enable-dht` dual-form acceptance (bare flag = true; `=`
    /// value form = the sidecar spawn contract); default **true**
    /// (frozen default, opposite to the false defaults of
    /// bt-lsd/bt-detach-seed-only).
    #[test]
    fn enable_dht_accepts_bare_flag_and_eq_value_form() {
        let parse = |args: &[&str]| match Cli::command().try_get_matches_from(args) {
            Ok(m) => match Cli::from_arg_matches(&m) {
                Ok(cli) => cli.enable_dht,
                Err(e) => panic!("valid matches rejected: {e}"),
            },
            Err(e) => panic!("flag must parse: {e}"),
        };
        assert!(
            parse(vec!["taiji"].as_slice()),
            "default true (SPEC §11 enable-dht)"
        );
        assert!(parse(vec!["taiji", "--enable-dht"].as_slice()));
        assert!(parse(vec!["taiji", "--enable-dht=true"].as_slice()));
        assert!(!parse(vec!["taiji", "--enable-dht=false"].as_slice()));
        // aria2 bool options accept only true/false (not yes/1).
        assert!(
            Cli::command()
                .try_get_matches_from(vec!["taiji", "--enable-dht=yes"].as_slice())
                .is_err()
        );
    }

    /// `--check-integrity` dual-form acceptance: bare flag = true;
    /// `=true|=false` value forms accepted; default **false** (same as
    /// aria2 `PREF_CHECK_INTEGRITY` — zero bare-mode behavior change);
    /// out-of-domain rejected.
    #[test]
    fn check_integrity_accepts_bare_flag_and_eq_value_form() {
        let parse = |args: &[&str]| match Cli::command().try_get_matches_from(args) {
            Ok(m) => match Cli::from_arg_matches(&m) {
                Ok(cli) => cli.check_integrity,
                Err(e) => panic!("valid matches rejected: {e}"),
            },
            Err(e) => panic!("flag must parse: {e}"),
        };
        assert!(
            !parse(vec!["taiji"].as_slice()),
            "default false (the aria2 PREF_CHECK_INTEGRITY rule, zero behavior difference)"
        );
        assert!(parse(vec!["taiji", "--check-integrity"].as_slice()));
        assert!(parse(vec!["taiji", "--check-integrity=true"].as_slice()));
        assert!(!parse(vec!["taiji", "--check-integrity=false"].as_slice()));
        // aria2 bool options accept only true/false (not yes/1).
        assert!(
            Cli::command()
                .try_get_matches_from(vec!["taiji", "--check-integrity=yes"].as_slice())
                .is_err()
        );
        // Invariant (require_equals): a boolean flag must not swallow
        // the positional — torrent stays positional (the same invariant
        // as --enable-rpc).
        let m = Cli::command()
            .try_get_matches_from(vec!["taiji", "--check-integrity", "x.torrent"])
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        let cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
        assert!(cli.check_integrity);
        assert_eq!(
            cli.torrent,
            Some(std::path::PathBuf::from("x.torrent")),
            "the positional must not be swallowed as the flag's optional value"
        );
    }

    /// outcome -> preset mapping: bitmap columns map field-for-field
    /// (both the v1 full-bitfield and v2-only per-file forms);
    /// suspended files' all-zero entries map verbatim (bare mode has no
    /// previous-session values to preserve).
    #[test]
    fn preset_progress_from_outcome_maps_bitfield_columns_verbatim() {
        let v1 = taiji_core::session::RecheckOutcome {
            v1_bitfield: Some(vec![0b1100_0000]),
            v2_file_bits: None,
            verified: 2,
            total: 2,
            suspended_files: Vec::new(),
        };
        assert_eq!(
            preset_progress_from_outcome(&v1),
            taiji_core::engine::PresetProgress {
                v1_bitfield: Some(vec![0b1100_0000]),
                v2_file_bits: None,
            }
        );
        // v2-only: per-file bitmap maps verbatim (including all-zero
        // entries for suspended files).
        let v2 = taiji_core::session::RecheckOutcome {
            v1_bitfield: None,
            v2_file_bits: Some(vec![
                0,
                0,
                0,
                1, // file 0
                0,
                0,
                0,
                2,           // 2 pieces
                0b1000_0000, // piece 0 verified
            ]),
            verified: 1,
            total: 2,
            suspended_files: vec![1],
        };
        assert_eq!(
            preset_progress_from_outcome(&v2),
            taiji_core::engine::PresetProgress {
                v1_bitfield: None,
                v2_file_bits: v2.v2_file_bits.clone(),
            }
        );
    }

    /// `--rpc-listen-all` dual-form acceptance (bare flag and
    /// `=true|=false` both allowed, mirroring aria2
    /// TEXT_RPC_LISTEN_ALL's `[=true|false]` form in usage_text.h);
    /// default **false** (OptionHandlerFactory.cc A2_V_FALSE —
    /// loopback-only by default).
    #[test]
    fn rpc_listen_all_accepts_bare_flag_and_eq_value_form() {
        let parse = |args: &[&str]| match Cli::command().try_get_matches_from(args) {
            Ok(m) => match Cli::from_arg_matches(&m) {
                Ok(cli) => cli.rpc_listen_all,
                Err(e) => panic!("valid matches rejected: {e}"),
            },
            Err(e) => panic!("flag must parse: {e}"),
        };
        assert!(
            !parse(vec!["taiji"].as_slice()),
            "default false (loopback only, the aria2 A2_V_FALSE rule)"
        );
        assert!(parse(vec!["taiji", "--rpc-listen-all"].as_slice()));
        assert!(parse(vec!["taiji", "--rpc-listen-all=true"].as_slice()));
        assert!(!parse(vec!["taiji", "--rpc-listen-all=false"].as_slice()));
        // aria2 bool options accept only true/false (not yes/1).
        assert!(
            Cli::command()
                .try_get_matches_from(vec!["taiji", "--rpc-listen-all=yes"].as_slice())
                .is_err()
        );
    }

    /// `--bt-tracker` / `--bt-tracker-file` into the CLI option
    /// surface of both modes (frozen names + value forms; default
    /// empty = no import).
    #[test]
    fn bt_tracker_args_parse_with_frozen_names() {
        let parse = |args: &[&str]| match Cli::command().try_get_matches_from(args) {
            Ok(m) => match Cli::from_arg_matches(&m) {
                Ok(cli) => Some((cli.bt_tracker, cli.bt_tracker_file)),
                Err(e) => panic!("valid matches rejected: {e}"),
            },
            Err(_) => None,
        };
        // Default: empty string + no file.
        let (tracker, file) = parse(vec!["taiji"].as_slice()).unwrap_or_else(|| panic!("default"));
        assert_eq!(tracker, "");
        assert!(file.is_none());
        // Explicit values + the `=` form (aria2 value forms).
        let (tracker, file) = parse(
            vec![
                "taiji",
                "--bt-tracker=udp://a:6969/announce,udp://b:1337/announce",
                "--bt-tracker-file=/list/all.txt",
            ]
            .as_slice(),
        )
        .unwrap_or_else(|| panic!("explicit"));
        assert_eq!(tracker, "udp://a:6969/announce,udp://b:1337/announce");
        assert_eq!(file, Some(PathBuf::from("/list/all.txt")));
        // Parsing: split_bt_tracker (the single core option parser).
        assert_eq!(
            taiji_core::session::split_bt_tracker(&tracker),
            vec!["udp://a:6969/announce", "udp://b:1337/announce"]
        );
    }

    /// `--listen-port` explicit value form into the CLI.
    #[test]
    fn listen_port_accepts_explicit_value() {
        let m = Cli::command()
            .try_get_matches_from(vec!["taiji", "--listen-port", "58013"])
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        let cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(cli.listen_port, 58013);
    }

    /// `--bt-enable-upnp` / `--bt-enable-nat-pmp` dual-form acceptance
    /// (bare flag and `=` value forms); default **false** (zero
    /// behavior change by default — no aria2 option to mirror; the
    /// libtorrent settings_pack.cpp default-true contrast note is in
    /// the Cli field docs).
    #[test]
    fn bt_enable_upnp_and_natpmp_parse_bare_flag_and_eq_value_form() {
        let parse = |args: &[&str]| match Cli::command().try_get_matches_from(args) {
            Ok(m) => match Cli::from_arg_matches(&m) {
                Ok(cli) => (cli.bt_enable_upnp, cli.bt_enable_natpmp),
                Err(e) => panic!("valid matches rejected: {e}"),
            },
            Err(e) => panic!("flag must parse: {e}"),
        };
        // Both off by default (zero behavior change).
        assert_eq!(parse(vec!["taiji"].as_slice()), (false, false));
        // bare flag = true (aria2 bool-option dual form).
        assert_eq!(
            parse(vec!["taiji", "--bt-enable-upnp"].as_slice()),
            (true, false)
        );
        assert_eq!(
            parse(vec!["taiji", "--bt-enable-nat-pmp"].as_slice()),
            (false, true)
        );
        // `=` value forms (sidecar spawn contract).
        assert_eq!(
            parse(vec!["taiji", "--bt-enable-upnp=true"].as_slice()),
            (true, false)
        );
        assert_eq!(
            parse(vec!["taiji", "--bt-enable-upnp=true", "--bt-enable-nat-pmp=true"].as_slice()),
            (true, true)
        );
        assert_eq!(
            parse(vec!["taiji", "--bt-enable-nat-pmp=false"].as_slice()),
            (false, false)
        );
        // aria2 bool options accept only true/false (not yes/1).
        assert!(
            Cli::command()
                .try_get_matches_from(vec!["taiji", "--bt-enable-upnp=yes"].as_slice())
                .is_err()
        );
        assert!(
            Cli::command()
                .try_get_matches_from(vec!["taiji", "--bt-enable-nat-pmp=1"].as_slice())
                .is_err()
        );
    }

    /// Bare intake parse gate — no tracker + DHT on -> accept (pure
    /// DHT discovery, no notice); DHT off -> **accept + WARN** (the
    /// stall-state recovery paths exist; the text matches the session
    /// addTorrent gate, both arms locked).
    #[test]
    fn trackerless_metainfo_intake_follows_dht_flag() {
        let info = taiji_bt::bencode::Value::Dict(vec![
            (b"length".to_vec(), taiji_bt::bencode::Value::Int(16384)),
            (
                b"name".to_vec(),
                taiji_bt::bencode::Value::Bytes(b"blob.bin".to_vec()),
            ),
            (
                b"piece length".to_vec(),
                taiji_bt::bencode::Value::Int(16384),
            ),
            (
                b"pieces".to_vec(),
                taiji_bt::bencode::Value::Bytes(vec![0u8; 20]),
            ),
        ]);
        let top = taiji_bt::bencode::Value::Dict(vec![(b"info".to_vec(), info)]);
        let bytes = taiji_bt::bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"));

        // DHT-on arm: accepted, announce = an empty-string sentinel (no
        // fake URL).
        let meta = parse_metainfo_intake(&bytes, true).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(meta.announce, "");

        // DHT-off arm: accepted + WARN — guidance matches the session
        // gate (hot-enable DHT / add tracker / restart).
        let meta = parse_metainfo_intake(&bytes, false).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(meta.announce, "");
        let warn = meta
            .check_intake(false)
            .unwrap_or_else(|| panic!("DHT off + no tracker must produce the stall WARN"));
        assert!(
            warn.contains("enable-dht") && warn.contains("bt-disable-dht"),
            "{warn}"
        );
    }

    /// `--enable-rpc` dual-form acceptance (bare flag and
    /// `=true|=false` value forms both allowed, mirroring aria2
    /// OptionHandlerFactory.cc's OPT_ARG form); default **false**
    /// (A2_V_FALSE — the default bare path is unchanged).
    #[test]
    fn enable_rpc_accepts_bare_flag_and_eq_value_form() {
        let parse = |args: &[&str]| match Cli::command().try_get_matches_from(args) {
            Ok(m) => match Cli::from_arg_matches(&m) {
                Ok(cli) => cli.enable_rpc,
                Err(e) => panic!("valid matches rejected: {e}"),
            },
            Err(e) => panic!("flag must parse: {e}"),
        };
        assert!(
            !parse(vec!["taiji"].as_slice()),
            "default false (OptionHandlerFactory.cc A2_V_FALSE, same rule)"
        );
        assert!(parse(vec!["taiji", "--enable-rpc"].as_slice()));
        assert!(parse(vec!["taiji", "--enable-rpc=true"].as_slice()));
        assert!(!parse(vec!["taiji", "--enable-rpc=false"].as_slice()));
        // aria2 bool options accept only true/false (not yes/1).
        assert!(
            Cli::command()
                .try_get_matches_from(vec!["taiji", "--enable-rpc=yes"].as_slice())
                .is_err()
        );
        // require_equals invariant: when a dual-form boolean flag
        // precedes the positional, the positional must not be swallowed
        // as the flag's optional value (values only via `=`; the bare
        // form stays = default_missing_value semantics unchanged).
        let parse_with_positional = |args: &[&str]| match Cli::command().try_get_matches_from(args)
        {
            Ok(m) => match Cli::from_arg_matches(&m) {
                Ok(cli) => (cli.enable_rpc, cli.torrent),
                Err(e) => panic!("valid matches rejected: {e}"),
            },
            Err(e) => panic!("flag before positional must parse: {e}"),
        };
        // a) bare flag first + positional: parses and the positional
        // stays [TORRENT] (previously swallowed as the flag's value ->
        // usage error).
        assert_eq!(
            parse_with_positional(vec!["taiji", "--enable-rpc", "x.torrent"].as_slice()),
            (true, Some(PathBuf::from("x.torrent")))
        );
        // b) `=false` value form first + positional: value via `=`,
        // positional intact.
        assert_eq!(
            parse_with_positional(vec!["taiji", "--enable-rpc=false", "x.torrent"].as_slice()),
            (false, Some(PathBuf::from("x.torrent")))
        );
        // c) another dual-form flag (--bt-lsd) repeats form a: bare
        // first also does not swallow the positional.
        let m = Cli::command()
            .try_get_matches_from(vec!["taiji", "--bt-lsd", "x.torrent"].as_slice())
            .unwrap_or_else(|e| panic!("flag before positional must parse: {e}"));
        let cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("matches to cli: {e}"));
        assert!(cli.bt_lsd);
        assert_eq!(cli.torrent, Some(PathBuf::from("x.torrent")));
    }

    /// Truth table for the silent no-op conflict arm — download mode +
    /// RPC group options **explicitly given** + `--enable-rpc` off ->
    /// Some(explicit items); defaults never trigger (the value_source
    /// test); `--enable-rpc` (including explicit =false) or idle mode
    /// never triggers; rpc-* options outside the enumerated set are
    /// not in the arm.
    #[test]
    fn rpc_group_conflict_truth_table() {
        let verdict = |args: &[&str]| {
            let m = Cli::command()
                .try_get_matches_from(args)
                .unwrap_or_else(|e| panic!("must parse: {e}"));
            let cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
            rpc_group_conflict(cli.torrent.is_some(), cli.enable_rpc, &m)
        };
        // The old silent no-op behavior is now a hard error (download
        // + rpc-listen-port).
        assert_eq!(
            verdict(vec!["taiji", "x.torrent", "--rpc-listen-port", "16801"].as_slice()),
            Some(vec!["--rpc-listen-port"])
        );
        // The remaining group items arm one by one
        // (secret/user/passwd/aria2-compat).
        assert_eq!(
            verdict(vec!["taiji", "x.torrent", "--rpc-secret", "s"].as_slice()),
            Some(vec!["--rpc-secret"])
        );
        assert_eq!(
            verdict(vec!["taiji", "x.torrent", "--rpc-user", "u"].as_slice()),
            Some(vec!["--rpc-user"])
        );
        assert_eq!(
            verdict(vec!["taiji", "x.torrent", "--rpc-passwd", "p"].as_slice()),
            Some(vec!["--rpc-passwd"])
        );
        assert_eq!(
            verdict(vec!["taiji", "x.torrent", "--rpc-aria2-compat"].as_slice()),
            Some(vec!["--rpc-aria2-compat"])
        );
        // Multiple at once = all listed (complete guidance in the
        // text).
        assert_eq!(
            verdict(
                vec![
                    "taiji",
                    "x.torrent",
                    "--rpc-secret=s",
                    "--rpc-listen-port=1"
                ]
                .as_slice()
            ),
            Some(vec!["--rpc-listen-port", "--rpc-secret"])
        );
        // Defaults never trigger (rpc-listen-port's default 6800 is
        // not explicit — bare mode unchanged).
        assert_eq!(verdict(vec!["taiji", "x.torrent"].as_slice()), None);
        // --enable-rpc on -> group options take effect, no conflict.
        assert_eq!(
            verdict(
                vec![
                    "taiji",
                    "x.torrent",
                    "--enable-rpc",
                    "--rpc-listen-port",
                    "1"
                ]
                .as_slice()
            ),
            None
        );
        // Explicit --enable-rpc=false also counts as off (the group
        // options would still be ignored — no silence; the error text
        // points at --enable-rpc or removal).
        assert_eq!(
            verdict(
                vec![
                    "taiji",
                    "x.torrent",
                    "--enable-rpc=false",
                    "--rpc-listen-port",
                    "1"
                ]
                .as_slice()
            ),
            Some(vec!["--rpc-listen-port"])
        );
        // Idle mode unrestricted (idle is the daemon form; RPC group
        // options naturally apply).
        assert_eq!(
            verdict(vec!["taiji", "--rpc-listen-port", "16801"].as_slice()),
            None
        );
        // rpc-* options outside the enumerated set are not in the arm
        // (listen-all/allow-origin-all/max-request-size stay accepted
        // without error).
        assert_eq!(
            verdict(vec!["taiji", "x.torrent", "--rpc-listen-all"].as_slice()),
            None
        );
    }

    /// rpc-secret normalization — CLI empty/whitespace-only = unset
    /// (aria2 empty-string = unset semantics; the trim tightening also
    /// makes pure whitespace unset), non-empty values are trimmed (the
    /// guard and AppState consume the same normalized result).
    #[test]
    fn rpc_config_from_cli_normalizes_blank_secret() {
        let cfg_of = |args: &[&str]| {
            let m = Cli::command()
                .try_get_matches_from(args)
                .unwrap_or_else(|e| panic!("must parse: {e}"));
            let cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
            rpc_config_from_cli(&cli)
        };
        assert_eq!(cfg_of(["taiji"].as_slice()).secret, None, "unset");
        assert_eq!(
            cfg_of(["taiji", "--rpc-secret", ""].as_slice()).secret,
            None,
            "empty string = unset"
        );
        assert_eq!(
            cfg_of(["taiji", "--rpc-secret", "   "].as_slice()).secret,
            None,
            "pure whitespace = unset"
        );
        assert_eq!(
            cfg_of(["taiji", "--rpc-secret", "  s3cr3t  "].as_slice()).secret,
            Some("s3cr3t".to_string()),
            "non-empty values are trimmed"
        );
    }

    /// Domain B: the RPC TLS family decision table —
    /// `--rpc-secure/certificate/private-key` map straight into
    /// [`rpc_config_from_cli`] (the default = the plaintext form, zero
    /// change; both the bare flag and the `=true|=false` dual forms are
    /// accepted; pair validation belongs to the serve assembly point,
    /// only the mapping face is locked here).
    #[test]
    fn rpc_tls_family_maps_into_rpc_config() {
        let cfg_of = |args: &[&str]| {
            let m = Cli::command()
                .try_get_matches_from(args)
                .unwrap_or_else(|e| panic!("must parse: {e}"));
            let cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
            rpc_config_from_cli(&cli)
        };
        let dflt = cfg_of(["taiji"].as_slice());
        assert!(
            !dflt.secure,
            "the default = plaintext (the zero-behavior-change anchor)"
        );
        assert!(dflt.certificate.is_none() && dflt.private_key.is_none());
        let on = cfg_of(
            [
                "taiji",
                "--rpc-secure",
                "--rpc-certificate=/etc/rpc.pem",
                "--rpc-private-key=/etc/rpc.key",
            ]
            .as_slice(),
        );
        assert!(on.secure, "bare flag = true (default_missing_value)");
        assert_eq!(on.certificate, Some(PathBuf::from("/etc/rpc.pem")));
        assert_eq!(on.private_key, Some(PathBuf::from("/etc/rpc.key")));
        let off = cfg_of(["taiji", "--rpc-secure=false"].as_slice());
        assert!(!off.secure, "the =false value form is accepted");
    }

    /// Domain B: the RPC TLS family enters the conflict arm
    /// (explicitly given in download mode without --enable-rpc = the
    /// hard-error verdict; a truth-table check after the in-group
    /// enumeration table grew by three items).
    #[test]
    fn rpc_tls_family_in_group_conflict_arm() {
        let verdict = |args: &[&str]| {
            let m = Cli::command()
                .try_get_matches_from(args)
                .unwrap_or_else(|e| panic!("must parse: {e}"));
            let cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
            rpc_group_conflict(crate::download_mode_given(&cli), cli.enable_rpc, &m)
        };
        // Download mode (.torrent positional) + secure explicitly given,
        // RPC off -> conflict.
        assert_eq!(
            verdict(vec!["taiji", "x.torrent", "--rpc-secure"].as_slice()),
            Some(vec!["--rpc-secure"])
        );
        // Same for the certificate/private key (each enters the arm on
        // its own).
        assert_eq!(
            verdict(vec!["taiji", "x.torrent", "--rpc-certificate=/c.pem"].as_slice()),
            Some(vec!["--rpc-certificate"])
        );
        assert_eq!(
            verdict(vec!["taiji", "x.torrent", "--rpc-private-key=/k.pem"].as_slice()),
            Some(vec!["--rpc-private-key"])
        );
        // The --input-file batch form is judged the same
        // (download_mode_given covers the batch list).
        assert_eq!(
            verdict(vec!["taiji", "--input-file", "u.txt", "--rpc-secure"].as_slice()),
            Some(vec!["--rpc-secure"])
        );
        // --enable-rpc disarms the conflict arm.
        assert_eq!(
            verdict(
                vec![
                    "taiji",
                    "--enable-rpc",
                    "--rpc-secure",
                    "--rpc-certificate=/c.pem",
                    "--rpc-private-key=/k.pem"
                ]
                .as_slice()
            ),
            None
        );
        // The idle form is unrestricted (defaults never trigger —
        // rpc-secure defaults false, not explicit).
        assert_eq!(verdict(vec!["taiji"].as_slice()), None);
    }

    /// Domain B: the client TLS three-flag value domain / pair face (the
    /// clap parse layer) — the min-tls version domain is frozen
    /// (tls1.2|tls1.3) and the mTLS path pair is accepted (pair
    /// validation belongs to the transport build point, the CLI face
    /// does not re-judge).
    #[test]
    fn client_tls_family_cli_domain() {
        let parse = |args: &[&str]| Cli::command().try_get_matches_from(args.to_vec());
        assert!(
            parse(vec!["taiji", "--min-tls-version", "tls1.1"].as_slice()).is_err(),
            "out-of-domain versions must be rejected"
        );
        assert!(
            parse(vec!["taiji", "--min-tls-version", "TLSv1.2"].as_slice()).is_err(),
            "the aria2 original literal is out of domain (the v-less lowercase form)"
        );
        let m = parse(vec!["taiji", "--min-tls-version", "tls1.3"].as_slice())
            .unwrap_or_else(|e| panic!("must parse: {e}"));
        let cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(cli.min_tls_version.as_deref(), Some("tls1.3"));
        // The mTLS pair: both flags given together = accepted (the
        // values are the verbatim paths).
        let m = parse(
            vec![
                "taiji",
                "--certificate=/c.pem",
                "--private-key=/k.pem",
                "https://h/f.bin",
            ]
            .as_slice(),
        )
        .unwrap_or_else(|e| panic!("must parse: {e}"));
        let cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(cli.certificate, Some(PathBuf::from("/c.pem")));
        assert_eq!(cli.private_key, Some(PathBuf::from("/k.pem")));
    }

    /// Decision table: the top-level `--summary-interval` flag —
    /// default 60 (SUMMARY_INTERVAL_DEFAULT), 0 = disabled, the
    /// INT32_MAX upper bound accepted; out-of-range (upper + 1) /
    /// negatives = clap domain rejection. No conflict when combined
    /// with a URL positional (not an RPC group option; the positional
    /// form is injected into the http pipeline via delegate_positional).
    #[test]
    fn summary_interval_flag_decision_table() {
        let parse = |args: &[&str]| {
            let m = Cli::command()
                .try_get_matches_from(args)
                .unwrap_or_else(|e| panic!("must parse: {e}"));
            Cli::from_arg_matches(&m)
                .map(|cli| (cli.summary_interval, cli.torrent.clone()))
                .unwrap_or_else(|e| panic!("valid matches rejected: {e}"))
        };
        // Default 60 (aria2 OptionHandlerFactory.cc rule).
        let (interval, torrent) = parse(vec!["taiji"].as_slice());
        assert_eq!(interval, taiji_core::session::SUMMARY_INTERVAL_DEFAULT);
        assert_eq!(torrent, None);
        // 0 = disabled; combined with a URL positional (the injection
        // entry for the positional URL form).
        let (interval, torrent) =
            parse(vec!["taiji", "--summary-interval=0", "http://h/f.bin"].as_slice());
        assert_eq!(interval, 0, "0 = disabled");
        assert_eq!(
            torrent,
            Some(PathBuf::from("http://h/f.bin")),
            "the flag must not swallow the positional (the value form passes via =)"
        );
        // Space value form + explicit value.
        let (interval, _) = parse(vec!["taiji", "--summary-interval", "90"].as_slice());
        assert_eq!(interval, 90);
        // Extreme value: the INT32_MAX upper bound accepted.
        let (interval, _) = parse(vec!["taiji", "--summary-interval=2147483647"].as_slice());
        assert_eq!(interval, taiji_core::session::SUMMARY_INTERVAL_MAX);
        // Out-of-range = clap domain rejection (upper + 1; negatives
        // are outside u32).
        assert!(
            Cli::command()
                .try_get_matches_from(vec!["taiji", "--summary-interval=2147483648"])
                .is_err(),
            "the upper bound + 1 must be rejected"
        );
        assert!(
            Cli::command()
                .try_get_matches_from(vec!["taiji", "--summary-interval=-1"])
                .is_err(),
            "negatives must be rejected"
        );
    }

    // ---- domain A: the --input-file batch face (line parsing / the
    // read cap / mutual exclusion / the RPC gate / option merging) ----

    /// The domain A line-parse decision table (the [`parse_input_file_lines`]
    /// pure function; mirrors aria2 UriListParser.cc line
    /// semantics + taiji hardening):
    /// - a leading BOM is stripped; blank/whitespace-only/`#` comment
    ///   lines are skipped; CRLF tolerated;
    /// - only a line-leading `#` is a comment (the URI fragment `#frag`
    ///   is preserved verbatim);
    /// - tab split: the first token = the target, the rest `key=value`
    ///   (split on the first `=`, an inner `=` verbatim — the checksum
    ///   six-hash value-domain case); whitespace on both sides of a
    ///   token is stripped;
    /// - a token missing `=` / with an empty key = the line is
    ///   Malformed (line number + reason kept explicitly, never silently
    ///   dropped); 1-based line numbers travel with the entries.
    #[test]
    fn input_file_line_parser_decision_table() {
        let text = "\u{feff}# header comment\n\
                    \n   \n\
                    \t \n\
                    https://a.test/f.bin\r\n\
                    magnet:?xt=urn:btih:abc&dn=x#frag\n\
                    http://b.test/f\tout=name\tmax-download-limit=5M\n\
                    http://c.test/f\tchecksum=sha-256=abc123\n\
                    http://d.test/f\tbroken-option\n\
                    http://e.test/f\t=no-key\n";
        let lines = parse_input_file_lines(text);
        assert_eq!(
            lines.len(),
            6,
            "BOM/comments/blank lines/pure-tab lines all skipped: 6 tasks/malformed lines"
        );
        assert_eq!(
            lines[0],
            InputFileLine::Task {
                line_no: 5,
                target: "https://a.test/f.bin".to_string(),
                options: Default::default(),
            },
            "a plain URI line: no tab options"
        );
        assert_eq!(
            lines[1],
            InputFileLine::Task {
                line_no: 6,
                target: "magnet:?xt=urn:btih:abc&dn=x#frag".to_string(),
                options: Default::default(),
            },
            "only a line-leading # is a comment: the URI fragment is preserved verbatim"
        );
        assert_eq!(
            lines[2],
            InputFileLine::Task {
                line_no: 7,
                target: "http://b.test/f".to_string(),
                options: std::collections::BTreeMap::from([
                    ("out".to_string(), "name".to_string()),
                    ("max-download-limit".to_string(), "5M".to_string()),
                ]),
            },
            "tab option surface: multiple key=value entries enter the table one by one"
        );
        assert_eq!(
            lines[3],
            InputFileLine::Task {
                line_no: 8,
                target: "http://c.test/f".to_string(),
                options: std::collections::BTreeMap::from([(
                    "checksum".to_string(),
                    "sha-256=abc123".to_string(),
                )]),
            },
            "split on the first =: an inner = is preserved verbatim"
        );
        let InputFileLine::Malformed { line_no, reason } = &lines[4] else {
            panic!("a token missing = must be Malformed");
        };
        assert_eq!(*line_no, 9, "1-based line numbers travel with the entries");
        assert!(reason.contains("broken-option"), "{reason}");
        let InputFileLine::Malformed { line_no: l9, .. } = &lines[5] else {
            panic!("an empty-key token must be Malformed");
        };
        assert_eq!(*l9, 10);
    }

    /// The domain A read cap (the 1 MiB pre-read precheck + post-read
    /// recheck — the same shape as bt-tracker-file): a normal list reads
    /// in as usual; over the cap = Oversize (the cap comes first, the
    /// read never happens — a sparse file constructs an oversized
    /// logical size); missing = the Io face.
    #[tokio::test]
    async fn input_file_read_bounded_prechecks_size() {
        let root = std::env::temp_dir().join(format!("tj-inputfile-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let ok = root.join("ok.txt");
        std::fs::write(&ok, b"http://a/f.bin\n# c\n").unwrap_or_else(|e| panic!("write: {e}"));
        let bytes = read_input_file_bounded(ok.clone())
            .await
            .unwrap_or_else(|e| panic!("small must read: {e:?}"));
        assert_eq!(bytes, b"http://a/f.bin\n# c\n");
        // Sparse file: set_len raises the logical size — the Oversize
        // branch returns before the read.
        let big = root.join("big.txt");
        let f = std::fs::File::create(&big).unwrap_or_else(|e| panic!("create: {e}"));
        f.set_len(INPUT_FILE_MAX_BYTES as u64 + 1)
            .unwrap_or_else(|e| panic!("set_len: {e}"));
        drop(f);
        let err = match read_input_file_bounded(big.clone()).await {
            Err(e) => e,
            Ok(_) => panic!("oversize must be refused before read"),
        };
        let InputFileReadError::Oversize { got, limit } = err else {
            panic!("expected Oversize, got {err:?}");
        };
        assert_eq!(got, INPUT_FILE_MAX_BYTES as u64 + 1);
        assert_eq!(limit, INPUT_FILE_MAX_BYTES as u64);
        let missing = read_input_file_bounded(root.join("missing.txt")).await;
        assert!(
            matches!(missing, Err(InputFileReadError::Io(_))),
            "{missing:?}"
        );
        let _ = std::fs::remove_file(&ok);
        let _ = std::fs::remove_file(&big);
        let _ = std::fs::remove_dir(&root);
    }

    /// The domain A mutual-exclusion decision table: --input-file is
    /// mutually exclusive with the [TORRENT] positional — the clap
    /// conflict arm rejects both orders (the exit 2 face), alone it is
    /// accepted (both the space and `=` value forms), a missing value is
    /// rejected.
    #[test]
    fn input_file_conflicts_with_positional_decision_table() {
        assert!(
            Cli::command()
                .try_get_matches_from(["taiji", "--input-file", "u.txt", "x.torrent"])
                .is_err(),
            "the flag first + the positional must be rejected"
        );
        assert!(
            Cli::command()
                .try_get_matches_from(["taiji", "x.torrent", "--input-file", "u.txt"])
                .is_err(),
            "the positional first + the flag must be rejected"
        );
        assert_eq!(
            cli_of(&["taiji", "--input-file", "u.txt"]).input_file,
            Some(PathBuf::from("u.txt"))
        );
        assert_eq!(
            cli_of(&["taiji", "--input-file=u.txt"]).input_file,
            Some(PathBuf::from("u.txt"))
        );
        assert!(
            Cli::command()
                .try_get_matches_from(["taiji", "--input-file"])
                .is_err(),
            "a missing value must be rejected"
        );
    }

    /// The domain A RPC-gate coverage decision table (the
    /// [`download_mode_given`] criterion face): a batch list present =
    /// download mode — RPC group options explicitly given without
    /// --enable-rpc = the hard-error face (same as the positional-arg
    /// download form, no silence); an explicit --enable-rpc disarms the
    /// group conflict arm; no group options = no trigger; the idle form
    /// (no list, no positional) is unrestricted.
    #[test]
    fn input_file_rpc_gates_cover_batch_form() {
        let verdict = |args: &[&str]| {
            let m = Cli::command()
                .try_get_matches_from(args)
                .unwrap_or_else(|e| panic!("must parse: {e}"));
            let cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
            (
                download_mode_given(&cli),
                rpc_group_conflict(download_mode_given(&cli), cli.enable_rpc, &m),
                conf_enable_rpc_download_conflict(download_mode_given(&cli), cli.enable_rpc, &m),
            )
        };
        let (dm, conflict, conf_conflict) =
            verdict(["taiji", "--input-file", "u.txt", "--rpc-secret", "s"].as_slice());
        assert!(dm, "a batch list present = download mode");
        assert_eq!(
            conflict,
            Some(vec!["--rpc-secret"]),
            "the group-option hard-error face covers the batch form"
        );
        assert!(
            !conf_conflict,
            "enable-rpc defaults false -> the conf restriction arm does not fire"
        );
        let (_, conflict, _) = verdict(
            [
                "taiji",
                "--input-file",
                "u.txt",
                "--enable-rpc",
                "--rpc-secret",
                "s",
            ]
            .as_slice(),
        );
        assert_eq!(
            conflict, None,
            "an explicit --enable-rpc releases the group conflict arm"
        );
        let (_, conflict, _) = verdict(["taiji", "--input-file", "u.txt"].as_slice());
        assert_eq!(conflict, None, "no group options = no trigger");
        let (dm, conflict, _) = verdict(["taiji", "--rpc-listen-port", "16801"].as_slice());
        assert!(!dm, "the idle form (no list, no positional)");
        assert_eq!(conflict, None, "the idle form is unrestricted");
    }

    /// The domain A task-option assembly decision table: the shared
    /// knobs (rate limits/watchdog — keys written only when explicitly
    /// non-zero, the default empty table = zero behavior change) + the
    /// kind delta (the magnet three families / the .torrent sequential
    /// download and webseed shutdown / zero delta for WebUri — the aria2
    /// "only when Magnet URI is used" rule) + the merge order (in-line
    /// tab > CLI shared > kind — per-line override semantics).
    #[test]
    fn input_file_task_options_merge_decision_table() {
        // Default face: all three knobs zero -> an empty table (the
        // default writes no keys).
        let cli = cli_of(&["taiji"]);
        assert!(cli_shared_task_options(&cli).is_empty());
        // Explicit face: the three knobs map straight through (size
        // literals are 1024-based, converted at the clap parse face).
        let cli = cli_of(&[
            "taiji",
            "--max-download-limit=5M",
            "--max-upload-limit=1M",
            "--bt-stop-timeout",
            "90",
        ]);
        let shared = cli_shared_task_options(&cli);
        assert_eq!(
            shared.get("max-download-limit").map(String::as_str),
            Some("5242880")
        );
        assert_eq!(
            shared.get("max-upload-limit").map(String::as_str),
            Some("1048576")
        );
        assert_eq!(
            shared.get("bt-stop-timeout").map(String::as_str),
            Some("90")
        );
        // Kind delta: the magnet line's three families (keys written
        // only when set).
        let cli = cli_of(&[
            "taiji",
            "--bt-save-metadata",
            "--bt-metadata-only",
            "--bt-load-saved-metadata",
        ]);
        let magnet = classify_positional(std::ffi::OsStr::new("magnet:?xt=urn:btih:ab"));
        let extra = kind_extra_task_options(&cli, &magnet);
        assert_eq!(
            extra.get("bt-save-metadata").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            extra.get("bt-metadata-only").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            extra.get("bt-load-saved-metadata").map(String::as_str),
            Some("true")
        );
        // WebUri lines have no delta (the HTTP task face's key domain
        // belongs to the session parse_task_options).
        let web = classify_positional(std::ffi::OsStr::new("http://a/f.bin"));
        assert!(kind_extra_task_options(&cli, &web).is_empty());
        // .torrent lines: sequential download (written only when set) +
        // the webseed shutdown (written only on explicit false).
        let cli = cli_of(&[
            "taiji",
            "--bt-sequential-download",
            "--enable-http-seeding=false",
        ]);
        let torrent = classify_positional(std::ffi::OsStr::new("x.torrent"));
        let extra = kind_extra_task_options(&cli, &torrent);
        assert_eq!(
            extra.get("bt-sequential-download").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            extra.get("enable-http-seeding").map(String::as_str),
            Some("false")
        );
        // Merge order (the run_input_file order): the kind delta -> the
        // CLI shared -> the in-line tab (written later overrides) — the
        // line value overrides the CLI value, the kind keys are
        // unaffected by the shared arm.
        let mut merged = kind_extra_task_options(&cli, &torrent);
        let cli2 = cli_of(&["taiji", "--max-download-limit=5M"]);
        merged.extend(cli_shared_task_options(&cli2));
        merged.extend([("max-download-limit".to_string(), "1M".to_string())]);
        assert_eq!(
            merged.get("max-download-limit").map(String::as_str),
            Some("1M"),
            "an in-line tab option overrides the CLI shared value (per-line override \
             semantics -- the value passes through verbatim; size conversion \
             belongs to the session parse_task_options)"
        );
        assert_eq!(
            merged.get("bt-sequential-download").map(String::as_str),
            Some("true"),
            "the kind delta keys are unaffected by the later merge arms"
        );
    }

    /// The domain A summarized exit-code truth table (the ask contract):
    /// any failure = 1, all passed = 0; a signal interrupt does not go
    /// through this function (the polling select arm breaks with 1
    /// directly — the documented-declaration face).
    #[test]
    fn input_file_exit_code_truth_table() {
        assert_eq!(input_file_exit_code(false), 0, "all passed = 0");
        assert_eq!(input_file_exit_code(true), 1, "any failure = 1");
    }

    /// The domain A memory face / linearity (the 100k-line scale): the
    /// parse pure function handles a 100k-line list in <1s and its
    /// output is <= the input bytes (no superlinear amplification path)
    /// — the list text is always pinned by the read cap
    /// [`INPUT_FILE_MAX_BYTES`] (a realistic-URI-length 100k-line list
    /// starts at ~3MB, over cap = refused with exit 2); this test pins
    /// that the parse face itself is not a second amplification point.
    #[test]
    fn input_file_parser_scales_to_100k_lines_under_1s() {
        let mut text = String::with_capacity(1 << 22);
        for i in 0..100_000 {
            text.push_str(&format!("http://h{i}.example.test/f.bin\n"));
        }
        let t0 = std::time::Instant::now();
        let lines = parse_input_file_lines(&text);
        let elapsed = t0.elapsed();
        assert_eq!(lines.len(), 100_000, "no lines lost at full scale");
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "parsing 100k lines must stay under 1s, got {elapsed:?}"
        );
        let bytes: usize = lines
            .iter()
            .map(|l| match l {
                InputFileLine::Task {
                    target, options, ..
                } => {
                    target.len()
                        + options
                            .iter()
                            .map(|(k, v)| k.len() + v.len())
                            .sum::<usize>()
                }
                InputFileLine::Malformed { .. } => 0,
            })
            .sum();
        assert!(
            bytes <= text.len(),
            "the parse output ({bytes}B) must not amplify beyond the input ({}B)",
            text.len()
        );
    }

    // ---- domain C: cookies/session/interface misc family ----

    /// The domain C `--gid` value-domain decision table
    /// ([`parse_cli_gid`]; the aria2 GID form = 16 hex digits): legal
    /// hex passes through + the high-bit mask normalization (the taiji
    /// GID space rule — fork GIDs with a zero high bit are
    /// normalized, our own exports round-trip losslessly); a length
    /// != 16 / non-hex / empty = rejected (the same face as the clap
    /// value_parser -> exit 2).
    #[test]
    fn parse_cli_gid_decision_table() {
        // Legal 16-digit hex (our own form — the high bit already set):
        // round-trip lossless.
        let g = parse_cli_gid("9234567890abcdef").unwrap_or_else(|e| panic!("must parse: {e}"));
        assert_eq!(g.to_string(), "9234567890abcdef");
        // A fork GID with a zero high bit: normalized into the taiji
        // space (the high bit set).
        let g = parse_cli_gid("1234567890abcdef").unwrap_or_else(|e| panic!("must parse: {e}"));
        assert_eq!(
            g.to_string(),
            "9234567890abcdef",
            "the high-bit mask normalization"
        );
        assert_eq!(
            g.as_u64() & taiji_core::gid::GID_HIGH_BIT,
            taiji_core::gid::GID_HIGH_BIT,
            "the high bit must be set (the Gid::from_u64 precondition is met by the parser)"
        );
        // Uppercase hex accepted (from_str_radix semantics; the output
        // is always lowercase hex16).
        assert!(parse_cli_gid("ABCDEF0123456789").is_ok());
        // Out-of-domain: length != 16.
        assert!(parse_cli_gid("1234").is_err(), "a short GID is rejected");
        assert!(
            parse_cli_gid("1234567890abcdef0").is_err(),
            "17 digits are rejected"
        );
        // Out-of-domain: non-hex / empty.
        assert!(parse_cli_gid("zz34567890abcdef").is_err());
        assert!(parse_cli_gid("").is_err());
    }

    /// The domain C `--dht-entry-point6` value-domain decision table
    /// ([`parse_dht_entry_point6`]; the aria2 HostPortOptionHandler form
    /// = HOST:PORT): host:port passes through, a v6 literal in the
    /// `[...]` bracket form passes through; a bare-colon v6 (split
    /// ambiguity) / a missing port / an empty host / port 0 / 65536+ =
    /// rejected.
    #[test]
    fn parse_dht_entry_point6_decision_table() {
        // Pass-through face (the original text travels verbatim — the
        // consumption point is the host:port text vector).
        assert_eq!(
            parse_dht_entry_point6("router6.example.com:6881").ok(),
            Some("router6.example.com:6881".to_string())
        );
        assert_eq!(
            parse_dht_entry_point6("[2001:db8::1]:6881").ok(),
            Some("[2001:db8::1]:6881".to_string()),
            "the v6 literal bracket form passes through"
        );
        // Rejection face.
        assert!(parse_dht_entry_point6("host.only").is_err(), "missing port");
        assert!(parse_dht_entry_point6(":6881").is_err(), "empty host");
        assert!(parse_dht_entry_point6("host:0").is_err(), "port 0");
        assert!(
            parse_dht_entry_point6("host:65536").is_err(),
            "port out of range"
        );
        assert!(
            parse_dht_entry_point6("host:abc").is_err(),
            "port is not a number"
        );
        assert!(
            parse_dht_entry_point6("2001:db8::1:6881").is_err(),
            "a bare-colon v6 is split-ambiguous -- explicitly rejected (the [..] form is required)"
        );
        assert!(parse_dht_entry_point6("").is_err());
        assert!(parse_dht_entry_point6("[::1").is_err(), "unclosed bracket");
    }

    /// The domain C flags' CLI parse decision table (the clap face):
    /// defaults = both cookie families unset / save-session unset /
    /// interval 0 / auto-save unset / interface unset / disable-ipv6
    /// unset / dht6 unset / ftp-type unset / netrc unset / gid unset /
    /// dry-run unset / show-files false; the explicit face = both the
    /// space and `=` value forms + the bool dual forms (bare/`=`) pass
    /// through; out-of-domain = value_parser rejection (auto-save-
    /// interval 601, ftp-type quic, a malformed gid, a malformed dht6 —
    /// the unified exit 2 face, rejected at the parse layer and never
    /// entering run).
    #[test]
    fn domain_c_flags_cli_parse_decision_table() {
        // Default face.
        let c = cli_of(&["taiji"]);
        assert!(c.load_cookies.is_none() && c.save_cookies.is_none());
        assert!(c.save_session.is_none());
        assert_eq!(c.save_session_interval, 0);
        assert!(c.auto_save_interval.is_none());
        assert!(c.interface.is_none() && c.disable_ipv6.is_none());
        assert!(c.dht_entry_point6.is_none() && c.ftp_type.is_none());
        assert!(c.netrc_path.is_none() && c.no_netrc.is_none());
        assert!(c.gid.is_none() && c.dry_run.is_none());
        assert!(!c.show_files);
        // Explicit face (the space/`=` value forms coexist; the bool
        // dual forms).
        let c = cli_of(&[
            "taiji",
            "--load-cookies",
            "/tmp/c.txt",
            "--save-cookies=/tmp/sc.txt",
            "--save-session",
            "/tmp/s.txt",
            "--save-session-interval=120",
            "--auto-save-interval",
            "60",
            "--interface=eth0",
            "--disable-ipv6",
            "--dht-entry-point6",
            "router6.example.com:6881",
            "--ftp-type=ascii",
            "--netrc-path",
            "/home/u/.netrc",
            "--no-netrc=true",
            "--gid=1234567890abcdef",
            "--dry-run",
        ]);
        assert_eq!(
            c.load_cookies.as_deref().map(std::path::Path::new),
            Some(std::path::Path::new("/tmp/c.txt"))
        );
        assert_eq!(
            c.save_cookies.as_deref().map(std::path::Path::new),
            Some(std::path::Path::new("/tmp/sc.txt"))
        );
        assert_eq!(
            c.save_session.as_deref().map(std::path::Path::new),
            Some(std::path::Path::new("/tmp/s.txt"))
        );
        assert_eq!(c.save_session_interval, 120);
        assert_eq!(c.auto_save_interval, Some(60));
        assert_eq!(c.interface.as_deref(), Some("eth0"));
        assert_eq!(c.disable_ipv6, Some(true), "bare flag = true");
        assert_eq!(
            c.dht_entry_point6.as_deref(),
            Some("router6.example.com:6881")
        );
        assert_eq!(c.ftp_type.as_deref(), Some("ascii"));
        assert_eq!(
            c.netrc_path.as_deref().map(std::path::Path::new),
            Some(std::path::Path::new("/home/u/.netrc"))
        );
        assert_eq!(c.no_netrc, Some(true));
        assert!(c.gid.is_some(), "a legal GID passes through (--gid)");
        assert_eq!(c.dry_run, Some(true), "bare flag = true");
        // The show-files independent face (a bare bool).
        assert!(cli_of(&["taiji", "--show-files"]).show_files);
        // Out-of-domain rejection (the clap value_parser face).
        assert!(
            Cli::command()
                .try_get_matches_from(["taiji", "--auto-save-interval", "601"])
                .is_err()
        );
        assert!(
            Cli::command()
                .try_get_matches_from(["taiji", "--ftp-type", "quic"])
                .is_err()
        );
        assert!(
            Cli::command()
                .try_get_matches_from(["taiji", "--gid", "nothex"])
                .is_err()
        );
        assert!(
            Cli::command()
                .try_get_matches_from(["taiji", "--dht-entry-point6", "host:0"])
                .is_err()
        );
        assert!(
            Cli::command()
                .try_get_matches_from(["taiji", "--disable-ipv6=yes"])
                .is_err(),
            "the bool domain is true|false (no yes -- the same domain as the flag surface)"
        );
    }

    /// The domain C session projection (the assembly single point shared
    /// by idle/download+rpc): Cli -> build_idle_options ->
    /// to_session_options maps the three keys straight onto
    /// GlobalOptions (the load_cookies session-level default source /
    /// the save_session shutdown text export / the
    /// save_session_interval_secs periodic save tick — defaults match
    /// GlobalOptions::default = zero behavior change).
    #[test]
    fn domain_c_idle_options_project_to_session_globals() {
        let project = |args: &[&str]| {
            let cli = cli_of(args);
            let opts = build_idle_options(
                &cli,
                taiji_bt::mse::CryptoPolicy::optional(),
                taiji_bt::utp::PeerConnectionType::default(),
            );
            opts.to_session_options(&taiji_rpc::RpcConfig {
                port: 6800,
                listen_all: false,
                secret: None,
                rpc_user: None,
                rpc_passwd: None,
                allow_origin_all: false,
                max_request_size: 10 * 1024 * 1024,
                aria2_compat: false,
                secure: false,
                certificate: None,
                private_key: None,
            })
            .global
        };
        // Defaults = GlobalOptions::default values (zero behavior
        // change).
        let g = project(&["taiji"]);
        assert_eq!(g.load_cookies, None);
        assert_eq!(g.save_session, None);
        assert_eq!(
            g.save_session_interval_secs,
            taiji_core::session::GlobalOptions::default().save_session_interval_secs
        );
        // The explicit face maps straight through.
        let g = project(&[
            "taiji",
            "--load-cookies=/tmp/ck.txt",
            "--save-session=/tmp/ss.txt",
            "--save-session-interval=30",
        ]);
        assert_eq!(
            g.load_cookies.as_deref().map(std::path::Path::new),
            Some(std::path::Path::new("/tmp/ck.txt")),
            "the cookie session-level default-source projection (fail-closed load at task acceptance)"
        );
        assert_eq!(
            g.save_session.as_deref().map(std::path::Path::new),
            Some(std::path::Path::new("/tmp/ss.txt"))
        );
        assert_eq!(g.save_session_interval_secs, 30);
    }

    /// Minimal v1 single-file torrent bytes (synthetic; the announce
    /// length is computed by format! — hand-counting bencode length
    /// prefixes is an error surface). Single file 10B / piece 16KiB /
    /// 1 piece (a 20B zero hash — the parse face does not verify the
    /// hash/content match).
    fn sample_v1_single_torrent() -> Vec<u8> {
        let url = "udp://a:1";
        let mut b = format!(
            "d8:announce{}:{url}4:infod6:lengthi10e4:name3:abc12:piece \
             lengthi16384e6:pieces20:",
            url.len()
        )
        .into_bytes();
        b.extend_from_slice(&[0u8; 20]);
        b.extend_from_slice(b"ee");
        b
    }

    /// Minimal v1 two-file torrent bytes (the multi-file form; two real
    /// files, no pad).
    fn sample_v1_multi_torrent() -> Vec<u8> {
        let url = "udp://a:1";
        let mut b = format!(
            "d8:announce{}:{url}4:infod5:filesld6:lengthi5e4:pathl3:aaae\
             ed6:lengthi7e4:pathl3:bbbeee4:name3:dir12:piece lengthi16384\
             e6:pieces20:",
            url.len()
        )
        .into_bytes();
        b.extend_from_slice(&[0u8; 20]);
        b.extend_from_slice(b"ee");
        b
    }

    /// The `--show-files` output-face decision table
    /// ([`format_torrent_listing`]; styled after aria2
    /// `bittorrent_helper.h` print): the single-file form
    /// asserts Mode: single, Name, and the file lines; the multi-file
    /// form asserts Mode: multi and the disk view with the name prefix.
    /// An absent announce/url_list = the saving face (no empty
    /// sections).
    #[test]
    fn format_torrent_listing_decision_table() {
        // Single-file form.
        let meta =
            Metainfo::parse(&sample_v1_single_torrent()).unwrap_or_else(|e| panic!("parse: {e}"));
        let text = format_torrent_listing(&meta);
        assert!(
            text.starts_with("*** BitTorrent File Information ***\n"),
            "{text}"
        );
        assert!(text.contains("Mode: single\n"), "{text}");
        assert!(text.contains("Announce:\n udp://a:1\n"), "{text}");
        assert!(text.contains("Info Hash: "), "{text}");
        assert!(text.contains("Piece Length: 16384B\n"), "{text}");
        assert!(text.contains("The Number of Pieces: 1\n"), "{text}");
        assert!(text.contains("Total Length: 10B (10 bytes)\n"), "{text}");
        assert!(text.contains("Name: abc\n"), "{text}");
        assert!(text.contains("Files:\n1. abc (10 bytes)\n"), "{text}");
        assert!(
            !text.contains("URL List:"),
            "an absent url-list produces no empty section"
        );

        // Multi-file form: the disk view carries the name prefix (the
        // BEP3 name prepends the first path element).
        let meta =
            Metainfo::parse(&sample_v1_multi_torrent()).unwrap_or_else(|e| panic!("parse: {e}"));
        let text = format_torrent_listing(&meta);
        assert!(text.contains("Mode: multi\n"), "{text}");
        assert!(text.contains("Name: dir\n"), "{text}");
        assert!(
            text.contains("1. dir/aaa (5 bytes)\n") && text.contains("2. dir/bbb (7 bytes)\n"),
            "file lines are 1-based with the name prefix: {text}"
        );
        assert!(text.contains("Total Length: 12B (12 bytes)\n"), "{text}");
    }

    /// The [`abbrev_size`] decision table (the aria2 abbrevSize
    /// counterpart — 1024-based, one decimal; below 1KiB the raw byte
    /// count).
    #[test]
    fn abbrev_size_decision_table() {
        assert_eq!(abbrev_size(0), "0B");
        assert_eq!(abbrev_size(10), "10B");
        assert_eq!(abbrev_size(1023), "1023B");
        assert_eq!(abbrev_size(1024), "1.0KiB");
        assert_eq!(abbrev_size(10 * 1024 * 1024), "10.0MiB");
        assert_eq!(abbrev_size(2 * 1024 * 1024 * 1024), "2.0GiB");
    }

    /// The domain C dry-run/show-files meta-mode gate (the usage-error
    /// arm of [`run_show_files`] — the non-async IO arm verified at the
    /// clap/Cli level): no positional = exit 2; a magnet/URL positional
    /// = exit 2 (refused explicitly here; the declared divergence from
    /// aria2's carry-on not-torrent line is in the flag docs). The IO
    /// arm (read/parse) semantics share the bare gate (1 = a read/parse
    /// failure), so no bad-torrent matrix is rebuilt here.
    #[test]
    fn show_files_usage_gate_decision_table() {
        // No positional arg.
        let cli = cli_of(&["taiji", "--show-files"]);
        assert_eq!(run_show_files(&cli), 2);
        // A magnet positional (not a torrent file).
        let cli = cli_of(&[
            "taiji",
            "--show-files",
            "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567",
        ]);
        assert_eq!(run_show_files(&cli), 2);
        // A URL positional.
        let cli = cli_of(&["taiji", "--show-files", "https://example.com/f.bin"]);
        assert_eq!(run_show_files(&cli), 2);
    }

    // ---- batch C: the max family (defaults + value forms + domains)
    // ----

    /// batch C: the max family flag defaults and value forms —
    /// `--max-concurrent-downloads` (default 5, domain >= 1); the
    /// rate-limit family K/M/G literals (default "0" = unlimited, the
    /// same parse_aria2_size parser); out-of-domain values are refused
    /// at startup.
    #[test]
    fn w3c_max_family_flags_parse() {
        let parse = |args: &[&str]| match Cli::command().try_get_matches_from(args) {
            Ok(m) => match Cli::from_arg_matches(&m) {
                Ok(cli) => (
                    cli.max_concurrent_downloads,
                    cli.max_download_limit,
                    cli.max_upload_limit,
                    cli.max_overall_download_limit,
                    cli.max_overall_upload_limit,
                ),
                Err(e) => panic!("valid matches rejected: {e}"),
            },
            Err(e) => panic!("flag must parse: {e}"),
        };
        // The default form: 5 / all zero (0 = unlimited).
        assert_eq!(parse(vec!["taiji"].as_slice()), (5, 0, 0, 0, 0));
        // Explicit values + the `=` form (the aria2 value-form face).
        assert_eq!(
            parse(
                vec![
                    "taiji",
                    "--max-concurrent-downloads=3",
                    "--max-download-limit=512K",
                    "--max-upload-limit=2M",
                    "--max-overall-download-limit=10M",
                    "--max-overall-upload-limit=1G",
                ]
                .as_slice()
            ),
            (
                3,
                512 * 1024,
                2 * 1024 * 1024,
                10 * 1024 * 1024,
                1024 * 1024 * 1024
            )
        );
        // Out-of-domain: concurrency 0 refused (the aria2 RANGE(1..) same
        // rule); invalid sizes refused.
        assert!(
            Cli::command()
                .try_get_matches_from(vec!["taiji", "--max-concurrent-downloads=0"])
                .is_err()
        );
        assert!(
            Cli::command()
                .try_get_matches_from(vec!["taiji", "--max-download-limit=abc"])
                .is_err()
        );
    }

    /// The startup CLI face carries the same upper bound
    /// the RPC apply-side clamp enforces ([1,64] — the memory
    /// amplification close: each concurrent task multiplies the
    /// per-task wr_cache/arena/engine faces). Pre-fix the flag took
    /// any n >= 1, so a config-pulled 128 slipped past startup and
    /// only the later changeGlobalOption path clamped.
    #[test]
    fn max_concurrent_downloads_upper_bound_matches_rpc_clamp() {
        let parse = |v: &str| {
            Cli::command()
                .try_get_matches_from(vec!["taiji", &format!("--max-concurrent-downloads={v}")])
                .map(|m| Cli::from_arg_matches(&m).map(|cli| cli.max_concurrent_downloads))
        };
        assert_eq!(
            parse("64")
                .unwrap_or_else(|e| panic!("must parse: {e}"))
                .unwrap_or_else(|e| panic!("valid matches rejected: {e}")),
            64,
            "the bound itself accepts"
        );
        assert_eq!(
            parse("1")
                .unwrap_or_else(|e| panic!("must parse: {e}"))
                .unwrap_or_else(|e| panic!("valid matches rejected: {e}")),
            1,
            "the floor accepts"
        );
        assert!(parse("65").is_err(), "n > 64 refused at the CLI face");
        assert!(parse("0").is_err(), "n < 1 refused at the CLI face");
    }

    /// batch C: the enable/dht family — `--enable-peer-exchange`
    /// (default **true**, the A2_V_TRUE same rule; the bare and `=`
    /// dual forms); `--enable-dht6` (default false, the value face);
    /// `--dht-entry-point` HOST:PORT parsing and refusals;
    /// `--dht-message-timeout` domain 1..=60 (the aria2 handler anchor).
    #[test]
    fn w3c_enable_and_dht_flags_parse() {
        let parse = |args: &[&str]| match Cli::command().try_get_matches_from(args) {
            Ok(m) => match Cli::from_arg_matches(&m) {
                Ok(cli) => (
                    cli.enable_peer_exchange,
                    cli.enable_dht6,
                    cli.dht_entry_point.clone(),
                    cli.dht_message_timeout,
                ),
                Err(e) => panic!("valid matches rejected: {e}"),
            },
            Err(e) => panic!("flag must parse: {e}"),
        };
        // The default form: true / false / unset / 10.
        assert_eq!(parse(vec!["taiji"].as_slice()), (true, false, None, 10));
        // The PEX dual forms (the bare flag = explicit true; =false =
        // explicitly off).
        assert!(
            parse(vec!["taiji", "--enable-peer-exchange"].as_slice()).0,
            "the bare flag = explicit true"
        );
        assert!(
            !parse(vec!["taiji", "--enable-peer-exchange=false"].as_slice()).0,
            "=false = explicitly off"
        );
        // The dht6 dual forms + the dht group explicit values.
        assert_eq!(
            parse(
                vec![
                    "taiji",
                    "--enable-dht6",
                    "--dht-entry-point=router.bittorrent.com:6881",
                    "--dht-message-timeout=30",
                ]
                .as_slice()
            ),
            (
                true,
                true,
                Some("router.bittorrent.com:6881".to_string()),
                30
            )
        );
        // The aria2 bool options only accept true/false.
        assert!(
            Cli::command()
                .try_get_matches_from(vec!["taiji", "--enable-peer-exchange=yes"])
                .is_err()
        );
        // dht-entry-point out-of-domain: a missing port / a non-u16 port.
        assert!(
            Cli::command()
                .try_get_matches_from(vec!["taiji", "--dht-entry-point=host-only"])
                .is_err()
        );
        assert!(
            Cli::command()
                .try_get_matches_from(vec!["taiji", "--dht-entry-point=h:70000"])
                .is_err()
        );
        // dht-message-timeout out-of-domain: both 0 and 61 are refused
        // (the aria2 1..=60).
        assert!(
            Cli::command()
                .try_get_matches_from(vec!["taiji", "--dht-message-timeout=0"])
                .is_err()
        );
        assert!(
            Cli::command()
                .try_get_matches_from(vec!["taiji", "--dht-message-timeout=61"])
                .is_err()
        );
    }

    /// The `--dht-entry-point` parser single point (reused by the conf
    /// face): hostnames / v4 / bracketed v6 literals accepted; a missing
    /// host, a missing port, a non-u16 port, no `:` refused.
    #[test]
    fn dht_entry_point_parser_domain() {
        assert_eq!(
            parse_dht_entry_point("router.bittorrent.com:6881").unwrap_or_default(),
            "router.bittorrent.com:6881"
        );
        assert_eq!(
            parse_dht_entry_point("67.230.169.182:6881").unwrap_or_default(),
            "67.230.169.182:6881"
        );
        assert_eq!(
            parse_dht_entry_point("[2001:db8::1]:6881").unwrap_or_default(),
            "[2001:db8::1]:6881"
        );
        for bad in ["", "host-only", ":6881", "h:", "h:0x1F90", "h:70000"] {
            assert!(
                parse_dht_entry_point(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    /// batch C: the bare rate-limit topology assembly — the LimiterSet
    /// mounts only when any limit is non-zero (all-zero = None, zero
    /// change); the bucket values map straight through (global =
    /// max-overall-*, per_torrent = max-*). A pure assembly-face pin
    /// (the same truth table as the extracted predicate of the
    /// run_download inline logic).
    #[test]
    fn w3c_bare_limiter_mount_truth_table() {
        let mounts = |od, ou, d, u: u64| od != 0 || ou != 0 || d != 0 || u != 0;
        assert!(
            !mounts(0, 0, 0, 0),
            "all zero = no mount (the existing form)"
        );
        assert!(mounts(1024, 0, 0, 0), "overall download only");
        assert!(mounts(0, 1024, 0, 0), "overall upload only");
        assert!(mounts(0, 0, 1024, 0), "per-task download only");
        assert!(mounts(0, 0, 0, 1024), "per-task upload only");
    }

    // ---- Domain 5: the behavior misc family (the frozen flag names +
    // the value-domain / mode-verdict single points) ----

    /// The behavior-5 flag frozen-name acceptance (the clap frozen-name
    /// spelling lock) + the default face (unset = None/false — zero
    /// behavior change). The bool dual forms (the bare and
    /// =true|=false) and the --seed-time/--stop negative literals
    /// (allow_negative_numbers) are exercised.
    #[test]
    fn behavior_flags_parse_frozen_names() {
        let parsed = Cli::try_parse_from([
            "taiji",
            "x.torrent",
            "--select-file",
            "1-3,5",
            "--seed-time",
            "30.5",
            "--stop=10",
            "--hash-check-only",
            "--peer-agent",
            "TaijiTest/1.0",
        ])
        .unwrap_or_else(|e| panic!("args must parse: {e}"));
        assert_eq!(parsed.select_file.as_deref(), Some("1-3,5"));
        assert_eq!(parsed.seed_time, Some(30.5));
        assert_eq!(parsed.stop, Some(10.0));
        assert!(parsed.hash_check_only);
        assert_eq!(parsed.peer_agent.as_deref(), Some("TaijiTest/1.0"));
        // The `=` value form (the aria2 single-value `=` form accepted
        // the same way).
        let parsed = Cli::try_parse_from([
            "taiji",
            "x.torrent",
            "--select-file=2",
            "--seed-time=0",
            "--hash-check-only=false",
        ])
        .unwrap_or_else(|e| panic!("eq-form must parse: {e}"));
        assert_eq!(parsed.select_file.as_deref(), Some("2"));
        assert_eq!(parsed.seed_time, Some(0.0));
        assert!(!parsed.hash_check_only);
        // The default face: all unset = None/false.
        let parsed = Cli::try_parse_from(["taiji"]).unwrap_or_else(|e| panic!("defaults: {e}"));
        assert_eq!(parsed.select_file, None);
        assert_eq!(parsed.seed_time, None);
        assert_eq!(parsed.stop, None);
        assert!(!parsed.hash_check_only);
        assert_eq!(parsed.peer_agent, None);
    }

    /// The minutes value-domain parse single point (the shared predicate
    /// of --seed-time/--stop): None is an identity, 0 = ZERO (the
    /// disabled semantics), fractional minutes convert x60,
    /// negative/NaN/inf/beyond the Duration domain = Err (the caller
    /// exits 2).
    #[test]
    fn parse_minutes_option_domain_table() {
        let ok = |v: Option<f64>, f: &str| {
            parse_minutes_option(v, f).unwrap_or_else(|e| panic!("valid minutes: {e}"))
        };
        assert_eq!(ok(None, "stop"), None);
        assert_eq!(
            ok(Some(0.0), "stop"),
            Some(Duration::ZERO),
            "0 = the disabled semantics (decided by the consumption face)"
        );
        assert_eq!(
            ok(Some(30.5), "seed-time"),
            Some(Duration::from_secs_f64(30.5 * 60.0)),
            "fractional minutes x60"
        );
        for bad in [-1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(
                parse_minutes_option(Some(bad), "stop").is_err(),
                "{bad} must be refused (domain >= 0 and finite)"
            );
        }
        // Beyond the Duration domain (outside the u64 seconds bound) =
        // Err — absurd values do not panic.
        assert!(parse_minutes_option(Some(f64::MAX), "seed-time").is_err());
    }

    /// The --hash-check-only mode-restriction truth table (the
    /// fail-closed arm): only "the download form + --enable-rpc" hits;
    /// bare and idle do not (the former is the effective arm, the latter
    /// the not-effective warning arm — neither belongs to this verdict).
    #[test]
    fn hash_check_only_mode_conflict_truth_table() {
        assert!(
            hash_check_only_mode_conflict(true, true),
            "download + RPC = the exit 2 refusal arm"
        );
        assert!(
            !hash_check_only_mode_conflict(true, false),
            "bare = the effective arm"
        );
        assert!(
            !hash_check_only_mode_conflict(false, true),
            "idle = the warning arm"
        );
        assert!(!hash_check_only_mode_conflict(false, false));
    }

    /// The --seed-time session global default injection: the CLI value
    /// goes through build_idle_options -> to_session_options onto
    /// GlobalOptions.seed_time_min (the getGlobalOption echo source; the
    /// fallback default for tasks whose add payload carries no
    /// seed-time). Unset = 0.0 (no time limit, zero change by default).
    #[test]
    fn seed_time_cli_projects_to_session_global_default() {
        let project = |args: &[&str]| {
            let m = Cli::command()
                .try_get_matches_from(args)
                .unwrap_or_else(|e| panic!("must parse: {e}"));
            let cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
            let crypto = taiji_bt::mse::CryptoPolicy {
                require_crypto: false,
                min_level: taiji_bt::mse::CryptoLevel::Plain,
            };
            let conn_type = taiji_bt::utp::PeerConnectionType::default();
            crate::build_idle_options(&cli, crypto, conn_type)
                .to_session_options(&crate::rpc_config_from_cli(&cli))
                .global
                .seed_time_min
        };
        assert_eq!(
            project(&["taiji"]),
            0.0,
            "unset = 0 (no time limit, zero change)"
        );
        assert_eq!(
            project(&["taiji", "--seed-time", "45"]),
            45.0,
            "the CLI value injects the session global default (a direct minutes map)"
        );
    }

    // ---- Seed-ratio wiring + the
    // acceptance-disclosure family ----

    /// The --seed-ratio frozen-name acceptance (the clap frozen-name
    /// spelling lock) + the value-domain face: unset = None (zero
    /// change), `0.0`/fractional floats accepted (the aria2 `0.0|RATIO`
    /// face), negative literals parse via allow_negative_numbers and are
    /// refused at the domain single point (exit 2).
    #[test]
    fn seed_ratio_flag_parse_and_domain() {
        let parsed = Cli::try_parse_from(["taiji", "x.torrent", "--seed-ratio", "2.5"])
            .unwrap_or_else(|e| panic!("args must parse: {e}"));
        assert_eq!(parsed.seed_ratio, Some(2.5));
        // The `=` value form + the disable-criterion 0.0 literal.
        let parsed = Cli::try_parse_from(["taiji", "x.torrent", "--seed-ratio=0"])
            .unwrap_or_else(|e| panic!("eq-form must parse: {e}"));
        assert_eq!(parsed.seed_ratio, Some(0.0));
        // The default face: unset = None.
        let parsed = Cli::try_parse_from(["taiji"]).unwrap_or_else(|e| panic!("defaults: {e}"));
        assert_eq!(parsed.seed_ratio, None);
        // The negative literal parses (allow_negative_numbers) and is
        // refused by the domain single point — the same shape as
        // --seed-time.
        let parsed = Cli::try_parse_from(["taiji", "--seed-ratio", "-1"])
            .unwrap_or_else(|e| panic!("negative literal must parse: {e}"));
        assert!(parse_seed_ratio_option(parsed.seed_ratio).is_err());
    }

    /// The seed-ratio value-domain parse single point (the CLI face of
    /// the core `checked_seed_ratio` rule): None is an identity, 0.0 =
    /// Some(0.0) (the criterion disabled — decided by the consumption
    /// face), fractional ratios pass through, negative/NaN/inf = Err
    /// (the caller exits 2).
    #[test]
    fn parse_seed_ratio_option_domain_table() {
        let ok = |v: Option<f64>| {
            parse_seed_ratio_option(v).unwrap_or_else(|e| panic!("valid ratio: {e}"))
        };
        assert_eq!(ok(None), None);
        assert_eq!(ok(Some(0.0)), Some(0.0), "0.0 = the criterion disabled");
        assert_eq!(ok(Some(1.0)), Some(1.0));
        assert_eq!(ok(Some(2.5)), Some(2.5), "fractional ratios pass through");
        for bad in [-1.0, -0.5, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(
                parse_seed_ratio_option(Some(bad)).is_err(),
                "{bad} must be refused (domain >= 0 and finite, checked_seed_ratio rule)"
            );
        }
    }

    /// The --seed-ratio session global default injection: the CLI value
    /// goes through build_idle_options -> to_session_options onto
    /// GlobalOptions.seed_ratio (the getGlobalOption echo source; the
    /// fallback default for tasks whose add payload carries no
    /// seed-ratio). Unset = 1.0 (the standing GlobalOptions::default —
    /// zero change by default).
    #[test]
    fn seed_ratio_cli_projects_to_session_global_default() {
        let project = |args: &[&str]| {
            let m = Cli::command()
                .try_get_matches_from(args)
                .unwrap_or_else(|e| panic!("must parse: {e}"));
            let cli = Cli::from_arg_matches(&m).unwrap_or_else(|e| panic!("{e}"));
            let crypto = taiji_bt::mse::CryptoPolicy {
                require_crypto: false,
                min_level: taiji_bt::mse::CryptoLevel::Plain,
            };
            let conn_type = taiji_bt::utp::PeerConnectionType::default();
            crate::build_idle_options(&cli, crypto, conn_type)
                .to_session_options(&crate::rpc_config_from_cli(&cli))
                .global
                .seed_ratio
        };
        assert_eq!(
            project(&["taiji"]),
            1.0,
            "unset = the standing 1.0 default (zero change)"
        );
        assert_eq!(
            project(&["taiji", "--seed-ratio", "2.5"]),
            2.5,
            "the CLI value injects the session global default"
        );
        assert_eq!(
            project(&["taiji", "--seed-ratio", "0"]),
            0.0,
            "0.0 disables the ratio criterion (the aria2 same rule)"
        );
    }

    /// Alias promotion: `--bt-enable-lpd` is now a visible alias
    /// (the help/completion faces list it) and keeps sharing the
    /// `--bt-lsd` slot; the hidden `--rpc-port` alias stays hidden (the
    /// completion surface follows the help surface — completions.rs
    /// module docs).
    #[test]
    fn bt_enable_lpd_is_a_visible_alias() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let lsd = cmd
            .get_arguments()
            .find(|a| a.get_long() == Some("bt-lsd"))
            .unwrap_or_else(|| panic!("bt-lsd arg must exist"));
        let names = lsd
            .get_long_and_visible_aliases()
            .unwrap_or_else(|| panic!("visible aliases must exist"))
            .to_vec();
        assert!(
            names.contains(&"bt-enable-lpd"),
            "bt-enable-lpd must be a visible alias: {names:?}"
        );
        // The alias still fills the same slot (the dual forms).
        assert!(cli_of(&["taiji", "--bt-enable-lpd"]).bt_lsd);
        assert!(!cli_of(&["taiji", "--bt-enable-lpd=false"]).bt_lsd);
        let rpc_port = cmd
            .get_arguments()
            .find(|a| a.get_long() == Some("rpc-listen-port"))
            .unwrap_or_else(|| panic!("rpc-listen-port arg must exist"));
        assert!(
            rpc_port
                .get_visible_aliases()
                .unwrap_or_default()
                .is_empty(),
            "rpc-port stays a hidden alias (help/completion faces unchanged)"
        );
    }

    /// The acceptance-disclosure family: the seven frozen
    /// names parse with aria2-typed value faces (the bool dual form for
    /// the async-dns family, the multi-value string for
    /// bt-exclude-tracker, the numeric face for the four max-*), and the
    /// defaults stay unset (zero noise, zero change — the warnings fire
    /// only on explicit givens in run).
    #[test]
    fn d_tier_disclosure_flags_parse_frozen_names() {
        let parsed = Cli::try_parse_from([
            "taiji",
            "--async-dns",
            "--enable-async-dns6=false",
            "--bt-exclude-tracker",
            "udp://a:1/announce,udp://b:1/announce",
            "--max-download-result=5000",
            "--max-file-not-found",
            "3",
            "--max-mmap-limit=0",
            "--max-resume-failure-tries=-1",
        ])
        .unwrap_or_else(|e| panic!("args must parse: {e}"));
        assert_eq!(parsed.async_dns, Some(true), "bare bool flag = true");
        assert_eq!(
            parsed.enable_async_dns6,
            Some(false),
            "=false explicitly suppresses"
        );
        assert_eq!(
            parsed.bt_exclude_tracker.as_deref(),
            Some("udp://a:1/announce,udp://b:1/announce"),
            "the comma multi-value string passes through verbatim"
        );
        assert_eq!(parsed.max_download_result, Some(5000));
        assert_eq!(parsed.max_file_not_found, Some(3));
        assert_eq!(parsed.max_mmap_limit, Some(0));
        assert_eq!(
            parsed.max_resume_failure_tries,
            Some(-1),
            "the negative sentinel is tolerated (numeric pass-through face)"
        );
        // The default face: all unset = None (zero noise on defaults).
        let parsed = Cli::try_parse_from(["taiji"]).unwrap_or_else(|e| panic!("defaults: {e}"));
        assert_eq!(parsed.async_dns, None);
        assert_eq!(parsed.enable_async_dns6, None);
        assert_eq!(parsed.bt_exclude_tracker, None);
        assert_eq!(parsed.max_download_result, None);
        assert_eq!(parsed.max_file_not_found, None);
        assert_eq!(parsed.max_mmap_limit, None);
        assert_eq!(parsed.max_resume_failure_tries, None);
    }
}
