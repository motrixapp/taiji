//! `taiji http` subcommand: one-shot HTTP(S)/FTP(S) download, end to end.
//!
//! Same shape as the existing bare-BT download mode: no RPC server is
//! started; the SessionActor is bootstrapped directly (session-store
//! persistence + bootstrap recovery).
//!
//! Resume semantics: the persisted bitmap snapshot is the resume truth.
//! Before addUri the CLI reads the same read path as bootstrap (active
//! rows) to decide whether to attach to an in-flight same-source task
//! instead of creating a duplicate (the session-store counterpart of
//! aria2's `<file>.aria2` control file). Attach never silently drops
//! options: a `--checksum` conflict rejects attach; other mismatches
//! attach with an explicit warning, the persisted value winning. Terminal
//! rows (error/done) are not on the recovery read path: rerunning after a
//! failure starts a fresh task from zero.
//!
//! Single-session guard: a kernel advisory lock on `<db>.lock`
//! ([`crate::db_lock`]) is taken before bootstrapping; a second concurrent
//! process exits with an explicit error instead of co-writing the same
//! `.part`.
//!
//! Exit codes: 0 = download complete; 1 = task failed/removed/interrupted,
//! concurrent session refused, or attach refused; 2 = session command
//! error (including the `taiji.option.invalid` value-domain rejection and
//! lockfile filesystem failure).
//!
//! Upstream anchor mapping: docs/design/cli.md

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::Parser;
use tracing::{error, info, warn};

use taiji_core::gid::Gid;
use taiji_core::session::{
    CommandReply, GlobalOptions, SessionActor, SessionCommand, SessionError, SessionHandle,
    SessionOptions, StatusKind,
};

/// Status-polling interval (the waiting cadence while session events
/// arrive asynchronously).
/// `pub(crate)`: the domain A `--input-file` batch face (main.rs
/// run_input_file) reuses the same cadence — one cadence face for the
/// multi-task terminal-state polling, no drift between the two places.
pub(crate) const STATUS_POLL: Duration = Duration::from_millis(200);

/// Progress-log interval (the polling cadence x10 ~= 2s). `pub(crate)`:
/// reused by the batch face the same way.
pub(crate) const PROGRESS_EVERY: u32 = 10;

/// Shutdown budget (1s). The actor drain and the persistence-writer drain
/// share this budget (full budgets each would stack past the bound; the
/// allocation mirrors the remaining-time scheme of the main entry's
/// `SHUTDOWN_BUDGET`).
const SESSION_SHUTDOWN_BUDGET: Duration = Duration::from_secs(1);

/// Value-domain rejection code. The error protocol is
/// `"<taiji.* code>: message"`, shared with the RPC error shape;
/// structured matching compares the first token exactly (no substring
/// sniffing).
const CODE_OPTION_INVALID: &str = "taiji.option.invalid";

/// `taiji http <url>...` argument surface.
#[derive(Parser, Debug, Default)]
pub struct HttpArgs {
    /// Source URIs (>= 1; multiple URIs = mirrors of the same file, aria2
    /// addUri semantics). http(s)/ftp(s) schemes are always accepted:
    /// multi-source probing merges and shards across sources; FTP goes
    /// through the `--ftp-*` options (FTPS = ftp:// plus `--ftp-ssl`; the
    /// `ftps://` scheme is not accepted). Sources whose probe fails are
    /// dropped without dragging down the remaining ones.
    pub urls: Vec<String>,
    /// Download directory (aria2-compatible name `--dir`; defaults to the
    /// current directory).
    #[arg(short, long, default_value = ".")]
    pub dir: PathBuf,
    /// Output file name (aria2-compatible name `--out`; derived from the
    /// final URL when omitted).
    #[arg(short, long)]
    pub out: Option<String>,
    /// Completion-time verification (aria2-compatible name `--checksum`;
    /// value domain is the six hashes
    /// `md5|sha-1|sha-224|sha-256|sha-384|sha-512=<hex>`, an invalid value
    /// rejects the task; on failure the task ends in error and the `.part`
    /// file stays on disk for inspection).
    ///
    /// Metalink form difference: under `--metalink-file` this option is not
    /// forwarded to any subtask — entry checksums come only from the
    /// document's own six-hash declarations (an entry without a declaration
    /// never inherits the external checksum; fail-closed against leakage).
    #[arg(long)]
    pub checksum: Option<String>,
    /// Incomplete-data suffix (strict name domain
    /// `^\.[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`; persisted with the task at
    /// creation — resume prefers the task's persisted value, so changing
    /// the default never affects in-flight tasks).
    #[arg(long = "http-incomplete-suffix")]
    pub incomplete_suffix: Option<String>,
    /// Resume switch (aria2-compatible name `--continue`). Declared
    /// semantic inversion: aria2's `--continue=false` discards existing
    /// progress and restarts from zero; this engine always resumes — the
    /// session-store bitmap is the resume truth, so `false` does not change
    /// behavior (it is ignored) and the inversion is disclosed with an
    /// explicit warning. Both the bare flag and the `=true|=false` value
    /// forms are accepted (aria2's two bool-option forms).
    #[arg(
        long = "continue",
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    pub continue_dl: Option<bool>,
    /// After download completes, set the file mtime from the remote
    /// Last-Modified (best effort — parse or set failures only warn). Both
    /// the bare flag and the `=true|=false` value forms are accepted
    /// (aria2's two bool-option forms).
    #[arg(
        long,
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    pub remote_time: Option<bool>,
    /// Per-task connection hint (aria2-compatible name `--split`, domain
    /// 1-4096, out-of-domain rejects the task). Under dynamic scheduling
    /// (the default) it is the AIMD slow-start starting point (concurrency
    /// intent takes effect immediately) plus the initial extent hint; the
    /// connection ceiling is set by `--max-connection-per-server`. Under
    /// static scheduling (`--http-scheduler=static`) it is the split count
    /// — the first wave runs exactly `split` workers per source, an upper
    /// bound guarding against task amplification. The redefined semantics
    /// are a declared difference. Domain validation belongs to the
    /// session-side parser as the single source of truth
    /// (`taiji.option.invalid`; not a clap value parser — the same rule for
    /// every flag in the scheduler group).
    #[arg(long)]
    pub split: Option<u32>,
    /// Minimum split size (aria2-compatible name `--min-split-size`;
    /// k/M/G suffixes are 1024-based. Under dynamic scheduling it only
    /// seeds the initial extent — a declared difference; under static
    /// scheduling it is the minimum segment length).
    #[arg(long)]
    pub min_split_size: Option<String>,
    /// Per-server connection cap (aria2-compatible name
    /// `--max-connection-per-server`; domain 1-16, out-of-domain rejected).
    /// Growth cap of the AIMD connection loop: connections ramp from the
    /// slow-start start (= `--split`) up to this cap. Default = 16; the
    /// upstream default of 1 would pin the growth cap and keep dynamic
    /// scheduling on a single connection for the whole run — the cap is a
    /// ceiling, not a connection count, so AIMD still climbs adaptively.
    /// The default divergence from upstream is a declared difference.
    /// Explicit 1 pins a single connection; Motrix presets send explicit
    /// values within the same domain.
    #[arg(long = "max-connection-per-server")]
    pub max_connection_per_server: Option<u32>,
    /// Stall-steal detection window in seconds (taiji extension
    /// `--http-stall-window`; default 15s; a stall is declared only after
    /// a full window of zero-byte growth — a slow connection that keeps
    /// writing is never stalled. aria2 has no such option).
    #[arg(long = "http-stall-window")]
    pub http_stall_window: Option<u64>,
    /// Scheduling mode (taiji extension `--http-scheduler=dynamic|static`;
    /// default dynamic = guided self-scheduling + the AIMD connection
    /// loop; static = fixed splitting as control/fallback (no AIMD or
    /// stealing, `--split` is the concurrent connection count). aria2 has
    /// no such option). Unknown values reject the task
    /// (`taiji.option.invalid`; validated by the same session-side parser —
    /// not a clap value parser, the scheduler-group rule).
    #[arg(long = "http-scheduler")]
    pub http_scheduler: Option<String>,
    /// Block grid granularity (taiji extension `--http-block-size`;
    /// default 4MiB; domain = powers of two from 256KiB to 16MiB.
    /// Immutable per task — fixed into the task row at creation;
    /// changeOption during a run is explicitly rejected. aria2 has no such
    /// option). Invalid values reject the task (`taiji.option.invalid`).
    #[arg(long = "http-block-size")]
    pub http_block_size: Option<String>,
    /// Guided extent cap (taiji extension `--http-max-chunk`; default
    /// 32MiB; domain lower bound = the effective block granularity.
    /// Scheduler-class — changeable at run time via changeOption. aria2
    /// has no such option). Out-of-domain values reject the task
    /// (`taiji.option.invalid`).
    #[arg(long = "http-max-chunk")]
    pub http_max_chunk: Option<String>,
    /// Transfer timeout in seconds (aria2-compatible name `--timeout`;
    /// read idleness — shared by reqwest's per-read floor and the
    /// task-level byte-stall detector).
    #[arg(long)]
    pub timeout: Option<u64>,
    /// Connection timeout in seconds (aria2-compatible name
    /// `--connect-timeout`).
    #[arg(long)]
    pub connect_timeout: Option<u64>,
    /// Retry count (aria2-compatible name `--max-tries`; redefined
    /// semantics = per extent, a declared difference; 0 = unlimited, the
    /// same rule as aria2).
    #[arg(long = "max-tries")]
    pub max_tries: Option<u32>,
    /// Retry wait in seconds (aria2-compatible name `--retry-wait`).
    #[arg(long)]
    pub retry_wait: Option<u64>,
    /// User-Agent (aria2-compatible name `--user-agent`; default
    /// `taiji/<semver>` as an honest identifier).
    #[arg(long)]
    pub user_agent: Option<String>,
    /// Extra request headers (aria2-compatible name `--header`,
    /// repeatable).
    #[arg(long = "header", action = clap::ArgAction::Append)]
    pub headers: Vec<String>,
    /// HTTP auth user (aria2-compatible name `--http-user`; the same
    /// credential pair serves both Basic pre-auth and the 401 Digest
    /// challenge response).
    #[arg(long)]
    pub http_user: Option<String>,
    /// HTTP auth password (aria2-compatible name `--http-passwd`).
    #[arg(long)]
    pub http_passwd: Option<String>,
    /// Global proxy (aria2-compatible name `--all-proxy`; http/https
    /// proxy URL, auth via URL userinfo. socks5(h) is not supported yet —
    /// a declared transport limitation).
    #[arg(long)]
    pub all_proxy: Option<String>,
    /// HTTP proxy (aria2-compatible name `--http-proxy`; per-protocol
    /// slots are NOT done — this maps onto the single `--all-proxy` slot,
    /// the same taiji-http `reqwest::Proxy` transport seam. Declared
    /// difference: the one slot serves every scheme (aria2's slot covers
    /// http:// traffic only); coexistence with `--all-proxy` = explicit
    /// rejection (exit 2, a single proxy source).
    #[arg(long = "http-proxy")]
    pub http_proxy: Option<String>,
    /// Proxy auth user (aria2-compatible name `--http-proxy-user`).
    /// Folded into the userinfo of the parsed proxy URL (taiji's declared
    /// proxy-credential carrying form); a URL that already carries
    /// userinfo wins (the same URL-credentials-first rule as aria2).
    #[arg(long = "http-proxy-user")]
    pub http_proxy_user: Option<String>,
    /// Proxy auth password (aria2-compatible name `--http-proxy-passwd`;
    /// same folding rule as `--http-proxy-user`; a password without a
    /// user is never folded in alone — no auth subject, explicit
    /// rejection).
    #[arg(long = "http-proxy-passwd")]
    pub http_proxy_passwd: Option<String>,
    /// HTTPS-dedicated proxy (aria2-compatible name `--https-proxy`;
    /// domain-2 per-scheme slot): effective order = dedicated slot >
    /// `--all-proxy` > no proxy — projected through the session
    /// `https-proxy` option onto `ClientConfig.proxy_https`, registered
    /// as the second reqwest proxy (the dedicated slot registers first:
    /// first-match-wins + `Proxy::https` only intercepts https targets);
    /// http targets still go through `--all-proxy`. Coexistence with
    /// `--all-proxy`/`--http-proxy` is legal (per-scheme coexistence is
    /// this slot's whole point; the single-slot mutual-exclusion rule
    /// `--all-proxy` x `--http-proxy` is unchanged).
    #[arg(long = "https-proxy")]
    pub https_proxy: Option<String>,
    /// HTTPS proxy auth user (aria2-compatible name
    /// `--https-proxy-user`; domain 2). Folded into the `--https-proxy`
    /// URL (the dedicated slot); without the dedicated slot it folds into
    /// the `--all-proxy`/`--http-proxy` URL (the single slot also serves
    /// https) — folding into the same URL as `--http-proxy-user`
    /// conflicts (a single userinfo carrier) and is explicitly rejected.
    #[arg(long = "https-proxy-user")]
    pub https_proxy_user: Option<String>,
    /// HTTPS proxy auth password (aria2-compatible name
    /// `--https-proxy-passwd`; domain 2; same folding rule as
    /// `--https-proxy-user`; a password without a user is explicitly
    /// rejected).
    #[arg(long = "https-proxy-passwd")]
    pub https_proxy_passwd: Option<String>,
    /// FTP-dedicated proxy (aria2-compatible name `--ftp-proxy`; domain
    /// 2). Honest boundary: FTP-over-HTTP proxying (P2) is not done —
    /// the FTP transport face (suppaftp) connects directly, with no
    /// proxy seam. An ftp(s):// source present = explicit rejection
    /// (exit 2, the same rejection style as `--ftp-pasv=false`); no FTP
    /// source = accepted with a warn-not-effective disclosure.
    #[arg(long = "ftp-proxy")]
    pub ftp_proxy: Option<String>,
    /// FTP proxy auth user (aria2-compatible name `--ftp-proxy-user`;
    /// domain 2; folded into the `--ftp-proxy` URL userinfo — no
    /// subject, explicit rejection).
    #[arg(long = "ftp-proxy-user")]
    pub ftp_proxy_user: Option<String>,
    /// FTP proxy auth password (aria2-compatible name
    /// `--ftp-proxy-passwd`; domain 2; same folding rule as
    /// `--ftp-proxy-user`; a password without a user is explicitly
    /// rejected).
    #[arg(long = "ftp-proxy-passwd")]
    pub ftp_proxy_passwd: Option<String>,
    /// Proxy bypass (aria2-compatible name `--no-proxy`; domain 2).
    /// Whole-value semantics: a non-empty value = bypass every proxy
    /// slot and connect directly (the highest-priority face). aria2's
    /// per-host exemption list syntax is not parsed — a value containing
    /// commas (the list form) draws an explicit warning disclosure;
    /// coexisting with proxy flags bypasses the proxy face (per-flag
    /// warnings, never silent).
    #[arg(long = "no-proxy")]
    pub no_proxy: Option<String>,
    /// Probe method (aria2-compatible name `--use-head`, default false,
    /// same rule). Declared difference: true is accepted but treated as
    /// false with an explicit warning — this engine's probe red line:
    /// HEAD semantics are not enforced uniformly across HTTP
    /// implementations (Content-Length/entity headers may be omitted or
    /// misreported), so it is never a segmentation criterion; the only
    /// probe means = GET + `Range: bytes=0-0` (the taiji-http probe
    /// decision table). Both the bare flag and the `=true|=false` value
    /// forms are accepted (the aria2 bool-option dual form).
    #[arg(
        long = "use-head",
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    pub use_head: Option<bool>,
    /// Referer header (aria2-compatible name `--referer`; domain-2
    /// knob): injected via the session `referer` option into
    /// `RequestCtx.referer` — carried on every hop of probing and
    /// fetching (aria2 carries it on the first request only; carrying it
    /// on every hop is a declared behavior extension). Coexisting with
    /// an explicit `--header "Referer: ..."` line = conflict rejection
    /// (a single Referer source).
    #[arg(long)]
    pub referer: Option<String>,
    /// Transparent gzip decompression switch (aria2-compatible name
    /// `--http-accept-gzip`, default false, same rule; domain-2 knob):
    /// false = the status-quo explicit `Accept-Encoding: identity`
    /// (a single source of truth for compression); true = hand
    /// negotiation back to reqwest — transparent decompression on the
    /// data face (the checksum applies to the decompressed bytes); the
    /// probe face reading a non-identity encoding → decision-table row 7
    /// single-connection degradation + the bitmap not enabled (the
    /// explicit trade of segmentation for compression). Both the bare
    /// flag and the `=true|=false` value forms are accepted.
    #[arg(
        long = "http-accept-gzip",
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    pub http_accept_gzip: Option<bool>,
    /// Per-task download speed limit (aria2-compatible name
    /// `--max-download-limit`; K/M/G suffixes are 1024-based, 0 =
    /// unlimited). Sent through the addUri option face — the per_torrent
    /// bucket enforcement face (HTTP and BT tasks share the same
    /// channel).
    #[arg(long = "max-download-limit", value_parser = crate::parse_aria2_size)]
    pub max_download_limit: Option<u64>,
    /// Per-task upload speed limit (aria2-compatible name
    /// `--max-upload-limit`; 0 = unlimited; same semantics as above).
    #[arg(long = "max-upload-limit", value_parser = crate::parse_aria2_size)]
    pub max_upload_limit: Option<u64>,
    /// TLS certificate verification switch (aria2-compatible name
    /// `--check-certificate`, default true; false = verification off).
    #[arg(long, action = clap::ArgAction::Set, num_args(0..=1), require_equals(true), default_missing_value = "true")]
    pub check_certificate: Option<bool>,
    /// Task-level CA certificate file (aria2-compatible name
    /// `--ca-certificate`, PEM format; when non-empty it REPLACES the
    /// platform trust roots — the same semantics as aria2. The RPC
    /// addUri/changeOption surface accepts the same key; a bad path or bad
    /// PEM rejects the task (`taiji.option.invalid`, the same session-side
    /// parser — not a clap value parser, the scheduler-group rule).
    #[arg(long = "ca-certificate", value_name = "FILE")]
    pub ca_certificate: Option<String>,
    /// Cookie ingestion gate (first step of the aria2-compatible
    /// `--load-cookies`; Netscape cookie file path, same name and meaning
    /// as aria2). Loading is fail-closed (missing/unreadable/over 1MiB =
    /// task rejection `taiji.option.invalid`, the same session-side
    /// parser). Effect = the task's CookieStore is prefilled; when it
    /// coexists with a manual `--header` Cookie line the jar is
    /// authoritative (the manual Cookie line is stripped; the
    /// fork-equivalence note lives on the session side). RPC addUri
    /// options and the changeGlobalOption global surface accept the same
    /// key.
    #[arg(long = "load-cookies", value_name = "FILE")]
    pub load_cookies: Option<String>,
    /// Per-host connection cap (taiji extension `--http-max-per-host`;
    /// default 64, unit = connections; a session-level shared registry,
    /// counted across tasks. Dual channel: this value initializes the
    /// session HostCap (also effective on attach resume) and is sent along
    /// with the addUri options for run-time adjustment (last-set-wins,
    /// task-level override taking priority). Domain >= 1 (0 = rejected —
    /// the same value_parser as the RPC server form in main.rs, so both
    /// parse surfaces reject 0 identically).
    #[arg(
        long = "http-max-per-host",
        value_parser = clap::value_parser!(u32).range(1..)
    )]
    pub http_max_per_host: Option<u32>,
    /// Protocol form (taiji extension `--http-protocol=auto|h1|h2`;
    /// default auto = plaintext h1 plus rustls ALPN-negotiated h2/h1
    /// fallback on https; h1 = force HTTP/1.1 (upgrades disabled); h2 =
    /// HTTP/2 with prior knowledge (plaintext endpoints use h2c, no
    /// Upgrade and no fallback — fails outright against h1-only peers).
    /// aria2 has no such option. Unknown values reject the task
    /// (`taiji.option.invalid`, the same session-side parser — not a clap
    /// value parser, the scheduler-group rule).
    #[arg(long = "http-protocol")]
    pub http_protocol: Option<String>,
    /// h2 adaptive flow-control window (taiji extension; default false =
    /// static engine defaults (stream 8MiB / connection 16MiB) — hyper's
    /// library defaults of 2MiB/5MiB are reachable only via the
    /// programmatic None path; true = grow the receive window dynamically
    /// from ping/BDP estimation. aria2 has no such option. Invalid values
    /// reject the task, same session-side parser).
    #[arg(long = "http2-adaptive-window")]
    pub http2_adaptive_window: Option<String>,
    /// h2 stream-level initial receive window in bytes (taiji extension;
    /// domain 65535..=2^31-1, RFC 7540 §5.2.2; default = the engine
    /// default 8MiB. aria2 has no such option. Out-of-domain values reject
    /// the task, same session-side parser).
    #[arg(long = "http2-stream-window")]
    pub http2_stream_window: Option<String>,
    /// h2 connection-level initial receive window in bytes (taiji
    /// extension; same domain, shared across streams; default = the engine
    /// default 16MiB. aria2 has no such option. Out-of-domain values
    /// reject the task, same session-side parser).
    #[arg(long = "http2-connection-window")]
    pub http2_connection_window: Option<String>,
    /// h2 per-origin connection cap (taiji extension; default 1 = the
    /// status quo of a single multiplexed connection; domain 1..=8 — K
    /// independent transport instances spread round-robin. K semantics
    /// note: negotiating down to h1 is not entirely wasted — connections
    /// are spread sequentially, min(K, request count) of them (versus the
    /// K=1 single keep-alive connection, reclaimed after 90s idle); the
    /// cap pays off only together with concurrency intent (split /
    /// max-connection-per-server / AIMD want) — on the default grid path
    /// want->1 makes K nearly a no-op. aria2 has no such option.
    /// Out-of-domain values reject the task, same session-side parser).
    #[arg(long = "http2-max-connections")]
    pub http2_max_connections: Option<String>,
    /// h2 PING keep-alive interval in seconds (taiji extension; default
    /// 0 = off = the hyper status quo; domain 0..=3600 — liveness probing
    /// of idle pooled connections. aria2 has no such option.
    /// Out-of-domain values reject the task, same session-side parser).
    #[arg(long = "http2-keep-alive-interval")]
    pub http2_keep_alive_interval: Option<String>,
    /// FTP auth user (aria2-compatible name `--ftp-user`; default
    /// anonymous. A separate slot from `--http-user`, no cross-leak).
    #[arg(long)]
    pub ftp_user: Option<String>,
    /// FTP auth password (aria2-compatible name `--ftp-passwd`; default
    /// anonymous@).
    #[arg(long)]
    pub ftp_passwd: Option<String>,
    /// FTPS mode (taiji extension `--ftp-ssl=none|auth|implicit`; default
    /// auth = explicit TLS. aria2 has no FTPS capability — a declared
    /// capability extension).
    #[arg(long)]
    pub ftp_ssl: Option<String>,
    /// Passive-mode switch (aria2-compatible name `--ftp-pasv`, default
    /// true; `false` = active-mode PORT is not implemented — the task is
    /// rejected, a declared difference).
    #[arg(
        long,
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    pub ftp_pasv: Option<bool>,
    /// Control-connection reuse (aria2-compatible name
    /// `--ftp-reuse-connection`, default true; false = a new control
    /// connection per extent).
    #[arg(
        long = "ftp-reuse-connection",
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    pub ftp_reuse_connection: Option<bool>,
    /// Session store path (aria2-compatible name `--sqlite3-db-path`;
    /// default taiji.sqlite3. The single source of truth for resume
    /// decisions and task-row persistence; the concurrent-session mutex
    /// lives next to it as `<db>.lock`).
    #[arg(long, default_value = "taiji.sqlite3")]
    pub sqlite3_db_path: PathBuf,
    /// Periodic task summary log interval in seconds (aria2-compatible
    /// name `--summary-interval`, prefs.cc; default 60 / domain
    /// 0..=INT32_MAX / 0 = disabled — OptionHandlerFactory.cc anchor).
    /// Effect = session periodic INFO summaries (gid/speed/progress/
    /// connection count, target `taiji::core::summary`). Startup-time
    /// option: changeGlobalOption does not accept it (capability bits
    /// aligned with the reference).
    #[arg(
        long,
        default_value_t = taiji_core::session::SUMMARY_INTERVAL_DEFAULT,
        value_parser = clap::value_parser!(u32).range(0..=taiji_core::session::SUMMARY_INTERVAL_MAX as i64)
    )]
    pub summary_interval: u32,
    /// Local metalink document path (aria2-compatible name
    /// `--metalink-file`): the document is parsed as RFC 5854 v4 (16MiB
    /// document cap pre-checked before read and enforced again at parse),
    /// each `<file>` entry expands into an independent task (multi-file
    /// GID chain), and `<metaurl mediatype="torrent">` converts directly
    /// to BT (magnet / `.torrent` metadata entry). Mutually exclusive with
    /// positional URLs. Same expansion semantics as RPC addMetalink;
    /// differences from the single-URL form: no attach decision (the
    /// multi-task form has no single-source attach key — rerunning the
    /// same document creates new tasks; bitmap resume goes through the
    /// daemon surface), and `--out`/`--checksum` are not forwarded to
    /// subtasks (the entry name is the per-task out; checksums come only
    /// from the document — see `--checksum`; explicit values warn, they
    /// are never silently dropped).
    /// Exit code 2 = document missing/unreadable/over the 16MiB document
    /// cap/parse failure (including the explicit v3 downgrade error
    /// `taiji.metalink.unsupported_version`)/zero usable entries (all
    /// mirrors/metaurls outside the accepted surface, unusable, or
    /// duplicated within the document).
    #[cfg(feature = "metalink")]
    #[arg(long = "metalink-file")]
    pub metalink_file: Option<PathBuf>,
    /// HTTP-response metalink auto-discovery switch (aria2-compatible
    /// name `--metalink-enable-auto-discover`; DEFAULT false).
    /// Declared difference: response-body sniffing and auto-conversion is
    /// not in this build — `true` is accepted but handled as `false` with
    /// an explicit warning (the semantics aria2 reaches via
    /// `--follow-metalink` defaulting to true; here the default is off and
    /// the accepted-but-ineffective state is disclosed). Both the bare
    /// flag and the `=true|=false` value forms are accepted.
    #[cfg(feature = "metalink")]
    #[arg(
        long = "metalink-enable-auto-discover",
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    pub metalink_enable_auto_discover: Option<bool>,
    /// Entry language filter (aria2-compatible name `--metalink-language`,
    /// the §4.7 metalink selector group): the entry's `<language>` set,
    /// EXACT match (the aria2 `MetalinkEntry::containsLanguage` —
    /// `Metalinker.cc queryEntry` rule; case-sensitive; an empty string =
    /// no filter, the DefaultOptionHandler empty-value rule). Consumed by
    /// the `--metalink-file` form's pre-expansion entry filter (domain 5);
    /// given on the single-URL form = accepted with a warn-not-effective
    /// disclosure. Every entry filtered out = exit 2 (the aria2
    /// EX_NO_RESULT_WITH_YOUR_PREFS equivalent).
    #[cfg(feature = "metalink")]
    #[arg(long = "metalink-language")]
    pub metalink_language: Option<String>,
    /// Mirror location preference (aria2-compatible name
    /// `--metalink-location`, a comma-separated list; the RFC 5854
    /// `location` advisory value = ISO 3166-1 alpha-2). A hit on an entry
    /// URL's `location` (normalized case-insensitively, the same method
    /// as aria2's `util::lowercase`) applies priority -= 999999 (a direct
    /// translation of `MetalinkEntry::setLocationPriority` —
    /// `-MetalinkResource::getLowestPriority`, at most once per URL).
    /// Consumed by the `--metalink-file` form; the single-URL form =
    /// accepted with a warn-not-effective disclosure.
    #[cfg(feature = "metalink")]
    #[arg(long = "metalink-location")]
    pub metalink_location: Option<String>,
    /// Entry OS filter (aria2-compatible name `--metalink-os`): the
    /// entry's `<os>` set, EXACT match (the same rule as aria2's
    /// `MetalinkEntry::containsOS`; case-sensitive; an empty string = no
    /// filter). Consumed by the `--metalink-file` form.
    #[cfg(feature = "metalink")]
    #[arg(long = "metalink-os")]
    pub metalink_os: Option<String>,
    /// Entry version filter (aria2-compatible name `--metalink-version`):
    /// `<version>` EXACT equality (the same rule as aria2's
    /// `Metalinker::queryEntry` `version != entry->version`;
    /// case-sensitive; an empty string = no filter). Consumed by the
    /// `--metalink-file` form.
    #[cfg(feature = "metalink")]
    #[arg(long = "metalink-version")]
    pub metalink_version: Option<String>,
    /// Protocol preference (aria2-compatible name
    /// `--metalink-preferred-protocol`; the value domain
    /// http|https|ftp|none — aria2's DefaultOptionHandler does not check
    /// the value domain and neither does this build: `none`/empty = no
    /// preference (the usage_text.h "Specify 'none'" rule); other values
    /// match the URL scheme exactly (lowercase normalized). A hit applies
    /// priority -= 999999 to the URL (a direct translation of
    /// `MetalinkEntry::setProtocolPriority`; stacking with a location hit
    /// applies twice). Consumed by the `--metalink-file` form.
    #[cfg(feature = "metalink")]
    #[arg(long = "metalink-preferred-protocol")]
    pub metalink_preferred_protocol: Option<String>,
    /// Per-entry mirror cap (`--metalink-servers`; a fork-extension
    /// acceptance — aria2 1.37.0 prefs.cc has no such name, only the
    /// usage_text.h `TEXT_METALINK_SERVERS` remnant, the historical `-C`
    /// name). Semantics = the entry's `<url>` set pre-sorted by priority
    /// ascending (document order within an equal priority) and truncated
    /// to the first N into the addUri multi-source path (the expansion
    /// seam `expand_add_uri_plans` re-sorts stably on the same key — the
    /// order is conserved). Value domain >= 1. Consumed by the
    /// `--metalink-file` form.
    #[cfg(feature = "metalink")]
    #[arg(
        long = "metalink-servers",
        value_parser = clap::value_parser!(u32).range(1..)
    )]
    pub metalink_servers: Option<u32>,
    /// Relative URI resolution base (aria2-compatible name
    /// `--metalink-base-uri`; the RPC/session face does not accept it — a
    /// declaration-table "not accepted (RPC/session face)" entry). RELATIVE
    /// `<url>`/`<metaurl>` URIs in a `--metalink-file` document are
    /// resolved against this value per RFC 3986 §5 (the same consumption
    /// point as aria2's `MetalinkParserStateMachine::setBaseUri` — the
    /// usage_text.h TEXT_METALINK_BASE_URI two-element face); absolute
    /// URIs pass through verbatim; an entry whose reference fails to
    /// resolve is dropped with a warning (fail-soft, the same soft-drop
    /// discipline as the parse face). A directory-form base should carry
    /// the trailing `/` (the same usage_text.h guidance). Consumed by the
    /// `--metalink-file` form.
    #[cfg(feature = "metalink")]
    #[arg(long = "metalink-base-uri")]
    pub metalink_base_uri: Option<String>,
    /// Follow-torrent switch (aria2-compatible name `--follow-torrent`;
    /// prefs.cc `makePref("follow-torrent")` — usage_text.h
    /// TEXT_FOLLOW_TORRENT "whether or not to download the files
    /// mentioned in .torrent and .metalink files when they are
    /// downloaded"; default **true** = the standing behavior).
    /// **Wiring (the `--metalink-file` form)**: false skips the
    /// `<metaurl mediatype="torrent">` -> torrent conversion (the direct
    /// BT conversion described in the `metalink_file` field doc) — the
    /// metaurl candidates are dropped with a notice and the `<url>`
    /// mirror downloads proceed; an entry with only metaurls then
    /// produces no task (the zero-usable-entries exit-2 face covers a
    /// fully metaurl-only document). Declared
    /// divergence: the taiji face is "conversion skipped" — the
    /// metaurl-as-plain-HTTP-download fallback is not in this build. The
    /// session task-payload face already accepts per-task
    /// `follow-torrent` values (parse_task_options; the RPC
    /// addMetalink face is unchanged) — this gate is the CLI form's
    /// face. Given on the plain-URL forms (no `--metalink-file`) =
    /// accepted with a warn-not-effective disclosure. Both the bare
    /// flag and the `=true|=false` value forms are accepted.
    #[cfg(feature = "metalink")]
    #[arg(
        long = "follow-torrent",
        default_value_t = true,
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    pub follow_torrent: bool,
    /// Unique-protocol selection (aria2-compatible name
    /// `--metalink-enable-unique-protocol`; the metalink group, prefs.cc
    /// same-name entry; DEFAULT false = the aria2 default). **Acceptance
    /// disclosure** (the same style as `--metalink-enable-auto-
    /// discover`, no masquerading): the wiring seam is absent — taiji's
    /// metalink expansion dedups and caps mirrors by priority and
    /// (dir,out) occupancy (the expansion seam's mirror selection), with
    /// no per-protocol unique-selection face (declared divergence).
    /// Given explicitly = one warning, not effective. Both the bare flag
    /// and the `=true|=false` value forms are accepted.
    #[cfg(feature = "metalink")]
    #[arg(
        long = "metalink-enable-unique-protocol",
        action = clap::ArgAction::Set,
        num_args(0..=1),
        require_equals(true),
        default_missing_value = "true"
    )]
    pub metalink_enable_unique_protocol: Option<bool>,
}

impl HttpArgs {
    /// Accepted-but-not-effective disclosure: each explicitly given option
    /// in the deferred group warns once instead of pretending to work.
    /// `--continue=false` is called out separately — that is the aria2
    /// semantic inversion (see the argument docs); the generic warning
    /// must not drown it.
    fn warn_deferred(&self) {
        if self.continue_dl == Some(false) {
            warn!(
                target: "taiji::cli",
                "--continue=false is NOT honored: aria2 would restart from scratch, \
                 but this engine always resumes from the session bitmap (explicit inversion)"
            );
        }
        // Only --continue remains in the deferred group (the inversion gets
        // its own callout).
        if self.continue_dl.is_some() {
            warn!(
                target: "taiji::cli",
                "--continue accepted; resume always honors the session bitmap"
            );
        }
        // Domain 2: `--use-head=true` is treated as invalid-input posture
        // (the probe red line — HEAD semantics are unenforced across HTTP
        // implementations and never a segmentation criterion; disclosed
        // the same way as metalink-enable-auto-discover). false = the
        // status quo (GET probes), no warning.
        if self.use_head == Some(true) {
            warn!(
                target: "taiji::cli",
                "--use-head=true is NOT honored: HEAD is not used as probe evidence \
                 in this engine (HEAD semantics are unenforced across HTTP servers; \
                 probe verdicts require GET + 'Range: bytes=0-0'). Treated as false \
                 (declared difference)"
            );
        }
        // Domain 2: the --ftp-proxy family has no effect on a run with no
        // FTP source (an FTP source present = the add_options /
        // check_proxy_sources explicit rejection, not this warning face).
        // The source face of the metalink form (empty urls) is checked
        // after expansion — not prejudged here.
        let ftp_proxy_family_given = self.ftp_proxy.is_some()
            || self.ftp_proxy_user.is_some()
            || self.ftp_proxy_passwd.is_some();
        if ftp_proxy_family_given
            && !self.urls.is_empty()
            && !self.urls.iter().any(|u| is_ftp_uri(u))
        {
            warn!(
                target: "taiji::cli",
                "--ftp-proxy accepted but NOT effective: no ftp(s):// source in this \
                 run (FTP-over-HTTP proxy is not implemented, declared P2)"
            );
        }
        // Domain 2: the --no-proxy whole-value semantics disclosure
        // (bypass everything + the per-host list is not parsed) + naming
        // each bypassed flag (never silent).
        if self
            .no_proxy
            .as_deref()
            .is_some_and(|v| !v.trim().is_empty())
        {
            if self.no_proxy.as_deref().is_some_and(|v| v.contains(',')) {
                warn!(
                    target: "taiji::cli",
                    "--no-proxy value is treated as a whole (bypass ALL proxy slots); \
                     aria2 per-host exemption list syntax is not parsed"
                );
            }
            for (flag, given_slot) in [
                (
                    "--all-proxy",
                    self.all_proxy.as_deref().is_some_and(|v| !v.is_empty()),
                ),
                (
                    "--http-proxy",
                    self.http_proxy.as_deref().is_some_and(|v| !v.is_empty()),
                ),
                (
                    "--https-proxy",
                    self.https_proxy.as_deref().is_some_and(|v| !v.is_empty()),
                ),
                (
                    "--ftp-proxy",
                    self.ftp_proxy.as_deref().is_some_and(|v| !v.is_empty()),
                ),
            ] {
                if given_slot {
                    warn!(
                        target: "taiji::cli",
                        "--no-proxy bypasses {flag} (whole-value semantics; direct \
                         connection for this run)"
                    );
                }
            }
        }
        // Metalink auto-discovery (declared difference): default off;
        // `true` is accepted but not effective — response-body sniffing
        // auto-conversion is not in this build, disclosed explicitly
        // (never disguised).
        #[cfg(feature = "metalink")]
        if self.metalink_enable_auto_discover == Some(true) {
            warn!(
                target: "taiji::cli",
                "--metalink-enable-auto-discover accepted but NOT effective in this build; \
                 treated as false (declared difference)"
            );
        }
        // Acceptance disclosure: the unique-protocol
        // selection seam is absent (mirror selection = priority +
        // (dir,out) occupancy dedup in the expansion seam); given
        // explicitly = one warning, not effective (the same
        // never-disguised style as auto-discover).
        #[cfg(feature = "metalink")]
        if self.metalink_enable_unique_protocol == Some(true) {
            warn!(
                target: "taiji::cli",
                "--metalink-enable-unique-protocol accepted but NOT effective in this build: \
                 no per-protocol unique-selection seam (mirror selection is by priority \
                 and (dir,out) occupancy; declared difference)"
            );
        }
        // Wiring: --follow-torrent is consumed only by the
        // `--metalink-file` form (the metaurl->torrent gate); a plain-URL
        // run has no metalink face — an explicit false warns once, never
        // silent.
        #[cfg(feature = "metalink")]
        if !self.follow_torrent && self.metalink_file.is_none() {
            warn!(
                target: "taiji::cli",
                "--follow-torrent=false accepted but NOT effective: only the \
                 --metalink-file form has a metaurl->torrent conversion face; \
                 proceeding with plain URL downloads"
            );
        }
        // Domain 5: the metalink selector family is consumed only by the
        // `--metalink-file` form; given on the single-URL form = accepted
        // with a warn-not-effective disclosure (never silent — the
        // "accepted-but-not-effective is a disguise" prohibition).
        #[cfg(feature = "metalink")]
        {
            let selector_given = self.metalink_language.is_some()
                || self.metalink_location.is_some()
                || self.metalink_os.is_some()
                || self.metalink_version.is_some()
                || self.metalink_preferred_protocol.is_some()
                || self.metalink_servers.is_some()
                || self.metalink_base_uri.is_some();
            if selector_given && self.metalink_file.is_none() {
                warn!(
                    target: "taiji::cli",
                    "--metalink-language/--metalink-location/--metalink-os/--metalink-version/\
                     --metalink-preferred-protocol/--metalink-servers/--metalink-base-uri are \
                     only consumed by the --metalink-file form; accepted but NOT effective \
                     for plain URL downloads"
                );
            }
        }
    }

    /// addUri option map (wired options map directly; empty strings are
    /// not sent = the blank-unset semantics). Err = ambiguous proxy-face
    /// input (`--all-proxy` together with `--http-proxy` / credentials
    /// without a proxy subject / https and http credentials on one
    /// carrier) and ambiguous Referer-face input (`--referer` x a
    /// `--header` Referer line) — explicit failure, never silent (exit 2).
    fn add_options(&self) -> Result<BTreeMap<String, String>, String> {
        // A single Referer source (domain 2): the dedicated slot and a
        // manual header line coexisting would send two Referer values
        // (reqwest's same-name header append semantics) — explicit
        // rejection.
        if self
            .referer
            .as_deref()
            .is_some_and(|r| !r.trim().is_empty())
            && self.headers.iter().any(|h| {
                h.split_once(':')
                    .is_some_and(|(n, _)| n.trim().eq_ignore_ascii_case("referer"))
            })
        {
            return Err(
                "taiji.option.invalid: --referer conflicts with an explicit \
                 `--header \"Referer: ...\"` line (single Referer source)"
                    .to_string(),
            );
        }
        let mut options = BTreeMap::from([("dir".to_string(), self.dir.display().to_string())]);
        if let Some(o) = self.out.as_deref().filter(|o| !o.is_empty()) {
            options.insert("out".to_string(), o.to_string());
        }
        if let Some(c) = self.checksum.as_deref().filter(|c| !c.is_empty()) {
            options.insert("checksum".to_string(), c.to_string());
        }
        if let Some(s) = self.incomplete_suffix.as_deref().filter(|s| !s.is_empty()) {
            options.insert("http-incomplete-suffix".to_string(), s.to_string());
        }
        // Complete face (frozen aria2 names; values in aria2 option string
        // form).
        if let Some(v) = self.remote_time {
            options.insert("remote-time".to_string(), v.to_string());
        }
        if let Some(v) = self.timeout {
            options.insert("timeout".to_string(), v.to_string());
        }
        if let Some(v) = self.connect_timeout {
            options.insert("connect-timeout".to_string(), v.to_string());
        }
        if let Some(v) = self.max_tries {
            options.insert("max-tries".to_string(), v.to_string());
        }
        if let Some(v) = self.retry_wait {
            options.insert("retry-wait".to_string(), v.to_string());
        }
        if let Some(ua) = self.user_agent.as_deref().filter(|v| !v.is_empty()) {
            options.insert("user-agent".to_string(), ua.to_string());
        }
        // aria2 semantics: multiple headers are joined with "\n" into one
        // option value.
        if !self.headers.is_empty() {
            options.insert("header".to_string(), self.headers.join("\n"));
        }
        if let Some(u) = self.http_user.as_deref().filter(|v| !v.is_empty()) {
            options.insert("http-user".to_string(), u.to_string());
        }
        if let Some(p) = self.http_passwd.as_deref().filter(|v| !v.is_empty()) {
            options.insert("http-passwd".to_string(), p.to_string());
        }
        // Per-scheme proxy slots (domain 2: the `--all-proxy`/`--http-proxy`
        // single slot + the `--https-proxy` dedicated slot + credential
        // folding; ambiguous input propagates as Err — see
        // [`HttpArgs::resolved_proxies`]) + the `--no-proxy` whole-value
        // bypass (bypassed = a payload with zero proxy keys, direct
        // connection).
        let proxies = self.resolved_proxies()?;
        let bypassed = self
            .no_proxy
            .as_deref()
            .is_some_and(|v| !v.trim().is_empty());
        if !bypassed {
            if let Some(p) = proxies.all_proxy {
                options.insert("all-proxy".to_string(), p);
            }
            if let Some(p) = proxies.https_proxy {
                options.insert("https-proxy".to_string(), p);
            }
        }
        // Per-task speed limits (--max-download-limit/--max-upload-limit
        // sent through the addUri option face — the per_torrent bucket
        // enforcement face, the same channel for HTTP and BT tasks; 0 =
        // unlimited sent as-is, the same session-side parse_size
        // semantics).
        if let Some(v) = self.max_download_limit {
            options.insert("max-download-limit".to_string(), v.to_string());
        }
        if let Some(v) = self.max_upload_limit {
            options.insert("max-upload-limit".to_string(), v.to_string());
        }
        if let Some(v) = self.check_certificate {
            options.insert("check-certificate".to_string(), v.to_string());
        }
        // Referer header (domain 2): mapped directly onto the session
        // `referer` key (the RequestCtx.referer projection); the conflict
        // with a --header Referer line was already explicitly rejected
        // earlier in this function.
        if let Some(r) = self.referer.as_deref().filter(|r| !r.trim().is_empty()) {
            options.insert("referer".to_string(), r.trim().to_string());
        }
        // Transparent gzip decompression switch (domain 2): the bool dual
        // form maps directly (the default false is not sent — the
        // session-side default = the status-quo identity).
        if let Some(v) = self.http_accept_gzip {
            options.insert("http-accept-gzip".to_string(), v.to_string());
        }
        if let Some(v) = self
            .ca_certificate
            .as_deref()
            .filter(|v| !v.trim().is_empty())
        {
            options.insert("ca-certificate".to_string(), v.to_string());
        }
        // Cookie ingestion gate: the CLI only forwards; loading and
        // validation live in the session-side add_uri direct-read arm as
        // the single source of truth (fail-closed task-level rejection).
        if let Some(v) = self
            .load_cookies
            .as_deref()
            .filter(|v| !v.trim().is_empty())
        {
            options.insert("load-cookies".to_string(), v.to_string());
        }
        if let Some(v) = self.http_max_per_host {
            options.insert("http-max-per-host".to_string(), v.to_string());
        }
        // Scheduler group (frozen aria2 names + taiji extensions).
        if let Some(v) = self.split {
            options.insert("split".to_string(), v.to_string());
        }
        if let Some(v) = self
            .min_split_size
            .as_deref()
            .filter(|v| !v.trim().is_empty())
        {
            options.insert("min-split-size".to_string(), v.to_string());
        }
        if let Some(v) = self.max_connection_per_server {
            options.insert("max-connection-per-server".to_string(), v.to_string());
        }
        if let Some(v) = self.http_stall_window {
            options.insert("http-stall-window".to_string(), v.to_string());
        }
        if let Some(v) = self
            .http_scheduler
            .as_deref()
            .filter(|v| !v.trim().is_empty())
        {
            options.insert("http-scheduler".to_string(), v.to_string());
        }
        if let Some(v) = self
            .http_block_size
            .as_deref()
            .filter(|v| !v.trim().is_empty())
        {
            options.insert("http-block-size".to_string(), v.to_string());
        }
        if let Some(v) = self
            .http_max_chunk
            .as_deref()
            .filter(|v| !v.trim().is_empty())
        {
            options.insert("http-max-chunk".to_string(), v.to_string());
        }
        // Protocol form: the CLI only forwards; domain validation belongs
        // to the session-side `http_task_runtime_options` single source of
        // truth (unknown values reject the task).
        if let Some(v) = self
            .http_protocol
            .as_deref()
            .filter(|v| !v.trim().is_empty())
        {
            options.insert("http-protocol".to_string(), v.to_string());
        }
        // h2 flow-control windows: the CLI only forwards; domain validation
        // belongs to the session-side `http_task_runtime_options` single
        // source of truth (out-of-domain rejects the task).
        if let Some(v) = self
            .http2_adaptive_window
            .as_deref()
            .filter(|v| !v.trim().is_empty())
        {
            options.insert("http2-adaptive-window".to_string(), v.to_string());
        }
        if let Some(v) = self
            .http2_stream_window
            .as_deref()
            .filter(|v| !v.trim().is_empty())
        {
            options.insert("http2-stream-window".to_string(), v.to_string());
        }
        if let Some(v) = self
            .http2_connection_window
            .as_deref()
            .filter(|v| !v.trim().is_empty())
        {
            options.insert("http2-connection-window".to_string(), v.to_string());
        }
        // h2 multi-connection + keep-alive: the CLI only forwards; domain
        // validation belongs to the session-side
        // `http_task_runtime_options` single source of truth
        // (out-of-domain rejects the task).
        if let Some(v) = self
            .http2_max_connections
            .as_deref()
            .filter(|v| !v.trim().is_empty())
        {
            options.insert("http2-max-connections".to_string(), v.to_string());
        }
        if let Some(v) = self
            .http2_keep_alive_interval
            .as_deref()
            .filter(|v| !v.trim().is_empty())
        {
            options.insert("http2-keep-alive-interval".to_string(), v.to_string());
        }
        // FTP family (ftp-pasv=false is still sent as-is — the session
        // side rejects it by domain and gives the declared semantics; the
        // CLI does not preempt that judgment).
        if let Some(u) = self.ftp_user.as_deref().filter(|v| !v.is_empty()) {
            options.insert("ftp-user".to_string(), u.to_string());
        }
        if let Some(p) = self.ftp_passwd.as_deref().filter(|v| !v.is_empty()) {
            options.insert("ftp-passwd".to_string(), p.to_string());
        }
        if let Some(v) = self.ftp_ssl.as_deref().filter(|v| !v.is_empty()) {
            options.insert("ftp-ssl".to_string(), v.to_string());
        }
        if let Some(v) = self.ftp_pasv {
            options.insert("ftp-pasv".to_string(), v.to_string());
        }
        if let Some(v) = self.ftp_reuse_connection {
            options.insert("ftp-reuse-connection".to_string(), v.to_string());
        }
        Ok(options)
    }

    /// Per-scheme proxy-slot resolution (domain 2): `--all-proxy` union
    /// `--http-proxy` → one all slot + the `--https-proxy` dedicated slot +
    /// the three credential families folded in (the http/https/ftp
    /// family each folds into its own slot URL's userinfo; a URL that
    /// already carries userinfo wins). Ambiguous input fails explicitly
    /// (the Err text = the exit-2 error face):
    /// `--all-proxy` x `--http-proxy` together (single-slot source
    /// mutual exclusion, the batch-C rule unchanged) / any family's
    /// password without a user / credentials without a proxy subject /
    /// https credentials and http credentials landing on the same all-slot
    /// URL (a single userinfo carrier).
    ///
    /// The priority order is not finalized here but at transport build
    /// time: the two slots are sent COEXISTING (the `all-proxy` +
    /// `https-proxy` payload keys), and reqwest's first-match-wins with
    /// the dedicated slot registered first yields "dedicated > all > no
    /// proxy". The `--no-proxy` bypass = the caller drops this resolution
    /// result (a payload with zero proxy keys).
    fn resolved_proxies(&self) -> Result<ProxySlots, String> {
        let given = |v: &Option<String>| v.as_deref().is_some_and(|s| !s.is_empty());
        // A single all-slot source (the batch-C rule unchanged).
        if given(&self.all_proxy) && given(&self.http_proxy) {
            return Err(
                "taiji.option.invalid: --all-proxy and --http-proxy are mutually \
                 exclusive (single all-proxy slot)"
                    .to_string(),
            );
        }
        let base = if given(&self.all_proxy) {
            self.all_proxy.as_deref()
        } else {
            self.http_proxy.as_deref()
        };
        let https_slot = self.https_proxy.as_deref().filter(|v| !v.is_empty());
        let ftp_slot = self.ftp_proxy.as_deref().filter(|v| !v.is_empty());
        fn family<'a>(
            u: &'a Option<String>,
            p: &'a Option<String>,
        ) -> (Option<&'a str>, Option<&'a str>) {
            (
                u.as_deref().filter(|s| !s.is_empty()),
                p.as_deref().filter(|s| !s.is_empty()),
            )
        }
        let (http_user, http_pass) = family(&self.http_proxy_user, &self.http_proxy_passwd);
        let (https_user, https_pass) = family(&self.https_proxy_user, &self.https_proxy_passwd);
        let (ftp_user, ftp_pass) = family(&self.ftp_proxy_user, &self.ftp_proxy_passwd);
        // A password without a user (the same rule for all three families
        // — no auth subject).
        for (user, pass, flag) in [
            (http_user, http_pass, "--http-proxy-passwd"),
            (https_user, https_pass, "--https-proxy-passwd"),
            (ftp_user, ftp_pass, "--ftp-proxy-passwd"),
        ] {
            if user.is_none() && pass.is_some() {
                return Err(format!(
                    "taiji.option.invalid: {flag} requires its --*-proxy-user counterpart"
                ));
            }
        }
        // Credentials without a proxy subject (each family's fold target
        // missing = reject).
        if (http_user.is_some() || http_pass.is_some()) && base.is_none() {
            return Err(
                "taiji.option.invalid: --http-proxy-user/--http-proxy-passwd given \
                 without --http-proxy/--all-proxy"
                    .to_string(),
            );
        }
        // The https credential fold target = the dedicated slot > the all
        // slot (the single-slot fallback also serves https).
        let https_fold_target = https_slot.or(base);
        if (https_user.is_some() || https_pass.is_some()) && https_fold_target.is_none() {
            return Err(
                "taiji.option.invalid: --https-proxy-user/--https-proxy-passwd given \
                 without --https-proxy/--all-proxy/--http-proxy"
                    .to_string(),
            );
        }
        if (ftp_user.is_some() || ftp_pass.is_some()) && ftp_slot.is_none() {
            return Err(
                "taiji.option.invalid: --ftp-proxy-user/--ftp-proxy-passwd given \
                 without --ftp-proxy"
                    .to_string(),
            );
        }
        // A single userinfo carrier: https credentials falling back to the
        // all-slot URL while http credentials are also present — one URL
        // carries at most one userinfo, explicit rejection (pointing at
        // the dedicated slot).
        if https_slot.is_none()
            && base.is_some()
            && (https_user.is_some() || https_pass.is_some())
            && (http_user.is_some() || http_pass.is_some())
        {
            return Err(
                "taiji.option.invalid: --http-proxy-user and --https-proxy-user would \
                 both fold into the single all-proxy URL userinfo (one carrier per URL); \
                 give --https-proxy for a dedicated carrier"
                    .to_string(),
            );
        }
        let all_proxy = match base {
            Some(url) => {
                // The https credential fallback target: without the
                // dedicated slot they fold into the all-slot URL (the
                // single-slot fallback also serves https); with the
                // dedicated slot present the https credentials follow the
                // dedicated slot and the all slot folds only the http
                // family. The same-carrier two-family conflict was already
                // explicitly rejected above — at most one family is
                // non-empty here (the or chain has no override face).
                let (fallback_user, fallback_pass) = if https_slot.is_none() {
                    (https_user, https_pass)
                } else {
                    (None, None)
                };
                Some(apply_proxy_credentials(
                    url,
                    http_user.or(fallback_user),
                    http_pass.or(fallback_pass),
                )?)
            }
            None => None,
        };
        let https_proxy = match https_slot {
            Some(url) => Some(apply_proxy_credentials(url, https_user, https_pass)?),
            None => None,
        };
        // The ftp slot has no payload key (the declared P2 face) — this
        // only runs the value-domain validation (the scheme gate + the
        // credential-folding feasibility; out-of-domain values like socks
        // fail early; the fold product has no consumer and is dropped).
        if let Some(url) = ftp_slot {
            let _ = apply_proxy_credentials(url, ftp_user, ftp_pass)?;
        }
        Ok(ProxySlots {
            all_proxy,
            https_proxy,
        })
    }

    /// Proxy face x source-scheme cross-check (domain 2): the `--ftp-proxy`
    /// family present and any URI ftp(s):// → explicit rejection
    /// (FTP-over-HTTP proxying P2 is not done — the same rejection style
    /// as `--ftp-pasv=false`). The single-URL form passes the CLI sources,
    /// the metalink form passes the expanded entry URIs.
    fn check_proxy_sources<'a>(
        &self,
        uris: impl IntoIterator<Item = &'a String>,
    ) -> Result<(), String> {
        // The --no-proxy whole-value bypass: every slot (the ftp slot
        // included) is ineffective — direct FTP connection is an
        // implemented path, so a moot flag does not block (the bypass face
        // is disclosed in the warn_deferred warnings).
        if self
            .no_proxy
            .as_deref()
            .is_some_and(|v| !v.trim().is_empty())
        {
            return Ok(());
        }
        let ftp_proxy_family_given = self.ftp_proxy.is_some()
            || self.ftp_proxy_user.is_some()
            || self.ftp_proxy_passwd.is_some();
        if ftp_proxy_family_given && uris.into_iter().any(|u| is_ftp_uri(u)) {
            return Err(
                "taiji.option.invalid: --ftp-proxy with an ftp(s):// source is not \
                 supported: FTP-over-HTTP proxying is not implemented (declared P2; \
                 the FTP transport connects directly)"
                    .to_string(),
            );
        }
        Ok(())
    }
}

/// The ftp(s):// URI verdict (the same prefix domain as the session-side
/// source-kind dispatch: `ftp://` + `ftps://`).
fn is_ftp_uri(uri: &str) -> bool {
    uri.starts_with("ftp://") || uri.starts_with("ftps://")
}

/// The proxy-slot resolution product (the addUri payload projection;
/// `None` = the key absent).
struct ProxySlots {
    /// The all slot (the `--all-proxy` union `--http-proxy` mapping;
    /// http+https targets).
    all_proxy: Option<String>,
    /// The https dedicated slot (`--https-proxy`; effective order =
    /// dedicated slot > all slot).
    https_proxy: Option<String>,
}

/// Proxy-URL credential folding (the userinfo single-carrier form —
/// taiji's declared face): a URL authority that already carries userinfo
/// wins explicitly (returned verbatim); otherwise `user[:pass]@` is
/// inserted before the authority (the RFC 3986 authority terminates at
/// `/`, `?`, `#` — path/query preserved verbatim). A missing scheme =
/// Err (the same face as the session-side all-proxy value-domain
/// validation; the CLI-context text is produced here first).
fn apply_proxy_credentials(
    url: &str,
    user: Option<&str>,
    pass: Option<&str>,
) -> Result<String, String> {
    let Some((scheme, rest)) = url.split_once("://") else {
        return Err(format!(
            "taiji.option.invalid: invalid proxy url (missing scheme://): {url}"
        ));
    };
    if scheme != "http" && scheme != "https" {
        return Err(format!(
            "taiji.option.invalid: unsupported proxy scheme {scheme:?} (http/https only; \
             socks requires the transport-side declaration)"
        ));
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    if authority.contains('@') {
        return Ok(url.to_string());
    }
    match user {
        Some(u) => {
            let cred = match pass {
                Some(p) => format!("{u}:{p}"),
                None => u.to_string(),
            };
            Ok(format!("{scheme}://{cred}@{authority}{tail}"))
        }
        None => Ok(url.to_string()),
    }
}

// ---- attach decision surface (row-level, pure functions, unit-testable) ----

/// CLI-side projection of a session-store http_task row (the input shape
/// for attach decisions; projected from the same bootstrap read path
/// `load_http_tasks_at_startup` — decision unit tests need no store
/// type).
#[derive(Debug, Clone)]
struct InflightRow {
    gid: String,
    url: String,
    dir: String,
    out: String,
    config_json: String,
}

/// CLI read subset of a row's config_json (producer: core `http_task`'s
/// `HttpPersistConfig`; this side reads only the checksum/suffix keys,
/// missing keys mean defaults — fields outside the schema get zero
/// interpretation. Uses serde_json::Value to avoid a serde derive
/// dependency edge).
#[derive(Debug, Default, PartialEq)]
struct RowConfig {
    checksum: Option<String>,
    incomplete_suffix: Option<String>,
}

impl RowConfig {
    fn parse(config_json: &str) -> Self {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(config_json) else {
            return RowConfig::default();
        };
        let field = |key: &str| {
            v.get(key)
                .and_then(serde_json::Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        };
        RowConfig {
            checksum: field("checksum"),
            incomplete_suffix: field("incomplete_suffix"),
        }
    }
}

/// Attach decision.
#[derive(Debug, PartialEq)]
enum AttachDecision {
    /// No matching in-flight row: create via addUri.
    None,
    /// Match: wait for that task to finish (warnings = explicit disclosure
    /// of dropped options).
    Attach { gid: String, warnings: Vec<String> },
    /// Attach rejected (checksum conflicts with the persisted value — the
    /// in-flight task finalizes with its persisted value and this run's
    /// value would be silently dropped; better to fail explicitly).
    Reject { reason: String },
}

/// Checksum normalization (scheme and hex are both case-insensitive — the
/// same rule as the engine's verification; compared as a whole after
/// trim, so a scheme spelling difference is a value difference).
fn normalize_checksum(v: &str) -> String {
    v.trim().to_ascii_lowercase()
}

/// Directory equality: canonicalized path comparison (relative / `..` /
/// symlink forms never produce false negatives); if either side cannot be
/// canonicalized (e.g. the directory does not exist) fall back to raw
/// string comparison.
fn same_dir(a: &str, b: &Path) -> bool {
    // canonicalize's OS call goes through the winpath conversion (long
    // paths without the Windows prefix always fail -> false negative;
    // both sides use the same function, comparison semantics unchanged).
    let canon = |p: &Path| {
        taiji_io::winpath::to_fs_path(p)
            .canonicalize()
            .unwrap_or_else(|_| p.to_path_buf())
    };
    canon(Path::new(a)) == canon(b)
}

/// Attach decision (pure function; rows come from the bootstrap read
/// path's active rows).
///
/// Match key: source URL (the task's primary URI persisted verbatim,
/// equal to this command's first URI) + directory (canonicalized
/// comparison) + exact file-name equality when `--out` is explicit. On a
/// hit, the row's persisted config is compared with this run's options:
///
/// - `--checksum` given on both sides with different values ->
/// [`AttachDecision::Reject`] (the only rejection — the checksum is the
/// completion-time final verdict, and attaching would silently void the
/// new value);
/// - other differences (one side missing / suffix differs) -> warnings
/// returned with [`AttachDecision::Attach`] (the persisted value wins;
/// the new value is disclosed then dropped).
fn decide_attach(
    rows: &[InflightRow],
    url: &str,
    dir: &Path,
    out: Option<&str>,
    checksum: Option<&str>,
    suffix: Option<&str>,
) -> AttachDecision {
    let Some(row) = rows.iter().find(|r| {
        let url_hit = r.url == url;
        let dir_hit = same_dir(&r.dir, dir);
        let out_hit = match out {
            Some(o) => r.out == o,
            None => true,
        };
        url_hit && dir_hit && out_hit
    }) else {
        return AttachDecision::None;
    };
    let persisted = RowConfig::parse(&row.config_json);
    let mut warnings: Vec<String> = Vec::new();
    match (
        persisted.checksum.as_deref().map(normalize_checksum),
        checksum.map(normalize_checksum),
    ) {
        (Some(p), Some(n)) if p != n => {
            return AttachDecision::Reject {
                reason: format!(
                    "in-flight task {} was created with --checksum {:?}; refusing to attach \
                     with conflicting --checksum {:?} (the running task would finalize with \
                     its persisted verification). Remove the in-flight task first or use \
                     matching options",
                    row.gid, p, n
                ),
            };
        }
        (Some(p), None) => warnings.push(format!(
            "attaching in-flight task {gid}: it will still verify with its persisted \
             --checksum={p:?} (no --checksum given this run)",
            gid = row.gid,
            p = p
        )),
        (None, Some(n)) => warnings.push(format!(
            "attaching in-flight task {gid}: it was created WITHOUT --checksum; the \
             requested --checksum={n:?} will NOT apply to it",
            gid = row.gid,
            n = n
        )),
        _ => {}
    }
    if let (Some(persisted_suffix), Some(requested)) = (&persisted.incomplete_suffix, suffix)
        && persisted_suffix != requested
    {
        warnings.push(format!(
            "attaching in-flight task {gid}: incomplete suffix stays at its persisted \
                 value {persisted_suffix:?} (--http-incomplete-suffix={requested:?} is dropped)",
            gid = row.gid,
            persisted_suffix = persisted_suffix,
            requested = requested
        ));
    }
    AttachDecision::Attach {
        gid: row.gid.clone(),
        warnings,
    }
}

/// Session-store mutex acquisition (shared base: the single-URL and
/// metalink forms use the same source; exit-code semantics = held 1 /
/// filesystem 2). The lock handle lives until teardown (dropped =
/// released). Opening and locking the store is disk IO (blocking; done
/// via spawn_blocking; the Connection is Send and the locked connection
/// moves into this task).
pub(crate) async fn acquire_db_lock(db: &Path) -> Result<crate::db_lock::SessionDbLock, i32> {
    let lock_db = db.to_path_buf();
    match tokio::task::spawn_blocking(move || crate::db_lock::SessionDbLock::acquire(&lock_db))
        .await
    {
        Ok(Ok(l)) => {
            info!(target: "taiji::cli", lock = %l.path().display(),
            "session lock acquired (single-session guard)");
            Ok(l)
        }
        Ok(Err(crate::db_lock::LockError::Held { path })) => {
            error!(target: "taiji::cli",
            lock = %path.display(),
            "session db is held by another taiji process: concurrent sessions on one \
             db would co-write the same .part (lockfile guard)");
            Err(1)
        }
        Ok(Err(crate::db_lock::LockError::Io { path, error })) => {
            error!(target: "taiji::cli", lock = %path.display(), %error,
            "cannot create session db lockfile");
            Err(2)
        }
        Err(e) => {
            error!(target: "taiji::cli", %e, "session lock join failed");
            Err(2)
        }
    }
}

/// Session-store open + actor bootstrap (shared base for the metalink
/// form; the tuple type follows `open_session_writer` inference —
/// PersistHandle is a store-private re-export, not named here). Open
/// failure = degraded run without persistence (same as the single-URL
/// form).
#[cfg(feature = "metalink")]
async fn open_session_for_metalink(
    db: PathBuf,
    dir: PathBuf,
    http_max_per_host: u32,
    summary_interval: u32,
) -> (
    std::sync::Arc<SessionHandle>,
    tokio::task::JoinHandle<()>,
    Option<tokio::task::JoinHandle<()>>,
) {
    let opened = match taiji_core::session::persist::import::open_session_writer_with_metrics(db)
        .await
    {
        Ok((h, j)) => (Some(h), Some(j)),
        Err(e) => {
            error!(target: "taiji::cli", %e, "cannot open session db; running WITHOUT persistence");
            (None, None)
        }
    };
    let options = SessionOptions {
        global: GlobalOptions {
            dir,
            // Same face as the single-URL form (the value is also present
            // in the addUri options of metalink-expanded subtasks; both
            // faces agree so there is no conflict; this only seeds session
            // initialization — all subtasks go through addUri, run-time
            // adjustment uses the same channel).
            http_max_per_host,
            // Periodic task summary (direct CLI mapping; 0 = disabled).
            summary_interval,
            ..Default::default()
        },
    };
    let (session, actor_join) = SessionActor::spawn_with_persist(options, opened.0);
    (std::sync::Arc::new(session), actor_join, opened.1)
}

/// Metalink document read from disk (blocking work via spawn_blocking):
/// the size is pre-checked BEFORE the read — the 16MiB document cap
/// rejects oversized files before they enter process memory (closing off
/// `std::fs::read`'s unbounded blind read). A TOCTOU window remains
/// between the pre-check and the read (the file can grow concurrently),
/// so the parse side enforces the same cap — the pre-check is resource
/// hygiene, parsing is enforcement; they stack, neither replaces the
/// other.
#[cfg(feature = "metalink")]
#[derive(Debug)]
enum MetalinkDocReadError {
    /// IO failure across open/stat/read (normalized form, including
    /// blocking-task join failures).
    Io(std::io::Error),
    /// Pre-read size check hit the document cap (len = bytes measured at
    /// pre-check).
    Oversize { len: u64, limit: u64 },
}

#[cfg(feature = "metalink")]
async fn read_metalink_document(path: PathBuf) -> Result<Vec<u8>, MetalinkDocReadError> {
    use taiji_rpc::metalink::MAX_DOCUMENT_BYTES;
    tokio::task::spawn_blocking(move || {
        // The pre-check stat and the read go through the winpath
        // conversion (an identity borrow off Windows; the error surface
        // keeps the original path).
        let limit = MAX_DOCUMENT_BYTES as u64;
        let len = std::fs::metadata(taiji_io::winpath::to_fs_path(&path))
            .map_err(MetalinkDocReadError::Io)?
            .len();
        if len > limit {
            return Err(MetalinkDocReadError::Oversize { len, limit });
        }
        std::fs::read(taiji_io::winpath::to_fs_path(&path)).map_err(MetalinkDocReadError::Io)
    })
    .await
    .map_err(|e| MetalinkDocReadError::Io(std::io::Error::other(e.to_string())))?
}

/// Caller-option drop disclosure for the metalink form (aligns with the
/// warn_deferred/attach "never silently drop user options" discipline):
/// explicit `--out`/`--checksum` yields the warning text (empty = no
/// warning; empty string = unset semantics, no warning, same rule as
/// add_options). Single source for the text, so tests can pin it.
#[cfg(feature = "metalink")]
fn metalink_dropped_option_warnings(out: Option<&str>, checksum: Option<&str>) -> Vec<String> {
    let non_blank = |v: Option<&str>| v.is_some_and(|s| !s.is_empty());
    let mut warnings = Vec::new();
    if non_blank(out) {
        warnings.push(
            "--out is NOT forwarded to metalink subtasks: each entry's name becomes the \
             per-task out (declared difference)"
                .to_string(),
        );
    }
    if non_blank(checksum) {
        warnings.push(
            "--checksum is NOT forwarded to metalink subtasks: entry checksums come from \
             the document's own hash declarations only, sha-256 preferred among the \
             six-algorithm --checksum domain (declared difference)"
                .to_string(),
        );
    }
    warnings
}

/// The metalink selector (domain 5, the single point before the
/// `--metalink-file` form expands): relative-base resolution → entry
/// preference filtering → location/protocol priority boost → mirror cap.
///
/// aria2 anchors (read-only reference):
/// - Entry filtering = `Metalinker.cc queryEntry` — version EXACT
/// equality, language/os EXACT containment
/// (`MetalinkEntry::containsLanguage` / `containsOS`); an empty option
/// value = no filtering (the DefaultOptionHandler empty value);
/// - The priority boost = `Metalink2RequestGroup.cc` — a URL
/// matching `--metalink-location` (compared after lowercase
/// normalization) or `--metalink-preferred-protocol` (compared via
/// `MetalinkResource::getTypeString`) gets
/// `priority += -MetalinkResource::getLowestPriority` (once per
/// criterion, both hits stack); saturating subtraction on the u32 face
/// (0 = best; the ordering within an equal-priority group stays in
/// document order via the expansion seam's stable sort — the
/// post-boost order invariant is not broken);
/// - The mirror cap = the fork extension `--metalink-servers` (a
/// DECLARED_OPTION_DIFFS declaration-table entry): a stable pre-sort by
/// (priority, document order) truncated to the first N — the expansion
/// seam `expand_add_uri_plans` re-sorts stably on the same key, so the
/// order is conserved.
///
/// Every entry filtered out by the preferences = the caller exits 2 (the
/// aria2 `EX_NO_RESULT_WITH_YOUR_PREFS` equivalent, decided in
/// [`run_metalink`]).
#[cfg(feature = "metalink")]
fn apply_metalink_selection(args: &HttpArgs, doc: &mut taiji_rpc::metalink::Metalink) {
    // 1. The relative URI resolution base (RFC 3986 §5;
    // usage_text.h TEXT_METALINK_BASE_URI: both the metalink:url and
    // metalink:metaurl element faces). Absolute URIs pass through
    // verbatim; an entry whose reference fails to resolve is dropped
    // with a warning (fail-soft, the same soft-drop discipline as the
    // parse face).
    if let Some(base) = args
        .metalink_base_uri
        .as_deref()
        .map(str::trim)
        .filter(|b| !b.is_empty())
    {
        let mut dropped = 0usize;
        for f in &mut doc.files {
            for u in &mut f.urls {
                match resolve_uri_reference(base, &u.uri) {
                    Some(abs) => u.uri = abs,
                    None => {
                        u.uri.clear();
                        dropped += 1;
                    }
                }
            }
            f.urls.retain(|u| !u.uri.is_empty());
            for mu in &mut f.metaurls {
                match resolve_uri_reference(base, &mu.uri) {
                    Some(abs) => mu.uri = abs,
                    None => {
                        mu.uri.clear();
                        dropped += 1;
                    }
                }
            }
            f.metaurls.retain(|mu| !mu.uri.is_empty());
        }
        if dropped > 0 {
            warn!(
                target: "taiji::cli",
                dropped,
                base = %base,
                "--metalink-base-uri: relative URIs failed to resolve; entries dropped"
            );
        }
    }
    // 2. Entry preference filtering (the queryEntry rule; an empty string
    // = that criterion does not filter).
    let lang = args.metalink_language.as_deref().unwrap_or("");
    let os = args.metalink_os.as_deref().unwrap_or("");
    let ver = args.metalink_version.as_deref().unwrap_or("");
    if !(lang.is_empty() && os.is_empty() && ver.is_empty()) {
        let before = doc.files.len();
        doc.files.retain(|f| {
            (ver.is_empty() || f.version.as_deref() == Some(ver))
                && (lang.is_empty() || f.languages.iter().any(|l| l == lang))
                && (os.is_empty() || f.oses.iter().any(|o| o == os))
        });
        info!(
            target: "taiji::cli",
            kept = doc.files.len(),
            dropped = before - doc.files.len(),
            "metalink preference filter applied (--metalink-language/os/version)"
        );
    }
    // 3. The location/protocol priority boost (once per criterion;
    // saturating subtraction on the u32 face).
    let locations: Vec<String> = args
        .metalink_location
        .as_deref()
        .map(|l| {
            l.split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let preferred_proto = args
        .metalink_preferred_protocol
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty() && !p.eq_ignore_ascii_case("none"))
        .map(str::to_ascii_lowercase);
    if !locations.is_empty() || preferred_proto.is_some() {
        for f in &mut doc.files {
            for u in &mut f.urls {
                let mut priority = u.priority;
                if u.location
                    .as_deref()
                    .map(str::to_ascii_lowercase)
                    .is_some_and(|l| locations.contains(&l))
                {
                    priority = priority.saturating_sub(taiji_rpc::metalink::DEFAULT_PRIORITY);
                }
                if let Some(p) = &preferred_proto
                    && uri_scheme(&u.uri).is_some_and(|s| s.eq_ignore_ascii_case(p))
                {
                    priority = priority.saturating_sub(taiji_rpc::metalink::DEFAULT_PRIORITY);
                }
                u.priority = priority;
            }
        }
    }
    // 4. The mirror cap (the fork extension): a stable pre-sort truncated
    // to the first N (order conserved under the re-sort on the same
    // key).
    if let Some(n) = args.metalink_servers {
        for f in &mut doc.files {
            if f.urls.len() <= n as usize {
                continue;
            }
            let mut order: Vec<(u32, usize)> = f
                .urls
                .iter()
                .enumerate()
                .map(|(i, u)| (u.priority, i))
                .collect();
            order.sort_by_key(|&(p, i)| (p, i));
            let keep: std::collections::HashSet<usize> =
                order.into_iter().take(n as usize).map(|(_, i)| i).collect();
            let mut i = 0usize;
            f.urls.retain(|_| {
                let k = keep.contains(&i);
                i += 1;
                k
            });
        }
    }
}

/// The `--follow-torrent` gate (wired into the CLI face; a pure function
/// for the decision-table test): `true` = an identity (the standing
/// behavior — `<metaurl mediatype="torrent">` converts directly to
/// torrent tasks); `false` = the metaurl candidates are cleared so the
/// expansion seam produces no BT tasks and the `<url>` mirror downloads
/// proceed. Declared face: "conversion skipped" — the
/// metaurl-as-plain-HTTP-download fallback is not in this build.
/// Returns the number of cleared metaurl candidates (the caller's
/// notice count; 0 = no notice).
#[cfg(feature = "metalink")]
fn apply_follow_torrent_gate(
    follow_torrent: bool,
    doc: &mut taiji_rpc::metalink::Metalink,
) -> usize {
    if follow_torrent {
        return 0;
    }
    let mut skipped = 0usize;
    for f in &mut doc.files {
        skipped += f.metaurls.len();
        f.metaurls.clear();
    }
    skipped
}

/// URI scheme-face recognition (RFC 3986 §3.1: a leading alpha followed
/// by alphanumerics/+/-/.; the presence of `scheme:` is the
/// absolute-reference verdict — shared by the relative-base resolution
/// and the preferred-protocol comparison).
#[cfg(feature = "metalink")]
fn uri_scheme(s: &str) -> Option<&str> {
    let i = s.find(':')?;
    let sch = &s[..i];
    (!sch.is_empty()
        && sch.starts_with(|c: char| c.is_ascii_alphabetic())
        && sch
            .chars()
            .all(|c: char| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
    .then_some(sch)
}

/// RFC 3986 §5 relative-reference resolution (a restricted layered form):
/// `base` must be the `scheme://authority[/path][?query]` form. Rules
/// (§5.2.2/§5.2.3/§5.2.4): a reference with a scheme = absolute,
/// verbatim; a `//` prefix = network-path, inheriting the base scheme; a
/// path starting with `/` = the absolute-path replacement; otherwise it
/// merges into the base directory segments; dot segments are removed and
/// the result recombined, the query comes from the reference side (with a
/// fallback to the base query when the reference has no path); the
/// fragment never participates in mirror URIs (stripped). `None` = the
/// base form is unparseable.
#[cfg(feature = "metalink")]
fn resolve_uri_reference(base: &str, r: &str) -> Option<String> {
    let r = r.split('#').next().unwrap_or(r);
    if r.is_empty() {
        return Some(base.to_string());
    }
    if uri_scheme(r).is_some() {
        return Some(r.to_string());
    }
    if let Some(rest) = r.strip_prefix("//") {
        let scheme = base.split_once("://")?.0;
        return Some(format!("{scheme}://{rest}"));
    }
    let (scheme, rest) = base.split_once("://")?;
    let (authority, bpath_q) = match rest.split_once('/') {
        Some((a, p)) => (a, p),
        // A pathless base: an absolute-path reference concatenates
        // directly, a relative reference joins the directory root.
        None => {
            return Some(if r.starts_with('/') {
                format!("{base}{r}")
            } else {
                format!("{base}/{r}")
            });
        }
    };
    let (bpath, bquery) = match bpath_q.split_once('?') {
        Some((p, q)) => (format!("/{p}"), Some(q)),
        None => (format!("/{bpath_q}"), None),
    };
    let (rpath, rquery) = match r.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (r, None),
    };
    // An empty-path reference (query only / empty) → the full base path
    // is inherited (the §5.2.2 empty-path arm — the base query falls back
    // only while the reference query is absent).
    let (path, inherit_base_query) = if rpath.is_empty() {
        (bpath, true)
    } else if rpath.starts_with('/') {
        (remove_dot_segments(rpath), false)
    } else {
        let dir = bpath
            .rsplit_once('/')
            .map(|(d, _)| d.to_string())
            .unwrap_or_default();
        (remove_dot_segments(&format!("{dir}/{rpath}")), false)
    };
    let mut out = format!("{scheme}://{authority}{path}");
    if let Some(q) = rquery.or(if inherit_base_query { bquery } else { None }) {
        out.push('?');
        out.push_str(q);
    }
    Some(out)
}

/// RFC 3986 §5.2.4 remove_dot_segments (the segment-table merge form;
/// the absolute/trailing-slash forms are conserved — `a/b/..` → `a/`,
/// `a/./b` → `a/b`, `/../x` → `/x`).
#[cfg(feature = "metalink")]
fn remove_dot_segments(path: &str) -> String {
    let absolute = path.starts_with('/');
    let trailing = path.ends_with('/') || path.ends_with("/.") || path.ends_with("/..");
    let mut segs: Vec<&str> = Vec::new();
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        match seg {
            "." => {}
            ".." => {
                segs.pop();
            }
            s => segs.push(s),
        }
    }
    let mut out = String::new();
    if absolute {
        out.push('/');
    }
    out.push_str(&segs.join("/"));
    if trailing && !out.ends_with('/') {
        out.push('/');
    }
    out
}

/// Metalink form (`--metalink-file`): read the document -> parse ->
/// expand into per-task plans -> AddUri per task to build the chain ->
/// poll all tasks to a terminal state -> unwind.
///
/// Shares the lock/store/session base with the single-URL form;
/// differences (mirrored in the `--metalink-file` argument docs): no
/// attach decision (rerunning the same document creates new tasks);
/// `--out`/`--checksum` are not forwarded to subtasks (the entry name is
/// the per-task out; checksums come only from the document — explicit
/// values warn). All tasks Complete = 0; any task Error/Removed or signal
/// interruption = 1; document-level failure (missing/unreadable/over the
/// 16MiB cap/parse failure/zero usable entries) = 2.
#[cfg(feature = "metalink")]
async fn run_metalink(args: HttpArgs, path: PathBuf) -> i32 {
    use taiji_rpc::metalink::{expand_add_uri_plans, parse};

    args.warn_deferred();
    // Disclosure for caller `--out`/`--checksum` dropped by the metalink
    // form (previously silent — aligns with the "never silently drop user
    // options" discipline, same as attach/warn_deferred; the single text
    // source is [`metalink_dropped_option_warnings`]).
    for w in metalink_dropped_option_warnings(args.out.as_deref(), args.checksum.as_deref()) {
        warn!(target: "taiji::cli", "{w}");
    }
    // Document read (disk IO via spawn_blocking; the 16MiB document cap
    // is pre-checked BEFORE the read — oversized files never enter
    // process memory; the parse side enforces the same cap, see
    // [`read_metalink_document`]).
    let bytes = match read_metalink_document(path.clone()).await {
        Ok(b) => b,
        Err(MetalinkDocReadError::Oversize { len, limit }) => {
            error!(target: "taiji::cli", path = %path.display(), len, limit,
                "metalink document exceeds the size limit");
            return 2;
        }
        Err(MetalinkDocReadError::Io(e)) => {
            error!(target: "taiji::cli", path = %path.display(), %e,
                "cannot read metalink file");
            return 2;
        }
    };
    // Parse (v3/unknown version = explicit downgrade to
    // `taiji.metalink.unsupported_version`).
    let mut doc = match tokio::task::spawn_blocking(move || parse(&bytes)).await {
        Ok(Ok(doc)) => doc,
        Ok(Err(e)) => {
            error!(target: "taiji::cli", path = %path.display(), error = %e,
                "taiji.metalink.parse_failed: metalink document rejected");
            return 2;
        }
        Err(e) => {
            error!(target: "taiji::cli", %e, "metalink parse join failed");
            return 2;
        }
    };
    // Domain 5: the metalink selector (`--metalink-base-uri` relative
    // resolution → the `--metalink-language/os/version` entry filter →
    // the `--metalink-location`/`--metalink-preferred-protocol` priority
    // boost → the `--metalink-servers` mirror cap). Every entry filtered
    // out by the preferences = exit 2 (the aria2
    // EX_NO_RESULT_WITH_YOUR_PREFS equivalent — distinguished from the
    // expansion seam's "zero usable entries" message: this is the
    // user-preference-side rejection, not an unusable document).
    let files_before = doc.files.len();
    apply_metalink_selection(&args, &mut doc);
    if files_before > 0 && doc.files.is_empty() {
        error!(target: "taiji::cli", path = %path.display(),
            "no result with your preference conditions \
             (--metalink-language/--metalink-os/--metalink-version)");
        return 2;
    }
    // Expansion (the same function as RPC addMetalink; caller out/checksum
    // stripped at this single seam — `--out` never reaches subtasks,
    // checksums come only from the document). Ambiguous proxy-face input
    // (--all-proxy/--http-proxy together, etc.) = exit 2.
    // Wiring: the `--follow-torrent` gate runs between the
    // selection and the expansion — `false` clears the metaurl
    // candidates so the expansion seam produces no BT tasks and the
    // `<url>` mirror downloads proceed (the session task-payload face
    // and the RPC addMetalink face are unchanged; this gate is the CLI
    // form's face).
    let skipped_metaurls = apply_follow_torrent_gate(args.follow_torrent, &mut doc);
    if skipped_metaurls > 0 {
        warn!(target: "taiji::cli", skipped = skipped_metaurls,
            "--follow-torrent=false: metaurl->torrent conversion skipped; \
             <url> mirror downloads proceed");
    }
    let base = match args.add_options() {
        Ok(b) => b,
        Err(msg) => {
            error!(target: "taiji::cli", "{msg}");
            return 2;
        }
    };
    let plans = expand_add_uri_plans(&doc, base);
    if plans.is_empty() {
        error!(target: "taiji::cli", path = %path.display(),
            "metalink document has no downloadable entries (mirrors/metaurls all \
             outside the supported scheme face, in-document duplicates, or unusable)");
        return 2;
    }
    // The proxy face x source-scheme cross-check (domain 2; over the
    // expanded entry URI domain — the metalink form's sources are not in
    // the CLI urls positional).
    let plan_uris: Vec<String> = plans.iter().flat_map(|p| p.uris.iter().cloned()).collect();
    if let Err(msg) = args.check_proxy_sources(&plan_uris) {
        error!(target: "taiji::cli", path = %path.display(), "{msg}");
        return 2;
    }

    // Lock + session store + actor (no attach; the same base as
    // bootstrap).
    let _db_lock = match acquire_db_lock(&args.sqlite3_db_path).await {
        Ok(l) => l,
        Err(code) => return code,
    };
    let (session, actor_join, persist_join) = open_session_for_metalink(
        args.sqlite3_db_path.clone(),
        args.dir.clone(),
        // The CLI cap value seeds the session HostCap initialization.
        args.http_max_per_host
            .unwrap_or(taiji_core::session::DEFAULT_MAX_PER_HOST),
        // Periodic task summary interval (direct CLI mapping; 0 =
        // disabled).
        args.summary_interval,
    )
    .await;

    // Task chain (multi-file GID chain; order = document expansion
    // order).
    let mut gids: Vec<String> = Vec::with_capacity(plans.len());
    for plan in &plans {
        match session
            .call(SessionCommand::AddUri {
                uris: plan.uris.clone(),
                options: plan.options.clone(),
                position: None,
            })
            .await
        {
            Ok(CommandReply::Gid(g)) => gids.push(g.to_string()),
            Ok(other) => {
                error!(target: "taiji::cli", reply = ?other, "unexpected addUri reply in metalink expansion");
                return unwind(session, actor_join, persist_join, 1).await;
            }
            Err(e) => {
                error!(target: "taiji::cli", %e, "addUri rejected during metalink expansion");
                return unwind(session, actor_join, persist_join, exit_code_of(&e)).await;
            }
        }
    }
    info!(target: "taiji::cli", count = gids.len(), "metalink expanded into tasks");

    // Poll all tasks to a terminal state (the CLI consumer of the GID
    // chain: tellStatus per gid, finish only when all reach a terminal
    // state; any failure sets the failure bit).
    let mut pending: std::collections::VecDeque<String> = gids.iter().cloned().collect();
    let mut ticks = 0u32;
    let mut shutdown = std::pin::pin!(crate::wait_shutdown_signal());
    let code = loop {
        if pending.is_empty() {
            break 0;
        }
        let Some(gid) = pending.front().cloned() else {
            break 0;
        };
        tokio::select! {
            _ = &mut shutdown => {
                info!(target: "taiji::cli", gid = %gid, "interrupted: stopping session");
                break 1;
            }
            r = session.call(SessionCommand::TellStatus { gid: gid.clone(), keys: vec![] }) => {
                match r {
                    Ok(CommandReply::TorrentStatus(v)) => match v.status {
                        StatusKind::Complete => {
                            info!(target: "taiji::cli", gid = %gid,
                                total = v.total_length, "task complete");
                            pending.pop_front();
                        }
                        StatusKind::Error | StatusKind::Removed => {
                            error!(target: "taiji::cli", gid = %gid,
                                code = ?v.error_code, message = ?v.error_message,
                                "task failed");
                            break 1;
                        }
                        _ => {
                            ticks += 1;
                            if ticks.is_multiple_of(PROGRESS_EVERY) {
                                info!(target: "taiji::cli", gid = %gid,
                                    done = v.completed_length, total = v.total_length,
                                    speed = v.download_speed,
                                    remaining = pending.len(),
                                    "downloading metalink tasks");
                            }
                            tokio::time::sleep(STATUS_POLL).await;
                        }
                    },
                    Ok(other) => {
                        error!(target: "taiji::cli", reply = ?other, "unexpected tellStatus reply");
                        break 1;
                    }
                    Err(e) => {
                        error!(target: "taiji::cli", %e, "tellStatus failed");
                        break 1;
                    }
                }
            }
        }
    };
    unwind(session, actor_join, persist_join, code).await
}

/// Subcommand entry: the session mutex -> session bootstrap -> the
/// attach verdict (an in-flight same-source task hit waits for it) ->
/// addUri -> terminal-state polling -> wind-down.
/// The top-level URL positional form : minimal default
/// HttpArgs (dir + the session-db defaults aligned with the clap
/// defaults — the Default-derive zeros differ from the clap defaults in
/// these two places, filled in explicitly), reusing the full http
/// subcommand pipeline (attach verdict / bitmap resume / exit codes).
/// Since `summary_interval` is passed in by the caller (the
/// top-level `--summary-interval` flag — previously hard-coded
/// SUMMARY_INTERVAL_DEFAULT, the flag was silently ineffective in that
/// form; the default matches the clap default at 60). Since domain B
/// `ca_certificate` maps the same way (the top-level `--ca-certificate`
/// -> the addUri option — a single source at the session parse arm;
/// None = unset, the platform trust roots). Since domain C
/// `load_cookies` maps the same way (the top-level `--load-cookies` ->
/// the addUri option — the same gate as `taiji http --load-cookies`;
/// None = unset, no cookie seed).
pub(crate) fn args_from_positional(
    url: String,
    dir: PathBuf,
    summary_interval: u32,
    ca_certificate: Option<String>,
    load_cookies: Option<String>,
) -> HttpArgs {
    HttpArgs {
        urls: vec![url],
        dir,
        sqlite3_db_path: PathBuf::from("taiji.sqlite3"),
        summary_interval,
        ca_certificate,
        load_cookies,
        // The positional form has no metalink face — the follow-torrent
        // default true (the clap default; the Default-derive false is
        // filled explicitly here, the same shape as dir/sqlite3-db-path
        // — keeps the warn_deferred single-URL-form check quiet).
        #[cfg(feature = "metalink")]
        follow_torrent: true,
        ..Default::default()
    }
}

/// Top-level positional URL: delegate to the http subcommand pipeline.
pub(crate) async fn delegate_positional(
    url: String,
    dir: PathBuf,
    summary_interval: u32,
    ca_certificate: Option<String>,
    load_cookies: Option<String>,
) -> i32 {
    run(args_from_positional(
        url,
        dir,
        summary_interval,
        ca_certificate,
        load_cookies,
    ))
    .await
}

pub async fn run(args: HttpArgs) -> i32 {
    // Metalink form (`--metalink-file`): expand the document into tasks,
    // then wait for each task's terminal state — an independent flow
    // (multi-GID polling / no attach) sharing the lock and session
    // bootstrap base.
    #[cfg(feature = "metalink")]
    if let Some(path) = args.metalink_file.clone() {
        if !args.urls.is_empty() {
            error!(target: "taiji::cli",
                "taiji http: --metalink-file and positional URLs are mutually exclusive");
            return 2;
        }
        return run_metalink(args, path).await;
    }
    if args.urls.is_empty() {
        error!(target: "taiji::cli", "taiji http: at least one URL is required");
        return 2;
    }
    args.warn_deferred();
    let url = args.urls[0].clone();

    // Proxy-face ambiguous input, rejected up front (batch C:
    // --all-proxy/--http-proxy together, credentials without a proxy
    // subject; domain 2: --https-proxy dedicated-slot ambiguity,
    // --ftp-proxy x an ftp source — exit 2, before the lock and session
    // bootstrap; add_options is a pure function, so the same-argument
    // recomputation at the downstream AddUri site is always equal).
    if let Err(msg) = args.add_options() {
        error!(target: "taiji::cli", "{msg}");
        return 2;
    }
    // The proxy face x source-scheme cross-check (domain 2: the
    // --ftp-proxy family x an ftp(s):// source = the explicit
    // FTP-over-HTTP P2 rejection).
    if let Err(msg) = args.check_proxy_sources(&args.urls) {
        error!(target: "taiji::cli", "{msg}");
        return 2;
    }

    // Single-session guard: the lock precedes opening the store — a
    // concurrent second process fails explicitly before touching the
    // store (no bootstrap, no task creation, no `.part` contact). The
    // lock handle lives until teardown (dropped = released). Opening and
    // locking the store is disk IO (blocking; via spawn_blocking; the
    // Connection is Send and the locked connection moves into this task).
    let _db_lock = match acquire_db_lock(&args.sqlite3_db_path).await {
        Ok(l) => l,
        Err(code) => return code,
    };

    // Session store open (bootstrap precedes command handling: the attach
    // read path shares the bootstrap source, so the row set is
    // deterministic). Observability: the persist writer receives metrics
    // callbacks (process-default registry persistence family).
    let (persist, persist_join) =
        match taiji_core::session::persist::import::open_session_writer_with_metrics(
            args.sqlite3_db_path.clone(),
        )
        .await
        {
            Ok((h, j)) => (Some(h), Some(j)),
            Err(e) => {
                error!(target: "taiji::cli", %e, "cannot open session db; running WITHOUT persistence");
                (None, None)
            }
        };

    // Attach decision (before actor spawn; blocking work = directory
    // canonicalization, via spawn_blocking). A row-read failure fails
    // explicitly instead of silently degrading into a duplicate task
    // (swallowing the error would revive the co-write race in the
    // two-CLIs-one-store scenario).
    let loaded = match &persist {
        Some(p) => Some(p.load_http_tasks_at_startup().await),
        None => None,
    };
    let decision = match loaded {
        Some(Ok(snaps)) => {
            let rows: Vec<InflightRow> = snaps
                .iter()
                .map(|s| InflightRow {
                    gid: s.row.gid.clone(),
                    url: s.row.url.clone(),
                    dir: s.row.dir.clone(),
                    out: s.row.out.clone(),
                    config_json: s.row.config_json.clone(),
                })
                .collect();
            let url = url.clone();
            let dir = args.dir.clone();
            let out = args.out.clone();
            let checksum = args.checksum.clone();
            let suffix = args.incomplete_suffix.clone();
            tokio::task::spawn_blocking(move || {
                decide_attach(
                    &rows,
                    &url,
                    &dir,
                    out.as_deref(),
                    checksum.as_deref(),
                    suffix.as_deref(),
                )
            })
            .await
            .unwrap_or_else(|e| AttachDecision::Reject {
                reason: format!("attach scan join: {e}"),
            })
        }
        Some(Err(e)) => {
            error!(target: "taiji::cli", %e,
                "cannot read in-flight rows from session db; refusing to risk a duplicate task");
            drop(persist); // dropping the writer handle ends it; the join closes via drain.
            return drain_persist_only(persist_join).await;
        }
        None => {
            warn!(target: "taiji::cli",
                "no persistence: in-flight resume unavailable (fresh download every run)");
            AttachDecision::None
        }
    };

    let mut attached_gid: Option<Gid> = None;
    let options = SessionOptions {
        global: GlobalOptions {
            dir: args.dir.clone(),
            // One-shot form: a task reaching an error terminal state has
            // its cookies cleared immediately.
            one_shot: true,
            // `--http-max-per-host` seeds the session HostCap
            // initialization (the attach form used to drop it silently —
            // without the addUri channel the value had no effect); addUri
            // task-level overrides keep last-set-wins and take priority
            // over this initialization. Unset = the taiji-http
            // single-source default (64).
            http_max_per_host: args
                .http_max_per_host
                .unwrap_or(taiji_core::session::DEFAULT_MAX_PER_HOST),
            // Periodic task summary interval (`--summary-interval`; direct
            // CLI mapping, 0 = disabled).
            summary_interval: args.summary_interval,
            ..Default::default()
        },
    };
    let (session, actor_join) = match &decision {
        AttachDecision::Reject { reason } => {
            error!(target: "taiji::cli", "{reason}");
            drop(persist); // dropping the writer handle ends it; the join closes via drain.
            return drain_persist_only(persist_join).await;
        }
        AttachDecision::Attach { gid, warnings } => {
            for w in warnings {
                warn!(target: "taiji::cli", "{w}");
            }
            match parse_gid_hex(gid) {
                Some(g) => {
                    info!(target: "taiji::cli", gid = %g, url = %url,
                        "resuming in-flight download from previous session");
                    attached_gid = Some(g);
                    // The actor still has to spawn: bootstrap rebuilds the
                    // task so this process can poll its terminal state.
                    SessionActor::spawn_with_persist(options, persist)
                }
                None => {
                    error!(target: "taiji::cli", gid = %gid,
                        "in-flight row has malformed gid; refusing to duplicate the task");
                    drop(persist);
                    return drain_persist_only(persist_join).await;
                }
            }
        }
        AttachDecision::None => SessionActor::spawn_with_persist(options, persist),
    };
    let session = std::sync::Arc::new(session);

    let gid = match attached_gid {
        Some(g) => g,
        // The add_options ambiguity face was already rejected by the
        // up-front validation (a pure function on the same arguments is
        // always equal) — this unreachable arm only narrows the type; the
        // panic text never enters the normal path.
        None => match session
            .call(SessionCommand::AddUri {
                uris: args.urls.clone(),
                options: args.add_options().unwrap_or_default(),
                position: None,
            })
            .await
        {
            Ok(CommandReply::Gid(g)) => g,
            Ok(other) => {
                error!(target: "taiji::cli", reply = ?other, "unexpected addUri reply");
                return unwind(session, actor_join, persist_join, 1).await;
            }
            Err(e) => {
                error!(target: "taiji::cli", %e, "addUri rejected");
                return unwind(session, actor_join, persist_join, exit_code_of(&e)).await;
            }
        },
    };

    // Terminal-state poll (aria2 tellStatus semantics: active/waiting ->
    // the three terminal states complete/error/removed).
    //
    // The signal listener is registered ONCE outside the loop (pinned and
    // reused): each select round previously rebuilt the listener, leaving
    // a 200ms poll-sleep window with no listener — a SIGTERM landing in
    // the gap was lost (reproduced in graceful-shutdown e2e: the task ran
    // to completion after the signal, exit 0). A single registration held
    // until the first signal = no gap.
    let gid_hex = gid.to_string();
    let mut ticks = 0u32;
    let mut shutdown = std::pin::pin!(crate::wait_shutdown_signal());
    let code = loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!(target: "taiji::cli", gid = %gid_hex, "interrupted: stopping session");
                break 1;
            }
            r = session.call(SessionCommand::TellStatus {
                gid: gid_hex.clone(),
                keys: vec![],
            }) => {
                match r {
                    Ok(CommandReply::TorrentStatus(v)) => match v.status {
                        StatusKind::Complete => {
                            let path = v.files.first().map(|f| f.path.clone());
                            info!(target: "taiji::cli", gid = %gid_hex,
                                total = v.total_length, path = ?path,
                                "download complete");
                            break 0;
                        }
                        StatusKind::Error | StatusKind::Removed => {
                            error!(target: "taiji::cli", gid = %gid_hex,
                                code = ?v.error_code, message = ?v.error_message,
                                "download failed");
                            break 1;
                        }
                        _ => {
                            ticks += 1;
                            if ticks.is_multiple_of(PROGRESS_EVERY) {
                                info!(target: "taiji::cli", gid = %gid_hex,
                                    done = v.completed_length, total = v.total_length,
                                    speed = v.download_speed,
                                    "downloading");
                            }
                            tokio::time::sleep(STATUS_POLL).await;
                        }
                    },
                    Ok(other) => {
                        error!(target: "taiji::cli", reply = ?other, "unexpected tellStatus reply");
                        break 1;
                    }
                    Err(e) => {
                        error!(target: "taiji::cli", %e, "tellStatus failed");
                        break 1;
                    }
                }
            }
        }
    };
    unwind(session, actor_join, persist_join, code).await
}

/// 16-hex GID parse (defense for resumed row gids; the same parsing
/// discipline as bootstrap).
fn parse_gid_hex(hex: &str) -> Option<Gid> {
    u64::from_str_radix(hex, 16).ok().map(Gid::from_u64)
}

/// Teardown without an actor (attach rejected / row-read failure early
/// return): drain only the persistence writer (keeping the "opened store
/// must be drained" discipline), return the rejection exit code 1.
async fn drain_persist_only(persist_join: Option<tokio::task::JoinHandle<()>>) -> i32 {
    if let Some(j) = persist_join
        && tokio::time::timeout(SESSION_SHUTDOWN_BUDGET, j)
            .await
            .is_err()
    {
        warn!(target: "taiji::cli", "persist writer drain exceeded shutdown budget (exiting anyway)");
    }
    1
}

/// Session wind-down: shutdown + the double join. The budget scheme =
/// §7.5 (1s; the actor and the persistence writer share the total
/// budget — isomorphic to the main entry's remaining allocation, full
/// budgets each would stack past the bound). The return exit code is
/// passed through. `pub(crate)`: the domain A `--input-file` batch face
/// (main.rs run_input_file) shares the same wind-down single point —
/// the "opened db must be drained" discipline has no second
/// implementation.
pub(crate) async fn unwind(
    session: std::sync::Arc<SessionHandle>,
    actor_join: tokio::task::JoinHandle<()>,
    persist_join: Option<tokio::task::JoinHandle<()>>,
    code: i32,
) -> i32 {
    let t0 = Instant::now();
    session.shutdown().await;
    let remaining = SESSION_SHUTDOWN_BUDGET.saturating_sub(t0.elapsed());
    let _ = tokio::time::timeout(remaining, actor_join).await;
    if let Some(j) = persist_join {
        let remaining = SESSION_SHUTDOWN_BUDGET.saturating_sub(t0.elapsed());
        if tokio::time::timeout(remaining, j).await.is_err() {
            warn!(target: "taiji::cli", "persist writer drain exceeded shutdown budget (exiting anyway)");
        }
    }
    code
}

/// Session command error -> exit code (structured: the error protocol is
/// `"taiji.* code: message"` — an exact first-token match against the
/// value-domain rejection code means 2, any other task failure means 1;
/// no whole-string substring sniffing).
fn exit_code_of(e: &SessionError) -> i32 {
    let message = match e {
        SessionError::Failed { message } => message,
        _ => return 1,
    };
    let code = message.split(':').next().unwrap_or("").trim();
    if code == CODE_OPTION_INVALID { 2 } else { 1 }
}

// Graceful-shutdown signals (Ctrl-C / SIGTERM) reuse the main entry's
// `wait_shutdown_signal`.

#[cfg(test)]
mod tests {
    use super::*;

    /// Frozen argument names: `taiji http` accepts the full frozen name
    /// list (aria2 same-name options; the clap spellings are pinned — a
    /// rename breaks the compatibility surface).
    #[test]
    fn http_args_parse_frozen_names() {
        let parsed = HttpArgs::try_parse_from([
            "http",
            "http://a.test/f.bin",
            "http://b.test/f.bin",
            "-d",
            "/tmp/dl",
            "-o",
            "f.bin",
            "--checksum=sha-256=ab",
            "--http-incomplete-suffix=.motrix",
            "--continue=true",
            "--remote-time",
            "--split=8",
            "--min-split-size=4M",
            "--max-connection-per-server=4",
            "--http-scheduler=static",
            "--http-block-size=256K",
            "--http-max-chunk=2M",
            "--timeout=30",
            "--connect-timeout=10",
            "--max-tries=3",
            "--retry-wait=2",
            "--user-agent=taiji-test",
            "--header=X-A: 1",
            "--header=X-B: 2",
            "--http-user=u",
            "--http-passwd=p",
            "--all-proxy=http://127.0.0.1:1",
            "--check-certificate=false",
            "--ca-certificate=/tmp/ca.pem",
            "--http-max-per-host=8",
            "--sqlite3-db-path=/tmp/s.sqlite3",
        ])
        .unwrap_or_else(|e| panic!("args must parse: {e}"));
        assert_eq!(parsed.urls.len(), 2);
        assert_eq!(parsed.dir, PathBuf::from("/tmp/dl"));
        assert_eq!(parsed.out.as_deref(), Some("f.bin"));
        assert_eq!(parsed.checksum.as_deref(), Some("sha-256=ab"));
        assert_eq!(parsed.incomplete_suffix.as_deref(), Some(".motrix"));
        assert_eq!(parsed.split, Some(8));
        assert_eq!(parsed.max_connection_per_server, Some(4));
        assert_eq!(parsed.http_scheduler.as_deref(), Some("static"));
        assert_eq!(parsed.http_block_size.as_deref(), Some("256K"));
        assert_eq!(parsed.http_max_chunk.as_deref(), Some("2M"));
        assert_eq!(parsed.headers.len(), 2);
        assert_eq!(parsed.check_certificate, Some(false));
        assert_eq!(parsed.ca_certificate.as_deref(), Some("/tmp/ca.pem"));
        assert_eq!(parsed.http_max_per_host, Some(8));
        assert_eq!(parsed.sqlite3_db_path, PathBuf::from("/tmp/s.sqlite3"));
    }

    /// CLI option-surface declaration audit: every `taiji http` long
    /// option name must have a stance in the core declaration tables
    /// (reference list / declared-difference whitelist / not-accepted
    /// declaration), or belong to CLI-private plumbing (no aria2 option
    /// semantics). The name list comes from clap `Command` introspection
    /// (`HttpArgs::command`) — a new flag without a declaration turns
    /// red; this closes the hole of a hand-written list silently missing
    /// an unregistered flag (introspection failing = the audit failing).
    /// Metalink feature flags enter and leave with the compilation state.
    #[test]
    fn cli_long_options_all_have_declaration_or_are_cli_plumbing() {
        use clap::CommandFactory;
        use taiji_core::session::option_name_has_declaration;
        // clap auto-generated names + CLI-private plumbing (no aria2
        // option semantics: the --help/--version introspection family,
        // the session store path — the fork's conventional name).
        const CLI_AUTO_OR_PLUMBING: &[&str] = &["help", "version", "sqlite3-db-path"];
        let cmd = HttpArgs::command();
        let longs: Vec<&str> = cmd
            .get_arguments()
            .filter_map(|a| a.get_long())
            .filter(|n| !CLI_AUTO_OR_PLUMBING.contains(n))
            .collect();
        assert!(
            longs.len() >= 20,
            "clap introspection narrowed abnormally ({longs:?}) -- \
             a broken introspection pipeline invalidates the audit"
        );
        for name in longs {
            assert!(
                option_name_has_declaration(name),
                "CLI option --{name} has no declaration stance (the core \
                 session::options three tables) and is not CLI plumbing -- \
                 add the declaration before shipping the flag"
            );
        }
        // Reverse check for plumbing names: plumbing/auto-generated names
        // must not leak into the option declaration tables (stance-surface
        // pollution).
        for name in CLI_AUTO_OR_PLUMBING {
            assert!(
                !option_name_has_declaration(name),
                "CLI plumbing name {name} leaked into the option declaration \
                 tables (stance-surface pollution)"
            );
        }
    }

    /// addUri option map: wired options map directly (dir always present;
    /// out/checksum/suffix sent only when explicit — blank = unset).
    #[test]
    fn add_options_mirror_wired_face() {
        let base = HttpArgs::try_parse_from(["http", "http://a.test/f.bin"])
            .unwrap_or_else(|e| panic!("parse: {e}"));
        let opts = base.add_options().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(opts.get("dir").map(String::as_str), Some("."));
        assert!(!opts.contains_key("out"));
        assert!(!opts.contains_key("checksum"));
        assert!(!opts.contains_key("http-incomplete-suffix"));

        let full = HttpArgs::try_parse_from([
            "http",
            "http://a.test/f.bin",
            "-d",
            "dl",
            "-o",
            "f.bin",
            "--checksum=sha-1=cd",
            "--http-incomplete-suffix=.part",
        ])
        .unwrap_or_else(|e| panic!("parse: {e}"));
        let opts = full.add_options().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(opts.get("dir").map(String::as_str), Some("dl"));
        assert_eq!(opts.get("out").map(String::as_str), Some("f.bin"));
        assert_eq!(opts.get("checksum").map(String::as_str), Some("sha-1=cd"));
        assert_eq!(
            opts.get("http-incomplete-suffix").map(String::as_str),
            Some(".part")
        );
    }

    /// Complete face: newly wired options map straight into the addUri
    /// option map (frozen aria2 names; multiple headers joined with "\n"
    /// into one value; both bool forms). Absent defaults are not sent.
    #[test]
    fn add_options_wires_b20_complete_face() {
        let args = HttpArgs::try_parse_from([
            "http",
            "http://a.test/f.bin",
            "--remote-time",
            "--timeout=45",
            "--connect-timeout=15",
            "--max-tries=3",
            "--retry-wait=4",
            "--user-agent=taiji-test",
            "--header=X-A: 1",
            "--header=X-B: 2",
            "--http-user=u",
            "--http-passwd=p",
            "--all-proxy=http://p.test:8080",
            "--check-certificate=false",
            "--ca-certificate=/tmp/ca.pem",
            "--http-max-per-host=8",
            "--ftp-user=fu",
            "--ftp-passwd=fp",
            "--ftp-ssl=implicit",
            "--ftp-pasv",
            "--ftp-reuse-connection=false",
        ])
        .unwrap_or_else(|e| panic!("parse: {e}"));
        let opts = args.add_options().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(opts.get("remote-time").map(String::as_str), Some("true"));
        assert_eq!(opts.get("timeout").map(String::as_str), Some("45"));
        assert_eq!(opts.get("connect-timeout").map(String::as_str), Some("15"));
        assert_eq!(opts.get("max-tries").map(String::as_str), Some("3"));
        assert_eq!(opts.get("retry-wait").map(String::as_str), Some("4"));
        assert_eq!(
            opts.get("user-agent").map(String::as_str),
            Some("taiji-test")
        );
        assert_eq!(
            opts.get("header").map(String::as_str),
            Some("X-A: 1\nX-B: 2")
        );
        assert_eq!(opts.get("http-user").map(String::as_str), Some("u"));
        assert_eq!(opts.get("http-passwd").map(String::as_str), Some("p"));
        assert_eq!(
            opts.get("all-proxy").map(String::as_str),
            Some("http://p.test:8080")
        );
        assert_eq!(
            opts.get("check-certificate").map(String::as_str),
            Some("false")
        );
        assert_eq!(
            opts.get("ca-certificate").map(String::as_str),
            Some("/tmp/ca.pem")
        );
        assert_eq!(opts.get("http-max-per-host").map(String::as_str), Some("8"));
        // FTP family maps directly.
        assert_eq!(opts.get("ftp-user").map(String::as_str), Some("fu"));
        assert_eq!(opts.get("ftp-passwd").map(String::as_str), Some("fp"));
        assert_eq!(opts.get("ftp-ssl").map(String::as_str), Some("implicit"));
        assert_eq!(opts.get("ftp-pasv").map(String::as_str), Some("true"));
        assert_eq!(
            opts.get("ftp-reuse-connection").map(String::as_str),
            Some("false")
        );
        // Absent options are not sent (blank = unset semantics).
        let bare = HttpArgs::try_parse_from(["http", "http://a.test/f.bin"])
            .unwrap_or_else(|e| panic!("parse: {e}"));
        let opts = bare.add_options().unwrap_or_else(|e| panic!("{e}"));
        for absent in [
            "remote-time",
            "timeout",
            "connect-timeout",
            "max-tries",
            "retry-wait",
            "user-agent",
            "header",
            "http-user",
            "http-passwd",
            "all-proxy",
            "check-certificate",
            "ca-certificate",
            "http-max-per-host",
            "ftp-user",
            "ftp-passwd",
            "ftp-ssl",
            "ftp-pasv",
            "ftp-reuse-connection",
        ] {
            assert!(
                !opts.contains_key(absent),
                "{absent} must not be sent when unset"
            );
        }
    }

    /// Scheduler-group coverage: the four scheduler-group options
    /// (split/min-split-size/max-connection-per-server/http-stall-window)
    /// plus the scheduling mode (http-scheduler) all reach the addUri
    /// option payload (warn_deferred narrowed to the --continue callout).
    #[test]
    fn scheduler_group_options_flow_into_add_payload() {
        let args = HttpArgs::try_parse_from([
            "http",
            "http://a.test/f.bin",
            "--split=4",
            "--min-split-size=1M",
            "--max-connection-per-server=4",
            "--http-stall-window=9",
            "--http-scheduler=static",
            "--http-block-size=256K",
            "--http-max-chunk=2M",
            "--http-protocol=h2",
            "--http2-adaptive-window=true",
            "--http2-stream-window=8388608",
            "--http2-connection-window=16777216",
            "--http2-max-connections=4",
            "--http2-keep-alive-interval=30",
            "--timeout=30",
        ])
        .unwrap_or_else(|e| panic!("parse: {e}"));
        let opts = args.add_options().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(opts.get("split").map(String::as_str), Some("4"));
        assert_eq!(opts.get("min-split-size").map(String::as_str), Some("1M"));
        assert_eq!(
            opts.get("max-connection-per-server").map(String::as_str),
            Some("4")
        );
        assert_eq!(opts.get("http-stall-window").map(String::as_str), Some("9"));
        assert_eq!(
            opts.get("http-scheduler").map(String::as_str),
            Some("static")
        );
        assert_eq!(
            opts.get("http-block-size").map(String::as_str),
            Some("256K")
        );
        assert_eq!(opts.get("http-max-chunk").map(String::as_str), Some("2M"));
        // Protocol form: forwarded into the payload (domain validation on
        // the session side).
        assert_eq!(opts.get("http-protocol").map(String::as_str), Some("h2"));
        // h2 flow-control windows: forwarded into the payload (domain
        // validation on the session side).
        assert_eq!(
            opts.get("http2-adaptive-window").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            opts.get("http2-stream-window").map(String::as_str),
            Some("8388608")
        );
        assert_eq!(
            opts.get("http2-connection-window").map(String::as_str),
            Some("16777216")
        );
        // h2 multi-connection + keep-alive: forwarded into the payload
        // (domain validation on the session side).
        assert_eq!(
            opts.get("http2-max-connections").map(String::as_str),
            Some("4")
        );
        assert_eq!(
            opts.get("http2-keep-alive-interval").map(String::as_str),
            Some("30")
        );
        // Scheduler-group keys not given never enter the payload (defaults
        // filled on the session side).
        let bare = HttpArgs::try_parse_from(["http", "http://a.test/f.bin"])
            .unwrap_or_else(|e| panic!("parse: {e}"));
        assert!(
            !bare
                .add_options()
                .unwrap_or_else(|e| panic!("{e}"))
                .contains_key("split")
        );
        assert!(
            !bare
                .add_options()
                .unwrap_or_else(|e| panic!("{e}"))
                .contains_key("http-scheduler")
        );
        assert!(
            !bare
                .add_options()
                .unwrap_or_else(|e| panic!("{e}"))
                .contains_key("http-block-size")
        );
        assert!(
            !bare
                .add_options()
                .unwrap_or_else(|e| panic!("{e}"))
                .contains_key("http-max-chunk")
        );
        // --timeout is wired, not part of the deferred face.
        assert!(args.timeout.is_some());
    }

    /// Per-task speed-limit family mapped straight into the addUri
    /// payload (--max-download-limit / --max-upload-limit — the
    /// per_torrent bucket enforcement face, the same channel for HTTP and
    /// BT tasks); not given = not sent.
    #[test]
    fn w3c_per_task_limit_flags_flow_into_add_payload() {
        let args = HttpArgs::try_parse_from([
            "http",
            "http://a.test/f.bin",
            "--max-download-limit=512K",
            "--max-upload-limit=2M",
        ])
        .unwrap_or_else(|e| panic!("parse: {e}"));
        let opts = args.add_options().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            opts.get("max-download-limit").map(String::as_str),
            Some("524288")
        );
        assert_eq!(
            opts.get("max-upload-limit").map(String::as_str),
            Some("2097152")
        );
        // Not given = not sent; a bad size is rejected by clap (the same
        // parse_aria2_size parser).
        let bare = HttpArgs::try_parse_from(["http", "http://a.test/f.bin"])
            .unwrap_or_else(|e| panic!("parse: {e}"));
        let opts = bare.add_options().unwrap_or_else(|e| panic!("{e}"));
        assert!(!opts.contains_key("max-download-limit"));
        assert!(!opts.contains_key("max-upload-limit"));
        assert!(
            HttpArgs::try_parse_from(["http", "http://a.test/f.bin", "--max-download-limit=abc"])
                .is_err()
        );
    }

    /// The proxy family's single-slot mapping — `--http-proxy` maps onto
    /// the all-proxy payload; coexistence with `--all-proxy` is rejected;
    /// `--http-proxy-user`/`--http-proxy-passwd` fold into the userinfo
    /// (a URL that already carries userinfo wins); credentials without a
    /// proxy subject / a password without a user / an out-of-domain
    /// scheme are rejected.
    #[test]
    fn w3c_proxy_family_maps_to_single_slot() {
        let opts_of = |args: &[&str]| {
            HttpArgs::try_parse_from([vec!["http", "http://a.test/f.bin"], args.to_vec()].concat())
                .unwrap_or_else(|e| panic!("parse: {e}"))
                .add_options()
        };
        // http-proxy maps onto the single all-proxy slot.
        let opts = opts_of(&["--http-proxy=http://p.test:8080"]).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            opts.get("all-proxy").map(String::as_str),
            Some("http://p.test:8080")
        );
        // Credential folding: user[:pass] inserted before the authority
        // (the path verbatim).
        let opts = opts_of(&[
            "--http-proxy=http://p.test:8080/base",
            "--http-proxy-user=u",
            "--http-proxy-passwd=p",
        ])
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            opts.get("all-proxy").map(String::as_str),
            Some("http://u:p@p.test:8080/base")
        );
        // user only (no pass) also folds.
        let opts = opts_of(&["--all-proxy=http://p.test:8080", "--http-proxy-user=u"])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            opts.get("all-proxy").map(String::as_str),
            Some("http://u@p.test:8080")
        );
        // A URL that already carries userinfo wins (the same
        // URL-credentials-first rule as aria2).
        let opts = opts_of(&[
            "--http-proxy=http://explicit:cred@p.test:8080",
            "--http-proxy-user=u",
        ])
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            opts.get("all-proxy").map(String::as_str),
            Some("http://explicit:cred@p.test:8080")
        );
        // The ambiguous-input rejection face: both proxies together.
        let both = opts_of(&[
            "--all-proxy=http://a.test:1",
            "--http-proxy=http://b.test:2",
        ]);
        assert!(
            both.is_err(),
            "two proxies together must be explicitly rejected"
        );
        // Credentials without a proxy subject.
        let cred_only = opts_of(&["--http-proxy-user=u"]);
        assert!(cred_only.is_err());
        // A password without a user.
        let pass_only = opts_of(&["--http-proxy=http://p.test:1", "--http-proxy-passwd=p"]);
        assert!(pass_only.is_err());
        // Out-of-domain scheme (socks not enabled — the same rule as the
        // declared transport limitation).
        let socks = opts_of(&["--http-proxy=socks5://p.test:1080", "--http-proxy-user=u"]);
        assert!(socks.is_err());
    }

    /// The proxy-URL credential folding pure function (query/path/
    /// fragment preserved; the three authority terminator classes).
    #[test]
    fn w3c_apply_proxy_credentials_shape() {
        assert_eq!(
            apply_proxy_credentials("http://h:1/a?q=1#f", Some("u"), Some("p")).unwrap_or_default(),
            "http://u:p@h:1/a?q=1#f"
        );
        assert_eq!(
            apply_proxy_credentials("https://h", Some("u"), None).unwrap_or_default(),
            "https://u@h"
        );
        // A URL that already carries userinfo passes through (explicit
        // win).
        assert_eq!(
            apply_proxy_credentials("http://a:b@h", Some("u"), None).unwrap_or_default(),
            "http://a:b@h"
        );
        // No credentials passes through.
        assert_eq!(
            apply_proxy_credentials("http://h", None, None).unwrap_or_default(),
            "http://h"
        );
        // A missing scheme / an out-of-domain scheme.
        assert!(apply_proxy_credentials("h:1", Some("u"), None).is_err());
        assert!(apply_proxy_credentials("socks5://h", Some("u"), None).is_err());
    }

    // ---- domain 2: per-scheme dedicated proxy slots + HTTP knobs ----

    fn opts_of(args: &[&str]) -> Result<BTreeMap<String, String>, String> {
        HttpArgs::try_parse_from([vec!["http", "http://a.test/f.bin"], args.to_vec()].concat())
            .unwrap_or_else(|e| panic!("parse: {e}"))
            .add_options()
    }

    /// Domain 2: the https dedicated slot payload + the coexistence
    /// priority face — `--https-proxy` alone = the https-proxy key;
    /// together with `--all-proxy`/`--http-proxy` = both keys coexist
    /// (the dedicated-slot-wins switching is finalized at transport build
    /// time: the dedicated slot registers first, first-match-wins +
    /// `Proxy::https` only intercepts https targets); the
    /// `--all-proxy` x `--http-proxy` single-slot source mutual exclusion
    /// is unchanged.
    #[test]
    fn d2_https_dedicated_slot_coexists_with_all_slot() {
        // Alone: the https dedicated slot maps directly (no all-slot
        // mapping).
        let opts =
            opts_of(&["--https-proxy=http://hs.test:8443"]).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            opts.get("https-proxy").map(String::as_str),
            Some("http://hs.test:8443")
        );
        assert!(
            !opts.contains_key("all-proxy"),
            "the dedicated slot must not map the all slot"
        );
        // With --all-proxy: both keys coexist (the priority is finalized
        // at transport time).
        let opts = opts_of(&[
            "--all-proxy=http://p.test:8080",
            "--https-proxy=http://hs.test:8443",
        ])
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            opts.get("all-proxy").map(String::as_str),
            Some("http://p.test:8080")
        );
        assert_eq!(
            opts.get("https-proxy").map(String::as_str),
            Some("http://hs.test:8443")
        );
        // With --http-proxy (mapping the all slot): both keys coexist the
        // same way.
        let opts = opts_of(&[
            "--http-proxy=http://hp.test:8080",
            "--https-proxy=http://hs.test:8443",
        ])
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            opts.get("all-proxy").map(String::as_str),
            Some("http://hp.test:8080")
        );
        assert_eq!(
            opts.get("https-proxy").map(String::as_str),
            Some("http://hs.test:8443")
        );
        // The single-slot source mutual exclusion (the batch-C rule
        // unchanged).
        assert!(
            opts_of(&[
                "--all-proxy=http://a.test:1",
                "--http-proxy=http://b.test:2"
            ])
            .is_err()
        );
    }

    /// Domain 2: https credential folding — folding into the dedicated
    /// slot / without the dedicated slot, falling back into the all-slot
    /// URL (the single-slot fallback also serves https) / a URL that
    /// already carries userinfo wins / the single-userinfo-carrier
    /// conflict rejection / credentials without a subject / a password
    /// without a user.
    #[test]
    fn d2_https_credential_folding_targets() {
        // Dedicated-slot folding (user[:pass] inserted before the
        // authority).
        let opts = opts_of(&[
            "--https-proxy=https://hs.test:8443/base",
            "--https-proxy-user=u",
            "--https-proxy-passwd=p",
        ])
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            opts.get("https-proxy").map(String::as_str),
            Some("https://u:p@hs.test:8443/base")
        );
        // No dedicated slot: folding falls back into the all-slot URL.
        let opts = opts_of(&["--all-proxy=http://p.test:8080", "--https-proxy-user=u"])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            opts.get("all-proxy").map(String::as_str),
            Some("http://u@p.test:8080")
        );
        assert!(
            !opts.contains_key("https-proxy"),
            "no dedicated slot must not produce the https key"
        );
        // A URL that already carries userinfo wins.
        let opts = opts_of(&[
            "--https-proxy=http://explicit:c@hs.test:1",
            "--https-proxy-user=u",
        ])
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            opts.get("https-proxy").map(String::as_str),
            Some("http://explicit:c@hs.test:1")
        );
        // A single userinfo carrier: without the dedicated slot, http and
        // https credentials landing on the same all-slot URL = conflict
        // rejection.
        let both_families = opts_of(&[
            "--all-proxy=http://p.test:8080",
            "--http-proxy-user=h1",
            "--https-proxy-user=h2",
        ]);
        assert!(
            both_families.is_err(),
            "two credential families on one carrier must be explicitly rejected"
        );
        // Credentials without a subject / a password without a user.
        assert!(opts_of(&["--https-proxy-user=u"]).is_err());
        assert!(opts_of(&["--https-proxy=http://hs.test:1", "--https-proxy-passwd=p"]).is_err());
    }

    /// Domain 2: the `--no-proxy` whole-value bypass — a non-empty value =
    /// a payload with zero proxy keys (the dedicated slot and the all
    /// slot bypassed together); the ambiguous-input validation still runs
    /// (the bypass does not excuse bad input).
    #[test]
    fn d2_no_proxy_bypasses_all_slots() {
        let opts = opts_of(&[
            "--all-proxy=http://p.test:8080",
            "--https-proxy=http://hs.test:8443",
            "--no-proxy=*",
        ])
        .unwrap_or_else(|e| panic!("{e}"));
        assert!(
            !opts.contains_key("all-proxy"),
            "the bypass face = zero proxy keys"
        );
        assert!(!opts.contains_key("https-proxy"));
        // An empty string = the unset semantics (the aria2 blank face):
        // proxies carried as usual.
        let opts = opts_of(&["--all-proxy=http://p.test:8080", "--no-proxy="])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            opts.get("all-proxy").map(String::as_str),
            Some("http://p.test:8080")
        );
        // The bypass face does not excuse bad input: a password without a
        // user is still explicitly rejected.
        assert!(
            opts_of(&[
                "--no-proxy=*",
                "--https-proxy=http://hs.test:1",
                "--https-proxy-passwd=p"
            ])
            .is_err()
        );
    }

    /// Domain 2: the `--ftp-proxy` family — no FTP source = accepted with
    /// zero payload keys (the declared P2 face); an ftp(s):// source
    /// present = the `check_proxy_sources` explicit rejection;
    /// credentials without a subject / a password without a user / a
    /// socks scheme value-domain rejection.
    #[test]
    fn d2_ftp_proxy_family_rules() {
        // No FTP source: accepted, zero ftp payload keys (the warning is
        // on the log face).
        let opts = opts_of(&["--ftp-proxy=http://fp.test:21"]).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            !opts.contains_key("ftp-proxy"),
            "the declared P2 face: no payload key"
        );
        // An ftp source present = explicit rejection (the same rejection
        // style as --ftp-pasv=false).
        let ftp_args = HttpArgs::try_parse_from([
            "http",
            "ftp://mirror.test/f.bin",
            "--ftp-proxy=http://fp.test:21",
        ])
        .unwrap_or_else(|e| panic!("parse: {e}"));
        assert!(
            ftp_args.add_options().is_ok(),
            "the payload parse face does not involve the source scheme"
        );
        assert!(
            ftp_args.check_proxy_sources(&ftp_args.urls).is_err(),
            "an ftp source x ftp-proxy must be explicitly rejected"
        );
        // Credentials without a subject / a password without a user / the
        // socks value domain.
        assert!(opts_of(&["--ftp-proxy-user=u"]).is_err());
        assert!(opts_of(&["--ftp-proxy=http://fp.test:1", "--ftp-proxy-passwd=p"]).is_err());
        assert!(opts_of(&["--ftp-proxy=socks5://fp.test:1080"]).is_err());
        // The --no-proxy bypass face: a moot --ftp-proxy flag does not
        // block a direct FTP connection.
        let bypassed = HttpArgs::try_parse_from([
            "http",
            "ftp://mirror.test/f.bin",
            "--ftp-proxy=http://fp.test:21",
            "--no-proxy=*",
        ])
        .unwrap_or_else(|e| panic!("parse: {e}"));
        assert!(bypassed.check_proxy_sources(&bypassed.urls).is_ok());
    }

    /// Domain 2: `--referer`/`--http-accept-gzip` mapped straight into the
    /// payload (trim, the bool dual form); `--referer` x a `--header`
    /// Referer line = conflict rejection; `--use-head` accepted but not
    /// effective (zero payload keys — the explicit warning disclosure is
    /// on the log face).
    #[test]
    fn d2_referer_accept_gzip_and_use_head_faces() {
        let opts = opts_of(&["--referer=https://ref.test/page", "--http-accept-gzip"])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            opts.get("referer").map(String::as_str),
            Some("https://ref.test/page")
        );
        assert_eq!(
            opts.get("http-accept-gzip").map(String::as_str),
            Some("true")
        );
        // The =false dual form + the default not sent.
        let opts = opts_of(&["--http-accept-gzip=false"]).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            opts.get("http-accept-gzip").map(String::as_str),
            Some("false")
        );
        let bare = opts_of(&[]).unwrap_or_else(|e| panic!("{e}"));
        assert!(!bare.contains_key("referer") && !bare.contains_key("http-accept-gzip"));
        // Conflict rejection: --referer x a manual Referer header line.
        let conflict = opts_of(&[
            "--referer=https://ref.test/page",
            "--header=Referer: https://other.test/",
        ]);
        assert!(conflict.is_err(), "a single Referer source");
        // The case-insensitive header-name comparison.
        let conflict = opts_of(&["--referer=x", "--header=REFERER: y"]);
        assert!(conflict.is_err());
        // use-head accepted but zero payload keys (accepted but not
        // effective — the explicit warning disclosure is on the log face).
        let opts = opts_of(&["--use-head"]).unwrap_or_else(|e| panic!("{e}"));
        assert!(!opts.contains_key("use-head"));
    }

    /// Domain 2 frozen-name assembly lock (the aria2 same names; a clap
    /// long-name spelling regression guard).
    #[test]
    fn d2_frozen_names_parse() {
        let parsed = HttpArgs::try_parse_from([
            "http",
            "http://a.test/f.bin",
            "--https-proxy=https://hs.test:8443",
            "--https-proxy-user=u",
            "--https-proxy-passwd=p",
            "--ftp-proxy=http://fp.test:21",
            "--ftp-proxy-user=fu",
            "--ftp-proxy-passwd=fp",
            "--no-proxy=*",
            "--use-head=false",
            "--referer=https://ref.test/",
            "--http-accept-gzip=true",
        ])
        .unwrap_or_else(|e| panic!("args must parse: {e}"));
        assert_eq!(parsed.https_proxy.as_deref(), Some("https://hs.test:8443"));
        assert_eq!(parsed.https_proxy_user.as_deref(), Some("u"));
        assert_eq!(parsed.https_proxy_passwd.as_deref(), Some("p"));
        assert_eq!(parsed.ftp_proxy.as_deref(), Some("http://fp.test:21"));
        assert_eq!(parsed.ftp_proxy_user.as_deref(), Some("fu"));
        assert_eq!(parsed.ftp_proxy_passwd.as_deref(), Some("fp"));
        assert_eq!(parsed.no_proxy.as_deref(), Some("*"));
        assert_eq!(parsed.use_head, Some(false));
        assert_eq!(parsed.referer.as_deref(), Some("https://ref.test/"));
        assert_eq!(parsed.http_accept_gzip, Some(true));
    }

    // ---- attach decision (option-comparison tests) ----

    fn row(gid: &str, url: &str, dir: &str, out: &str, config_json: &str) -> InflightRow {
        InflightRow {
            gid: gid.to_string(),
            url: url.to_string(),
            dir: dir.to_string(),
            out: out.to_string(),
            config_json: config_json.to_string(),
        }
    }

    const CFG_CHECKSUM_AB: &str =
        r#"{"incomplete_suffix":".part","checksum":"sha-256=AB","rename_pending":false}"#;
    const CFG_CHECKSUM_CD: &str =
        r#"{"incomplete_suffix":".part","checksum":"sha-256=cd","rename_pending":false}"#;
    const CFG_NO_CHECKSUM: &str = r#"{"incomplete_suffix":".motrix"}"#;

    /// Hit path: same URL + same dir + no explicit out -> attach with zero
    /// warnings (matching checksums on both sides also give zero
    /// warnings).
    #[test]
    fn attach_hit_without_warnings() {
        let rows = [row(
            "80ab",
            "http://a/f.bin",
            "/tmp/dl",
            "f.bin",
            CFG_NO_CHECKSUM,
        )];
        let d = decide_attach(
            &rows,
            "http://a/f.bin",
            Path::new("/tmp/dl"),
            None,
            None,
            None,
        );
        match d {
            AttachDecision::Attach { gid, warnings } => {
                assert_eq!(gid, "80ab");
                assert!(
                    warnings.is_empty(),
                    "a same-args rerun must have zero warnings: {warnings:?}"
                );
            }
            other => panic!("expected Attach, got {other:?}"),
        }
        // Same value on both sides (persisted sha-256=AB vs requested
        // sha-256=ab, case-normalized).
        let with_cs = [row(
            "80ab",
            "http://a/f.bin",
            "/tmp/dl",
            "f.bin",
            CFG_CHECKSUM_AB,
        )];
        let d = decide_attach(
            &with_cs,
            "http://a/f.bin",
            Path::new("/tmp/dl"),
            None,
            Some("sha-256=ab"),
            None,
        );
        match d {
            AttachDecision::Attach { warnings, .. } => {
                assert!(
                    warnings.is_empty(),
                    "same value on both sides = zero warnings: {warnings:?}"
                )
            }
            other => panic!("expected Attach, got {other:?}"),
        }
    }

    /// Checksum mismatch -> reject (the only rejection; hex
    /// case-insensitivity is not a difference).
    #[test]
    fn attach_rejects_checksum_conflict_case_insensitive_match() {
        let rows = [row(
            "80ab",
            "http://a/f.bin",
            "/tmp/dl",
            "f.bin",
            CFG_CHECKSUM_AB,
        )];
        // A case-only difference normalizes to the same value: attach.
        let d = decide_attach(
            &rows,
            "http://a/f.bin",
            Path::new("/tmp/dl"),
            None,
            Some("sha-256=ab"),
            None,
        );
        assert!(matches!(d, AttachDecision::Attach { .. }), "{d:?}");
        // A real value difference = reject.
        let d = decide_attach(
            &rows,
            "http://a/f.bin",
            Path::new("/tmp/dl"),
            None,
            Some("sha-256=cd"),
            None,
        );
        match d {
            AttachDecision::Reject { reason } => {
                assert!(
                    reason.contains("80ab"),
                    "rejection must carry the in-flight gid: {reason}"
                );
                assert!(
                    reason.contains("sha-256"),
                    "rejection must carry both values: {reason}"
                );
            }
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    /// One-sided checksum -> attach with an explicit warning (the
    /// in-flight persisted value will apply).
    #[test]
    fn attach_warns_one_sided_checksum() {
        let with_cs = [row(
            "80ab",
            "http://a/f.bin",
            "/tmp/dl",
            "f.bin",
            CFG_CHECKSUM_CD,
        )];
        let d = decide_attach(
            &with_cs,
            "http://a/f.bin",
            Path::new("/tmp/dl"),
            None,
            None,
            None,
        );
        let AttachDecision::Attach { warnings, .. } = d else {
            panic!("expected Attach, got {d:?}")
        };
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("persisted"), "{warnings:?}");

        let without_cs = [row(
            "80cd",
            "http://a/f.bin",
            "/tmp/dl",
            "f.bin",
            CFG_NO_CHECKSUM,
        )];
        let d = decide_attach(
            &without_cs,
            "http://a/f.bin",
            Path::new("/tmp/dl"),
            None,
            Some("sha-1=ff"),
            None,
        );
        let AttachDecision::Attach { warnings, .. } = d else {
            panic!("expected Attach, got {d:?}")
        };
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("NOT apply"), "{warnings:?}");
    }

    /// Suffix difference -> attach with a warning (persisted value wins);
    /// no match (dir/out mismatch) -> None.
    #[test]
    fn attach_suffix_warning_and_miss_paths() {
        let rows = [row(
            "80ab",
            "http://a/f.bin",
            "/tmp/dl",
            "f.bin",
            CFG_NO_CHECKSUM,
        )];
        let d = decide_attach(
            &rows,
            "http://a/f.bin",
            Path::new("/tmp/dl"),
            None,
            None,
            Some(".part"),
        );
        let AttachDecision::Attach { warnings, .. } = d else {
            panic!("expected Attach, got {d:?}")
        };
        assert!(
            warnings.len() == 1 && warnings[0].contains(".motrix"),
            "{warnings:?}"
        );

        // Different directory (still different after canonicalization) ->
        // miss.
        assert!(matches!(
            decide_attach(
                &rows,
                "http://a/f.bin",
                Path::new("/tmp/other"),
                None,
                None,
                None
            ),
            AttachDecision::None
        ));
        // Explicit out different from the row's out -> miss.
        assert!(matches!(
            decide_attach(
                &rows,
                "http://a/f.bin",
                Path::new("/tmp/dl"),
                Some("g.bin"),
                None,
                None
            ),
            AttachDecision::None
        ));
        // Different URL -> miss.
        assert!(matches!(
            decide_attach(
                &rows,
                "http://b/f.bin",
                Path::new("/tmp/dl"),
                None,
                None,
                None
            ),
            AttachDecision::None
        ));
    }

    /// Canonicalized directory comparison: relative / `..` /
    /// trailing-slash forms denoting the same directory as an absolute
    /// path -> hit. (False positives rest on system semantics: two
    /// spellings of one path.)
    #[test]
    fn attach_dir_comparison_is_canonical() {
        let rows = [row(
            "80ab",
            "http://a/f.bin",
            "/tmp",
            "f.bin",
            CFG_NO_CHECKSUM,
        )];
        // /tmp/../tmp and /tmp denote the same path (canonicalize).
        let d = decide_attach(
            &rows,
            "http://a/f.bin",
            Path::new("/tmp/../tmp"),
            None,
            None,
            None,
        );
        assert!(matches!(d, AttachDecision::Attach { .. }), "{d:?}");
        // Missing directory -> fall back to raw string comparison (no
        // panic, literal comparison).
        let missing = [row(
            "80cd",
            "http://a/f.bin",
            "/tmp/dl",
            "f.bin",
            CFG_NO_CHECKSUM,
        )];
        assert!(matches!(
            decide_attach(
                &missing,
                "http://a/f.bin",
                Path::new("/tmp/dl"),
                None,
                None,
                None
            ),
            AttachDecision::Attach { .. }
        ));
    }

    /// Row config read subset: missing keys default, broken JSON does not
    /// panic (defensive defaults).
    #[test]
    fn row_config_parse_is_defensive() {
        let cfg = RowConfig::parse(CFG_NO_CHECKSUM);
        assert!(cfg.checksum.is_none());
        assert_eq!(cfg.incomplete_suffix.as_deref(), Some(".motrix"));
        let broken = RowConfig::parse("{not json");
        assert!(broken.checksum.is_none() && broken.incomplete_suffix.is_none());
    }

    /// Exit-code structured matching: the value-domain rejection code
    /// (exact first token) = 2; everything else = 1; code-like text later
    /// in the message must not match (substring-sniffing regression pin).
    #[test]
    fn exit_code_structured_on_code_token() {
        let invalid_msg = format!("{CODE_OPTION_INVALID}: --out 'x/y' must be a plain file name");
        let invalid = SessionError::Failed {
            message: invalid_msg,
        };
        assert_eq!(exit_code_of(&invalid), 2);
        let mentions_code_late = SessionError::Failed {
            message: "task failed while validating taiji.option.invalid docs".into(),
        };
        assert_eq!(
            exit_code_of(&mentions_code_late),
            1,
            "a non-first token must not match"
        );
        let plain = SessionError::Failed {
            message: "file already exists".into(),
        };
        assert_eq!(exit_code_of(&plain), 1);
        assert_eq!(exit_code_of(&SessionError::SessionClosed), 1);
    }

    // ---- metalink form (silent-drop disclosure + pre-read size check) ----

    /// Drop-disclosure text for `--out`/`--checksum` in the metalink form
    /// (previously silent): explicit = one warning each; absent or empty
    /// string (unset semantics) = zero warnings — no false reports.
    #[test]
    #[cfg(feature = "metalink")]
    fn metalink_form_dropped_option_warnings() {
        let w = metalink_dropped_option_warnings(Some("f.bin"), Some("sha-256=ab"));
        assert_eq!(w.len(), 2, "both explicit options disclosed: {w:?}");
        assert!(w[0].contains("--out"), "{w:?}");
        assert!(w[1].contains("--checksum"), "{w:?}");
        // Absent / empty string = unset semantics, zero warnings.
        assert!(metalink_dropped_option_warnings(None, None).is_empty());
        assert!(metalink_dropped_option_warnings(Some(""), Some("")).is_empty());
        // One-sided presence gets one-sided disclosure.
        let w = metalink_dropped_option_warnings(Some("f.bin"), None);
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("--out"), "{w:?}");
    }

    /// Pre-read size check on document read: a normal document reads as
    /// usual; over the 16MiB document cap = Oversize (check first — an
    /// oversized file never enters process memory); missing = Io.
    #[tokio::test]
    #[cfg(feature = "metalink")]
    async fn read_metalink_document_prechecks_size_before_read() {
        let root = std::env::temp_dir().join(format!("tj-ml-read-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let small = root.join("small.metalink");
        std::fs::write(&small, b"<metalink/>").unwrap_or_else(|e| panic!("write: {e}"));
        let bytes = read_metalink_document(small.clone())
            .await
            .unwrap_or_else(|e| panic!("small doc must read: {e:?}"));
        assert_eq!(bytes, b"<metalink/>");

        // Sparse file: set_len raises the logical size with zero physical
        // writes — the pre-read cap means the read never happens (the
        // Oversize branch returns before reading).
        let big = root.join("big.metalink");
        let f = std::fs::File::create(&big).unwrap_or_else(|e| panic!("create: {e}"));
        f.set_len(taiji_rpc::metalink::MAX_DOCUMENT_BYTES as u64 + 1)
            .unwrap_or_else(|e| panic!("set_len: {e}"));
        drop(f);
        let err = match read_metalink_document(big.clone()).await {
            Err(e) => e,
            Ok(_) => panic!("oversize doc must be refused before read"),
        };
        let MetalinkDocReadError::Oversize { len, limit } = err else {
            panic!("expected Oversize, got {err:?}");
        };
        assert_eq!(limit, taiji_rpc::metalink::MAX_DOCUMENT_BYTES as u64);
        assert_eq!(len, limit + 1);
        // Missing file = Io.
        let missing = read_metalink_document(root.join("missing.metalink")).await;
        assert!(
            matches!(missing, Err(MetalinkDocReadError::Io(_))),
            "{missing:?}"
        );
        let _ = std::fs::remove_file(&small);
        let _ = std::fs::remove_file(&big);
        let _ = std::fs::remove_dir(&root);
    }
    /// `--http-max-per-host` 0 is rejected identically on BOTH parse
    /// surfaces — the `taiji http` subcommand (HttpArgs in this module)
    /// and the RPC server root form (main.rs Cli) share one
    /// `value_parser!(u32).range(1..)`. Before the fix the subcommand
    /// form had no value_parser: 0 was silently accepted (within u32) and
    /// the two surfaces diverged (the >= 1 domain declaration lives in
    /// the main.rs option note).
    #[test]
    fn http_max_per_host_zero_rejected_in_both_cli_forms() {
        // Subcommand form: 0 and equivalent below-domain forms are all
        // rejected.
        for bad in ["0", "0x0"] {
            assert!(
                HttpArgs::try_parse_from([
                    "http",
                    "http://a.test/f.bin",
                    &format!("--http-max-per-host={bad}"),
                ])
                .is_err(),
                "http subcommand form --http-max-per-host={bad} must be rejected (domain >= 1)"
            );
        }
        assert!(
            HttpArgs::try_parse_from(["http", "http://a.test/f.bin", "--http-max-per-host=1",])
                .is_ok(),
            "in-domain value 1 is accepted as usual"
        );
        // Root form (RPC server): main.rs Cli, same value_parser.
        assert!(
            crate::Cli::try_parse_from(["taiji", "--http-max-per-host=0"]).is_err(),
            "root form --http-max-per-host=0 must be rejected (domain >= 1)"
        );
        assert!(
            crate::Cli::try_parse_from(["taiji", "--http-max-per-host=1"]).is_ok(),
            "root form accepts in-domain value 1 as usual"
        );
    }

    // ---- domain 5: the metalink selector family (frozen flag names +
    // the selection-semantics single point) ----

    /// The metalink selector's seven flags accepted under their frozen
    /// names (a clap frozen-name spelling lock — the aria2 §4.7 group +
    /// the fork extension `--metalink-servers`).
    #[cfg(feature = "metalink")]
    #[test]
    fn metalink_selector_flags_parse_frozen_names() {
        let parsed = HttpArgs::try_parse_from([
            "http",
            "--metalink-file",
            "/tmp/d.metalink",
            "--metalink-language",
            "en-US",
            "--metalink-location",
            "jp,US",
            "--metalink-os",
            "windows",
            "--metalink-version",
            "1.2.3",
            "--metalink-preferred-protocol",
            "https",
            "--metalink-servers",
            "2",
            "--metalink-base-uri",
            "https://mirror.test/pub/",
        ])
        .unwrap_or_else(|e| panic!("args must parse: {e}"));
        assert_eq!(parsed.metalink_language.as_deref(), Some("en-US"));
        assert_eq!(parsed.metalink_location.as_deref(), Some("jp,US"));
        assert_eq!(parsed.metalink_os.as_deref(), Some("windows"));
        assert_eq!(parsed.metalink_version.as_deref(), Some("1.2.3"));
        assert_eq!(parsed.metalink_preferred_protocol.as_deref(), Some("https"));
        assert_eq!(parsed.metalink_servers, Some(2));
        assert_eq!(
            parsed.metalink_base_uri.as_deref(),
            Some("https://mirror.test/pub/")
        );
        // The cap value domain >= 1 (the fork-extension declared face).
        assert!(
            HttpArgs::try_parse_from([
                "http",
                "--metalink-file",
                "/tmp/d.metalink",
                "--metalink-servers=0",
            ])
            .is_err(),
            "--metalink-servers=0 must be rejected (value domain >= 1)"
        );
    }

    /// The selector test bed: a three-entry document construction
    /// (varied language/OS/version/location/protocol) + default HttpArgs
    /// (the `--metalink-file` form).
    #[cfg(feature = "metalink")]
    fn selector_doc() -> taiji_rpc::metalink::Metalink {
        use taiji_rpc::metalink::{MetaUrl, Metalink, MetalinkFile, Url};
        let url = |uri: &str, location: Option<&str>, priority: u32| Url {
            uri: uri.to_string(),
            location: location.map(str::to_string),
            priority,
        };
        let en = MetalinkFile {
            name: "en.bin".into(),
            version: Some("1.2.3".into()),
            languages: vec!["en-US".into()],
            oses: vec!["windows".into()],
            urls: vec![
                url("http://a.test/f.bin", Some("us"), 5),
                url("ftp://b.test/f.bin", Some("jp"), 3),
            ],
            ..Default::default()
        };
        let zh = MetalinkFile {
            name: "zh.bin".into(),
            version: Some("2.0.0".into()),
            languages: vec!["zh-CN".into()],
            oses: vec!["linux".into()],
            urls: vec![url("http://c.test/f.bin", None, 1)],
            ..Default::default()
        };
        let bt = MetalinkFile {
            name: "bt.bin".into(),
            metaurls: vec![MetaUrl {
                uri: "https://t.test/f.torrent".into(),
                mediatype: "torrent".into(),
                priority: 1,
                name: None,
            }],
            ..Default::default()
        };
        Metalink {
            files: vec![en, zh, bt],
            ..Default::default()
        }
    }

    #[cfg(feature = "metalink")]
    fn selector_args(extra: &[&str]) -> HttpArgs {
        let mut argv = vec!["http", "--metalink-file", "/tmp/d.metalink"];
        argv.extend_from_slice(extra);
        HttpArgs::try_parse_from(argv).unwrap_or_else(|e| panic!("selector args: {e}"))
    }

    /// Entry preference filtering (the same rule as aria2's
    /// `Metalinker::queryEntry`): version exact equality / language, os
    /// exact containment; an entry WITHOUT that field declared = no hit
    /// (the same rule as the reference `containsLanguage` empty set being
    /// always false); an empty string = no filter; everything filtered =
    /// the caller's exit-2 face (decided by `run_metalink` — the filter
    /// itself is pinned here).
    #[cfg(feature = "metalink")]
    #[test]
    fn metalink_selection_filters_entries_by_prefs() {
        // language hits en-US → only en.bin remains (bt.bin has no
        // language declaration = an empty set never hits, the same rule
        // as the reference containsLanguage; zh.bin does not match).
        let mut doc = selector_doc();
        apply_metalink_selection(&selector_args(&["--metalink-language=en-US"]), &mut doc);
        assert_eq!(
            doc.files
                .iter()
                .map(|f| f.name.as_str())
                .collect::<Vec<_>>(),
            ["en.bin"]
        );
        // version exact equality: 2.0.0 hits → only zh.bin remains.
        let mut doc = selector_doc();
        apply_metalink_selection(&selector_args(&["--metalink-version=2.0.0"]), &mut doc);
        assert_eq!(
            doc.files
                .iter()
                .map(|f| f.name.as_str())
                .collect::<Vec<_>>(),
            ["zh.bin"]
        );
        // A version that is not exact (a prefix) does not hit; bt.bin has
        // no version declaration and does not hit either — every entry
        // dropped (the caller's exit-2 criterion).
        let mut doc = selector_doc();
        apply_metalink_selection(&selector_args(&["--metalink-version=1"]), &mut doc);
        assert!(
            doc.files.is_empty(),
            "a non-exact prefix version = drop all"
        );
        // os exact containment: windows → en.bin (bt.bin has no os
        // declaration = no hit).
        let mut doc = selector_doc();
        apply_metalink_selection(&selector_args(&["--metalink-os=windows"]), &mut doc);
        assert_eq!(
            doc.files
                .iter()
                .map(|f| f.name.as_str())
                .collect::<Vec<_>>(),
            ["en.bin"]
        );
        // Everything filtered: language=fr → zero entries (the caller's
        // exit-2 criterion).
        let mut doc = selector_doc();
        apply_metalink_selection(&selector_args(&["--metalink-language=fr"]), &mut doc);
        assert!(
            doc.files.is_empty(),
            "all filtered by preferences = an empty document"
        );
        // An empty-string value = no filter (the DefaultOptionHandler
        // empty-value rule) — an empty flag value equals not giving it.
        let mut doc = selector_doc();
        apply_metalink_selection(&selector_args(&["--metalink-language="]), &mut doc);
        assert_eq!(doc.files.len(), 3);
    }

    /// The location/protocol priority boost (a direct translation of
    /// aria2's setLocationPriority/setProtocolPriority): a hit applies
    /// priority -= 999999 (saturating); two hits stack; `none`/an empty
    /// value = no preference; case-insensitive.
    #[cfg(feature = "metalink")]
    #[test]
    fn metalink_selection_boosts_location_and_protocol_priority() {
        // location=jp: en.bin's ftp mirror (jp, priority 3) outranks the
        // http one (us, 5).
        let mut doc = selector_doc();
        apply_metalink_selection(&selector_args(&["--metalink-location=jp"]), &mut doc);
        let en = &doc.files[0];
        assert_eq!(en.urls[0].priority, 5, "the us mirror does not hit");
        assert_eq!(
            en.urls[1].priority,
            3u32.saturating_sub(taiji_rpc::metalink::DEFAULT_PRIORITY),
            "the jp mirror is boosted (saturating subtraction)"
        );
        // Case-insensitive + whitespace tolerant: uppercase JP hits; a
        // multi-value comma list.
        let mut doc = selector_doc();
        apply_metalink_selection(&selector_args(&["--metalink-location= US,jp "]), &mut doc);
        let en = &doc.files[0];
        assert_eq!(
            en.urls[0].priority,
            5u32.saturating_sub(taiji_rpc::metalink::DEFAULT_PRIORITY)
        );
        assert_eq!(
            en.urls[1].priority,
            3u32.saturating_sub(taiji_rpc::metalink::DEFAULT_PRIORITY)
        );
        // Protocol preference ftp: the ftp:// mirror hits; none/empty = no
        // preference.
        let mut doc = selector_doc();
        apply_metalink_selection(
            &selector_args(&["--metalink-preferred-protocol=ftp"]),
            &mut doc,
        );
        assert_eq!(
            doc.files[0].urls[1].priority,
            3u32.saturating_sub(taiji_rpc::metalink::DEFAULT_PRIORITY)
        );
        assert_eq!(doc.files[0].urls[0].priority, 5);
        let mut doc = selector_doc();
        apply_metalink_selection(
            &selector_args(&["--metalink-preferred-protocol=none"]),
            &mut doc,
        );
        assert_eq!(doc.files[0].urls[0].priority, 5, "none = no preference");
        // Two hits stack (location=us + protocol=http → the same URL
        // subtracted twice).
        let mut doc = selector_doc();
        apply_metalink_selection(
            &selector_args(&[
                "--metalink-location=us",
                "--metalink-preferred-protocol=http",
            ]),
            &mut doc,
        );
        let boost = taiji_rpc::metalink::DEFAULT_PRIORITY;
        assert_eq!(
            doc.files[0].urls[0].priority,
            5u32.saturating_sub(2 * boost)
        );
    }

    /// The mirror cap (the fork extension `--metalink-servers`): a stable
    /// pre-sort by priority ascending (document order within an equal
    /// priority) truncated to the first N.
    #[cfg(feature = "metalink")]
    #[test]
    fn metalink_selection_caps_servers_after_priority_sort() {
        use taiji_rpc::metalink::{Metalink, MetalinkFile, Url};
        let f = MetalinkFile {
            name: "cap.bin".into(),
            urls: vec![
                Url {
                    uri: "http://lo.test/f".into(),
                    location: None,
                    priority: 7,
                },
                Url {
                    uri: "http://hi.test/f".into(),
                    location: None,
                    priority: 1,
                },
                Url {
                    uri: "http://mid.test/f".into(),
                    location: None,
                    priority: 4,
                },
            ],
            ..Default::default()
        };
        let mut doc = Metalink {
            files: vec![f],
            ..Default::default()
        };
        apply_metalink_selection(&selector_args(&["--metalink-servers=2"]), &mut doc);
        assert_eq!(
            doc.files[0]
                .urls
                .iter()
                .map(|u| u.uri.as_str())
                .collect::<Vec<_>>(),
            ["http://hi.test/f", "http://mid.test/f"],
            "truncation = the 2 best by priority (in priority-ascending order)"
        );
        // A cap larger than the mirror count = identity.
        let mut doc = selector_doc();
        apply_metalink_selection(&selector_args(&["--metalink-servers=99"]), &mut doc);
        assert_eq!(doc.files[0].urls.len(), 2);
        // The cap combined with preference filtering: filter first, then
        // cap (zh.bin has only 1 mirror, cap 1 = identity).
        let mut doc = selector_doc();
        apply_metalink_selection(
            &selector_args(&["--metalink-version=2.0.0", "--metalink-servers=1"]),
            &mut doc,
        );
        assert_eq!(doc.files.len(), 1);
        assert_eq!(doc.files[0].urls.len(), 1);
    }

    /// The relative URI resolution base (the RFC 3986 §5 restricted
    /// face): absolute verbatim / network-path inherits the scheme /
    /// absolute and relative paths / dot-segment removal / query
    /// inheritance / fragment stripping / an unparseable base form =
    /// None (the caller drops it with a warning).
    #[cfg(feature = "metalink")]
    #[test]
    fn metalink_base_uri_resolves_relative_references() {
        let base = "https://mirror.test/pub/dir/";
        assert_eq!(
            resolve_uri_reference(base, "f.iso").as_deref(),
            Some("https://mirror.test/pub/dir/f.iso")
        );
        assert_eq!(
            resolve_uri_reference(base, "../f.iso").as_deref(),
            Some("https://mirror.test/pub/f.iso")
        );
        assert_eq!(
            resolve_uri_reference(base, "/abs/f.iso").as_deref(),
            Some("https://mirror.test/abs/f.iso")
        );
        assert_eq!(
            resolve_uri_reference(base, "http://other.test/f.iso").as_deref(),
            Some("http://other.test/f.iso"),
            "an absolute reference passes through verbatim"
        );
        assert_eq!(
            resolve_uri_reference(base, "//cdn.test/f.iso").as_deref(),
            Some("https://cdn.test/f.iso"),
            "a network-path reference inherits the scheme"
        );
        assert_eq!(
            resolve_uri_reference(base, "a/../b.iso?x=1").as_deref(),
            Some("https://mirror.test/pub/dir/b.iso?x=1"),
            "dot-segment removal + the reference query"
        );
        assert_eq!(
            resolve_uri_reference("https://h.test/dir/page", "f.iso").as_deref(),
            Some("https://h.test/dir/f.iso"),
            "a base without the trailing slash = last-segment replacement (the §5.2.3 merge)"
        );
        assert_eq!(
            resolve_uri_reference(base, "f.iso#frag").as_deref(),
            Some("https://mirror.test/pub/dir/f.iso"),
            "the fragment is stripped"
        );
        assert_eq!(
            resolve_uri_reference("https://h.test/dir?q=1", "").as_deref(),
            Some("https://h.test/dir?q=1"),
            "an empty reference = the base verbatim"
        );
        assert_eq!(
            resolve_uri_reference("not-a-base", "f.iso"),
            None,
            "a scheme-less base is unparseable"
        );
        // The document face: base-uri lands on both the url and metaurl
        // faces.
        let mut doc = selector_doc();
        doc.files[0].urls[0].uri = "f.iso".into();
        doc.files[2].metaurls[0].uri = "meta/f.torrent".into();
        apply_metalink_selection(
            &selector_args(&["--metalink-base-uri=https://m.test/pub/"]),
            &mut doc,
        );
        assert_eq!(doc.files[0].urls[0].uri, "https://m.test/pub/f.iso");
        assert_eq!(
            doc.files[2].metaurls[0].uri,
            "https://m.test/pub/meta/f.torrent"
        );
    }

    /// Wiring: the `--follow-torrent` gate decision table
    /// (a pure-function pin). true (the default) = an identity — the
    /// standing shape (metaurl candidates intact, the expansion seam's
    /// BT conversion proceeds); false = the metaurl candidates are
    /// cleared (the count is returned for the caller's notice) while
    /// the `<url>` mirror set is untouched.
    #[cfg(feature = "metalink")]
    #[test]
    fn follow_torrent_gate_decision_table() {
        // true = identity (the standing conversion proceeds).
        let mut doc = selector_doc();
        assert_eq!(
            apply_follow_torrent_gate(true, &mut doc),
            0,
            "true = no candidates cleared, no notice"
        );
        assert_eq!(doc.files[2].metaurls.len(), 1, "metaurl face intact");

        // false = the metaurl face cleared (the bt.bin entry carries the
        // one candidate), the mirror set untouched.
        let mut doc = selector_doc();
        assert_eq!(
            apply_follow_torrent_gate(false, &mut doc),
            1,
            "the cleared candidate count feeds the notice"
        );
        assert!(
            doc.files.iter().all(|f| f.metaurls.is_empty()),
            "the metaurl face is cleared (no BT conversion)"
        );
        assert_eq!(
            doc.files[0].urls.len(),
            2,
            "the <url> mirror downloads proceed"
        );
        // An already-empty document = no-op (0 cleared).
        let mut doc = selector_doc();
        apply_follow_torrent_gate(false, &mut doc);
        assert_eq!(apply_follow_torrent_gate(false, &mut doc), 0);
    }

    /// Acceptance pin: the `--follow-torrent` /
    /// `--metalink-enable-unique-protocol` frozen-name acceptance (the
    /// bool dual forms + the defaults: follow-torrent true = the
    /// standing behavior, unique-protocol unset = the aria2 default
    /// false face) + the positional form's clap-default fill
    /// (follow_torrent = true keeps the warn_deferred single-URL-form
    /// check quiet).
    #[cfg(feature = "metalink")]
    #[test]
    fn follow_torrent_and_unique_protocol_parse_frozen_names() {
        let parsed = HttpArgs::try_parse_from([
            "http",
            "https://h.test/f.bin",
            "--follow-torrent=false",
            "--metalink-enable-unique-protocol",
        ])
        .unwrap_or_else(|e| panic!("args must parse: {e}"));
        assert!(!parsed.follow_torrent, "=false explicitly suppresses");
        assert_eq!(
            parsed.metalink_enable_unique_protocol,
            Some(true),
            "bare bool flag = true"
        );
        // The default face: follow-torrent true, unique-protocol unset.
        let parsed = HttpArgs::try_parse_from(["http", "https://h.test/f.bin"])
            .unwrap_or_else(|e| panic!("defaults: {e}"));
        assert!(parsed.follow_torrent, "default true = the standing shape");
        assert_eq!(
            parsed.metalink_enable_unique_protocol, None,
            "unset = the aria2 default false face (zero noise)"
        );
        // The positional form carries the clap-default true explicitly.
        let a = args_from_positional(
            "http://h/f.bin".into(),
            PathBuf::from("/d"),
            taiji_core::session::SUMMARY_INTERVAL_DEFAULT,
            None,
            None,
        );
        assert!(a.follow_torrent, "the positional form keeps the default");
    }
}

#[cfg(test)]
mod cli_ex1_tests {
    use super::*;

    /// Top-level positional argument -> minimal HttpArgs construction
    /// (clap-default alignment: dir/session-store path; the summary
    /// interval is passed in by the caller, the default form passes the
    /// clap-equal SUMMARY_INTERVAL_DEFAULT).
    #[test]
    fn args_from_positional_mirrors_clap_defaults() {
        let a = args_from_positional(
            "http://h/f.bin".into(),
            std::path::PathBuf::from("/d"),
            taiji_core::session::SUMMARY_INTERVAL_DEFAULT,
            None,
            None,
        );
        assert_eq!(a.urls, vec!["http://h/f.bin".to_string()]);
        assert_eq!(a.dir, std::path::PathBuf::from("/d"));
        assert_eq!(a.sqlite3_db_path, std::path::PathBuf::from("taiji.sqlite3"));
        assert_eq!(
            a.summary_interval,
            taiji_core::session::SUMMARY_INTERVAL_DEFAULT
        );
        assert!(
            a.out.is_none() && a.checksum.is_none() && a.ca_certificate.is_none(),
            "minimal surface: optional pieces unset"
        );
    }

    /// Top-level `--summary-interval` flag injection into the positional
    /// URL form (previously hardcoded to SUMMARY_INTERVAL_DEFAULT — the
    /// flag was silently ignored in that form). 0 = summary disabled
    /// (same rule as aria2 summary-interval=0), 60 = default, the
    /// INT32_MAX upper bound passes through (domain validation lives in
    /// the clap value_parser on the main.rs Cli side).
    #[test]
    fn args_from_positional_summary_interval_decision_table() {
        // 0 = disabled.
        let a = args_from_positional("http://h/f.bin".into(), PathBuf::from("/d"), 0, None, None);
        assert_eq!(a.summary_interval, 0, "0 = summary disabled");
        // 60 = default (clap default_value = SUMMARY_INTERVAL_DEFAULT).
        let a = args_from_positional(
            "http://h/f.bin".into(),
            PathBuf::from("/d"),
            taiji_core::session::SUMMARY_INTERVAL_DEFAULT,
            None,
            None,
        );
        assert_eq!(
            a.summary_interval,
            taiji_core::session::SUMMARY_INTERVAL_DEFAULT,
            "60 = the default"
        );
        // Extreme value: the INT32_MAX upper bound passes through (no
        // truncation, no fallback).
        let a = args_from_positional(
            "http://h/f.bin".into(),
            PathBuf::from("/d"),
            taiji_core::session::SUMMARY_INTERVAL_MAX,
            None,
            None,
        );
        assert_eq!(
            a.summary_interval,
            taiji_core::session::SUMMARY_INTERVAL_MAX,
            "the INT32_MAX upper bound passes through"
        );
    }

    /// Domain B decision table: the top-level `--ca-certificate` maps
    /// onto the addUri option face (None = the key is not sent — the
    /// same rule as the add_options empty values are not sent; Some =
    /// the value travels verbatim, validation belongs to the session
    /// parse arm's single source).
    #[test]
    fn args_from_positional_ca_certificate_mapping() {
        let a = args_from_positional(
            "https://h/f.bin".into(),
            PathBuf::from("/d"),
            taiji_core::session::SUMMARY_INTERVAL_DEFAULT,
            None,
            None,
        );
        assert!(
            !a.add_options()
                .unwrap_or_else(|e| panic!("{e}"))
                .contains_key("ca-certificate"),
            "the ca-certificate key is not sent when unset"
        );
        let a = args_from_positional(
            "https://h/f.bin".into(),
            PathBuf::from("/d"),
            taiji_core::session::SUMMARY_INTERVAL_DEFAULT,
            Some("/etc/taiji/ca.pem".to_string()),
            None,
        );
        assert_eq!(
            a.add_options()
                .unwrap_or_else(|e| panic!("{e}"))
                .get("ca-certificate")
                .map(String::as_str),
            Some("/etc/taiji/ca.pem"),
            "Some = passes through verbatim (validation lives in the session parse arm)"
        );
    }

    /// Domain C decision table: the top-level `--load-cookies` maps onto
    /// the addUri option face (None = the key is not sent; Some = the
    /// path travels verbatim, loading/validation belongs to the
    /// session's fail-closed single point at task acceptance — the same
    /// gate as `taiji http --load-cookies`).
    #[test]
    fn args_from_positional_load_cookies_mapping() {
        let a = args_from_positional(
            "https://h/f.bin".into(),
            PathBuf::from("/d"),
            taiji_core::session::SUMMARY_INTERVAL_DEFAULT,
            None,
            None,
        );
        assert!(
            !a.add_options()
                .unwrap_or_else(|e| panic!("{e}"))
                .contains_key("load-cookies"),
            "the load-cookies key is not sent when unset"
        );
        let a = args_from_positional(
            "https://h/f.bin".into(),
            PathBuf::from("/d"),
            taiji_core::session::SUMMARY_INTERVAL_DEFAULT,
            None,
            Some("/tmp/cookies.txt".to_string()),
        );
        assert_eq!(
            a.add_options()
                .unwrap_or_else(|e| panic!("{e}"))
                .get("load-cookies")
                .map(String::as_str),
            Some("/tmp/cookies.txt"),
            "Some = the path passes through verbatim (fail-closed load at task acceptance)"
        );
    }
}
