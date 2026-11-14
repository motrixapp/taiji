//! Full RPC/option differential guard: cross-validates taiji against a live
//! aria2 fork reference build in two processes with identical inputs.
//!
//! Method (docs/rpc-api-diff.md governance rules): taiji runs its RPC server
//! in-process in compat mode (`aria2_compat = true`) with sqlite persistence
//! (the Motrix runtime shape); the fork binary runs as a child process with
//! `--enable-rpc --enable-sqlite3-persistence`; both sides get the same
//! `--dir`, the same secret, and the same task sequence, and every method is
//! compared one by one — response shape, error codes, error messages, event
//! names, and option echo values.
//!
//! **Zero differences outside the whitelist**: every observed difference must
//! hit an entry in [`WHITELIST`] below (each entry is checked at compile time
//! against its anchor text in docs/rpc-api-diff.md); a difference with no
//! matching entry turns the test red. Reverse governance: a whitelist entry
//! whose two sides have converged (no actual difference) is also red — entry
//! removal requires a PR.
//!
//! # Explicit skip policy (no fake green)
//!
//! When the reference binary is unavailable (no fork checkout / path not
//! configured), the test is **red by default** — a "fully green differential"
//! with zero comparisons is fake green (a SKIP marker with no gate consuming
//! it would be a backdoor). Only setting `TAIJI_DIFF_ALLOW_SKIP=1` downgrades
//! to a SKIP-green pass: the test prints a machine-readable marker
//! `SKIP(taiji.rpc.live-diff): …` to stderr and returns; downgrade consumers
//! (CI / release scripts) must check that marker — a SKIP present means this
//! green is not a differential green. Local / release verification must be
//! based on one fully green run without the SKIP marker. The fork checkout is
//! read-only (ADR discipline): this test only runs its existing build as a
//! child process; it never builds or modifies the checkout.
//!
//! Reference location: setting the `TAIJI_DIFF_ARIA2C` environment variable
//! (a path) takes effect explicitly (an invalid path means the reference is
//! absent; no fallback probing); when unset, the default probe looks for the
//! workspace sibling checkouts `aria2/src/aria2c` (the upstream layout) and
//! the Motrix fork layout `aria2_motrix/src/aria2c` (see
//! [`DEFAULT_PROBE_LAYOUTS`]; the resolution core is unit-anchored in
//! `reference_resolution_absent_and_explicit_shapes`).
//!
//! WS push event names are not driven live by this test (fork events are
//! driven by real downloads, with nondeterministic timing); the event-name
//! surface is pinned jointly by the live zero-diff of
//! `system.listNotifications` and the in-process push tests in `http_ws.rs`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use taiji_core::session::{RPC_METHODS, SessionActor};
use taiji_rpc::{RpcConfig, ServerHandle, serve};

const SECRET: &str = "taiji-live-diff";
const TOKEN: &str = "token:taiji-live-diff";

/// Shutdown family is excluded from the parameter matrix (it terminates both
/// engines); `system.multicall` has its own zero-diff row; `forceRecheck` (a
/// bare-name capability extension) has no fork counterpart (upstream has no
/// recheck RPC) — excluded from the matrix in the same direction as
/// `taiji.*`; declared in rpc-api-diff §1.
const MATRIX_EXCLUDED: &[&str] = &[
    "shutdown",
    "forceShutdown",
    "system.multicall",
    "forceRecheck",
];

/// No-arg methods (skipped in the missing-arg / wrong-type matrix rows —
/// both sides loosely ignore extra arguments, so no difference is observable
/// there; their empty-arg success surface is asserted in a dedicated row).
const NO_ARG_METHODS: &[&str] = &[
    "pauseAll",
    // forcePauseAll: once part of the committed method set, it joins the
    // no-arg matrix plus its own empty-arg success zero-diff row (the
    // reference answers from the same pauseAllDownloads family, always OK).
    "forcePauseAll",
    "unpauseAll",
    "purgeDownloadResult",
    "saveSession",
    "getSessionInfo",
    "getGlobalOption",
    "getGlobalStat",
    "tellActive",
    "getVersion",
    "system.listMethods",
    "system.listNotifications",
];

/// Bare-name methods that take a gid (the set exercised by the unknown-gid /
/// invalid-gid zero-diff rows). `changeUri`/`changeOption` are not listed
/// here: the two sides check required parameters in a different order (this
/// side resolves the gid first) and their surface is covered by the
/// state-scenario rows; the gid row of `changePosition` only reaches the
/// missing-parameter-1 message (same order on both sides), so its behavior
/// surface is cross-validated in a dedicated row.
const GID_METHODS: &[&str] = &[
    "tellStatus",
    "getFiles",
    "getPeers",
    "getServers",
    "getUris",
    "getOption",
    "pause",
    "forcePause",
    "unpause",
    "remove",
    "removeDownloadResult",
    "changePosition",
];

/// Declaration doc for differences (embedded at compile time): the source
/// checked against whitelist anchors.
const DOC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/rpc-api-diff.md"
));

/// Whitelist (the in-repo check basis for the controlled living doc):
/// `(entry id, anchor substring in docs/rpc-api-diff.md)`. Governance = PR +
/// user approval; each id's anchor must appear in the declaration doc (a doc
/// edit that drops the anchor turns the test red). Entries come in two
/// kinds: live-driven surfaces (consumed at the call site via `declared()`;
/// reverse governance = a converged difference is red) and declaration-
/// surface entries (seam semantics already in rustdoc with no deterministic
/// fork counterpart — only anchored in the doc to prevent drift, not
/// promised to be live-driven).
const WHITELIST: &[(&str, &str)] = &[
    ("get-version-face", "getVersion"),
    ("http-output-ready-event", "taiji.onHttpOutputReady"),
    ("method-face-missing", "Method-face missing entries"),
    // Fork-specific task-level cookie RPC surface: accepted with Motrix as
    // the baseline, but committed under canonical `taiji.*` names
    // (rpc-api-diff §1); compat mode does not project `aria2.*` aliases, so
    // same-name fork calls still land on "No such method" — this entry
    // anchors that surface.
    (
        "method-face-missing-adduri-with-cookies",
        "addUriWithCookies",
    ),
    ("method-face-missing-set-task-cookies", "setTaskCookies"),
    ("bare-name-acceptance", "Bare-name acceptance"),
    ("taiji-extension-methods", "`taiji.*` extension methods"),
    ("global-echo-subset", "Echo-surface direction"),
    ("global-echo-taiji-only", "taiji-only echo keys"),
    ("global-echo-shared-values", "Shared-key value differences"),
    // getOption echo surface (declaration-surface entry): the behavioral
    // differences (accepted-subset projection, baseline-value projection,
    // value shape, default handling, final-state domain reads) are only
    // observed when values are taken live from a real task; the parameter
    // matrix zero-diff rows are unaffected.
    ("get-option-echo-face", "`getOption` echo surface"),
    ("option-invalid-value", "Invalid-value semantics"),
    (
        "option-domain-reject",
        "explicitly rejected by taiji (`taiji.option.invalid`, no truncation)",
    ),
    ("status-http-subdict", "`http` subdict"),
    ("status-progress-granularity", "Progress accounting basis"),
    ("status-bt-superset", "BT-face superset keys"),
    ("pre-probe-projection", "Pre-probe projection"),
    ("sftp-deferred", "sftp:// deferred"),
    ("unknown-scheme", "Unknown scheme"),
    ("add-torrent-base64", "addTorrent invalid base64"),
    ("metalink-version", "Version surface"),
    ("metalink-boundary", "Parsing boundary"),
    // Declaration-surface entries (expanded seam semantics already in
    // rustdoc; no deterministic live counterpart — only anchored in the
    // declaration doc to prevent drift, not driven via `declared()`):
    (
        "metalink-dir-out-dedup",
        "Later entries with the same (dir,out) are skipped",
    ),
    (
        "metalink-caller-out-checksum-stripped",
        "Caller-supplied out/checksum stripped wholesale",
    ),
    (
        "metalink-same-doc-dedup",
        "Same-document magnet/metaurl dedup skip",
    ),
    (
        "metalink-bt-plan-no-hash",
        "BT plans consume no entry hash and carry no out/checksum",
    ),
    (
        "metalink-partial-failure-message",
        "Partial-failure receipt message wording difference",
    ),
    ("metalink-parse-timeout", "taiji.metalink.timeout"),
];

/// Echo-drift audit (2026-10-28, dev @ 13dc8855 + fork live run):
/// every taiji-only `getGlobalOption` key observed in the live differential,
/// one row per key — `(key, anchor substring in docs/rpc-api-diff.md)`.
/// Each row is ruled a **legitimate extension** and counted in the budget;
/// the anchor test below keeps every ruling tied to its declaration text
/// (a doc edit that drops the anchor turns the test red — the same
/// governance as [`WHITELIST`]). Two families, both ruled legitimate:
/// - declared extension names (Phase A pairs / hook family / session keys /
///   the tracker import / the HTTP cap): the fork has no such option at
///   all (upstream `prefs.cc` has no such `makePref`, or the name is a
///   declared rename);
/// - accepted aria2-name value faces (`all-proxy`, `https-proxy`,
///   `async-dns`, `enable-async-dns6`, `bt-exclude-tracker`, `pause`,
///   `dht-entry-point`, `load-cookies`): the fork's `getGlobalOption`
///   returns defined prefs only (`RpcMethodImpl.cc` skips entries not
///   present in the global option table — verified live 2026-10-28: a
///   default startup echoes 132 defined keys, and a NO_DEFAULT pref such
///   as `all-proxy` appears only once set on the command line), while
///   taiji echoes the accepted value face always (empty string = unset)
///   — the Motrix-alignment round-trip; convergence when the fork side is
///   explicitly set is by design, not drift.
///
/// The table IS the budget (audited count 25 + the media family 10 —
/// the 8 unified-registration keys plus media-archive/media-info-json — +
/// the four-pool budget trio 3 — `max-concurrent-seeds`/
/// `max-concurrent-checks`/`media-synthesis-concurrency`, anchors =
/// the §3 dedicated entry — = 38): rows
/// stay sorted, and the live set must equal the table
/// member-for-member — a new taiji-only key without a ruled anchor row is
/// red, and a converged row (a key the live set no longer observes) is red
/// until reclaimed via governance.
///
/// Source attribution: the hook family ×6 and the proxy pair
/// (`all-proxy`/`https-proxy`) — ; `load-cookies`/`save-session`
/// — ; the remaining keys — the Phase A / §3 declarations
/// (`DECLARED_OPTION_DIFFS` and the `GLOBAL_PATCH_TABLE` echo rows,
/// taiji-core `session::options`).
const TAIJI_ONLY_ECHO_AUDIT: &[(&str, &str)] = &[
    ("all-proxy", "`all-proxy` / `https-proxy`"),
    ("async-dns", "`async-dns` / `enable-async-dns6` (resolver"),
    ("bt-enable-nat-pmp", "`bt-enable-nat-pmp`"),
    ("bt-enable-upnp", "`bt-enable-upnp`"),
    (
        "bt-exclude-tracker",
        "`bt-exclude-tracker` (no exclusion face",
    ),
    ("bt-lsd", "`bt-lsd`"),
    ("bt-metadata-web-sources", "`bt-metadata-web-sources`"),
    ("bt-peer-connection-type", "`bt-peer-connection-type`"),
    ("bt-tracker", "`bt-tracker` (the fork silently ignores"),
    ("bt-tracker-file", "`bt-tracker-file`"),
    ("client-ban-prefixes", "`client-ban-prefixes`"),
    ("dht-entry-point", "`dht-entry-point`"),
    ("dht-entry-point6", "`dht-entry-point6`"),
    ("enable-async-dns6", "`enable-async-dns6`"),
    (
        "http-max-per-host",
        "`http-max-per-host` has since actually entered the getGlobalOption",
    ),
    ("https-proxy", "`all-proxy` / `https-proxy`"),
    ("load-cookies", "`load-cookies` accepted"),
    ("max-concurrent-checks", "Four-pool budget trio"),
    ("max-concurrent-seeds", "Four-pool budget trio"),
    // The media family (2026-10-28: the unified-registration 8 +
    // 2026-10-30: the media-archive/media-info-json product
    // faces — the fork has no media surface at all; anchors = the §3
    // media option-family declaration in docs/rpc-api-diff.md, whose
    // product-face entry carries the two new keys).
    (
        "media-allow-private-key-url",
        "Media option family (unified registration",
    ),
    ("media-archive", "Media product faces (taiji extensions"),
    (
        "media-audio-lang",
        "Media option family (unified registration",
    ),
    (
        "media-ffmpeg-path",
        "Media option family (unified registration",
    ),
    ("media-info-json", "Media product faces (taiji extensions"),
    (
        "media-segment-concurrency",
        "Media option family (unified registration",
    ),
    (
        "media-staging-dir",
        "Media option family (unified registration",
    ),
    (
        "media-staging-quota-gib",
        "Media option family (unified registration",
    ),
    (
        "media-subtitles",
        "Media option family (unified registration",
    ),
    ("media-synthesis-concurrency", "Four-pool budget trio"),
    (
        "media-variant-policy",
        "Media option family (unified registration",
    ),
    ("motrix-peer-listeners", "`motrix-peer-listeners`"),
    ("motrix-startup-tasks", "`motrix-startup-tasks`"),
    ("on-bt-download-complete", "`on-bt-download-complete`"),
    ("on-download-complete", "the hook notification family"),
    ("on-download-error", "the hook notification family"),
    ("on-download-pause", "the hook notification family"),
    ("on-download-start", "the hook notification family"),
    ("on-download-stop", "the hook notification family"),
    ("pause", "no global pause template face"),
    ("save-session", "`save-session`"),
    ("seed-time", "`seed-time`"),
];

/// Shared-key value-diff audit (2026-10-28, same live run): shared
/// `getGlobalOption` keys whose values differ under identical default
/// inputs — `(key, anchor substring in docs/rpc-api-diff.md)`. Two
/// families, both ruled declared divergences:
/// - the three Phase A declarations (`listen-port` range vs single value,
///   the `peer-id-prefix` namespacing, the `seed-ratio` minimal numeric
///   form — §3 "Shared-key value differences");
/// - the Motrix-alignment no-op value faces shared with the fork's echo:
///   unset records no override (the empty-string echo), while the fork
///   echoes its **defined defaults** for the same keys (defaults are
///   defined prefs there — the declared divergence direction, the same
///   accepted-value-face family as [`TAIJI_ONLY_ECHO_AUDIT`]).
///
/// Rows stay sorted; a value drift outside this table is red, and a
/// converged row is red until reclaimed (same governance as WHITELIST).
const SHARED_VALUE_DIFF_AUDIT: &[(&str, &str)] = &[
    ("async-dns", "`async-dns` / `enable-async-dns6` (resolver"),
    (
        "connect-timeout",
        "unset no-op value faces echo the empty string",
    ),
    ("continue", "unset no-op value faces echo the empty string"),
    ("listen-port", "fork default `6881-6999`"),
    (
        "max-connection-per-server",
        "unset no-op value faces echo the empty string",
    ),
    (
        "max-download-result",
        "unset no-op value faces echo the empty string",
    ),
    (
        "max-file-not-found",
        "unset no-op value faces echo the empty string",
    ),
    (
        "max-mmap-limit",
        "unset no-op value faces echo the empty string",
    ),
    (
        "max-resume-failure-tries",
        "unset no-op value faces echo the empty string",
    ),
    ("max-tries", "unset no-op value faces echo the empty string"),
    (
        "min-split-size",
        "unset no-op value faces echo the empty string",
    ),
    ("peer-id-prefix", "fork `A2-1-37-0-`; taiji `-TJ0001-`"),
    (
        "remote-time",
        "unset no-op value faces echo the empty string",
    ),
    (
        "retry-wait",
        "unset no-op value faces echo the empty string",
    ),
    ("seed-ratio", "fork default literal `1.0`"),
    ("split", "unset no-op value faces echo the empty string"),
    ("timeout", "unset no-op value faces echo the empty string"),
    (
        "user-agent",
        "unset no-op value faces echo the empty string",
    ),
];

/// Whitelist anchor check (no reference dependency, always green): every
/// id's anchor substring must appear in the declaration doc. Extended with
/// the audit tables: every ruled taiji-only echo key and every
/// ruled shared-key value diff must keep their declaration anchors, and
/// both tables must stay sorted and duplicate free (the live comparisons
/// run member-for-member against them).
#[test]
fn whitelist_entries_are_anchored_in_the_declaration_doc() {
    for (id, anchor) in WHITELIST {
        assert!(
            DOC.contains(anchor),
            "whitelist entry {id}'s anchor {anchor:?} is not in docs/rpc-api-diff.md — the doc and the guard have drifted"
        );
    }
    let keys: Vec<&str> = TAIJI_ONLY_ECHO_AUDIT.iter().map(|(k, _)| *k).collect();
    assert!(
        keys.windows(2).all(|w| w[0] < w[1]),
        "the audit table must be sorted and duplicate-free: {keys:?}"
    );
    for (key, anchor) in TAIJI_ONLY_ECHO_AUDIT {
        assert!(
            DOC.contains(anchor),
            "audit key {key}'s declaration anchor {anchor:?} is not in docs/rpc-api-diff.md — the audit ruling and the doc have drifted"
        );
    }
    let vkeys: Vec<&str> = SHARED_VALUE_DIFF_AUDIT.iter().map(|(k, _)| *k).collect();
    assert!(
        vkeys.windows(2).all(|w| w[0] < w[1]),
        "the value-diff audit table must be sorted and duplicate-free: {vkeys:?}"
    );
    for (key, anchor) in SHARED_VALUE_DIFF_AUDIT {
        assert!(
            DOC.contains(anchor),
            "value-diff audit key {key}'s declaration anchor {anchor:?} is not in docs/rpc-api-diff.md — the audit ruling and the doc have drifted"
        );
    }
}

/// Reference-resolution anchor (no reference dependency, always green):
/// pins the header contract's red shapes after the probe fix — a
/// bare run with a fork checkout present is differential green, so the
/// "absent default red" semantics is anchored here on a manifest base
/// where no probe path exists:
/// (1) env unset + all probe layouts absent → None (the live test is then
/// red unless SKIP-downgraded — zero comparisons must never claim a
/// green differential);
/// (2) an explicit path that does not exist is absent as-is — no fallback
/// onto an existing probe candidate (an explicit absence must not be
/// silently overturned by probing; the SKIP-gate premise);
/// (3) a probe hit resolves;
/// (4) an explicit valid path wins over probing.
#[test]
fn reference_resolution_absent_and_explicit_shapes() {
    let base = std::env::temp_dir().join(format!("taiji-rpc-ref-anchor-{}", std::process::id()));
    let manifest = base.join("repo/crates/taiji-rpc");
    std::fs::create_dir_all(&manifest)
        .unwrap_or_else(|e| panic!("mkdir {}: {e}", manifest.display()));
    // (1) No checkout anywhere near this base: none of the probe layouts
    // exists under it (the `../..` chains land inside the private temp
    // root, which has no aria2/aria2_motrix sibling).
    assert_eq!(
        resolve_reference(None, &manifest),
        None,
        "all probe paths nonexistent -> no reference binary (the absent-default-red anchor)"
    );
    // (3) Probe hit: create a probe candidate relative to the manifest
    // (layout `../../../aria2/src/aria2c`; the fork layout entries probe
    // later in order and stay missable here — the ordered-probe contract).
    let fork = manifest.join("../../../aria2/src/aria2c");
    let fork_dir = fork.parent().unwrap_or_else(|| panic!("fork parent"));
    std::fs::create_dir_all(fork_dir)
        .unwrap_or_else(|e| panic!("mkdir {}: {e}", fork_dir.display()));
    std::fs::write(&fork, b"#!/bin/sh\n")
        .unwrap_or_else(|e| panic!("write {}: {e}", fork.display()));
    assert_eq!(resolve_reference(None, &manifest), Some(fork.clone()));
    // (2) Explicit invalid path: absent as-is even though a probe
    // candidate now exists.
    assert_eq!(
        resolve_reference(Some("/nonexistent/aria2c-explicit"), &manifest),
        None,
        "an explicit absence does not fall back to probing (the SKIP-gate premise)"
    );
    // (4) Explicit valid path wins over probing.
    let explicit = base.join("explicit-aria2c");
    std::fs::write(&explicit, b"#!/bin/sh\n")
        .unwrap_or_else(|e| panic!("write {}: {e}", explicit.display()));
    let explicit_str = explicit
        .to_str()
        .unwrap_or_else(|| panic!("utf8 path {}", explicit.display()));
    assert_eq!(
        resolve_reference(Some(explicit_str), &manifest),
        Some(explicit)
    );
    std::fs::remove_dir_all(&base).ok();
}

// ---- reference location and process management ----

/// Default probe layouts (`TAIJI_DIFF_ARIA2C` unset): workspace sibling
/// checkouts resolved from the crate manifest dir — the upstream layout
/// `aria2/src/aria2c` and the Motrix fork layout `aria2_motrix/src/aria2c`;
/// the two `../` depths cover a plain checkout (repo root one level above
/// the workspace) and a git-worktree sibling of the workspace itself. The
/// upstream layout is probed first (a built upstream checkout wins over the
/// fork), the fork layout after — the reference contract of this test is
/// either build, and the ordered probe keeps resolution deterministic when
/// both exist.
const DEFAULT_PROBE_LAYOUTS: &[&str] = &[
    "../../../../aria2/src/aria2c",
    "../../../aria2/src/aria2c",
    "../../../../aria2_motrix/src/aria2c",
    "../../../aria2_motrix/src/aria2c",
];

/// Resolution core (pure; unit-anchored in
/// `reference_resolution_absent_and_explicit_shapes`): an explicit value is
/// taken as-is — an invalid path means the reference is absent (no fallback
/// to default probing; an explicit absence must not be silently overturned
/// by probing — the premise of the SKIP gate); unset = probe the default
/// layouts from the manifest dir.
fn resolve_reference(explicit: Option<&str>, manifest: &Path) -> Option<PathBuf> {
    if let Some(p) = explicit {
        let pb = PathBuf::from(p);
        return pb.is_file().then_some(pb);
    }
    DEFAULT_PROBE_LAYOUTS
        .iter()
        .map(|rel| manifest.join(rel))
        .find(|p| p.is_file())
}

fn find_reference() -> Option<PathBuf> {
    resolve_reference(
        std::env::var("TAIJI_DIFF_ARIA2C").ok().as_deref(),
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")),
    )
}

fn note_skip(reason: &str) {
    eprintln!("SKIP(taiji.rpc.live-diff): {reason}");
}

/// Explicit downgrade switch (off by default): an absent reference is red by
/// default — zero comparisons must never claim a green differential; only
/// `TAIJI_DIFF_ALLOW_SKIP=1` downgrades to SKIP-green (marker surface in
/// [`note_skip`]; downgrade consumers must check the marker).
fn allow_skip() -> bool {
    std::env::var("TAIJI_DIFF_ALLOW_SKIP").as_deref() == Ok("1")
}

/// Fork child-process guard: killed on drop (no orphan processes on panic
/// paths).
struct ReferenceProc {
    child: Child,
    addr: SocketAddr,
}

impl Drop for ReferenceProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .and_then(|l| l.local_addr().map(|a| a.port()))
        .unwrap_or(0)
}

/// Spawns the fork (Motrix runtime shape: sqlite3 persistence — the
/// precondition for the saveSession zero-diff); readiness = TCP connectable
/// (listening implies bind complete; the fork has no second-phase init
/// gate).
fn spawn_reference(bin: &Path, dir: &Path) -> ReferenceProc {
    let log_path = dir.join("fork-rpc.log");
    for _ in 0..3 {
        let port = free_port();
        let Ok(log) = std::fs::File::create(&log_path) else {
            panic!("create fork log {}", log_path.display())
        };
        let Ok(err_log) = log.try_clone() else {
            panic!("clone fork log handle")
        };
        let spawned = Command::new(bin)
            .arg("--enable-rpc")
            .arg(format!("--rpc-listen-port={port}"))
            .arg(format!("--rpc-secret={SECRET}"))
            .arg("--enable-sqlite3-persistence")
            .arg(format!(
                "--sqlite3-db-path={}",
                dir.join("bt.sqlite3").display()
            ))
            .arg(format!("--dir={}", dir.display()))
            .stdout(log)
            .stderr(err_log)
            .spawn();
        let Ok(child) = spawned else { continue };
        let addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .unwrap_or_else(|_| panic!("reference addr parse 127.0.0.1:{port}"));
        let proc = ReferenceProc { child, addr };
        if ready(&proc.addr) {
            return proc;
        }
    }
    panic!("fork reference failed to become ready on any candidate port")
}

/// Blocking readiness poll (up to 10s; runs on the test main thread — no
/// tokio task dependency at this point).
fn ready(addr: &SocketAddr) -> bool {
    for _ in 0..100 {
        if std::net::TcpStream::connect(addr).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

// ---- JSON-RPC client (single-shot raw TCP; mirrors http_ws.rs, no new
// dependencies) ----

async fn raw_post(addr: SocketAddr, body: &str) -> (u16, Value) {
    let mut s = TcpStream::connect(addr)
        .await
        .unwrap_or_else(|e| panic!("connect {addr}: {e}"));
    let req = format!(
        "POST /jsonrpc HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    s.write_all(req.as_bytes())
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    let mut buf = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut buf)).await;
    match read {
        Ok(Ok(_)) => {}
        other => panic!("read_to_end {addr}: {other:?}"),
    }
    let text = String::from_utf8_lossy(&buf).to_string();
    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let payload = text
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or_default()
        .to_string();
    let parsed = serde_json::from_str::<Value>(&payload)
        .unwrap_or_else(|e| panic!("json parse {e}: {payload:?}"));
    (status, parsed)
}

async fn call(addr: SocketAddr, method: &str, params: &[Value]) -> (u16, Value) {
    let body = json!({"jsonrpc": "2.0", "id": "d", "method": method, "params": params});
    raw_post(addr, &body.to_string()).await
}

/// Reference-side method name (the fork only accepts the registered full
/// name `aria2.<bare>`; `system.*` literals are identical on both sides).
/// The taiji side uses the registered name (bare / `system.*` /
/// `taiji.*`) — the bare-name acceptance difference is itself a whitelist
/// entry (`bare-name-acceptance`) and is cross-validated in a dedicated
/// row.
fn reference_name(m: &str) -> String {
    if m.contains('.') {
        m.to_string()
    } else {
        format!("aria2.{m}")
    }
}

fn result_of(resp: &Value) -> &Value {
    resp.get("result").unwrap_or(&Value::Null)
}

fn err_msg(resp: &Value) -> String {
    resp.get("error")
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .unwrap_or_default()
        .to_string()
}

/// Exact-equality zero-diff assertion (only surfaces promised to be
/// zero-diff reach here; an observed difference is red).
fn zero_diff(label: &str, o: &Value, n: &Value) {
    assert_eq!(
        o, n,
        "{label}: a difference outside the whitelist (reference vs taiji)"
    );
}

/// The getGlobalStat extension keys (the four-pool model's
/// taiji-side capability extensions) have no reference-aria2
/// counterpart — a sanctioned user-visible observation-face change
/// declared in docs/rpc-api-diff.md §4 ("getGlobalStat caliber
/// migration"; the keys were live for one serialized window before
/// the declaration entry landed, now closed). Stripped from the
/// taiji side before the zero-diff comparison; the helper stays the
/// sanctioned stripping face (never a drift-absorption — the keys are
/// ruled in-card, not converged drift).
fn strip_global_stat_extension_keys(v: &Value) -> Value {
    let mut envelope = match v {
        Value::Object(map) => map.clone(),
        other => return other.clone(),
    };
    if let Some(Value::Object(map)) = envelope.get_mut("result") {
        for k in ["numSeeding", "numChecking", "numSynthesizing"] {
            map.remove(k);
        }
    }
    Value::Object(envelope)
}

/// Declared-difference assertion: the difference must actually exist (a
/// converged pair means the entry is stale and should be reclaimed via
/// governance) and must hit a whitelist entry id. The direction of the
/// difference (e.g. error code prefix) is asserted nearby at the call site.
fn declared(label: &str, id: &str, o: &Value, n: &Value) {
    assert_ne!(
        o, n,
        "{label}: whitelist entry {id} no longer shows an actual difference — please reclaim the entry (governance)"
    );
    assert!(
        WHITELIST.iter().any(|(wid, _)| *wid == id),
        "{label}: whitelist entry {id} not registered"
    );
}

/// GID normalization inside strings (fork GID -> taiji GID) — surfaces whose
/// error messages carry each side's own GID are asserted against one
/// identical message.
fn subst(v: &Value, from: &str, to: &str) -> Value {
    match v {
        Value::String(s) => Value::String(s.replace(from, to)),
        Value::Array(a) => Value::Array(a.iter().map(|x| subst(x, from, to)).collect()),
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, x)| (k.clone(), subst(x, from, to)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn set_diff(a: &[Value], b: &[Value]) -> Vec<String> {
    let mut out: Vec<String> = a
        .iter()
        .filter(|x| !b.contains(*x))
        .filter_map(|x| x.as_str().map(str::to_string))
        .collect();
    out.sort();
    out
}

// ---- taiji side (in-process compat server) ----

struct TaijiProc {
    _handle: ServerHandle,
    addr: SocketAddr,
    token: CancellationToken,
}

async fn spawn_taiji(dir: &Path) -> TaijiProc {
    // Motrix runtime shape alignment: the fork half starts with
    // `--enable-sqlite3-persistence`, so the taiji half also mounts sqlite
    // persistence (the zero-diff precondition for saveSession's
    // full-persist semantics — taiji without persistence errors out
    // explicitly, which is outside the cross-validation scope).
    let (persist, _writer) =
        taiji_core::session::persist::import::open_session_writer(dir.join("taiji.sqlite3"))
            .await
            .unwrap_or_else(|e| panic!("open taiji session db: {e}"));
    let (session, _join) = SessionActor::spawn_with_persist(
        taiji_core::session::SessionOptions {
            global: taiji_core::session::GlobalOptions {
                dir: dir.to_path_buf(),
                ..Default::default()
            },
        },
        Some(persist),
    );
    let cfg = RpcConfig {
        port: 0,
        secret: Some(SECRET.to_string()),
        aria2_compat: true,
        ..Default::default()
    };
    let token = CancellationToken::new();
    let handle = serve(cfg, Arc::new(session), token.clone())
        .await
        .unwrap_or_else(|e| panic!("taiji serve: {e}"));
    let addr = handle.local_addr;
    TaijiProc {
        _handle: handle,
        addr,
        token,
    }
}

#[tokio::test]
async fn live_differential_outside_whitelist_is_zero_diff() {
    let Some(reference_bin) = find_reference() else {
        let reason = "fork reference binary not found (set TAIJI_DIFF_ARIA2C)";
        note_skip(reason);
        assert!(
            allow_skip(),
            "SKIP(taiji.rpc.live-diff): {reason} — an absent reference defaults red (a zero-comparison \
             run must never claim a fully green differential); explicitly set TAIJI_DIFF_ALLOW_SKIP=1 \
             to downgrade SKIP to green"
        );
        return;
    };
    let root = std::env::temp_dir().join(format!("taiji-rpc-live-diff-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap_or_else(|e| panic!("mkdir {}: {e}", root.display()));
    let reference = spawn_reference(&reference_bin, &root);
    let taiji = spawn_taiji(&root).await;
    let (oa, na) = (reference.addr, taiji.addr);
    let tok = || json!(TOKEN);

    // ---- 1. Introspection / transport protocol surface (zero diff) ----
    let (_, lo) = call(oa, "system.listMethods", &[]).await;
    let (_, ln) = call(na, "system.listMethods", &[]).await;
    let so = result_of(&lo)
        .as_array()
        .unwrap_or_else(|| panic!("reference listMethods array"))
        .clone();
    let sn = result_of(&ln)
        .as_array()
        .unwrap_or_else(|| panic!("taiji listMethods array"))
        .clone();
    // Set equation: taiji − reference = the `taiji.*` extension surface
    // (including the canonical forms of
    // addUriWithCookies/setTaskCookies); reference − taiji = the 6 missing
    // method names (whitelist `method-face-missing` family: after
    // changePosition/getOption/forcePauseAll joined the committed set, the
    // remaining fork-only additions are the sqlite3 family (4 names) plus
    // the cookie family (2 names); the latter are accepted as canonical
    // `taiji.*` while compat mode does not project `aria2.*` aliases, so
    // the fork's same-name literals stay in the difference set). All other
    // members are verbatim-identical.
    let mut expect_extra: Vec<String> = RPC_METHODS
        .iter()
        .filter(|m| m.contains('.') && !m.starts_with("system."))
        .map(|m| m.to_string())
        .collect();
    // Bare-name capability extension `forceRecheck` (registered on neither
    // upstream nor the fork — a capability addition declared in rpc-api-diff
    // §1 "RPC method surface additions") is projected as
    // `aria2.forceRecheck` on the compat surface (the bare-name prefix
    // projection of `method_face_names`; that projection function is
    // crate-private, so this test appends the literal and reconciles it
    // with the declaration entry).
    expect_extra.push("aria2.forceRecheck".to_string());
    expect_extra.sort();
    assert_eq!(
        set_diff(&sn, &so),
        expect_extra,
        "the compat-face taiji.* extension set drifted"
    );
    // Fork releases added checkpoint import and retained HTTP retry APIs.
    // These names are intentionally absent: taiji owns its native persistence
    // and import paths. Compare every name present in the selected reference;
    // an undeclared future fork method still fails this exact-set assertion.
    let known_fork_only = [
        "aria2.addLegacyTorrentV1",
        "aria2.addUriWithCookies",
        "aria2.exportSession",
        "aria2.getCheckpointStatus",
        "aria2.getDownloadResultCount",
        "aria2.getHttpRetryStatusV1",
        "aria2.importLegacyCheckpointV1",
        "aria2.inspectLegacyCheckpointV1",
        "aria2.reconcileLegacyCheckpointV1",
        "aria2.requeueDownloadResult",
        "aria2.retryHttpDownloadV1",
        "aria2.searchDownloadResult",
        "aria2.setTaskCookies",
    ];
    let expected_missing: Vec<String> = known_fork_only
        .iter()
        .filter(|name| so.iter().any(|value| value == **name))
        .map(|name| (*name).to_string())
        .collect();
    assert_eq!(
        set_diff(&so, &sn),
        expected_missing,
        "the missing-method set drifted outside the declared fork-only families"
    );
    let (_, no) = call(oa, "system.listNotifications", &[]).await;
    let (_, nn) = call(na, "system.listNotifications", &[]).await;
    declared("listNotifications", "http-output-ready-event", &no, &nn);
    let compat_notifications: Vec<_> = result_of(&nn)
        .as_array()
        .unwrap_or_else(|| panic!("notification list missing"))
        .iter()
        .filter(|name| **name != json!("taiji.onHttpOutputReady"))
        .cloned()
        .collect();
    zero_diff(
        "listNotifications compatibility events",
        result_of(&no),
        &json!(compat_notifications),
    );
    assert_eq!(
        result_of(&nn).as_array().map(Vec::len),
        Some(compat_notifications.len() + 1)
    );

    // Non-committed methods (registered on the fork; taiji answers with the
    // unknown-method surface — token auth runs first, same as the fork).
    // changePosition/getOption/forcePauseAll have joined the committed set
    // (covered by the no-arg / parameter matrix zero-diff rows) and moved
    // out of this row. The remaining 4 fork-only names (fork checkout
    // RpcMethodFactory.cc, HAVE_SQLITE3 family: sqlite3 download-record
    // surface extensions, absent upstream and not in taiji's committed set
    // — same whitelist entry method-face-missing). Fork-side shape (pinned
    // live): getDownloadResultCount with empty params returns
    // `{"count":"0"}`, the others error on missing params; the taiji side
    // always answers "No such method".
    for m in [
        "aria2.exportSession",
        "aria2.getDownloadResultCount",
        "aria2.requeueDownloadResult",
        "aria2.searchDownloadResult",
    ] {
        let (_, ro) = call(oa, m, &[tok()]).await;
        let (_, rn) = call(na, m, &[tok()]).await;
        assert_eq!(err_msg(&rn), format!("No such method: {m}"));
        declared(m, "method-face-missing", &ro, &rn);
    }
    // 2 fork-only cookie names (`addUriWithCookies`/`setTaskCookies`, the
    // fork-specific task-level cookie RPC surface; absent upstream).
    // Accepted with Motrix as the baseline but committed under canonical
    // `taiji.*` names (compat mode does not project `aria2.*` aliases), so
    // same-name fork calls always land on "No such method" (the taiji.*
    // acceptance behavior is covered by taiji-side tests; each name has its
    // own whitelist entry anchored in docs/rpc-api-diff.md). Fork side
    // errors on missing params; taiji side always answers "No such method".
    for (m, id) in [
        (
            "aria2.addUriWithCookies",
            "method-face-missing-adduri-with-cookies",
        ),
        (
            "aria2.setTaskCookies",
            "method-face-missing-set-task-cookies",
        ),
    ] {
        let (_, ro) = call(oa, m, &[tok()]).await;
        let (_, rn) = call(na, m, &[tok()]).await;
        assert_eq!(err_msg(&rn), format!("No such method: {m}"));
        declared(m, id, &ro, &rn);
    }
    // `taiji.*` extension (the fork has no such surface — the dual
    // direction of the missing-method set).
    {
        let (_, ro) = call(oa, "taiji.moveStorage", &[tok(), json!("g"), json!("d")]).await;
        let (_, rn) = call(na, "taiji.moveStorage", &[tok(), json!("g"), json!("d")]).await;
        assert_eq!(err_msg(&ro), "No such method: taiji.moveStorage");
        declared("taiji.moveStorage", "taiji-extension-methods", &ro, &rn);
    }
    // Bare-name acceptance (whitelist bare-name-acceptance): taiji's
    // canonical committed surface always accepts bare names (kept in compat
    // mode — a superset); the fork only accepts registered full names, so a
    // bare name hits the unknown-method surface. Later matrix/task
    // reference-side calls are normalized to fork full names via
    // reference_name; this row pins the difference itself.
    {
        let (_, ro) = call(oa, "addUri", &[tok()]).await;
        let (_, rn) = call(na, "addUri", &[tok()]).await;
        assert_eq!(err_msg(&ro), "No such method: addUri");
        declared("bare-name face", "bare-name-acceptance", &ro, &rn);
    }

    // Unknown method / auth (zero diff, including HTTP status mapping).
    for (label, method, params) in [
        ("unknown-method", "nosuchmethod", vec![tok()]),
        ("wrong-token", "getVersion", vec![json!("token:wrong")]),
    ] {
        let (st_o, ro) = call(oa, method, &params.clone()).await;
        let (st_n, rn) = call(na, method, &params).await;
        assert_eq!(st_o, st_n, "{label}: HTTP status");
        zero_diff(label, &ro, &rn);
    }
    // Transport surface: malformed JSON / missing id / non-array params
    // (-32700/-32600/-32602 and HTTP status mapping, live zero diff).
    for (label, raw) in [
        ("parse error", "{oops".to_string()),
        (
            "missing id",
            json!({"jsonrpc": "2.0", "method": "getVersion", "params": []}).to_string(),
        ),
        (
            "named params",
            json!({"jsonrpc": "2.0", "id": "d", "method": "getVersion", "params": {"a": 1}})
                .to_string(),
        ),
    ] {
        let (st_o, po) = raw_post(oa, &raw).await;
        let (st_n, pn) = raw_post(na, &raw).await;
        assert_eq!(st_o, st_n, "{label}: HTTP status");
        zero_diff(label, &po, &pn);
    }
    // multicall recursion ban (message verbatim-identical live).
    let spec = json!([[{"methodName": "system.multicall", "params": [[]]}]]);
    let (_, ro) = call(oa, "system.multicall", std::slice::from_ref(&spec)).await;
    let (_, rn) = call(na, "system.multicall", &[spec]).await;
    zero_diff("multicall recursive", &ro, &rn);

    // ---- 2. Full parameter matrix (committed methods x {missing arg /
    // wrong type / unknown GID / invalid GID}) ----
    for m in RPC_METHODS {
        if MATRIX_EXCLUDED.contains(m) || m.starts_with("taiji.") {
            continue; // taiji.* has no fork counterpart (whitelist taiji-extension-methods).
        }
        let has_args = !NO_ARG_METHODS.contains(m);
        if has_args && *m != "addMetalink" {
            let (_, ro) = call(oa, &reference_name(m), &[tok()]).await;
            let (_, rn) = call(na, m, &[tok()]).await;
            zero_diff(m, &ro, &rn);
        }
        if has_args {
            let (_, ro) = call(oa, &reference_name(m), &[tok(), json!(12345)]).await;
            let (_, rn) = call(na, m, &[tok(), json!(12345)]).await;
            zero_diff(m, &ro, &rn);
        }
        if GID_METHODS.contains(m) {
            for gid in ["beef000000000000", "xyz"] {
                let (_, ro) = call(oa, &reference_name(m), &[tok(), json!(gid)]).await;
                let (_, rn) = call(na, m, &[tok(), json!(gid)]).await;
                zero_diff(m, &ro, &rn);
            }
        }
    }
    // No-arg methods: the empty-arg success surface is zero-diff (value
    // differences asserted separately). The listMethods member-set
    // difference is already pinned by the set equation at the top of this
    // function (taiji.* extensions + the 6 missing names); table order is
    // not part of the commitment — a whole-response equality comparison
    // does not apply, so it is skipped.
    for m in NO_ARG_METHODS {
        if matches!(
            *m,
            "getVersion"
                | "getGlobalOption"
                | "getSessionInfo"
                | "system.listMethods"
                | "system.listNotifications"
        ) {
            continue;
        }
        let (_, ro) = call(oa, &reference_name(m), &[tok()]).await;
        let (_, rn) = call(na, m, &[tok()]).await;
        if *m == "getGlobalStat" {
            // The four-pool extension keys (see
            // strip_global_stat_extension_keys): live but undeclared
            // until the declaration entry landed.
            zero_diff(m, &ro, &strip_global_stat_extension_keys(&rn));
        } else {
            zero_diff(m, &ro, &rn);
        }
    }

    // ---- 3. getVersion / getSessionInfo / getGlobalOption (value-diff
    // surfaces) ----
    let (_, ro) = call(oa, &reference_name("getVersion"), &[tok()]).await;
    let (_, rn) = call(na, "getVersion", &[tok()]).await;
    let shape = |v: &Value| {
        json!({
            "version": v.get("version").is_some(),
            // The feature list itself is not promised equal (declaration
            // doc §2: only that entries are real) — the shape surface only
            // pins "key present + value is an array".
            "enabledFeatures": v.get("enabledFeatures").map(|f| f.is_array()),
        })
    };
    zero_diff(
        "getVersion shape",
        &shape(result_of(&ro)),
        &shape(result_of(&rn)),
    );
    assert!(
        result_of(&ro)["version"]
            .as_str()
            .unwrap_or("")
            .starts_with("1.37")
    );
    assert!(
        result_of(&rn)["version"]
            .as_str()
            .unwrap_or("")
            .starts_with("taiji/")
    );
    declared("getVersion values", "get-version-face", &ro, &rn);
    let (_, ro) = call(oa, &reference_name("getSessionInfo"), &[tok()]).await;
    let (_, rn) = call(na, "getSessionInfo", &[tok()]).await;
    zero_diff(
        "getSessionInfo shape",
        &json!({"keys": result_of(&ro).as_object().map(|d| d.len())}),
        &json!({"keys": result_of(&rn).as_object().map(|d| d.len())}),
    );

    let (_, ro) = call(oa, &reference_name("getGlobalOption"), &[tok()]).await;
    let (_, rn) = call(na, "getGlobalOption", &[tok()]).await;
    let oo = result_of(&ro)
        .as_object()
        .unwrap_or_else(|| panic!("reference echo dict"))
        .clone();
    let on = result_of(&rn)
        .as_object()
        .unwrap_or_else(|| panic!("taiji echo dict"))
        .clone();
    let reference_only: Vec<String> = oo
        .keys()
        .filter(|k| !on.contains_key(*k))
        .cloned()
        .collect();
    let taiji_only: Vec<String> = on
        .keys()
        .filter(|k| !oo.contains_key(*k))
        .cloned()
        .collect();
    assert!(
        !reference_only.is_empty(),
        "the fork's echo table is empty — the reference run shape is abnormal"
    );
    // Reference builds differ in enabled features (notably c-ares). A key
    // already echoed by that build is shared, not a taiji-only extension.
    // Every declared native key must still exist; unknown additions fail.
    for (key, _) in TAIJI_ONLY_ECHO_AUDIT {
        assert!(
            on.contains_key(*key),
            "declared native echo key missing: {key}"
        );
    }
    let mut audited: Vec<&str> = TAIJI_ONLY_ECHO_AUDIT
        .iter()
        .map(|(key, _)| *key)
        .filter(|key| !oo.contains_key(*key))
        .collect();
    audited.sort_unstable();
    assert_eq!(
        taiji_only, audited,
        "taiji-only echo keys drifted outside the declared audit"
    );
    // Only the audited keys may differ in value among shared keys (three
    // Phase A declarations + the Motrix-alignment no-op value faces —
    // SHARED_VALUE_DIFF_AUDIT); dir must be exactly equal under
    // the same-input cross-validation.
    for (k, vo) in &oo {
        let Some(vn) = on.get(k) else { continue };
        if vo == vn {
            continue;
        }
        assert!(
            SHARED_VALUE_DIFF_AUDIT.iter().any(|(dk, _)| dk == k),
            "getGlobalOption[{k}] has an undeclared value difference: {vo} vs {vn}"
        );
    }
    assert_eq!(
        oo.get("dir").and_then(|v| v.as_str()),
        on.get("dir").and_then(|v| v.as_str()),
        "the same-input cross-validation dir must be exactly equal"
    );
    declared("getGlobalOption echo set", "global-echo-subset", &ro, &rn);
    declared(
        "getGlobalOption values",
        "global-echo-shared-values",
        &ro,
        &rn,
    );
    // changeGlobalOption: unknown keys are ignored on both sides (zero
    // diff); bt-tracker is imported and echoed by taiji but silently
    // ignored by the fork (whitelist global-echo-taiji-only).
    let (_, ro) = call(
        oa,
        &reference_name("changeGlobalOption"),
        &[tok(), json!({"totally-unknown-key": "1"})],
    )
    .await;
    let (_, rn) = call(
        na,
        "changeGlobalOption",
        &[tok(), json!({"totally-unknown-key": "1"})],
    )
    .await;
    zero_diff("changeGlobalOption unknown key", &ro, &rn);
    let (_, ro) = call(
        oa,
        &reference_name("changeGlobalOption"),
        &[tok(), json!({"bt-tracker": "ws://t/announce"})],
    )
    .await;
    let (_, rn) = call(
        na,
        "changeGlobalOption",
        &[tok(), json!({"bt-tracker": "ws://t/announce"})],
    )
    .await;
    zero_diff("changeGlobalOption bt-tracker", &ro, &rn);
    let (_, rn2) = call(na, "getGlobalOption", &[tok()]).await;
    assert_eq!(
        result_of(&rn2)["bt-tracker"].as_str().unwrap_or(""),
        "ws://t/announce",
        "taiji imports and echoes bt-tracker globally"
    );
    declared(
        "getGlobalOption taiji-only keys",
        "global-echo-taiji-only",
        &ro,
        &rn2,
    );
    // Invalid value: the fork errors, taiji ignores (whitelist
    // option-invalid-value).
    let (_, ro) = call(
        oa,
        &reference_name("changeGlobalOption"),
        &[tok(), json!({"max-overall-download-limit": "notanumber"})],
    )
    .await;
    let (_, rn) = call(
        na,
        "changeGlobalOption",
        &[tok(), json!({"max-overall-download-limit": "notanumber"})],
    )
    .await;
    declared(
        "changeGlobalOption invalid value",
        "option-invalid-value",
        &ro,
        &rn,
    );

    // ---- 4. Task surface (both sides driven through the same sequence:
    // paused ftp + paused magnet) ----
    let ftp_uri = "ftp://127.0.0.1:1/f.bin";
    let magnet = "magnet:?xt=urn:btih:0000000000000000000000000000000000000001";
    let (_, ro) = call(
        oa,
        &reference_name("addUri"),
        &[tok(), json!([ftp_uri]), json!({"pause": "true"})],
    )
    .await;
    let (_, rn) = call(
        na,
        "addUri",
        &[tok(), json!([ftp_uri]), json!({"pause": "true"})],
    )
    .await;
    let gid_o = result_of(&ro)
        .as_str()
        .unwrap_or_else(|| panic!("reference gid"))
        .to_string();
    let gid_n = result_of(&rn)
        .as_str()
        .unwrap_or_else(|| panic!("taiji gid"))
        .to_string();
    assert_eq!(gid_o.len(), 16, "reference gid hex16");
    assert_eq!(gid_n.len(), 16, "taiji gid hex16");
    zero_diff("addUri paused shape", &subst(&ro, &gid_o, &gid_n), &rn);
    let (_, ro) = call(
        oa,
        &reference_name("addUri"),
        &[tok(), json!([magnet]), json!({"pause": "true"})],
    )
    .await;
    let (_, rn) = call(
        na,
        "addUri",
        &[tok(), json!([magnet]), json!({"pause": "true"})],
    )
    .await;
    let bt_o = result_of(&ro)
        .as_str()
        .unwrap_or_else(|| panic!("reference bt gid"))
        .to_string();
    let bt_n = result_of(&rn)
        .as_str()
        .unwrap_or_else(|| panic!("taiji bt gid"))
        .to_string();
    let (_, ro) = call(oa, &reference_name("getGlobalStat"), &[tok()]).await;
    let (_, rn) = call(na, "getGlobalStat", &[tok()]).await;
    zero_diff(
        "getGlobalStat counts",
        &ro,
        &strip_global_stat_extension_keys(&rn),
    );
    let (_, ro) = call(oa, &reference_name("tellActive"), &[tok()]).await;
    let (_, rn) = call(na, "tellActive", &[tok()]).await;
    zero_diff("tellActive", &ro, &rn);

    // ftp task query surface: getUris/getPeers/getServers are zero-diff
    // (GID-normalized); getFiles/tellStatus differences fall to the
    // whitelist (pre-probe projection / http subdict / BT superset keys).
    let (_, ro) = call(oa, &reference_name("getUris"), &[tok(), json!(gid_o)]).await;
    let (_, rn) = call(na, "getUris", &[tok(), json!(gid_n)]).await;
    zero_diff("getUris", &subst(&ro, &gid_o, &gid_n), &rn);
    let (_, ro) = call(oa, &reference_name("getPeers"), &[tok(), json!(gid_o)]).await;
    let (_, rn) = call(na, "getPeers", &[tok(), json!(gid_n)]).await;
    zero_diff("getPeers", &ro, &rn);
    let (_, ro) = call(oa, &reference_name("getServers"), &[tok(), json!(gid_o)]).await;
    let (_, rn) = call(na, "getServers", &[tok(), json!(gid_n)]).await;
    zero_diff("getServers paused", &subst(&ro, &gid_o, &gid_n), &rn);
    let (_, ro) = call(oa, &reference_name("getFiles"), &[tok(), json!(gid_o)]).await;
    let (_, rn) = call(na, "getFiles", &[tok(), json!(gid_n)]).await;
    declared("getFiles pre-probe", "pre-probe-projection", &ro, &rn);
    let (_, ro) = call(oa, &reference_name("tellStatus"), &[tok(), json!(gid_o)]).await;
    let (_, rn) = call(na, "tellStatus", &[tok(), json!(gid_n)]).await;
    assert!(
        result_of(&rn).get("http").is_some() && result_of(&ro).get("http").is_none(),
        "the http sub-dictionary is a taiji extension"
    );
    declared("tellStatus pre-probe", "pre-probe-projection", &ro, &rn);
    declared("tellStatus http subdict", "status-http-subdict", &ro, &rn);
    declared("tellStatus bt superset", "status-bt-superset", &ro, &rn);
    // keys filter is zero-diff (GID-normalized).
    let keys = json!(["gid", "status"]);
    let (_, ro) = call(
        oa,
        &reference_name("tellStatus"),
        &[tok(), json!(gid_o), keys.clone()],
    )
    .await;
    let (_, rn) = call(na, "tellStatus", &[tok(), json!(gid_n), keys.clone()]).await;
    zero_diff("tellStatus keys", &subst(&ro, &gid_o, &gid_n), &rn);
    // Magnet task: BT-face shape difference (declared direction); the keys
    // filter is zero-diff.
    let (_, ro) = call(oa, &reference_name("tellStatus"), &[tok(), json!(bt_o)]).await;
    let (_, rn) = call(na, "tellStatus", &[tok(), json!(bt_n)]).await;
    declared("tellStatus bt face", "status-bt-superset", &ro, &rn);
    let (_, ro) = call(
        oa,
        &reference_name("tellStatus"),
        &[tok(), json!(bt_o), keys.clone()],
    )
    .await;
    let (_, rn) = call(na, "tellStatus", &[tok(), json!(bt_n), keys]).await;
    zero_diff("tellStatus bt keys", &subst(&ro, &bt_o, &bt_n), &rn);
    // changeOption: unknown keys are zero-diff; out-of-domain scheduler
    // values are explicitly rejected by taiji (whitelist
    // option-domain-reject: the fork accepts, taiji rejects without
    // truncating).
    let (_, ro) = call(
        oa,
        &reference_name("changeOption"),
        &[tok(), json!(gid_o), json!({"totally-unknown-key": "1"})],
    )
    .await;
    let (_, rn) = call(
        na,
        "changeOption",
        &[tok(), json!(gid_n), json!({"totally-unknown-key": "1"})],
    )
    .await;
    zero_diff("changeOption unknown key", &ro, &rn);
    let (_, ro) = call(
        oa,
        &reference_name("changeOption"),
        &[
            tok(),
            json!(gid_o),
            json!({"max-connection-per-server": "99"}),
        ],
    )
    .await;
    let (_, rn) = call(
        na,
        "changeOption",
        &[
            tok(),
            json!(gid_n),
            json!({"max-connection-per-server": "99"}),
        ],
    )
    .await;
    assert!(err_msg(&rn).starts_with("taiji.option.invalid"));
    declared(
        "changeOption domain reject",
        "option-domain-reject",
        &ro,
        &rn,
    );
    // Task removal chain: remove echoes the gid; removeDownloadResult /
    // purgeDownloadResult answer OK.
    let (_, ro) = call(oa, &reference_name("remove"), &[tok(), json!(gid_o)]).await;
    let (_, rn) = call(na, "remove", &[tok(), json!(gid_n)]).await;
    zero_diff("remove echoes gid", &subst(&ro, &gid_o, &gid_n), &rn);
    let (_, ro) = call(
        oa,
        &reference_name("removeDownloadResult"),
        &[tok(), json!(gid_o)],
    )
    .await;
    let (_, rn) = call(na, "removeDownloadResult", &[tok(), json!(gid_n)]).await;
    // Result cleanup right after remove: both sides land on the same
    // "GID X is not found" message (verbatim zero diff; each carries its
    // own GID -> normalized comparison).
    zero_diff("removeDownloadResult", &subst(&ro, &gid_o, &gid_n), &rn);
    let (_, ro) = call(oa, &reference_name("purgeDownloadResult"), &[tok()]).await;
    let (_, rn) = call(na, "purgeDownloadResult", &[tok()]).await;
    zero_diff("purgeDownloadResult", &ro, &rn);
    let (_, ro) = call(oa, &reference_name("getGlobalStat"), &[tok()]).await;
    let (_, rn) = call(na, "getGlobalStat", &[tok()]).await;
    zero_diff(
        "getGlobalStat after removal",
        &ro,
        &strip_global_stat_extension_keys(&rn),
    );

    // ---- 4b. changePosition behavior surface (zero diff) ----
    // Both sides driven through the same sequence: each adds 3 paused ftp
    // tasks (at this point both waiting queues are isomorphic =
    // [magnet, q0, q1, q2]); the three modes x {head / middle / tail /
    // out-of-range clamping} are compared case by case on the returned
    // target position; the waiting-queue error message and the illegal-how
    // message are verbatim zero-diff; the final tellWaiting order is
    // normalized to add-order rank and compared zero-diff.
    let mut q_gids_o = Vec::new();
    let mut q_gids_n = Vec::new();
    for k in 0..3 {
        let (_, ro) = call(
            oa,
            &reference_name("addUri"),
            &[
                tok(),
                json!([format!("ftp://127.0.0.1:1/q{k}.bin")]),
                json!({"pause": "true"}),
            ],
        )
        .await;
        q_gids_o.push(
            result_of(&ro)
                .as_str()
                .unwrap_or_else(|| panic!("reference q{k} gid"))
                .to_string(),
        );
        let (_, rn) = call(
            na,
            "addUri",
            &[
                tok(),
                json!([format!("ftp://127.0.0.1:1/q{k}.bin")]),
                json!({"pause": "true"}),
            ],
        )
        .await;
        q_gids_n.push(
            result_of(&rn)
                .as_str()
                .unwrap_or_else(|| panic!("taiji q{k} gid"))
                .to_string(),
        );
    }
    // Drive sequence: (q slot, pos, how). Same params and order on both
    // sides, so returned target positions must match case by case
    // (absolute positions are comparable — both queue configurations are
    // bit-identical).
    let seq: [(usize, i64, &str); 8] = [
        (0, 0, "POS_SET"),  // q0 -> head
        (2, 9, "POS_SET"),  // q2 past end -> clamped to tail
        (2, -7, "POS_SET"), // q2 past start -> clamped to head
        (1, 1, "POS_CUR"),  // q1 (tail) +1 -> clamped in place
        (1, -2, "POS_CUR"), // q1 relative move forward
        (0, 0, "POS_END"),  // q0 tail-anchored 0 -> in place
        (2, -9, "POS_END"), // q2 past start -> clamped to head
        (2, 9, "POS_END"),  // q2 past end -> clamped to tail
    ];
    for (k, (slot, pos, how)) in seq.iter().enumerate() {
        let (_, ro) = call(
            oa,
            &reference_name("changePosition"),
            &[tok(), json!(&q_gids_o[*slot]), json!(pos), json!(how)],
        )
        .await;
        let (_, rn) = call(
            na,
            "changePosition",
            &[tok(), json!(&q_gids_n[*slot]), json!(pos), json!(how)],
        )
        .await;
        zero_diff(
            &format!("changePosition seq[{k}] ({pos},{how})"),
            result_of(&ro),
            result_of(&rn),
        );
        // Shape guard: both receipts must be real execution surfaces (a
        // bare integer target position) — guards against a fake zero diff
        // where both sides return the same error message.
        assert!(
            result_of(&ro).is_u64() && result_of(&rn).is_u64(),
            "seq[{k}]: the receipt must be an integer target position, o={} n={}",
            result_of(&ro),
            result_of(&rn)
        );
    }
    // Final order agreement: the tellWaiting sequence is normalized to
    // add-order rank (magnet = 0, q0..q2 = 1..3) and compared zero-diff.
    let ordering = |waiting: &Value, q_gids: &[String]| -> Vec<usize> {
        waiting
            .as_array()
            .unwrap_or_else(|| panic!("tellWaiting array"))
            .iter()
            .filter_map(|v| v["gid"].as_str())
            .map(|g| {
                q_gids
                    .iter()
                    .position(|x| x == g)
                    .map(|p| p + 1)
                    .unwrap_or(0) // magnet = 0 (first in add order)
            })
            .collect()
    };
    let (_, ro) = call(
        oa,
        &reference_name("tellWaiting"),
        &[tok(), json!(0), json!(100)],
    )
    .await;
    let (_, rn) = call(na, "tellWaiting", &[tok(), json!(0), json!(100)]).await;
    zero_diff(
        "changePosition final order",
        &json!(ordering(result_of(&ro), &q_gids_o)),
        &json!(ordering(result_of(&rn), &q_gids_n)),
    );
    // Waiting-queue error message verbatim zero-diff: the gid of a
    // non-waiting entry (active or result entry; scope note:
    // RequestGroupMan.cc only searches reservedGroups_) lands on
    // "GID#X not found in the waiting queue." on both sides, each carrying
    // its own GID -> normalized comparison. The active face is the ftp
    // task added without pause (after connection refusal it becomes a
    // result entry; both sides' GroupId lifetime is likewise covered — the
    // message does not drift with timing).
    let (_, ro) = call(
        oa,
        &reference_name("addUri"),
        &[tok(), json!(["ftp://127.0.0.1:1/w.bin"])],
    )
    .await;
    let (_, rn) = call(na, "addUri", &[tok(), json!(["ftp://127.0.0.1:1/w.bin"])]).await;
    let w_o = result_of(&ro)
        .as_str()
        .unwrap_or_else(|| panic!("reference w gid"))
        .to_string();
    let w_n = result_of(&rn)
        .as_str()
        .unwrap_or_else(|| panic!("taiji w gid"))
        .to_string();
    let (_, ro) = call(
        oa,
        &reference_name("changePosition"),
        &[tok(), json!(w_o), json!(0), json!("POS_SET")],
    )
    .await;
    let (_, rn) = call(
        na,
        "changePosition",
        &[tok(), json!(w_n), json!(0), json!("POS_SET")],
    )
    .await;
    zero_diff(
        "changePosition not-in-waiting",
        &subst(&ro, &w_o, &w_n),
        &rn,
    );
    // Illegal how -> "Illegal argument." verbatim zero-diff
    // (RpcMethodImpl.cc).
    let (_, ro) = call(
        oa,
        &reference_name("changePosition"),
        &[tok(), json!(&q_gids_o[0]), json!(0), json!("POS_UP")],
    )
    .await;
    let (_, rn) = call(
        na,
        "changePosition",
        &[tok(), json!(&q_gids_n[0]), json!(0), json!("POS_UP")],
    )
    .await;
    zero_diff("changePosition illegal how", result_of(&ro), result_of(&rn));

    // ---- 5. Protocol acceptance difference surfaces (whitelist) ----
    // sftp deferred: the fork creates the task, taiji rejects explicitly.
    let (_, ro) = call(
        oa,
        &reference_name("addUri"),
        &[
            tok(),
            json!(["sftp://127.0.0.1/f.bin"]),
            json!({"pause": "true"}),
        ],
    )
    .await;
    let (_, rn) = call(
        na,
        "addUri",
        &[
            tok(),
            json!(["sftp://127.0.0.1/f.bin"]),
            json!({"pause": "true"}),
        ],
    )
    .await;
    assert!(err_msg(&rn).starts_with("taiji.sftp.deferred"));
    declared("sftp addUri", "sftp-deferred", &ro, &rn);
    // Unknown scheme: message difference (whitelist unknown-scheme).
    let (_, ro) = call(
        oa,
        &reference_name("addUri"),
        &[tok(), json!(["xyz://host/f"]), json!({"pause": "true"})],
    )
    .await;
    let (_, rn) = call(
        na,
        "addUri",
        &[tok(), json!(["xyz://host/f"]), json!({"pause": "true"})],
    )
    .await;
    declared("unknown scheme", "unknown-scheme", &ro, &rn);
    // addTorrent invalid base64 (whitelist add-torrent-base64).
    let (_, ro) = call(oa, "addTorrent", &[tok(), json!("not-base64!!")]).await;
    let (_, rn) = call(na, "addTorrent", &[tok(), json!("not-base64!!")]).await;
    declared("addTorrent bad base64", "add-torrent-base64", &ro, &rn);

    // ---- 6. addMetalink surface (feature on; method absent when off) ----
    #[cfg(feature = "metalink")]
    {
        let v4 = b"<?xml version=\"1.0\"?><metalink xmlns=\"urn:ietf:params:xml:ns:metalink\">\
                  <file name=\"d.bin\"><size>4</size>\
                  <url type=\"http\" location=\"us\">http://127.0.0.1:1/d.bin</url></file></metalink>";
        let b64 = base64_encode(v4);
        // Happy path: both sides return a plain GID array (values assigned
        // independently — shape zero diff).
        let (_, ro) = call(
            oa,
            "aria2.addMetalink",
            &[tok(), json!(b64), json!({"pause": "true"})],
        )
        .await;
        let (_, rn) = call(
            na,
            "aria2.addMetalink",
            &[tok(), json!(b64), json!({"pause": "true"})],
        )
        .await;
        let shape = |v: &Value| {
            v.as_array()
                .map(|a| {
                    a.iter()
                        .all(|g| g.as_str().map(|s| s.len() == 16).unwrap_or(false))
                })
                .unwrap_or(false)
        };
        assert!(
            shape(result_of(&ro)) && shape(result_of(&rn)),
            "the addMetalink GID array shape"
        );
        // Version / boundary differences (whitelist metalink-version /
        // metalink-boundary).
        let v3 = b"<?xml version=\"1.0\"?><metalink version=\"3.0\" xmlns=\"http://www.metalinker.org/\">\
                  <files><file name=\"v3.bin\"><size>1</size>\
                  <url>http://127.0.0.1:1/v3.bin</url></file></files></metalink>";
        let (_, ro) = call(oa, "aria2.addMetalink", &[tok(), json!(base64_encode(v3))]).await;
        let (_, rn) = call(na, "aria2.addMetalink", &[tok(), json!(base64_encode(v3))]).await;
        assert!(err_msg(&rn).starts_with("taiji.metalink.unsupported_version"));
        declared("metalink v3", "metalink-version", &ro, &rn);
        let (_, ro) = call(
            oa,
            "aria2.addMetalink",
            &[tok(), json!(base64_encode(b"<foo/>"))],
        )
        .await;
        let (_, rn) = call(
            na,
            "aria2.addMetalink",
            &[tok(), json!(base64_encode(b"<foo/>"))],
        )
        .await;
        declared("metalink wrong root", "metalink-boundary", &ro, &rn);
        let (_, ro) = call(
            oa,
            "aria2.addMetalink",
            &[tok(), json!(base64_encode(b"\x00garbage"))],
        )
        .await;
        let (_, rn) = call(
            na,
            "aria2.addMetalink",
            &[tok(), json!(base64_encode(b"\x00garbage"))],
        )
        .await;
        declared("metalink not xml", "metalink-boundary", &ro, &rn);
    }

    // ---- 7. Shutdown surface (zero diff; runs last) ----
    let (_, ro) = call(oa, &reference_name("shutdown"), &[tok()]).await;
    let (_, rn) = call(na, "shutdown", &[tok()]).await;
    zero_diff("shutdown", &ro, &rn);
    assert!(
        taiji.token.is_cancelled(),
        "shutdown propagates through the stop token"
    );

    std::fs::remove_dir_all(&root).ok();
}

/// Standard base64 (the fork's parameter-surface encoding; self-contained in
/// the test, no new dependencies).
/// Invariant: the only consumer is the addMetalink surface below (inside
/// the metalink gate), so it compiles with the gate — excluded from the
/// build when the feature is off, avoiding a dead-code warning.
#[cfg(feature = "metalink")]
fn base64_encode(data: &[u8]) -> String {
    const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(TBL[(n >> 18) as usize & 63] as char);
        out.push(TBL[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TBL[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TBL[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Slow fixture origin (the download window for the projection invariant):
/// standard 206/200 dual-arm semantics (Range: bytes=a-b -> 206 +
/// Content-Range; bare GET -> 200 full body — the (0,0) probe and the grid
/// fetches share this source), body written in 32KiB chunks with 20ms
/// pauses (a 1MiB body takes ~0.7s per connection, enough to sample).
async fn spawn_slow_origin(body: std::sync::Arc<Vec<u8>>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let body = Arc::clone(&body);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                // Read until the request head delimiter (single-request,
                // short-lived connection).
                let mut head = Vec::new();
                loop {
                    let n = match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    head.extend_from_slice(&buf[..n]);
                    if head.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let text = String::from_utf8_lossy(&head);
                let range = text
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("range:"))
                    .and_then(|l| l.split(':').nth(1))
                    .and_then(|spec| {
                        let spec = spec.trim().strip_prefix("bytes=")?.trim();
                        let (a, b) = spec.split_once('-')?;
                        Some((a.trim().parse::<u64>().ok()?, b.trim().parse::<u64>().ok()?))
                    });
                let total = body.len() as u64;
                let (start, end, status_line, extra) = match range {
                    Some((a, b)) => {
                        let end = b.min(total - 1);
                        (
                            a,
                            end,
                            "HTTP/1.1 206 Partial Content\r\n",
                            format!("Content-Range: bytes {a}-{end}/{total}\r\n"),
                        )
                    }
                    None => (0, total - 1, "HTTP/1.1 200 OK\r\n", String::new()),
                };
                let slice = &body[start as usize..=(end) as usize];
                let head = format!(
                    "{status_line}{}Content-Length: {}\r\nConnection: close\r\n\r\n",
                    extra,
                    slice.len()
                );
                sock.write_all(head.as_bytes()).await.ok();
                // Slow body: written in 32KiB chunks with 20ms pauses
                // (keeps the download window sampleable).
                for chunk in slice.chunks(32 * 1024) {
                    sock.write_all(chunk).await.ok();
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                let _ = sock.shutdown().await;
            });
        }
    });
    addr
}

/// Projection invariant (self-proven on the local compat `aria2.*` surface —
/// does not depend on the reference being present; an extension row of the
/// live cross-validation main test): while live, `tellStatus`
/// `completedLength` is a byte-level realtime count — monotonic across
/// samples, always <= totalLength, and may run ahead of block accounting
/// (bytes of a not-yet-full block are visible; the
/// `http.blocksDone/blocksTotal` subdict keeps block units — projection is
/// not accounting). The final value converges to the accounting final value
/// (the stopped surface is the block-accounting authority). This is the
/// live pin for the declaration entry "progress accounting basis"
/// (docs/rpc-api-diff.md §4).
#[tokio::test]
async fn live_completed_length_projects_byte_level_and_converges_to_accounting() {
    let dir = std::env::temp_dir().join(format!("taiji-rpc-p63-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir {}: {e}", dir.display()));
    // 1MiB = 4 blocks @256KiB (the task-level `http-block-size` tightens
    // the block size, widening the observable window where the byte-level
    // count runs ahead of block accounting); 32KiB/20ms slow speed gives
    // ~0.7s.
    let body: std::sync::Arc<Vec<u8>> =
        std::sync::Arc::new((0..1024 * 1024u32).map(|i| (i % 251) as u8).collect());
    let origin = spawn_slow_origin(Arc::clone(&body)).await;
    let taiji = spawn_taiji(&dir).await;
    let url = format!("http://{origin}/f.bin");
    let (_, resp) = call(
        taiji.addr,
        "aria2.addUri",
        &[
            json!(TOKEN),
            json!([url]),
            json!({"dir": dir.display().to_string(), "http-block-size": "256K"}),
        ],
    )
    .await;
    let gid = result_of(&resp)
        .as_str()
        .unwrap_or_else(|| panic!("taiji gid"))
        .to_string();
    const BLOCK: u64 = 256 * 1024;
    let keys = json!(["gid", "status", "completedLength", "totalLength", "http"]);
    let num = |v: &Value, k: &str| -> u64 {
        v.get(k)
            .and_then(|x| x.as_str())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or_else(|| panic!("{k} missing its numeric face: {v}"))
    };
    // Sample while downloading (download window capped at 30s):
    // `(completed, blocksDone, total)`.
    let mut samples: Vec<(u64, u64, u64)> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the download window timed out; samples={samples:?}"
        );
        let (_, resp) = call(
            taiji.addr,
            "aria2.tellStatus",
            &[json!(TOKEN), json!(gid), keys.clone()],
        )
        .await;
        let entry = result_of(&resp);
        match entry.get("status").and_then(|s| s.as_str()) {
            Some("active") => {
                let blocks = entry
                    .get("http")
                    .and_then(|h| h.get("blocksDone"))
                    .and_then(|x| x.as_str())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                samples.push((
                    num(entry, "completedLength"),
                    blocks,
                    num(entry, "totalLength"),
                ));
            }
            Some(_) => break, // terminal state (complete/error) — sampling ends.
            None => panic!("tellStatus has no status key: {entry}"),
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // (1) Byte level: at least one sample must show the projection ahead of
    // block accounting (bytes of a not-yet-full block are visible; under
    // block units completed would always equal blocksDone x block length,
    // which would turn this check red).
    assert!(
        samples.iter().any(|&(c, b, _)| c > b * BLOCK),
        "completedLength must advance at byte level (it may run ahead of block accounting); samples={samples:?}"
    );
    // (2) Monotonic and <= totalLength.
    let mut prev = 0u64;
    for &(c, _, t) in &samples {
        assert!(
            c >= prev,
            "completedLength must be monotonic: {prev} -> {c}"
        );
        assert!(c <= t, "completedLength <= totalLength: {c} > {t}");
        prev = c;
    }
    assert!(
        samples.len() >= 4,
        "the sampling face must cover the download window (>=4 beats); samples={samples:?}"
    );
    // (3) Final value = accounting final value: the stopped surface is at
    // full amount (completed = total = body length) and the block surface
    // is at full amount (the accounting authority closes unaffected by the
    // byte projection).
    let (_, resp) = call(
        taiji.addr,
        "aria2.tellStatus",
        &[json!(TOKEN), json!(gid), keys],
    )
    .await;
    let entry = result_of(&resp);
    assert_eq!(
        entry.get("status").and_then(|s| s.as_str()),
        Some("complete"),
        "the fixture task must close out fully: {entry}"
    );
    assert_eq!(num(entry, "totalLength"), body.len() as u64);
    assert_eq!(num(entry, "completedLength"), body.len() as u64);
    let blocks_total = entry
        .get("http")
        .and_then(|h| h.get("blocksTotal"))
        .and_then(|x| x.as_str())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    assert_eq!(blocks_total, 4, "1MiB @ 256KiB = a 4-block grid");
    let http_dict = entry.get("http").unwrap_or(&Value::Null);
    assert_eq!(num(http_dict, "blocksDone"), 4);

    taiji.token.cancel();
    std::fs::remove_dir_all(&dir).ok();
}
