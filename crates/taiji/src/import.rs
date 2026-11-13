//! `taiji import` — the migration importer subcommand.
//!
//! One command, two source faces, both parsed strictly read-only: the
//! legacy aria2-fork sqlite database (BitTorrent + HTTP/FTP faces
//! collected in one read-only pass) and `.aria2` control files (BT face
//! imported directly, HTTP face reconciled against fork rows as
//! orphans). Plans land in the target `taiji.sqlite3` via the
//! PersistWriter face, followed by a stdout report and the list of
//! aria2 GIDs to deregister; `--purge-via-aria2` optionally runs
//! `aria2.remove` + `aria2.purgeDownloadResult` after user
//! confirmation. The engine never writes fork storage itself.
//!
//! Hard invariants: the pre-import backup (`.v1.bak`) precedes any
//! open/migration of the target database; a dry-run is a read-only
//! snapshot that never advances an existing database's migration
//! ledger; same-path and fork-shaped targets are refused.
//!
//! Upstream anchor mapping: docs/design/cli.md

use std::path::{Path, PathBuf};

use clap::{Args, ValueEnum};
use serde_json::json;

use taiji_core::gid::GidAllocator;
use taiji_core::session::persist::import::{
    self, AssembleInput, CtrlEntry, ImportSource, PlannedImport, SourceTask, TaskReport,
    TaskReportKind, resolve_metadata,
};
use taiji_core::session::persist::import_http::{
    self, Aria2Reconciliation, ForkClosedProof, HttpCollectEntry, HttpImportPlanner, HttpPlanEntry,
    HttpPlanInput, PathConflictAction,
};

/// Per-call budget for one aria2 JSON-RPC call: deregistration runs
/// outside the batch, so a hung fork must not stall the process.
const PURGE_RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Report-line assembly (a buffered `println!`).
macro_rules! emit {
    ($dst:expr, $($arg:tt)*) => {{
        use std::fmt::Write as _;
        let _ = writeln!($dst, $($arg)*);
    }};
}

/// Decision for a (dir,out) path conflict on a second import (default:
/// skip and surface it in the report — never silently overwrite;
/// `rename` = import under a name from the aria2 candidate-name
/// algorithm).
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathConflictArg {
    /// Skip the conflicting task (surfaced in the report; the user
    /// resolves it manually afterwards).
    Skip,
    /// Rename via the aria2 candidate-name algorithm
    /// (`file.tar.gz` → `file.tar.1.gz`).
    Rename,
}

impl From<PathConflictArg> for PathConflictAction {
    fn from(v: PathConflictArg) -> Self {
        match v {
            PathConflictArg::Skip => PathConflictAction::Skip,
            PathConflictArg::Rename => PathConflictAction::Rename,
        }
    }
}

/// `taiji import` arguments (the CLI input surface + the aria2-compatible
/// `sqlite3-db-path`/`import-from-aria2-db` option-name family).
#[derive(Args, Debug)]
pub struct ImportArgs {
    /// Path of the legacy aria2-fork sqlite database (opened read-only;
    /// never written under any circumstance).
    #[arg(long)]
    from_aria2_db: Option<PathBuf>,
    /// Directory scanned for `.aria2` control files (recursive
    /// `<dir>/**/<file>.aria2`).
    #[arg(long)]
    from_aria2_dir: Option<PathBuf>,
    /// Target taiji.sqlite3 (aria2-compatible name `--sqlite3-db-path`).
    #[arg(long, default_value = "taiji.sqlite3")]
    sqlite3_db_path: PathBuf,
    /// Fallback download directory when a fork task's serialized form has
    /// no ` dir=` line (aria2-compatible name).
    #[arg(long, default_value = ".")]
    dir: PathBuf,
    /// Report only, write nothing (idempotent: already-imported tasks are
    /// intercepted via imported_from and surfaced). An existing target
    /// database is only probed/queried over a read-only connection —
    /// zero write side effects: the migration ledger does not advance, no
    /// pre-import backup is made, the target database is not created
    /// (equally safe on an older-ledger database; a real import migrates
    /// only after the automatic backup).
    #[arg(long)]
    dry_run: bool,
    /// Preserve the existing Motrix task identity during an engine replacement.
    #[arg(long)]
    preserve_gids: bool,
    /// Explicit responsibility flag (preflight layer 3): when the fork
    /// live-fd scan cannot prove the old version is closed (platform
    /// unsupported, lsof missing, other "cannot prove" states), the
    /// import is refused by default; passing this flag lets it through
    /// with the user accepting responsibility that the fork is closed.
    /// It does not waive preflight layers 1-2 — a held sqlite lock and a
    /// live hit (reported with the pid) are direct facts that the fork is
    /// still running and have no bypass.
    #[arg(long)]
    i_know_fork_is_closed: bool,
    /// Decision for a (dir,out) conflict on a second import (default skip
    /// = surface in the report, never silently overwrite; rename = the
    /// aria2 candidate-name algorithm).
    #[arg(long, value_enum, default_value_t = PathConflictArg::Skip)]
    on_path_conflict: PathConflictArg,
    /// After the import, deregister the original tasks through this aria2
    /// JSON-RPC endpoint (`http://token:SECRET@host:port/jsonrpc`; runs
    /// `aria2.remove` + `aria2.purgeDownloadResult` after user
    /// confirmation).
    #[arg(long)]
    purge_via_aria2: Option<String>,
    /// Skip the interactive confirmation of --purge-via-aria2 (scripts).
    #[arg(long)]
    yes: bool,
}

/// A task entry during planning/application (intermediate face for report
/// assembly; the Ready box mirrors CtrlEntry — suppresses
/// large_enum_variant).
enum Entry {
    Ready(Box<SourceTask>),
    /// Entry that failed directly during the directory scan (a corrupt
    /// .aria2 file etc.).
    Failed {
        source: ImportSource,
        reason: String,
    },
    Skipped {
        source: ImportSource,
        reason: String,
    },
}

/// Subcommand entry point. Exit codes: 0 = no failures; 2 = some tasks
/// failed (the batch still ran to completion); 1 = infrastructure error
/// (bad arguments, unreadable source db, preflight refusal, unreachable
/// deregistration endpoint).
pub async fn run(args: ImportArgs) -> i32 {
    if args.from_aria2_db.is_none() && args.from_aria2_dir.is_none() {
        eprintln!("error: nothing to import (give --from-aria2-db and/or --from-aria2-dir)");
        return 1;
    }

    let _target_lock = if args.dry_run {
        None
    } else {
        match crate::http::acquire_db_lock(&args.sqlite3_db_path).await {
            Ok(guard) => Some(guard),
            Err(code) => return code,
        }
    };

    // ---- 0) Same-path guard: if `--sqlite3-db-path` and `--from-aria2-db`
    // canonicalize to the same file, the source database would be
    // rewritten as the target (the backup would copy the fork db to
    // `.v1.bak` and then "migrate" in place, polluting fork storage) —
    // refused before any IO; canonicalize normalizes spelling variants
    // (`/./` segments, mixed relative/absolute forms). ----
    if let Some(fork_db) = args.from_aria2_db.clone() {
        let target = args.sqlite3_db_path.clone();
        // canonicalize's OS calls go through the winpath conversion
        // (identity borrow off Windows); the clash message reports the
        // original fork path (the user-visible surface carries no prefix).
        let clash = tokio::task::spawn_blocking(move || {
            let fork_for_report = fork_db.clone();
            match (
                std::fs::canonicalize(taiji_io::winpath::to_fs_path(&fork_db)),
                std::fs::canonicalize(taiji_io::winpath::to_fs_path(&target)),
            ) {
                (Ok(a), Ok(b)) if a == b => Some(fork_for_report),
                _ => None,
            }
        })
        .await
        .unwrap_or(None);
        if let Some(p) = clash {
            eprintln!(
                "error: --sqlite3-db-path and --from-aria2-db resolve to the same \
                 database file ({}): the import would read the fork database and \
                 rewrite it as the taiji target — give distinct paths",
                p.display()
            );
            return 1;
        }
    }

    // ---- 0.5) Three preflight layers: (1) a held sqlite lock -> refuse
    // and advise exiting the old version; (2) a live-fd scan of the fork
    // (a WAL-normal fork holds no lock most of the time, so layer (1)
    // misses an "alive but idle" old version) -> refuse on a hit and
    // report the pid; (3) cannot prove (platform unsupported, lsof
    // missing) -> refuse by default, with --i-know-fork-is-closed as the
    // explicit responsibility bypass. The flag never waives layers (1)/(2).
    // Refusal = exit 1 (preflight face). ----
    if let Some(db) = args.from_aria2_db.clone() {
        match import_http::preflight_fork_liveness(db, args.i_know_fork_is_closed).await {
            Ok((_total, proof)) => {
                if let ForkClosedProof::AcknowledgedUncertain(reason) = proof {
                    eprintln!(
                        "warning: cannot prove the fork is closed ({reason}); \
                         proceeding because --i-know-fork-is-closed was given \
                         — you accept responsibility for the fork being closed"
                    );
                }
            }
            Err(e) => {
                eprintln!("error: {e}");
                return 1;
            }
        }
    }

    // ---- 1) Source collection: one command, two faces (the fork DB is
    // opened read-only once, and the BT and HTTP faces account for
    // complementary tasks; the lock probe is forced first — preflight
    // item 1, ForkLocked maps to "exit the old version" guidance) ----
    let mut bt_entries: Vec<Entry> = Vec::new();
    let mut http_entries: Vec<HttpCollectEntry> = Vec::new();
    let mut fork_task_total: Option<i64> = None;
    if let Some(db) = args.from_aria2_db.clone() {
        match import_http::collect_fork_all_tasks(db.clone(), args.dir.clone()).await {
            Ok(fc) => {
                fork_task_total = Some(fc.total_tasks);
                bt_entries.extend(fc.bt.into_iter().map(|t| Entry::Ready(Box::new(t))));
                http_entries = fc.http;
            }
            Err(e) => {
                eprintln!("error: cannot read fork db {}: {e}", db.display());
                return 1;
            }
        }
    }
    let http_state = match args.from_aria2_db.clone() {
        Some(path) => match import_http::read_fork_http_state(path).await {
            Ok(state) => state,
            Err(error) => {
                eprintln!("error: cannot read legacy HTTP state: {error}");
                return 1;
            }
        },
        None => import_http::ForkHttpState::default(),
    };
    let mut recon = None;
    if let Some(dir) = args.from_aria2_dir.clone() {
        match import::collect_ctrl_tasks(dir.clone()).await {
            Ok(list) => {
                // ctrl tasks carry no queue-order notion — they take scan
                // order after the fork tasks.
                let base = bt_entries.len() as i64;
                for (i, e) in list.into_iter().enumerate() {
                    bt_entries.push(match e {
                        // CtrlEntry::Ready is already a Box — moved into
                        // Entry without re-boxing.
                        CtrlEntry::Ready(mut t) => {
                            t.queue_pos = base + i as i64;
                            Entry::Ready(t)
                        }
                        CtrlEntry::Skipped { path, reason } => Entry::Skipped {
                            source: ImportSource::Aria2Ctrl { ctrl_path: path },
                            reason,
                        },
                        CtrlEntry::Failed { path, reason } => Entry::Failed {
                            source: ImportSource::Aria2Ctrl { ctrl_path: path },
                            reason,
                        },
                    });
                }
            }
            Err(e) => {
                eprintln!("error: cannot scan .aria2 dir: {e}");
                return 1;
            }
        }
        // HTTP-face orphan reconciliation: the reconciliation key is
        // totalLength + output path. A hit merges the entry (filling in
        // the bitmap payload for rows without progress lines); no match
        // marks a standalone orphan (read-only discipline — file and data
        // are kept as-is; the real import emits no row for it).
        match import_http::reconcile_aria2_orphans(dir, http_entries).await {
            Ok((entries, report)) => {
                http_entries = entries;
                recon = Some(report);
            }
            Err(e) => {
                eprintln!("error: cannot reconcile .aria2 dir: {e}");
                return 1;
            }
        }
    }

    // ---- 1.5) Target shape/ledger probe (read-only; runs before the
    // backup — if the fork db were mistaken for the target, the backup's
    // checkpoint and the subsequent open+migration would both write fork
    // storage, the red line of read-only discipline; the mirror-image
    // guard of the fork-side open_fork_readonly table-set probe) ----
    let target_exists = args.sqlite3_db_path.exists();
    if target_exists {
        match import_http::probe_import_target(args.sqlite3_db_path.clone()).await {
            Ok(p) if p.fork_shaped => {
                eprintln!(
                    "error: --sqlite3-db-path {} is a legacy aria2-fork database \
                     (task/task_progress schema): the import target must be the \
                     taiji database — refusing (fork storage is never written)",
                    args.sqlite3_db_path.display()
                );
                return 1;
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!(
                    "error: cannot inspect target db {}: {e}",
                    args.sqlite3_db_path.display()
                );
                return 1;
            }
        }
    }

    // ---- 2) Automatic pre-import backup (preflight item 4; must precede
    // any open/migration of the target — `.v1.bak` preserves the bytes
    // that 0.1.x could still open before the migration ledger advances).
    // Dry-run skips it (zero write side effects). A live target, or one
    // left uncleanly shut down (-wal/-shm still on disk), is explicitly
    // refused here — preflight item 3 ----
    let backup_line = if args.dry_run {
        None
    } else {
        match import_http::backup_target_for_import(args.sqlite3_db_path.clone()).await {
            Ok(b) => Some(match b.path() {
                Some(p) => format!("pre-import backup: {} ({})", p.display(), b.description()),
                None => "pre-import backup: none needed (no existing target db)".to_string(),
            }),
            Err(e) => {
                eprintln!("error: pre-import backup refused (is the target offline?): {e}");
                return 1;
            }
        }
    };

    // ---- 3) Target database: the writer opens only on the real-import
    // face; a dry-run takes a read-only snapshot and never opens an
    // existing database through PersistWriter — opening it advances the
    // migration ledger (v2→v3), and a "dry-run first, real import second"
    // flow once poisoned the `.v1.bak` rollback anchor into an
    // already-migrated snapshot. The join handle is kept until the exit
    // drain — if process exit killed an unfinished writer thread, sqlite
    // would have no clean close and the leftover sidecar files would jam
    // the next import's pre-import backup ----
    let (writer, writer_join) = if !args.dry_run {
        match import::open_import_writer(args.sqlite3_db_path.clone()).await {
            Ok((w, join)) => (Some(w), Some(join)),
            Err(e) => {
                eprintln!(
                    "error: cannot open target db {}: {e}",
                    args.sqlite3_db_path.display()
                );
                return 1;
            }
        }
    } else {
        (None, None)
    };
    // Dry-run dedup/occupancy query face: the read-only snapshot fetches
    // everything in one pass (the probe already passed the shape guard).
    // A snapshot read failure (e.g. session_kv missing) means dedup
    // cross-validation is unavailable — the whole dry run is refused
    // explicitly, not degraded to "nothing imported yet".
    let occupied_gids = if args.preserve_gids && target_exists {
        let target = args.sqlite3_db_path.clone();
        match tokio::task::spawn_blocking(
            move || -> Result<std::collections::HashSet<String>, rusqlite::Error> {
                let db = rusqlite::Connection::open_with_flags(
                    target,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
                )?;
                let mut ids = std::collections::HashSet::new();
                for table in ["torrent", "http_task", "media_task"] {
                    let exists: bool = db.query_row(
                        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                        [table],
                        |row| row.get(0),
                    )?;
                    if !exists {
                        continue;
                    }
                    let mut query = db.prepare(&format!("SELECT gid FROM {table}"))?;
                    for id in query.query_map([], |row| row.get::<_, String>(0))? {
                        ids.insert(id?);
                    }
                }
                Ok(ids)
            },
        )
        .await
        {
            Ok(Ok(ids)) => ids,
            _ => {
                eprintln!("error: cannot inspect target identities safely");
                return 1;
            }
        }
    } else {
        std::collections::HashSet::new()
    };

    let target_snapshot = if args.dry_run && target_exists {
        let mut keys: Vec<String> = bt_entries
            .iter()
            .filter_map(|e| match e {
                Entry::Ready(t) => Some(t.source_key.clone()),
                _ => None,
            })
            .collect();
        keys.extend(http_entries.iter().filter_map(|e| match e {
            HttpCollectEntry::Ready(t) => Some(t.source_key.clone()),
            _ => None,
        }));
        match import_http::read_target_snapshot_for_dry_run(args.sqlite3_db_path.clone(), keys)
            .await
        {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!(
                    "error: cannot read target db {} (dedup/path-conflict state): {e}",
                    args.sqlite3_db_path.display()
                );
                return 1;
            }
        }
    } else {
        None
    };

    // ---- 4) Per-task planning: dedup -> metadata cross-validation (BT) /
    // assembly (HTTP) ----
    let mut gid_alloc = GidAllocator::new();
    let mut planned_bt: Vec<PlannedImport> = Vec::new();
    let mut planned_http: Vec<taiji_core::session::persist::import_http::PlannedHttpImport> =
        Vec::new();
    let mut reports: Vec<TaskReport> = Vec::new();
    for entry in &bt_entries {
        let task = match entry {
            Entry::Ready(t) => t,
            Entry::Skipped { source, reason } => {
                reports.push(TaskReport {
                    source: source.display(),
                    fork_gid: None,
                    info_hash_hex: None,
                    metadata_path: None,
                    new_gid: None,
                    state: None,
                    degraded: false,
                    degrade_reason: None,
                    note: Some(reason.clone()),
                    kind: TaskReportKind::Skipped,
                });
                continue;
            }
            Entry::Failed { source, reason } => {
                reports.push(TaskReport {
                    source: source.display(),
                    fork_gid: None,
                    info_hash_hex: None,
                    metadata_path: None,
                    new_gid: None,
                    state: None,
                    degraded: false,
                    degrade_reason: None,
                    note: Some(reason.clone()),
                    kind: TaskReportKind::Failed,
                });
                continue;
            }
        };
        let ih_hex = import::hex_lower(&task.progress.info_hash);
        // Dedup (session_kv.imported_from): surfaced in dry-run
        // too. A read failure is never silently treated as "not imported"
        // — with unknown dedup state a re-import would overwrite live
        // task rows with import-time state; on the real-import face the
        // task is Failed (a dry-run snapshot read failure already
        // rejected the whole run above, so None here is the snapshot key
        // face).
        let imported = match &writer {
            Some(w) => match w.get_kv(&task.source_key).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(target: "taiji::cli", %e, "dedup kv read failed");
                    reports.push(failed_report(
                        task,
                        Some(ih_hex),
                        format!(
                            "dedup kv read failed: {e} — already-imported state \
                             unknown; refusing to plan (a re-import would overwrite \
                             live rows)"
                        ),
                    ));
                    continue;
                }
            },
            None => target_snapshot
                .as_ref()
                .and_then(|s| s.imported.get(&task.source_key))
                .cloned()
                .flatten(),
        };
        if let Some(prev_gid) = imported {
            reports.push(TaskReport {
                source: task.source.display(),
                fork_gid: task.fork_gid.clone(),
                info_hash_hex: Some(ih_hex),
                metadata_path: None,
                new_gid: Some(prev_gid),
                state: None,
                degraded: false,
                degrade_reason: None,
                note: Some("already imported (session_kv.imported_from)".to_string()),
                kind: TaskReportKind::Skipped,
            });
            continue;
        }
        // Metadata candidate resolution (IO + metainfo parsing → run in
        // spawn_blocking).
        let candidates = task.candidates.clone();
        let want = task.progress.info_hash;
        let resolved = tokio::task::spawn_blocking(move || resolve_metadata(&candidates, &want))
            .await
            .map_err(|e| format!("metadata resolve join: {e}"))
            .and_then(|r| r);
        let meta = match resolved {
            Ok(m) => m,
            Err(reason) => {
                reports.push(failed_report(task, Some(ih_hex), reason));
                continue;
            }
        };
        let gid_hex = if args.preserve_gids {
            task.fork_gid
                .clone()
                .unwrap_or_else(|| gid_alloc.allocate().to_string())
        } else {
            gid_alloc.allocate().to_string()
        };
        if args.preserve_gids
            && (occupied_gids.contains(&gid_hex) || !valid_preserved_gid(&gid_hex))
        {
            eprintln!("error: preserved task identity conflicts with the target session");
            return 1;
        }
        let input = AssembleInput {
            source: task.source.clone(),
            source_key: task.source_key.clone(),
            gid_hex,
            meta,
            progress: task.progress.clone(),
            dir: task.dir.clone(),
            paused: task.paused,
            options: task.options.clone(),
            queue_pos: task.queue_pos,
        };
        match import::assemble(input) {
            Ok(p) => {
                reports.push(TaskReport {
                    source: task.source.display(),
                    fork_gid: p.fork_gid.clone(),
                    info_hash_hex: Some(ih_hex),
                    metadata_path: Some(p.metadata_path.clone()),
                    new_gid: Some(p.gid.clone()),
                    state: Some(p.state.clone()),
                    degraded: p.degraded,
                    degrade_reason: p.degrade_reason.clone(),
                    note: None,
                    kind: TaskReportKind::Planned,
                });
                planned_bt.push(p);
            }
            Err(reason) => {
                reports.push(failed_report(task, Some(ih_hex), reason));
            }
        }
    }

    // HTTP-face planning (the path-conflict decision face for second
    // imports = the target db's in-flight (dir,out) occupancy set +
    // earlier tasks of this batch). Dry-run uses the read-only snapshot;
    // on the real-import face a read failure keeps the degraded
    // presentation (warn + empty set — the worst outcome of a wrong
    // path-conflict decision is a "skip", not an overwrite, a different
    // severity class than the dedup kv overwrite risk).
    let occupied: Vec<(String, String)> = match &writer {
        Some(w) => w
            .load_http_tasks_at_startup()
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(target: "taiji::cli", %e, "existing http rows read failed (path-conflict adjudication degraded)");
                Vec::new()
            })
            .into_iter()
            .map(|s| (s.row.dir.clone(), s.row.out.clone()))
            .collect(),
        None => target_snapshot
            .as_ref()
            .map(|s| s.occupied_http.clone())
            .unwrap_or_default(),
    };
    let mut planner = HttpImportPlanner::new(occupied);
    for entry in &http_entries {
        match entry {
            HttpCollectEntry::Ready(t) => {
                // Dedup read failure, same as the BT face: the task is
                // Failed on the real-import face, never silently degraded
                // to "not imported" (live-row overwrite risk; a dry-run
                // None is the snapshot key face).
                let mut imported = match &writer {
                    Some(w) => match w.get_kv(&t.source_key).await {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!(target: "taiji::cli", %e, "dedup kv read failed");
                            reports.push(TaskReport {
                                source: t.source.display(),
                                fork_gid: t.fork_gid.clone(),
                                info_hash_hex: None,
                                metadata_path: None,
                                new_gid: None,
                                state: None,
                                degraded: false,
                                degrade_reason: None,
                                note: Some(format!(
                                    "dedup kv read failed: {e} — already-imported \
                                     state unknown; refusing to plan (a re-import \
                                     would overwrite live rows)"
                                )),
                                kind: TaskReportKind::Failed,
                            });
                            continue;
                        }
                    },
                    None => target_snapshot
                        .as_ref()
                        .and_then(|s| s.imported.get(&t.source_key))
                        .cloned()
                        .flatten(),
                };
                let gid_hex = if args.preserve_gids {
                    t.fork_gid
                        .clone()
                        .unwrap_or_else(|| gid_alloc.allocate().to_string())
                } else {
                    gid_alloc.allocate().to_string()
                };
                if args.preserve_gids && imported.is_none() {
                    if let Some(writer) = &writer {
                        match writer.load_http_task(&gid_hex).await {
                            Ok(Some(snapshot)) => {
                                let config: serde_json::Value =
                                    serde_json::from_str(&snapshot.row.config_json)
                                        .unwrap_or_default();
                                if config.get("origin_fork_key").and_then(|v| v.as_str())
                                    == Some(t.source_key.as_str())
                                {
                                    if let Err(error) = import_http::restore_imported_http_state(
                                        writer,
                                        &snapshot.row,
                                        t.fork_gid.as_deref().unwrap_or(""),
                                        &http_state,
                                    )
                                    .await
                                    {
                                        eprintln!(
                                            "error: interrupted HTTP adoption cannot resume: {error}"
                                        );
                                        return 1;
                                    }
                                    if writer.put_kv(&t.source_key, &gid_hex).await.is_err() {
                                        return 1;
                                    }
                                    imported = Some(gid_hex.clone());
                                }
                            }
                            Ok(None) => {}
                            Err(error) => {
                                eprintln!("error: target identity lookup failed: {error}");
                                return 1;
                            }
                        }
                    }
                }
                if args.preserve_gids
                    && imported.is_none()
                    && (occupied_gids.contains(&gid_hex) || !valid_preserved_gid(&gid_hex))
                {
                    eprintln!("error: preserved task identity conflicts with the target session");
                    return 1;
                }
                match planner.plan(HttpPlanInput {
                    task: t,
                    gid_hex,
                    imported_gid: imported,
                    conflict_action: args.on_path_conflict.into(),
                }) {
                    HttpPlanEntry::Planned(p) => {
                        reports.push(TaskReport {
                            source: p.source.display(),
                            fork_gid: p.fork_gid.clone(),
                            info_hash_hex: None,
                            metadata_path: None,
                            new_gid: Some(p.gid.clone()),
                            state: Some(p.state.clone()),
                            degraded: false,
                            degrade_reason: None,
                            note: if p.warnings.is_empty() {
                                None
                            } else {
                                Some(p.warnings.join("; "))
                            },
                            kind: TaskReportKind::Planned,
                        });
                        planned_http.push(*p);
                    }
                    HttpPlanEntry::Skipped { source, reason } => {
                        reports.push(TaskReport {
                            source: source.display(),
                            fork_gid: None,
                            info_hash_hex: None,
                            metadata_path: None,
                            new_gid: None,
                            state: None,
                            degraded: false,
                            degrade_reason: None,
                            note: Some(reason),
                            kind: TaskReportKind::Skipped,
                        });
                    }
                    HttpPlanEntry::Failed { source, reason } => {
                        reports.push(TaskReport {
                            source: source.display(),
                            fork_gid: None,
                            info_hash_hex: None,
                            metadata_path: None,
                            new_gid: None,
                            state: None,
                            degraded: false,
                            degrade_reason: None,
                            note: Some(reason),
                            kind: TaskReportKind::Failed,
                        });
                    }
                }
            }
            HttpCollectEntry::Skipped { source, reason } => {
                reports.push(TaskReport {
                    source: source.display(),
                    fork_gid: None,
                    info_hash_hex: None,
                    metadata_path: None,
                    new_gid: None,
                    state: None,
                    degraded: false,
                    degrade_reason: None,
                    note: Some(reason.clone()),
                    kind: TaskReportKind::Skipped,
                });
            }
            HttpCollectEntry::Failed { source, reason } => {
                reports.push(TaskReport {
                    source: source.display(),
                    fork_gid: None,
                    info_hash_hex: None,
                    metadata_path: None,
                    new_gid: None,
                    state: None,
                    degraded: false,
                    degrade_reason: None,
                    note: Some(reason.clone()),
                    kind: TaskReportKind::Failed,
                });
            }
        }
    }

    // ---- 5) Report assembly (shared by dry-run and real runs): every row
    // goes into the buffer first — one final print + persist (operations
    // that change user data must leave a durable receipt; the buffer text
    // = the stdout output = the persisted content) ----
    let mut report = String::new();
    emit!(
        report,
        "taiji import {}",
        if args.dry_run { "(dry-run)" } else { "" }
    );
    if let (Some(db), Some(total)) = (&args.from_aria2_db, fork_task_total) {
        emit!(report, "fork db: {} ({total} task row(s))", db.display());
    }
    if let Some(line) = &backup_line {
        emit!(report, "{line}");
    }
    // Accurate notice for an older-ledger target (a 0.1.x db): a dry-run
    // itself never touches it; a real import first makes the automatic
    // backup (`.v1.bak` preserves the restorable old-form bytes) and only
    // then advances the migration ledger.
    if let Some(s) = &target_snapshot
        && s.user_version > 0
        && s.user_version < s.latest_supported
    {
        emit!(
            report,
            "target db: {} (user_version {}; older than this build — the real \
             import migrates it after creating {}.v1.bak)",
            args.sqlite3_db_path.display(),
            s.user_version,
            args.sqlite3_db_path.display()
        );
    }
    let failed = reports
        .iter()
        .filter(|r| r.kind == TaskReportKind::Failed)
        .count();
    let degraded = reports.iter().filter(|r| r.degraded).count();
    let skipped = reports
        .iter()
        .filter(|r| r.kind == TaskReportKind::Skipped)
        .count();
    for r in &reports {
        let head = match r.kind {
            TaskReportKind::Planned => {
                if r.degraded {
                    "degraded"
                } else {
                    "planned"
                }
            }
            TaskReportKind::Skipped => "skipped",
            TaskReportKind::Failed => "failed",
        };
        let mut line = format!("  [{head}] {}", r.source);
        if let Some(ih) = &r.info_hash_hex {
            line.push_str(&format!(" infohash={ih}"));
        }
        if let Some(meta) = &r.metadata_path {
            line.push_str(&format!(" metadata={}", meta.display()));
        }
        if let Some(gid) = &r.new_gid {
            line.push_str(&format!(" -> {gid}"));
        }
        if let Some(state) = &r.state {
            line.push_str(&format!(" state={state}"));
        }
        if let Some(note) = &r.note {
            line.push_str(&format!(" ({note})"));
        }
        if let Some(reason) = &r.degrade_reason {
            line.push_str(&format!(" ({reason})"));
        }
        emit!(report, "{line}");
    }
    // `.aria2` reconciliation accounting: merged / orphan / corrupt each
    // get their own presentation.
    let mut recon_failed = 0usize;
    if let Some(r) = &recon {
        for e in &r.entries {
            match e {
                Aria2Reconciliation::Reconciled {
                    ctrl_path,
                    output_path,
                    fork_gid,
                    total_length,
                    progress_filled,
                    data_present,
                } => {
                    emit!(
                        report,
                        "  [reconciled] ctrl:{} -> {} (fork row {fork_gid}, \
                         totalLength={total_length}{}{})",
                        ctrl_path.display(),
                        output_path.display(),
                        if *progress_filled {
                            ", progress filled from control file"
                        } else {
                            ""
                        },
                        if *data_present {
                            ", data file present"
                        } else {
                            ", data file absent"
                        }
                    );
                }
                Aria2Reconciliation::Orphan {
                    ctrl_path,
                    output_path,
                    total_length,
                    data_present,
                } => {
                    emit!(
                        report,
                        "  [orphan] ctrl:{} -> {} (totalLength={total_length}; \
                         no matching fork row — control files carry no URI, \
                         re-add the task by URI; file kept untouched{})",
                        ctrl_path.display(),
                        output_path.display(),
                        if *data_present {
                            "; data file present"
                        } else {
                            ""
                        }
                    );
                }
                Aria2Reconciliation::BitTorrentFace { ctrl_path } => {
                    emit!(
                        report,
                        "  [bt-face] ctrl:{} (BitTorrent control file — handled \
                         by the BitTorrent import face)",
                        ctrl_path.display()
                    );
                }
                Aria2Reconciliation::Failed { ctrl_path, reason } => {
                    recon_failed += 1;
                    emit!(report, "  [failed] ctrl:{} ({reason})", ctrl_path.display());
                }
            }
        }
        emit!(
            report,
            "aria2 reconciliation: {} reconciled, {} orphan(s) (report-only), \
             {recon_failed} unreadable",
            r.reconciled_count(),
            r.orphan_count()
        );
    }
    emit!(
        report,
        "{} planned ({} degraded), {skipped} skipped, {failed} failed",
        planned_bt.len() + planned_http.len(),
        degraded
    );

    // ---- 6) Persist / deregistration list ----
    if args.dry_run {
        emit!(
            report,
            "dry-run: nothing written to {}",
            args.sqlite3_db_path.display()
        );
        let mut would: Vec<String> = planned_bt
            .iter()
            .filter_map(|p| p.fork_gid.clone())
            .collect();
        would.extend(planned_http.iter().filter_map(|p| p.fork_gid.clone()));
        would.sort();
        would.dedup();
        emit!(report, "{}", deregister_text(&would, true));
        finish_report(&mut report, &args.sqlite3_db_path);
        let exit_failed = failed + recon_failed;
        // Writer drain (the dedup-key read face is done with it) — the
        // sidecars fold away cleanly before the process exits.
        drop(writer);
        if let Some(join) = writer_join {
            let _ = join.await;
        }
        return if exit_failed > 0 { 2 } else { 0 };
    }
    let Some(writer) = writer else {
        eprintln!("error: target writer unavailable (internal)");
        return 1;
    };
    let applied_bt = import::apply_import(&writer, &planned_bt).await;
    let mut import_failed = 0usize;
    for (p, a) in planned_bt.iter().zip(&applied_bt) {
        match &a.error {
            Some(e) => {
                import_failed += 1;
                emit!(
                    report,
                    "  [failed] {} -> {} ({e})",
                    p.source.display(),
                    p.gid
                );
            }
            None => {
                emit!(report, "  [imported] {} -> {}", p.source.display(), p.gid)
            }
        }
    }
    let applied_http =
        import_http::apply_http_import_with_state(&writer, &planned_http, &http_state).await;
    for (p, a) in planned_http.iter().zip(&applied_http) {
        match &a.error {
            Some(e) => {
                import_failed += 1;
                emit!(
                    report,
                    "  [failed] {} -> {} ({e})",
                    p.source.display(),
                    p.gid
                );
            }
            None => {
                emit!(report, "  [imported] {} -> {}", p.source.display(), p.gid)
            }
        }
    }
    // The deregistration list = fork-source tasks that persisted
    // successfully (ctrl sources carry no GID and stay out of the RPC
    // deregistration face).
    let mut deregister: Vec<String> = planned_bt
        .iter()
        .zip(&applied_bt)
        .filter(|(_, a)| a.error.is_none())
        .filter_map(|(p, _)| p.fork_gid.clone())
        .collect();
    deregister.extend(
        planned_http
            .iter()
            .zip(&applied_http)
            .filter(|(_, a)| a.error.is_none())
            .filter_map(|(p, _)| p.fork_gid.clone()),
    );
    deregister.sort();
    deregister.dedup();
    emit!(report, "{}", deregister_text(&deregister, false));
    // Report finalization: persist to disk + print the full text to
    // stdout (before the interactive purge output — stdout after the
    // receipt belongs to the interactive process, not the report).
    finish_report(&mut report, &args.sqlite3_db_path);

    let exit_failed = failed + recon_failed + import_failed;
    // ---- 7) Optional aria2 deregistration (remove +
    // purgeDownloadResult) ----
    let mut purge_error = false;
    if let Some(url) = args
        .purge_via_aria2
        .as_ref()
        .filter(|_| !deregister.is_empty())
    {
        if !confirm_purge(&deregister, args.yes).await {
            println!("purge cancelled by user; deregister list printed above");
        } else if let Err(e) = run_purge(url, &deregister).await {
            eprintln!("error: aria2 purge failed: {e}");
            purge_error = true;
        }
    }
    // Writer drain (last step): the process exits only after the persist
    // queue is empty and the connection is cleanly closed.
    drop(writer);
    if let Some(join) = writer_join {
        let _ = join.await;
    }
    if purge_error {
        return 1;
    }
    if exit_failed > 0 { 2 } else { 0 }
}

fn failed_report(task: &SourceTask, ih: Option<String>, reason: String) -> TaskReport {
    TaskReport {
        source: task.source.display(),
        fork_gid: task.fork_gid.clone(),
        info_hash_hex: ih,
        metadata_path: None,
        new_gid: None,
        state: None,
        degraded: false,
        degrade_reason: None,
        note: Some(reason),
        kind: TaskReportKind::Failed,
    }
}

/// Deregistration-list text ("print the list of aria2 GIDs that
/// should be deregistered"; the user then drives the aria2 RPC
/// themselves, or hands it to --purge-via-aria2). The returned text goes
/// into the report buffer (no direct stdout printing — the report is
/// printed once by the finalization face).
fn deregister_text(gids: &[String], dry: bool) -> String {
    if gids.is_empty() {
        return "no aria2 GIDs to deregister".to_string();
    }
    let mut s = format!(
        "deregister via aria2 RPC (remove + purgeDownloadResult){}:\n",
        if dry { " (after confirmation)" } else { "" }
    );
    for g in gids {
        s.push_str(&format!("  {g}\n"));
    }
    s
}

// ---- Import report persistence ("operations that change user data must
// leave a durable receipt"): dry-run and real imports each write
// `<db>.import-report-<timestamp>.txt` whose content is the full stdout
// report (including the receipt path line); stdout prints the path in
// sync. A persistence failure degrades to a warn and does not block (the
// stdout report stays complete, minus the receipt path line). ----

/// Report path: `<db>.import-report-<timestamp>.txt` (millisecond
/// timestamps — a dry-run and a real run back to back never collide).
fn import_report_path(db_path: &Path) -> PathBuf {
    let mut s = db_path.as_os_str().to_os_string();
    s.push(format!(".import-report-{}.txt", report_timestamp()));
    PathBuf::from(s)
}

/// Finalization face: persist to disk (the receipt path line joins the
/// report only if the write succeeded — stdout never claims a file that
/// does not exist), then print the full text once. Write failure degrades
/// to a warn.
fn finish_report(report: &mut String, db_path: &Path) {
    let path = import_report_path(db_path);
    let line = format!("import report: {}\n", path.display());
    let mut content = String::with_capacity(report.len() + line.len());
    content.push_str(report);
    if !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(&line);
    // The disk write goes through the winpath conversion (identity off
    // Windows; the warn carries the original path).
    match std::fs::write(taiji_io::winpath::to_fs_path(&path), &content) {
        Ok(()) => report.push_str(&line),
        Err(e) => tracing::warn!(
            target: "taiji::cli",
            path = %path.display(),
            "import report could not be written (non-blocking): {e}"
        ),
    }
    print!("{report}");
    let _ = std::io::Write::flush(&mut std::io::stdout());
}

/// UTC report timestamp for the current instant
/// (`YYYYMMDDTHHMMSS.mmmZ` — filename-safe, no colons).
fn report_timestamp() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format_timestamp(d.as_secs(), d.subsec_millis())
}

/// Epoch seconds + milliseconds -> report timestamp text (UTC).
fn format_timestamp(secs: u64, millis: u32) -> String {
    let (y, mo, da) = civil_from_days((secs / 86_400) as i64);
    let sod = secs % 86_400;
    format!(
        "{y:04}{mo:02}{da:02}T{:02}{:02}{:02}.{millis:03}Z",
        sod / 3_600,
        (sod % 3_600) / 60,
        sod % 60
    )
}

/// Days since 1970-01-01 -> (year, month, day). Direct translation of
/// Howard Hinnant's `civil_from_days` (no time-library dependency — one
/// timestamp formatter is not worth an extra dependency edge).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Interactive confirmation (--yes skips; immediate EOF on a
/// non-interactive stdin = refusal — scripts should pass --yes
/// explicitly).
async fn confirm_purge(gids: &[String], yes: bool) -> bool {
    if yes {
        return true;
    }
    println!(
        "about to remove {} aria2 task(s) via RPC: {}",
        gids.len(),
        gids.join(", ")
    );
    println!("type 'yes' to confirm: ");
    let mut line = String::new();
    use tokio::io::AsyncBufReadExt;
    // tokio Stdin implements only AsyncRead — read_line goes through a
    // BufReader.
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
    if tokio::time::timeout(PURGE_RPC_TIMEOUT, stdin.read_line(&mut line))
        .await
        .is_err()
    {
        return false;
    }
    matches!(line.trim(), "yes" | "y")
}

// ---- aria2 JSON-RPC deregistration client (bare HTTP/1.1, zero new
// dependencies — same shape as the rpc_smoke integration-test client;
// http endpoints only, the LAN scenario) ----

#[derive(Debug, Clone, PartialEq, Eq)]
struct Aria2Url {
    host: String,
    port: u16,
    path: String,
    /// `token:SECRET` userinfo form (the aria2 client convention).
    secret: Option<String>,
}

/// Parse `http://[token:SECRET@]host[:port][/path]` (default port 6800,
/// default path `/jsonrpc` — the aria2 defaults). https is explicitly
/// unsupported (this subcommand targets a LAN sidecar; it reports the
/// error honestly instead of pretending to work).
fn parse_aria2_url(url: &str) -> Result<Aria2Url, String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| format!("invalid aria2 rpc url (need scheme://): {url}"))?;
    if scheme != "http" {
        return Err(format!(
            "unsupported aria2 rpc url scheme '{scheme}': only http is supported"
        ));
    }
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/jsonrpc".to_string()),
    };
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, authority),
    };
    let secret = userinfo.and_then(|u| u.strip_prefix("token:").map(|s| s.to_string()));
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>()
                .map_err(|_| format!("invalid port in url: {url}"))?,
        ),
        None => (hostport.to_string(), 6800),
    };
    if host.is_empty() {
        Err(format!("missing host in url: {url}"))
    } else {
        Ok(Aria2Url {
            host,
            port,
            path,
            secret,
        })
    }
}

/// One JSON-RPC call (the token is prefixed `token:SECRET`, the same
/// rule as aria2 clients).
async fn aria2_call(
    url: &Aria2Url,
    method: &str,
    mut params: Vec<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    if let Some(secret) = &url.secret {
        params.insert(0, json!(format!("token:{secret}")));
    }
    let body = json!({
        "jsonrpc": "2.0",
        "id": "taiji-import",
        "method": method,
        "params": params,
    })
    .to_string();
    let text = http_post_json(url, &body).await?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("rpc response not json: {e}: {text}"))?;
    if let Some(err) = v.get("error") {
        return Err(format!(
            "rpc error for {method}: {}",
            err.get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown")
        ));
    }
    Ok(v.get("result").cloned().unwrap_or(serde_json::Value::Null))
}

/// Bare HTTP/1.1 POST (Connection: close; blocking semantics bounded by
/// the tokio timeout budget).
async fn http_post_json(url: &Aria2Url, body: &str) -> Result<String, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let fut = async {
        let mut s = tokio::net::TcpStream::connect((url.host.as_str(), url.port))
            .await
            .map_err(|e| format!("connect {}:{}: {e}", url.host, url.port))?;
        let req = format!(
            "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            url.path,
            url.host,
            url.port,
            body.len()
        );
        s.write_all(req.as_bytes())
            .await
            .map_err(|e| format!("write: {e}"))?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf)
            .await
            .map_err(|e| format!("read: {e}"))?;
        String::from_utf8(buf).map_err(|e| format!("response not utf8: {e}"))
    };
    let raw = tokio::time::timeout(PURGE_RPC_TIMEOUT, fut)
        .await
        .map_err(|_| "rpc timeout".to_string())??;
    let (head, payload) = raw
        .split_once("\r\n\r\n")
        .ok_or_else(|| format!("malformed http response: {raw}"))?;
    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| format!("malformed http status line: {head}"))?;
    if status != 200 {
        return Err(format!("rpc http status {status}"));
    }
    Ok(payload.to_string())
}

/// Perform the deregistration: `aria2.remove` per GID (an error on
/// completed tasks is expected — their result rows are cleaned up
/// wholesale by `purgeDownloadResult`, the two-step
/// semantics), then one final purge.
async fn run_purge(url: &str, gids: &[String]) -> Result<(), String> {
    let url = parse_aria2_url(url)?;
    let mut removed = 0usize;
    for gid in gids {
        match aria2_call(&url, "aria2.remove", vec![json!(gid)]).await {
            Ok(_) => {
                removed += 1;
                println!("  removed {gid}");
            }
            Err(e) => println!("  remove {gid}: not removable ({e}); result row purged below"),
        }
    }
    aria2_call(&url, "aria2.purgeDownloadResult", vec![])
        .await
        .map_err(|e| format!("purgeDownloadResult: {e}"))?;
    println!("aria2 purge done: {removed} active removed, results purged");
    Ok(())
}

fn valid_preserved_gid(gid: &str) -> bool {
    gid.len() == 16
        && gid.bytes().all(|byte| byte.is_ascii_hexdigit())
        && u64::from_str_radix(gid, 16).is_ok_and(|raw| raw != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Endpoint parsing: token userinfo / default port and path /
    /// invalid forms.
    #[test]
    fn aria2_url_parsing() {
        let u = parse_aria2_url("http://token:secret@127.0.0.1:6800/jsonrpc")
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            (u.host.as_str(), u.port, u.path.as_str()),
            ("127.0.0.1", 6800, "/jsonrpc")
        );
        assert_eq!(u.secret.as_deref(), Some("secret"));
        let bare = parse_aria2_url("http://localhost").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((bare.port, bare.path.as_str()), (6800, "/jsonrpc"));
        assert_eq!(bare.secret, None);
        assert!(
            parse_aria2_url("https://h/jsonrpc").is_err(),
            "https explicitly unsupported"
        );
        assert!(parse_aria2_url("nonsense").is_err());
        assert!(parse_aria2_url("http://h:notaport/").is_err());
    }

    // ---- Import report persistence (unit tests) ----

    /// Timestamp formatting anchors: the epoch origin, known instants
    /// (2026-09-18T00:00:00Z = 1789689600, exercising civil_from_days'
    /// leap tables) and the last millisecond of a day.
    #[test]
    fn timestamp_format_known_instants() {
        assert_eq!(format_timestamp(0, 0), "19700101T000000.000Z");
        assert_eq!(format_timestamp(1_789_689_600, 7), "20260918T000000.007Z");
        assert_eq!(
            format_timestamp(1_789_689_600 + 23 * 3_600 + 59 * 60 + 59, 999),
            "20260918T235959.999Z"
        );
        assert!(
            !report_timestamp().contains(':'),
            "filename-safe (no colon)"
        );
    }

    /// civil_from_days: the origin, a leap day (2024-02-29), a century
    /// regression (2000-02-29).
    #[test]
    fn civil_from_days_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(
            civil_from_days(1_704_067_200 / 86_400 + 59),
            (2024, 2, 29),
            "leap day (2024-01-01 + 59 days = Feb 29 -- day 60 in a leap year)"
        );
        assert_eq!(
            civil_from_days(951_782_400 / 86_400),
            (2000, 2, 29),
            "the 400-year century leap day"
        );
        assert_eq!(
            civil_from_days(1_789_689_600 / 86_400),
            (2026, 9, 18),
            "the reference date (2026-09-18)"
        );
    }

    /// Report path shape: `<db>.import-report-<ts>.txt` (spelled directly
    /// against the db path).
    #[test]
    fn import_report_path_shape() {
        let p = import_report_path(Path::new("/root/taiji.sqlite3"));
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("?");
        assert!(name.starts_with("taiji.sqlite3.import-report-"), "{name}");
        assert!(name.ends_with(".txt"), "{name}");
        assert!(p.starts_with("/root"), "{p:?}");
    }

    /// Persistence degradation: an unwritable directory -> non-blocking,
    /// no receipt path line in the report (stdout never claims a file
    /// that does not exist); a writable directory -> the file lands on
    /// disk and the report carries the full text plus the path line.
    #[test]
    fn finish_report_degrades_to_warn_on_unwritable_target() {
        let report = &mut String::from("taiji import (dry-run)\n0 planned\n");
        // Unwritable: the parent directory does not exist (fs::write must
        // fail).
        finish_report(report, Path::new("/nonexistent-dir/taiji.sqlite3"));
        assert!(
            !report.contains("import report:"),
            "a failed write must not claim a receipt path: {report}"
        );
        assert!(
            report.contains("0 planned"),
            "the report body must survive the write failure: {report}"
        );
        // Writable: the file is on disk, content = the full report
        // (including the path line).
        let dir = std::env::temp_dir().join(format!(
            "taiji-import-report-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let db = dir.join("taiji.sqlite3");
        finish_report(report, &db);
        let line = report
            .lines()
            .find(|l| l.starts_with("import report: "))
            .unwrap_or_else(|| panic!("path line appended: {report}"));
        let path = PathBuf::from(line.trim_start_matches("import report: "));
        let on_disk = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read: {e}"));
        assert_eq!(on_disk, *report, "on-disk content = the full stdout report");
        assert!(on_disk.starts_with("taiji import (dry-run)\n"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
