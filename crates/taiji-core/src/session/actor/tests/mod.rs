//! The actor session-test facade: every test is included! directly into
//! this module (`mod tests`). Invariant: the full test names stay
//! `session::actor::tests::xxx` — a submodule form would rewrite the
//! libtest collection path and filter-word behavior, so the tests are
//! split into per-domain files instead of being mounted with `mod`.
//! Each domain file is a verbatim move of the original tests.rs
//! entries; cross-domain references rely on the shared module scope.

use super::*;
use std::time::Instant;

use super::super::{GlobalOptions, RPC_METHODS, SessionOptions};
// This domain's own sibling-module imports (the parent's shared symbol
// area keeps only glob-consumed names).
use super::lifecycle::progress_row_complete;
use super::tasks::build_engine_config;
use super::views::file_views;
use taiji_bt::bencode::{self, Value};
use taiji_store::merkle;

type CmdResult = Result<CommandReply, SessionError>;

async fn call(handle: &SessionHandle, cmd: SessionCommand) -> CmdResult {
    handle.call(cmd).await
}

fn gid_of(r: &CmdResult) -> Gid {
    match r {
        Ok(CommandReply::Gid(g)) => *g,
        other => panic!("expected Gid reply, got {other:?}"),
    }
}

fn status_list(r: &CmdResult) -> Vec<TorrentStatusView> {
    match r {
        Ok(CommandReply::StatusList(v)) => v.clone(),
        other => panic!("expected StatusList reply, got {other:?}"),
    }
}

fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("bh-p34-{tag}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&d);
    d
}

fn torrent_cmd(bytes: Vec<u8>, dir: &std::path::Path) -> SessionCommand {
    SessionCommand::AddTorrent {
        torrent: bytes,
        options: BTreeMap::from([("dir".to_string(), dir.display().to_string())]),
        position: None,
    }
}

fn read_config_json(db: &std::path::Path, gid: &Gid) -> String {
    let conn = ok(rusqlite::Connection::open(db), "open db");
    ok(
        conn.query_row(
            "SELECT config_json FROM torrent WHERE gid = ?1",
            params![gid.to_string()],
            |r| r.get(0),
        ),
        "config_json",
    )
}

fn count_rows(db: &std::path::Path) -> i64 {
    let conn = ok(rusqlite::Connection::open(db), "open db");
    ok(
        conn.query_row("SELECT COUNT(*) FROM torrent", [], |r| r.get(0)),
        "count",
    )
}

/// Poll until the condition holds (a default 5s window; the waiting
/// face for session events arriving asynchronously).
async fn wait_until(mut f: impl AsyncFnMut() -> bool) {
    for _ in 0..250 {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("condition not reached within wait window");
}

include!("lifecycle.rs");
include!("options.rs");
include!("queue.rs");
include!("bt.rs");
include!("select.rs");
include!("torrent_selection.rs");
include!("events.rs");
include!("persist.rs");
include!("bans.rs");
include!("http.rs");
include!("batch.rs");
include!("rate.rs");
include!("seed.rs");
include!("check.rs");
include!("synthesis.rs");
include!("observe.rs");
include!("budget_keys.rs");
