//! Three-face option-registration consistency (the media-family
//! precedent): the four-pool budget trio is registered on
//! the faces **from one source** —
//!
//! 1. the declaration table (`DECLARED_OPTION_DIFFS`, the core single
//!    source — the keys are taiji capability extensions, not aria2
//!    names),
//! 2. the runtime name lists (the CLI `--max-concurrent-seeds` /
//!    `--max-concurrent-checks` / `--media-synthesis-concurrency` flag
//!    surface + the getGlobalOption echo; the conf/completions faces
//!    are pinned to the CLI surface by the in-crate key-surface lock
//!    tests),
//! 3. the diff declaration document (`docs/rpc-api-diff.md`, the §3
//!    four-pool budget trio entry).
//!
//! A name on one face but missing another turns red here (the drift
//! the card's "three-face key-surface consistency" acceptance
//! criterion pins). The echo values at the defaults additionally pin
//! the two-state seed note (16 while the connection-budget card is
//! unmerged) end-to-end through a live session.

use std::process::Command;

/// The four-pool budget trio.
const BUDGET_KEY_FAMILY: &[&str] = &[
    "max-concurrent-seeds",
    "max-concurrent-checks",
    "media-synthesis-concurrency",
];

/// Face 1: every key is declared in the core table.
#[test]
fn budget_keys_are_declared_in_the_diff_table() {
    for name in BUDGET_KEY_FAMILY {
        assert!(
            taiji_core::session::option_name_declared(name),
            "{name}: missing from DECLARED_OPTION_DIFFS (face 1)"
        );
    }
}

/// Face 2a: the CLI surface carries every flag — asserted against the
/// real binary's `--help` text (the runtime name list).
#[test]
fn budget_keys_exist_on_the_cli_surface() {
    let out = Command::new(env!("CARGO_BIN_EXE_taiji"))
        .arg("--help")
        .output()
        .unwrap_or_else(|e| panic!("spawn taiji: {e}"));
    assert!(out.status.success(), "help exits 0");
    let help = String::from_utf8_lossy(&out.stdout);
    for name in BUDGET_KEY_FAMILY {
        assert!(
            help.contains(&format!("--{name}")),
            "--{name}: missing from the CLI top-level face (face 2a)"
        );
    }
}

/// Face 2b: the getGlobalOption echo carries every key, and the echo
/// values at the defaults pin the two-state seed note end-to-end
/// (16/2/2 — the aria2-compatible max-concurrent-downloads default 5
/// rides along as the shared-shape witness).
#[tokio::test]
async fn budget_keys_echo_on_get_global_option() {
    let (session, _actor) = taiji_core::session::SessionActor::spawn();
    let echo = match session
        .call(taiji_core::session::SessionCommand::GetGlobalOption)
        .await
    {
        Ok(taiji_core::session::CommandReply::Options(m)) => m,
        other => panic!("getGlobalOption: {other:?}"),
    };
    for name in BUDGET_KEY_FAMILY {
        assert!(
            echo.contains_key(*name),
            "{name}: missing from the getGlobalOption echo (face 2b)"
        );
    }
    assert_eq!(
        echo.get("max-concurrent-seeds").map(String::as_str),
        Some("16"),
        "seed budget defaults to 16 (the two-state note while the connection-budget \
         card is unmerged; live-echo face)"
    );
    assert_eq!(
        echo.get("max-concurrent-checks").map(String::as_str),
        Some("2")
    );
    assert_eq!(
        echo.get("media-synthesis-concurrency").map(String::as_str),
        Some("2")
    );
    let _ = session.shutdown().await;
}

/// Face 3: the diff declaration document registers every key (the §3
/// four-pool budget trio entry + the option-key list in rpc-api.md's
/// Main Options).
#[test]
fn budget_keys_are_declared_in_the_docs() {
    let diff = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/rpc-api-diff.md"
    ))
    .unwrap_or_else(|e| panic!("read rpc-api-diff.md: {e}"));
    for name in BUDGET_KEY_FAMILY {
        assert!(
            diff.contains(name),
            "{name}: missing from docs/rpc-api-diff.md (face 3)"
        );
    }
    assert!(
        diff.contains("Four-pool budget trio"),
        "the §3 dedicated entry heading must exist (the live-diff audit anchor)"
    );
    let rpc_api = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/rpc-api.md"
    ))
    .unwrap_or_else(|e| panic!("read rpc-api.md: {e}"));
    for name in BUDGET_KEY_FAMILY {
        assert!(
            rpc_api.contains(&format!("--{name}")),
            "--{name}: missing from docs/rpc-api.md Main Options (the key-name list)"
        );
    }
}
