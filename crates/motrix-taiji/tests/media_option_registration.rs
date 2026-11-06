//! Three-face option-registration consistency (extended to the
//! per-task face): the media flag family is registered on the three faces
//! **from one source** —
//!
//! 1. the declaration table (`DECLARED_OPTION_DIFFS`, the core
//! single source),
//! 2. the runtime name lists (the CLI `--media-*` flag surface +
//! the getGlobalOption echo / the GLOBAL_PATCH table mirror),
//! 3. the diff declaration document (`docs/rpc-api-diff.md`).
//!
//! A name on one face but missing another turns red here (the drift
//! the card's "three-face consistency" acceptance criterion pins). The
//! extension grows the
//! session-global family 8→10 (`media-archive`/`media-info-json`) and
//! pins the **per-task key face** (media-template/no-meta/…): its three
//! faces are the addMedia option acceptance (a live actor parse, the
//! strict `taiji.option.invalid` face), the CLI flags, and the doc.

use std::process::Command;

/// The unified-registration flag family (8 names + 2 later product
/// faces): the session-global shape.
const MEDIA_FLAG_FAMILY: &[&str] = &[
    "media-variant-policy",
    "media-audio-lang",
    "media-subtitles",
    "media-segment-concurrency",
    "media-staging-quota-gib",
    "media-staging-dir",
    "media-allow-private-key-url",
    "media-ffmpeg-path",
    "media-archive",
    "media-info-json",
];

/// The per-task addMedia key face (the keys that ride the options dict
/// but not the session globals): the third status check —
/// media-template/no-meta's three faces = the addMedia acceptance (a
/// live actor parse), the CLI flag spelling, and the doc.
const MEDIA_TASK_KEY_FAMILY: &[&str] = &[
    "media-selector",
    "sub-lang",
    "media-template",
    "no-meta",
    "media-muxer",
    "media-output-format",
    "probe-token",
];

/// Face 1 ⊇ the family: every flag is declared in the core table.
#[test]
fn media_flags_are_declared_in_the_diff_table() {
    for name in MEDIA_FLAG_FAMILY {
        assert!(
            taiji_core::session::option_name_declared(name),
            "{name}: missing from DECLARED_OPTION_DIFFS (face 1)"
        );
    }
}

/// Face 2a: the CLI surface carries every flag on the `media
/// download` subcommand — asserted against the real binary's `--help`
/// text (the runtime name list). clap renders require_equals flags as
/// `--flag=<VALUE>` in help, so the `=<` form checks both existence
/// and the require_equals discipline in one face.
#[test]
fn media_flags_exist_on_the_cli_media_subcommand() {
    let out = Command::new(env!("CARGO_BIN_EXE_taiji"))
        .args(["media", "download", "--help"])
        .output()
        .unwrap_or_else(|e| panic!("spawn taiji: {e}"));
    assert!(out.status.success(), "help exits 0");
    let help = String::from_utf8_lossy(&out.stdout);
    for name in MEDIA_FLAG_FAMILY {
        assert!(
            help.contains(&format!("--{name}=<")),
            "--{name}=<VALUE>: missing or not require_equals on the CLI face (face 2a)"
        );
    }
    // The declared CLI shape: the positional URL + --selector/--sub/
    // --no-meta. The per-task family's CLI spellings ride the same
    // help face (media-template's flag is `--template`; sub-lang's is
    // `--sub`).
    for long in ["--selector", "--sub", "--no-meta", "--template=<"] {
        assert!(
            help.contains(long),
            "{long}: missing from the CLI media face (the declared shape)"
        );
    }
    // The one-shot archive pre-clear flag (the clearMediaArchive CLI
    // counterpart) is on the same subcommand.
    assert!(
        help.contains("--media-archive-clear=<"),
        "--media-archive-clear=<VALUE>: missing or not require_equals (the one-shot clear)"
    );
    assert!(
        help.contains("<URL>"),
        "the positional URL rides the media download face"
    );
}

/// Face 2b: the getGlobalOption echo carries every flag (the rpc
/// registry face — GlobalOptions echo through the GLOBAL_PATCH rows).
#[tokio::test]
async fn media_flags_echo_on_get_global_option() {
    // The echo face is session-internal but mirrors the GLOBAL_PATCH
    // rows one-for-one (the mirror-const governance test); the public
    // consumer-level check = a live SessionActor's GetGlobalOption.
    let (session, _actor) = taiji_core::session::SessionActor::spawn();
    let echo = match session
        .call(taiji_core::session::SessionCommand::GetGlobalOption)
        .await
    {
        Ok(taiji_core::session::CommandReply::Options(m)) => m,
        other => panic!("getGlobalOption: {other:?}"),
    };
    for name in MEDIA_FLAG_FAMILY {
        assert!(
            echo.contains_key(*name),
            "{name}: missing from the getGlobalOption echo (face 2b)"
        );
    }
}

/// Face 3: the diff declaration document registers every flag (the
/// same-name anchor — a rename on any face without the doc turns red).
#[test]
fn media_flags_are_declared_in_rpc_api_diff() {
    let doc = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/rpc-api-diff.md"
    ))
    .unwrap_or_else(|e| panic!("read rpc-api-diff.md: {e}"));
    for name in MEDIA_FLAG_FAMILY {
        assert!(
            doc.contains(name),
            "{name}: missing from docs/rpc-api-diff.md (face 3)"
        );
    }
    // The methods + the extension event are declared too (the media
    // line plus the archive clear).
    for needle in [
        "taiji.addMedia",
        "taiji.probeMedia",
        "taiji.getMediaFormats",
        "taiji.stopRecording",
        "taiji.clearMediaArchive",
        "taiji.media.phaseChanged",
        "media-archive-clear",
    ] {
        assert!(doc.contains(needle), "{needle}: missing from the diff doc");
    }
}

/// The per-task key face (the third check): every task-only option key is
/// **accepted by a live addMedia parse** (an unknown key answers
/// `taiji.option.invalid` naming the key — the strict face; an
/// accepted key answers a GID or a value-domain error, never the
/// unknown-key error), pinning the actor's acceptance list from the
/// runtime side (the const itself is crate-private by design).
#[tokio::test]
async fn media_task_keys_are_accepted_by_add_media() {
    let (session, _actor) = taiji_core::session::SessionActor::spawn();
    let unknown_key = "media-totally-unheard-of";
    for key in MEDIA_TASK_KEY_FAMILY.iter().copied().chain([unknown_key]) {
        let options = std::collections::BTreeMap::from([
            // A syntactically valid URL (the add face's scheme gate
            // passes; nothing is fetched at add time).
            ("dir".to_string(), ".".to_string()),
            (key.to_string(), "true".to_string()),
        ]);
        let reply = session
            .call(taiji_core::session::SessionCommand::AddMedia {
                url: "https://example.test/stream.m3u8".into(),
                options,
                cookies: Vec::new(),
                position: None,
            })
            .await;
        let text = match reply {
            Err(e) => format!("{e}"),
            Ok(_) => String::new(),
        };
        if key == unknown_key {
            assert!(
                text.contains("unknown media option"),
                "the unknown key must be refused with the unknown-option face: {text}"
            );
        } else {
            assert!(
                !text.contains("unknown media option"),
                "{key}: must be an accepted addMedia key (got: {text})"
            );
        }
    }
    let _ = session.shutdown().await;
}
