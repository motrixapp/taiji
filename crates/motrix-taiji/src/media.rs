//! `taiji media` subcommand: the doctor face + the media
//! download face.
//!
//! `taiji media <url> [--selector] [--sub lang] [--no-meta]` — the
//! one-shot download: the SessionActor is bootstrapped directly (the
//! same shape as `taiji http`: session-store persistence + bootstrap
//! recovery; no RPC server), the task is added via the addMedia
//! session face, and the CLI polls to the terminal state. The flag
//! family rides the `--media-*` require_equals discipline.
//!
//! Exit codes: 0 = the product is in place; 1 = the task failed or
//! was interrupted; 2 = session/option errors (the
//! `taiji.option.invalid` value-domain rejection included).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use clap::Args;
use tracing::{error, info, warn};

use taiji_core::session::{
    CommandReply, GlobalOptions, SessionActor, SessionCommand, SessionError, SessionOptions,
    StatusKind, TorrentStatusView,
};

/// Status-polling interval (the http face's cadence).
const STATUS_POLL: Duration = Duration::from_millis(200);
/// Shutdown budget (the http face's 1s).
const SHUTDOWN_BUDGET: Duration = Duration::from_secs(1);

/// `media` subcommand tree.
#[derive(Debug, Args)]
pub struct MediaArgs {
    #[command(subcommand)]
    command: MediaSubcommand,
}

/// `media` subcommands.
#[derive(Debug, clap::Subcommand)]
pub enum MediaSubcommand {
    /// ffmpeg/ffprobe health check: discovery + version/license gate +
    /// capability table (human-readable by default, `--json` for
    /// machines).
    Doctor(DoctorArgs),
    /// One-shot media download (the addMedia session face; the
    /// SessionActor runs in-process with session-store persistence).
    #[command(alias = "get")]
    Download(Box<MediaDownloadArgs>),
}

/// `doctor` arguments.
#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Emit the machine-readable JSON report instead of the human
    /// rendering.
    #[arg(long)]
    pub json: bool,
}

/// `media download` arguments (`taiji media <url>`'s shape — the URL
/// rides the positional).
#[derive(Debug, Args)]
pub struct MediaDownloadArgs {
    /// The media entry URL (an HLS manifest; a direct media file
    /// routes to the HTTP task family automatically).
    pub url: String,

    /// Download directory.
    #[arg(long, default_value = ".")]
    pub dir: PathBuf,

    /// Output base name (pre-template; the expansion + sanitization
    /// red line applies downstream).
    #[arg(long, require_equals = true)]
    pub out: Option<String>,

    /// The three-layer selector (`best`/`best-combined`/`audio-only`
    /// | predicates `res<=`, `codec!=`, `lang=`, `ext=` | escape hatch
    /// `format_id=v0,a1`).
    #[arg(long, require_equals = true)]
    pub selector: Option<String>,

    /// Subtitle language (RFC 5646 prefix; sidecar mode; a preference
    /// that matches no rendition downloads none).
    #[arg(long = "sub", value_name = "LANG", require_equals = true)]
    pub sub_lang: Option<String>,

    /// Skip metadata embedding (the 0.3 value domain is
    /// manifest-available anyway; the flag rides for the bridge era).
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    pub no_meta: bool,

    /// Output template (0.3 fields: {title}{id}{ext}{res}{lang}
    /// {playlist_index}; the expansion result is force-sanitized).
    #[arg(long, require_equals = true)]
    pub template: Option<String>,

    /// Session database path (resume truth).
    #[arg(long, default_value = "taiji.sqlite3")]
    pub sqlite3_db_path: PathBuf,

    // ---- The unified-registration flag family (require_equals
    // discipline; the parse/validation source = taiji-media's
    // option faces, relayed verbatim into the addMedia options) ----
    /// Variant policy: highest|resolution=<H>|bandwidth=<B>.
    #[arg(long, require_equals = true)]
    pub media_variant_policy: Option<String>,

    /// Audio language (RFC 5646 prefix).
    #[arg(long, require_equals = true)]
    pub media_audio_lang: Option<String>,

    /// Subtitles: sidecar|none.
    #[arg(long, require_equals = true)]
    pub media_subtitles: Option<String>,

    /// Per-task segment concurrency (1..=64).
    #[arg(long, require_equals = true)]
    pub media_segment_concurrency: Option<String>,

    /// Staging quota (GiB).
    #[arg(long, require_equals = true)]
    pub media_staging_quota_gib: Option<String>,

    /// Staging root directory.
    #[arg(long, require_equals = true)]
    pub media_staging_dir: Option<String>,

    /// Allow private-network key/segment URLs (SSRF line).
    #[arg(long, require_equals = true)]
    pub media_allow_private_key_url: Option<String>,

    /// ffmpeg discovery input: auto|<dir>|path:<dir>.
    #[arg(long, require_equals = true)]
    pub media_ffmpeg_path: Option<String>,

    /// Record this download in the media archive + refuse duplicate
    /// entries (default false; the archive's sensitivity = browsing
    /// history — clear it with --media-archive-clear or the
    /// taiji.clearMediaArchive RPC).
    #[arg(long, require_equals = true)]
    pub media_archive: Option<String>,

    /// Write the whitelisted, redacted `<product>.info.json` sidecar
    /// at completion (default false; orthogonal to --no-meta).
    #[arg(long, require_equals = true)]
    pub media_info_json: Option<String>,

    /// One-shot full archive clear **before** this download runs (the
    /// taiji.clearMediaArchive RPC's CLI counterpart; after a clear
    /// the same fingerprints re-download).
    #[arg(long, require_equals = true)]
    pub media_archive_clear: Option<String>,
}

/// Entry point (`run(cli)` dispatch arm).
pub async fn run(args: MediaArgs) -> i32 {
    match args.command {
        MediaSubcommand::Doctor(doctor) => {
            let report = taiji_media::run_doctor(taiji_media::DoctorOptions {
                strictness: taiji_media::LicenseStrictness::Gate,
                explicit_dir: None,
                // Production shim host: this very executable (the `main`
                // entry routes the marker argv to
                // `taiji_media::exec_shim`).
                shim_program: None,
            })
            .await;
            if doctor.json {
                match serde_json::to_string_pretty(&report) {
                    Ok(text) => println!("{text}"),
                    Err(e) => {
                        error!(target: "taiji::cli", "doctor report serialization: {e}");
                        return 2;
                    }
                }
            } else {
                print!("{}", report.render_human());
            }
            i32::from(report.red != 0)
        }
        MediaSubcommand::Download(args) => run_download(*args).await,
    }
}

/// The addMedia options payload assembled from the CLI flags.
fn add_media_options(a: &MediaDownloadArgs) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("dir".into(), a.dir.display().to_string());
    if let Some(out) = &a.out {
        m.insert("out".into(), out.clone());
    }
    if let Some(sel) = &a.selector {
        m.insert("media-selector".into(), sel.clone());
    }
    if let Some(lang) = &a.sub_lang {
        m.insert("sub-lang".into(), lang.clone());
    }
    if a.no_meta {
        m.insert("no-meta".into(), "true".into());
    }
    if let Some(t) = &a.template {
        m.insert("media-template".into(), t.clone());
    }
    for (key, val) in [
        ("media-variant-policy", &a.media_variant_policy),
        ("media-audio-lang", &a.media_audio_lang),
        ("media-subtitles", &a.media_subtitles),
        ("media-segment-concurrency", &a.media_segment_concurrency),
        ("media-staging-quota-gib", &a.media_staging_quota_gib),
        ("media-staging-dir", &a.media_staging_dir),
        (
            "media-allow-private-key-url",
            &a.media_allow_private_key_url,
        ),
        ("media-ffmpeg-path", &a.media_ffmpeg_path),
        ("media-archive", &a.media_archive),
        ("media-info-json", &a.media_info_json),
    ] {
        if let Some(v) = val {
            m.insert(key.to_string(), v.clone());
        }
    }
    m
}

/// The one-shot download drive (the http face's session shape).
async fn run_download(args: MediaDownloadArgs) -> i32 {
    let _db_lock = match crate::http::acquire_db_lock(&args.sqlite3_db_path).await {
        Ok(l) => l,
        Err(code) => return code,
    };
    let (persist, persist_join) =
        match taiji_core::session::persist::import::open_session_writer_with_metrics(
            args.sqlite3_db_path.clone(),
        )
        .await
        {
            Ok((h, j)) => (Some(h), Some(j)),
            Err(e) => {
                error!(target: "taiji::cli", %e,
                    "cannot open session db; running WITHOUT persistence");
                (None, None)
            }
        };
    let options = SessionOptions {
        global: GlobalOptions {
            dir: args.dir.clone(),
            one_shot: true,
            ..Default::default()
        },
    };
    let (session, actor_join) = SessionActor::spawn_with_persist(options, persist);
    // The one-shot archive pre-clear (`--media-archive-clear`, the
    // taiji.clearMediaArchive RPC's CLI counterpart): validated at
    // flag-parse semantics here, executed through the session's
    // single-writer face BEFORE the task is added — a clear-then-
    // download in one invocation (after a clear the same fingerprints
    // re-download).
    if let Some(v) = &args.media_archive_clear {
        let on = match taiji_media::parse_media_archive_clear(v) {
            Ok(on) => on,
            Err(e) => {
                error!(target: "taiji::cli", "{e}");
                return 2;
            }
        };
        if on {
            match session.call(SessionCommand::ClearMediaArchive).await {
                Ok(CommandReply::ArchiveCleared { removed }) => {
                    info!(target: "taiji::cli", removed,
                        "media archive cleared (one-shot pre-clear)");
                }
                Ok(_) => {
                    error!(target: "taiji::cli", "unexpected clearMediaArchive reply");
                    return 2;
                }
                Err(e) => {
                    error!(target: "taiji::cli", "{e}");
                    return 2;
                }
            }
        }
    }
    // Media phase events (the phaseChanged bypass) log at info while
    // the CLI drives.
    let mut media_rx = session.subscribe_media_events();
    let url = args.url.clone();
    let add = session
        .call(SessionCommand::AddMedia {
            url: url.clone(),
            options: add_media_options(&args),
            cookies: Vec::new(),
            position: None,
        })
        .await;
    let gid = match add {
        Ok(CommandReply::Gid(g)) => g,
        Ok(_) => {
            error!(target: "taiji::cli", "unexpected addMedia reply");
            return 2;
        }
        Err(SessionError::Failed { message }) => {
            error!(target: "taiji::cli", "{message}");
            return 2;
        }
        Err(e) => {
            error!(target: "taiji::cli", "{e}");
            return 2;
        }
    };
    info!(target: "taiji::cli", gid = %gid, url, "media task added");
    let mut ticks: u32 = 0;
    let code = loop {
        tokio::select! {
            ev = media_rx.recv() => {
                if let Ok(ev) = ev {
                    if let Some(w) = &ev.warning {
                        warn!(target: "taiji::cli", gid = %ev.gid,
                              code = %w.code, "{}", w.message);
                    } else {
                        info!(target: "taiji::cli", gid = %ev.gid,
                              phase = ev.phase.as_str(),
                              detail = ev.phase_detail.as_deref().unwrap_or(""),
                              "media phase");
                    }
                    continue;
                }
            }
            _ = tokio::time::sleep(STATUS_POLL) => {
                ticks += 1;
                match session.call(SessionCommand::TellStatus {
                    gid: gid.to_string(),
                    keys: Vec::new(),
                })
                .await
                {
                    Ok(CommandReply::TorrentStatus(view)) => {
                        let view = *view;
                        if ticks % 25 == 0 {
                            log_progress(&view);
                        }
                        match view.status {
                            StatusKind::Complete => {
                                if let Some(m) = &view.media {
                                    info!(target: "taiji::cli", gid = %gid,
                                          name = m.output_name.as_deref().unwrap_or(""),
                                          bytes = view.completed_length,
                                          "media download complete");
                                }
                                break 0;
                            }
                            StatusKind::Error => {
                                error!(target: "taiji::cli", gid = %gid,
                                       msg = view.error_message.as_deref().unwrap_or(""),
                                       "media download failed");
                                break 1;
                            }
                            StatusKind::Removed => {
                                warn!(target: "taiji::cli", gid = %gid, "media task removed");
                                break 1;
                            }
                            _ => {}
                        }
                    }
                    // The actor exits at shutdown; a closed channel =
                    // interrupted.
                    Err(SessionError::SessionClosed) => break 1,
                    Err(e) => {
                        warn!(target: "taiji::cli", "{e}");
                    }
                    Ok(_) => {}
                }
            }
        }
    };
    let _ = tokio::time::timeout(SHUTDOWN_BUDGET, session.shutdown()).await;
    let _ = tokio::time::timeout(SHUTDOWN_BUDGET, actor_join).await;
    if let Some(join) = persist_join {
        let _ = tokio::time::timeout(SHUTDOWN_BUDGET, join).await;
    }
    code
}

fn log_progress(view: &TorrentStatusView) {
    if let Some(m) = &view.media {
        info!(target: "taiji::cli", phase = %m.phase,
              bytes = view.completed_length,
              "media progress");
    }
}
