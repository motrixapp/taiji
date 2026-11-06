//! Self-exec shim: the resource-limit applier for media children
//! (see `process.rs` module docs for why `pre_exec` is
//! replaced — workspace `unsafe_code = forbid` vs std's unsafe
//! `CommandExt::pre_exec`).
//!
//! Mechanism: [`crate::process::MediaCommand::spawn`] launches *this
//! executable* with [`SHIM_ARG`] as the first argument plus a guard
//! environment variable. [`maybe_run_shim`] — called at the very top of
//! the binary's `main`, before any runtime or argument parsing —
//! recognizes that shape, applies RLIMIT_AS/RLIMIT_CPU/niceness through
//! safe rustix calls, scrubs the shim environment variables, and runs
//! the real ffmpeg/ffprobe as its own child in the same process group
//! (inheriting the limits — limits propagate to descendants), exiting
//! with the media child's exit code.
//!
//! The limits are therefore in force before any ffmpeg/ffprobe code
//! runs — the property `pre_exec` would provide — with zero
//! unsafe code on our side.
//!
//! Guard rails: the marker argument alone is not enough (a user typing
//! it on a real CLI must not land in shim mode) — the spawner-set
//! [`ENV_GUARD`] must also be present, else the process refuses (125).
//! Non-absolute targets refuse (126), matching the spawner-side
//! contract.
//!
//! Windows: the shim is never spawned (direct spawn in
//! `process.rs`); [`maybe_run_shim`] is a constant `None` there and
//! this module has no windows code (the limits are unix-only — the
//! "Windows not applicable" note).

/// Marker argument (argv[1] of a shim invocation).
pub const SHIM_ARG: &str = "__taiji-media-exec";

/// Guard environment variable (spawner sets "1"; without it a marker
/// argv is refused).
pub const ENV_GUARD: &str = "__TAIJI_MEDIA_EXEC_SHIM";

/// RLIMIT_AS bytes for the shim (spawner-encoded).
pub const ENV_RLIMIT_AS: &str = "__TAIJI_MEDIA_EXEC_RLIMIT_AS";

/// RLIMIT_CPU seconds for the shim (spawner-encoded).
pub const ENV_RLIMIT_CPU: &str = "__TAIJI_MEDIA_EXEC_RLIMIT_CPU";

/// Shim entry point. `Some(code)` = the process IS a shim invocation
/// and has terminated by the time this returns (the caller exits with
/// the code); `None` = normal program start, fall through to the real
/// `main`.
///
/// Must be called before the async runtime exists and before clap
/// parsing: a shim invocation carries a non-option argv shape clap
/// would reject.
#[cfg(unix)]
pub fn maybe_run_shim() -> Option<i32> {
    let mut args = std::env::args_os();
    let _argv0 = args.next()?;
    let marker = args.next()?;
    if marker != SHIM_ARG {
        return None;
    }
    if std::env::var_os(ENV_GUARD).as_deref() != Some(std::ffi::OsStr::new("1")) {
        // Marker without the spawner guard: refuse rather than run an
        // unlimited media child (no silent degradation).
        eprintln!("taiji media exec shim: guard env {ENV_GUARD} absent; refusing");
        return Some(125);
    }
    let payload: Vec<std::ffi::OsString> = args.collect();
    Some(run_shim(payload))
}

#[cfg(windows)]
pub fn maybe_run_shim() -> Option<i32> {
    // Never spawned on windows (direct spawn); the marker argv, if a
    // user types it, falls through to clap's unknown-argument error.
    None
}

/// Shim body: limits → scrub env → run the media child → exit with its
/// code.
#[cfg(unix)]
fn run_shim(payload: Vec<std::ffi::OsString>) -> i32 {
    use std::path::Path;

    let Some(target) = payload.first() else {
        eprintln!("taiji media exec shim: empty payload");
        return 126;
    };
    if !Path::new(target).is_absolute() {
        eprintln!(
            "taiji media exec shim: non-absolute target {:?}; refusing",
            target
        );
        return 126;
    }
    if let Err(code) = apply_limits() {
        return code;
    }
    // The media child gets the shim plumbing vars scrubbed from its
    // environment (per-command `env_remove` — the process-global
    // `std::env::remove_var` is unsafe under edition 2024 and stays
    // out; the vars also gate this very shim mode).
    let mut command = std::process::Command::new(target);
    command
        .env_remove(ENV_GUARD)
        .env_remove(ENV_RLIMIT_AS)
        .env_remove(ENV_RLIMIT_CPU);
    command.args(payload.iter().skip(1));
    match command.status() {
        Ok(status) => match status.code() {
            Some(code) => code,
            None => {
                use std::os::unix::process::ExitStatusExt;
                match status.signal() {
                    Some(sig) => 128 + sig,
                    None => 127,
                }
            }
        },
        Err(e) => {
            eprintln!("taiji media exec shim: spawn {:?}: {e}", target);
            126
        }
    }
}

/// Apply the resource limits to this process (the shim) — inherited by the
/// media child it spawns. RLIMIT_CPU failure refuses the shim
/// (fail-closed: a real limit that must hold). RLIMIT_AS failure is
/// tolerated with a stderr note: macOS's setrlimit(RLIMIT_AS, x) is
/// EINVAL for any x (neither settable nor enforced there — verified
/// 2026-10-27, macOS 27/arm64), while Linux (the enforcement platform
/// the posture targets) sets it and stays fail-closed.
#[cfg(unix)]
fn apply_limits() -> Result<(), i32> {
    use rustix::process::{Resource, Rlimit};

    let as_bytes = std::env::var(ENV_RLIMIT_AS)
        .ok()
        .and_then(|v| v.parse::<u64>().ok());
    let cpu_secs = std::env::var(ENV_RLIMIT_CPU)
        .ok()
        .and_then(|v| v.parse::<u64>().ok());

    // Both vars are spawner-mandatory (cpu always set; as=0 would be a
    // nonsense limit) — absence means a hand-rolled invocation.
    let (Some(as_bytes), Some(cpu_secs)) = (as_bytes, cpu_secs) else {
        eprintln!("taiji media exec shim: limit env vars absent/malformed; refusing");
        return Err(125);
    };

    let as_limit = Rlimit {
        current: Some(as_bytes),
        maximum: Some(as_bytes),
    };
    if let Err(e) = rustix::process::setrlimit(Resource::As, as_limit) {
        eprintln!(
            "taiji media exec shim: setrlimit AS {as_bytes} refused ({e}); \
             continuing with RLIMIT_CPU + -max_alloc (platform without a \
             settable RLIMIT_AS)"
        );
    }
    let cpu_limit = Rlimit {
        current: Some(cpu_secs),
        maximum: Some(cpu_secs),
    };
    if let Err(e) = rustix::process::setrlimit(Resource::Cpu, cpu_limit) {
        eprintln!("taiji media exec shim: setrlimit CPU {cpu_secs}: {e}");
        return Err(126);
    }
    // `nice lowest`: niceness 19, best-effort — an unprivileged
    // process may already sit at a lower ceiling; failure is not a
    // refusal (scheduling priority is not a memory-safety control).
    let _ = rustix::process::setpriority_process(None, 19);
    Ok(())
}
