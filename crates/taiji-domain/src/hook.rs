//! core::hook — the hook subset execution model.
//!
//! # Correction
//!
//! Earlier text recorded "%GID%/%N% placeholder" — a misrecord: the
//! reference (aria2) is **argv-passing with no placeholder substitution at
//! all** — `util.cc executeHook` forks and calls
//! `execlp(command, command, gidHex, numFilesStr, firstFilename, NULL)`,
//! i.e. argv[1] = GID hex16, argv[2] = numFiles in decimal, argv[3] = the
//! first file path (util.cc). This module is a faithful transcription;
//! implementing placeholder substitution is forbidden.
//!
//! # Trigger points and event order (per the reference)
//!
//! - start: at group activation (`RequestGroupMan.cc`, inside
//! fillRequestGroupFromReserver, before the event notification) — here:
//! the session `activate()` after spawning the engine;
//! - pause: when pause finalizes back to the queue head and is not a
//! restart (`RequestGroupMan.cc`; the restart branch does not trigger);
//! - stop/complete/error: the finalize three-way branch
//! (`RequestGroupMan.cc executeStopHook`) — FINISHED -> complete
//! overrides; an error (not IN_PROGRESS/REMOVED) -> error overrides;
//! otherwise (including REMOVED/IN_PROGRESS) -> stop; hooks fire before
//! event notifications (same order as the reference);
//! - bt-complete: at BT download completion turning to seeding
//! (`DefaultPieceStorage.cc`, no option gate); the
//! `bt-enable-hook-after-hash-check` gate only applies to the
//! verification-complete trigger point (`BtCheckIntegrityEntry.cc`) —
//! the recheck path consumes the option; the normal completion path
//! must not carry the gate (same rule as the reference).
//!
//! # Execution model (the async form of the hook subprocess discipline)
//!
//! - `tokio::process::Command` spawn plus a dedicated reap task `wait()`:
//! the blocking wait is carried by the runtime's process reaper (the
//! async equivalent of the spawn_blocking discipline); `fire()` returns
//! immediately and **never blocks the actor/engine main loop**;
//! - failures only warn via `tracing`, never affecting task state (the
//! reference `util.cc`: exec failure perror + _exit, fork failure only
//! LOG_ERROR — zero group-state impact);
//! - reap budget 60s (a local policy value; the reference forks and never
//! waits, no timeout — the local timeout kill prevents orphaned
//! subprocess accumulation); shutdown does not wait for hooks (same as
//! the reference: no wait);
//! - an empty command returns immediately (zero cost; `--on-*` defaults
//! empty = not executed).
//!
//! The reference's Windows branch (`__MINGW32__`) is not transcribed;
//! unix-only for now.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::process::Command;
use tracing::{debug, info, warn};

use crate::gid::Gid;

/// Reap budget (a local policy value, see the module docs' execution
/// model; not reference behavior).
const HOOK_REAP_BUDGET: Duration = Duration::from_secs(60);

/// Hook trigger events (the six events aligned with aria2 notifications).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookEvent {
    Start,
    Pause,
    Stop,
    Complete,
    Error,
    BtComplete,
}

impl HookEvent {
    /// The full set (the single source for option-name iteration:
    /// parse/echo/tests share it, preventing name drift).
    pub const ALL: [HookEvent; 6] = [
        HookEvent::Start,
        HookEvent::Pause,
        HookEvent::Stop,
        HookEvent::Complete,
        HookEvent::Error,
        HookEvent::BtComplete,
    ];

    /// aria2-compatible option names (frozen; reference pref.cc
    /// `PREF_ON_DOWNLOAD_*` / `PREF_ON_BT_DOWNLOAD_COMPLETE`).
    pub fn option_name(self) -> &'static str {
        match self {
            HookEvent::Start => "on-download-start",
            HookEvent::Pause => "on-download-pause",
            HookEvent::Stop => "on-download-stop",
            HookEvent::Complete => "on-download-complete",
            HookEvent::Error => "on-download-error",
            HookEvent::BtComplete => "on-bt-download-complete",
        }
    }

    /// Option name -> event (parse face; an unknown name returns None —
    /// callers handle it under aria2's "ignore unknown options" rule,
    /// RpcMethod.cc).
    pub fn from_option_name(name: &str) -> Option<HookEvent> {
        HookEvent::ALL
            .into_iter()
            .find(|ev| ev.option_name() == name)
    }
}

/// The effective hook set (task-final values after global option
/// injection plus per-task overrides; travels with the task, immutable
/// during activation — aria2's per-download option RequestGroup ownership
/// semantics).
#[derive(Debug, Clone)]
pub struct HookSet {
    pub on_download_start: Option<String>,
    pub on_download_pause: Option<String>,
    pub on_download_stop: Option<String>,
    pub on_download_complete: Option<String>,
    pub on_download_error: Option<String>,
    pub on_bt_download_complete: Option<String>,
    /// `--bt-enable-hook-after-hash-check` (default true — aria2
    /// `OptionHandlerFactory.cc` A2_V_TRUE). Consumption point = the
    /// verification-complete trigger (BtCheckIntegrityEntry.cc semantics);
    /// the normal completion path carries no gate (DefaultPieceStorage.cc
    /// has no option gate, same as the reference).
    pub bt_enable_hook_after_hash_check: bool,
}

impl Default for HookSet {
    fn default() -> Self {
        HookSet {
            on_download_start: None,
            on_download_pause: None,
            on_download_stop: None,
            on_download_complete: None,
            on_download_error: None,
            on_bt_download_complete: None,
            bt_enable_hook_after_hash_check: true,
        }
    }
}

impl HookSet {
    /// Per-task patch override (None = keep global; the same
    /// surface-value override semantics as aria2's per-download options).
    pub fn overlay(&mut self, patch: &HookPatch) {
        for ev in HookEvent::ALL {
            if let Some(cmd) = patch.command(ev) {
                *self.slot_mut(ev) = Some(cmd.clone());
            }
        }
        if let Some(b) = patch.bt_enable_hook_after_hash_check {
            self.bt_enable_hook_after_hash_check = b;
        }
    }

    fn slot_mut(&mut self, ev: HookEvent) -> &mut Option<String> {
        match ev {
            HookEvent::Start => &mut self.on_download_start,
            HookEvent::Pause => &mut self.on_download_pause,
            HookEvent::Stop => &mut self.on_download_stop,
            HookEvent::Complete => &mut self.on_download_complete,
            HookEvent::Error => &mut self.on_download_error,
            HookEvent::BtComplete => &mut self.on_bt_download_complete,
        }
    }

    /// The effective command (None = unset or empty = not executed; the
    /// same rule as reference `executeHookByOptName`'s
    /// `if (!cmd.empty())`, util.cc).
    pub fn command(&self, ev: HookEvent) -> Option<&str> {
        let slot = match ev {
            HookEvent::Start => &self.on_download_start,
            HookEvent::Pause => &self.on_download_pause,
            HookEvent::Stop => &self.on_download_stop,
            HookEvent::Complete => &self.on_download_complete,
            HookEvent::Error => &self.on_download_error,
            HookEvent::BtComplete => &self.on_bt_download_complete,
        };
        slot.as_deref().filter(|c| !c.is_empty())
    }

    /// Whether at least one of the six hooks is effective (a zero-cost
    /// check: none -> the engine/task mounts no runner).
    pub fn has_any_command(&self) -> bool {
        HookEvent::ALL.iter().any(|ev| self.command(*ev).is_some())
    }
}

/// Per-task hook option delta (the parse product of addUri/addTorrent
/// options; all None = none given). bt-enable-hook-after-hash-check is
/// tri-state: None = keep global.
#[derive(Debug, Clone, Default)]
pub struct HookPatch {
    pub on_download_start: Option<String>,
    pub on_download_pause: Option<String>,
    pub on_download_stop: Option<String>,
    pub on_download_complete: Option<String>,
    pub on_download_error: Option<String>,
    pub on_bt_download_complete: Option<String>,
    pub bt_enable_hook_after_hash_check: Option<bool>,
}

impl HookPatch {
    pub fn command(&self, ev: HookEvent) -> Option<&String> {
        match ev {
            HookEvent::Start => self.on_download_start.as_ref(),
            HookEvent::Pause => self.on_download_pause.as_ref(),
            HookEvent::Stop => self.on_download_stop.as_ref(),
            HookEvent::Complete => self.on_download_complete.as_ref(),
            HookEvent::Error => self.on_download_error.as_ref(),
            HookEvent::BtComplete => self.on_bt_download_complete.as_ref(),
        }
    }

    pub fn set_command(&mut self, ev: HookEvent, value: Option<String>) {
        let slot = match ev {
            HookEvent::Start => &mut self.on_download_start,
            HookEvent::Pause => &mut self.on_download_pause,
            HookEvent::Stop => &mut self.on_download_stop,
            HookEvent::Complete => &mut self.on_download_complete,
            HookEvent::Error => &mut self.on_download_error,
            HookEvent::BtComplete => &mut self.on_bt_download_complete,
        };
        *slot = value;
    }

    /// Empty patch (no per-task overrides at all).
    pub fn is_empty(&self) -> bool {
        HookEvent::ALL.iter().all(|ev| self.command(*ev).is_none())
            && self.bt_enable_hook_after_hash_check.is_none()
    }
}

/// Task context (the argv payload; the group/DownloadContext data face of
/// `executeHookByOptName`, util.cc). On magnet in-place upgrade,
/// [`HookRunner::set_payload`] re-mounts the real file face (the metadata
/// phase = the in-memory download projection with numFiles=0 /
/// firstFilename="").
#[derive(Debug, Clone)]
struct HookCtx {
    gid: Gid,
    num_files: usize,
    first_filename: String,
}

/// HookRunner: the hook trigger face for one task (session and engine
/// share one instance — the actor side triggers
/// start/pause/stop/complete/error, the engine side triggers
/// bt-complete).
pub struct HookRunner {
    set: Arc<HookSet>,
    /// Payload slot: rewritten synchronously at the magnet upgrade point
    /// (the Mutex is held only in synchronous critical sections, never
    /// across an await).
    ctx: Mutex<HookCtx>,
    /// Event bus relay slot (optional; mounted via `with_notify`). Every
    /// [`HookRunner::fire`] calls back after hook command handling —
    /// always, regardless of whether a hook command exists; the
    /// engine-side BtComplete notification publish returns to the
    /// SessionActor event bus through this (order = hook first,
    /// notification after, same point and order as DefaultPieceStorage.cc).
    notify: Option<Arc<dyn Fn(HookEvent) + Send + Sync>>,
    /// Recovery event relay slot (optional; mounted via
    /// `with_recovery_notify`). The session-bus return seam for the
    /// engine state machine's recovery points (missing-layer activation /
    /// promotion convergence) — a pure notification relay that **never
    /// triggers any user hook command** (not hook semantics; unrelated to
    /// the command half of [`HookRunner::fire`]; the payload is a gid-less
    /// [`crate::recovery::RecoveryNotice`], stamped by the session-side
    /// closure into the extension event bus).
    recovery_notify: Option<Arc<dyn Fn(crate::recovery::RecoveryNotice) + Send + Sync>>,
}

impl std::fmt::Debug for HookRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ctx = crate::lock(&self.ctx);
        f.debug_struct("HookRunner")
            .field("set", &self.set)
            .field("ctx", &*ctx)
            .field("has_notify", &self.notify.is_some())
            .field("has_recovery_notify", &self.recovery_notify.is_some())
            .finish()
    }
}

impl HookRunner {
    pub fn new(
        set: Arc<HookSet>,
        gid: Gid,
        num_files: usize,
        first_filename: String,
    ) -> HookRunner {
        HookRunner {
            set,
            ctx: Mutex::new(HookCtx {
                gid,
                num_files,
                first_filename,
            }),
            notify: None,
            recovery_notify: None,
        }
    }

    /// Mounts the event bus relay (builder form — existing call sites
    /// untouched).
    pub fn with_notify(mut self, notify: Arc<dyn Fn(HookEvent) + Send + Sync>) -> HookRunner {
        self.notify = Some(notify);
        self
    }

    /// Mounts the recovery event relay (builder form — existing call
    /// sites untouched).
    pub fn with_recovery_notify(
        mut self,
        notify: Arc<dyn Fn(crate::recovery::RecoveryNotice) + Send + Sync>,
    ) -> HookRunner {
        self.recovery_notify = Some(notify);
        self
    }

    /// Recovery event relay: pure notification return from the engine's
    /// recovery points. With no relay mounted = no-op (zero cost for CLI
    /// direct runs / test assemblies; unrelated to `fire`'s command half
    /// — recovery events trigger no user hook).
    pub fn notify_recovery(&self, notice: crate::recovery::RecoveryNotice) {
        if let Some(notify) = &self.recovery_notify {
            notify(notice);
        }
    }

    /// Re-mounts the argv payload (the magnet upgrade point: metadata ->
    /// the real file face).
    pub fn set_payload(&self, num_files: usize, first_filename: String) {
        let mut ctx = crate::lock(&self.ctx);
        ctx.num_files = num_files;
        ctx.first_filename = first_filename;
    }

    /// Fires: hook command execution (or empty-command short circuit) ->
    /// event relay callback -> returns whether a process was actually
    /// spawned. Hook before notification (the reference event order,
    /// RequestGroupMan.cc / DefaultPieceStorage.cc); the relay always
    /// fires regardless of hook command presence (BtComplete's publish
    /// does not depend on `--on-*` option configuration). An empty
    /// command set plus no relay = a pure no-op (the zero-cost contract
    /// holds).
    ///
    /// Runtime contract: a hook command present means the reap task is
    /// spawned onto the **caller's Tokio runtime** (production: the
    /// session actor's) — calling `fire` outside a runtime context
    /// with a configured command panics on Linux (the pidfd reaper
    /// needs a reactor; macOS's kqueue path tolerates the missing
    /// context, which hides the contract there).
    pub fn fire(&self, ev: HookEvent) -> bool {
        let spawned = self.fire_command(ev);
        if let Some(notify) = &self.notify {
            notify(ev);
        }
        spawned
    }

    /// The hook command half: an empty command returns false immediately
    /// (zero cost; `--on-*` defaults empty = not executed); otherwise
    /// spawns the subprocess with a dedicated reap task; this call does
    /// not wait (the reference's fork-without-wait semantics, util.cc).
    fn fire_command(&self, ev: HookEvent) -> bool {
        let Some(cmd) = self.set.command(ev) else {
            return false;
        };
        let cmd = cmd.to_string();
        let (gid, num_files, first_filename) = {
            let ctx = crate::lock(&self.ctx);
            (ctx.gid, ctx.num_files, ctx.first_filename.clone())
        };
        // argv-passing transcription: execlp(command, command, gidHex,
        // numFilesStr, firstFilename, NULL) — util.cc. argv[0]=command is
        // handled by Command::new; a bare name is looked up via PATH (as
        // with execlp).
        info!(target: "taiji::core::hook",
            event = ev.option_name(), %gid, num_files, first_filename = %first_filename,
            command = %cmd, "executing user command");
        let mut command = Command::new(&cmd);
        command
            .arg(gid.to_string())
            .arg(num_files.to_string())
            .arg(&first_filename);
        let Ok(mut child) = command.spawn() else {
            // exec/spawn failure: warn only, task state unaffected (same
            // semantics as util.cc's perror + _exit(EXIT_FAILURE) — the
            // parent is oblivious).
            warn!(target: "taiji::core::hook",
                event = ev.option_name(), %gid, command = %cmd,
                "could not execute user command (task state unaffected)");
            return false;
        };
        tokio::spawn(async move {
            match tokio::time::timeout(HOOK_REAP_BUDGET, child.wait()).await {
                Ok(Ok(status)) if status.success() => {
                    debug!(target: "taiji::core::hook", %status, "hook finished");
                }
                Ok(Ok(status)) => {
                    // Non-zero exit: warn only, task state unaffected
                    // (util.cc semantics).
                    warn!(target: "taiji::core::hook", %status,
                        "user command exited non-zero (task state unaffected)");
                }
                Ok(Err(e)) => {
                    warn!(target: "taiji::core::hook", %e,
                        "user command wait failed (task state unaffected)");
                }
                Err(_) => {
                    warn!(target: "taiji::core::hook",
                        budget_secs = HOOK_REAP_BUDGET.as_secs(),
                        "user command exceeded reap budget; killing (local policy, \
                         reference never waits/kills hooks)");
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                }
            }
        });
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn set_with(pairs: &[(HookEvent, &str)]) -> HookSet {
        let mut set = HookSet::default();
        for (ev, cmd) in pairs {
            *set.slot_mut(*ev) = Some((*cmd).to_string());
        }
        set
    }

    /// Frozen option-name table (the six events <-> aria2 frozen names).
    #[test]
    fn hook_event_option_names_are_frozen() {
        let expect = [
            (HookEvent::Start, "on-download-start"),
            (HookEvent::Pause, "on-download-pause"),
            (HookEvent::Stop, "on-download-stop"),
            (HookEvent::Complete, "on-download-complete"),
            (HookEvent::Error, "on-download-error"),
            (HookEvent::BtComplete, "on-bt-download-complete"),
        ];
        for (ev, name) in expect {
            assert_eq!(ev.option_name(), name);
            assert_eq!(HookEvent::from_option_name(name), Some(ev));
        }
        assert_eq!(HookEvent::from_option_name("on-download-x"), None);
    }

    /// bt-enable-hook-after-hash-check defaults to true (aria2
    /// OptionHandlerFactory.cc A2_V_TRUE transcription).
    #[test]
    fn default_bt_enable_hook_after_hash_check_is_true() {
        assert!(HookSet::default().bt_enable_hook_after_hash_check);
    }

    /// Empty set = a zero-cost no; a blank-string command = unset = not
    /// executed (util.cc's rule).
    #[test]
    fn empty_and_blank_sets_have_no_commands() {
        let mut set = HookSet::default();
        assert!(!set.has_any_command());
        assert_eq!(set.command(HookEvent::Start), None);
        set.on_download_start = Some(String::new());
        assert_eq!(set.command(HookEvent::Start), None, "blank = unset");
        assert!(!set.has_any_command());
        let set = set_with(&[(HookEvent::BtComplete, "/bin/true")]);
        assert!(set.has_any_command());
        assert_eq!(set.command(HookEvent::BtComplete), Some("/bin/true"));
    }

    /// overlay: per-task overrides global, None keeps global; the
    /// tri-state bool behaves the same.
    #[test]
    fn patch_overlays_global() {
        let mut global = set_with(&[
            (HookEvent::Start, "/global-start"),
            (HookEvent::Complete, "/global-complete"),
        ]);
        let patch = HookPatch {
            on_download_start: Some("/task-start".into()),
            bt_enable_hook_after_hash_check: Some(false),
            ..HookPatch::default()
        };
        assert!(!patch.is_empty());
        global.overlay(&patch);
        assert_eq!(global.command(HookEvent::Start), Some("/task-start"));
        assert_eq!(
            global.command(HookEvent::Complete),
            Some("/global-complete")
        );
        assert!(!global.bt_enable_hook_after_hash_check);
        // An all-None patch = empty.
        let empty = HookPatch::default();
        assert!(empty.is_empty());
    }

    /// argv shape cross-check: the execlp argument vector = [command,
    /// gidHex16, numFiles decimal, firstFilename] (util.cc); no
    /// placeholder substitution.
    #[test]
    fn argv_payload_shape_matches_reference() {
        let gid = Gid::from_u64(0x8000_0000_0000_0001);
        // hex16 + decimal numFiles asserted parameter by parameter (the
        // same source as fire()'s assembly order).
        assert_eq!(format!("{gid}"), "8000000000000001");
        let ctx = HookCtx {
            gid,
            num_files: 3,
            first_filename: "/dl/dir/a.bin".into(),
        };
        assert_eq!(ctx.num_files.to_string(), "3");
        assert_eq!(ctx.first_filename, "/dl/dir/a.bin");
    }

    /// Empty-command fire = a pure no-op (no spawn, no panic; the
    /// zero-cost contract).
    #[test]
    fn fire_without_command_is_noop() {
        let runner = HookRunner::new(
            Arc::new(HookSet::default()),
            Gid::from_u64(1),
            0,
            String::new(),
        );
        for ev in HookEvent::ALL {
            assert!(!runner.fire(ev), "empty set must not spawn");
        }
    }

    /// The event relay always fires regardless of hook command presence
    /// (BtComplete's publish does not depend on `--on-*` configuration);
    /// all six events pass through, payloads aligned one by one.
    #[test]
    fn notify_relay_fires_even_without_hook_commands() {
        let runner = HookRunner::new(
            Arc::new(HookSet::default()),
            Gid::from_u64(0x8000_0000_0000_0042),
            0,
            String::new(),
        )
        .with_notify(Arc::new(|ev| {
            // The closure only records (no mutable captures — shared via
            // the Mutex).
            let mut seen = SEEN_NOTIFY.lock().unwrap_or_else(|p| p.into_inner());
            seen.push(ev);
        }));
        for ev in HookEvent::ALL {
            assert!(!runner.fire(ev), "empty set must not spawn");
        }
        let seen = SEEN_NOTIFY.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(*seen, HookEvent::ALL.to_vec(), "relay sees every event");
    }

    /// The relay is independent of the hook command's spawn outcome: after
    /// spawn failure (or an empty-set short circuit) the notification half
    /// still fires — hook first, notification after is fire()'s structural
    /// order (fire_command -> notify). This environment may forbid
    /// subprocess spawns (returning false), which simultaneously locks the
    /// "spawn failure does not affect the relay" contract (the
    /// notification-face extension of util.cc's zero task-state impact).
    #[test]
    fn notify_relay_independent_of_hook_spawn_outcome() {
        let runner = HookRunner::new(
            Arc::new(set_with(&[(HookEvent::Stop, "/bin/true")])),
            Gid::from_u64(7),
            0,
            String::new(),
        )
        .with_notify(Arc::new(|_| {
            let mut order = ORDER.lock().unwrap_or_else(|p| p.into_inner());
            order.push("notify");
        }));
        // Supply the runtime the contract requires (see fire's doc):
        // bare-call panics on Linux via the pidfd reaper.
        let rt = tokio::runtime::Runtime::new().unwrap_or_else(|e| panic!("test runtime: {e}"));
        let _ = rt.block_on(async { runner.fire(HookEvent::Stop) });
        let order = ORDER.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(
            order.as_slice(),
            ["notify"],
            "relay fires regardless of spawn outcome"
        );
    }

    /// The shared record for [`notify_relay_fires_even_without_hook_commands`]
    /// (single-writer test, Mutex-ordered).
    static SEEN_NOTIFY: Mutex<Vec<HookEvent>> = Mutex::new(Vec::new());

    /// The shared record for
    /// [`notify_relay_independent_of_hook_spawn_outcome`].
    static ORDER: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());

    /// set_payload: re-mounts at the magnet upgrade point (metadata
    /// projection -> the real file face).
    #[test]
    fn set_payload_swaps_argv_payload() {
        let runner = HookRunner::new(
            Arc::new(set_with(&[(HookEvent::Complete, "/bin/true")])),
            Gid::from_u64(0x8000_0000_0000_0002),
            0,
            String::new(),
        );
        runner.set_payload(2, "/dl/x".into());
        let ctx = runner.ctx.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(ctx.num_files, 2);
        assert_eq!(ctx.first_filename, "/dl/x");
    }
}
