//! Event name tables — the WS notification surface's single source.
//!
//! The six-event dual-face tables (canonical `taiji.onXxx` / compat
//! `aria2.onXxx`) and the `EventKind` -> method-name matches moved here
//! from core `session::events` (the kernel keeps only the event
//! *kinds*); `system.listNotifications` and the WS push both render
//! through this module (rule R2: no event-name strings below the rpc
//! crate). The extension-event *names* stay kernel-owned (the
//! capabilities injection consumes them core-side); this module keeps
//! the registry plus a consistency lock so the two cannot drift.
//!
//! Excision: deleting this module leaves the kernel compiling (the
//! kinds and payloads carry no names); `scripts/ci/excision_check.sh`
//! pins that.
//!
//! Upstream anchor mapping: docs/design/rpc.md

use taiji_core::session::EventKind;
#[cfg(test)]
use taiji_core::session::{MEDIA_PHASE_EVENT_METHOD, RecoveryEventKind, TASK_COOKIE_EVENT_METHOD};

/// The six event notification names (the canonical face:
/// `taiji.onXxx`, the payload `[{gid}]` unchanged). Same source as the
/// [`notification_method`] match below (locked by a consistency
/// test); `system.listNotifications` emits this table directly in the
/// default (compat off) state.
pub const RPC_NOTIFICATIONS: &[&str] = &[
    "taiji.onHttpOutputReady",
    "taiji.onDownloadStart",
    "taiji.onDownloadPause",
    "taiji.onDownloadStop",
    "taiji.onDownloadComplete",
    "taiji.onDownloadError",
    "taiji.onBtDownloadComplete",
];

/// The six event notification names (the `--rpc-aria2-compat` alias
/// face). Verbatim cross-validation: `RpcMethodFactory.cc` (the
/// system.listNotifications table) and `WebSocketSessionMan.cc` (the
/// WS push method names) — one-to-one with the canonical table
/// (`taiji.X` <-> `aria2.X`); the extension events (`taiji.recovery*`)
/// are not in this table (the compat face covers only the six events).
pub const RPC_NOTIFICATIONS_ARIA2: &[&str] = &[
    "taiji.onHttpOutputReady",
    "aria2.onDownloadStart",
    "aria2.onDownloadPause",
    "aria2.onDownloadStop",
    "aria2.onDownloadComplete",
    "aria2.onDownloadError",
    "aria2.onBtDownloadComplete",
];

/// The listNotifications presentation-face selector (one API face at a time).
pub(crate) fn notification_face(aria2_compat: bool) -> &'static [&'static str] {
    if aria2_compat {
        RPC_NOTIFICATIONS_ARIA2
    } else {
        RPC_NOTIFICATIONS
    }
}

/// EventKind -> WS notification method name (the dual-face match,
/// migrated from core `session::events`; both faces selected at one
/// point — one API face at a time, double-publish forbidden).
pub(crate) fn notification_method(kind: EventKind, aria2_compat: bool) -> &'static str {
    match kind {
        EventKind::HttpReady => "taiji.onHttpOutputReady",
        EventKind::Start => face(
            "taiji.onDownloadStart",
            "aria2.onDownloadStart",
            aria2_compat,
        ),
        EventKind::Pause => face(
            "taiji.onDownloadPause",
            "aria2.onDownloadPause",
            aria2_compat,
        ),
        EventKind::Stop => face("taiji.onDownloadStop", "aria2.onDownloadStop", aria2_compat),
        EventKind::Complete => face(
            "taiji.onDownloadComplete",
            "aria2.onDownloadComplete",
            aria2_compat,
        ),
        EventKind::Error => face(
            "taiji.onDownloadError",
            "aria2.onDownloadError",
            aria2_compat,
        ),
        EventKind::BtComplete => face(
            "taiji.onBtDownloadComplete",
            "aria2.onBtDownloadComplete",
            aria2_compat,
        ),
    }
}

fn face(canonical: &'static str, compat: &'static str, aria2_compat: bool) -> &'static str {
    if aria2_compat { compat } else { canonical }
}

/// The `taiji.*` extension-event registry (the recovery pair + the
/// media phase-change bypass + the task-cookie alert). The names are
/// **kernel-owned single sources** (the core capabilities injection
/// consumes them); this table is the rpc-side registry the
/// `getCapabilities.notifications` face and the WS bypasses align
/// with — the consistency test below locks the two against drift (a
/// second spelling of any name is a wire break).
pub const EXTENSION_EVENTS: &[&str] = &[
    // taiji.recoveryStarted / taiji.recoveryCompleted
    // (RecoveryEventKind::notification_method, domain-owned).
    "taiji.recoveryStarted",
    "taiji.recoveryCompleted",
    // taiji.media.phaseChanged (MEDIA_PHASE_EVENT_METHOD, core-owned).
    "taiji.media.phaseChanged",
    // taiji.task.cookiesClearedOnError (TASK_COOKIE_EVENT_METHOD,
    // core-owned).
    "taiji.task.cookiesClearedOnError",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-validate the dual notification name sets (migrated from
    /// core `session::events`; reference = WebSocketSessionMan.cc
    /// literals). The faces map one-to-one with zero additions or
    /// removals, the WS-push match agrees with both tables, and the
    /// compat name is always the canonical name with the prefix
    /// replaced (`taiji.` -> `aria2.`; HttpReady stays canonical on
    /// both faces).
    #[test]
    fn notification_method_names_are_frozen() {
        let canonical = [
            (EventKind::Start, "taiji.onDownloadStart"),
            (EventKind::Pause, "taiji.onDownloadPause"),
            (EventKind::Stop, "taiji.onDownloadStop"),
            (EventKind::Complete, "taiji.onDownloadComplete"),
            (EventKind::Error, "taiji.onDownloadError"),
            (EventKind::BtComplete, "taiji.onBtDownloadComplete"),
        ];
        let compat = [
            (EventKind::Start, "aria2.onDownloadStart"),
            (EventKind::Pause, "aria2.onDownloadPause"),
            (EventKind::Stop, "aria2.onDownloadStop"),
            (EventKind::Complete, "aria2.onDownloadComplete"),
            (EventKind::Error, "aria2.onDownloadError"),
            (EventKind::BtComplete, "aria2.onBtDownloadComplete"),
        ];
        for ((k1, c), (k2, a)) in canonical.into_iter().zip(compat) {
            assert_eq!(k1, k2, "face tables must enumerate the same order");
            assert_eq!(notification_method(k1, false), c);
            assert_eq!(notification_method(k1, true), a);
        }
        assert_eq!(EventKind::ALL.len(), 7, "the kind set is seven");
        for kind in EventKind::ALL {
            if kind == EventKind::HttpReady {
                // The HTTP output-ready extension keeps its canonical
                // name on both faces (one name, not in the compat swap).
                assert_eq!(notification_method(kind, true), "taiji.onHttpOutputReady");
                continue;
            }
            let swapped = notification_method(kind, false)
                .strip_prefix("taiji.")
                .map(|rest| format!("aria2.{rest}"))
                .unwrap_or_default();
            assert_eq!(
                notification_method(kind, true),
                swapped,
                "faces must stay one-to-one"
            );
        }
    }

    /// The six notification names match the EventKind enumeration in
    /// both faces (the `system.listNotifications` table and the WS
    /// push share one source — WebSocketSessionMan.cc dual outlets,
    /// kept drift-free; migrated from the dispatch test suite).
    #[test]
    fn notifications_match_core_event_kinds() {
        let canonical: Vec<&str> = EventKind::ALL
            .iter()
            .map(|k| notification_method(*k, false))
            .collect();
        assert_eq!(canonical, RPC_NOTIFICATIONS.to_vec());
        let compat: Vec<&str> = EventKind::ALL
            .iter()
            .map(|k| notification_method(*k, true))
            .collect();
        assert_eq!(compat, RPC_NOTIFICATIONS_ARIA2.to_vec());
        // The face selector agrees with both tables (one face at a time).
        assert_eq!(notification_face(false), RPC_NOTIFICATIONS);
        assert_eq!(notification_face(true), RPC_NOTIFICATIONS_ARIA2);
    }

    /// Extension-event registry lock: the four names equal the
    /// kernel-owned constants member-for-member (the capabilities
    /// injection face and the WS bypasses cannot drift from this
    /// table). A name change on either side turns this red.
    #[test]
    fn extension_event_registry_matches_kernel_constants() {
        let kernel: Vec<&str> = RecoveryEventKind::ALL
            .iter()
            .map(|k| k.notification_method())
            .chain([MEDIA_PHASE_EVENT_METHOD, TASK_COOKIE_EVENT_METHOD])
            .collect();
        let mut registry = EXTENSION_EVENTS.to_vec();
        let mut kernel_sorted = kernel.clone();
        registry.sort_unstable();
        kernel_sorted.sort_unstable();
        assert_eq!(
            registry, kernel_sorted,
            "the extension-event registry drifted from the kernel constants"
        );
        // None of them may appear in the six-event tables (the bypass
        // declaration: listNotifications does not grow).
        for name in EXTENSION_EVENTS {
            assert!(
                !RPC_NOTIFICATIONS.contains(name) && !RPC_NOTIFICATIONS_ARIA2.contains(name),
                "{name} must stay out of the six-event tables"
            );
        }
    }
}
