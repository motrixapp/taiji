//! SessionEvent event bus (SPEC §7.4/§8.1; the event *kinds* only —
//! their WS method-name faces are rendered by the rpc adapter
//! `taiji_rpc::aria2::event`).
//!
//! Topology, backpressure, and publish-point anchors:
//! docs/design/core.md

use crate::gid::Gid;

/// Event bus capacity (bounded at 256). A full bus never blocks the
/// sender; the slowest subscriber enters lag (see the module doc's
/// backpressure note).
pub const EVENT_BUS_CAPACITY: usize = 256;

/// Event kinds (the six events align with aria2 DownloadEvent, SPEC
/// §7.4; one-to-one with [`crate::hook::HookEvent`] — hook trigger
/// points and notification publish points share one source).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
    /// HTTP bytes are durable; the embedding host can publish or postprocess them.
    HttpReady,
    /// Group activation (aria2 `EVENT_ON_DOWNLOAD_START`).
    Start,
    /// Pause, finished back to the queue front
    /// (`EVENT_ON_DOWNLOAD_PAUSE`; the restart branch does not
    /// publish).
    Pause,
    /// IN_PROGRESS/REMOVED teardown such as removal or shutdown
    /// interruption (`EVENT_ON_DOWNLOAD_STOP`).
    Stop,
    /// Terminal FINISHED (`EVENT_ON_DOWNLOAD_COMPLETE`).
    Complete,
    /// Error teardown (`EVENT_ON_DOWNLOAD_ERROR`).
    Error,
    /// BT download finished, turning to seed
    /// (`EVENT_ON_BT_DOWNLOAD_COMPLETE`; double-fired with Complete at
    /// the same DefaultPieceStorage.cc point).
    BtComplete,
}

impl EventKind {
    /// The full set (shared by iteration and cross-validation tests;
    /// guards against name-face drift).
    pub const ALL: [EventKind; 7] = [
        EventKind::HttpReady,
        EventKind::Start,
        EventKind::Pause,
        EventKind::Stop,
        EventKind::Complete,
        EventKind::Error,
        EventKind::BtComplete,
    ];
}

// The WS notification method-name tables moved to the rpc adapter
// (`taiji_rpc::aria2::event` — both faces plus the frozen-name tests;
// the six event *kinds* stay here). No event-name strings below the
// rpc crate (protocol/internal split plan, rule R2).

/// Session event payload (core semantics, no JSON — the aria2
/// notification envelope is serialized by taiji-rpc; the GID hex16
/// output goes through `Display`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionEvent {
    pub gid: Gid,
    pub kind: EventKind,
}

// The recovery event kinds and the engine relay payload live in the
// engine subtree (`engine::recovery` — the producers are the
// engine-side HookRunner notification slot and the admission arm);
// re-exported here so the existing `session::events` public path is
// unchanged. The per-file recovery projection enum rides along (the
// getFiles `recoveryStatus` payload; wire words = the rpc adapter).
pub use crate::engine::recovery::{RecoveryEventKind, RecoveryNotice, RecoveryStatus};

/// Session recovery event bus payload (the params[0] semantics source
/// of `taiji.recoveryStarted/Completed`). The bus topology and
/// backpressure semantics mirror the six-event bus: broadcast(256),
/// sending never blocks the publisher, lag -> the rpc face counts,
/// warns, and disconnects (same rule as the module doc's backpressure
/// note).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryEvent {
    pub gid: Gid,
    pub kind: RecoveryEventKind,
    /// Client file order, 1-based (same anchor as the getFiles
    /// `index`).
    pub files: Vec<u32>,
}

// ---- taiji.media.* extension event face ----

/// The media extension event's single method name:
/// `taiji.media.phaseChanged` — the `taiji.recovery*` precedent's
/// bypass: **not** in the compat face swap, **not** in the six-event
/// table, `system.listNotifications` does not grow (the freeze tests
/// pin all three).
pub const MEDIA_PHASE_EVENT_METHOD: &str = "taiji.media.phaseChanged";

/// A warning/alarm riding the phaseChanged bypass (the single event
/// face the media line is allowed): the synthesis pipeline's
/// sidecar-degradation / both-channels-failed / sidecar-splice-failure
/// payloads, the add path's `taiji.media.template_unsafe`, and the
/// close-out's `taiji.media.archive_duplicate` (the duplicate skip) +
/// `taiji.media.metadata_degraded` (the metadata-enhancement faces'
/// degrade) all publish here — an alarm is not a phase transition, so
/// the payload distinguishes the two faces by `warning: Some(...)`
/// (the current phase rides along for context). Payload codes are
/// **not** §14 RPC error codes (an alarm never fails a task).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaWarning {
    /// Canonical `taiji.media.*` code (`template_unsafe` among them).
    pub code: String,
    /// Redacted human text (the same discipline as error_msg).
    pub message: String,
}

/// Media extension event payload (the params[0] semantics of
/// [`MEDIA_PHASE_EVENT_METHOD`]): the gid, the phase the task entered
/// (the media phase domain), the pause phase-memory detail, and the
/// optional warning face. Bus topology mirrors the recovery bus
/// (broadcast(EVENT_BUS_CAPACITY), never blocks the publisher, lag ->
/// the rpc face disconnects).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaEvent {
    pub gid: Gid,
    pub phase: taiji_media::MediaPhase,
    /// The remembered phase when `phase` is Paused (§3.2 phase
    /// memory); otherwise None.
    pub phase_detail: Option<String>,
    /// The alarm face (see [`MediaWarning`]); None = a pure phase
    /// transition.
    pub warning: Option<MediaWarning>,
}

// ---- taiji.task.* extension event face ----

/// The task-cookie clear-on-error alert's single method name:
/// `taiji.task.cookiesClearedOnError` — the same bypass shape (the
/// `taiji.recovery*` / `taiji.media.phaseChanged` precedent):
/// **not** in the compat face swap, **not** in the
/// six-event table, `system.listNotifications` does not grow (the
/// freeze tests pin all three). One cross-family event covers the
/// http and media tasks alike; the payload carries gid / task_kind /
/// the cleared row count and **never a cookie value**.
pub const TASK_COOKIE_EVENT_METHOD: &str = "taiji.task.cookiesClearedOnError";

/// The task-cookie alert payload (the params[0] semantics of
/// [`TASK_COOKIE_EVENT_METHOD`]): which task's cookies were cleared at
/// the error terminal (the tightened cookie semantics — done and error
/// both clear; the error clear raises this alarm because the operator
/// may want to re-supply credentials before a retry), how many rows
/// went, and nothing else. Cookie values/names/domains never enter the
/// payload (the redact discipline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskCookieEvent {
    pub gid: Gid,
    /// `http`|`media` (the unified table's task_kind).
    pub task_kind: &'static str,
    /// Cookie rows cleared (a count only).
    pub count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use tokio::sync::broadcast;

    /// Structural anchor: ALL enumerates exactly the seven kinds (the
    /// name-face freeze test moved to the rpc adapter together with the
    /// word tables — this side pins only the kind set).
    #[test]
    fn event_kind_all_enumerates_the_seven_kinds() {
        assert_eq!(EventKind::ALL.len(), 7);
        // Exhaustive match over ALL: adding a variant without extending
        // ALL turns the count red; adding a variant at all breaks this
        // match at compile time.
        let mut http_ready = 0;
        for kind in EventKind::ALL {
            match kind {
                EventKind::HttpReady => http_ready += 1,
                EventKind::Start
                | EventKind::Pause
                | EventKind::Stop
                | EventKind::Complete
                | EventKind::Error
                | EventKind::BtComplete => {}
            }
        }
        assert_eq!(http_ready, 1, "HTTP output-ready extends the set once");
    }

    /// Multi-subscriber broadcast: every subscriber receives the full
    /// event set (cross-validation of the WS multi-session notify face
    /// — WebSocketSessionMan.cc pushes the same message to every
    /// session).
    #[tokio::test]
    async fn broadcast_reaches_every_subscriber() {
        let (tx, mut rx_a) = broadcast::channel::<SessionEvent>(EVENT_BUS_CAPACITY);
        let mut rx_b = tx.subscribe();
        let mut rx_c = tx.subscribe();
        let gid = Gid::from_u64(0x8000_0000_0000_0001);
        for (i, kind) in EventKind::ALL.into_iter().enumerate() {
            let sent = tx.send(SessionEvent { gid, kind });
            assert!(sent.is_ok(), "send {i} must reach >=1 subscriber");
        }
        for rx in [&mut rx_a, &mut rx_b, &mut rx_c] {
            let mut kinds = Vec::new();
            while let Ok(ev) = rx.try_recv() {
                assert_eq!(ev.gid, gid);
                kinds.push(ev.kind);
            }
            assert_eq!(kinds, EventKind::ALL.to_vec(), "every subscriber sees all");
        }
    }

    /// No subscribers = the send is dropped (notification semantics:
    /// with no WS session the bus idles silently — no error, no
    /// blocking, no caching).
    #[test]
    fn send_without_subscribers_is_silent_noop() {
        let (tx, _rx) = broadcast::channel::<SessionEvent>(EVENT_BUS_CAPACITY);
        // Dropping the only receiver zeroes the subscriber count.
        drop(_rx);
        let gid = Gid::from_u64(0x8000_0000_0000_0002);
        for kind in EventKind::ALL {
            let r = tx.send(SessionEvent { gid, kind });
            assert!(
                r.is_err(),
                "zero subscribers → SendError (dropped), got {r:?}"
            );
        }
    }

    /// Slow-subscriber injection: an unread subscriber that falls
    /// behind by more than the capacity receives `Lagged`, while the
    /// publisher is never blocked throughout (backpressure does not
    /// spill onto the engine — the bus half of the lag-acceptance
    /// criterion).
    #[tokio::test]
    async fn lagging_subscriber_never_blocks_publisher() {
        let (tx, mut slow) = broadcast::channel::<SessionEvent>(EVENT_BUS_CAPACITY);
        let gid = Gid::from_u64(0x8000_0000_0000_0003);
        // 2x capacity + slack: the slow reader never reads.
        // broadcast::send returns synchronously and never waits (a full
        // bus = the slowest subscriber lags; the non-blocking face).
        let total = EVENT_BUS_CAPACITY * 2 + 10;
        let t0 = Instant::now();
        for i in 0..total {
            let kind = EventKind::ALL[i % EventKind::ALL.len()];
            let sent = tx.send(SessionEvent { gid, kind });
            assert!(
                sent.is_ok(),
                "publish {i} must not block/drop while a subscriber lags: {sent:?}"
            );
        }
        let publish_elapsed = t0.elapsed();
        // Publishing is instantaneous (all synchronous sends succeed;
        // a 1s order-of-magnitude slack guards against CI jitter).
        assert!(
            publish_elapsed < Duration::from_secs(1),
            "publisher must never wait on the slow reader: {publish_elapsed:?}"
        );
        // The slow reader's first item = Lagged(n), n = the number of
        // overwritten entries (total - capacity).
        match slow.try_recv() {
            Err(broadcast::error::TryRecvError::Lagged(n)) => {
                assert_eq!(
                    n as usize,
                    total - EVENT_BUS_CAPACITY,
                    "lag count = messages overwritten while unread"
                );
            }
            other => panic!("slow reader must observe Lagged first, got {other:?}"),
        }
        // After Lag the slow reader can still drain the backlog (in
        // order, capacity entries).
        for i in total - EVENT_BUS_CAPACITY..total {
            let ev = slow
                .try_recv()
                .unwrap_or_else(|e| panic!("slow backlog {i}: {e}"));
            assert_eq!(ev.kind, EventKind::ALL[i % EventKind::ALL.len()]);
        }
        // After draining, the slow reader receives new events normally
        // (disconnect is an rpc-face policy; the bus itself stays
        // alive); a new (fast) subscriber loses nothing.
        let mut fast = tx.subscribe();
        let tail = [EventKind::Pause, EventKind::BtComplete];
        for kind in tail {
            tx.send(SessionEvent { gid, kind })
                .unwrap_or_else(|e| panic!("send: {e}"));
        }
        for kind in tail {
            let ev = fast.try_recv().unwrap_or_else(|e| panic!("fast recv: {e}"));
            assert_eq!(ev.kind, kind, "fast subscriber sees every event in order");
            let ev = slow.try_recv().unwrap_or_else(|e| panic!("slow recv: {e}"));
            assert_eq!(ev.kind, kind, "slow subscriber resumes after Lag");
        }
    }

    // ---- taiji.* extension event face ----

    /// Extension event name freeze (taiji.* namespace policy): the two
    /// event names are always taiji.* — only the six events have the
    /// compat dual face; extension events do not switch faces
    /// under `--rpc-aria2-compat`.
    #[test]
    fn recovery_notification_method_names_are_frozen() {
        let expect = [
            (RecoveryEventKind::Started, "taiji.recoveryStarted"),
            (RecoveryEventKind::Completed, "taiji.recoveryCompleted"),
        ];
        for (kind, name) in expect {
            assert_eq!(kind.notification_method(), name);
        }
        assert_eq!(
            RecoveryEventKind::ALL.len(),
            2,
            "extension event surface (two events)"
        );
        for kind in RecoveryEventKind::ALL {
            assert!(
                kind.notification_method().starts_with("taiji."),
                "new events must use the taiji.* namespace: {}",
                kind.notification_method()
            );
        }
    }

    /// The extension bus shares the six-event bus topology: multi-
    /// subscriber full delivery + silent idle with no subscribers (the
    /// bus half of "backpressure/lag-disconnect applies to the new
    /// events the same way"; the rpc disconnect half is covered by the
    /// server tests).
    #[test]
    fn recovery_bus_mirrors_six_event_bus_semantics() {
        let (tx, mut rx_a) = broadcast::channel::<RecoveryEvent>(EVENT_BUS_CAPACITY);
        let mut rx_b = tx.subscribe();
        let gid = Gid::from_u64(0x8000_0000_0000_0004);
        for (i, kind) in RecoveryEventKind::ALL.into_iter().enumerate() {
            let ev = RecoveryEvent {
                gid,
                kind,
                files: vec![(i + 1) as u32],
            };
            assert!(tx.send(ev).is_ok(), "send {i} must reach subscribers");
        }
        for rx in [&mut rx_a, &mut rx_b] {
            let mut kinds = Vec::new();
            while let Ok(ev) = rx.try_recv() {
                assert_eq!(ev.gid, gid);
                assert_eq!(ev.files, vec![kinds.len() as u32 + 1]);
                kinds.push(ev.kind);
            }
            assert_eq!(kinds, RecoveryEventKind::ALL.to_vec());
        }
        // All subscribers dropped -> the send is dropped (SendError,
        // same rule as the six-event bus).
        drop(rx_a);
        drop(rx_b);
        assert!(
            tx.send(RecoveryEvent {
                gid,
                kind: RecoveryEventKind::Started,
                files: vec![1]
            })
            .is_err()
        );
    }

    /// The extension bus backpressure follows the six-event bus rule:
    /// the publisher is never blocked, a subscriber behind by more than the
    /// capacity receives `Lagged(n)` first (n = overwritten
    /// entries) and resumes after draining (the bus half of
    /// "backpressure/lag-disconnect applies to the new events the same
    /// way"; disconnect is an rpc-face policy — see the
    /// [`crate::session::actor`] topology note and the server.rs
    /// recovery arm).
    #[test]
    fn recovery_bus_lagging_subscriber_never_blocks_publisher() {
        use std::time::Instant;
        let (tx, mut slow) = broadcast::channel::<RecoveryEvent>(EVENT_BUS_CAPACITY);
        let gid = Gid::from_u64(0x8000_0000_0000_0005);
        // 2x capacity + slack: the slow reader never reads.
        // broadcast::send returns synchronously and never waits (zero
        // publisher wait = the engine event path is never blocked; same
        // rule as the six events).
        let total = EVENT_BUS_CAPACITY * 2 + 10;
        let t0 = Instant::now();
        for i in 0..total {
            let kind = RecoveryEventKind::ALL[i % RecoveryEventKind::ALL.len()];
            let ev = RecoveryEvent {
                gid,
                kind,
                files: vec![(i % 3 + 1) as u32],
            };
            assert!(
                tx.send(ev).is_ok(),
                "publish {i} must not block while a subscriber lags"
            );
        }
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(1),
            "publisher must never wait on the slow reader"
        );
        // The slow reader's first item = Lagged(n), n = overwritten
        // entries (total - capacity).
        match slow.try_recv() {
            Err(broadcast::error::TryRecvError::Lagged(n)) => {
                assert_eq!(n as usize, total - EVENT_BUS_CAPACITY);
            }
            other => panic!("slow reader must observe Lagged first, got {other:?}"),
        }
        // After Lag the slow reader drains the backlog (in order,
        // capacity entries) and resumes receiving new events.
        for i in total - EVENT_BUS_CAPACITY..total {
            let ev = slow
                .try_recv()
                .unwrap_or_else(|e| panic!("slow backlog {i}: {e}"));
            assert_eq!(
                ev.kind,
                RecoveryEventKind::ALL[i % RecoveryEventKind::ALL.len()]
            );
        }
        let mut fast = tx.subscribe();
        let tail = [RecoveryEventKind::Started, RecoveryEventKind::Completed];
        for kind in tail {
            tx.send(RecoveryEvent {
                gid,
                kind,
                files: vec![1],
            })
            .unwrap_or_else(|e| panic!("send: {e}"));
        }
        for kind in tail {
            let ev = fast.try_recv().unwrap_or_else(|e| panic!("fast recv: {e}"));
            assert_eq!(ev.kind, kind, "fast subscriber sees every event in order");
            let ev = slow.try_recv().unwrap_or_else(|e| panic!("slow recv: {e}"));
            assert_eq!(ev.kind, kind, "slow subscriber resumes after Lag");
        }
    }

    // ---- taiji.media.* extension event face ----

    /// The event freeze: the media extension event exists **only** as
    /// `taiji.media.phaseChanged` — the kernel-side constant pin (the
    /// six-event-table / compat-face / listNotifications non-growth
    /// halves moved to the rpc adapter's registry lock together with
    /// the name tables).
    #[test]
    fn media_phase_event_name_is_frozen() {
        assert_eq!(MEDIA_PHASE_EVENT_METHOD, "taiji.media.phaseChanged");
        // Not a recovery extension name either.
        for kind in RecoveryEventKind::ALL {
            assert_ne!(kind.notification_method(), MEDIA_PHASE_EVENT_METHOD);
        }
    }

    /// The task-cookie alert rides the same single-name bypass — the
    /// kernel-side constant pin (the six-event-table halves moved to
    /// the rpc adapter's registry lock).
    #[test]
    fn task_cookie_event_name_is_frozen() {
        assert_eq!(TASK_COOKIE_EVENT_METHOD, "taiji.task.cookiesClearedOnError");
        assert_ne!(TASK_COOKIE_EVENT_METHOD, MEDIA_PHASE_EVENT_METHOD);
        for kind in RecoveryEventKind::ALL {
            assert_ne!(kind.notification_method(), TASK_COOKIE_EVENT_METHOD);
        }
    }

    /// The media bus mirrors the six-event/recovery bus topology:
    /// multi-subscriber full delivery, silent idle with no
    /// subscribers, and a never-blocked publisher while a subscriber
    /// lags (the rpc disconnect half lives in the server tests).
    #[tokio::test]
    async fn media_bus_mirrors_extension_bus_semantics() {
        let (tx, mut rx_a) = broadcast::channel::<MediaEvent>(EVENT_BUS_CAPACITY);
        let mut rx_b = tx.subscribe();
        let gid = Gid::from_u64(0x8000_0000_0000_0006);
        let ev = MediaEvent {
            gid,
            phase: taiji_media::MediaPhase::Processing,
            phase_detail: None,
            warning: Some(MediaWarning {
                code: "taiji.media.template_unsafe".into(),
                message: "leading-dash-prefixed".into(),
            }),
        };
        assert!(tx.send(ev.clone()).is_ok());
        for rx in [&mut rx_a, &mut rx_b] {
            assert_eq!(rx.try_recv().ok(), Some(ev.clone()));
        }
        // No subscribers → the send is dropped (SendError), never a
        // block.
        drop(rx_a);
        drop(rx_b);
        assert!(tx.send(ev).is_err());
        // The publisher never waits on a lagging subscriber.
        let (tx, mut slow) = broadcast::channel::<MediaEvent>(2);
        let t0 = std::time::Instant::now();
        for _ in 0..EVENT_BUS_CAPACITY * 2 {
            let ev = MediaEvent {
                gid,
                phase: taiji_media::MediaPhase::Verifying,
                phase_detail: None,
                warning: None,
            };
            assert!(tx.send(ev).is_ok(), "publisher must never block");
        }
        assert!(t0.elapsed() < std::time::Duration::from_secs(1));
        assert!(matches!(
            slow.try_recv(),
            Err(broadcast::error::TryRecvError::Lagged(_))
        ));
    }
}
