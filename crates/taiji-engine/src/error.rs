//! Error type for the engine command face (owned by the engine
//! subtree).
//!
//! Invariant: variant semantics and Display strings are **verbatim
//! identical** to the corresponding `session::SessionError` arms —
//! engine-handle errors originally surfaced through the session error
//! face in logs/RPC; after decoupling, the session side's
//! `From<EngineError> for SessionError` maps per variant, so both
//! sides' literals must evolve in sync (a new variant = added in both
//! places), keeping the error-code mapping and the `match`
//! classification at zero drift.

/// [`EngineHandle`](super::command::EngineHandle) command-face error
/// (the send/recv channel face + the engine-side validation-rejection
/// face).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EngineError {
    /// Command channel closed: the engine main loop exited after all
    /// handles dropped (send failure), or the command arm died before
    /// answering (oneshot reply recv failure). The Display string
    /// shares a single source with
    /// `session::SessionError::SessionClosed` (the RPC string code
    /// `taiji.session.closed`) — the engine side mirrors the same
    /// literal so the session-side `%e` logs and the error mapping stay
    /// at zero drift.
    #[error("taiji.session.closed")]
    EngineClosed,
    /// Task-level explicit failure: an engine-side validation rejection
    /// (out-of-range file / empty selection / outside the tier domain /
    /// unimplemented scheduler policy / private-DHT hard gate etc.);
    /// the message comes verbatim from the validation point. Display =
    /// the message as-is (the same shape as the corresponding session
    /// arm; the caller's warn/panic text passes straight through).
    #[error("{message}")]
    Failed { message: String },
}

impl EngineError {
    /// Constructor shortcut for [`EngineError::Failed`] (the same shape
    /// as the session side's `SessionError::failed` — the
    /// rejection-reason text passes straight through, no re-wrapping).
    pub fn failed(message: impl Into<String>) -> Self {
        EngineError::Failed {
            message: message.into(),
        }
    }
}
