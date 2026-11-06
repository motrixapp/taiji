//! MediaTask phase vocabulary (the media spec's task-phase domain): the
//! persisted `state` domain's single source + the phaseChanged event
//! payload basis.
//!
//! The persisted domain (no CHECK on the column — the domain is
//! anchored here): `queued|resolving|downloading|recording|processing|
//! verifying|finalizing|paused|error|done`. `recording`/`finalizing`
//! are the LIVE-only phases (0.4) — the enum carries them from
//! day one so the persisted domain never widens later (the
//! "comment value domain extended alongside" posture).
//!
//! Pause phase memory: a pause landing in Processing/Verifying
//! persists `state=paused` with the interrupted phase in
//! `phase_detail`; unpause resumes from the remembered phase
//! (Processing is an idempotent re-run — both channels' products are
//! cleaned, staging retained).

use crate::error::MediaError;

/// One media task's phase (`Paused`/`Error`/`Done`
/// are terminal-ish bookkeeping states, the rest are live phases).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum MediaPhase {
    #[default]
    Queued,
    Resolving,
    Downloading,
    /// LIVE only (0.4) — present in the domain, unreachable in
    /// the 0.3 pipeline.
    Recording,
    Processing,
    Verifying,
    /// LIVE graceful-stop finalization (0.4).
    Finalizing,
    Paused,
    Error,
    Done,
}

impl MediaPhase {
    /// The full phase set, table order (tests pin the frozen domain).
    pub const ALL: [MediaPhase; 10] = [
        MediaPhase::Queued,
        MediaPhase::Resolving,
        MediaPhase::Downloading,
        MediaPhase::Recording,
        MediaPhase::Processing,
        MediaPhase::Verifying,
        MediaPhase::Finalizing,
        MediaPhase::Paused,
        MediaPhase::Error,
        MediaPhase::Done,
    ];

    /// Persisted `state` string (the column domain's single source).
    pub fn as_str(self) -> &'static str {
        match self {
            MediaPhase::Queued => "queued",
            MediaPhase::Resolving => "resolving",
            MediaPhase::Downloading => "downloading",
            MediaPhase::Recording => "recording",
            MediaPhase::Processing => "processing",
            MediaPhase::Verifying => "verifying",
            MediaPhase::Finalizing => "finalizing",
            MediaPhase::Paused => "paused",
            MediaPhase::Error => "error",
            MediaPhase::Done => "done",
        }
    }

    /// Parse a persisted `state` value (round-trip with [`Self::as_str`];
    /// unknown strings are an explicit error — a hand-edited row never
    /// silently maps to a live phase).
    pub fn parse(s: &str) -> Result<MediaPhase, MediaError> {
        Ok(match s {
            "queued" => MediaPhase::Queued,
            "resolving" => MediaPhase::Resolving,
            "downloading" => MediaPhase::Downloading,
            "recording" => MediaPhase::Recording,
            "processing" => MediaPhase::Processing,
            "verifying" => MediaPhase::Verifying,
            "finalizing" => MediaPhase::Finalizing,
            "paused" => MediaPhase::Paused,
            "error" => MediaPhase::Error,
            "done" => MediaPhase::Done,
            other => {
                return Err(MediaError::Staging(format!(
                    "unknown media task state {other:?} (outside the phase domain)"
                )));
            }
        })
    }

    /// A live (non-bookkeeping) phase: the phases that carry
    /// phaseChanged transitions while the task runs.
    pub fn is_live(self) -> bool {
        matches!(
            self,
            MediaPhase::Resolving
                | MediaPhase::Downloading
                | MediaPhase::Recording
                | MediaPhase::Processing
                | MediaPhase::Verifying
                | MediaPhase::Finalizing
        )
    }

    /// The phases a pause may interrupt with phase memory
    /// (Processing/Verifying/Finalizing; a Downloading pause needs no
    /// memory — resume re-enters Downloading via the bitmap).
    pub fn pauses_with_memory(self) -> bool {
        matches!(
            self,
            MediaPhase::Processing | MediaPhase::Verifying | MediaPhase::Finalizing
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The persisted domain round-trips exactly and is frozen (the
    /// literal set — widening this list is a schema event, the
    /// state column has no CHECK by design).
    #[test]
    fn persisted_domain_round_trips_and_is_frozen() {
        const FROZEN: &[&str] = &[
            "queued",
            "resolving",
            "downloading",
            "recording",
            "processing",
            "verifying",
            "finalizing",
            "paused",
            "error",
            "done",
        ];
        assert_eq!(MediaPhase::ALL.len(), FROZEN.len());
        for (phase, want) in MediaPhase::ALL.into_iter().zip(FROZEN) {
            assert_eq!(phase.as_str(), *want);
            assert_eq!(MediaPhase::parse(want).ok(), Some(phase));
        }
        let err = MediaPhase::parse("Paused")
            .err()
            .unwrap_or_else(|| panic!("the domain is case-sensitive: Paused must not parse"));
        assert!(err.to_string().contains("unknown media task state"));
    }

    #[test]
    fn live_and_memory_classification() {
        for p in [
            MediaPhase::Resolving,
            MediaPhase::Downloading,
            MediaPhase::Recording,
            MediaPhase::Processing,
            MediaPhase::Verifying,
            MediaPhase::Finalizing,
        ] {
            assert!(p.is_live(), "{}", p.as_str());
        }
        for p in [
            MediaPhase::Queued,
            MediaPhase::Paused,
            MediaPhase::Error,
            MediaPhase::Done,
        ] {
            assert!(!p.is_live(), "{}", p.as_str());
        }
        // Phase-memory set: Processing/Verifying/Finalizing.
        assert!(MediaPhase::Processing.pauses_with_memory());
        assert!(MediaPhase::Verifying.pauses_with_memory());
        assert!(MediaPhase::Finalizing.pauses_with_memory());
        assert!(!MediaPhase::Downloading.pauses_with_memory());
    }
}
