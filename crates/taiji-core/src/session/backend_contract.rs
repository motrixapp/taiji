//! BackendContract — the explicit per-family statement of what each
//! task-backend family puts behind the four surfaces a SessionActor
//! task consumes: the live-read surface, the row persistence
//! surface, the control surface, and — as a first-class field — the
//! verification position (WHERE data integrity is decided).
//!
//! This module is a statement of record, not a runtime detour: the
//! actor keeps matching on `TaskBackend` directly (zero behavior
//! change by design — rewriting the actor is out of scope). The
//! consumers are this crate's tests (the three pinned verification
//! positions + the family mapping) and the new-family project cards
//! named in the onboarding checklist below (ed2k / iroh); hence the
//! module-level dead_code allow.
//!
//! The contract is the stated face of the actor's private
//! `TaskBackend` enum (session/actor/mod.rs): the enum stays the
//! runtime shape — four variants, three families (the Metadata
//! variant is the BT family's magnet-metadata phase, swapping into
//! Engine at the upgrade notice) — while the contract states each
//! family's surfaces explicitly, closing the protocol map's
//! third-family split condition ("BT channel mode + HTTP
//! atomic-snapshot mode" were two implicit precedents; the third
//! family's arrival turns them into one explicit artifact).
//!
//! # Verification positions (the three pinned values)
//!
//! 1. BT = verify-before-disk: no byte reaches the data files before
//! verification passes (the `taiji-store` verified pipeline,
//! store/src/verified.rs — a failed or unverified piece is dropped
//! and refetched, never written).
//! 2. HTTP = atomic snapshot: no protocol-level content hash;
//! integrity = the fsync-before-bitmap-snapshot discipline (a
//! power-loss bitmap never runs ahead of the data; the
//! session::http snapshot pipeline) plus the
//! "file exists + accumulated chunk size match" second line of
//! defense on recovery.
//! 3. Media = segment-boundary accounting + synthesis-time final
//! ruling: media segments carry no protocol-level hash; integrity
//! = segment-boundary bookkeeping (seg_len / media_sequence
//! reconciliation) + TLS transport integrity, with the
//! synthesis-time probe as the final ruling (the Verifying
//! phase's probe assertions).
//!
//! # New-family onboarding checklist (protocol-extension map,
//! governance principle, verbatim: verification location is a
//! first-class contract field; capabilities are a new protocol's
//! doorplate; a new protocol's onboarding card must include the
//! "substrate reuse checklist" item)
//!
//! A new task family's project card (ed2k / iroh are the named
//! candidates) must carry all three items:
//!
//! 1. **substrate reuse checklist** — which of the five crossing
//! layers the family reuses vs builds (L1 identity/GID/queue,
//! L2 source discovery, L3 transport/sub-scheduling (swarm- vs
//! segment-shaped), L4 verification/storage, L5
//! observation/control);
//! 2. **capabilities doorplate** — the family's capability set
//! declared at the capabilities registration face (the
//! `taiji_core::engine` CapabilitiesView consumed by the rpc
//! `taiji.capabilities` reply). Deliberately NOT a field here:
//! the doorplate is an engine/RPC registration concern, not a
//! per-task runtime surface — the contract keeps the four fields
//! above;
//! 3. **verification-position declaration** — which
//! [`VerificationPosition`] value the family pins (a value
//! outside the three pinned ones — e.g. a self-verifying
//! transport such as Iroh's per-chunk BLAKE3 stream — is a
//! decision-record matter: new enum variant + this contract's
//! tests extended).

// Statement-of-record face: consumed by this crate's tests and the
// future family cards (ed2k/iroh), not by lib-runtime code paths (the
// actor keeps its direct TaskBackend matches — zero behavior change).
#![allow(dead_code)]

/// The family key: which [`BackendContract`] applies. Three families
/// across the four `TaskBackend` variants (Metadata is the BT
/// family's magnet-metadata phase).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TaskFamily {
    /// BT: torrent tasks + the magnet metadata phase.
    Bittorrent,
    /// HTTP(S)/FTP/SFTP direct-link tasks (the segment-grid family).
    Http,
    /// Media tasks (the third family).
    Media,
}

/// WHERE the family's data integrity is verified — the first-class
/// contract field (the protocol map's key two: a one-shot contract
/// design for admitting any self-verifying protocol). Exactly three
/// pinned values; see the module doc for each family's statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VerificationPosition {
    /// verify-before-disk (BT): no byte reaches disk before
    /// verification passes (taiji-store/src/verified.rs).
    VerifyBeforeDisk,
    /// atomic snapshot (HTTP): fsync the task file before the bitmap
    /// snapshot lands + the "file exists + accumulated chunk size
    /// match" second line of defense on recovery.
    AtomicSnapshot,
    /// segment-boundary accounting + synthesis-time final ruling
    /// (media): seg_len/media_sequence reconciliation +
    /// TLS transport integrity, with the synthesis-time probe as the
    /// final verdict.
    SegmentBoundaryAccounting,
}

/// The live-read surface: where tellStatus live readings come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LiveSurface {
    /// The engine query seam (EngineStatusSnapshot behind the
    /// actor-side status cache, STATUS_CACHE_TTL). The BT family's
    /// magnet-metadata phase has no engine yet — honest zero (the
    /// aria2 metadata-group shape).
    EngineQuerySeam,
    /// The HTTP driver's lock-free atomics (http_task::HttpLive —
    /// the tellStatus `http` sub-dictionary's data source).
    DriverAtomics,
    /// The media pipeline's small-mutex rollup
    /// (session::media::MediaLiveState; reads never span await).
    PipelineRollup,
}

/// The row persistence surface: how the family's progress rows reach
/// the store (all families serialize through the single
/// PersistWriter).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RowSurface {
    /// The engine's own pipeline (watch barrier → upsert; terminal
    /// transitions fsync the data files before the terminal row —
    /// the fsync-before-terminal-row discipline).
    EnginePipeline,
    /// The HTTP driver's row mirror (HttpTaskRow) landed through the
    /// session http snapshot pipeline (fsync-before-snapshot + 2s
    /// debounce); the remove tombstone reads the mirror.
    DriverRowMirror,
    /// The media pipeline's own persist face (media_task/media_format
    /// row lifecycle inside the pipeline).
    PipelinePersistFace,
}

/// The control surface: how pause/remove/control reach the backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ControlSurface {
    /// The engine handle (pause/changeUri/...) + the per-task
    /// CancellationToken (forceRemove = abort). The BT family's
    /// metadata phase: token only (a fetch task has no engine to
    /// abort).
    EngineHandleAndToken,
    /// The per-task CancellationToken + the pause cancel-source flag
    /// (the driver teardown distinguishes the paused/resume row
    /// states; forceRemove = abort).
    TokenAndPauseFlag,
}

/// The per-family backend contract: the four surfaces a SessionActor
/// task consumes, stated explicitly (the convergence face of the
/// actor's `TaskBackend` enum — the enum stays the runtime shape,
/// zero behavior change).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BackendContract {
    /// Live-read surface (tellStatus live readings).
    pub(crate) live: LiveSurface,
    /// Row persistence surface (progress rows → store).
    pub(crate) persist: RowSurface,
    /// Control surface (pause/remove/control).
    pub(crate) control: ControlSurface,
    /// Verification position — first-class: where data integrity is
    /// decided (see [`VerificationPosition`]).
    pub(crate) verification: VerificationPosition,
}

impl BackendContract {
    /// The BT family: Engine + Metadata variants (the magnet phase).
    pub(crate) const BITTORRENT: BackendContract = BackendContract {
        live: LiveSurface::EngineQuerySeam,
        persist: RowSurface::EnginePipeline,
        control: ControlSurface::EngineHandleAndToken,
        verification: VerificationPosition::VerifyBeforeDisk,
    };

    /// The HTTP family: the Http variant (driver trio).
    pub(crate) const HTTP: BackendContract = BackendContract {
        live: LiveSurface::DriverAtomics,
        persist: RowSurface::DriverRowMirror,
        control: ControlSurface::TokenAndPauseFlag,
        verification: VerificationPosition::AtomicSnapshot,
    };

    /// The media family: the Media variant (the third family).
    pub(crate) const MEDIA: BackendContract = BackendContract {
        live: LiveSurface::PipelineRollup,
        persist: RowSurface::PipelinePersistFace,
        control: ControlSurface::TokenAndPauseFlag,
        verification: VerificationPosition::SegmentBoundaryAccounting,
    };

    /// The contract for a family (exhaustive; a new family = a new
    /// const + the onboarding checklist of the module doc).
    pub(crate) const fn for_family(family: TaskFamily) -> BackendContract {
        match family {
            TaskFamily::Bittorrent => BackendContract::BITTORRENT,
            TaskFamily::Http => BackendContract::HTTP,
            TaskFamily::Media => BackendContract::MEDIA,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BT pins verify-before-disk (the taiji-store verified
    /// pipeline: no byte reaches disk before verification passes).
    #[test]
    fn bt_family_pins_verify_before_disk() {
        let c = BackendContract::for_family(TaskFamily::Bittorrent);
        assert_eq!(c.verification, VerificationPosition::VerifyBeforeDisk);
        // The full four-surface statement for the BT family.
        assert_eq!(c.live, LiveSurface::EngineQuerySeam);
        assert_eq!(c.persist, RowSurface::EnginePipeline);
        assert_eq!(c.control, ControlSurface::EngineHandleAndToken);
        assert_eq!(c, BackendContract::BITTORRENT);
    }

    /// HTTP pins the atomic-snapshot position (fsync-before-snapshot
    /// + the "file exists + size" second line on recovery).
    #[test]
    fn http_family_pins_atomic_snapshot() {
        let c = BackendContract::for_family(TaskFamily::Http);
        assert_eq!(c.verification, VerificationPosition::AtomicSnapshot);
        assert_eq!(c.live, LiveSurface::DriverAtomics);
        assert_eq!(c.persist, RowSurface::DriverRowMirror);
        assert_eq!(c.control, ControlSurface::TokenAndPauseFlag);
        assert_eq!(c, BackendContract::HTTP);
    }

    /// Media pins segment-boundary accounting + the synthesis-time
    /// final ruling (seg_len/media_sequence reconciliation + TLS
    /// transport integrity; the probe verdict).
    #[test]
    fn media_family_pins_segment_boundary_accounting() {
        let c = BackendContract::for_family(TaskFamily::Media);
        assert_eq!(
            c.verification,
            VerificationPosition::SegmentBoundaryAccounting
        );
        assert_eq!(c.live, LiveSurface::PipelineRollup);
        assert_eq!(c.persist, RowSurface::PipelinePersistFace);
        assert_eq!(c.control, ControlSurface::TokenAndPauseFlag);
        assert_eq!(c, BackendContract::MEDIA);
    }

    /// Three families, three distinct verification positions (the
    /// pinned three-value enum is the record — the ledger caliber that
    /// closes the "first non-BT value" wording of the media spec).
    #[test]
    fn three_families_three_verification_positions() {
        let positions = [
            BackendContract::for_family(TaskFamily::Bittorrent).verification,
            BackendContract::for_family(TaskFamily::Http).verification,
            BackendContract::for_family(TaskFamily::Media).verification,
        ];
        // Pairwise distinct: exactly the three pinned values.
        assert_ne!(positions[0], positions[1]);
        assert_ne!(positions[0], positions[2]);
        assert_ne!(positions[1], positions[2]);
        // Every stated position is one of the pinned variants (no
        // family carries an unstated position).
        for p in positions {
            assert!(matches!(
                p,
                VerificationPosition::VerifyBeforeDisk
                    | VerificationPosition::AtomicSnapshot
                    | VerificationPosition::SegmentBoundaryAccounting
            ));
        }
    }
}
