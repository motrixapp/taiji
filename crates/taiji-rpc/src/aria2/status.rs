//! Status word tables — the single render point of every status-shaped
//! field on the aria2 v1 wire surface.
//!
//! One table per kernel enum: exhaustive `match` + a frozen literal
//! test per table (a new variant breaks the match at compile time; a
//! drifted word breaks the test). Kernel enums carry no wire strings
//! (rule R2) — deleting this whole module leaves the kernel compiling
//! (the excision check pins that).
//!
//! `MediaView.phase`/`phaseDetail` are **passthrough, not a second
//! table**: their value domain is the kernel canonical table
//! `taiji_media::MediaPhase::as_str`/`parse` (the persisted media
//! phase vocabulary, consumed kernel-side by core `session::media`,
//! `actor::views`, and `taiji-media`'s own drivers). The adapter
//! renders those fields verbatim; building a second word table here
//! would fork that vocabulary (the single-source rule).
//!
//! Upstream anchor mapping: docs/design/rpc.md

use taiji_core::session::{
    BanSource, HttpOutputPhase, HttpSourceState, MediaTrackState, RecoveryStatus, ServerStatus,
    StatusKind, UriStatus,
};

/// The task-status word table (RpcMethodImpl.cc VLB_* constants; the
/// value-domain anchor test below migrated from core `session::view`).
pub(crate) fn status_word(kind: StatusKind) -> &'static str {
    match kind {
        StatusKind::Active => "active",
        StatusKind::Waiting => "waiting",
        StatusKind::Paused => "paused",
        StatusKind::Error => "error",
        StatusKind::Complete => "complete",
        StatusKind::Removed => "removed",
        StatusKind::Seeding => "seeding",
        StatusKind::Checking => "checking",
    }
}

/// `taiji.getHttpOutput`'s closed-output lifecycle words (the enum
/// stays core-side; this is the only render point).
pub(crate) fn http_output_phase_word(phase: HttpOutputPhase) -> &'static str {
    match phase {
        HttpOutputPhase::Downloading => "downloading",
        HttpOutputPhase::Ready => "ready",
        HttpOutputPhase::Publishing => "publishing",
        HttpOutputPhase::Published => "published",
    }
}

/// getUris words (createUriEntry, RpcMethodImpl.cc: used = spent,
/// waiting = pending).
pub(crate) fn uri_status_word(status: UriStatus) -> &'static str {
    match status {
        UriStatus::Used => "used",
        UriStatus::Waiting => "waiting",
    }
}

/// The `http.sources[].state` words (the taiji extension sub-dict's
/// own domain — active/waiting driven by the worker, demoted/removed
/// the source ledger, failed the probe/merge eviction).
pub(crate) fn source_state_word(state: HttpSourceState) -> &'static str {
    match state {
        HttpSourceState::Active => "active",
        HttpSourceState::Waiting => "waiting",
        HttpSourceState::Demoted => "demoted",
        HttpSourceState::Removed => "removed",
        HttpSourceState::Failed => "failed",
    }
}

/// getServers words (the aria2 server domain: working/error/waiting/
/// disabled). The kernel-side fold that decides *which* of these a
/// source or tracker projects is L2 (`http_source_server_status` /
/// the tracker-row synthesis); this table only renders.
pub(crate) fn server_status_word(status: ServerStatus) -> &'static str {
    match status {
        ServerStatus::Working => "working",
        ServerStatus::Error => "error",
        ServerStatus::Waiting => "waiting",
        ServerStatus::Disabled => "disabled",
    }
}

/// getFiles `recoveryStatus` words + the recovery-completed event
/// payload's `status` slot (both faces render through this one table —
/// the event payload is handler output too).
pub(crate) fn recovery_status_word(status: RecoveryStatus) -> &'static str {
    match status {
        RecoveryStatus::LayerMissing => "layer_missing",
        RecoveryStatus::Recovering => "recovering",
        RecoveryStatus::Ready => "ready",
    }
}

/// The media sub-dict's per-track words (active/degraded/failed/done —
/// a per-track liveness concept, distinct from the task-phase domain).
pub(crate) fn track_state_word(state: MediaTrackState) -> &'static str {
    match state {
        MediaTrackState::Active => "active",
        MediaTrackState::Degraded => "degraded",
        MediaTrackState::Failed => "failed",
        MediaTrackState::Done => "done",
    }
}

/// listBans source words (auto/manual/client-ban).
pub(crate) fn ban_source_word(source: BanSource) -> &'static str {
    match source {
        BanSource::Auto => "auto",
        BanSource::Manual => "manual",
        BanSource::ClientBan => "client-ban",
    }
}

/// The `/metrics taiji_torrents` label set (the six base states; the
/// seeded/checking extensions are row-state words, not metric labels).
/// Rendering goes through [`status_word`] — the label vocabulary and
/// the wire vocabulary share one table (no second handwritten list).
pub(crate) const METRICS_STATES: [StatusKind; 6] = [
    StatusKind::Active,
    StatusKind::Waiting,
    StatusKind::Paused,
    StatusKind::Complete,
    StatusKind::Error,
    StatusKind::Removed,
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The StatusKind value-domain anchor (migrated from core
    /// `session::view`): exactly eight variants — the aria2 six
    /// (active/waiting/paused/error/complete/removed) plus the one
    /// extension ('seeding') and the row-state shared 'checking'. A new
    /// variant breaks the exhaustive match at compile time; a drifted
    /// word or a duplicate word turns this red.
    #[test]
    fn status_kind_variant_set_and_wire_strings_anchor() {
        let all: [(StatusKind, &str); 8] = [
            (StatusKind::Active, "active"),
            (StatusKind::Waiting, "waiting"),
            (StatusKind::Paused, "paused"),
            (StatusKind::Error, "error"),
            (StatusKind::Complete, "complete"),
            (StatusKind::Removed, "removed"),
            (StatusKind::Seeding, "seeding"),
            (StatusKind::Checking, "checking"),
        ];
        for (kind, wire) in all {
            assert_eq!(status_word(kind), wire, "wire-string drift: {wire}");
        }
        let mut words: Vec<&str> = all.iter().map(|(_, w)| *w).collect();
        words.sort();
        let total = words.len();
        words.dedup();
        assert_eq!(words.len(), total, "duplicate wire strings");
    }

    #[test]
    fn http_output_phase_words_are_frozen() {
        assert_eq!(
            http_output_phase_word(HttpOutputPhase::Downloading),
            "downloading"
        );
        assert_eq!(http_output_phase_word(HttpOutputPhase::Ready), "ready");
        assert_eq!(
            http_output_phase_word(HttpOutputPhase::Publishing),
            "publishing"
        );
        assert_eq!(
            http_output_phase_word(HttpOutputPhase::Published),
            "published"
        );
    }

    #[test]
    fn uri_status_words_are_frozen() {
        assert_eq!(uri_status_word(UriStatus::Used), "used");
        assert_eq!(uri_status_word(UriStatus::Waiting), "waiting");
    }

    #[test]
    fn source_state_words_are_frozen() {
        let all: [(HttpSourceState, &str); 5] = [
            (HttpSourceState::Active, "active"),
            (HttpSourceState::Waiting, "waiting"),
            (HttpSourceState::Demoted, "demoted"),
            (HttpSourceState::Removed, "removed"),
            (HttpSourceState::Failed, "failed"),
        ];
        for (state, wire) in all {
            assert_eq!(source_state_word(state), wire, "drift: {wire}");
        }
    }

    #[test]
    fn server_status_words_are_frozen() {
        let all: [(ServerStatus, &str); 4] = [
            (ServerStatus::Working, "working"),
            (ServerStatus::Error, "error"),
            (ServerStatus::Waiting, "waiting"),
            (ServerStatus::Disabled, "disabled"),
        ];
        for (status, wire) in all {
            assert_eq!(server_status_word(status), wire, "drift: {wire}");
        }
    }

    #[test]
    fn recovery_status_words_are_frozen() {
        let all: [(RecoveryStatus, &str); 3] = [
            (RecoveryStatus::LayerMissing, "layer_missing"),
            (RecoveryStatus::Recovering, "recovering"),
            (RecoveryStatus::Ready, "ready"),
        ];
        for (status, wire) in all {
            assert_eq!(recovery_status_word(status), wire, "drift: {wire}");
        }
    }

    #[test]
    fn track_state_words_are_frozen() {
        let all: [(MediaTrackState, &str); 4] = [
            (MediaTrackState::Active, "active"),
            (MediaTrackState::Degraded, "degraded"),
            (MediaTrackState::Failed, "failed"),
            (MediaTrackState::Done, "done"),
        ];
        for (state, wire) in all {
            assert_eq!(track_state_word(state), wire, "drift: {wire}");
        }
    }

    #[test]
    fn ban_source_words_are_frozen() {
        assert_eq!(ban_source_word(BanSource::Auto), "auto");
        assert_eq!(ban_source_word(BanSource::Manual), "manual");
        assert_eq!(ban_source_word(BanSource::ClientBan), "client-ban");
    }

    /// The metrics label set is a subset of the wire table and shares
    /// its render point (the six base words; seeded/checking are absent).
    #[test]
    fn metrics_states_render_through_the_wire_table() {
        let words: Vec<&str> = METRICS_STATES.iter().map(|k| status_word(*k)).collect();
        assert_eq!(
            words,
            vec![
                "active", "waiting", "paused", "complete", "error", "removed"
            ],
            "the metrics labels are the six base wire words"
        );
    }
}
