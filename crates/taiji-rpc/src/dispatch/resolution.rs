//! Native magnet timing projection. Compatibility task status remains unchanged.
use serde_json::{Value, json};
use taiji_core::magnet::{CacheOrigin, ResolutionMilestone, ResolutionSnapshot, ResolutionState};

pub(super) fn encode(snapshot: ResolutionSnapshot) -> Value {
    let milestones: serde_json::Map<String, Value> = snapshot
        .milestones
        .into_iter()
        .map(|(stage, millis)| {
            let name = match stage {
                ResolutionMilestone::Admitted => "admittedMs",
                ResolutionMilestone::FirstCandidate => "firstCandidateMs",
                ResolutionMilestone::FirstHandshake => "firstHandshakeMs",
                ResolutionMilestone::FirstInfoBlock => "firstInfoBlockMs",
                ResolutionMilestone::InfoVerified => "infoVerifiedMs",
                ResolutionMilestone::VerificationReady => "verificationReadyMs",
                ResolutionMilestone::MetadataReady => "metadataReadyMs",
                ResolutionMilestone::SelectionCommitted => "selectionCommittedMs",
            };
            (name.into(), json!(millis))
        })
        .collect();
    json!({
        "state": match snapshot.state {
            ResolutionState::Queued => "queued",
            ResolutionState::Resolving => "resolving",
            ResolutionState::Ready => "ready",
            ResolutionState::Paused => "paused",
            ResolutionState::Failed => "failed",
        },
        "attemptId": format!("{:016x}", snapshot.attempt_id),
        "revision": snapshot.revision,
        "elapsedMs": snapshot.elapsed_ms,
        "milestones": milestones,
        "cache": snapshot.cache.map(|source| match source {
            CacheOrigin::Memory => "memory",
            CacheOrigin::Persistent => "persistent",
        }),
    })
}
