//! TorrentTask skeleton: the single-torrent orchestration state
//! machine (SPEC §7.1).
//!
//! **Skeleton**: this module holds only the state enum, the legal
//! transition table, and shutdown propagation; the actual
//! download/seed orchestration (owning the PieceStore/HashTreeCache/
//! RequestBook views) is not faked here.
//!
//! Concurrency discipline:
//! - TorrentTask exclusively owns its state (no shared locks);
//! - subtasks (PeerTask/TrackerTask/...) are managed via
//! `tokio::task::JoinSet`; shutdown propagates through the
//! `CancellationToken` child-token hierarchy (Session -> Torrent ->
//! Peer);
//! - control commands use `mpsc::channel(16)`: commands are
//! low-frequency; a full channel backpressures the caller; unbounded
//! is banned.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use taiji_bt::peer::{PeerConfig, PeerTask};

/// TorrentTask's teardown drain timeout share (total budget 1s; see
/// SPEC §3.2).
const DRAIN_TIMEOUT: Duration = Duration::from_millis(500);

/// TorrentTask state machine (SPEC §7.1; the transition graph is in
/// [`legal_transition`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorrentState {
    /// Queued (not started).
    Queued,
    /// magnet: waiting for ut_metadata metadata.
    MetadataPending,
    /// Recheck (skippable).
    Checking,
    /// Preallocation (trunc/falloc).
    Allocating,
    /// Downloading.
    Downloading,
    /// Seeding.
    Seeding,
    /// Done (the normal terminal state).
    Done,
    /// Stopping (shutdown/remove path).
    Stopping,
    /// User-paused (unpause returns to the queue front, SPEC §7.2).
    Paused,
    /// Errored (the GID keeps its result, SPEC §7.1).
    Error,
}

/// Whether a state transition is legal (the SPEC §7.1 transition graph;
/// `Paused -> Queued` comes from §7.2 "pause -> return to the queue
/// front + persist the state").
///
/// Skeleton-stage table: `Checking` is skippable (recheck can be
/// skipped -> the predecessor reaches `Allocating` directly); all
/// active states can enter `Stopping` (remove/shutdown is reachable at
/// any time).
pub fn legal_transition(from: TorrentState, to: TorrentState) -> bool {
    use TorrentState::*;
    matches!(
        (from, to),
        (Queued, MetadataPending)
            | (Queued, Checking)
            | (Queued, Allocating)
            | (MetadataPending, Checking)
            | (MetadataPending, Allocating)
            | (Checking, Allocating)
            | (Allocating, Downloading)
            | (Downloading, Seeding)
            | (Seeding, Downloading)
            | (Downloading, Done)
            | (Seeding, Done)
            | (Queued, Stopping)
            | (MetadataPending, Stopping)
            | (Checking, Stopping)
            | (Allocating, Stopping)
            | (Downloading, Stopping)
            | (Seeding, Stopping)
            | (Paused, Stopping)
            | (Downloading, Paused)
            | (Seeding, Paused)
            | (Paused, Queued)
            | (Queued, Error)
            | (MetadataPending, Error)
            | (Checking, Error)
            | (Allocating, Error)
            | (Downloading, Error)
            | (Seeding, Error)
    )
}

/// Control commands the upper layer sends to TorrentTask.
///
/// The skeleton stage has only `Shutdown`; pause/unpause/priority and
/// the like extend later.
#[derive(Debug)]
pub enum TorrentCommand {
    Shutdown,
}

/// TorrentTask skeleton: the state machine only logs transitions (SPEC
/// §7.1); subtask slots are managed by [`tokio::task::JoinSet`].
///
/// Flow: [`TorrentTask::new`] constructs -> (during wiring:
/// [`TorrentTask::spawn_peer`] spawns subtasks) -> [`TorrentTask::spawn`]
/// starts the main loop.
pub struct TorrentTask {
    gid: crate::gid::Gid,
    state: TorrentState,
    cmd_tx: mpsc::Sender<TorrentCommand>,
    cmd_rx: mpsc::Receiver<TorrentCommand>,
    /// TorrentTask's lifetime token: derived from the Session's token;
    /// child tokens derive further for PeerTask etc., realizing the
    /// Session -> Torrent -> Peer shutdown propagation.
    token: CancellationToken,
    children: tokio::task::JoinSet<()>,
}

/// The control handle of a [`TorrentTask`].
pub struct TorrentHandle {
    pub(crate) cmd_tx: mpsc::Sender<TorrentCommand>,
    // SessionActor's queue now drives the DownloadEngine directly
    // (session/actor.rs); this skeleton remains only for test
    // consumption (the Session->Torrent->Peer propagation-chain
    // evidence is kept).
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "skeleton join handle, read only by the chain tests"
        )
    )]
    pub(crate) join: tokio::task::JoinHandle<()>,
}

impl TorrentHandle {
    /// Request a graceful stop (idempotent; shutdown is dual-channel:
    /// command + token hierarchy — either one triggers the teardown
    /// path).
    pub fn shutdown(&self) {
        let _ = self.cmd_tx.try_send(TorrentCommand::Shutdown);
    }
}

impl TorrentTask {
    /// Construct a skeleton task: initial `Queued`; the main loop only
    /// handles commands and shutdown.
    pub fn new(gid: crate::gid::Gid, parent: &CancellationToken) -> Self {
        // Capacity 16: control commands are low-frequency; a full
        // channel = backpressure (unbounded banned).
        let (cmd_tx, cmd_rx) = mpsc::channel::<TorrentCommand>(16);
        TorrentTask {
            gid,
            state: TorrentState::Queued,
            cmd_tx,
            cmd_rx,
            token: parent.child_token(),
            children: tokio::task::JoinSet::new(),
        }
    }

    /// Spawn an idling PeerTask subtask (the skeleton wiring point; the
    /// real PeerTask constructor args — connection, TorrentShared,
    /// request bookkeeping views — arrive with the peer wire; peers are
    /// then spawned dynamically by the message loop per connection
    /// rather than by external calls).
    ///
    /// Returns a receiver for the peer's exit so shutdown
    /// propagation-chain tests can observe it.
    pub fn spawn_peer<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        &mut self,
        socket: S,
        config: PeerConfig,
    ) -> tokio::sync::oneshot::Receiver<()> {
        let (_handle, peer_join, _data_rx) = PeerTask::spawn(&self.token, socket, config);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        // The wrapper task stays in children for shutdown_routine's
        // drain; after the peer finishes it notifies the caller via the
        // oneshot (JoinSet::spawn only returns an AbortHandle, which
        // cannot be awaited).
        self.children.spawn(async move {
            let _ = peer_join.await;
            let _ = done_tx.send(());
        });
        done_rx
    }

    /// State transition: legality check + log (the skeleton's only
    /// behavior; an illegal transition does not panic — the actor
    /// boundary is the failure boundary; log a warn and still apply the
    /// transition for observability).
    fn transition(&mut self, next: TorrentState) {
        if !legal_transition(self.state, next) {
            warn!(
                target: "taiji::core::torrent",
                gid = %self.gid, from = ?self.state, to = ?next,
                "illegal state transition (skeleton table; see SPEC §7.1)"
            );
        }
        debug!(target: "taiji::core::torrent", gid = %self.gid, from = ?self.state, to = ?next, "torrent state: transition");
        self.state = next;
    }

    /// Start the main-loop task. The JoinHandle is exposed via
    /// `TorrentHandle::join` (pub(crate)).
    pub fn spawn(mut self) -> TorrentHandle {
        let cmd_tx = self.cmd_tx.clone();
        let join = tokio::spawn(async move {
            self.run().await;
        });
        TorrentHandle { cmd_tx, join }
    }

    async fn run(&mut self) {
        info!(target: "taiji::core::torrent", gid = %self.gid, "torrent task skeleton up (state machine logs only; see PLAN M0 W2-W3)");
        // Skeleton: TorrentCommand has only Shutdown (no continuation
        // commands), so a single select suffices; the message loop
        // returns when the command face (pause/unpause etc.) extends.
        tokio::select! {
            biased;
            _ = self.token.cancelled() => {}
            cmd = self.cmd_rx.recv() => match cmd {
                Some(TorrentCommand::Shutdown) | None => {}
            },
        }
        self.shutdown_routine().await;
    }

    /// Teardown: Stopping -> cancel the child token -> drain subtasks
    /// (<= [`DRAIN_TIMEOUT`]).
    async fn shutdown_routine(&mut self) {
        self.transition(TorrentState::Stopping);
        self.token.cancel();
        let children = std::mem::take(&mut self.children);
        let _ = tokio::time::timeout(DRAIN_TIMEOUT, children.join_all()).await;
        info!(target: "taiji::core::torrent", gid = %self.gid, "torrent task skeleton exited");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gid::GidAllocator;
    use std::time::Instant;

    fn gid() -> crate::gid::Gid {
        GidAllocator::new().allocate()
    }

    #[test]
    fn spec_transition_graph_accepts_happy_path() {
        use TorrentState::*;
        // The SPEC §7.1 main chain: Queued -> MetadataPending? ->
        // Checking -> Allocating -> Downloading <=> Seeding -> Done.
        for (from, to) in [
            (Queued, MetadataPending),
            (MetadataPending, Checking),
            (Checking, Allocating),
            (Allocating, Downloading),
            (Downloading, Seeding),
            (Seeding, Downloading),
            (Downloading, Done),
        ] {
            assert!(
                legal_transition(from, to),
                "{from:?} → {to:?} must be legal"
            );
        }
    }

    #[test]
    fn spec_transition_graph_rejects_terminal_reentry() {
        use TorrentState::*;
        for (from, to) in [(Done, Downloading), (Error, Downloading), (Done, Seeding)] {
            assert!(
                !legal_transition(from, to),
                "{from:?} → {to:?} must be illegal"
            );
        }
    }

    #[test]
    fn checking_may_be_skipped_and_paused_returns_to_queue() {
        use TorrentState::*;
        // Recheck is skippable; unpause returns to the queue front
        // (SPEC §7.2).
        assert!(legal_transition(Queued, Allocating));
        assert!(legal_transition(MetadataPending, Allocating));
        assert!(legal_transition(Paused, Queued));
        assert!(!legal_transition(Queued, Downloading));
    }

    #[tokio::test]
    async fn torrent_exits_within_budget_on_session_token_cancel() {
        let root = CancellationToken::new();
        let handle = TorrentTask::new(gid(), &root).spawn();

        let t0 = Instant::now();
        root.cancel();
        let TorrentHandle { join, cmd_tx } = handle;
        let joined = tokio::time::timeout(Duration::from_secs(1), join).await;
        assert!(
            joined.is_ok(),
            "torrent must exit within 1s shutdown budget"
        );
        assert!(t0.elapsed() < Duration::from_secs(1), "{:?}", t0.elapsed());
        // Idempotent: after exit the command channel is closed; the
        // failed try_send is swallowed.
        assert!(cmd_tx.try_send(TorrentCommand::Shutdown).is_err());
    }

    #[tokio::test]
    async fn shutdown_token_cancel_propagates_root_to_peer_within_budget() {
        // Measured propagation chain: root(Session) -> torrent -> peer,
        // all exiting within 1s.
        let root = CancellationToken::new();
        let mut torrent = TorrentTask::new(gid(), &root);
        let (local, _remote) = tokio::io::duplex(1024);
        let peer_done = torrent.spawn_peer(local, PeerConfig::flat());
        let TorrentHandle {
            join: torrent_join, ..
        } = torrent.spawn();

        let t0 = Instant::now();
        root.cancel();
        let (peer, t) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(1), peer_done),
            tokio::time::timeout(Duration::from_secs(1), torrent_join),
        );
        assert!(peer.is_ok(), "peer must exit within 1s");
        assert!(t.is_ok(), "torrent must exit within 1s");
        assert!(t0.elapsed() < Duration::from_secs(1), "{:?}", t0.elapsed());
    }

    #[tokio::test]
    async fn shutdown_command_reaches_peer_via_handle() {
        // The explicit Shutdown command path (SessionActor ->
        // TorrentTask command channel).
        let root = CancellationToken::new();
        let mut torrent = TorrentTask::new(gid(), &root);
        let (local, _remote) = tokio::io::duplex(1024);
        let peer_done = torrent.spawn_peer(local, PeerConfig::flat());
        let handle = torrent.spawn();

        handle.shutdown();
        let TorrentHandle {
            join: torrent_join, ..
        } = handle;
        let (peer, t) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(1), peer_done),
            tokio::time::timeout(Duration::from_secs(1), torrent_join),
        );
        assert!(peer.is_ok(), "peer must exit via command path");
        assert!(t.is_ok(), "torrent must exit via command path");
    }
}
