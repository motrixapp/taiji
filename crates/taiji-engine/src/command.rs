//! Engine control command face: `EngineCommand`, `EngineHandle` (a
//! cheap-to-clone control handle) and the select-branch helper
//! `engine_command_recv`.
//!
//! Scope: the low-frequency control/query channel of a running engine;
//! command business decisions live in the run main-loop arms and the
//! query/tracker modules.

use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::sync::oneshot;

use taiji_store::persist::TrackerRow;

use taiji_domain::peer_guard::ManualBanRule;

use super::error::EngineError;
use crate::query::{EnginePeerSnapshot, EngineStatusSnapshot};
use crate::strategy::SchedulerPolicy;
/// Select-branch helper: with no control channel (`spawn`/`spawn_with`)
/// this stays pending forever and costs no polling (the uniform read
/// face for `Option<Receiver>` inside select).
pub(super) async fn engine_command_recv(
    rx: &mut Option<mpsc::Receiver<EngineCommand>>,
) -> Option<EngineCommand> {
    match rx {
        Some(rx) => match rx.recv().await {
            Some(cmd) => Some(cmd),
            // All EngineHandles dropped (command channel closed) => no
            // command can ever arrive again. Returning None here would
            // leave this arm always-ready under a biased select and spin
            // the main loop, starving every later arm — normalize to
            // forever-pending, the same semantics as "no control
            // channel".
            None => std::future::pending().await,
        },
        None => std::future::pending().await,
    }
}
/// Control commands from the session side to a **running** engine
/// (bounded 16, low frequency; a full channel backpressures the caller).
/// pause/remove go through the token hierarchy, not this channel.
#[non_exhaustive]
pub enum EngineCommand {
    /// Rebuild the tracker table (tier, url) — the global bt-tracker
    /// import hot-push plus the tracker edit face
    /// (taiji.addTracker/removeTracker): forwards
    /// `TrackerCommand::SetTrackers` to all face actors and rebuilds the
    /// shadow row set (new URL rows registered, removed URL rows gone).
    /// Empty table = remove all (legal for DHT/LSD-only tasks).
    SetTrackers {
        tiers: Vec<(usize, String)>,
        reply: oneshot::Sender<()>,
    },
    /// tellStatus live snapshot query.
    QueryStatus {
        reply: oneshot::Sender<EngineStatusSnapshot>,
    },
    /// getPeers snapshot query.
    QueryPeers {
        /// Bitfield materialization switch: false = skip packing the
        /// bitfield (the snapshot only counts / decides the seeder face,
        /// saving an N/8×P-byte transient); the aria2 getPeers face
        /// always passes true (protocol fields unchanged).
        want_bitfield: bool,
        reply: oneshot::Sender<Vec<EnginePeerSnapshot>>,
    },
    /// getServers tracker table snapshot query (union of the shadow row
    /// set).
    QueryTrackers {
        reply: oneshot::Sender<Vec<TrackerRow>>,
    },
    /// BEP53 select-file application face: the selected file indexes the
    /// session sends right after spawn (0-based = client file list order
    /// = non-pad entry order within the layout; BEP53 "Files are
    /// zero-indexed"). The engine projects them onto its own layout as a
    /// flat piece mask — a piece is selected when its byte range
    /// intersects any selected file's range (under piece-granularity
    /// download semantics, cross-file pieces are fetched whole); false
    /// pieces are not dispatched, not counted complete, and v2 lazy
    /// fetching never triggers — selecting 1/2 of the files lands only
    /// the selection. Out-of-range indexes / empty selection = Err
    /// (explicit failure, never silently ignored).
    SetFileSelection {
        files: Arc<[u32]>,
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// File multi-level priority application face (capability parity with
    /// libtorrent `torrent_handle::prioritize_files` any-time
    /// semantics). `priority` = client file index (0-based non-pad
    /// order) -> level (-1 skip / 0 normal / 1..7 high). The engine
    /// projects it via [`crate::dispatch::priority_mask`] and replaces
    /// the piece-level table wholesale — this only affects **subsequent**
    /// selection order (priority descending as the primary key ahead of
    /// rarity), never completion counts / in-flight bookkeeping (the
    /// skip face is still expressed by the SetFileSelection mask; the
    /// two commands are issued in pairs under the session-side
    /// mutual-consistency rules). Out-of-range indexes / empty table /
    /// level out of domain = Err (explicit failure).
    SetFilePriority {
        priority: Arc<[(u32, i8)]>,
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// ut_holepunch runtime switch (internal config face; enabled by
    /// default — libtorrent has no separate switch, it follows extension
    /// negotiation). Loaded via the config_json chain: the session sends
    /// it right after spawn. Effective face = **new-connection** assembly
    /// (existing connections keep their negotiated state for the
    /// connection's lifetime); off = new connections neither advertise
    /// nor consume ut_holepunch.
    SetHolepunch {
        enabled: bool,
        reply: oneshot::Sender<()>,
    },
    /// Ban face full push: client identity rules (`client_ban_prefixes`) +
    /// manual ban ranges (the engine-effective face of
    /// `taiji.banAddr`). Full replacement (not incremental — session-side
    /// bookkeeping is the source of truth; idempotent replays are
    /// harmless) -> snapshot hot update -> online connections hitting an
    /// unexpired manual range are disconnected immediately. Low frequency
    /// over the bounded command channel (on activation + on config
    /// change).
    SetBanConfig {
        client_deny: Vec<String>,
        manual: Vec<ManualBanRule>,
        reply: oneshot::Sender<()>,
    },
    /// Scheduler policy runtime switch: the engine's single-writer loop
    /// atomically replaces the whole piece-selection policy object
    /// (lock-free; the policy object lives in EngineLoop state). default
    /// = [`SchedulerPolicy::RarestFirst`] = the port, unchanged;
    /// Sequential remains unimplemented (rejected by the
    /// [`SchedulerPolicy::is_supported`] checks on both the session and
    /// engine sides, with an explicit Err). A switch only affects
    /// subsequent selection decisions — in-flight requests / re-fetch
    /// queues / claim bookkeeping are policy-independent and are not
    /// cleared on switch.
    SetSchedulerPolicy {
        policy: SchedulerPolicy,
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Stream-while-downloading playhead push: `file` = client file
    /// order (non-pad entry order, same anchor as BEP53), `position` =
    /// byte offset within the file, `bytes_per_sec` = playback bitrate
    /// (None = default tier). After validation (out-of-range file /
    /// position = explicit Err) the engine replaces the playhead runtime
    /// state; **advancing = calling again** (idempotent replacement). The
    /// playhead only influences selection while the policy is streaming
    /// (combined switch = setSchedulerPolicy(streaming) + this command,
    /// in either order — the policy face does not consume it and the
    /// command face does not check the current policy); not persisted
    /// (runtime state; the caller replays it after a restart).
    SetStreamingPlayhead {
        file: u32,
        position: u64,
        bytes_per_sec: Option<u64>,
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// disk_tier live face (the engine-effective face of
    /// taiji.setDiskTier): pushes the disk protection policy at runtime.
    /// Forwarded over a watch single-value channel to every store
    /// pipeline (one per face); the pipelines shift gears live: IoGate
    /// ops quota, flush cadence and write-coalescing window take effect
    /// immediately. **prealloc/falloc allocation methods only affect new
    /// allocations** (an existing task's files were allocated at pipeline
    /// build time and are not re-allocated while running — noted in the
    /// RPC docs too). watch = single-value bounded channel (a new value
    /// overwrites the old, no backlog — a low-frequency config face with
    /// no backpressure risk).
    SetDiskPolicy {
        policy: taiji_store::disk_policy::DiskPolicy,
        reply: oneshot::Sender<()>,
    },
    /// Live reading: reports the disk policy **actually in effect** in
    /// the store pipeline (the atomic reading
    /// [`taiji_store::disk_policy::LivePolicy`] written after pipeline
    /// application — not a config mirror; the live-application assertion
    /// face).
    QueryDiskPolicy {
        reply: oneshot::Sender<taiji_store::disk_policy::LivePolicy>,
    },
    /// DHT runtime enable/disable (a hot switch; counterpart to
    /// libtorrent `apply_settings(enable_dht)` runtime effect plus
    /// flipping the per-torrent `torrent_flags::disable_dht` flag).
    /// Enable = warming up each family's cold wiring (DHT engine spawn +
    /// handshake DHT bit + attach slots + **immediate announce
    /// registration** — the stalled-task revival path); disable =
    /// halt-save then tear down the wiring. Enable on a private engine =
    /// Err (BEP27 hard gate, `torrent.cpp` priv() cannot be overridden);
    /// idempotent (repeating the same state = Ok). Err text = the reason
    /// (the caller's warn face).
    SetDhtEnabled {
        enabled: bool,
        reply: oneshot::Sender<Result<(), String>>,
    },
}

// Hand-written `Debug`: every variant's `reply` oneshot::Sender endpoint is
// redacted (an opaque channel handle with no debug value; the payload
// fields are the surface), signaled by the trailing `.. ` of
// `finish_non_exhaustive`.
impl std::fmt::Debug for EngineCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SetTrackers { tiers, .. } => f
                .debug_struct("SetTrackers")
                .field("tiers", tiers)
                .finish_non_exhaustive(),
            Self::QueryStatus { .. } => f.debug_struct("QueryStatus").finish_non_exhaustive(),
            Self::QueryPeers { want_bitfield, .. } => f
                .debug_struct("QueryPeers")
                .field("want_bitfield", want_bitfield)
                .finish_non_exhaustive(),
            Self::QueryTrackers { .. } => f.debug_struct("QueryTrackers").finish_non_exhaustive(),
            Self::SetFileSelection { files, .. } => f
                .debug_struct("SetFileSelection")
                .field("files", files)
                .finish_non_exhaustive(),
            Self::SetFilePriority { priority, .. } => f
                .debug_struct("SetFilePriority")
                .field("priority", priority)
                .finish_non_exhaustive(),
            Self::SetHolepunch { enabled, .. } => f
                .debug_struct("SetHolepunch")
                .field("enabled", enabled)
                .finish_non_exhaustive(),
            Self::SetBanConfig {
                client_deny,
                manual,
                ..
            } => f
                .debug_struct("SetBanConfig")
                .field("client_deny", client_deny)
                .field("manual", manual)
                .finish_non_exhaustive(),
            Self::SetSchedulerPolicy { policy, .. } => f
                .debug_struct("SetSchedulerPolicy")
                .field("policy", policy)
                .finish_non_exhaustive(),
            Self::SetStreamingPlayhead {
                file,
                position,
                bytes_per_sec,
                ..
            } => f
                .debug_struct("SetStreamingPlayhead")
                .field("file", file)
                .field("position", position)
                .field("bytes_per_sec", bytes_per_sec)
                .finish_non_exhaustive(),
            Self::SetDiskPolicy { policy, .. } => f
                .debug_struct("SetDiskPolicy")
                .field("policy", policy)
                .finish_non_exhaustive(),
            Self::QueryDiskPolicy { .. } => {
                f.debug_struct("QueryDiskPolicy").finish_non_exhaustive()
            }
            Self::SetDhtEnabled { enabled, .. } => f
                .debug_struct("SetDhtEnabled")
                .field("enabled", enabled)
                .finish_non_exhaustive(),
        }
    }
}

/// Control handle for
/// [`crate::run::DownloadEngine::spawn_controlled::spawn_controlled`]
/// (cheap to clone).
#[derive(Clone, Debug)]
pub struct EngineHandle {
    pub(super) cmd_tx: mpsc::Sender<EngineCommand>,
}

impl EngineHandle {
    /// Rebuild the tracker table and wait for the engine side to accept
    /// it (after the actor acks all entries).
    ///
    /// # Errors
    ///
    /// [`EngineError::EngineClosed`]: the engine main loop has exited (the
    /// command channel is closed), or the command arm dropped the reply
    /// before answering.
    pub async fn set_trackers(&self, tiers: Vec<(usize, String)>) -> Result<(), EngineError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(EngineCommand::SetTrackers { tiers, reply: tx })
            .await
            .map_err(|_| EngineError::EngineClosed)?;
        rx.await.map_err(|_| EngineError::EngineClosed)
    }

    /// tellStatus live snapshot.
    ///
    /// # Errors
    ///
    /// [`EngineError::EngineClosed`]: the engine main loop has exited (the
    /// command channel is closed), or the command arm dropped the reply
    /// before answering.
    pub async fn query_status(&self) -> Result<EngineStatusSnapshot, EngineError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(EngineCommand::QueryStatus { reply: tx })
            .await
            .map_err(|_| EngineError::EngineClosed)?;
        rx.await.map_err(|_| EngineError::EngineClosed)
    }

    /// getPeers snapshot, full face: the per-peer bitfield **is**
    /// packed (the aria2 getPeers protocol face — see the
    /// [`EngineCommand::QueryPeers`] variant docs). The reading-count /
    /// seeder-face-only variant is [`Self::query_peers_summary`].
    ///
    /// # Errors
    ///
    /// [`EngineError::EngineClosed`]: the engine main loop has exited (the
    /// command channel is closed), or the command arm dropped the reply
    /// before answering.
    pub async fn query_peers(&self) -> Result<Vec<EnginePeerSnapshot>, EngineError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(EngineCommand::QueryPeers {
                want_bitfield: true,
                reply: tx,
            })
            .await
            .map_err(|_| EngineError::EngineClosed)?;
        rx.await.map_err(|_| EngineError::EngineClosed)
    }

    /// getPeers snapshot, summary face: the bitfield is **not** packed
    /// (the snapshot only counts / decides the seeder face, saving an
    /// N/8×P-byte transient — see the [`EngineCommand::QueryPeers`]
    /// variant docs).
    ///
    /// # Errors
    ///
    /// [`EngineError::EngineClosed`]: the engine main loop has exited (the
    /// command channel is closed), or the command arm dropped the reply
    /// before answering.
    pub async fn query_peers_summary(&self) -> Result<Vec<EnginePeerSnapshot>, EngineError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(EngineCommand::QueryPeers {
                want_bitfield: false,
                reply: tx,
            })
            .await
            .map_err(|_| EngineError::EngineClosed)?;
        rx.await.map_err(|_| EngineError::EngineClosed)
    }

    /// getServers tracker table snapshot.
    ///
    /// # Errors
    ///
    /// [`EngineError::EngineClosed`]: the engine main loop has exited (the
    /// command channel is closed), or the command arm dropped the reply
    /// before answering.
    pub async fn query_trackers(&self) -> Result<Vec<TrackerRow>, EngineError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(EngineCommand::QueryTrackers { reply: tx })
            .await
            .map_err(|_| EngineError::EngineClosed)?;
        rx.await.map_err(|_| EngineError::EngineClosed)
    }

    /// BEP53 select-file file-index push. **Call immediately after
    /// activation**: the engine consumes this command before
    /// announce/discovery connections are established (ahead of
    /// dispatch, within the bounded command channel); effective face =
    /// dispatch / completion counting / v2 lazy fetching. Out-of-range
    /// indexes / empty selection = Err (explicit failure on the caller
    /// side, never silently ignored).
    ///
    /// # Errors
    ///
    /// - [`EngineError::EngineClosed`]: the engine main loop has exited (the
    ///   command channel is closed), or the command arm dropped the reply
    ///   before answering.
    /// - [`EngineError::Failed`]: engine-side validation rejected the
    ///   selection (an out-of-range file index or an empty selection); the
    ///   message is the rejection reason verbatim.
    pub async fn set_file_selection(&self, files: Arc<[u32]>) -> Result<(), EngineError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(EngineCommand::SetFileSelection { files, reply: tx })
            .await
            .map_err(|_| EngineError::EngineClosed)?;
        rx.await
            .map_err(|_| EngineError::EngineClosed)?
            .map_err(EngineError::failed)
    }

    /// File multi-level priority push: same channel timing as
    /// [`Self::set_file_selection`] (immediately after spawn / any time
    /// over RPC live); after engine-side validation and projection the
    /// piece-level table is replaced wholesale. Out-of-range indexes /
    /// empty table / level out of domain = Err.
    ///
    /// # Errors
    ///
    /// - [`EngineError::EngineClosed`]: the engine main loop has exited (the
    ///   command channel is closed), or the command arm dropped the reply
    ///   before answering.
    /// - [`EngineError::Failed`]: engine-side validation rejected the table
    ///   (an out-of-range file index, an empty table, or a level outside
    ///   -1..=7); the message is the rejection reason verbatim.
    pub async fn set_file_priority(&self, priority: Arc<[(u32, i8)]>) -> Result<(), EngineError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(EngineCommand::SetFilePriority {
                priority,
                reply: tx,
            })
            .await
            .map_err(|_| EngineError::EngineClosed)?;
        rx.await
            .map_err(|_| EngineError::EngineClosed)?
            .map_err(EngineError::failed)
    }

    /// ut_holepunch runtime enable (paired with [`Self::disable_holepunch`];
    /// enabled by default — only the disable path needs to call that).
    /// Effective face = new-connection assembly (see
    /// [`EngineCommand::SetHolepunch`]).
    ///
    /// # Errors
    ///
    /// [`EngineError::EngineClosed`]: the engine main loop has exited (the
    /// command channel is closed), or the command arm dropped the reply
    /// before answering.
    pub async fn enable_holepunch(&self) -> Result<(), EngineError> {
        self.set_holepunch_switch(true).await
    }

    /// ut_holepunch runtime disable: new connections neither advertise
    /// nor consume ut_holepunch (existing connections keep their
    /// negotiated state; see [`EngineCommand::SetHolepunch`]).
    ///
    /// # Errors
    ///
    /// [`EngineError::EngineClosed`]: the engine main loop has exited (the
    /// command channel is closed), or the command arm dropped the reply
    /// before answering.
    pub async fn disable_holepunch(&self) -> Result<(), EngineError> {
        self.set_holepunch_switch(false).await
    }

    /// Shared send path of the holepunch pair (the variant field keeps
    /// the named `enabled` fact; the pair exists so no call site passes
    /// a positional bool).
    async fn set_holepunch_switch(&self, enabled: bool) -> Result<(), EngineError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(EngineCommand::SetHolepunch { enabled, reply: tx })
            .await
            .map_err(|_| EngineError::EngineClosed)?;
        rx.await.map_err(|_| EngineError::EngineClosed)
    }

    /// Ban face full push ([`EngineCommand::SetBanConfig`]): identity
    /// rules + manual ban ranges replaced wholesale, waiting for the
    /// engine's hot-update confirmation.
    ///
    /// # Errors
    ///
    /// [`EngineError::EngineClosed`]: the engine main loop has exited (the
    /// command channel is closed), or the command arm dropped the reply
    /// before answering.
    pub async fn set_ban_config(
        &self,
        client_deny: Vec<String>,
        manual: Vec<ManualBanRule>,
    ) -> Result<(), EngineError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(EngineCommand::SetBanConfig {
                client_deny,
                manual,
                reply: tx,
            })
            .await
            .map_err(|_| EngineError::EngineClosed)?;
        rx.await.map_err(|_| EngineError::EngineClosed)
    }

    /// Scheduler policy switch ([`EngineCommand::SetSchedulerPolicy`]):
    /// waits for the engine's atomic policy-object swap receipt;
    /// unsupported / unimplemented policy = Err (explicit failure, no
    /// silent fallback).
    ///
    /// # Errors
    ///
    /// - [`EngineError::EngineClosed`]: the engine main loop has exited (the
    ///   command channel is closed), or the command arm dropped the reply
    ///   before answering.
    /// - [`EngineError::Failed`]: the engine rejected the policy as
    ///   unsupported / unimplemented ([`SchedulerPolicy::is_supported`] is
    ///   false, e.g. the Sequential face); the message is the rejection
    ///   reason verbatim.
    pub async fn set_scheduler_policy(&self, policy: SchedulerPolicy) -> Result<(), EngineError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(EngineCommand::SetSchedulerPolicy { policy, reply: tx })
            .await
            .map_err(|_| EngineError::EngineClosed)?;
        rx.await
            .map_err(|_| EngineError::EngineClosed)?
            .map_err(EngineError::failed)
    }

    /// Stream-while-downloading playhead push
    /// ([`EngineCommand::SetStreamingPlayhead`]): out-of-range file /
    /// position = Err (explicit failure); advancing = calling again. The
    /// playhead only influences selection under the streaming policy.
    ///
    /// # Errors
    ///
    /// - [`EngineError::EngineClosed`]: the engine main loop has exited (the
    ///   command channel is closed), or the command arm dropped the reply
    ///   before answering.
    /// - [`EngineError::Failed`]: engine-side validation rejected the
    ///   playhead (an out-of-range file index or a position past the file's
    ///   length); the message is the rejection reason verbatim.
    pub async fn set_streaming_playhead(
        &self,
        file: u32,
        position: u64,
        bytes_per_sec: Option<u64>,
    ) -> Result<(), EngineError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(EngineCommand::SetStreamingPlayhead {
                file,
                position,
                bytes_per_sec,
                reply: tx,
            })
            .await
            .map_err(|_| EngineError::EngineClosed)?;
        rx.await
            .map_err(|_| EngineError::EngineClosed)?
            .map_err(EngineError::failed)
    }

    /// Disk policy live push ([`EngineCommand::SetDiskPolicy`]): all
    /// store pipelines shift gears live (IoGate quota / flush cadence /
    /// write-coalescing window); allocation methods only affect new
    /// allocations (see the command docs).
    ///
    /// # Errors
    ///
    /// [`EngineError::EngineClosed`]: the engine main loop has exited (the
    /// command channel is closed), or the command arm dropped the reply
    /// before answering.
    pub async fn set_disk_policy(
        &self,
        policy: taiji_store::disk_policy::DiskPolicy,
    ) -> Result<(), EngineError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(EngineCommand::SetDiskPolicy { policy, reply: tx })
            .await
            .map_err(|_| EngineError::EngineClosed)?;
        rx.await.map_err(|_| EngineError::EngineClosed)
    }

    /// Disk policy live reading ([`EngineCommand::QueryDiskPolicy`]):
    /// the value actually in effect in the store pipeline (not a config
    /// mirror).
    ///
    /// # Errors
    ///
    /// [`EngineError::EngineClosed`]: the engine main loop has exited (the
    /// command channel is closed), or the command arm dropped the reply
    /// before answering.
    pub async fn query_disk_policy(
        &self,
    ) -> Result<taiji_store::disk_policy::LivePolicy, EngineError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(EngineCommand::QueryDiskPolicy { reply: tx })
            .await
            .map_err(|_| EngineError::EngineClosed)?;
        rx.await.map_err(|_| EngineError::EngineClosed)
    }

    /// DHT runtime enable (paired with [`Self::disable_dht`]): enabling
    /// DHT on a private engine / a dead engine = Err (the caller's warn
    /// face), otherwise Ok.
    ///
    /// # Errors
    ///
    /// - [`EngineError::EngineClosed`]: the engine main loop has exited (the
    ///   command channel is closed), or the command arm dropped the reply
    ///   before answering.
    /// - [`EngineError::Failed`]: enabling DHT on a private (BEP 27) engine
    ///   — the hard gate cannot be overridden; the message is the rejection
    ///   reason verbatim.
    pub async fn enable_dht(&self) -> Result<(), EngineError> {
        self.set_dht_switch(true).await
    }

    /// DHT runtime disable (paired with [`Self::enable_dht`]): unwires
    /// the discovery faces; disabling is always Ok (the hard gate only
    /// guards the enable direction).
    ///
    /// # Errors
    ///
    /// [`EngineError::EngineClosed`]: the engine main loop has exited (the
    /// command channel is closed), or the command arm dropped the reply
    /// before answering.
    pub async fn disable_dht(&self) -> Result<(), EngineError> {
        self.set_dht_switch(false).await
    }

    /// Shared send path of the DHT pair (the variant field keeps the
    /// named `enabled` fact; the pair exists so no call site passes a
    /// positional bool).
    async fn set_dht_switch(&self, enabled: bool) -> Result<(), EngineError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(EngineCommand::SetDhtEnabled { enabled, reply: tx })
            .await
            .map_err(|_| EngineError::EngineClosed)?;
        match rx.await.map_err(|_| EngineError::EngineClosed)? {
            Ok(()) => Ok(()),
            Err(reason) => Err(EngineError::failed(reason)),
        }
    }
}
