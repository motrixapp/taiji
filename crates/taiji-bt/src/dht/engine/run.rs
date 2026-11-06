//! Main loop: due maintenance -> transaction timeout sweep -> queue
//! refill (periodic then immediate) -> `tokio::select!` waiting for the
//! next event (command / inbound packet / wake deadline), plus every exit
//! path (Shutdown / handles dropped / inbound channel closed — each
//! halt-saves before exiting).
//!
//! Owns: the event junction and the wake-deadline computation (the
//! earlier of the maintenance timers and the transaction deadlines).
//! Does not own: the handling of each event (see the responsibility
//! modules).

use std::time::Instant;

use tracing::{info, warn};

use super::*;

/// Wake future: never ready when there is no timer.
async fn sleep_or_pending(wake: Option<Instant>) {
    match wake {
        Some(at) => tokio::time::sleep_until(at.into()).await,
        None => std::future::pending::<()>().await,
    }
}

/// Inbound batch cap (inbound hot path): after the select arm wakes on one
/// packet, the rest of the channel is drained synchronously up to this many
/// packets before the loop top re-runs maintenance, the timeout sweep, both
/// queue refills and the wake-deadline computation. At public-node packet
/// rates (~k/s) this amortizes the per-iteration bookkeeping (an O(transactions)
/// sweep scan + two queue scans + the deadline walk) across a batch instead
/// of paying it per packet; the cap bounds the deferral of commands and
/// timers to one batch of packets (tens of microseconds even on slow
/// emulated cores — far below any protocol timescale; per-packet handling
/// order inside the batch is unchanged). 64 matches a burst of DHT_CHANNEL_
/// CAPACITY-sized arrivals without letting a flood starve the command face.
const INBOUND_BATCH_MAX: usize = 64;

impl DhtEngine {
    pub(super) async fn run(mut self) {
        info!(
            target: LOG_TARGET,
            family = ?self.family,
            node_id = %hex_id(&self.local_id),
            port = self.dht_port,
            "dht engine up"
        );
        loop {
            // 1) Due maintenance (table-driven).
            let now = Instant::now();
            let fired = self.timers.fire_due(now);
            for kind in fired {
                self.run_maintenance(kind, now).await;
            }
            // 2) Transaction timeout sweep.
            self.sweep_timeouts(now).await;
            // 3) Queue refill (periodic then immediate, the reference
            // execution order).
            self.refill(QueueKind::Periodic, now).await;
            self.refill(QueueKind::Immediate, now).await;

            // 4) Wait for the next event (command / inbound packet / next
            // maintenance instant). The wake deadline is the earlier of
            // the maintenance timers and the transaction timeouts: a
            // maintenance-only deadline would put resends after packet
            // loss to sleep until the next inbound packet or 5min
            // maintenance point — bootstrap/lookups could not converge at
            // transaction-timeout pace (see
            // TransactionTable::next_deadline docs).
            let wake = [self.timers.next_wake(), self.txns.next_deadline()]
                .into_iter()
                .flatten()
                .min();
            tokio::select! {
                cmd = self.cmd_rx.recv() => match cmd {
                    Some(cmd) => {
                        if !self.handle_command(cmd, Instant::now()).await {
                            break;
                        }
                    }
                    None => {
                        // All handles dropped: save and exit (halt-save
                        // semantics).
                        self.emit_persist(Instant::now()).await;
                        break;
                    }
                },
                pkt = self.transport.inbound.recv() => match pkt {
                    Some(pkt) => {
                        // Batch drain: handle the woken packet plus any
                        // that queued behind it in this same iteration
                        // (same decision instant per batch — the per-source
                        // query limiter and the table both stay within one
                        // token-bucket/last-contact rounding step of the
                        // per-packet-clock shape).
                        let now = Instant::now();
                        self.handle_packet(pkt, now).await;
                        for _ in 1..INBOUND_BATCH_MAX {
                            match self.transport.inbound.try_recv() {
                                Ok(pkt) => self.handle_packet(pkt, now).await,
                                Err(_) => break,
                            }
                        }
                    }
                    None => {
                        // Inbound channel closed = the demux exited (socket
                        // closed); save and exit.
                        warn!(target: LOG_TARGET, "inbound channel closed; dht engine exiting");
                        self.emit_persist(Instant::now()).await;
                        break;
                    }
                },
                _ = sleep_or_pending(wake) => {}
            }
        }
        info!(target: LOG_TARGET, "dht engine down");
    }
}
