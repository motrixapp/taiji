//! Periodic task summary logging (the `--summary-interval` feed;
//! reference = aria2's `--summary-interval` periodic readings output,
//! prefs.cc / the progress summary line shape).
//!
//! Owns: the periodic INFO summary of active tasks (gid/speed/progress/
//! connection count).
//! Does not own: the option acceptance face (options.rs) and the ticker
//! rhythm (the run() select arm — paced by
//! `interval_at(now + period)`, the first summary one period in, 0 =
//! disabled and the arm is not assembled).
//!
//! # Reference alignment and divergence
//!
//! - Name/default/domain cross-validated against aria2 (prefs.cc;
//! OptionHandlerFactory.cc default "60", domain 0..INT32_MAX, 0 =
//! disabled — pinned by the options.rs cross-validation tests);
//! - carrier difference (deliberate): aria2 prints periodic summaries
//! to the console reading face; there is no console reading here, so
//! the summary = a tracing INFO event (target `taiji::core::summary`,
//! the `taiji::<crate>::<module>` shape) — equally visible to
//! frontends / file logs;
//! - frequency discipline: periods with no active tasks emit no events
//! (zero noise; aria2's idle readings share the silence orientation);
//! - capability alignment with the reference: changeOption/
//! changeGlobalOption do not accept it (options.rs
//! `apply_global_patch` has no such arm; a startup-time option,
//! effective after restart).

use tracing::info;

use super::*;

/// The single-task summary line format (the golden anchor — format
/// changes must explicitly update this function's unit test). Byte
/// fields are decimal integers (machine-parseable first; aria2's
/// console human abbreviations do not enter the structured log face),
/// progress carries an accurate percentage (`--` when total = 0).
pub(crate) fn summary_line(
    gid: &Gid,
    down_bps: u64,
    up_bps: u64,
    completed: u64,
    total: u64,
    connections: u64,
) -> String {
    let pct = match (completed * 100).checked_div(total) {
        Some(p) => format!("{p}%"),
        None => "--".to_string(), // total = 0 (metadata phase / unknown total)
    };
    format!(
        "gid={gid} DL={down_bps}B/s UL={up_bps}B/s done={completed}/{total}({pct}) cn={connections}"
    )
}

impl SessionActor {
    /// Emit one periodic summary: one INFO event per active task
    /// (structured fields + the [`summary_line`] text). No active tasks
    /// = emit nothing (the frequency discipline).
    ///
    /// Reading source = the same seam as live_status_view (BT: the
    /// engine `query_status` snapshot — read through the per-engine
    /// status snapshot cache seam, zero engine round-trips within the
    /// TTL; an engine-exit race falls back to the honest base-zero
    /// face; HTTP: HttpLive's atomic synchronous read, not occupying
    /// the command channel). A 60s default period x low-frequency
    /// queries = no pressure on the engine command channel.
    /// `&mut self`: the cache seam backfills on expiry/absence (the
    /// invalidation face = the TaskNotice event arm).
    pub(super) async fn emit_summary(&mut self) {
        // Member caliber (deliberate, pinned by
        // `summary_caliber_download_pool_only_under_mixed_load`): the
        // download pool's active set only. Seeding/checking/synthesis
        // observation rides the tell* projections and the getGlobalStat
        // extension keys — never the periodic summary lines (no
        // four-pool expansion).
        let active = self.queue.summary_gids();
        if active.is_empty() {
            return;
        }
        for gid in active {
            let view = self.live_status_view(gid).await;
            let line = summary_line(
                &gid,
                view.download_speed,
                view.upload_speed,
                view.completed_length,
                view.total_length,
                view.connections,
            );
            info!(
                target: "taiji::core::summary",
                gid = %gid,
                down_bps = view.download_speed,
                up_bps = view.upload_speed,
                completed = view.completed_length,
                total = view.total_length,
                connections = view.connections,
                "{line}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Gid, summary_line};

    /// Summary line golden (the format anchor): field order =
    /// gid/DL/UL/done/pct/cn; the zero-rate/zero-progress and real
    /// progress shapes; total = 0 (the metadata phase) renders the
    /// accurate `--` percentage.
    #[test]
    fn summary_line_golden() {
        let g = Gid::from_u64(0x8000_0000_0000_0001);
        assert_eq!(
            summary_line(&g, 1_572_864, 0, 12_582_912, 104_857_600, 4),
            "gid=8000000000000001 DL=1572864B/s UL=0B/s done=12582912/104857600(12%) cn=4"
        );
        // The honest zero face (an unupgraded magnet / an early engine
        // death — aria2's metadata-phase readings are also zero).
        assert_eq!(
            summary_line(&g, 0, 0, 0, 0, 0),
            "gid=8000000000000001 DL=0B/s UL=0B/s done=0/0(--) cn=0"
        );
        // The completed state: 100%.
        assert_eq!(
            summary_line(&g, 0, 4096, 100, 100, 1),
            "gid=8000000000000001 DL=0B/s UL=4096B/s done=100/100(100%) cn=1"
        );
    }
}
