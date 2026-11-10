    // taiji-engine unit/integration suite: choke wiring, advertisement-aware
    // dispatch and spread, multi-piece supply, endgame gates and last-mile
    // fan-out, the two-phase in-flight ledger, stall/churn levers, progress
    // restore, PEX bookkeeping, and BEP53 selection masks. Mechanism notes
    // and upstream anchors live in docs/design/engine.md.
    use super::*;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use taiji_bt::choke::{LeecherChoke, SeederChoke};
    use taiji_bt::peer::PeerTaskHandle;
    use taiji_bt::peer_wire::Reserved;
    use taiji_bt::piece_id::Addressing;
    use taiji_bt::piece_stat::PieceStatMan;

    use taiji_store::layout::Layout;
    use taiji_store::merkle;

    use tokio::sync::{mpsc, oneshot};

    use tokio_util::sync::CancellationToken;

    use crate::ban::{BanBook, SmartBanLedger, client_v_deny_check, client_violation};
    use crate::choke::{budget_derived_slots, choke_round, leecher_choke_round, preemptive_unchoke};
    use crate::dispatch::{BlockState, ClaimedSet, DISPATCH_REISSUE_WINDOW, DispatchReply, ENDGAME_MAX_COPIES, NO_OWNER, PieceIssueCtx, PieceSentLedger, REISSUE_WINDOW_CEIL, STORE_PENDING_GUARD, checkout_occupancy, checkout_weight, dispatch_face, dispatch_face_selected, dispatch_face_selected_with_stream, drain_dispatch_replies_core, endgame_busy_admitted, endgame_busy_admitted_dispatch, endgame_busy_admitted_tiered, endgame_cursor_pick, endgame_fast_tier, endgame_inflight_copies, endgame_lastmile_active, endgame_lastmile_copies_limit, endgame_lastmile_peer_order, endgame_peer_busy_pieces, endgame_peer_inflight, endgame_peer_order, endgame_piece_holders, endgame_piece_holders_face, endgame_piece_overdue, endgame_tail_active, endgame_tail_window_floor, endgame_triggered, multi_piece_supply_budget, multi_piece_supply_budget_floored, multi_piece_supply_enabled, next_adjacent_supply_piece, next_adjacent_supply_piece_skipping, note_peer_bitfield, note_peer_have, note_peer_have_all, note_peer_have_none, on_block_arrived, parole_pick_piece, peer_holds_missing_piece, peer_with_piece, priority_mask, rates_median, rebuild_claimed, reissue_window, reissue_window_ceiled, remove_peer_avail, select_advertised_piece, select_advertised_piece_spread, selection_mask, store_pending_guard_scan, supply_adjacent_pieces, supply_adjacent_pieces_with, supply_cap};
    use crate::faces::{FaceState, FaceView, PeerMeta, PeerRate, PeerState, PexCandidates, SwarmSnapshot, XorShift, on_piece_verified, on_piece_written, pex_note_left, pex_note_registered, pex_snapshot, recheck_face_completion};
    use crate::pipeline::DataFlushState;
    use crate::progress::{encode_v2_file_bits, restore_progress_bits};
    use crate::query::drain_peer_counters;
    use crate::run::{PEER_CONNECTIONS_MAX, PEER_CONNECTIONS_TARGET, PeerStallRow, SEEDER_ROTATE_BATCH, SEEDER_ROTATE_IDLE_SECS, STALL_ACTION_PERIOD, STALL_DETECT_SECS, SlowChurnParams, StallValve, UTP_MUTE_AFTER, admission_verdict, admission_verdict_limits, rotation_pick, slow_churn_faces, stall_valve_advance, utp_mute_face};
    use crate::strategy::{PieceSelectionStrategy, Playhead, RarestFirstStrategy, SelectionCtx, StreamGeo, StreamPlan, StreamingStrategy};
    use crate::tracker::{TrackerMirror, epoch_secs};
    use crate::bitmap::PieceBitmap;
    use crate::upload::{PartialFaceSource, RateWindow};
    use taiji_domain::progress::ProgressModel;
    // Choke modes are constructed explicitly so test determinism does not
    // drift with the env fallback knobs.
    use taiji_bt::choke::{ChokeMode, SeedingPolicy};

    // ---- Inline ledger assembly bridge (old two-table shape -> PieceSentLedger) ----

    /// Inline form of the old `blocks_sent.insert(p, map)`: build a row per
    /// face piece length and set states per coordinate (`at` = the piece-
    /// level timestamp; the fresh age of InFlight-family states reads it).
    fn seed_blocks_sent(face: &mut FaceState, piece: u64, at: Instant, marks: &[(u32, BlockState)]) {
        let blocks = face
            .piece_bytes
            .get(piece as usize)
            .copied()
            .unwrap_or(u64::from(merkle::BLOCK_SIZE))
            .div_ceil(u64::from(merkle::BLOCK_SIZE))
            .max(1) as usize;
        face.blocks_sent
            .insert(piece, ledger_seeded(blocks, at, marks));
    }

    /// Bare-row form of [`seed_blocks_sent`] (block count explicit — for
    /// direct-drive faces such as `endgame_inflight_copies` that bypass
    /// FaceState).
    fn ledger_seeded(blocks: usize, at: Instant, marks: &[(u32, BlockState)]) -> PieceSentLedger {
        let mut l = PieceSentLedger::new(blocks, at);
        for &(begin, st) in marks {
            match st {
                BlockState::InFlight => l.set_inflight(begin, None, at),
                BlockState::InFlightDup => l.set_inflight_dup(begin, None, at),
                BlockState::Settling => l.mark_settling(begin, false),
                BlockState::SettlingDup => l.mark_settling(begin, true),
                BlockState::Buffered => l.mark_buffered(begin),
                BlockState::None => l.clear_slot(begin),
            }
        }
        l
    }

    /// Inline form of the old `block_dispatch.insert((p, b), cuid)`: locate
    /// the `peer_cuids` index by cuid and write the owner (the row is
    /// created from the face piece length when missing — the old global
    /// table existed independently of blocks_sent).
    fn dispatch_note(face: &mut FaceState, piece: u64, begin: u32, cuid: u64) {
        let owner = face
            .peer_cuids
            .iter()
            .position(|&c| c == cuid)
            .map(|i| i as u32)
            .unwrap_or_else(|| {
                panic!("dispatch_note: cuid {cuid} not in peer_cuids (test assembly must push peer_cuids)")
            });
        let blocks = face
            .piece_bytes
            .get(piece as usize)
            .copied()
            .unwrap_or(u64::from(merkle::BLOCK_SIZE))
            .div_ceil(u64::from(merkle::BLOCK_SIZE))
            .max(1) as usize;
        face.blocks_sent
            .entry(piece)
            .or_insert_with(|| PieceSentLedger::new(blocks, Instant::now()))
            .set_owner(begin, Some(owner));
    }

    /// Read bridge for the old `block_dispatch.get(&(p, b))`: owner -> cuid.
    fn dispatch_owner(face: &FaceState, piece: u64, begin: u32) -> Option<u64> {
        face.blocks_sent
            .get(&piece)
            .and_then(|l| l.owner_of(begin))
            .and_then(|o| face.peer_cuids.get(o as usize).copied())
    }

    /// Full entry view of the old `block_dispatch` as `(piece, begin, cuid)`
    /// (uniform base for len/keys/values assertions).
    fn dispatch_entries(face: &FaceState) -> Vec<(u64, u32, u64)> {
        let block = u64::from(merkle::BLOCK_SIZE);
        let mut v = Vec::new();
        for (&piece, ledger) in face.blocks_sent.iter() {
            for (bi, slot) in ledger.slots().iter().enumerate() {
                if slot.owner != NO_OWNER
                    && let Some(&cuid) = face.peer_cuids.get(slot.owner as usize)
                {
                    v.push((piece, (bi as u64 * block) as u32, cuid));
                }
            }
        }
        v
    }

    /// Old `block_dispatch.is_empty()`.
    fn dispatch_is_empty(face: &FaceState) -> bool {
        dispatch_entries(face).is_empty()
    }

    /// Locate the first `InFlightDup` coordinate `(piece, begin)` (the old
    /// "inner map scan for InFlightDuplicate" assertion face).
    fn any_inflight_dup(face: &FaceState) -> Option<(u64, u32)> {
        let block = u64::from(merkle::BLOCK_SIZE);
        face.blocks_sent.iter().find_map(|(&piece, ledger)| {
            ledger.slots().iter().enumerate().find_map(|(bi, slot)| {
                (slot.state == BlockState::InFlightDup)
                    .then(|| (piece, (bi as u64 * block) as u32))
            })
        })
    }

    /// Total `InFlightDup` slots across all ledgers (the old
    /// "values().flatten() count" assertion face).
    fn inflight_dup_count(face: &FaceState) -> usize {
        face.blocks_sent
            .values()
            .map(|l| {
                l.slots()
                    .iter()
                    .filter(|s| s.state == BlockState::InFlightDup)
                    .count()
            })
            .sum()
    }

    /// Old `block_dispatch.len()`.
    fn dispatch_count(face: &FaceState) -> usize {
        dispatch_entries(face).len()
    }

    // ---- Dispatch reply draining ----

    /// Table-driven reply semantics: `Ok`/`Duplicate` keep the bookkeeping
    /// in flight; `WindowFull`/peer exit (Closed) clears the in-flight mark
    /// and re-queues a refetch (length recomputed truncated to the piece's
    /// actual bytes); no reply (Empty) keeps the entry for the next round.
    #[test]
    fn dispatch_reply_drain_semantics() {
        use taiji_bt::request_book::DispatchError;
        let piece_bytes = [4u64 * merkle::BLOCK_SIZE as u64];  // piece 0: 4 blocks
        let mut blocks_sent: std::collections::HashMap<u64, PieceSentLedger> =
            std::collections::HashMap::new();
        let now = Instant::now();
        blocks_sent.insert(
            0,
            ledger_seeded(
                4,
                now,
                &[
                    (0, BlockState::InFlight),
                    (16_384, BlockState::InFlight),
                    (32_768, BlockState::InFlight),
                    (49_152, BlockState::InFlight),
                ],
            ),
        );
        // Four replies: Ok(())/Duplicate(keep)/WindowFull(clear mark and
        // requeue)/no reply(keep).
        let (tx_ok, rx_ok) = oneshot::channel();
        let _ = tx_ok.send(Ok(()));
        let (tx_dup, rx_dup) = oneshot::channel();
        let _ = tx_dup.send(Err(DispatchError::Duplicate {
            id: taiji_bt::piece_id::PieceId::V1(0),
            begin: 16_384,
            length: 16_384,
        }));
        let (tx_full, rx_full) = oneshot::channel();
        let _ = tx_full.send(Err(DispatchError::WindowFull {
            window: 6,
            outstanding: 6,
        }));
        let (_tx_open, rx_open) = oneshot::channel();  // peer has not answered: Empty
        let mut replies: Vec<DispatchReply> = vec![
            (0, 0, rx_ok),
            (0, 16_384, rx_dup),
            (0, 32_768, rx_full),
            (0, 49_152, rx_open),
        ];
        let mut refetch: Vec<(u32, u32, u32)> = Vec::new();
        drain_dispatch_replies_core(&mut replies, &mut blocks_sent, &mut refetch, &piece_bytes);
        let set = &blocks_sent[&0];
        assert_eq!(set.block_state(0), BlockState::InFlight, "Ok: booked on the peer, awaiting storage-pipeline settlement");
        assert_eq!(set.block_state(16_384), BlockState::InFlight, "Duplicate: genuinely in flight, the mark kept");
        assert_eq!(set.block_state(32_768), BlockState::None, "WindowFull: never booked, the mark cleared");
        assert_eq!(set.block_state(49_152), BlockState::InFlight, "no reply: waiting for the next round's receipt");
        assert_eq!(replies.len(), 1, "only the unanswered entry is kept");
        assert_eq!(replies[0].1, 49_152);
        // WindowFull blocks re-enter the refetch queue: length recomputed as
        // (piece_len - begin).min(BLOCK).
        assert_eq!(refetch, vec![(0, 32_768, 16_384)]);
    }

    /// Peer exit on the reply side (Closed): clears marks and re-queues a
    /// refetch; out-of-range defense — unknown piece (missing piece_bytes
    /// entry) or wire index beyond u32 yields no refetch entry, only mark
    /// clearing.
    #[test]
    fn dispatch_reply_drain_peer_gone_requeues_and_guards_oob() {
        let piece_bytes = [merkle::BLOCK_SIZE as u64];  // piece 0: single block
        let mut blocks_sent: std::collections::HashMap<u64, PieceSentLedger> =
            std::collections::HashMap::new();
        let now = Instant::now();
        blocks_sent.insert(0, ledger_seeded(1, now, &[(0, BlockState::InFlight)]));
        blocks_sent.insert(
            u64::from(u32::MAX) + 1,
            ledger_seeded(1, now, &[(0, BlockState::InFlight)]),
        );
        let (tx1, rx1) =
            oneshot::channel::<Result<(), taiji_bt::request_book::DispatchError>>();
        drop(tx1);  // peer task exited: Closed
        let (tx2, rx2) =
            oneshot::channel::<Result<(), taiji_bt::request_book::DispatchError>>();
        drop(tx2);
        let mut replies = vec![
            (0u64, 0u32, rx1),
            (u64::from(u32::MAX) + 1, 0, rx2),  // wire index beyond u32
        ];
        let mut refetch: Vec<(u32, u32, u32)> = Vec::new();
        drain_dispatch_replies_core(&mut replies, &mut blocks_sent, &mut refetch, &piece_bytes);
        assert!(replies.is_empty(), "Closed is not kept");
        assert!(
            blocks_sent.values().all(|l| l.tracked_count() == 0),
            "both marks cleared"
        );
        // Only representable blocks of known-length pieces re-enter the queue;
        // length = last-block truncation of a single-block piece (1 block).
        assert_eq!(refetch, vec![(0, 0, merkle::BLOCK_SIZE)]);
    }

    /// Shadow-row rebuild for the changeUri path: keep existing rows,
    /// register new rows, remove vanished rows, clear dangling success
    /// pointers (engine-side unit face of the tracker-row round-trip; the
    /// actor-side SetTrackers forwarding is covered by the taiji-bt
    /// tracker actor tests).
    #[test]
    fn tracker_mirror_set_trackers_rebuilds_rows() {
        let tiers = vec![(0usize, "http://a/announce".to_string())];
        let mut mirror = TrackerMirror::new(&tiers, "8000000000000001");
        assert_eq!(mirror.rows.len(), 1);
        // Simulate one successful attribution (the success pointer sits at a
        // URL about to be removed).
        mirror.last_success = Some((0, "http://a/announce".to_string()));

        let next = vec![
            (0usize, "http://a/announce".to_string()),
            (1usize, "http://b/announce".to_string()),
        ];
        mirror.set_trackers(&next);
        assert!(
            mirror
                .rows
                .contains_key(&(0, "http://a/announce".to_string()))
        );
        let b = mirror
            .rows
            .get(&(1, "http://b/announce".to_string()))
            .unwrap_or_else(|| panic!("new row registered"));
        assert!(b.enabled && b.tier == 1 && b.gid == "8000000000000001");

        let shrunk = vec![(0usize, "http://c/announce".to_string())];
        mirror.set_trackers(&shrunk);
        assert!(
            !mirror
                .rows
                .contains_key(&(0, "http://a/announce".to_string()))
        );
        assert!(
            mirror
                .rows
                .contains_key(&(0, "http://c/announce".to_string()))
        );
        assert!(
            mirror.last_success.is_none(),
            "success pointer to removed URL must clear"
        );
        // Empty list = remove all (a legal DHT/LSD-only face).
        mirror.set_trackers(&[]);
        assert!(mirror.rows.is_empty());
        assert!(mirror.tiers.is_empty());
    }

    // ---- Bitmap encode and restore ----

    /// Multi-file v2 model fixture (per-file piece counts differ).
    fn v2_progress(lens: &[u64], piece_len: u32) -> ProgressModel {
        ProgressModel::from_lengths(lens, piece_len)
    }

    /// v2_file_bits encode -> restore is a lossless roundtrip; the return
    /// value is the restored piece count; the bitmaps compare equal
    /// (synthesized_bitfield, bit for bit).
    #[test]
    fn v2_file_bits_encode_restore_roundtrip_is_lossless() {
        let mut pm = v2_progress(&[70_000, 30_000], 16_384);
        // File 0: pieces 0, 2, 4; file 1: piece 1.
        pm.set_piece_done(0, 0);
        pm.set_piece_done(0, 2);
        pm.set_piece_done(0, 4);
        pm.set_piece_done(1, 1);
        let bits = encode_v2_file_bits(&pm).unwrap_or_else(|| panic!("encode"));
        let mut restored = v2_progress(&[70_000, 30_000], 16_384);
        let n = restore_progress_bits(&mut restored, None, Some(&bits));
        assert_eq!(n, 4, "the restored piece count = the number of set bits");
        assert_eq!(pm.synthesized_bitfield(), restored.synthesized_bitfield());
        // Roundtrip again with all pieces set.
        let mut full = v2_progress(&[70_000, 30_000], 16_384);
        for f in 0..2 {
            let count = full.files[f].piece_count;
            for i in 0..count {
                full.set_piece_done(f, i);
            }
        }
        let bits = encode_v2_file_bits(&full).unwrap_or_else(|| panic!("encode full"));
        let mut restored = v2_progress(&[70_000, 30_000], 16_384);
        assert_eq!(
            restore_progress_bits(&mut restored, None, Some(&bits)),
            full.global_piece_count() as usize
        );
        assert_eq!(full.synthesized_bitfield(), restored.synthesized_bitfield());
        assert!(restored.all_done());
    }

    /// v1 global bitfield restore (v1 path; MSB bit order matches the
    /// synthesized bitmap) plus partial bitmaps restoring only the set
    /// pieces.
    #[test]
    fn v1_global_bitfield_restore() {
        // 50_000 bytes at 16_384 -> ceil = 4 pieces.
        let mut pm = ProgressModel::from_lengths(&[50_000], 16_384);
        assert_eq!(pm.global_piece_count(), 4);
        // Bitmap 0b1010_0000: pieces 0 and 2.
        let bits = vec![0b1010_0000];
        let n = restore_progress_bits(&mut pm, Some(&bits), None);
        assert_eq!(n, 2);
        assert!(pm.piece_done_global(0));
        assert!(!pm.piece_done_global(1));
        assert!(pm.piece_done_global(2));
        assert!(!pm.piece_done_global(3));
        // Repeat restore is idempotent: already-set pieces are not counted
        // again.
        let n2 = restore_progress_bits(&mut pm, Some(&bits), None);
        assert_eq!(n2, 0, "already-set pieces are not counted again");
    }

    /// Restore-side defense: truncated or out-of-range payloads neither
    /// panic nor write out of bounds; when both are present the v2
    /// authoritative bitmap takes precedence over the v1 global bitmap.
    #[test]
    fn restore_is_defensive_against_corrupt_payload() {
        let mut pm = v2_progress(&[30_000], 16_384);  // 2 pieces
        // Truncated payload: declares 3 files but carries only the 8-byte
        // header -> the tail is dropped safely.
        let mut corrupt = Vec::new();
        corrupt.extend_from_slice(&0u32.to_be_bytes());
        corrupt.extend_from_slice(&2u32.to_be_bytes());
        // Bitmap bytes missing (truncated).
        let n = restore_progress_bits(&mut pm, None, Some(&corrupt));
        assert_eq!(n, 0, "a truncated payload produces no restore");
        // Out-of-range file_index: piece_done(file_index) is bounds-safe
        // (returns false).
        let mut oob = Vec::new();
        oob.extend_from_slice(&9u32.to_be_bytes());
        oob.extend_from_slice(&2u32.to_be_bytes());
        oob.extend_from_slice(&[0b1100_0000]);
        let n = restore_progress_bits(&mut pm, None, Some(&oob));
        assert_eq!(n, 0, "an out-of-range file_index produces no restore and no panic");
        // v2 authority wins: v1 global sets piece 0, v2 per-file sets piece
        // 1 -> the result reflects only v2.
        let mut both = v2_progress(&[30_000], 16_384);
        let mut v2bits = Vec::new();
        v2bits.extend_from_slice(&0u32.to_be_bytes());
        v2bits.extend_from_slice(&2u32.to_be_bytes());
        v2bits.extend_from_slice(&[0b0100_0000]);
        let n = restore_progress_bits(&mut both, Some(&[0b1000_0000]), Some(&v2bits));
        assert_eq!(n, 1);
        assert!(!both.piece_done_global(0), "the v1 global bitmap is ignored by the v2 authority");
        assert!(both.piece_done_global(1));
    }

    // ---- PEX outbound candidate bookkeeping (pure functions) ----

    fn pex_addr(oct: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::from(oct)), port)
    }

    /// Inbound connections are not recorded (the aria2 addFreshPeer
    /// admission precondition); outbound registration marks the set dirty;
    /// re-registration with the same cuid overwrites the old entry.
    #[test]
    fn pex_bookkeeping_registration() {
        let mut c = PexCandidates::default();
        let t0 = Instant::now();
        // inbound is not recorded.
        pex_note_registered(&mut c, 1, pex_addr([203, 0, 113, 1], 6881), true, t0);
        assert!(c.fresh.is_empty() && !c.dirty);
        // outbound is recorded and marks the set dirty.
        pex_note_registered(&mut c, 2, pex_addr([203, 0, 113, 2], 6881), false, t0);
        assert_eq!(c.fresh, vec![(2, pex_addr([203, 0, 113, 2], 6881), t0)]);
        assert!(c.dirty);
        // same-cuid re-registration overwrites (no duplicates).
        pex_note_registered(&mut c, 2, pex_addr([203, 0, 113, 3], 6881), false, t0);
        assert_eq!(c.fresh.len(), 1);
        assert_eq!(c.fresh[0].1, pex_addr([203, 0, 113, 3], 6881));
    }

    /// Leave: withdraw from fresh and register in dropped; an unknown cuid
    /// is a no-op.
    #[test]
    fn pex_bookkeeping_leave_moves_to_dropped() {
        let mut c = PexCandidates::default();
        let t0 = Instant::now();
        pex_note_registered(&mut c, 7, pex_addr([203, 0, 113, 7], 6881), false, t0);
        pex_note_registered(&mut c, 8, pex_addr([203, 0, 113, 8], 6881), false, t0);
        let t1 = t0 + Duration::from_secs(5);
        // unknown cuid: no-op.
        pex_note_left(&mut c, 99, t1);
        assert_eq!(c.fresh.len(), 2);
        // cuid 7 leaves -> withdrawn from fresh, recorded in dropped.
        pex_note_left(&mut c, 7, t1);
        assert_eq!(c.fresh.len(), 1);
        assert_eq!(c.fresh[0].0, 8);
        assert_eq!(c.dropped, vec![(pex_addr([203, 0, 113, 7], 6881), t1)]);
        assert!(c.dirty);
    }

    /// Snapshot projection: correct PexCandidate shape plus pruning of
    /// out-of-window entries.
    #[test]
    fn pex_snapshot_projects_and_prunes_window() {
        let mut c = PexCandidates::default();
        let t0 = Instant::now();
        pex_note_registered(&mut c, 1, pex_addr([203, 0, 113, 1], 6881), false, t0);
        pex_note_registered(&mut c, 2, pex_addr([203, 0, 113, 2], 6881), false, t0);
        let t1 = t0 + Duration::from_secs(10);
        pex_note_left(&mut c, 1, t1);
        // In-window projection: fresh(cuid 2) + dropped(cuid 1's address).
        let (fresh, dropped) = pex_snapshot(&mut c, t1);
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].peer.addr, pex_addr([203, 0, 113, 2], 6881));
        assert!(fresh[0].active && !fresh[0].incoming && fresh[0].drop_started.is_none());
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].peer.addr, pex_addr([203, 0, 113, 1], 6881));
        assert!(!dropped[0].active);
        assert_eq!(dropped[0].drop_started, Some(t1));
        // After 61s: fresh (first touched t0) is pruned out of the window;
        // dropped (started t1 = t0+10s) is 51s old and still in it — the two
        // lists have independent window anchors (fresh = first touch,
        // dropped = drop start; UTPexExtensionMessage.cc/157-167).
        let t2 = t0 + taiji_bt::pex::DEFAULT_INTERVAL + Duration::from_secs(1);
        let (fresh, dropped) = pex_snapshot(&mut c, t2);
        assert!(fresh.is_empty());
        assert_eq!(dropped.len(), 1);
        // After 71s: dropped also leaves the window (60s after the drop
        // start).
        let t3 = t2 + Duration::from_secs(10);
        let (fresh, dropped) = pex_snapshot(&mut c, t3);
        assert!(fresh.is_empty() && dropped.is_empty());
    }

    // ---- Advertisement-aware dispatch ----

    // ---- Leecher choking wiring ----

    /// duplex pair + PeerTask: returns (handle, remote read/write end). The
    /// test plays the remote peer (raw frames: interested = [0,0,0,1,2]).
    ///
    /// Reciprocity: the dispatch request face sends zero requests to peers
    /// that choke us (aria2 fillPiece port, dispatch.rs main-loop gate).
    /// This fixture therefore plays the peer sending Unchoke ([0,0,0,1,1])
    /// and waits for the mirror to flip, modeling the steady supply face
    /// after a choke round admits the peer in a real swarm; the
    /// zero-request verdict for choked peers has a dedicated decision row
    /// in `dispatch_choke_gate_decision_table`.
    async fn choke_peer_pair(
        root: &CancellationToken,
    ) -> (PeerTaskHandle, tokio::io::DuplexStream) {
        let (local, mut remote) = tokio::io::duplex(64 * 1024);
        let config = taiji_bt::peer::PeerConfig::flat();
        let (handle, _join, _data) = taiji_bt::peer::PeerTask::spawn(root, local, config);
        // Unchoke frame (msg id 1); wait for the mirror (the peer task
        // consumes it asynchronously).
        use tokio::io::AsyncWriteExt as _;
        remote
            .write_all(&[0, 0, 0, 1, 1])
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let deadline = Instant::now() + Duration::from_secs(2);
        while handle.is_choking_us() {
            assert!(
                Instant::now() < deadline,
                "the unchoke mirror did not flip within the deadline (the peer task consumed no frame)"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        (handle, remote)
    }

    /// Choked peer pair (no unchoke is sent; used by the choke gate
    /// decision rows). The caller must keep the returned remote end alive
    /// (drop = EOF = peer task exit).
    async fn choked_peer_pair(
        root: &CancellationToken,
    ) -> (PeerTaskHandle, tokio::io::DuplexStream) {
        let (local, remote) = tokio::io::duplex(64 * 1024);
        let config = taiji_bt::peer::PeerConfig::flat();
        let (handle, _join, _data) = taiji_bt::peer::PeerTask::spawn(root, local, config);
        (handle, remote)
    }

    /// Read one wire frame (length prefix + id); timeout or disconnect =
    /// None.
    async fn read_wire_msg_id<R: tokio::io::AsyncRead + Unpin>(remote: &mut R) -> Option<u8> {
        use tokio::io::AsyncReadExt as _;
        let mut len_buf = [0u8; 4];
        match tokio::time::timeout(Duration::from_millis(400), remote.read_exact(&mut len_buf))
            .await
        {
            Err(_) | Ok(Err(_)) => return None,
            Ok(Ok(_)) => {}
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 {
            return Some(0); // keepalive
        }
        let mut body = vec![0u8; len];
        match tokio::time::timeout(Duration::from_millis(400), remote.read_exact(&mut body)).await {
            Ok(Ok(_)) => Some(body[0]),
            _ => None,
        }
    }

    /// Wait for a wire frame to appear: poll until `msg_id` shows up or
    /// the budget runs out. A single 400ms read can time out before the
    /// PeerTask writes the frame under full parallel load (a load-induced
    /// false negative); retrying within the budget removes that
    /// sensitivity. Returns whether the target frame was seen (budget
    /// exhausted = false, reused by negative assertions).
    async fn wait_wire_msg_id<R: tokio::io::AsyncRead + Unpin>(
        remote: &mut R,
        msg_id: u8,
        budget: Duration,
    ) -> bool {
        let deadline = Instant::now() + budget;
        loop {
            match read_wire_msg_id(remote).await {
                Some(id) if id == msg_id => return true,
                Some(_) => continue,
                None if Instant::now() < deadline => continue,
                None => return false,
            }
        }
    }

    /// Wait until peer shutdown is observable at face level:
    /// `handle.shutdown()` -> child token cancelled -> PeerTask exits ->
    /// duplex local half closes -> remote reads EOF (Ok(0)). Polling
    /// within the budget removes the task-exit race (same shape as
    /// wait_wire_msg_id); a live peer whose read keeps timing out returns
    /// false (a pending keepalive read is not misreported as EOF).
    async fn wait_peer_eof(remote: &mut tokio::io::DuplexStream, budget: Duration) -> bool {
        use tokio::io::AsyncReadExt as _;
        let deadline = Instant::now() + budget;
        loop {
            let mut buf = [0u8; 1];
            match tokio::time::timeout(Duration::from_millis(50), remote.read(&mut buf)).await {
                Ok(Ok(0)) => return true,
                Ok(Ok(_)) => continue,
                Err(_) | Ok(Err(_)) if Instant::now() < deadline => continue,
                Err(_) | Ok(Err(_)) => return false,
            }
        }
    }

    /// Leecher choking decision table (engine wiring layer; libtorrent-
    /// mode 8-slot semantics): interested filtering, the rate sort key,
    /// 7 regular + 1 optimistic slots (the optimistic seat counts toward
    /// the total), the 30s optimistic re-election phase (longest wait
    /// first), and idempotent unchoke/choke landing points.
    ///
    /// Row 1 (3 interested): all fit (8 total slots) -> exactly 3 Unchoke
    /// frames and zero frames for non-interested peers (the landing = the
    /// am_unchoked state machine).
    /// Row 2 (4 interested): same capacity, 4 Unchoke frames; after peer 4
    /// switches to NotInterested the only well-defined choke landing is
    /// the lost interest (BEP3: losing the slot returns to choke). The
    /// old 3+1-slot rows (slot-boundary transfers etc.) were re-locked
    /// with the slot upgrade; the aria2 fallback decision table is pinned
    /// in the bt::choke unit tests.
    #[tokio::test]
    async fn leecher_choke_round_wiring_table() {
        for (row, n_interested) in [("3-interested", 3usize), ("4-interested", 4)] {
            let root = CancellationToken::new();
            let mut face = adv_face(8);
            let mut remotes = Vec::new();
            for cuid in 1..=4u64 {
                let (handle, remote) = choke_peer_pair(&root).await;
                face.peers.push(handle);
                face.peer_cuids.push(cuid);
                remotes.push(remote);
            }
            // interested 1..=n (raw Interested frames); wait for the mirror
            // to set.
            use tokio::io::AsyncWriteExt as _;
            for remote in remotes.iter_mut().take(n_interested) {
                remote
                    .write_all(&[0, 0, 0, 1, 2])
                    .await
                    .unwrap_or_else(|e| panic!("{e}"));
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            while face
                .peers
                .iter()
                .take(n_interested)
                .any(|p| !p.is_interested())
                && Instant::now() < deadline
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            // Download rates 1 > 2 > 3 > 4 (sort-key input).
            for (cuid, rate) in [(1u64, 300.0), (2, 200.0), (3, 100.0), (4, 50.0)] {
                let mut w = RateWindow::new();
                for _ in 0..RateWindow::WINDOW_SECS {
                    w.advance();
                    w.add(rate as u64);
                }
                face.peer_state_row(cuid).down_window = Some(w);
            }

            let mut rng = XorShift(0x2545F4914F6CDD1Du64);
            leecher_choke_round(&mut face, &mut rng, None);  // static arm (default-off: no behavior change)
            // Read frames from every peer until drained: tally unchoke(1)/
            // choke(0) landings.
            let mut unchoke_by = [0usize; 4];
            for (i, remote) in remotes.iter_mut().enumerate() {
                while let Some(id) = read_wire_msg_id(remote).await {
                    match id {
                        1 => unchoke_by[i] += 1,
                        0 => panic!("row {row}: the first round must not produce a Choke"),
                        _ => {}
                    }
                }
            }
            let n_unchoke: usize = unchoke_by.iter().sum();
            if n_interested == 3 {
                assert_eq!(n_unchoke, 3, "row {row}: all 8 total slots accommodate");
                assert_eq!(
                    unchoke_by[3], 0,
                    "row {row}: a non-interested peer must not be unchoked"
                );
            } else {
                assert_eq!(n_unchoke, 4, "row {row}: the regular 3 + optimistic 1 (peer 1 waited longest, picked first)");
                assert!(
                    unchoke_by[0] == 1 && unchoke_by[1] == 1 && unchoke_by[2] == 1,
                    "row {row}: the interested top three all seated"
                );
            }
            // State-keeping key = the regular slot set (the optimistic slot
            // is accounted separately: the slot sets are disjoint — the
            // optimistic pick is the longest-waiting peer (stable first
            // under None = cuid 1) and does not occupy a regular slot).
            let expected_regular: std::collections::HashSet<u64> = if n_interested == 3 {
                [2u64, 3].into_iter().collect()
            } else {
                [2u64, 3, 4].into_iter().collect()
            };
            assert_eq!(
                face.regular_unchoked, expected_regular,
                "row {row}: the state-keeping key = the regular slot set (disjoint from the optimistic slot)"
            );

            // Second round: the decision is unchanged (same regular seats;
            // the optimistic holder is kept across rounds — no re-election
            // when round != 0, cc:231-233) -> zero frames in both rows
            // (idempotent landings).
            leecher_choke_round(&mut face, &mut rng, None);  // static arm (default-off: no behavior change)
            for remote in remotes.iter_mut() {
                assert!(
                    read_wire_msg_id(remote).await.is_none(),
                    "row {row}: the second round's unchanged decision emits zero frames"
                );
            }
            // Before rounds 3 and 4 (4-interested row): peer 4 switches to
            // NotInterested — the only well-defined choke landing is the
            // lost interest (BEP3; the unchoke set shrinks -> the dropped
            // peer returns to choke).
            if n_interested == 4 {
                use tokio::io::AsyncWriteExt as _;
                remotes[3]
                    .write_all(&[0, 0, 0, 1, 3])
                    .await
                    .unwrap_or_else(|e| panic!("{e}"));
                let deadline = Instant::now() + Duration::from_secs(2);
                while face.peers[3].is_interested() && Instant::now() < deadline {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
            // Rounds 3 and 4 (phase): round 3 is the optimistic re-election
            // round (round 2, 30s wait) — holder cuid 1 sorts last by its
            // carried timestamp, so the longest-waiting cuid 2 wins; the
            // unchoke set ({1,2,3} in the 3-interested row) is unchanged ->
            // zero frames. Round 4 is not a re-election round: holder 2 is
            // kept -> still zero frames. In the 4-interested row peer 4 has
            // lost interest and its slot -> exactly 1 Choke (the others
            // keep).
            let mut choke_by = [0usize; 4];
            let mut extra_unchoke = 0usize;
            for _ in 0..2 {
                leecher_choke_round(&mut face, &mut rng, None);  // static arm (default-off: no behavior change)
                for (i, remote) in remotes.iter_mut().enumerate() {
                    while let Some(id) = read_wire_msg_id(remote).await {
                        match id {
                            0 => choke_by[i] += 1,
                            1 => extra_unchoke += 1,
                            _ => {}
                        }
                    }
                }
            }
            if n_interested == 4 {
                assert_eq!(
                    (choke_by[0], choke_by[1], choke_by[2], choke_by[3]),
                    (0, 0, 0, 1),
                    "row {row}: only the lost-interest peer (4) returns to choke"
                );
                assert_eq!(extra_unchoke, 0, "row {row}: already-unchoke peers are not resent");
            } else {
                assert_eq!(
                    choke_by.iter().sum::<usize>(),
                    0,
                    "row {row}: everyone seated, no choke"
                );
            }
            root.cancel();
        }
    }

    /// Budget-derived slot assembly, both arms ([`budget_derived_slots`]
    /// direct drive; the `enabled` parameter is the injection seam since
    /// env is immutable in tests; floor/static knobs take the env
    /// defaults 16384/8): the off arm = None (bit-for-bit the static
    /// `BH_UNCHOKE_SLOTS` path); the on arm derives from the
    /// `per_torrent.up` bucket rate (the `--max-upload-limit` bucket
    /// face); unlimited (=0) falls back through the bt pure function to
    /// static 8.
    #[test]
    fn budget_derived_slots_wiring_two_arm_table() {
        use taiji_io::rate_limit::{LimiterPair, LimiterSet};
        let set_with_up = |up_bps: u64| {
            Some(LimiterSet {
                global: LimiterPair::new(0, 0),
                per_torrent: LimiterPair::new(0, up_bps),
            })
        };
        // Off arm: a limiter present with a large budget -> still None (the
        // default-off static slot path, pinned by
        // `leecher_choke_round_wiring_table`).
        assert_eq!(budget_derived_slots(false, set_with_up(1 << 20).as_ref()), None);
        // On arm without a limiter (a bare CLI run, unthrottled) -> None
        // (no budget face, no guessing — the global bucket is not
        // consulted).
        assert_eq!(budget_derived_slots(true, None), None);
        // On arm with unlimited upload (up=0) -> the bt pure function
        // returns static 8 (= the BH_UNCHOKE_SLOTS default).
        assert_eq!(budget_derived_slots(true, set_with_up(0).as_ref()), Some(8));
        // On arm at 64KiB/s upload: 64K/16K = 4 slots (exactly at the
        // lower clamp — 16KiB/s per peer is the meaningful rate).
        assert_eq!(
            budget_derived_slots(true, set_with_up(64 * 1024).as_ref()),
            Some(4)
        );
        // On arm at 160KiB/s: 160K/16K = 10 slots, passed through.
        assert_eq!(
            budget_derived_slots(true, set_with_up(160 * 1024).as_ref()),
            Some(10)
        );
        // On arm at 1MiB/s: quotient 64 -> clamped to the upper bound 32.
        assert_eq!(
            budget_derived_slots(true, set_with_up(1 << 20).as_ref()),
            Some(32)
        );
        // The global bucket does not participate (the budget face is
        // per_torrent.up only): finite global up with unlimited
        // per_torrent -> still static (no guessing).
        let global_only = Some(LimiterSet {
            global: LimiterPair::new(0, 4096),
            per_torrent: LimiterPair::new(0, 0),
        });
        assert_eq!(budget_derived_slots(true, global_only.as_ref()), Some(8));
    }

    /// Preemptive unchoke decision table (the preemptive edge; libtorrent
    /// peer_connection.cpp + session_impl.cpp).
    /// Row 1 free slot (7/8) -> the edge fires an Unchoke frame +
    /// am_unchoked set; row 2 full slots (8/8) -> zero frames; row 3
    /// already unchoked (level-idempotent) -> zero frames; row 4 aria2
    /// fallback mode -> semantics disabled, zero frames; row 5 an
    /// unregistered cuid (the peer left, an out-of-order event) -> zero
    /// frames, no panic.
    #[tokio::test]
    async fn preemptive_unchoke_edge_table() {
        let root = CancellationToken::new();
        let mut face = adv_face(8);
        let mut remotes = Vec::new();
        for cuid in 1..=3u64 {
            let (handle, remote) = choke_peer_pair(&root).await;
            face.peers.push(handle);
            face.peer_cuids.push(cuid);
            remotes.push(remote);
        }
        // Pre-seed 7 unchoke states without connections (fake cuids; the
        // free-slot check counts state only). With peer 1 admitted this
        // reaches 8 = full.
        for cuid in 100..=106u64 {
            face.peer_state_row(cuid).am_unchoked = true;
        }

        // Row 1: free slot (7 < 8) -> the edge fires Unchoke (peer 1 sees
        // id=1 on the wire; polling within budget — under full load the
        // PeerTask may write the frame later than a single 400ms read).
        preemptive_unchoke(&mut face, 1);
        assert!(
            face.peer_state.get(&1).is_some_and(|ps| ps.am_unchoked),
            "row 1: the state set"
        );
        assert!(
            wait_wire_msg_id(&mut remotes[0], 1, Duration::from_secs(5)).await,
            "row 1: the edge emits an Unchoke frame"
        );

        // Row 2: full slots (8/8) -> zero frames, no state.
        preemptive_unchoke(&mut face, 2);
        assert!(
            !face.peer_state.get(&2).is_some_and(|ps| ps.am_unchoked),
            "row 2: full slots refuse entry"
        );
        assert!(
            read_wire_msg_id(&mut remotes[1]).await.is_none(),
            "row 2: full slots emit zero frames"
        );

        // Row 3: already unchoked (level-idempotent) -> no resend.
        preemptive_unchoke(&mut face, 1);
        assert!(
            read_wire_msg_id(&mut remotes[0]).await.is_none(),
            "row 3: already unchoked emits zero frames"
        );

        // Row 4: aria2 fallback mode -> preemptive semantics disabled (the
        // fallback keeps the existing round cadence).
        let mut face_aria2 = adv_face(8);
        face_aria2.choke = SeederChoke::with(ChokeMode::Aria2, SeedingPolicy::FastestUpload);
        face_aria2.leecher_choke = LeecherChoke::with_mode(ChokeMode::Aria2);
        let (handle, mut remote) = choke_peer_pair(&root).await;
        face_aria2.peers.push(handle);
        face_aria2.peer_cuids.push(7);
        preemptive_unchoke(&mut face_aria2, 7);
        assert!(
            !face_aria2.peer_state.get(&7).is_some_and(|ps| ps.am_unchoked),
            "row 4: aria2 fallback sets no state"
        );
        assert!(
            read_wire_msg_id(&mut remote).await.is_none(),
            "row 4: zero frames"
        );

        // Row 5: unregistered cuid (the peer already left) -> zero frames,
        // no panic.
        preemptive_unchoke(&mut face, 999);
        root.cancel();
    }

    /// Seeder fastest_upload wiring table (seeder-side selection;
    /// choker.cpp): in the completed state the choke round unchokes the
    /// top-8 peers by `peer_rates.up` sliding-window rate descending —
    /// peers 1..=8 have 100 B/s and peer 9 has zero rate (no window) ->
    /// the first 8 each get an Unchoke frame and the 9th gets none
    /// (9 interested > 8 slots).
    #[tokio::test]
    async fn seeder_choke_round_fastest_upload_wiring() {
        let root = CancellationToken::new();
        let mut face = adv_face(8);
        face.completed = true;
        let mut remotes = Vec::new();
        for cuid in 1..=9u64 {
            let (handle, remote) = choke_peer_pair(&root).await;
            face.peers.push(handle);
            face.peer_cuids.push(cuid);
            remotes.push(remote);
        }
        // interested 1..=9 (raw Interested frames); wait for the mirrors
        // to set (10s budget — under parallel load 9 PeerTasks may set
        // slower than a short budget allows; on timeout panic with the
        // peer index list instead of silently degrading).
        use tokio::io::AsyncWriteExt as _;
        for remote in remotes.iter_mut() {
            remote
                .write_all(&[0, 0, 0, 1, 2])
                .await
                .unwrap_or_else(|e| panic!("{e}"));
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while face.peers.iter().any(|p| !p.is_interested()) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let uninterested: Vec<usize> = face
            .peers
            .iter()
            .enumerate()
            .filter(|(_, p)| !p.is_interested())
            .map(|(i, _)| i)
            .collect();
        assert!(
            uninterested.is_empty(),
            "mirror-set timeout: indices of peers still not interested: {uninterested:?}"
        );
        // fastest_upload key: peer_rates.up (200B fed 2s ago in
        // SessionSpeedCalc -> 100 B/s); peer 9 has no window = 0 (sorts
        // last, the only one dropped).
        for cuid in 1..=8u64 {
            let mut rate = PeerRate {
                up: taiji_domain::seed::SessionSpeedCalc::default(),
                down: taiji_domain::seed::SessionSpeedCalc::default(),
                last_up: 0,
                last_down: 0,
            };
            rate.up.add_at(Instant::now() - Duration::from_secs(2), 200);
            face.peer_state_row(cuid).rates = Some(rate);
        }
        choke_round(&mut face);
        // The first 8 (cuid 1..=8, 100 B/s) each get an Unchoke frame
        // (poll within budget).
        for remote in remotes.iter_mut().take(8) {
            assert!(
                wait_wire_msg_id(remote, 1, Duration::from_secs(5)).await,
                "the top 8 by rate must each get an Unchoke"
            );
        }
        // Unchoke state bookkeeping (the input to the preemptive free-slot
        // count): 8 true entries. The seeder path keys by peers index
        // 0..=7 while the asserts key by cuid — two key spaces; the count
        // only looks at values.
        assert_eq!(
            face.peer_state.values().filter(|ps| ps.am_unchoked).count(),
            8,
            "the first 8 bookkeeping entries set"
        );
        assert!(
            face.peer_state.values().all(|ps| ps.am_unchoked),
            "bookkeeping all true"
        );
        // The 9th peer (zero rate) is dropped: zero frames.
        assert!(
            read_wire_msg_id(&mut remotes[8]).await.is_none(),
            "cuid 9: zero rate deselected, zero frames"
        );
        root.cancel();
    }

    /// Minimal FaceState (v1 single file, `piece_count` pieces of 16KiB
    /// each, no peer connections) — driven by the pure functions for
    /// advertisement bookkeeping, piece selection, and dispatch gating.
    fn adv_face(piece_count: usize) -> FaceState {
        let (block_tx, _rx) = mpsc::channel(1);
        let (fetch_tx, _frx) = mpsc::channel(1);
        // Final-flush barrier seam: the fixture has no pipeline
        // counterpart — nothing triggers the barrier and it stays Pending
        // (the completion-await path is outside the fixture's consumption
        // path).
        let (final_flush_tx, _final_flush_rx) = mpsc::channel::<()>(1);
        let (_data_flush_gate, data_flush_gate) =
            tokio::sync::watch::channel(DataFlushState::Pending);
        let mut stat_rng = XorShift(0x853C49E6748FEA9Bu64);
        let file_len = piece_count as u64 * merkle::BLOCK_SIZE as u64;
        FaceState {
            kind: FaceKind::V1,
            info_hash: [0u8; 20],
            reserved: Reserved::aria2_default(),
            addressing: Addressing::Flat,
            piece_bytes: vec![u64::from(merkle::BLOCK_SIZE); piece_count].into(),
            piece_goffs: Arc::new(
                (0..piece_count as u64)
                    .map(|k| k * u64::from(merkle::BLOCK_SIZE))
                    .collect(),
            ),
            progress: ProgressModel::from_lengths(&[file_len], merkle::BLOCK_SIZE),
            piece_count,
            verified_count: 0,
            stat_man: PieceStatMan::new(piece_count as u64, &mut |n| stat_rng.next(n)),
            peer_avail: std::collections::HashMap::new(),
            peer_seeds: std::collections::HashSet::new(),
            peers: Vec::new(),
            peer_cuids: Vec::new(),
            // per-peer state merged into one table
            peer_state: std::collections::HashMap::new(),
            block_senders: Arc::new(Mutex::new(HashMap::new())),
            choke: SeederChoke::with(ChokeMode::Libtorrent, SeedingPolicy::FastestUpload),
            leecher_choke: LeecherChoke::with_mode(ChokeMode::Libtorrent),
            regular_unchoked: std::collections::HashSet::new(),
            download_source: None,
            written_bits: Arc::new(PieceBitmap::new(piece_count)),
            // mirrors progress (production clones it after restore; the
            // two-bit model diverges here)
            written_progress: ProgressModel::from_lengths(&[file_len], merkle::BLOCK_SIZE),
            written_count: 0,
            completed: false,
            hash_files: None,
            swarm: FaceView(Arc::new(Mutex::new(SwarmSnapshot {
                total: file_len,
                completed: 0,
                all_finished: false,
                peers: 0,
                uploaded: 0,
                downloaded: 0,
            }))),
            mirror: TrackerMirror::new(&[], ""),
            block_cursor: 0,
            block_tx,
            trees: None,
            flat_coords: Arc::new((0..piece_count as u64).map(|i| (0, i as u32)).collect()),
            layers: Vec::new(),
            fetch_tx,
            refetch: Vec::new(),
            dispatch_replies: Vec::new(),
            // dispatch-round scratch persists on the face
            dispatch_scratch: Default::default(),
            endgame_live: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            endgame_edge: None,
            endgame_cum: Duration::ZERO,
            last_mile_edge: None,
            last_mile_final: None,
            last8_edge: None,
            last8_final: None,
            endgame_deadline: std::collections::HashMap::new(),
            write_adjacent: 0,
            write_isolated: 0,
            blocks_sent: std::collections::HashMap::new(),
            parole_peers: std::collections::HashSet::new(),
        block_arena: None,
            block_inflight: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            pex_candidates: PexCandidates::default(),
            read_pool: None,
            final_flush_tx,
            data_flush_gate,
            // Snapshot barrier face: the dirty flag starts false; the cell
            // stays empty (its consumer is outside the fixture path).
            dirty_since_snapshot: false,
            snapshot_sync: Arc::new(std::sync::OnceLock::new()),
        }
    }

    /// Decision table: un-advertised pieces get zero requests. Selection
    /// candidates = the peer-advertised bitmap intersected with locally
    /// incomplete pieces; missing evidence (no bitfield/HAVE sent), an
    /// empty bitmap, or an advertised set that is entirely complete ->
    /// None (the caller skips the peer = zero requests). Rows 3/6 are
    /// evidence regressions: when the peer advertises only piece 2, the
    /// old blind fallback `unwrap_or(current)` would produce the first
    /// incomplete piece 0 (in the shape of a request the canonical seed
    /// rejects with FIN). Cross-validation sources: the
    /// [`select_advertised_piece`] docs (libtorrent request_blocks.cpp/181 +
    /// piece_picker.cpp; aria2 DefaultPieceStorage.cc).
    #[test]
    fn advertised_selection_zero_request_table() {
        // (name, advertised bitmap, done bitmap, expected). Advertised
        // rows use bitmaps (literals go through from_bools; the verdict
        // semantics are unchanged).
        type AdvRow<'a> = (&'a str, Option<PieceBitmap>, Vec<bool>, Option<u64>);
        let stat = PieceStatMan::new(4, &mut |n| n / 2);
        let none_done = vec![false; 4];
        let rows: Vec<AdvRow> = vec![
            // The peer sent no advertisement (silent after handshake) ->
            // zero requests (BEP3 treats this as have_none; libtorrent
            // peer_connection.cpp).
            ("silent peer", None, none_done.clone(), None),
            // Empty bitmap (the peer sent HaveNone / all zeros) -> zero
            // requests.
            (
                "empty bitfield",
                Some(PieceBitmap::new(4)),
                none_done.clone(),
                None,
            ),
            // Advertises only piece 0 -> exactly piece 0.
            (
                "advertises only piece 0",
                Some(PieceBitmap::from_bools(&[true, false, false, false])),
                none_done.clone(),
                Some(0),
            ),
            // Advertises pieces 1..3 but 1 and 2 are done -> only piece 3
            // remains selectable.
            (
                "advertised subset partially done",
                Some(PieceBitmap::from_bools(&[false, true, true, true])),
                vec![false, true, true, false],
                Some(3),
            ),
            // Every advertised piece is done -> zero requests (no blind
            // fallback to some other piece).
            (
                "all advertised pieces done",
                Some(PieceBitmap::from_bools(&[true, false, false, false])),
                vec![true, false, false, false],
                None,
            ),
            // Key regression: advertises only piece 2 while the locally
            // first incomplete piece is 0 -> must pick 2 (the old blind
            // pick produced 0 = requesting an unadvertised piece).
            (
                "advertises piece 2 only, current=0",
                Some(PieceBitmap::from_bools(&[false, false, true, false])),
                none_done.clone(),
                Some(2),
            ),
        ];
        for (name, avail, done, expect) in rows {
            let got = select_advertised_piece(avail.as_ref(), &done, &stat, None);
            assert_eq!(got, expect, "row: {name}");
        }
    }

    /// The advertised bitmap updates immediately on HAVE
    /// ([`note_peer_have`]); duplicate HAVEs are idempotent (no double
    /// counting in the rarest-first tally); out-of-range index defense.
    #[test]
    fn have_updates_advertised_map_immediately() {
        let mut face = adv_face(4);
        note_peer_have(&mut face, 7, 2);
        assert_eq!(
            face.peer_avail.get(&7),
            Some(&PieceBitmap::from_bools(&[false, false, true, false]))
        );
        assert_eq!(face.stat_man.count(2), 1, "a HAVE enters the rarest-first tally immediately");
        // Duplicate HAVE: idempotent.
        note_peer_have(&mut face, 7, 2);
        assert_eq!(face.stat_man.count(2), 1);
        // Out-of-range index: no panic, no out-of-bounds write.
        note_peer_have(&mut face, 7, 999);
        assert_eq!(face.peer_avail.get(&7).map(|v| v.len()), Some(4));
    }

    /// Bitfield advertisement sets bits individually (BEP3 MSB order,
    /// tail padding bits ignored) + duplicate advertisements are
    /// idempotent ([`note_peer_bitfield`] feeds increments into the
    /// rarest-first tally).
    #[test]
    fn bitfield_updates_advertised_map() {
        let mut face = adv_face(8);
        // 0b1010_0000 -> pieces 0 and 2; the second byte holds only
        // padding bits (piece 8 onward does not exist) -> ignored.
        note_peer_bitfield(&mut face, 9, &[0b1010_0000, 0b1111_1111]);
        assert!(face.peer_avail.contains_key(&9), "the bitfield builds a row");
        let row = &face.peer_avail[&9];
        assert!(row.get(0) && row.get(2));
        assert!(!row.get(1) && !row.get(3) && !row.get(7));
        assert_eq!(row.len(), 8, "the bitmap never crosses piece_count");
        assert_eq!(face.stat_man.count(0), 1);
        assert_eq!(face.stat_man.count(2), 1);
        // The same bitfield again: the tally is unchanged (incremental
        // semantics).
        note_peer_bitfield(&mut face, 9, &[0b1010_0000, 0b0000_0000]);
        assert_eq!(face.stat_man.count(0), 1);
        assert_eq!(face.stat_man.count(2), 1);
        // A newly advertised bit (piece 1): enters the tally.
        note_peer_bitfield(&mut face, 9, &[0b1110_0000, 0b0000_0000]);
        assert_eq!(face.stat_man.count(1), 1);
        // Another peer gets its own row.
        note_peer_bitfield(&mut face, 10, &[0b0000_0000]);
        assert!(face.peer_avail.contains_key(&10));
    }

    // ---- BEP6 have_all/have_none ----

    /// Core criterion: HaveAll unlocks dispatch. A fast-negotiated seeder
    /// advertises with have_all instead of a bitfield (BEP6 "replace the
    /// Have Bitfield") — the synthesized all-ones candidate set (piece
    /// count = the face flat space) goes through exactly the same
    /// bookkeeping path as a bitfield: the rarity tally fills in and
    /// dispatch really selects a piece and enqueues requests at that peer.
    /// The old implementation only logged at debug level -> zero requests
    /// from that peer.
    #[tokio::test]
    async fn have_all_unlocks_dispatch_for_fast_seeder() {
        let root = tokio_util::sync::CancellationToken::new();
        let mut face = adv_face(8);
        let (handle, _remote) = choke_peer_pair(&root).await;
        face.peers.push(handle);
        face.peer_cuids.push(11);
        note_peer_have_all(&mut face, 11);
        // All-ones row (width = the face flat piece count, no overrun) +
        // the rarity tally fully populated.
        let Some(row) = face.peer_avail.get(&11) else {
            panic!("have_all builds a row");
        };
        assert_eq!(row.len(), 8, "piece count follows the face's flat space");
        assert!(row.is_full(), "have_all = an all-ones selectable set");
        for i in 0..8u64 {
            assert_eq!(face.stat_man.count(i), 1, "piece {i} enters the rarest-first tally");
        }
        // Dispatch unlocked: selection hits and requests are really
        // enqueued at that peer (in-flight and dispatch-target bookkeeping
        // land).
        dispatch_face(&mut face, 0);
        assert!(
            !dispatch_is_empty(&face),
            "a HaveAll peer must unlock dispatch (the old implementation sent zero requests)"
        );
        assert!(
            dispatch_entries(&face).iter().all(|&(_, _, c)| c == 11),
            "the dispatch target = that HaveAll peer"
        );
        root.cancel();
    }

    /// HaveNone = explicit zero holdings (replacement semantics). Late-
    /// arriving HAVE evidence is subtracted (cross-validation: libtorrent
    /// incoming_have_none's peer_lost + clear_all); an explicit empty row
    /// does not unlock dispatch (observationally equal to the missing "no
    /// evidence" row); HAVE increments after HaveNone enter the tally and
    /// the bitmap row normally.
    #[test]
    fn have_none_explicit_empty_then_have_increments() {
        let mut face = adv_face(4);
        // Prior evidence (defense outside the BEP6 order: have_none must
        // subtract, not accumulate).
        note_peer_have(&mut face, 7, 2);
        assert_eq!(face.stat_man.count(2), 1);
        note_peer_have_none(&mut face, 7);
        assert_eq!(face.stat_man.count(2), 0, "late-arriving evidence is subtracted");
        assert_eq!(
            face.peer_avail.get(&7),
            Some(&PieceBitmap::new(4)),
            "the explicit empty row lands"
        );
        // An explicit empty row does not unlock dispatch (selection None =
        // zero requests).
        let done = vec![false; 4];
        assert_eq!(
            select_advertised_piece(face.peer_avail.get(&7), &done, &face.stat_man, None),
            None,
            "an explicit empty row must not unlock dispatch"
        );
        // HAVE increments after HaveNone work normally.
        note_peer_have(&mut face, 7, 0);
        assert_eq!(face.stat_man.count(0), 1);
        assert_eq!(face.stat_man.count(2), 0);
        assert_eq!(
            face.peer_avail.get(&7),
            Some(&PieceBitmap::from_bools(&[true, false, false, false]))
        );
        // have_none without prior evidence: also lands an explicit empty
        // row (no panic).
        note_peer_have_none(&mut face, 8);
        assert_eq!(face.peer_avail.get(&8), Some(&PieceBitmap::new(4)));
    }

    /// Peer-leave subtraction carries over naturally to the new
    /// bookkeeping (HaveAll/HAVE/HaveNone share `peer_avail` via the
    /// extracted face [`remove_peer_avail`] — handle_peer_left goes
    /// through it): a HaveAll all-ones row zeroes rarity and removes the
    /// row on leave; a HaveNone all-zero row leaves by zero-subtraction,
    /// idempotently.
    #[test]
    fn leave_subtracts_have_all_and_have_none_bookkeeping() {
        let mut face = adv_face(4);
        note_peer_have_all(&mut face, 5);
        note_peer_have_none(&mut face, 6);
        for i in 0..4u64 {
            assert_eq!(face.stat_man.count(i), 1, "the HaveAll peer fully registered");
        }
        remove_peer_avail(&mut face, 5);
        for i in 0..4u64 {
            assert_eq!(face.stat_man.count(i), 0, "the HaveAll row's leave subtracts");
        }
        remove_peer_avail(&mut face, 6);
        for i in 0..4u64 {
            assert_eq!(face.stat_man.count(i), 0, "the HaveNone row's leave is a zero-subtraction idempotent");
        }
        assert!(!face.peer_avail.contains_key(&5));
        assert!(!face.peer_avail.contains_key(&6));
    }

    /// Regression: with only HaveNone peers connected, dispatch sends
    /// zero requests (no mistaken unlock — the old behavior of the "no
    /// evidence" path is kept); the existing evidence paths
    /// (bitfield/HAVE) are unchanged and stay pinned by the existing
    /// tables and spread tests.
    #[tokio::test]
    async fn have_none_peer_alone_dispatches_zero_requests() {
        let root = tokio_util::sync::CancellationToken::new();
        let mut face = adv_face(4);
        let (handle, _remote) = choke_peer_pair(&root).await;
        face.peers.push(handle);
        face.peer_cuids.push(13);
        note_peer_have_none(&mut face, 13);
        dispatch_face(&mut face, 0);
        assert!(
            dispatch_is_empty(&face),
            "a HaveNone peer gets zero requests (waiting for real advertising)"
        );
        root.cancel();
    }

    /// Refetch-queue advertisement gating: entries wait in the queue and
    /// are not dispatched while no peer advertises the piece (the old
    /// fallback blind-picked peer 0); regular dispatch sends zero
    /// requests when no advertising peer exists (no in-flight
    /// bookkeeping, no reply churn). This drives the queue-management
    /// layer of [`dispatch_face`] with an empty peers face; the wire-
    /// level zero-request end-to-end lives in tests/advertised_dispatch.rs.
    #[test]
    fn dispatch_face_gates_refetch_on_advertisement() {
        let mut face = adv_face(2);
        // A refetch entry is queued (no peer connected) -> it stays
        // queued after a dispatch round.
        face.refetch.push((0, 0, merkle::BLOCK_SIZE));
        dispatch_face(&mut face, 0);
        assert_eq!(face.refetch, vec![(0, 0, merkle::BLOCK_SIZE)]);
        assert!(face.blocks_sent.is_empty() && face.dispatch_replies.is_empty());
        // Regular dispatch (no peers): no in-flight bookkeeping is
        // created.
        dispatch_face(&mut face, 0);
        assert!(face.blocks_sent.is_empty());
    }

    // ---- Dispatch spread ----

    /// Spread-round selection decision table
    /// ([`select_advertised_piece_spread`]; source chain in its docs —
    /// aria2 DefaultPieceStorage.cc isPieceUsed exclusion + :322-331
    /// per-peer checkout + getMissingFastPiece :293/:351 fallback).
    /// Rows: an empty claimed set matches the plain selection; pieces
    /// inside the claimed set are skipped; a fully claimed advertised
    /// set -> None (the caller falls back, no idle peer); the advertised
    /// intersect incomplete intersect unclaimed constraint is preserved.
    #[test]
    fn spread_selection_table() {
        let stat = PieceStatMan::new(4, &mut |n| n / 2);
        let full = Some(PieceBitmap::ones(4));
        let none_done = vec![false; 4];
        let mut claimed = ClaimedSet::with_len(4);

        // Row 1: claimed empty -> the same as the plain selection (the
        // same rarest-first first pick).
        let plain = select_advertised_piece(full.as_ref(), &none_done, &stat, None);
        let spread = select_advertised_piece_spread(full.as_ref(), &none_done, &stat, &claimed, None);
        assert_eq!(plain, spread, "row 1: empty claimed = the original selection");
        let Some(first) = spread else {
            panic!("row 1: a non-empty full-advertised face must yield a selection");
        };

        // Row 2: the first pick claimed -> move to the next-best (skip
        // the piece in flight elsewhere).
        claimed.mark_claimed(first);
        let Some(second) =
            select_advertised_piece_spread(full.as_ref(), &none_done, &stat, &claimed, None)
        else {
            panic!("row 2: after 4 pieces with 1 claimed a candidate must still exist");
        };
        assert_ne!(second, first, "row 2: another peer's in-flight piece is skipped");
        // Claim again: the third choice still differs (three fully
        // advertising peers each get a different piece).
        claimed.mark_claimed(second);
        let Some(third) =
            select_advertised_piece_spread(full.as_ref(), &none_done, &stat, &claimed, None)
        else {
            panic!("row 2: after 4 pieces with 2 claimed a candidate must still exist");
        };
        assert_ne!(third, first, "row 2: claimed picks are pairwise distinct (a)");
        assert_ne!(third, second, "row 2: claimed picks are pairwise distinct (b)");

        // Row 3: everything claimed -> None (the caller falls back to the
        // plain selection; the peer does not idle).
        for p in 0..4u64 {
            claimed.mark_claimed(p);
        }
        assert_eq!(
            select_advertised_piece_spread(full.as_ref(), &none_done, &stat, &claimed, None),
            None,
            "row 3: all claimed -> None"
        );

        // Row 4: the intersection constraint holds — with {2,3}
        // advertised and 3 claimed, piece 2 is still selected; with only
        // piece 3 advertised and claimed -> None (the done/advertisement
        // constraints are not loosened by spreading).
        let avail2 = PieceBitmap::from_bools(&[false, false, true, true]);
        let mut claimed2 = ClaimedSet::with_len(4);
        claimed2.mark_claimed(3);
        assert_eq!(
            select_advertised_piece_spread(Some(&avail2), &none_done, &stat, &claimed2, None),
            Some(2),
            "row 4a: advertised ∩ unclaimed candidates as usual"
        );
        let avail2 = PieceBitmap::from_bools(&[false, false, false, true]);
        assert_eq!(
            select_advertised_piece_spread(Some(&avail2), &none_done, &stat, &claimed2, None),
            None,
            "row 4b: only claimed pieces remain -> None"
        );
    }

    /// Dispatch spread ([`dispatch_face`] wiring, a real-swarm probe
    /// regression): three fully advertising peers each claim a DIFFERENT
    /// piece in one round (the old behavior funneled deterministic-order
    /// selection onto the same peer — with 39 connections only the first
    /// connection got blocks); zero duplicate dispatch of pieces in
    /// flight elsewhere; zero requests when everything is claimed (no
    /// resend); stale in flight (>= [`DISPATCH_REISSUE_WINDOW`]) can be
    /// taken over and redispatched (the self-healing semantics is
    /// unchanged).
    ///
    /// Counting note: with the default floor of 4, rarest-first
    /// cross-piece append is always on — each peer fills its supply
    /// window with the primary piece plus an adjacent chain (within the
    /// checkout cap). The old single-piece-era counting row "3 peers = 3
    /// pieces" becomes all pieces claimed; the spread semantics itself
    /// (pieces pairwise distinct + every peer dispatched) is unchanged.
    ///
    /// Counting note: with the default window 6 -> 16 the fixture grew
    /// from 8 to 48 pieces (with window 16 a single peer's chain
    /// swallows an 8-piece face, making the three-peer spread
    /// unobservable). Claiming every piece is no longer expected: the
    /// three-chain shape follows the rarity order (fixture-seeded) —
    /// primary pieces 34/19/10, chains 34-47 (broken at the file tail),
    /// 19-33 (stopped by another peer's claim), 10-18; pieces 0-9 sort
    /// last with no owner (3x16 window supply exhausted). The assertions
    /// anchor the deterministic chain shape: the spread core =
    /// pairwise-disjoint chains + contiguous claims per peer (the
    /// adjacent-chain structure) + at most window 16 blocks per peer.
    #[tokio::test]
    async fn dispatch_spreads_claims_across_peers() {
        // Peers + advertisement assembly (the duplex remotes must be
        // kept alive — dropping one disconnects the peer = the command
        // channel closes).
        async fn spread_face(
            root: &tokio_util::sync::CancellationToken,
        ) -> (FaceState, Vec<tokio::io::DuplexStream>) {
            let mut face = adv_face(48);
            let mut remotes = Vec::new();
            for cuid in 1..=3u64 {
                let (handle, remote) = choke_peer_pair(root).await;
                face.peers.push(handle);
                face.peer_cuids.push(cuid);
                note_peer_bitfield(&mut face, cuid, &[0xFF; 6]);
                remotes.push(remote);
            }
            (face, remotes)
        }
        // Claimed pieces aggregated per peer (ascending) — the face for
        // the chain-shape assertions.
        fn runs_by_cuid(face: &FaceState) -> Vec<(u64, Vec<u64>)> {
            let mut by_cuid: std::collections::HashMap<u64, Vec<u64>> =
                std::collections::HashMap::new();
            for (p, _, c) in dispatch_entries(face) {
                by_cuid.entry(c).or_default().push(p);
            }
            let mut runs: Vec<(u64, Vec<u64>)> = by_cuid
                .into_iter()
                .map(|(c, mut v)| {
                    v.sort_unstable();
                    (c, v)
                })
                .collect();
            runs.sort_by_key(|(c, _)| *c);
            runs
        }
        let mut roots = Vec::new();

        // Row 1 (spread): 3 fully advertising peers -> one contiguous
        // chain per peer (primary + adjacent appends), chains pairwise
        // disjoint (at most one claim per piece), and all 3 peers get
        // dispatch.
        let root = tokio_util::sync::CancellationToken::new();
        let (mut face, remotes) = spread_face(&root).await;
        roots.push(root);
        dispatch_face(&mut face, 0);
        let entries = dispatch_entries(&face);
        let claimed_pieces: std::collections::HashSet<u64> =
            entries.iter().map(|&(p, _, _)| p).collect();
        assert_eq!(
            claimed_pieces.len(),
            entries.len(),
            "row 1: at most one claim per piece (blocks = pieces, single-block pieces)"
        );
        let runs = runs_by_cuid(&face);
        assert_eq!(
            runs,
            vec![
                (1, (34..=47u64).collect::<Vec<_>>()),
                (2, (19..=33u64).collect::<Vec<_>>()),
                (3, (10..=18u64).collect::<Vec<_>>()),
            ],
            "row 1: the three-chain shape (window 16: primary pieces 34/19/10 + \
             adjacent chains; breakpoints = the file tail / another peer's claim / \
             window supply exhausted — pieces 0-9 sort last with no owner)"
        );
        for (_, pieces) in &runs {
            assert!(
                pieces.len() <= 16,
                "row 1: each peer <= 16 blocks of the window (the supply cap), got {}",
                pieces.len()
            );
            assert!(
                pieces.windows(2).all(|w| w[1] == w[0] + 1),
                "row 1: each peer's claims contiguous (the adjacent-chain structure)"
            );
        }
        let dispatched_cuids: std::collections::HashSet<u64> =
            dispatch_entries(&face).into_iter().map(|(_, _, c)| c).collect();
        assert_eq!(dispatched_cuids.len(), 3, "row 1: all 3 peers receive dispatch");
        let _keep_alive: Vec<tokio::io::DuplexStream> = remotes;

        // Row 2 (zero duplicates in flight): a fresh face + piece 20
        // pre-claimed (fresh InFlight, landing mid-chain 19-33 of peer 2)
        // -> piece 20 gets zero dispatch and peer 2's chain soft-breaks
        // at 20 and resumes (the default N=2: skip 1 piece -> chain
        // 21-33; primary 19 + a skipped tail; the =0 old "break at the
        // piece" shape is pinned by the dedicated skipping decision
        // tables).
        let root = tokio_util::sync::CancellationToken::new();
        let (mut face, remotes) = spread_face(&root).await;
        roots.push(root);
        seed_blocks_sent(&mut face, 20, Instant::now(), &[(0, BlockState::InFlight)]);
        dispatch_face(&mut face, 0);
        assert!(
            !dispatch_entries(&face).iter().any(|&(p, _, _)| p == 20),
            "row 2: zero duplicate dispatch of another peer's in-flight piece"
        );
        assert_eq!(
            runs_by_cuid(&face),
            vec![
                (1, (34..=47u64).collect::<Vec<_>>()),
                (
                    2,
                    std::iter::once(19u64).chain(21..=33u64).collect::<Vec<_>>()
                ),
                (3, (10..=18u64).collect::<Vec<_>>()),
            ],
            "row 2: the pre-claimed piece 20 is soft-skipped (peer 2 = primary 19 + \
             skip-chain 21-33); the other two chains untouched"
        );
        let _keep_alive: Vec<tokio::io::DuplexStream> = remotes;

        // Row 3 (everything claimed -> zero requests): all 48 pieces
        // fresh InFlight -> after the fallback the candidate set is
        // empty and no request is produced (an idle peer beats resending
        // in flight).
        let root = tokio_util::sync::CancellationToken::new();
        let (mut face, remotes) = spread_face(&root).await;
        roots.push(root);
        for p in 0..48u64 {
            seed_blocks_sent(&mut face, p, Instant::now(), &[(0, BlockState::InFlight)]);
        }
        dispatch_face(&mut face, 0);
        assert!(
            dispatch_is_empty(&face) && face.dispatch_replies.is_empty(),
            "row 3: zero requests when everything is claimed (no resending in flight)"
        );
        let _keep_alive: Vec<tokio::io::DuplexStream> = remotes;

        // Row 4 (stale claims can be taken over): the other 47 pieces
        // all fresh in flight (the claim face is closed) + piece 0's
        // in-flight mark beyond the reissue window -> piece 0 no longer
        // counts as claimed and is taken over and redispatched (the
        // anti-starvation semantics; spreading does not change it).
        // Row detail: these blocks have no dispatch owner (synthetic in
        // flight, never dispatched) -> the reissue window takes the
        // unowned fallback = the existing 2s (the adaptive read side
        // only applies to attributable blocks) — a 2.05s-old mark already
        // counts as stale; the row's assertions are unchanged.
        let root = tokio_util::sync::CancellationToken::new();
        let (mut face, remotes) = spread_face(&root).await;
        roots.push(root);
        let stale = Instant::now() - DISPATCH_REISSUE_WINDOW - Duration::from_millis(50);
        for p in 1..48u64 {
            seed_blocks_sent(&mut face, p, Instant::now(), &[(0, BlockState::InFlight)]);
        }
        seed_blocks_sent(&mut face, 0, stale, &[(0, BlockState::InFlight)]);
        dispatch_face(&mut face, 0);
        assert!(
            dispatch_owner(&face, 0, 0).is_some(),
            "row 4: a stale in-flight claim can be taken over and redispatched \
             (everything else claimed -> the only dispatchable piece)"
        );
        let _keep_alive: Vec<tokio::io::DuplexStream> = remotes;

        for root in roots {
            root.cancel();
        }
    }

    /// Reissue-window clamp table (rows 1-5 go through the
    /// [`reissue_window`] production entry — env unset = the default 5s
    /// ceiling path; rows 6-9 exercise the ceiling arm via
    /// [`reissue_window_ceiled`] direct injection — env is process-
    /// immutable (edition 2024 forbids unsafe, no set_var), so the knob
    /// is injected through the ceil parameter):
    /// row 1 a fast peer (the adaptive 2s floor) -> the existing 2s
    /// (supply latency does not regress); row 2 sub-floor -> floored at
    /// 2s; row 3 a slow peer (adaptive 3s) -> window 3s (extends with
    /// the adaptive value); row 4 no samples (adaptive = the configured
    /// 60s cap) -> capped at 5s; row 5 out of range (100s) -> still 5s
    /// (min before max, the capping order); rows 6-7 knob injected 15/30
    /// -> the window ceiling follows (the 60/100s adaptive values are
    /// capped at the ceil); row 8 sub-floor after the knob raises the
    /// cap -> still floored at 2s; row 9 adaptive 3s < ceil 15s -> still
    /// the adaptive value (the cap only limits, never raises).
    #[test]
    fn reissue_window_clamp_table() {
        assert_eq!(
            reissue_window(Duration::from_secs(2)),
            DISPATCH_REISSUE_WINDOW,
            "row 1: a fast peer = the existing 2s window"
        );
        assert_eq!(
            reissue_window(Duration::from_millis(500)),
            DISPATCH_REISSUE_WINDOW,
            "row 2: sub-floor floored at 2s"
        );
        assert_eq!(
            reissue_window(Duration::from_secs(3)),
            Duration::from_secs(3),
            "row 3: a slow peer's window extends with the adaptive value"
        );
        assert_eq!(
            reissue_window(Duration::from_secs(60)),
            REISSUE_WINDOW_CEIL,
            "row 4: no samples (the 60s configured cap) -> capped at 5s"
        );
        assert_eq!(
            reissue_window(Duration::from_secs(100)),
            REISSUE_WINDOW_CEIL,
            "row 5: the capping order min before max"
        );
        assert_eq!(
            reissue_window_ceiled(Duration::from_secs(60), Duration::from_secs(15)),
            Duration::from_secs(15),
            "row 6: knob=15 -> the 60s adaptive value capped at 15s (the A/B arm)"
        );
        assert_eq!(
            reissue_window_ceiled(Duration::from_secs(100), Duration::from_secs(30)),
            Duration::from_secs(30),
            "row 7: knob=30 -> the same capping-order min-before-max shape (the A/B arm)"
        );
        assert_eq!(
            reissue_window_ceiled(Duration::from_millis(500), Duration::from_secs(15)),
            DISPATCH_REISSUE_WINDOW,
            "row 8: after the knob raises the ceiling, sub-floor still floors at 2s"
        );
        assert_eq!(
            reissue_window_ceiled(Duration::from_secs(3), Duration::from_secs(15)),
            Duration::from_secs(3),
            "row 9: adaptive 3s < ceil 15s -> the adaptive value kept"
        );
    }

    /// Dispatch-round supply cap decision table (a spec formula; the
    /// [`supply_cap`] pure function): row 1 normal (target 10, in
    /// flight 4, ample headroom) -> 6; row 2 depth saturated (in flight >=
    /// target) -> 0 (saturating subtraction, no chasing); row 3 a
    /// channel constraint (headroom 2) -> 2 (min semantics); row 4 both
    /// constraints take the smaller (target headroom 6, headroom 2) ->
    /// 2.
    #[test]
    fn supply_cap_decision_table() {
        assert_eq!(supply_cap(10, 4, 64), 6, "row 1: target minus in flight");
        assert_eq!(supply_cap(4, 5, 64), 0, "row 2: in flight over target -> saturates to 0");
        assert_eq!(supply_cap(500, 0, 2), 2, "row 3: capped by channel headroom");
        assert_eq!(supply_cap(8, 2, 2), 2, "row 4: both constraints take the smaller");
        assert_eq!(supply_cap(0, 0, 64), 0, "row 5: zero target (the pre-window-floor shape) = 0");
    }

    /// Supply-cap dispatch wiring: a real PeerTask handle with
    /// `max_out_request_queue: 2` (mirror initial value min(6,2) = 2,
    /// see the bt-side wiring tests) — of a multi-block piece only 2
    /// candidates are enqueued (the cap intercepts); the remaining
    /// candidates are NOT marked in flight, not claimed, and leave no
    /// replies (the same semantics as the channel-full skip; they stay
    /// queued for the next trigger). Block-length face: piece = 4x16KiB
    /// (adv_face single-block pieces cannot exercise the cap, hence the
    /// custom piece length).
    #[tokio::test]
    async fn dispatch_supply_cap_gates_per_peer_depth() {
        let root = tokio_util::sync::CancellationToken::new();
        let mut face = adv_face(2);
        // Piece 0 = 4 blocks (4x16KiB).
        face.piece_bytes = vec![4 * 16384, 16384].into();
        let config = taiji_bt::peer::PeerConfig {
            max_out_request_queue: 2,
            ..taiji_bt::peer::PeerConfig::flat()
        };
        let (local, mut remote) = tokio::io::duplex(64 * 1024);
        let (handle, _join, _data) = taiji_bt::peer::PeerTask::spawn(&root, local, config);
        // Unchoke + wait for the mirror to flip (the dispatch choke gate
        // precondition, same as choke_peer_pair).
        use tokio::io::AsyncWriteExt as _;
        remote
            .write_all(&[0, 0, 0, 1, 1])
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let deadline = Instant::now() + Duration::from_secs(2);
        while handle.is_choking_us() {
            assert!(
                Instant::now() < deadline,
                "the unchoke mirror did not flip within the deadline"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        face.peers.push(handle);
        face.peer_cuids.push(1);
        // Advertise only piece 0 (an MSB-order bitmap) — unambiguous
        // selection (if piece 1 were advertised it could be picked first
        // under equal availability, and its single-block shape cannot
        // exercise the cap).
        note_peer_bitfield(&mut face, 1, &[0b1000_0000]);
        assert_eq!(face.peers[0].target_request_window(), 2, "the ceiling mirror carried through");
        dispatch_face(&mut face, 0);
        // Exactly 2 in-flight marks (the cap intercepts candidates 3/4):
        // unenqueued candidates are not marked in flight and leave no
        // replies (the same semantics as the channel-full skip).
        let sent = face
            .blocks_sent
            .get(&0)
            .unwrap_or_else(|| panic!("piece 0 in-flight marks"));
        assert_eq!(sent.tracked_count(), 2, "supply cap = 2: of 4 candidates only 2 enqueued");
        assert_eq!(face.dispatch_replies.len(), 2, "receipts exist only on enqueued requests");
        root.cancel();
    }

    /// Reissue-window read-side wiring ([`dispatch_face`] via the
    /// checkout continuation arm): the block is owned by a real task
    /// handle (`choke_peer_pair`, no RTT sample -> adaptive timeout =
    /// the configured 60s cap -> window = [`REISSUE_WINDOW_CEIL`] 5s).
    /// Row 1 (no samples, fresh within the window, no takeover): 2.5s in
    /// flight < 5s -> the in-flight mark is not refreshed (if the
    /// implementation wrongly used the fixed 2s fallback it would take
    /// over at 2.5s — this row is the counter-evidence that the mirror
    /// is really consumed); row 2 (no samples, past the window,
    /// takeover): 5.05s >= 5s -> the continuation arm takes over and
    /// redispatches (the in-flight mark refreshed + a dispatch reply
    /// present).
    #[tokio::test]
    async fn reissue_window_uses_adaptive_mirror_wiring() {
        // Row 1: a peer without samples, 2.5s in flight = within the
        // window -> no takeover.
        let root = tokio_util::sync::CancellationToken::new();
        let mut face = adv_face(8);
        let (handle, _remote) = choke_peer_pair(&root).await;
        face.peers.push(handle);
        face.peer_cuids.push(1);
        note_peer_bitfield(&mut face, 1, &[0b1111_1111]);
        let stale = Instant::now() - Duration::from_millis(2500);
        seed_blocks_sent(&mut face, 0, stale, &[(0, BlockState::InFlight)]);
        dispatch_note(&mut face, 0, 0, 1);
        face.peer_state_row(1).piece = Some(0);
        dispatch_face(&mut face, 0);
        match face.blocks_sent.get(&0).map(|l| (l.block_state(0), l.dispatched_at())) {
            Some((BlockState::InFlight, t)) => {
                assert_eq!(t, stale, "row 1: 2.5s < the 5s sampleless window, no takeover");
            }
            _other => panic!("row 1: the in-flight bookkeeping was rewritten (not InFlight)"),
        }
        assert!(
            face.dispatch_replies.iter().all(|(p, _, _)| *p != 0),
            "row 1: no new dispatch receipt for piece 0 (counter-evidence that the \
             mirror is consumed; cross-piece appends from the default floor enqueue \
             receipts for other pieces, unrelated to this row)"
        );
        root.cancel();

        // Row 2: a peer without samples, 5.05s in flight = past the
        // window -> takeover and redispatch.
        let root = tokio_util::sync::CancellationToken::new();
        let mut face = adv_face(8);
        let (handle, _remote) = choke_peer_pair(&root).await;
        face.peers.push(handle);
        face.peer_cuids.push(1);
        note_peer_bitfield(&mut face, 1, &[0b1111_1111]);
        let stale = Instant::now() - REISSUE_WINDOW_CEIL - Duration::from_millis(50);
        seed_blocks_sent(&mut face, 0, stale, &[(0, BlockState::InFlight)]);
        dispatch_note(&mut face, 0, 0, 1);
        face.peer_state_row(1).piece = Some(0);
        dispatch_face(&mut face, 0);
        match face.blocks_sent.get(&0).map(|l| (l.block_state(0), l.dispatched_at())) {
            Some((BlockState::InFlight, t)) => {
                assert_ne!(t, stale, "row 2: 5.05s >= the 5s window; the takeover redispatch refreshes the in-flight mark");
            }
            _other => panic!("row 2: the in-flight bookkeeping was rewritten (not InFlight)"),
        }
        assert!(
            !face.dispatch_replies.is_empty(),
            "row 2: the takeover redispatch produces a dispatch receipt"
        );
        assert_eq!(
            dispatch_owner(&face, 0, 0),
            Some(1),
            "row 2: takeover at the same coordinate (the only connected peer)"
        );
        root.cancel();
    }

    /// Reciprocity choke gate decision table (the aria2
    /// `DefaultBtInteractive::fillPiece` cc:375-402 port; the
    /// `dispatch_face_selected_with_stream` main-loop gate + the
    /// [`peer_with_piece`] endpoint gate):
    /// Row 1 (choked -> zero requests): the only advertising peer chokes
    /// us -> dispatch sends zero requests (no in-flight bookkeeping, no
    /// dispatch target) and `peer_with_piece` returns None — injecting
    /// would be pure waste (with fast-ext the reject would bounce,
    /// without it the request would vanish -> slot timeout -> snub ->
    /// the peer is permanently excluded from choke candidates = a
    /// reciprocity deadlock).
    /// Row 2 (unchoke restores): the same face, the same peer, an Unchoke
    /// frame arrives -> rerunning enqueues requests at that peer (the
    /// supply recovery path; the unchoke-edge redelivery trigger is
    /// carried by `AvailEvent::Unchoked`, see the bt-side
    /// `unchoke_emits_avail_event_edge`).
    #[tokio::test]
    async fn dispatch_choke_gate_decision_table() {
        // Row 1 (choked -> zero requests).
        let root = tokio_util::sync::CancellationToken::new();
        let mut face = adv_face(8);
        let (handle, mut remote) = choked_peer_pair(&root).await;
        face.peers.push(handle);
        face.peer_cuids.push(21);
        note_peer_bitfield(&mut face, 21, &[0b1111_1111]);
        dispatch_face(&mut face, 0);
        assert!(
            dispatch_is_empty(&face) && face.blocks_sent.is_empty(),
            "row 1: a choked peer gets zero requests (no in-flight / no dispatch target)"
        );
        assert_eq!(
            peer_with_piece(&face, 0),
            None,
            "row 1: all-choke candidates -> selection None (left queued, waiting)"
        );

        // Row 2 (Unchoke -> dispatch restored).
        {
            use tokio::io::AsyncWriteExt as _;
            remote
                .write_all(&[0, 0, 0, 1, 1])
                .await
                .unwrap_or_else(|e| panic!("{e}"));
            let deadline = Instant::now() + Duration::from_secs(2);
            while face.peers[0].is_choking_us() {
                assert!(Instant::now() < deadline, "row 2: the unchoke mirror timed out");
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        dispatch_face(&mut face, 0);
        // Note: with the default floor of 4 the cross-piece append
        // enqueues in the same round (primary + adjacent chain, multiple
        // coordinates with this single-block-piece fixture) — this row's
        // focus is that all requests land at the unchoked peer (the
        // target face); the per-coordinate shape is pinned by the
        // multi_piece tests.
        let dispatch_targets: std::collections::HashSet<u64> =
            dispatch_entries(&face).into_iter().map(|(_, _, c)| c).collect();
        assert!(!dispatch_targets.is_empty(), "row 2: after the unchoke, requests are enqueued");
        assert_eq!(
            dispatch_targets,
            std::collections::HashSet::from([21u64]),
            "row 2: after the unchoke, all requests are enqueued at that peer"
        );
        let _keep_alive = remote;
        root.cancel();
    }

    /// The continuation arm (an aria2 `DefaultPieceStorage.cc`
    /// getMissingPiece(peer) whole-piece checkout port;
    /// `FaceState::peer_piece`):
    /// Row 1 (continuation): after a peer claims piece P in round one,
    /// the next round CONTINUES on P — with every block of the claimed
    /// piece fresh InFlight (the peer's window is full) there are zero
    /// new claims. Regression lock: previously each dispatch round
    /// re-selected statelessly, so under slow RTT convergence peers
    /// accumulated partial pieces round after round.
    /// Row 2 (stale continuation): if the checked-out piece's in-flight
    /// marks pass the reissue window the continuation arm still selects
    /// that piece and takes over the stale blocks (the piece still
    /// converges via continuation; the piece is not switched).
    /// Row 3 (release): the claimed piece completes (done bitmap +
    /// bookkeeping cleanup) -> the checkout is invalidated and the next
    /// round claims a new piece.
    #[tokio::test]
    async fn dispatch_continues_own_partial_piece_until_release() {
        // Multi-block-piece geometry (6 pieces x 4 blocks): single-block
        // faces (adv_face) have no "partial piece" shape.
        // Chain-break note: with the default floor of 4 the cross-piece
        // append is always on — the advertised set is spaced non-
        // adjacently; with the default N=2 a soft break may skip <= 2
        // pieces (lookahead d <= 3) — the advertised set {0, 5} (gap 5)
        // lies outside the skip window (a hard chain break), preserving
        // this test's focus on the "one piece per peer" continuation
        // face (cross-piece append behavior is pinned by the
        // multi_piece tests).
        async fn multi_face(
            root: &tokio_util::sync::CancellationToken,
        ) -> (FaceState, tokio::io::DuplexStream) {
            let mut face = adv_face(6);
            let blocks = 4u64;
            let piece_len = u64::from(merkle::BLOCK_SIZE) * blocks;
            face.piece_bytes = vec![piece_len; 6].into();
            face.piece_goffs = Arc::new((0..6).map(|k| k * piece_len).collect());
            // The progress model is isomorphic to the face geometry (6
            // pieces x 4 blocks; piece_len = the piece length).
            face.progress =
                ProgressModel::from_lengths(&[piece_len * 6], piece_len as u32);
            let (handle, remote) = choke_peer_pair(root).await;
            face.peers.push(handle);
            face.peer_cuids.push(1);
            note_peer_bitfield(&mut face, 1, &[0b1000_0100]);
            (face, remote)
        }
        let mut roots = Vec::new();

        // Row 1 (continuation + zero new claims with a full window).
        let root = tokio_util::sync::CancellationToken::new();
        let (mut face, remote) = multi_face(&root).await;
        roots.push(root);
        dispatch_face(&mut face, 0);
        // Yield: the PeerTask is a real task (command channel cap 8);
        // inside a single-threaded test it only consumes commands and
        // replies when yielded, so later rounds' enqueues are not
        // blocked by a full channel.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let first_piece = face
            .peer_state
            .get(&1)
            .and_then(|ps| ps.piece)
            .unwrap_or_else(|| panic!("row 1: the first-round claim must register the checkout"));
        assert_eq!(
            dispatch_entries(&face)
                .into_iter()
                .map(|(p, _, _)| p)
                .collect::<std::collections::HashSet<_>>(),
            std::collections::HashSet::from([first_piece]),
            "row 1: the first round claims only the checkout piece"
        );
        dispatch_face(&mut face, 0);
        assert_eq!(
            face.peer_state.get(&1).and_then(|ps| ps.piece),
            Some(first_piece),
            "row 1: the next round continues on the same piece (checkout kept)"
        );
        assert!(
            dispatch_entries(&face)
                .iter()
                .all(|&(p, _, _)| p == first_piece),
            "row 1: the full-window shape claims nothing new (the partial-piece \
             proliferation regression lock), got {:?}",
            dispatch_entries(&face)
        );

        // Row 2 (stale continuation): all in-flight marks of the
        // checked-out piece are rewound past the reissue window -> the
        // continuation arm still selects the piece and takes over the
        // stale blocks (no piece switch).
        // Adaptation note: the blocks are owned by peer 1 (a real task
        // handle, no RTT sample -> adaptive timeout = the configured 60s
        // cap -> reissue window = max(2s, min(60s, 5s)) =
        // [`REISSUE_WINDOW_CEIL`] 5s) — the stale marks must exceed 5s
        // to count as stale (under the old fixed 2s window a 2.05s mark
        // was stale; under the adaptive window it is still fresh).
        let stale = Instant::now() - REISSUE_WINDOW_CEIL - Duration::from_millis(50);
        // Rewind all slots to past-window InFlight (the piece-level
        // timestamp = stale, ownership kept — in the inline shape "per-
        // block timestamp rewind" converges to the shared timestamp
        // rewind).
        let stale_count = {
            let ledger = face
                .blocks_sent
                .get_mut(&first_piece)
                .unwrap_or_else(|| panic!("row 2: the first-round bookkeeping present"));
            let n = ledger.tracked_count();
            *ledger = PieceSentLedger::new(4, stale);
            for bi in 0..n {
                let begin = (bi as u64 * u64::from(merkle::BLOCK_SIZE)) as u32;
                ledger.set_inflight(begin, Some(0), stale);
            }
            n
        };
        dispatch_face(&mut face, 0);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            face.peer_state.get(&1).and_then(|ps| ps.piece),
            Some(first_piece),
            "row 2: a stale in-flight piece still continues on the same piece"
        );
        assert!(
            dispatch_entries(&face)
                .iter()
                .all(|&(p, _, _)| p == first_piece),
            "row 2: the stale-block takeover resends without switching pieces \
             ({} blocks of bookkeeping)",
            stale_count
        );

        // Row 3 (release): the piece completes -> the checkout is
        // invalidated -> the next round claims a new piece.
        face.progress.set_piece_done_global(first_piece);
        face.blocks_sent.remove(&first_piece);
        dispatch_face(&mut face, 0);
        tokio::time::sleep(Duration::from_millis(20)).await;
        let next_piece = face
            .peer_state
            .get(&1)
            .and_then(|ps| ps.piece)
            .unwrap_or_else(|| panic!("row 3: after release a new piece should be claimed"));
        assert_ne!(
            next_piece, first_piece,
            "row 3: after the checkout is released a new piece is claimed"
        );
        drop(remote);
        for root in roots {
            root.cancel();
        }
    }

    // ---- Multi-piece contiguous requests (supply fills across pieces) ----

    /// Cross-piece supply budget decision table (a reference
    /// request_blocks.cpp ported face `min(rate x 20s, 8MiB) / piece_len`
    /// with a 256KiB piece baseline). The production entry adds the
    /// default floor 4 (`BH_MULTI_PIECE_BUDGET_FLOOR` default 0 -> 4 —
    /// the slow-peer cross-piece gate is always on; the raw ported
    /// values are pinned bit-for-bit by the floor=0 rows of
    /// `multi_piece_supply_budget_floored`):
    /// row 1 a fast seeder (8MiB/s) hits the 8MiB cap = 32 pieces; rows
    /// 2/3 the linear region under the cap (a ported value above the
    /// floor passes through); rows 4-6 the slow-peer/zero-rate shapes
    /// with ported values 2/1/0 land on the floor -> 4; row 7 the cap
    /// boundary (400KiB/s x 20s = 8MiB); row 8 zero-length piece
    /// defense.
    #[test]
    fn multi_piece_supply_budget_decision_table() {
        const P: u64 = 256 * 1024;
        assert_eq!(
            multi_piece_supply_budget(8 * 1024 * 1024, P),
            32,
            "row 1: an 8MiB/s fast seeder = the 8MiB cap, 32 pieces"
        );
        assert_eq!(
            multi_piece_supply_budget(1024 * 1024, P),
            32,
            "row 2: 1MiB/s -> 20MiB hits the same cap"
        );
        assert_eq!(
            multi_piece_supply_budget(128 * 1024, P),
            10,
            "row 3: 128KiB/s -> 2.5MiB/256KiB = 10 (the linear region, the direct-\
             translation value passes above the floor)"
        );
        assert_eq!(
            multi_piece_supply_budget(26 * 1024, P),
            4,
            "row 4: direct translation 2 (exactly 2 pieces in window) lands on the \
             floor -> 4 (the default)"
        );
        assert_eq!(
            multi_piece_supply_budget(13 * 1024, P),
            4,
            "row 5: direct translation 1 (a single-piece budget) lands on the floor \
             -> 4 (the slow-peer cross-piece gate opens)"
        );
        assert_eq!(
            multi_piece_supply_budget(0, P),
            4,
            "row 6: zero rate (no evidence) direct translation 0 -> the floor 4"
        );
        assert_eq!(
            multi_piece_supply_budget(410 * 1024, P),
            32,
            "row 7: 410KiB/s x 20s = 8,396,800 >= the 8MiB cap (the critical upper side)"
        );
        assert_eq!(
            multi_piece_supply_budget(400 * 1024, P),
            31,
            "row 7b: 400KiB/s x 20s = 8,192,000 < 8MiB (the critical lower side, \
             linear below the cap)"
        );
        assert_eq!(
            multi_piece_supply_budget(8 * 1024 * 1024, 0),
            0,
            "row 8: zero-length piece defense = 0"
        );
    }

    /// Cross-piece supply budget floor decision table (knob 2, the
    /// `multi_piece_supply_budget_floored` pure function direct drive;
    /// the effective floor is clamped [0, 8] by the knob parser — the
    /// same bounds as the checkout default cap): row 1 floor=0 = the
    /// explicit `=0` fallback arm (the old values bit-for-bit; when
    /// unset the current default is 4, pinned by the knob parser table
    /// and budget rows 4-6); rows 2/3 the floor raises above the ported
    /// value (unlocks the slow-peer cross-piece gate); row 4 a ported
    /// value above the floor passes through (fast peers unchanged);
    /// row 5 floor=8 (the parser upper bound); row 6 zero-length piece
    /// defense first (the floor never raises a zero-length piece).
    #[test]
    fn multi_piece_supply_budget_floor_table() {
        const P: u64 = 256 * 1024;
        // floor=0: the explicit `=0` fallback arm = the old values
        // (13KiB/s -> 1 piece; zero rate -> 0).
        assert_eq!(multi_piece_supply_budget_floored(13 * 1024, P, 0), 1);
        assert_eq!(multi_piece_supply_budget_floored(0, P, 0), 0);
        // Floor in effect: max(ported, floor) — zero-reading slow peers
        // raised to 2/4.
        assert_eq!(
            multi_piece_supply_budget_floored(0, P, 2),
            2,
            "a zero reading raised to 2 (the cross-piece gate opens)"
        );
        assert_eq!(multi_piece_supply_budget_floored(13 * 1024, P, 4), 4);
        // A ported value above the floor: passes through (128KiB/s -> 10
        // pieces; fast peers unchanged).
        assert_eq!(multi_piece_supply_budget_floored(128 * 1024, P, 4), 10);
        // floor = 8 (the parser upper bound, same as the checkout cap).
        assert_eq!(multi_piece_supply_budget_floored(0, P, 8), 8);
        // Zero-length piece defense first: the floor never raises a
        // zero-length piece.
        assert_eq!(multi_piece_supply_budget_floored(8 * 1024 * 1024, 0, 4), 0);
    }

    /// Adjacent-piece scan decision table ([`next_adjacent_supply_piece`]):
    /// row 1 a contiguous eligible run -> the next piece; row 2 a goff
    /// gap (file-boundary padding / a hole) breaks the chain; row 3
    /// done/mask-folded pieces; row 4 fresh in flight elsewhere (the
    /// spread exclusion); row 5 not advertised (advertisement
    /// awareness); row 6 the torrent's last piece; row 7 zero-length
    /// piece defense (goff does not advance).
    #[test]
    fn next_adjacent_supply_piece_decision_table() {
        let blk = u64::from(merkle::BLOCK_SIZE);
        let mut face = adv_face(4);
        face.piece_bytes = vec![4 * blk; 4].into();
        face.piece_goffs = Arc::new((0..4).map(|k| k * 4 * blk).collect());
        note_peer_bitfield(&mut face, 7, &[0b1111_0000]);
        face.peer_cuids.push(7);
        let done_all_live = vec![false; 4];
        let claimed = ClaimedSet::with_len(4);

        // Row 1: contiguous + incomplete + unclaimed + advertised ->
        // Some(1).
        assert_eq!(
            next_adjacent_supply_piece(&face, 0, &done_all_live, &claimed, 0),
            Some(1),
            "row 1: a contiguous run fully eligible"
        );

        // Row 2: a goff gap breaks the chain (piece_goffs[2] jumps past
        // the contiguous position).
        face.piece_goffs = Arc::new(vec![0, 4 * blk, 9 * blk, 13 * blk]);
        assert_eq!(
            next_adjacent_supply_piece(&face, 1, &done_all_live, &claimed, 0),
            None,
            "row 2: a discontinuous goff = no contiguous dispatchable piece"
        );
        face.piece_goffs = Arc::new((0..4).map(|k| k * 4 * blk).collect());

        // Row 3: done (done and mask-folded share the source).
        let done_one = vec![false, true, false, false];
        assert_eq!(
            next_adjacent_supply_piece(&face, 0, &done_one, &claimed, 0),
            None,
            "row 3: the adjacent piece is done"
        );

        // Row 4: fresh in flight elsewhere (the spread exclusion).
        let mut claimed_one = ClaimedSet::with_len(4);
        claimed_one.mark_claimed(1);
        assert_eq!(
            next_adjacent_supply_piece(&face, 0, &done_all_live, &claimed_one, 0),
            None,
            "row 4: the adjacent piece already claimed (spread exclusion)"
        );

        // Row 5: not advertised (advertisement awareness).
        let mut face_no_adv = adv_face(4);
        face_no_adv.piece_bytes = vec![4 * blk; 4].into();
        face_no_adv.piece_goffs = Arc::new((0..4).map(|k| k * 4 * blk).collect());
        note_peer_bitfield(&mut face_no_adv, 7, &[0b1000_0000]);
        assert_eq!(
            next_adjacent_supply_piece(&face_no_adv, 0, &done_all_live, &claimed, 0),
            None,
            "row 5: the adjacent piece not in the advertised bitmap"
        );

        // Row 6: the torrent's last piece has no next piece.
        assert_eq!(
            next_adjacent_supply_piece(&face, 3, &done_all_live, &claimed, 0),
            None,
            "row 6: the last piece has no adjacent"
        );

        // Row 7: zero-length piece (goff does not advance) defense.
        let mut pbytes_zero = face.piece_bytes.to_vec();
        pbytes_zero[0] = 0;
        face.piece_bytes = pbytes_zero.into();
        assert_eq!(
            next_adjacent_supply_piece(&face, 0, &done_all_live, &claimed, 0),
            None,
            "row 7: a zero-length piece's goff does not advance = a broken chain"
        );
    }

    /// Adjacent-piece scan, soft-break decision table
    /// ([`next_adjacent_supply_piece_skipping`]; `BH_ADJACENT_SKIP_N`
    /// default 2, previously 0 = off): row 0 max_skip=0 is bit-for-bit
    /// the old function (the whole existing table re-run — pins the `=0`
    /// explicit fallback arm as behavior-identical); row 1 a soft break
    /// (done) skips 1 and continues the chain; row 2 two consecutive
    /// soft breaks skip 2 (within the window) / break outside it; row 3
    /// a hard break (a goff gap) still breaks (no skipping to an
    /// eligible piece past the gap); row 4 the minimal skip distance
    /// (the first eligible piece within the window — d-1 is minimal, no
    /// greed); row 5 claimed/unadvertised soft breaks are judged the
    /// same; row 6 a hard break = a zero-length piece in the walked
    /// segment; row 7 the torrent end (from+d out of range = break).
    #[test]
    fn next_adjacent_supply_piece_skipping_decision_table() {
        let blk = u64::from(merkle::BLOCK_SIZE);
        let mut face = adv_face(6);
        face.piece_bytes = vec![4 * blk; 6].into();
        face.piece_goffs = Arc::new((0..6).map(|k| k * 4 * blk).collect());
        note_peer_bitfield(&mut face, 7, &[0b1111_1100]);
        face.peer_cuids.push(7);
        let done_all_live = vec![false; 6];
        let claimed = ClaimedSet::with_len(6);

        // Row 0: max_skip=0 is bit-for-bit the old function (four rows
        // re-run: fully eligible / break / done / last piece).
        assert_eq!(
            next_adjacent_supply_piece_skipping(&face, 0, 0, &done_all_live, &claimed, 0),
            next_adjacent_supply_piece(&face, 0, &done_all_live, &claimed, 0).map(|p| (p, 0u64)),
            "row 0a: fully eligible — the old Some(1) = the new (1, 0)"
        );
        let done_one = vec![false, true, false, false, false, false];
        assert_eq!(
            next_adjacent_supply_piece_skipping(&face, 0, 0, &done_one, &claimed, 0),
            next_adjacent_supply_piece(&face, 0, &done_one, &claimed, 0).map(|p| (p, 0u64)),
            "row 0b: a done break, both functions judge alike"
        );
        let mut claimed_one = ClaimedSet::with_len(6);
        claimed_one.mark_claimed(1);
        assert_eq!(
            next_adjacent_supply_piece_skipping(&face, 0, 0, &done_all_live, &claimed_one, 0),
            next_adjacent_supply_piece(&face, 0, &done_all_live, &claimed_one, 0)
                .map(|p| (p, 0u64)),
            "row 0c: a claimed break, same verdict"
        );
        assert_eq!(
            next_adjacent_supply_piece_skipping(&face, 5, 0, &done_all_live, &claimed, 0),
            next_adjacent_supply_piece(&face, 5, &done_all_live, &claimed, 0).map(|p| (p, 0u64)),
            "row 0d: the last piece, same verdict"
        );

        // Row 1: a soft break (piece 1 done) skips 1 and continues ->
        // (2, 1).
        assert_eq!(
            next_adjacent_supply_piece_skipping(&face, 0, 2, &done_one, &claimed, 0),
            Some((2, 1)),
            "row 1: a done soft break skips 1 -> piece 2 (skipped=1)"
        );

        // Row 2: two consecutive soft breaks (pieces 1/2 done) — N=2
        // skips 2 -> (3, 2); N=1 is outside the window -> None.
        let done_two = vec![false, true, true, false, false, false];
        assert_eq!(
            next_adjacent_supply_piece_skipping(&face, 0, 2, &done_two, &claimed, 0),
            Some((3, 2)),
            "row 2: two soft breaks skip 2 (within the window)"
        );
        assert_eq!(
            next_adjacent_supply_piece_skipping(&face, 0, 1, &done_two, &claimed, 0),
            None,
            "row 2': a skip of 2 exceeds the N=1 window -> break"
        );

        // Row 3: a hard break (a goff gap in walked segment 1->2; piece
        // 1 is a soft break first, advancing the walk to the gap) —
        // eligible pieces 2/3 beyond the window are not skipped (the
        // segment after the gap is no longer the same chain).
        face.piece_goffs = Arc::new(vec![0, 4 * blk, 9 * blk, 13 * blk, 17 * blk, 21 * blk]);
        assert_eq!(
            next_adjacent_supply_piece_skipping(&face, 0, 2, &done_one, &claimed, 0),
            None,
            "row 3: a goff gap = a hard break still breaks"
        );
        face.piece_goffs = Arc::new((0..6).map(|k| k * 4 * blk).collect());

        // Row 4: the minimal skip distance — piece 1 done, pieces 2 and
        // 3 both eligible -> take (2, 1) not (3, 2) (the first eligible
        // piece within the lookahead window = the minimal gap).
        assert_eq!(
            next_adjacent_supply_piece_skipping(&face, 0, 2, &done_one, &claimed, 0),
            Some((2, 1)),
            "row 4: the minimal skip distance (no greedy reach)"
        );

        // Row 5: claimed/unadvertised soft breaks are judged the same
        // (skip 1 and continue).
        assert_eq!(
            next_adjacent_supply_piece_skipping(&face, 0, 1, &done_all_live, &claimed_one, 0),
            Some((2, 1)),
            "row 5a: a claimed soft break skips 1"
        );
        let mut face_no_adv = adv_face(6);
        face_no_adv.piece_bytes = vec![4 * blk; 6].into();
        face_no_adv.piece_goffs = Arc::new((0..6).map(|k| k * 4 * blk).collect());
        note_peer_bitfield(&mut face_no_adv, 7, &[0b1011_1100]);  // piece 1 not advertised
        face_no_adv.peer_cuids.push(7);
        assert_eq!(
            next_adjacent_supply_piece_skipping(&face_no_adv, 0, 1, &done_all_live, &claimed, 0),
            Some((2, 1)),
            "row 5b: an unadvertised soft break skips 1"
        );

        // Row 6: a hard break = a zero-length piece in the walked
        // segment (piece 1 zero-length -> goff does not advance; piece 1
        // is a soft break first, advancing the walk into the zero-length
        // segment).
        let mut pbytes_zero = face.piece_bytes.to_vec();
        pbytes_zero[1] = 0;
        face.piece_bytes = pbytes_zero.into();
        assert_eq!(
            next_adjacent_supply_piece_skipping(&face, 0, 2, &done_one, &claimed, 0),
            None,
            "row 6: a zero-length piece in the walked segment = a hard break"
        );
        let mut pbytes_restore = face.piece_bytes.to_vec();
        pbytes_restore[1] = 4 * blk;
        face.piece_bytes = pbytes_restore.into();

        // Row 7: past the torrent end (from=5, no lookahead).
        assert_eq!(
            next_adjacent_supply_piece_skipping(&face, 5, 2, &done_all_live, &claimed, 0),
            None,
            "row 7: the last piece has no adjacent (out of range = a broken chain)"
        );
    }

    /// Cross-piece append arm, direct drive ([`supply_adjacent_pieces`]
    /// with real PeerTask handles): a high rate-window reading + a large
    /// supply cap -> the adjacent chain fills up to the checkout cap
    /// (default 16: the primary piece + 15 secondary; the era cap of 8 is
    /// reachable via the `BH_MULTI_PIECE_SUPPLY_MAX=8` explicit
    /// fallback); secondary pieces are registered in
    /// `peer_extra_pieces` and NEVER overwrite the primary checkout (the
    /// continuation arm has priority); piece 16 beyond the cap is
    /// untouched. 8MiB/s with 64KiB pieces (4 blocks/piece): budget =
    /// 8MiB/64KiB = 128 >= 2 (gate open). Under the default soft
    /// accounting a fully in-flight secondary piece counts as a whole
    /// piece (the degenerate shape) — this chain shape is identical
    /// under both arms.
    #[tokio::test]
    async fn supply_adjacent_pieces_fills_chain_to_checkout_cap() {
        let root = CancellationToken::new();
        let blk = u64::from(merkle::BLOCK_SIZE);
        let mut face = adv_face(20);
        face.piece_bytes = vec![4 * blk; 20].into();
        face.piece_goffs = Arc::new((0..20).map(|k| k * 4 * blk).collect());
        face.progress = ProgressModel::from_lengths(&[4 * blk * 20], (4 * blk) as u32);
        let (handle, _remote) = choke_peer_pair(&root).await;
        face.peers.push(handle);
        face.peer_cuids.push(1);
        note_peer_bitfield(&mut face, 1, &[0b1111_1111, 0b1111_1111, 0b1111_0000]);
        // High-rate reading (8MiB/s; a 1s-window fed shape).
        face.peer_state_row(1).down_window = Some(down_windows_for(8.0 * 1024.0 * 1024.0));

        let mut supply_cap = 1000usize;
        let mut claimed = ClaimedSet::with_len(20);
        let mut round_copies = std::collections::HashMap::new();
        let done = vec![false; 20];
        let mut ctx = PieceIssueCtx {
            fi: 0,
            peer_i: 0,
            my_cuid: Some(1),
            block: blk,
            endgame_rf: false,
            last_mile: false,
            supply_cap: &mut supply_cap,
            claimed: &mut claimed,
            round_copies: &mut round_copies,
            endgame_overdue: &std::collections::HashSet::new(),
            endgame_overdue_done: &mut std::collections::HashSet::new(),
            endgame_tail_deadline: std::time::Duration::ZERO,
        };
        supply_adjacent_pieces(&mut face, &mut ctx, 0, &done);

        // Appended chain = pieces 1..16 (cap 16 = the primary piece 0
        // counting one slot + 15 secondary), all 4 blocks of each piece
        // enqueued; piece 0's dispatch belongs to the primary dispatch
        // arm (this direct drive skips the primary arm — the append arm
        // must not dispatch the primary piece).
        for p in 1..16u64 {
            let sent = face
                .blocks_sent
                .get(&p)
                .unwrap_or_else(|| panic!("piece {p} should be in the appended chain"));
            assert_eq!(sent.tracked_count(), 4, "piece {p}: all 4 blocks enqueued");
        }
        assert!(
            !face.blocks_sent.contains_key(&0) && !face.blocks_sent.contains_key(&16),
            "the append arm never touches the primary; the checkout cap 16 intercepts piece 16"
        );
        assert_eq!(
            face.peer_state.get(&1).map(|ps| &ps.extra_pieces),
            Some(&(1..16u64).collect::<Vec<_>>()),
            "secondaries registered in append order"
        );
        assert!(
            face.peer_state.get(&1).is_none_or(|ps| ps.piece.is_none()),
            "the append arm never rewrites the primary checkout (registration belongs \
             to the primary arm's call site)"
        );
        assert_eq!(supply_cap, 1000 - 60, "supply decremented by the enqueued block count");
        assert_eq!(face.dispatch_replies.len(), 60, "each enqueued block leaves a receipt");
        root.cancel();
    }

    /// Cross-piece append arm, old-secondary continuation priority + stale
    /// takeover (no stranding): the primary piece is fresh in flight (no
    /// dispatchable blocks) + an old secondary carries a stale block ->
    /// this round the old secondary's stale block is taken over and
    /// resent BEFORE new pieces are appended (dispatch order = primary ->
    /// old secondary -> new pieces; "in-flight chains finish first");
    /// after the stale block is resent the chain frontier keeps extending
    /// to the checkout cap (default 16; the era cap of 8 is reachable via
    /// the `BH_MULTI_PIECE_SUPPLY_MAX=8` explicit fallback). Under the
    /// default soft accounting a fully in-flight secondary counts as a
    /// whole piece (the degenerate shape) — the chain shape is identical
    /// under both arms.
    #[tokio::test]
    async fn supply_adjacent_pieces_drains_stale_extras_before_append() {
        let root = CancellationToken::new();
        let blk = u64::from(merkle::BLOCK_SIZE);
        let mut face = adv_face(20);
        face.piece_bytes = vec![4 * blk; 20].into();
        face.piece_goffs = Arc::new((0..20).map(|k| k * 4 * blk).collect());
        face.progress = ProgressModel::from_lengths(&[4 * blk * 20], (4 * blk) as u32);
        let (handle, _remote) = choke_peer_pair(&root).await;
        face.peers.push(handle);
        face.peer_cuids.push(1);
        note_peer_bitfield(&mut face, 1, &[0b1111_1111, 0b1111_1111, 0b1111_0000]);
        face.peer_state_row(1).down_window = Some(down_windows_for(8.0 * 1024.0 * 1024.0));

        // Primary piece 0: the first block fresh in flight (the
        // continuation shape — no dispatchable blocks).
        seed_blocks_sent(&mut face, 0, Instant::now(), &[(0, BlockState::InFlight)]);
        // Old secondary 1: the first block stale (> the 5s reissue
        // window) — the stranded shape beyond the continuation arm.
        let stale = Instant::now() - REISSUE_WINDOW_CEIL - Duration::from_millis(50);
        seed_blocks_sent(&mut face, 1, stale, &[(0, BlockState::InFlight)]);
        dispatch_note(&mut face, 1, 0, 1);
        face.peer_state_row(1).piece = Some(0);
        face.peer_state_row(1).extra_pieces = vec![1];

        let mut supply_cap = 1000usize;
        let mut claimed = ClaimedSet::with_len(20);
        let mut round_copies = std::collections::HashMap::new();
        let done = vec![false; 20];
        let mut ctx = PieceIssueCtx {
            fi: 0,
            peer_i: 0,
            my_cuid: Some(1),
            block: blk,
            endgame_rf: false,
            last_mile: false,
            supply_cap: &mut supply_cap,
            claimed: &mut claimed,
            round_copies: &mut round_copies,
            endgame_overdue: &std::collections::HashSet::new(),
            endgame_overdue_done: &mut std::collections::HashSet::new(),
            endgame_tail_deadline: std::time::Duration::ZERO,
        };
        supply_adjacent_pieces(&mut face, &mut ctx, 0, &done);

        // The old secondary's stale block taken over (the timestamp
        // refreshed = resent) + the remaining 3 blocks filled in.
        let sent1 = face
            .blocks_sent
            .get(&1)
            .unwrap_or_else(|| panic!("secondary 1's bookkeeping present"));
        assert_eq!(sent1.tracked_count(), 4, "stale block takeover + the pending blocks filled");
        assert_ne!(
            sent1.dispatched_at(),
            stale,
            "the stale in-flight mark refreshed (takeover resend, piece-level timestamp)"
        );
        // Chain frontier extension (cap 16 = the primary + secondary 1 +
        // new pieces 2..15).
        assert_eq!(
            face.peer_state.get(&1).map(|ps| &ps.extra_pieces),
            Some(&(1..16u64).collect::<Vec<_>>())
        );
        assert!(
            (2..16u64).all(|p| face.blocks_sent.contains_key(&p)),
            "new pieces 2..15 all chained"
        );
        assert!(!face.blocks_sent.contains_key(&16), "the cap 16 intercepts piece 16");
        root.cancel();
    }

    /// Accounting function decision table ([`checkout_weight`]; 256KiB
    /// pieces = a 16 blocks/piece anchor — the caller passes the TOTAL
    /// in-flight block count of the secondary set, so decision rows may
    /// exceed a single piece's block count): row 0 live=0 -> 0 (the
    /// piece complete/arrived = fully released); any non-zero in flight
    /// within one piece -> 1 (ceil never folds to zero — a half piece
    /// 8/16 still occupies 1); a full piece (= bpp) -> 1; cross-piece
    /// 17-32 -> 2 and 33 -> 3; the bpp=0 zero-length defense -> 0.
    #[test]
    fn checkout_weight_decision_table() {
        // Row 0: live=0 -> 0 (fully arrived / no bookkeeping = the slot
        // is fully released).
        assert_eq!(checkout_weight(0, 16), 0);
        // Half piece (a 16-block piece with 8 arrived -> 8 in flight):
        // ceil(8/16) = 1 (never folds to zero within a piece).
        assert_eq!(checkout_weight(8, 16), 1);
        // Full piece: live = bpp -> 1; any non-zero within one piece is
        // the same (1 block in flight -> 1).
        assert_eq!(checkout_weight(16, 16), 1);
        assert_eq!(checkout_weight(1, 16), 1);
        // Cross-piece boundary (the total exceeds one piece's blocks):
        // 17-32 -> 2, exactly 32 -> 2, 33 -> 3.
        assert_eq!(checkout_weight(17, 16), 2);
        assert_eq!(checkout_weight(32, 16), 2);
        assert_eq!(checkout_weight(33, 16), 3);
        // 64KiB pieces (4 blocks/piece): the same shape.
        assert_eq!(checkout_weight(4, 4), 1);
        assert_eq!(checkout_weight(5, 4), 2);
        // Zero-length piece defense: bpp=0 -> 0 (no blocks, no occupancy;
        // the same shape as the next_adjacent row 7).
        assert_eq!(checkout_weight(0, 0), 0);
        assert_eq!(checkout_weight(3, 0), 0);
    }

    /// Occupancy-count switch, both arms ([`checkout_occupancy`]; the
    /// production entry is step 3 of [`supply_adjacent_pieces`], a
    /// single source): OFF = the old whole-piece count `1 + the
    /// continuable count` bit-for-bit (the folded input is pinned
    /// ignored — the fallback face); ON = `1 + checkout_weight(sum in
    /// flight, bpp)`. Half-arrived differential anchor: 7 secondary
    /// pieces x 8 in flight = 56 -> ON occupancy 5 / OFF 8 — the source
    /// of earlier append eligibility; full secondary pieces give both
    /// arms the same value (folding = whole-piece counting, the
    /// degenerate shape; the old semantics is bit-identical on the
    /// full-piece domain).
    #[test]
    fn checkout_occupancy_switch_table() {
        // OFF arm: 1 + len bit-for-bit; the live/bpp inputs are not
        // consumed (any values, the same verdict).
        assert_eq!(checkout_occupancy(false, 0, 0, 0), 1);
        assert_eq!(checkout_occupancy(false, 3, 0, 0), 4);
        assert_eq!(checkout_occupancy(false, 7, 56, 16), 8, "the OFF arm ignores the folded inputs");
        // ON arm: no secondary pieces / all arrived (live=0) -> the
        // primary counts 1.
        assert_eq!(checkout_occupancy(true, 0, 0, 16), 1);
        assert_eq!(checkout_occupancy(true, 7, 0, 16), 1);
        // ON arm: 3 full secondary pieces (48 in flight) -> 1 + 3 (the
        // same as OFF — the degenerate shape).
        assert_eq!(checkout_occupancy(true, 3, 48, 16), 4);
        assert_eq!(checkout_occupancy(false, 3, 48, 16), 4);
        // ON arm half-arrived differential: 7 x 8 in flight -> 1 +
        // ceil(56/16) = 5 (OFF = 8).
        assert_eq!(checkout_occupancy(true, 7, 56, 16), 5);
        // ON arm: bpp=0 (a zero-length piece) -> the primary counts 1.
        assert_eq!(checkout_occupancy(true, 2, 9, 0), 1);
    }

    /// Cross-piece append arm, soft accounting both arms over time
    /// ([`supply_adjacent_pieces_with`] direct drive with injected block
    /// states; default-on, the OFF arm is the `=0` fallback): 15
    /// HALF-ARRIVED secondary pieces (64KiB pieces = 4 blocks/piece with
    /// 2 fresh InFlight + 2 Buffered — the mid-stream shape of a seeder
    /// serving uniformly; the block scale uses small pieces to stay
    /// within the fixture peer command channel capacity of 64) under the
    /// checkout cap 16 (default):
    /// - OFF arm (the `=0` fallback, the old behavior bit-for-bit):
    /// whole-piece counting 1+15 = the cap full -> ZERO appends — the
    /// sawtooth model's "refill only when a whole batch arrives" face;
    /// - ON arm: total in-flight blocks 15x2 = 30 folded to whole pieces
    /// ceil(30/4) = 8 -> occupancy 1+8 = 9, cap headroom 7 -> pieces
    /// 16-22 append EARLY (4 blocks each enqueued, piece 23 intercepted
    /// by the cap) — half-arrived pieces each release about half a slot
    /// and new pieces join the chain early: a continuous flow.
    /// Step 2 (continuation) touches fresh InFlight/Buffered blocks zero
    /// times (the half-arrived shape stays stable); the window dimension
    /// (supply_cap deducted per block) is identical in both arms — a
    /// wider cap is not a wider window.
    #[tokio::test]
    async fn supply_adjacent_pieces_soft_accounting_frees_half_arrived_slots() {
        let root = CancellationToken::new();
        let blk = u64::from(merkle::BLOCK_SIZE);
        let bpp = 4u64;  // 64KiB pieces = 4 blocks/piece (the block scale within the fixture channel capacity)
        let mut face = adv_face(24);
        face.piece_bytes = vec![bpp * blk; 24].into();
        face.piece_goffs = Arc::new((0..24).map(|k| k * bpp * blk).collect());
        face.progress = ProgressModel::from_lengths(&[bpp * blk * 24], (bpp * blk) as u32);
        let (handle, _remote) = choke_peer_pair(&root).await;
        face.peers.push(handle);
        face.peer_cuids.push(1);
        note_peer_bitfield(&mut face, 1, &[0b1111_1111, 0b1111_1111, 0b1111_1111]);
        // High-rate reading (8MiB/s; budget = 8MiB/64KiB = 128 >= 2, the
        // gate is open).
        face.peer_state_row(1).down_window = Some(down_windows_for(8.0 * 1024.0 * 1024.0));
        // 15 half-arrived secondary pieces: blocks 0-1 fresh InFlight,
        // blocks 2-3 Buffered (arrived locally).
        let now = Instant::now();
        for p in 1..16u64 {
            let mut marks = Vec::new();
            for bi in 0..bpp {
                let begin = (bi * blk) as u32;
                marks.push((
                    begin,
                    if bi < 2 {
                        BlockState::InFlight
                    } else {
                        BlockState::Buffered
                    },
                ));
            }
            seed_blocks_sent(&mut face, p, now, &marks);
        }
        face.peer_state_row(1).extra_pieces = (1..16u64).collect();

        // OFF arm (the `=0` fallback, the old behavior bit-for-bit):
        // whole-piece counting 1+15 = the cap 16 full -> zero appends.
        {
            let mut supply_cap = 1000usize;
            let mut claimed = ClaimedSet::with_len(24);
            let mut round_copies = HashMap::new();
            let done = vec![false; 24];
            let mut ctx = PieceIssueCtx {
                fi: 0,
                peer_i: 0,
                my_cuid: Some(1),
                block: blk,
                endgame_rf: false,
                last_mile: false,
                supply_cap: &mut supply_cap,
                claimed: &mut claimed,
                round_copies: &mut round_copies,
                endgame_overdue: &std::collections::HashSet::new(),
                endgame_overdue_done: &mut std::collections::HashSet::new(),
                endgame_tail_deadline: std::time::Duration::ZERO,
            };
        // max_skip=0: the explicit =0 fallback arm (the old break behavior bit-for-bit).
            supply_adjacent_pieces_with(&mut face, &mut ctx, 0, &done, false, 0);
            assert_eq!(
                face.peer_state.get(&1).map(|ps| &ps.extra_pieces),
                Some(&(1..16u64).collect::<Vec<_>>()),
                "OFF: whole-piece counting fills the cap, zero appends"
            );
            assert!(
                !face.blocks_sent.contains_key(&16),
                "OFF: piece 16 not early (a refill only when the whole batch \
                 arrives = the sawtooth shape)"
            );
            assert_eq!(supply_cap, 1000, "OFF: zero enqueued, zero decremented");
            assert!(face.dispatch_replies.is_empty(), "OFF: zero receipts");
        }

        // ON arm (the same injected state): folded occupancy 1 +
        // ceil(30/4) = 9 -> 7 pieces appended.
        {
            let mut supply_cap = 1000usize;
            let mut claimed = ClaimedSet::with_len(24);
            let mut round_copies = HashMap::new();
            let done = vec![false; 24];
            let mut ctx = PieceIssueCtx {
                fi: 0,
                peer_i: 0,
                my_cuid: Some(1),
                block: blk,
                endgame_rf: false,
                last_mile: false,
                supply_cap: &mut supply_cap,
                claimed: &mut claimed,
                round_copies: &mut round_copies,
                endgame_overdue: &std::collections::HashSet::new(),
                endgame_overdue_done: &mut std::collections::HashSet::new(),
                endgame_tail_deadline: std::time::Duration::ZERO,
            };
            // max_skip=0: the explicit =0 fallback arm (the old break behavior bit-for-bit).
            supply_adjacent_pieces_with(&mut face, &mut ctx, 0, &done, true, 0);
            assert_eq!(
                face.peer_state.get(&1).map(|ps| &ps.extra_pieces),
                Some(&((1..23u64).collect::<Vec<_>>())),
                "ON: half-arrived secondaries fold to free slots; pieces 16-22 \
                 chain early"
            );
            for p in 16..=22u64 {
                assert_eq!(
                    face.blocks_sent.get(&p).map(|s| s.tracked_count()),
                    Some(4),
                    "ON: piece {p} all 4 blocks enqueued"
                );
            }
            assert!(
                !face.blocks_sent.contains_key(&23),
                "ON: the cap 16 intercepts piece 23 (1 primary + 8 folded + 7 appended)"
            );
            assert_eq!(
                supply_cap, 1000 - 28,
                "ON: the window dimension still deducts per block (red line: a wider \
                 cap is not a wider window)"
            );
            assert_eq!(face.dispatch_replies.len(), 28, "ON: each enqueued block leaves a receipt");
            // The half-arrived shape stays stable: step 2 touches fresh
            // InFlight/Buffered blocks zero times.
            let sent1 = face
                .blocks_sent
                .get(&1)
                .unwrap_or_else(|| panic!("the half-arrived secondary 1's bookkeeping present"));
            let inflight = sent1.live_inflight_count();
            assert_eq!(inflight, 2, "ON: a half-arrived secondary's fresh in-flight blocks are not resent");
            assert_eq!(sent1.tracked_count(), 4, "ON: arrived-block bookkeeping kept (no half-fold clearing)");
        }
        root.cancel();
    }

    /// Cross-piece append arm, soft-break budget
    /// ([`supply_adjacent_pieces_with`] max_skip direct drive;
    /// `BH_ADJACENT_SKIP_N` default 2, and the `=0` explicit fallback
    /// arm is pinned by the max_skip=0 arms of the two tests above):
    /// soft breaks (done) are skipped and the chain continues, with a
    /// round-level budget decremented per skip (cumulative <= N per
    /// round — no unbounded skipping); an exhausted budget tolerates a
    /// soft break by breaking the chain (the old behavior); skipped
    /// pieces are not dispatched, not claimed, and consume no window
    /// (the window dimension `supply_cap` only deducts actually enqueued
    /// blocks — a selection-side-only invariant). Shape: 64KiB pieces
    /// (4 blocks), pieces 1/3 done (two soft breaks in claim-dense
    /// territory), all advertised, the 8MiB/s budget gate open, the
    /// whole-piece counting arm (soft=false — isolates the soft-break
    /// budget face so the cap dimension does not interfere).
    #[tokio::test]
    async fn supply_adjacent_pieces_skip_budget_crosses_soft_gaps() {
        let root = CancellationToken::new();
        let blk = u64::from(merkle::BLOCK_SIZE);
        let bpp = 4u64;
        let mut done = vec![false; 8];
        done[1] = true;
        done[3] = true;

        // N=1 arm: the first hop (the piece 1 soft break) -> piece 2
        // joins the chain, budget 1->0; the second soft break (piece 3)
        // at zero budget -> break (the old behavior).
        {
            let mut face = adv_face(8);
            face.piece_bytes = vec![bpp * blk; 8].into();
            face.piece_goffs = Arc::new((0..8).map(|k| k * bpp * blk).collect());
            face.progress = ProgressModel::from_lengths(&[bpp * blk * 8], (bpp * blk) as u32);
            let (handle, _remote) = choke_peer_pair(&root).await;
            face.peers.push(handle);
            face.peer_cuids.push(1);
            note_peer_bitfield(&mut face, 1, &[0b1111_1111]);
            face.peer_state_row(1).down_window = Some(down_windows_for(8.0 * 1024.0 * 1024.0));
            let mut supply_cap = 1000usize;
            let mut claimed = ClaimedSet::with_len(8);
            let mut round_copies = HashMap::new();
            let mut ctx = PieceIssueCtx {
                fi: 0,
                peer_i: 0,
                my_cuid: Some(1),
                block: blk,
                endgame_rf: false,
                last_mile: false,
                supply_cap: &mut supply_cap,
                claimed: &mut claimed,
                round_copies: &mut round_copies,
                endgame_overdue: &std::collections::HashSet::new(),
                endgame_overdue_done: &mut std::collections::HashSet::new(),
                endgame_tail_deadline: std::time::Duration::ZERO,
            };
            supply_adjacent_pieces_with(&mut face, &mut ctx, 0, &done, false, 1);
            assert_eq!(
                face.peer_state.get(&1).map(|ps| &ps.extra_pieces),
                Some(&vec![2u64]),
                "N=1: one cross-piece soft break appends piece 2; the budget \
                 exhausts at the second break"
            );
            assert_eq!(
                face.blocks_sent.get(&2).map(|s| s.tracked_count()),
                Some(4),
                "N=1: piece 2 all 4 blocks enqueued"
            );
            assert!(
                !face.blocks_sent.contains_key(&4),
                "N=1: the second soft break (piece 3) at a zero budget breaks the chain"
            );
            assert_eq!(
                supply_cap, 1000 - 4,
                "skipped pieces consume no window (only the 4 actually enqueued blocks deducted)"
            );
        }

        // N=2 arm (the same shape, a fresh face): both hops within
        // budget; the chain crosses both breaks and continues to the
        // torrent end with no breaks left (extras = 2,4,5,6,7; skipped
        // pieces 1/3 occupy no checkout/window).
        {
            let mut face = adv_face(8);
            face.piece_bytes = vec![bpp * blk; 8].into();
            face.piece_goffs = Arc::new((0..8).map(|k| k * bpp * blk).collect());
            face.progress = ProgressModel::from_lengths(&[bpp * blk * 8], (bpp * blk) as u32);
            let (handle, _remote) = choke_peer_pair(&root).await;
            face.peers.push(handle);
            face.peer_cuids.push(1);
            note_peer_bitfield(&mut face, 1, &[0b1111_1111]);
            face.peer_state_row(1).down_window = Some(down_windows_for(8.0 * 1024.0 * 1024.0));
            let mut supply_cap = 1000usize;
            let mut claimed = ClaimedSet::with_len(8);
            let mut round_copies = HashMap::new();
            let mut ctx = PieceIssueCtx {
                fi: 0,
                peer_i: 0,
                my_cuid: Some(1),
                block: blk,
                endgame_rf: false,
                last_mile: false,
                supply_cap: &mut supply_cap,
                claimed: &mut claimed,
                round_copies: &mut round_copies,
                endgame_overdue: &std::collections::HashSet::new(),
                endgame_overdue_done: &mut std::collections::HashSet::new(),
                endgame_tail_deadline: std::time::Duration::ZERO,
            };
            supply_adjacent_pieces_with(&mut face, &mut ctx, 0, &done, false, 2);
            assert_eq!(
                face.peer_state.get(&1).map(|ps| &ps.extra_pieces),
                Some(&vec![2u64, 4, 5, 6, 7]),
                "N=2: both hops within budget; the chain crosses both breaks to the end"
            );
            assert_eq!(
                supply_cap, 1000 - 20,
                "5 pieces x 4 blocks = 20 (the two soft-break pieces consume zero window)"
            );
        }
        root.cancel();
    }

    /// Dispatch-round wiring (through [`dispatch_face`] end to end):
    /// row 1 gate open (the default floor 4 — no rate reading (a new
    /// connection shape), the ported 0 raised to 4 >= 2; the old
    /// floor=0 reading "zero rate = gate closed = the single-piece
    /// rhythm unchanged" is pinned by the budget table's floor=0 rows)
    /// -> the primary piece 4 blocks + an adjacent secondary chain
    /// filling the supply window; row 2 gate open (an 8KiB/s reading —
    /// the ported budget 2, also raised to 4 by the floor, the same
    /// shape as row 1) -> all primary blocks + an adjacent secondary
    /// chain filling the BDP target window (fixture window 16 — the
    /// default 6 -> 16: primary 4 blocks + 3 adjacent secondary x 4
    /// blocks = 16), the secondary chain starts adjacent at primary+1
    /// and is registered in extras; row 3 gate open (13KiB/s ported 1 ->
    /// floor 4) but a 256KiB piece = 16 blocks exactly exhausts the
    /// supply window 16 -> a single piece (closed by supply_cap, not by
    /// the budget gate).
    /// Switch differential: with `BH_MULTI_PIECE_SUPPLY=0` rows 1/2 skip
    /// their assertions (the OFF face is bypassed entirely = the
    /// existing behavior; OFF equivalence is proven by the full in-
    /// domain re-run).
    #[tokio::test]
    async fn dispatch_multi_piece_supply_wiring_table() {
        // Row 1: no rate reading (a new connection shape) — the default
        // floor 4 opens the gate: primary + adjacent secondary chain
        // (the same shape as row 2 — both rows have budget 4).
        let root = CancellationToken::new();
        let mut face = multi_piece_face(&root).await;
        dispatch_face(&mut face, 0);
        if multi_piece_supply_enabled() {
            let primary = face
                .peer_state
                .get(&1)
                .and_then(|ps| ps.piece)
                .unwrap_or_else(|| panic!("row 1: the primary checkout is booked"));
            let mut by_piece: std::collections::HashMap<u64, usize> =
                std::collections::HashMap::new();
            for (p, _, _) in dispatch_entries(&face) {
                *by_piece.entry(p).or_insert(0) += 1;
            }
            assert_eq!(
                by_piece.len(),
                4,
                "row 1: the default floor 4 opens the gate = the primary + 3 adjacent secondaries"
            );
            assert_eq!(by_piece.get(&primary), Some(&4), "row 1: the primary's all 4 blocks");
            for k in 1..4u64 {
                assert_eq!(
                    by_piece.get(&(primary + k)),
                    Some(&4),
                    "row 1: secondary {k} all 4 blocks (the chain fills window 16)"
                );
            }
            assert_eq!(
                face.peer_state.get(&1).map(|ps| &ps.extra_pieces),
                Some(&((primary + 1..=primary + 3).collect::<Vec<_>>())),
                "row 1: the secondary chain registered in extras"
            );
        }
        drop(face);
        root.cancel();

        // Row 2: gate open — the adjacent secondary chain fills the
        // supply window. Rate 8KiB/s: budget = max(min(8KiB x 20s,
        // 8MiB)/64KiB, default floor 4) = 4, and the face ETA =
        // 512KiB/8KiB/s = 64s >= 30s (the endgame gate is not hit — see
        // ENDGAME_ETA_THRESHOLD_SECS; high-rate small faces would take
        // the endgame cursor arm).
        let root = CancellationToken::new();
        let mut face = multi_piece_face(&root).await;
        face.peer_state_row(1).down_window = Some(down_windows_for(8.0 * 1024.0));
        dispatch_face(&mut face, 0);
        if multi_piece_supply_enabled() {
            let primary = face
                .peer_state
                .get(&1)
                .and_then(|ps| ps.piece)
                .unwrap_or_else(|| panic!("row 2: the primary checkout is booked"));
            let mut by_piece: std::collections::HashMap<u64, usize> =
                std::collections::HashMap::new();
            for (p, _, _) in dispatch_entries(&face) {
                *by_piece.entry(p).or_insert(0) += 1;
            }
            assert_eq!(by_piece.len(), 4, "row 2: the primary + 3 adjacent secondaries");
            assert_eq!(
                by_piece.get(&primary),
                Some(&4),
                "row 2: the primary's all 4 blocks"
            );
            for k in 1..4u64 {
                assert_eq!(
                    by_piece.get(&(primary + k)),
                    Some(&4),
                    "row 2: secondary {k} = the primary+{k} adjacent chain (4x4 fills window 16)"
                );
            }
            assert_eq!(
                face.peer_state.get(&1).map(|ps| &ps.extra_pieces),
                Some(&((primary + 1..=primary + 3).collect::<Vec<_>>())),
                "row 2: the secondary chain registered in extras"
            );
            assert_eq!(
                face.peer_state.get(&1).and_then(|ps| ps.piece),
                Some(primary),
                "row 2: the primary checkout is not rewritten by secondaries"
            );
        }
        drop(face);
        root.cancel();

        // Row 3: the ported budget 1 (13KiB/s x 20s = 260KiB / 256KiB)
        // raised to 4 by the default floor (gate open) — but a 256KiB
        // piece = 16 blocks exactly exhausts the supply window 16 (the
        // default window); the primary exhausts the supply cap with
        // nothing left for cross-piece supply (a single piece, closed by
        // supply_cap).
        let root = CancellationToken::new();
        let mut face = multi_piece_face256(&root).await;
        face.peer_state_row(1).down_window = Some(down_windows_for(13.0 * 1024.0));
        dispatch_face(&mut face, 0);
        let pieces: std::collections::HashSet<u64> =
            dispatch_entries(&face).into_iter().map(|(p, _, _)| p).collect();
        assert_eq!(
            pieces.len(),
            1,
            "row 3: the supply window exhausted by the primary = a single piece \
             (closed by supply_cap, anti-dilution)"
        );
        drop(face);
        root.cancel();
    }

    /// Multi-block-piece geometry (fixture): 8 pieces x 4 blocks (64KiB
    /// pieces), one fully advertising peer, the progress model
    /// isomorphic.
    async fn multi_piece_face(
        root: &CancellationToken,
    ) -> FaceState {
        let blk = u64::from(merkle::BLOCK_SIZE);
        let mut face = adv_face(8);
        face.piece_bytes = vec![4 * blk; 8].into();
        face.piece_goffs = Arc::new((0..8).map(|k| k * 4 * blk).collect());
        face.progress = ProgressModel::from_lengths(&[4 * blk * 8], (4 * blk) as u32);
        let (handle, _remote) = choke_peer_pair(root).await;
        face.peers.push(handle);
        face.peer_cuids.push(1);
        note_peer_bitfield(&mut face, 1, &[0b1111_1111, 0b1111_1111]);
        face
    }

    /// The 256KiB-piece shape (dedicated to wiring row 3): 4 pieces x 16
    /// blocks (piece length = 256KiB, the budget table's piece-length
    /// baseline).
    async fn multi_piece_face256(
        root: &CancellationToken,
    ) -> FaceState {
        let blk = u64::from(merkle::BLOCK_SIZE);
        let piece_len = 16 * blk;
        let mut face = adv_face(4);
        face.piece_bytes = vec![piece_len; 4].into();
        face.piece_goffs = Arc::new((0..4).map(|k| k * piece_len).collect());
        face.progress = ProgressModel::from_lengths(&[piece_len * 4], piece_len as u32);
        let (handle, _remote) = choke_peer_pair(root).await;
        face.peers.push(handle);
        face.peer_cuids.push(1);
        note_peer_bitfield(&mut face, 1, &[0b1111_1111]);
        face
    }

    /// Rate-window reading fixture (`down_windows` with one 1s tick fed:
    /// the current-second bucket = r, the other 29 empty, fed = 1 ->
    /// `rate()` = r).
    fn down_windows_for(rate_bps: f64) -> RateWindow {
        let mut buckets = vec![0u64; RateWindow::WINDOW_SECS];
        buckets[0] = rate_bps as u64;
        RateWindow {
            buckets,
            cursor: 0,
            fed: 1,
        }
    }

    // ---- Lever 1: connection admission ----

    /// Connection admission decision table (the aria2
    /// bt-max-peers/minPeers semantics; `run::state::admission_verdict`):
    /// Row 1: the count below target -> both shapes (the outbound
    /// target / the hard cap) always admit (downloads healthy or not).
    /// Row 2: target <= count < hard cap -> the outbound-target shape
    /// (Discovery) closes while downloads are healthy and admits via the
    /// slow-download reprieve while unhealthy (the stall backfill band);
    /// the hard-cap shape (Redial / inbound) admits while the count is
    /// under the cap.
    /// Row 3: the count >= hard cap -> BOTH shapes always closed (the
    /// tightening) — the reprieve converged from "always open" to
    /// "relax up to the hard cap": during a recorded stall period (DL=0)
    /// the fully open reprieve let connections balloon (connections added
    /// without supply only burn CPU and bring no bytes); the reference's
    /// reprieve backfill is likewise count-gated (aria2
    /// `ActivePeerConnectionCommand.cc`: slow downloads add at
    /// most 5 connections per 10s within bt-max-peers). Seeding has no
    /// reprieve (the aria2 seeder arm has only the count gate).
    /// Anti-starvation property row: the reprieve band between target and
    /// hard cap stays open during stalls (row 2) — the discovery face's
    /// non-starvation property = "during a stall connections can still
    /// grow to the hard cap".
    /// Defaults 51/64 -> 100/120 (symbolic constants; the semantic rows
    /// are unchanged); the fallback reading (`BH_PEER_TARGET=51` /
    /// `BH_PEER_MAX=64`, the current values) is pinned via
    /// [`admission_verdict_limits`] direct drive.
    #[test]
    fn peer_admission_verdict_table() {
        // Row 1: below the target, always admit.
        for &total in &[0usize, PEER_CONNECTIONS_TARGET - 1] {
            for &healthy in &[true, false] {
                for &hard in &[true, false] {
                    assert!(
                        admission_verdict(total, false, healthy, hard),
                        "row 1: total={total} healthy={healthy} hard={hard}"
                    );
                }
            }
        }
        // Row 2: between target and hard cap — the target shape splits on
        // health (the reprieve = the stall backfill band); the hard-cap
        // shape is always open.
        let mid = PEER_CONNECTIONS_TARGET + 1;
        assert!(
            !admission_verdict(mid, false, true, false),
            "row 2: Discovery closed while healthy"
        );
        assert!(
            admission_verdict(mid, false, false, false),
            "row 2: Discovery's slow-download reprieve (the stall backfill band)"
        );
        assert!(
            admission_verdict(mid, false, false, true),
            "row 2: the hard-cap shape admits during a stall without reaching the cap"
        );
        assert!(
            admission_verdict(mid, false, true, true),
            "row 2: the hard-cap shape admits (peers with past successes reconnect first)"
        );
        // Row 3: the hard cap full — after the tightening both shapes are
        // always closed, healthy or stalled (connection-bloat governance:
        // new connections may only backfill, never exceed the cap).
        for &total in &[PEER_CONNECTIONS_MAX, PEER_CONNECTIONS_MAX + 10] {
            assert!(
                !admission_verdict(total, false, true, false)
                    && !admission_verdict(total, false, true, true),
                "row 3: both shapes fully closed while healthy total={total}"
            );
            assert!(
                !admission_verdict(total, false, false, false)
                    && !admission_verdict(total, false, false, true),
                "row 3: the R6 tightening — the stall reprieve never crosses the \
                 hard cap total={total}"
            );
            // Seeding: no reprieve (the healthy parameter is always true
            // in the wrapper; the pure function short-circuits on
            // completed — the reprieve arm is unreachable).
            assert!(
                !admission_verdict(total, true, true, false)
                    && !admission_verdict(total, true, false, true),
                "row 3: the seeding-state count gate has no reprieve total={total}"
            );
        }
        // Seeding below the hard cap: admit (seeders backfill to the cap).
        assert!(admission_verdict(PEER_CONNECTIONS_TARGET + 1, true, true, false));
        // Default anchors: TARGET 100 / MAX 120 (aria2-next's configured
        // `bt-max-peers` 100 + a 1.2x handshake over-cap margin; the
        // symbolic constants are the effective values when env is unset).
        assert_eq!(PEER_CONNECTIONS_TARGET, 100);
        assert_eq!(PEER_CONNECTIONS_MAX, 120);
        // Fallback reading pinned: 51/64 = the current values;
        // `BH_PEER_TARGET=51` / `BH_PEER_MAX=64` restores that verdict
        // face — the semantics is bit-for-bit (a 51->64 backfill band),
        // proven by the explicit limits direct drive.
        {
            let (t, m) = (51usize, 64usize);
            // Row 1: below the fallback target, always admit.
            for &total in &[0usize, t - 1] {
                assert!(admission_verdict_limits(total, false, true, false, t, m));
                assert!(admission_verdict_limits(total, false, false, false, t, m));
            }
            // Row 2: the fallback backfill band (51-64) closes when
            // healthy / opens on the stalled reprieve; the hard-cap shape
            // is always open.
            let mid = t + 1;
            assert!(!admission_verdict_limits(mid, false, true, false, t, m));
            assert!(admission_verdict_limits(mid, false, false, false, t, m));
            assert!(admission_verdict_limits(mid, false, false, true, t, m));
            assert!(admission_verdict_limits(mid, false, true, true, t, m));
            // Row 3: the fallback hard cap full is always closed (the same
            // tightening).
            for &total in &[m, m + 10] {
                assert!(!admission_verdict_limits(total, false, true, false, t, m));
                assert!(!admission_verdict_limits(total, false, false, false, t, m));
                assert!(!admission_verdict_limits(total, true, true, false, t, m));
            }
        }
    }

    // ---- Stall detection valve (seeder slot starvation + connection bloat) ----

    /// Stall-detection state machine, table-driven
    /// (`run::stall::stall_valve_advance`):
    /// row 1 not armed (the session younger than the minimum) -> zero
    /// increments do not accumulate (the startup noise gate);
    /// row 2 after arming, consecutive zero increments below the
    /// threshold do not fire;
    /// row 3 the [`STALL_DETECT_SECS`]-th zero increment edge fires once
    /// on entry;
    /// row 4 within the period (< [`STALL_ACTION_PERIOD`]) no repeat
    /// firing;
    /// row 5 the period elapsing fires again (action-window throttling);
    /// row 6 a supply-recovery edge clears all state (the count / stall
    /// flag / action anchor) and a new stall walks the full detection
    /// window again (anti-oscillation: recovery resets to zero, no half-
    /// way state).
    #[test]
    fn stall_valve_advance_state_machine() {
        let t0 = Instant::now();
        let mut valve = StallValve::default();
        // Row 1: not armed.
        for _ in 0..STALL_DETECT_SECS * 2 {
            assert!(!stall_valve_advance(&mut valve, true, false, t0));
        }
        assert_eq!(valve.zero_secs, 0, "row 1: not armed, nothing accumulates");
        // Rows 2/3: after arming the count accumulates per second; the
        // entry edge lands exactly at the threshold second.
        let mut fired = 0;
        for i in 1..=STALL_DETECT_SECS {
            if stall_valve_advance(&mut valve, true, true, t0) {
                fired += 1;
                assert_eq!(i, STALL_DETECT_SECS, "row 3: the entry edge = the threshold second");
                assert!(valve.active, "row 3: the stall state set");
            }
        }
        assert_eq!(fired, 1, "row 3: the entry edge fires exactly once");
        // Row 4: no repeat within the period.
        for sec in 1..STALL_ACTION_PERIOD.as_secs() {
            assert!(
                !stall_valve_advance(&mut valve, true, true, t0 + Duration::from_secs(sec)),
                "row 4: no firing within the period sec={sec}"
            );
        }
        // Row 5: the period elapsing fires again.
        assert!(
            stall_valve_advance(
                &mut valve,
                true,
                true,
                t0 + Duration::from_secs(STALL_ACTION_PERIOD.as_secs())
            ),
            "row 5: the action-window period edge fires"
        );
        // Row 6: the recovery edge clears state; a new stall walks the
        // full window again.
        assert!(!stall_valve_advance(&mut valve, false, true, t0));
        assert!(!valve.active && valve.zero_secs == 0 && valve.last_action.is_none(),
            "row 6: the recovery edge clears all state");
        let mut refired = 0;
        for _ in 1..=STALL_DETECT_SECS {
            if stall_valve_advance(&mut valve, true, true, t0) {
                refired += 1;
            }
        }
        assert_eq!(refired, 1, "row 6: after re-stalling, the entry edge fires exactly once after the full detection window");
    }

    /// Seeder rotation decision table (`run::stall::rotation_pick`):
    /// row 1 the first sight of an eligible row -> only record the
    /// observation start, no disconnect (the continuity criterion
    /// starts);
    /// row 2 an eligible row persisting >= [`SEEDER_ROTATE_IDLE_SECS`] ->
    /// disconnect;
    /// row 3 the batch limit [`SEEDER_ROTATE_BATCH`] (bounding =
    /// conservative rotation pressure; disconnecting every seeder at
    /// once would cut off our own supply);
    /// row 4 an ineligible row clears the observation bookkeeping (supply
    /// recovery / unchoke revokes the rotation intent);
    /// row 5 after a disconnect the bookkeeping is cleared — a reconnect
    /// restarts the observation (respecting the redial pool's 60s
    /// backoff and its one-connection-at-a-time order; it must not
    /// disconnect again immediately).
    #[test]
    fn stall_rotation_pick_table() {
        let t0 = Instant::now();
        let idle = Duration::from_secs(SEEDER_ROTATE_IDLE_SECS);
        let mut book = std::collections::HashMap::new();
        // Row 1: the first sight only records.
        let rows = |cuids: &[u64], starved: bool| {
            cuids
                .iter()
                .map(|&cuid| PeerStallRow { cuid, starved })
                .collect::<Vec<_>>()
        };
        let picked = rotation_pick(&rows(&[1], true), &mut book, 0, t0, SEEDER_ROTATE_BATCH);
        assert!(picked.is_empty() && book.contains_key(&(0, 1)), "row 1: the first sight only records");
        // Row 2: the elapsed duration disconnects.
        let picked =
            rotation_pick(&rows(&[1], true), &mut book, 0, t0 + idle, SEEDER_ROTATE_BATCH);
        assert_eq!(picked, vec![1], "row 2: after the idle period elapses, disconnect");
        assert!(!book.contains_key(&(0, 1)), "row 2: bookkeeping cleared after the disconnect");
        // Row 3: the batch limit (3 fully-elapsed eligible rows, batch=2
        // -> exactly 2 disconnected).
        let mut book3 = std::collections::HashMap::new();
        let _ = rotation_pick(&rows(&[1, 2, 3], true), &mut book3, 0, t0, SEEDER_ROTATE_BATCH);
        let picked = rotation_pick(
            &rows(&[1, 2, 3], true),
            &mut book3,
            0,
            t0 + idle,
            SEEDER_ROTATE_BATCH,
        );
        assert_eq!(picked.len(), SEEDER_ROTATE_BATCH, "row 3: the batch limit");
        assert_eq!(book3.len(), 1, "row 3: the un-disconnected row's bookkeeping kept (disconnected next window)");
        // Row 4: an ineligible row clears the bookkeeping.
        let mut book4 = std::collections::HashMap::new();
        let _ = rotation_pick(&rows(&[7], true), &mut book4, 0, t0, SEEDER_ROTATE_BATCH);
        assert!(book4.contains_key(&(0, 7)));
        let _ = rotation_pick(&rows(&[7], false), &mut book4, 0, t0 + idle, SEEDER_ROTATE_BATCH);
        assert!(!book4.contains_key(&(0, 7)), "row 4: an ineligible row clears the bookkeeping");
        // Row 5: after a disconnect a re-sighting restarts (no immediate
        // re-disconnect).
        let picked = rotation_pick(&rows(&[1], true), &mut book, 0, t0 + idle, SEEDER_ROTATE_BATCH);
        assert!(picked.is_empty(), "row 5: a re-sighting after disconnect restarts");
    }

    // ---- Lever 2: slow-peer redispatch amortization (transfer implies cancel) ----

    /// Transfer implies cancel (the "cancel" half of the
    /// `DefaultBtMessageDispatcher.cc` cross-validation): when peer 2
    /// takes over a stale in-flight block originally held by cuid 1 —
    /// (1) engine face: the dispatch ownership is rewritten to the new
    /// peer while `blocks_sent` stays InFlight (TRANSFER, NOT CANCEL:
    /// block-level in-flight does not drop to zero — the anti-starvation
    /// assertion face);
    /// (2) wire face: the original holder receives a Cancel frame (its
    /// RequestBook holds a real round-1 slot; the wire cancel is only
    /// sent when the cancellation succeeds — end-to-end proof the
    /// transfer chain works).
    /// Round-2 orchestration (synthetic state): peer 1's checkout is
    /// repointed to piece 1 (all its blocks fresh — the continuation arm
    /// adds no requests and does not re-request its own stale block);
    /// peer 2's checkout is synthetically released (the spread round
    /// selects normally) -> it lands on the stale piece 0 and takes
    /// over.
    #[tokio::test]
    async fn dispatch_transfer_cancels_displaced_request() {
        let root = tokio_util::sync::CancellationToken::new();
        // Multi-block-piece geometry (2 pieces x 4 blocks): single-block
        // faces have no "multiple stale blocks within a piece" shape.
        let mut face = adv_face(2);
        let blocks = 4u64;
        let piece_len = u64::from(merkle::BLOCK_SIZE) * blocks;
        face.piece_bytes = vec![piece_len; 2].into();
        // Chain-break note: with the default floor of 4 the cross-piece
        // append is always on — a 1-piece goff gap is placed between the
        // two pieces (the file-boundary padding shape;
        // `next_adjacent_supply_piece` breaks there), preserving this
        // orchestration's "one-piece checkout per peer" premise (in round
        // 2 peer 1's cross-piece append would otherwise consume the
        // stale piece's blocks first, moving the takeover onto peer 1);
        // cross-piece append behavior is pinned by the multi_piece tests.
        face.piece_goffs = Arc::new(vec![0, 2 * piece_len]);
        face.progress = ProgressModel::from_lengths(&[piece_len * 2], piece_len as u32);
        // Peer 1 (index 0) + peer 2 (index 1), fully advertising.
        let (handle1, mut remote1) = choke_peer_pair(&root).await;
        face.peers.push(handle1);
        face.peer_cuids.push(1);
        let (handle2, remote2) = choke_peer_pair(&root).await;
        face.peers.push(handle2);
        face.peer_cuids.push(2);
        note_peer_bitfield(&mut face, 1, &[0b1100_0000]);
        note_peer_bitfield(&mut face, 2, &[0b1100_0000]);
        // Round 1: spread claims — the two peers claim different pieces
        // (really entering their own RequestBooks, wire Requests sent).
        // The piece numbers are the actual claims (rarest-first initial
        // values derive from the deterministic rng; piece 0 is not
        // assumed rarest).
        dispatch_face(&mut face, 0);
        tokio::time::sleep(Duration::from_millis(20)).await;
        let piece1 = face
            .peer_state
            .get(&1)
            .and_then(|ps| ps.piece)
            .unwrap_or_else(|| panic!("round 1: peer 1 claims a checkout"));
        let piece2 = face
            .peer_state
            .get(&2)
            .and_then(|ps| ps.piece)
            .unwrap_or_else(|| panic!("round 1: peer 2 claims a checkout"));
        assert_ne!(piece1, piece2, "round 1: spread exclusivity (the two peers claim different pieces)");
        // Pre-round-2 (synthetic state): piece piece1 (peer 1's claim)
        // has its in-flight marks rewound past the reissue window
        // (stale); peer 1's checkout is repointed to piece2 (all fresh —
        // the continuation arm adds no requests); peer 2's checkout is
        // synthetically released (the spread round lands on the stale
        // piece piece1).
        // Adaptation note: the blocks are owned by peer 1 (a real task
        // handle, no RTT sample -> the reissue window =
        // [`REISSUE_WINDOW_CEIL`] 5s, as in the row 2 note) — stale
        // marks must exceed 5s.
        let stale = Instant::now() - REISSUE_WINDOW_CEIL - Duration::from_millis(50);
        // Rewind all slots past the window (the piece-level timestamp =
        // stale, ownership kept — peer 1's inline owner is untouched,
        // equivalent to the old "block_dispatch kept + per-block
        // timestamp rewind" shape).
        {
            let ledger = face
                .blocks_sent
                .get_mut(&piece1)
                .unwrap_or_else(|| panic!("round-1 bookkeeping present"));
            let stale_marks: Vec<u32> = (0..ledger.slots().len() as u64)
                .map(|bi| (bi * u64::from(merkle::BLOCK_SIZE)) as u32)
                .collect();
            let owners: Vec<Option<u32>> = stale_marks
                .iter()
                .map(|&b| ledger.owner_of(b))
                .collect();
            *ledger = PieceSentLedger::new(ledger.slots().len(), stale);
            for (&b, &owner) in stale_marks.iter().zip(owners.iter()) {
                ledger.set_inflight(b, owner, stale);
            }
        }
        face.peer_state_row(1).piece = Some(piece2);
        if let Some(ps) = face.peer_state.get_mut(&2) {
                ps.piece = None;
            }
        dispatch_face(&mut face, 0);
        tokio::time::sleep(Duration::from_millis(20)).await;
        // (1) engine face: piece1's first block is taken over by peer 2;
        // the in-flight state is kept (transfer, not cancel).
        assert_eq!(
            dispatch_owner(&face, piece1, 0),
            Some(2),
            "peer 2 takes over piece1 (the ownership rewritten in row)"
        );
        assert_eq!(
            face.blocks_sent
                .get(&piece1)
                .map(|l| l.block_state(0)),
            Some(BlockState::InFlight),
            "the in-flight mark kept after the transfer (block-level in flight does not drop to zero)"
        );
        // (2) wire face: peer 1 receives Cancel (id 8) — the round-1
        // Request(6) frame comes first; read frame by frame until the
        // Cancel (a 16-frame bound covers both rounds' request frames).
        let mut saw_cancel = false;
        for _ in 0..16 {
            match tokio::time::timeout(
                Duration::from_millis(400),
                read_wire_msg_id(&mut remote1),
            )
            .await
            {
                Ok(Some(8)) => {
                    saw_cancel = true;
                    break;
                }
                Ok(Some(_)) => continue,
                _ => break,
            }
        }
        assert!(saw_cancel, "the original holder must receive a wire Cancel frame (transfer implies cancel)");
        drop(remote2);
        root.cancel();
    }

    // ---- Piece settle clears in flight (cancel-on-verified) ----

    /// Criterion (wire-level end to end): a peer has in-flight requests
    /// -> the piece verifies -> the in-flight requests are withdrawn.
    /// (1) The holder receives wire Cancel frames for every in-flight
    /// coordinate (RequestBook slots match on the full (id, begin,
    /// length) key — the length must match the dispatch byte for byte);
    /// (2) after the cancellation the slots are clear; withdrawing again
    /// at the same coordinates produces zero new Cancel frames (the
    /// peer-side `cancel_with_grace` is silent without a slot — a
    /// fire-and-forget safety face);
    /// (3) after the withdrawal the `blocks_sent` bookkeeping is cleared
    /// as usual via on_piece_verified (this test drives the function
    /// directly; the actual clearing belongs to the existing
    /// PieceVerified arm).
    #[tokio::test]
    async fn piece_verified_cancels_inflight_requests_to_holders() {
        let root = tokio_util::sync::CancellationToken::new();
        let mut face = adv_face(2);
        let blocks = 4u64;
        let piece_len = u64::from(merkle::BLOCK_SIZE) * blocks;
        face.piece_bytes = vec![piece_len; 2].into();
        face.piece_goffs = Arc::new((0..2).map(|k| k * piece_len).collect());
        face.progress = ProgressModel::from_lengths(&[piece_len * 2], piece_len as u32);
        let (handle1, mut remote1) = choke_peer_pair(&root).await;
        face.peers.push(handle1);
        face.peer_cuids.push(1);
        note_peer_bitfield(&mut face, 1, &[0b1100_0000]);
        dispatch_face(&mut face, 0);
        tokio::time::sleep(Duration::from_millis(20)).await;
        let piece1 = face
            .peer_state
            .get(&1)
            .and_then(|ps| ps.piece)
            .unwrap_or_else(|| panic!("round 1: peer 1 claims a checkout"));
        // Synthetic state: peer 1 has multiple in-flight coordinates for
        // piece1 (round 1's supply window).
        assert!(
            face.blocks_sent.contains_key(&piece1),
            "round-1 in-flight bookkeeping present"
        );
        // Piece verification: the same take-out sequence as the evidence
        // face (the PieceVerified arm shape) -> withdraw in flight.
        let targets = crate::ban::take_piece_dispatch_targets(&mut face, piece1);
        assert!(!targets.is_empty(), "piece1's dispatch-target bookkeeping present");
        crate::dispatch::cancel_piece_requests_on_verify(
            std::slice::from_mut(&mut face),
            0,
            piece1,
            &targets,
        );
        // (1) wire face: peer 1 receives Cancel (id 8) frames — read
        // until the channel goes quiet; the count must be >= 1 (the
        // in-flight coordinates = round 1's supply window, all
        // withdrawn).
        let mut cancels = 0u32;
        for _ in 0..64 {
            match tokio::time::timeout(
                Duration::from_millis(200),
                read_wire_msg_id(&mut remote1),
            )
            .await
            {
                Ok(Some(8)) => cancels += 1,
                Ok(Some(_)) => continue,
                _ => break,
            }
        }
        assert!(cancels >= 1, "after the piece verifies, the holder must receive wire Cancel frames");
        // (2) the slots are clear (all Cancels drained): withdrawing
        // again produces zero new Cancel frames.
        crate::dispatch::cancel_piece_requests_on_verify(
            std::slice::from_mut(&mut face),
            0,
            piece1,
            &targets,
        );
        let mut extra_cancel = false;
        for _ in 0..24 {
            match tokio::time::timeout(
                Duration::from_millis(120),
                read_wire_msg_id(&mut remote1),
            )
            .await
            {
                Ok(Some(8)) => {
                    extra_cancel = true;
                    break;
                }
                Ok(Some(_)) => continue,
                _ => break,
            }
        }
        assert!(
            !extra_cancel,
            "a slot-less re-withdrawal must not resend a wire Cancel (the \
             cancel_with_grace silent face)"
        );
        root.cancel();
    }

    // ---- Early have announcement (the verified/written two-bit split) ----

    /// Read one complete wire frame (length prefix + body); timeout or
    /// disconnect = None.
    async fn read_wire_frame<R: tokio::io::AsyncRead + Unpin>(
        remote: &mut R,
    ) -> Option<(u8, Vec<u8>)> {
        use tokio::io::AsyncReadExt as _;
        let mut len_buf = [0u8; 4];
        match tokio::time::timeout(Duration::from_millis(400), remote.read_exact(&mut len_buf))
            .await
        {
            Err(_) | Ok(Err(_)) => return None,
            Ok(Ok(_)) => {}
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 {
            return Some((0, Vec::new())); // keepalive
        }
        let mut body = vec![0u8; len];
        match tokio::time::timeout(Duration::from_millis(400), remote.read_exact(&mut body)).await
        {
            Ok(Ok(_)) => Some((body[0], body[1..].to_vec())),
            _ => None,
        }
    }

    /// Criteria (wire-level end to end; the verified != written state
    /// case):
    /// (1) on_piece_verified (hash pass, before the disk write): the peer
    /// immediately receives a HAVE frame (msg id 4; the libtorrent
    /// RC_2_1 `7f691246a` passed->have port), the completedLength-face
    /// bit and the registration-arm advertised bitmap advance together,
    /// and the completion verdict does not flip;
    /// (2) verified != written: PartialFaceSource (the upload-serving
    /// gate = the written bit) still refuses — the bytes are in the
    /// write cache / mid-write, and the disk holds sparse zero data;
    /// (3) on_piece_written (flushed; the `7f691246a` have->flushed
    /// half): the gate lifts and the served bytes = the disk bytes; the
    /// face completes only when EVERY piece is flushed (the precondition
    /// for the ungated direct disk read of the full seeding source).
    #[tokio::test]
    async fn have_advertises_at_hash_pass_upload_gates_until_written() {
        use taiji_bt::peer::PieceSource as _;
        let root = CancellationToken::new();
        let mut face = adv_face(2);
        let (handle, mut remote) = choke_peer_pair(&root).await;
        face.peers.push(handle);
        face.peer_cuids.push(1);

        // Disk face: a 2 pieces x 16KiB layout + a real file (the
        // criterion face for reads served after written — once the gate
        // lifts, what is served must be real disk bytes, not sparse
        // zeros).
        let piece_len = merkle::BLOCK_SIZE as usize;
        let content: Vec<u8> = (0..2 * piece_len).map(|i| (i % 251) as u8).collect();
        let tmp = std::env::temp_dir().join(format!(
            "taiji-ns03-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&tmp).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(tmp.join("blob.bin"), &content).unwrap_or_else(|e| panic!("{e}"));
        let layout = Layout::plan_v1_padded(
            &[taiji_store::layout::PlanEntry {
                path: "blob.bin".into(),
                length: content.len() as u64,
                padding: false,
            }],
            merkle::BLOCK_SIZE,
        )
        .unwrap_or_else(|e| panic!("{e}"));

        // (1) hash pass: the HAVE broadcast is immediate, the progress and
        // advertising bitmaps advance, completion does not flip.
        on_piece_verified(std::slice::from_mut(&mut face), 0, 0);
        let (id, body) = read_wire_frame(&mut remote)
            .await
            .unwrap_or_else(|| panic!("the HAVE frame never arrived after hash pass"));
        assert_eq!(id, 4, "hash pass immediately broadcasts HAVE (msg id 4)");
        assert_eq!(body, 0u32.to_be_bytes(), "HAVE index = 0");
        assert!(
            face.progress.piece_done_global(0),
            "the completedLength-semantics bit advances with hash pass"
        );
        assert!(
            face.bitfield_bytes()[0] & 0x80 != 0,
            "the registration arm's advertised bitmap contains the hash-passed piece"
        );
        assert!(!face.written_bits.get(0), "the written bit unset (the disk write in flight)");
        assert!(!face.completed, "the face completion verdict does not flip on hash pass");

        // (2) verified != written: upload serving still refuses (the
        // written gate).
        let partial = PartialFaceSource {
            reader: taiji_store::torrent_writer::TorrentReader::new(layout.clone(), tmp.clone()),
            goffs: face.piece_goffs.clone(),
            written: face.written_bits.clone(),
        };
        let mut buf = vec![0u8; piece_len];
        assert!(
            partial.read_block(0, 0, &mut buf).is_err(),
            "hash-passed but not flushed: upload serving must refuse (sparse zero \
             data never leaves)"
        );

        // (3) piece 0 flushed: the gate lifts and real disk bytes are
        // served; completion still does not flip (piece 1 not yet
        // flushed).
        on_piece_written(std::slice::from_mut(&mut face), 0, 0, &[2]);
        assert!(face.written_bits.get(0), "flushing sets the written bit");
        let n = partial
            .read_block(0, 0, &mut buf)
            .unwrap_or_else(|e| panic!("serving allowed after written: {e}"));
        assert_eq!(n, piece_len);
        assert_eq!(&buf[..], &content[..piece_len], "served bytes = disk bytes");
        assert!(!face.completed, "piece 1 not flushed: the face does not complete");

        // (4) piece 1 verified (completion still does not flip — all
        // hash-passed != complete) -> written (everything flushed:
        // completion flips).
        on_piece_verified(std::slice::from_mut(&mut face), 0, 1);
        assert!(!face.completed, "all hash-passed does not equal complete (the written semantics)");
        let all = on_piece_written(std::slice::from_mut(&mut face), 0, 1, &[2]);
        assert!(all, "all pieces flushed -> the whole face complete");
        assert!(face.completed, "the face completion flag flips with the last piece written");

        let _ = std::fs::remove_dir_all(&tmp);
        root.cancel();
    }

    /// Completion recheck regression: the recheck reads ONLY the written
    /// count — the SetFileSelection mask arm / the main loop's startup
    /// pre-pass / [`on_piece_written`] all share
    /// [`recheck_face_completion`] (a single source of truth).
    /// Scenario = the imbalance face: select-file lands inside the final
    /// batch's write-in-flight window — every piece hash-passed
    /// (verified_count == required) but not everything is flushed; the
    /// recheck must not set completed (before the fix the verified_count
    /// criterion flipped completed right here, triggering the completion
    /// blocks early via on_piece_written's all verdict: the ungated
    /// seeding source mount / BtComplete hook / EngineEnd::Completed).
    #[test]
    fn face_completion_recheck_waits_for_written_not_verified() {
        let mut face = adv_face(2);
        let required = [2usize];
        // Every piece hash-passed (verified_count = 2 = required), zero
        // flushed.
        on_piece_verified(std::slice::from_mut(&mut face), 0, 0);
        on_piece_verified(std::slice::from_mut(&mut face), 0, 1);
        assert_eq!(face.verified_count, 2, "hash pass counts as verified");
        assert_eq!(face.written_count, 0, "the written count is zero before flushing");
        recheck_face_completion(std::slice::from_mut(&mut face), &required);
        assert!(
            !face.completed,
            "all hash-passed does not equal complete: the written-semantics recheck \
             must not set completed (review regression)"
        );
        // Piece 0 flushed: the recheck still does not flip (partially
        // flushed).
        on_piece_written(std::slice::from_mut(&mut face), 0, 0, &required);
        recheck_face_completion(std::slice::from_mut(&mut face), &required);
        assert!(!face.completed, "partially flushed does not complete");
        // Everything flushed: the recheck flips (the same criterion
        // source as on_piece_written).
        on_piece_written(std::slice::from_mut(&mut face), 0, 1, &required);
        let all = recheck_face_completion(std::slice::from_mut(&mut face), &required);
        assert!(all && face.completed, "everything flushed -> complete");
    }

    /// Write-locality count table ([`on_piece_written`] first-write arm
    /// feed point; zero behavior change observed): row 1 the first piece
    /// isolated (neither index±1 flushed); row 2 a jumping piece isolated
    /// (piece 2 flushed while 1/3 are not); row 3 an in-fill piece
    /// adjacent (piece 1 flushed while 0/2 already are — a contiguous
    /// goff-region write); row 4 duplicate written events do not double
    /// count (the store pipeline is authoritative; this is the first-
    /// write arm). The two counts sum to the total flushed pieces.
    #[test]
    fn write_locality_counts_adjacent_and_isolated() {
        let mut face = adv_face(4);
        let required = [4usize];
        // Row 1: the first piece (index 0, right neighbor 1 not flushed)
        // -> isolated.
        on_piece_written(std::slice::from_mut(&mut face), 0, 0, &required);
        assert_eq!((face.write_adjacent, face.write_isolated), (0, 1), "row 1: the first piece isolated");
        // Row 2: piece 2 (left neighbor 1 and right neighbor 3 not
        // flushed) -> isolated.
        on_piece_written(std::slice::from_mut(&mut face), 0, 2, &required);
        assert_eq!((face.write_adjacent, face.write_isolated), (0, 2), "row 2: a jumping piece isolated");
        // Row 3: piece 1 (left neighbor 0 flushed) -> adjacent.
        on_piece_written(std::slice::from_mut(&mut face), 0, 1, &required);
        assert_eq!((face.write_adjacent, face.write_isolated), (1, 2), "row 3: an in-fill piece adjacent");
        // Row 4: a duplicate written event (the pipeline already counted)
        // -> not counted again.
        on_piece_written(std::slice::from_mut(&mut face), 0, 1, &required);
        assert_eq!(
            (face.write_adjacent, face.write_isolated),
            (1, 2),
            "row 4: duplicate events are not double counted (the first-write arm)"
        );
        // Sum = total flushed pieces (written_count, the same criterion:
        // 3 pieces flushed first-time).
        assert_eq!(
            face.write_adjacent + face.write_isolated,
            face.written_count as u64,
            "the two counts sum to the total flushed pieces"
        );
    }

    // ---- Strategy skeleton: switching atomicity ----

    /// Test stub: never selects (the observable counterpart of zero
    /// requests after a policy swap; the reachability of the production
    /// Sequential/Streaming stubs is guarded by SetSchedulerPolicy
    /// parameter validation — this stub only verifies the mechanism that
    /// a strategy object can be swapped wholesale).
    struct NoPickStrategy;
    impl PieceSelectionStrategy for NoPickStrategy {
        fn name(&self) -> &'static str {
            "test_no_pick"
        }
        fn select_piece(&self, _ctx: &SelectionCtx<'_>) -> Option<u64> {
            None
        }
    }

    /// Test stub: always selects the given piece (it must be incomplete
    /// and advertised — the done/advertisement constraints are not
    /// loosened by the strategy; the observable face of a new selection
    /// decision taking effect after the swap).
    struct PinStrategy(u64);
    impl PieceSelectionStrategy for PinStrategy {
        fn name(&self) -> &'static str {
            "test_pin"
        }
        fn select_piece(&self, ctx: &SelectionCtx<'_>) -> Option<u64> {
            let p = self.0 as usize;
            let advertised = ctx.advertised?;
            if !advertised.get(p) {
                return None;
            }
            (!ctx.done.get(p).copied().unwrap_or(true)).then_some(self.0)
        }
    }

    /// (wire piece) -> in-flight block count snapshot (the observation
    /// face for the switching-atomicity assertions).
    fn inflight_snapshot(
        face: &FaceState,
    ) -> std::collections::BTreeMap<u64, usize> {
        face.blocks_sent
            .iter()
            .map(|(p, l)| (*p, l.tracked_count()))
            .collect()
    }

    /// Switching atomicity: strategy object replacement —
    /// (a) in-flight requests are unaffected by the swap: blocks_sent /
    /// claim bookkeeping are preserved as-is, zero resend, zero cancel
    /// (the in-flight bookkeeping is strategy-independent; the swap only
    /// affects later selection decisions);
    /// (b) the swap takes effect immediately on later selection: the
    /// no-pick stub -> zero new requests; the pin stub -> the given
    /// unclaimed piece is dispatched (block-level in-flight dedup /
    /// windowing still run through the dispatch loop — the strategy does
    /// not overstep).
    #[tokio::test]
    async fn scheduler_policy_swap_atomicity() {
        let root = tokio_util::sync::CancellationToken::new();
        let mut face = adv_face(16);
        let mut remotes = Vec::new();
        // Chain-break note: with the default floor of 4 rarest-first
        // cross-piece append is always on — the advertised set is spaced
        // non-adjacently; with the default N=2 a soft break may skip <= 2
        // pieces (lookahead d <= 3) — the advertised set {0,4,8,12} (gap
        // 4) lies outside the skip window (a hard chain break),
        // preserving the "one piece per peer" premise of the atomicity
        // observation (with a single-block-piece supply window the append
        // chain would swallow the whole advertised set and the round-3
        // pin would have no piece left); cross-piece append behavior is
        // pinned by the multi_piece tests.
        for cuid in 1..=3u64 {
            let (handle, remote) = choke_peer_pair(&root).await;
            face.peers.push(handle);
            face.peer_cuids.push(cuid);
            note_peer_bitfield(&mut face, cuid, &[0b1000_1000, 0b1000_1000]);
            remotes.push(remote);
        }
        let _keep_alive: Vec<tokio::io::DuplexStream> = remotes;

        // Round 1 (default rarest-first): the 3 peers claim different
        // pieces (the spread baseline).
        dispatch_face_selected(&mut face, 0, None, &RarestFirstStrategy);
        assert_eq!(dispatch_count(&face), 3, "baseline: 3 peers each claim one piece");
        let claimed_before: std::collections::BTreeSet<(u64, u32)> =
            dispatch_entries(&face)
                .into_iter()
                .map(|(p, b, _)| (p, b))
                .collect();
        let inflight_before = inflight_snapshot(&face);
        assert_eq!(inflight_before.len(), 3);

        // Round 2 (swap to the no-pick stub): the in-flight bookkeeping
        // is unchanged (the swap neither cancels nor resends in flight).
        dispatch_face_selected(&mut face, 0, None, &NoPickStrategy);
        assert_eq!(
            inflight_snapshot(&face),
            inflight_before,
            "(a) the in-flight bookkeeping unaffected by the swap"
        );
        assert_eq!(
            dispatch_entries(&face)
                .into_iter()
                .map(|(p, b, _)| (p, b))
                .collect::<std::collections::BTreeSet<_>>(),
            claimed_before,
            "(a) the claim bookkeeping unaffected by the swap"
        );
        assert!(face.refetch.is_empty(), "(a) the swap produces no refetch entries");

        // Round 3 (swap to the pin stub -> an unclaimed piece): the new
        // decision takes effect immediately; after the first peer
        // enqueues the single-block piece, block-level dedup blocks the
        // other peers (1 new claim), and claimed pieces get zero resend.
        // Pin candidates are limited to every 4th piece (the advertised
        // set = {0,4,8,12} — the PinStrategy advertisement constraint).
        let pin = (0..16u64)
            .filter(|p| p % 4 == 0)
            .find(|p| !claimed_before.contains(&(*p, 0)))
            .unwrap_or_else(|| panic!("with 4 advertised pieces and 3 claimed a spare piece must exist"));
        dispatch_face_selected(&mut face, 0, None, &PinStrategy(pin));
        assert_eq!(
            dispatch_entries(&face).iter().filter(|&&(p, _, _)| p == pin).count(),
            1,
            "(b) the pin stub's selection takes effect immediately (a single-block piece = exactly 1 dispatch)"
        );
        assert_eq!(
            inflight_snapshot(&face).len(),
            4,
            "(b) the new piece booked + the 3 claimed pieces kept"
        );
        for p in claimed_before.iter().map(|&(p, _)| p) {
            let n = face.blocks_sent.get(&p).map(|l| l.tracked_count()).unwrap_or(0);
            assert_eq!(
                Some(n),
                inflight_before.get(&p).copied(),
                "(a) the claimed piece {p} zero resend"
            );
        }
        root.cancel();
    }

    // ---- smart_ban parole dispatch gate ----

    /// Parole selection pure-function decision table
    /// ([`parole_pick_piece`]): the first piece in rarity order that is
    /// "advertised AND incomplete AND unclaimed AND unowned (no
    /// blocks_sent entry)"; any unmet condition skips the piece; none
    /// satisfiable -> None (skip the peer; waiting is not
    /// disconnecting).
    #[test]
    fn parole_pick_piece_decision_table() {
        let mut face = adv_face(4);
        let mut stat_rng = XorShift(0x1234567890ABCDEFu64);
        face.stat_man = PieceStatMan::new(4, &mut |n| stat_rng.next(n));
        let mut claimed = ClaimedSet::with_len(4);
        // The full advertised set; the rarity order comes from the
        // shuffle source (the values themselves do not matter; only the
        // call-face semantics are under test).
        face.peer_avail.insert(7u64, PieceBitmap::ones(4));
        // The pure function only reads peer_cuids (to locate the
        // advertised bitmap) — the registration-face bookkeeping is
        // filled directly.
        face.peer_cuids.push(7);
        // After compaction order is u32 (a seam conversion; this test
        // only covers call-face semantics).
        let order: Vec<u32> = face.stat_man.order().to_vec();
        assert_eq!(order.len(), 4);
        // Row 1: all conditions met -> take the rarity-order first.
        let done = vec![false; 4];
        assert_eq!(
            parole_pick_piece(&face, 0, &done, &claimed),
            order.first().copied().map(u64::from),
            "all conditions met = the rarity-order first piece"
        );
        // Row 2: the first piece is claimed elsewhere -> skip to the
        // next.
        claimed.mark_claimed(u64::from(order[0]));
        assert_eq!(
            parole_pick_piece(&face, 0, &done, &claimed),
            order.get(1).copied().map(u64::from),
            "a claimed piece skipped"
        );
        // Row 3: the piece has an owner (any block was already delivered
        // elsewhere = a blocks_sent entry) -> skip (the unowned-whole-
        // piece constraint — necessary and sufficient for unambiguous
        // blame).
        let owned = order[1];
        seed_blocks_sent(
            &mut face,
            u64::from(owned),
            Instant::now(),
            &[(0, BlockState::Buffered)],
        );
        assert_eq!(
            parole_pick_piece(&face, 0, &done, &claimed),
            order.get(2).copied().map(u64::from),
            "a piece with an owner (including pure Buffered) skipped"
        );
        // Row 4: every remaining piece is done -> None.
        let done_all = vec![true, true, true, true];
        assert_eq!(parole_pick_piece(&face, 0, &done_all, &claimed), None);
        // Row 5: a peer with no advertisement -> None (the advertisement-
        // awareness semantics is not exempted).
        assert_eq!(parole_pick_piece(&face, 1, &done, &claimed), None, "no advertised row");
    }

    /// Parole peer dispatch, face-level: a suspect peer claims only
    /// unowned whole pieces this round — after a normal peer claims
    /// piece X, the parole peer must take a different piece with no
    /// prior delivery bookkeeping (exclusivity = if the piece fails
    /// again the bad block must come from that peer).
    #[tokio::test]
    async fn parole_peer_claims_only_pristine_whole_piece() {
        let root = tokio_util::sync::CancellationToken::new();
        let mut face = adv_face(6);
        // Peer A (cuid 1, normal) + peer B (cuid 2, parole suspect).
        let (handle_a, _ra) = choke_peer_pair(&root).await;
        let (handle_b, _rb) = choke_peer_pair(&root).await;
        face.peers.push(handle_a);
        face.peers.push(handle_b);
        face.peer_cuids.push(1);
        face.peer_cuids.push(2);
        // Chain-break note: with the default floor of 4 cross-piece
        // append is always on — the advertised set is spaced non-
        // adjacently; with the default N=2 a soft break may skip <= 2
        // pieces (lookahead d <= 3) — the advertised set {0, 5} (gap 5)
        // lies outside the skip window (a hard chain break), preserving
        // the parole focus face of "A claims one piece + B gets an
        // unowned whole piece" (A's adjacent append chain would otherwise
        // swallow the whole advertised set, leaving B no unowned piece);
        // cross-piece append behavior is pinned by the multi_piece tests.
        note_peer_bitfield(&mut face, 1, &[0b1000_0100]);
        note_peer_bitfield(&mut face, 2, &[0b1000_0100]);
        face.parole_peers.insert(2);

        // Round 1: A selects normally and claims P_A; B (parole) may
        // only claim an unowned whole piece.
        dispatch_face_selected(&mut face, 0, None, &RarestFirstStrategy);
        let a_pieces: std::collections::HashSet<u64> = dispatch_entries(&face)
            .into_iter()
            .filter(|&(_, _, c)| c == 1)
            .map(|(p, _, _)| p)
            .collect();
        let b_pieces: std::collections::HashSet<u64> = dispatch_entries(&face)
            .into_iter()
            .filter(|&(_, _, c)| c == 2)
            .map(|(p, _, _)| p)
            .collect();
        assert_eq!(a_pieces.len(), 1, "A claims one piece normally: {a_pieces:?}");
        assert_eq!(b_pieces.len(), 1, "B (parole) claims one piece: {b_pieces:?}");
        assert!(
            a_pieces.is_disjoint(&b_pieces),
            "the parole peer shares no piece with others (the unowned constraint)"
        );
        let b_piece = *b_pieces.iter().next().unwrap_or_else(|| panic!("B has a piece"));
        let b_only = face
            .blocks_sent
            .get(&b_piece)
            .is_some_and(|l| {
                l.slots()
                    .iter()
                    .all(|s| s.state == BlockState::InFlight)
            });
        assert!(b_only, "all of B's piece's blocks are B's in-flight requests (claimed this round, no historical bookkeeping)");
        root.cancel();
    }

    /// Parole peers are barred from endgame busy (face level): when
    /// every remaining piece is in flight (condition A triggers
    /// endgame) the suspect peer sends zero new requests this round —
    /// duplicate-copy rounds are off limits (duplicate delivery blurs
    /// block attribution; that shape is excluded while under suspicion).
    #[tokio::test]
    async fn parole_peer_excluded_from_endgame_round() {
        let root = tokio_util::sync::CancellationToken::new();
        let mut face = adv_face(4);
        let (handle_a, _ra) = choke_peer_pair(&root).await;
        let (handle_b, _rb) = choke_peer_pair(&root).await;
        face.peers.push(handle_a);
        face.peers.push(handle_b);
        face.peer_cuids.push(1);
        face.peer_cuids.push(2);
        note_peer_bitfield(&mut face, 1, &[0b1111_0000]);
        note_peer_bitfield(&mut face, 2, &[0b1111_0000]);
        face.parole_peers.insert(2);
        // Piece 0 done; pieces 1-3 all in flight by A (fresh InFlight)
        // -> in_flight(3) >= missing(3) = endgame condition A holds.
        face.progress.set_piece_done_global(0);
        for p in 1..=3u64 {
            seed_blocks_sent(&mut face, p, Instant::now(), &[(0, BlockState::InFlight)]);
            face.peer_state_row(1).piece = Some(p);
        }
        dispatch_face_selected(&mut face, 0, None, &RarestFirstStrategy);
        // B (parole) sends zero new requests; every dispatch owner = A
        // (including the duplicate copies A is allowed within its own x2
        // gate).
        assert!(
            dispatch_entries(&face).iter().all(|&(_, _, c)| c == 1),
            "the parole peer sends zero requests in the endgame round: {:?}",
            dispatch_entries(&face)
        );
        root.cancel();
    }

    // ---- Client identification bans + manual ban enforcement ----

    /// Identity matching (client_violation): a configured prefix hit ->
    /// a Violation (reason = `client-ban: <matched>`, flowing through
    /// the existing violation channel to storage + disconnect); the
    /// default empty list always returns None (identification is not
    /// banning).
    #[test]
    fn client_violation_matches_configured_prefix_only() {
        let guard = taiji_bt::peer_policy::IpGuardHandle::default();
        assert!(
            client_violation(&guard, b"-XL0011-0123456789AB", ip4([10, 0, 0, 1])).is_none(),
            "an empty list rejects no client"
        );
        guard.store(
            taiji_bt::peer_policy::IpGuard::default()
                .with_client_deny(["-XL".to_string(), "-QD".to_string()]),
        );
        let v = client_violation(&guard, b"-XL0011-0123456789AB", ip4([10, 0, 0, 1]))
            .unwrap_or_else(|| panic!("prefix hit must reject"));
        assert_eq!(v.reason, "client-ban:-XL");
        assert_eq!(v.ip, ip4([10, 0, 0, 1]));
        assert!(client_violation(&guard, b"-qB4550-0123456789AB", ip4([10, 0, 0, 2])).is_none());
    }

    /// The v-dimension recheck callback (`client_v_deny_check`): after a
    /// peer_id prefix escape, an ext-handshake `v` self-report hitting
    /// the list is handled as client-ban (the reason matches the
    /// handshake-time shape; substring, case-insensitive). Table-driven.
    #[test]
    fn client_v_deny_check_hits_v_substring_after_peer_id_escape() {
        let guard = taiji_bt::peer_policy::IpGuardHandle::default();
        guard.store(
            taiji_bt::peer_policy::IpGuard::default()
                .with_client_deny(["-XL".to_string(), "xunlei".to_string()]),
        );
        let check = client_v_deny_check(&guard);
        // peer_id escape face (the same baseline as the test above): a
        // clean peer_id does not enter the prefix table.
        assert!(
            guard
                .load()
                .client_blocks(Some(b"-qB4550-0123456789AB"), None)
                .is_none()
        );
        // The same peer's v self-report hit -> client-ban handling (the
        // second dimension in effect).
        let rows = [
            ("Xunlei 5.0.1.2", Some("client-ban:xunlei".to_string())),
            ("thunder (XUNLEI) 迅雷", Some("client-ban:xunlei".to_string())),
            ("qBittorrent v4.2.5", None),
            ("", None),
        ];
        for (v, want) in rows {
            assert_eq!(check(v), want, "v = {v:?}");
        }
        // Prefix-shaped entries also take effect through the v path (the
        // "prefix OR v substring" union promise).
        assert_eq!(
            check("衍生版 -XL0001"),
            Some("client-ban:-XL".to_string())
        );
        // Hot reload takes effect immediately (arc-swap snapshot read).
        guard.store(taiji_bt::peer_policy::IpGuard::default());
        assert_eq!(check("Xunlei 5.0.1.2"), None);
        // An empty list bans no client (identification is not banning).
        let empty = client_v_deny_check(&taiji_bt::peer_policy::IpGuardHandle::default());
        assert_eq!(empty("Xunlei 5"), None);
    }

    /// BanBook::set_ban_config wholesale replacement: identity rules /
    /// manual ranges enter the snapshot, expired manual ranges are
    /// dropped, and automatic bans are preserved.
    #[test]
    fn ban_book_set_ban_config_swaps_snapshot() {
        let mut book = BanBook {
            guard: taiji_bt::peer_policy::IpGuardHandle::default(),
            static_rules: Vec::new(),
            ledger: taiji_domain::peer_guard::BanLedger::new(Box::new(|| Duration::from_secs(300))),
            client_deny: Vec::new(),
            manual: Vec::new(),
            metrics: None,
            smart_ban: SmartBanLedger::from_env(),
            smart_ban_read_gate: Arc::new(tokio::sync::Semaphore::new(1)),
        };
        let now = epoch_secs();
        // Automatic-ban fold baseline.
        assert!(book.ledger.record_violation(ip4([192, 0, 2, 1]), "viol", now));
        let mut faces: Vec<FaceState> = Vec::new();
        book.set_ban_config(
            vec!["-XL".to_string()],
            vec![
                taiji_domain::peer_guard::ManualBanRule {
                    start: ip4([10, 66, 0, 0]),
                    end: ip4([10, 66, 0, 255]),
                    until: now + 600,
                },
                taiji_domain::peer_guard::ManualBanRule {
                    start: ip4([10, 77, 0, 0]),
                    end: ip4([10, 77, 0, 255]),
                    until: now - 1,  // already expired -> not in the snapshot
                },
            ],
            &mut faces,
        );
        let snap = book.guard.load();
        assert_eq!(
            snap.client_blocks(Some(b"-XL0011-0123456789AB"), None),
            Some("-XL".to_string()),
            "the identity rules enter the snapshot"
        );
        assert!(
            matches!(
                snap.blocks(ip4([10, 66, 0, 9]), now),
                Some(taiji_bt::peer_policy::IpBlock::Banned(r)) if r == "manual"
            ),
            "an unexpired manual range intercepts (reason=manual)"
        );
        assert_eq!(snap.blocks(ip4([10, 77, 0, 9]), now), None, "an expired manual range allows through");
        assert!(snap.blocks(ip4([192, 0, 2, 1]), now).is_some(), "the automatic ban kept");
        // Wholesale replacement (empty lists): the identity rules vanish
        // with it.
        book.set_ban_config(Vec::new(), Vec::new(), &mut faces);
        assert_eq!(
            book.guard.load().client_blocks(Some(b"-XL0011-0123456789AB"), None),
            None
        );
    }

    fn ip4(oct: [u8; 4]) -> std::net::IpAddr {
        std::net::IpAddr::V4(std::net::Ipv4Addr::from(oct))
    }

// ---- StreamingStrategy dispatch wiring (duplex face) ----

/// Streaming dispatch fixture: an 8-piece v1 face (adv_face reused) +
/// layout projection geometry + a playhead payload. `pos_piece` = the
/// piece under the playhead; `win_pieces` controls the window width
/// (bps = stride x win / STREAM_WINDOW_SECS tier).
fn stream_plan(pos_piece: u64, win_pieces: u64) -> StreamPlan {
    let stride = u64::from(merkle::BLOCK_SIZE);
    let layout = Layout::plan_v1_padded(
        &[taiji_store::layout::PlanEntry {
            path: std::path::PathBuf::from("blob.bin"),
            length: 8 * stride,
            padding: false,
        }],
        merkle::BLOCK_SIZE,
    )
    .unwrap_or_else(|e| panic!("layout: {e}"));
    StreamPlan {
        playhead: Playhead {
            file: 0,
            position: pos_piece * stride,
            bytes_per_sec: Some(stride * win_pieces / 30 + 1),
        },
        geo: Arc::new(StreamGeo::from_layout(&layout, merkle::BLOCK_SIZE)),
    }
}

/// Dispatch wiring x playhead advance (the engine half of criteria 2/4):
/// a single fully advertising duplex peer —
/// (a) the first-round claim = the piece under the playhead (EDF
/// nearest; not piece 0, not the shuffle order);
/// (b) later rounds expand outward in ascending distance (5 -> 7 -> 4;
/// distance ties break by flat ascending);
/// (c) advancing the playhead = re-issuing the plan: the nearest
/// unclaimed piece in the new window takes effect immediately;
/// (d) verified pieces (the done bitmap) are never selected — the
/// defense against "a repeated request targeting a completed piece"
/// holds under the streaming strategy too.
#[tokio::test]
async fn streaming_dispatch_edf_and_playhead_advance() {
    let root = tokio_util::sync::CancellationToken::new();
    let mut face = adv_face(8);
    let (handle, remote) = choke_peer_pair(&root).await;
    face.peers.push(handle);
    face.peer_cuids.push(7);
    note_peer_bitfield(&mut face, 7, &[0b1111_1111]);
    let _keep_alive = remote;

    // A 1-piece window (the bps floor = stride -> the window contains
    // exactly the playhead piece).
    let plan = stream_plan(6, 1);
    dispatch_face_selected_with_stream(&mut face, 0, None, &StreamingStrategy, Some(&plan), None);
    let claimed: std::collections::BTreeSet<u64> = dispatch_entries(&face)
        .into_iter()
        .map(|(p, _, _)| p)
        .collect();
    assert_eq!(
        claimed.into_iter().collect::<Vec<_>>(),
        vec![6],
        "(a) the first round claims the playhead's piece"
    );
    let mut claimed: std::collections::HashSet<u64> = dispatch_entries(&face)
        .into_iter()
        .map(|(p, _, _)| p)
        .collect();

    // (b) Spread advance: the distance-1 tie (5,7) breaks by flat
    // ascending -> 5; then 7; then 4.
    for expect in [[5u64], [7], [4]] {
        dispatch_face_selected_with_stream(&mut face, 0, None, &StreamingStrategy, Some(&plan), None);
        let mut new: Vec<u64> = dispatch_entries(&face)
            .into_iter()
            .map(|(p, _, _)| p)
            .filter(|p| !claimed.contains(p))
            .collect();
        new.sort_unstable();
        assert_eq!(new, expect, "(b) the EDF outward-expansion order");
        claimed.extend(new);
    }

    // (c) The playhead advances to piece 2: the next round claims the
    // nearest unclaimed piece 2 in the new window.
    let plan2 = stream_plan(2, 1);
    dispatch_face_selected_with_stream(&mut face, 0, None, &StreamingStrategy, Some(&plan2), None);
    let mut new: Vec<u64> = dispatch_entries(&face)
        .into_iter()
        .map(|(p, _, _)| p)
        .filter(|p| !claimed.contains(p))
        .collect();
    new.sort_unstable();
    assert_eq!(new, vec![2], "(c) the playhead advance takes effect immediately");
    claimed.extend(new);

    // (d) Verified pieces are never selected (the front half of the
    // defense — dispatch targets never land inside the done bitmap): a
    // fresh face pre-marks piece 6 done with the playhead at 6 -> the
    // first round claims the nearest incomplete piece 5 (skipping 6),
    // not 6.
    let mut face2 = adv_face(8);
    assert!(face2.progress.set_piece_done_global(6));
    let (handle2, remote2) = choke_peer_pair(&root).await;
    face2.peers.push(handle2);
    face2.peer_cuids.push(9);
    note_peer_bitfield(&mut face2, 9, &[0b1111_1111]);
    let _keep_alive2 = remote2;
    dispatch_face_selected_with_stream(&mut face2, 0, None, &StreamingStrategy, Some(&plan), None);
    let claimed2: Vec<u64> = dispatch_entries(&face2)
        .into_iter()
        .map(|(p, _, _)| p)
        .collect();
    assert_eq!(claimed2, vec![5], "(d) the completed piece 6 skipped; the nearest incomplete piece 5 selected");
    root.cancel();
}

/// Dispatch convergence when the window and beyond are fully claimed
/// (the "duplicate request backstop" half of criterion 4): with every
/// piece in flight (fresh) the tier-3 fallback hits a window piece
/// whose blocks are all in flight -> the candidate set is empty ->
/// zero new requests (an idle peer beats resending in flight; the
/// spread semantics unchanged); the strategy's return value never
/// lands on a completed piece (the front half of the backstop).
#[tokio::test]
async fn streaming_dispatch_no_duplicate_when_all_inflight() {
    let root = tokio_util::sync::CancellationToken::new();
    let mut face = adv_face(8);
    let (handle, remote) = choke_peer_pair(&root).await;
    face.peers.push(handle);
    face.peer_cuids.push(7);
    note_peer_bitfield(&mut face, 7, &[0b1111_1111]);
    let _keep_alive = remote;
    // Every piece fresh InFlight (single-block pieces).
    for p in 0..8u64 {
        seed_blocks_sent(&mut face, p, Instant::now(), &[(0, BlockState::InFlight)]);
    }
    let plan = stream_plan(6, 1);
    dispatch_face_selected_with_stream(&mut face, 0, None, &StreamingStrategy, Some(&plan), None);
    assert!(
        face.dispatch_replies.is_empty(),
        "all in flight -> zero new requests (no resend)"
    );
    // Claim bookkeeping unchanged (all 8 pieces stay fresh in flight).
    assert_eq!(face.blocks_sent.len(), 8);
    root.cancel();
}

    // ---- Smart scheduling: adaptive endgame + bandwidth-aware dispatch ----

    /// Endgame trigger boundary table ([`endgame_triggered`]; cross-
    /// validation sources in its docs):
    /// row 1 the completed state is not endgame; rows 2-4 condition A
    /// (every remaining incomplete piece is "downloaded or in flight" —
    /// the complement of libtorrent request_blocks.cpp's reverse
    /// condition, `set_endgame(true)` at :285) boundary = equality
    /// triggers; rows 5-8 condition B (remaining bytes / rate ETA <
    /// [`crate::dispatch::ENDGAME_ETA_THRESHOLD_SECS`]) boundary =
    /// strictly less than, and zero rate does not trigger; row 9
    /// condition A does not depend on rate/byte evidence.
    #[test]
    fn endgame_trigger_boundary_table() {
        // Condition A: in_flight >= missing (missing > 0).
        assert!(!endgame_triggered(0, 0, 0, 0.0), "row 1: all complete = not endgame");
        assert!(
            endgame_triggered(8, 8, 8 * 16, 0.0),
            "row 2: all in flight (condition A fires even with zero rate evidence)"
        );
        assert!(endgame_triggered(1, 1, 16, 0.0), "row 3: a single piece fully in flight");
        assert!(
            !endgame_triggered(8, 7, 8 * 16, 0.0),
            "row 4: pieces still not in flight -> not endgame (boundary: only equal counts trigger)"
        );
        // Condition B: missing_bytes / rate < 30s (strictly less than).
        assert!(endgame_triggered(8, 0, 1000, 100.0), "row 5: ETA 10s < 30s");
        assert!(
            !endgame_triggered(8, 0, 3000, 100.0),
            "row 6: ETA exactly 30s = does not fire (the strictly-less boundary)"
        );
        assert!(!endgame_triggered(8, 0, 3001, 100.0), "row 7: ETA 30.01s");
        assert!(
            !endgame_triggered(8, 0, 1000, 0.0),
            "row 8: zero rate, no statistical evidence -> condition B does not fire"
        );
        assert!(
            endgame_triggered(2, 2, 1_000_000, 0.0),
            "row 9: condition A does not depend on rate/bytes (the union set; A judged first)"
        );
    }

    /// Bandwidth-aware dispatch order + reciprocity tie-break
    /// ([`endgame_peer_order`]): the primary key = 30s-window rate
    /// descending (bandwidth-aware dispatch; the libtorrent pick-face
    /// peer order cross-validation torrent.cpp + peer_connection.cpp);
    /// the tie-break = interested first (among equal-rate candidates,
    /// prefer the peer that "wants our pieces" — tit-for-tat reciprocity,
    /// BiToS thinking; it does not harm the rarest-first primary key —
    /// this order only reorders peers, selection stays with the
    /// strategy); a full tie = the connection order, stable.
    #[test]
    fn endgame_peer_order_bandwidth_then_reciprocity() {
        // Row 1: rate descending (1KiB/s, 100KiB/s, 10KiB/s -> 1,2,0).
        let rates = [1024.0, 100.0 * 1024.0, 10.0 * 1024.0];
        assert_eq!(
            endgame_peer_order(&rates, &[false; 3]),
            vec![1, 2, 0],
            "row 1: the primary key = 30s-window rate descending"
        );
        // Row 2: peers 1/2 tie (50KiB/s) -> the interested one first.
        let rates = [1024.0, 50.0 * 1024.0, 50.0 * 1024.0];
        assert_eq!(
            endgame_peer_order(&rates, &[false, false, true]),
            vec![2, 1, 0],
            "row 2: the tie-break = interested (reciprocity) first"
        );
        // Row 3: when rates differ, interested does not overtake the
        // primary key.
        assert_eq!(
            endgame_peer_order(&rates, &[true, false, false]),
            vec![1, 2, 0],
            "row 3: the reciprocity bit never overtakes the rate primary key (tie-break tier)"
        );
        // Row 4: a full tie -> the connection order (deterministic).
        assert_eq!(
            endgame_peer_order(&[0.0; 3], &[false; 3]),
            vec![0, 1, 2],
            "row 4: a full tie = the connection order"
        );
    }

    /// x2 gate metering table ([`endgame_inflight_copies`]): no/empty
    /// bookkeeping -> 0; fresh InFlight -> 1; any fresh InFlightDup -> 2
    /// (the one-shot duplicate marker = the metering basis for refusing
    /// a third hop); stale (>= the reissue window) does not count (a
    /// stale slot is presumed dead and takeable); Buffered does not
    /// count (the bytes are already local). The window is parameterized
    /// (rows 1-7 pass the existing [`DISPATCH_REISSUE_WINDOW`] 2s = the
    /// OFF reading, bit-for-bit) plus Settling rows (rows 8-10: the
    /// store segment counts 0 — arrived blocks need no duplicate
    /// coverage and dup marks grant no third-hop eligibility). Freshness
    /// reads the piece-level shared timestamp ([`PieceSentLedger`]) —
    /// the old "mixed fresh/stale ages within one piece" row is not
    /// expressible (one piece, one freshness); its two assertion faces
    /// are carried by row 4 (fresh caps at 2) and row 6 (all stale 0)
    /// with unchanged expectations.
    #[test]
    fn endgame_inflight_copies_table() {
        let now = Instant::now();
        let stale = now - DISPATCH_REISSUE_WINDOW - Duration::from_millis(50);
        assert_eq!(
            endgame_inflight_copies(None, now, DISPATCH_REISSUE_WINDOW),
            0,
            "row 1: no bookkeeping"
        );
        let empty = ledger_seeded(4, now, &[]);
        assert_eq!(
            endgame_inflight_copies(Some(&empty), now, DISPATCH_REISSUE_WINDOW),
            0,
            "row 2: empty bookkeeping"
        );
        let fresh_first =
            ledger_seeded(4, now, &[(0, BlockState::InFlight)]);
        assert_eq!(
            endgame_inflight_copies(Some(&fresh_first), now, DISPATCH_REISSUE_WINDOW),
            1,
            "row 3: the first copy -> 1"
        );
        let fresh_dup = ledger_seeded(
            4,
            now,
            &[(0, BlockState::InFlight), (16_384, BlockState::InFlightDup)],
        );
        assert_eq!(
            endgame_inflight_copies(Some(&fresh_dup), now, DISPATCH_REISSUE_WINDOW),
            2,
            "row 4: any duplicate copy -> 2 (the x2 capped metering; row 5's fresh \
             cap face merged into this row — mixed ages are not expressible, the \
             shared-timestamp note)"
        );
        let all_stale =
            ledger_seeded(4, stale, &[(0, BlockState::InFlightDup)]);
        assert_eq!(
            endgame_inflight_copies(Some(&all_stale), now, DISPATCH_REISSUE_WINDOW),
            0,
            "row 6: all stale -> 0 (a stale slot is takeable; row 5's stale-not-counted \
             face merged into this row)"
        );
        let buffered = ledger_seeded(4, now, &[(0, BlockState::Buffered)]);
        assert_eq!(
            endgame_inflight_copies(Some(&buffered), now, DISPATCH_REISSUE_WINDOW),
            0,
            "row 7: Buffered not counted (the bytes are already local; a duplicate \
             request is pointless)"
        );
        // Store-segment rows (the ON path).
        let settling = ledger_seeded(4, now, &[(0, BlockState::Settling)]);
        assert_eq!(
            endgame_inflight_copies(Some(&settling), now, DISPATCH_REISSUE_WINDOW),
            0,
            "row 8: Settling first copy -> 0 (arrived blocks need no duplicate coverage)"
        );
        let settling_dup = ledger_seeded(
            4,
            now,
            &[(0, BlockState::Settling), (16_384, BlockState::SettlingDup)],
        );
        assert_eq!(
            endgame_inflight_copies(Some(&settling_dup), now, DISPATCH_REISSUE_WINDOW),
            0,
            "row 9: SettlingDup -> 0 (a dup mark grants no third-hop eligibility; \
             the R8 criterion is consumed only at settle time)"
        );
        let settling_stale = now - Duration::from_secs(60);
        let settling_old = ledger_seeded(4, settling_stale, &[(0, BlockState::Settling)]);
        assert_eq!(
            endgame_inflight_copies(Some(&settling_old), now, DISPATCH_REISSUE_WINDOW),
            0,
            "row 10: beyond the guard age Settling still counts 0 (the store segment \
             never participates in redispatch/duplicate verdicts)"
        );
        // Window-parameterized row: under an adaptive window (the 5s
        // upper bound) a 2.5s-old network-segment block counts as fresh.
        let aged_t = now - Duration::from_millis(2500);
        let aged = ledger_seeded(4, aged_t, &[(0, BlockState::InFlight)]);
        assert_eq!(
            endgame_inflight_copies(Some(&aged), now, DISPATCH_REISSUE_WINDOW),
            0,
            "row 11: 2.5s age at the 2s window -> 0 (the existing semantics)"
        );
        assert_eq!(
            endgame_inflight_copies(Some(&aged), now, REISSUE_WINDOW_CEIL),
            1,
            "row 12: 2.5s age at the 5s window -> 1 (the metering face follows the \
             window's track: the same semantics as the reissue window, so a slow \
             peer's piece does not yield its copy slot early)"
        );
    }

    /// Endgame cursor two-level pick decision table
    /// ([`endgame_cursor_pick`]):
    /// rows 1-3 strict=on — unowned first (row 1 takes the unowned
    /// piece; row 2 everything held and the busy gate forbids -> None;
    /// row 3 everything held AND the busy gate admits -> take another's
    /// held piece); row 4 every missing piece at x2 capacity -> the busy
    /// gate passes but the x2 backstop caps -> None; rows 5-6 strict=off
    /// (the `BH_ENDGAME_STRICT=0` fallback) — restores the x2 reading
    /// byte for byte: the busy gate is bypassed (row 5 = the
    /// counterpart of row 2's state) and only the copy count matters
    /// (row 6 takes another's held piece directly — the wire-
    /// amplification residue the strict gate removes; with off it
    /// returns by design).
    #[test]
    fn endgame_cursor_pick_two_level_table() {
        let claimed_01 = {
            let mut c = ClaimedSet::with_len(3);
            c.mark_claimed(0);
            c.mark_claimed(1);
            c
        };
        let claimed_all = {
            let mut c = ClaimedSet::with_len(3);
            c.mark_claimed(0);
            c.mark_claimed(1);
            c.mark_claimed(2);
            c
        };
        let avail_all = Some(PieceBitmap::ones(3));
        let mut copies_one: std::collections::HashMap<u64, u64> = Default::default();
        copies_one.insert(0, 1);
        copies_one.insert(1, 1);
        copies_one.insert(2, 1);
        let mut copies_all_full: std::collections::HashMap<u64, u64> = Default::default();
        copies_all_full.insert(0, 2);
        copies_all_full.insert(1, 2);
        copies_all_full.insert(2, 2);
        let mut copies_head_full: std::collections::HashMap<u64, u64> = Default::default();
        copies_head_full.insert(0, 2);
        copies_head_full.insert(1, 2);
        copies_head_full.insert(2, 1);
        let pieces: Vec<u64> = vec![0, 1, 2];
        // Row 1: strict on, piece 2 unowned -> take it directly (the x2
        // gate is not consulted).
        assert_eq!(
            endgame_cursor_pick(
                &pieces,
                avail_all.as_ref(),
                &claimed_01,
                &copies_one,
                true,
                true,
                &|_| ENDGAME_MAX_COPIES
            ),
            Some(2),
            "row 1: unowned first — an unowned piece is taken directly"
        );
        // Row 2: strict on, no unowned work left AND the busy gate ->
        // None.
        assert_eq!(
            endgame_cursor_pick(
                &pieces,
                avail_all.as_ref(),
                &claimed_all,
                &copies_one,
                true,
                false,
                &|_| ENDGAME_MAX_COPIES
            ),
            None,
            "row 2: the busy gate (strict active / the peer's in-flight non-zero) -> \
             zero busy picks"
        );
        // Row 3: strict on, no unowned work left AND the busy gate admits
        // -> take another's held piece (copies < x2), the one-hop
        // duplicate path.
        assert_eq!(
            endgame_cursor_pick(
                &pieces,
                avail_all.as_ref(),
                &claimed_all,
                &copies_one,
                true,
                true,
                &|_| ENDGAME_MAX_COPIES
            ),
            Some(0),
            "row 3: the busy gate admits -> another's held piece (copies < x2), the \
             one-hop duplicate path"
        );
        // Row 4: strict on, every missing piece at x2 capacity -> the
        // busy gate passes but the cap holds -> None.
        assert_eq!(
            endgame_cursor_pick(
                &pieces,
                avail_all.as_ref(),
                &claimed_all,
                &copies_all_full,
                true,
                true,
                &|_| ENDGAME_MAX_COPIES
            ),
            None,
            "row 4: every missing piece at x2 capacity -> no busy path (the cap boundary)"
        );
        // Row 5: the fallback counterpart (the same shape as row 2, which
        // was None): strict off -> the busy gate is bypassed while the x2
        // copy count is still respected (0/1 at capacity are skipped) ->
        // take piece 2.
        assert_eq!(
            endgame_cursor_pick(
                &pieces,
                avail_all.as_ref(),
                &claimed_all,
                &copies_head_full,
                false,
                false,
                &|_| ENDGAME_MAX_COPIES
            ),
            Some(2),
            "row 5: the fallback mode restores the x2 semantics — a piece with \
             copies < x2 is still taken while the busy gate forbids (the counterpart \
             of row 2's state)"
        );
        // Row 6: strict off, another's held piece (copies 1 < x2) is
        // taken directly — the wire-amplification residue the strict gate
        // removes; with off it returns by design.
        assert_eq!(
            endgame_cursor_pick(
                &pieces,
                avail_all.as_ref(),
                &claimed_all,
                &copies_one,
                false,
                false,
                &|_| ENDGAME_MAX_COPIES
            ),
            Some(0),
            "row 6: the fallback mode takes another's held piece directly (the busy gate bypassed)"
        );
    }

    /// Busy-pick two-level eligibility gate boundary table
    /// ([`endgame_busy_admitted`]):
    /// rows 1-2 gate 1 (strict, libtorrent `strict_end_game_mode`:
    /// `get_download_queue_size() < num_want_left()` forbids busy picks,
    /// request_blocks.cpp) — pieces in flight < missing -> forbidden
    /// (unowned work remains); pieces in flight >= missing -> passes
    /// (true endgame).
    /// rows 3-5 gate 2 (the peer is not empty-handed, `:188` `dq.size() +
    /// rq.size() > 0` forbids busy picks) — non-zero in flight ->
    /// forbidden (including the busy count = 1 shape: the per-peer busy
    /// allocation cap verdict); empty-handed -> passes. Row 6 both gates
    /// conjunct: 1 passes AND 2 forbids -> forbidden.
    #[test]
    fn endgame_busy_admitted_boundary_table() {
        // Gate 1: strict (pieces in flight vs missing pieces).
        assert!(
            !endgame_busy_admitted(2, 3, 0),
            "row 1: in flight 2 < missing 3 -> busy picks forbidden (the strict gate; \
             unowned work remains)"
        );
        assert!(
            endgame_busy_admitted(2, 2, 0),
            "row 2: in flight 2 >= missing 2 -> strict inactive (true endgame; \
             boundary: equality passes)"
        );
        // Gate 2: the peer is empty-handed (fresh in-flight blocks).
        assert!(
            !endgame_busy_admitted(3, 3, 1),
            "row 3: strict inactive but the peer's in-flight non-zero -> busy picks \
             forbidden (requests still outstanding)"
        );
        assert!(
            !endgame_busy_admitted(3, 3, 2),
            "row 4: a busy count >= 1 shape forbidden alike (the per-peer busy \
             allocation cap)"
        );
        assert!(
            endgame_busy_admitted(3, 3, 0),
            "row 5: strict inactive and empty-handed -> busy picks admitted (the \
             one-hop duplicate generation condition)"
        );
        assert!(
            !endgame_busy_admitted(2, 3, 1),
            "row 6: both gates conjunct — either gate -> forbidden"
        );
    }

    /// Busy gate rate-tier decision table
    /// ([`endgame_busy_admitted_tiered`]; `BH_ENDGAME_FAST_BUSY_K`
    /// default 2, previously 0 = off): row 1 K=0 explicit fallback
    /// bit-for-bit — the fast/slow tier flags are not consumed and
    /// every input cell equals [`endgame_busy_admitted`]'s old two-
    /// level gate (the busy piece count feeds the zero check in place
    /// of the block count; zero is equivalent); row 2 K=2 fast tier,
    /// two pieces — busy pieces 0/1 admit and 2 is blocked (at most K
    /// at once); row 3 the slow tier still `==0` (strict bit-for-bit —
    /// K only relaxes the fast tier); row 4 strict gate 1 judges both
    /// tiers the same; row 5 K=1 is equivalent to strict (a fast-tier
    /// cap of 1 = zero tolerance). Red line: the x2 copy cap and the
    /// last-mile boundary do not pass through this function
    /// (`endgame_busy_admitted_dispatch_table` rows 1/2).
    #[test]
    fn endgame_busy_admitted_tiered_decision_table() {
        // Row 1: K=0 is bit-for-bit the old gate — every input cell (in
        // flight / missing / count x both tier flags; the flags are not
        // consumed in the K=0 arm, any values give the same verdict).
        for &in_flight in &[0u64, 2, 3] {
            for &missing in &[0u64, 2, 3] {
                for &count in &[0u64, 1, 2] {
                    for &fast in &[false, true] {
                        assert_eq!(
                            endgame_busy_admitted_tiered(count, fast, 0, in_flight, missing),
                            endgame_busy_admitted(in_flight, missing, count),
                            "K=0: in_flight={in_flight} missing={missing} count={count} fast={fast}, the old gate bit-for-bit"
                        );
                    }
                }
            }
        }
        // Row 2: K=2 fast tier, two pieces — 0/1 admit (a second busy
        // piece may enter), 2 is blocked (full = already holding K busy
        // pieces).
        assert!(endgame_busy_admitted_tiered(0, true, 2, 3, 3), "the fast tier with 0 pieces admits");
        assert!(endgame_busy_admitted_tiered(1, true, 2, 3, 3), "the fast tier with 1 piece admits (K=2 allows two)");
        assert!(
            !endgame_busy_admitted_tiered(2, true, 2, 3, 3),
            "the fast tier with 2 pieces = full tier, blocked"
        );
        // Row 3: the slow tier still ==0 (strict bit-for-bit — non-fast
        // tiers are not relaxed).
        assert!(endgame_busy_admitted_tiered(0, false, 2, 3, 3), "the slow tier with 0 pieces admits");
        assert!(
            !endgame_busy_admitted_tiered(1, false, 2, 3, 3),
            "the slow tier with 1 piece still blocked (strict ==0)"
        );
        // Row 4: strict gate 1 judges both tiers the same — with pieces
        // in flight < missing (unowned work remains) even an empty-
        // handed fast peer is forbidden.
        assert!(
            !endgame_busy_admitted_tiered(0, true, 2, 2, 3),
            "row 4: strict active -> the fast tier forbidden (unowned work first)"
        );
        // Row 5: K=1 is equivalent to strict (a fast-tier cap of 1 =
        // zero tolerance).
        assert!(endgame_busy_admitted_tiered(0, true, 1, 3, 3));
        assert!(!endgame_busy_admitted_tiered(1, true, 1, 3, 3), "K=1: a fast tier with 1 piece is already a full tier");
    }

    /// Busy gate tiering criterion decision table ([`endgame_fast_tier`]
    /// / [`rates_median`]): rate >= 2x median AND >= the 100KiB/s floor
    /// — row 1 both conditions pass (exactly 2x inclusive, exactly the
    /// floor inclusive); row 2 the floor blocks (99KiB/s < 100KiB/s);
    /// row 3 the 2x-median condition blocks (150 < 2x80 despite passing
    /// the floor); row 4 an all-dead swarm (median 0) leaves the floor
    /// as the only guard — above the floor is truly fast, below is a
    /// false fast blocked; row 5 the median function (empty / odd /
    /// even-upper-median, the same formula as tick.rs p50).
    #[test]
    fn endgame_fast_tier_decision_table() {
        const KIB: f64 = 1024.0;
        // Row 1: exactly 2x the median AND exactly the floor -> pass
        // (both boundaries inclusive).
        assert!(endgame_fast_tier(100.0 * KIB, 50.0 * KIB), "100 = 2x50 and = the floor");
        assert!(endgame_fast_tier(300.0 * KIB, 100.0 * KIB), "300 >= 2x100 and >= the floor");
        // Row 2: the floor blocks (99KiB/s).
        assert!(!endgame_fast_tier(99.0 * KIB, 50.0 * KIB), "99 < the 100KiB/s floor");
        // Row 3: the 2x-median condition blocks (150 < 160 despite >=
        // floor).
        assert!(!endgame_fast_tier(150.0 * KIB, 80.0 * KIB), "150 < 2x80");
        // Row 4: an all-dead swarm (median 0) — the floor is the only
        // guard.
        assert!(endgame_fast_tier(150.0 * KIB, 0.0), "above the floor at median 0 = truly fast (absolute evidence)");
        assert!(
            !endgame_fast_tier(50.0 * KIB, 0.0),
            "below the floor at median 0 = a false fast blocked (2x0 is always true; \
             the floor is the fallback)"
        );
        // Row 5: the median (copy+sort takes sorted[len/2]; even lengths
        // take the upper median).
        assert_eq!(rates_median(&[]), 0.0, "an empty table has no evidence");
        assert_eq!(rates_median(&[30.0, 10.0, 20.0]), 20.0, "odd length takes the median");
        assert_eq!(rates_median(&[10.0, 20.0, 30.0, 40.0]), 30.0, "even length takes the upper median (tick p50's same formula)");
    }

    /// Busy gate dispatch-round closure decision table
    /// ([`endgame_busy_admitted_dispatch`]): row 1 last-mile bypasses
    /// wholesale — K / busy count / tier / strict are all unconsumed
    /// (the wide-fanout semantics as-is; K does not touch the last-mile
    /// boundary); row 2 strict off bypasses (the `BH_ENDGAME_STRICT=0`
    /// fallback x2 reading; the busy gate is unreachable); row 3 K=0 =
    /// the old two-level gate bit-for-bit; row 4 K>=1 tiers (fast/slow
    /// arms).
    #[test]
    fn endgame_busy_admitted_dispatch_table() {
        // Row 1: last-mile first — any K / count / tier / even strict
        // off admits (last_mile = endgame_rf AND strict AND active;
        // always true on the wiring face).
        assert!(endgame_busy_admitted_dispatch(true, true, 2, 5, false, 0, 0), "row 1: last-mile opens wholesale");
        assert!(endgame_busy_admitted_dispatch(true, true, 2, 5, true, 0, 0), "row 1': the tier flags unconsumed");
        // Row 2: strict off bypass (the busy gate is unreachable).
        assert!(
            !endgame_busy_admitted_dispatch(false, false, 0, 0, false, 3, 3),
            "row 2: strict off -> busy always forbidden"
        );
        // Row 3: K=0 = the old two-level gate bit-for-bit (the count
        // zero check judges the same).
        assert!(endgame_busy_admitted_dispatch(false, true, 0, 0, false, 3, 3), "row 3: K=0, empty-handed passes");
        assert!(
            !endgame_busy_admitted_dispatch(false, true, 0, 1, true, 3, 3),
            "row 3': K=0, non-zero in flight forbidden (the flags unconsumed)"
        );
        // Row 4: the K>=1 tiered arms.
        assert!(
            endgame_busy_admitted_dispatch(false, true, 2, 1, true, 3, 3),
            "row 4: the fast tier with 1 busy piece < K=2 passes"
        );
        assert!(
            !endgame_busy_admitted_dispatch(false, true, 2, 1, false, 3, 3),
            "row 4': the slow tier with 1 busy piece still forbidden"
        );
    }

    // ---- Endgame last-mile wide fan-out (gate / cap / order) ----

    /// Last-mile verdict boundary table ([`endgame_lastmile_active`]):
    /// rows 1-4 the N=4 default arm — 0 missing is always false (the
    /// completed state has no tail segment), 1/4 true (4 = boundary
    /// inclusive), 5 false (beyond the first piece); rows 5-7 the N=0
    /// fallback arm — always false for every missing count (the
    /// fallback switch is N=0, strict semantics bit-for-bit); rows 8-9
    /// the parameter arms N=1/N=165 (a governance window sized from
    /// real-network tail evidence).
    #[test]
    fn endgame_lastmile_gate_boundary_table() {
        // The N=4 default arm.
        assert!(
            !endgame_lastmile_active(4, 0),
            "row 1: 0 missing = the completed state -> not last-mile"
        );
        assert!(endgame_lastmile_active(4, 1), "row 2: 1 missing <= 4 -> active");
        assert!(endgame_lastmile_active(4, 4), "row 3: 4 missing = the boundary inclusive");
        assert!(
            !endgame_lastmile_active(4, 5),
            "row 4: 5 missing > 4 -> the strict domain (the decision surface)"
        );
        // The N=0 fallback arm (BH_ENDGAME_LASTMILE=0 -> strict
        // bit-for-bit).
        assert!(!endgame_lastmile_active(0, 0), "row 5: N=0, 0 missing");
        assert!(!endgame_lastmile_active(0, 1), "row 6: N=0, 1 missing -> always strict");
        assert!(!endgame_lastmile_active(0, 165), "row 7: N=0, every arm always false");
        // Parameter arms.
        assert!(endgame_lastmile_active(1, 1), "row 8: N=1, 1 missing -> active");
        assert!(
            endgame_lastmile_active(165, 165),
            "row 9: N=165 (the fast-window tail-evidence shape) -> a 165-piece tail window active"
        );
    }

    /// Last-mile wide-fanout copy cap table
    /// ([`endgame_lastmile_copies_limit`]): a RELAX-ONLY relaxation of
    /// the x2 gate — holders 0/1/2 -> always the x2 floor (single-
    /// holder shapes never tighten: a single-holder piece's stale block
    /// takeover still uses the default x2); holders >= 3 -> the holder
    /// count (a real-network wide-supply shape of ~60 -> 60).
    #[test]
    fn endgame_lastmile_copies_limit_table() {
        assert_eq!(endgame_lastmile_copies_limit(0), ENDGAME_MAX_COPIES);
        assert_eq!(
            endgame_lastmile_copies_limit(1),
            ENDGAME_MAX_COPIES,
            "1 holder -> the x2 floor (relax-only: never tightened)"
        );
        assert_eq!(endgame_lastmile_copies_limit(2), ENDGAME_MAX_COPIES);
        assert_eq!(endgame_lastmile_copies_limit(3), 3, "the holder count admits");
        assert_eq!(endgame_lastmile_copies_limit(60), 60);
    }

    /// Piece holder count table ([`endgame_piece_holders`]): the per-
    /// peer conjunction of advertised AND not choking us (the
    /// interested-unchoke dispatch path) — peers choking us do not
    /// count (the same eligibility face the dispatch round skips),
    /// unadvertised peers do not count, and mismatched lengths converge
    /// by zip.
    #[test]
    fn endgame_piece_holders_table() {
        // (advertised bitmap, choke bitmap, expected).
        assert_eq!(endgame_piece_holders(&[], &[]), 0, "zero peers -> 0");
        assert_eq!(
            endgame_piece_holders(&[true, true, true], &[false, false, false]),
            3,
            "all advertised, all unchoked -> 3"
        );
        assert_eq!(
            endgame_piece_holders(&[true, true, true], &[true, false, true]),
            1,
            "peers choking us do not count (the same eligibility face as dispatch)"
        );
        assert_eq!(
            endgame_piece_holders(&[false, true, false], &[false, false, false]),
            1,
            "unadvertised peers do not count"
        );
        assert_eq!(
            endgame_piece_holders(&[false, false, false], &[false, false, false]),
            0,
            "zero holders -> 0"
        );
    }

    /// Bitmap-direct-read equivalence lock:
    /// [`endgame_piece_holders_face`] (the dispatch-round consumer —
    /// reads peer_avail bitmap rows directly, avoiding materializing an
    /// intermediate Vec) judges identically to the
    /// [`endgame_piece_holders`] pure table: a missing row (no bitmap
    /// for the peer) = not advertised; chokers do not count.
    #[test]
    fn endgame_piece_holders_face_matches_pure_table() {
        let mut face = adv_face(6);
        // Peer 7: advertises piece 2; peer 8: an all-zero row; peer 9:
        // NO row (no bitfield yet); peer 10: advertises piece 2 (choking
        // us).
        face.peer_avail.insert(7, PieceBitmap::from_bools(&[false, false, true, false, false, false]));
        face.peer_avail.insert(8, PieceBitmap::new(6));
        face.peer_avail.insert(10, PieceBitmap::from_bools(&[false, false, true, false, false, false]));
        for cuid in [7u64, 8, 9, 10] {
            face.peer_cuids.push(cuid);
        }
        let choking = [false, false, false, true];
        // Piece 2: peer 7 advertises and does not choke -> 1 (8 zero row,
        // 9 no row, 10 choking).
        assert_eq!(endgame_piece_holders_face(&face, 2, &choking), 1);
        // Judged identically to the pure table (missing/zero rows ->
        // false projection).
        let adv: Vec<bool> = [7u64, 8, 9, 10]
            .iter()
            .map(|&c| face.peer_avail.get(&c).is_some_and(|r| r.get(2)))
            .collect();
        assert_eq!(
            endgame_piece_holders_face(&face, 2, &choking),
            endgame_piece_holders(&adv, &choking),
            "the bitmap direct read == the pure-function table"
        );
        // Piece 0 (nobody advertises) -> 0; an out-of-range piece (bitmap
        // get returns false) -> 0.
        assert_eq!(endgame_piece_holders_face(&face, 0, &choking), 0);
        assert_eq!(endgame_piece_holders_face(&face, 99, &choking), 0);
    }

    /// Last-mile fast-holder priority order table
    /// ([`endgame_lastmile_peer_order`]): the primary key = 30s-window
    /// rate descending (the same reading as the leecher choke sort
    /// key), ties = cuid ascending (a deterministic tie-break);
    /// interested does not participate (an intentional divergence from
    /// [`endgame_peer_order`] — a reciprocity tie-break is meaningless
    /// in the tail; a pure rate order cures serial waiting).
    #[test]
    fn endgame_lastmile_peer_order_table() {
        // Row 1: rate descending.
        assert_eq!(
            endgame_lastmile_peer_order(&[1.0, 3.0, 2.0], &[10, 20, 30]),
            vec![1, 2, 0],
            "row 1: rate descending"
        );
        // Row 2: rate tie -> cuid ascending (deterministic).
        assert_eq!(
            endgame_lastmile_peer_order(&[2.0, 2.0, 2.0], &[7, 3, 5]),
            vec![1, 2, 0],
            "row 2: a rate tie -> cuid ascending"
        );
        // Row 3: mixed — the only fast peer first, the tie group by cuid.
        assert_eq!(
            endgame_lastmile_peer_order(&[0.0, 5.0, 0.0, 0.0], &[9, 1, 4, 2]),
            vec![1, 3, 2, 0],
            "row 3: the fast peer first, the tie group by cuid"
        );
        // Row 4: zero rates, a full tie (cold windows) -> pure cuid order.
        assert_eq!(
            endgame_lastmile_peer_order(&[0.0; 3], &[30, 20, 10]),
            vec![2, 1, 0],
            "row 4: all-zero rates -> cuid ascending"
        );
    }

    /// Last-mile wide-fanout cursor table ([`endgame_cursor_pick`] with
    /// a copies_limit parameter): rows 1-2 the wide-fanout arm — a
    /// piece at x2 capacity (copies 2) is admitted under a holder-count
    /// cap of 3 (cures "a zombie in place while a fast peer joins late":
    /// the third holder joins); row 3 the relax-only floor arm — 1
    /// holder -> cap x2, copies 2 full -> None (the strict verdict,
    /// never tightened); row 4 the per-piece cap table — piece 0 full
    /// (2/2) and piece 1 has room (2 < 3) -> take piece 1 (an earlier
    /// table entry at capacity is skipped); rows 5-6 the fallback-
    /// equivalence arms — copies_limit always x2 (the =0 fallback /
    /// non-last-mile rounds) -> bit-for-bit the existing decision table
    /// (row 5 = the existing row 4's shape, row 6 = the existing row
    /// 3's shape).
    #[test]
    fn endgame_cursor_pick_lastmile_wide_fanout_table() {
        let claimed_all = {
            let mut c = ClaimedSet::with_len(3);
            c.mark_claimed(0);
            c.mark_claimed(1);
            c.mark_claimed(2);
            c
        };
        let avail_all = Some(PieceBitmap::ones(3));
        let mut copies_two: std::collections::HashMap<u64, u64> = Default::default();
        copies_two.insert(0, 2);
        copies_two.insert(1, 2);
        copies_two.insert(2, 2);
        let mut copies_mixed: std::collections::HashMap<u64, u64> = Default::default();
        copies_mixed.insert(0, 2);
        copies_mixed.insert(1, 2);
        copies_mixed.insert(2, 1);
        let pieces: Vec<u64> = vec![0, 1, 2];
        // Row 1: every missing piece at x2 capacity, cap = holders 3 ->
        // the busy gate admits the first piece.
        assert_eq!(
            endgame_cursor_pick(
                &pieces,
                avail_all.as_ref(),
                &claimed_all,
                &copies_two,
                true,
                true,
                &|_| 3
            ),
            Some(0),
            "row 1: x2-full pieces admitted under the holder-count cap (wide fan-out)"
        );
        // Row 2: a holder cap of 5 -> the same shape admits (the cap
        // scales with the holder count).
        assert_eq!(
            endgame_cursor_pick(
                &pieces,
                avail_all.as_ref(),
                &claimed_all,
                &copies_two,
                true,
                true,
                &|_| 5
            ),
            Some(0),
            "row 2: the cap = the holder count (5) -> admits"
        );
        // Row 3: 1 holder -> the relax-only floor x2, copies 2 full ->
        // None.
        assert_eq!(
            endgame_cursor_pick(
                &pieces,
                avail_all.as_ref(),
                &claimed_all,
                &copies_two,
                true,
                true,
                &|_| ENDGAME_MAX_COPIES
            ),
            None,
            "row 3: the x2 floor never loosens (the 1-holder shape = the strict verdict)"
        );
        // Row 4: per-piece caps — pieces 0/1 full (x2), piece 2's cap 3
        // has room -> take piece 2.
        assert_eq!(
            endgame_cursor_pick(
                &pieces,
                avail_all.as_ref(),
                &claimed_all,
                &copies_mixed,
                true,
                true,
                &|p| if p == 2 { 3 } else { ENDGAME_MAX_COPIES }
            ),
            Some(2),
            "row 4: per-piece caps — a full piece is skipped, a piece with room admits"
        );
        // Rows 5-6: fallback equivalence (copies_limit always x2 = a non-
        // last-mile round / BH_ENDGAME_LASTMILE=0) — the existing
        // decision table behavior unchanged.
        assert_eq!(
            endgame_cursor_pick(
                &pieces,
                avail_all.as_ref(),
                &claimed_all,
                &copies_two,
                true,
                true,
                &|_| ENDGAME_MAX_COPIES
            ),
            None,
            "row 5: fallback equivalence — x2 full -> None (the existing row 4's \
             shape, same verdict)"
        );
        let mut copies_one: std::collections::HashMap<u64, u64> = Default::default();
        copies_one.insert(0, 1);
        copies_one.insert(1, 1);
        copies_one.insert(2, 1);
        assert_eq!(
            endgame_cursor_pick(
                &pieces,
                avail_all.as_ref(),
                &claimed_all,
                &copies_one,
                true,
                true,
                &|_| ENDGAME_MAX_COPIES
            ),
            Some(0),
            "row 6: fallback equivalence — a piece with copies < x2 held by another, \
             one hop (the existing row 3's shape, same verdict)"
        );
    }

    /// Last-mile wide fan-out, the full dispatch chain (a wiring face).
    /// Three-peer shape: peer 1 (cuid 1, zero rate, the "zombie" —
    /// piece 0 blocks fresh InFlight in place), peer 2 (cuid 2, mid
    /// rate, advertises only piece 0), peer 3 (cuid 3, fastest,
    /// advertises pieces 0/1). 2 missing <= N(4) -> last-mile active:
    /// - peer 3 (first in rate order) takes the UNOWNED piece 1 (the
    /// first level's unowned-first is unchanged);
    /// - peer 2, with no unowned work left, has its busy gate lifted by
    /// last-mile (strict gate 1: in flight 1 < missing 2 would have
    /// blocked) -> a one-hop duplicate of piece 0 (InFlight ->
    /// InFlightDuplicate, ownership overwritten to cuid 2);
    /// - peer 1 (the original holder, overwritten -> "held by another"
    /// on the audit face) -> the wide fan-out SECOND hop: the fresh
    /// InFlightDuplicate (owner cuid 2 != 1) is dispatched again (the
    /// state stays InFlightDuplicate, the timestamp refreshes) — 3
    /// copies of the same block in flight (the seed hop + two fan-out
    /// hops = within the holder-count cap of 3), first-wins.
    /// The tail observation edges (last_mile_edge/last8_edge) register
    /// in the same round.
    /// Control arm: 6 missing > N -> the strict domain — a peer
    /// advertising only already-held pieces is blocked by strict gate 1
    /// (the busy-forbid zero-request verdict).
    #[tokio::test]
    async fn endgame_lastmile_wide_fanout_round() {
        let root = tokio_util::sync::CancellationToken::new();
        let mut face = adv_face(2);
        let mut remotes = Vec::new();
        for cuid in 1..=3u64 {
            let (handle, remote) = choke_peer_pair(&root).await;
            face.peers.push(handle);
            face.peer_cuids.push(cuid);
            remotes.push(remote);
        }
        // Advertisement shape: piece 1 is held only by peer 3 (rarest ->
        // the cursor table head); piece 0 is held by all three (holders
        // 3 = the fan-out cap).
        note_peer_bitfield(&mut face, 1, &[0b1000_0000]);
        note_peer_bitfield(&mut face, 2, &[0b1000_0000]);
        note_peer_bitfield(&mut face, 3, &[0b1100_0000]);
        // Zombie in place: piece 0's (0,0) fresh InFlight owned by cuid
        // 1 (peer 1's original request in flight — the claimed set
        // contains piece 0).
        seed_blocks_sent(&mut face, 0, Instant::now(), &[(0, BlockState::InFlight)]);
        dispatch_note(&mut face, 0, 0, 1);
        // Rate windows (30s readings, the choke sort key's source):
        // cuid 3 fastest -> the last-mile rate order [3, 2, 1]; ETA
        // 2x16KiB / 4MiB < 30s -> endgame triggers.
        for (cuid, bps) in [(1u64, 0u64), (2, 1024 * 1024), (3, 4 * 1024 * 1024)] {
            let mut w = RateWindow::new();
            w.advance();
            w.add(bps);
            face.peer_state_row(cuid).down_window = Some(w);
        }
        dispatch_face(&mut face, 0);
        // Peer 3 (fastest) takes the unowned piece 1 — the first level's
        // unowned-first is unchanged by the fan-out.
        assert_eq!(
            dispatch_owner(&face, 1, 0),
            Some(3),
            "the fastest holder takes the unowned piece in the first round (rate order + unowned first)"
        );
        // Fan-out first hop: peer 2 one-hop-duplicates piece 0 (the busy
        // gate lifted — strict gate 1: in flight 1 < missing 2 would
        // have blocked).
        assert_eq!(
            dispatch_owner(&face, 0, 0),
            Some(1),
            "the wide-fanout terminal state: after the fresh InFlightDup is \
             redispatched, ownership = the last-hop peer 1"
        );
        assert_eq!(
            face.blocks_sent[&0].block_state(0),
            BlockState::InFlightDup,
            "piece 0's (0,0) lands InFlightDup (the one-hop mark + wide fan-out \
             holds without downgrade)"
        );
        // All three requests in flight: the unowned piece 1 (peer 3) +
        // piece 0's two fan-out hops (peers 2/1) — 3 copies of the same
        // block, within the holder-count cap (first-wins).
        assert_eq!(
            face.dispatch_replies.len(),
            3,
            "one request per peer (1 unowned + 2 wide-fanout hops)"
        );
        // Tail observation edges (2 missing <= N=4 AND <= 8 -> both
        // edges register in the same round).
        assert!(face.last_mile_edge.is_some(), "the last-mile entry edge registered");
        assert!(face.last8_edge.is_some(), "the last-8-pieces window entry edge registered");
        assert!(
            face.last_mile_final.is_none() && face.last8_final.is_none(),
            "the completion terminal values not yet set (the face incomplete)"
        );
        // Control arm: 6 missing > N -> the strict domain (the busy
        // gate's original verdict).
        let mut face6 = adv_face(6);
        let (handle_a, _ra) = choke_peer_pair(&root).await;
        face6.peers.push(handle_a);
        face6.peer_cuids.push(10);
        let (handle_b, _rb) = choke_peer_pair(&root).await;
        face6.peers.push(handle_b);
        face6.peer_cuids.push(20);
        note_peer_bitfield(&mut face6, 10, &[0b1111_1100]);
        // Peer 20 advertises only piece 0 (already claimed in flight by
        // peer 10) — the only observable busy-block face under strict
        // gate 1.
        note_peer_bitfield(&mut face6, 20, &[0b1000_0000]);
        seed_blocks_sent(&mut face6, 0, Instant::now(), &[(0, BlockState::InFlight)]);
        dispatch_note(&mut face6, 0, 0, 10);
        for cuid in [10u64, 20] {
            let mut w = RateWindow::new();
            w.advance();
            w.add(1024 * 1024);
            face6.peer_state_row(cuid).down_window = Some(w);
        }
        dispatch_face(&mut face6, 0);
        assert_eq!(
            dispatch_owner(&face6, 0, 0),
            Some(10),
            "strict-domain control: busy picks forbidden (in flight 1 < missing 6, \
             gate 1) -> piece 0's ownership not overwritten"
        );
        assert_eq!(
            face6.dispatch_replies.len(),
            1,
            "strict-domain control: only peer 10's unowned-piece request (peer 20 zero requests)"
        );
        assert!(
            face6.last_mile_edge.is_none(),
            "6 missing > N=4 -> not last-mile (no tail-segment edge)"
        );
        root.cancel();
    }

    // ---- Endgame-tail supply face (1 window floor / 2 piece deadline /
    // 3 holder unchoke priority) ----

    /// Tail gate decision table ([`endgame_tail_active`]): the band is
    /// `(0, pct% of total]` (saturating `missing x 100 <= total x pct`);
    /// pct=0 = the whole face off; missing 0 (complete) = never active.
    /// The percent semantics keep tiny torrents out of the band by
    /// design (a 4-piece torrent's tail is the last-mile/last-8 faces,
    /// not the 5% band).
    #[test]
    fn endgame_tail_gate_decision_table() {
        // pct=0 = off (the explicit fallback arm) regardless of shape.
        assert!(!endgame_tail_active(0, 1, 3000));
        assert!(!endgame_tail_active(0, 150, 3000));
        // missing 0 = complete = never.
        assert!(!endgame_tail_active(5, 0, 3000));
        // 5% band: 150 of 3003 exactly at the boundary is active
        // (<=); 151 is not.
        assert!(endgame_tail_active(5, 150, 3000), "150/3000 = 5%, exactly in the band");
        assert!(!endgame_tail_active(5, 151, 3000), "151/3000 outside the band");
        // Rounding is truncating (percent of a small total): 1 of 100
        // (exactly 1%) in; 6 of 100 (6%) out; 5 of 100 (exactly 5%) in.
        assert!(endgame_tail_active(5, 1, 100));
        assert!(endgame_tail_active(5, 5, 100));
        assert!(!endgame_tail_active(5, 6, 100));
        // Tiny torrent: 2 of 4 (50%) far out of the band.
        assert!(!endgame_tail_active(5, 2, 4));
        // pct=100 = the whole download is the band.
        assert!(endgame_tail_active(100, 3000, 3000));
    }

    /// Holder predicate + window-floor value tables
    /// ([`peer_holds_missing_piece`] / [`endgame_tail_window_floor`]).
    #[test]
    fn endgame_tail_holder_and_window_floor_table() {
        let avail = PieceBitmap::new(8);
        avail.set(2);
        avail.set(5);
        // Holds: an advertised missing piece.
        assert!(peer_holds_missing_piece(&avail, &[3, 5, 7]));
        // No intersection with the missing list.
        assert!(!peer_holds_missing_piece(&avail, &[0, 1, 3]));
        // Empty missing list = false (nothing to hold).
        assert!(!peer_holds_missing_piece(&avail, &[]));
        // Floor value: k=0 = off (0); k x missing blocks, UB-clamped.
        assert_eq!(endgame_tail_window_floor(0, 2400), 0, "k=0 = the face off");
        assert_eq!(endgame_tail_window_floor(1, 1), 1);
        assert_eq!(endgame_tail_window_floor(1, 80), 80);
        assert_eq!(endgame_tail_window_floor(2, 80), 160, "k=2 doubles");
        assert_eq!(endgame_tail_window_floor(1, 2400), 256, "the UB 256 clamp");
        assert_eq!(
            endgame_tail_window_floor(8, u64::MAX),
            256,
            "saturating multiply never overflows, still clamped to 256"
        );
    }

    /// Per-piece deadline table ([`endgame_piece_overdue`]): zero
    /// deadline = never; the boundary (exactly `deadline` elapsed)
    /// counts as overdue (>= semantics, the slot-timeout precedent).
    #[test]
    fn endgame_piece_overdue_table() {
        let t0 = Instant::now();
        assert!(!endgame_piece_overdue(Duration::ZERO, t0, t0 + Duration::from_secs(600)));
        assert!(!endgame_piece_overdue(Duration::from_secs(30), t0, t0 + Duration::from_secs(29)));
        assert!(endgame_piece_overdue(Duration::from_secs(30), t0, t0 + Duration::from_secs(30)));
        assert!(endgame_piece_overdue(Duration::from_secs(30), t0, t0 + Duration::from_secs(31)));
        // A clock at/before the anchor (defensive) is not overdue.
        assert!(!endgame_piece_overdue(Duration::from_secs(30), t0, t0));
    }

    /// ② Overdue takeover round: a single missing piece whose only block
    /// is fresh-looking in flight (the shared timestamp was refreshed by
    /// a re-dispatch trickle — the mask this face exists to break), owned
    /// by another peer, its tail deadline expired. The dispatch round
    /// takes the block over: plain InFlight (no dup mark — the displaced
    /// owner is cancelled, the takeover semantics), the deadline re-armed
    /// from now. Control arm: the same shape with a live (un-expired)
    /// deadline keeps the pre-change verdict — a one-hop InFlightDup.
    #[tokio::test]
    async fn endgame_tail_overdue_takeover_round() {
        let root = tokio_util::sync::CancellationToken::new();
        // 200 pieces, only piece 199 missing (1 <= 5% of 200 = 10: the
        // tail band). Peer cuid 1 = the stalled original owner; peer
        // cuid 2 = the advertising holder that takes over.
        let mut face = adv_face(200);
        for i in 0..199u64 {
            face.progress.set_piece_done_global(i);
        }
        let (handle_a, _ra) = choke_peer_pair(&root).await;
        face.peers.push(handle_a);
        face.peer_cuids.push(1);
        let (handle_b, _rb) = choke_peer_pair(&root).await;
        face.peers.push(handle_b);
        face.peer_cuids.push(2);
        note_peer_have(&mut face, 1, 199);
        note_peer_have(&mut face, 2, 199);
        // Single-block piece; the fresh timestamp masks per-block
        // staleness (well inside the 2-5s reissue window).
        seed_blocks_sent(&mut face, 199, Instant::now(), &[(0, BlockState::InFlight)]);
        dispatch_note(&mut face, 199, 0, 1);
        // Rate windows: cuid 2 faster -> the last-mile rate order visits
        // cuid 2 first (the deterministic takeover taker).
        for (cuid, rate) in [(1u64, 1024u64), (2, 4 * 1024 * 1024)] {
            let mut w = RateWindow::new();
            w.advance();
            w.add(rate);
            face.peer_state_row(cuid).down_window = Some(w);
        }
        // Deadline expired 31s ago (the default window is 30s).
        face.endgame_deadline
            .insert(199, Instant::now() - Duration::from_secs(31));
        let before = Instant::now();
        dispatch_face(&mut face, 0);
        // Takeover: the coordinate re-dispatched to the round's peer —
        // plain InFlight (not a dup hop), ownership moved.
        assert_eq!(
            face.blocks_sent[&199].block_state(0),
            BlockState::InFlight,
            "overdue bypass = a takeover redispatch (not an InFlightDup mark)"
        );
        assert_eq!(dispatch_owner(&face, 199, 0), Some(2), "ownership moved to peer 2");
        assert!(
            face.endgame_deadline[&199] >= before,
            "the deadline re-armed from this round (the supply moved)"
        );
        assert!(
            !face.dispatch_replies.is_empty(),
            "the takeover redispatch produced a real request"
        );

        // Control arm: deadline live (seeded in the future by the round's
        // own anchor semantics — a busy piece observed this round) — the
        // fresh masked block keeps the old one-hop dup verdict.
        let mut face = adv_face(200);
        for i in 0..199u64 {
            face.progress.set_piece_done_global(i);
        }
        let (handle_a, _ra) = choke_peer_pair(&root).await;
        face.peers.push(handle_a);
        face.peer_cuids.push(1);
        let (handle_b, _rb) = choke_peer_pair(&root).await;
        face.peers.push(handle_b);
        face.peer_cuids.push(2);
        note_peer_have(&mut face, 1, 199);
        note_peer_have(&mut face, 2, 199);
        seed_blocks_sent(&mut face, 199, Instant::now(), &[(0, BlockState::InFlight)]);
        dispatch_note(&mut face, 199, 0, 1);
        // Rate windows: cuid 2 faster -> the last-mile rate order visits
        // cuid 2 first (the deterministic takeover taker).
        for (cuid, rate) in [(1u64, 1024u64), (2, 4 * 1024 * 1024)] {
            let mut w = RateWindow::new();
            w.advance();
            w.add(rate);
            face.peer_state_row(cuid).down_window = Some(w);
        }
        // A fresh anchor (the round's seed writes exactly this for a
        // first observation): 30s of budget still live — not overdue.
        face.endgame_deadline.insert(199, Instant::now());
        dispatch_face(&mut face, 0);
        assert_eq!(
            face.blocks_sent[&199].block_state(0),
            BlockState::InFlightDup,
            "the not-yet-overdue control = the old one-hop duplicate verdict bit-for-bit"
        );
        root.cancel();
    }

    /// 1. Holder window-floor write pass: in the tail band, peers
    /// advertising a missing piece get their RequestBook floor command
    /// raised to the tail's missing-block volume (k=1 default; the
    /// read-back seam is the commanded value — the book applies it
    /// lazily), non-holders (and every peer in a non-tail round) get 0.
    /// Also pins the 2. deadline seeding side effect (a busy missing
    /// piece observed in a tail round gains a deadline anchor).
    #[tokio::test]
    async fn endgame_tail_window_floor_write_round() {
        let root = tokio_util::sync::CancellationToken::new();
        // Tail band: 1 missing of 200.
        let mut face = adv_face(200);
        for i in 0..199u64 {
            face.progress.set_piece_done_global(i);
        }
        let (holder, _rh) = choke_peer_pair(&root).await;
        face.peers.push(holder);
        face.peer_cuids.push(1);
        let (other, _ro) = choke_peer_pair(&root).await;
        face.peers.push(other);
        face.peer_cuids.push(2);
        note_peer_have(&mut face, 1, 199); // holder: advertises the missing piece
        note_peer_have(&mut face, 2, 0); // non-holder: only a done piece
        seed_blocks_sent(&mut face, 199, Instant::now(), &[(0, BlockState::InFlight)]);
        dispatch_note(&mut face, 199, 0, 1);
        dispatch_face(&mut face, 0);
        // 1 missing block (16KiB piece) x k=1 -> floor command 1; the
        // non-holder gets 0.
        assert_eq!(
            face.peers[0].endgame_window_floor(),
            1,
            "the holder's floor command = k x the missing block count"
        );
        assert_eq!(face.peers[1].endgame_window_floor(), 0, "a non-holder gets 0");
        // The busy missing piece gained a deadline anchor (seeded at the
        // round's now; the expiry math is table-tested separately).
        assert!(
            face.endgame_deadline.contains_key(&199),
            "a busy missing piece gains a deadline anchor in a tail round"
        );

        // Non-tail control: 20 missing of 200 (10% > 5%) — every floor
        // command 0, no deadline table.
        let mut face20 = adv_face(200);
        for i in 0..180u64 {
            face20.progress.set_piece_done_global(i);
        }
        let (h1, _r1) = choke_peer_pair(&root).await;
        face20.peers.push(h1);
        face20.peer_cuids.push(1);
        note_peer_have(&mut face20, 1, 180);
        seed_blocks_sent(&mut face20, 180, Instant::now(), &[(0, BlockState::InFlight)]);
        dispatch_note(&mut face20, 180, 0, 1);
        dispatch_face(&mut face20, 0);
        assert_eq!(
            face20.peers[0].endgame_window_floor(),
            0,
            "a non-tail round's floor command 0 (the face off)"
        );
        assert!(
            face20.endgame_deadline.is_empty(),
            "a non-tail round has no deadline table"
        );
        root.cancel();
    }

    /// 3. Holder unchoke priority wiring: in the tail band the slowest
    /// interested peer — the sole holder of the last missing piece —
    /// enters the regular unchoke slots (the flag outranks the rate and
    /// keep-position keys); in a non-tail round the same shape loses to
    /// the faster peers (the pre-change verdict).
    #[tokio::test]
    async fn endgame_tail_holder_unchoke_priority_round() {
        use tokio::io::AsyncWriteExt as _;
        for (row, tail) in [("tail", true), ("non-tail", false)] {
            let root = CancellationToken::new();
            let mut face = adv_face(200);
            let done_until = if tail { 199u64 } else { 180u64 };
            for i in 0..done_until {
                face.progress.set_piece_done_global(i);
            }
            let mut remotes = Vec::new();
            for cuid in 1..=10u64 {
                let (handle, remote) = choke_peer_pair(&root).await;
                face.peers.push(handle);
                face.peer_cuids.push(cuid);
                remotes.push(remote);
            }
            // All 10 interested (raw frames; wait for the mirrors).
            for remote in remotes.iter_mut() {
                remote
                    .write_all(&[0, 0, 0, 1, 2])
                    .await
                    .unwrap_or_else(|e| panic!("{e}"));
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            while face.peers.iter().any(|p| !p.is_interested())
                && Instant::now() < deadline
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            // Rates cuid 1 fastest .. cuid 10 slowest (the choke sort
            // key); cuid 10 — the slowest — is the sole holder of the
            // (only / a) missing piece.
            for (cuid, rate) in (1u64..=10).map(|c| (c, (11 - c) * 1000)) {
                let mut w = RateWindow::new();
                for _ in 0..RateWindow::WINDOW_SECS {
                    w.advance();
                    w.add(rate);
                }
                face.peer_state_row(cuid).down_window = Some(w);
            }
            note_peer_have(&mut face, 10, done_until);
            let mut rng = XorShift(0x2545F4914F6CDD1Du64);
            leecher_choke_round(&mut face, &mut rng, None);
            let holder_in = face
                .peer_state
                .get(&10u64)
                .is_some_and(|ps| ps.am_unchoked);
            if tail {
                assert!(holder_in, "row {row}: the slowest holder of the last piece enters a regular slot");
            } else {
                assert!(!holder_in, "row {row}: the slowest peer in a non-tail round is out as usual");
            }
            root.cancel();
        }
    }

    // ---- Two-phase in-flight bookkeeping (network in flight x store pending) ----

    /// Arrival transition table ([`on_block_arrived`]; the "arrival"
    /// column of the 12-cell decision table): row 1 `InFlight` ->
    /// `Settling{dup:false}`; row 2 `InFlightDuplicate` ->
    /// `Settling{dup:true}` (the dup criterion survives the segment so
    /// settle-time sibling cancellation still fires); row 3 `Buffered`
    /// -> no-op (confirms the earlier-arriving out-of-order window);
    /// row 4 missing bookkeeping -> no-op (a degraded channel-full non-
    /// send / the piece already settled and cleared); row 5 duplicate
    /// arrival is idempotent (the first arrival time is kept — the
    /// guard age takes the conservative value). Degraded face: an
    /// absent arrival event is row 4's shape — InFlight stays = current
    /// behavior (the send point try_send drops when full; a transit-
    /// side switch gate).
    #[test]
    fn block_arrival_transition_table() {
        let now = Instant::now();
        // Row 1 + row 5 (duplicate arrival idempotent; Settling age reads
        // the piece-level shared timestamp — "arrival time booked / keep
        // the first arrival" converge into dispatched_at being untouched
        // by the arrival; row 1's timestamp assertion moved to the
        // structural test).
        let mut face = adv_face(2);
        seed_blocks_sent(
            &mut face,
            0,
            now - Duration::from_secs(1),
            &[(0, BlockState::InFlight)],
        );
        let pre_arrival_ts = face.blocks_sent[&0].dispatched_at();
        on_block_arrived(&mut face, 0, 0, now);
        assert_eq!(
            face.blocks_sent[&0].block_state(0),
            BlockState::Settling,
            "row 1: the first copy arrives -> Settling (dup:false expressed by the variant)"
        );
        assert_eq!(
            face.blocks_sent[&0].dispatched_at(),
            pre_arrival_ts,
            "rows 1+5: the arrival never touches the piece-level timestamp (the \
             guard-age anchor does not drift with late arrivals)"
        );
        on_block_arrived(&mut face, 0, 0, now + Duration::from_secs(5));
        assert_eq!(
            face.blocks_sent[&0].block_state(0),
            BlockState::Settling,
            "row 5: a duplicate arrival is idempotent (Settling kept)"
        );
        assert_eq!(
            face.blocks_sent[&0].dispatched_at(),
            pre_arrival_ts,
            "row 5: a duplicate arrival does not refresh the timestamp (idempotent)"
        );
        // Row 2: the dup mark survives the segment (piece 1 gets a four-
        // slot row — the inline shape sizes slots by the piece's real
        // block count, carrying what the old inner map could write at
        // arbitrary begins).
        face.blocks_sent.insert(
            1,
            ledger_seeded(
                4,
                now - Duration::from_secs(1),
                &[(0, BlockState::InFlightDup)],
            ),
        );
        on_block_arrived(&mut face, 1, 0, now);
        assert_eq!(
            face.blocks_sent[&1].block_state(0),
            BlockState::SettlingDup,
            "row 2: InFlightDup -> SettlingDup (the R8 criterion survives)"
        );
        // Row 3: Buffered (the confirmation arrived first) -> no-op.
        if let Some(ledger) = face.blocks_sent.get_mut(&1) {
            ledger.mark_buffered(16_384);
        }
        on_block_arrived(&mut face, 1, 16_384, now);
        assert_eq!(
            face.blocks_sent[&1].block_state(16_384),
            BlockState::Buffered,
            "row 3: Buffered kept (the total function: arrival/confirmation out-of-order is harmless)"
        );
        // Row 4: missing bookkeeping -> no-op (and nothing is created).
        on_block_arrived(&mut face, 1, 32_768, now);
        assert_eq!(
            face.blocks_sent[&1].block_state(32_768),
            BlockState::None,
            "row 4: missing bookkeeping creates no entry"
        );
    }

    /// Anchor for the 12-cell decision table (three segments x timeout
    /// / cancel / late delivery / evict-reject; the table is locked
    /// cell by cell — synchronous cells re-run here as regressions,
    /// async cells have their own locks):
    /// - Timeout column: the network segment =
    ///   `reissue_window_uses_adaptive_mirror_wiring` (an existing lock,
    ///   async); the store segment's counter-assertions =
    ///   `settling_coordinate_never_reissued` (zero candidates past the
    ///   guard age) + `settling_piece_not_dispatched_wiring` (the wiring
    ///   face) + `store_pending_guard_scan_table` (the guard action =
    ///   warn + count);
    /// - Cancel column: the cross-segment sibling cancel =
    ///   `block_settle_cancels_sibling_after_arrival` (async, wire
    ///   level); the piece lifecycle =
    ///   `piece_lifecycle_clears_two_phase_segments`; the transfer arm is
    ///   unchanged (the candidate filter's Settling-is-always-false arm
    ///   guarantees only network-segment coordinates are touched; see
    ///   the ownership-never-overwritten row in
    ///   `settling_coordinate_never_reissued`);
    /// - Late delivery column: `block_arrival_transition_table` rows 3/4
    ///   (out-of-order / degraded no-ops) + `settle_two_phase_segment_table`
    ///   (duplicate-coordinate drop counting = the pipeline's existing
    ///   two duplicate-drop faces, not part of this table);
    /// - Evict/reject column: `piece_lifecycle_clears_two_phase_segments` +
    ///   `drain_replies_two_phase_table` (reply draining is segment-
    ///   agnostic).
    #[test]
    fn two_phase_decision_table() {
        block_arrival_transition_table();
        settling_coordinate_never_reissued();
        store_pending_guard_scan_table();
        settle_two_phase_segment_table();
        drain_replies_two_phase_table();
        piece_lifecycle_clears_two_phase_segments();
    }

    /// Store-segment timeout counter-assertion (the 12-cell "timeout x
    /// Settling" cell): Settling coordinates past the guard age give the
    /// dispatch round ZERO candidates — no dispatch replies (no wire
    /// resend), no ownership rewrite (nothing to trigger a transfer
    /// cancel), and the entry stays Settling (the guard action = warn +
    /// count; takeover does not cancel).
    #[test]
    fn settling_coordinate_never_reissued() {
        let mut face = adv_face(2);
        let stale = Instant::now() - STORE_PENDING_GUARD - Duration::from_secs(10);
        seed_blocks_sent(&mut face, 0, stale, &[(0, BlockState::Settling)]);
        face.peer_cuids.push(7);
        dispatch_note(&mut face, 0, 0, 7);
        dispatch_face(&mut face, 0);
        assert!(
            face.dispatch_replies.is_empty(),
            "a Settling coordinate yields zero candidates: no wire resend (even past the guard age)"
        );
        assert_eq!(
            face.blocks_sent[&0].block_state(0),
            BlockState::Settling,
            "the store-segment entry is untouched by the dispatch round (the guard does not cancel)"
        );
        assert_eq!(
            dispatch_owner(&face, 0, 0),
            Some(7),
            "ownership not overwritten (no transfer cancel can trigger)"
        );
    }

    /// store_pending guard scan table ([`store_pending_guard_scan`]):
    /// fresh Settling is not over; past the guard age it counts (dup
    /// marks count too); network-segment/Buffered does not count; worst
    /// = the maximum age.
    #[test]
    fn store_pending_guard_scan_table() {
        let now = Instant::now();
        let mut face = adv_face(5);
        assert_eq!(
            store_pending_guard_scan(&face, now),
            (0, Duration::ZERO),
            "row 1: empty bookkeeping, zero violations"
        );
        seed_blocks_sent(
            &mut face,
            0,
            now - STORE_PENDING_GUARD - Duration::from_secs(5),
            &[(0, BlockState::Settling)],
        );
        seed_blocks_sent(
            &mut face,
            1,
            now - STORE_PENDING_GUARD - Duration::from_secs(15),
            &[(0, BlockState::SettlingDup)],
        );
        seed_blocks_sent(&mut face, 2, now, &[(0, BlockState::Settling)]);
        seed_blocks_sent(&mut face, 3, now, &[(0, BlockState::InFlight)]);
        seed_blocks_sent(&mut face, 4, now, &[(0, BlockState::Buffered)]);
        let (hits, worst) = store_pending_guard_scan(&face, now);
        assert_eq!(hits, 2, "row 2: only past-guard-age Settling counts (dup counted alike)");
        assert_eq!(
            worst,
            Duration::from_secs(45),
            "row 3: worst = the maximum age (15s + the 30s guard)"
        );
    }

    /// Claimed-set re-track table ([`rebuild_claimed`]): rows 1-2 fresh
    /// network-segment claims (on/off the same); row 3 Settling does not
    /// claim (an arrived piece's wire work is finished); row 4 expired
    /// network segments do not claim (stale slots presumed takeable,
    /// both readings); row 5 the adaptive-window re-track (unowned ->
    /// the window falls back to 2s, on and off bit-identical = the
    /// equivalence gate's lower bound; owned by a real task handle ->
    /// no samples gives the 60s adaptive -> window 5s; a 2.5s-old block
    /// is claimed with on and not with off = the metering re-track
    /// differential).
    #[tokio::test]
    async fn claimed_rebuild_two_phase_table() {
        let now = Instant::now();
        // Rows 1-4: the no-peer-stack shape (the reissue window's
        // unowned fallback of 2s; on/off share the window).
        let mut face = adv_face(4);
        seed_blocks_sent(
            &mut face,
            0,
            now - Duration::from_millis(500),
            &[(0, BlockState::InFlight)],
        );
        seed_blocks_sent(
            &mut face,
            1,
            now - Duration::from_millis(100),
            &[(0, BlockState::Settling)],
        );
        seed_blocks_sent(
            &mut face,
            2,
            now - DISPATCH_REISSUE_WINDOW - Duration::from_secs(1),
            &[(0, BlockState::InFlight)],
        );
        seed_blocks_sent(&mut face, 3, now, &[(0, BlockState::Buffered)]);
        let claimed_on = rebuild_claimed(&face, now, true);
        let claimed_off = rebuild_claimed(&face, now, false);
        assert!(claimed_on.contains(0), "row 1: a fresh network segment claims (on)");
        assert!(claimed_off.contains(0), "row 1: a fresh network segment claims (off alike)");
        assert!(
            !claimed_on.contains(1),
            "row 3: Settling does not claim (an arrived piece holds no spread slot)"
        );
        assert!(!claimed_off.contains(1), "row 3 control: off has no reachable Settling");
        assert!(!claimed_on.contains(2), "row 4: an expired network segment does not claim");
        assert!(!claimed_on.contains(3), "row 4': Buffered does not claim");
        assert_eq!(
            claimed_on.len(),
            claimed_off.len(),
            "row 5: unowned (the window falling back to 2s), on/off bit-identical \
             (the equivalence gate's lower bound)"
        );
        // Row 5': owned by a real task handle (no RTT sample -> adaptive
        // 60s -> window 5s).
        let root = tokio_util::sync::CancellationToken::new();
        let mut face = adv_face(2);
        let (handle, _remote) = choke_peer_pair(&root).await;
        face.peers.push(handle);
        face.peer_cuids.push(1);
        seed_blocks_sent(
            &mut face,
            0,
            now - Duration::from_millis(2500),
            &[(0, BlockState::InFlight)],
        );
        dispatch_note(&mut face, 0, 0, 1);
        let claimed_on = rebuild_claimed(&face, now, true);
        let claimed_off = rebuild_claimed(&face, now, false);
        assert!(
            claimed_on.contains(0) && !claimed_off.contains(0),
            "row 5': a 2.5s-old block claims at the 5s window (on) and not at the \
             2s window (off) — the metering re-track differential face"
        );
        root.cancel();
    }

    /// Busy in-flight count re-track table ([`endgame_peer_inflight`]):
    /// the network-segment reading — row 1 a fresh network segment
    /// counts exactly 1 (Settling/expired/unowned do not stack); row 2
    /// Settling{dup} does not count (arrived, holds no peer in-flight
    /// budget); row 3 expired does not count; row 4 unowned does not
    /// count (conservative); row 5 the window re-track differential (a
    /// 5s window with on counts / a 2s window with off does not).
    #[tokio::test]
    async fn endgame_peer_inflight_two_phase_table() {
        let now = Instant::now();
        let root = tokio_util::sync::CancellationToken::new();
        let mut face = adv_face(4);
        let (handle, _remote) = choke_peer_pair(&root).await;
        face.peers.push(handle);
        face.peer_cuids.push(1);
        // Row 1: a fresh network segment (owned).
        seed_blocks_sent(
            &mut face,
            0,
            now - Duration::from_millis(500),
            &[(0, BlockState::InFlight)],
        );
        dispatch_note(&mut face, 0, 0, 1);
        assert_eq!(
            endgame_peer_inflight(&face, now, true).get(&1),
            Some(&1),
            "row 1: a fresh network segment counts 1"
        );
        // Row 2: SettlingDup (owned).
        seed_blocks_sent(
            &mut face,
            1,
            now - Duration::from_millis(100),
            &[(0, BlockState::SettlingDup)],
        );
        dispatch_note(&mut face, 1, 0, 1);
        assert_eq!(
            endgame_peer_inflight(&face, now, true).get(&1),
            Some(&1),
            "row 2: Settling{{dup}} does not count (the total still 1 — an arrived \
             block holds no in-flight budget)"
        );
        // Row 3: an expired network segment (owned).
        seed_blocks_sent(
            &mut face,
            2,
            now - Duration::from_secs(6),
            &[(0, BlockState::InFlight)],
        );
        dispatch_note(&mut face, 2, 0, 1);
        assert_eq!(
            endgame_peer_inflight(&face, now, true).get(&1),
            Some(&1),
            "row 3: an expired network segment does not count (the total still 1)"
        );
        // Row 4: fresh and unowned.
        seed_blocks_sent(&mut face, 3, now, &[(0, BlockState::InFlight)]);
        assert_eq!(
            endgame_peer_inflight(&face, now, true).get(&1),
            Some(&1),
            "row 4: unowned does not count (conservative; the total still 1)"
        );
        assert!(
            endgame_peer_inflight(&adv_face(1), now, true).is_empty(),
            "row 4': empty bookkeeping counts zero"
        );
        // Row 5: the window re-track differential — a 2.5s-old block,
        // not counted with off (a 2s window) / counted with on (no
        // samples -> the 60s adaptive -> a 5s window).
        let mut face = adv_face(1);
        let (handle, _remote) = choke_peer_pair(&root).await;
        face.peers.push(handle);
        face.peer_cuids.push(1);
        seed_blocks_sent(
            &mut face,
            0,
            now - Duration::from_millis(2500),
            &[(0, BlockState::InFlight)],
        );
        dispatch_note(&mut face, 0, 0, 1);
        assert_eq!(
            endgame_peer_inflight(&face, now, false).get(&1),
            None,
            "row 5: 2.5s at the 2s window -> not counted (off)"
        );
        assert_eq!(
            endgame_peer_inflight(&face, now, true).get(&1),
            Some(&1),
            "row 5': 2.5s at the 5s window -> counted (on, the window re-track)"
        );
        root.cancel();
    }

    /// Busy piece count decision table ([`endgame_peer_busy_pieces`] —
    /// the tiered-gate input builder; same ownership/freshness reading
    /// as [`endgame_peer_inflight`], at piece granularity): row 1 two
    /// blocks of one piece count 1; row 2 across pieces accumulates 2
    /// (the number of distinct pieces where the peer holds fresh in-
    /// flight blocks); row 3 Settling/expired/unowned do not count (the
    /// same reading as the block count); row 4 redispatch takeover
    /// splits ownership — two owners of the same piece each count that
    /// piece (honest counting for single-coordinate single-owner
    /// bookkeeping); row 5 empty bookkeeping counts zero.
    #[test]
    fn endgame_peer_busy_pieces_granularity_table() {
        let now = Instant::now();
        let mut face = adv_face(4);
        // 2-blocks-per-piece geometry (multiple blocks per piece = the
        // premise of the granularity differential; the old inner map
        // could store 16KiB coordinates on a single-block piece; the
        // inline shape sizes slots by real block counts).
        let blk = u64::from(merkle::BLOCK_SIZE);
        face.piece_bytes = vec![2 * blk; 4].into();
        face.piece_goffs = Arc::new((0..4).map(|k| k * 2 * blk).collect());
        face.progress = ProgressModel::from_lengths(&[8 * blk], (2 * blk) as u32);
        // Ownership bookkeeping present (a pure counting face: the
        // peer_cuids mapping suffices; no connection handles needed).
        face.peer_cuids.push(1);
        face.peer_cuids.push(2);
        // Rows 1+2: piece 0 two blocks + piece 1 one block, all fresh
        // owned by peer 1 -> piece count 2 (block count 3 — the
        // granularity differential).
        seed_blocks_sent(
            &mut face,
            0,
            now - Duration::from_millis(500),
            &[
                (0, BlockState::InFlight),
                (merkle::BLOCK_SIZE, BlockState::InFlight),
            ],
        );
        dispatch_note(&mut face, 0, 0, 1);
        dispatch_note(&mut face, 0, merkle::BLOCK_SIZE, 1);
        seed_blocks_sent(
            &mut face,
            1,
            now - Duration::from_millis(400),
            &[(0, BlockState::InFlight)],
        );
        dispatch_note(&mut face, 1, 0, 1);
        assert_eq!(
            endgame_peer_busy_pieces(&face, now, false).get(&1),
            Some(&2),
            "rows 1+2: two blocks of one piece count 1, across pieces accumulates 2 \
             (the block-count face = 3)"
        );
        assert_eq!(
            endgame_peer_inflight(&face, now, false).get(&1),
            Some(&3),
            "the block-count differential: 3 blocks for the same input (the direct \
             read of the granularity difference)"
        );
        // Row 3: Settling + expired + unowned (piece 2) do not count.
        seed_blocks_sent(&mut face, 2, now, &[(0, BlockState::Settling)]);
        seed_blocks_sent(
            &mut face,
            3,
            now - Duration::from_secs(6),
            &[(0, BlockState::InFlight)],
        );
        dispatch_note(&mut face, 3, 0, 1);
        seed_blocks_sent(
            &mut face,
            2,
            now,
            &[(0, BlockState::Settling), (merkle::BLOCK_SIZE, BlockState::InFlight)],
        );
        // (Piece 2's second block is fresh but unowned — conservatively
        // not counted.)
        assert_eq!(
            endgame_peer_busy_pieces(&face, now, false).get(&1),
            Some(&2),
            "row 3: Settling/expired/unowned do not count (the same semantics as the block count)"
        );
        // Row 4: redispatch takeover splits ownership — piece 0 block 0
        // belongs to peer 1 and block 16KiB to peer 2 (a per-block
        // ownership split beyond the same-coordinate overwrite
        // semantics) -> both owners count the piece.
        dispatch_note(&mut face, 0, merkle::BLOCK_SIZE, 2);
        let m = endgame_peer_busy_pieces(&face, now, false);
        assert_eq!(m.get(&1), Some(&2), "row 4: peer 1 still counts pieces 0+1");
        assert_eq!(m.get(&2), Some(&1), "row 4': peer 2 counts piece 0 (each counts the piece)");
        // Row 5: empty bookkeeping counts zero.
        assert!(
            endgame_peer_busy_pieces(&adv_face(1), now, false).is_empty(),
            "row 5: empty bookkeeping counts zero"
        );
    }

    /// Settle convergence table ([`on_block_settled`], the three-
    /// segment total function; the 12-cell "settle" column):
    /// `Settling{dup:false}` -> Buffered with no cancel precondition;
    /// `Settling{dup:true}` -> Buffered keeping the sibling-cancel
    /// criterion (wire level in
    /// [`block_settle_cancels_sibling_after_arrival`]); `InFlight` ->
    /// Buffered directly (tolerating an absent arrival event = the
    /// current path, unchanged); `InFlightDuplicate` -> Buffered +
    /// cancel (the existing behavior); missing bookkeeping is a no-op.
    #[test]
    fn settle_two_phase_segment_table() {
        let now = Instant::now();
        let mut face = adv_face(4);
        // No peers: the cancel branch exits before locating a peer (the
        // state transitions are still assertable; the wire-level
        // sibling cancel is in block_settle_cancels_sibling_after_arrival).
        seed_blocks_sent(&mut face, 0, now, &[(0, BlockState::Settling)]);
        seed_blocks_sent(&mut face, 1, now, &[(0, BlockState::SettlingDup)]);
        seed_blocks_sent(&mut face, 2, now, &[(0, BlockState::InFlight)]);
        seed_blocks_sent(&mut face, 3, now, &[(0, BlockState::InFlightDup)]);
        for piece in 0..4u64 {
            super::run::arms::on_block_settled(&mut face, piece as u32, 0);
        }
        assert!(
            face.blocks_sent.values().all(|l| {
                l.slots()
                    .iter()
                    .all(|s| s.state == BlockState::Buffered)
            }),
            "all four segment states converge to Buffered (the total function)"
        );
        // Missing bookkeeping is a no-op (no panic, nothing created).
        super::run::arms::on_block_settled(&mut face, 9, 0);
        assert!(!face.blocks_sent.contains_key(&9), "an absent coordinate is a no-op");
    }

    /// Reply draining x two-phase states
    /// ([`drain_dispatch_replies_core`]; the 12-cell "reply" row):
    /// `WindowFull`/`Closed` act identically on `Settling` entries —
    /// clear + refetch (the total function, segment-agnostic; a peer
    /// task exiting = that peer never delivers, and with arrival events
    /// absent the surviving entries converge here).
    #[test]
    fn drain_replies_two_phase_table() {
        use taiji_bt::request_book::DispatchError;
        let piece_bytes = [2u64 * merkle::BLOCK_SIZE as u64];
        let mut blocks_sent: std::collections::HashMap<u64, PieceSentLedger> =
            std::collections::HashMap::new();
        let now = Instant::now();
        blocks_sent.insert(
            0,
            ledger_seeded(
                2,
                now,
                &[(0, BlockState::Settling), (16_384, BlockState::SettlingDup)],
            ),
        );
        let (tx_full, rx_full) = oneshot::channel();
        let _ = tx_full.send(Err(DispatchError::WindowFull {
            window: 6,
            outstanding: 6,
        }));
        let (tx_closed, rx_closed) =
            oneshot::channel::<Result<(), taiji_bt::request_book::DispatchError>>();
        drop(tx_closed);
        let mut replies: Vec<DispatchReply> = vec![(0, 0, rx_full), (0, 16_384, rx_closed)];
        let mut refetch: Vec<(u32, u32, u32)> = Vec::new();
        drain_dispatch_replies_core(&mut replies, &mut blocks_sent, &mut refetch, &piece_bytes);
        // An all-empty row is reclaimed after its slots clear (absence
        // equals the old all-slots-None verdict).
        let set = blocks_sent.get(&0);
        assert!(
            set.is_none_or(|s| {
                s.block_state(0) == BlockState::None
                    && s.block_state(16_384) == BlockState::None
            }),
            "after WindowFull/Closed clear the slots both coordinates are None (an \
             all-empty row reclaimed into the absent shape)"
        );
        assert_eq!(
            refetch,
            vec![(0, 0, 16_384), (0, 16_384, 16_384)],
            "both coordinates re-enter the refetch queue (segment-agnostic, the existing semantics)"
        );
    }

    /// Piece-lifecycle cleanup x two-phase states (the 12-cell "evict/
    /// reject" column; a state-independent regression lock on the
    /// existing arms): piece settle ([`on_piece_verified`]) clears a
    /// whole piece mixing all three segment states; the
    /// PieceDropped/PieceEvicted arms do the same `blocks_sent.remove`
    /// (the arm bodies read faces directly; this locks the settle
    /// representative row + the bookkeeping precondition of the
    /// single-block reject row).
    #[test]
    fn piece_lifecycle_clears_two_phase_segments() {
        let now = Instant::now();
        let mut faces = vec![adv_face(2)];
        seed_blocks_sent(
            &mut faces[0],
            1,
            now,
            &[
                (0, BlockState::InFlight),
                (16_384, BlockState::SettlingDup),
                (32_768, BlockState::Buffered),
            ],
        );
        on_piece_verified(&mut faces, 0, 1);
        assert!(
            !faces[0].blocks_sent.contains_key(&1),
            "R9: piece settle clears the whole piece (all three segment states alike)"
        );
    }

    /// Store-segment coordinates, end-to-end dispatch face (wiring; the
    /// 12-cell "timeout x Settling" cell's wiring face): a real
    /// unchoked peer + a single-piece face entirely Settling -> the
    /// dispatch round has zero candidates (no replies / no resend / no
    /// ownership rewrite). A single-piece face = the only piece cannot
    /// be bypassed — the clean shape for the zero-request assertion
    /// (with more pieces, normal dispatch of the others is existing
    /// semantics and not an assertion face).
    #[tokio::test]
    async fn settling_piece_not_dispatched_wiring() {
        let root = tokio_util::sync::CancellationToken::new();
        let mut face = adv_face(1);
        let (handle, _remote) = choke_peer_pair(&root).await;
        face.peers.push(handle);
        face.peer_cuids.push(1);
        note_peer_bitfield(&mut face, 1, &[0b1000_0000]);
        seed_blocks_sent(
            &mut face,
            0,
            Instant::now() - STORE_PENDING_GUARD - Duration::from_secs(10),
            &[(0, BlockState::Settling)],
        );
        dispatch_face(&mut face, 0);
        assert!(
            face.dispatch_replies.is_empty(),
            "an all-Settling face: the dispatch round sends zero requests (zero new \
             on the wire, even past the guard age)"
        );
        assert!(
            dispatch_is_empty(&face),
            "ownership not rewritten (no transfer cancel can trigger)"
        );
        root.cancel();
    }

    /// Endgame dispatch, the full chain (two-level restraint; extended
    /// from the fan-out equivalence test): round 1 not endgame —
    /// spread unchanged, two peers claim different pieces; round 2
    /// condition B triggers (ETA <
    /// [`crate::dispatch::ENDGAME_ETA_THRESHOLD_SECS`]) AND the strict
    /// gate is active (in flight 5 < missing 6,
    /// [`endgame_busy_admitted`] gate 1) — busy picks forbidden: peer 1
    /// takes an UNOWNED piece (supply spread, no re-picking an in-
    /// flight piece) and peer 2, out of unowned work and busy-forbidden,
    /// sends zero requests (the old behavior's "one-hop duplicate of an
    /// in-flight piece" generation is stopped by the two-level gate);
    /// round 3 peer 1's original claim settles -> strict releases (in
    /// flight 5 >= missing 5) + peer 3 arrives EMPTY-HANDED -> the busy
    /// gate admits (libtorrent "only enter when you cannot fill + an
    /// empty queue", request_blocks.cpp) -> a one-hop duplicate lands as
    /// [`BlockSentState::InFlightDuplicate`]; round 4 peer 3's busy
    /// count = 1 -> its second busy piece is blocked (the per-peer busy
    /// allocation cap, gate 2), and peer 2's original request ownership
    /// was overwritten by peer 3 at the same coordinate (existing
    /// single-owner bookkeeping) -> on the audit face peer 2 is empty-
    /// handed and issues its FIRST busy allocation — the per-piece x2
    /// cap is independent of ownership, so the filled piece is not re-
    /// picked; round 5 reachable pieces at capacity / busy counts full
    /// -> the busy gate has no path -> zero requests (the final
    /// boundary). Duplicate block arrivals are backstopped by the
    /// verified-coverage check on the store side (benign duplicate-
    /// drop counting; see the dispatch notes).
    /// Scenario lift note: this chain's original 3-piece shape (during
    /// the strict-release segment, 2-3 missing <= the
    /// [`BH_ENDGAME_LASTMILE`] default 4 — the last-mile wide-fanout
    /// domain) made the strict busy gate's timing lock unreachable
    /// under the default N. The scenario is now 6 pieces + 3 seed
    /// claims (pieces 0/1/2 fresh InFlight, synthetic owners cuid
    /// 8/9/10 — no peer consumes them; [`rebuild_claimed`] only reads
    /// coordinate states) so every round has missing in {6,5} > N — the
    /// strict semantics stays locked bit-for-bit under the default N;
    /// the last-mile domain is locked separately by
    /// `endgame_lastmile_wide_fanout_round`.
    #[tokio::test]
    async fn endgame_busy_gate_strict_then_release_chain() {
        let root = tokio_util::sync::CancellationToken::new();
        let mut face = adv_face(6);
        // Chain-break note: with the default floor of 4 cross-piece
        // append is always on — a 1-byte goff gap is placed between
        // pieces 3/4 (the file-boundary padding shape;
        // `next_adjacent_supply_piece` breaks there; pieces 4->5 stay
        // adjacent), preserving this chain's "one piece per peer"
        // premise for the strict busy gate timing (in round 1 peer 2's
        // 3->4 adjacent append would otherwise consume round 2's unowned
        // piece 4 and shift condition A's in-flight base); cross-piece
        // append behavior is pinned by the multi_piece tests.
        let blk = u64::from(merkle::BLOCK_SIZE);
        face.piece_goffs = Arc::new((0..6u64).map(|k| k * blk + u64::from(k == 4)).collect());
        let mut remotes = Vec::new();
        // Advertisement shape (deterministic rarity): peer 1 = {4,5},
        // peer 2 = {3,4} — pieces 5/3 are each's unique rarest (round 1
        // spreads deterministically), piece 4 is doubly advertised
        // (round 2's unowned remainder); pieces 0/1/2 have no advertising
        // peer (seed-claim-only slots, unselectable by cursor/spread
        // rounds — they only raise the missing count and the claim base,
        // never dispatched).
        for (cuid, bits) in [(1u64, 0b0000_1100u8), (2, 0b0001_1000)] {
            let (handle, remote) = choke_peer_pair(&root).await;
            face.peers.push(handle);
            face.peer_cuids.push(cuid);
            note_peer_bitfield(&mut face, cuid, &[bits]);
            remotes.push(remote);
        }
        // Seed claims (pieces 0/1/2 fresh InFlight, synthetic owners
        // 8/9/10): this builds round 2's strict gate 1 input (in flight
        // 5 < missing 6) and round 3's release input (in flight 5 >=
        // missing 5) — the block coordinates have no connected peer, the
        // reissue window falls back to the default 2s, and the busy count
        // face (aggregated by cuid) is unconsumed; purely bookkeeping
        // seeds.
        let seeded = Instant::now();
        // Synthetic owners 8/9/10: an owner is a peer_cuids index (the
        // inline shape) => the three bookkeeping slots must sit parallel
        // in peers — real choked handles are mounted as placeholders
        // (choking us -> the reciprocity gate skips them + no advertised
        // bitmap -> selection None, zero requests, zero disturbance;
        // under the old direct-cuid shape these three cuids had no
        // consuming peer, the same "unowned idle ownership" semantics).
        // The placeholders join before the seed claims (indexes 2/3/4).
        for owner_cuid in [8u64, 9, 10] {
            let (h, _r) = choked_peer_pair(&root).await;
            face.peers.push(h);
            face.peer_cuids.push(owner_cuid);
        }
        for (piece, owner) in [(0u64, 8u64), (1, 9), (2, 10)] {
            seed_blocks_sent(&mut face, piece, seeded, &[(0, BlockState::InFlight)]);
            dispatch_note(&mut face, piece, 0, owner);
        }
        // Round 1 (not endgame): spread — each claims a different piece
        // (semantics unchanged). Peer 1 takes its advertised set's
        // unique rarest piece 5 (count 1 < piece 4's 2), peer 2 takes
        // piece 3 (count 1 < piece 4's 2) — deterministic. The
        // bookkeeping-face assertion (the dispatch count;
        // dispatch_replies drain after peers reply Ok in a later round —
        // cross-round counts are not deterministic, so they are not an
        // assertion face).
        dispatch_face(&mut face, 0);
        assert_eq!(
            dispatch_count(&face),
            5,
            "round 1: the two peers each claim one piece (3 seeds + 2 new claims)"
        );
        assert_eq!(
            dispatch_owner(&face, 5, 0),
            Some(1),
            "round 1: peer 1 claims piece 5 (spread: different pieces)"
        );
        assert_eq!(
            dispatch_owner(&face, 3, 0),
            Some(2),
            "round 1: peer 2 claims piece 3 (spread: different pieces)"
        );
        // Rate windows fed 1s x 1MiB (both peers): remaining bytes
        // 6x16KiB / 2MiB = about 0.047s < 30s -> condition B triggers
        // endgame (condition A: in flight 5 < missing 6, unmet).
        for cuid in [1u64, 2u64] {
            let mut w = RateWindow::new();
            w.advance();
            w.add(1024 * 1024);
            face.peer_state_row(cuid).down_window = Some(w);
        }
        // Round 2 (endgame AND the strict gate active: in flight 5 <
        // missing 6 -> busy picks forbidden; 6 missing > N=4 -> not
        // last-mile, the strict verdict bit-for-bit).
        dispatch_face(&mut face, 0);
        assert_eq!(
            dispatch_count(&face),
            6,
            "round 2: only peer 1 takes the unowned piece 4 (supply spread); peer 2 \
             is out of unowned work + busy-forbidden -> zero requests"
        );
        assert_eq!(
            dispatch_owner(&face, 4, 0),
            Some(1),
            "round 2: peer 1 took an unowned piece (no re-picking an in-flight piece; \
             under the strict gate only unowned blocks are sent)"
        );
        assert_eq!(
            inflight_dup_count(&face),
            0,
            "round 2: the strict gate active -> busy picks forbidden -> zero duplicate \
             copies generated (this fix's governance face)"
        );
        assert!(
            face.endgame_live.load(std::sync::atomic::Ordering::Relaxed),
            "round 2: the endgame live flag set (the entry edge)"
        );
        // Round 3: peer 1's original claim piece 5 settles -> missing
        // {0..4} (5 pieces) all in flight (3 seeds + pieces 3/4 claims)
        // -> strict releases; peer 3 (empty-handed, advertising only
        // piece 3 — peer 2's claimed piece, the busy-skip ownership-
        // overwrite face) joins -> the busy gate admits.
        face.progress.set_piece_done_global(5);
        face.blocks_sent.remove(&5);
        let (handle3, _remote3) = choke_peer_pair(&root).await;
        face.peers.push(handle3);
        face.peer_cuids.push(3);
        note_peer_bitfield(&mut face, 3, &[0b0001_0000]);
        dispatch_face(&mut face, 0);
        // Coordinate bookkeeping does not grow: the busy skip shares the
        // original holder's coordinate (a same-key overwrite); the
        // settled piece's residual key ((5,0)) is an existing face and
        // not counted.
        assert_eq!(
            dispatch_count(&face),
            5,
            "round 3: strict released + peer 3 empty-handed -> the busy gate admits \
             exactly one hop (the in-flight peers still zero requests, zero new \
             coordinates; piece 5's row removal takes its ownership with it — the \
             old block_dispatch residual key no longer counts; live coordinates = \
             3 seeds + pieces 3/4)"
        );
        let (dup_piece, dup_begin) = any_inflight_dup(&face)
            .unwrap_or_else(|| panic!("round 3: the busy gate admitting must produce an InFlightDup"));
        assert_eq!(
            (dup_piece, dup_begin),
            (3, 0),
            "round 3: peer 3's only advertised and other-held piece = piece 3 (copies 1 < x2)"
        );
        assert_eq!(
            dispatch_owner(&face, dup_piece, dup_begin),
            Some(3),
            "round 3: the duplicate request comes from the empty-handed peer 3 (a busy \
             allocation is empty-hand-exclusive); piece 3's ownership overwritten"
        );
        assert_ne!(
            dup_piece, 5,
            "round 3: the duplicate coordinate must be in the missing set (a settled \
             piece never returns)"
        );
        // Round 4 (the conjunction boundary of the busy allocation cap +
        // the x2 cap): peer 3's busy count = 1 -> gate 2 blocks its
        // second busy piece; peer 2's original request ownership (piece
        // 3) was overwritten by peer 3's busy skip (same-coordinate
        // single-owner bookkeeping, existing) -> on the audit face peer 2
        // is empty-handed and issues its FIRST busy allocation against
        // piece 4 (the second hop). The per-piece x2 cap is unaffected by
        // ownership: piece 3 is full (copies = 2) and not re-picked;
        // peer 1 holds piece 4 fresh in flight (blocked by gate 2) and
        // does not participate.
        dispatch_face(&mut face, 0);
        let dup_count: usize = inflight_dup_count(&face);
        assert_eq!(
            dup_count, 2,
            "round 4: at most one duplicate hop per missing piece (the x2 cap) — \
             piece 3 full no longer hops, piece 4 exactly one hop"
        );
        assert_eq!(
            dispatch_owner(&face, dup_piece, dup_begin),
            Some(3),
            "round 4: peer 3's busy allocation is not double-consumed by itself (a busy \
             count < 1 -> its second busy piece blocked)"
        );
        assert_eq!(
            dispatch_owner(&face, 4, 0),
            Some(2),
            "round 4: peer 2 (its ownership overwritten -> empty-handed on the audit \
             face) issues its first busy allocation against piece 4"
        );
        // Round 5 (reachable pieces at capacity / busy counts full):
        // pieces 3/4 at x2 capacity, seed pieces 0/1/2 have no
        // advertising peer, all three peers' busy counts = 1 -> the busy
        // gate has no path -> no third hop (the redundancy discipline's
        // final boundary).
        dispatch_face(&mut face, 0);
        let dup_count_after: usize = inflight_dup_count(&face);
        assert_eq!(
            dup_count_after, 2,
            "round 5: reachable pieces x2-full / busy counts full -> the busy re-pick \
             has no path -> zero new requests (the cap boundary unchanged)"
        );
        assert_eq!(
            dispatch_count(&face),
            5,
            "round 5: the dispatch bookkeeping coordinates did not grow (live \
             coordinates 5: 3 seeds + pieces 3/4, including 2 ownership overwrites; \
             settled pieces' rows died with the removal — old residual keys not counted)"
        );
        // Edge observation face (zero behavior observed): from round 2
        // the endgame is live -> the live flag sets; the edge time is
        // registered (the in-flight segment of the duration-slice
        // checkpoint).
        assert!(face.endgame_edge.is_some(), "the entry edge registers the in-flight segment's instant");
        // Exit edge: the BEP53 mask all-off = every piece merged into
        // done (missing = 0 -> the endgame verdict is always false) ->
        // the flag clears and the in-flight segment slices into
        // endgame_cum.
        let all_off = vec![false; 6];
        dispatch_face_selected(&mut face, 0, Some(&all_off), &RarestFirstStrategy);
        assert!(
            !face.endgame_live.load(std::sync::atomic::Ordering::Relaxed),
            "the exit edge: the missing set emptying leaves endgame and the flag clears"
        );
        assert!(face.endgame_edge.is_none(), "the exit edge: the in-flight segment closed and sliced in");
        root.cancel();
    }

    /// Redundancy-economy fix: the moment an x2 duplicate coordinate
    /// lands (BlockSettled -> Buffered) the sibling in-flight request is
    /// cancelled in place — wire-level assertion that the second-hop
    /// peer receives a Cancel frame + the bookkeeping flips to Buffered.
    /// References: libtorrent torrent.cpp (cancel the siblings when the
    /// first copy lands); aria2 BtPieceMessage.cc (the receive-side
    /// backstop). Anchors and semantic boundaries in
    /// [`crate::run::arms::on_block_settled`].
    /// The duplicate coordinate is generated through the busy gate path
    /// (after peer 1's claimed piece settles and clears it is empty-
    /// handed AND strict is inactive -> the busy gate admits,
    /// [`endgame_busy_admitted`]).
    #[tokio::test]
    async fn block_settle_cancels_sibling_duplicate_request() {
        let root = tokio_util::sync::CancellationToken::new();
        let mut face = adv_face(2);
        let (handle1, mut remote1) = choke_peer_pair(&root).await;
        face.peers.push(handle1);
        face.peer_cuids.push(1);
        let (handle2, mut remote2) = choke_peer_pair(&root).await;
        face.peers.push(handle2);
        face.peer_cuids.push(2);
        note_peer_bitfield(&mut face, 1, &[0b1100_0000]);
        note_peer_bitfield(&mut face, 2, &[0b1100_0000]);
        // Round 1 (spread claims): the two peers claim different pieces.
        dispatch_face(&mut face, 0);
        let first = dispatch_entries(&face)
            .into_iter()
            .find_map(|(p, _, c)| (c == 1).then_some(p))
            .unwrap_or_else(|| panic!("round 1: peer 1 must have a claim"));
        // Peer 1's claimed piece settles and clears: peer 1 is empty-
        // handed; missing = peer 2's in-flight piece (missing 1 = in
        // flight 1 -> condition A endgame, the strict gate inactive).
        face.progress.set_piece_done_global(first);
        face.blocks_sent.remove(&first);
        // Round 2 (the busy gate admits): peer 1 empty-handed -> busy-
        // picks peer 2's in-flight piece -> a block-level one-hop
        // duplicate (InFlightDup).
        dispatch_face(&mut face, 0);
        // Locate the duplicate coordinate (state = InFlightDup) and its
        // dispatch target (the inline ownership = the second-hop
        // sibling).
        let (dup_piece, dup_begin) = any_inflight_dup(&face)
            .unwrap_or_else(|| panic!("round 2 must have an InFlightDup coordinate"));
        assert_ne!(dup_piece, first, "the duplicate coordinate is in the missing set (a settled piece never returns)");
        let sibling = dispatch_owner(&face, dup_piece, dup_begin)
            .unwrap_or_else(|| panic!("the duplicate coordinate must have dispatch-target bookkeeping"));
        // Landing: the Buffered flip + the sibling cancel.
        super::run::arms::on_block_settled(&mut face, dup_piece as u32, dup_begin);
        assert_eq!(
            face.blocks_sent
                .get(&dup_piece)
                .map(|l| l.block_state(dup_begin)),
            Some(BlockState::Buffered),
            "the landing coordinate flips to Buffered"
        );
        // Wire face: the sibling peer receives Cancel (id 8) — read past
        // the preceding Request frames until the Cancel (a 16-frame bound
        // covers both rounds' request frames).
        let mut saw_cancel = false;
        let remote = match sibling {
            1 => &mut remote1,
            2 => &mut remote2,
            other => unreachable!("adv_face's two-peer busy hop = peers 1/2, got {other}"),
        };
        for _ in 0..16 {
            match tokio::time::timeout(
                Duration::from_millis(400),
                read_wire_msg_id(remote),
            )
            .await
            {
                Ok(Some(8)) => {
                    saw_cancel = true;
                    break;
                }
                Ok(Some(_)) => continue,
                _ => break,
            }
        }
        assert!(
            saw_cancel,
            "the sibling's in-flight request must receive a wire Cancel frame (the \
             landing cancels the sibling)"
        );
        root.cancel();
    }

    /// Settle-time sibling cancel through the arrival->settle sequence
    /// (the 12-cell "cancel x Settling" cell, wire level): the dup
    /// coordinate walks the full arrival->settle sequence
    /// (`on_block_arrived` first converts to `Settling{dup:true}`, then
    /// `on_block_settled` settles) — the sibling cancel still fires (the
    /// dup criterion survives the segment, the semantics move up byte
    /// for byte). The chain reuses
    /// `block_settle_cancels_sibling_duplicate_request` (the busy gate
    /// generates the InFlightDuplicate -> arrival re-segments -> settle
    /// cancels the sibling).
    #[tokio::test]
    async fn block_settle_cancels_sibling_after_arrival() {
        let root = tokio_util::sync::CancellationToken::new();
        let mut face = adv_face(2);
        let (handle1, mut remote1) = choke_peer_pair(&root).await;
        face.peers.push(handle1);
        face.peer_cuids.push(1);
        let (handle2, mut remote2) = choke_peer_pair(&root).await;
        face.peers.push(handle2);
        face.peer_cuids.push(2);
        note_peer_bitfield(&mut face, 1, &[0b1100_0000]);
        note_peer_bitfield(&mut face, 2, &[0b1100_0000]);
        dispatch_face(&mut face, 0);
        let first = dispatch_entries(&face)
            .into_iter()
            .find_map(|(p, _, c)| (c == 1).then_some(p))
            .unwrap_or_else(|| panic!("round 1: peer 1 must have a claim"));
        face.progress.set_piece_done_global(first);
        face.blocks_sent.remove(&first);
        dispatch_face(&mut face, 0);
        let (dup_piece, dup_begin) = any_inflight_dup(&face)
            .unwrap_or_else(|| panic!("round 2 must have an InFlightDup coordinate"));
        let sibling = dispatch_owner(&face, dup_piece, dup_begin)
            .unwrap_or_else(|| panic!("the duplicate coordinate must have dispatch-target bookkeeping"));
        // Arrival re-segments: InFlightDup -> SettlingDup (the dup
        // criterion survives the segment). The late wire frame's Cancel
        // attributes to the second hop itself (inline single-owner
        // ownership, existing) — the sibling = the same coordinate's
        // first-hop requester, here the other of peers 1/2, decided by
        // the wire read side.
        on_block_arrived(&mut face, dup_piece as u32, dup_begin, Instant::now());
        assert_eq!(
            face.blocks_sent
                .get(&dup_piece)
                .map(|l| l.block_state(dup_begin)),
            Some(BlockState::SettlingDup),
            "the arrival transition: the dup coordinate lands SettlingDup"
        );
        // Settle (the store-segment confirmation): SettlingDup ->
        // Buffered + the sibling cancel.
        super::run::arms::on_block_settled(&mut face, dup_piece as u32, dup_begin);
        assert_eq!(
            face.blocks_sent
                .get(&dup_piece)
                .map(|l| l.block_state(dup_begin)),
            Some(BlockState::Buffered),
            "the settled coordinate flips to Buffered (the cross-segment total function)"
        );
        let mut saw_cancel = false;
        let remote = match sibling {
            1 => &mut remote1,
            2 => &mut remote2,
            other => unreachable!("adv_face's two-peer busy hop = peers 1/2, got {other}"),
        };
        for _ in 0..16 {
            match tokio::time::timeout(
                Duration::from_millis(400),
                read_wire_msg_id(remote),
            )
            .await
            {
                Ok(Some(8)) => {
                    saw_cancel = true;
                    break;
                }
                Ok(Some(_)) => continue,
                _ => break,
            }
        }
        assert!(
            saw_cancel,
            "in the arrival->settle sequence the sibling must still receive a wire \
             Cancel frame (the R8 semantics survives across segments)"
        );
        root.cancel();
    }

    /// Supply byte metering (observability infrastructure, zero behavior
    /// change): `drain_peer_counters` splits the download delta by the
    /// connection transport recorded at registration — the two
    /// transports always sum to the total download reading (the
    /// cross-check anchor between /metrics
    /// `taiji_peer_supply_bytes_total{transport}` and
    /// `taiji_torrent_bytes_total{direction="down"}`); per-transport
    /// baselines advance per transport (the dependency of the leave
    /// arm subtracting the matching baseline); no delta reports an
    /// honest zero.
    #[test]
    fn drain_peer_counters_splits_supply_by_transport() {
        use taiji_bt::utp::Transport;
        let mut face = adv_face(4);
        let tcp_down = Arc::new(std::sync::atomic::AtomicU64::new(100));
        let utp_down = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mk_meta = |transport, down: Arc<
            std::sync::atomic::AtomicU64,
        >| PeerMeta {
            ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port: 51417,
            inbound: true,
            peer_id: [0u8; 20],
            crypto: taiji_bt::mse::CryptoLevel::Plain,
            transport,
            up: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            down,
            upload_only: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        face.peer_state_row(1).meta = Some(mk_meta(Transport::Tcp, Arc::clone(&tcp_down)));
        face.peer_state_row(2).meta = Some(mk_meta(Transport::Utp, Arc::clone(&utp_down)));
        for cuid in [1u64, 2u64] {
            face.peer_state_row(cuid).rates = Some(PeerRate {
                    up: taiji_domain::seed::SessionSpeedCalc::default(),
                    down: taiji_domain::seed::SessionSpeedCalc::default(),
                    last_up: 0,
                    last_down: 0,
                },
            );
        }
        let mut last_up = 0u64;
        let mut last_down = 0u64;
        let mut last_tcp = 0u64;
        let mut last_utp = 0u64;
        let session_up = std::sync::atomic::AtomicU64::new(0);
        let session_down = std::sync::atomic::AtomicU64::new(0);
        use crate::query::CounterDrain;
        fn drain(
            face: &mut FaceState,
            last_up: &mut u64,
            last_down: &mut u64,
            last_tcp: &mut u64,
            last_utp: &mut u64,
            session_up: &std::sync::atomic::AtomicU64,
            session_down: &std::sync::atomic::AtomicU64,
        ) -> CounterDrain {
            let mut speed_up = taiji_domain::seed::SessionSpeedCalc::default();
            let mut speed_down = taiji_domain::seed::SessionSpeedCalc::default();
            drain_peer_counters(
                std::slice::from_mut(face),
                last_up,
                last_down,
                last_tcp,
                last_utp,
                session_up,
                session_down,
                &mut speed_up,
                &mut speed_down,
            )
        }
        // Round 1: TCP 100 / uTP 0 — a fresh connection books in full;
        // the transport split is exact.
        let d = drain(
            &mut face,
            &mut last_up,
            &mut last_down,
            &mut last_tcp,
            &mut last_utp,
            &session_up,
            &session_down,
        );
        assert_eq!(d.down, 100, "the total-download semantics (the same source as bytes_down_total)");
        assert_eq!(d.down_tcp, 100);
        assert_eq!(d.down_utp, 0);
        // Round 2: TCP +50 / uTP +20 — each transport takes its own
        // delta, and they sum to the total delta.
        tcp_down.fetch_add(50, std::sync::atomic::Ordering::Relaxed);
        utp_down.fetch_add(20, std::sync::atomic::Ordering::Relaxed);
        let d = drain(
            &mut face,
            &mut last_up,
            &mut last_down,
            &mut last_tcp,
            &mut last_utp,
            &session_up,
            &session_down,
        );
        assert_eq!(d.down, 70);
        assert_eq!(d.down_tcp, 50);
        assert_eq!(d.down_utp, 20);
        assert_eq!(d.down_tcp + d.down_utp, d.down, "the two families sum to the total semantics");
        // Transport baselines = the sum of same-transport counters at
        // the last bridge (the dependency of the leave arm subtracting
        // the per-transport baseline).
        assert_eq!(last_tcp, 150);
        assert_eq!(last_utp, 20);
        // Round 3 (control): no delta -> both transports stay zero (no
        // inflated reporting).
        let d = drain(
            &mut face,
            &mut last_up,
            &mut last_down,
            &mut last_tcp,
            &mut last_utp,
            &session_up,
            &session_down,
        );
        assert_eq!(d.down, 0);
        assert_eq!(d.down_tcp, 0);
        assert_eq!(d.down_utp, 0);
    }

    /// uTP zero-throughput governance wiring face ([`utp_mute_face`]
    /// direct drive): three bookkeeping states (the first observation
    /// records / holds within the window / past the window disconnects
    /// and clears) + TCP neighbors untouched + missing bookkeeping =
    /// the zero-rate path + a download-output exemption clears the
    /// record + the disconnect decision lands as (peers position, cuid)
    /// (the caller performs the shutdown; turnover follows the same
    /// shape).
    #[test]
    fn utp_mute_face_books_and_fires() {
        use taiji_bt::utp::Transport;
        let mut face = adv_face(4);
        let mk_meta = |transport| PeerMeta {
            ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port: 51417,
            inbound: true,
            peer_id: [0u8; 20],
            crypto: taiji_bt::mse::CryptoLevel::Plain,
            transport,
            up: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            down: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            upload_only: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        // cuid 1 = uTP (position 0), cuid 2 = the TCP control (position
        // 1); no down_windows/peer_rates entry = the missing-bookkeeping
        // zero-rate path.
        face.peer_cuids = vec![1, 2];
        face.peer_state_row(1).meta = Some(mk_meta(Transport::Utp));
        face.peer_state_row(2).meta = Some(mk_meta(Transport::Tcp));
        let t0 = Instant::now();
        // Round 1: the uTP first observation records, TCP never records,
        // zero disconnects.
        assert!(utp_mute_face(&mut face, t0).is_empty());
        assert_eq!(
            face.peer_state.get(&1).and_then(|ps| ps.utp_mute_since),
            Some(t0),
            "the µTP peer recorded"
        );
        assert!(
            face.peer_state.get(&2).is_none_or(|ps| ps.utp_mute_since.is_none()),
            "TCP never recorded"
        );
        // Round 2 (within the 60s window): the original anchor holds,
        // zero disconnects.
        assert!(utp_mute_face(&mut face, t0 + Duration::from_secs(60)).is_empty());
        assert_eq!(
            face.peer_state.get(&1).and_then(|ps| ps.utp_mute_since),
            Some(t0),
            "the in-window anchor does not drift"
        );
        // Round 3: the download-output exemption — one positive bucket
        // enters the 30s window (rate > 0 after advance) -> the record
        // clears, zero disconnects.
        let mut win = RateWindow::new();
        win.advance();
        win.add(16_384);
        face.peer_state_row(1).down_window = Some(win);
        assert!(utp_mute_face(&mut face, t0 + Duration::from_secs(61)).is_empty());
        assert!(
            face.peer_state.get(&1).is_none_or(|ps| ps.utp_mute_since.is_none()),
            "the output exemption clears the record"
        );
        // Round 4: the record re-enters (output stopped — with the
        // window entry removed the missing-bookkeeping zero-rate path
        // applies) -> the past-window disconnect decision lands at
        // (peers position 0, cuid 1); the TCP neighbor is never in the
        // decision.
        if let Some(ps) = face.peer_state.get_mut(&1) {
                ps.down_window = None;
            }
        assert!(utp_mute_face(&mut face, t0 + Duration::from_secs(62)).is_empty());
        let fired = utp_mute_face(
            &mut face,
            t0 + Duration::from_secs(62) + UTP_MUTE_AFTER,
        );
        assert_eq!(fired, vec![(0, 1)], "the µTP past-window disconnect: position 0 + cuid 1");
        assert!(
            face.peer_state.get(&1).is_none_or(|ps| ps.utp_mute_since.is_none()),
            "the disconnect clears the record"
        );
    }

    /// Webseed empty-set fixture (the default argument of the
    /// `slow_churn_faces` direct-drive face — existing decision rows
    /// have no webseeds).
    fn no_webseeds() -> std::collections::HashSet<u64> {
        std::collections::HashSet::new()
    }

    /// Webseed predicate exemption (the slow-churn collection face):
    /// the two slowest of a 10-peer pool (cuid 1/2) are webseeds — not
    /// collected and not evicted (CDNs have infinite patience, slowness
    /// is transient, and the no-alternative semantics does not apply;
    /// the EngineLoop::is_webseed direct-drive face takes equal
    /// parameters); the collection = the other 8 peers (exactly past
    /// the pool floor gate of 8) -> the line is 70 -> evictable
    /// {3,4,5,6}, K = min(4, max(1, 8x30%) = 2, candidates 5) = 2 -> the
    /// worst order [3, 4]. The turnover/stall rotations share the same
    /// exemption rule (the same continue at the collection gate; the
    /// decision core adds no behavior — carried by the same
    /// webseed_cuids semantics, no separate table).
    #[tokio::test]
    async fn slow_churn_exempts_webseed_peers() {
        use taiji_bt::utp::Transport;
        let root = CancellationToken::new();
        let mut face = adv_face(10);
        // cuid k -> rate k x 10 (10..100), all age 100s (past the
        // observation period).
        let mut remotes = Vec::new();
        let t0 = Instant::now();
        for cuid in 1u64..=10 {
            let (handle, remote) = choked_peer_pair(&root).await;
            face.peers.push(handle);
            face.peer_cuids.push(cuid);
            face.peer_state_row(cuid).meta = Some(PeerMeta {
                    ip: std::net::IpAddr::V4(std::net::Ipv4Addr::from([203, 0, 113, cuid as u8])),
                    port: 6881,
                    inbound: false,
                    peer_id: [0u8; 20],
                    crypto: taiji_bt::mse::CryptoLevel::Plain,
                    transport: Transport::Tcp,
                    up: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                    down: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                    upload_only: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                });
            let mut win = RateWindow::new();
            win.advance();
            win.add(cuid * 10);
            face.peer_state_row(cuid).down_window = Some(win);
            face.peer_state_row(cuid).registered_at = t0 - Duration::from_secs(100);
            remotes.push((cuid, remote));
        }
        let mut faces = vec![face];
        let mut marks = std::collections::HashMap::new();
        let params = SlowChurnParams {
            enabled: true,
            frac_pct: 100,
            k_pct: 30,
            min_age: Duration::from_secs(45),
            rarity_exempt: false,
            candidates: 5,
        };
        // webseed = the two slowest of the pool (cuid 1/2) — after the
        // exemption exactly 8 rows pass the pool floor gate.
        let webseeds: std::collections::HashSet<u64> = [1u64, 2].into_iter().collect();
        let d = slow_churn_faces(&mut faces, &params, &mut marks, &webseeds, t0);
        assert_eq!(d.picked, vec![3, 4], "only real peers evicted, worst-first (cuid 3/4)");
        assert_eq!(d.evictable, 4, "collected rows = non-webseed and below the line (3/4/5/6)");
        assert_eq!(d.median, 70.0, "the median over the collected pool (30..100's lower median 70)");
        // EOF observation: cuid 3/4 disconnected (shutdown); the
        // webseeds (1/2) and the on-line peers (5..10) survive.
        for (cuid, remote) in remotes.iter_mut() {
            let expect_eof = *cuid == 3 || *cuid == 4;
            let saw_eof = wait_peer_eof(remote, Duration::from_secs(2)).await;
            assert_eq!(saw_eof, expect_eof, "cuid {cuid}'s shutdown observation mismatched");
        }
        root.cancel();
    }

    /// Slow-peer eviction at face level ([`slow_churn_faces`] direct
    /// drive — the tick is only assembly; utp_mute_face follows the
    /// same shape): an 8-peer pool (3 fast + 2 mid-low + 1 new + 2
    /// slow, past the [`SLOW_CHURN_MIN_POOL`] floor gate) — the 2 worst
    /// below the line are shutdown (child token cancelled -> observable
    /// remote EOF) + the mark table hits the disconnected peers' addrs
    /// (peer_meta ip/port construction, the same shape as the leave
    /// arm's redial admission); fast/new (observation-period exempt)/
    /// exactly-on-line peers are not disconnected. The
    /// `BH_SLOW_PEER_CHURN=0` equivalence face: enabled=false drives
    /// zero disconnects and zero marks.
    /// Note: the spec's "3 fast 2 slow + 1 new" = 6 peers < the pool
    /// floor of 8 — two mid-low-rate peers are added to pass the gate
    /// (the decision core's pool-floor behavior is separately locked by
    /// the decision table rows).
    #[tokio::test]
    async fn slow_churn_faces_evicts_worst_slow_peers() {
        use taiji_bt::utp::Transport;
        let root = CancellationToken::new();
        let mut face = adv_face(8);
        // cuid -> 30s-window rate (B/s; advance+add one bucket -> rate =
        // the bucket value): rates = [5, 10, 50, 90, 100, 200, 250, 300]
        // -> the lower median (n/2=4) = 100 = the eviction line
        // (frac=100); evictable = {5, 10, 90} (cuid 1/2/4) — cuid 3
        // (rate 50) is below the line but age 10s < the 45s observation
        // period exempts it; K = min(3, max(1, 8x30%) = 2, candidates 5)
        // = 2 -> the worst order [cuid 1, cuid 2].
        let rates: [(u64, f64); 8] = [
            (1, 5.0),
            (2, 10.0),
            (3, 50.0),
            (4, 90.0),
            (5, 100.0),
            (6, 200.0),
            (7, 250.0),
            (8, 300.0),
        ];
        let mut remotes = Vec::new();
        let t0 = Instant::now();
        for (cuid, rate) in rates {
            let (handle, remote) = choked_peer_pair(&root).await;
            face.peers.push(handle);
            face.peer_cuids.push(cuid);
            face.peer_state_row(cuid).meta = Some(PeerMeta {
                    ip: std::net::IpAddr::V4(std::net::Ipv4Addr::from([203, 0, 113, cuid as u8])),
                    port: 6881,
                    inbound: false,
                    peer_id: [0u8; 20],
                    crypto: taiji_bt::mse::CryptoLevel::Plain,
                    transport: Transport::Tcp,
                    up: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                    down: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                    upload_only: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                });
            let mut win = RateWindow::new();
            win.advance();
            win.add(rate as u64);
            face.peer_state_row(cuid).down_window = Some(win);
            // Registration-time bookkeeping (a projection of the
            // registration arm's peer_state row): cuid 3 = a new peer
            // (10s), the rest = 100s (past the observation period).
            face.peer_state_row(cuid).registered_at = if cuid == 3 {
                t0 - Duration::from_secs(10)
            } else {
                t0 - Duration::from_secs(100)
            };
            remotes.push((cuid, remote));
        }
        let mut faces = vec![face];
        let mut marks = std::collections::HashMap::new();
        // The BH_SLOW_PEER_CHURN=0 equivalence face: enabled=false
        // direct drive -> zero disconnects, zero marks (the current
        // behavior bit-for-bit).
        let mut off = SlowChurnParams {
            enabled: false,
            frac_pct: 100,
            k_pct: 30,
            min_age: Duration::from_secs(45),
            rarity_exempt: false,
            candidates: 5,
        };
        let d = slow_churn_faces(&mut faces, &off, &mut marks, &no_webseeds(), t0);
        assert!(d.picked.is_empty(), "enabled=false gives an empty decision");
        assert!(marks.is_empty(), "zero marks");
        assert_eq!(d.evictable, 0);
        off.enabled = true;
        // Main row: the worst 2 (cuid 1 rate 5, cuid 2 rate 10) are
        // evicted.
        let d = slow_churn_faces(&mut faces, &off, &mut marks, &no_webseeds(), t0);
        assert_eq!(d.picked, vec![1, 2], "worst-first: disconnected in ascending down_rate order");
        assert_eq!(
            d.evictable, 3,
            "cuid 1/2/4 below the line; cuid 3 observation-period exempt, cuid 5 exactly-on-line exempt"
        );
        assert_eq!(d.median, 100.0);
        assert_eq!(d.threshold, 100.0);
        // The mark table hits the disconnected peers' addrs (the ip/port
        // construction = the same SocketAddr::new as the leave arm's
        // redial admission).
        for cuid in [1u64, 2] {
            let addr = std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from([203, 0, 113, cuid as u8])),
                6881,
            );
            assert_eq!(marks.get(&addr), Some(&t0), "cuid {cuid}'s eviction mark hit");
        }
        assert_eq!(marks.len(), 2, "only the disconnected are recorded");
        // shutdown observable: disconnected peers EOF; fast/new/on-line
        // peers (cuid 3..8) do not EOF (the wiring evidence of the
        // observation-period and on-line exemptions).
        for (cuid, remote) in remotes.iter_mut() {
            let expect_eof = *cuid == 1 || *cuid == 2;
            let saw_eof = wait_peer_eof(remote, Duration::from_secs(2)).await;
            assert_eq!(saw_eof, expect_eof, "cuid {cuid}'s shutdown observation mismatched");
        }
        root.cancel();
    }

    /// Endgame trigger condition B (ETA <
    /// [`crate::dispatch::ENDGAME_ETA_THRESHOLD_SECS`]) with a control
    /// row:
    /// row 1 the rate window has evidence (1MiB/s) and remaining bytes
    /// / rate = about 0.047s < 30s -> endgame — the strict gate is
    /// active (in flight 1 < missing 3, [`endgame_busy_admitted`] gate
    /// 1) AND the peer has non-zero in flight (gate 2) -> busy picks
    /// forbidden: only UNOWNED blocks are sent (the cursor's first
    /// level skips the in-flight piece for an unclaimed one — no
    /// refocusing an in-flight piece, no self-duplication, like
    /// libtorrent's "do not pick busy blocks you already requested",
    /// and rounds with unowned work remaining generate zero duplicates);
    /// row 2 (control) zero rate evidence -> not endgame -> the
    /// continuation arm keeps the checkout (the claimed piece is not
    /// switched while incomplete, the partial-piece proliferation
    /// regression lock) -> only after release does the spread claim the
    /// next piece.
    #[tokio::test]
    async fn endgame_eta_trigger_vs_rate_zero_control() {
        // Row 1: the ETA triggers.
        let root = tokio_util::sync::CancellationToken::new();
        let mut face = adv_face(3);
        let (handle, remote) = choke_peer_pair(&root).await;
        face.peers.push(handle);
        face.peer_cuids.push(5);
        note_peer_bitfield(&mut face, 5, &[0b1110_0000]);
        let _keep_alive = remote;
        dispatch_face(&mut face, 0);
        assert_eq!(face.dispatch_replies.len(), 1, "row 1 round 1: one piece dispatched normally");
        let first_piece = dispatch_entries(&face)
            .into_iter()
            .find_map(|(p, _, c)| (c == 5).then_some(p))
            .unwrap_or_else(|| panic!("row 1 round 1: the dispatch bookkeeping"));
        // Rate window fed 1s x 1MiB: remaining (3x16KiB) / rate = about
        // 0.047s < 30s.
        let mut w = RateWindow::new();
        w.advance();
        w.add(1024 * 1024);
        face.peer_state_row(5).down_window = Some(w);
        dispatch_face(&mut face, 0);
        assert_eq!(
            dispatch_count(&face),
            2,
            "row 1 round 2: the ETA triggers endgame AND the strict gate — only \
             unowned blocks sent (claiming the next unclaimed piece)"
        );
        let second_piece = dispatch_entries(&face)
            .into_iter()
            .find_map(|(p, _, c)| (c == 5 && p != first_piece).then_some(p))
            .unwrap_or_else(|| panic!("row 1 round 2: a newly claimed piece must exist"));
        assert_ne!(
            second_piece, first_piece,
            "row 1 round 2: under the strict gate no in-flight piece is re-picked \
             (busy picks forbidden, unowned first)"
        );
        assert_eq!(
            inflight_dup_count(&face),
            0,
            "row 1 round 2: zero duplicate copies (the strict gate active + the peer's \
             in-flight non-zero -> busy picks forbidden)"
        );
        assert_eq!(
            face.blocks_sent
                .get(&first_piece)
                .map(|l| l.block_state(0)),
            Some(BlockState::InFlight),
            "row 1 round 2: the in-flight piece keeps its first-copy state (not \
             duplicated by itself)"
        );
        root.cancel();

        // Row 2 (control): zero rate evidence -> not endgame. Round 2
        // continues the checkout piece (a single-block fresh in flight ->
        // an empty candidate set -> zero new claims); round 3 the piece
        // settles and releases the checkout -> the spread round claims
        // the next piece.
        let root = tokio_util::sync::CancellationToken::new();
        let mut face = adv_face(3);
        let (handle, remote) = choke_peer_pair(&root).await;
        face.peers.push(handle);
        face.peer_cuids.push(5);
        note_peer_bitfield(&mut face, 5, &[0b1110_0000]);
        let _keep_alive = remote;
        dispatch_face(&mut face, 0);
        assert_eq!(face.dispatch_replies.len(), 1, "row 2 round 1: one piece dispatched normally");
        let first_piece = face
            .peer_state
            .get(&5)
            .and_then(|ps| ps.piece)
            .unwrap_or_else(|| panic!("row 2 round 1: the checkout registration"));
        dispatch_face(&mut face, 0);
        assert_eq!(
            face.dispatch_replies.len(),
            1,
            "row 2 round 2: not endgame (zero rate evidence) -> the checkout piece \
             continues, zero new claims"
        );
        assert_eq!(
            face.peer_state.get(&5).and_then(|ps| ps.piece),
            Some(first_piece),
            "row 2 round 2: the checkout kept (the partial-piece proliferation regression lock)"
        );
        face.progress.set_piece_done_global(first_piece);
        face.blocks_sent.remove(&first_piece);
        dispatch_face(&mut face, 0);
        assert_eq!(
            face.dispatch_replies.len(),
            2,
            "row 2 round 3: after the non-endgame checkout release, the spread claims the next piece"
        );
        assert_ne!(
            face.peer_state.get(&5).and_then(|ps| ps.piece),
            Some(first_piece),
            "row 2 round 3: after the release a new piece is claimed"
        );
        root.cancel();
    }

    // ---- BEP53 selection_mask v2-only mask projection ----

    /// v2-only compact layout fixture (no padding; DFS order = client
    /// file order = the BEP53 index anchor). Piece length fixed at
    /// 16KiB (the same scale as the face assembly).
    fn v2_layout(lens: &[u64]) -> Layout {
        let entries: Vec<taiji_store::layout::PlanEntry> = lens
            .iter()
            .enumerate()
            .map(|(i, &len)| taiji_store::layout::PlanEntry {
                path: std::path::PathBuf::from(format!("f{i}.bin")),
                length: len,
                padding: false,
            })
            .collect();
        Layout::plan_v2_compact(&entries, 16384).unwrap_or_else(|e| panic!("{e}"))
    }

    /// Reproduction + regression: for a v2-only multi-file torrent whose
    /// file lengths leave non-piece-multiple remainders (a short final
    /// piece + unaligned file boundaries), the mask MUST project along
    /// the face plan cursor — per file pieces_f = ceil(len/piece_len);
    /// selected -> the file's flat segment all ones, unselected -> 0
    /// (the same walk as session/recheck.rs `encode_v2_file_bits`). The
    /// old implementation flattened by the layout byte space
    /// ceil(total/piece_len); on a v2 face (piece identity =
    /// (file_index, piece_in_file); global piece index assumptions are
    /// invalid) it selected/skipped the wrong pieces and produced a
    /// mask length != the face's piece count.
    ///
    /// Fixture: f0 = 20_000 (2 pieces, last 3_616B), f1 = 20_000 (2
    /// pieces), f2 = 10_000 (1 piece) -> 5 face pieces !=
    /// ceil(50_000/16_384) = 4.
    #[test]
    fn selection_mask_v2_only_multi_file_cursor_projection() {
        let layout = v2_layout(&[20_000, 20_000, 10_000]);
        let mask = selection_mask(&layout, 16384, &[0])
            .unwrap_or_else(|e| panic!("select [0]: {e}"));
        assert_eq!(mask, vec![true, true, false, false, false], "the first file selected");
        let mask = selection_mask(&layout, 16384, &[1])
            .unwrap_or_else(|e| panic!("select [1]: {e}"));
        assert_eq!(mask, vec![false, false, true, true, false], "the middle file selected");
        let mask = selection_mask(&layout, 16384, &[2])
            .unwrap_or_else(|e| panic!("select [2]: {e}"));
        assert_eq!(mask, vec![false, false, false, false, true], "the last file selected");
        let mask = selection_mask(&layout, 16384, &[0, 2])
            .unwrap_or_else(|e| panic!("select [0,2]: {e}"));
        assert_eq!(mask, vec![true, true, false, false, true], "a mixed selection");
        let mask = selection_mask(&layout, 16384, &[0, 1, 2])
            .unwrap_or_else(|e| panic!("select all: {e}"));
        assert_eq!(mask, vec![true, true, true, true, true], "select all = all face pieces");
    }

    /// priority_mask v2-only cursor projection (whole per-file segments
    /// take the level, unlisted files default to 0) + rejection faces
    /// (an empty table / an out-of-range index / a level outside the
    /// domain).
    #[test]
    fn priority_mask_v2_only_cursor_and_rejects() {
        let layout = v2_layout(&[20_000, 20_000, 10_000]);
        let m = priority_mask(&layout, 16384, &[(1, 7)])
            .unwrap_or_else(|e| panic!("prio [1]=7: {e}"));
        assert_eq!(m, vec![0, 0, 7, 7, 0], "file 1's whole segment takes 7; the rest default 0");
        let m = priority_mask(&layout, 16384, &[(0, -1), (2, 3)])
            .unwrap_or_else(|e| panic!("prio [0]=-1,[2]=3: {e}"));
        assert_eq!(m, vec![-1, -1, 0, 0, 3], "the -1 segments projected accurately (the skip face expressed by the mask)");
        assert!(priority_mask(&layout, 16384, &[]).is_err(), "an empty table rejected");
        assert!(priority_mask(&layout, 16384, &[(3, 1)]).is_err(), "an out-of-range index rejected");
        assert!(priority_mask(&layout, 16384, &[(0, 8)]).is_err(), "a level outside the domain rejected");
        assert!(priority_mask(&layout, 16384, &[(0, -2)]).is_err(), "a level outside the domain (negative) rejected");
    }

    /// priority_mask v1/hybrid byte-grid projection — a cross-file
    /// piece takes the highest level of the intersecting files (a
    /// piece-granularity whole-piece fetch: the strongest demand is
    /// served first).
    #[test]
    fn priority_mask_v1_grid_max_of_spanning() {
        // Two unaligned v1 files (16K pieces): file 0 = [0,24_000),
        // file 1 = [24_000,36_000) -> piece 1 [16K,32K) spans both
        // files.
        let entry = |i: usize, len: u64| taiji_store::layout::PlanEntry {
            path: std::path::PathBuf::from(format!("f{i}.bin")),
            length: len,
            padding: false,
        };
        let layout = Layout::plan_v1_padded(&[entry(0, 24_000), entry(1, 12_000)], 16384)
            .unwrap_or_else(|e| panic!("{e}"));
        let m = priority_mask(&layout, 16384, &[(0, 2), (1, 6)])
            .unwrap_or_else(|e| panic!("prio: {e}"));
        // Piece 0 = file 0 (2); piece 1 spans both -> max(2,6) = 6;
        // piece 2 = file 1 (6).
        assert_eq!(m, vec![2, 6, 6], "a cross-file piece takes the highest level of its intersections");
        // -1 does not join the max: file 0 = -1, file 1 = 5 -> the
        // spanning piece 1 takes 5.
        let m = priority_mask(&layout, 16384, &[(0, -1), (1, 5)])
            .unwrap_or_else(|e| panic!("prio -1: {e}"));
        assert_eq!(m, vec![0, 5, 5], "-1 does not raise the level (the skip face expressed by the mask)");
    }

    /// Mixed shapes: v2-only with an empty file (its 0-piece segment is
    /// skipped naturally — the `encode_v2_file_bits` empty-segment
    /// shape) and v2-only single file (cursor projection and byte grid
    /// are identical — the no-boundary-misalignment shape, a regression
    /// lock).
    #[test]
    fn selection_mask_v2_only_empty_file_and_single_file() {
        // [10_000 -> 1 piece][0 -> 0 pieces][20_000 -> 2 pieces]: mask
        // length 3.
        let layout = v2_layout(&[10_000, 0, 20_000]);
        let mask = selection_mask(&layout, 16384, &[0])
            .unwrap_or_else(|e| panic!("select [0]: {e}"));
        assert_eq!(mask, vec![true, false, false], "the empty file's front boundary does not cross the segment");
        let mask = selection_mask(&layout, 16384, &[2])
            .unwrap_or_else(|e| panic!("select [2]: {e}"));
        assert_eq!(mask, vec![false, true, true], "the segments after the empty file align");
        let mask = selection_mask(&layout, 16384, &[0, 1, 2])
            .unwrap_or_else(|e| panic!("select all: {e}"));
        assert_eq!(mask, vec![true, true, true], "select all including the empty file = all pieces");
        // Single file: cursor projection == the byte grid
        // (ceil(50_000/16_384) = 4).
        let single = v2_layout(&[50_000]);
        let mask = selection_mask(&single, 16384, &[0])
            .unwrap_or_else(|e| panic!("select single: {e}"));
        assert_eq!(mask, vec![true, true, true, true]);
    }

    /// v1/hybrid face bit-equivalence lock: the byte-grid reading (a
    /// piece's byte interval intersecting a selected file's interval
    /// selects it) is behaviorally unchanged — this test is green
    /// before and after the fix. On pad-aligned faces (hybrid) file
    /// starts are piece-aligned, so the byte grid == the cursor
    /// projection (an instantiation of the two readings always
    /// agreeing); likewise for aligned v2-only multi-file (no
    /// remainders).
    #[test]
    fn selection_mask_v1_padded_face_bit_equivalence_lock() {
        let entry = |i: usize, len: u64| taiji_store::layout::PlanEntry {
            path: std::path::PathBuf::from(format!("f{i}.bin")),
            length: len,
            padding: false,
        };
        // v1-only unaligned multi-file (no padding): the v1 face's
        // piece space = the byte grid, cross-file pieces fetched whole
        // (piece-granularity download semantics) — the existing bit
        // shape locked.
        let v1 = Layout::plan_v1_padded(&[entry(0, 20_000), entry(1, 20_000)], 16384)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            selection_mask(&v1, 16384, &[0]).unwrap_or_else(|e| panic!("{e}")),
            vec![true, true, false]
        );
        assert_eq!(
            selection_mask(&v1, 16384, &[1]).unwrap_or_else(|e| panic!("{e}")),
            vec![false, true, true]
        );
        assert_eq!(
            selection_mask(&v1, 16384, &[0, 1]).unwrap_or_else(|e| panic!("{e}")),
            vec![true, true, true]
        );
        // Hybrid pad-aligned face: padding aligns file starts (BEP47
        // L85) -> files = whole piece segments, byte grid == cursor
        // projection.
        let hybrid = Layout::plan_v1_padded(
            &[
                entry(0, 10_000),
                taiji_store::layout::PlanEntry {
                    path: std::path::PathBuf::from(".pad/0"),
                    length: 6_384,
                    padding: true,
                },
                entry(1, 20_000),
            ],
            16384,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            selection_mask(&hybrid, 16384, &[0]).unwrap_or_else(|e| panic!("{e}")),
            vec![true, false, false]
        );
        assert_eq!(
            selection_mask(&hybrid, 16384, &[1]).unwrap_or_else(|e| panic!("{e}")),
            vec![false, true, true]
        );
        // v2-only aligned multi-file (file lengths exactly piece
        // multiples): the two readings always agree.
        let aligned = v2_layout(&[16_384, 16_384, 16_384]);
        assert_eq!(
            selection_mask(&aligned, 16384, &[1]).unwrap_or_else(|e| panic!("{e}")),
            vec![false, true, false]
        );
    }

    /// Error semantics consistent across shapes (BEP53 invalid so= is
    /// rejected explicitly, never silently ignored): an empty selection
    /// = Err; an out-of-range index = Err (with index and file count
    /// context).
    #[test]
    fn selection_mask_error_semantics() {
        let layout = v2_layout(&[20_000, 20_000, 10_000]);
        assert!(selection_mask(&layout, 16384, &[]).is_err(), "an empty selection = Err");
        let Err(err) = selection_mask(&layout, 16384, &[3]) else {
            panic!("an out-of-range index must be explicitly rejected");
        };
        assert!(err.contains("3") && err.contains("out of range"), "{err}");
        // The v1 face, the same semantics (an existing-behavior
        // regression lock).
        let v1 = Layout::plan_v1_padded(
            &[taiji_store::layout::PlanEntry {
                path: std::path::PathBuf::from("f0.bin"),
                length: 20_000,
                padding: false,
            }],
            16384,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert!(selection_mask(&v1, 16384, &[]).is_err(), "v1 empty selection = Err");
        let Err(err) = selection_mask(&v1, 16384, &[9]) else {
            panic!("v1 out-of-range index must be explicitly rejected");
        };
        assert!(err.contains("out of range"), "{err}");
    }

    /// Batched settle application: the semantics lock for batched
    /// `Progress::BlocksSettled` application (the arms batch branch's
    /// loop body = single-point reuse of the per-coordinate
    /// [`super::run::arms::on_block_settled`] semantics) — every
    /// coordinate in the batch flips InFlight/InFlightDuplicate ->
    /// Buffered (in pipeline delivery order); the was_dup sibling
    /// cancel fires EXACTLY ONCE per coordinate (re-applying an
    /// already-Buffered coordinate is a harmless no-op and sends no
    /// further Cancel — the safety face for batch replay / duplicate
    /// events). The dispatch shape uses two real dispatch rounds
    /// (spread claim + endgame x2) — the sibling peer holds a real
    /// RequestBook slot so the Cancel frame reaches the wire (no slot =
    /// no-op; see the on_block_settled semantic boundary notes).
    #[tokio::test]
    async fn blocks_settled_batch_applies_in_order_and_cancels_sibling_once() {
        let root = tokio_util::sync::CancellationToken::new();
        let mut face = adv_face(2);
        // 4-blocks-per-piece geometry: a batch of >= 2 coordinates forms
        // naturally from a busy skip dup-marking a whole fresh piece
        // (the old single-block-piece shape needed the inner map to
        // store out-of-range begins; the inline shape sizes slots by
        // real block counts — out-of-range writes do not book).
        let blk = u64::from(merkle::BLOCK_SIZE);
        face.piece_bytes = vec![4 * blk; 2].into();
        face.piece_goffs = Arc::new((0..2).map(|k| k * 4 * blk).collect());
        face.progress = ProgressModel::from_lengths(&[8 * blk], (4 * blk) as u32);
        let (handle1, mut remote1) = choke_peer_pair(&root).await;
        face.peers.push(handle1);
        face.peer_cuids.push(1);
        let (handle2, mut remote2) = choke_peer_pair(&root).await;
        face.peers.push(handle2);
        face.peer_cuids.push(2);
        note_peer_bitfield(&mut face, 1, &[0b1100_0000]);
        note_peer_bitfield(&mut face, 2, &[0b1100_0000]);
        // Round 1 (spread claims) -> merge-semantics adaptation (under
        // the strict gate round 2 alone does not necessarily produce an
        // x2 duplicate): the same three-step recipe as
        // [`block_settle_cancels_sibling_duplicate_request`] — peer 1's
        // claimed piece settles and clears (endgame condition A
        // activates, the strict gate deactivates) -> round 2 busy-picks
        // peer 2's in-flight piece -> InFlightDup (a one-hop duplicate).
        dispatch_face(&mut face, 0);
        let first = dispatch_entries(&face)
            .into_iter()
            .find_map(|(p, _, c)| (c == 1).then_some(p))
            .unwrap_or_else(|| panic!("round 1: peer 1 must have a claim"));
        face.progress.set_piece_done_global(first);
        face.blocks_sent.remove(&first);
        dispatch_face(&mut face, 0);
        let block = u64::from(merkle::BLOCK_SIZE);
        let settled: Vec<(u32, u32)> = face
            .blocks_sent
            .iter()
            .flat_map(|(&piece, ledger)| {
                ledger
                    .slots()
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| s.state != BlockState::None)
                    .map(move |(bi, _)| {
                        (
                            u32::try_from(piece).unwrap_or(u32::MAX),
                            (bi as u64 * block) as u32,
                        )
                    })
            })
            .collect();
        assert!(settled.len() >= 2, "the batch shape must have >= 2 in-flight coordinates");
        assert!(
            inflight_dup_count(&face) > 0,
            "round 2 must have duplicate in-flight coordinates (the sibling cancel's precondition)"
        );
        // Capture the dup coordinate and the sibling direction before
        // the batch applies (the dup state flips to Buffered during it;
        // the sibling = the dup coordinate's dispatch target, judged as
        // in [`block_settle_cancels_sibling_duplicate_request`]).
        let dup_coord = any_inflight_dup(&face)
            .unwrap_or_else(|| panic!("the batch must have a dup coordinate (asserted above)"));
        let sibling = dispatch_owner(&face, dup_coord.0, dup_coord.1)
            .unwrap_or_else(|| panic!("a dup coordinate must have dispatch-target bookkeeping"));
        // The count anchor is read before the batch applies (in-batch
        // dup coordinates flip to Buffered on settle).
        let expected_cancels = inflight_dup_count(&face);
        assert!(expected_cancels >= 1, "the batch must have >= 1 dup coordinate (asserted above)");
        // Batch application (the arms BlocksSettled branch loop body,
        // verbatim).
        for (index, begin) in &settled {
            super::run::arms::on_block_settled(&mut face, *index, *begin);
        }
        for (index, begin) in &settled {
            assert_eq!(
                face.blocks_sent
                    .get(&u64::from(*index))
                    .map(|l| l.block_state(*begin)),
                Some(BlockState::Buffered),
                "in-batch coordinate ({index},{begin}) flips to Buffered"
            );
        }
        // Wire face: the sibling peer receives exactly one Cancel (id 8)
        // per dup coordinate — the sibling direction was captured
        // before the batch (dup states flip to Buffered during it); a
        // multi-block busy skip lands several dup coordinates -> several
        // Cancel frames, the count anchor = the dup slot count read
        // before the batch above.
        let remote = match sibling {
            1 => &mut remote1,
            2 => &mut remote2,
            other => unreachable!("adv_face has two peers, got {other}"),
        };
        let mut cancels = 0;
        for _ in 0..32 {
            match tokio::time::timeout(Duration::from_millis(400), read_wire_msg_id(remote))
                .await
            {
                Ok(Some(8)) => cancels += 1,
                Ok(Some(_)) => continue,
                _ => break,
            }
        }
        assert_eq!(
            cancels, expected_cancels,
            "exactly one Cancel frame per dup coordinate (the landing cancels the sibling)"
        );
        // Whole-batch replay (already-Buffered coordinates): was_dup is
        // always false -> zero second Cancel frames.
        for (index, begin) in &settled {
            super::run::arms::on_block_settled(&mut face, *index, *begin);
        }
        let mut second_cancel = false;
        for _ in 0..32 {
            match tokio::time::timeout(Duration::from_millis(200), read_wire_msg_id(match sibling {
                1 => &mut remote1,
                _ => &mut remote2,
            }))
            .await
            {
                Ok(Some(8)) => {
                    second_cancel = true;
                    break;
                }
                Ok(Some(_)) => continue,
                _ => break,
            }
        }
        assert!(
            !second_cancel,
            "replaying already-Buffered coordinates sends zero Cancels (was_dup \
             cancels exactly once)"
        );
        root.cancel();
    }

    // -----------------------------------------------------------------------
    // Structural tests
    // -----------------------------------------------------------------------

    /// DispatchScratch reuse assertion: transient buffer capacity
    /// persists across dispatch rounds' take-out/put-back — the first
    /// round grows to the face's piece count, the second does not
    /// shrink (the clear + resize/clear reuse path never frees the heap
    /// = the anchor for zero-alloc later rounds).
    #[test]
    fn dispatch_scratch_reuse_capacity_retained() {
        let mut face = adv_face(64);
        // Zero starting capacity (the fixture's Default start — the
        // first round grows it).
        assert_eq!(face.dispatch_scratch.done.capacity(), 0, "zero starting capacity");
        dispatch_face(&mut face, 0);
        // After the round the scratch is back on the face (the done
        // bitmap persists, length = the face's piece count).
        assert_eq!(face.dispatch_scratch.done.len(), 64, "the done bitmap persists after the round");
        let cap1 = face.dispatch_scratch.done.capacity();
        assert!(cap1 >= 64, "the first round grows to the face's piece count, got {cap1}");
        // Second call: capacity does not shrink (clear+resize reuses
        // without reallocating or shrinking).
        dispatch_face(&mut face, 0);
        let cap2 = face.dispatch_scratch.done.capacity();
        assert!(
            cap2 >= cap1,
            "the second call does not shrink capacity (the zero-alloc reuse \
             anchor), cap1={cap1} cap2={cap2}"
        );
        // done semantics recheck: all missing (no completions / masks /
        // missing layers) -> 64 false.
        assert!(
            face.dispatch_scratch.done.iter().all(|&d| !d),
            "the done bitmap recomputed per round (an all-missing face is all false)"
        );
    }

    /// ClaimedSet::reset in-place reuse semantics: reset matches a
    /// discard-and-rebuild (with_len) verdict bit for bit + capacity
    /// persists.
    #[test]
    fn claimed_set_reset_matches_fresh_build() {
        let mut reused = ClaimedSet::with_len(32);
        reused.mark_claimed(3);
        reused.mark_claimed(7);
        reused.mark_claimed(3);  // duplicate claims are idempotent
        assert_eq!(reused.len(), 2);
        reused.reset(32);
        assert_eq!(reused.len(), 0, "the count cleared");
        assert!(!reused.contains(3) && !reused.contains(7), "the bitmap cleared");
        // Bit-for-bit equal to a fresh rebuild (the equivalence gate).
        let fresh = ClaimedSet::with_len(32);
        assert_eq!(reused.len(), fresh.len());
        for i in 0u64..32 {
            assert_eq!(reused.contains(i), fresh.contains(i));
        }
        // Growth face: after the piece count grows, out-of-range bits
        // are writable.
        reused.reset(64);
        reused.mark_claimed(63);
        assert!(reused.contains(63));
    }

    /// PeerState structural test (the per-peer single merged table):
    /// registration writes its fields in full / lazy fields start as
    /// Option zero values / bookkeeping write points take-or-create
    /// the row / leave removes the row.
    #[test]
    fn peer_state_row_lifecycle() {
        use taiji_bt::utp::Transport;
        let mut face = adv_face(4);
        // — Registration writes (PeerState::registered: the registration
        // arm's final shape) —
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::from([203, 0, 113, 7]));
        let meta = PeerMeta {
            ip,
            port: 6881,
            inbound: false,
            peer_id: [7u8; 20],
            crypto: taiji_bt::mse::CryptoLevel::Plain,
            transport: Transport::Tcp,
            up: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            down: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            upload_only: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let t0 = Instant::now();
        let row = PeerState::registered(7, ip, meta, t0);
        assert_eq!(row.cuid, 7, "the row's self-describing key");
        assert_eq!(row.registered_at, t0, "the registration instant (the old peer_registered_at merged in)");
        assert!(
            row.ip.is_some()
                && row.meta.is_some()
                && row.rates.is_some()
                && row.down_window.is_some(),
            "registration writes every field in full (ip/meta/rates/down_window)"
        );
        // — Lazy fields start at zero values —
        assert!(row.last_unchoke.is_none(), "last_unchoke lazily None");
        assert!(!row.am_unchoked, "am_unchoked defaults false (BEP3 connections start choked)");
        assert!(row.last_opt_unchoke.is_none(), "the optimistic key lazily None");
        assert!(row.utp_mute_since.is_none(), "the µTP governance anchor lazily None");
        assert!(row.piece.is_none(), "the checkout lazily None");
        assert!(row.extra_pieces.is_empty(), "an empty secondary vector = none");
        face.peer_state.insert(7, row);
        // — Bookkeeping write point (peer_state_row): a missing row is
        // created minimal —
        face.peer_state_row(9).piece = Some(3);
        let ps9 = face.peer_state.get(&9).unwrap_or_else(|| panic!("row 9 created"));
        assert_eq!(ps9.cuid, 9, "the minimal row's self-describing key");
        assert_eq!(ps9.piece, Some(3));
        assert!(
            ps9.meta.is_none() && ps9.rates.is_none() && ps9.down_window.is_none(),
            "the minimal row's Option fields lazy (the fixture's partial assembly = \
             the old split-tables' absence, same verdict)"
        );
        assert!(
            Instant::now().duration_since(ps9.registered_at) <= Duration::from_secs(60),
            "the minimal row's registration instant defaults to now (the age-0 \
             defensive semantics)"
        );
        // — Field writes (the equivalent of the old per-table inserts) —
        {
            let r = face.peer_state_row(7);
            r.am_unchoked = true;
            r.last_unchoke = Some(t0);
            r.last_opt_unchoke = Some(t0);
            r.utp_mute_since = Some(t0);
            r.piece = Some(1);
            r.extra_pieces.push(2);  // the append face's dedup is the production write point's contains guard
        }
        let ps7 = face
            .peer_state
            .get(&7)
            .unwrap_or_else(|| panic!("row 7 booked"));
        assert!(ps7.am_unchoked && ps7.last_unchoke == Some(t0) && ps7.piece == Some(1));
        assert_eq!(ps7.extra_pieces, vec![2u64]);
        // — Leave removes the row (the leave arm's final shape: a single
        // remove = all tables withdrawn) —
        assert!(face.peer_state.remove(&7).is_some(), "leaving removes the row");
        assert!(!face.peer_state.contains_key(&7));
        assert!(
            face.peer_state.contains_key(&9),
            "removing the row touches only the target cuid (cuids are unique per connection)"
        );
    }

    /// The getPeers bitmap's on-demand materialization switch —
    /// `want_bitfield=false` (the internal counting face) packs nothing;
    /// `true` (the aria2 protocol face) packs every row with None rows =
    /// all zeros (length piece_count/8, semantics unchanged); the
    /// seeder verdict is identical in both states.
    #[test]
    fn peer_snapshots_bitfield_lazy_switch() {
        use taiji_bt::utp::Transport;
        let mut face = adv_face(64);
        let mk_meta = |id: u8| PeerMeta {
            ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, id)),
            port: 51417,
            inbound: false,
            peer_id: [id; 20],
            crypto: taiji_bt::mse::CryptoLevel::Plain,
            transport: Transport::Tcp,
            up: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            down: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            upload_only: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        for (cuid, id) in [(11u64, 1u8), (22, 2)] {
            face.peer_cuids.push(cuid);
            face.peer_state_row(cuid).meta = Some(mk_meta(id));
        }
        // p11's bitmap row = all ones (seeder); p22 has no row (the None
        // arm, not a seeder).
        face.peer_avail.insert(11, PieceBitmap::ones(64));
        // want=true: the aria2 face packs every row.
        let snaps = crate::query::peer_snapshots(std::slice::from_mut(&mut face), true);
        assert_eq!(snaps.len(), 2, "both peers produce snapshots");
        for s in &snaps {
            assert_eq!(s.bitfield.len(), 8, "64 pieces -> 8B packed (None rows all zeros included)");
        }
        let by_id = |id: u8| {
            snaps
                .iter()
                .find(|s| s.peer_id == [id; 20])
                .unwrap_or_else(|| panic!("peer {id} must be in the snapshots"))
        };
        assert!(by_id(1).seeder, "an all-ones row = seeder");
        assert!(!by_id(2).seeder, "a None row = not a seeder");
        // want=false: the counting face packs nothing; the seeder verdict
        // does not change with the switch.
        let snaps = crate::query::peer_snapshots(std::slice::from_mut(&mut face), false);
        assert_eq!(snaps.len(), 2);
        assert!(
            snaps.iter().all(|s| s.bitfield.is_empty()),
            "want=false must pack nothing"
        );
        assert!(
            snaps
                .iter()
                .find(|s| s.peer_id == [1u8; 20])
                .is_some_and(|s| s.seeder)
        );
        assert!(
            snaps
                .iter()
                .find(|s| s.peer_id == [2u8; 20])
                .is_some_and(|s| !s.seeder)
        );
    }

    /// am_choking reads the live unchoke state (`am_unchoked`), not the
    /// last-unchoke bookkeeping: a peer that was unchoked in an earlier
    /// round and has since lost its slot keeps a stale `last_unchoke`
    /// residual and must still read am_choking=true (aria2
    /// RpcMethodImpl.cc reads the live am-choking bool; the same source
    /// as tick's telemetry). The choke-mirror gauge
    /// (`count_peer_gauges`) follows the same rule.
    #[test]
    fn peer_snapshots_am_choking_reads_unchoke_state() {
        use taiji_bt::utp::Transport;
        let mut face = adv_face(4);
        let mk_meta = |id: u8| PeerMeta {
            ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, id)),
            port: 51417,
            inbound: false,
            peer_id: [id; 20],
            crypto: taiji_bt::mse::CryptoLevel::Plain,
            transport: Transport::Tcp,
            up: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            down: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            upload_only: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let t0 = Instant::now();
        // Three regulator rows: A never unchoked (the BEP3 connect
        // default), B in the live unchoke set, C yielded its slot in an
        // earlier round and was re-choked (the stale last_unchoke
        // residual stays — it is the choke round's sort key, never
        // cleared).
        for (cuid, id) in [(31u64, 1u8), (32, 2), (33, 3)] {
            face.peer_cuids.push(cuid);
            face.peer_state_row(cuid).meta = Some(mk_meta(id));
        }
        {
            let b = face.peer_state_row(32);
            b.am_unchoked = true;
            b.last_unchoke = Some(t0);
        }
        {
            let c = face.peer_state_row(33);
            c.am_unchoked = false;
            c.last_unchoke = Some(t0);
        }
        let snaps = crate::query::peer_snapshots(std::slice::from_mut(&mut face), false);
        let by_id = |id: u8| {
            snaps
                .iter()
                .find(|s| s.peer_id == [id; 20])
                .unwrap_or_else(|| panic!("peer {id} must be in the snapshots"))
        };
        // A: never unchoked (both fields idle) -> choked.
        assert!(by_id(1).am_choking, "never unchoked -> am_choking");
        // B: in the live unchoke set -> not choking.
        assert!(!by_id(2).am_choking, "currently unchoked -> !am_choking");
        // C: the regression anchor — a stale last_unchoke residual must
        // not mask the re-choke (the pre-fix last_unchoke.is_none() read
        // reported am_choking=false here).
        assert!(
            by_id(3).am_choking,
            "a re-choked peer with a stale last_unchoke -> am_choking"
        );
        // The choke-mirror gauge follows the same source: A and C choked;
        // the transport split pins the denominator (all three rows
        // visible, all outbound tcp).
        let (tcp_in, tcp_out, utp_in, utp_out, choked) =
            crate::query::count_peer_gauges(std::slice::from_ref(&face));
        assert_eq!(
            (tcp_in, tcp_out, utp_in, utp_out),
            (0, 3, 0, 0),
            "all three peers visible to the gauge as outbound tcp"
        );
        assert_eq!(choked, 2, "choked gauge = A + C (the same live-bool source)");
    }

    /// Completion hooks release the dispatch scratch and the stat_man
    /// bucket view — when written_count reaches the need,
    /// `recheck_face_completion` releases at a single point (capacity to
    /// zero; a later take lazily rebuilds and self-heals).
    #[test]
    fn completion_releases_scratch_and_bucket_view() {
        let mut face = adv_face(64);
        // First persist scratch capacity + a bucket view (simulating
        // past dispatch/endgame rounds).
        face.dispatch_scratch.done = vec![false; 64];
        face.stat_man.add_bitfield(|_| true, 64);
        let (p, _) = face
            .stat_man
            .select_two_phase(|_| true, |_| false, None);
        assert!(p.is_some());
        assert!(face.dispatch_scratch.done.capacity() >= 64);
        assert!(!face.completed);
        // Completion verdict -> release.
        face.written_count = 64;
        let all = crate::faces::recheck_face_completion(std::slice::from_mut(&mut face), &[64]);
        assert!(all && face.completed, "64/64 flushed -> complete");
        assert_eq!(
            face.dispatch_scratch.done.capacity(),
            0,
            "completion releases the scratch"
        );
        // The counting face is kept permanently (stat_man counts
        // untouched).
        assert_eq!(face.stat_man.count(0), 1);
    }

    /// Quick win 1: at seeding entry
    /// [`crate::faces::release_download_state`] hands every face
    /// arena's idle pages back (counter observable on all platforms via
    /// the small-bucket truncation; the main bucket's madvise face is
    /// linux-only) and arena-less faces are skipped without ceremony.
    #[test]
    fn release_download_state_releases_face_arenas() {
        use taiji_io::block_arena::BLOCK_SIZE;
        let arena = taiji_io::block_arena::BlockArena::new(512 * 1024);
        // Seed the idle lists: lease + return main and small blocks
        // (300 small > the 256 release floor).
        let mains: Vec<_> = (0..2).map(|_| arena.lease(BLOCK_SIZE)).collect();
        let smalls: Vec<_> = (0..300).map(|_| arena.lease(1024)).collect();
        drop(mains);
        drop(smalls);
        let mut f0 = adv_face(4);
        f0.block_arena = Some(arena.clone());
        let f1 = adv_face(4);
        let faces = [f0, f1];
        let released = crate::faces::release_download_state(&faces);
        assert!(
            released > 0,
            "the small-bucket truncation contributes released bytes on every \
             platform (300-256 = a 44KiB floor)"
        );
        assert_eq!(
            arena.readout().released_idle_bytes_total,
            released,
            "the readout accumulation semantics matches the return value"
        );
    }
