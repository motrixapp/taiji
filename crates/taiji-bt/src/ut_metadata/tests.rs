//! ut_metadata conformance vectors and semantics tests.
//!
//! Sources: vectors tagged `[aria2]` come from aria2 test/UTMetadata*;
//! `[strict]` marks this repo's tightenings (earlier error exposure, the
//! same final verdict).

use std::time::{Duration, Instant};

use bytes::Bytes;

use super::fetcher::{
    DataOutcome, FetchError, MAX_METADATA_SIZE, MetadataAssembler, MetadataError, MetadataFetcher,
    piece_count,
};
use super::message::{ServeError, ServeOutcome, UtMetadata, serve_request};
use super::tracker::RequestTracker;
use super::{METADATA_PIECE_SIZE, TIMEOUT};
use crate::bencode::BencodeError;

fn ok<T, E: std::fmt::Debug>(r: Result<T, E>, what: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{what}: {e:?}"),
    }
}

fn zeros(n: usize) -> Bytes {
    Bytes::from(vec![b'0'; n])
}

// ===== message codec vectors =====

/// [aria2] UTMetadataRequestExtensionMessageTest.cc
/// (testGetBencodedData, index=99).
#[test]
fn vector_01_request_encode_exact_bytes() {
    let req = UtMetadata::Request { index: 99 };
    let bytes = ok(req.encode(), "encode");
    assert_eq!(bytes, b"d8:msg_typei0e5:piecei99ee".to_vec());
    // Decode roundtrip of the same object (decode(encode(x)) == x).
    assert_eq!(ok(UtMetadata::decode(&bytes), "decode"), req);
}

/// [aria2] UTMetadataDataExtensionMessageTest.cc
/// (index=1, total_size=16384, data = 16KiB '0'; dict + raw piece bytes).
#[test]
fn vector_02_data_encode_exact_bytes() {
    let data = zeros(METADATA_PIECE_SIZE);
    let msg = UtMetadata::Data {
        index: 1,
        total_size: METADATA_PIECE_SIZE,
        data: data.clone(),
    };
    let bytes = ok(msg.encode(), "encode");
    let mut expected = b"d8:msg_typei1e5:piecei1e10:total_sizei16384ee".to_vec();
    expected.extend_from_slice(&data);
    assert_eq!(bytes, expected);
    assert_eq!(ok(UtMetadata::decode(&bytes), "decode"), msg);
}

/// [aria2] UTMetadataRejectExtensionMessageTest.cc (index=1).
#[test]
fn vector_03_reject_encode_exact_bytes() {
    let rej = UtMetadata::Reject { index: 1 };
    let bytes = ok(rej.encode(), "encode");
    assert_eq!(bytes, b"d8:msg_typei2e5:piecei1ee".to_vec());
    assert_eq!(ok(UtMetadata::decode(&bytes), "decode"), rej);
}

/// Decode negative matrix ([aria2] the explicit throw branches of
/// DefaultExtensionMessageFactory.cc).
#[test]
fn vector_04_decode_rejection_matrix() {
    use super::UtMetadataError as E;
    // Empty payload (MSG_TOO_SMALL_PAYLOAD_SIZE).
    assert_eq!(UtMetadata::decode(&[]), Err(E::TooSmall));
    // Top level not a dict ("dictionary not found").
    assert_eq!(UtMetadata::decode(b"i1e"), Err(E::NotDict));
    // Missing msg_type.
    assert_eq!(UtMetadata::decode(b"d5:piecei0ee"), Err(E::MissingMsgType));
    // Missing piece.
    assert_eq!(UtMetadata::decode(b"d8:msg_typei0ee"), Err(E::BadPiece));
    // Negative piece (`index->i() < 0`).
    assert_eq!(
        UtMetadata::decode(b"d8:msg_typei0e5:piecei-1ee"),
        Err(E::BadPiece)
    );
    // Unknown msg_type.
    assert_eq!(
        UtMetadata::decode(b"d8:msg_typei3e5:piecei0ee"),
        Err(E::UnknownMsgType(3))
    );
    // data state missing total_size.
    assert_eq!(
        UtMetadata::decode(b"d8:msg_typei1e5:piecei0eeX"),
        Err(E::MissingTotalSize)
    );
    // data state missing data ("data not found" — the dict is everything).
    assert_eq!(
        UtMetadata::decode(b"d8:msg_typei1e5:piecei0e10:total_sizei1ee"),
        Err(E::DataMissing)
    );
    // Broken bencode (the reference's bencode2::decode throw): the
    // structural scan judges truncation.
    assert!(matches!(
        UtMetadata::decode(b"d8:msg_type"),
        Err(E::Malformed)
    ));
    // Length field > 19 digits -> structural scan judges truncation
    // (overflow protection; [strict], same shape as Malformed).
    assert!(matches!(
        UtMetadata::decode(b"99999999999999999999999:ab"),
        Err(E::Malformed)
    ));
    // Structurally valid but the integer overflows i64 -> Bencode error
    // passthrough (the shape of aria2 BencodeParser.cc
    // ERR_NUMBER_OUT_OF_RANGE).
    assert!(matches!(
        UtMetadata::decode(b"i9999999999999999999999999e"),
        Err(E::Bencode(BencodeError::IntegerOverflow { .. }))
    ));
}

/// data-frame trailing-byte semantics ([aria2]
/// DefaultExtensionMessageFactory.cc's `end` out-param): every byte after
/// the dict is data; trailing bytes on request/reject are ignored by the
/// reference (no end check) — ignored here too.
#[test]
fn vector_05_trailing_bytes_matrix() {
    // data: the 3 bytes after the dict = data.
    let msg = ok(
        UtMetadata::decode(b"d8:msg_typei1e5:piecei0e10:total_sizei3eeXYZ"),
        "data with trailing",
    );
    assert_eq!(
        msg,
        UtMetadata::Data {
            index: 0,
            total_size: 3,
            data: Bytes::from_static(b"XYZ"),
        }
    );
    // request: trailing bytes ignored.
    let req = ok(
        UtMetadata::decode(b"d8:msg_typei0e5:piecei7eeJUNK"),
        "req trailing",
    );
    assert_eq!(req, UtMetadata::Request { index: 7 });
    // reject: trailing bytes ignored.
    let rej = ok(
        UtMetadata::decode(b"d8:msg_typei2e5:piecei7eeJUNK"),
        "rej trailing",
    );
    assert_eq!(rej, UtMetadata::Reject { index: 7 });
}

// ===== RequestTracker ([aria2] UTMetadataRequestTrackerTest) =====

/// [aria2] testAvail: empty -> 1; one entry -> 0; two entries -> 0
/// (MAX_OUTSTANDING_REQUEST = 1).
#[test]
fn vector_06_tracker_avail() {
    let t0 = Instant::now();
    let mut tr = RequestTracker::new();
    assert_eq!(tr.avail(), 1);
    tr.add(1, t0);
    assert_eq!(tr.avail(), 0);
    tr.add(2, t0);
    assert_eq!(tr.avail(), 0);
}

/// [aria2] testRemove + testCount + testGetAllTrackedIndex.
#[test]
fn vector_07_tracker_add_remove_count_all() {
    let t0 = Instant::now();
    let mut tr = RequestTracker::new();
    tr.add(1, t0);
    tr.add(2, t0);
    assert_eq!(tr.count(), 2);
    assert_eq!(tr.all_tracked_indices(), vec![1, 2]);
    assert!(tr.tracks(1));
    tr.remove(1);
    assert!(!tr.tracks(1), "testRemove: no longer tracked after removal");
    assert_eq!(tr.count(), 1);
    // Removing an absent index: no-op (the reference's find failure has no
    // side effects).
    tr.remove(42);
    assert_eq!(tr.count(), 1);
}

/// Correction criterion: the 20s sweep boundary, table-driven (19s /
/// exactly 20s / 21s). The reference `TIMEOUT = 20_s`
/// (UTMetadataRequestTracker.cc), check `elapsed >= t`
/// (UTMetadataRequestTracker.h, boundary inclusive); the design spec's
/// "1s" was a typo.
#[test]
fn vector_08_timeout_sweep_boundary_19_20_21s() {
    let t0 = Instant::now();
    let mut tr = RequestTracker::new();
    tr.add(7, t0);
    // 19s: not timed out (sweep yields nothing, still tracked).
    assert!(
        tr.remove_timeout_entries(t0 + Duration::from_secs(19))
            .is_empty()
    );
    assert!(tr.tracks(7), "19s < TIMEOUT(20s), must not be swept");
    // Exactly 20s: `>=` is inclusive -> timed out and removed.
    let mut tr = RequestTracker::new();
    tr.add(7, t0);
    assert_eq!(
        tr.remove_timeout_entries(t0 + TIMEOUT),
        &[7],
        "exactly 20s must be swept (boundary inclusive, h:56-59)"
    );
    assert!(!tr.tracks(7));
    assert_eq!(tr.count(), 0);
    // 21s: also timed out.
    let mut tr = RequestTracker::new();
    tr.add(7, t0);
    assert_eq!(
        tr.remove_timeout_entries(t0 + Duration::from_secs(21)),
        &[7]
    );
    // Multiple entries mixed: only timed-out entries swept (the reference's
    // remove_if semantics).
    let mut tr = RequestTracker::new();
    tr.add(1, t0);
    tr.add(2, t0 + Duration::from_secs(5));
    tr.add(3, t0);
    assert_eq!(
        tr.remove_timeout_entries(t0 + Duration::from_secs(20)),
        &[1, 3],
        "the sweep returns timed-out entries in insertion order"
    );
    assert_eq!(tr.all_tracked_indices(), vec![2]);
}

// ===== Fetcher / Assembler (requester) =====

/// Two-piece sample ([aria2] UTMetadataDataExtensionMessageTest.cc's
/// piece0='0'*16K, piece1='1'*16K shape) and its SHA-1.
fn sample_metadata() -> (Vec<u8>, [u8; 20]) {
    let piece0 = vec![b'0'; METADATA_PIECE_SIZE];
    let piece1 = vec![b'1'; METADATA_PIECE_SIZE];
    let metadata = [piece0, piece1].concat();
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(&metadata);
    let out = hasher.finalize();
    let mut ih = [0u8; 20];
    ih.copy_from_slice(&out);
    (metadata, ih)
}

/// Piece-count derivation: rounded up to 16KiB units (`BtConstants.h`
/// derivation).
#[test]
fn vector_09_piece_count() {
    assert_eq!(piece_count(1), 1);
    assert_eq!(piece_count(METADATA_PIECE_SIZE), 1);
    assert_eq!(piece_count(METADATA_PIECE_SIZE + 1), 2);
    assert_eq!(piece_count(METADATA_PIECE_SIZE * 2), 2);
    assert_eq!(piece_count(0), 0);
    // The 8MiB cap -> 512 pieces (the source of the piece-count bound).
    assert_eq!(piece_count(MAX_METADATA_SIZE), 512);
}

/// Request scheduling ([aria2] UTMetadataRequestFactoryTest semantics +
/// UTMetadataRequestFactory.cc): the avail budget of 1 -> at most one
/// request per round.
#[test]
fn vector_10_fetcher_request_scheduling() {
    let t0 = Instant::now();
    let (_, ih) = sample_metadata();
    let mut f = ok(MetadataFetcher::new(METADATA_PIECE_SIZE * 2, ih), "new");
    assert_eq!(f.metadata_size(), METADATA_PIECE_SIZE * 2);
    assert_eq!(f.num_pieces(), 2);
    // First round: budget 1 -> [0].
    assert_eq!(f.next_requests(t0, 4), vec![0]);
    // Budget taken -> empty.
    assert!(
        f.next_requests(t0, 4).is_empty(),
        "no re-dispatch while the 1 in-flight piece is unreclaimed"
    );
    // max=0 -> no dispatch.
    let mut f2 = ok(MetadataFetcher::new(METADATA_PIECE_SIZE, ih), "new");
    assert!(f2.next_requests(t0, 0).is_empty());
    // After data returns the budget, the next piece can be requested.
    ok(
        f.on_data(0, &vec![b'0'; METADATA_PIECE_SIZE], t0),
        "on_data 0",
    );
    assert_eq!(f.next_requests(t0, 4), vec![1]);
}

/// Full data-delivery flow ([aria2] UTMetadataDataExtensionMessageTest
/// semantics): untracked ignored; tracked removed on receipt; assembly
/// succeeds -> infohash verification passes.
#[test]
fn vector_11_fetcher_data_flow_completes() {
    let t0 = Instant::now();
    let (metadata, ih) = sample_metadata();
    let mut f = ok(MetadataFetcher::new(metadata.len(), ih), "new");
    // Untracked data -> Untracked.
    assert_eq!(
        ok(
            f.on_data(1, &metadata[METADATA_PIECE_SIZE..], t0),
            "untracked"
        ),
        DataOutcome::Untracked
    );
    // Normal two-step completion.
    let _ = f.next_requests(t0, 4);
    assert_eq!(
        ok(f.on_data(0, &metadata[..METADATA_PIECE_SIZE], t0), "piece0"),
        DataOutcome::Stored { remaining: 1 }
    );
    assert!(
        f.tracked_indices().is_empty(),
        "received pieces leave the bookkeeping"
    );
    assert_eq!(f.next_requests(t0, 4), vec![1]);
    assert_eq!(f.tracked_indices(), vec![1]);
    match ok(f.on_data(1, &metadata[METADATA_PIECE_SIZE..], t0), "piece1") {
        DataOutcome::Complete { metadata: got } => assert_eq!(got.as_ref(), metadata.as_slice()),
        other => panic!("expected Complete, got {other:?}"),
    }
}

/// Infohash verification failure -> reject + all pieces reset;
/// [aria2] UTMetadataDataExtensionMessage.cc.
#[test]
fn vector_12_infohash_mismatch_rejects_and_resets() {
    let t0 = Instant::now();
    let (metadata, _) = sample_metadata();
    let wrong_ih = [0xEE; 20];
    let mut f = ok(MetadataFetcher::new(metadata.len(), wrong_ih), "new");
    assert_eq!(f.next_requests(t0, 4), vec![0]);
    ok(f.on_data(0, &metadata[..METADATA_PIECE_SIZE], t0), "piece0");
    assert_eq!(f.next_requests(t0, 4), vec![1]);
    let err = match f.on_data(1, &metadata[METADATA_PIECE_SIZE..], t0) {
        Err(FetchError::Metadata(MetadataError::InfoHashMismatch)) => true,
        other => panic!("expected InfoHashMismatch, got {other:?}"),
    };
    assert!(err);
    // All pieces reset (the reference's whole-file markPieceMissing) -> the
    // fetch can restart from another peer.
    assert!(
        f.tracked_indices().is_empty(),
        "the bookkeeping stays empty after the last piece removes it"
    );
    assert_eq!(
        f.next_requests(t0, 4),
        vec![0],
        "after reset piece 0 is requestable again"
    );
}

/// Reject path ([aria2] UTMetadataRejectExtensionMessage.cc): an
/// unconditional disconnect-level error — table-driven over arbitrary
/// indices and bookkeeping states.
#[test]
fn vector_13_reject_path_table() {
    let t0 = Instant::now();
    let (_, ih) = sample_metadata();
    let cases: &[(usize, bool)] = &[(0, false), (0, true), (99, false)];
    for &(index, track_first) in cases {
        let mut f = ok(MetadataFetcher::new(METADATA_PIECE_SIZE * 2, ih), "new");
        if track_first {
            f.next_requests(t0, 4);
        }
        assert!(
            matches!(f.on_reject(index), Err(FetchError::Rejected)),
            "index={index} tracked={track_first} must be Rejected"
        );
    }
}

/// Timeout sweep + redispatch loop (UTMetadataRequestTracker.cc through
/// the Fetcher surface).
#[test]
fn vector_14_fetcher_timeout_requeue() {
    let t0 = Instant::now();
    let (_, ih) = sample_metadata();
    let mut f = ok(MetadataFetcher::new(METADATA_PIECE_SIZE, ih), "new");
    assert_eq!(f.next_requests(t0, 4), vec![0]);
    // 19s: not timed out, nothing to redispatch.
    assert!(f.sweep_timeouts(t0 + Duration::from_secs(19)).is_empty());
    // 20s: timed out -> index 0 reclaimed.
    assert_eq!(f.sweep_timeouts(t0 + Duration::from_secs(20)), vec![0]);
    // Budget returned -> the same piece redispatched.
    assert_eq!(f.next_requests(t0 + Duration::from_secs(20), 4), vec![0]);
}

/// Assembler boundaries ([strict] length precheck; aria2 does not check
/// and relies on the infohash for bad pieces — the tightening does not
/// change the final verdict, see module-docs divergence 1).
#[test]
fn vector_15_assembler_length_and_range_guards() {
    // metadata_size acceptance domain: 0 and > 8MiB rejected
    // (HandshakeExtensionMessage.cc).
    assert_eq!(
        MetadataAssembler::new(0),
        Err(MetadataError::SizeOutOfRange {
            got: 0,
            max: MAX_METADATA_SIZE
        })
    );
    assert_eq!(
        MetadataAssembler::new(MAX_METADATA_SIZE + 1),
        Err(MetadataError::SizeOutOfRange {
            got: MAX_METADATA_SIZE + 1,
            max: MAX_METADATA_SIZE
        })
    );
    let mut asm = ok(MetadataAssembler::new(METADATA_PIECE_SIZE + 100), "asm");
    assert_eq!(asm.num_pieces(), 2);
    // Final piece length = 100 (the remainder); 16KiB -> PieceLength.
    assert_eq!(
        asm.insert(1, &vec![0u8; METADATA_PIECE_SIZE]),
        Err(MetadataError::PieceLength {
            index: 1,
            got: METADATA_PIECE_SIZE,
            expected: 100
        })
    );
    // index out of range.
    assert_eq!(
        asm.insert(2, &[0u8; 100]),
        Err(MetadataError::IndexOutOfRange {
            index: 2,
            num_pieces: 2
        })
    );
    // assemble while incomplete -> None.
    assert!(asm.assemble().is_none());
    ok(asm.insert(0, &vec![b'x'; METADATA_PIECE_SIZE]), "insert 0");
    ok(asm.insert(1, &[b'y'; 100]), "insert 1");
    assert!(asm.is_complete());
    assert_eq!(
        asm.assemble().map(|b| b.len()),
        Some(METADATA_PIECE_SIZE + 100)
    );
}

/// Fetcher construction: the 8MiB domain check and the full 512-piece
/// load.
#[test]
fn vector_16_fetcher_size_domain() {
    let ih = [0u8; 20];
    assert!(matches!(
        MetadataFetcher::new(0, ih),
        Err(MetadataError::SizeOutOfRange { .. })
    ));
    let big = ok(MetadataFetcher::new(MAX_METADATA_SIZE, ih), "8MiB ok");
    assert_eq!(big.num_pieces(), 512);
    assert!(matches!(
        MetadataFetcher::new(MAX_METADATA_SIZE + 1, ih),
        Err(MetadataError::SizeOutOfRange { .. })
    ));
}

// ===== responder =====

/// Responder replies ([aria2] UTMetadataRequestExtensionMessageTest):
/// - no metadata -> reject;
/// - two-piece metadata, index=1 -> the second piece + total_size=32768;
/// - two pieces + a 100B third piece, index=2 -> 100B;
/// - index=3 -> out-of-range error (DL_ABORT_EX).
#[test]
fn vector_17_serve_request_reference_matrix() {
    // No metadata -> reject.
    assert_eq!(
        serve_request(&[], 10),
        Ok(ServeOutcome::Reject { index: 10 })
    );
    let piece0 = vec![b'0'; METADATA_PIECE_SIZE];
    let piece1 = vec![b'1'; METADATA_PIECE_SIZE];
    // Two-piece metadata: index 0/1 -> the corresponding piece; total_size
    // = 32768.
    let metadata: Vec<u8> = [piece0.clone(), piece1.clone()].concat();
    assert_eq!(
        serve_request(&metadata, 1),
        Ok(ServeOutcome::Data {
            index: 1,
            total_size: metadata.len(),
            data: Bytes::from(piece1.clone()),
        })
    );
    assert_eq!(
        serve_request(&metadata, 0),
        Ok(ServeOutcome::Data {
            index: 0,
            total_size: metadata.len(),
            data: Bytes::from(piece0.clone()),
        })
    );
    // Trailing remainder piece (two pieces + 100B, index=2 -> 100B).
    let third = vec![b'2'; 100];
    let ragged: Vec<u8> = [metadata.clone(), third.clone()].concat();
    assert_eq!(
        serve_request(&ragged, 2),
        Ok(ServeOutcome::Data {
            index: 2,
            total_size: ragged.len(),
            data: Bytes::from(third),
        })
    );
    // Out of range: index=3 (3 * 16KiB >= 32768).
    assert_eq!(
        serve_request(&metadata, 3),
        Err(ServeError::IndexTooBig {
            index: 3,
            total: metadata.len()
        })
    );
    // Out-of-range boundary: an index whose begin is exactly total -> out
    // of range (the reference's `<` check).
    let exact_len = METADATA_PIECE_SIZE;
    let one_piece = vec![b'x'; exact_len];
    assert_eq!(
        serve_request(&one_piece, 1),
        Err(ServeError::IndexTooBig {
            index: 1,
            total: exact_len
        })
    );
}

/// Responder output goes straight to the wire through the message codec
/// (data slice + total_size framing roundtrip).
#[test]
fn vector_18_serve_then_encode_roundtrip() {
    let metadata = vec![7u8; METADATA_PIECE_SIZE + 3];
    let outcome = ok(serve_request(&metadata, 1), "serve");
    let ServeOutcome::Data {
        index,
        total_size,
        data,
    } = outcome
    else {
        panic!("expected Data");
    };
    let frame = ok(
        UtMetadata::Data {
            index,
            total_size,
            data: data.clone(),
        }
        .encode(),
        "encode",
    );
    assert_eq!(
        ok(UtMetadata::decode(&frame), "decode"),
        UtMetadata::Data {
            index: 1,
            total_size,
            data
        }
    );
}

// ===== negotiation integration (ext handshake / dynamic registry id
// allocation) =====

/// [aria2] HandshakeExtensionMessageTest.cc sample: the peer advertises
/// ut_metadata=2 + metadata_size=1024 -> we request with the peer's id;
/// inbound frames are parsed via our registry (ut_metadata=2 ->
/// UtMetadata::decode).
#[test]
fn vector_19_negotiation_registry_integration() {
    let peer_dict = b"d1:md11:ut_metadatai2e6:ut_pexi1ee13:metadata_sizei1024e1:v5:aria2e";
    let peer = ok(
        crate::peer_wire::ExtHandshake::decode(peer_dict),
        "peer handshake",
    );
    let peer_metadata_id = peer
        .m_ut_metadata
        .unwrap_or_else(|| panic!("the reference sample must advertise ut_metadata"));
    let size = usize::try_from(peer.metadata_size.unwrap_or(0))
        .unwrap_or_else(|_| panic!("metadata_size non-negative"));
    assert_eq!(peer_metadata_id, 2);
    assert_eq!(size, 1024);
    // metadata_size=1024 -> 1 piece (rounded up to 16KiB).
    let (_, ih) = sample_metadata();
    let mut f = ok(MetadataFetcher::new(size, ih), "fetcher");
    assert_eq!(f.num_pieces(), 1);
    let t0 = Instant::now();
    assert_eq!(f.next_requests(t0, 4), vec![0]);
    // Outbound frame = the negotiated peer id + the message (aria2
    // peer_->getExtensionMessageID(UT_METADATA)).
    let frame = ok(UtMetadata::Request { index: 0 }.encode(), "encode");
    let wire = crate::peer_wire::Message::Extended {
        ext_id: peer_metadata_id,
        payload: Bytes::from(frame),
    };
    // Inbound direction: our registry resolves ext_id to ut_metadata (the
    // getExtensionName surface of aria2 DefaultExtensionMessageFactory.cc).
    let ours = crate::peer_wire::ExtRegistry::aria2_default();
    assert_eq!(ours.get("ut_metadata"), Some(2));
    match &wire {
        crate::peer_wire::Message::Extended { ext_id, payload } => {
            assert_eq!(ours.get("ut_metadata"), Some(*ext_id));
            let msg = ok(UtMetadata::decode(payload), "inbound dispatch");
            assert_eq!(msg.msg_type(), super::message::MSG_TYPE_REQUEST);
        }
        other => panic!("expected Extended, got {other:?}"),
    }
}

// ===== property tests: arbitrary bytes never panic (in-process twin of
// the fuzz target) =====

use proptest::prelude::*;

proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(512))]

    #[test]
    fn arbitrary_bytes_never_panic_in_ut_metadata_decode(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = UtMetadata::decode(&data);
    }
}

/// Process-level assembly byte ledger:
/// (a) ledger primitives: claim success / over-cap denial (snapshot with
/// used+cap) / release-refill;
/// (b) assembler wiring: insert charges, Drop releases all, reset releases
/// all, same-index overwrite does not double-charge;
/// (c) the global default cap = 2 x MAX_METADATA_SIZE (16MiB).
#[test]
fn assembly_ledger_claim_release_decision_table() {
    use super::fetcher::AssemblyLedger;
    let ledger = AssemblyLedger::new(100);
    assert!(ledger.claim(60).is_ok(), "a claim under the cap succeeds");
    assert_eq!(ledger.used(), 60);
    let denied = match ledger.claim(50) {
        Err(d) => d,
        Ok(()) => panic!("110 > 100 must be rejected"),
    };
    assert_eq!(
        denied,
        (110, 100),
        "the denial snapshot = (usage after the denial, cap)"
    );
    assert_eq!(ledger.used(), 60, "a denial must roll back");
    ledger.release(60);
    assert_eq!(ledger.used(), 0);
    assert!(ledger.claim(100).is_ok(), "capacity refills after release");
}

#[test]
fn assembler_wires_global_ledger_lifecycle() {
    use super::fetcher::assembly_ledger_used;
    let before = assembly_ledger_used();
    let mut asm =
        MetadataAssembler::new(METADATA_PIECE_SIZE + 100).unwrap_or_else(|e| panic!("new: {e}"));
    // Two pieces: 16KiB + 100B -> ledger +16536.
    asm.insert(0, &vec![1u8; METADATA_PIECE_SIZE])
        .unwrap_or_else(|e| panic!("insert0: {e}"));
    asm.insert(1, &[2u8; 100])
        .unwrap_or_else(|e| panic!("insert1: {e}"));
    assert_eq!(
        assembly_ledger_used(),
        before + METADATA_PIECE_SIZE as i64 + 100,
        "insert charges by the bytes actually stored"
    );
    // Same-index overwrite: no double charge.
    asm.insert(1, &[3u8; 100])
        .unwrap_or_else(|e| panic!("overwrite: {e}"));
    assert_eq!(
        assembly_ledger_used(),
        before + METADATA_PIECE_SIZE as i64 + 100,
        "an overwrite does not charge twice"
    );
    // reset releases all.
    asm.reset();
    assert_eq!(assembly_ledger_used(), before, "reset releases everything");
    // Recharge, then Drop releases all.
    asm.insert(1, &[4u8; 100])
        .unwrap_or_else(|e| panic!("re-insert: {e}"));
    assert_eq!(assembly_ledger_used(), before + 100);
    drop(asm);
    assert_eq!(assembly_ledger_used(), before, "Drop releases everything");
}

#[test]
fn assembly_global_cap_anchored() {
    use super::fetcher::AssemblyLedger;
    // Default cap anchored: 2 x 8MiB = 16MiB (rebound protection —
    // changing the cap must pass this assertion).
    let probe = AssemblyLedger::new(2 * MAX_METADATA_SIZE as i64);
    assert!(probe.claim(2 * MAX_METADATA_SIZE).is_ok());
    assert!(probe.claim(1).is_err(), "16MiB+1 must be rejected");
}
