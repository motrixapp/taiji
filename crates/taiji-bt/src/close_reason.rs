//! Peer-visible close reasons (`ut_close`, carried over BEP-10) and the
//! single error -> close-reason mapping table.
//!
//! # Why a stable enumeration
//!
//! Disconnect reasons previously existed only in local metrics; the peer
//! saw a plain TCP close. The `ut_close` extension carries a small
//! close-reason value to peers that negotiated it (both sides must have
//! advertised the extension in their extended-handshake `m` dict), so the
//! value table is a published contract: **values are grouped by category
//! with trailing reserved gaps and are never renumbered** — new reasons
//! take a free slot inside their group, later values never shift (the
//! reserved-gap discipline; the table shape follows the grouped error
//! tables of long-lived upstreams such as libtorrent's
//! `src/error_code.cpp`). The value table is documented for peer
//! implementers in `docs/design/peer-protocol.md`.
//!
//! # Single source
//!
//! [`close_reason_of_end`] is the ONE table from internal disconnect
//! causes ([`crate::peer::PeerEnd`], subclassifying the io error kinds)
//! to wire close reasons. The local
//! `taiji_peer_leaves_total{reason}` metric derives from the same table
//! via [`CloseReason::close_class`] (engine-side five-way projection) —
//! sent values and local counters can never disagree by construction.
//!
//! The wire format is a bencoded dict `d1:ci<value>e` (`c` = close
//! reason as an integer); unknown keys are ignored (BEP-10 extension
//! interop convention). Sending is best-effort at disconnect and is
//! gated by the runtime knob `BH_CLOSE_NOTIFY` (exactly `"0"` disables
//! advertisement and sending; default on) — with the gate off the wire
//! is bit-for-bit the pre-extension shape.

use crate::peer::PeerEnd;
use crate::peer::PeerError;

/// Our advertised `ut_close` extension name (BEP-10 m-dict key).
pub const UT_CLOSE_NAME: &str = "ut_close";

/// Close-reason value table (published contract; never renumber — see
/// the module docs). Values are explicit `u16` discriminants grouped by
/// category in blocks of ten with trailing reserved gaps:
///
/// | Group | Values | Meaning |
/// |---|---|---|
/// | local | 100..=109 | we ended the connection deliberately |
/// | transport | 110..=119 | transport-layer (io) failure |
/// | protocol | 120..=129 | the peer violated the protocol |
/// | lifecycle | 130..=139 | engine/peer lifecycle endings |
///
/// Value 0 is never sent (reserved); unknown inbound values are logged
/// with their raw number and otherwise ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
#[non_exhaustive]
pub enum CloseReason {
    // ---- local group (100..=109): we disconnected deliberately ----
    /// We closed via an explicit command (shutdown command / dropped
    /// command channel; `PeerEnd::Clean`).
    LocalShutdown = 100,
    /// We closed for a local policy reason not distinguishable on the
    /// wire (metadata fetch abort, stall-valve rotation — the local
    /// metric keeps its own finer command-point attribution; the wire
    /// face does not leak it).
    LocalPolicy = 101,
    // (102..=109 reserved: new local reasons take these slots)
    //
    // ---- transport group (110..=119): io failure ----
    /// Transport timeout (`io::ErrorKind::TimedOut`).
    IoTimedOut = 110,
    /// Connection reset (`io::ErrorKind::ConnectionReset` /
    /// `ConnectionAborted`).
    IoReset = 111,
    /// Broken pipe on write (`io::ErrorKind::BrokenPipe` / `WriteZero`).
    IoBrokenPipe = 112,
    /// Any other transport error (the residual class; the local metric
    /// does not subdivide io either).
    IoOther = 113,
    // (114..=119 reserved)
    //
    // ---- protocol group (120..=129): peer violation ----
    /// Piece index outside swarm addressing (`PeerError::BadPieceIndex`).
    BadPieceIndex = 120,
    /// Block coordinates violate wire request geometry
    /// (`PeerError::BadBlockCoords`).
    BadBlockCoords = 121,
    /// Unsolicited piece push (`PeerError::UnsolicitedPiece`).
    UnsolicitedPiece = 122,
    /// Request length over the 16KiB block cap
    /// (`PeerError::OversizeRequest`).
    OversizeRequest = 123,
    /// Requests while choked beyond the grace period
    /// (`PeerError::RequestsWhileChoked`).
    RequestsWhileChoked = 124,
    /// Client identity ban (`PeerError::ClientBanned`).
    ClientBanned = 125,
    /// Message flooding disconnect (`PeerEnd::Flooded`).
    Flooded = 126,
    // (127..=129 reserved)
    //
    // ---- lifecycle group (130..=139) ----
    /// Engine shutdown cancellation (`PeerEnd::Cancelled`; not churn).
    Cancelled = 130,
    /// The peer closed the connection normally (EOF, `PeerEnd::Closed`).
    PeerClosed = 131,
    // (132..=139 reserved)
}

impl CloseReason {
    /// Wire value (the stable published integer).
    pub fn wire_value(self) -> u16 {
        self as u16
    }

    /// Known-value decode; `None` = a value this version does not know
    /// (the caller logs the raw number — reserved-gap discipline means
    /// the value still belongs to some future release's group).
    pub fn from_wire(v: u16) -> Option<CloseReason> {
        Some(match v {
            100 => CloseReason::LocalShutdown,
            101 => CloseReason::LocalPolicy,
            110 => CloseReason::IoTimedOut,
            111 => CloseReason::IoReset,
            112 => CloseReason::IoBrokenPipe,
            113 => CloseReason::IoOther,
            120 => CloseReason::BadPieceIndex,
            121 => CloseReason::BadBlockCoords,
            122 => CloseReason::UnsolicitedPiece,
            123 => CloseReason::OversizeRequest,
            124 => CloseReason::RequestsWhileChoked,
            125 => CloseReason::ClientBanned,
            126 => CloseReason::Flooded,
            130 => CloseReason::Cancelled,
            131 => CloseReason::PeerClosed,
            _ => return None,
        })
    }

    /// The five-way local metric class (the single reconciliation point:
    /// the `taiji_peer_leaves_total{reason}` label family derives from
    /// this projection of the same table that produces the wire value —
    /// the label set itself is frozen, additive only).
    pub fn close_class(self) -> CloseClass {
        use CloseReason as R;
        match self {
            R::LocalShutdown | R::LocalPolicy => CloseClass::Local,
            R::IoTimedOut | R::IoReset | R::IoBrokenPipe | R::IoOther => CloseClass::Io,
            R::BadPieceIndex
            | R::BadBlockCoords
            | R::UnsolicitedPiece
            | R::OversizeRequest
            | R::RequestsWhileChoked
            | R::ClientBanned
            | R::Flooded => CloseClass::Protocol,
            R::Cancelled => CloseClass::Cancelled,
            R::PeerClosed => CloseClass::PeerClosed,
        }
    }

    /// Compact wire name (log faces; stable string, gap-grouped like the
    /// values — the dasherized group prefix plus the variant name).
    pub fn as_str(self) -> &'static str {
        use CloseReason as R;
        match self {
            R::LocalShutdown => "local-shutdown",
            R::LocalPolicy => "local-policy",
            R::IoTimedOut => "io-timed-out",
            R::IoReset => "io-reset",
            R::IoBrokenPipe => "io-broken-pipe",
            R::IoOther => "io-other",
            R::BadPieceIndex => "protocol-bad-piece-index",
            R::BadBlockCoords => "protocol-bad-block-coords",
            R::UnsolicitedPiece => "protocol-unsolicited-piece",
            R::OversizeRequest => "protocol-oversize-request",
            R::RequestsWhileChoked => "protocol-requests-while-choked",
            R::ClientBanned => "protocol-client-banned",
            R::Flooded => "protocol-flooded",
            R::Cancelled => "cancelled",
            R::PeerClosed => "peer-closed",
        }
    }
}

/// The five-way connection-leave classification (the local metric face;
/// frozen label family `local|peer-closed|io|protocol|cancelled`). This
/// mirrors the engine-side leave kind one to one — the engine derives
/// its counters from [`CloseReason::close_class`] so both faces of the
/// reconciliation share the single bt-side table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseClass {
    Local,
    Io,
    Protocol,
    Cancelled,
    PeerClosed,
}

/// THE mapping table: internal disconnect cause -> wire close reason.
/// Exhaustive over [`PeerEnd`] (io subclassified by
/// [`std::io::ErrorKind`]; violations exhaustive over [`PeerError`]) —
/// the exhaustiveness is the guarantee that every disconnect cause has
/// exactly one close reason. Local metrics and sent frames both derive
/// from this table (see the module docs).
pub fn close_reason_of_end(end: &PeerEnd) -> CloseReason {
    match end {
        // Clean covers the command-driven local endings (shutdown /
        // dropped command channel / metadata abort): on the wire they
        // collapse to "we shut the connection down"; the finer local
        // attribution (turnover / stall valve / metadata abort) stays
        // with the engine's command points.
        PeerEnd::Clean => CloseReason::LocalShutdown,
        PeerEnd::Cancelled => CloseReason::Cancelled,
        PeerEnd::Closed => CloseReason::PeerClosed,
        PeerEnd::Io { kind, .. } => match kind {
            std::io::ErrorKind::TimedOut => CloseReason::IoTimedOut,
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted => {
                CloseReason::IoReset
            }
            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::WriteZero => {
                CloseReason::IoBrokenPipe
            }
            _ => CloseReason::IoOther,
        },
        PeerEnd::Violation(err) => match err {
            PeerError::BadPieceIndex { .. } => CloseReason::BadPieceIndex,
            PeerError::BadBlockCoords { .. } => CloseReason::BadBlockCoords,
            PeerError::UnsolicitedPiece { .. } => CloseReason::UnsolicitedPiece,
            PeerError::OversizeRequest { .. } => CloseReason::OversizeRequest,
            PeerError::RequestsWhileChoked { .. } => CloseReason::RequestsWhileChoked,
            PeerError::ClientBanned(_) => CloseReason::ClientBanned,
        },
        PeerEnd::Flooded => CloseReason::Flooded,
    }
}

/// `ut_close` frame payload codec. Payload = bencoded dict with the
/// single key `c` (close reason, integer). Total frame body is 8 bytes
/// for three-digit values — a "small frame sent at disconnect".
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CloseFrameError {
    /// Not a bencoded dict / malformed bencode.
    #[error("malformed close frame (not a bencoded dict)")]
    Malformed,
    /// A dict, but the `c` key is missing or not an integer (a broken
    /// peer implementation; ignored, never a disconnect).
    #[error("close frame has no usable `c` reason key")]
    NoReason,
}

/// Encode the close frame payload (`d1:ci<value>e`).
pub fn encode_close_frame(reason: CloseReason) -> Result<Vec<u8>, CloseFrameError> {
    use crate::bencode::{Value, encode};
    let dict = vec![(b"c".to_vec(), Value::Int(i64::from(reason.wire_value())))];
    encode(&Value::Dict(dict)).map_err(|_| CloseFrameError::Malformed)
}

/// Decode a close frame payload to the raw wire value (unknown values
/// pass through as the raw number — reserved-gap discipline: the value
/// belongs to a future release; the caller logs it raw).
pub fn decode_close_frame(payload: &[u8]) -> Result<u16, CloseFrameError> {
    use crate::bencode::{Value, decode_permissive};
    let value = decode_permissive(payload).map_err(|_| CloseFrameError::Malformed)?;
    let Value::Dict(dict) = value else {
        return Err(CloseFrameError::Malformed);
    };
    for (key, val) in dict {
        if key.as_slice() == b"c" {
            if let Value::Int(i) = val {
                return u16::try_from(i).map_err(|_| CloseFrameError::NoReason);
            }
            return Err(CloseFrameError::NoReason);
        }
    }
    Err(CloseFrameError::NoReason)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published value table: discriminants are locked here — any
    /// change to an existing value is a contract break (never renumber;
    /// new reasons take free group slots only).
    #[test]
    fn wire_values_are_locked() {
        assert_eq!(CloseReason::LocalShutdown.wire_value(), 100);
        assert_eq!(CloseReason::LocalPolicy.wire_value(), 101);
        assert_eq!(CloseReason::IoTimedOut.wire_value(), 110);
        assert_eq!(CloseReason::IoReset.wire_value(), 111);
        assert_eq!(CloseReason::IoBrokenPipe.wire_value(), 112);
        assert_eq!(CloseReason::IoOther.wire_value(), 113);
        assert_eq!(CloseReason::BadPieceIndex.wire_value(), 120);
        assert_eq!(CloseReason::BadBlockCoords.wire_value(), 121);
        assert_eq!(CloseReason::UnsolicitedPiece.wire_value(), 122);
        assert_eq!(CloseReason::OversizeRequest.wire_value(), 123);
        assert_eq!(CloseReason::RequestsWhileChoked.wire_value(), 124);
        assert_eq!(CloseReason::ClientBanned.wire_value(), 125);
        assert_eq!(CloseReason::Flooded.wire_value(), 126);
        assert_eq!(CloseReason::Cancelled.wire_value(), 130);
        assert_eq!(CloseReason::PeerClosed.wire_value(), 131);
        // Group layout: values sit inside their decade, never on a
        // group boundary (the boundary is the reserved-gap headroom).
        for (v, group_base) in [
            (CloseReason::LocalShutdown, 100),
            (CloseReason::LocalPolicy, 100),
            (CloseReason::IoTimedOut, 110),
            (CloseReason::IoOther, 110),
            (CloseReason::BadPieceIndex, 120),
            (CloseReason::Flooded, 120),
            (CloseReason::Cancelled, 130),
            (CloseReason::PeerClosed, 130),
        ] {
            let w = v.wire_value();
            assert!(
                w >= group_base && w < group_base + 10,
                "{v:?} value {w} outside group {group_base}..{}",
                group_base + 9
            );
        }
    }

    /// Wire roundtrip: every known value decodes back; unknown values
    /// (reserved-gap slots of this or a future release) decode to None.
    #[test]
    fn from_wire_roundtrip_and_unknown() {
        for reason in [
            CloseReason::LocalShutdown,
            CloseReason::LocalPolicy,
            CloseReason::IoTimedOut,
            CloseReason::IoReset,
            CloseReason::IoBrokenPipe,
            CloseReason::IoOther,
            CloseReason::BadPieceIndex,
            CloseReason::BadBlockCoords,
            CloseReason::UnsolicitedPiece,
            CloseReason::OversizeRequest,
            CloseReason::RequestsWhileChoked,
            CloseReason::ClientBanned,
            CloseReason::Flooded,
            CloseReason::Cancelled,
            CloseReason::PeerClosed,
        ] {
            assert_eq!(CloseReason::from_wire(reason.wire_value()), Some(reason));
        }
        // Reserved-gap slots and out-of-table values are unknown but
        // well-formed (logged raw by the inbound face).
        assert_eq!(CloseReason::from_wire(0), None);
        assert_eq!(CloseReason::from_wire(102), None);
        assert_eq!(CloseReason::from_wire(109), None);
        assert_eq!(CloseReason::from_wire(114), None);
        assert_eq!(CloseReason::from_wire(127), None);
        assert_eq!(CloseReason::from_wire(132), None);
        assert_eq!(CloseReason::from_wire(139), None);
        assert_eq!(CloseReason::from_wire(999), None);
    }

    /// The ONE table, exhaustively: every PeerEnd variant (io
    /// subclassified by ErrorKind, violations by variant) maps to its
    /// documented close reason.
    #[test]
    fn close_reason_of_end_table() {
        use std::io::ErrorKind;
        let io = |kind| PeerEnd::Io {
            kind,
            message: "x".into(),
        };
        // Local / lifecycle.
        assert_eq!(
            close_reason_of_end(&PeerEnd::Clean),
            CloseReason::LocalShutdown
        );
        assert_eq!(
            close_reason_of_end(&PeerEnd::Cancelled),
            CloseReason::Cancelled
        );
        assert_eq!(
            close_reason_of_end(&PeerEnd::Closed),
            CloseReason::PeerClosed
        );
        // Transport subclassification.
        assert_eq!(
            close_reason_of_end(&io(ErrorKind::TimedOut)),
            CloseReason::IoTimedOut
        );
        assert_eq!(
            close_reason_of_end(&io(ErrorKind::ConnectionReset)),
            CloseReason::IoReset
        );
        assert_eq!(
            close_reason_of_end(&io(ErrorKind::ConnectionAborted)),
            CloseReason::IoReset
        );
        assert_eq!(
            close_reason_of_end(&io(ErrorKind::BrokenPipe)),
            CloseReason::IoBrokenPipe
        );
        assert_eq!(
            close_reason_of_end(&io(ErrorKind::WriteZero)),
            CloseReason::IoBrokenPipe
        );
        for residual in [
            ErrorKind::ConnectionRefused,
            ErrorKind::UnexpectedEof,
            ErrorKind::Other,
            ErrorKind::InvalidData,
        ] {
            assert_eq!(
                close_reason_of_end(&io(residual)),
                CloseReason::IoOther,
                "residual kind {residual:?} must class IoOther"
            );
        }
        // Protocol violations (variant-exhaustive).
        assert_eq!(
            close_reason_of_end(&PeerEnd::Violation(PeerError::BadPieceIndex { index: 9 })),
            CloseReason::BadPieceIndex
        );
        assert_eq!(
            close_reason_of_end(&PeerEnd::Violation(PeerError::BadBlockCoords {
                index: 1,
                begin: 1,
                length: 1
            })),
            CloseReason::BadBlockCoords
        );
        assert_eq!(
            close_reason_of_end(&PeerEnd::Violation(PeerError::UnsolicitedPiece {
                index: 1,
                begin: 0,
                length: 4
            })),
            CloseReason::UnsolicitedPiece
        );
        assert_eq!(
            close_reason_of_end(&PeerEnd::Violation(PeerError::OversizeRequest {
                length: 17 * 1024
            })),
            CloseReason::OversizeRequest
        );
        assert_eq!(
            close_reason_of_end(&PeerEnd::Violation(PeerError::RequestsWhileChoked {
                index: 1,
                begin: 0,
                length: 4
            })),
            CloseReason::RequestsWhileChoked
        );
        assert_eq!(
            close_reason_of_end(&PeerEnd::Violation(PeerError::ClientBanned(
                "client-ban:x".into()
            ))),
            CloseReason::ClientBanned
        );
        assert_eq!(close_reason_of_end(&PeerEnd::Flooded), CloseReason::Flooded);
    }

    /// Reconciliation: the metric projection covers every reason, each
    /// group landing on exactly one of the five frozen classes (same
    /// shape as the engine-side leave-kind lock test).
    #[test]
    fn close_class_projection_of_every_reason() {
        let rows = [
            (CloseReason::LocalShutdown, CloseClass::Local),
            (CloseReason::LocalPolicy, CloseClass::Local),
            (CloseReason::IoTimedOut, CloseClass::Io),
            (CloseReason::IoReset, CloseClass::Io),
            (CloseReason::IoBrokenPipe, CloseClass::Io),
            (CloseReason::IoOther, CloseClass::Io),
            (CloseReason::BadPieceIndex, CloseClass::Protocol),
            (CloseReason::BadBlockCoords, CloseClass::Protocol),
            (CloseReason::UnsolicitedPiece, CloseClass::Protocol),
            (CloseReason::OversizeRequest, CloseClass::Protocol),
            (CloseReason::RequestsWhileChoked, CloseClass::Protocol),
            (CloseReason::ClientBanned, CloseClass::Protocol),
            (CloseReason::Flooded, CloseClass::Protocol),
            (CloseReason::Cancelled, CloseClass::Cancelled),
            (CloseReason::PeerClosed, CloseClass::PeerClosed),
        ];
        for (reason, class) in rows {
            assert_eq!(reason.close_class(), class, "{reason:?}");
        }
    }

    /// Frame codec: encode is the documented minimal dict; decode
    /// roundtrips; unknown values pass through raw; malformed payloads
    /// and missing/non-integer keys report their error class (the
    /// inbound face ignores, never disconnects).
    #[test]
    fn close_frame_codec() {
        let bytes = encode_close_frame(CloseReason::LocalShutdown)
            .unwrap_or_else(|e| panic!("encode: {e:?}"));
        assert_eq!(bytes, b"d1:ci100ee", "minimal documented form");
        assert_eq!(decode_close_frame(&bytes), Ok(100), "roundtrip");
        // Unknown (future/reserved) value passes through raw.
        assert_eq!(decode_close_frame(b"d1:ci108ee"), Ok(108));
        // Malformed / wrong shapes.
        assert_eq!(
            decode_close_frame(b"i100e"),
            Err(CloseFrameError::Malformed)
        );
        assert_eq!(decode_close_frame(b""), Err(CloseFrameError::Malformed));
        assert_eq!(decode_close_frame(b"de"), Err(CloseFrameError::NoReason));
        assert_eq!(
            decode_close_frame(b"d1:c1:1e"),
            Err(CloseFrameError::NoReason)
        );
        assert_eq!(
            decode_close_frame(b"d1:ci-1ee"),
            Err(CloseFrameError::NoReason)
        );
        assert_eq!(
            decode_close_frame(b"d1:ci70000ee"),
            Err(CloseFrameError::NoReason)
        );
        // Unknown dict keys are ignored (BEP-10 interop convention).
        assert_eq!(
            decode_close_frame(b"d1:ci131e1:xi0ee"),
            Ok(131),
            "unknown keys ignored"
        );
    }
}
