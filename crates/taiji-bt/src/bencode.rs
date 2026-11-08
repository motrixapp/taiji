//! bencode decoding/encoding (in-house; no third-party parser in this layer).
//!
//! # Design facts
//!
//! - BEP3: bencode is the BitTorrent metadata encoding; dict keys must be in
//!   strict ascending byte order.
//! - The v1/v2 infohash must be computed over the **raw byte slice** of the
//!   `info` section in the metadata (required by BEP52); decode->re-encode
//!   round-trips are forbidden. [`decode_with_info_span`] returns the value
//!   tree and the `info` span `[start, end)` in a single parse, so callers
//!   can hash `&input[span]` directly — zero copy, no round-trip.
//!
//! # Strictness divergence from aria2
//!
//! aria2's `BencodeParser` tolerates several non-canonical inputs. taiji
//! rejects all of them: non-canonical bytes would let one logical object map
//! to several infohashes, breaking hash integrity and swarm addressing. See
//! the divergence list in `docs/design/peer-protocol.md`; test cases are
//! tagged `strict-divergence`.
//!
//! # Constant provenance
//!
//! Nesting depth cap of 50 mirrors aria2 `src/BencodeParser.cc`
//! (`stateStack_.size() >= 50` -> `ERR_STRUCTURE_TOO_DEEP`); the boundary is
//! locked by `test/ValueBaseBencodeParserTest.cc` (a 51-level list errors).

use std::ops::Range;
use std::vec::Vec;

use thiserror::Error;

/// Container (list/dict) nesting depth cap. Provenance in the module docs
/// (aria2 `BencodeParser.cc`).
pub const MAX_DEPTH: usize = 50;

/// Key of the top-level `info` section in metadata (BEP3/BEP52).
pub const INFO_KEY: &[u8] = b"info";

/// bencode value tree produced by decoding.
///
/// `Dict` entries are stored in strict ascending key order (enforced on
/// decode, and rejected on encode if out of order), so [`Value::get`] can
/// binary-search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Int(i64),
    /// Byte string; binary safe (no UTF-8 assumption, BEP3).
    Bytes(Vec<u8>),
    List(Vec<Value>),
    Dict(Vec<(Vec<u8>, Value)>),
}

impl Value {
    /// Look up `key` in a dict (binary search over the ascending entries).
    ///
    /// Precondition: entries are stored in ascending key order. Strict
    /// [`decode`] enforces this; permissive [`decode_permissive`] sorts every
    /// dict level after parsing. Binary search silently misses on unsorted
    /// input (returns `None` or the wrong entry), so the invariant is guarded
    /// by a debug assertion here.
    pub fn get(&self, key: &[u8]) -> Option<&Value> {
        match self {
            Value::Dict(pairs) => {
                debug_assert!(
                    pairs.windows(2).all(|w| w[0].0 <= w[1].0),
                    "Value::get requires ascending dict keys (decode guarantees; hand-built Values must be sorted)"
                );
                pairs
                    .binary_search_by(|(k, _)| k.as_slice().cmp(key))
                    .ok()
                    .map(|i| &pairs[i].1)
            }
            _ => None,
        }
    }

    /// The `Int` payload (`i64`); `None` for any other variant.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// The `Bytes` payload as a raw byte slice; `None` for any other
    /// variant.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// The `List` payload as a value slice; `None` for any other variant.
    pub fn as_list(&self) -> Option<&[Value]> {
        match self {
            Value::List(l) => Some(l),
            _ => None,
        }
    }

    /// The `Dict` payload as its `(key, value)` pairs (decode keeps them
    /// key-ascending, the [`Value::get`] contract); `None` for any other
    /// variant.
    pub fn as_dict(&self) -> Option<&[(Vec<u8>, Value)]> {
        match self {
            Value::Dict(d) => Some(d),
            _ => None,
        }
    }
}

/// Decode/encode error. `pos` is a byte offset in the input (an entry index
/// for `UnsortedDictKeys`).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum BencodeError {
    #[error("unexpected end of input at offset {pos}")]
    Eof { pos: usize },
    #[error("trailing bytes after complete top-level value at offset {pos}")]
    Trailing { pos: usize },
    /// Malformed integer: empty digits, non-digit characters, leading zeros,
    /// `-0`.
    #[error("invalid integer at offset {pos}")]
    Integer { pos: usize },
    /// Value out of i64 range (matches aria2 `ERR_NUMBER_OUT_OF_RANGE`,
    /// `BencodeParser.cc`).
    #[error("integer out of i64 range at offset {pos}")]
    IntegerOverflow { pos: usize },
    /// Invalid string length: empty, leading zeros, non-digits, overflow
    /// (matches aria2 `ERR_STRING_LENGTH_OUT_OF_RANGE`, `BencodeParser.cc`).
    #[error("invalid string length at offset {pos}")]
    StringLength { pos: usize },
    #[error("byte {byte:#04x} not expected at offset {pos}")]
    UnexpectedByte { pos: usize, byte: u8 },
    /// Container nesting exceeds [`MAX_DEPTH`] (mirrors aria2
    /// `ERR_STRUCTURE_TOO_DEEP`, `BencodeParser.cc`).
    #[error("nesting deeper than {max} at offset {pos}")]
    TooDeep { pos: usize, max: usize },
    /// dict keys not in strict ascending order (out of order or duplicate;
    /// BEP3 canonical requirement).
    #[error("dict keys not in strict ascending order at offset {pos}")]
    DictKeyOrder { pos: usize },
    #[error("cannot encode: dict keys not in strict ascending order at entry {pos}")]
    UnsortedDictKeys { pos: usize },
    /// Top-level value is not a dict containing an `info` key; the info
    /// section cannot be sliced out.
    #[error("top-level value is not a dict containing an `info` key")]
    MissingInfoKey,
}

/// Internal parse tree: dict entries additionally carry the raw byte range of
/// their value, so [`decode_with_info_span`] can slice out the info section.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Parsed {
    Int(i64),
    Bytes(Vec<u8>),
    List(Vec<Parsed>),
    /// (key, value, raw byte range of the value).
    Dict(Vec<(Vec<u8>, Parsed, Range<usize>)>),
}

impl Parsed {
    fn into_value(self) -> Value {
        match self {
            Parsed::Int(i) => Value::Int(i),
            Parsed::Bytes(b) => Value::Bytes(b),
            Parsed::List(l) => Value::List(l.into_iter().map(Parsed::into_value).collect()),
            Parsed::Dict(d) => {
                Value::Dict(d.into_iter().map(|(k, v, _)| (k, v.into_value())).collect())
            }
        }
    }
}

/// Strictly decode a single bencode value; any trailing bytes are an error.
pub fn decode(input: &[u8]) -> Result<Value, BencodeError> {
    let (value, end) = parse_once(input)?;
    if end != input.len() {
        return Err(BencodeError::Trailing { pos: end });
    }
    Ok(value.into_value())
}

/// Strictly decode and additionally return the raw byte range of the `info`
/// value in the top-level dict (BEP52 requires the infohash to be computed
/// over the raw slice).
///
/// - The top level must be a dict containing an `info` key, otherwise
///   [`BencodeError::MissingInfoKey`];
/// - the `info` value itself need not be a dict (corrupt input is rejected by
///   higher-level validation; this returns its span as-is);
/// - a BEP9 ut_metadata payload is the info dict itself, so it does not go
///   through this API — hash the whole payload directly.
pub fn decode_with_info_span(input: &[u8]) -> Result<(Value, Range<usize>), BencodeError> {
    let (parsed, end) = parse_once(input)?;
    if end != input.len() {
        return Err(BencodeError::Trailing { pos: end });
    }
    let info_span = match &parsed {
        Parsed::Dict(entries) => {
            match entries.binary_search_by(|(k, _, _)| k.as_slice().cmp(INFO_KEY)) {
                Ok(i) => entries[i].2.clone(),
                Err(_) => return Err(BencodeError::MissingInfoKey),
            }
        }
        _ => return Err(BencodeError::MissingInfoKey),
    };
    Ok((parsed.into_value(), info_span))
}

/// Permissive decode (peer-message path): the only difference from [`decode`]
/// is that dict keys are not required to be in strict ascending order.
/// Rationale: peer-controlled dicts such as the BEP10 extended handshake and
/// PEX are not sorted by real clients (aria2's own handshake sample puts
/// `1:v` before `1:md`, see `HandshakeExtensionMessageTest.cc`), and
/// enforcing order there would mis-reject valid traffic (interop defect).
/// The metainfo/infohash path must use [`decode`], which stays strict.
///
/// Safety: permissive parsing accepts dicts in any order at any depth, while
/// [`Value::get`] binary search relies on ascending entries — unsorted output
/// would silently miss. This function therefore sorts Dict entries at **every**
/// level after parsing, so permissive output satisfies the same invariant as
/// strict output (for inputs without duplicate keys, the sorted tree can be
/// written back verbatim by [`encode`]). Duplicate keys are kept (permissive
/// semantics; adjacent after sorting, [`Value::get`] hits one of them, and
/// [`encode`] still rejects them).
pub fn decode_permissive(input: &[u8]) -> Result<Value, BencodeError> {
    let (mut value, end) = parse_once_with(input, true)?;
    if end != input.len() {
        return Err(BencodeError::Trailing { pos: end });
    }
    sort_parsed_dicts(&mut value);
    Ok(value.into_value())
}

/// Recursively sort the Dict entries of the internal tree at every level
/// (ascending by key; nested dicts included).
fn sort_parsed_dicts(value: &mut Parsed) {
    match value {
        Parsed::List(items) => items.iter_mut().for_each(sort_parsed_dicts),
        Parsed::Dict(entries) => {
            entries
                .iter_mut()
                .for_each(|(_, v, _)| sort_parsed_dicts(v));
            entries.sort_by(|a, b| a.0.cmp(&b.0));
        }
        Parsed::Int(_) | Parsed::Bytes(_) => {}
    }
}

/// Encode as canonical bencode: dict keys must be in strict ascending order
/// (out of order is an error, never silently reordered — bytes this encoder
/// produces are always valid infohash input).
pub fn encode(value: &Value) -> Result<Vec<u8>, BencodeError> {
    let mut out = Vec::new();
    encode_into(value, &mut out)?;
    Ok(out)
}

fn encode_into(value: &Value, out: &mut Vec<u8>) -> Result<(), BencodeError> {
    match value {
        Value::Int(i) => {
            out.push(b'i');
            push_i64(out, *i);
            out.push(b'e');
        }
        Value::Bytes(b) => {
            push_usize(out, b.len());
            out.push(b':');
            out.extend_from_slice(b);
        }
        Value::List(items) => {
            out.push(b'l');
            for item in items {
                encode_into(item, out)?;
            }
            out.push(b'e');
        }
        Value::Dict(pairs) => {
            out.push(b'd');
            for (i, (k, v)) in pairs.iter().enumerate() {
                if i > 0 && pairs[i - 1].0.as_slice() >= k.as_slice() {
                    return Err(BencodeError::UnsortedDictKeys { pos: i });
                }
                push_usize(out, k.len());
                out.push(b':');
                out.extend_from_slice(k);
                encode_into(v, out)?;
            }
            out.push(b'e');
        }
    }
    Ok(())
}

fn push_i64(out: &mut Vec<u8>, v: i64) {
    if v < 0 {
        out.push(b'-');
    }
    push_u64(out, v.unsigned_abs());
}

fn push_u64(out: &mut Vec<u8>, mut v: u64) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    out.extend_from_slice(&buf[i..]);
}

fn push_usize(out: &mut Vec<u8>, v: usize) {
    match u64::try_from(v) {
        Ok(x) => push_u64(out, x),
        // usize > u64 only exists on theoretical 16-bit platforms; saturate
        // instead of panicking.
        Err(_) => push_u64(out, u64::MAX),
    }
}

/// Parse one top-level value; returns (internal tree, end offset of the value).
fn parse_once(input: &[u8]) -> Result<(Parsed, usize), BencodeError> {
    parse_once_with(input, false)
}

fn parse_once_with(input: &[u8], permissive: bool) -> Result<(Parsed, usize), BencodeError> {
    let mut parser = Parser {
        input,
        pos: 0,
        permissive,
    };
    let (value, _) = parser.parse_value(1)?;
    Ok((value, parser.pos))
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
    /// Peer-message path (BEP10/PEX etc.): do not enforce ascending dict
    /// keys. Real clients — aria2 included — send extended handshakes with
    /// unsorted top-level keys; enforcing order would mis-reject them. The
    /// metainfo path still goes through strict decode.
    permissive: bool,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    /// Returns (value, raw byte range of the value; the range end includes
    /// the terminator).
    fn parse_value(&mut self, depth: usize) -> Result<(Parsed, Range<usize>), BencodeError> {
        if depth > MAX_DEPTH {
            return Err(BencodeError::TooDeep {
                pos: self.pos,
                max: MAX_DEPTH,
            });
        }
        match self.peek() {
            Some(b'i') => self.parse_integer(),
            Some(b'l') => self.parse_list(depth),
            Some(b'd') => self.parse_dict(depth),
            Some(b'0'..=b'9') => self.parse_string(),
            Some(byte) => Err(BencodeError::UnexpectedByte {
                pos: self.pos,
                byte,
            }),
            None => Err(BencodeError::Eof { pos: self.pos }),
        }
    }

    /// Strict integer: `i[-]?[0-9]+e`, no leading zeros, `-0` rejected, must
    /// fit in i64. For aria2's tolerated variants (floats ignored, leading
    /// zeros, `-0`) see the module docs.
    fn parse_integer(&mut self) -> Result<(Parsed, Range<usize>), BencodeError> {
        let start = self.pos;
        self.pos += 1; // 'i'
        let negative = match self.peek() {
            Some(b'-') => {
                self.pos += 1;
                true
            }
            _ => false,
        };
        let digits_start = self.pos;
        let mut acc: u64 = 0;
        while let Some(b @ b'0'..=b'9') = self.peek() {
            self.pos += 1;
            acc = acc
                .checked_mul(10)
                .and_then(|a| a.checked_add(u64::from(b - b'0')))
                .ok_or(BencodeError::IntegerOverflow { pos: start })?;
        }
        let digits_len = self.pos - digits_start;
        if digits_len == 0 || (digits_len > 1 && self.input[digits_start] == b'0') {
            return Err(BencodeError::Integer { pos: start });
        }
        match self.peek() {
            Some(b'e') => self.pos += 1,
            Some(_) => return Err(BencodeError::Integer { pos: start }),
            None => return Err(BencodeError::Eof { pos: self.pos }),
        }
        let value = if negative {
            if acc == 0 {
                return Err(BencodeError::Integer { pos: start }); // -0 is invalid
            }
            if acc <= i64::MAX as u64 {
                -(acc as i64)
            } else if acc == (i64::MAX as u64) + 1 {
                i64::MIN
            } else {
                return Err(BencodeError::IntegerOverflow { pos: start });
            }
        } else if acc <= i64::MAX as u64 {
            acc as i64
        } else {
            return Err(BencodeError::IntegerOverflow { pos: start });
        };
        Ok((Parsed::Int(value), start..self.pos))
    }

    /// Strict string length: `<len>:<bytes>`, decimal length without leading
    /// zeros or overflow; all payload bytes must be present.
    fn parse_string(&mut self) -> Result<(Parsed, Range<usize>), BencodeError> {
        let start = self.pos;
        let digits_start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        let digits = &self.input[digits_start..self.pos];
        if digits.is_empty() || (digits.len() > 1 && digits[0] == b'0') {
            return Err(BencodeError::StringLength { pos: start });
        }
        let mut len: u64 = 0;
        for &d in digits {
            len = len
                .checked_mul(10)
                .and_then(|l| l.checked_add(u64::from(d - b'0')))
                .ok_or(BencodeError::StringLength { pos: start })?;
        }
        match self.peek() {
            Some(b':') => self.pos += 1,
            Some(_) => return Err(BencodeError::StringLength { pos: start }),
            None => return Err(BencodeError::Eof { pos: self.pos }),
        }
        let remaining = self.input.len() - self.pos;
        let Ok(len) = usize::try_from(len) else {
            return Err(BencodeError::StringLength { pos: start });
        };
        if len > remaining {
            return Err(BencodeError::Eof {
                pos: self.input.len(),
            });
        }
        let data = self.input[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok((Parsed::Bytes(data), start..self.pos))
    }

    fn parse_list(&mut self, depth: usize) -> Result<(Parsed, Range<usize>), BencodeError> {
        let start = self.pos;
        self.pos += 1; // 'l'
        let mut items = Vec::new();
        loop {
            match self.peek() {
                Some(b'e') => {
                    self.pos += 1;
                    return Ok((Parsed::List(items), start..self.pos));
                }
                Some(_) => {
                    let (v, _) = self.parse_value(depth + 1)?;
                    items.push(v);
                }
                None => return Err(BencodeError::Eof { pos: self.pos }),
            }
        }
    }

    fn parse_dict(&mut self, depth: usize) -> Result<(Parsed, Range<usize>), BencodeError> {
        let start = self.pos;
        self.pos += 1; // 'd'
        let mut entries: Vec<(Vec<u8>, Parsed, Range<usize>)> = Vec::new();
        loop {
            match self.peek() {
                Some(b'e') => {
                    self.pos += 1;
                    return Ok((Parsed::Dict(entries), start..self.pos));
                }
                Some(_) => {
                    let key_start = self.pos;
                    let key = match self.parse_value(depth + 1)? {
                        (Parsed::Bytes(b), _) => b,
                        (_, _) => {
                            return Err(BencodeError::UnexpectedByte {
                                pos: key_start,
                                byte: self.input[key_start],
                            });
                        }
                    };
                    if let Some((prev, _, _)) = entries.last()
                        && !self.permissive
                        && prev.as_slice() >= key.as_slice()
                    {
                        return Err(BencodeError::DictKeyOrder { pos: key_start });
                    }
                    let (value, span) = self.parse_value(depth + 1)?;
                    entries.push((key, value, span));
                }
                None => return Err(BencodeError::Eof { pos: self.pos }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use std::vec;

    use super::*;

    // Test-vector tags:
    // - `aria2 <test file>` = vector taken from that aria2 test file;
    // - [strict-divergence] = aria2 tolerates the input, taiji rejects it by
    // design (see the module docs);
    // - [strict] = canonical-bencode strictness case (BEP3) with no upstream
    // counterpart.

    fn dec(input: &[u8]) -> Value {
        match decode(input) {
            Ok(v) => v,
            Err(e) => panic!("decode({input:?}) unexpectedly failed: {e:?}"),
        }
    }

    fn dec_err(input: &[u8]) -> BencodeError {
        match decode(input) {
            Ok(v) => panic!("decode({input:?}) unexpectedly succeeded: {v:?}"),
            Err(e) => e,
        }
    }

    fn enc(value: &Value) -> Vec<u8> {
        match encode(value) {
            Ok(b) => b,
            Err(e) => panic!("encode({value:?}) unexpectedly failed: {e:?}"),
        }
    }

    fn bytes(b: &[u8]) -> Value {
        Value::Bytes(b.to_vec())
    }

    fn list(items: Vec<Value>) -> Value {
        Value::List(items)
    }

    fn dict(pairs: Vec<(&[u8], Value)>) -> Value {
        Value::Dict(pairs.into_iter().map(|(k, v)| (k.to_vec(), v)).collect())
    }

    /// Valid-input matrix: upstream vectors, provenance noted per case.
    #[test]
    fn decode_accepts_canonical_inputs() {
        let cases: Vec<(&[u8], Value)> = vec![
            // aria2 ValueBaseBencodeParserTest.cc
            (b"0:", bytes(b"")),
            (b"i0e", Value::Int(0)),
            (b"de", dict(vec![])),
            (b"le", list(vec![])),
            (b"3:foo", bytes(b"foo")),
            // i64 upper bound
            (b"i9223372036854775807e", Value::Int(i64::MAX)),
            // [strict] i64 lower bound. aria2 accumulates the magnitude after
            // the sign and cannot express i64::MIN (src/BencodeParser.cc);
            // this decoder covers the full i64 domain.
            (b"i-9223372036854775808e", Value::Int(i64::MIN)),
            (b"d3:fooi123ee", dict(vec![(b"foo", Value::Int(123))])),
            (b"l3:fooe", list(vec![bytes(b"foo")])),
            (b"l3:fooi123ee", list(vec![bytes(b"foo"), Value::Int(123)])),
            (
                b"ld1:ki123eee",
                list(vec![dict(vec![(b"k", Value::Int(123))])]),
            ),
            // empty key is valid (smallest in byte order)
            (b"d0:1:ve", dict(vec![(b"", bytes(b"v"))])),
            (b"d0:i123ee", dict(vec![(b"", Value::Int(123))])),
            // The original upstream vector orders its keys name/size/files
            // (unsorted; see the strict-divergence entry in
            // decode_rejects_malformed_inputs); this is the canonical
            // re-ordering of the same logical object.
            (
                b"d5:filesl3:bin3:doce4:name5:aria24:sizei12345678900ee",
                dict(vec![
                    (b"files", list(vec![bytes(b"bin"), bytes(b"doc")])),
                    (b"name", bytes(b"aria2")),
                    (b"size", Value::Int(12_345_678_900)),
                ]),
            ),
            // aria2 Bencode2Test.cc encode vector (decodes back identically)
            (
                b"d5:attrsd7:license3:GPLe5:filesl6:aria2ce3:loci80000e4:name5:aria2e",
                dict(vec![
                    (b"attrs", dict(vec![(b"license", bytes(b"GPL"))])),
                    (b"files", list(vec![bytes(b"aria2c")])),
                    (b"loc", Value::Int(80_000)),
                    (b"name", bytes(b"aria2")),
                ]),
            ),
            // [strict] binary safe: non-UTF-8 bytes preserved verbatim
            // (BEP3; no UTF-8 assumption)
            (b"3:\x00\xff\x80", bytes(&[0x00, 0xff, 0x80])),
            // [strict] binary dict key
            (b"d1:\xffi1ee", dict(vec![(&[0xffu8][..], Value::Int(1))])),
        ];
        for (input, expected) in cases {
            assert_eq!(dec(input), expected, "input = {input:?}");
        }
    }

    /// Malformed-input matrix, with strict-divergence tags where taiji is
    /// stricter than aria2.
    #[test]
    fn decode_permissive_accepts_unsorted_keys() {
        // Interop: aria2's own BEP10 extended handshake has unsorted
        // top-level keys (HandshakeExtensionMessageTest.cc, `1:v` before
        // `1:md`). The permissive path accepts it; the strict path still
        // rejects it (unchanged).
        let unsorted = b"d1:v5:aria21:md6:ut_pexi1eee";
        assert!(super::decode_permissive(unsorted).is_ok());
        assert!(super::decode(unsorted).is_err());
        // Other strictness (trailing garbage) unchanged.
        let trailing = b"d1:v5:aria21:md6:ut_pexi1eeeX";
        assert!(super::decode_permissive(trailing).is_err());
    }

    /// Regression for the safety hardening: permissive output could be
    /// unsorted while `Value::get` binary search relies on ascending entries
    /// — unsorted dicts used to miss silently (returning None / the wrong
    /// entry). decode_permissive now sorts every level.
    #[test]
    fn decode_permissive_output_sorted_for_binary_search() {
        // Top level unsorted ("m" after "v" = descending) plus a nested dict
        // unsorted ("zzzzzz" before "aaa" = descending); permissive checks
        // no level's order.
        // raw = d{"v":"aria2", "m": d{"zzzzzz":1, "aaa":2}}
        let raw = b"d1:v5:aria21:md6:zzzzzzi1e3:aaai2eee";
        let v = match super::decode_permissive(raw) {
            Ok(x) => x,
            Err(e) => panic!("decode_permissive failed: {e:?}"),
        };
        // Top-level hit (before sorting, binary search missed "m": mid lands
        // on "v" -> shrink left -> None).
        let md = match v.get(b"m") {
            Some(x) => x,
            None => panic!("key m must be found after sort (binary search precondition)"),
        };
        // Nested level is sorted and hit too (unsorted would miss "aaa").
        assert_eq!(
            md.get(b"aaa"),
            Some(&Value::Int(2)),
            "nested keys hit after sort"
        );
        assert_eq!(
            md.get(b"zzzzzz"),
            Some(&Value::Int(1)),
            "nested keys hit after sort"
        );
        assert_eq!(v.get(b"v"), Some(&bytes(b"aria2")));
        // The sorted tree is canonical: encodable as-is (no duplicate keys).
        assert!(
            encode(&v).is_ok(),
            "sorted permissive output must be canonical-encodable"
        );
        // Duplicate keys: kept under the permissive semantics (adjacent after
        // sorting, get hits one of them); encode still rejects.
        let dup = match super::decode_permissive(b"d1:ki1e1:ki2ee") {
            Ok(x) => x,
            Err(e) => panic!("decode_permissive(dup) failed: {e:?}"),
        };
        assert!(matches!(dup.get(b"k"), Some(&Value::Int(_))));
        assert!(
            encode(&dup).is_err(),
            "duplicate keys must not enter canonical encoding"
        );
        // Strict path unaffected: out-of-order still rejected.
        assert!(super::decode(raw).is_err());
    }

    #[test]
    fn decode_rejects_malformed_inputs() {
        let cases: Vec<(&[u8], BencodeError)> = vec![
            // [strict-divergence] aria2 returns "no value" for empty input
            // (ValueBaseBencodeParserTest.cc); taiji requires exactly one
            // top-level value.
            (b"", BencodeError::Eof { pos: 0 }),
            // aria2 vector: missing 'e'
            (b"i3", BencodeError::Eof { pos: 2 }),
            (b"d", BencodeError::Eof { pos: 1 }),
            (b"l", BencodeError::Eof { pos: 1 }),
            // aria2 vector: not enough payload bytes
            (b"3:ab", BencodeError::Eof { pos: 4 }),
            (
                b"x:abc",
                BencodeError::UnexpectedByte { pos: 0, byte: b'x' },
            ),
            // aria2 vector: negative length notation
            (b"-1:a", BencodeError::UnexpectedByte { pos: 0, byte: b'-' }),
            (b"ixe", BencodeError::Integer { pos: 0 }),
            (b"ie", BencodeError::Integer { pos: 0 }),
            // Rejected by both, for different reasons (aria2's float branch
            // hits the bad character).
            (b"i-1.134a+33e", BencodeError::Integer { pos: 0 }),
            // [strict-divergence] aria2 accepts floats in the integer field
            // and yields 0 (ValueBaseBencodeParserTest.cc,
            // src/BencodeParser.cc).
            (b"i+343243.342E-1333e", BencodeError::Integer { pos: 0 }),
            // [strict-divergence] aria2 ignores trailing garbage and reports
            // the position (ValueBaseBencodeParserTest.cc).
            (b"5:aria2trail", BencodeError::Trailing { pos: 7 }),
            // [strict] trailing garbage in integer form
            (b"i0ei0e", BencodeError::Trailing { pos: 3 }),
            // [strict-divergence] aria2 accepts unsorted keys (its Dict is a
            // sorted map and silently reorders).
            (
                b"d3:fooi123e3:bar1:ee",
                BencodeError::DictKeyOrder { pos: 11 },
            ),
            // [strict-divergence] same as above
            (
                b"d4:name5:aria24:sizei12345678900e5:filesl3:bin3:docee",
                BencodeError::DictKeyOrder { pos: 33 },
            ),
            // [strict] duplicate keys (BEP3 requires uniqueness; aria2 does
            // not check)
            (b"d1:ki1e1:ki2ee", BencodeError::DictKeyOrder { pos: 7 }),
            // [strict-divergence] leading-zero integer: aria2 accepts as 1
            (b"i01e", BencodeError::Integer { pos: 0 }),
            // [strict-divergence] -0: aria2 accepts as 0
            (b"i-0e", BencodeError::Integer { pos: 0 }),
            // [strict-divergence] leading-zero string length: aria2 accepts
            (b"03:foo", BencodeError::StringLength { pos: 0 }),
            // [strict] missing ':' after the length
            (b"1e", BencodeError::StringLength { pos: 0 }),
            // aria2: i64 overflow (src/BencodeParser.cc
            // ERR_NUMBER_OUT_OF_RANGE)
            (
                b"i9223372036854775808e",
                BencodeError::IntegerOverflow { pos: 0 },
            ),
            // [strict] negative overflow (aria2 errors too)
            (
                b"i-9223372036854775809e",
                BencodeError::IntegerOverflow { pos: 0 },
            ),
            // aria2: string length overflow (src/BencodeParser.cc
            // ERR_STRING_LENGTH_OUT_OF_RANGE)
            (
                b"99999999999999999999:ab",
                BencodeError::StringLength { pos: 0 },
            ),
            // dict value missing / list value missing / dict key not a string
            (b"d3:fooi123e", BencodeError::Eof { pos: 11 }),
            (b"l3:foo", BencodeError::Eof { pos: 6 }),
            (
                b"di1ei1ee",
                BencodeError::UnexpectedByte { pos: 1, byte: b'i' },
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(dec_err(input), expected, "input = {input:?}");
        }
    }

    /// Depth-limit boundary (aria2 ValueBaseBencodeParserTest.cc +
    /// src/BencodeParser.cc).
    #[test]
    fn depth_limit_matches_aria2() {
        let ok = "l".repeat(50) + &"e".repeat(50);
        assert!(matches!(dec(ok.as_bytes()), Value::List(_)));
        let too_deep = "l".repeat(51) + &"e".repeat(51);
        assert_eq!(
            dec_err(too_deep.as_bytes()),
            BencodeError::TooDeep { pos: 50, max: 50 }
        );
        // A 50-level list wrapping a dict: aria2 errors too (its state stack
        // counts the dict).
        let deep_dict = "l".repeat(50) + "d3:fooi100ee" + &"e".repeat(50);
        assert!(matches!(
            dec_err(deep_dict.as_bytes()),
            BencodeError::TooDeep { .. }
        ));
    }

    /// Encoding: aria2 Bencode2Test.cc forward vector + canonical-only
    /// constraint.
    #[test]
    fn encode_matches_aria2_vector() {
        // Same logical object as Bencode2Test, constructed in its original
        // insertion order (unsorted).
        let unsorted = dict(vec![
            (b"name", bytes(b"aria2")),
            (b"loc", Value::Int(80_000)),
            (b"files", list(vec![bytes(b"aria2c")])),
            (b"attrs", dict(vec![(b"license", bytes(b"GPL"))])),
        ]);
        assert_eq!(
            encode(&unsorted),
            Err(BencodeError::UnsortedDictKeys { pos: 1 })
        );
        let sorted = dict(vec![
            (b"attrs", dict(vec![(b"license", bytes(b"GPL"))])),
            (b"files", list(vec![bytes(b"aria2c")])),
            (b"loc", Value::Int(80_000)),
            (b"name", bytes(b"aria2")),
        ]);
        assert_eq!(
            enc(&sorted),
            b"d5:attrsd7:license3:GPLe5:filesl6:aria2ce3:loci80000e4:name5:aria2e".to_vec()
        );
    }

    /// Encode idempotence: for all canonical inputs, encode(decode(x)) == x.
    #[test]
    fn encode_decode_roundtrip_on_canonical_inputs() {
        let inputs: [&[u8]; 8] = [
            b"0:",
            b"i0e",
            b"i-9223372036854775808e",
            b"i9223372036854775807e",
            b"d3:fooi123ee",
            b"ld1:ki123eee",
            b"3:\x00\xff\x80",
            b"d5:attrsd7:license3:GPLe5:filesl6:aria2ce3:loci80000e4:name5:aria2e",
        ];
        for input in inputs {
            let value = dec(input);
            assert_eq!(enc(&value), input.to_vec(), "input = {input:?}");
        }
    }

    /// A Value built with duplicate keys is likewise rejected by encode
    /// (canonical-only).
    #[test]
    fn encode_rejects_duplicate_keys() {
        let v = dict(vec![(b"a", Value::Int(1)), (b"a", Value::Int(2))]);
        assert_eq!(encode(&v), Err(BencodeError::UnsortedDictKeys { pos: 1 }));
    }

    /// Value::get binary search (relies on the strict-ascending invariant).
    #[test]
    fn dict_lookup_is_binary_search() {
        let v = dec(b"d1:ai1e1:bi2e2:\xc3\xa9i3ee");
        assert_eq!(v.get(b"a"), Some(&Value::Int(1)));
        assert_eq!(v.get(b"b"), Some(&Value::Int(2)));
        assert_eq!(v.get(b"\xc3\xa9"), Some(&Value::Int(3)));
        assert_eq!(v.get(b"c"), None);
        assert_eq!(v.get(b""), None);
        assert_eq!(Value::Int(1).get(b"a"), None);
    }

    /// RawInfoSlice: the info span must cover exactly the raw bytes.
    #[test]
    fn info_span_covers_raw_info_bytes() {
        let torrent = b"d8:announce3:abc4:infod6:lengthi3e4:name3:abcee";
        let (value, span) = match decode_with_info_span(torrent) {
            Ok(x) => x,
            Err(e) => panic!("decode_with_info_span failed: {e:?}"),
        };
        assert_eq!(span, 22..46);
        assert_eq!(&torrent[span.clone()], &b"d6:lengthi3e4:name3:abce"[..]);
        // The value tree matches the raw slice contents (no drift from a
        // re-encode round-trip).
        assert_eq!(
            value.get(b"info"),
            Some(&dict(vec![
                (b"length", Value::Int(3)),
                (b"name", bytes(b"abc")),
            ]))
        );
    }

    #[test]
    fn info_span_requires_top_level_info_key() {
        // Top level has no info key.
        assert_eq!(
            decode_with_info_span(b"d4:name5:aria2e"),
            Err(BencodeError::MissingInfoKey)
        );
        // Top level is not a dict.
        assert_eq!(
            decode_with_info_span(b"i1e"),
            Err(BencodeError::MissingInfoKey)
        );
        // info nested inside a list does not count.
        assert_eq!(
            decode_with_info_span(b"d4:listld4:infoi1eeee"),
            Err(BencodeError::MissingInfoKey)
        );
        // info value not a dict: return its span as-is (corrupt input is
        // rejected by higher-level metadata validation).
        let (value, span) = match decode_with_info_span(b"d4:infoi1ee") {
            Ok(x) => x,
            Err(e) => panic!("unexpected: {e:?}"),
        };
        assert_eq!(span, 7..10);
        assert_eq!(value.get(b"info"), Some(&Value::Int(1)));
    }

    // ===== property tests =====

    fn arb_leaf() -> impl Strategy<Value = Value> {
        prop_oneof![
            any::<i64>().prop_map(Value::Int),
            prop::collection::vec(any::<u8>(), 0..64).prop_map(Value::Bytes),
        ]
    }

    /// Generator for arbitrary encodable Values: dicts use BTreeMap (keys
    /// naturally unique and ascending), matching the decoder's
    /// strict-ascending invariant.
    fn arb_value() -> impl Strategy<Value = Value> {
        arb_leaf().prop_recursive(6, 128, 8, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..8).prop_map(Value::List),
                prop::collection::btree_map(prop::collection::vec(any::<u8>(), 0..16), inner, 0..8)
                    .prop_map(|m| Value::Dict(m.into_iter().collect())),
            ]
        })
    }

    proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(1024))]

        #[test]
        fn arbitrary_bytes_never_panic(data in prop::collection::vec(any::<u8>(), 0..4096)) {
            let _ = decode(&data);
            let _ = decode_with_info_span(&data);
        }

        #[test]
        fn encode_decode_roundtrip(v in arb_value()) {
            let encoded = enc(&v);
            let decoded = match decode(&encoded) {
                Ok(d) => d,
                Err(e) => panic!("decode of canonical encoding failed: {e:?}"),
            };
            prop_assert_eq!(&decoded, &v);
            // Re-encoding is stable at the same canonical bytes.
            prop_assert_eq!(enc(&decoded), encoded);
        }
    }
}
