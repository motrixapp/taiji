//! ut_metadata three-message (request/data/reject) codec + responder
//! decision.
//!
//! Encoding is byte-for-byte the aria2 `getPayload` implementations
//! (vectors: `UTMetadataRequestExtensionMessageTest.cc` /
//! `UTMetadataDataExtensionMessageTest.cc` /
//! `UTMetadataRejectExtensionMessageTest.cc`); decoding mirrors
//! `DefaultExtensionMessageFactory.cc` (msg_type dispatch and negative
//! cases).
//!
//! The data frame shape = bencode dict + **raw piece bytes** (the end of
//! the dict value is the data start; encoded by
//! `UTMetadataDataExtensionMessage.cc`, decoded by
//! `DefaultExtensionMessageFactory.cc` via its `end` out-param). This
//! codebase's frozen `bencode` surface has no "prefix parse" exit, so the
//! in-frame offset is scanned by [`value_end`] per the BEP3 syntax
//! (covered by a fuzz target).

use bytes::Bytes;
use thiserror::Error;

use crate::bencode::{self, Value};
use crate::ut_metadata::{METADATA_PIECE_SIZE, UtMetadataError};

/// msg_type = request (`UTMetadataRequestExtensionMessage.cc`).
pub const MSG_TYPE_REQUEST: i64 = 0;
/// msg_type = data (`UTMetadataDataExtensionMessage.cc`).
pub const MSG_TYPE_DATA: i64 = 1;
/// msg_type = reject (`UTMetadataRejectExtensionMessage.cc`).
pub const MSG_TYPE_REJECT: i64 = 2;

/// One ut_metadata message (already dispatched by msg_type).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UtMetadata {
    Request {
        index: usize,
    },
    Data {
        index: usize,
        total_size: usize,
        data: Bytes,
    },
    Reject {
        index: usize,
    },
}

impl UtMetadata {
    pub fn msg_type(&self) -> i64 {
        match self {
            UtMetadata::Request { .. } => MSG_TYPE_REQUEST,
            UtMetadata::Data { .. } => MSG_TYPE_DATA,
            UtMetadata::Reject { .. } => MSG_TYPE_REJECT,
        }
    }

    pub fn index(&self) -> usize {
        match self {
            UtMetadata::Request { index } | UtMetadata::Data { index, .. } => *index,
            UtMetadata::Reject { index } => *index,
        }
    }

    /// Encode the dict ([+ data]). Mirrors the getPayload implementations:
    /// keys ascending `msg_type < piece < total_size`, data immediately
    /// after the bencode value.
    pub fn encode(&self) -> Result<Vec<u8>, UtMetadataError> {
        let (index, total_size) = match self {
            UtMetadata::Request { index } => (index, None),
            UtMetadata::Data {
                index, total_size, ..
            } => (index, Some(total_size)),
            UtMetadata::Reject { index } => (index, None),
        };
        let mut dict = vec![
            (b"msg_type".to_vec(), Value::Int(self.msg_type())),
            (b"piece".to_vec(), Value::Int(*index as i64)),
        ];
        if let Some(total) = total_size {
            dict.push((b"total_size".to_vec(), Value::Int(*total as i64)));
        }
        let mut out = bencode::encode(&Value::Dict(dict))?;
        if let UtMetadata::Data { data, .. } = self {
            out.extend_from_slice(data);
        }
        Ok(out)
    }

    /// Decode (mirrors `DefaultExtensionMessageFactory.cc`): empty payload
    /// / broken bencode / non-dict / missing msg_type / piece missing or
    /// negative -> explicit errors; data state missing data or total_size
    /// -> explicit error; unknown msg_type -> explicit error.
    pub fn decode(payload: &[u8]) -> Result<Self, UtMetadataError> {
        if payload.is_empty() {
            return Err(UtMetadataError::TooSmall);
        }
        let end = value_end(payload)?;
        let value = bencode::decode_permissive(&payload[..end])?;
        let Value::Dict(dict) = &value else {
            return Err(UtMetadataError::NotDict);
        };
        let get_int = |key: &[u8]| -> Option<i64> {
            match dict
                .iter()
                .find(|(k, _)| k.as_slice() == key)
                .map(|(_, v)| v)
            {
                Some(Value::Int(i)) => Some(*i),
                _ => None,
            }
        };
        // Reference: msg_type must be an Integer; piece must be an Integer
        // and >= 0.
        let msg_type = get_int(b"msg_type").ok_or(UtMetadataError::MissingMsgType)?;
        let index = get_int(b"piece").ok_or(UtMetadataError::BadPiece)?;
        let Ok(index) = usize::try_from(index) else {
            return Err(UtMetadataError::BadPiece);
        };
        match msg_type {
            MSG_TYPE_REQUEST => Ok(UtMetadata::Request { index }),
            MSG_TYPE_DATA => {
                let total_size = get_int(b"total_size").ok_or(UtMetadataError::MissingTotalSize)?;
                let Ok(total_size) = usize::try_from(total_size) else {
                    return Err(UtMetadataError::MissingTotalSize);
                };
                // Reference: `end == length` -> "data not found".
                if end == payload.len() {
                    return Err(UtMetadataError::DataMissing);
                }
                Ok(UtMetadata::Data {
                    index,
                    total_size,
                    data: Bytes::copy_from_slice(&payload[end..]),
                })
            }
            MSG_TYPE_REJECT => Ok(UtMetadata::Reject { index }),
            other => Err(UtMetadataError::UnknownMsgType(other)),
        }
    }
}

/// End offset of the top-level bencode value (the equivalent of the `end`
/// out-param of `DefaultExtensionMessageFactory.cc`'s
/// `bencode2::decode(data+1, len-1, end)`).
///
/// Performs a **structural scan only** (length-field validity + bounds),
/// building no value tree; value-content parsing stays with
/// [`crate::bencode`] (the ut_metadata dict has <= 3 keys, so two passes
/// are acceptable). A length field longer than 19 digits (beyond u64) is
/// judged truncated outright, avoiding overflow arithmetic.
fn value_end(input: &[u8]) -> Result<usize, UtMetadataError> {
    let mut depth = 0usize;
    let mut i = 0usize;
    loop {
        let Some(&b) = input.get(i) else {
            return Err(UtMetadataError::Malformed);
        };
        match b {
            b'i' => {
                let Some(rel) = input[i..].iter().position(|&c| c == b'e') else {
                    return Err(UtMetadataError::Malformed);
                };
                i += rel + 1;
                if depth == 0 {
                    return Ok(i);
                }
            }
            b'l' | b'd' => {
                depth += 1;
                i += 1;
            }
            b'e' => {
                if depth == 0 {
                    return Err(UtMetadataError::Malformed);
                }
                depth -= 1;
                i += 1;
                if depth == 0 {
                    return Ok(i);
                }
            }
            b'0'..=b'9' => {
                let start = i;
                while matches!(input.get(i), Some(b'0'..=b'9')) {
                    i += 1;
                }
                if input.get(i) != Some(&b':') {
                    return Err(UtMetadataError::Malformed);
                }
                let digits = &input[start..i];
                if digits.len() > 19 {
                    return Err(UtMetadataError::Malformed);
                }
                let Some(len) = digits.iter().try_fold(0usize, |acc, d| {
                    acc.checked_mul(10)
                        .and_then(|a| a.checked_add((*d - b'0') as usize))
                }) else {
                    return Err(UtMetadataError::Malformed);
                };
                i += 1;
                if len > input.len() - i {
                    return Err(UtMetadataError::Malformed);
                }
                i += len;
                if depth == 0 {
                    return Ok(i);
                }
            }
            _ => return Err(UtMetadataError::Malformed),
        }
    }
}

/// Responder decision outcome (mirrors
/// `UTMetadataRequestExtensionMessage.cc`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeOutcome {
    /// Metadata is held -> a data piece (`metadataSize` = the total
    /// metadata length).
    Data {
        index: usize,
        total_size: usize,
        data: Bytes,
    },
    /// Metadata not held -> reject.
    Reject { index: usize },
}

/// Responder error (out-of-range index — the reference throws
/// DL_ABORT_EX and drops the connection,
/// `UTMetadataRequestExtensionMessage.cc`; the caller should disconnect).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ServeError {
    #[error(
        "metadata piece index is too big: piece={index} (x16KiB >= metadata_size {total}); reference drops the connection (UTMetadataRequestExtensionMessage.cc)"
    )]
    IndexTooBig { index: usize, total: usize },
}

/// Responder decision: the reply to an inbound request when the complete
/// metadata is held.
///
/// Mirrors the reference `doReceivedAction`:
/// - empty metadata -> reject;
/// - `index * 16KiB < metadata length` -> the data slice
/// `[index*16KiB, min((index+1)*16KiB, len))` (a short final piece);
/// - otherwise out of range -> [`ServeError::IndexTooBig`] (a peer
/// violation -> disconnect recommended).
pub fn serve_request(metadata: &[u8], index: usize) -> Result<ServeOutcome, ServeError> {
    if metadata.is_empty() {
        return Ok(ServeOutcome::Reject { index });
    }
    let total = metadata.len();
    let begin = match index.checked_mul(METADATA_PIECE_SIZE) {
        Some(b) if b < total => b,
        _ => return Err(ServeError::IndexTooBig { index, total }),
    };
    let end = begin
        .checked_add(METADATA_PIECE_SIZE)
        .unwrap_or(total)
        .min(total);
    Ok(ServeOutcome::Data {
        index,
        total_size: total,
        data: Bytes::copy_from_slice(&metadata[begin..end]),
    })
}
