//! DA-01 bounded `GetPalwDaChunk` / `PalwDaChunk` transport guard.
//!
//! The router only provides message delivery. This tracker supplies the security properties required
//! at the request/response boundary: one chunk per request, a hard in-flight cap, exact 64-byte roots,
//! no unsolicited/replayed responses, a small encoded response cap, and consensus-core proof checks.

use crate::pb::{GetPalwDaChunkMessage, Hash, PalwDaChunkMessage};
use kaspa_consensus_core::palw::da::{
    PALW_DA_MAX_CHUNKS, PALW_RECEIPT_DA_PROOF_VERSION_V1, PalwDaError, PalwReceiptDaChunkProofV1, verify_palw_receipt_da_chunk,
};
use kaspa_hashes::{HASH64_SIZE, Hash64};
use prost::Message;
use std::collections::BTreeSet;
use thiserror::Error;

pub const PALW_DA_P2P_MAX_IN_FLIGHT: usize = 16;
pub const PALW_DA_P2P_MAX_GET_BYTES: usize = 128;
pub const PALW_DA_P2P_MAX_CHUNK_BYTES: usize = 18 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PalwDaPendingChunk {
    pub object_root: Hash64,
    pub chunk_index: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum PalwDaTransportError {
    #[error("PALW DA request/response exceeds its encoded byte cap")]
    Oversize,
    #[error("PALW DA object root is missing or not exactly 64 bytes")]
    InvalidRoot,
    #[error("PALW DA chunk index exceeds the hard object chunk cap")]
    InvalidIndex,
    #[error("PALW DA request duplicates an outstanding request")]
    DuplicateRequest,
    #[error("PALW DA peer exceeded the outstanding request cap")]
    TooManyInFlight,
    #[error("PALW DA chunk was unsolicited, replayed, or names another request")]
    UnsolicitedChunk,
    #[error(transparent)]
    InvalidProof(#[from] PalwDaError),
}

fn decode_root(bytes: &[u8]) -> Result<Hash64, PalwDaTransportError> {
    let array: [u8; HASH64_SIZE] = bytes.try_into().map_err(|_| PalwDaTransportError::InvalidRoot)?;
    Ok(Hash64::from_bytes(array))
}

fn wire_hash(hash: Hash64) -> Hash {
    Hash { bytes: hash.as_byte_slice().to_vec() }
}

pub fn palw_da_get_chunk_message(object_root: Hash64, chunk_index: u16) -> GetPalwDaChunkMessage {
    GetPalwDaChunkMessage { object_root: Some(wire_hash(object_root)), chunk_index: chunk_index as u32 }
}

/// Encode a consensus-core proof into the bounded protobuf response. Proof generation is kept in
/// consensus-core so the serving and receiving sides use exactly the same chunk metadata rules.
pub fn palw_da_chunk_message(object_root: Hash64, proof: &PalwReceiptDaChunkProofV1) -> PalwDaChunkMessage {
    PalwDaChunkMessage {
        object_root: Some(wire_hash(object_root)),
        object_version: proof.object_version as u32,
        object_len: proof.object_len,
        chunk_count: proof.chunk_count as u32,
        chunk_index: proof.chunk_index as u32,
        chunk: proof.chunk.clone(),
        siblings: proof.siblings.iter().copied().map(wire_hash).collect(),
    }
}

pub fn validate_get_palw_da_chunk(message: &GetPalwDaChunkMessage) -> Result<PalwDaPendingChunk, PalwDaTransportError> {
    if message.encoded_len() > PALW_DA_P2P_MAX_GET_BYTES {
        return Err(PalwDaTransportError::Oversize);
    }
    let root = message.object_root.as_ref().ok_or(PalwDaTransportError::InvalidRoot)?;
    let chunk_index = u16::try_from(message.chunk_index).map_err(|_| PalwDaTransportError::InvalidIndex)?;
    if chunk_index as usize >= PALW_DA_MAX_CHUNKS {
        return Err(PalwDaTransportError::InvalidIndex);
    }
    Ok(PalwDaPendingChunk { object_root: decode_root(&root.bytes)?, chunk_index })
}

#[derive(Clone, Debug, Default)]
pub struct PalwDaRequestTracker {
    pending: BTreeSet<PalwDaPendingChunk>,
}

impl PalwDaRequestTracker {
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub fn register(&mut self, message: &GetPalwDaChunkMessage) -> Result<PalwDaPendingChunk, PalwDaTransportError> {
        let request = validate_get_palw_da_chunk(message)?;
        if self.pending.contains(&request) {
            return Err(PalwDaTransportError::DuplicateRequest);
        }
        if self.pending.len() >= PALW_DA_P2P_MAX_IN_FLIGHT {
            return Err(PalwDaTransportError::TooManyInFlight);
        }
        self.pending.insert(request);
        Ok(request)
    }

    pub fn cancel(&mut self, request: PalwDaPendingChunk) -> bool {
        self.pending.remove(&request)
    }

    pub fn validate_response(&mut self, message: &PalwDaChunkMessage) -> Result<PalwReceiptDaChunkProofV1, PalwDaTransportError> {
        if message.encoded_len() > PALW_DA_P2P_MAX_CHUNK_BYTES {
            return Err(PalwDaTransportError::Oversize);
        }
        let root_wire = message.object_root.as_ref().ok_or(PalwDaTransportError::InvalidRoot)?;
        let object_root = decode_root(&root_wire.bytes)?;
        let chunk_index = u16::try_from(message.chunk_index).map_err(|_| PalwDaTransportError::InvalidIndex)?;
        let request = PalwDaPendingChunk { object_root, chunk_index };
        if !self.pending.contains(&request) {
            return Err(PalwDaTransportError::UnsolicitedChunk);
        }
        let proof = PalwReceiptDaChunkProofV1 {
            version: PALW_RECEIPT_DA_PROOF_VERSION_V1,
            object_version: u16::try_from(message.object_version)
                .map_err(|_| PalwDaTransportError::InvalidProof(PalwDaError::ChunkMetadata))?,
            object_len: message.object_len,
            chunk_count: u16::try_from(message.chunk_count)
                .map_err(|_| PalwDaTransportError::InvalidProof(PalwDaError::ChunkMetadata))?,
            chunk_index,
            chunk: message.chunk.clone(),
            siblings: message.siblings.iter().map(|hash| decode_root(&hash.bytes)).collect::<Result<Vec<_>, _>>()?,
        };
        verify_palw_receipt_da_chunk(&object_root, &proof)?;
        self.pending.remove(&request);
        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KaspadMessagePayloadType;
    use crate::pb::{KaspadMessage, PruningPointPalwSnapshotMessage, RequestPruningPointPalwSnapshotMessage, kaspad_message::Payload};
    use kaspa_consensus_core::palw::da::{palw_receipt_da_chunk_proof, palw_receipt_da_commitment};

    fn h(byte: u8) -> Hash64 {
        Hash64::from_bytes([byte; HASH64_SIZE])
    }

    fn get(root: Hash64, chunk_index: u32) -> GetPalwDaChunkMessage {
        GetPalwDaChunkMessage { object_root: Some(wire_hash(root)), chunk_index }
    }

    #[test]
    fn requested_chunk_round_trip_rejects_unsolicited_replay_and_wrong_proof() {
        let object: Vec<u8> = (0..40_000).map(|index| (index % 251) as u8).collect();
        let commitment = palw_receipt_da_commitment(1, &object).unwrap();
        let proof = palw_receipt_da_chunk_proof(1, &object, 1).unwrap();
        let request = get(commitment.root, 1);
        let response = palw_da_chunk_message(commitment.root, &proof);

        let mut tracker = PalwDaRequestTracker::default();
        tracker.register(&request).unwrap();
        assert_eq!(tracker.validate_response(&response).unwrap(), proof);
        assert!(tracker.is_empty());
        assert_eq!(tracker.validate_response(&response), Err(PalwDaTransportError::UnsolicitedChunk));

        tracker.register(&request).unwrap();
        let mut wrong = response.clone();
        wrong.chunk[0] ^= 1;
        assert!(matches!(tracker.validate_response(&wrong), Err(PalwDaTransportError::InvalidProof(PalwDaError::WrongProof))));
        assert_eq!(tracker.len(), 1, "invalid responses never consume the honest outstanding request");
    }

    #[test]
    fn caps_reject_oversize_bad_roots_duplicate_and_request_floods() {
        let mut tracker = PalwDaRequestTracker::default();
        let duplicate = get(h(1), 0);
        tracker.register(&duplicate).unwrap();
        assert_eq!(tracker.register(&duplicate), Err(PalwDaTransportError::DuplicateRequest));
        for byte in 2..=PALW_DA_P2P_MAX_IN_FLIGHT as u8 {
            tracker.register(&get(h(byte), 0)).unwrap();
        }
        assert_eq!(tracker.register(&get(h(0xfe), 0)), Err(PalwDaTransportError::TooManyInFlight));
        assert_eq!(validate_get_palw_da_chunk(&get(h(1), PALW_DA_MAX_CHUNKS as u32)), Err(PalwDaTransportError::InvalidIndex));
        let bad_root = GetPalwDaChunkMessage { object_root: Some(Hash { bytes: vec![0; 63] }), chunk_index: 0 };
        assert_eq!(validate_get_palw_da_chunk(&bad_root), Err(PalwDaTransportError::InvalidRoot));

        let mut fresh = PalwDaRequestTracker::default();
        fresh.register(&get(h(9), 0)).unwrap();
        let oversized = PalwDaChunkMessage {
            object_root: Some(wire_hash(h(9))),
            object_version: 1,
            object_len: 19_000,
            chunk_count: 2,
            chunk_index: 0,
            chunk: vec![0; PALW_DA_P2P_MAX_CHUNK_BYTES],
            siblings: vec![],
        };
        assert_eq!(fresh.validate_response(&oversized), Err(PalwDaTransportError::Oversize));
    }

    #[test]
    fn protobuf_tags_71_72_pruning_and_73_74_da_coexist_round_trip() {
        let messages = [
            KaspadMessage {
                payload: Some(Payload::RequestPruningPointPalwSnapshot(RequestPruningPointPalwSnapshotMessage {
                    pruning_point_hash: Some(wire_hash(h(0x71))),
                })),
                ..Default::default()
            },
            KaspadMessage {
                payload: Some(Payload::PruningPointPalwSnapshot(PruningPointPalwSnapshotMessage {
                    found: true,
                    snapshot: vec![0x72],
                })),
                ..Default::default()
            },
            KaspadMessage { payload: Some(Payload::GetPalwDaChunk(get(h(0x73), 0))), ..Default::default() },
            KaspadMessage {
                payload: Some(Payload::PalwDaChunk(PalwDaChunkMessage {
                    object_root: Some(wire_hash(h(0x74))),
                    object_version: 1,
                    object_len: 1,
                    chunk_count: 1,
                    chunk_index: 0,
                    chunk: vec![0],
                    siblings: vec![],
                })),
                ..Default::default()
            },
        ];
        let expected = [
            KaspadMessagePayloadType::RequestPruningPointPalwSnapshot,
            KaspadMessagePayloadType::PruningPointPalwSnapshot,
            KaspadMessagePayloadType::GetPalwDaChunk,
            KaspadMessagePayloadType::PalwDaChunk,
        ];
        for (message, expected_type) in messages.into_iter().zip(expected) {
            let decoded = KaspadMessage::decode(message.encode_to_vec().as_slice()).unwrap();
            assert_eq!(KaspadMessagePayloadType::from(decoded.payload.as_ref().unwrap()), expected_type);
        }
    }
}
