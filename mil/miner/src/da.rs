//! DA-01 producer and operator constructors.
//!
//! This is the LLM/miner side of the consensus-core receipt object. It signs both owner→session
//! authorizations and both execution receipts, derives the private match commitment from the full
//! signed receipt hashes, and returns the exact bytes/root that must be bound into the public leaf.
//! Object-v1 deliberately signs ZERO in each embedded legacy `receipt_da_root`; the outer leaf root
//! commits to the complete object and avoids an impossible signature/root self-reference.

use kaspa_consensus_core::palw::da::{
    PALW_DA_CHALLENGE_V1_MLDSA87_CONTEXT, PALW_DA_CHALLENGE_VERSION_V1, PALW_DA_MAX_SESSION_EPOCHS,
    PALW_DA_RESPONSE_V1_MLDSA87_CONTEXT, PALW_DA_RESPONSE_VERSION_V1, PALW_DA_TIMEOUT_EVIDENCE_VERSION_V1,
    PALW_PROVIDER_SESSION_AUTH_VERSION_V1, PALW_PROVIDER_SESSION_V1_MLDSA87_CONTEXT, PALW_RECEIPT_DA_OBJECT_VERSION_V1,
    PALW_REPLICA_RECEIPT_V1_MLDSA87_CONTEXT, PalwDaChallengeV1, PalwDaError, PalwDaResponseV1, PalwDaTimeoutEvidenceV1,
    PalwProviderSessionAuthorizationV1, PalwReceiptDaCommitmentV1, PalwReceiptDaObjectV1, palw_receipt_da_chunk_proof,
    palw_receipt_da_commitment, palw_receipt_da_object_bytes,
};
use kaspa_consensus_core::{
    palw::{PalwPublicLeafV1, ReplicaExecutionReceiptV1, ReplicaMatchRecordV1, private_match_commitment},
    tx::TransactionOutpoint,
};
use kaspa_hashes::Hash64;
use kaspa_pq_validator_core::ValidatorKey;
use thiserror::Error;

pub const DA_CHALLENGE_SUBNETWORK_BYTE: u8 = 0x3a;
pub const DA_RESPONSE_SUBNETWORK_BYTE: u8 = 0x3b;
pub const DA_TIMEOUT_SUBNETWORK_BYTE: u8 = 0x3c;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PalwDaReceiptSemantics {
    pub job_nullifier: Hash64,
    pub job_set_commitment: Hash64,
    pub model_profile_id: Hash64,
    pub runtime_class_id: Hash64,
    pub shape_id: u16,
    pub quantum_count: u16,
    pub output_commitment: Hash64,
    pub canonical_gemm_trace_root: Hash64,
    pub operation_schedule_commitment: Hash64,
    pub completed_at_epoch: u64,
}

pub struct PalwDaProviderSigner<'a> {
    pub provider_bond: TransactionOutpoint,
    pub owner_key: &'a ValidatorKey,
    pub session_key: &'a ValidatorKey,
    pub valid_from_epoch: u64,
    pub valid_until_epoch: u64,
    pub authorization_nonce: Hash64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PalwDaProducerArtifact {
    pub object: PalwReceiptDaObjectV1,
    pub object_bytes: Vec<u8>,
    pub commitment: PalwReceiptDaCommitmentV1,
    pub private_match_commitment: Hash64,
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum PalwDaProducerError {
    #[error("the two DA providers must use distinct bond outpoints")]
    DuplicateProvider,
    #[error("provider session authorization is out of range or exceeds 64 epochs")]
    SessionEpochRange,
    #[error("provider session authorization nonce must be nonzero")]
    ZeroAuthorizationNonce,
    #[error("the candidate public leaf does not match the signed DA object")]
    LeafMismatch,
    #[error("DA response deadline overflows u64")]
    DeadlineOverflow,
    #[error(transparent)]
    Core(#[from] PalwDaError),
    #[error("borsh serialization failed")]
    Encode,
}

fn signed_session_authorization(
    network_id: u32,
    provider: &PalwDaProviderSigner<'_>,
    completed_at_epoch: u64,
) -> Result<PalwProviderSessionAuthorizationV1, PalwDaProducerError> {
    if provider.valid_from_epoch > provider.valid_until_epoch
        || provider.valid_until_epoch.saturating_sub(provider.valid_from_epoch) > PALW_DA_MAX_SESSION_EPOCHS
        || !(provider.valid_from_epoch..=provider.valid_until_epoch).contains(&completed_at_epoch)
    {
        return Err(PalwDaProducerError::SessionEpochRange);
    }
    if provider.authorization_nonce == Hash64::default() {
        return Err(PalwDaProducerError::ZeroAuthorizationNonce);
    }
    let mut authorization = PalwProviderSessionAuthorizationV1 {
        version: PALW_PROVIDER_SESSION_AUTH_VERSION_V1,
        network_id,
        provider_bond: provider.provider_bond,
        owner_public_key: provider.owner_key.public_key().to_vec(),
        session_public_key: provider.session_key.public_key().to_vec(),
        valid_from_epoch: provider.valid_from_epoch,
        valid_until_epoch: provider.valid_until_epoch,
        authorization_nonce: provider.authorization_nonce,
        signature: vec![],
    };
    authorization.signature = provider
        .owner_key
        .sign_with_context(authorization.signing_hash().as_byte_slice(), PALW_PROVIDER_SESSION_V1_MLDSA87_CONTEXT)
        .to_vec();
    Ok(authorization)
}

fn signed_receipt(provider: &PalwDaProviderSigner<'_>, fields: PalwDaReceiptSemantics) -> ReplicaExecutionReceiptV1 {
    let mut receipt = ReplicaExecutionReceiptV1 {
        version: 1,
        provider_bond: provider.provider_bond,
        session_public_key: provider.session_key.public_key().to_vec(),
        job_nullifier: fields.job_nullifier,
        job_set_commitment: fields.job_set_commitment,
        model_profile_id: fields.model_profile_id,
        runtime_class_id: fields.runtime_class_id,
        shape_id: fields.shape_id,
        quantum_count: fields.quantum_count,
        output_commitment: fields.output_commitment,
        canonical_gemm_trace_root: fields.canonical_gemm_trace_root,
        operation_schedule_commitment: fields.operation_schedule_commitment,
        receipt_da_root: Hash64::default(),
        completed_at_epoch: fields.completed_at_epoch,
        signature: vec![],
    };
    receipt.signature = provider
        .session_key
        .sign_with_context(receipt.signing_hash().as_byte_slice(), PALW_REPLICA_RECEIPT_V1_MLDSA87_CONTEXT)
        .to_vec();
    receipt
}

#[allow(clippy::too_many_arguments)]
pub fn build_signed_receipt_da_object(
    network_id: u32,
    batch_id: Hash64,
    leaf_index: u32,
    fields: PalwDaReceiptSemantics,
    provider_a: &PalwDaProviderSigner<'_>,
    provider_b: &PalwDaProviderSigner<'_>,
) -> Result<PalwDaProducerArtifact, PalwDaProducerError> {
    if provider_a.provider_bond == provider_b.provider_bond {
        return Err(PalwDaProducerError::DuplicateProvider);
    }
    let session_authorization_a = signed_session_authorization(network_id, provider_a, fields.completed_at_epoch)?;
    let session_authorization_b = signed_session_authorization(network_id, provider_b, fields.completed_at_epoch)?;
    let receipt_a = signed_receipt(provider_a, fields);
    let receipt_b = signed_receipt(provider_b, fields);
    let receipt_a_hash = receipt_a.hash();
    let receipt_b_hash = receipt_b.hash();
    let match_record = ReplicaMatchRecordV1 {
        receipt_a_hash,
        receipt_b_hash,
        job_nullifier: fields.job_nullifier,
        output_commitment: fields.output_commitment,
        canonical_gemm_trace_root: fields.canonical_gemm_trace_root,
        operation_schedule_commitment: fields.operation_schedule_commitment,
        matched_at_epoch: fields.completed_at_epoch,
    };
    let match_commitment = private_match_commitment(
        &fields.output_commitment,
        &fields.canonical_gemm_trace_root,
        &fields.operation_schedule_commitment,
        &fields.job_set_commitment,
        &receipt_a_hash,
        &receipt_b_hash,
    );
    let object = PalwReceiptDaObjectV1 {
        version: PALW_RECEIPT_DA_OBJECT_VERSION_V1,
        network_id,
        batch_id,
        leaf_index,
        receipt_a,
        receipt_b,
        match_record,
        session_authorization_a,
        session_authorization_b,
    };
    let object_bytes = palw_receipt_da_object_bytes(&object)?;
    let commitment = palw_receipt_da_commitment(object.version, &object_bytes)?;
    Ok(PalwDaProducerArtifact { object, object_bytes, commitment, private_match_commitment: match_commitment })
}

impl PalwDaProducerArtifact {
    /// Bind the candidate leaf before manifest/chunk publication. This is intentionally consuming:
    /// callers cannot accidentally keep publishing the pre-DA zero-root candidate as the final leaf.
    pub fn bind_leaf(&self, mut leaf: PalwPublicLeafV1) -> Result<PalwPublicLeafV1, PalwDaProducerError> {
        let receipt = &self.object.receipt_a;
        if leaf.batch_id != self.object.batch_id
            || leaf.leaf_index != self.object.leaf_index
            || leaf.provider_a_bond != self.object.receipt_a.provider_bond
            || leaf.provider_b_bond != self.object.receipt_b.provider_bond
            || leaf.job_nullifier != receipt.job_nullifier
            || leaf.model_profile_id != receipt.model_profile_id
            || leaf.runtime_class_id != receipt.runtime_class_id
            || leaf.shape_id != receipt.shape_id
            || leaf.quantum_count != receipt.quantum_count
        {
            return Err(PalwDaProducerError::LeafMismatch);
        }
        leaf.private_match_commitment = self.private_match_commitment;
        leaf.receipt_da_object_version = self.commitment.object_version;
        leaf.receipt_da_root = self.commitment.root;
        leaf.receipt_da_object_len = self.commitment.object_len;
        leaf.receipt_da_chunk_count = self.commitment.chunk_count;
        leaf.receipt_v3_compute_set_id = Hash64::default();
        leaf.receipt_v3_job_challenge = Hash64::default();
        leaf.receipt_v3_issued_epoch = 0;
        leaf.receipt_v3_expires_epoch = 0;
        Ok(leaf)
    }
}

pub fn build_signed_da_challenge(
    network_id: u32,
    obligation_id: Hash64,
    challenge_epoch: u64,
    opened_daa_score: u64,
    response_window_daa: u64,
    challenger_bond: TransactionOutpoint,
    challenger_owner_key: &ValidatorKey,
    challenge_nonce: Hash64,
) -> Result<PalwDaChallengeV1, PalwDaProducerError> {
    let response_deadline_daa_score =
        opened_daa_score.checked_add(response_window_daa).ok_or(PalwDaProducerError::DeadlineOverflow)?;
    let mut challenge = PalwDaChallengeV1 {
        version: PALW_DA_CHALLENGE_VERSION_V1,
        network_id,
        obligation_id,
        challenge_epoch,
        opened_daa_score,
        response_deadline_daa_score,
        challenger_bond,
        challenger_owner_public_key: challenger_owner_key.public_key().to_vec(),
        challenge_nonce,
        signature: vec![],
    };
    challenge.signature = challenger_owner_key
        .sign_with_context(challenge.signing_hash().as_byte_slice(), PALW_DA_CHALLENGE_V1_MLDSA87_CONTEXT)
        .to_vec();
    Ok(challenge)
}

pub fn build_signed_da_response(
    network_id: u32,
    challenge_id: Hash64,
    provider_bond: TransactionOutpoint,
    provider_owner_key: &ValidatorKey,
    object_bytes: &[u8],
    chunk_index: u16,
) -> Result<PalwDaResponseV1, PalwDaProducerError> {
    let chunk_proof = palw_receipt_da_chunk_proof(PALW_RECEIPT_DA_OBJECT_VERSION_V1, object_bytes, chunk_index)?;
    let mut response = PalwDaResponseV1 {
        version: PALW_DA_RESPONSE_VERSION_V1,
        network_id,
        challenge_id,
        provider_bond,
        provider_owner_public_key: provider_owner_key.public_key().to_vec(),
        chunk_proof,
        signature: vec![],
    };
    response.signature =
        provider_owner_key.sign_with_context(response.signing_hash().as_byte_slice(), PALW_DA_RESPONSE_V1_MLDSA87_CONTEXT).to_vec();
    Ok(response)
}

pub fn build_da_timeout_evidence(
    network_id: u32,
    challenge_id: Hash64,
    provider_bond: TransactionOutpoint,
) -> PalwDaTimeoutEvidenceV1 {
    PalwDaTimeoutEvidenceV1 { version: PALW_DA_TIMEOUT_EVIDENCE_VERSION_V1, network_id, challenge_id, provider_bond }
}

pub fn encode_da_challenge(challenge: &PalwDaChallengeV1) -> Result<(u8, Vec<u8>), PalwDaProducerError> {
    Ok((DA_CHALLENGE_SUBNETWORK_BYTE, borsh::to_vec(challenge).map_err(|_| PalwDaProducerError::Encode)?))
}

pub fn encode_da_response(response: &PalwDaResponseV1) -> Result<(u8, Vec<u8>), PalwDaProducerError> {
    Ok((DA_RESPONSE_SUBNETWORK_BYTE, borsh::to_vec(response).map_err(|_| PalwDaProducerError::Encode)?))
}

pub fn encode_da_timeout(evidence: &PalwDaTimeoutEvidenceV1) -> Result<(u8, Vec<u8>), PalwDaProducerError> {
    Ok((DA_TIMEOUT_SUBNETWORK_BYTE, borsh::to_vec(evidence).map_err(|_| PalwDaProducerError::Encode)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::palw::da::{PALW_DA_MAX_ONCHAIN_RESPONSE_BYTES, verify_palw_receipt_da_chunk};
    use kaspa_txscript::verify_mldsa87_with_context;

    fn h(byte: u8) -> Hash64 {
        Hash64::from_bytes([byte; 64])
    }

    fn fields() -> PalwDaReceiptSemantics {
        PalwDaReceiptSemantics {
            job_nullifier: h(1),
            job_set_commitment: h(2),
            model_profile_id: h(3),
            runtime_class_id: h(4),
            shape_id: 7,
            quantum_count: 2,
            output_commitment: h(5),
            canonical_gemm_trace_root: h(6),
            operation_schedule_commitment: h(7),
            completed_at_epoch: 9,
        }
    }

    #[test]
    fn producer_signs_canonical_object_and_operational_payloads() {
        let owner_a = ValidatorKey::from_seed([1; 32]);
        let session_a = ValidatorKey::from_seed([2; 32]);
        let owner_b = ValidatorKey::from_seed([3; 32]);
        let session_b = ValidatorKey::from_seed([4; 32]);
        let provider_a = PalwDaProviderSigner {
            provider_bond: TransactionOutpoint::new(h(0xa1), 0),
            owner_key: &owner_a,
            session_key: &session_a,
            valid_from_epoch: 8,
            valid_until_epoch: 10,
            authorization_nonce: h(0xb1),
        };
        let provider_b = PalwDaProviderSigner {
            provider_bond: TransactionOutpoint::new(h(0xa2), 0),
            owner_key: &owner_b,
            session_key: &session_b,
            valid_from_epoch: 8,
            valid_until_epoch: 10,
            authorization_nonce: h(0xb2),
        };
        let artifact = build_signed_receipt_da_object(111, h(0xc1), 3, fields(), &provider_a, &provider_b).unwrap();
        assert_eq!(artifact.object.receipt_a.receipt_da_root, Hash64::default());
        assert_eq!(artifact.object.receipt_b.receipt_da_root, Hash64::default());
        assert!(matches!(
            verify_mldsa87_with_context(
                &artifact.object.receipt_a.session_public_key,
                artifact.object.receipt_a.signing_hash().as_byte_slice(),
                &artifact.object.receipt_a.signature,
                PALW_REPLICA_RECEIPT_V1_MLDSA87_CONTEXT,
            ),
            Ok(true)
        ));
        assert!(matches!(
            verify_mldsa87_with_context(
                &artifact.object.session_authorization_a.owner_public_key,
                artifact.object.session_authorization_a.signing_hash().as_byte_slice(),
                &artifact.object.session_authorization_a.signature,
                PALW_PROVIDER_SESSION_V1_MLDSA87_CONTEXT,
            ),
            Ok(true)
        ));

        let challenge = build_signed_da_challenge(111, h(0xd1), 9, 1_000, 200, provider_b.provider_bond, &owner_a, h(0xd2)).unwrap();
        assert!(matches!(
            verify_mldsa87_with_context(
                &challenge.challenger_owner_public_key,
                challenge.signing_hash().as_byte_slice(),
                &challenge.signature,
                PALW_DA_CHALLENGE_V1_MLDSA87_CONTEXT,
            ),
            Ok(true)
        ));
        let response =
            build_signed_da_response(111, challenge.challenge_id(), provider_a.provider_bond, &owner_a, &artifact.object_bytes, 0)
                .unwrap();
        assert!(matches!(
            verify_mldsa87_with_context(
                &response.provider_owner_public_key,
                response.signing_hash().as_byte_slice(),
                &response.signature,
                PALW_DA_RESPONSE_V1_MLDSA87_CONTEXT,
            ),
            Ok(true)
        ));
        verify_palw_receipt_da_chunk(&artifact.commitment.root, &response.chunk_proof).unwrap();
        let (_, response_bytes) = encode_da_response(&response).unwrap();
        assert!(response_bytes.len() <= PALW_DA_MAX_ONCHAIN_RESPONSE_BYTES);
        assert_eq!(encode_da_challenge(&challenge).unwrap().0, 0x3a);
        assert_eq!(
            encode_da_timeout(&build_da_timeout_evidence(111, challenge.challenge_id(), provider_a.provider_bond)).unwrap().0,
            0x3c
        );
    }
}
