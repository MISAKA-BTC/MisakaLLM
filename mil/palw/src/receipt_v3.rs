//! Node-owned PALW Receipt v3 off-chain wire contract.
//!
//! This module deliberately stops at the authenticated off-chain artifact boundary. It defines the
//! bytes workers sign, verifies a receipt against node-supplied job/epoch/registry expectations, and
//! evaluates the k=2 match predicate. It does not make the artifact selected-chain state and does not
//! by itself close receipt DA, audit execution, or certificate provenance.
//!
//! # Canonical rules
//!
//! * fixed-width fields are concatenated in declaration order;
//! * integers are little-endian;
//! * all consensus-recomputed digests are 64-byte keyed BLAKE2b-512 values under the public domains
//!   below;
//! * `worker_credential_id` is the provider-registry identity: unkeyed BLAKE2b-512 of the exact
//!   2592-byte ML-DSA-87 verification key;
//! * the signature is ML-DSA-87 over [`ComputeReceiptV3::signing_digest`] under
//!   [`PALW_RECEIPT_V3_MLDSA87_CONTEXT`].

use blake2b_simd::Params as Blake2bParams;
use borsh::{BorshDeserialize, BorshSerialize};
use kaspa_hashes::{HASH64_SIZE, Hash64, blake2b_512_keyed};
use libcrux_ml_dsa::ml_dsa_87 as mldsa;

/// Receipt body schema version.
pub const RECEIPT_V3_VERSION: u16 = 3;
/// The only signature algorithm accepted by Receipt v3.
pub const MLDSA87_ALGORITHM_ID: u8 = 1;
/// ML-DSA-87 verification-key length in bytes.
pub const MLDSA87_VERIFYING_KEY_LEN: usize = 2592;
/// ML-DSA-87 signature length in bytes.
pub const MLDSA87_SIGNATURE_LEN: usize = 4627;

/// Keyed-hash domain for a canonical [`MatchProjectionV2`].
pub const PALW_RECEIPT_V3_PROJECTION_DOMAIN: &[u8] = b"misaka-palw-v3/projection";
/// Keyed-hash domain for the canonical receipt body that is signed.
pub const PALW_RECEIPT_V3_SIGNING_DOMAIN: &[u8] = b"misaka-palw-v3/receipt-signing";
/// Keyed-hash domain for receipt identity.
pub const PALW_RECEIPT_V3_ID_DOMAIN: &[u8] = b"misaka-palw-v3/receipt-id";
/// Keyed-hash domain for per-worker, per-job execution nullifiers.
pub const PALW_RECEIPT_V3_EXECUTION_NULLIFIER_DOMAIN: &[u8] = b"misaka-palw-v3/execution-nullifier";
/// Keyed-hash domain for canonical output-token commitments.
pub const PALW_RECEIPT_V3_OUTPUT_DOMAIN: &[u8] = b"misaka-palw-v3/output";
/// Keyed-hash domain for an order-independent matched-pair identity.
pub const PALW_RECEIPT_V3_PAIR_DOMAIN: &[u8] = b"misaka-palw-v3/pair-id";
/// ML-DSA-87 context for an off-chain PALW Receipt v3 signature.
pub const PALW_RECEIPT_V3_MLDSA87_CONTEXT: &[u8] = b"misaka-palw-v3/receipt/mldsa87";

fn push_hash(out: &mut Vec<u8>, hash: &Hash64) {
    out.extend_from_slice(hash.as_byte_slice());
}

/// Non-matched implementation diagnostics. These bytes are authenticated by the signature, but do
/// not participate in [`MatchProjectionV2::first_mismatch`].
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ImplementationTelemetryV3 {
    /// Runtime/hardware-class diagnostic identifier.
    pub runtime_class_id: [u8; 32],
    /// Exact runtime artifact diagnostic identifier.
    pub runtime_manifest_hash: [u8; 32],
}

impl ImplementationTelemetryV3 {
    /// Canonical telemetry length.
    pub const CANONICAL_LEN: usize = 64;

    fn append_canonical(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.runtime_class_id);
        out.extend_from_slice(&self.runtime_manifest_hash);
    }
}

/// Receipt v3 match projection. Every field is exact-match consensus input; worker identity and
/// implementation telemetry are deliberately excluded.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MatchProjectionV2 {
    /// Registered compute-set identity.
    pub compute_set_id: Hash64,
    /// Node-issued job/beacon challenge.
    pub job_challenge: Hash64,
    /// Commitment to the canonical output-token sequence.
    pub output_commitment: Hash64,
    /// Canonical operation-schedule root.
    pub schedule_root: Hash64,
    /// Canonical execution/checkpoint root.
    pub execution_root: Hash64,
    /// Canonical MoE route root, or zero for dense models.
    pub route_root: Hash64,
    /// Canonical recurrent-state root, or zero for stateless models.
    pub state_root: Hash64,
    /// Semantic canonical compute units.
    pub canonical_compute_units: u64,
    /// Total committed token count.
    pub token_count: u64,
    /// Node-owned canonical stop-reason tag.
    pub stop_reason: u8,
}

impl MatchProjectionV2 {
    /// Fixed canonical encoding length.
    pub const CANONICAL_LEN: usize = 7 * HASH64_SIZE + 8 + 8 + 1;

    /// Fixed-width canonical wire bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::CANONICAL_LEN);
        for hash in [
            &self.compute_set_id,
            &self.job_challenge,
            &self.output_commitment,
            &self.schedule_root,
            &self.execution_root,
            &self.route_root,
            &self.state_root,
        ] {
            push_hash(&mut out, hash);
        }
        out.extend_from_slice(&self.canonical_compute_units.to_le_bytes());
        out.extend_from_slice(&self.token_count.to_le_bytes());
        out.push(self.stop_reason);
        debug_assert_eq!(out.len(), Self::CANONICAL_LEN);
        out
    }

    /// Keyed digest of [`Self::canonical_bytes`].
    pub fn digest(&self) -> Hash64 {
        blake2b_512_keyed(PALW_RECEIPT_V3_PROJECTION_DOMAIN, &self.canonical_bytes())
    }

    /// Return the first diverging exact-match field.
    pub fn first_mismatch(&self, other: &Self) -> Option<&'static str> {
        if self.compute_set_id != other.compute_set_id {
            return Some("compute_set_id");
        }
        if self.job_challenge != other.job_challenge {
            return Some("job_challenge");
        }
        if self.output_commitment != other.output_commitment {
            return Some("output_commitment");
        }
        if self.schedule_root != other.schedule_root {
            return Some("schedule_root");
        }
        if self.execution_root != other.execution_root {
            return Some("execution_root");
        }
        if self.route_root != other.route_root {
            return Some("route_root");
        }
        if self.state_root != other.state_root {
            return Some("state_root");
        }
        if self.canonical_compute_units != other.canonical_compute_units {
            return Some("canonical_compute_units");
        }
        if self.token_count != other.token_count {
            return Some("token_count");
        }
        if self.stop_reason != other.stop_reason {
            return Some("stop_reason");
        }
        None
    }
}

/// Authenticated Receipt v3 body.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ComputeReceiptV3 {
    /// Must be [`RECEIPT_V3_VERSION`].
    pub receipt_version: u16,
    /// Node-provided network/genesis identity.
    pub network_id: Hash64,
    /// Exact-match projection.
    pub projection: MatchProjectionV2,
    /// Signed, non-matched diagnostics.
    pub telemetry: ImplementationTelemetryV3,
    /// Unkeyed BLAKE2b-512 of the registered ML-DSA-87 verification key.
    pub worker_credential_id: Hash64,
    /// Replica slot. Receipt v3 accepts only 0 or 1.
    pub replica_slot: u8,
    /// Recomputed by [`execution_nullifier_v3`].
    pub execution_nullifier: Hash64,
    /// Exact issue epoch supplied with the job.
    pub issued_epoch: u64,
    /// Exact expiry epoch supplied with the job.
    pub expires_epoch: u64,
}

impl ComputeReceiptV3 {
    /// Fixed canonical body length.
    pub const CANONICAL_LEN: usize = 2
        + HASH64_SIZE
        + MatchProjectionV2::CANONICAL_LEN
        + ImplementationTelemetryV3::CANONICAL_LEN
        + HASH64_SIZE
        + 1
        + HASH64_SIZE
        + 8
        + 8;

    /// Canonical body bytes signed by the worker.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::CANONICAL_LEN);
        out.extend_from_slice(&self.receipt_version.to_le_bytes());
        push_hash(&mut out, &self.network_id);
        out.extend_from_slice(&self.projection.canonical_bytes());
        self.telemetry.append_canonical(&mut out);
        push_hash(&mut out, &self.worker_credential_id);
        out.push(self.replica_slot);
        push_hash(&mut out, &self.execution_nullifier);
        out.extend_from_slice(&self.issued_epoch.to_le_bytes());
        out.extend_from_slice(&self.expires_epoch.to_le_bytes());
        debug_assert_eq!(out.len(), Self::CANONICAL_LEN);
        out
    }

    /// Digest signed under [`PALW_RECEIPT_V3_MLDSA87_CONTEXT`].
    pub fn signing_digest(&self) -> Hash64 {
        blake2b_512_keyed(PALW_RECEIPT_V3_SIGNING_DOMAIN, &self.canonical_bytes())
    }

    /// Stable identity of this exact authenticated body.
    pub fn receipt_id(&self) -> Hash64 {
        blake2b_512_keyed(PALW_RECEIPT_V3_ID_DOMAIN, self.signing_digest().as_byte_slice())
    }
}

/// ML-DSA-87 envelope for a canonical Receipt v3 body.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SignedEnvelopeV3 {
    /// Must equal [`ComputeReceiptV3::signing_digest`].
    pub body_digest: Hash64,
    /// Must equal [`MLDSA87_ALGORITHM_ID`].
    pub algorithm: u8,
    /// Must equal both the receipt credential and the verification-key-derived credential.
    pub signer_credential_id: Hash64,
    /// Exactly [`MLDSA87_SIGNATURE_LEN`] bytes.
    pub signature: Vec<u8>,
}

/// Node-supplied expectations for verifying one submitted receipt. Supplying these from selected
/// chain state is mandatory; the worker is not authoritative for any field here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptV3Expectations {
    /// Expected network/genesis identity.
    pub network_id: Hash64,
    /// Expected registered compute set.
    pub compute_set_id: Hash64,
    /// Expected node-issued job challenge.
    pub job_challenge: Hash64,
    /// Expected replica slot (0 or 1).
    pub replica_slot: u8,
    /// Exact issue epoch of the assigned job.
    pub issued_epoch: u64,
    /// Exact expiry epoch of the assigned job.
    pub expires_epoch: u64,
    /// Node's current verification epoch.
    pub current_epoch: u64,
    /// Credential resolved from the active provider registry.
    pub registered_credential_id: Hash64,
}

/// Derive the registry credential identity from an ML-DSA-87 verification key. This intentionally
/// matches `consensus-core::dns_finality::validator_id_from_pubkey`.
pub fn credential_id_from_verifying_key(verifying_key: &[u8]) -> Hash64 {
    let mut out = [0u8; HASH64_SIZE];
    out.copy_from_slice(Blake2bParams::new().hash_length(HASH64_SIZE).to_state().update(verifying_key).finalize().as_bytes());
    Hash64::from_bytes(out)
}

/// Derive the only valid execution nullifier for a worker's assigned slot and job.
pub fn execution_nullifier_v3(
    network_id: &Hash64,
    compute_set_id: &Hash64,
    job_challenge: &Hash64,
    worker_credential_id: &Hash64,
    replica_slot: u8,
    issued_epoch: u64,
) -> Hash64 {
    let mut preimage = Vec::with_capacity(2 + 4 * HASH64_SIZE + 1 + 8);
    preimage.extend_from_slice(&RECEIPT_V3_VERSION.to_le_bytes());
    for hash in [network_id, compute_set_id, job_challenge, worker_credential_id] {
        push_hash(&mut preimage, hash);
    }
    preimage.push(replica_slot);
    preimage.extend_from_slice(&issued_epoch.to_le_bytes());
    blake2b_512_keyed(PALW_RECEIPT_V3_EXECUTION_NULLIFIER_DOMAIN, &preimage)
}

/// Commit a node-issued challenge and a canonical `u32` token-id sequence. A count prefix makes an
/// empty sequence and all sequence boundaries explicit.
pub fn output_commitment_v3(tokens: &[u32], job_challenge: &Hash64) -> Hash64 {
    let mut preimage = Vec::with_capacity(2 + HASH64_SIZE + 8 + tokens.len() * 4);
    preimage.extend_from_slice(&RECEIPT_V3_VERSION.to_le_bytes());
    push_hash(&mut preimage, job_challenge);
    preimage.extend_from_slice(&(tokens.len() as u64).to_le_bytes());
    for token in tokens {
        preimage.extend_from_slice(&token.to_le_bytes());
    }
    blake2b_512_keyed(PALW_RECEIPT_V3_OUTPUT_DOMAIN, &preimage)
}

/// Fail-closed Receipt v3 verification failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyReceiptV3Error {
    /// Envelope selected an algorithm other than ML-DSA-87.
    UnsupportedAlgorithm(u8),
    /// Verification-key length was not ML-DSA-87's exact length.
    VerifyingKeyLength(usize),
    /// Signature length was not ML-DSA-87's exact length.
    SignatureLength(usize),
    /// Receipt version was not v3.
    ReceiptVersion(u16),
    /// Receipt slot was outside the closed set {0, 1}.
    InvalidReplicaSlot(u8),
    /// Receipt slot did not equal the assigned slot.
    ReplicaSlotMismatch,
    /// Receipt network did not equal the node expectation.
    NetworkMismatch,
    /// Receipt compute set did not equal the registered expected set.
    ComputeSetMismatch,
    /// Receipt challenge did not equal the node-issued job challenge.
    JobChallengeMismatch,
    /// Receipt issue epoch did not equal the job issue epoch.
    IssuedEpochMismatch,
    /// Receipt expiry epoch did not equal the job expiry epoch.
    ExpiresEpochMismatch,
    /// Receipt carried an inverted epoch window.
    InvalidEpochWindow,
    /// The receipt is not valid yet at the node's current epoch.
    NotYetValid,
    /// The receipt has expired at the node's current epoch.
    Expired,
    /// The verification-key-derived identity was not the selected-chain registered credential.
    UnregisteredCredential,
    /// Envelope credential did not equal the verification-key-derived credential.
    EnvelopeCredentialMismatch,
    /// Receipt credential did not equal the verification-key-derived credential.
    ReceiptCredentialMismatch,
    /// Receipt nullifier was not the node rederivation.
    ExecutionNullifierMismatch,
    /// Envelope digest did not equal the canonical receipt digest.
    BodyDigestMismatch,
    /// ML-DSA-87 verification failed under the Receipt v3 context.
    SignatureInvalid,
}

/// Verify one Receipt v3 submission against selected-chain expectations and the supplied ML-DSA-87
/// key. Every identity edge is checked explicitly:
/// `hash(vk) == registered == envelope.signer == receipt.worker`.
pub fn verify_receipt_v3(
    receipt: &ComputeReceiptV3,
    envelope: &SignedEnvelopeV3,
    verifying_key: &[u8],
    expected: &ReceiptV3Expectations,
) -> Result<(), VerifyReceiptV3Error> {
    if envelope.algorithm != MLDSA87_ALGORITHM_ID {
        return Err(VerifyReceiptV3Error::UnsupportedAlgorithm(envelope.algorithm));
    }
    let verifying_key: &[u8; MLDSA87_VERIFYING_KEY_LEN] =
        verifying_key.try_into().map_err(|_| VerifyReceiptV3Error::VerifyingKeyLength(verifying_key.len()))?;
    let signature: &[u8; MLDSA87_SIGNATURE_LEN] =
        envelope.signature.as_slice().try_into().map_err(|_| VerifyReceiptV3Error::SignatureLength(envelope.signature.len()))?;
    if receipt.receipt_version != RECEIPT_V3_VERSION {
        return Err(VerifyReceiptV3Error::ReceiptVersion(receipt.receipt_version));
    }
    if receipt.replica_slot > 1 {
        return Err(VerifyReceiptV3Error::InvalidReplicaSlot(receipt.replica_slot));
    }
    if receipt.replica_slot != expected.replica_slot {
        return Err(VerifyReceiptV3Error::ReplicaSlotMismatch);
    }
    if receipt.network_id != expected.network_id {
        return Err(VerifyReceiptV3Error::NetworkMismatch);
    }
    if receipt.projection.compute_set_id != expected.compute_set_id {
        return Err(VerifyReceiptV3Error::ComputeSetMismatch);
    }
    if receipt.projection.job_challenge != expected.job_challenge {
        return Err(VerifyReceiptV3Error::JobChallengeMismatch);
    }
    if receipt.issued_epoch != expected.issued_epoch {
        return Err(VerifyReceiptV3Error::IssuedEpochMismatch);
    }
    if receipt.expires_epoch != expected.expires_epoch {
        return Err(VerifyReceiptV3Error::ExpiresEpochMismatch);
    }
    if receipt.issued_epoch > receipt.expires_epoch {
        return Err(VerifyReceiptV3Error::InvalidEpochWindow);
    }
    if expected.current_epoch < receipt.issued_epoch {
        return Err(VerifyReceiptV3Error::NotYetValid);
    }
    if expected.current_epoch > receipt.expires_epoch {
        return Err(VerifyReceiptV3Error::Expired);
    }

    let derived_credential = credential_id_from_verifying_key(verifying_key);
    if derived_credential != expected.registered_credential_id {
        return Err(VerifyReceiptV3Error::UnregisteredCredential);
    }
    if envelope.signer_credential_id != derived_credential {
        return Err(VerifyReceiptV3Error::EnvelopeCredentialMismatch);
    }
    if receipt.worker_credential_id != derived_credential {
        return Err(VerifyReceiptV3Error::ReceiptCredentialMismatch);
    }

    let expected_nullifier = execution_nullifier_v3(
        &receipt.network_id,
        &receipt.projection.compute_set_id,
        &receipt.projection.job_challenge,
        &receipt.worker_credential_id,
        receipt.replica_slot,
        receipt.issued_epoch,
    );
    if receipt.execution_nullifier != expected_nullifier {
        return Err(VerifyReceiptV3Error::ExecutionNullifierMismatch);
    }

    if envelope.body_digest != receipt.signing_digest() {
        return Err(VerifyReceiptV3Error::BodyDigestMismatch);
    }

    let vk = mldsa::MLDSA87VerificationKey::new(*verifying_key);
    let sig = mldsa::MLDSA87Signature::new(*signature);
    if mldsa::portable::verify(&vk, envelope.body_digest.as_byte_slice(), PALW_RECEIPT_V3_MLDSA87_CONTEXT, &sig).is_err() {
        return Err(VerifyReceiptV3Error::SignatureInvalid);
    }
    Ok(())
}

/// Successful k=2 match output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MatchedPairV3 {
    /// Stable identity independent of receipt ordering and implementation telemetry.
    pair_id: Hash64,
}

impl MatchedPairV3 {
    /// Stable order-independent pair identity.
    pub const fn pair_id(&self) -> Hash64 {
        self.pair_id
    }
}

/// Fail-closed k=2 match failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MatchReceiptV3Error {
    /// Either body is not Receipt v3.
    ReceiptVersion,
    /// Networks differ.
    NetworkMismatch,
    /// Validity windows differ.
    EpochWindowMismatch,
    /// A slot is outside {0, 1}.
    InvalidReplicaSlot(u8),
    /// The pair did not contain distinct replica slots.
    SameReplicaSlot,
    /// The pair used the same registered worker credential.
    SameWorkerCredential,
    /// The pair reused one execution nullifier.
    SameExecutionNullifier,
    /// An exact-match projection field diverged.
    ProjectionMismatch(&'static str),
}

/// Low-level predicate over bodies that already passed [`verify_receipt_v3`]. Private so public
/// callers cannot accidentally turn unauthenticated JSON bodies into a match verdict.
fn match_verified_bodies_v3(a: &ComputeReceiptV3, b: &ComputeReceiptV3) -> Result<MatchedPairV3, MatchReceiptV3Error> {
    if a.receipt_version != RECEIPT_V3_VERSION || b.receipt_version != RECEIPT_V3_VERSION {
        return Err(MatchReceiptV3Error::ReceiptVersion);
    }
    if a.network_id != b.network_id {
        return Err(MatchReceiptV3Error::NetworkMismatch);
    }
    if a.issued_epoch != b.issued_epoch || a.expires_epoch != b.expires_epoch {
        return Err(MatchReceiptV3Error::EpochWindowMismatch);
    }
    if a.replica_slot > 1 {
        return Err(MatchReceiptV3Error::InvalidReplicaSlot(a.replica_slot));
    }
    if b.replica_slot > 1 {
        return Err(MatchReceiptV3Error::InvalidReplicaSlot(b.replica_slot));
    }
    if a.replica_slot == b.replica_slot {
        return Err(MatchReceiptV3Error::SameReplicaSlot);
    }
    if a.worker_credential_id == b.worker_credential_id {
        return Err(MatchReceiptV3Error::SameWorkerCredential);
    }
    if a.execution_nullifier == b.execution_nullifier {
        return Err(MatchReceiptV3Error::SameExecutionNullifier);
    }
    if let Some(field) = a.projection.first_mismatch(&b.projection) {
        return Err(MatchReceiptV3Error::ProjectionMismatch(field));
    }

    let a_tuple = (a.worker_credential_id, a.execution_nullifier);
    let b_tuple = (b.worker_credential_id, b.execution_nullifier);
    let (lo, hi) = if a_tuple <= b_tuple { (a_tuple, b_tuple) } else { (b_tuple, a_tuple) };
    let mut preimage = Vec::with_capacity(MatchProjectionV2::CANONICAL_LEN + 4 * HASH64_SIZE);
    push_hash(&mut preimage, &a.projection.digest());
    for hash in [&lo.0, &lo.1, &hi.0, &hi.1] {
        push_hash(&mut preimage, hash);
    }
    Ok(MatchedPairV3 { pair_id: blake2b_512_keyed(PALW_RECEIPT_V3_PAIR_DOMAIN, &preimage) })
}

/// Borrowed inputs for one independently verified replica submission.
pub struct ReceiptV3SubmissionRef<'a> {
    /// Canonical receipt body.
    pub receipt: &'a ComputeReceiptV3,
    /// ML-DSA-87 envelope.
    pub envelope: &'a SignedEnvelopeV3,
    /// Exact 2592-byte verification key.
    pub verifying_key: &'a [u8],
    /// Selected-chain job, epoch, network, and registry expectations.
    pub expected: &'a ReceiptV3Expectations,
}

/// Failures from [`verify_and_match_receipts_v3`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyAndMatchReceiptV3Error {
    /// Replica A failed independent verification.
    ReceiptA(VerifyReceiptV3Error),
    /// Replica B failed independent verification.
    ReceiptB(VerifyReceiptV3Error),
    /// Both replicas verified, but the k=2 predicate failed.
    Match(MatchReceiptV3Error),
}

/// Verify both replicas independently before evaluating the k=2 predicate. This is the only public
/// path to [`MatchedPairV3`].
pub fn verify_and_match_receipts_v3(
    a: ReceiptV3SubmissionRef<'_>,
    b: ReceiptV3SubmissionRef<'_>,
) -> Result<MatchedPairV3, VerifyAndMatchReceiptV3Error> {
    verify_receipt_v3(a.receipt, a.envelope, a.verifying_key, a.expected).map_err(VerifyAndMatchReceiptV3Error::ReceiptA)?;
    verify_receipt_v3(b.receipt, b.envelope, b.verifying_key, b.expected).map_err(VerifyAndMatchReceiptV3Error::ReceiptB)?;
    match_verified_bodies_v3(a.receipt, b.receipt).map_err(VerifyAndMatchReceiptV3Error::Match)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(byte: u8) -> Hash64 {
        Hash64::from_bytes([byte; HASH64_SIZE])
    }

    fn projection() -> MatchProjectionV2 {
        MatchProjectionV2 {
            compute_set_id: h(0x22),
            job_challenge: h(0x33),
            output_commitment: output_commitment_v3(&[3555, 374, 279, 7290, 315, 279], &h(0x33)),
            schedule_root: h(0x44),
            execution_root: h(0x55),
            route_root: h(0x66),
            state_root: h(0x77),
            canonical_compute_units: 41_692,
            token_count: 6,
            stop_reason: 0,
        }
    }

    fn signed(slot: u8, seed_byte: u8, class_byte: u8) -> (ComputeReceiptV3, SignedEnvelopeV3, Vec<u8>, ReceiptV3Expectations) {
        let keypair = mldsa::generate_key_pair([seed_byte; 32]);
        let verifying_key = keypair.verification_key.as_ref().to_vec();
        let credential = credential_id_from_verifying_key(&verifying_key);
        let network_id = h(0x11);
        let projection = projection();
        let issued_epoch = 10;
        let expires_epoch = 20;
        let execution_nullifier = execution_nullifier_v3(
            &network_id,
            &projection.compute_set_id,
            &projection.job_challenge,
            &credential,
            slot,
            issued_epoch,
        );
        let receipt = ComputeReceiptV3 {
            receipt_version: RECEIPT_V3_VERSION,
            network_id,
            projection,
            telemetry: ImplementationTelemetryV3 {
                runtime_class_id: [class_byte; 32],
                runtime_manifest_hash: [class_byte.wrapping_add(1); 32],
            },
            worker_credential_id: credential,
            replica_slot: slot,
            execution_nullifier,
            issued_epoch,
            expires_epoch,
        };
        let body_digest = receipt.signing_digest();
        let signature = mldsa::sign(&keypair.signing_key, body_digest.as_byte_slice(), PALW_RECEIPT_V3_MLDSA87_CONTEXT, [0u8; 32])
            .expect("sign")
            .as_ref()
            .to_vec();
        let envelope = SignedEnvelopeV3 { body_digest, algorithm: MLDSA87_ALGORITHM_ID, signer_credential_id: credential, signature };
        let expected = ReceiptV3Expectations {
            network_id,
            compute_set_id: receipt.projection.compute_set_id,
            job_challenge: receipt.projection.job_challenge,
            replica_slot: slot,
            issued_epoch,
            expires_epoch,
            current_epoch: 15,
            registered_credential_id: credential,
        };
        (receipt, envelope, verifying_key, expected)
    }

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            write!(&mut out, "{byte:02x}").unwrap();
            out
        })
    }

    #[test]
    #[ignore = "maintainer helper for refreshing the checked-in cross-repo fixture"]
    fn print_receipt_v3_golden_vector() {
        let (a, _, _, _) = signed(0, 1, 0xaa);
        let (b, _, _, _) = signed(1, 2, 0xbb);
        println!("canonical_body={}", hex(&a.canonical_bytes()));
        println!("output_commitment={}", hex(a.projection.output_commitment.as_byte_slice()));
        println!("projection_digest={}", hex(a.projection.digest().as_byte_slice()));
        println!("credential_id={}", hex(a.worker_credential_id.as_byte_slice()));
        println!("execution_nullifier={}", hex(a.execution_nullifier.as_byte_slice()));
        println!("signing_digest={}", hex(a.signing_digest().as_byte_slice()));
        println!("receipt_id={}", hex(a.receipt_id().as_byte_slice()));
        println!("pair_id={}", hex(match_verified_bodies_v3(&a, &b).unwrap().pair_id().as_byte_slice()));
    }

    #[test]
    fn node_owned_golden_vector_fixture_is_consumed() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../test-data/receipt_v3_golden_v1.json")).expect("valid fixture JSON");
        assert_eq!(fixture["schema"], "misaka.palw.receipt-v3-golden.v1");
        assert_eq!(fixture["inputs"]["worker_a_seed_byte"], 1);
        assert_eq!(fixture["inputs"]["worker_b_seed_byte"], 2);
        assert_eq!(fixture["inputs"]["worker_a_replica_slot"], 0);
        assert_eq!(fixture["inputs"]["worker_b_replica_slot"], 1);

        let expected = &fixture["expected"];
        let (a, _, _, _) = signed(0, 1, 0xaa);
        let (b, _, _, _) = signed(1, 2, 0xbb);
        assert_eq!(hex(&a.canonical_bytes()), expected["canonical_body_hex"].as_str().unwrap());
        assert_eq!(hex(a.projection.output_commitment.as_byte_slice()), expected["output_commitment_hex"].as_str().unwrap());
        assert_eq!(hex(a.projection.digest().as_byte_slice()), expected["projection_digest_hex"].as_str().unwrap());
        assert_eq!(hex(a.worker_credential_id.as_byte_slice()), expected["credential_id_hex"].as_str().unwrap());
        assert_eq!(hex(a.execution_nullifier.as_byte_slice()), expected["execution_nullifier_hex"].as_str().unwrap());
        assert_eq!(hex(a.signing_digest().as_byte_slice()), expected["signing_digest_hex"].as_str().unwrap());
        assert_eq!(hex(a.receipt_id().as_byte_slice()), expected["receipt_id_hex"].as_str().unwrap());
        assert_eq!(
            hex(match_verified_bodies_v3(&a, &b).unwrap().pair_id().as_byte_slice()),
            expected["pair_id_hex"].as_str().unwrap()
        );
    }

    #[test]
    fn domains_and_signature_context_are_pinned_and_distinct() {
        let hashes = [
            PALW_RECEIPT_V3_PROJECTION_DOMAIN,
            PALW_RECEIPT_V3_SIGNING_DOMAIN,
            PALW_RECEIPT_V3_ID_DOMAIN,
            PALW_RECEIPT_V3_EXECUTION_NULLIFIER_DOMAIN,
            PALW_RECEIPT_V3_OUTPUT_DOMAIN,
            PALW_RECEIPT_V3_PAIR_DOMAIN,
        ];
        for (i, a) in hashes.iter().enumerate() {
            assert!(!a.is_empty() && a.len() <= 64);
            for b in hashes.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
        assert_eq!(PALW_RECEIPT_V3_MLDSA87_CONTEXT, b"misaka-palw-v3/receipt/mldsa87");
        assert!(PALW_RECEIPT_V3_MLDSA87_CONTEXT.len() <= 255);
        assert!(!hashes.contains(&PALW_RECEIPT_V3_MLDSA87_CONTEXT));
    }

    #[test]
    fn explicit_canonical_encoding_equals_borsh_and_is_fixed_width() {
        let (receipt, _, _, _) = signed(0, 1, 0xaa);
        let projection_bytes = receipt.projection.canonical_bytes();
        assert_eq!(projection_bytes.len(), MatchProjectionV2::CANONICAL_LEN);
        assert_eq!(projection_bytes, borsh::to_vec(&receipt.projection).unwrap());
        let receipt_bytes = receipt.canonical_bytes();
        assert_eq!(receipt_bytes.len(), ComputeReceiptV3::CANONICAL_LEN);
        assert_eq!(receipt_bytes, borsh::to_vec(&receipt).unwrap());
        assert_eq!(&receipt_bytes[..2], &RECEIPT_V3_VERSION.to_le_bytes());
    }

    #[test]
    fn valid_receipt_verifies_with_all_identity_edges_bound() {
        let (receipt, envelope, verifying_key, expected) = signed(0, 1, 0xaa);
        assert_eq!(credential_id_from_verifying_key(&verifying_key), receipt.worker_credential_id);
        assert_eq!(verify_receipt_v3(&receipt, &envelope, &verifying_key, &expected), Ok(()));
    }

    #[test]
    fn verifier_rejects_every_structural_expected_identity_and_crypto_failure() {
        let (receipt, envelope, verifying_key, expected) = signed(0, 1, 0xaa);

        let mut bad_envelope = envelope.clone();
        bad_envelope.algorithm = 0;
        assert_eq!(
            verify_receipt_v3(&receipt, &bad_envelope, &verifying_key, &expected),
            Err(VerifyReceiptV3Error::UnsupportedAlgorithm(0))
        );
        assert_eq!(
            verify_receipt_v3(&receipt, &envelope, &verifying_key[..MLDSA87_VERIFYING_KEY_LEN - 1], &expected),
            Err(VerifyReceiptV3Error::VerifyingKeyLength(MLDSA87_VERIFYING_KEY_LEN - 1))
        );
        bad_envelope = envelope.clone();
        bad_envelope.signature.pop();
        assert_eq!(
            verify_receipt_v3(&receipt, &bad_envelope, &verifying_key, &expected),
            Err(VerifyReceiptV3Error::SignatureLength(MLDSA87_SIGNATURE_LEN - 1))
        );

        let mut bad_receipt = receipt.clone();
        bad_receipt.receipt_version = 2;
        assert_eq!(
            verify_receipt_v3(&bad_receipt, &envelope, &verifying_key, &expected),
            Err(VerifyReceiptV3Error::ReceiptVersion(2))
        );
        bad_receipt = receipt.clone();
        bad_receipt.replica_slot = 2;
        assert_eq!(
            verify_receipt_v3(&bad_receipt, &envelope, &verifying_key, &expected),
            Err(VerifyReceiptV3Error::InvalidReplicaSlot(2))
        );
        let mut bad_expected = expected.clone();
        bad_expected.replica_slot = 1;
        assert_eq!(
            verify_receipt_v3(&receipt, &envelope, &verifying_key, &bad_expected),
            Err(VerifyReceiptV3Error::ReplicaSlotMismatch)
        );
        bad_expected = expected.clone();
        bad_expected.network_id = h(0xfe);
        assert_eq!(verify_receipt_v3(&receipt, &envelope, &verifying_key, &bad_expected), Err(VerifyReceiptV3Error::NetworkMismatch));
        bad_expected = expected.clone();
        bad_expected.compute_set_id = h(0xfe);
        assert_eq!(
            verify_receipt_v3(&receipt, &envelope, &verifying_key, &bad_expected),
            Err(VerifyReceiptV3Error::ComputeSetMismatch)
        );
        bad_expected = expected.clone();
        bad_expected.job_challenge = h(0xfe);
        assert_eq!(
            verify_receipt_v3(&receipt, &envelope, &verifying_key, &bad_expected),
            Err(VerifyReceiptV3Error::JobChallengeMismatch)
        );
        bad_expected = expected.clone();
        bad_expected.issued_epoch += 1;
        assert_eq!(
            verify_receipt_v3(&receipt, &envelope, &verifying_key, &bad_expected),
            Err(VerifyReceiptV3Error::IssuedEpochMismatch)
        );
        bad_expected = expected.clone();
        bad_expected.expires_epoch += 1;
        assert_eq!(
            verify_receipt_v3(&receipt, &envelope, &verifying_key, &bad_expected),
            Err(VerifyReceiptV3Error::ExpiresEpochMismatch)
        );

        bad_receipt = receipt.clone();
        bad_receipt.issued_epoch = 21;
        bad_receipt.expires_epoch = 20;
        bad_expected = expected.clone();
        bad_expected.issued_epoch = 21;
        assert_eq!(
            verify_receipt_v3(&bad_receipt, &envelope, &verifying_key, &bad_expected),
            Err(VerifyReceiptV3Error::InvalidEpochWindow)
        );
        bad_expected = expected.clone();
        bad_expected.current_epoch = receipt.issued_epoch - 1;
        assert_eq!(verify_receipt_v3(&receipt, &envelope, &verifying_key, &bad_expected), Err(VerifyReceiptV3Error::NotYetValid));
        bad_expected = expected.clone();
        bad_expected.current_epoch = receipt.expires_epoch + 1;
        assert_eq!(verify_receipt_v3(&receipt, &envelope, &verifying_key, &bad_expected), Err(VerifyReceiptV3Error::Expired));

        bad_expected = expected.clone();
        bad_expected.registered_credential_id = h(0xfe);
        assert_eq!(
            verify_receipt_v3(&receipt, &envelope, &verifying_key, &bad_expected),
            Err(VerifyReceiptV3Error::UnregisteredCredential)
        );
        bad_envelope = envelope.clone();
        bad_envelope.signer_credential_id = h(0xfe);
        assert_eq!(
            verify_receipt_v3(&receipt, &bad_envelope, &verifying_key, &expected),
            Err(VerifyReceiptV3Error::EnvelopeCredentialMismatch)
        );
        bad_receipt = receipt.clone();
        bad_receipt.worker_credential_id = h(0xfe);
        assert_eq!(
            verify_receipt_v3(&bad_receipt, &envelope, &verifying_key, &expected),
            Err(VerifyReceiptV3Error::ReceiptCredentialMismatch)
        );
        bad_receipt = receipt.clone();
        bad_receipt.execution_nullifier = h(0xfe);
        assert_eq!(
            verify_receipt_v3(&bad_receipt, &envelope, &verifying_key, &expected),
            Err(VerifyReceiptV3Error::ExecutionNullifierMismatch)
        );
        bad_receipt = receipt.clone();
        bad_receipt.telemetry.runtime_manifest_hash[0] ^= 1;
        assert_eq!(
            verify_receipt_v3(&bad_receipt, &envelope, &verifying_key, &expected),
            Err(VerifyReceiptV3Error::BodyDigestMismatch)
        );
        bad_envelope = envelope.clone();
        bad_envelope.signature[MLDSA87_SIGNATURE_LEN / 2] ^= 1;
        assert_eq!(verify_receipt_v3(&receipt, &bad_envelope, &verifying_key, &expected), Err(VerifyReceiptV3Error::SignatureInvalid));

        let keypair = mldsa::generate_key_pair([1u8; 32]);
        bad_envelope = envelope.clone();
        bad_envelope.signature =
            mldsa::sign(&keypair.signing_key, envelope.body_digest.as_byte_slice(), b"misaka-palw-v3/wrong/mldsa87", [0u8; 32])
                .unwrap()
                .as_ref()
                .to_vec();
        assert_eq!(verify_receipt_v3(&receipt, &bad_envelope, &verifying_key, &expected), Err(VerifyReceiptV3Error::SignatureInvalid));
    }

    #[test]
    fn cross_runtime_pair_matches_and_pair_id_is_order_independent() {
        let (a, ea, vka, xa) = signed(0, 1, 0xaa);
        let (b, eb, vkb, xb) = signed(1, 2, 0xbb);
        verify_receipt_v3(&a, &ea, &vka, &xa).unwrap();
        verify_receipt_v3(&b, &eb, &vkb, &xb).unwrap();
        assert_ne!(a.telemetry, b.telemetry);
        let ab = match_verified_bodies_v3(&a, &b).unwrap();
        let ba = match_verified_bodies_v3(&b, &a).unwrap();
        assert_eq!(ab, ba);

        let mut changed_telemetry = b.clone();
        changed_telemetry.telemetry.runtime_class_id = [0xcc; 32];
        assert_eq!(match_verified_bodies_v3(&a, &changed_telemetry).unwrap().pair_id(), ab.pair_id());
    }

    #[test]
    fn public_verify_and_match_cannot_be_reached_by_invalid_signature_or_registry_binding() {
        let (a, ea, vka, xa) = signed(0, 1, 0xaa);
        let (b, eb, vkb, xb) = signed(1, 2, 0xbb);
        let submit = |receipt, envelope, key, expected| ReceiptV3SubmissionRef { receipt, envelope, verifying_key: key, expected };

        assert!(verify_and_match_receipts_v3(submit(&a, &ea, &vka, &xa), submit(&b, &eb, &vkb, &xb)).is_ok());

        let mut bad_signature = eb.clone();
        bad_signature.signature[MLDSA87_SIGNATURE_LEN / 2] ^= 1;
        assert_eq!(
            verify_and_match_receipts_v3(submit(&a, &ea, &vka, &xa), submit(&b, &bad_signature, &vkb, &xb),),
            Err(VerifyAndMatchReceiptV3Error::ReceiptB(VerifyReceiptV3Error::SignatureInvalid))
        );

        let mut unregistered = xb.clone();
        unregistered.registered_credential_id = h(0xfe);
        assert_eq!(
            verify_and_match_receipts_v3(submit(&a, &ea, &vka, &xa), submit(&b, &eb, &vkb, &unregistered),),
            Err(VerifyAndMatchReceiptV3Error::ReceiptB(VerifyReceiptV3Error::UnregisteredCredential))
        );
    }

    #[test]
    fn matcher_rejects_all_non_match_and_non_independence_cases() {
        let (a, _, _, _) = signed(0, 1, 0xaa);
        let (b, _, _, _) = signed(1, 2, 0xbb);

        let mut bad = b.clone();
        bad.receipt_version = 2;
        assert_eq!(match_verified_bodies_v3(&a, &bad), Err(MatchReceiptV3Error::ReceiptVersion));
        bad = b.clone();
        bad.network_id = h(0xfe);
        assert_eq!(match_verified_bodies_v3(&a, &bad), Err(MatchReceiptV3Error::NetworkMismatch));
        bad = b.clone();
        bad.expires_epoch += 1;
        assert_eq!(match_verified_bodies_v3(&a, &bad), Err(MatchReceiptV3Error::EpochWindowMismatch));
        bad = b.clone();
        bad.replica_slot = 2;
        assert_eq!(match_verified_bodies_v3(&a, &bad), Err(MatchReceiptV3Error::InvalidReplicaSlot(2)));
        bad = b.clone();
        bad.replica_slot = a.replica_slot;
        assert_eq!(match_verified_bodies_v3(&a, &bad), Err(MatchReceiptV3Error::SameReplicaSlot));
        bad = b.clone();
        bad.worker_credential_id = a.worker_credential_id;
        assert_eq!(match_verified_bodies_v3(&a, &bad), Err(MatchReceiptV3Error::SameWorkerCredential));
        bad = b.clone();
        bad.execution_nullifier = a.execution_nullifier;
        assert_eq!(match_verified_bodies_v3(&a, &bad), Err(MatchReceiptV3Error::SameExecutionNullifier));

        let fields: [(&str, fn(&mut MatchProjectionV2)); 10] = [
            ("compute_set_id", |p| p.compute_set_id = h(0xfe)),
            ("job_challenge", |p| p.job_challenge = h(0xfe)),
            ("output_commitment", |p| p.output_commitment = h(0xfe)),
            ("schedule_root", |p| p.schedule_root = h(0xfe)),
            ("execution_root", |p| p.execution_root = h(0xfe)),
            ("route_root", |p| p.route_root = h(0xfe)),
            ("state_root", |p| p.state_root = h(0xfe)),
            ("canonical_compute_units", |p| p.canonical_compute_units += 1),
            ("token_count", |p| p.token_count += 1),
            ("stop_reason", |p| p.stop_reason += 1),
        ];
        for (name, mutate) in fields {
            bad = b.clone();
            mutate(&mut bad.projection);
            assert_eq!(match_verified_bodies_v3(&a, &bad), Err(MatchReceiptV3Error::ProjectionMismatch(name)), "field {name}");
        }
    }
}
