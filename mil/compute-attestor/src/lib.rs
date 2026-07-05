//! MISAKA Inference Lane (MIL) compute-attestor — Phase A library (ADR-0024 §20).
//!
//! A GPU provider that takes on the security-issuance duty runs this sidecar. It
//! **mirrors the DNS-validator epoch-attestation flow** (`kaspa-pq-validator`):
//! per epoch it signs the ready-to-attest chain anchor with its ML-DSA-87 key
//! under the disjoint compute-attest context, commits its device-certificate
//! hash (§20.5), and records the attestation on-chain.
//!
//! **Phase A is consensus-neutral by construction.** The attestation is carried
//! as an ordinary NATIVE-tx payload (the same `MilAnchorPayload` mechanism the
//! v0 provider anchors use) — there is no new subnetwork, no coinbase change,
//! and no reorg-gate participation, so it adds **zero liveness risk**. A
//! keeper/indexer reads these payloads to measure `compute_depth`. The issuance
//! reward (reviving the `FeeSplitParams` service slot, §20.4) and the Phase-C
//! reorg-gate dimension are separate HF-gated steps and are NOT here.

use kaspa_addresses::{Address, Prefix};
use kaspa_consensus_core::constants::{MAX_TX_IN_SEQUENCE_NUM, TX_VERSION};
use kaspa_consensus_core::hashing::sighash::{Mldsa87SigHashReusedValuesUnsync, calc_mldsa87_signature_hash};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::mass::MassCalculator;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    MutableTransaction, PopulatedTransaction, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_hashes::Hash64;
use kaspa_pq_validator_core::{ATTESTATION_TX_FEE_FLOOR_SOMPI, ValidatorKey, relay_fee_for_compute_mass};
use kaspa_txscript::{MLDSA87_TX_CONTEXT, pay_to_address_script, script_builder::ScriptBuilder};
use misaka_mil_core::anchor::{MilAnchorPayload, encode_anchor_payload};
use misaka_mil_core::compute_attest::{BondOutpoint, ComputeAttestation, ComputeAttestationBody, attestor_id};
use misaka_mil_core::domains::{MIL_COMPUTE_ATTEST_MLDSA87_CONTEXT, MIL_PROTOCOL_VERSION};
use misaka_mil_core::job::Tier;

/// Length of the compute-attestor ML-DSA-87 keygen seed (matches the validator).
pub const ATTESTOR_SEED_LEN: usize = 32;

/// The materialized compute-attestor key: an ML-DSA-87 keypair (reused from the
/// validator core, so the funding-tx signing + address derivation are shared)
/// plus its compute-attestor overlay identity.
pub struct ComputeAttestorKey {
    key: ValidatorKey,
    /// Overlay identity `Hash64_k("misaka-mil-v1/compute-attest", pubkey)`.
    pub attestor_id: Hash64,
}

impl ComputeAttestorKey {
    pub fn from_seed(seed: [u8; ATTESTOR_SEED_LEN]) -> Self {
        let key = ValidatorKey::from_seed(seed);
        let attestor_id = attestor_id(key.public_key());
        Self { key, attestor_id }
    }

    /// The raw ML-DSA-87 verification key.
    pub fn public_key(&self) -> &[u8] {
        self.key.public_key()
    }

    /// The attestor's own P2PKH-ML-DSA funding address (pays the anchor fee).
    pub fn funding_address(&self, prefix: Prefix) -> Address {
        self.key.funding_address(prefix)
    }

    /// Sign an epoch attestation body for `network_id` under the compute-attest
    /// context, producing a self-contained [`ComputeAttestation`].
    pub fn sign_attestation(&self, body: ComputeAttestationBody, network_id: &[u8]) -> ComputeAttestation {
        let signature = self.key.sign_with_context(&body.signing_message(network_id), MIL_COMPUTE_ATTEST_MLDSA87_CONTEXT).to_vec();
        ComputeAttestation { body, signature, attestor_pubkey: self.public_key().to_vec() }
    }

    /// Assemble the signed attestation body from the per-epoch inputs.
    pub fn attestation_body(
        &self,
        bond: BondOutpoint,
        epoch: u64,
        target_hash: Hash64,
        target_daa_score: u64,
        device_cert_hash: Hash64,
        tier: Tier,
    ) -> ComputeAttestationBody {
        ComputeAttestationBody {
            version: MIL_PROTOCOL_VERSION,
            attestor_id: self.attestor_id,
            bond,
            epoch,
            target_hash,
            target_daa_score,
            device_cert_hash,
            tier,
        }
    }

    /// Build a fee-funded, signed NATIVE transaction anchoring `attestation` as
    /// a `MilAnchorPayload` (Phase A record path). Same signing shape as the
    /// validator's overlay txs; funded from this key's own P2PKH-ML-DSA UTXOs.
    pub fn build_attestation_anchor_tx(
        &self,
        attestation: ComputeAttestation,
        fundings: &[(TransactionOutpoint, UtxoEntry)],
        fee: u64,
        storage_mass_parameter: u64,
    ) -> Result<Transaction, String> {
        let payload = MilAnchorPayload::ComputeAttestation(attestation);
        build_anchor_tx(&self.key, &payload, fundings, fee, storage_mass_parameter)
    }
}

/// Build a signed NATIVE transaction carrying a MIL anchor `payload`, funded by
/// `fundings` (all at `key`'s own funding script), change back to it. Every
/// input is ML-DSA-87 signed under [`MLDSA87_TX_CONTEXT`] — the exact overlay-tx
/// signing shape the validator sidecar uses.
pub fn build_anchor_tx(
    key: &ValidatorKey,
    payload: &MilAnchorPayload,
    fundings: &[(TransactionOutpoint, UtxoEntry)],
    fee: u64,
    storage_mass_parameter: u64,
) -> Result<Transaction, String> {
    if fundings.is_empty() {
        return Err("attestation anchor tx needs at least one funding UTXO".to_string());
    }
    let payload_bytes = encode_anchor_payload(payload).map_err(|e| format!("anchor payload encode failed: {e}"))?;
    let total: u64 = fundings.iter().try_fold(0u64, |acc, (_, e)| acc.checked_add(e.amount)).ok_or("funding total overflows u64")?;
    if total <= fee {
        return Err(format!("funding total {total} does not cover fee {fee}"));
    }
    let self_spk = fundings[0].1.script_public_key.clone();
    let inputs: Vec<TransactionInput> =
        fundings.iter().map(|(op, _)| TransactionInput::new(*op, vec![], MAX_TX_IN_SEQUENCE_NUM, 1)).collect();
    let entries: Vec<UtxoEntry> = fundings.iter().map(|(_, e)| e.clone()).collect();
    let change = TransactionOutput::new(total - fee, self_spk);
    let tx = Transaction::new(TX_VERSION, inputs, vec![change], 0, SUBNETWORK_ID_NATIVE, 0, payload_bytes);

    let storage_mass = MassCalculator::new(0, 0, 0, storage_mass_parameter)
        .calc_contextual_masses(&PopulatedTransaction::new(&tx, entries.clone()))
        .ok_or("contextual mass not computable for the anchor tx")?
        .storage_mass;
    tx.set_mass(storage_mass);

    let mtx = MutableTransaction::with_entries(tx, entries);
    let reused = Mldsa87SigHashReusedValuesUnsync::new();
    let mut sig_scripts = Vec::with_capacity(fundings.len());
    for i in 0..fundings.len() {
        let sighash = calc_mldsa87_signature_hash(&mtx.as_verifiable(), i, SIG_HASH_ALL, &reused);
        let mut sig_data = key.sign_with_context(sighash.as_bytes().as_slice(), MLDSA87_TX_CONTEXT).to_vec();
        sig_data.push(SIG_HASH_ALL.to_u8());
        let script = ScriptBuilder::new()
            .add_data(&sig_data)
            .map_err(|e| format!("anchor sig push failed: {e}"))?
            .add_data(key.public_key())
            .map_err(|e| format!("anchor pubkey push failed: {e}"))?
            .drain();
        sig_scripts.push(script);
    }
    let mut tx = mtx.tx;
    for (i, script) in sig_scripts.into_iter().enumerate() {
        tx.inputs[i].signature_script = script;
    }
    Ok(tx)
}

/// Mass-based fee (sompi) for an attestation anchor tx with `n_inputs` funding
/// UTXOs — a dummy tx of the real shape, same method as the validator estimators.
pub fn estimate_attestation_anchor_fee(
    key: &ComputeAttestorKey,
    mass_calculator: &MassCalculator,
    prefix: Prefix,
    network_id: &[u8],
    n_inputs: usize,
) -> u64 {
    let funding_spk = pay_to_address_script(&key.funding_address(prefix));
    let n = n_inputs.max(1);
    let per = u64::MAX / (2 * n as u64);
    let fundings: Vec<(TransactionOutpoint, UtxoEntry)> = (0..n)
        .map(|i| {
            let mut id = [0u8; 64];
            id[0] = i as u8;
            id[1] = (i >> 8) as u8;
            (TransactionOutpoint::new(Hash64::from_bytes(id), 0), UtxoEntry::new(per, funding_spk.clone(), 0, false))
        })
        .collect();
    let dummy = key.sign_attestation(
        key.attestation_body(
            BondOutpoint { txid: Hash64::from_bytes([0u8; 64]), index: 0 },
            0,
            Hash64::from_bytes([0u8; 64]),
            0,
            Hash64::from_bytes([0u8; 64]),
            Tier::Open,
        ),
        network_id,
    );
    match key.build_attestation_anchor_tx(dummy, &fundings, ATTESTATION_TX_FEE_FLOOR_SOMPI, 0) {
        Ok(tx) => relay_fee_for_compute_mass(mass_calculator.calc_non_contextual_masses(&tx).compute_mass),
        Err(_) => ATTESTATION_TX_FEE_FLOOR_SOMPI,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn funding(key: &ComputeAttestorKey, amount: u64) -> (TransactionOutpoint, UtxoEntry) {
        let spk = pay_to_address_script(&key.funding_address(Prefix::Testnet));
        (TransactionOutpoint::new(Hash64::from_bytes([9u8; 64]), 0), UtxoEntry::new(amount, spk, 0, false))
    }

    #[test]
    fn signs_verifiable_attestation_and_anchor_tx() {
        let key = ComputeAttestorKey::from_seed([5u8; 32]);
        let net = b"testnet-10";
        let body = key.attestation_body(
            BondOutpoint { txid: Hash64::from_bytes([1u8; 64]), index: 3 },
            77,
            Hash64::from_bytes([2u8; 64]),
            2_000_000,
            Hash64::from_bytes([3u8; 64]),
            Tier::Tee,
        );
        let att = key.sign_attestation(body, net);
        att.verify(net).expect("attestor-signed attestation must verify");
        assert_eq!(att.body.attestor_id, key.attestor_id);

        // it rides a native tx as a MIL anchor payload
        let tx = key.build_attestation_anchor_tx(att.clone(), &[funding(&key, 10_000_000)], 250_000, 0).unwrap();
        assert!(tx.subnetwork_id.is_native());
        assert!(!tx.inputs[0].signature_script.is_empty());
        let decoded = misaka_mil_core::anchor::decode_anchor_payload(&tx.payload).unwrap().unwrap();
        assert_eq!(decoded, MilAnchorPayload::ComputeAttestation(att));
    }

    #[test]
    fn attestor_id_binds_the_key() {
        let a = ComputeAttestorKey::from_seed([7u8; 32]);
        let b = ComputeAttestorKey::from_seed([7u8; 32]);
        let c = ComputeAttestorKey::from_seed([8u8; 32]);
        assert_eq!(a.attestor_id, b.attestor_id);
        assert_ne!(a.attestor_id, c.attestor_id);
        assert_eq!(a.attestor_id, attestor_id(a.public_key()));
    }
}
