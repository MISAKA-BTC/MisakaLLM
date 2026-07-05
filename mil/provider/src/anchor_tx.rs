//! v0 on-chain anchor transactions (design §8.1).
//!
//! Registration and receipt anchors ride ordinary **NATIVE** transactions
//! whose payload carries the borsh MIL anchor document
//! ([`misaka_mil_core::anchor`]). This fork places no payload restriction on
//! native txs, so anchoring needs zero consensus changes; the provider funds
//! the tx from its own P2PKH-ML-DSA UTXOs (direct pay, §8.1) and signs each
//! input under [`MLDSA87_TX_CONTEXT`] — the exact signing shape the validator
//! sidecar uses for its overlay txs.
//!
//! Pure builders only: funding discovery and submission live in the binary
//! (mirroring the `kaspa-pq-validator` core/bin split). Anchoring is opt-in
//! and dry-run by default.

use kaspa_consensus_core::constants::{MAX_TX_IN_SEQUENCE_NUM, TX_VERSION};
use kaspa_consensus_core::hashing::sighash::{Mldsa87SigHashReusedValuesUnsync, calc_mldsa87_signature_hash};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::mass::MassCalculator;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    MutableTransaction, PopulatedTransaction, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_hashes::Hash64;
use kaspa_pq_validator_core::{ValidatorKey, relay_fee_for_compute_mass};
use kaspa_txscript::{MLDSA87_TX_CONTEXT, pay_to_address_script, script_builder::ScriptBuilder};
use misaka_mil_core::anchor::{MilAnchorPayload, encode_anchor_payload};
use misaka_mil_core::anchor::{ProviderRegistrationV1, ReceiptAnchorV1};
use misaka_mil_core::receipt::SignedReceipt;

/// Build a signed NATIVE transaction that anchors `payload`, funded by
/// `fundings` (all locked to `key`'s own funding script), returning the fee
/// change to that same script. Every input is ML-DSA-87 signed under
/// [`MLDSA87_TX_CONTEXT`] over the SIG_HASH_ALL v2 sighash.
pub fn build_anchor_tx(
    key: &ValidatorKey,
    payload: &MilAnchorPayload,
    fundings: &[(TransactionOutpoint, UtxoEntry)],
    fee: u64,
    storage_mass_parameter: u64,
) -> Result<Transaction, String> {
    if fundings.is_empty() {
        return Err("anchor tx needs at least one funding UTXO".to_string());
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

/// Mass-based fee (sompi) for an anchor tx carrying `payload`, for
/// `n_inputs` funding UTXOs. Builds a dummy tx of the real shape (field sizes,
/// not values, drive the compute mass) and takes its relay-rate fee — same
/// method as the validator's `estimate_*_fee`.
pub fn estimate_anchor_fee(
    key: &ValidatorKey,
    mass_calculator: &MassCalculator,
    prefix: kaspa_addresses::Prefix,
    payload: &MilAnchorPayload,
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
    match build_anchor_tx(key, payload, &fundings, kaspa_pq_validator_core::ATTESTATION_TX_FEE_FLOOR_SOMPI, 0) {
        Ok(tx) => relay_fee_for_compute_mass(mass_calculator.calc_non_contextual_masses(&tx).compute_mass),
        Err(_) => kaspa_pq_validator_core::ATTESTATION_TX_FEE_FLOOR_SOMPI,
    }
}

/// Convenience wrappers for the two anchor kinds.
pub fn registration_payload(reg: ProviderRegistrationV1) -> MilAnchorPayload {
    MilAnchorPayload::ProviderRegistration(reg)
}

/// Build a [`ReceiptAnchorV1`] from a final signed receipt (§8.1) and the
/// provider id.
pub fn receipt_anchor_payload(provider_id: Hash64, receipt: &SignedReceipt) -> MilAnchorPayload {
    let b = &receipt.body;
    MilAnchorPayload::ReceiptAnchor(ReceiptAnchorV1 {
        version: b.version,
        provider_id,
        session_id: b.session_id,
        counter: b.counter,
        cum_tokens_in: b.cum_tokens_in,
        cum_tokens_out: b.cum_tokens_out,
        cm_resp: b.cm_resp,
        receipt_hash: receipt.receipt_hash(),
        is_final: b.is_final,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_addresses::Prefix;
    use misaka_mil_core::domains::MIL_PROTOCOL_VERSION;
    use misaka_mil_core::ident::provider_id;
    use misaka_mil_core::job::{SlaParams, Tier};

    fn dummy_funding(key: &ValidatorKey, amount: u64) -> (TransactionOutpoint, UtxoEntry) {
        let spk = pay_to_address_script(&key.funding_address(Prefix::Testnet));
        (TransactionOutpoint::new(Hash64::from_bytes([9u8; 64]), 0), UtxoEntry::new(amount, spk, 0, false))
    }

    fn registration(key: &ValidatorKey) -> MilAnchorPayload {
        registration_payload(ProviderRegistrationV1 {
            version: MIL_PROTOCOL_VERSION,
            provider_id: provider_id(key.public_key()),
            quote_hash: Hash64::from_bytes([1u8; 64]),
            model_id: Hash64::from_bytes([2u8; 64]),
            tier: Tier::Open,
            gpu_class_weight: 1,
            pk_kem: vec![0x11u8; 1568],
            pk_receipt: key.public_key().to_vec(),
            binding: Hash64::from_bytes([3u8; 64]),
            ask_in_per_1k_sompi: 100_000,
            ask_out_per_1k_sompi: 500_000,
            sla: SlaParams { ttfb_ms: 1500, min_tps: 20 },
            region: "test".into(),
            data_plane_addr: "127.0.0.1:37110".into(),
            hot: true,
            timestamp_ms: 1_780_000_000_000,
        })
    }

    #[test]
    fn anchor_tx_is_native_carries_payload_and_is_signed() {
        let key = ValidatorKey::from_seed([5u8; 32]);
        let payload = registration(&key);
        let funding = dummy_funding(&key, 10_000_000);
        let tx = build_anchor_tx(&key, &payload, &[funding], 250_000, 0).unwrap();

        assert!(tx.subnetwork_id.is_native());
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].value, 10_000_000 - 250_000);
        assert!(!tx.inputs[0].signature_script.is_empty(), "input must be signed");

        // the payload round-trips back to the same anchor
        let decoded = misaka_mil_core::anchor::decode_anchor_payload(&tx.payload).unwrap().unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn underfunded_anchor_is_rejected() {
        let key = ValidatorKey::from_seed([5u8; 32]);
        let payload = registration(&key);
        let funding = dummy_funding(&key, 100_000);
        assert!(build_anchor_tx(&key, &payload, &[funding], 250_000, 0).is_err());
        assert!(build_anchor_tx(&key, &payload, &[], 1, 0).is_err());
    }

    #[test]
    fn receipt_anchor_payload_matches_receipt() {
        use misaka_mil_core::receipt::{ReceiptBody, ReceiptSigner};
        let signer = ReceiptSigner::from_seed([3u8; 32]);
        let receipt = signer.sign(ReceiptBody {
            version: MIL_PROTOCOL_VERSION,
            session_id: Hash64::from_bytes([1u8; 64]),
            counter: 4,
            cum_tokens_in: 20,
            cum_tokens_out: 2048,
            timestamp_ms: 1,
            cm_resp: Hash64::from_bytes([2u8; 64]),
            is_final: true,
        });
        let pid = provider_id(signer.public_key());
        let MilAnchorPayload::ReceiptAnchor(a) = receipt_anchor_payload(pid, &receipt) else {
            panic!("expected receipt anchor");
        };
        assert_eq!(a.receipt_hash, receipt.receipt_hash());
        assert_eq!(a.cum_tokens_out, 2048);
        assert!(a.is_final);
    }
}
