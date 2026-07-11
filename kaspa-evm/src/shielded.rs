//! F006 `SHIELDED_VERIFY` precompile (ADR-0033 §5.2 / ADR-0025 §21 L2). A PURE
//! verifier the `ShieldedPool` (F010) and the anonymous `JobEscrow` claim path
//! call to make a spend/claim private WITHOUT naming which note or which provider.
//!
//! Same shape as F003 (`mldsa_verify`): registered ONLY at/above its (own) fence
//! (`crate::precompiles::register_all_misaka_precompiles`, gated on `f006_active`);
//! below the fence the handler is absent and `0x…F006` is an empty account
//! (byte-identical execution, genesis/state-root unchanged). Fail-closed: any
//! malformed/invalid/inactive-proof-system input returns ABI `false`, never a
//! panic or revert (except the non-payable value guard). [`F006_VERIFY_GAS`] is
//! charged up-front so a malformed-proof flood pays the same — the per-block
//! `EVM_GAS_LIMIT / F006_VERIFY_GAS` ceiling on shielded-verify CPU.
//!
//! ## Calldata (`input`)
//!
//! ```text
//! version(1)=0x01 ‖ expected_vk_hash(64) ‖ shield_proof(borsh ShieldProof, var)
//! ```
//!
//! `expected_vk_hash` is the verifier key the *caller contract* trusts for the
//! circuit (governance-pinned in the pool/escrow); the precompile enforces the
//! proof's `verifier_key_hash` equals it, so a proof can only satisfy a contract
//! that already trusts its circuit. Output is a 32-byte ABI bool.

use kaspa_consensus_core::evm::{F006_VERIFY_GAS, MISAKA_SHIELDED_VERIFY_PRECOMPILE};
use kaspa_hashes::Hash64;
use misaka_mil_shield::{ProofPolicy, verify_shield_proof_with_policy};
use misaka_mil_shield_stark_verify::StarkBackend;
use revm::handler::register::EvmHandler;
use revm::interpreter::{CallOutcome, Gas, InstructionResult, InterpreterResult};
use revm::primitives::{Address, Bytes};
use revm::{Database, FrameOrResult, FrameResult};

/// The reserved F006 address as a revm [`Address`].
pub fn f006_address() -> Address {
    Address::from(MISAKA_SHIELDED_VERIFY_PRECOMPILE.as_bytes())
}

/// Calldata version tag for a shielded-verify call.
const F006_VERSION_SHIELDED: u8 = 0x01;

/// Map the per-network `stark_only` consensus flag to the acceptance policy (audit H-03 /
/// A7). `Params::evm_f006_shielded_verify_stark_only` is `true` on mainnet (StarkOnly —
/// transparent reference proofs rejected) and `false` on the testnet stepping-stone; it is
/// threaded from the executor input into [`register_f006_shielded_verify`], so the policy is
/// the real, network-correct code path (not a hard-coded value). Inert while the F006 fence
/// is `u64::MAX`; activation only flips the fence.
fn f006_proof_policy(stark_only: bool) -> ProofPolicy {
    if stark_only { ProofPolicy::StarkOnly } else { ProofPolicy::ReferenceAndStark }
}

fn abi_bool(b: bool) -> Bytes {
    let mut out = [0u8; 32];
    if b {
        out[31] = 1;
    }
    Bytes::from(out.to_vec())
}

/// The verify logic (pure): `true` iff the calldata is a well-formed shielded
/// proof over a statement whose `verifier_key_hash` equals the caller's pinned
/// key AND the proof verifies. Fail-closed on every other input.
pub fn run_f006_shielded_verify(input: &[u8], stark_only: bool) -> bool {
    // version(1) ‖ vk_hash(64) ‖ proof(var)
    if input.first() != Some(&F006_VERSION_SHIELDED) || input.len() < 1 + 64 {
        return false;
    }
    let vk_hash = Hash64::from_bytes(match input[1..1 + 64].try_into() {
        Ok(a) => a,
        Err(_) => return false,
    });
    let proof = &input[1 + 64..];
    // The reference→STARK swap (ADR-0034 §5): route through the injected
    // `StarkBackend` instead of the default inert verifier. REFERENCE proofs are
    // still verified in-process; STARK-tagged proofs go to the backend, which is
    // fail-closed (`ProofSystemNotActivated`) until the audited §SP-0 milestone — so
    // this wiring is behaviourally inert (identical ABI result for every input) yet
    // makes F006 STARK-ready: activation is then only the fence flip + policy change,
    // no code change here. Panic-free (verify returns `Err`, never unwinds). The
    // acceptance policy (audit H-03) is applied here, not hard-coded in the verify.
    verify_shield_proof_with_policy(proof, &vk_hash, &StarkBackend, f006_proof_policy(stark_only)).is_ok()
}

/// Wrap `handler.execution.call` so calls targeting F006 run the shielded verify.
/// Registered ONLY when `f006_active` (see
/// [`crate::precompiles::register_all_misaka_precompiles`]).
pub fn register_f006_shielded_verify<EXT, DB: Database>(handler: &mut EvmHandler<'_, EXT, DB>, stark_only: bool) {
    let prev = handler.execution.call.clone();
    handler.execution.call = std::sync::Arc::new(move |ctx, inputs| {
        let f006 = f006_address();
        if inputs.target_address != f006 || inputs.bytecode_address != f006 {
            return prev(ctx, inputs);
        }
        // Charge the fixed cost first; an under-gassed call fails outright (the
        // per-block/per-tx bound on shielded-verify CPU — paid by malformed calls).
        let mut gas = Gas::new(inputs.gas_limit);
        if !gas.record_cost(F006_VERIFY_GAS) {
            return Ok(FrameOrResult::Result(FrameResult::Call(CallOutcome::new(
                InterpreterResult { result: InstructionResult::PrecompileOOG, output: Bytes::new(), gas },
                inputs.return_memory_offset.clone(),
            ))));
        }
        // NON-PAYABLE (a pure verify): a value-bearing call reverts so value is
        // never stranded. STATICCALL / zero-value CALL are fine.
        if let Some(v) = inputs.value.transfer()
            && !v.is_zero()
        {
            return Ok(FrameOrResult::Result(FrameResult::Call(CallOutcome::new(
                InterpreterResult { result: InstructionResult::Revert, output: Bytes::new(), gas },
                inputs.return_memory_offset.clone(),
            ))));
        }
        let ok = run_f006_shielded_verify(&inputs.input, stark_only);
        Ok(FrameOrResult::Result(FrameResult::Call(CallOutcome::new(
            InterpreterResult { result: InstructionResult::Return, output: abi_bool(ok), gas },
            inputs.return_memory_offset.clone(),
        ))))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_mil_shield::merkle::MerklePath;
    use misaka_mil_shield::merkle::{MerkleTree, TREE_DEPTH};
    use misaka_mil_shield::note::{Commitment, Note, commit, derive_output_rho, nullifier, shielded_address};
    use misaka_mil_shield::proof::{CIRCUIT_PROVIDER_CLAIM, CIRCUIT_SPEND, PROOF_SYSTEM_REFERENCE, ShieldProof};
    use misaka_mil_shield::provider::{ProviderClaimStatement, ProviderClaimWitness, claim_ctx, provider_leaf, provider_nullifier};
    use misaka_mil_shield::spend::{SpendStatement, SpendWitness};

    fn h(b: u8) -> Hash64 {
        Hash64::from_bytes([b; 64])
    }

    fn calldata(vk_hash: Hash64, proof: &[u8]) -> Vec<u8> {
        let mut c = Vec::with_capacity(1 + 64 + proof.len());
        c.push(F006_VERSION_SHIELDED);
        c.extend_from_slice(vk_hash.as_byte_slice());
        c.extend_from_slice(proof);
        c
    }

    // A valid reference shield (shield 100 → one 100-note).
    fn spend_proof(vk_hash: Hash64) -> Vec<u8> {
        let dummy = Note { value: 0, owner_pk: h(0), rho: h(0), r: h(0), token_id: 0 };
        let nf0 = nullifier(&h(1), &dummy.rho);
        let nf1 = nullifier(&h(2), &dummy.rho);
        let out0 =
            Note { value: 100, owner_pk: shielded_address(&h(0x71)), rho: derive_output_rho(&nf0, &nf1, 0), r: h(0x31), token_id: 0 };
        let out1 = Note { value: 0, owner_pk: h(0), rho: derive_output_rho(&nf0, &nf1, 1), r: h(0), token_id: 0 };
        let stmt = SpendStatement {
            anchor: h(0),
            nf_old: [nf0, nf1],
            cm_new: [commit(&out0), commit(&out1)],
            v_pub_in: 100,
            v_pub_out: 0,
            token_id: 0,
            ctx: h(0xC7),
        };
        let wit = SpendWitness {
            notes_in: [dummy, dummy],
            sk_in: [h(1), h(2)],
            paths_in: [MerklePath { siblings: vec![], index: 0 }, MerklePath { siblings: vec![], index: 0 }],
            enable_in: [false, false],
            notes_out: [out0, out1],
        };
        ShieldProof {
            proof_system_id: PROOF_SYSTEM_REFERENCE,
            circuit_version: CIRCUIT_SPEND,
            verifier_key_hash: vk_hash,
            public_inputs: borsh::to_vec(&stmt).unwrap(),
            proof: borsh::to_vec(&wit).unwrap(),
        }
        .encode()
    }

    #[test]
    fn valid_spend_precompile_returns_true() {
        let vk = h(0xB0);
        assert!(run_f006_shielded_verify(&calldata(vk, &spend_proof(vk)), false));
    }

    #[test]
    fn stark_tagged_proof_stays_inert_through_the_wired_backend() {
        // The reference→STARK swap wired `StarkBackend` in. A STARK-tagged proof must
        // still return ABI false (fail-closed) — the backend is inert until §SP-0, so
        // F006 is byte-identical to the pre-swap node for every input. Retag the same
        // reference bytes as STARK and confirm the precompile rejects them.
        let vk = h(0xB0);
        let mut p = ShieldProof::decode(&spend_proof(vk)).unwrap();
        p.proof_system_id = misaka_mil_shield::proof::PROOF_SYSTEM_STARK;
        assert!(!run_f006_shielded_verify(&calldata(vk, &p.encode()), false));
        // …while the REFERENCE arm still verifies (the swap did not disturb it).
        assert!(run_f006_shielded_verify(&calldata(vk, &spend_proof(vk)), false));
    }

    #[test]
    fn wrong_vk_returns_false() {
        let vk = h(0xB0);
        // caller pins a different vk than the proof carries → false
        assert!(!run_f006_shielded_verify(&calldata(h(0x00), &spend_proof(vk)), false));
    }

    #[test]
    fn malformed_calldata_is_fail_closed() {
        assert!(!run_f006_shielded_verify(&[], false)); // empty
        assert!(!run_f006_shielded_verify(&[0x01], false)); // version only
        assert!(!run_f006_shielded_verify(&[0x02; 200], false)); // wrong version
        let vk = h(0xB0);
        let mut c = calldata(vk, &spend_proof(vk));
        c.truncate(80); // truncated proof
        assert!(!run_f006_shielded_verify(&c, false));
    }

    #[test]
    fn provider_claim_precompile_returns_true() {
        let vk = h(0xB0);
        let (pkh, sec) = (h(0x41), h(0x81));
        let mut tree = MerkleTree::new(TREE_DEPTH); // (audit M-03) provider-set membership is pinned to exactly TREE_DEPTH
        let idx = tree.append(Commitment(provider_leaf(&pkh, &shielded_address(&sec))));
        let session_cm = h(0x5E);
        let amount = 500u64;
        let payout = Note { value: amount, owner_pk: shielded_address(&h(0x71)), rho: h(1), r: h(2), token_id: 0 };
        let cm_payout = commit(&payout);
        let pnf = provider_nullifier(&sec, &session_cm);
        let stmt = ProviderClaimStatement {
            provider_set_root: tree.root(),
            session_cm,
            amount,
            provider_nf: pnf,
            cm_payout,
            ctx: claim_ctx(&session_cm, amount, &cm_payout, &pnf),
        };
        let wit = ProviderClaimWitness {
            pk_receipt_hash: pkh,
            claim_secret: sec,
            leaf_index: idx,
            path: tree.path(idx).unwrap(),
            payout_note: payout,
        };
        let proof = ShieldProof {
            proof_system_id: PROOF_SYSTEM_REFERENCE,
            circuit_version: CIRCUIT_PROVIDER_CLAIM,
            verifier_key_hash: vk,
            public_inputs: borsh::to_vec(&stmt).unwrap(),
            proof: borsh::to_vec(&wit).unwrap(),
        }
        .encode();
        assert!(run_f006_shielded_verify(&calldata(vk, &proof), false));
    }
}
