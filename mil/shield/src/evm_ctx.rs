//! The on-chain spend/claim CONTEXT derivations, byte-for-byte matching the Solidity
//! `ShieldedPool._computeCtx` and `MilShieldedEscrow._computeClaimCtx` (audit remediation
//! C-05/H-04/H-05). After that remediation `ctx` is a binding VALUE the settling contract
//! RECOMPUTES; the relation binds it via the public inputs but does not re-derive it, so a
//! STARK prover MUST produce its proof over the SAME public inputs the contract builds — and
//! therefore needs this exact `ctx`. This module closes the regression the remediation would
//! otherwise leave (contract recomputes a ctx the Rust side could not reproduce).
//!
//! `blake2b_512_keyed(domain, data)` is exactly the F004 precompile `Hash64Lib.keyed(domain,
//! data)` (kaspa-evm/src/hash64.rs parses `key_len ‖ key ‖ data` and returns
//! `blake2b_512_keyed(key, data)`), so the ONLY thing that must match is the
//! `abi.encodePacked` preimage layout — encoded here identically, field by field. The
//! cross-language differential test (audit M-07) is what pins the equality end-to-end.

use crate::note::{Commitment, Nullifier};
use kaspa_hashes::{Hash64, blake2b_512_keyed};

const SPEND_CTX_DOMAIN: &[u8] = b"misaka-shield-v1/spend-ctx";
const CLAIM_CTX_DOMAIN: &[u8] = b"misaka-shield-v1/claim-ctx";

/// Action discriminators — MUST equal `ShieldedPool.ACTION_{SHIELD,TRANSFER,UNSHIELD}`.
pub const ACTION_SHIELD: u8 = 1;
pub const ACTION_TRANSFER: u8 = 2;
pub const ACTION_UNSHIELD: u8 = 3;

/// `ShieldedPool._computeCtx`. `abi.encodePacked(uint256 chainId, address(this), uint8 action,
/// address to, le64(vPubIn), le64(vPubOut), le32(tokenId), cm0(64), cm1(64), encHash0(32),
/// encHash1(32))`. `chain_id` is the 32-byte big-endian EVM chainId; `contract`/`to` are
/// 20-byte EVM addresses; `enc_hash{0,1}` are `keccak256(encNote{0,1})`.
#[allow(clippy::too_many_arguments)]
pub fn spend_ctx(
    chain_id: &[u8; 32],
    contract: &[u8; 20],
    action: u8,
    to: &[u8; 20],
    v_pub_in: u64,
    v_pub_out: u64,
    token_id: u32,
    cm0: &Commitment,
    cm1: &Commitment,
    enc_hash0: &[u8; 32],
    enc_hash1: &[u8; 32],
) -> Hash64 {
    let mut b = Vec::with_capacity(32 + 20 + 1 + 20 + 8 + 8 + 4 + 64 + 64 + 32 + 32);
    b.extend_from_slice(chain_id);
    b.extend_from_slice(contract);
    b.push(action);
    b.extend_from_slice(to);
    b.extend_from_slice(&v_pub_in.to_le_bytes());
    b.extend_from_slice(&v_pub_out.to_le_bytes());
    b.extend_from_slice(&token_id.to_le_bytes());
    b.extend_from_slice(cm0.0.as_byte_slice());
    b.extend_from_slice(cm1.0.as_byte_slice());
    b.extend_from_slice(enc_hash0);
    b.extend_from_slice(enc_hash1);
    blake2b_512_keyed(SPEND_CTX_DOMAIN, &b)
}

/// `MilShieldedEscrow._computeClaimCtx`. `abi.encodePacked(uint256 chainId, address(this),
/// bytes32 escrowId, providerSetRoot(64), sessionCm(64), uint256 grossSompi, providerNf(64),
/// cmPayout(64), keccak256(encNote)(32))`. `gross_sompi` is the 32-byte big-endian value.
#[allow(clippy::too_many_arguments)]
pub fn claim_ctx_onchain(
    chain_id: &[u8; 32],
    contract: &[u8; 20],
    escrow_id: &[u8; 32],
    provider_set_root: &Hash64,
    session_cm: &Hash64,
    gross_sompi: &[u8; 32],
    provider_nf: &Nullifier,
    cm_payout: &Commitment,
    enc_hash: &[u8; 32],
) -> Hash64 {
    let mut b = Vec::with_capacity(32 + 20 + 32 + 64 + 64 + 32 + 64 + 64 + 32);
    b.extend_from_slice(chain_id);
    b.extend_from_slice(contract);
    b.extend_from_slice(escrow_id);
    b.extend_from_slice(provider_set_root.as_byte_slice());
    b.extend_from_slice(session_cm.as_byte_slice());
    b.extend_from_slice(gross_sompi);
    b.extend_from_slice(provider_nf.0.as_byte_slice());
    b.extend_from_slice(cm_payout.0.as_byte_slice());
    b.extend_from_slice(enc_hash);
    blake2b_512_keyed(CLAIM_CTX_DOMAIN, &b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: u8) -> Hash64 {
        Hash64::from_bytes([b; 64])
    }

    #[test]
    fn spend_ctx_is_deterministic_and_field_sensitive() {
        let base = spend_ctx(
            &[1u8; 32], &[2u8; 20], ACTION_UNSHIELD, &[3u8; 20], 100, 0, 0,
            &Commitment(h(0x11)), &Commitment(h(0x12)), &[4u8; 32], &[5u8; 32],
        );
        assert_eq!(
            base,
            spend_ctx(&[1u8; 32], &[2u8; 20], ACTION_UNSHIELD, &[3u8; 20], 100, 0, 0,
                &Commitment(h(0x11)), &Commitment(h(0x12)), &[4u8; 32], &[5u8; 32]),
            "deterministic"
        );
        // recipient, action, and ciphertext each move the ctx (the C-05/H-04 binding).
        let to = spend_ctx(&[1u8; 32], &[2u8; 20], ACTION_UNSHIELD, &[9u8; 20], 100, 0, 0,
            &Commitment(h(0x11)), &Commitment(h(0x12)), &[4u8; 32], &[5u8; 32]);
        let act = spend_ctx(&[1u8; 32], &[2u8; 20], ACTION_SHIELD, &[3u8; 20], 100, 0, 0,
            &Commitment(h(0x11)), &Commitment(h(0x12)), &[4u8; 32], &[5u8; 32]);
        let ct = spend_ctx(&[1u8; 32], &[2u8; 20], ACTION_UNSHIELD, &[3u8; 20], 100, 0, 0,
            &Commitment(h(0x11)), &Commitment(h(0x12)), &[6u8; 32], &[5u8; 32]);
        assert_ne!(base, to);
        assert_ne!(base, act);
        assert_ne!(base, ct);
    }

    #[test]
    fn claim_ctx_binds_escrow_and_chain() {
        let base = claim_ctx_onchain(&[1u8; 32], &[2u8; 20], &[7u8; 32], &h(0x5E), &h(0x5F),
            &[0u8; 32], &Nullifier(h(0x42)), &Commitment(h(0x43)), &[8u8; 32]);
        // escrowId and chainId each change the ctx (H-05 replay defense).
        let esc = claim_ctx_onchain(&[1u8; 32], &[2u8; 20], &[99u8; 32], &h(0x5E), &h(0x5F),
            &[0u8; 32], &Nullifier(h(0x42)), &Commitment(h(0x43)), &[8u8; 32]);
        let chain = claim_ctx_onchain(&[9u8; 32], &[2u8; 20], &[7u8; 32], &h(0x5E), &h(0x5F),
            &[0u8; 32], &Nullifier(h(0x42)), &Commitment(h(0x43)), &[8u8; 32]);
        assert_ne!(base, esc);
        assert_ne!(base, chain);
    }
}
