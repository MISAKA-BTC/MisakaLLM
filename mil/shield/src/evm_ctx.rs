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
            &[1u8; 32],
            &[2u8; 20],
            ACTION_UNSHIELD,
            &[3u8; 20],
            100,
            0,
            0,
            &Commitment(h(0x11)),
            &Commitment(h(0x12)),
            &[4u8; 32],
            &[5u8; 32],
        );
        assert_eq!(
            base,
            spend_ctx(
                &[1u8; 32],
                &[2u8; 20],
                ACTION_UNSHIELD,
                &[3u8; 20],
                100,
                0,
                0,
                &Commitment(h(0x11)),
                &Commitment(h(0x12)),
                &[4u8; 32],
                &[5u8; 32]
            ),
            "deterministic"
        );
        // recipient, action, and ciphertext each move the ctx (the C-05/H-04 binding).
        let to = spend_ctx(
            &[1u8; 32],
            &[2u8; 20],
            ACTION_UNSHIELD,
            &[9u8; 20],
            100,
            0,
            0,
            &Commitment(h(0x11)),
            &Commitment(h(0x12)),
            &[4u8; 32],
            &[5u8; 32],
        );
        let act = spend_ctx(
            &[1u8; 32],
            &[2u8; 20],
            ACTION_SHIELD,
            &[3u8; 20],
            100,
            0,
            0,
            &Commitment(h(0x11)),
            &Commitment(h(0x12)),
            &[4u8; 32],
            &[5u8; 32],
        );
        let ct = spend_ctx(
            &[1u8; 32],
            &[2u8; 20],
            ACTION_UNSHIELD,
            &[3u8; 20],
            100,
            0,
            0,
            &Commitment(h(0x11)),
            &Commitment(h(0x12)),
            &[6u8; 32],
            &[5u8; 32],
        );
        assert_ne!(base, to);
        assert_ne!(base, act);
        assert_ne!(base, ct);
    }

    /// (audit M-07) Cross-language LAYOUT pin: independently build the exact bytes
    /// Solidity `_computeCtx`'s `abi.encodePacked(...)` produces for fixed inputs, and assert
    /// `spend_ctx` == `blake2b_512_keyed(domain, those_bytes)`. Since F004 ==
    /// `blake2b_512_keyed` (kaspa-evm/src/hash64.rs) and the Solidity side encodes in this
    /// same documented order, preimage equality ⇒ ctx equality. (The live Solidity↔Rust
    /// byte differential via a real-BLAKE2b F004 in forge remains a CI follow-up.)
    #[test]
    fn spend_ctx_matches_solidity_abi_encode_packed_layout() {
        let chain_id = {
            let mut c = [0u8; 32];
            c[31] = 1;
            c
        }; // uint256(1)
        let contract = [0xaau8; 20];
        let to = [0xbbu8; 20];
        let cm0 = Commitment(h(0x11));
        let cm1 = Commitment(h(0x12));
        let enc0 = [0x04u8; 32];
        let enc1 = [0x05u8; 32];
        let (v_in, v_out, token): (u64, u64, u32) = (0, 40, 0);

        // abi.encodePacked(uint256 chainId, address(this), uint8 action, address to,
        //   le64(vPubIn), le64(vPubOut), le32(tokenId), cm0(64), cm1(64), encHash0, encHash1)
        let mut golden = Vec::new();
        golden.extend_from_slice(&chain_id); // 32
        golden.extend_from_slice(&contract); // 20
        golden.push(ACTION_UNSHIELD); // 1
        golden.extend_from_slice(&to); // 20
        golden.extend_from_slice(&v_in.to_le_bytes()); // 8
        golden.extend_from_slice(&v_out.to_le_bytes()); // 8
        golden.extend_from_slice(&token.to_le_bytes()); // 4
        golden.extend_from_slice(cm0.0.as_byte_slice()); // 64
        golden.extend_from_slice(cm1.0.as_byte_slice()); // 64
        golden.extend_from_slice(&enc0); // 32
        golden.extend_from_slice(&enc1); // 32
        assert_eq!(golden.len(), 32 + 20 + 1 + 20 + 8 + 8 + 4 + 64 + 64 + 32 + 32, "packed length");

        let expected = blake2b_512_keyed(SPEND_CTX_DOMAIN, &golden);
        let got = spend_ctx(&chain_id, &contract, ACTION_UNSHIELD, &to, v_in, v_out, token, &cm0, &cm1, &enc0, &enc1);
        assert_eq!(got, expected, "spend_ctx must hash the exact Solidity abi.encodePacked preimage");
    }

    #[test]
    fn claim_ctx_binds_escrow_and_chain() {
        let base = claim_ctx_onchain(
            &[1u8; 32],
            &[2u8; 20],
            &[7u8; 32],
            &h(0x5E),
            &h(0x5F),
            &[0u8; 32],
            &Nullifier(h(0x42)),
            &Commitment(h(0x43)),
            &[8u8; 32],
        );
        // escrowId and chainId each change the ctx (H-05 replay defense).
        let esc = claim_ctx_onchain(
            &[1u8; 32],
            &[2u8; 20],
            &[99u8; 32],
            &h(0x5E),
            &h(0x5F),
            &[0u8; 32],
            &Nullifier(h(0x42)),
            &Commitment(h(0x43)),
            &[8u8; 32],
        );
        let chain = claim_ctx_onchain(
            &[9u8; 32],
            &[2u8; 20],
            &[7u8; 32],
            &h(0x5E),
            &h(0x5F),
            &[0u8; 32],
            &Nullifier(h(0x42)),
            &Commitment(h(0x43)),
            &[8u8; 32],
        );
        assert_ne!(base, esc);
        assert_ne!(base, chain);
    }

    /// (audit H-01 / M-07) Cross-language LAYOUT pin for the CLAIM ctx — the analog of
    /// `spend_ctx_matches_solidity_abi_encode_packed_layout`. Independently reconstruct
    /// the exact 404-byte preimage Solidity `MilShieldedEscrow._computeClaimCtx`'s
    /// `abi.encodePacked(...)` produces, and assert `claim_ctx_onchain` ==
    /// `blake2b_512_keyed(CLAIM_CTX_DOMAIN, those_bytes)`. Since F004 ==
    /// `blake2b_512_keyed` (kaspa-evm/src/hash64.rs) and the Solidity side encodes in
    /// this documented order, preimage equality ⇒ ctx equality. This is the claim-side
    /// authority the claim-v2 AIR (`docs/bench/plonky3-shield-air/claim_v2.rs`) binds
    /// `PI_CTX` to OPAQUELY (H-01): the AIR no longer recomputes a stale 4-field ctx, so
    /// THIS 404-byte layout is the sole ctx authority for the anonymous claim.
    #[test]
    fn claim_ctx_matches_solidity_abi_encode_packed_layout() {
        let chain_id = {
            let mut c = [0u8; 32];
            c[31] = 1;
            c
        }; // uint256(1)
        let contract = [0xaau8; 20];
        let escrow_id = [0x07u8; 32];
        let set_root = h(0x21);
        let session_cm = h(0x5e);
        let gross_sompi = {
            let mut g = [0u8; 32];
            g[31] = 88;
            g
        }; // uint256(88), 32-byte big-endian
        let provider_nf = Nullifier(h(0x42));
        let cm_payout = Commitment(h(0x43));
        let enc_hash = [0x08u8; 32]; // keccak256(encNote)

        // abi.encodePacked(uint256 chainId, address(this), bytes32 escrowId,
        //   providerSetRoot(64), sessionCm(64), uint256 grossSompi, providerNf(64),
        //   cmPayout(64), keccak256(encNote)(32))
        let mut golden = Vec::new();
        golden.extend_from_slice(&chain_id); // 32
        golden.extend_from_slice(&contract); // 20
        golden.extend_from_slice(&escrow_id); // 32
        golden.extend_from_slice(set_root.as_byte_slice()); // 64
        golden.extend_from_slice(session_cm.as_byte_slice()); // 64
        golden.extend_from_slice(&gross_sompi); // 32
        golden.extend_from_slice(provider_nf.0.as_byte_slice()); // 64
        golden.extend_from_slice(cm_payout.0.as_byte_slice()); // 64
        golden.extend_from_slice(&enc_hash); // 32
        assert_eq!(golden.len(), 32 + 20 + 32 + 64 + 64 + 32 + 64 + 64 + 32, "packed length");
        assert_eq!(golden.len(), 404, "the 404-byte deployment-scoped claim-ctx preimage");

        let expected = blake2b_512_keyed(CLAIM_CTX_DOMAIN, &golden);
        let got = claim_ctx_onchain(
            &chain_id,
            &contract,
            &escrow_id,
            &set_root,
            &session_cm,
            &gross_sompi,
            &provider_nf,
            &cm_payout,
            &enc_hash,
        );
        assert_eq!(got, expected, "claim_ctx_onchain must hash the exact Solidity abi.encodePacked preimage");

        // Every one of the 9 fields moves the digest (no aliasing / no dropped field).
        let flip32 = |b: &[u8; 32]| -> [u8; 32] {
            let mut x = *b;
            x[0] ^= 0xff;
            x
        };
        let flip20 = |b: &[u8; 20]| -> [u8; 20] {
            let mut x = *b;
            x[0] ^= 0xff;
            x
        };
        // 1. chainId
        assert_ne!(
            got,
            claim_ctx_onchain(&flip32(&chain_id), &contract, &escrow_id, &set_root, &session_cm, &gross_sompi, &provider_nf, &cm_payout, &enc_hash)
        );
        // 2. contract
        assert_ne!(
            got,
            claim_ctx_onchain(&chain_id, &flip20(&contract), &escrow_id, &set_root, &session_cm, &gross_sompi, &provider_nf, &cm_payout, &enc_hash)
        );
        // 3. escrowId
        assert_ne!(
            got,
            claim_ctx_onchain(&chain_id, &contract, &flip32(&escrow_id), &set_root, &session_cm, &gross_sompi, &provider_nf, &cm_payout, &enc_hash)
        );
        // 4. providerSetRoot
        assert_ne!(
            got,
            claim_ctx_onchain(&chain_id, &contract, &escrow_id, &h(0x22), &session_cm, &gross_sompi, &provider_nf, &cm_payout, &enc_hash)
        );
        // 5. sessionCm
        assert_ne!(
            got,
            claim_ctx_onchain(&chain_id, &contract, &escrow_id, &set_root, &h(0x5f), &gross_sompi, &provider_nf, &cm_payout, &enc_hash)
        );
        // 6. grossSompi
        assert_ne!(
            got,
            claim_ctx_onchain(&chain_id, &contract, &escrow_id, &set_root, &session_cm, &flip32(&gross_sompi), &provider_nf, &cm_payout, &enc_hash)
        );
        // 7. providerNf
        assert_ne!(
            got,
            claim_ctx_onchain(&chain_id, &contract, &escrow_id, &set_root, &session_cm, &gross_sompi, &Nullifier(h(0x99)), &cm_payout, &enc_hash)
        );
        // 8. cmPayout
        assert_ne!(
            got,
            claim_ctx_onchain(&chain_id, &contract, &escrow_id, &set_root, &session_cm, &gross_sompi, &provider_nf, &Commitment(h(0x44)), &enc_hash)
        );
        // 9. keccak256(encNote)
        assert_ne!(
            got,
            claim_ctx_onchain(&chain_id, &contract, &escrow_id, &set_root, &session_cm, &gross_sompi, &provider_nf, &cm_payout, &flip32(&enc_hash))
        );
    }
}
