//! C-P6 step 3 (compose) — the **correctness-gate ORACLE**: `libcrux_ml_dsa::ml_dsa_87`
//! accept/reject over real (pk, msg, sig) vectors. The design gate is "our in-circuit verify
//! accepts **iff** libcrux accepts" (cp6 §5 step 3). This harness pins the RHS of that iff:
//! it generates valid signatures and a family of tampered ones, and records libcrux's verdict
//! for each — the exact reference the composed in-circuit `Verify` (wiring the proven
//! sub-gadgets: SHAKE, NTT, ExpandA, SampleInBall, Decompose/UseHint, norm, popcount) must
//! reproduce. It also confirms the ML-DSA-87 byte structure the decode gadgets target
//! (`pk = 2592 B`, `sig = 4627 B`).
//!
//! This is the reference oracle, not the circuit: it makes the composition's target concrete
//! and testable before the (multi-week) AIR wiring lands.

use libcrux_ml_dsa::ml_dsa_87;

fn main() {
    // deterministic keypair (ML-DSA-87 keygen wants a 32-byte seed).
    let seed: [u8; 32] = core::array::from_fn(|i| (0x1b_u8).wrapping_mul(i as u8 + 1) ^ 0xa5);
    let kp = ml_dsa_87::generate_key_pair(seed);

    let msg = b"MISAKA MIL session receipt: provider served 50000 tokens";
    let ctx = b"mil-receipt-v1";
    let rnd: [u8; 32] = core::array::from_fn(|i| (0x9e_u8).wrapping_add(i as u8));

    let sig = ml_dsa_87::sign(&kp.signing_key, msg, ctx, rnd).expect("sign");

    let vk_bytes = kp.verification_key.as_ref();
    let sig_bytes = sig.as_ref();
    assert_eq!(vk_bytes.len(), 2592, "ML-DSA-87 pk = 2592 B (ρ‖t1)");
    assert_eq!(sig_bytes.len(), 4627, "ML-DSA-87 sig = 4627 B (c̃‖z‖h)");

    let verify = |pk: &[u8], m: &[u8], c: &[u8], s: &[u8]| -> bool {
        let pk: [u8; 2592] = match pk.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let s: [u8; 4627] = match s.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let vk = ml_dsa_87::MLDSA87VerificationKey::new(pk);
        let sg = ml_dsa_87::MLDSA87Signature::new(s);
        ml_dsa_87::portable::verify(&vk, m, c, &sg).is_ok()
    };

    // (1) the valid signature verifies.
    let ok_valid = verify(vk_bytes, msg, ctx, sig_bytes);

    // (2) a family of tampered inputs must ALL reject — the reject side of the gate.
    let mut bad_sig = sig_bytes.to_vec();
    bad_sig[100] ^= 1; // flip a z byte
    let rej_sig = !verify(vk_bytes, msg, ctx, &bad_sig);

    let mut bad_ctilde = sig_bytes.to_vec();
    bad_ctilde[0] ^= 1; // flip the challenge hash c̃
    let rej_ctilde = !verify(vk_bytes, msg, ctx, &bad_ctilde);

    let rej_msg = !verify(vk_bytes, b"a different message entirely!!", ctx, sig_bytes);
    let rej_ctx = !verify(vk_bytes, msg, b"wrong-context", sig_bytes);

    let mut bad_pk = vk_bytes.to_vec();
    bad_pk[50] ^= 1; // flip a t1 byte
    let rej_pk = !verify(&bad_pk, msg, ctx, sig_bytes);

    let all_reject = rej_sig && rej_ctilde && rej_msg && rej_ctx && rej_pk;

    if ok_valid && all_reject {
        println!(
            "MLDSA ORACLE ok — libcrux ml_dsa_87 verify pinned as the C-P6 correctness gate: \
             valid sig ACCEPTS; 5 tamper classes (z / c̃ / message / context / pk) all REJECT. \
             pk=2592 B, sig=4627 B. This is the reference the composed in-circuit Verify \
             (SHAKE+NTT+ExpandA+SampleInBall+Decompose/UseHint+norm+popcount AIRs) must match \
             accept⇔accept, diff-tested byte-for-byte."
        );
    } else {
        println!(
            "ORACLE FAIL — valid={ok_valid} reject(sig={rej_sig} ctilde={rej_ctilde} msg={rej_msg} ctx={rej_ctx} pk={rej_pk})"
        );
        std::process::exit(1);
    }
}
