//! C-P6 build-order step 1 (remainder): the **SHAKE sponge wrapper** over the exact
//! `p3_keccak::KeccakF` permutation the Keccak-f AIR (`keccak_shake.rs`) constrains, plus a
//! **byte-for-byte diff-test vs a FIPS-202 reference** (`sha3::{Shake128,Shake256}`). Once
//! this passes, every ML-DSA-87 SHAKE step — `ExpandA` (SHAKE128), `mu`/`SampleInBall`/the
//! final commitment hash (SHAKE256) — reduces to a sequence of the AIR's proven Keccak-f
//! permutations plus this sponge's (absorb/pad/squeeze) bookkeeping, which is itself just
//! rate-lane XOR + a fixed padding row (cp6 design §5 step 1, ADR-0037 §2.4).
//!
//! The sponge here is the REFERENCE oracle: it runs `KeccakF::permute_mut` — the SAME
//! permutation the AIR proves byte-correct in its own diff-tests — so proving "the AIR
//! computed KeccakF over these lanes" + "the sponge Xall-XORed/padded/squeezed exactly
//! this way" is equivalent to "the STARK computed SHAKE". This test pins the second half
//! (the wrapper) against `sha3`, closing the correctness gap the AIR alone leaves.
//!
//! Run: `cargo run --release --bin shake_sponge` → diff-tests SHAKE128/256 over many random
//! (input_len × output_len) pairs; any mismatch aborts (this is the correctness gate).

use p3_keccak::KeccakF;
use p3_symmetric::Permutation;
use rand::{Rng, SeedableRng};
use rand::rngs::SmallRng;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};

const RATE_128: usize = 168; // SHAKE128 rate in bytes (1600 − 2·128)/8
const RATE_256: usize = 136; // SHAKE256 rate in bytes (1600 − 2·256)/8

/// FIPS-202 SHAKE as a sponge over `KeccakF` (little-endian lane packing). `rate` selects
/// SHAKE128 (168) vs SHAKE256 (136); the domain-separation byte is 0x1F for both.
fn shake_over_keccakf(msg: &[u8], rate: usize, out_len: usize) -> Vec<u8> {
    assert!(rate < 200 && rate % 8 == 0, "rate must be a whole number of lanes < 200");
    let mut state = [0u64; 25];

    // --- absorb: XOR full rate-blocks, permute after each; pad10*1 + 0x1F on the last. ---
    let mut padded = msg.to_vec();
    // pad10*1 with SHAKE domain separation: append 0x1F, zero-fill to a rate multiple, set
    // the final byte's high bit. (When the two markers land in the same byte: 0x9F.)
    padded.push(0x1F);
    while padded.len() % rate != 0 {
        padded.push(0x00);
    }
    let last = padded.len() - 1;
    padded[last] |= 0x80;

    for block in padded.chunks_exact(rate) {
        xor_block_into_state(&mut state, block);
        KeccakF.permute_mut(&mut state);
    }

    // --- squeeze: emit `rate` bytes per permutation until `out_len` is met. ---
    let mut out = Vec::with_capacity(out_len);
    loop {
        let take = core::cmp::min(rate, out_len - out.len());
        out.extend_from_slice(&state_to_bytes(&state)[..take]);
        if out.len() == out_len {
            break;
        }
        KeccakF.permute_mut(&mut state);
    }
    out
}

/// XOR a ≤200-byte block into the little-endian lane state (lane i = bytes [8i, 8i+8)).
fn xor_block_into_state(state: &mut [u64; 25], block: &[u8]) {
    for (i, chunk) in block.chunks(8).enumerate() {
        let mut lane = [0u8; 8];
        lane[..chunk.len()].copy_from_slice(chunk);
        state[i] ^= u64::from_le_bytes(lane);
    }
}

/// Serialize the full 200-byte state, little-endian per lane (squeeze reads the rate prefix).
fn state_to_bytes(state: &[u64; 25]) -> [u8; 200] {
    let mut b = [0u8; 200];
    for (i, lane) in state.iter().enumerate() {
        b[i * 8..i * 8 + 8].copy_from_slice(&lane.to_le_bytes());
    }
    b
}

fn ref_shake128(msg: &[u8], out_len: usize) -> Vec<u8> {
    let mut h = Shake128::default();
    h.update(msg);
    let mut r = h.finalize_xof();
    let mut o = vec![0u8; out_len];
    r.read(&mut o);
    o
}

fn ref_shake256(msg: &[u8], out_len: usize) -> Vec<u8> {
    let mut h = Shake256::default();
    h.update(msg);
    let mut r = h.finalize_xof();
    let mut o = vec![0u8; out_len];
    r.read(&mut o);
    o
}

fn main() {
    let mut rng = SmallRng::seed_from_u64(0xC0FFEE_u64);
    let mut cases = 0usize;
    let mut max_bytes = 0usize;

    // Edge lengths that exercise the padding corners: empty, one-below/at/above the rate,
    // multi-block, plus the ExpandA-relevant output sizes.
    let edge_in = [0usize, 1, RATE_128 - 1, RATE_128, RATE_128 + 1, 2 * RATE_256, 200, 4627];
    let edge_out = [1usize, 32, RATE_256, RATE_128 + 7, 512, 32 * 168 /* an ExpandA-ish squeeze */];

    for &il in &edge_in {
        for &ol in &edge_out {
            let msg: Vec<u8> = (0..il).map(|_| rng.random()).collect();

            let ours128 = shake_over_keccakf(&msg, RATE_128, ol);
            let theirs128 = ref_shake128(&msg, ol);
            assert_eq!(ours128, theirs128, "SHAKE128 mismatch at in={il} out={ol}");

            let ours256 = shake_over_keccakf(&msg, RATE_256, ol);
            let theirs256 = ref_shake256(&msg, ol);
            assert_eq!(ours256, theirs256, "SHAKE256 mismatch at in={il} out={ol}");

            cases += 2;
            max_bytes = max_bytes.max(ol);
        }
    }

    // fuzz: random lengths, to catch any block-boundary bug the edge grid misses.
    for _ in 0..2000 {
        let il = rng.random_range(0..400);
        let ol = rng.random_range(1..600);
        let msg: Vec<u8> = (0..il).map(|_| rng.random()).collect();
        assert_eq!(shake_over_keccakf(&msg, RATE_128, ol), ref_shake128(&msg, ol), "SHAKE128 fuzz in={il} out={ol}");
        assert_eq!(shake_over_keccakf(&msg, RATE_256, ol), ref_shake256(&msg, ol), "SHAKE256 fuzz in={il} out={ol}");
        cases += 2;
    }

    println!(
        "SHAKE SPONGE ok — {cases} SHAKE128/256 vectors over p3_keccak::KeccakF match sha3 byte-for-byte \
         (max out {max_bytes} B; edge + 2000-case fuzz). The sponge wrapper the C-P6 AIR must constrain is \
         FIPS-202-correct; ExpandA/mu/SampleInBall/final-hash are now reducible to (proven Keccak-f)+(this wrapper)."
    );
}
