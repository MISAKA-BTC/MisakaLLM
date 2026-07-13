//! C-P6 verify prerequisite: **sigDecode `z` unpacking** (FIPS-204 `BitUnpack`, 20-bit) as a
//! Plonky3 AIR — the LAST non-plumbing soundness gap in the ML-DSA-87 `Verify` decomposition
//! (design §7 wire 22, previously `GADGET_ONLY_NOT_WIRED — partial`: only the 20-bit *value
//! range* of `t=γ1−z` was covered by `norm_bound_air.rs`; the exact byte→coefficient regroup
//! had no dedicated AIR — only `t1`'s 10-bit `pkdecode_t1_air.rs` existed).
//!
//! ML-DSA-87 `Verify` parses `sig = (c̃, z, h)` where each of the `l=7` polynomials of `z` is
//! packed 20 bits per coefficient (`bitlen(2·γ1−1) = 20`, γ1 = 2¹⁹). `BitUnpack(v, a=γ1−1,
//! b=γ1)` reads a 20-bit unsigned field `raw ∈ [0, 2²⁰)` and decodes the SIGNED coefficient
//! `z = γ1 − raw ∈ (−γ1, γ1]`; the forward NTT (`ntt_wired*_air.rs`) then transforms `z` in the
//! mod-q residue system. A 20-bit width regroups as `lcm(20,8) = 40` bits = 2 coefficients per 5
//! bytes, little-endian. This AIR proves that unpack AND the signed→residue conversion:
//!
//!   1. **byte↔coeff regroup (THE gap):** given the 5 packed bytes and the 2 raw 20-bit values,
//!      the 40 bits regroup EXACTLY — each `raw[k]` a 20-bit grouping, each `byte[j]` an 8-bit
//!      grouping, of the SAME bit vector. A wrong-endianness / off-by-a-bit unpack — which would
//!      feed the NTT the wrong `z` — is rejected (`--corrupt`). `raw = γ1 − z = t` is exactly the
//!      value `norm_bound_air.rs` range-checks, so this AIR and the norm bound share the `t` wire.
//!   2. **signed → mod-q residue:** `z_q = (γ1 − raw) mod q` is surfaced as the value the forward
//!      NTT consumes. The sign is a proven boolean `neg = [raw > γ1]` (a sound lt-comparator:
//!      `raw − (γ1+1) + (1−neg)·2²¹ = diff`, `diff ∈ [0, 2²¹)` bit-range-checked FORCES `neg`),
//!      and `z_q = γ1 − raw + neg·q` (`neg=0 ⇒ γ1−raw ∈ [0,γ1]`; `neg=1 ⇒ γ1−raw+q ∈ (q−γ1, q)`
//!      — both canonical `< q`). `--corrupt-neg` (forged sign) and `--corrupt-z` (forged residue)
//!      are rejected.
//!
//! One row = one 2-coefficient / 5-byte group. Driven by a REAL `libcrux_ml_dsa::ml_dsa_87`
//! signature (poly 0 of `z`, 128 groups) and diff-tested coefficient-exact vs the reference
//! `decode_z_poly`. Run: `cargo run --release --bin sigdecode_z_air [--corrupt|--corrupt-neg|--corrupt-z]`.

use libcrux_ml_dsa::ml_dsa_87;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, prove, verify};

const Q: u64 = 8380417; // ML-DSA-87 modulus
const GAMMA1: u64 = 1 << 19; // 524288
const Z_BITS: usize = 20; // bitlen(2·γ1 − 1)
const NC: usize = 2; // coefficients per group (lcm(20,8)/20)
const NBY: usize = 5; // bytes per group (lcm(20,8)/8)
const NBITS: usize = NC * Z_BITS; // 40 shared bits = 5 bytes × 8
const DIFF_BITS: usize = 21; // comparator slack width: raw−(γ1+1)+le·2²¹ ∈ [0,2²¹)
const NDBITS: usize = NC * DIFF_BITS; // 42

// column layout
const RAW: usize = 0; // raw[0..2]  — 20-bit unsigned BitUnpack outputs (= t = γ1 − z)
const ZQ: usize = RAW + NC; // z_q[0..2] — mod-q residue (γ1 − raw) mod q (the NTT input)
const NEG: usize = ZQ + NC; // neg[0..2] — boolean [raw > γ1]
const DIFF: usize = NEG + NC; // diff[0..2] — comparator slack value
const BY: usize = DIFF + NC; // byte[0..5]
const BITS: usize = BY + NBY; // 40 shared bits
const DBITS: usize = BITS + NBITS; // 42 comparator slack bits
const NUM_COLS: usize = DBITS + NDBITS; // 95

struct SigDecodeZAir {}

impl<F> BaseAir<F> for SigDecodeZAir {
    fn width(&self) -> usize {
        NUM_COLS
    }
    fn num_public_values(&self) -> usize {
        0
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

impl<AB: AirBuilder> Air<AB> for SigDecodeZAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let one = AB::Expr::ONE;
        let e = |i: usize| -> AB::Expr { row[i].into() };
        let gamma1p1 = AB::Expr::from_u64(GAMMA1 + 1);
        let two21 = AB::Expr::from_u64(1u64 << DIFF_BITS);
        let gamma1 = AB::Expr::from_u64(GAMMA1);
        let q = AB::Expr::from_u64(Q);

        // boolean-check every shared bit and every comparator-slack bit.
        for b in 0..NBITS {
            let bit: AB::Expr = row[BITS + b].into();
            builder.assert_zero(bit.clone() * (bit.clone() - one.clone()));
        }
        for b in 0..NDBITS {
            let bit: AB::Expr = row[DBITS + b].into();
            builder.assert_zero(bit.clone() * (bit.clone() - one.clone()));
        }

        // (1) each raw[k] is a 20-bit grouping of the shared bits (bits [20k, 20k+20)).
        for k in 0..NC {
            let mut acc = AB::Expr::ZERO;
            let mut w = AB::Expr::ONE;
            for i in 0..Z_BITS {
                let bit: AB::Expr = row[BITS + Z_BITS * k + i].into();
                acc = acc + bit * w.clone();
                w = w.clone() + w.clone();
            }
            builder.assert_eq(e(RAW + k), acc);
        }
        // (1) each byte is an 8-bit grouping of the SAME shared bits (bits [8j, 8j+8)).
        for j in 0..NBY {
            let mut acc = AB::Expr::ZERO;
            let mut w = AB::Expr::ONE;
            for i in 0..8 {
                let bit: AB::Expr = row[BITS + 8 * j + i].into();
                acc = acc + bit * w.clone();
                w = w.clone() + w.clone();
            }
            builder.assert_eq(e(BY + j), acc);
        }

        // (2) signed → mod-q residue with a proven sign.
        for k in 0..NC {
            // diff[k] is a 21-bit grouping (⇒ diff ∈ [0, 2²¹)).
            let mut dacc = AB::Expr::ZERO;
            let mut w = AB::Expr::ONE;
            for i in 0..DIFF_BITS {
                let bit: AB::Expr = row[DBITS + DIFF_BITS * k + i].into();
                dacc = dacc + bit * w.clone();
                w = w.clone() + w.clone();
            }
            builder.assert_eq(e(DIFF + k), dacc);
            // neg[k] boolean.
            let neg = e(NEG + k);
            builder.assert_zero(neg.clone() * (neg.clone() - one.clone()));
            // comparator: raw − (γ1+1) + (1−neg)·2²¹ = diff. With diff ∈ [0,2²¹) this FORCES
            // neg = [raw > γ1]: le = 1−neg = [raw ≤ γ1] (a wrong neg drives diff out of range).
            let le = one.clone() - neg.clone();
            builder.assert_eq(e(RAW + k) - gamma1p1.clone() + le * two21.clone(), e(DIFF + k));
            // residue: z_q = γ1 − raw + neg·q  (neg=0 ⇒ γ1−raw ∈ [0,γ1]; neg=1 ⇒ +q ⇒ ∈ (q−γ1,q)).
            builder.assert_eq(e(ZQ + k), gamma1.clone() - e(RAW + k) + neg * q.clone());
        }
    }
}

/// Read `nbits`-wide little-endian bit-packed unsigned integers (FIPS-204 packs LSB-first).
fn bit_unpack_unsigned(bytes: &[u8], nbits: usize, count: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(count);
    let mut acc: u64 = 0;
    let mut have = 0usize;
    let mut bi = 0usize;
    for _ in 0..count {
        while have < nbits {
            acc |= (bytes[bi] as u64) << have;
            have += 8;
            bi += 1;
        }
        out.push((acc & ((1u64 << nbits) - 1)) as u32);
        acc >>= nbits;
        have -= nbits;
    }
    out
}

/// Reference `BitUnpack` for `z`: 20-bit fields → signed coefficient `γ1 − raw ∈ (−γ1, γ1]`.
fn decode_z_poly(bytes: &[u8]) -> [i64; 256] {
    let raw = bit_unpack_unsigned(bytes, Z_BITS, 256);
    core::array::from_fn(|i| GAMMA1 as i64 - raw[i] as i64)
}

/// Canonical mod-q residue of a signed value.
fn residue(z_signed: i64) -> u64 {
    z_signed.rem_euclid(Q as i64) as u64
}

fn generate<F: PrimeField64>(groups: &[[u8; NBY]]) -> RowMajorMatrix<F> {
    let n = groups.len();
    assert!(n.is_power_of_two());
    let mut vals = F::zero_vec(n * NUM_COLS);
    for (r, bytes) in groups.iter().enumerate() {
        let base = r * NUM_COLS;
        let mut v: u64 = 0;
        for (j, &b) in bytes.iter().enumerate() {
            v |= (b as u64) << (8 * j);
        }
        for k in 0..NC {
            let raw = (v >> (Z_BITS * k)) & ((1u64 << Z_BITS) - 1);
            let neg = (raw > GAMMA1) as u64;
            let z_signed = GAMMA1 as i64 - raw as i64;
            let zq = residue(z_signed);
            // comparator slack: raw − (γ1+1) + le·2²¹, le = 1 − neg.
            let le = 1 - neg;
            let diff = (raw as i64 - (GAMMA1 as i64 + 1) + le as i64 * (1i64 << DIFF_BITS)) as u64;
            vals[base + RAW + k] = F::from_u64(raw);
            vals[base + ZQ + k] = F::from_u64(zq);
            vals[base + NEG + k] = F::from_u64(neg);
            vals[base + DIFF + k] = F::from_u64(diff);
            for i in 0..DIFF_BITS {
                vals[base + DBITS + DIFF_BITS * k + i] = F::from_u64((diff >> i) & 1);
            }
        }
        for j in 0..NBY {
            vals[base + BY + j] = F::from_u64(bytes[j] as u64);
        }
        for b in 0..NBITS {
            vals[base + BITS + b] = F::from_u64((v >> b) & 1);
        }
    }
    RowMajorMatrix::new(vals, NUM_COLS)
}

type Val = BabyBear;
type Perm = Poseidon2BabyBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs = MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 2, 8>;
type Challenge = BinomialExtensionField<Val, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
type Dft = Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;

fn make_config() -> MyConfig {
    let perm = default_babybear_poseidon2_16();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = FriParameters {
        log_blowup: 2,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 8,
        commit_proof_of_work_bits: 1,
        query_proof_of_work_bits: 1,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);
    MyConfig::new(pcs, challenger)
}

fn main() {
    let corrupt = std::env::args().any(|a| a == "--corrupt");
    let corrupt_neg = std::env::args().any(|a| a == "--corrupt-neg");
    let corrupt_z = std::env::args().any(|a| a == "--corrupt-z");
    let air = SigDecodeZAir {};

    // REAL libcrux ML-DSA-87 signature; unpack poly 0 of z (640 bytes = 128 groups).
    const Z_POLY_BYTES: usize = 256 * Z_BITS / 8; // 640
    const CTILDE_LEN: usize = 64;
    let ctx = b"mil-receipt-v1";
    let seed = [5u8; 32];
    let kp = ml_dsa_87::generate_key_pair(seed);
    let sig = ml_dsa_87::sign(&kp.signing_key, b"MISAKA session receipt", ctx, [0x9e_u8; 32]).expect("sign");
    let sb = sig.as_ref();
    // libcrux itself accepts it (the z we decode is a genuine accepted signature's).
    let vk = ml_dsa_87::MLDSA87VerificationKey::new(*kp.verification_key.as_ref());
    let sg = ml_dsa_87::MLDSA87Signature::new(*sb);
    assert!(ml_dsa_87::portable::verify(&vk, b"MISAKA session receipt", ctx, &sg).is_ok(), "libcrux accepts");
    let z_bytes: &[u8] = &sb[CTILDE_LEN..CTILDE_LEN + Z_POLY_BYTES];

    let groups: Vec<[u8; NBY]> =
        (0..Z_POLY_BYTES / NBY).map(|g| core::array::from_fn(|j| z_bytes[g * NBY + j])).collect();
    assert_eq!(groups.len(), 128);
    let mut trace = generate::<Val>(&groups);

    // diff-test: raw / z_q columns match the reference decode, coefficient-exact, over the whole poly.
    let ref_signed = decode_z_poly(z_bytes);
    let ref_raw = bit_unpack_unsigned(z_bytes, Z_BITS, 256);
    let bound = GAMMA1 - 120; // γ1 − β = 524168 (the norm bound; t = raw = γ1 − z is inside it)
    let mut max_abs = 0i64;
    for (r, _) in groups.iter().enumerate() {
        for k in 0..NC {
            let ci = r * NC + k;
            assert!(ref_raw[ci] < (1 << Z_BITS));
            assert_eq!(trace.values[r * NUM_COLS + RAW + k], Val::from_u64(ref_raw[ci] as u64), "row {r} raw {k}");
            assert_eq!(
                trace.values[r * NUM_COLS + ZQ + k],
                Val::from_u64(residue(ref_signed[ci])),
                "row {r} z_q {k} residue mismatch"
            );
            // faithfulness: γ1 − raw == the reference signed coefficient.
            assert_eq!(GAMMA1 as i64 - ref_raw[ci] as i64, ref_signed[ci]);
            max_abs = max_abs.max(ref_signed[ci].abs());
        }
    }
    assert!(max_abs < bound as i64, "‖z_poly0‖∞ {max_abs} < γ1−β {bound}");

    if corrupt {
        trace.values[RAW] += Val::ONE; // wrong raw 0 → its 20-bit grouping no longer matches the bytes
    }
    if corrupt_neg {
        // forge the sign flag of coeff 0 → the lt-comparator drives diff out of [0,2²¹).
        let cur = trace.values[NEG].as_canonical_u64();
        trace.values[NEG] = Val::from_u64(1 - cur);
    }
    if corrupt_z {
        trace.values[ZQ] += Val::ONE; // wrong residue → z_q = γ1 − raw + neg·q fails
    }

    let config = make_config();
    let pis: Vec<Val> = vec![];
    let proof = prove(&config, &air, trace, &pis);
    let any_corrupt = corrupt || corrupt_neg || corrupt_z;
    match verify(&config, &air, &proof, &pis) {
        Ok(_) if any_corrupt => println!("NEGATIVE TEST FAIL — wrong z decode accepted!"),
        Ok(_) => println!(
            "VERIFY ok — ML-DSA-87 sigDecode z unpacking (FIPS-204 BitUnpack, 20-bit) proven as a \
             Plonky3 AIR over a REAL libcrux signature (poly 0, 128 groups / 256 coeffs): 2 coefficients \
             unpacked from 5 packed bytes via 40 shared bits regrouped 20-bit-per-coeff vs 8-bit-per-byte, \
             the raw = t = γ1−z (‖·‖∞ {max_abs} < γ1−β {bound}, the value the norm bound consumes), and the \
             signed→mod-q residue z_q = (γ1−raw) mod q surfaced via a proven sign neg=[raw>γ1]. raw and z_q \
             are diff-tested == the reference decode_z_poly, coefficient-exact. This closes design §7 wire 22 \
             — the last non-plumbing decode gap (a wrong-endianness unpack, a forged sign, or a forged \
             residue are each caught)."
        ),
        Err(er) if any_corrupt => println!("NEGATIVE TEST PASS — wrong z decode rejected: {er:?}"),
        Err(er) => println!("UNEXPECTED reject on a valid trace: {er:?}"),
    }
}
