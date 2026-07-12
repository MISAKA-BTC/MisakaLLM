//! C-P6 claim-bridge (ADR-0037 §2.4 / cp6-design §2 item 1) — **`pk_receipt_hash == H(pk)`
//! IN-AIR**: bind the 2592-byte ML-DSA-87 verification key `pk` to the 64-byte
//! `pk_receipt_hash` that sits in the anonymous provider-registry leaf
//! (`provider_leaf = H_k("provider-leaf", pk_receipt_hash ‖ claim_pk)`, `mil/shield/src/
//! provider.rs::provider_leaf`). This closes the LAST inventory gap of the cp6 soundness
//! wire (`docs/mil-shield-cp6-mldsa-in-circuit-design.md` §7 wire 24, "claim ⇐ ML-DSA-verify
//! bridge — FREE, no gadget"): until now a prover could put ANY `pk_receipt_hash` in the
//! leaf, unlinked from a real ML-DSA key; here the public `pk_receipt_hash` is the PROVEN
//! keyed-BLAKE2b-512 of a 2592-byte preimage the prover must exhibit in the trace.
//!
//! ## Exact hash (read from source, not assumed)
//! `pk_receipt_hash = blake2b_512_keyed(b"misaka-mil-v1/provider-id", pk)` where `pk` is the
//! 2592-byte ML-DSA-87 vk (`ρ‖t1`). This is `mil/core/src/ident.rs::provider_id(pk_receipt)`
//! — the 64-byte Hash64 provider-registry identity anchored at registration
//! (`mil/core/src/anchor.rs::RegistrationAnchor.provider_id`) and the low-32 of the on-chain
//! `ProviderRegistry.sol` `providerId`. `blake2b_512_keyed` (`crypto/hashes/src/lib.rs`) is
//! `blake2b_simd::Params::new().hash_length(64).key(domain).to_state().update(pk).finalize()`:
//! keyed BLAKE2b-512, 128-byte blocks, keyed-hash parameter block `P0 = 0x01010000 ^
//! (keylen<<8) ^ 64` XORed into `h[0]`, little-endian byte order — identical construction to
//! build#1..#7. NOTE the on-chain registry ALSO stores a 32-byte `keccak256(pk_receipt)`
//! (`pkReceiptHash`); that is a DIFFERENT field (keccak, 32 B) and is NOT the shielded leaf's
//! 64-byte `pk_receipt_hash` — the leaf value is the keyed-BLAKE2b provider-id above.
//!
//! ## Construction (proven building blocks, verbatim)
//! One full 12-round keyed-BLAKE2b-512 compression per row (build#1 `compress.rs`
//! `Blake2bCompressAir`), multi-block-chained exactly like `merkle.rs`/`spend.rs`/`claim.rs`:
//! the universal `next.CUR == HOUT` transition threads the chaining value, per-row `v_init`
//! (`t` counter + `last` flag) live in PREPROCESSED columns, `chain` selects `v_init[0..8] =
//! CUR` for message rows. Block schedule for a 2592-byte pk:
//!   - row 0        — KEY block: `m = domain ‖ 0-pad` (128 B), `t=128`, not last  → `HOUT =
//!                    h_domain` (the state after absorbing the BLAKE2b key block);
//!   - rows 1..=21  — MESSAGE blocks 0..20 (private pk): block i sources `pk[128i .. 128i+128]`
//!                    (last block = `pk[2560..2592] ‖ 0-pad`), `t = 128 + min(128(i+1),2592)`,
//!                    last on block 20 → row 21 `HOUT = pk_receipt_hash`.
//! Block count = key-block(1) + ⌈2592/128⌉(21) = 22 compressions, padded to 32 rows.
//!
//! ## Public interface (M-09 canonical bytes)
//! The computed `pk_receipt_hash` is exposed as 64 PUBLIC BYTES. Each public byte is bound to
//! `Σ_{t<8} HOUT_bit·2^t` of the final-row output, and every `HOUT` column is boolean (the
//! global `x(x−1)=0`), so each public byte is a sum of 8 boolean bits ∈ [0,256) — CANONICAL
//! by construction (M-09: a distinct field-equal non-byte limb is unprovable). The last
//! message block's 96 zero-pad bytes are pinned to 0 in-AIR, so the proven preimage is
//! exactly the 2592-byte pk (byte-identical to `blake2b_512_keyed(domain, pk)`).
//!
//! ## Validation gates
//! (1) host diff-test — the AIR's final-row `HOUT` == `blake2b_512_keyed(domain, pk)` computed
//! BOTH by the in-file word-level `keyed_ref` AND by the `blake2b_simd` library (the exact
//! `crypto/hashes` construction), byte-for-byte, over a REAL `libcrux_ml_dsa::ml_dsa_87` pk;
//! plus row-0 `HOUT == h_domain` and a host-bind of `provider_leaf(pk_receipt_hash, claim_pk)`
//! showing the output is the value that enters the leaf. (2) VERIFY ok with prove/verify times,
//! cols/rows, prep width, proof bytes. (3) NEGATIVES reject (OodEvaluationMismatch):
//! `--corrupt-pk` (flip one pk byte ⇒ different hash ⇒ the claimed public no longer matches),
//! `--corrupt-hash` (claim a wrong `pk_receipt_hash` public for the honest pk). (4) printed
//! self-audit: block count == key-block + ⌈2592/128⌉, chaining wires bound, output canonical.
//!
//! ## BENCH-CONFIG CAVEAT (identical to the sibling bins — NOT a circuit-logic caveat)
//! `FriParameters::new_testing(_, 2)` is ~5-bit FRI soundness (2 queries) and the hiding
//! salts use `SmallRng::seed_from_u64(1)` (deterministic): a green run proves the CIRCUIT
//! LOGIC, not a binding proof, and the `PRIVACY OK` banner is a witness-absence SMOKE TEST,
//! not a ZK guarantee. Production: ~100 queries / grinding + OS entropy per proof. The
//! `blake2b_simd` reference is the same standard BLAKE2b-512 algorithm kaspa's
//! `blake2b_512_keyed` uses (1.0.x is output-stable across patch releases).
//!
//! Run: `cargo run --release --bin pk_receipt_bind_air [--corrupt-pk|--corrupt-hash]`

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_fri::{FriParameters, HidingFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::{StarkConfig, prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
use rand::SeedableRng;
use rand::rngs::SmallRng;

use libcrux_ml_dsa::ml_dsa_87;

const W: usize = 64;
const NROUNDS: usize = 12;
const PK_LEN: usize = 2592; // ML-DSA-87 vk (ρ‖t1)
const NBLOCKS: usize = PK_LEN.div_ceil(128); // 21 message blocks
const HEIGHT: usize = 32; // key(1) + 21 message + 10 padding

/// The exact keyed-BLAKE2b domain of the shielded provider-registry `pk_receipt_hash`.
/// == `mil/core/src/domains.rs::MIL_PROVIDER_ID_DOMAIN` (the `provider_id` derivation).
const PK_RECEIPT_DOMAIN: &[u8] = b"misaka-mil-v1/provider-id";
/// Only used for the host-bind demonstration that the output enters the registry leaf.
const PROVIDER_LEAF_DOMAIN: &[u8] = b"misaka-shield-v1/provider-leaf";

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];
const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

// ---- main-trace column layout (bit columns) ----
const CUR: usize = 0; // chaining value (== previous row's HOUT via transition)
const M: usize = 8 * W; // 16-word message block
const VINIT: usize = 24 * W; // 16-word initialized v state
const FFTMP: usize = 40 * W;
const HOUT: usize = 48 * W;
const GBLK: usize = 56 * W;
const GSTRIDE: usize = 16 * W;
const NUM_COLS: usize = GBLK + NROUNDS * 8 * GSTRIDE;

// ---- public values: pk_receipt_hash as 64 canonical bytes ----
const NUM_PIS: usize = 64;

// ---- preprocessed columns ----
const PREP_VINIT: usize = 0; // 16*W bits
const PREP_CHAIN: usize = 16 * W;
const PREP_FLAG: usize = 16 * W + 1;
const F_KEY: usize = 0; // row 0: message == the fixed domain key block
const F_LASTPAD: usize = 1; // last message row: pad bytes 32..128 pinned to 0
const F_OUT: usize = 2; // last message row: publics == canonical HOUT bytes
const NFLAGS: usize = 3;
const PREP_W: usize = PREP_FLAG + NFLAGS;

// G-block word indices
const AB: usize = 0;
const A1: usize = 1;
const D1: usize = 2;
const C1: usize = 3;
const B1: usize = 4;
const A1B1: usize = 5;
const A2: usize = 6;
const D2: usize = 7;
const C2: usize = 8;
const B2: usize = 9;
const CAB: usize = 10;
const CA1: usize = 11;
const CC1: usize = 12;
const CA1B1: usize = 13;
const CA2: usize = 14;
const CC2: usize = 15;

fn vw(i: usize) -> usize {
    VINIT + i * W
}
fn mw(i: usize) -> usize {
    M + i * W
}
fn gb(block: usize) -> usize {
    GBLK + block * GSTRIDE
}
fn a2(block: usize) -> usize {
    gb(block) + A2 * W
}
fn b2(block: usize) -> usize {
    gb(block) + B2 * W
}
fn c2(block: usize) -> usize {
    gb(block) + C2 * W
}
fn d2(block: usize) -> usize {
    gb(block) + D2 * W
}

fn ripple<AB2: AirBuilder>(b: &mut AB2, row: &[AB2::Var], ao: usize, bo: usize, so: usize, co: usize) {
    let two = AB2::Expr::ONE + AB2::Expr::ONE;
    for i in 0..W {
        let cin: AB2::Expr = if i == 0 { AB2::Expr::ZERO } else { row[co + i - 1].into() };
        let lhs = Into::<AB2::Expr>::into(row[ao + i]) + row[bo + i].into() + cin;
        let rhs = Into::<AB2::Expr>::into(row[so + i]) + Into::<AB2::Expr>::into(row[co + i]) * two.clone();
        b.assert_eq(lhs, rhs);
    }
}
fn xorrot<AB2: AirBuilder>(b: &mut AB2, row: &[AB2::Var], ao: usize, bo: usize, oo: usize, sh: usize) {
    let two = AB2::Expr::ONE + AB2::Expr::ONE;
    for i in 0..W {
        let j = (i + sh) % W;
        let aj: AB2::Expr = row[ao + j].into();
        let bj: AB2::Expr = row[bo + j].into();
        let xor = aj.clone() + bj.clone() - aj * bj * two.clone();
        b.assert_eq(Into::<AB2::Expr>::into(row[oo + i]), xor);
    }
}
#[allow(clippy::too_many_arguments)]
fn g_constraints<AB2: AirBuilder>(b: &mut AB2, row: &[AB2::Var], ia: usize, ib: usize, ic: usize, id: usize, ix: usize, iy: usize, g: usize) {
    ripple(b, row, ia, ib, g + AB * W, g + CAB * W);
    ripple(b, row, g + AB * W, ix, g + A1 * W, g + CA1 * W);
    xorrot(b, row, id, g + A1 * W, g + D1 * W, 32);
    ripple(b, row, ic, g + D1 * W, g + C1 * W, g + CC1 * W);
    xorrot(b, row, ib, g + C1 * W, g + B1 * W, 24);
    ripple(b, row, g + A1 * W, g + B1 * W, g + A1B1 * W, g + CA1B1 * W);
    ripple(b, row, g + A1B1 * W, iy, g + A2 * W, g + CA2 * W);
    xorrot(b, row, g + D1 * W, g + A2 * W, g + D2 * W, 16);
    ripple(b, row, g + C1 * W, g + D2 * W, g + C2 * W, g + CC2 * W);
    xorrot(b, row, g + B1 * W, g + C2 * W, g + B2 * W, 63);
}

#[derive(Clone, Copy)]
struct RowSpec {
    vinit: [u64; 16],
    chain: bool,
    flags: u32,
}
fn flag(f: usize) -> u32 {
    1 << f
}
fn vc(h: Option<[u64; 8]>, t: u64, last: bool) -> [u64; 16] {
    let mut v = [0u64; 16];
    if let Some(hh) = h {
        v[..8].copy_from_slice(&hh);
    }
    v[8..12].copy_from_slice(&IV[0..4]);
    v[12] = IV[4] ^ t;
    v[13] = IV[5];
    v[14] = IV[6] ^ if last { u64::MAX } else { 0 };
    v[15] = IV[7];
    v
}

// row indices
const R_KEY: usize = 0;
const R_MSG0: usize = 1; // ..= R_MSG0 + NBLOCKS - 1 = 21
const R_LAST: usize = R_MSG0 + NBLOCKS - 1; // 21

/// Initial BLAKE2b state before the key block: IV with the keyed-hash parameter block
/// `P0 = 0x01010000 ^ (keylen<<8) ^ 64` XORed into `h[0]` (digest_len=64, fanout=depth=1).
fn key_init() -> [u64; 8] {
    let kk = PK_RECEIPT_DOMAIN.len() as u64;
    let mut h = IV;
    h[0] ^= 0x0101_0000 ^ (kk << 8) ^ 64;
    h
}
/// The 128-byte key block: the domain string, zero-padded (BLAKE2b keyed mode).
fn domain_key_words() -> [u64; 16] {
    let mut kb = [0u8; 128];
    kb[..PK_RECEIPT_DOMAIN.len()].copy_from_slice(PK_RECEIPT_DOMAIN);
    block_words(&kb)
}

fn schedule() -> Vec<RowSpec> {
    // padding rows: a valid all-zero-message compression that chains the value forward.
    let mut s = vec![RowSpec { vinit: vc(None, 256, true), chain: true, flags: 0 }; HEIGHT];
    // row 0: KEY block — h_in = key_init, t=128, not last; message pinned to the domain block.
    s[R_KEY] = RowSpec { vinit: vc(Some(key_init()), 128, false), chain: false, flags: flag(F_KEY) };
    // rows 1..=21: MESSAGE blocks 0..20 of the 2592-byte pk (chained).
    for i in 0..NBLOCKS {
        let end = ((i + 1) * 128).min(PK_LEN);
        let t = (128 + end) as u64; // cumulative bytes incl. the 128-byte key block
        let last = i == NBLOCKS - 1;
        let mut f = 0u32;
        if last {
            f |= flag(F_LASTPAD) | flag(F_OUT);
        }
        s[R_MSG0 + i] = RowSpec { vinit: vc(None, t, last), chain: true, flags: f };
    }
    s
}

struct PkReceiptBindAir {
    sched: Vec<RowSpec>,
}
impl<F: PrimeField64> BaseAir<F> for PkReceiptBindAir {
    fn width(&self) -> usize {
        NUM_COLS
    }
    fn num_public_values(&self) -> usize {
        NUM_PIS
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
    fn preprocessed_width(&self) -> usize {
        PREP_W
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let bit = |b: bool| F::from_u64(b as u64);
        let mut vals = F::zero_vec(HEIGHT * PREP_W);
        for (r, spec) in self.sched.iter().enumerate() {
            let base = r * PREP_W;
            for i in 0..16 {
                for k in 0..W {
                    vals[base + PREP_VINIT + i * W + k] = bit((spec.vinit[i] >> k) & 1 == 1);
                }
            }
            vals[base + PREP_CHAIN] = bit(spec.chain);
            for f in 0..NFLAGS {
                vals[base + PREP_FLAG + f] = bit((spec.flags >> f) & 1 == 1);
            }
        }
        Some(RowMajorMatrix::new(vals, PREP_W))
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}

impl<AB2: AirBuilder> Air<AB2> for PkReceiptBindAir
where
    AB2::F: PrimeField64,
{
    fn eval(&self, builder: &mut AB2) {
        let pis: Vec<AB2::Expr> = (0..NUM_PIS).map(|k| builder.public_values()[k].into()).collect();
        let prep: Vec<AB2::Var> = builder.preprocessed().current_slice().to_vec();
        let main = builder.main();
        let row = main.current_slice();
        let nxt = main.next_slice();
        let one = AB2::Expr::ONE;
        // booleanity of every main column (bits + carries) — also makes the HOUT byte publics
        // canonical (each public byte is a sum of 8 boolean bits < 256).
        for i in 0..NUM_COLS {
            let x: AB2::Expr = row[i].into();
            builder.assert_zero(x.clone() * (x - one.clone()));
        }
        // v_init: low 8 words = chain·CUR + prep_vinit ; high 8 words = prep_vinit constant.
        let pchain: AB2::Expr = prep[PREP_CHAIN].into();
        for k in 0..8 * W {
            let v: AB2::Expr = row[VINIT + k].into();
            let c: AB2::Expr = row[CUR + k].into();
            let p: AB2::Expr = prep[PREP_VINIT + k].into();
            builder.assert_zero(v - pchain.clone() * c - p);
        }
        for k in 8 * W..16 * W {
            builder.assert_eq(Into::<AB2::Expr>::into(row[VINIT + k]), Into::<AB2::Expr>::into(prep[PREP_VINIT + k]));
        }
        // the build#1 compression: thread the 16-word state, σ per round.
        let mut sin: [usize; 16] = core::array::from_fn(vw);
        for r in 0..NROUNDS {
            let g: [usize; 8] = core::array::from_fn(|k| gb(r * 8 + k));
            let s = SIGMA[r];
            g_constraints(builder, row, sin[0], sin[4], sin[8], sin[12], mw(s[0]), mw(s[1]), g[0]);
            g_constraints(builder, row, sin[1], sin[5], sin[9], sin[13], mw(s[2]), mw(s[3]), g[1]);
            g_constraints(builder, row, sin[2], sin[6], sin[10], sin[14], mw(s[4]), mw(s[5]), g[2]);
            g_constraints(builder, row, sin[3], sin[7], sin[11], sin[15], mw(s[6]), mw(s[7]), g[3]);
            g_constraints(builder, row, a2(r * 8), b2(r * 8 + 1), c2(r * 8 + 2), d2(r * 8 + 3), mw(s[8]), mw(s[9]), g[4]);
            g_constraints(builder, row, a2(r * 8 + 1), b2(r * 8 + 2), c2(r * 8 + 3), d2(r * 8), mw(s[10]), mw(s[11]), g[5]);
            g_constraints(builder, row, a2(r * 8 + 2), b2(r * 8 + 3), c2(r * 8), d2(r * 8 + 1), mw(s[12]), mw(s[13]), g[6]);
            g_constraints(builder, row, a2(r * 8 + 3), b2(r * 8), c2(r * 8 + 1), d2(r * 8 + 2), mw(s[14]), mw(s[15]), g[7]);
            let base = r * 8;
            sin = [
                a2(base + 4),
                a2(base + 5),
                a2(base + 6),
                a2(base + 7),
                b2(base + 7),
                b2(base + 4),
                b2(base + 5),
                b2(base + 6),
                c2(base + 6),
                c2(base + 7),
                c2(base + 4),
                c2(base + 5),
                d2(base + 5),
                d2(base + 6),
                d2(base + 7),
                d2(base + 4),
            ];
        }
        for i in 0..8 {
            xorrot(builder, row, vw(i), sin[i], FFTMP + i * W, 0);
            xorrot(builder, row, FFTMP + i * W, sin[i + 8], HOUT + i * W, 0);
        }
        // ---- per-row flag-gated bindings ----
        let fl: Vec<AB2::Expr> = (0..NFLAGS).map(|f| prep[PREP_FLAG + f].into()).collect();
        // F_KEY: the key-block message is the fixed domain block (domain ‖ 0-pad).
        let kw = domain_key_words();
        for i in 0..16 {
            for k in 0..W {
                let c = if (kw[i] >> k) & 1 == 1 { AB2::Expr::ONE } else { AB2::Expr::ZERO };
                builder.assert_zero(fl[F_KEY].clone() * (Into::<AB2::Expr>::into(row[mw(i) + k]) - c));
            }
        }
        // F_LASTPAD: the last message block's pad bytes (32..128) are zero, so the proven
        // preimage is EXACTLY the 2592-byte pk (byte-identical to blake2b_512_keyed(domain,pk)).
        for bit in (PK_LEN % 128) * 8..16 * W {
            builder.assert_zero(fl[F_LASTPAD].clone() * Into::<AB2::Expr>::into(row[M + bit]));
        }
        // F_OUT: pk_receipt_hash public bytes == canonical bytes of the final HOUT (M-09).
        for b in 0..64 {
            let byte = (0..8).fold(AB2::Expr::ZERO, |acc, t| {
                acc + Into::<AB2::Expr>::into(row[HOUT + b * 8 + t]) * AB2::Expr::from_u64(1u64 << t)
            });
            builder.assert_zero(fl[F_OUT].clone() * (byte - pis[b].clone()));
        }
        // ---- transition: universal digest chaining (next.CUR == HOUT) ----
        {
            let mut wt = builder.when_transition();
            for k in 0..8 * W {
                wt.assert_eq(nxt[CUR + k], row[HOUT + k]);
            }
        }
    }
}

// ---- reference keyed BLAKE2b-512 (mirrors crypto/hashes::blake2b_512_keyed word-for-word) ----
#[inline]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}
fn compress_ref(h_in: &[u64; 8], m: &[u64; 16], t: u128, last: bool) -> [u64; 8] {
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h_in);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    if last {
        v[14] ^= 0xffff_ffff_ffff_ffff;
    }
    for s in SIGMA.iter() {
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    let mut h = *h_in;
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
    h
}
fn block_words(block: &[u8; 128]) -> [u64; 16] {
    let mut m = [0u64; 16];
    for (i, w) in m.iter_mut().enumerate() {
        *w = u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
    }
    m
}
fn h_domain(domain: &[u8]) -> [u64; 8] {
    let kk = domain.len() as u64;
    let mut h = IV;
    h[0] ^= 0x0101_0000 ^ (kk << 8) ^ 64;
    let mut kb = [0u8; 128];
    kb[..domain.len()].copy_from_slice(domain);
    compress_ref(&h, &block_words(&kb), 128, false)
}
/// Word-level keyed BLAKE2b-512 — identical construction to `blake2b_512_keyed`.
fn keyed_ref(domain: &[u8], data: &[u8]) -> [u64; 8] {
    let mut h = h_domain(domain);
    let nblocks = data.len().div_ceil(128).max(1);
    for i in 0..nblocks {
        let start = i * 128;
        let end = (start + 128).min(data.len());
        let mut b = [0u8; 128];
        b[..end - start].copy_from_slice(&data[start..end]);
        let t = (128 + end) as u128;
        let last = i == nblocks - 1;
        h = compress_ref(&h, &block_words(&b), t, last);
    }
    h
}
fn words_to_bytes(w: &[u64; 8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for (i, x) in w.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&x.to_le_bytes());
    }
    out
}
/// The EXACT `crypto/hashes/src/lib.rs::blake2b_512_keyed` construction, via `blake2b_simd`.
fn blake2b_simd_ref(domain: &[u8], data: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out.copy_from_slice(blake2b_simd::Params::new().hash_length(64).key(domain).to_state().update(data).finalize().as_bytes());
    out
}
/// Host demonstration that the output feeds the registry leaf: `provider_leaf =
/// H_k("provider-leaf", pk_receipt_hash ‖ claim_pk)` (mil/shield/src/provider.rs).
fn provider_leaf_ref(pk_receipt_hash: &[u64; 8], claim_pk: &[u64; 8]) -> [u64; 8] {
    let mut d = [0u8; 128];
    d[..64].copy_from_slice(&words_to_bytes(pk_receipt_hash));
    d[64..].copy_from_slice(&words_to_bytes(claim_pk));
    keyed_ref(PROVIDER_LEAF_DOMAIN, &d)
}

// ---- trace generation ----
fn set_word<F: PrimeField64>(vals: &mut [F], off: usize, w: u64) {
    for i in 0..W {
        vals[off + i] = F::from_u64((w >> i) & 1);
    }
}
fn set_words<F: PrimeField64>(vals: &mut [F], off: usize, w: &[u64; 8]) {
    for (i, x) in w.iter().enumerate() {
        set_word(vals, off + i * W, *x);
    }
}
fn carries(p: u64, q: u64) -> [u64; W] {
    let mut c = [0u64; W];
    let mut cin = 0u64;
    for i in 0..W {
        let cout = (((p >> i) & 1) + ((q >> i) & 1) + cin) >> 1;
        c[i] = cout;
        cin = cout;
    }
    c
}
fn fill_g<F: PrimeField64>(vals: &mut [F], base: usize, g_off: usize, a: u64, b: u64, c: u64, d: u64, x: u64, y: u64) -> [u64; 4] {
    let ab = a.wrapping_add(b);
    let a1 = ab.wrapping_add(x);
    let d1 = (d ^ a1).rotate_right(32);
    let c1 = c.wrapping_add(d1);
    let b1 = (b ^ c1).rotate_right(24);
    let a1b1 = a1.wrapping_add(b1);
    let a2v = a1b1.wrapping_add(y);
    let d2v = (d1 ^ a2v).rotate_right(16);
    let c2v = c1.wrapping_add(d2v);
    let b2v = (b1 ^ c2v).rotate_right(63);
    for (idx, val) in [(AB, ab), (A1, a1), (D1, d1), (C1, c1), (B1, b1), (A1B1, a1b1), (A2, a2v), (D2, d2v), (C2, c2v), (B2, b2v)] {
        set_word(vals, base + g_off + idx * W, val);
    }
    for (idx, p, q) in [(CAB, a, b), (CA1, ab, x), (CC1, c, d1), (CA1B1, a1, b1), (CA2, a1b1, y), (CC2, c1, d2v)] {
        let cc = carries(p, q);
        for i in 0..W {
            vals[base + g_off + idx * W + i] = F::from_u64(cc[i]);
        }
    }
    [a2v, b2v, c2v, d2v]
}

/// Build the trace over the 2592-byte `pk`; returns the matrix and the final-row digest.
fn generate<F: PrimeField64>(pk: &[u8; PK_LEN], sched: &[RowSpec]) -> (RowMajorMatrix<F>, [u64; 8]) {
    let mut vals = F::zero_vec(HEIGHT * NUM_COLS);
    let key_words = domain_key_words();
    let mut cur = [0u64; 8];
    let mut last_digest = [0u64; 8];
    for r in 0..HEIGHT {
        let base = r * NUM_COLS;
        let spec = &sched[r];
        // build this row's message block
        let mut m = [0u64; 16];
        if spec.flags & flag(F_KEY) != 0 {
            m = key_words;
        } else if (R_MSG0..R_MSG0 + NBLOCKS).contains(&r) {
            let i = r - R_MSG0;
            let start = i * 128;
            let end = (start + 128).min(PK_LEN);
            let mut b = [0u8; 128];
            b[..end - start].copy_from_slice(&pk[start..end]);
            m = block_words(&b);
        }
        set_words(&mut vals, base + CUR, &cur);
        for i in 0..16 {
            set_word(&mut vals, base + mw(i), m[i]);
        }
        // v_init (chain low 8 words from CUR when flagged)
        let mut vinit = spec.vinit;
        if spec.chain {
            vinit[..8].copy_from_slice(&cur);
        }
        for i in 0..16 {
            set_word(&mut vals, base + vw(i), vinit[i]);
        }
        // compression
        let mut v = vinit;
        for (rr, s) in SIGMA.iter().enumerate().take(NROUNDS) {
            let bk = rr * 8;
            let o0 = fill_g(&mut vals, base, gb(bk), v[0], v[4], v[8], v[12], m[s[0]], m[s[1]]);
            let o1 = fill_g(&mut vals, base, gb(bk + 1), v[1], v[5], v[9], v[13], m[s[2]], m[s[3]]);
            let o2 = fill_g(&mut vals, base, gb(bk + 2), v[2], v[6], v[10], v[14], m[s[4]], m[s[5]]);
            let o3 = fill_g(&mut vals, base, gb(bk + 3), v[3], v[7], v[11], v[15], m[s[6]], m[s[7]]);
            let o4 = fill_g(&mut vals, base, gb(bk + 4), o0[0], o1[1], o2[2], o3[3], m[s[8]], m[s[9]]);
            let o5 = fill_g(&mut vals, base, gb(bk + 5), o1[0], o2[1], o3[2], o0[3], m[s[10]], m[s[11]]);
            let o6 = fill_g(&mut vals, base, gb(bk + 6), o2[0], o3[1], o0[2], o1[3], m[s[12]], m[s[13]]);
            let o7 = fill_g(&mut vals, base, gb(bk + 7), o3[0], o0[1], o1[2], o2[3], m[s[14]], m[s[15]]);
            v = [
                o4[0], o5[0], o6[0], o7[0], o7[1], o4[1], o5[1], o6[1], o6[2], o7[2], o4[2], o5[2], o5[3], o6[3], o7[3], o4[3],
            ];
        }
        let mut hout = [0u64; 8];
        for i in 0..8 {
            let ff = vinit[i] ^ v[i];
            set_word(&mut vals, base + FFTMP + i * W, ff);
            hout[i] = ff ^ v[i + 8];
            set_word(&mut vals, base + HOUT + i * W, hout[i]);
        }
        if r == R_LAST {
            last_digest = hout;
        }
        cur = hout;
    }
    (RowMajorMatrix::new(vals, NUM_COLS), last_digest)
}

// ---- hiding / ZK config (verbatim from claim.rs — bench FRI params, NOT production) ----
type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;
type Dft = Radix2DitParallel<Val>;
type ZkByteHash = Keccak256Hash;
type ZkU64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type ZkFieldHash = SerializingHasher<ZkU64Hash>;
type ZkCompress = CompressionFunctionFromHasher<ZkU64Hash, 2, 4>;
type ZkValHidingMmcs = MerkleTreeHidingMmcs<[Val; p3_keccak::VECTOR_LEN], [u64; p3_keccak::VECTOR_LEN], ZkFieldHash, ZkCompress, SmallRng, 2, 4, 4>;
type ZkChallenger = SerializingChallenger32<Val, HashChallenger<u8, ZkByteHash, 32>>;
type ZkChallengeHidingMmcs = ExtensionMmcs<Val, Challenge, ZkValHidingMmcs>;
type ZkHidingPcs = HidingFriPcs<Val, Dft, ZkValHidingMmcs, ZkChallengeHidingMmcs, SmallRng>;
type ZkConfig = StarkConfig<ZkHidingPcs, Challenge, ZkChallenger>;
fn make_zk_config() -> ZkConfig {
    let byte_hash = ZkByteHash {};
    let u64_hash = ZkU64Hash::new(KeccakF {});
    let field_hash = ZkFieldHash::new(u64_hash);
    let compress = ZkCompress::new(u64_hash);
    let val_mmcs = ZkValHidingMmcs::new(field_hash, compress, 0, SmallRng::seed_from_u64(1));
    let challenge_mmcs = ZkChallengeHidingMmcs::new(val_mmcs.clone());
    let fri_params = FriParameters::new_testing(challenge_mmcs, 2);
    let pcs = ZkHidingPcs::new(Dft::default(), val_mmcs, fri_params, 4, SmallRng::seed_from_u64(1));
    ZkConfig::new(pcs, ZkChallenger::from_hasher(vec![], byte_hash))
}

fn hout_at(trace: &RowMajorMatrix<Val>, r: usize) -> [u64; 8] {
    core::array::from_fn(|i| {
        (0..W).fold(0u64, |acc, k| acc | ((trace.values[r * NUM_COLS + HOUT + i * W + k].as_canonical_u64() & 1) << k))
    })
}

fn main() {
    let arg = |s: &str| std::env::args().any(|a| a == s);
    let (corrupt_pk, corrupt_hash) = (arg("--corrupt-pk"), arg("--corrupt-hash"));
    let negative = corrupt_pk || corrupt_hash;

    // ---- a REAL ML-DSA-87 verification key (2592 B) from libcrux ----
    let seed: [u8; 32] = core::array::from_fn(|i| (0x1b_u8).wrapping_mul(i as u8 + 1) ^ 0xa5);
    let kp = ml_dsa_87::generate_key_pair(seed);
    let vk = kp.verification_key.as_ref();
    assert_eq!(vk.len(), PK_LEN, "ML-DSA-87 pk must be 2592 B (ρ‖t1)");
    let mut pk = [0u8; PK_LEN];
    pk.copy_from_slice(vk);

    // ---- GATE 1: reference cross-check (hand-rolled words == blake2b_simd library) ----
    let href_words = keyed_ref(PK_RECEIPT_DOMAIN, &pk);
    let href_bytes = words_to_bytes(&href_words);
    let lib_bytes = blake2b_simd_ref(PK_RECEIPT_DOMAIN, &pk);
    assert_eq!(
        href_bytes, lib_bytes,
        "in-file keyed BLAKE2b-512 != blake2b_simd (the crypto/hashes::blake2b_512_keyed construction)"
    );
    let pk_receipt_hash = href_words;

    // the trace's pk (flip one byte for --corrupt-pk; the trace stays internally consistent,
    // so only the F_OUT public binding is violated against the honest public hash).
    let mut tpk = pk;
    if corrupt_pk {
        tpk[1234] ^= 0x01;
    }

    let sched = schedule();
    let air = PkReceiptBindAir { sched: sched.clone() };
    let (trace, trace_digest) = generate::<Val>(&tpk, &sched);

    // ---- host diff-test: row-0 == h_domain, final row == blake2b_512_keyed(domain, tpk) ----
    let row0 = hout_at(&trace, R_KEY);
    let final_row = hout_at(&trace, R_LAST);
    let hd = h_domain(PK_RECEIPT_DOMAIN);
    let ref_tpk = keyed_ref(PK_RECEIPT_DOMAIN, &tpk);
    let ref_tpk_lib = blake2b_simd_ref(PK_RECEIPT_DOMAIN, &tpk);
    let host_ok = row0 == hd && final_row == ref_tpk && words_to_bytes(&final_row) == ref_tpk_lib;
    // host-bind: the output is exactly the value that enters provider_leaf(pk_receipt_hash, claim_pk).
    let claim_pk = keyed_ref(b"misaka-shield-v1/addr", &words_to_bytes(&[0x51u64; 8]));
    let leaf = provider_leaf_ref(&trace_digest, &claim_pk);
    println!(
        "host diff-test: row0==h_domain && final HOUT==blake2b_512_keyed(\"{}\", pk[2592]) \
         (word-level AND blake2b_simd, byte-for-byte): {host_ok}  [pk_receipt_hash feeds \
         provider_leaf -> leaf[0..8]={:#018x}]",
        std::str::from_utf8(PK_RECEIPT_DOMAIN).unwrap(),
        leaf[0]
    );
    assert!(host_ok, "host diff-test failed");

    // ---- GATE 4: printed self-audit ----
    let n_active = 1 + NBLOCKS; // key block + message blocks
    let chain_wires = (HEIGHT - 1) * 8 * W; // next.CUR == HOUT bindings
    let pad_bits_pinned = 16 * W - (PK_LEN % 128) * 8; // zeroed last-block pad bits
    assert_eq!(n_active, 22, "block count must be key(1)+ceil(2592/128)(21)=22");
    assert_eq!(NBLOCKS, PK_LEN.div_ceil(128));
    println!(
        "self-audit: blocks = key-block(1) + ceil(2592/128)={NBLOCKS} message = {n_active} \
         compressions (rows 0..={R_LAST}, padded to {HEIGHT}); chaining wires bound = \
         {chain_wires} (next.CUR==HOUT over {} transitions x 8x64); output canonical = 64 \
         public bytes each == sum of 8 boolean HOUT bits (<256); last-block pad bits pinned to \
         0 = {pad_bits_pinned}; cols={NUM_COLS}, prep={PREP_W}",
        HEIGHT - 1
    );

    // ---- publics: pk_receipt_hash as 64 canonical bytes (flip one for --corrupt-hash) ----
    let hash_bytes = words_to_bytes(&pk_receipt_hash);
    let mut pis: Vec<Val> = hash_bytes.iter().map(|&b| Val::from_u64(b as u64)).collect();
    if corrupt_hash {
        pis[17] = Val::from_u64((hash_bytes[17] ^ 0x01) as u64);
    }

    // ---- prove + verify ----
    let config = make_zk_config();
    let degree_bits = HEIGHT.ilog2() as usize;
    let (pp_data, pp_vk) = setup_preprocessed::<ZkConfig, _>(&config, &air, degree_bits).expect("preprocessed setup");
    let t0 = std::time::Instant::now();
    let proof = prove_with_preprocessed(&config, &air, trace, &pis, Some(&pp_data));
    let t_prove = t0.elapsed();
    let proof_bytes = postcard::to_allocvec(&proof).unwrap().len();
    let t1 = std::time::Instant::now();
    let res = verify_with_preprocessed(&config, &air, &proof, &pis, Some(&pp_vk));
    let t_verify = t1.elapsed();
    match &res {
        Ok(_) if negative => println!("NEGATIVE TEST FAIL — an unlinked pk_receipt_hash was accepted!"),
        Ok(_) => println!(
            "VERIFY ok — pk_receipt_hash == keyed-BLAKE2b(\"misaka-mil-v1/provider-id\", pk[2592]) \
             proven IN-AIR over a REAL ML-DSA-87 vk ({n_active} compressions chained), 64-byte \
             canonical public output; hiding-ZK [prove {t_prove:.1?}, verify {t_verify:.1?}, \
             {NUM_COLS} cols x {HEIGHT} rows, prep {PREP_W}, proof {proof_bytes} bytes]"
        ),
        Err(e) if negative => println!("NEGATIVE TEST PASS — unlinked/wrong pk_receipt_hash rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on a valid bridge: {e:?}"),
    }

    // ---- privacy smoke test (positive runs): the private pk does not appear verbatim ----
    if !negative {
        let pb = postcard::to_allocvec(&proof).unwrap();
        let mut words: Vec<u64> = pk.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
        words.retain(|&w| w != 0);
        let leaked = words.iter().filter(|&&w| pb.windows(8).any(|win| win == w.to_le_bytes())).count();
        if leaked == 0 {
            println!(
                "PRIVACY OK (witness-absence smoke test) — the private ML-DSA-87 pk ({} nonzero \
                 8-byte words) does not appear verbatim in the proof ({} bytes). NOTE: real \
                 hiding needs prod entropy (see caveats).",
                words.len(),
                pb.len()
            );
        } else {
            println!("PRIVACY LEAK — {leaked} private pk word(s) present in the proof");
        }
    }
}
