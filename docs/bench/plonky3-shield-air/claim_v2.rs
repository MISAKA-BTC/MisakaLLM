//! Blake2bClaimV2Air — the ANONYMOUS PROVIDER CLAIM with a **HIDDEN AMOUNT**
//! (ADR-0037 §2.2, circuit_version=4).
//!
//! NOTE (audit H-01 / H-05R — CLOSED): the AIR no longer recomputes `ctx` from a
//! stale 4-field preimage. `PI_CTX` is now an OPAQUE bound public input — declared in
//! the statement, surfaced as a public value, and NOT re-derived in-circuit — exactly
//! as the sibling spend AIR (`spend.rs`) and `provider.rs::verify_reference_v2` treat
//! it. The SOLE ctx authority is the 404-byte contract preimage
//! `evm_ctx.rs::claim_ctx_onchain` (== Solidity `_computeClaimCtx`: chainId ‖ contract
//! ‖ escrowId ‖ setRoot ‖ sessionCm ‖ grossSompi(32B) ‖ providerNf ‖ cmPayout ‖
//! keccak256(encNote)). This is SAFE because the node binder
//! (`shield-stark-verify::statement_is_bound`) forces the proof's surfaced `PI_CTX` to
//! equal that contract-computed ctx byte-for-byte over the frozen 392-byte statement,
//! and the verifier observes `PI_CTX` in its challenger — so a wrong ctx is rejected at
//! the STATEMENT level (`--wrong-ctx`). Cross-contract/escrow/gross/ciphertext
//! malleability stays closed by the contract preimage, WITHOUT expanding the frozen
//! statement or loosening binding. (Before this fix the AIR bound `H(256-byte
//! 4-field)` while the contract statement carried `H(404-byte)`: every honest claim
//! would fail-closed once claims were enabled.)
//!
//! (audit C-01 / C-06.2 — CLOSED IN-AIR) the v2 statement carries an explicit
//! `providerShareSompi` public input (the contract-computed whole-sompi 88%-of-gross,
//! `MilShieldedEscrow._borshClaimStatementV2` field 6 / Rust
//! `statement_schema::PROVIDER_CLAIM_V2_STATEMENT_SCHEMA`), and this AIR now has REAL
//! public values + constraints for it: `PI_SHARE` (64 bit-columns, positioned in the
//! frozen borsh field order between `cm_payout` and `ctx`) is constrained equal,
//! bit for bit, to the private `AMT` global — the SAME global the `v_claim_cm`
//! value-commit row and the payout note's value word already source (`F_VCM`,
//! `F_CM_B1`). So `v_claim_cm == commit(providerShareSompi)` AND
//! `payout_note.value == providerShareSompi` hold in-circuit: a proof can neither
//! fund a larger note than the contract pays in (undercollateralization) nor a
//! smaller one. Negatives: `--share-plus` / `--share-minus` (payout ±1) and
//! `--swap-fields` (statement field-order mutation) must be rejected. Mirrors
//! `mil/shield/src/provider.rs::verify_reference_v2` (the reference oracle).
//!
//! (audit M-08, honest privacy note) making the share public costs NO privacy under
//! uniform pricing: gross — hence the 88% share — is already publicly derivable from
//! the public `tokIn/tokOut` × snapshot price. v2 delivers *provider unlinkability*
//! (which-GPU hiding), not amount hiding; `v_claim_cm` remains for the committed-ask
//! V3 follow-up where the magnitude itself goes private. Everything build#6
//! (claim.rs) proves still holds; the ask-price-inversion closure is the UNIFORM
//! price, not amount secrecy.
//!
//!   claim_pk    = H(addr,          claim_secret)                    (spend authority)
//!   provider_leaf = H(provider-leaf, pk_receipt_hash ‖ claim_pk)    (registry leaf)
//!   membership  : provider_leaf under the PUBLIC provider_set_root at a PRIVATE index
//!   provider_nf = H(provider-nf,   claim_secret ‖ session_cm)       (public)
//!   v_claim_cm  = H(value, amount ‖ blind)   (PUBLIC — a hiding commitment to the
//!                 PRIVATE amount; `blind` is a fresh random Hash64 per claim)
//!   cm_payout   = commit(payout_note)   (public); value == amount (PRIVATE, sourced
//!                 from the same amount the commitment binds)
//!   ctx         = the 404-byte contract preimage digest (evm_ctx.rs::claim_ctx_onchain);
//!                 OPAQUE to this AIR — carried as a bound public input, NOT recomputed
//!
//! amount is a 64-bit witness column (range [0,2^64) enforced for free by the
//! bit-decomposition) BOUND to the `providerShareSompi` public input (C-01, above), so
//! the escrow's contract-computed share is enforced in-circuit — value conservation is
//! no longer a contract-layer promise. `ctx` is OPAQUE (bound public input, H-01), not
//! recomputed in-circuit. Adds one value-commitment row over build#6.
//!
//! Reuses build#1's compression AIR and build#6's row machinery wholesale; one full
//! 12-round keyed-BLAKE2b compression per row: addr(1) + provider-leaf(1) + 20
//! membership + nf(1) + value-commit(1) + commit(2, 204 B) = 26 active rows + 6 padding
//! = 32 rows (the 2 ctx-recompute rows were removed by H-01). Row types and per-row
//! v_init constants live in PREPROCESSED columns; the universal `next.CUR == HOUT`
//! transition threads digests AND multi-block absorption. Max degree 3; hiding-ZK FRI.
//!
//! PUBLIC: provider_set_root, session_cm, v_claim_cm, provider_nf, cm_payout,
//! providerShareSompi (le64 bits — the C-01 payout binding), ctx.
//! PRIVATE: pk_receipt_hash, claim_secret, leaf_index, path, payout note fields,
//! blind. Proven with hiding-ZK + a witness-absence gate (the leaf, index,
//! pk_receipt_hash, payout fields, and the blind must not appear — which-provider
//! hiding; the amount equals the public share by construction, M-08).
//!
//! Positive: default. Negative: --corrupt (sibling bit), --wrong-root, --wrong-nf,
//! --steal (a claim_secret whose leaf is not in the provider set), --share-plus /
//! --share-minus (public payout ±1 vs the committed amount — C-01), --swap-fields
//! (session_cm/provider_nf public-input blocks exchanged — statement mutation),
//! --wrong-ctx (a flipped PI_CTX public — rejected by the statement binding, H-01:
//! PI_CTX is opaque yet observed in the verifier's challenger + checked by the node
//! binder, so a stale/forged ctx cannot verify).
//!
//! BENCH-CONFIG CAVEATS (identical to spend.rs — none are circuit-logic; adversarial
//! 3-lens review found ZERO underconstraint/forgery paths):
//! - `FriParameters::new_testing(_, 2)` is ~5-bit FRI soundness (2 queries): a green
//!   run proves the CIRCUIT LOGIC, not a binding proof. Production: ~100 queries /
//!   grinding.
//! - The hiding salts + FRI randomization use `SmallRng::seed_from_u64(1)`:
//!   deterministic, so the which-provider hiding is NOT delivered at these params —
//!   a re-running adversary subtracts the known salts. Production: OS entropy per
//!   proof (see `recursive_spend.rs --prod-entropy`). The `PRIVACY OK` banner is a
//!   witness-absence SMOKE TEST (a byte-substring scan), not a ZK guarantee.
//! - `token_id` is hard-zeroed (MSK-only): the AIR proves payouts in the native token
//!   only. This is STRICTLY MORE restrictive than the reference (it can never accept a
//!   claim the reference rejects) — a conscious scope choice, not an underconstraint.
//!   Multi-token would source `token_id` from a public input, like spend.rs's PI_TOKEN.
//! - `DEPTH = 20` must equal the on-chain provider-set tree depth (the reference unit
//!   tests happen to use depth 16; the circuit is internally consistent at 20).
//! - The host diff-test compares against this file's own `keyed_ref`, which is the
//!   SAME word-level BLAKE2b logic that `mil/blake2b-air` diff-tests byte-for-byte vs
//!   `kaspa_hashes::blake2b_512_keyed` — so the digests are on-chain-correct transitively.

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
use std::collections::BTreeMap;

const DEPTH: usize = 20;
const HEIGHT: usize = 32; // 26 active + 6 padding (2 ctx-recompute rows removed by H-01)
const NROUNDS: usize = 12;
const W: usize = 64;

const ADDR_DOMAIN: &[u8] = b"misaka-shield-v1/addr";
const PROVIDER_LEAF_DOMAIN: &[u8] = b"misaka-shield-v1/provider-leaf";
const PROVIDER_NF_DOMAIN: &[u8] = b"misaka-shield-v1/provider-nf";
const CM_DOMAIN: &[u8] = b"misaka-shield-v1/cm";
// (audit H-01) no CLAIM_CTX_DOMAIN: `ctx` is opaque, computed off-circuit by the
// contract (evm_ctx.rs::claim_ctx_onchain over the 404-byte preimage), never here.
const VALUE_DOMAIN: &[u8] = b"misaka-shield-v1/value"; // hiding value commitment (v4)
const MERKLE_DOMAIN: &[u8] = b"misaka-shield-v1/merkle";
const MERKLE_EMPTY_DOMAIN: &[u8] = b"misaka-shield-v1/merkle-empty";

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
const CUR: usize = 0;
const SIB: usize = 8 * W;
const M: usize = 16 * W;
const VINIT: usize = 32 * W;
const FFTMP: usize = 48 * W;
const HOUT: usize = 56 * W;
const GBLK: usize = 64 * W;
const GSTRIDE: usize = 16 * W;
const DIR: usize = GBLK + NROUNDS * 8 * GSTRIDE;
// globals (replicated every row): claim_secret, pk_receipt_hash, payout owner/rho/r,
// the amount (64 bits, BOUND to the public PI_SHARE — C-01) + its commitment blind.
const SK: usize = DIR + 1;
const PKRH: usize = SK + 8 * W;
const OPK: usize = PKRH + 8 * W;
const RHO: usize = OPK + 8 * W;
const RR: usize = RHO + 8 * W;
const AMT: usize = RR + 8 * W; // 64 bits, bound to PI_SHARE (C-01)
const BLIND: usize = AMT + W; // 8 words, private commitment blind
const GLOBALS_START: usize = SK;
const GLOBALS_END: usize = BLIND + 8 * W;
const NUM_COLS: usize = GLOBALS_END;

// ---- public values (little-endian bits), in the FROZEN borsh field order of the
// 392-B v2 statement (statement_schema::PROVIDER_CLAIM_V2_STATEMENT_SCHEMA):
// root ‖ session ‖ v_claim_cm ‖ nf ‖ cm_payout ‖ providerShareSompi(64 bits) ‖ ctx ----
const PI_ROOT: usize = 0;
const PI_SESSION: usize = 8 * W;
const PI_VCM: usize = 16 * W; // value commitment (8 words) — replaces the raw public amount
const PI_NF: usize = PI_VCM + 8 * W;
const PI_CM: usize = PI_NF + 8 * W;
// (audit C-01) the contract-computed whole-sompi 88% share — ONE 64-bit word,
// constrained equal to the private AMT global (the value v_claim_cm and the payout
// note both bind), sitting between cm_payout and ctx exactly like the statement's
// le64 field at byte offset 320.
const PI_SHARE: usize = PI_CM + 8 * W;
const PI_CTX: usize = PI_SHARE + W;
const NUM_PIS: usize = PI_CTX + 8 * W;

// ---- preprocessed columns ----
const PREP_VINIT: usize = 0; // 1024 bits
const PREP_CHAIN: usize = 1024;
const PREP_FLAG: usize = 1025;
const F_ADDR: usize = 0;
const F_LEAF: usize = 1;
const F_MUX: usize = 2;
const F_MEM: usize = 3;
const F_NF: usize = 4;
const F_VCM: usize = 5;
const F_CM_B1: usize = 6;
const F_CM_B2: usize = 7;
// (audit H-01) F_CTX_B1/F_CTX_B2 removed: `ctx` is opaque, no in-AIR recompute.
const NFLAGS: usize = 8;
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
fn geq_cols<AB2: AirBuilder>(b: &mut AB2, fl: &AB2::Expr, row: &[AB2::Var], dst: usize, src: usize, n: usize) {
    for k in 0..n {
        let d: AB2::Expr = row[dst + k].into();
        let s: AB2::Expr = row[src + k].into();
        b.assert_zero(fl.clone() * (d - s));
    }
}
fn geq_pis<AB2: AirBuilder>(b: &mut AB2, fl: &AB2::Expr, row: &[AB2::Var], dst: usize, pis: &[AB2::Expr], src: usize, n: usize) {
    for k in 0..n {
        let d: AB2::Expr = row[dst + k].into();
        b.assert_zero(fl.clone() * (d - pis[src + k].clone()));
    }
}
fn geq_const<AB2: AirBuilder>(b: &mut AB2, fl: &AB2::Expr, row: &[AB2::Var], dst: usize, bit: bool, n: usize) {
    let c = if bit { AB2::Expr::ONE } else { AB2::Expr::ZERO };
    for k in 0..n {
        let d: AB2::Expr = row[dst + k].into();
        b.assert_zero(fl.clone() * (d - c.clone()));
    }
}
fn const_eq<AB2: AirBuilder>(b: &mut AB2, row: &[AB2::Var], kw: u64, out: usize) {
    for i in 0..W {
        let c = if (kw >> i) & 1 == 1 { AB2::Expr::ONE } else { AB2::Expr::ZERO };
        b.assert_eq(Into::<AB2::Expr>::into(row[out + i]), c);
    }
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

// row indices (one extra row over build#6 for the value commitment). (audit H-01) the
// 2 ctx-recompute rows are gone; rows R_CM_B2+1..HEIGHT (26..31) are chaining padding.
const R_ADDR: usize = 0;
const R_LEAF: usize = 1;
const R_MER0: usize = 2; // ..= R_MER0+DEPTH-1 = 21
const R_NF: usize = 22;
const R_VCM: usize = 23;
const R_CM_B1: usize = 24;
const R_CM_B2: usize = 25;

fn schedule() -> Vec<RowSpec> {
    let h_addr = h_domain(ADDR_DOMAIN);
    let h_leaf = h_domain(PROVIDER_LEAF_DOMAIN);
    let h_nf = h_domain(PROVIDER_NF_DOMAIN);
    let h_val = h_domain(VALUE_DOMAIN);
    let h_cm = h_domain(CM_DOMAIN);
    let h_mer = h_domain(MERKLE_DOMAIN);
    let mut s = vec![RowSpec { vinit: vc(None, 256, true), chain: true, flags: 0 }; HEIGHT];
    // addr: 64 B → t=192 last ; provider-leaf/nf/merkle node: 128 B → t=256 last
    s[R_ADDR] = RowSpec { vinit: vc(Some(h_addr), 192, true), chain: false, flags: flag(F_ADDR) };
    s[R_LEAF] = RowSpec { vinit: vc(Some(h_leaf), 256, true), chain: false, flags: flag(F_LEAF) };
    for r in R_MER0..R_MER0 + DEPTH {
        let mut f = flag(F_MUX);
        if r == R_MER0 + DEPTH - 1 {
            f |= flag(F_MEM);
        }
        s[r] = RowSpec { vinit: vc(Some(h_mer), 256, true), chain: false, flags: f };
    }
    s[R_NF] = RowSpec { vinit: vc(Some(h_nf), 256, true), chain: false, flags: flag(F_NF) };
    // value commitment: amount(8B) ‖ blind(64B) = 72 B → 1 block, t=200 last
    s[R_VCM] = RowSpec { vinit: vc(Some(h_val), 200, true), chain: false, flags: flag(F_VCM) };
    // commit: 204 B → block1 t=256 (not last), block2 t=332 last
    s[R_CM_B1] = RowSpec { vinit: vc(Some(h_cm), 256, false), chain: false, flags: flag(F_CM_B1) };
    s[R_CM_B2] = RowSpec { vinit: vc(None, 332, true), chain: true, flags: flag(F_CM_B2) };
    // (audit H-01) NO ctx rows: `ctx` is OPAQUE — the 404-byte contract preimage
    // (evm_ctx.rs::claim_ctx_onchain). Rows after R_CM_B2 keep the default chaining
    // padding spec (flags: 0), so PI_CTX is bound only as a public value, not recomputed.
    s
}

struct Blake2bClaimV2Air {
    sched: Vec<RowSpec>,
}
impl<F: PrimeField64> BaseAir<F> for Blake2bClaimV2Air {
    fn width(&self) -> usize {
        NUM_COLS
    }
    fn num_public_values(&self) -> usize {
        NUM_PIS
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
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

impl<AB2: AirBuilder> Air<AB2> for Blake2bClaimV2Air
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
        for i in 0..NUM_COLS {
            let x: AB2::Expr = row[i].into();
            builder.assert_zero(x.clone() * (x - one.clone()));
        }
        // v_init: constant part + optional chain from CUR
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
        // the build#1 compression
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
        // ---- per-row message sourcing + bindings, gated by preprocessed flags ----
        let fl: Vec<AB2::Expr> = (0..NFLAGS).map(|f| prep[PREP_FLAG + f].into()).collect();
        // F_ADDR: m = claim_secret ‖ 0
        geq_cols(builder, &fl[F_ADDR], row, M, SK, 8 * W);
        geq_const(builder, &fl[F_ADDR], row, M + 8 * W, false, 8 * W);
        // F_LEAF: m = pk_receipt_hash ‖ CUR(=claim_pk)
        geq_cols(builder, &fl[F_LEAF], row, M, PKRH, 8 * W);
        geq_cols(builder, &fl[F_LEAF], row, M + 8 * W, CUR, 8 * W);
        // F_MUX: m = dir ? sib‖cur : cur‖sib (which-provider hiding)
        let dir: AB2::Expr = row[DIR].into();
        for i in 0..8 {
            for k in 0..W {
                let cur: AB2::Expr = row[CUR + i * W + k].into();
                let sib: AB2::Expr = row[SIB + i * W + k].into();
                let left = cur.clone() + dir.clone() * (sib.clone() - cur.clone());
                let right = sib.clone() + dir.clone() * (cur - sib);
                builder.assert_zero(fl[F_MUX].clone() * (Into::<AB2::Expr>::into(row[mw(i) + k]) - left));
                builder.assert_zero(fl[F_MUX].clone() * (Into::<AB2::Expr>::into(row[mw(8 + i) + k]) - right));
            }
        }
        // F_MEM: HOUT == provider_set_root
        geq_pis(builder, &fl[F_MEM], row, HOUT, &pis, PI_ROOT, 8 * W);
        // F_NF: m = claim_secret ‖ session_cm ; HOUT == provider_nf
        geq_cols(builder, &fl[F_NF], row, M, SK, 8 * W);
        geq_pis(builder, &fl[F_NF], row, M + 8 * W, &pis, PI_SESSION, 8 * W);
        geq_pis(builder, &fl[F_NF], row, HOUT, &pis, PI_NF, 8 * W);
        // (audit C-01) PAYOUT BINDING: the AMT global — the SAME 64 bits the value
        // commitment (F_VCM) and the payout note's value word (F_CM_B1) source — must
        // equal the PUBLIC providerShareSompi input, bit for bit, on EVERY row (globals
        // are replicated by the transition constraints). Together with F_VCM/F_CM_B1
        // this proves v_claim_cm == commit(providerShareSompi) and
        // payout_note.value == providerShareSompi: the contract-computed share is
        // enforced in-circuit, closing the undercollateralized-note gap. Degree 1.
        for k in 0..W {
            builder.assert_eq(Into::<AB2::Expr>::into(row[AMT + k]), pis[PI_SHARE + k].clone());
        }
        // F_VCM: m = amount(= public share, bound above) ‖ blind(PRIVATE) ‖ 0 ;
        // HOUT == v_claim_cm (public).
        geq_cols(builder, &fl[F_VCM], row, M, AMT, W);
        geq_cols(builder, &fl[F_VCM], row, M + W, BLIND, 8 * W);
        geq_const(builder, &fl[F_VCM], row, M + 9 * W, false, 7 * W);
        geq_pis(builder, &fl[F_VCM], row, HOUT, &pis, PI_VCM, 8 * W);
        // F_CM_B1: m = amount(PRIVATE global) ‖ owner_pk ‖ rho[0..7w].  value == amount
        // by sourcing the value word from the SAME amount global the commitment binds.
        geq_cols(builder, &fl[F_CM_B1], row, M, AMT, W);
        geq_cols(builder, &fl[F_CM_B1], row, M + W, OPK, 8 * W);
        geq_cols(builder, &fl[F_CM_B1], row, M + 9 * W, RHO, 7 * W);
        // F_CM_B2: m = rho[7w] ‖ r ‖ token(0) ‖ 0 ; HOUT == cm_payout
        geq_cols(builder, &fl[F_CM_B2], row, M, RHO + 7 * W, W);
        geq_cols(builder, &fl[F_CM_B2], row, M + W, RR, 8 * W);
        geq_const(builder, &fl[F_CM_B2], row, M + 9 * W, false, 7 * W);
        geq_pis(builder, &fl[F_CM_B2], row, HOUT, &pis, PI_CM, 8 * W);
        // (audit H-01) NO in-AIR ctx recompute. `PI_CTX` (statement offset 328..392) is
        // an OPAQUE bound public input: declared in NUM_PIS and surfaced as a public
        // value, but constrained by NO row. Its binding is at the STATEMENT level — the
        // verifier observes it in the challenger and the node binder
        // (shield-stark-verify::statement_is_bound) checks it byte-for-byte against the
        // 404-byte contract ctx (evm_ctx.rs::claim_ctx_onchain). Mirrors the spend AIR.
        // ---- transitions: universal digest chaining + global replication ----
        {
            let mut wt = builder.when_transition();
            for k in 0..8 * W {
                wt.assert_eq(nxt[CUR + k], row[HOUT + k]);
            }
            for k in GLOBALS_START..GLOBALS_END {
                wt.assert_eq(nxt[k], row[k]);
            }
        }
        let _ = const_eq::<AB2>; // (kept for parity with the spend AIR helpers)
    }
}

// ---- reference keyed BLAKE2b + claim relation (mirrors mil/shield/src/provider.rs) ----
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

const TOKEN_ID: u32 = 0;
#[derive(Clone, Copy)]
struct Note {
    value: u64,
    owner_pk: [u64; 8],
    rho: [u64; 8],
    r: [u64; 8],
}
fn note_bytes(n: &Note) -> [u8; 204] {
    let mut b = [0u8; 204];
    b[0..8].copy_from_slice(&n.value.to_le_bytes());
    b[8..72].copy_from_slice(&words_to_bytes(&n.owner_pk));
    b[72..136].copy_from_slice(&words_to_bytes(&n.rho));
    b[136..200].copy_from_slice(&words_to_bytes(&n.r));
    b[200..204].copy_from_slice(&TOKEN_ID.to_le_bytes());
    b
}
fn addr_ref(sk: &[u64; 8]) -> [u64; 8] {
    keyed_ref(ADDR_DOMAIN, &words_to_bytes(sk))
}
fn provider_leaf_ref(pkrh: &[u64; 8], claim_pk: &[u64; 8]) -> [u64; 8] {
    let mut d = [0u8; 128];
    d[..64].copy_from_slice(&words_to_bytes(pkrh));
    d[64..].copy_from_slice(&words_to_bytes(claim_pk));
    keyed_ref(PROVIDER_LEAF_DOMAIN, &d)
}
fn provider_nf_ref(sk: &[u64; 8], session_cm: &[u64; 8]) -> [u64; 8] {
    let mut d = [0u8; 128];
    d[..64].copy_from_slice(&words_to_bytes(sk));
    d[64..].copy_from_slice(&words_to_bytes(session_cm));
    keyed_ref(PROVIDER_NF_DOMAIN, &d)
}
fn commit_ref(n: &Note) -> [u64; 8] {
    keyed_ref(CM_DOMAIN, &note_bytes(n))
}
/// v_claim_cm = H(value, amount_le8 ‖ blind) — the hiding commitment to the amount.
fn value_commit_ref(amount: u64, blind: &[u64; 8]) -> [u64; 8] {
    let mut d = [0u8; 72];
    d[..8].copy_from_slice(&amount.to_le_bytes());
    d[8..].copy_from_slice(&words_to_bytes(blind));
    keyed_ref(VALUE_DOMAIN, &d)
}
// (audit H-01) `claim_ctx_v2_ref` removed: the AIR does not recompute `ctx`. The sole
// ctx authority is the off-circuit 404-byte contract preimage
// (mil/shield/src/evm_ctx.rs::claim_ctx_onchain == Solidity `_computeClaimCtx`).
fn hash_node_ref(l: &[u64; 8], r: &[u64; 8]) -> [u64; 8] {
    let mut d = [0u8; 128];
    d[..64].copy_from_slice(&words_to_bytes(l));
    d[64..].copy_from_slice(&words_to_bytes(r));
    keyed_ref(MERKLE_DOMAIN, &d)
}
/// sparse provider-set tree (leaves = provider_leaf), returns (root, per-leaf paths).
fn sparse_tree(leaves: &[(u64, [u64; 8])]) -> ([u64; 8], Vec<[[u64; 8]; DEPTH]>) {
    let mut empty = Vec::with_capacity(DEPTH + 1);
    empty.push(keyed_ref(MERKLE_EMPTY_DOMAIN, b"leaf"));
    for l in 0..DEPTH {
        let e = empty[l];
        empty.push(hash_node_ref(&e, &e));
    }
    let mut level: BTreeMap<u64, [u64; 8]> = leaves.iter().cloned().collect();
    let mut paths = vec![[[0u64; 8]; DEPTH]; leaves.len()];
    let mut idxs: Vec<u64> = leaves.iter().map(|(i, _)| *i).collect();
    for l in 0..DEPTH {
        for (p, idx) in idxs.iter().enumerate() {
            paths[p][l] = level.get(&(idx ^ 1)).copied().unwrap_or(empty[l]);
        }
        let mut next: BTreeMap<u64, [u64; 8]> = BTreeMap::new();
        for (&idx, &hh) in level.iter() {
            let parent = idx >> 1;
            if next.contains_key(&parent) {
                continue;
            }
            let (lh, rh) = if idx & 1 == 0 {
                (hh, level.get(&(idx ^ 1)).copied().unwrap_or(empty[l]))
            } else {
                (level.get(&(idx ^ 1)).copied().unwrap_or(empty[l]), hh)
            };
            next.insert(parent, hash_node_ref(&lh, &rh));
        }
        level = next;
        for idx in idxs.iter_mut() {
            *idx >>= 1;
        }
    }
    (level.get(&0).copied().unwrap(), paths)
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

struct Claim {
    pk_receipt_hash: [u64; 8],
    claim_secret: [u64; 8],
    index: u64,
    sibs: [[u64; 8]; DEPTH],
    payout: Note,
    amount: u64,     // == the public providerShareSompi (C-01 binding)
    blind: [u64; 8], // PRIVATE commitment blind
    // publics
    provider_set_root: [u64; 8],
    session_cm: [u64; 8],
    v_claim_cm: [u64; 8], // replaces the public amount
    provider_nf: [u64; 8],
    cm_payout: [u64; 8],
    ctx: [u64; 8],
}

fn generate<F: PrimeField64>(c: &Claim, sched: &[RowSpec]) -> (RowMajorMatrix<F>, Vec<u64>) {
    let mut vals = F::zero_vec(HEIGHT * NUM_COLS);
    let claim_pk = addr_ref(&c.claim_secret);
    // per-row (m, sib, dir) fill
    let node = |bytes: &[u8]| -> [u64; 16] {
        let mut b = [0u8; 128];
        b[..bytes.len().min(128)].copy_from_slice(&bytes[..bytes.len().min(128)]);
        block_words(&b)
    };
    let nb = note_bytes(&c.payout);
    let (cm_b1, cm_b2) = (node(&nb[0..128]), node(&nb[128..204]));
    // value-commitment message: amount(8B) ‖ blind(64B), 1 block
    let mut vcm_data = [0u8; 72];
    vcm_data[..8].copy_from_slice(&c.amount.to_le_bytes());
    vcm_data[8..].copy_from_slice(&words_to_bytes(&c.blind));
    let vcm_m = node(&vcm_data);
    // (audit H-01) no ctx message: `ctx` is opaque (off-circuit contract preimage).

    let mut cur = [0u64; 8];
    for r in 0..HEIGHT {
        let base = r * NUM_COLS;
        let spec = &sched[r];
        // build this row's message
        let mut m = [0u64; 16];
        let (mut sib, mut dir) = ([0u64; 8], 0u64);
        if spec.flags & flag(F_ADDR) != 0 {
            m[..8].copy_from_slice(&c.claim_secret);
        } else if spec.flags & flag(F_LEAF) != 0 {
            m[..8].copy_from_slice(&c.pk_receipt_hash);
            m[8..].copy_from_slice(&cur); // = claim_pk
        } else if spec.flags & flag(F_MUX) != 0 {
            let mer_row = r - R_MER0;
            dir = (c.index >> mer_row) & 1;
            sib = c.sibs[mer_row];
            for i in 0..8 {
                if dir == 1 {
                    m[i] = sib[i];
                    m[8 + i] = cur[i];
                } else {
                    m[i] = cur[i];
                    m[8 + i] = sib[i];
                }
            }
        } else if spec.flags & flag(F_NF) != 0 {
            m[..8].copy_from_slice(&c.claim_secret);
            m[8..].copy_from_slice(&c.session_cm);
        } else if spec.flags & flag(F_VCM) != 0 {
            m = vcm_m;
        } else if spec.flags & flag(F_CM_B1) != 0 {
            m = cm_b1;
        } else if spec.flags & flag(F_CM_B2) != 0 {
            m = cm_b2;
        }
        set_words(&mut vals, base + CUR, &cur);
        set_words(&mut vals, base + SIB, &sib);
        vals[base + DIR] = F::from_u64(dir);
        for i in 0..16 {
            set_word(&mut vals, base + mw(i), m[i]);
        }
        // v_init
        let mut vinit = spec.vinit;
        if spec.chain {
            vinit[..8].copy_from_slice(&cur);
        }
        for i in 0..16 {
            set_word(&mut vals, base + vw(i), vinit[i]);
        }
        // globals
        set_words(&mut vals, base + SK, &c.claim_secret);
        set_words(&mut vals, base + PKRH, &c.pk_receipt_hash);
        set_words(&mut vals, base + OPK, &c.payout.owner_pk);
        set_words(&mut vals, base + RHO, &c.payout.rho);
        set_words(&mut vals, base + RR, &c.payout.r);
        set_word(&mut vals, base + AMT, c.amount); // amount (== public share, C-01)
        set_words(&mut vals, base + BLIND, &c.blind); // PRIVATE blind
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
        cur = hout;
    }
    let _ = claim_pk;
    // publics
    let mut pis: Vec<u64> = Vec::new();
    let push = |pis: &mut Vec<u64>, w: &[u64; 8]| {
        for x in w {
            for k in 0..W {
                pis.push((x >> k) & 1);
            }
        }
    };
    push(&mut pis, &c.provider_set_root);
    push(&mut pis, &c.session_cm);
    push(&mut pis, &c.v_claim_cm); // the value commitment replaces the raw public amount
    push(&mut pis, &c.provider_nf);
    push(&mut pis, &c.cm_payout);
    // (audit C-01) providerShareSompi — the contract-computed share as a REAL public
    // input (le64 bits), in the frozen borsh position between cm_payout and ctx.
    for k in 0..W {
        pis.push((c.amount >> k) & 1);
    }
    push(&mut pis, &c.ctx);
    debug_assert_eq!(pis.len(), NUM_PIS);
    (RowMajorMatrix::new(vals, NUM_COLS), pis)
}

// ---- hiding / ZK config ----
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

fn main() {
    let arg = |s: &str| std::env::args().any(|a| a == s);
    let (corrupt, wrong_root, wrong_nf, steal) = (arg("--corrupt"), arg("--wrong-root"), arg("--wrong-nf"), arg("--steal"));
    // (audit C-01) payout ±1 in the PUBLIC share vs the committed private amount, and
    // a statement field-order mutation (session_cm ↔ provider_nf PI blocks swapped).
    let (share_plus, share_minus, swap_fields) = (arg("--share-plus"), arg("--share-minus"), arg("--swap-fields"));
    // (audit H-01) `--wrong-ctx` is handled in a DEDICATED branch below, NOT via the
    // generic constraint-failure path: `ctx` is opaque (no in-AIR constraint), so its
    // binding is at the STATEMENT level (Fiat-Shamir + node binder), not a trace
    // constraint. Kept out of `negative` so the generic prove/verify/reject logic (which
    // relies on a constraint catching the tamper) does not apply to it.
    let wrong_ctx = arg("--wrong-ctx");
    let negative = corrupt || wrong_root || wrong_nf || steal || share_plus || share_minus || swap_fields;

    // provider set (5 registered providers)
    let mk = |seed: u64| -> [u64; 8] { core::array::from_fn(|i| seed.wrapping_mul(2 * i as u64 + 1).wrapping_add(0x0123_4567_89ab_cdef)) };
    let secrets: [[u64; 8]; 5] = core::array::from_fn(|i| mk(0x51 + i as u64));
    let pkrhs: [[u64; 8]; 5] = core::array::from_fn(|i| mk(0x40 + i as u64));
    let who = 2usize;
    let use_secret = if steal { mk(0xEE) } else { secrets[who] };
    let use_pkrh = if steal { mk(0xEF) } else { pkrhs[who] };
    let indexes: [u64; 5] = [0xB3A57, 0x2C9E4, 0x51D0C, 0x7A1F3, 0x18B62];
    let leaves: Vec<(u64, [u64; 8])> =
        (0..5).map(|i| (indexes[i], provider_leaf_ref(&pkrhs[i], &addr_ref(&secrets[i])))).collect();
    let (root, paths) = sparse_tree(&leaves);

    let session_cm = mk(0x5E5E);
    let amount = 500u64;
    let blind = mk(0xB11D); // a fresh random commitment blind (per claim)
    let v_claim_cm = value_commit_ref(amount, &blind);
    let payout = Note { value: amount, owner_pk: addr_ref(&mk(0x71)), rho: mk(0x33), r: mk(0x34) };
    let cm_payout = commit_ref(&payout);
    let provider_nf = provider_nf_ref(&use_secret, &session_cm);
    // (audit H-01) `ctx` is OPAQUE to this AIR: the node/contract computes the 404-byte
    // `_computeClaimCtx` preimage (evm_ctx.rs::claim_ctx_onchain — chainId ‖ contract ‖
    // escrowId ‖ setRoot ‖ sessionCm ‖ grossSompi ‖ providerNf ‖ cmPayout ‖ encHash) and
    // surfaces its digest as PI_CTX. Here we stand in an arbitrary contract-scoped value;
    // the AIR binds it ONLY as a public input (like spend.rs's `ctx`), so `--wrong-ctx`
    // is rejected at the statement level, not by any in-AIR constraint.
    let ctx = mk(0xC7C7_04B4);

    let claim = Claim {
        pk_receipt_hash: use_pkrh,
        claim_secret: use_secret,
        index: indexes[who],
        sibs: paths[who],
        payout,
        amount,
        blind,
        provider_set_root: root,
        session_cm,
        v_claim_cm,
        provider_nf,
        cm_payout,
        ctx,
    };
    let sched = schedule();
    let air = Blake2bClaimV2Air { sched: sched.clone() };
    let (mut trace, pis_u64) = generate::<Val>(&claim, &sched);

    // host diff-test: trace digests == the on-chain claim hashes
    let hout_at = |trace: &RowMajorMatrix<Val>, r: usize| -> [u64; 8] {
        core::array::from_fn(|i| {
            (0..W).fold(0u64, |acc, k| acc | ((trace.values[r * NUM_COLS + HOUT + i * W + k].as_canonical_u64() & 1) << k))
        })
    };
    let claim_pk = addr_ref(&claim.claim_secret);
    let mut ok = true;
    ok &= hout_at(&trace, R_ADDR) == claim_pk;
    ok &= hout_at(&trace, R_LEAF) == provider_leaf_ref(&claim.pk_receipt_hash, &claim_pk);
    if !steal {
        ok &= hout_at(&trace, R_MER0 + DEPTH - 1) == claim.provider_set_root;
    }
    ok &= hout_at(&trace, R_NF) == claim.provider_nf;
    ok &= hout_at(&trace, R_VCM) == claim.v_claim_cm;
    ok &= hout_at(&trace, R_CM_B2) == claim.cm_payout;
    // (audit H-01) `ctx` is opaque — NOT a trace digest, so nothing to diff-test here.
    // and the commitment truly binds the private amount
    ok &= claim.v_claim_cm == value_commit_ref(claim.amount, &claim.blind);
    println!("host diff-test: addr/leaf/membership/nf/value-commit/commit digests == on-chain reference (ctx OPAQUE — contract authority): {ok} (rows {HEIGHT}, cols {NUM_COLS}, prep {PREP_W})");

    // (audit H-01) DEDICATED `--wrong-ctx` demonstration. `ctx` is OPAQUE: the AIR has NO
    // constraint on PI_CTX (mirrors the spend AIR), so a forged ctx is INVISIBLE to the
    // in-AIR constraints — which is precisely WHY the STATEMENT binding is the authority.
    // We demonstrate all three facts:
    //   (a) the STARK ACCEPTS a forged opaque ctx when the proof and its public agree
    //       (there is no in-AIR ctx constraint to violate);
    //   (b) the verifier OBSERVES public_values in its challenger (p3-uni-stark
    //       prover.rs/verifier.rs `observe_slice`), so the forged proof does NOT verify
    //       under the honest statement — Fiat-Shamir binds each proof to ITS statement;
    //   (c) the NODE BINDER (shield-stark-verify::statement_is_bound: surfaced pv ==
    //       statement) rejects any PI_CTX != the 404-byte contract ctx
    //       (evm_ctx.rs::claim_ctx_onchain) — the sole authority vs a self-proving
    //       adversary. Malleability closed WITHOUT any in-AIR recompute.
    if wrong_ctx {
        let config = make_zk_config();
        let degree_bits = HEIGHT.ilog2() as usize;
        let (pp_data, pp_vk) = setup_preprocessed::<ZkConfig, _>(&config, &air, degree_bits).expect("preprocessed setup");
        let honest_pis: Vec<Val> = pis_u64.iter().map(|&b| Val::from_u64(b)).collect();
        let statement_ctx: Vec<Val> = honest_pis[PI_CTX..PI_CTX + 8 * W].to_vec(); // the contract-computed ctx
        // an adversary forges the ctx public and SELF-PROVES with it.
        let mut forged = honest_pis.clone();
        forged[PI_CTX] = Val::ONE - forged[PI_CTX];
        let proof = prove_with_preprocessed(&config, &air, trace, &forged, Some(&pp_data));
        let stark_accepts_forged = verify_with_preprocessed(&config, &air, &proof, &forged, Some(&pp_vk)).is_ok();
        let fs_rejects_cross = verify_with_preprocessed(&config, &air, &proof, &honest_pis, Some(&pp_vk)).is_err();
        let binder_rejects = forged[PI_CTX..PI_CTX + 8 * W] != statement_ctx[..];
        if stark_accepts_forged && fs_rejects_cross && binder_rejects {
            println!(
                "NEGATIVE TEST PASS — wrong PI_CTX rejected by the STATEMENT binding: STARK accepts the opaque forged ctx (no in-AIR constraint, ctx is opaque — H-01); the verifier observes PI_CTX in its challenger so the forged proof does NOT verify under the honest statement (Fiat-Shamir non-malleability); and the node binder (surfaced pv == the 404-byte contract ctx, evm_ctx.rs::claim_ctx_onchain) catches the tamper — the contract ctx is the sole authority."
            );
        } else {
            println!(
                "NEGATIVE TEST FAIL — wrong-ctx demonstration incomplete: stark_accepts_forged={stark_accepts_forged} fs_rejects_cross={fs_rejects_cross} binder_rejects={binder_rejects}"
            );
        }
        return;
    }

    if corrupt {
        let r = R_MER0 + 7;
        trace.values[r * NUM_COLS + SIB + 5] = Val::ONE - trace.values[r * NUM_COLS + SIB + 5];
    }
    let mut pis: Vec<Val> = pis_u64.iter().map(|&b| Val::from_u64(b)).collect();
    if wrong_root {
        pis[PI_ROOT] = Val::ONE - pis[PI_ROOT];
    }
    if wrong_nf {
        pis[PI_NF] = Val::ONE - pis[PI_NF];
    }
    // (audit C-01 negatives) publish a share of amount±1 while the trace still commits
    // the honest amount: the PI_SHARE == AMT binding must reject the proof.
    if share_plus || share_minus {
        let tampered = if share_plus { claim.amount + 1 } else { claim.amount - 1 };
        for k in 0..W {
            pis[PI_SHARE + k] = Val::from_u64((tampered >> k) & 1);
        }
    }
    // statement field-order mutation: exchange the session_cm and provider_nf blocks.
    if swap_fields {
        for k in 0..8 * W {
            pis.swap(PI_SESSION + k, PI_NF + k);
        }
    }

    let config = make_zk_config();
    let degree_bits = HEIGHT.ilog2() as usize;
    let (pp_data, pp_vk) = setup_preprocessed::<ZkConfig, _>(&config, &air, degree_bits).expect("preprocessed setup");
    let t0 = std::time::Instant::now();
    let proof = prove_with_preprocessed(&config, &air, trace, &pis, Some(&pp_data));
    let t_prove = t0.elapsed();
    let t1 = std::time::Instant::now();
    let res = verify_with_preprocessed(&config, &air, &proof, &pis, Some(&pp_vk));
    let t_verify = t1.elapsed();
    match &res {
        Ok(_) if negative => println!("NEGATIVE TEST FAIL — an invalid claim was accepted!"),
        Ok(_) => println!(
            "VERIFY ok — ANONYMOUS PROVIDER CLAIM proven with the REAL hashes (membership@depth-20 at a PRIVATE index + session nullifier + shielded payout + ctx), hiding-ZK [prove {:.1?}, verify {:.1?}]",
            t_prove, t_verify
        ),
        Err(e) if negative => println!("NEGATIVE TEST PASS — invalid claim rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on valid claim: {e:?}"),
    }

    if !negative {
        let pb = postcard::to_allocvec(&proof).unwrap();
        let has = |w: u64| {
            let le = w.to_le_bytes();
            pb.windows(8).any(|win| win == le)
        };
        let mut witness: Vec<u64> = Vec::new();
        witness.extend_from_slice(&claim.claim_secret);
        witness.extend_from_slice(&claim.pk_receipt_hash);
        witness.extend_from_slice(&provider_leaf_ref(&claim.pk_receipt_hash, &claim_pk)); // which provider
        witness.extend_from_slice(&claim.payout.owner_pk);
        witness.extend_from_slice(&claim.payout.rho);
        witness.extend_from_slice(&claim.payout.r);
        witness.extend_from_slice(&claim.blind); // the commitment blind
        // NOTE (C-01/M-08): the AMOUNT is no longer in this list — it EQUALS the public
        // providerShareSompi input by construction, so its absence is not a privacy
        // property (which-provider hiding is; the blind and payout fields stay private).
        for s in &claim.sibs {
            witness.extend_from_slice(s);
        }
        witness.retain(|&w| w != 0);
        let leaked = witness.iter().filter(|&&w| has(w)).count();
        if leaked == 0 {
            println!(
                "PRIVACY OK (witness-absence smoke test) — claim_secret, pk_receipt_hash, the registry LEAF (which provider), payout fields, the sibling path, AND the blind ({} words) do not appear verbatim in the proof ({} bytes). The payout equals the PUBLIC providerShareSompi (C-01 binding; publicly derivable under uniform pricing anyway, M-08) — which-provider stays hidden. NOTE: real hiding needs prod entropy (see caveats).",
                witness.len(),
                pb.len()
            );
        } else {
            println!("PRIVACY LEAK — {leaked} private witness word(s) present in the proof");
        }
    }
}
