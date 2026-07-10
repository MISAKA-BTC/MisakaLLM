//! Blake2bSpendAir — build#4: the COMPLETE shielded-spend relation with the REAL
//! on-chain hashes. One Plonky3 statement proving `spend::verify_reference`
//! (mil/shield/src/spend.rs) semantics — the full 2-in/2-out JoinSplit:
//!
//!   per input i (gated by a PRIVATE enable bit e_i):
//!     membership : commit(note_i) is under the public anchor at a PRIVATE index
//!     authority  : note_i.owner_pk == shielded_address(sk_i)
//!     nullifier  : nf_old[i] == H_nf(sk_i ‖ rho_i)          (public)
//!     dummy rule : ¬e_i ⇒ note_i.value == 0
//!   per output j (always):
//!     faerie-gold: note'_j.rho == H_rho(nf_old[0] ‖ nf_old[1] ‖ j)
//!     commitment : cm_new[j] == commit(note'_j)             (public)
//!   value conservation (TRUE 66-bit integer equality, not mod 2^64):
//!     e_0·v_0 + e_1·v_1 + v_pub_in == v'_0 + v'_1 + v_pub_out
//!
//! Every hash is the real keyed BLAKE2b-512 (RFC 7693) with the on-chain domains —
//! commit (204 B, 2 data blocks), addr (64 B), nf (128 B), output-rho (129 B, 2
//! blocks), merkle node (128 B) — **one full 12-round compression per row** (the
//! build#1 gadget), 56 active rows + 8 chaining-padding rows = 64 rows.
//!
//! Row-type structure comes from PREPROCESSED columns (supported by uni-stark at this
//! HEAD: setup_preprocessed / prove_with_preprocessed / verify_with_preprocessed):
//! per row a 1024-bit v_init constant block VPREP (the domain's key-block chaining
//! value h_domain ‖ IV ‖ t ‖ last — all public constants), a PCHAIN flag (this row's
//! v_init h-part is the previous row's digest: multi-block absorption), and one-hot
//! row-type flags gating the message-source and output-binding constraints. The
//! universal transition `next.CUR == HOUT` threads the digest chain everywhere:
//! Merkle rows consume CUR in the message MUX, chained block-2 rows consume it in
//! v_init. Max constraint degree 3 (flag·enable·diff); hiding FRI log_blowup=2.
//!
//! PUBLIC: anchor, nf_old[2], cm_new[2], v_pub_in, v_pub_out, token_id, ctx (carried
//! for statement parity, unconstrained — the contract recomputes it, spend.rs:28).
//! PRIVATE: notes_in (value/owner_pk/rho/r), sk_in, enable_in, paths (siblings +
//! index bits), notes_out (value/owner_pk/r). Proven with hiding-ZK FRI + a
//! witness-absence gate. Supersedes the G-mix toy SpendAir previously at this path.
//!
//! Positive: default (2 real inputs) and --with-dummy (1 real + 1 dummy input).
//! Negative: --corrupt (sibling bit), --wrong-anchor, --wrong-nf, --steal (sk that
//! does not own the note), --bad-value (conservation off by one), --dummy-nonzero.
//!
//! BENCH-CONFIG CAVEATS (adversarial panel, 2026-07-10 — none are circuit-logic):
//! - `FriParameters::new_testing(_, 2)` is ~5-bit FRI soundness (2 queries): green
//!   proves the CIRCUIT LOGIC, not a binding proof. Production: ~100 queries /
//!   real grinding (`new_benchmark`-class parameters).
//! - The hiding salts + FRI randomization use `SmallRng::seed_from_u64(1)`:
//!   deterministic, so a re-running adversary can subtract them — NOT ZK as
//!   configured. Production: OS entropy per proof.
//! - Nullifier distinctness (same note in both input slots) is NOT a relation/
//!   circuit rule — the pool caller must apply nullifiers sequentially
//!   (check-then-insert each), see mil/shield/src/proof.rs. Matches Sprout.

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
const HEIGHT: usize = 64; // 56 active rows + 8 chaining padding
const NROUNDS: usize = 12;
const W: usize = 64;

const CM_DOMAIN: &[u8] = b"misaka-shield-v1/cm";
const NF_DOMAIN: &[u8] = b"misaka-shield-v1/nf";
const ADDR_DOMAIN: &[u8] = b"misaka-shield-v1/addr";
const RHO_DOMAIN: &[u8] = b"misaka-shield-v1/rho";
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
// per-row hash block (identical to build#3):
const CUR: usize = 0; // chaining digest entering this row (universal next.CUR == HOUT)
const SIB: usize = 8 * W; // merkle sibling (merkle rows)
const M: usize = 16 * W; // the 16-word message block
const VINIT: usize = 32 * W;
const FFTMP: usize = 48 * W;
const HOUT: usize = 56 * W;
const GBLK: usize = 64 * W;
const GSTRIDE: usize = 16 * W;
const DIR: usize = GBLK + NROUNDS * 8 * GSTRIDE; // merkle direction bit (private)
// globals, replicated on every row via transition equality:
const SK0: usize = DIR + 1;
const SK1: usize = SK0 + 8 * W;
const E0: usize = SK1 + 8 * W; // enable bit input 0 (private)
const E1: usize = E0 + 1;
const VAL0: usize = E1 + 1; // input note 0: value / owner_pk / rho / r
const OPK0: usize = VAL0 + W;
const RHO0: usize = OPK0 + 8 * W;
const R0: usize = RHO0 + 8 * W;
const VAL1: usize = R0 + 8 * W;
const OPK1: usize = VAL1 + W;
const RHO1: usize = OPK1 + 8 * W;
const R1: usize = RHO1 + 8 * W;
const OVAL0: usize = R1 + 8 * W; // output note 0: value / owner_pk / rho / r
const OOPK0: usize = OVAL0 + W;
const ORHO0: usize = OOPK0 + 8 * W;
const OR0: usize = ORHO0 + 8 * W;
const OVAL1: usize = OR0 + 8 * W;
const OOPK1: usize = OVAL1 + W;
const ORHO1: usize = OOPK1 + 8 * W;
const OR1: usize = ORHO1 + 8 * W;
const GLOBALS_START: usize = SK0;
const GLOBALS_END: usize = OR1 + 8 * W; // exclusive
// value-conservation locals (constrained on the F_CONS row; boolean everywhere):
const EVAL0: usize = GLOBALS_END; // e_i · value_i
const EVAL1: usize = EVAL0 + W;
const SI1: usize = EVAL1 + W; // EVAL0 + EVAL1
const CI1: usize = SI1 + W;
const SI2: usize = CI1 + W; // (SI1 ‖ carry) + v_pub_in — 65 bits
const CI2: usize = SI2 + 65;
const SO1: usize = CI2 + 65; // OVAL0 + OVAL1
const CO1: usize = SO1 + W;
const SO2: usize = CO1 + W; // (SO1 ‖ carry) + v_pub_out — 65 bits
const CO2: usize = SO2 + 65;
const NUM_COLS: usize = CO2 + 65;

// ---- public values (little-endian bits, statement order) ----
const PI_ANCHOR: usize = 0;
const PI_NF0: usize = 8 * W;
const PI_NF1: usize = 16 * W;
const PI_CM0: usize = 24 * W;
const PI_CM1: usize = 32 * W;
const PI_VPIN: usize = 40 * W;
const PI_VPOUT: usize = PI_VPIN + W;
const PI_TOKEN: usize = PI_VPOUT + W; // 32 bits
const PI_CTX: usize = PI_TOKEN + 32;
const NUM_PIS: usize = PI_CTX + 8 * W;

// ---- preprocessed columns ----
const PREP_VINIT: usize = 0; // 1024 bits: the constant part of v_init (h ‖ IV/t/last)
const PREP_CHAIN: usize = 1024; // 1 ⇒ v_init[0..512] comes from CUR (multi-block chaining)
const PREP_FLAG: usize = 1025; // one-hot row-type flags
const F_MUX: usize = 0; // merkle row: m = MUX(CUR, SIB, DIR)
const F_ADDR0: usize = 1;
const F_ADDR1: usize = 2;
const F_CI0B1: usize = 3; // commit(input note 0) block 1
const F_CI0B2: usize = 4;
const F_CI1B1: usize = 5;
const F_CI1B2: usize = 6;
const F_MEM0: usize = 7; // last merkle row of input 0: HOUT == anchor (·e0)
const F_MEM1: usize = 8;
const F_NF0: usize = 9;
const F_NF1: usize = 10;
const F_RHOB1: usize = 11; // output-rho block 1 (same message for both outputs)
const F_RHO0B2: usize = 12;
const F_RHO1B2: usize = 13;
const F_CO0B1: usize = 14; // commit(output note 0) block 1
const F_CO0B2: usize = 15;
const F_CO1B1: usize = 16;
const F_CO1B2: usize = 17;
const F_CONS: usize = 18; // the value-conservation row (row 0)
const NFLAGS: usize = 19;
const PREP_W: usize = PREP_FLAG + NFLAGS;

// G-block word indices (build#1)
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

/// One row of the fixed schedule: the constant v_init part, whether the h-part chains
/// from the previous digest, and this row's type flags.
#[derive(Clone, Copy)]
struct RowSpec {
    vinit: [u64; 16], // h-part zeroed when chain=true
    chain: bool,
    flags: u32,
}
fn flag(f: usize) -> u32 {
    1 << f
}

/// v_init constants for a fresh keyed-hash block: h_domain ‖ IV[0..4] ‖ IV[4]^t ‖
/// IV[5] ‖ IV[6]^last ‖ IV[7]. For chained (non-first) blocks pass h = None.
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

/// The fixed 64-row schedule. Row indices are the spec of the whole circuit.
const R_ADDR0: usize = 0;
const R_CI0B1: usize = 1;
const R_CI0B2: usize = 2;
const R_MER0: usize = 3; // ..= R_MER0+DEPTH-1 (row 22)
const R_NF0: usize = 23;
const R_ADDR1: usize = 24;
const R_CI1B1: usize = 25;
const R_CI1B2: usize = 26;
const R_MER1: usize = 27; // ..= row 46
const R_NF1: usize = 47;
const R_RHO0B1: usize = 48;
const R_RHO0B2: usize = 49;
const R_CO0B1: usize = 50;
const R_CO0B2: usize = 51;
const R_RHO1B1: usize = 52;
const R_RHO1B2: usize = 53;
const R_CO1B1: usize = 54;
const R_CO1B2: usize = 55;

fn schedule() -> Vec<RowSpec> {
    let h_cm = h_domain(CM_DOMAIN);
    let h_nf = h_domain(NF_DOMAIN);
    let h_addr = h_domain(ADDR_DOMAIN);
    let h_rho = h_domain(RHO_DOMAIN);
    let h_mer = h_domain(MERKLE_DOMAIN);
    // pad default: chained garbage compression (v_init h = previous digest)
    let mut s = vec![RowSpec { vinit: vc(None, 256, true), chain: true, flags: 0 }; HEIGHT];
    // data lengths (bytes): addr 64 → t=192 last; cm 204 → t 256 then 332 last;
    // nf 128 → t=256 last; rho' 129 → t 256 then 257 last; merkle node 128 → 256 last.
    s[R_ADDR0] = RowSpec { vinit: vc(Some(h_addr), 192, true), chain: false, flags: flag(F_ADDR0) | flag(F_CONS) };
    s[R_CI0B1] = RowSpec { vinit: vc(Some(h_cm), 256, false), chain: false, flags: flag(F_CI0B1) };
    s[R_CI0B2] = RowSpec { vinit: vc(None, 332, true), chain: true, flags: flag(F_CI0B2) };
    for r in R_MER0..R_MER0 + DEPTH {
        let mut f = flag(F_MUX);
        if r == R_MER0 + DEPTH - 1 {
            f |= flag(F_MEM0);
        }
        s[r] = RowSpec { vinit: vc(Some(h_mer), 256, true), chain: false, flags: f };
    }
    s[R_NF0] = RowSpec { vinit: vc(Some(h_nf), 256, true), chain: false, flags: flag(F_NF0) };
    s[R_ADDR1] = RowSpec { vinit: vc(Some(h_addr), 192, true), chain: false, flags: flag(F_ADDR1) };
    s[R_CI1B1] = RowSpec { vinit: vc(Some(h_cm), 256, false), chain: false, flags: flag(F_CI1B1) };
    s[R_CI1B2] = RowSpec { vinit: vc(None, 332, true), chain: true, flags: flag(F_CI1B2) };
    for r in R_MER1..R_MER1 + DEPTH {
        let mut f = flag(F_MUX);
        if r == R_MER1 + DEPTH - 1 {
            f |= flag(F_MEM1);
        }
        s[r] = RowSpec { vinit: vc(Some(h_mer), 256, true), chain: false, flags: f };
    }
    s[R_NF1] = RowSpec { vinit: vc(Some(h_nf), 256, true), chain: false, flags: flag(F_NF1) };
    s[R_RHO0B1] = RowSpec { vinit: vc(Some(h_rho), 256, false), chain: false, flags: flag(F_RHOB1) };
    s[R_RHO0B2] = RowSpec { vinit: vc(None, 257, true), chain: true, flags: flag(F_RHO0B2) };
    s[R_CO0B1] = RowSpec { vinit: vc(Some(h_cm), 256, false), chain: false, flags: flag(F_CO0B1) };
    s[R_CO0B2] = RowSpec { vinit: vc(None, 332, true), chain: true, flags: flag(F_CO0B2) };
    s[R_RHO1B1] = RowSpec { vinit: vc(Some(h_rho), 256, false), chain: false, flags: flag(F_RHOB1) };
    s[R_RHO1B2] = RowSpec { vinit: vc(None, 257, true), chain: true, flags: flag(F_RHO1B2) };
    s[R_CO1B1] = RowSpec { vinit: vc(Some(h_cm), 256, false), chain: false, flags: flag(F_CO1B1) };
    s[R_CO1B2] = RowSpec { vinit: vc(None, 332, true), chain: true, flags: flag(F_CO1B2) };
    s
}

struct Blake2bSpendAir {
    sched: Vec<RowSpec>,
}
impl<F: PrimeField64> BaseAir<F> for Blake2bSpendAir {
    fn width(&self) -> usize {
        NUM_COLS
    }
    fn num_public_values(&self) -> usize {
        NUM_PIS
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3) // flag(prep) · enable(var) · diff(var)
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
        // Only the CURRENT preprocessed row is read in eval(). INVARIANT: if any
        // constraint ever reads preprocessed().next_slice(), those column indices
        // MUST be returned here — the verifier substitutes ZEROS for unlisted next
        // columns (a silent prover/verifier divergence a cheater could exploit).
        vec![]
    }
}

/// flag-gated bitwise equality: fl · (row[dst..] − row[src..]) == 0
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
/// flag-gated ripple over explicit expr operands (used by conservation):
/// fl · (a_i + b_i + c_{i-1} − s_i − 2·c_i) == 0
fn gadd<AB2: AirBuilder>(b: &mut AB2, fl: &AB2::Expr, row: &[AB2::Var], a: &[AB2::Expr], bb: &[AB2::Expr], so: usize, co: usize) {
    let two = AB2::Expr::ONE + AB2::Expr::ONE;
    for i in 0..a.len() {
        let cin: AB2::Expr = if i == 0 { AB2::Expr::ZERO } else { row[co + i - 1].into() };
        let lhs = a[i].clone() + bb[i].clone() + cin;
        let rhs = Into::<AB2::Expr>::into(row[so + i]) + Into::<AB2::Expr>::into(row[co + i]) * two.clone();
        b.assert_zero(fl.clone() * (lhs - rhs));
    }
}

impl<AB2: AirBuilder> Air<AB2> for Blake2bSpendAir
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
        // ---- booleanity: every main column is a bit ----
        for i in 0..NUM_COLS {
            let x: AB2::Expr = row[i].into();
            builder.assert_zero(x.clone() * (x - one.clone()));
        }
        // ---- v_init: constant part from PREP, h-part optionally chained from CUR ----
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
        // ---- the build#1 compression (unconditional, every row) ----
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
        // ---- row-type flags ----
        let fl: Vec<AB2::Expr> = (0..NFLAGS).map(|f| prep[PREP_FLAG + f].into()).collect();
        let e0: AB2::Expr = row[E0].into();
        let e1: AB2::Expr = row[E1].into();
        // merkle MUX: m = dir ? sib‖cur : cur‖sib (which-note hiding), gated by F_MUX
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
        // addr rows: m = sk ‖ 0-pad(64 B); authority: e·(HOUT − owner_pk) == 0
        for (f, sk, opk, e) in [(F_ADDR0, SK0, OPK0, &e0), (F_ADDR1, SK1, OPK1, &e1)] {
            geq_cols(builder, &fl[f], row, M, sk, 8 * W);
            geq_const(builder, &fl[f], row, M + 8 * W, false, 8 * W);
            for k in 0..8 * W {
                let h: AB2::Expr = row[HOUT + k].into();
                let o: AB2::Expr = row[opk + k].into();
                builder.assert_zero(fl[f].clone() * e.clone() * (h - o));
            }
        }
        // commit block 1: m = value(8B) ‖ owner_pk(64B) ‖ rho[0..56B]
        for (f, val, opk, rho) in [
            (F_CI0B1, VAL0, OPK0, RHO0),
            (F_CI1B1, VAL1, OPK1, RHO1),
            (F_CO0B1, OVAL0, OOPK0, ORHO0),
            (F_CO1B1, OVAL1, OOPK1, ORHO1),
        ] {
            geq_cols(builder, &fl[f], row, M, val, W);
            geq_cols(builder, &fl[f], row, M + W, opk, 8 * W);
            geq_cols(builder, &fl[f], row, M + 9 * W, rho, 7 * W);
        }
        // commit block 2: m = rho[56..64B] ‖ r(64B) ‖ token_id(4B, public) ‖ 0-pad(52B)
        for (f, rho, rr) in [(F_CI0B2, RHO0, R0), (F_CI1B2, RHO1, R1), (F_CO0B2, ORHO0, OR0), (F_CO1B2, ORHO1, OR1)] {
            geq_cols(builder, &fl[f], row, M, rho + 7 * W, W);
            geq_cols(builder, &fl[f], row, M + W, rr, 8 * W);
            geq_pis(builder, &fl[f], row, M + 9 * W, &pis, PI_TOKEN, 32);
            geq_const(builder, &fl[f], row, M + 9 * W + 32, false, 7 * W - 32);
        }
        // nf rows: m = sk(64B) ‖ rho(64B); binding: e·(HOUT − nf_pi) == 0
        for (f, sk, rho, e, pinf) in [(F_NF0, SK0, RHO0, &e0, PI_NF0), (F_NF1, SK1, RHO1, &e1, PI_NF1)] {
            geq_cols(builder, &fl[f], row, M, sk, 8 * W);
            geq_cols(builder, &fl[f], row, M + 8 * W, rho, 8 * W);
            for k in 0..8 * W {
                let h: AB2::Expr = row[HOUT + k].into();
                builder.assert_zero(fl[f].clone() * e.clone() * (h - pis[pinf + k].clone()));
            }
        }
        // membership binding: e·(HOUT − anchor) == 0 at the last merkle row per input
        for (f, e) in [(F_MEM0, &e0), (F_MEM1, &e1)] {
            for k in 0..8 * W {
                let h: AB2::Expr = row[HOUT + k].into();
                builder.assert_zero(fl[f].clone() * e.clone() * (h - pis[PI_ANCHOR + k].clone()));
            }
        }
        // output-rho block 1: m = nf_old[0] ‖ nf_old[1] (both public)
        geq_pis(builder, &fl[F_RHOB1], row, M, &pis, PI_NF0, 8 * W);
        geq_pis(builder, &fl[F_RHOB1], row, M + 8 * W, &pis, PI_NF1, 8 * W);
        // output-rho block 2: m = j-byte ‖ 0-pad; binding: HOUT == ORHO_j
        for (f, orho, jbit) in [(F_RHO0B2, ORHO0, false), (F_RHO1B2, ORHO1, true)] {
            geq_const(builder, &fl[f], row, M, jbit, 1);
            geq_const(builder, &fl[f], row, M + 1, false, 16 * W - 1);
            geq_cols(builder, &fl[f], row, HOUT, orho, 8 * W);
        }
        // output commitment binding: HOUT == cm_new[j] (public) at the last cm block
        geq_pis(builder, &fl[F_CO0B2], row, HOUT, &pis, PI_CM0, 8 * W);
        geq_pis(builder, &fl[F_CO1B2], row, HOUT, &pis, PI_CM1, 8 * W);
        // ---- dummy rule + effective values (every row; globals are replicated) ----
        for (e, val, ev) in [(&e0, VAL0, EVAL0), (&e1, VAL1, EVAL1)] {
            for k in 0..W {
                let v: AB2::Expr = row[val + k].into();
                let x: AB2::Expr = row[ev + k].into();
                builder.assert_zero((one.clone() - e.clone()) * v.clone()); // ¬e ⇒ value = 0
                builder.assert_zero(x - e.clone() * v); // EVAL = e·value
            }
        }
        // ---- value conservation (66-bit exact) on the F_CONS row ----
        {
            let f = &fl[F_CONS];
            let eb: Vec<AB2::Expr> = (0..W).map(|k| row[EVAL0 + k].into()).collect();
            let fb: Vec<AB2::Expr> = (0..W).map(|k| row[EVAL1 + k].into()).collect();
            gadd(builder, f, row, &eb, &fb, SI1, CI1);
            let mut a: Vec<AB2::Expr> = (0..W).map(|k| row[SI1 + k].into()).collect();
            a.push(row[CI1 + W - 1].into());
            let mut b: Vec<AB2::Expr> = (0..W).map(|k| pis[PI_VPIN + k].clone()).collect();
            b.push(AB2::Expr::ZERO);
            gadd(builder, f, row, &a, &b, SI2, CI2);
            let ob: Vec<AB2::Expr> = (0..W).map(|k| row[OVAL0 + k].into()).collect();
            let pb: Vec<AB2::Expr> = (0..W).map(|k| row[OVAL1 + k].into()).collect();
            gadd(builder, f, row, &ob, &pb, SO1, CO1);
            let mut ao: Vec<AB2::Expr> = (0..W).map(|k| row[SO1 + k].into()).collect();
            ao.push(row[CO1 + W - 1].into());
            let mut bo: Vec<AB2::Expr> = (0..W).map(|k| pis[PI_VPOUT + k].clone()).collect();
            bo.push(AB2::Expr::ZERO);
            gadd(builder, f, row, &ao, &bo, SO2, CO2);
            for k in 0..65 {
                let l: AB2::Expr = row[SI2 + k].into();
                let r: AB2::Expr = row[SO2 + k].into();
                builder.assert_zero(f.clone() * (l - r));
            }
            let ci: AB2::Expr = row[CI2 + 64].into();
            let co: AB2::Expr = row[CO2 + 64].into();
            builder.assert_zero(f.clone() * (ci - co));
        }
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
    }
}

// ---- reference keyed BLAKE2b-512 (word-level; the trace-generator logic in
// mil/blake2b-air is diff-tested byte-for-byte vs kaspa_hashes) ----
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
/// chaining value after the keyed hash's key block for a domain — a PUBLIC constant.
fn h_domain(domain: &[u8]) -> [u64; 8] {
    let kk = domain.len() as u64;
    let mut h = IV;
    h[0] ^= 0x0101_0000 ^ (kk << 8) ^ 64;
    let mut kb = [0u8; 128];
    kb[..domain.len()].copy_from_slice(domain);
    compress_ref(&h, &block_words(&kb), 128, false)
}
/// full keyed BLAKE2b-512 (key block + data blocks) → 8 words.
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

// ---- the reference relation (mirrors mil/shield exactly, word-level) ----
#[derive(Clone, Copy)]
struct Note {
    value: u64,
    owner_pk: [u64; 8],
    rho: [u64; 8],
    r: [u64; 8],
}
const TOKEN_ID: u32 = 0; // MSK
fn note_bytes(n: &Note) -> [u8; 204] {
    let mut b = [0u8; 204];
    b[0..8].copy_from_slice(&n.value.to_le_bytes());
    b[8..72].copy_from_slice(&words_to_bytes(&n.owner_pk));
    b[72..136].copy_from_slice(&words_to_bytes(&n.rho));
    b[136..200].copy_from_slice(&words_to_bytes(&n.r));
    b[200..204].copy_from_slice(&TOKEN_ID.to_le_bytes());
    b
}
fn commit_ref(n: &Note) -> [u64; 8] {
    keyed_ref(CM_DOMAIN, &note_bytes(n))
}
fn addr_ref(sk: &[u64; 8]) -> [u64; 8] {
    keyed_ref(ADDR_DOMAIN, &words_to_bytes(sk))
}
fn nf_ref(sk: &[u64; 8], rho: &[u64; 8]) -> [u64; 8] {
    let mut d = [0u8; 128];
    d[..64].copy_from_slice(&words_to_bytes(sk));
    d[64..].copy_from_slice(&words_to_bytes(rho));
    keyed_ref(NF_DOMAIN, &d)
}
fn derive_rho_ref(nf0: &[u64; 8], nf1: &[u64; 8], j: u8) -> [u64; 8] {
    let mut d = [0u8; 129];
    d[..64].copy_from_slice(&words_to_bytes(nf0));
    d[64..128].copy_from_slice(&words_to_bytes(nf1));
    d[128] = j;
    keyed_ref(RHO_DOMAIN, &d)
}
fn hash_node_ref(l: &[u64; 8], r: &[u64; 8]) -> [u64; 8] {
    let mut d = [0u8; 128];
    d[..64].copy_from_slice(&words_to_bytes(l));
    d[64..].copy_from_slice(&words_to_bytes(r));
    keyed_ref(MERKLE_DOMAIN, &d)
}

/// sparse depth-20 tree: leaves at given indices, empty-subtree elsewhere.
/// Returns (anchor, per-leaf sibling paths).
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
            let sib = level.get(&(idx ^ 1)).copied().unwrap_or(empty[l]);
            paths[p][l] = sib;
        }
        let mut next: BTreeMap<u64, [u64; 8]> = BTreeMap::new();
        for (&idx, &h) in level.iter() {
            let parent = idx >> 1;
            if next.contains_key(&parent) {
                continue;
            }
            let (lh, rh) = if idx & 1 == 0 {
                (h, level.get(&(idx ^ 1)).copied().unwrap_or(empty[l]))
            } else {
                (level.get(&(idx ^ 1)).copied().unwrap_or(empty[l]), h)
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

// ---- witness / statement ----
struct Input {
    note: Note,
    sk: [u64; 8],
    enable: bool,
    index: u64,
    sibs: [[u64; 8]; DEPTH],
    nf_pub: [u64; 8], // = nf_ref(sk, rho) when enabled; arbitrary for dummies
}
struct Spend {
    ins: [Input; 2],
    outs: [Note; 2], // rho fields overwritten by derive_rho_ref
    anchor: [u64; 8],
    v_pub_in: u64,
    v_pub_out: u64,
    ctx: [u64; 8],
}

fn carries_vec(a: &[u8], b: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let n = a.len();
    let mut s = vec![0u8; n];
    let mut c = vec![0u8; n];
    let mut cin = 0u8;
    for i in 0..n {
        let t = a[i] + b[i] + cin;
        s[i] = t & 1;
        c[i] = t >> 1;
        cin = c[i];
    }
    (s, c)
}
fn u64_bits(w: u64) -> Vec<u8> {
    (0..64).map(|k| ((w >> k) & 1) as u8).collect()
}

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

/// per-row message blocks + merkle wiring for the whole schedule.
struct RowFill {
    m: [u64; 16],
    sib: [u64; 8],
    dir: u64,
}

fn generate<F: PrimeField64>(sp: &Spend, sched: &[RowSpec]) -> (RowMajorMatrix<F>, Vec<u64>) {
    // resolve output rhos + public values first
    let mut outs = sp.outs;
    outs[0].rho = derive_rho_ref(&sp.ins[0].nf_pub, &sp.ins[1].nf_pub, 0);
    outs[1].rho = derive_rho_ref(&sp.ins[0].nf_pub, &sp.ins[1].nf_pub, 1);
    let cm_new = [commit_ref(&outs[0]), commit_ref(&outs[1])];

    // per-row fills
    let mut fills: Vec<RowFill> = (0..HEIGHT).map(|_| RowFill { m: [0u64; 16], sib: [0u64; 8], dir: 0 }).collect();
    let blocks204 = |n: &Note| -> ([u64; 16], [u64; 16]) {
        let nb = note_bytes(n);
        let mut b1 = [0u8; 128];
        b1.copy_from_slice(&nb[0..128]);
        let mut b2 = [0u8; 128];
        b2[..76].copy_from_slice(&nb[128..204]);
        (block_words(&b1), block_words(&b2))
    };
    for (i, base) in [(0usize, R_ADDR0), (1, R_ADDR1)] {
        let inp = &sp.ins[i];
        // addr row: m = sk ‖ 0
        fills[base].m[..8].copy_from_slice(&inp.sk);
        // commit rows
        let (cb1, cb2) = blocks204(&inp.note);
        fills[base + 1].m = cb1;
        fills[base + 2].m = cb2;
        // merkle rows
        for l in 0..DEPTH {
            fills[base + 3 + l].sib = inp.sibs[l];
            fills[base + 3 + l].dir = (inp.index >> l) & 1;
        }
        // nf row: m = sk ‖ rho
        fills[base + 3 + DEPTH].m[..8].copy_from_slice(&inp.sk);
        fills[base + 3 + DEPTH].m[8..].copy_from_slice(&inp.note.rho);
    }
    for (j, base) in [(0usize, R_RHO0B1), (1, R_RHO1B1)] {
        fills[base].m[..8].copy_from_slice(&sp.ins[0].nf_pub);
        fills[base].m[8..].copy_from_slice(&sp.ins[1].nf_pub);
        fills[base + 1].m[0] = j as u64; // the j byte, rest zero
        let (ob1, ob2) = blocks204(&outs[j]);
        fills[base + 2].m = ob1;
        fills[base + 3].m = ob2;
    }

    // conservation bits
    let ev0 = if sp.ins[0].enable { sp.ins[0].note.value } else { 0 };
    let ev1 = if sp.ins[1].enable { sp.ins[1].note.value } else { 0 };
    let (si1, ci1) = carries_vec(&u64_bits(ev0), &u64_bits(ev1));
    let mut a = si1.clone();
    a.push(ci1[63]);
    let mut b = u64_bits(sp.v_pub_in);
    b.push(0);
    let (si2, ci2) = carries_vec(&a, &b);
    let (so1, co1) = carries_vec(&u64_bits(outs[0].value), &u64_bits(outs[1].value));
    let mut ao = so1.clone();
    ao.push(co1[63]);
    let mut bo = u64_bits(sp.v_pub_out);
    bo.push(0);
    let (so2, co2) = carries_vec(&ao, &bo);

    // fill the trace
    let mut vals = F::zero_vec(HEIGHT * NUM_COLS);
    let mut cur = [0u64; 8]; // row 0's CUR is free
    for r in 0..HEIGHT {
        let base = r * NUM_COLS;
        let spec = &sched[r];
        let f = &fills[r];
        // merkle rows build m from (cur, sib, dir)
        let mut m = f.m;
        if spec.flags & flag(F_MUX) != 0 {
            for i in 0..8 {
                if f.dir == 1 {
                    m[i] = f.sib[i];
                    m[8 + i] = cur[i];
                } else {
                    m[i] = cur[i];
                    m[8 + i] = f.sib[i];
                }
            }
        }
        set_words(&mut vals, base + CUR, &cur);
        set_words(&mut vals, base + SIB, &f.sib);
        vals[base + DIR] = F::from_u64(f.dir);
        for i in 0..16 {
            set_word(&mut vals, base + mw(i), m[i]);
        }
        // v_init: constants + optional chain
        let mut vinit = spec.vinit;
        if spec.chain {
            vinit[..8].copy_from_slice(&cur);
        }
        for i in 0..16 {
            set_word(&mut vals, base + vw(i), vinit[i]);
        }
        // globals (identical on every row)
        set_words(&mut vals, base + SK0, &sp.ins[0].sk);
        set_words(&mut vals, base + SK1, &sp.ins[1].sk);
        vals[base + E0] = F::from_u64(sp.ins[0].enable as u64);
        vals[base + E1] = F::from_u64(sp.ins[1].enable as u64);
        for (val, opk, rho, rr, n) in [(VAL0, OPK0, RHO0, R0, &sp.ins[0].note), (VAL1, OPK1, RHO1, R1, &sp.ins[1].note)] {
            set_word(&mut vals, base + val, n.value);
            set_words(&mut vals, base + opk, &n.owner_pk);
            set_words(&mut vals, base + rho, &n.rho);
            set_words(&mut vals, base + rr, &n.r);
        }
        for (val, opk, rho, rr, n) in [(OVAL0, OOPK0, ORHO0, OR0, &outs[0]), (OVAL1, OOPK1, ORHO1, OR1, &outs[1])] {
            set_word(&mut vals, base + val, n.value);
            set_words(&mut vals, base + opk, &n.owner_pk);
            set_words(&mut vals, base + rho, &n.rho);
            set_words(&mut vals, base + rr, &n.r);
        }
        // conservation locals (same on every row; constrained on the F_CONS row)
        set_word(&mut vals, base + EVAL0, ev0);
        set_word(&mut vals, base + EVAL1, ev1);
        for (off, bits) in [(SI1, &si1), (CI1, &ci1), (SO1, &so1), (CO1, &co1)] {
            for (k, bit) in bits.iter().enumerate() {
                vals[base + off + k] = F::from_u64(*bit as u64);
            }
        }
        for (off, bits) in [(SI2, &si2), (CI2, &ci2), (SO2, &so2), (CO2, &co2)] {
            for (k, bit) in bits.iter().enumerate() {
                vals[base + off + k] = F::from_u64(*bit as u64);
            }
        }
        // run the compression
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

    // public values: anchor ‖ nf0 ‖ nf1 ‖ cm0 ‖ cm1 ‖ v_pub_in ‖ v_pub_out ‖ token ‖ ctx
    let mut pis: Vec<u64> = Vec::new();
    let push_words = |pis: &mut Vec<u64>, w: &[u64; 8]| {
        for x in w {
            for k in 0..W {
                pis.push((x >> k) & 1);
            }
        }
    };
    push_words(&mut pis, &sp.anchor);
    push_words(&mut pis, &sp.ins[0].nf_pub);
    push_words(&mut pis, &sp.ins[1].nf_pub);
    push_words(&mut pis, &cm_new[0]);
    push_words(&mut pis, &cm_new[1]);
    for k in 0..W {
        pis.push((sp.v_pub_in >> k) & 1);
    }
    for k in 0..W {
        pis.push((sp.v_pub_out >> k) & 1);
    }
    for k in 0..32 {
        pis.push(((TOKEN_ID as u64) >> k) & 1);
    }
    push_words(&mut pis, &sp.ctx);
    (RowMajorMatrix::new(vals, NUM_COLS), pis)
}

// ---- hiding / ZK config (verbatim from the harness) ----
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
    let with_dummy = arg("--with-dummy") || arg("--dummy-nonzero");
    let negative =
        arg("--corrupt") || arg("--wrong-anchor") || arg("--wrong-nf") || arg("--steal") || arg("--bad-value") || arg("--dummy-nonzero");

    // ---- build the witness (all PRIVATE: notes, sks, enables, paths, indexes) ----
    let sk0: [u64; 8] = core::array::from_fn(|i| 0x517c_c1b7_2722_0a95u64.wrapping_mul(i as u64 + 3));
    let sk1: [u64; 8] = core::array::from_fn(|i| 0x9e37_79b9_7f4a_7c15u64.wrapping_mul(i as u64 + 7));
    let mk = |seed: u64| -> [u64; 8] { core::array::from_fn(|i| seed.wrapping_mul(2 * i as u64 + 1).wrapping_add(0x0123_4567_89ab_cdef)) };
    let n0 = Note { value: 100, owner_pk: addr_ref(&sk0), rho: mk(0xaaaa_1111), r: mk(0xbbbb_2222) };
    let mut n1 = Note { value: 200, owner_pk: addr_ref(&sk1), rho: mk(0xcccc_3333), r: mk(0xdddd_4444) };
    if with_dummy {
        // dummy note: arbitrary fields, value MUST be 0 (tested by --dummy-nonzero)
        n1 = Note { value: if arg("--dummy-nonzero") { 5 } else { 0 }, owner_pk: mk(0x5555_6666), rho: mk(0xcccc_3333), r: mk(0xdddd_4444) };
    }
    let steal_sk: [u64; 8] = mk(0x6666_7777);
    let use_sk0 = if arg("--steal") { steal_sk } else { sk0 };
    // the tree: enabled leaves at private indexes
    let (i0, i1) = (0xB3A57u64, 0x2C9E4u64);
    let leaves: Vec<(u64, [u64; 8])> = if with_dummy {
        vec![(i0, commit_ref(&n0))]
    } else {
        vec![(i0, commit_ref(&n0)), (i1, commit_ref(&n1))]
    };
    let (anchor, paths) = sparse_tree(&leaves);
    let nf0 = nf_ref(&use_sk0, &n0.rho);
    let nf1 = if with_dummy { mk(0x7777_8888) } else { nf_ref(&sk1, &n1.rho) };
    let (v_pub_in, v_pub_out) = if with_dummy { (0u64, 10u64) } else { (25u64, 10u64) };
    let in_total = if with_dummy { n0.value } else { n0.value + n1.value };
    let out_total = in_total + v_pub_in - v_pub_out;
    let bad = arg("--bad-value") as u64;
    let outs = [
        Note { value: 60 + bad, owner_pk: mk(0x1212_3434), rho: [0u64; 8], r: mk(0x5656_7878) },
        Note { value: out_total - 60, owner_pk: mk(0x9a9a_bcbc), rho: [0u64; 8], r: mk(0xdede_f0f0) },
    ];
    let sp = Spend {
        ins: [
            Input { note: n0, sk: use_sk0, enable: true, index: i0, sibs: paths[0], nf_pub: nf0 },
            Input {
                note: n1,
                sk: sk1,
                enable: !with_dummy,
                index: if with_dummy { 0 } else { i1 },
                sibs: if with_dummy { [[0u64; 8]; DEPTH] } else { paths[1] },
                nf_pub: nf1,
            },
        ],
        outs,
        anchor,
        v_pub_in,
        v_pub_out,
        ctx: mk(0xfefe_0101),
    };

    let sched = schedule();
    let air = Blake2bSpendAir { sched: sched.clone() };
    let (mut trace, pis_u64) = generate::<Val>(&sp, &sched);

    // ---- host diff-test: trace digests == full keyed reference (key blocks incl.) ----
    let hout_at = |trace: &RowMajorMatrix<Val>, r: usize| -> [u64; 8] {
        core::array::from_fn(|i| {
            (0..W).fold(0u64, |acc, k| acc | ((trace.values[r * NUM_COLS + HOUT + i * W + k].as_canonical_u64() & 1) << k))
        })
    };
    let mut ok = true;
    ok &= hout_at(&trace, R_ADDR0) == addr_ref(&sp.ins[0].sk);
    ok &= hout_at(&trace, R_CI0B2) == commit_ref(&sp.ins[0].note);
    ok &= hout_at(&trace, R_NF0) == nf_ref(&sp.ins[0].sk, &sp.ins[0].note.rho);
    if !arg("--steal") {
        ok &= hout_at(&trace, R_MER0 + DEPTH - 1) == sp.anchor;
    }
    if sp.ins[1].enable {
        ok &= hout_at(&trace, R_ADDR1) == addr_ref(&sp.ins[1].sk);
        ok &= hout_at(&trace, R_CI1B2) == commit_ref(&sp.ins[1].note);
        ok &= hout_at(&trace, R_MER1 + DEPTH - 1) == sp.anchor;
        ok &= hout_at(&trace, R_NF1) == nf_ref(&sp.ins[1].sk, &sp.ins[1].note.rho);
    }
    ok &= hout_at(&trace, R_RHO0B2) == derive_rho_ref(&sp.ins[0].nf_pub, &sp.ins[1].nf_pub, 0);
    ok &= hout_at(&trace, R_RHO1B2) == derive_rho_ref(&sp.ins[0].nf_pub, &sp.ins[1].nf_pub, 1);
    println!(
        "host diff-test: all trace digests == full-keyed reference (addr/commit/nf/rho'/merkle): {ok} (rows {HEIGHT}, cols {NUM_COLS}, prep {PREP_W})"
    );

    // ---- tampering variants ----
    if arg("--corrupt") {
        let r = R_MER0 + 7;
        trace.values[r * NUM_COLS + SIB + 5] = Val::ONE - trace.values[r * NUM_COLS + SIB + 5];
    }
    let mut pis: Vec<Val> = pis_u64.iter().map(|&b| Val::from_u64(b)).collect();
    if arg("--wrong-anchor") {
        pis[PI_ANCHOR] = Val::ONE - pis[PI_ANCHOR];
    }
    if arg("--wrong-nf") {
        pis[PI_NF0] = Val::ONE - pis[PI_NF0];
    }

    // ---- prove + verify (preprocessed row-type schedule) ----
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
        Ok(_) if negative => println!("NEGATIVE TEST FAIL — an invalid spend was accepted!"),
        Ok(_) => println!(
            "VERIFY ok — COMPLETE shielded spend proven with the REAL hashes (2-in/2-out{}: membership@depth-20 + authority + nullifier + faerie-gold rho + output commitments + 66-bit value conservation), hiding-ZK [prove {:.1?}, verify {:.1?}]",
            if with_dummy { ", 1 dummy" } else { "" },
            t_prove,
            t_verify
        ),
        Err(e) if negative => println!("NEGATIVE TEST PASS — invalid spend rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on valid spend: {e:?}"),
    }

    if !negative {
        // PRIVACY GATE: no private witness word may appear in the proof bytes.
        let pb = postcard::to_allocvec(&proof).unwrap();
        let has = |w: u64| {
            let le = w.to_le_bytes();
            pb.windows(8).any(|win| win == le)
        };
        let mut witness: Vec<u64> = Vec::new();
        for inp in &sp.ins {
            witness.extend_from_slice(&inp.sk);
            witness.extend_from_slice(&inp.note.owner_pk);
            witness.extend_from_slice(&inp.note.rho);
            witness.extend_from_slice(&inp.note.r);
            witness.push(inp.note.value);
            for s in &inp.sibs {
                witness.extend_from_slice(s);
            }
            witness.extend_from_slice(&commit_ref(&inp.note)); // the leaf (which note)
        }
        for o in &sp.outs {
            witness.extend_from_slice(&o.owner_pk);
            witness.extend_from_slice(&o.r);
            witness.push(o.value);
        }
        witness.retain(|&w| w != 0);
        let leaked = witness.iter().filter(|&&w| has(w)).count();
        if leaked == 0 {
            println!(
                "PRIVACY OK — sks, note fields, values, leaves and both sibling paths ({} words) do not appear in the proof ({} bytes)",
                witness.len(),
                pb.len()
            );
        } else {
            println!("PRIVACY LEAK — {leaked} private witness word(s) present in the proof");
        }
    }
}
