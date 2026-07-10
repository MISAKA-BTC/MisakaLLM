//! Recursive compression of the REAL shielded-spend proof (build#5).
//!
//! Pipeline (every stage on a recursion-repo TESTED code path):
//! - **Layer 0**: `Blake2bSpendAir` — the complete 2-in/2-out JoinSplit with every
//!   hash the real keyed BLAKE2b-512 (build#4, vendored at
//!   `docs/bench/plonky3-shield-air/spend.rs` in the misakas tree) — proven as a
//!   single-instance **p3-batch-stark** proof under the FULL hiding config
//!   (`HidingFriPcs` + salted `MerkleTreeHidingMmcs`, Poseidon2, DuplexChallenger),
//!   preprocessed columns included (the batch prover commits them globally). This is
//!   the `tests/zk_hiding_mmcs.rs` topology with our AIR.
//! - **Layer 1** (manual, same test): `BatchStarkVerifierInputsBuilder::allocate` +
//!   `verify_batch_circuit` build the verification circuit for the hiding proof;
//!   `set_hiding_salted_fri_mmcs_private_data` feeds the salted openings; the circuit
//!   is then proven with `BatchStarkProver` under a NON-hiding outer config (the
//!   outer witness is only the inner proof, which is already ZK).
//! - **Layers 2..N**: the unified API (`into_recursion_input::<BatchOnly>` →
//!   `build_next_layer_circuit`/`prove_next_layer`) chains until the verifier-circuit
//!   fixed point (the `recursive_keccak`/`recursive_fibonacci` loop).
//!
//! The layer-0 witness (sks, notes, paths, indexes, enables) is hidden by the salted
//! hiding layer-0 proof; a witness-absence gate scans the FINAL outer proof bytes.
//!
//! NOTE (found by the spike in this build): the unified `RecursionInput::UniStark`
//! path rejects proofs whose `preprocessed_next_row_columns()` omit the next-row
//! openings, and its ZK (HidingFriPcs) uni-stark path currently dies with a
//! `WitnessConflict` — hence batch-stark layer 0 on the tested lane instead.
//!
//! Flags: --spike (tiny preprocessed AIR instead of the spend — validates the whole
//! batch×hiding×preprocessed×manual-layer-1 path cheaply), --with-dummy (1 real +
//! 1 dummy input), --tamper (flip a public bit after layer-0 proving — the layer-1
//! circuit run MUST fail), --dump PATH (write the final outer proof bytes).
//!
//! ```bash
//! cargo run --release --example recursive_spend -- --spike --num-recursive-layers 3
//! cargo run --release --example recursive_spend -- --num-recursive-layers 4 --dump /tmp/spend_outer.bin
//! ```

#[macro_use]
mod common;
use common::*;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_batch_stark::{ProverData, StarkInstance, prove_batch, verify_batch};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_lookup::logup::LogUpGadget;
use p3_matrix::dense::RowMajorMatrix;
use p3_recursion::pcs::set_hiding_salted_fri_mmcs_private_data;
use p3_recursion::{BatchStarkVerifierInputsBuilder, verify_batch_circuit};
use std::collections::BTreeMap;
use std::rc::Rc;

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

#[derive(Clone)]
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
    // preprocessed_next_row_columns: default (open ALL columns at zeta AND zeta_next).
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


/// A minimal preprocessed AIR for the --spike path: row[2] = row[0] + prep·row[1],
/// with row[0] bound to a public value on the first row.
#[derive(Clone)]
struct SpikeAir;
impl<F: PrimeField64> BaseAir<F> for SpikeAir {
    fn width(&self) -> usize {
        3
    }
    fn num_public_values(&self) -> usize {
        1
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
    fn preprocessed_width(&self) -> usize {
        1
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let vals: Vec<F> = (0..64).map(|r| F::from_u64((r % 2) as u64)).collect();
        Some(RowMajorMatrix::new(vals, 1))
    }
    // preprocessed_next_row_columns: default (open ALL columns) — the recursion
    // verifier circuit requires the preprocessed NEXT openings to be present.
}
impl<AB2: AirBuilder> Air<AB2> for SpikeAir
where
    AB2::F: PrimeField64,
{
    fn eval(&self, builder: &mut AB2) {
        let pi0: AB2::Expr = builder.public_values()[0].into();
        let prep: Vec<AB2::Var> = builder.preprocessed().current_slice().to_vec();
        let main = builder.main();
        let row = main.current_slice();
        let p: AB2::Expr = prep[0].into();
        let a: AB2::Expr = row[0].into();
        let b: AB2::Expr = row[1].into();
        let c: AB2::Expr = row[2].into();
        builder.assert_zero(c - a.clone() - p * b);
        builder.when_first_row().assert_eq(a, pi0);
    }
}
fn spike_trace<F: PrimeField64>() -> (RowMajorMatrix<F>, Vec<F>) {
    let mut vals = F::zero_vec(64 * 3);
    for r in 0..64 {
        let (a, b) = (F::from_u64(7 + r as u64), F::from_u64(3 * r as u64 + 1));
        let p = F::from_u64((r % 2) as u64);
        vals[r * 3] = a;
        vals[r * 3 + 1] = b;
        vals[r * 3 + 2] = a + p * b;
    }
    (RowMajorMatrix::new(vals, 3), vec![F::from_u64(7)])
}

/// Deterministic test spend (the build#4 witness): 2 real inputs (100 + 200, v_pub_in
/// 25 → outs 60 + 255, v_pub_out 10), or 1 real + 1 dummy with --with-dummy.
fn build_spend(with_dummy: bool) -> Spend {
    let sk0: [u64; 8] = core::array::from_fn(|i| 0x517c_c1b7_2722_0a95u64.wrapping_mul(i as u64 + 3));
    let sk1: [u64; 8] = core::array::from_fn(|i| 0x9e37_79b9_7f4a_7c15u64.wrapping_mul(i as u64 + 7));
    let mk = |seed: u64| -> [u64; 8] { core::array::from_fn(|i| seed.wrapping_mul(2 * i as u64 + 1).wrapping_add(0x0123_4567_89ab_cdef)) };
    let n0 = Note { value: 100, owner_pk: addr_ref(&sk0), rho: mk(0xaaaa_1111), r: mk(0xbbbb_2222) };
    let n1 = if with_dummy {
        Note { value: 0, owner_pk: mk(0x5555_6666), rho: mk(0xcccc_3333), r: mk(0xdddd_4444) }
    } else {
        Note { value: 200, owner_pk: addr_ref(&sk1), rho: mk(0xcccc_3333), r: mk(0xdddd_4444) }
    };
    let (i0, i1) = (0xB3A57u64, 0x2C9E4u64);
    let leaves: Vec<(u64, [u64; 8])> = if with_dummy {
        vec![(i0, commit_ref(&n0))]
    } else {
        vec![(i0, commit_ref(&n0)), (i1, commit_ref(&n1))]
    };
    let (anchor, paths) = sparse_tree(&leaves);
    let nf0 = nf_ref(&sk0, &n0.rho);
    let nf1 = if with_dummy { mk(0x7777_8888) } else { nf_ref(&sk1, &n1.rho) };
    let (v_pub_in, v_pub_out) = if with_dummy { (0u64, 10u64) } else { (25u64, 10u64) };
    let in_total = if with_dummy { n0.value } else { n0.value + n1.value };
    let out_total = in_total + v_pub_in - v_pub_out;
    let outs = [
        Note { value: 60, owner_pk: mk(0x1212_3434), rho: [0u64; 8], r: mk(0x5656_7878) },
        Note { value: out_total - 60, owner_pk: mk(0x9a9a_bcbc), rho: [0u64; 8], r: mk(0xdede_f0f0) },
    ];
    Spend {
        ins: [
            Input { note: n0, sk: sk0, enable: true, index: i0, sibs: paths[0], nf_pub: nf0 },
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
    }
}

#[derive(Parser, Debug)]
#[command(version, about = "Recursive compression of the real shielded-spend proof")]
struct Args {
    #[arg(long, default_value_t = 3)]
    num_recursive_layers: usize,
    #[arg(long, default_value_t = 2)]
    log_blowup: usize,
    #[arg(long, default_value_t = 2)]
    max_log_arity: usize,
    #[arg(long, default_value_t = 0)]
    cap_height: usize,
    #[arg(long, default_value_t = 5)]
    log_final_poly_len: usize,
    #[arg(long, default_value_t = 0)]
    commit_pow_bits: usize,
    #[arg(long, default_value_t = 15)]
    query_pow_bits: usize,
    #[arg(long, default_value_t = 1)]
    public_lanes: usize,
    #[arg(long, default_value_t = 3)]
    alu_lanes: usize,
    #[arg(long, default_value_t = 4)]
    horner_packed_steps: usize,
    #[arg(long, default_value_t = 1)]
    recompose_lanes: usize,
    #[arg(long, default_value_t = false)]
    disable_recompose_npo: bool,
    #[arg(long, default_value_t = 124, help = "Targeted conjectured security level")]
    security_level: usize,
    /// Run the tiny preprocessed spike AIR instead of the spend (path validation).
    #[arg(long, default_value_t = false)]
    spike: bool,
    /// 1 real + 1 dummy input instead of 2 real inputs.
    #[arg(long, default_value_t = false)]
    with_dummy: bool,
    /// Negative test: flip a public bit after layer-0 proving; layer 1 MUST fail.
    #[arg(long, default_value_t = false)]
    tamper: bool,
    /// Layer-0 FRI log-blowup override (higher blowup = fewer queries = a much
    /// smaller layer-1 verification circuit; the layer-0 trace is tiny so the
    /// extra LDE cost is negligible).
    #[arg(long)]
    l0_log_blowup: Option<usize>,
    /// FRI log-blowup for the FINAL layer only (size squeeze at the fixed point).
    #[arg(long)]
    final_log_blowup: Option<usize>,
    /// Write the final outer proof bytes here.
    #[arg(long)]
    dump: Option<std::path::PathBuf>,
    /// Dump the LAYER-0 (hiding, witness-bearing) proof bytes and exit BEFORE any
    /// recursion — lets the real wide-AIR proof be produced on a RAM-limited box
    /// (recursion of a 110k-col inner AIR needs ~12-15 GB; see the header).
    #[arg(long)]
    dump_l0: Option<std::path::PathBuf>,
}

fn main() {
    init_logger();
    let args = Args::parse();
    let fri_params = FriParams {
        log_blowup: args.log_blowup,
        max_log_arity: args.max_log_arity,
        cap_height: args.cap_height,
        log_final_poly_len: args.log_final_poly_len,
        commit_pow_bits: args.commit_pow_bits,
        query_pow_bits: args.query_pow_bits,
    };
    let table_packing = TablePacking::new(args.public_lanes, args.alu_lanes)
        .with_horner_pack_k(args.horner_packed_steps)
        .with_npo_lanes(NpoTypeId::recompose(), args.recompose_lanes);
    baby_bear::run(&args, &fri_params, &table_packing);
}

mod baby_bear {
    use super::*;
    use p3_circuit::CircuitBuilder;
    use p3_circuit_prover::batch_stark_prover::{poseidon2_air_builders, recompose_air_builders};
    use p3_circuit_prover::common::{NpoPreprocessor, get_airs_and_degrees_with_prep};
    use p3_circuit_prover::{Poseidon2Preprocessor, RecomposePreprocessor};
    use p3_recursion::pcs::fri::{HidingFriProofTargets, InputProofTargets, RecValHidingMmcs, Witness};

    define_field_module_types!(
        p3_baby_bear::BabyBear,
        p3_baby_bear::Poseidon2BabyBear<16>,
        p3_baby_bear::default_babybear_poseidon2_16,
        Poseidon2Config::BABY_BEAR_D4_W16,
        p3_poseidon2_circuit_air::BabyBearD4Width16,
        4,
        16,
        8,
        8,
        enable_poseidon2_perm,
        p3_baby_bear::default_babybear_poseidon2_16,
        16,
        8,
        enable_recompose,
        generate_poseidon2_trace,
        p3_circuit::ops::Poseidon2Params
    );

    /// Salt width of the hiding MMCS leaves (matches tests/zk_hiding_mmcs.rs).
    const SALT_ELEMS: usize = 4;
    type HidingValMmcs = p3_merkle_tree::MerkleTreeHidingMmcs<
        <F as p3_field::Field>::Packing,
        <F as p3_field::Field>::Packing,
        MyHash,
        MyCompress,
        SmallRng,
        2,
        DIGEST_ELEMS,
        SALT_ELEMS,
    >;
    type HidingChallengeMmcs = p3_commit::ExtensionMmcs<F, Challenge, HidingValMmcs>;
    type L0PcsZk = p3_fri::HidingFriPcs<F, Dft, HidingValMmcs, HidingChallengeMmcs, SmallRng>;
    type L0ConfigZk = p3_uni_stark::StarkConfig<L0PcsZk, Challenge, Challenger>;
    type RecHidingValMmcs = RecValHidingMmcs<F, DIGEST_ELEMS, SALT_ELEMS, MyHash, MyCompress, SmallRng>;
    type L0InnerFriZk = HidingFriProofTargets<
        F,
        Challenge,
        p3_recursion::pcs::RecExtensionValMmcs<F, Challenge, DIGEST_ELEMS, RecHidingValMmcs>,
        InputProofTargets<F, Challenge, RecHidingValMmcs>,
        Witness<F>,
    >;

    /// Layer-0 hiding config: HidingFriPcs + salted Poseidon2 MMCS.
    /// log_final_poly_len is clamped to 0 — the spend trace is only 64 rows.
    fn l0_config(fp: &FriParams, security_level: usize, lb: usize) -> (L0ConfigZk, FriVerifierParams) {
        let perm = p3_baby_bear::default_babybear_poseidon2_16();
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm.clone());
        let val_mmcs = HidingValMmcs::new(hash, compress, fp.cap_height, SmallRng::seed_from_u64(11));
        let challenge_mmcs = HidingChallengeMmcs::new(val_mmcs.clone());
        let num_queries = (security_level - fp.query_pow_bits) / lb;
        let fri = p3_fri::FriParameters {
            max_log_arity: fp.max_log_arity,
            log_blowup: lb,
            log_final_poly_len: 0,
            num_queries,
            commit_proof_of_work_bits: fp.commit_pow_bits,
            query_proof_of_work_bits: fp.query_pow_bits,
            mmcs: challenge_mmcs,
        };
        let fvp = FriVerifierParams::with_mmcs(
            fri.log_blowup,
            fri.log_final_poly_len,
            fri.commit_proof_of_work_bits,
            fri.query_proof_of_work_bits,
            fri.num_queries,
            Poseidon2Config::BABY_BEAR_D4_W16,
        );
        let pcs = L0PcsZk::new(Dft::default(), val_mmcs, fri, SALT_ELEMS, SmallRng::seed_from_u64(1));
        (L0ConfigZk::new(pcs, Challenger::new(perm)), fvp)
    }

    pub fn run(args: &Args, fri_params: &FriParams, table_packing: &TablePacking) {
        macro_rules! drive {
            ($air:expr, $trace:expr, $pis:expr, $witness_words:expr) => {{
                let air = $air;
                let trace = $trace;
                let pis: Vec<F> = $pis;

                // ---- layer 0: hiding batch-stark (salted MMCS), preprocessed ----
                let lb0 = args.l0_log_blowup.unwrap_or(fri_params.log_blowup);
                let (config_0, fvp_0) = l0_config(fri_params, args.security_level, lb0);
                let t0 = std::time::Instant::now();
                let instances = vec![StarkInstance { air: &air, trace: &trace, public_values: pis.clone() }];
                let prover_data = ProverData::from_instances(&config_0, &instances);
                let proof_0 = prove_batch(&config_0, &instances, &prover_data);
                let t_prove0 = t0.elapsed();
                let pvs = vec![pis.clone()];
                verify_batch(&config_0, core::slice::from_ref(&air), &proof_0, &pvs, &prover_data.common)
                    .expect("layer-0 native verify failed");
                let bytes0 = postcard::to_allocvec(&proof_0).expect("serialize layer-0").len();
                info!("layer 0 (batch-stark, hiding+salted Poseidon2 MMCS, preprocessed): proof {} bytes, prove {:.1?}", bytes0, t_prove0);
                if let Some(path) = &args.dump_l0 {
                    std::fs::write(path, postcard::to_allocvec(&proof_0).expect("serialize layer-0")).expect("dump layer-0");
                    // witness-absence on the HIDING layer-0 proof itself.
                    let l0 = postcard::to_allocvec(&proof_0).unwrap();
                    let has = |w: u64| { let le = w.to_le_bytes(); l0.windows(8).any(|win| win == le) };
                    let witness: Vec<u64> = $witness_words;
                    let leaked = witness.iter().filter(|&&w| w != 0 && has(w)).count();
                    println!(
                        "LAYER-0 ok — real spend proof {} bytes = {} x 32 KiB DA chunks (hiding, witness-bearing); PRIVACY {} ({} witness words scanned); written to {}",
                        bytes0, bytes0.div_ceil(32 * 1024),
                        if leaked == 0 { "OK" } else { "LEAK" }, witness.len(), path.display()
                    );
                    return;
                }

                let pvs = if args.tamper {
                    let mut t = pvs.clone();
                    t[0][0] = F::ONE - t[0][0];
                    t
                } else {
                    pvs
                };

                // ---- layer 1 (manual): verification circuit for the hiding proof ----
                let t1 = std::time::Instant::now();
                let perm2 = p3_baby_bear::default_babybear_poseidon2_16();
                let mut cb = CircuitBuilder::new();
                cb.enable_poseidon2_perm::<p3_poseidon2_circuit_air::BabyBearD4Width16, _>(
                    generate_poseidon2_trace::<Challenge, p3_poseidon2_circuit_air::BabyBearD4Width16>,
                    perm2.clone(),
                );
                cb.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
                let lookup_gadget = LogUpGadget::new();
                let air_public_counts = vec![pis.len()];
                let verifier_inputs = BatchStarkVerifierInputsBuilder::<
                    L0ConfigZk,
                    MerkleCapTargets<F, DIGEST_ELEMS>,
                    L0InnerFriZk,
                >::allocate(&mut cb, &proof_0, &prover_data.common, &air_public_counts);
                let mmcs_op_ids = verify_batch_circuit::<_, _, _, _, _, _, _, WIDTH, RATE>(
                    &config_0,
                    core::slice::from_ref(&air),
                    &mut cb,
                    &verifier_inputs.proof_targets,
                    &verifier_inputs.air_public_targets,
                    &fvp_0,
                    &verifier_inputs.common_data,
                    &lookup_gadget,
                    Poseidon2Config::BABY_BEAR_D4_W16,
                )
                .expect("build layer-1 verification circuit");
                let verification_circuit = cb.build().expect("layer-1 circuit build");
                let (public_inputs, private_inputs) = verifier_inputs.pack_values(&pvs, &proof_0, &prover_data.common);
                let mut runner = verification_circuit.runner();
                runner.set_public_inputs(&public_inputs).expect("set publics");
                runner.set_private_inputs(&private_inputs).expect("set privates");
                assert!(!mmcs_op_ids.is_empty(), "hiding MMCS openings must be exercised");
                set_hiding_salted_fri_mmcs_private_data::<F, Challenge, HidingChallengeMmcs, HidingValMmcs, DIGEST_ELEMS>(
                    &mut runner,
                    &mmcs_op_ids,
                    &proof_0.opening_proof,
                    Poseidon2Config::BABY_BEAR_D4_W16,
                )
                .expect("set hiding MMCS private data");
                let traces_1 = match runner.run() {
                    Ok(t) => t,
                    Err(e) => {
                        if args.tamper {
                            println!("NEGATIVE TEST PASS — tampered public input rejected by the layer-1 verifier circuit: {e:?}");
                            return;
                        }
                        panic!("layer-1 circuit run failed on a VALID proof: {e:?}");
                    }
                };
                if args.tamper {
                    println!("NEGATIVE TEST FAIL — tampered public input accepted by the layer-1 circuit!");
                    return;
                }

                // ---- prove the layer-1 circuit (non-hiding outer) ----
                let l1_packing = TablePacking::new(1, 2)
                    .with_fri_params(fri_params.log_final_poly_len, fri_params.log_blowup)
                    .with_npo_lanes(
                        NpoTypeId::recompose(),
                        table_packing.npo_lanes(&NpoTypeId::recompose()).unwrap_or(1),
                    );
                let config_1 = config_with_fri_params(fri_params, args.security_level, args.disable_recompose_npo);
                let npo_prep: Vec<Box<dyn NpoPreprocessor<F>>> = vec![
                    Box::new(Poseidon2Preprocessor),
                    Box::new(RecomposePreprocessor::default()),
                ];
                let mut air_builders = poseidon2_air_builders::<_, D>();
                air_builders.extend(recompose_air_builders(1, false));
                let (airs_degrees_1, prim_cols_1, non_prim_cols_1) = get_airs_and_degrees_with_prep::<ConfigWithFriParams, _, D>(
                    &verification_circuit,
                    &l1_packing,
                    &npo_prep,
                    &air_builders,
                    ConstraintProfile::Standard,
                )
                .expect("layer-1 airs/degrees");
                let (airs_1, degrees_1): (Vec<_>, Vec<usize>) = airs_degrees_1.into_iter().unzip();
                let prover_data_1 = ProverData::from_airs_and_degrees(&config_1, &airs_1, &degrees_1);
                let cpd_1 = CircuitProverData::new(prover_data_1, prim_cols_1, non_prim_cols_1);
                let mut prover_1 = BatchStarkProver::new(config_1.clone()).with_table_packing(l1_packing.clone());
                prover_1.register_poseidon2_table::<D>(Poseidon2Config::BABY_BEAR_D4_W16);
                prover_1.register_recompose_table::<D>(false);
                let proof_1 = prover_1.prove_all_tables(&traces_1, &cpd_1).expect("prove layer-1 circuit");
                prover_1.verify_all_tables::<Challenge>(&proof_1).expect("verify layer-1");
                let bytes1 = postcard::to_allocvec(&proof_1).expect("serialize").len();
                info!("layer 1: outer proof {} bytes ({} x 32 KiB chunks), {:.1?}", bytes1, bytes1.div_ceil(32 * 1024), t1.elapsed());

                // ---- layers 2..N: unified chaining until the fixed point ----
                let backend = FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::BABY_BEAR_D4_W16)
                    .for_extension_degree::<D>();
                let mut output = RecursionOutput(proof_1, Rc::new(cpd_1));
                let mut final_bytes = postcard::to_allocvec(&output.0).expect("serialize");
                let mut prev_witness_count: Option<u32> = None;
                let mut stable_prep: Option<NextLayerPrepCache<ConfigWithFriParams>> = None;

                for layer in 2..=args.num_recursive_layers {
                    let t = std::time::Instant::now();
                    let is_final = layer == args.num_recursive_layers;
                    let lb_used = if is_final { args.final_log_blowup.unwrap_or(fri_params.log_blowup) } else { fri_params.log_blowup };
                    let layer_fp = FriParams { log_blowup: lb_used, ..*fri_params };
                    let params = ProveNextLayerParams {
                        table_packing: table_packing
                            .clone()
                            .with_fri_params(layer_fp.log_final_poly_len, layer_fp.log_blowup),
                        constraint_profile: ConstraintProfile::Standard,
                    };
                    // The struct couples the OUTER proving params with the INNER
                    // verification params; on a final-layer blowup change they differ:
                    // prove the outer at lb_used, verify the inner at the chain blowup.
                    let config = if lb_used == fri_params.log_blowup {
                        config_with_fri_params(&layer_fp, args.security_level, args.disable_recompose_npo)
                    } else {
                        ConfigWithFriParams {
                            config: std::sync::Arc::new(create_config(&layer_fp, args.security_level)),
                            fri_verifier_params: create_fri_verifier_params(fri_params, args.security_level),
                            disable_recompose_npo: args.disable_recompose_npo,
                        }
                    };
                    let input = output.into_recursion_input::<BatchOnly>();
                    let (verification_circuit, verifier_result) =
                        build_next_layer_circuit::<ConfigWithFriParams, BatchOnly, _, D>(&input, &config, &backend)
                            .unwrap_or_else(|e| panic!("layer {layer} circuit build: {e:?}"));
                    let current = verification_circuit.witness_count;
                    let is_stable = prev_witness_count == Some(current) && lb_used == fri_params.log_blowup;
                    prev_witness_count = Some(current);
                    if is_stable && stable_prep.is_none() {
                        stable_prep = Some(
                            build_next_layer_prep::<ConfigWithFriParams, BatchOnly, _, D>(
                                &verification_circuit,
                                &config,
                                &backend,
                                &params,
                            )
                            .expect("prep cache"),
                        );
                    }
                    let prep_for_layer = if lb_used == fri_params.log_blowup { stable_prep.as_ref() } else { None };
                    let out = prove_next_layer::<ConfigWithFriParams, BatchOnly, _, D>(
                        &input,
                        &verification_circuit,
                        &verifier_result,
                        &config,
                        &backend,
                        &params,
                        prep_for_layer,
                    )
                    .unwrap_or_else(|e| panic!("layer {layer} prove: {e:?}"));
                    let bytes = postcard::to_allocvec(&out.0).expect("serialize").len();
                    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(params.table_packing.clone());
                    prover.register_poseidon2_table::<D>(Poseidon2Config::BABY_BEAR_D4_W16);
                    if !args.disable_recompose_npo {
                        prover.register_recompose_table::<D>(false);
                    }
                    prover
                        .verify_all_tables::<Challenge>(&out.0)
                        .unwrap_or_else(|e| panic!("layer {layer} verify: {e:?}"));
                    info!("layer {layer}: outer proof {} bytes ({} x 32 KiB chunks), {:.1?}", bytes, bytes.div_ceil(32 * 1024), t.elapsed());
                    final_bytes = postcard::to_allocvec(&out.0).expect("serialize");
                    output = out;
                }

                // ---- witness-absence gate on the FINAL outer proof ----
                let witness: Vec<u64> = $witness_words;
                let has = |w: u64| {
                    let le = w.to_le_bytes();
                    final_bytes.windows(8).any(|win| win == le)
                };
                let leaked = witness.iter().filter(|&&w| w != 0 && has(w)).count();
                println!(
                    "RECURSION ok — final outer proof {} bytes = {} x 32 KiB DA chunks after {} layers (layer-0 hiding proof {} bytes); PRIVACY {} ({} witness words scanned)",
                    final_bytes.len(),
                    final_bytes.len().div_ceil(32 * 1024),
                    args.num_recursive_layers,
                    bytes0,
                    if leaked == 0 { "OK" } else { "LEAK" },
                    witness.len()
                );
                if let Some(path) = &args.dump {
                    std::fs::write(path, &final_bytes).expect("dump outer proof");
                    println!("outer proof written to {}", path.display());
                }
            }};
        }

        if args.spike {
            let (trace, pis) = spike_trace::<F>();
            drive!(SpikeAir, trace, pis, vec![]);
        } else {
            let sp = build_spend(args.with_dummy);
            let sched = schedule();
            let air = Blake2bSpendAir { sched: sched.clone() };
            let (trace, pis_u64) = generate::<F>(&sp, &sched);
            // host diff-test (same gate as build#4): trace digests == full keyed refs
            let ok_addr = hout_at::<F>(&trace, R_ADDR0) == addr_ref(&sp.ins[0].sk);
            let ok_cm = hout_at::<F>(&trace, R_CI0B2) == commit_ref(&sp.ins[0].note);
            let ok_mem = hout_at::<F>(&trace, R_MER0 + DEPTH - 1) == sp.anchor;
            let ok_rho = hout_at::<F>(&trace, R_RHO0B2) == derive_rho_ref(&sp.ins[0].nf_pub, &sp.ins[1].nf_pub, 0);
            println!("host diff-test: addr {ok_addr} commit {ok_cm} membership {ok_mem} rho' {ok_rho}");
            assert!(ok_addr && ok_cm && ok_mem && ok_rho, "diff-test failed");
            let pis: Vec<F> = pis_u64.iter().map(|&b| F::from_u64(b)).collect();
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
                witness.extend_from_slice(&commit_ref(&inp.note));
            }
            for o in &sp.outs {
                witness.extend_from_slice(&o.owner_pk);
                witness.extend_from_slice(&o.r);
                witness.push(o.value);
            }
            drive!(air, trace, pis, witness);
        }
    }

    /// digest words at a row's HOUT columns (diff-test helper).
    fn hout_at<F: PrimeField64>(trace: &RowMajorMatrix<F>, r: usize) -> [u64; 8] {
        core::array::from_fn(|i| {
            (0..W).fold(0u64, |acc, k| {
                acc | ((trace.values[r * NUM_COLS + HOUT + i * W + k].as_canonical_u64() & 1) << k)
            })
        })
    }
}
