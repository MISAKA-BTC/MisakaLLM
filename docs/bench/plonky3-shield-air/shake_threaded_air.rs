//! C-P6 / B1 integration (ADR-0037), composition-manifest item (ii): **MULTI-BLOCK SHAKE
//! THREADING as ONE Plonky3 AIR**. Until now the SHAKE side was three separately-proven
//! pieces — the Keccak-f[1600] permutation (`p3-keccak-air` via `keccak_shake.rs`), the
//! absorb/pad XOR bookkeeping (`shake_absorb_air.rs`), and a host-level sponge oracle
//! diff-tested vs `sha3` (`shake_sponge.rs`). Here a COMPLETE multi-block SHAKE computation
//! is constrained END-TO-END in a single AIR: multi-block absorb (FIPS-202 pad10*1 with the
//! 0x1F domain byte) → Keccak-f[1600] between/after absorbs → multi-block squeeze, with
//! EVERY cross-block sponge-state wire bound in-AIR — the prover cannot substitute any
//! intermediate sponge state.
//!
//! ## Layout: [KeccakCols | state-rate bits | block bits], 24 rows per permutation
//! `p3-keccak-air` lays out one permutation per 24 adjacent rows, so consecutive sponge
//! permutations sit in ADJACENT 24-row groups and every threading constraint is a plain
//! (current, next) equality on the group-boundary transition (last row of perm k → first
//! row of perm k+1), gated by PREPROCESSED one-hot boundary flags (the exact technique of
//! `ntt_wired256_air.rs` layer flags). The row is the upstream `KeccakCols` (2633 cols,
//! borrowed from the first NUM_KECCAK_COLS of our wider row — the upstream eval is vendored
//! verbatim below with only that subslice change, plus local re-derivation of the private
//! `BITS_PER_LIMB`/`RC_BITS`) extended with 2×rate_bits extra columns, populated only on
//! boundary rows: the bit decomposition of the current perm's output rate lanes, and the
//! bits of the next absorbed (padded) block.
//!
//! ## Threading constraints (all flag-gated, one equality per enumerated wire)
//! - **first absorb** (row 0): `preimage == 0 ⊕ block₀` — rate lanes equal the recomposed
//!   block bits, capacity lanes pinned to 0 (the all-zero initial sponge state).
//! - **absorb boundary** k−1 → k: rate lanes `next.preimage == out ⊕ blockₖ` via the
//!   build#1 `a+b−2ab` bit-XOR recomposed to 16-bit limbs; capacity lanes pass through as
//!   DIRECT limb equalities `next.preimage == out`. The state bits are bound to the actual
//!   permutation output by limb recomposition (`Σ bitⱼ·2ʲ == a'''`); both sides of every
//!   limb equality are bit/bool-constrained < 2¹⁶ < p, so field equality is exact integer
//!   equality (the `ntt_wired256_air.rs` recomposed-value-binding argument).
//! - **squeeze boundary** (between squeeze blocks): the state threads through Keccak-f with
//!   NO xor — flag-gated identity on ALL 25 lanes × 4 limbs.
//! - **pad10*1 pinning**: every non-message byte of every absorbed block is pinned bit-by-
//!   bit to the FIPS-202 pad constants (0x1F domain byte at msg_len, 0x00 fill, 0x80 final;
//!   0x9F when merged) — the constants are cross-checked against the diff-tested host
//!   padder in the self-audit.
//! - **statement binding**: message bytes and ALL squeeze-output bytes are PUBLIC VALUES;
//!   block bits recompose to the message publics, output limbs bind to `lo + 256·hi` byte
//!   pairs of the output publics.
//!
//! ## Trace height / padding
//! NUM_PERMS × 24 rows, padded to a power of two by `p3-keccak-air`'s own generator (full +
//! truncated all-zero dummy permutations, which satisfy every unconditional constraint and
//! keep the round-flag rotation valid). All boundary flags are zero on padding rows and none
//! is set on the last row, so no threading constraint crosses the real/padding boundary or
//! the cyclic wrap.
//!
//! ## Instances proven (structurally complete, small)
//! SHAKE256 (rate 136 B = 17 lanes) is primary — the μ/tr/c̃ path: 300-byte message = 3
//! absorb blocks (pad mid-block) + 2 squeeze blocks = 4 permutations. SHAKE128 (rate 168 B
//! = 21 lanes, the ExpandA path) is the SAME AIR with rate as a parameter. A third instance
//! pins the 0x9F merged-pad corner (msg_len ≡ rate−1). 128 rows each.
//!
//! ## Validation gates
//! (1) host oracle diff-test byte-for-byte vs `sha3::{Shake256,Shake128}` (edge lengths
//! incl. rate−1 / rate / rate+1 and multi-block squeeze) AND the proven trace's squeeze
//! limbs re-read and compared byte-for-byte vs `sha3`; (2) VERIFY ok with prove/verify
//! times, cols/rows, proof bytes; (3) negatives, all rejected: `--corrupt-thread` (flip one
//! bit of the threaded state between perm k and absorb k+1 — every permutation stays
//! internally valid, downstream states and ALL publics are recomputed consistently, so ONLY
//! the absorb-boundary XOR wire is violated), `--corrupt-pad` (0x1F domain bit, chain kept
//! consistent — only the pad pin fails), `--corrupt-cap` (capacity lane across a boundary —
//! caught by the pass-through equality), `--corrupt-squeeze` (state between squeeze blocks),
//! `--corrupt-out` (a squeeze output public byte); (4) a programmatic constraint-coverage
//! self-audit: every (lane, limb) of every boundary bound exactly once, every block byte
//! bound exactly once (public or pad constant), pad constants == the diff-tested padder.
//!
//! NOTE: bench FRI parameters (like the sibling bins) — NOT production soundness settings.
//! Run: `cargo run --release --bin shake_threaded_air \
//!       [--corrupt-thread|--corrupt-pad|--corrupt-cap|--corrupt-squeeze|--corrupt-out]`

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::KeccakF;
use p3_keccak_air::{
    KeccakCols, NUM_KECCAK_COLS, NUM_ROUNDS, NUM_ROUNDS_MIN_1, RC, U64_LIMBS, generate_trace_rows,
};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, Permutation, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};

/// Upstream `BITS_PER_LIMB` (private in `p3-keccak-air`).
const BPL: usize = 16;

// ---------------------------------------------------------------------------------------
// The AIR
// ---------------------------------------------------------------------------------------

/// One complete multi-block SHAKE computation: `num_absorb` (derived from `msg_len`) absorb
/// permutations followed by `num_squeeze − 1` squeeze permutations, threaded in-AIR.
/// `rate_lanes` = 17 (SHAKE256) or 21 (SHAKE128); the 0x1F domain byte is common to both.
struct ShakeThreadedAir {
    rate_lanes: usize,
    msg_len: usize,
    num_squeeze: usize,
}

impl ShakeThreadedAir {
    fn rate_bytes(&self) -> usize {
        self.rate_lanes * 8
    }
    fn rate_bits(&self) -> usize {
        self.rate_lanes * 64
    }
    /// pad10*1 always appends ≥ 1 byte, so A = ⌈(msg_len+1)/rate⌉.
    fn num_absorb(&self) -> usize {
        (self.msg_len + 1).div_ceil(self.rate_bytes())
    }
    /// Squeeze block j is read from the output of perm A−1+j: A+S−1 permutations total.
    fn num_perms(&self) -> usize {
        self.num_absorb() + self.num_squeeze - 1
    }
    fn height(&self) -> usize {
        (self.num_perms() * NUM_ROUNDS).next_power_of_two()
    }
    fn padded_len(&self) -> usize {
        self.num_absorb() * self.rate_bytes()
    }
    // main-trace extra-column bases
    fn x_state(&self) -> usize {
        NUM_KECCAK_COLS
    }
    fn x_block(&self) -> usize {
        NUM_KECCAK_COLS + self.rate_bits()
    }
    fn total_width(&self) -> usize {
        NUM_KECCAK_COLS + 2 * self.rate_bits()
    }
    // preprocessed one-hot boundary flags
    fn p_abs0(&self) -> usize {
        0 // row 0: first absorb into the zero state
    }
    fn p_abs(&self, k: usize) -> usize {
        debug_assert!(k >= 1 && k < self.num_absorb());
        k // cols 1..A−1: absorb boundary into perm k, set on row 24k−1
    }
    fn p_sqz(&self, j: usize) -> usize {
        debug_assert!(j >= 1 && j < self.num_squeeze);
        self.num_absorb() + j - 1 // squeeze boundary into perm A−1+j, set on row 24(A−1+j)−1
    }
    fn p_out(&self, j: usize) -> usize {
        debug_assert!(j < self.num_squeeze);
        self.num_absorb() + self.num_squeeze - 1 + j // output binding, set on row 24(A+j)−1
    }
    fn prep_width(&self) -> usize {
        self.num_absorb() + 2 * self.num_squeeze - 1
    }
    // public values: message bytes then S full squeeze blocks of output bytes
    fn pi_out_base(&self) -> usize {
        self.msg_len
    }
    fn num_pis(&self) -> usize {
        self.msg_len + self.num_squeeze * self.rate_bytes()
    }
    /// FIPS-202 pad10*1 + SHAKE 0x1F domain constant at padded position g (≥ msg_len).
    fn pad_byte(&self, g: usize) -> u8 {
        debug_assert!(g >= self.msg_len && g < self.padded_len());
        let mut b = 0u8;
        if g == self.msg_len {
            b |= 0x1F;
        }
        if g == self.padded_len() - 1 {
            b |= 0x80;
        }
        b
    }
    /// Byte dispositions of absorbed block k: `Ok(pi)` = message byte bound to public `pi`,
    /// `Err(c)` = pad byte pinned bit-by-bit to constant `c`. `eval` emits EXACTLY one
    /// binding per entry, so the self-audit of this enumeration audits the constraint set.
    fn block_bytes(&self, k: usize) -> Vec<(usize, Result<usize, u8>)> {
        let rate = self.rate_bytes();
        (0..rate)
            .map(|i| {
                let g = k * rate + i;
                if g < self.msg_len { (i, Ok(g)) } else { (i, Err(self.pad_byte(g))) }
            })
            .collect()
    }
}

/// The 100 (lane, limb) wires of one permutation-input boundary, with the rate/capacity
/// split: rate lanes bind via XOR-recomposition (or plain recomposition on row 0), capacity
/// lanes via direct limb pass-through (or zero-pin on row 0). `eval` emits EXACTLY one gated
/// equality per entry per boundary event (`ntt_wired256_air.rs` discipline).
fn input_wires(rate_lanes: usize) -> Vec<(usize, usize, bool)> {
    (0..25)
        .flat_map(|l| (0..U64_LIMBS).map(move |m| (l, m, l < rate_lanes)))
        .collect()
}

impl<F: PrimeField64> BaseAir<F> for ShakeThreadedAir {
    fn width(&self) -> usize {
        self.total_width()
    }
    fn num_public_values(&self) -> usize {
        self.num_pis()
    }
    fn preprocessed_width(&self) -> usize {
        self.prep_width()
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let w = self.prep_width();
        let mut vals = F::zero_vec(self.height() * w);
        vals[self.p_abs0()] = F::ONE; // row 0
        for k in 1..self.num_absorb() {
            vals[(NUM_ROUNDS * k - 1) * w + self.p_abs(k)] = F::ONE;
        }
        for j in 1..self.num_squeeze {
            vals[(NUM_ROUNDS * (self.num_absorb() - 1 + j) - 1) * w + self.p_sqz(j)] = F::ONE;
        }
        for j in 0..self.num_squeeze {
            vals[(NUM_ROUNDS * (self.num_absorb() + j) - 1) * w + self.p_out(j)] = F::ONE;
        }
        // padding rows: all flags zero — no threading constraint crosses the boundary.
        Some(RowMajorMatrix::new(vals, w))
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        // Only the CURRENT preprocessed row is read in eval(). INVARIANT: if any constraint
        // ever reads preprocessed().next_slice(), those columns MUST be listed here.
        vec![]
    }
}

/// The private upstream `RC_BITS` table, re-derived from the public `RC`.
fn rc_bits_table() -> [[u8; 64]; 24] {
    let mut t = [[0u8; 64]; 24];
    for (r, row) in t.iter_mut().enumerate() {
        for (z, bit) in row.iter_mut().enumerate() {
            *bit = ((RC[r] >> z) & 1) as u8;
        }
    }
    t
}

/// The COMPLETE upstream `p3-keccak-air` eval (round flags + all permutation constraints),
/// vendored verbatim except: (1) the KeccakCols row is borrowed from the first
/// NUM_KECCAK_COLS of our WIDER row; (2) `BITS_PER_LIMB` / `RC_BITS` are re-derived locally
/// (they are `pub(crate)` upstream). Source: ~/Plonky3/keccak-air/src/{air,round_flags}.rs.
fn eval_keccak<AB: AirBuilder>(builder: &mut AB) {
    let rc_bits = rc_bits_table();
    let main = builder.main();
    let row = main.current_slice();
    let nxt = main.next_slice();
    let local: &KeccakCols<AB::Var> = row[..NUM_KECCAK_COLS].borrow();
    let next: &KeccakCols<AB::Var> = nxt[..NUM_KECCAK_COLS].borrow();

    // ---- round flags (round_flags.rs): row 0 = round 0, rotation on every transition ----
    builder.when_first_row().assert_one(local.step_flags[0]);
    builder
        .when_first_row()
        .assert_zeros::<NUM_ROUNDS_MIN_1, _>(local.step_flags[1..].try_into().unwrap());
    builder
        .when_transition()
        .assert_zeros::<NUM_ROUNDS, _>(core::array::from_fn(|i| {
            local.step_flags[i] - next.step_flags[(i + 1) % NUM_ROUNDS]
        }));

    // ---- permutation constraints (air.rs) ----
    let first_step = local.step_flags[0];
    let final_step = local.step_flags[NUM_ROUNDS - 1];
    let not_final_step = AB::Expr::ONE - final_step;
    let transition_and_not_final = builder.is_transition() * not_final_step.clone();

    // If this is the first step, the input A must match the preimage.
    for y in 0..5 {
        for x in 0..5 {
            builder
                .when(first_step)
                .assert_zeros::<U64_LIMBS, _>(core::array::from_fn(|limb| {
                    local.preimage[y][x][limb] - local.a[y][x][limb]
                }));
        }
    }

    // If this is not the final step, the local and next preimages must match.
    for y in 0..5 {
        for x in 0..5 {
            builder
                .when(transition_and_not_final.clone())
                .assert_zeros::<U64_LIMBS, _>(core::array::from_fn(|limb| {
                    local.preimage[y][x][limb] - next.preimage[y][x][limb]
                }));
        }
    }

    // The export flag must be 0 or 1, and off when not the final step.
    builder.assert_bool(local.export);
    builder.when(not_final_step).assert_zero(local.export);

    // C'[x, z] = xor(C[x, z], C[x - 1, z], C[x + 1, z - 1]).
    for x in 0..5 {
        builder.assert_bools(local.c[x]);
        builder.assert_zeros::<64, _>(core::array::from_fn(|z| {
            let xor = local.c[x][z].into().xor3(
                &local.c[(x + 4) % 5][z].into(),
                &local.c[(x + 1) % 5][(z + 63) % 64].into(),
            );
            local.c_prime[x][z] - xor
        }));
    }

    // A[x, y, z] = xor(A'[x, y, z], C[x, z], C'[x, z]) — also range checks the limbs of A.
    for x in 0..5 {
        let c_xor_c_prime: [AB::Expr; 64] =
            core::array::from_fn(|z| local.c[x][z].into().xor(&local.c_prime[x][z].into()));
        for y in 0..5 {
            let get_bit = |z: usize| local.a_prime[y][x][z].into().xor(&c_xor_c_prime[z]);
            builder.assert_bools(local.a_prime[y][x]);
            builder.assert_zeros::<U64_LIMBS, _>(core::array::from_fn(|limb| {
                let computed_limb = (limb * BPL..(limb + 1) * BPL)
                    .rev()
                    .fold(AB::Expr::ZERO, |acc, z| acc.double() + get_bit(z));
                computed_limb - local.a[y][x][limb]
            }));
        }
    }

    // xor_{i=0}^4 A'[x, i, z] = C'[x, z]: diff ∈ {0, 2, 4}.
    for x in 0..5 {
        let four = AB::Expr::TWO.double();
        builder.assert_zeros::<64, _>(core::array::from_fn(|z| {
            let sum: AB::Expr = (0..5).map(|y| local.a_prime[y][x][z].into()).sum();
            let diff = sum - local.c_prime[x][z];
            diff.clone() * (diff.clone() - AB::Expr::TWO) * (diff - four.clone())
        }));
    }

    // A''[x, y] = xor(B[x, y], andn(B[x + 1, y], B[x + 2, y])).
    for y in 0..5 {
        for x in 0..5 {
            let get_bit = |z| {
                let andn = local
                    .b((x + 1) % 5, y, z)
                    .into()
                    .andn(&local.b((x + 2) % 5, y, z).into());
                andn.xor(&local.b(x, y, z).into())
            };
            builder.assert_zeros::<U64_LIMBS, _>(core::array::from_fn(|limb| {
                let computed_limb = (limb * BPL..(limb + 1) * BPL)
                    .rev()
                    .fold(AB::Expr::ZERO, |acc, z| acc.double() + get_bit(z));
                computed_limb - local.a_prime_prime[y][x][limb]
            }));
        }
    }

    // A''[0, 0] bit decomposition.
    builder.assert_bools(local.a_prime_prime_0_0_bits);
    builder.assert_zeros::<U64_LIMBS, _>(core::array::from_fn(|limb| {
        let computed = (limb * BPL..(limb + 1) * BPL)
            .rev()
            .fold(AB::Expr::ZERO, |acc, z| acc.double() + local.a_prime_prime_0_0_bits[z]);
        computed - local.a_prime_prime[0][0][limb]
    }));

    // A'''[0, 0] = A''[0, 0] XOR RC (iota).
    let get_xored_bit = |i: usize| {
        let rc_bit_i: AB::Expr = local
            .step_flags
            .iter()
            .zip(rc_bits.iter())
            .filter(|(_, rc_bits_r)| rc_bits_r[i] != 0)
            .map(|(&step_flag, _)| step_flag.into())
            .sum();
        rc_bit_i.xor(&AB::Expr::from(local.a_prime_prime_0_0_bits[i]))
    };
    builder.assert_zeros::<U64_LIMBS, _>(core::array::from_fn(|limb| {
        let computed = (limb * BPL..(limb + 1) * BPL)
            .rev()
            .fold(AB::Expr::ZERO, |acc, z| acc.double() + get_xored_bit(z));
        computed - local.a_prime_prime_prime_0_0_limbs[limb]
    }));

    // Within a permutation: this round's output equals the next round's input.
    for x in 0..5 {
        for y in 0..5 {
            builder
                .when(transition_and_not_final.clone())
                .assert_zeros::<U64_LIMBS, _>(core::array::from_fn(|limb| {
                    local.a_prime_prime_prime(y, x, limb) - next.a[y][x][limb]
                }));
        }
    }
}

impl<AB: AirBuilder> Air<AB> for ShakeThreadedAir
where
    AB::F: PrimeField64,
{
    fn eval(&self, builder: &mut AB) {
        // ---- the full vendored Keccak-f[1600] permutation AIR on every 24-row group ----
        eval_keccak::<AB>(builder);

        // ---- the sponge threading layer ----
        let rl = self.rate_lanes;
        let rbits = self.rate_bits();
        let na = self.num_absorb();
        let ns = self.num_squeeze;
        let pis: Vec<AB::Expr> = (0..self.num_pis()).map(|k| builder.public_values()[k].into()).collect();
        let prep: Vec<AB::Var> = builder.preprocessed().current_slice().to_vec();
        let main = builder.main();
        let row = main.current_slice();
        let nxt = main.next_slice();
        let lk: &KeccakCols<AB::Var> = row[..NUM_KECCAK_COLS].borrow();
        let nk: &KeccakCols<AB::Var> = nxt[..NUM_KECCAK_COLS].borrow();
        let one = AB::Expr::ONE;

        // booleanity of every extra bit column (state bits + block bits; zero off-boundary).
        for i in 0..2 * rbits {
            let b: AB::Expr = row[NUM_KECCAK_COLS + i].into();
            builder.assert_zero(b.clone() * (b - one.clone()));
        }

        // bit accessors over the flat little-endian layout: bit i of the rate region is
        // byte i/8, bit i%8 — equivalently lane i/64, limb (i%64)/16, limb-bit i%16.
        let sbit = |i: usize| -> AB::Expr { row[self.x_state() + i].into() };
        let bbit = |i: usize| -> AB::Expr { row[self.x_block() + i].into() };
        let pow2 = |j: usize| AB::Expr::from_u64(1u64 << j);
        // recomposed 16-bit limbs (lane l, limb m) of the block bits / state bits / their XOR
        // (`a+b−2ab` per bit) — every operand bit is boolean-constrained above, so each
        // recomposed value is < 2¹⁶ < p and field equality is exact integer equality.
        let block_limb = |l: usize, m: usize| -> AB::Expr {
            (0..BPL).fold(AB::Expr::ZERO, |acc, j| acc + bbit(l * 64 + m * BPL + j) * pow2(j))
        };
        let state_limb = |l: usize, m: usize| -> AB::Expr {
            (0..BPL).fold(AB::Expr::ZERO, |acc, j| acc + sbit(l * 64 + m * BPL + j) * pow2(j))
        };
        let xor_limb = |l: usize, m: usize| -> AB::Expr {
            (0..BPL).fold(AB::Expr::ZERO, |acc, j| {
                let i = l * 64 + m * BPL + j;
                acc + sbit(i).xor(&bbit(i)) * pow2(j)
            })
        };

        // block-byte statement binding: message bytes == publics, pad bytes pinned bit-wise.
        let bind_block = |builder: &mut AB, f: &AB::Expr, k: usize| {
            for (i, disp) in self.block_bytes(k) {
                match disp {
                    Ok(pi) => {
                        let byte =
                            (0..8).fold(AB::Expr::ZERO, |acc, t| acc + bbit(i * 8 + t) * pow2(t));
                        builder.assert_zero(f.clone() * (byte - pis[pi].clone()));
                    }
                    Err(c) => {
                        for t in 0..8 {
                            let cb = AB::Expr::from_u64(((c >> t) & 1) as u64);
                            builder.assert_zero(f.clone() * (bbit(i * 8 + t) - cb));
                        }
                    }
                }
            }
        };

        // (1) row 0 — first absorb into the ALL-ZERO initial state: preimage == 0 ⊕ block₀.
        let f0: AB::Expr = prep[self.p_abs0()].into();
        for (l, m, is_rate) in input_wires(rl) {
            let pre: AB::Expr = lk.preimage[l / 5][l % 5][m].into();
            if is_rate {
                builder.assert_zero(f0.clone() * (pre - block_limb(l, m)));
            } else {
                builder.assert_zero(f0.clone() * pre); // capacity lanes of the zero state
            }
        }
        bind_block(builder, &f0, 0);

        // (2) absorb boundaries: last row of perm k−1 (flag) → first row of perm k.
        for k in 1..na {
            let f: AB::Expr = prep[self.p_abs(k)].into();
            // bind the state bits to THIS perm's actual output (rate lanes, per limb) …
            for l in 0..rl {
                for m in 0..U64_LIMBS {
                    let out: AB::Expr = lk.a_prime_prime_prime(l / 5, l % 5, m).into();
                    builder.assert_zero(f.clone() * (state_limb(l, m) - out));
                }
            }
            // … then thread: next.preimage == out ⊕ blockₖ (rate) / out (capacity).
            for (l, m, is_rate) in input_wires(rl) {
                let pre: AB::Expr = nk.preimage[l / 5][l % 5][m].into();
                if is_rate {
                    builder.assert_zero(f.clone() * (pre - xor_limb(l, m)));
                } else {
                    let out: AB::Expr = lk.a_prime_prime_prime(l / 5, l % 5, m).into();
                    builder.assert_zero(f.clone() * (pre - out));
                }
            }
            bind_block(builder, &f, k);
        }

        // (3) squeeze boundaries: identity threading (NO xor), all 25 lanes.
        for j in 1..ns {
            let f: AB::Expr = prep[self.p_sqz(j)].into();
            for (l, m, _) in input_wires(rl) {
                let pre: AB::Expr = nk.preimage[l / 5][l % 5][m].into();
                let out: AB::Expr = lk.a_prime_prime_prime(l / 5, l % 5, m).into();
                builder.assert_zero(f.clone() * (pre - out));
            }
        }

        // (4) squeeze outputs: rate lanes of each post-permutation state == public bytes.
        for j in 0..ns {
            let f: AB::Expr = prep[self.p_out(j)].into();
            for l in 0..rl {
                for m in 0..U64_LIMBS {
                    let out: AB::Expr = lk.a_prime_prime_prime(l / 5, l % 5, m).into();
                    let base = self.pi_out_base() + j * self.rate_bytes() + l * 8 + m * 2;
                    let expect = pis[base].clone() + AB::Expr::from_u64(256) * pis[base + 1].clone();
                    builder.assert_zero(f.clone() * (out - expect));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// Host sponge (the diff-tested oracle) + trace generation
// ---------------------------------------------------------------------------------------

fn keccakf(mut st: [u64; 25]) -> [u64; 25] {
    KeccakF.permute_mut(&mut st);
    st
}

/// FIPS-202 pad10*1 with the SHAKE 0x1F domain byte, split into rate-sized blocks.
fn padded_blocks(msg: &[u8], rate: usize) -> Vec<Vec<u8>> {
    let mut p = msg.to_vec();
    p.push(0x1F);
    while p.len() % rate != 0 {
        p.push(0x00);
    }
    let last = p.len() - 1;
    p[last] |= 0x80;
    p.chunks_exact(rate).map(|c| c.to_vec()).collect()
}

/// XOR a rate block into the little-endian lane state (lane i = bytes [8i, 8i+8)).
fn xor_block_into_state(state: &mut [u64; 25], block: &[u8]) {
    for (i, chunk) in block.chunks(8).enumerate() {
        let mut lane = [0u8; 8];
        lane[..chunk.len()].copy_from_slice(chunk);
        state[i] ^= u64::from_le_bytes(lane);
    }
}

/// Serialize the full 200-byte state, little-endian per lane.
fn state_to_bytes(state: &[u64; 25]) -> [u8; 200] {
    let mut b = [0u8; 200];
    for (i, lane) in state.iter().enumerate() {
        b[i * 8..i * 8 + 8].copy_from_slice(&lane.to_le_bytes());
    }
    b
}

/// The host SHAKE oracle over `p3_keccak::KeccakF` (vendored from shake_sponge.rs) — GATE 1
/// diff-tests it byte-for-byte vs `sha3`, and the trace generator threads the SAME chain.
fn shake_over_keccakf(msg: &[u8], rate: usize, out_len: usize) -> Vec<u8> {
    let mut state = [0u64; 25];
    for block in padded_blocks(msg, rate) {
        xor_block_into_state(&mut state, &block);
        state = keccakf(state);
    }
    let mut out = Vec::with_capacity(out_len);
    loop {
        let take = core::cmp::min(rate, out_len - out.len());
        out.extend_from_slice(&state_to_bytes(&state)[..take]);
        if out.len() == out_len {
            break;
        }
        state = keccakf(state);
    }
    out
}

fn ref_shake(msg: &[u8], rate: usize, out_len: usize) -> Vec<u8> {
    let mut o = vec![0u8; out_len];
    if rate == 136 {
        let mut h = Shake256::default();
        h.update(msg);
        h.finalize_xof().read(&mut o);
    } else {
        let mut h = Shake128::default();
        h.update(msg);
        h.finalize_xof().read(&mut o);
    }
    o
}

/// Which sponge-state wire to corrupt (negatives). Every permutation in the corrupted chain
/// stays INTERNALLY valid and all downstream states/publics are recomputed consistently, so
/// exactly one flavor of threading constraint is violated.
#[derive(Clone, Copy, PartialEq)]
enum Corrupt {
    None,
    /// flip a RATE-lane bit of the input to absorb perm 2 (the perm-1 → perm-2 wire).
    Thread,
    /// flip bit 0 of the 0x1F domain byte in the final padded block.
    Pad,
    /// flip a CAPACITY-lane bit of the input to absorb perm 2 (pass-through wire).
    Cap,
    /// flip a bit of the state threaded between squeeze blocks (perm A−1 → perm A wire).
    Squeeze,
    /// flip a squeeze-output PUBLIC byte (trace stays fully valid).
    Out,
}

/// The sponge chain: padded blocks, per-permutation input states, per-permutation outputs.
struct Chain {
    blocks: Vec<Vec<u8>>,
    inputs: Vec<[u64; 25]>,
    outs: Vec<[u64; 25]>,
}

fn build_chain(air: &ShakeThreadedAir, msg: &[u8], corrupt: Corrupt) -> Chain {
    let rate = air.rate_bytes();
    let mut blocks = padded_blocks(msg, rate);
    let na = blocks.len();
    assert_eq!(na, air.num_absorb());
    if corrupt == Corrupt::Pad {
        // the 0x1F domain byte lives in the final block at in-block position msg_len % rate
        let pos = msg.len() % rate;
        blocks[na - 1][pos] ^= 0x01;
    }
    let mut inputs = Vec::new();
    let mut outs = Vec::new();
    let mut st = [0u64; 25];
    for (k, block) in blocks.iter().enumerate() {
        let mut inp = st;
        xor_block_into_state(&mut inp, block);
        if k == 2 {
            match corrupt {
                Corrupt::Thread => inp[3] ^= 1 << 5,                  // rate lane
                Corrupt::Cap => inp[air.rate_lanes + 2] ^= 1 << 7,    // capacity lane
                _ => {}
            }
        }
        inputs.push(inp);
        st = keccakf(inp);
        outs.push(st);
    }
    for _j in 1..air.num_squeeze {
        let mut inp = st;
        if corrupt == Corrupt::Squeeze {
            inp[6] ^= 1 << 9;
        }
        inputs.push(inp);
        st = keccakf(inp);
        outs.push(st);
    }
    Chain { blocks, inputs, outs }
}

/// Squeeze output bytes of the chain (S full rate blocks, from the outputs of the last S perms).
fn chain_out_bytes(air: &ShakeThreadedAir, chain: &Chain) -> Vec<u8> {
    let rate = air.rate_bytes();
    let na = air.num_absorb();
    (0..air.num_squeeze)
        .flat_map(|j| state_to_bytes(&chain.outs[na - 1 + j])[..rate].to_vec())
        .collect()
}

/// Wide trace: the `p3-keccak-air` trace (its own generator, incl. valid dummy-perm padding)
/// widened with the boundary-row extra columns.
fn generate<F: PrimeField64>(air: &ShakeThreadedAir, chain: &Chain) -> RowMajorMatrix<F> {
    let kc = generate_trace_rows::<F>(chain.inputs.clone(), 0);
    let h = air.height();
    assert_eq!(kc.height(), h, "keccak trace height != instance height");
    let w = air.total_width();
    let mut vals = F::zero_vec(h * w);
    for r in 0..h {
        vals[r * w..r * w + NUM_KECCAK_COLS]
            .copy_from_slice(&kc.values[r * NUM_KECCAK_COLS..(r + 1) * NUM_KECCAK_COLS]);
    }
    fn put_bits<F: PrimeField64>(vals: &mut [F], w: usize, row: usize, base: usize, bytes: &[u8]) {
        for (i, &bv) in bytes.iter().enumerate() {
            for t in 0..8 {
                vals[row * w + base + i * 8 + t] = F::from_u64(((bv >> t) & 1) as u64);
            }
        }
    }
    let rate = air.rate_bytes();
    put_bits(&mut vals, w, 0, air.x_block(), &chain.blocks[0]);
    for k in 1..air.num_absorb() {
        let r = NUM_ROUNDS * k - 1; // last row of perm k−1 = the absorb-boundary row
        put_bits(&mut vals, w, r, air.x_state(), &state_to_bytes(&chain.outs[k - 1])[..rate]);
        put_bits(&mut vals, w, r, air.x_block(), &chain.blocks[k]);
    }
    // squeeze boundaries need no extra columns: identity threading is direct limb equality.
    RowMajorMatrix::new(vals, w)
}

// ---------------------------------------------------------------------------------------
// Gates
// ---------------------------------------------------------------------------------------

/// GATE 4 — constraint-coverage self-audit. `eval` emits exactly one gated equality per
/// `input_wires` entry per boundary event and one binding per `block_bytes` entry, so
/// auditing the enumerations audits the emitted threading-constraint set.
fn self_audit(air: &ShakeThreadedAir, label: &str) {
    let rl = air.rate_lanes;
    let na = air.num_absorb();
    let ns = air.num_squeeze;
    let rate = air.rate_bytes();

    // every (lane, limb) of a boundary bound exactly once, with the right rate/capacity split
    let wires = input_wires(rl);
    assert_eq!(wires.len(), 25 * U64_LIMBS, "expected 100 input wires per boundary");
    let mut seen = [[false; U64_LIMBS]; 25];
    for &(l, m, is_rate) in &wires {
        assert!(!seen[l][m], "duplicate wire ({l},{m})");
        seen[l][m] = true;
        assert_eq!(is_rate, l < rl, "rate/capacity split wrong at lane {l}");
    }
    assert!(seen.iter().all(|r| r.iter().all(|&x| x)), "unbound (lane,limb) input wire");

    // every byte of every absorbed block bound exactly once (public message byte or pinned
    // pad constant), and the pad constants MATCH the diff-tested host padder (pad10*1/0x1F).
    let dummy = vec![0xABu8; air.msg_len];
    let blocks = padded_blocks(&dummy, rate);
    assert_eq!(blocks.len(), na, "block count");
    let (mut n_pi, mut n_pad) = (0usize, 0usize);
    for (k, block) in blocks.iter().enumerate() {
        let bb = air.block_bytes(k);
        assert_eq!(bb.len(), rate, "block {k}: expected {rate} byte bindings");
        let mut cov = vec![false; rate];
        for (i, disp) in bb {
            assert!(!cov[i], "block {k}: duplicate byte binding {i}");
            cov[i] = true;
            match disp {
                Ok(pi) => {
                    assert_eq!(pi, k * rate + i, "block {k} byte {i}: wrong public index");
                    n_pi += 1;
                }
                Err(c) => {
                    assert_eq!(c, block[i], "block {k} byte {i}: pad constant != FIPS-202 pad10*1");
                    n_pad += 1;
                }
            }
        }
        assert!(cov.iter().all(|&x| x), "block {k}: unbound byte");
    }
    assert_eq!(n_pi, air.msg_len, "message-byte public bindings");
    assert_eq!(n_pi + n_pad, na * rate, "total block-byte bindings");

    // boundary events: distinct flag rows, all inside the real (non-padding) region, and
    // every permutation transition is covered by exactly one threading event.
    let mut rows: Vec<(usize, &str)> = vec![(0, "absorb0")];
    for k in 1..na {
        rows.push((NUM_ROUNDS * k - 1, "absorb"));
    }
    for j in 1..ns {
        rows.push((NUM_ROUNDS * (na - 1 + j) - 1, "squeeze"));
    }
    let n_events = rows.len();
    let mut sorted = rows.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), n_events, "duplicate boundary rows");
    assert!(sorted.iter().all(|&(r, _)| r < air.num_perms() * NUM_ROUNDS), "flag outside real rows");
    assert_eq!(n_events, air.num_perms(), "every perm input bound by exactly one event");

    let thread_eqs = n_events * 25 * U64_LIMBS;
    let recomp_eqs = (na - 1) * rl * U64_LIMBS;
    let out_eqs = ns * rl * U64_LIMBS;
    let expected_thread = (1 + (na - 1) + (ns - 1)) * 100;
    assert_eq!(thread_eqs, expected_thread, "threading equality count");
    println!(
        "GATE 4 ok [{label}] — threading self-audit: {thread_eqs} boundary equalities \
         ({n_events} events × 25 lanes × {U64_LIMBS} limbs; rate via XOR, capacity via \
         pass-through), {recomp_eqs} state-bit limb recompositions, {out_eqs} output-limb \
         public bindings, {n_pi} message-byte publics + {n_pad} pinned pad bytes \
         (constants == host pad10*1/0x1F padder); no unbound boundary wire/byte"
    );
}

/// SplitMix64 — tiny deterministic PRNG, no deps (ntt_wired256_air.rs).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn byte(&mut self) -> u8 {
        (self.next() & 0xFF) as u8
    }
}

// ---------------------------------------------------------------------------------------
// STARK config (verbatim from ntt_wired256_air.rs — bench FRI params, NOT production)
// ---------------------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------------------
// Instance runner
// ---------------------------------------------------------------------------------------

fn run_instance(air: &ShakeThreadedAir, corrupt: Corrupt, label: &str) {
    let negative = corrupt != Corrupt::None;
    let rate = air.rate_bytes();
    let (na, ns, h, w) = (air.num_absorb(), air.num_squeeze, air.height(), air.total_width());

    // ---- GATE 4: constraint-coverage self-audit ----
    self_audit(air, label);

    // deterministic instance message
    let mut rng = Rng(0x51AE_C0FFEE_0712_u64 ^ ((air.rate_lanes as u64) << 32) ^ air.msg_len as u64);
    let msg: Vec<u8> = (0..air.msg_len).map(|_| rng.byte()).collect();

    let chain = build_chain(air, &msg, corrupt);
    assert_eq!(chain.inputs.len(), air.num_perms());

    // public values: message bytes ‖ S rate-blocks of squeeze output bytes. For state/pad
    // corruptions the outputs are the CORRUPTED chain's (fully consistent downstream — the
    // proof must be rejected by the ONE violated threading constraint, not by an output
    // mismatch the verifier could not know about).
    let out_bytes = chain_out_bytes(air, &chain);
    let mut pis: Vec<Val> = msg
        .iter()
        .chain(out_bytes.iter())
        .map(|&b| Val::from_u64(b as u64))
        .collect();
    if corrupt == Corrupt::Out {
        pis[air.pi_out_base() + 37] += Val::ONE;
        println!("corrupt-out: squeeze output public byte 37 flipped (trace untouched)");
    }
    assert_eq!(pis.len(), air.num_pis());

    let trace = generate::<Val>(air, &chain);

    // ---- GATE 2 (positive runs): trace ↔ sha3 byte-for-byte diff-test ----
    if !negative {
        let ref_out = ref_shake(&msg, rate, ns * rate);
        assert_eq!(out_bytes, ref_out, "chain squeeze output != sha3");
        assert_eq!(
            shake_over_keccakf(&msg, rate, ns * rate),
            ref_out,
            "host oracle != sha3 on the instance message"
        );
        // re-read the proven trace: row-0 preimage == 0 ⊕ block₀, squeeze rows == sha3 bytes
        let idx: Vec<usize> = (0..NUM_KECCAK_COLS).collect();
        let map: &KeccakCols<usize> = idx[..].borrow();
        let rd = |r: usize, c: usize| trace.values[r * w + c].as_canonical_u64();
        for l in 0..25 {
            for m in 0..U64_LIMBS {
                let expect = (chain.inputs[0][l] >> (16 * m)) & 0xFFFF;
                assert_eq!(rd(0, map.preimage[l / 5][l % 5][m]), expect, "row-0 preimage lane {l} limb {m}");
            }
        }
        for j in 0..ns {
            let r = NUM_ROUNDS * (na + j) - 1;
            for i in 0..rate {
                let (l, m, sh) = (i / 8, (i % 8) / 2, 8 * (i % 2));
                let limb = rd(r, map.a_prime_prime_prime(l / 5, l % 5, m));
                assert_eq!(
                    (limb >> sh) & 0xFF,
                    ref_out[j * rate + i] as u64,
                    "squeeze block {j} byte {i} != sha3"
                );
            }
        }
        println!(
            "GATE 2 ok [{label}] — trace diff-test: row-0 preimage == 0 ⊕ block₀ and all \
             {} squeeze-output bytes re-read from the trace == sha3, byte-for-byte",
            ns * rate
        );
    }

    // ---- prove + verify ----
    let config = make_config();
    let degree_bits = h.ilog2() as usize;
    let (pp_data, pp_vk) =
        setup_preprocessed::<MyConfig, _>(&config, air, degree_bits).expect("preprocessed setup");
    let t0 = std::time::Instant::now();
    let proof = prove_with_preprocessed(&config, air, trace, &pis, Some(&pp_data));
    let t_prove = t0.elapsed();
    let proof_bytes = postcard::to_allocvec(&proof).unwrap().len();
    let t1 = std::time::Instant::now();
    let res = verify_with_preprocessed(&config, air, &proof, &pis, Some(&pp_vk));
    let t_verify = t1.elapsed();
    match res {
        Ok(_) if negative => println!("NEGATIVE TEST FAIL [{label}] — a corrupted SHAKE threading trace was accepted!"),
        Ok(_) => println!(
            "VERIFY ok [{label}] — a COMPLETE multi-block SHAKE computation constrained \
             end-to-end in ONE AIR: {na}-block absorb (pad10*1/0x1F pinned) → Keccak-f[1600] \
             → {ns}-block squeeze, {} permutations in adjacent 24-row groups, every \
             cross-block sponge-state wire bound in-AIR by preprocessed-flag-gated \
             adjacent-row equalities; message + outputs bound to {} public values. \
             [prove {t_prove:.1?}, verify {t_verify:.1?}, {w} cols × {h} rows, prep {}, \
             proof {proof_bytes} bytes]",
            air.num_perms(),
            air.num_pis(),
            air.prep_width(),
        ),
        Err(e) if negative => println!("NEGATIVE TEST PASS [{label}] — corrupted SHAKE threading rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on a valid trace [{label}]: {e:?}"),
    }
}

fn main() {
    let arg = |s: &str| std::env::args().any(|a| a == s);
    let corrupt = if arg("--corrupt-thread") || arg("--corrupt") {
        Corrupt::Thread
    } else if arg("--corrupt-pad") {
        Corrupt::Pad
    } else if arg("--corrupt-cap") {
        Corrupt::Cap
    } else if arg("--corrupt-squeeze") {
        Corrupt::Squeeze
    } else if arg("--corrupt-out") {
        Corrupt::Out
    } else {
        Corrupt::None
    };

    // ---- GATE 1: host sponge oracle diff-test vs sha3 (both rates), edge lengths incl.
    //      rate−1 / rate / rate+1 and multi-block squeeze ----
    let mut rng = Rng(0xC0FFEE_2026_0712);
    let mut cases = 0usize;
    for &rate in &[136usize, 168] {
        for il in [0, 1, rate - 1, rate, rate + 1, 2 * rate, 2 * rate + 28, 3 * rate - 1, 300, 400, 407] {
            for ol in [1, 32, rate, rate + 1, 2 * rate] {
                let msg: Vec<u8> = (0..il).map(|_| rng.byte()).collect();
                assert_eq!(
                    shake_over_keccakf(&msg, rate, ol),
                    ref_shake(&msg, rate, ol),
                    "host sponge != sha3 at rate={rate} in={il} out={ol}"
                );
                cases += 1;
            }
        }
    }
    println!(
        "GATE 1 ok — host sponge oracle matches sha3::Shake256/Shake128 byte-for-byte on \
         {cases} (rate × in-length × out-length) vectors (incl. rate−1/rate/rate+1 pads and \
         2-block squeezes)"
    );

    // PRIMARY: SHAKE256 (the μ/tr/c̃ path) — 3 absorb blocks (pad mid-block) + 2 squeeze
    // blocks = 4 permutations. Negatives run against this instance.
    let primary = ShakeThreadedAir { rate_lanes: 17, msg_len: 300, num_squeeze: 2 };
    if corrupt != Corrupt::None {
        run_instance(&primary, corrupt, "SHAKE256 primary, negative");
        return;
    }
    run_instance(&primary, Corrupt::None, "SHAKE256 rate 136, msg 300 B, A=3 S=2");
    // the 0x9F merged-pad corner: msg_len ≡ rate−1 (mod rate) ⇒ single pad byte 0x1F|0x80
    run_instance(
        &ShakeThreadedAir { rate_lanes: 17, msg_len: 407, num_squeeze: 2 },
        Corrupt::None,
        "SHAKE256 rate 136, msg 407 B (0x9F merged pad), A=3 S=2",
    );
    // SHAKE128 (the ExpandA path): rate is a parameter, same AIR
    run_instance(
        &ShakeThreadedAir { rate_lanes: 21, msg_len: 400, num_squeeze: 2 },
        Corrupt::None,
        "SHAKE128 rate 168, msg 400 B, A=3 S=2",
    );
}
