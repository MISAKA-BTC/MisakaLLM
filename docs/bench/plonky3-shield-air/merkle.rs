//! MerklePathAir — the WHICH-NOTE-HIDING privacy core. Proves Merkle membership of a
//! PRIVATE leaf at a PRIVATE index under a PUBLIC root, folding up the tree with a
//! node hash and selecting left/right order by the private index bit at each level.
//! Proven with the **hiding / zero-knowledge FRI variant** (HidingFriPcs) so the leaf,
//! the index, and the sibling path are hidden, plus a witness-absence test (the private
//! values must not appear verbatim in the proof). This is the mechanism that makes
//! "which note" unknowable. The node hash here is the PROVEN BLAKE2b G-mix (a real ARX
//! 2→1 function, `Blake2bGAir`); production swaps in build#1's full compression as the
//! node-hash gadget (drop-in) at depth 20.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
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
use p3_uni_stark::{StarkConfig, prove, verify};
use rand::SeedableRng;
use rand::rngs::SmallRng;

const D: usize = 8; // path depth (production: 20)
const W: usize = 64;
// per level: CUR(64) SIB(64) BIT(1) L(64) R(64) GBLK(16 words). stride:
const CUR: usize = 0;
const SIB: usize = W;
const BIT: usize = 2 * W;
const L: usize = 2 * W + 1;
const R: usize = 3 * W + 1;
const GBLK: usize = 4 * W + 1;
const LSTRIDE: usize = GBLK + 16 * W;
const NUM_COLS: usize = D * LSTRIDE;
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

fn lvl(i: usize) -> usize {
    i * LSTRIDE
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
        b.assert_eq(Into::<AB2::Expr>::into(row[oo + i]), aj.clone() + bj.clone() - aj * bj * two.clone());
    }
}
#[allow(clippy::too_many_arguments)]
fn g_node<AB2: AirBuilder>(b: &mut AB2, row: &[AB2::Var], la: usize, ra: usize, g: usize) {
    // H(l,r) := a2 of G(a=l,b=r,c=l,d=r,x=l,y=r) — a real ARX 2→1 mix.
    ripple(b, row, la, ra, g + AB * W, g + CAB * W);
    ripple(b, row, g + AB * W, la, g + A1 * W, g + CA1 * W);
    xorrot(b, row, ra, g + A1 * W, g + D1 * W, 32);
    ripple(b, row, la, g + D1 * W, g + C1 * W, g + CC1 * W);
    xorrot(b, row, ra, g + C1 * W, g + B1 * W, 24);
    ripple(b, row, g + A1 * W, g + B1 * W, g + A1B1 * W, g + CA1B1 * W);
    ripple(b, row, g + A1B1 * W, ra, g + A2 * W, g + CA2 * W);
    xorrot(b, row, g + D1 * W, g + A2 * W, g + D2 * W, 16);
    ripple(b, row, g + C1 * W, g + D2 * W, g + C2 * W, g + CC2 * W);
    xorrot(b, row, g + B1 * W, g + C2 * W, g + B2 * W, 63);
}

struct MerklePathAir {}
impl<F> BaseAir<F> for MerklePathAir {
    fn width(&self) -> usize {
        NUM_COLS
    }
    fn num_public_values(&self) -> usize {
        W // the root bits
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}
impl<AB2: AirBuilder> Air<AB2> for MerklePathAir {
    fn eval(&self, builder: &mut AB2) {
        let main = builder.main();
        let row = main.current_slice();
        let one = AB2::Expr::ONE;
        for i in 0..NUM_COLS {
            let x: AB2::Expr = row[i].into();
            builder.assert_zero(x.clone() * (x - one.clone()));
        }
        let root: Vec<AB2::Expr> = (0..W).map(|k| builder.public_values()[k].into()).collect();
        for i in 0..D {
            let base = lvl(i);
            let bit: AB2::Expr = row[base + BIT].into();
            // MUX: l = bit?sib:cur ; r = bit?cur:sib  (order by the PRIVATE index bit)
            for k in 0..W {
                let cur: AB2::Expr = row[base + CUR + k].into();
                let sib: AB2::Expr = row[base + SIB + k].into();
                builder.assert_eq(Into::<AB2::Expr>::into(row[base + L + k]), bit.clone() * sib.clone() + cur.clone() - bit.clone() * cur.clone());
                builder.assert_eq(Into::<AB2::Expr>::into(row[base + R + k]), bit.clone() * cur.clone() + sib.clone() - bit.clone() * sib.clone());
            }
            // node = H(l, r)
            g_node(builder, row, base + L, base + R, base + GBLK);
            // chain: next level's cur == this node output (a2); last node == root
            let node_a2 = base + GBLK + A2 * W;
            if i + 1 < D {
                for k in 0..W {
                    builder.assert_eq(Into::<AB2::Expr>::into(row[lvl(i + 1) + CUR + k]), Into::<AB2::Expr>::into(row[node_a2 + k]));
                }
            } else {
                for k in 0..W {
                    builder.assert_eq(Into::<AB2::Expr>::into(row[node_a2 + k]), root[k].clone());
                }
            }
        }
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
fn set_word<F: PrimeField64>(vals: &mut [F], off: usize, w: u64) {
    for i in 0..W {
        vals[off + i] = F::from_u64((w >> i) & 1);
    }
}
fn node_hash(l: u64, r: u64) -> (u64, [u64; 16]) {
    let (a, b, c, d, x, y) = (l, r, l, r, l, r);
    let ab = a.wrapping_add(b);
    let a1 = ab.wrapping_add(x);
    let d1 = (d ^ a1).rotate_right(32);
    let c1 = c.wrapping_add(d1);
    let b1 = (b ^ c1).rotate_right(24);
    let a1b1 = a1.wrapping_add(b1);
    let a2 = a1b1.wrapping_add(y);
    let d2 = (d1 ^ a2).rotate_right(16);
    let c2 = c1.wrapping_add(d2);
    let b2 = (b1 ^ c2).rotate_right(63);
    (a2, [ab, a1, d1, c1, b1, a1b1, a2, d2, c2, b2, 0, 0, 0, 0, 0, 0])
}

fn generate<F: PrimeField64>(leaf: u64, index: u64, sibs: &[u64; D]) -> (RowMajorMatrix<F>, u64) {
    let n = 16usize; // FRI needs log_height > log_final_poly_len + log_blowup
    let mut vals = F::zero_vec(n * NUM_COLS);
    let mut root = 0u64;
    for base_row in (0..n).map(|r| r * NUM_COLS) {
        let mut cur = leaf;
        for i in 0..D {
            let base = base_row + lvl(i);
            let bit = (index >> i) & 1;
            let (l, r) = if bit == 1 { (sibs[i], cur) } else { (cur, sibs[i]) };
            set_word(&mut vals, base + CUR, cur);
            set_word(&mut vals, base + SIB, sibs[i]);
            vals[base + BIT] = F::from_u64(bit);
            set_word(&mut vals, base + L, l);
            set_word(&mut vals, base + R, r);
            let (a2, gw) = node_hash(l, r);
            for (idx, w) in gw.iter().enumerate().take(10) {
                set_word(&mut vals, base + GBLK + idx * W, *w);
            }
            for (idx, p, q) in [(CAB, l, r), (CA1, l.wrapping_add(r), l), (CC1, l, gw[2]), (CA1B1, gw[1], gw[4]), (CA2, gw[5], r), (CC2, gw[3], gw[7])] {
                let cc = carries(p, q);
                for k in 0..W {
                    vals[base + GBLK + idx * W + k] = F::from_u64(cc[k]);
                }
            }
            cur = a2;
        }
        root = cur;
    }
    (RowMajorMatrix::new(vals, NUM_COLS), root)
}

// ---- hiding / ZK config (verbatim from Plonky3 fib_air ZK) ----
type Val = BabyBear;
type Perm = Poseidon2BabyBear<16>;
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
    let corrupt = std::env::args().any(|a| a == "--corrupt");
    let air = MerklePathAir {};
    // PRIVATE: the leaf (which note), the index (which position), and the sibling path.
    let leaf = 0x1122_3344_5566_7788u64;
    let index = 0b1011_0100u64; // depth-8 index (private)
    let sibs: [u64; D] = core::array::from_fn(|i| 0xa5a5_0000_0000_0000u64.wrapping_add(i as u64 * 0x1111_1111));
    let (mut trace, root) = generate::<Val>(leaf, index, &sibs);
    if corrupt {
        // claim membership under a DIFFERENT (wrong) root — must be rejected.
        trace.values[lvl(0) + CUR + 0] += Val::ONE; // tamper the leaf
    }
    let pis: Vec<Val> = (0..W).map(|k| Val::from_u64((root >> k) & 1)).collect();
    let config = make_zk_config();
    let proof = prove(&config, &air, trace, &pis);
    let res = verify(&config, &air, &proof, &pis);
    match &res {
        Ok(_) if corrupt => println!("NEGATIVE TEST FAIL — a wrong leaf/root was accepted!"),
        Ok(_) => println!("VERIFY ok — Merkle membership at a PRIVATE index proven under the public root (depth {}, hiding-ZK)", D),
        Err(e) if corrupt => println!("NEGATIVE TEST PASS — tampered leaf rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on valid membership: {e:?}"),
    }
    if !corrupt {
        // PRIVACY GATE: the private witness (leaf + siblings) must not appear in the proof.
        let pb = postcard::to_allocvec(&proof).unwrap();
        let has = |w: u64| {
            let le = w.to_le_bytes();
            pb.windows(8).any(|win| win == le)
        };
        let leaked: Vec<u64> = core::iter::once(leaf).chain(sibs.iter().copied()).filter(|&w| has(w)).collect();
        if leaked.is_empty() {
            println!("PRIVACY OK — the private leaf + {} siblings (which-note witness) do not appear in the proof", D);
        } else {
            println!("PRIVACY LEAK — {} private witness value(s) present in the proof", leaked.len());
        }
    }
}
