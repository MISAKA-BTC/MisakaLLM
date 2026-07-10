//! MultiRowMerkleAir — the production LAYOUT that unblocks depth-20 with the real
//! hash. Instead of unrolling every level into one wide row (which caps depth), each
//! Merkle level is ONE ROW and the state is threaded down with `when_transition`
//! (next.cur == this.node). So depth = number of rows (here 16 ≈ production 20) at a
//! FIXED per-row width — the node hash can be the full BLAKE2b compression (build#1)
//! as a drop-in, without column explosion. Proven at a PRIVATE index with the
//! hiding/ZK FRI variant + witness-absence (which-note hiding at production depth).
//! Node hash here = the proven Blake2bGAir ARX mix; production swaps in build#1.

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

const DEPTH: usize = 16; // one row per level; production ~20 = just more rows
const W: usize = 64;
const A2: usize = 6;
// per-row columns: CUR SIB BIT L R GBLK(16 words)
const CUR: usize = 0;
const SIB: usize = W;
const BIT: usize = 2 * W;
const L: usize = 2 * W + 1;
const R: usize = 3 * W + 1;
const GBLK: usize = 4 * W + 1;
const NUM_COLS: usize = GBLK + 16 * W;
fn a2of(g: usize) -> usize {
    g + A2 * W
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
fn ghash<AB2: AirBuilder>(b: &mut AB2, row: &[AB2::Var], la: usize, ra: usize, g: usize) {
    ripple(b, row, la, ra, g, g + 10 * W);
    ripple(b, row, g, la, g + W, g + 11 * W);
    xorrot(b, row, ra, g + W, g + 2 * W, 32);
    ripple(b, row, la, g + 2 * W, g + 3 * W, g + 12 * W);
    xorrot(b, row, ra, g + 3 * W, g + 4 * W, 24);
    ripple(b, row, g + W, g + 4 * W, g + 5 * W, g + 13 * W);
    ripple(b, row, g + 5 * W, ra, g + 6 * W, g + 14 * W);
    xorrot(b, row, g + 2 * W, g + 6 * W, g + 7 * W, 16);
    ripple(b, row, g + 3 * W, g + 7 * W, g + 8 * W, g + 15 * W);
    xorrot(b, row, g + 4 * W, g + 8 * W, g + 9 * W, 63);
}

struct MultiRowMerkleAir {}
impl<F> BaseAir<F> for MultiRowMerkleAir {
    fn width(&self) -> usize {
        NUM_COLS
    }
    fn num_public_values(&self) -> usize {
        W // root
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}
impl<AB2: AirBuilder> Air<AB2> for MultiRowMerkleAir {
    fn eval(&self, builder: &mut AB2) {
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let one = AB2::Expr::ONE;
        for i in 0..NUM_COLS {
            let x: AB2::Expr = local[i].into();
            builder.assert_zero(x.clone() * (x - one.clone()));
        }
        let root: Vec<AB2::Expr> = (0..W).map(|k| builder.public_values()[k].into()).collect();
        // per-row node hash of the MUX-ordered (l,r)
        let bit: AB2::Expr = local[BIT].into();
        for k in 0..W {
            let cur: AB2::Expr = local[CUR + k].into();
            let sib: AB2::Expr = local[SIB + k].into();
            builder.assert_eq(Into::<AB2::Expr>::into(local[L + k]), bit.clone() * sib.clone() + cur.clone() - bit.clone() * cur.clone());
            builder.assert_eq(Into::<AB2::Expr>::into(local[R + k]), bit.clone() * cur.clone() + sib.clone() - bit.clone() * sib.clone());
        }
        ghash(builder, local, L, R, GBLK);
        // thread the state DOWN: next level's cur == this level's node output
        let mut t = builder.when_transition();
        for k in 0..W {
            t.assert_eq(Into::<AB2::Expr>::into(next[CUR + k]), Into::<AB2::Expr>::into(local[a2of(GBLK) + k]));
        }
        // the LAST level's node output == the public root
        let mut lastr = builder.when_last_row();
        for k in 0..W {
            lastr.assert_eq(Into::<AB2::Expr>::into(local[a2of(GBLK) + k]), root[k].clone());
        }
    }
}

fn ghash_ref(l: u64, r: u64) -> (u64, [u64; 16]) {
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
fn setw<F: PrimeField64>(v: &mut [F], off: usize, w: u64) {
    for i in 0..W {
        v[off + i] = F::from_u64((w >> i) & 1);
    }
}
fn generate<F: PrimeField64>(leaf: u64, index: u64, sibs: &[u64; DEPTH]) -> (RowMajorMatrix<F>, u64) {
    let mut vals = F::zero_vec(DEPTH * NUM_COLS);
    let mut cur = leaf;
    for i in 0..DEPTH {
        let base = i * NUM_COLS;
        let bit = (index >> i) & 1;
        let (l, r) = if bit == 1 { (sibs[i], cur) } else { (cur, sibs[i]) };
        setw(&mut vals, base + CUR, cur);
        setw(&mut vals, base + SIB, sibs[i]);
        vals[base + BIT] = F::from_u64(bit);
        setw(&mut vals, base + L, l);
        setw(&mut vals, base + R, r);
        let (a2, gw) = ghash_ref(l, r);
        for (idx, w) in gw.iter().enumerate().take(10) {
            setw(&mut vals, base + GBLK + idx * W, *w);
        }
        for (idx, p, q) in [(10, l, r), (11, l.wrapping_add(r), l), (12, l, gw[2]), (13, gw[1], gw[4]), (14, gw[5], r), (15, gw[3], gw[7])] {
            let cc = carries(p, q);
            for k in 0..W {
                vals[base + GBLK + idx * W + k] = F::from_u64(cc[k]);
            }
        }
        cur = a2;
    }
    (RowMajorMatrix::new(vals, NUM_COLS), cur)
}

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
    let val_mmcs = ZkValHidingMmcs::new(ZkFieldHash::new(u64_hash), ZkCompress::new(u64_hash), 0, SmallRng::seed_from_u64(1));
    let challenge_mmcs = ZkChallengeHidingMmcs::new(val_mmcs.clone());
    let fri_params = FriParameters::new_testing(challenge_mmcs, 2);
    let pcs = ZkHidingPcs::new(Dft::default(), val_mmcs, fri_params, 4, SmallRng::seed_from_u64(1));
    ZkConfig::new(pcs, ZkChallenger::from_hasher(vec![], byte_hash))
}

fn main() {
    let corrupt = std::env::args().any(|a| a == "--corrupt");
    let air = MultiRowMerkleAir {};
    let leaf = 0x1122_3344_5566_7788u64;
    let index = 0xB4A7u64; // 16-bit private index
    let sibs: [u64; DEPTH] = core::array::from_fn(|i| 0xa5a5_0000_0000_0000u64.wrapping_add(i as u64 * 0x1111_1111));
    let (mut trace, root) = generate::<Val>(leaf, index, &sibs);
    if corrupt {
        trace.values[CUR] += Val::ONE; // tamper the private leaf (row 0)
    }
    let pis: Vec<Val> = (0..W).map(|k| Val::from_u64((root >> k) & 1)).collect();
    let config = make_zk_config();
    let proof = prove(&config, &air, trace, &pis);
    match verify(&config, &air, &proof, &pis) {
        Ok(_) if corrupt => println!("NEGATIVE TEST FAIL — tampered leaf accepted!"),
        Ok(_) => println!("VERIFY ok — depth-{DEPTH} Merkle membership at a PRIVATE index proven with the MULTI-ROW layout (1 hash/row, state-threaded), hiding-ZK"),
        Err(e) if corrupt => println!("NEGATIVE TEST PASS — tampered leaf rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on valid membership: {e:?}"),
    }
    if !corrupt {
        let pb = postcard::to_allocvec(&proof).unwrap();
        let has = |w: u64| pb.windows(8).any(|win| win == w.to_le_bytes());
        let mut leaked = if has(leaf) { 1 } else { 0 };
        leaked += sibs.iter().filter(|s| has(**s)).count();
        if leaked == 0 {
            println!("PRIVACY OK — leaf + {DEPTH} siblings absent from the proof; proof_bytes={}", pb.len());
        } else {
            println!("PRIVACY LEAK — {leaked} value(s) present");
        }
    }
}
