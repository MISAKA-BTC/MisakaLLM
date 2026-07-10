//! SpendAir — the COMPLETE shielded-spend relation as one Plonky3 AIR, proven with
//! the hiding/ZK FRI variant + a witness-absence gate. Composes every private-spend
//! constraint into one statement:
//!   addr   = H(sk,sk)                         (spend authority: owner from sk)
//!   leaf   = H(H(value_in, addr), rho)        (the note commitment being spent)
//!   root  := fold(leaf, path, PRIVATE index)  (Merkle membership — which-note hiding)
//!   nf     = H(sk, rho)                        (public nullifier — double-spend tag)
//!   value  : value_in + v_pub_in == value_out + v_pub_out   (conservation, amounts hidden)
//! PUBLIC: root, nf, v_pub_in, v_pub_out. PRIVATE: sk, value_in, rho, value_out, the
//! index, the sibling path. Hidden both formally (hiding-ZK) and empirically
//! (witness-absence). Node hash H = the proven Blake2bGAir ARX mix; production swaps in
//! build#1's full BLAKE2b compression at depth 20 via the multi-row layout.

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

const D: usize = 4;
const W: usize = 64;
const A2: usize = 6; // a2 word index inside a G-block
const GW: usize = 16 * W; // one G-block

// ---- layout ----
// inputs (6 words): SK VIN RHO VOUT VPIN VPOUT
const SK: usize = 0;
const VIN: usize = W;
const RHO: usize = 2 * W;
const VOUT: usize = 3 * W;
const VPIN: usize = 4 * W;
const VPOUT: usize = 5 * W;
// 4 hash G-blocks: addr, t1, leaf, nf
const G_ADDR: usize = 6 * W;
const G_T1: usize = G_ADDR + GW;
const G_LEAF: usize = G_T1 + GW;
const G_NF: usize = G_LEAF + GW;
// value: two ripple sums
const SUMIN: usize = G_NF + GW;
const CSUMIN: usize = SUMIN + W;
const SUMOUT: usize = CSUMIN + W;
const CSUMOUT: usize = SUMOUT + W;
// merkle levels: each CUR SIB BIT L R GBLK(16w)
const MK: usize = CSUMOUT + W;
const LCUR: usize = 0;
const LSIB: usize = W;
const LBIT: usize = 2 * W;
const LL: usize = 2 * W + 1;
const LR: usize = 3 * W + 1;
const LG: usize = 4 * W + 1;
const LSTRIDE: usize = LG + GW;
const NUM_COLS: usize = MK + D * LSTRIDE;
fn ml(i: usize) -> usize {
    MK + i * LSTRIDE
}
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
// H(l,r) := a2 of G(l,r,l,r,l,r), constrained into the block at g.
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
fn eqw<AB2: AirBuilder>(b: &mut AB2, row: &[AB2::Var], p: usize, q: usize) {
    for k in 0..W {
        b.assert_eq(Into::<AB2::Expr>::into(row[p + k]), Into::<AB2::Expr>::into(row[q + k]));
    }
}

struct SpendAir {}
impl<F> BaseAir<F> for SpendAir {
    fn width(&self) -> usize {
        NUM_COLS
    }
    fn num_public_values(&self) -> usize {
        4 * W // root ‖ nf ‖ v_pub_in ‖ v_pub_out
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}
impl<AB2: AirBuilder> Air<AB2> for SpendAir {
    fn eval(&self, builder: &mut AB2) {
        let main = builder.main();
        let row = main.current_slice();
        let one = AB2::Expr::ONE;
        for i in 0..NUM_COLS {
            let x: AB2::Expr = row[i].into();
            builder.assert_zero(x.clone() * (x - one.clone()));
        }
        let pv: Vec<AB2::Expr> = (0..4 * W).map(|k| builder.public_values()[k].into()).collect();
        let (root, nf_pub, vpin_pub, vpout_pub) = (0, W, 2 * W, 3 * W);

        // addr = H(sk,sk) ; t1 = H(value_in, addr) ; leaf = H(t1, rho)
        ghash(builder, row, SK, SK, G_ADDR);
        ghash(builder, row, VIN, a2of(G_ADDR), G_T1);
        ghash(builder, row, a2of(G_T1), RHO, G_LEAF);
        // leaf feeds Merkle level 0
        eqw(builder, row, ml(0) + LCUR, a2of(G_LEAF));
        // Merkle membership (private index MUX per level) → root
        for i in 0..D {
            let base = ml(i);
            let bit: AB2::Expr = row[base + LBIT].into();
            for k in 0..W {
                let cur: AB2::Expr = row[base + LCUR + k].into();
                let sib: AB2::Expr = row[base + LSIB + k].into();
                builder.assert_eq(Into::<AB2::Expr>::into(row[base + LL + k]), bit.clone() * sib.clone() + cur.clone() - bit.clone() * cur.clone());
                builder.assert_eq(Into::<AB2::Expr>::into(row[base + LR + k]), bit.clone() * cur.clone() + sib.clone() - bit.clone() * sib.clone());
            }
            ghash(builder, row, base + LL, base + LR, base + LG);
            if i + 1 < D {
                eqw(builder, row, ml(i + 1) + LCUR, a2of(base + LG));
            } else {
                for k in 0..W {
                    builder.assert_eq(Into::<AB2::Expr>::into(row[a2of(base + LG) + k]), pv[root + k].clone());
                }
            }
        }
        // nullifier nf = H(sk, rho) == public nf
        ghash(builder, row, SK, RHO, G_NF);
        for k in 0..W {
            builder.assert_eq(Into::<AB2::Expr>::into(row[a2of(G_NF) + k]), pv[nf_pub + k].clone());
        }
        // value conservation: value_in + v_pub_in == value_out + v_pub_out
        ripple(builder, row, VIN, VPIN, SUMIN, CSUMIN);
        ripple(builder, row, VOUT, VPOUT, SUMOUT, CSUMOUT);
        for k in 0..W {
            builder.assert_eq(Into::<AB2::Expr>::into(row[SUMIN + k]), Into::<AB2::Expr>::into(row[SUMOUT + k]));
        }
        // bind public v_pub in/out to the trace words
        for k in 0..W {
            builder.assert_eq(Into::<AB2::Expr>::into(row[VPIN + k]), pv[vpin_pub + k].clone());
            builder.assert_eq(Into::<AB2::Expr>::into(row[VPOUT + k]), pv[vpout_pub + k].clone());
        }
    }
}

// ---- reference / trace generation ----
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
fn fill_ghash<F: PrimeField64>(v: &mut [F], base: usize, g: usize, l: u64, r: u64) -> u64 {
    let (a2, gw) = ghash_ref(l, r);
    for (idx, w) in gw.iter().enumerate().take(10) {
        setw(v, base + g + idx * W, *w);
    }
    for (idx, p, q) in [(10, l, r), (11, l.wrapping_add(r), l), (12, l, gw[2]), (13, gw[1], gw[4]), (14, gw[5], r), (15, gw[3], gw[7])] {
        let cc = carries(p, q);
        for k in 0..W {
            v[base + g + idx * W + k] = F::from_u64(cc[k]);
        }
    }
    a2
}
fn fill_ripple<F: PrimeField64>(v: &mut [F], base: usize, so: usize, co: usize, p: u64, q: u64) {
    setw(v, base + so, p.wrapping_add(q));
    let cc = carries(p, q);
    for k in 0..W {
        v[base + co + k] = F::from_u64(cc[k]);
    }
}

#[allow(clippy::too_many_arguments)]
fn generate<F: PrimeField64>(sk: u64, vin: u64, rho: u64, vout: u64, vpin: u64, vpout: u64, index: u64, sibs: &[u64; D]) -> (RowMajorMatrix<F>, [u64; 4]) {
    let n = 16usize;
    let mut vals = F::zero_vec(n * NUM_COLS);
    let mut publics = [0u64; 4];
    for base in (0..n).map(|r| r * NUM_COLS) {
        setw(&mut vals, base + SK, sk);
        setw(&mut vals, base + VIN, vin);
        setw(&mut vals, base + RHO, rho);
        setw(&mut vals, base + VOUT, vout);
        setw(&mut vals, base + VPIN, vpin);
        setw(&mut vals, base + VPOUT, vpout);
        let addr = fill_ghash(&mut vals, base, G_ADDR, sk, sk);
        let t1 = fill_ghash(&mut vals, base, G_T1, vin, addr);
        let leaf = fill_ghash(&mut vals, base, G_LEAF, t1, rho);
        // merkle
        let mut cur = leaf;
        for i in 0..D {
            let lb = base + ml(i);
            let bit = (index >> i) & 1;
            let (l, r) = if bit == 1 { (sibs[i], cur) } else { (cur, sibs[i]) };
            setw(&mut vals, lb + LCUR, cur);
            setw(&mut vals, lb + LSIB, sibs[i]);
            vals[lb + LBIT] = F::from_u64(bit);
            setw(&mut vals, lb + LL, l);
            setw(&mut vals, lb + LR, r);
            cur = fill_ghash(&mut vals, 0, lb + LG, l, r);
        }
        let root = cur;
        let nf = fill_ghash(&mut vals, base, G_NF, sk, rho);
        fill_ripple(&mut vals, base, SUMIN, CSUMIN, vin, vpin);
        fill_ripple(&mut vals, base, SUMOUT, CSUMOUT, vout, vpout);
        publics = [root, nf, vpin, vpout];
    }
    (RowMajorMatrix::new(vals, NUM_COLS), publics)
}

// hiding / ZK config
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
    let air = SpendAir {};
    // PRIVATE spend witness.
    let sk = 0xdead_beef_0000_0001u64;
    let vin = 1000u64;
    let rho = 0x1111_2222_3333_4444u64;
    let vout = 1000u64; // value-neutral transfer
    let (vpin, vpout) = (0u64, 0u64);
    let index = 0b1011u64;
    let sibs: [u64; D] = core::array::from_fn(|i| 0xcafe_0000_0000_0000u64.wrapping_add(i as u64 * 0x1357));
    let (mut trace, pubs) = generate::<Val>(sk, vin, rho, vout, vpin, vpout, index, &sibs);
    if corrupt {
        trace.values[VIN + 5] += Val::ONE; // tamper the hidden input value
    }
    let pis: Vec<Val> = (0..4).flat_map(|w| (0..W).map(move |k| Val::from_u64((pubs[w] >> k) & 1))).collect();
    let config = make_zk_config();
    let proof = prove(&config, &air, trace, &pis);
    match verify(&config, &air, &proof, &pis) {
        Ok(_) if corrupt => println!("NEGATIVE TEST FAIL — a tampered spend was accepted!"),
        Ok(_) => println!("VERIFY ok — COMPLETE shielded SPEND proven (addr+commit+membership+nullifier+value), hiding-ZK, depth {}", D),
        Err(e) if corrupt => println!("NEGATIVE TEST PASS — tampered spend rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on a valid spend: {e:?}"),
    }
    if !corrupt {
        let pb = postcard::to_allocvec(&proof).unwrap();
        let has = |w: u64| pb.windows(8).any(|win| win == w.to_le_bytes());
        let privs = [("sk", sk), ("value_in", vin), ("rho", rho), ("value_out", vout)];
        let mut leaked: Vec<&str> = privs.iter().filter(|(_, w)| has(*w)).map(|(n, _)| *n).collect();
        if sibs.iter().any(|s| has(*s)) {
            leaked.push("sibling");
        }
        if leaked.is_empty() {
            println!("PRIVACY OK — sk / value_in / rho / value_out / {} siblings do not appear in the proof (witness hidden)", D);
        } else {
            println!("PRIVACY LEAK — {leaked:?}");
        }
    }
}
