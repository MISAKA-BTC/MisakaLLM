//! SP1 zkVM guest — a REAL zero-knowledge proof of the MIL shielded SPEND relation
//! (ADR-0033 §4.1, 1-in/1-out). The witness (which note, its Merkle path, the spend
//! key) is PRIVATE; only the public statement (anchor/nullifier/cm_new/amounts) is
//! committed. A valid proof ⇔ "a registered note exists that opens to `nullifier`,
//! is under `anchor`, and conserves value into `cm_new`" — WITHOUT revealing which
//! note. Hashing is keyed BLAKE2b-512, byte-identical to `misaka_mil_shield`.
#![no_main]
sp1_zkvm::entrypoint!(main);

use blake2b_simd::Params;

const CM: &[u8] = b"misaka-shield-v1/cm";
const ADDR: &[u8] = b"misaka-shield-v1/addr";
const NF: &[u8] = b"misaka-shield-v1/nf";
const MERKLE: &[u8] = b"misaka-shield-v1/merkle";

fn keyed(ctx: &[u8], data: &[u8]) -> [u8; 64] {
    let h = Params::new().hash_length(64).key(ctx).to_state().update(data).finalize();
    let mut o = [0u8; 64];
    o.copy_from_slice(h.as_bytes());
    o
}
fn commit(value: u64, owner_pk: &[u8; 64], rho: &[u8; 64], r: &[u8; 64], token_id: u32) -> [u8; 64] {
    let mut b = Vec::with_capacity(8 + 64 + 64 + 64 + 4);
    b.extend_from_slice(&value.to_le_bytes());
    b.extend_from_slice(owner_pk);
    b.extend_from_slice(rho);
    b.extend_from_slice(r);
    b.extend_from_slice(&token_id.to_le_bytes());
    keyed(CM, &b)
}
fn addr(sk: &[u8; 64]) -> [u8; 64] {
    keyed(ADDR, sk)
}
fn nullifier(sk: &[u8; 64], rho: &[u8; 64]) -> [u8; 64] {
    let mut b = Vec::with_capacity(128);
    b.extend_from_slice(sk);
    b.extend_from_slice(rho);
    keyed(NF, &b)
}
fn hash_node(l: &[u8; 64], r: &[u8; 64]) -> [u8; 64] {
    let mut b = Vec::with_capacity(128);
    b.extend_from_slice(l);
    b.extend_from_slice(r);
    keyed(MERKLE, &b)
}

struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Cur<'a> {
    fn u32(&mut self) -> u32 {
        let v = u32::from_le_bytes(self.b[self.p..self.p + 4].try_into().unwrap());
        self.p += 4;
        v
    }
    fn u64(&mut self) -> u64 {
        let v = u64::from_le_bytes(self.b[self.p..self.p + 8].try_into().unwrap());
        self.p += 8;
        v
    }
    fn h(&mut self) -> [u8; 64] {
        let mut o = [0u8; 64];
        o.copy_from_slice(&self.b[self.p..self.p + 64]);
        self.p += 64;
        o
    }
}

pub fn main() {
    let input = sp1_zkvm::io::read::<Vec<u8>>();
    let mut c = Cur { b: &input, p: 0 };
    // ---- public statement ----
    let anchor = c.h();
    let nf = c.h();
    let cm_new = c.h();
    let v_pub_in = c.u64();
    let v_pub_out = c.u64();
    let token_id = c.u32();
    // ---- private witness ----
    let in_value = c.u64();
    let in_owner = c.h();
    let in_rho = c.h();
    let in_r = c.h();
    let sk = c.h();
    let out_value = c.u64();
    let out_owner = c.h();
    let out_rho = c.h();
    let out_r = c.h();
    let depth = c.u32() as usize;
    let mut sibs = Vec::with_capacity(depth);
    for _ in 0..depth {
        sibs.push(c.h());
    }
    let index = c.u64();

    // ---- the relation (mirror spend::verify_reference, 1-in/1-out) ----
    // 1. spend authority: owner_pk == H(sk)
    assert_eq!(in_owner, addr(&sk), "spend authority");
    // 2. nullifier is the correct one for (sk, rho)
    assert_eq!(nf, nullifier(&sk, &in_rho), "nullifier");
    // 3. Merkle membership of the consumed commitment under the anchor (hides which)
    let leaf = commit(in_value, &in_owner, &in_rho, &in_r, token_id);
    let mut cur = leaf;
    let mut idx = index;
    for s in &sibs {
        cur = if idx & 1 == 0 { hash_node(&cur, s) } else { hash_node(s, &cur) };
        idx >>= 1;
    }
    assert_eq!(cur, anchor, "merkle membership");
    // 4. output commitment opens to the declared output note
    assert_eq!(cm_new, commit(out_value, &out_owner, &out_rho, &out_r, token_id), "output commitment");
    // 5. value conservation
    assert_eq!(in_value as u128 + v_pub_in as u128, out_value as u128 + v_pub_out as u128, "value conservation");

    // ---- commit the PUBLIC statement (what was proven, over a hidden witness) ----
    let mut pub_out = Vec::with_capacity(64 * 3 + 8 + 8 + 4);
    pub_out.extend_from_slice(&anchor);
    pub_out.extend_from_slice(&nf);
    pub_out.extend_from_slice(&cm_new);
    pub_out.extend_from_slice(&v_pub_in.to_le_bytes());
    pub_out.extend_from_slice(&v_pub_out.to_le_bytes());
    pub_out.extend_from_slice(&token_id.to_le_bytes());
    sp1_zkvm::io::commit_slice(&pub_out);
}
