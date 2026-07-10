//! SP1 host — build a VALID shielded-spend witness (byte-identical hashing to
//! `misaka_mil_shield`), then execute + prove + verify a real ZK proof of the spend
//! relation. `--prove` generates the actual STARK proof; without it, `--execute`
//! runs the guest (relation check + cycle count) fast.

use blake2b_simd::Params;
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, ProvingKey, SP1Stdin,
};

const ELF: Elf = include_elf!("milshield-spend-program");

fn keyed(ctx: &[u8], data: &[u8]) -> [u8; 64] {
    let h = Params::new().hash_length(64).key(ctx).to_state().update(data).finalize();
    let mut o = [0u8; 64];
    o.copy_from_slice(h.as_bytes());
    o
}
fn commit(value: u64, owner_pk: &[u8; 64], rho: &[u8; 64], r: &[u8; 64], token_id: u32) -> [u8; 64] {
    let mut b = Vec::new();
    b.extend_from_slice(&value.to_le_bytes());
    b.extend_from_slice(owner_pk);
    b.extend_from_slice(rho);
    b.extend_from_slice(r);
    b.extend_from_slice(&token_id.to_le_bytes());
    keyed(b"misaka-shield-v1/cm", &b)
}
fn addr(sk: &[u8; 64]) -> [u8; 64] {
    keyed(b"misaka-shield-v1/addr", sk)
}
fn nullifier(sk: &[u8; 64], rho: &[u8; 64]) -> [u8; 64] {
    let mut b = Vec::new();
    b.extend_from_slice(sk);
    b.extend_from_slice(rho);
    keyed(b"misaka-shield-v1/nf", &b)
}
fn hash_node(l: &[u8; 64], r: &[u8; 64]) -> [u8; 64] {
    let mut b = Vec::new();
    b.extend_from_slice(l);
    b.extend_from_slice(r);
    keyed(b"misaka-shield-v1/merkle", &b)
}

fn main() {
    sp1_sdk::utils::setup_logger();
    let prove = std::env::args().any(|a| a == "--prove");

    // ---- a valid 1-in/1-out spend witness at Merkle depth 20 ----
    let depth = 20usize;
    let sk = [0x51u8; 64];
    let owner = addr(&sk);
    let in_rho = [0x11u8; 64];
    let in_r = [0x22u8; 64];
    let token_id = 0u32;
    let in_value = 100u64;
    let out_owner = addr(&[0x71u8; 64]);
    let out_rho = [0x31u8; 64];
    let out_r = [0x32u8; 64];
    let out_value = 100u64;
    let (v_pub_in, v_pub_out) = (0u64, 0u64); // a private transfer (value-neutral)

    let nf = nullifier(&sk, &in_rho);
    let leaf = commit(in_value, &owner, &in_rho, &in_r, token_id);
    let index = 0x0A_AAAu64 & ((1u64 << depth) - 1);
    let mut sibs = Vec::with_capacity(depth);
    let mut cur = leaf;
    let mut idx = index;
    for k in 0..depth {
        let s = keyed(b"sib", &[k as u8; 8]);
        sibs.push(s);
        cur = if idx & 1 == 0 { hash_node(&cur, &s) } else { hash_node(&s, &cur) };
        idx >>= 1;
    }
    let anchor = cur;
    let cm_new = commit(out_value, &out_owner, &out_rho, &out_r, token_id);

    // ---- serialize (public ‖ witness), the exact layout the guest parses ----
    let mut blob = Vec::new();
    blob.extend_from_slice(&anchor);
    blob.extend_from_slice(&nf);
    blob.extend_from_slice(&cm_new);
    blob.extend_from_slice(&v_pub_in.to_le_bytes());
    blob.extend_from_slice(&v_pub_out.to_le_bytes());
    blob.extend_from_slice(&token_id.to_le_bytes());
    blob.extend_from_slice(&in_value.to_le_bytes());
    blob.extend_from_slice(&owner);
    blob.extend_from_slice(&in_rho);
    blob.extend_from_slice(&in_r);
    blob.extend_from_slice(&sk);
    blob.extend_from_slice(&out_value.to_le_bytes());
    blob.extend_from_slice(&out_owner);
    blob.extend_from_slice(&out_rho);
    blob.extend_from_slice(&out_r);
    blob.extend_from_slice(&(depth as u32).to_le_bytes());
    for s in &sibs {
        blob.extend_from_slice(s);
    }
    blob.extend_from_slice(&index.to_le_bytes());

    let client = ProverClient::from_env();
    let mut stdin = SP1Stdin::new();
    stdin.write(&blob);

    // execute: fast run of the guest (relation must hold) + cycle count
    let (output, report) = client.execute(ELF, stdin.clone()).run().expect("execute");
    let out = output.as_slice();
    assert_eq!(&out[0..64], &anchor, "committed anchor");
    assert_eq!(&out[64..128], &nf, "committed nullifier");
    assert_eq!(&out[128..192], &cm_new, "committed cm_new");
    println!("EXECUTE ok — relation holds in the zkVM, cycles = {}", report.total_instruction_count());
    println!("committed public statement matches (anchor/nf/cm_new); witness stayed private");

    if prove {
        println!("proving (real STARK)…");
        let pk = client.setup(ELF).expect("setup");
        let proof = client.prove(&pk, stdin).run().expect("prove");
        client.verify(&proof, pk.verifying_key(), None).expect("verify");
        let pb = bincode::serialize(&proof).expect("serialize proof");
        println!("PROVE+VERIFY ok — real ZK proof generated and verified. proof_bytes ~= {}", pb.len());

        // ---- PRIVACY-EFFECTIVENESS TEST (the /goal acceptance gate) ----
        // The private witness must NOT appear verbatim anywhere in the proof. This is
        // a NECESSARY condition for the witness being hidden — its presence would be a
        // definitive leak (the failure mode of the reference proof system). Absence is
        // necessary but not sufficient: formal ZK also needs the hiding FRI variant
        // (Plonky3 `new_benchmark_zk`) in the production circuit.
        let has = |needle: &[u8]| pb.windows(needle.len()).any(|w| w == needle);
        let mut leaked: Vec<&str> = Vec::new();
        for (name, v) in [("sk", &sk), ("owner_pk", &owner), ("in_rho", &in_rho), ("in_r", &in_r), ("out_owner", &out_owner), ("out_rho", &out_rho), ("out_r", &out_r)] {
            if has(v) {
                leaked.push(name);
            }
        }
        let leaked_sibs = sibs.iter().filter(|s| has(*s)).count();
        if leaked.is_empty() && leaked_sibs == 0 {
            println!("PRIVACY OK — no private witness bytes (sk/owner/rho/r + {} Merkle siblings) appear in the proof", sibs.len());
        } else {
            println!("PRIVACY LEAK — witness present: fields={leaked:?}, siblings={leaked_sibs}");
        }
        // Sanity: the PUBLIC statement (nullifier) IS in the committed output, as intended.
        println!("public nullifier in committed output (expected true): {}", output.as_slice().windows(64).any(|w| w == nf));
    }
}
