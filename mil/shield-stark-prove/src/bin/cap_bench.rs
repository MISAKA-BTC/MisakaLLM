//! `mil-stark-cap-bench` — the O-SP-1 cap-feasibility table (ADR-0035).
//!
//! Prints the SOLID per-circuit cost (BLAKE2b-512 compressions derived from the
//! frozen relations) and the resulting proof-size regime for the 32 KiB cap. The
//! one uncertain input — AIR area per compression — is a CLI arg so the measured
//! `.119` bench can feed the real number in; the default is the Keccak-class
//! estimate. This tool does NOT run a prover; it sizes the circuits so the
//! backend decision rests on real structure.

use misaka_mil_shield_stark_prove::cost::{
    DEFAULT_CONSTRAINTS_PER_COMPRESSION, POOL_TREE_DEPTH, mldsa_verify_cost_note,
};
use misaka_mil_shield_stark_prove::{Backend, DA_CAP_BYTES, ProofSizeRegime, cap_feasibility, provider_claim_cost, spend_cost};

fn main() {
    // arg 1 (optional): AIR area per BLAKE2b-512 compression (measured on .119).
    let cpc: u32 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_CONSTRAINTS_PER_COMPRESSION);

    println!("MIL shielded-pool STARK cap-feasibility (ADR-0035 / §SP-0)");
    println!("DA cap = {} KiB per proof   |   area/compression = {cpc} (Keccak-class default)\n", DA_CAP_BYTES / 1024);

    println!("{:<22} {:>6} {:>8} {:>12} {:>7}  regime", "circuit", "hashes", "compr.", "est-area", "2^k");
    println!("{}", "-".repeat(74));
    for c in [spend_cost(POOL_TREE_DEPTH, cpc), provider_claim_cost(POOL_TREE_DEPTH, cpc)] {
        println!(
            "{:<22} {:>6} {:>8} {:>12} {:>7}  {:?}",
            c.circuit, c.hash_calls, c.blake2b_compressions, c.est_constraints, c.est_constraints_pow2, cap_feasibility(&c),
        );
    }

    println!("\nbackend eligibility (SP-05: production soundness must be hash-based):");
    for b in [Backend::CircleStark, Backend::Plonky3, Backend::Risc0, Backend::Sp1] {
        let ok = b.pq_only_subcap_path();
        println!("  {:<12} PQ-only sub-cap path: {}", format!("{b:?}"), if ok { "yes (eligible)" } else { "NO — pairing wrap (oracle only)" });
    }

    println!("\nnote: {}", mldsa_verify_cost_note());
    let spend = spend_cost(POOL_TREE_DEPTH, cpc);
    if cap_feasibility(&spend) == ProofSizeRegime::OverCapNeedsRecursion {
        println!("verdict: spend is OverCapNeedsRecursion → a hash-based STARK recursion layer (SP-05-safe) is required to reach the cap.");
        println!("measured (.119, Plonky3 Circle-STARK/M31, Keccak proxy): flat spend proof = 342 KiB (96-bit) .. 1.56 MB (116-bit) ⇒ ~11-50x over cap. See docs/mil-shield-stark-bench-runbook.md.");
    }
}
