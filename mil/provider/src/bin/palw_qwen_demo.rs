//! ADR-0039 PALW — REAL-inference reward-rail demo (design §33 step 3).
//!
//! Runs two independent [`QwenLocalBackend`]s over the SAME local GGUF Qwen model, greedy-decodes a
//! real answer, and proves the full off-chain → on-chain rail on REAL inference:
//!   1. k=2 dispatch: both providers must agree byte-for-byte on all eight [`ReplicaMatchKey`] fields;
//!   2. mint a candidate leaf from the shared match key;
//!   3. build the algo-4 template ticket from the leaf + resolver facts;
//!   4. the validator's full nine-clause `verify_palw_ticket` ACCEPTS it.
//!
//! This is the mock rail (`mock_backend_ticket_construction_equals_validation`) with the deterministic
//! hash swapped for an actual Qwen forward pass — so the "LLM" in proof-of-LLM is real here.
//!
//! ## Run it
//! ```text
//! # 1. get a GGUF Qwen + its tokenizer.json (any Qwen2/2.5; 0.5B is fastest), e.g. from HuggingFace:
//! #    Qwen2.5-0.5B-Instruct-GGUF/qwen2.5-0.5b-instruct-q4_k_m.gguf  +  the repo's tokenizer.json
//! export QWEN_GGUF_PATH=/path/to/qwen2.5-0.5b-instruct-q4_k_m.gguf
//! export QWEN_TOKENIZER_PATH=/path/to/tokenizer.json
//! export QWEN_PROMPT="What is the capital of France? Answer in one word."   # optional
//! cargo run -p misaka-mil-provider --features qwen-metal --bin palw-qwen-demo    # Apple Silicon
//! # (or --features qwen-backend for CPU, --features qwen-cuda for NVIDIA)
//! ```
//! No weights are bundled and none are downloaded — you supply the model file.

use anyhow::{Context, Result, bail};
use kaspa_consensus_core::palw::{
    PalwPublicLeafV1, PalwTicketBinding, palw_select_template_ticket, palw_template_candidate, ticket_nullifier_commitment,
    verify_palw_ticket,
};
use kaspa_consensus_core::tx::{ScriptPublicKey, ScriptVec, TransactionOutpoint};
use kaspa_hashes::{Hash64, blake2b_512_keyed};
use misaka_mil_core::palw::{PalwRuntimeProfileV1, PalwSamplingParams, PalwTier};
use misaka_mil_provider::palw_replica::{ReplicaK2Outcome, dispatch_k2_backends};
use misaka_mil_provider::qwen_backend::QwenLocalBackend;

fn env_path(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("set {key} to the model file path (see the bin docstring)"))
}

fn file_hash(path: &str) -> Result<Hash64> {
    let bytes = std::fs::read(path).with_context(|| format!("read {path}"))?;
    Ok(blake2b_512_keyed(b"palw-qwen-demo/file", &bytes))
}

/// A profile bound to the ACTUAL model files (tokenizer + quantized weights hashed in), so the
/// `runtime_class_id` genuinely reflects this local runtime. Both providers build it identically.
fn profile(tier: PalwTier, gguf_path: &str, tokenizer_path: &str) -> Result<PalwRuntimeProfileV1> {
    Ok(PalwRuntimeProfileV1 {
        version: 1,
        tier,
        model_id: tier.model_id(),
        tokenizer_hash: file_hash(tokenizer_path)?,
        quantization_manifest_hash: file_hash(gguf_path)?,
        runtime_image_hash: blake2b_512_keyed(b"palw-qwen-demo/runtime", b"candle-quantized-qwen2"),
        kernel_graph_hash: blake2b_512_keyed(b"palw-qwen-demo/kernels", b"candle-greedy-argmax"),
        operation_table_hash: Hash64::from_bytes([5; 64]),
        shape_table_hash: Hash64::from_bytes([6; 64]),
        // On ONE machine both providers share the arch class; cross-machine bit-exactness is the
        // deterministic-kernel activation problem (see qwen_backend.rs docstring).
        gpu_arch_class: 100,
        tensor_parallel_degree: 1,
        pipeline_parallel_degree: 1,
        deterministic_reduction: true,
        batch_invariant: true,
        speculative_decode: false,
        sampling: PalwSamplingParams::greedy(),
    })
}

fn main() -> Result<()> {
    let gguf = env_path("QWEN_GGUF_PATH")?;
    let tokenizer = env_path("QWEN_TOKENIZER_PATH")?;
    let prompt = std::env::var("QWEN_PROMPT").unwrap_or_else(|_| "What is the capital of France? Answer in one word.".to_string());
    let max_new_tokens: usize = std::env::var("QWEN_MAX_NEW_TOKENS").ok().and_then(|s| s.parse().ok()).unwrap_or(16);

    // Prefer Metal if this binary was built with it; else CPU.
    let device = QwenLocalBackend::metal_device().unwrap_or_else(|_| QwenLocalBackend::cpu_device());
    println!("== PALW real-inference demo ==");
    println!("model:     {gguf}");
    println!("tokenizer: {tokenizer}");
    println!("prompt:    {prompt:?}");
    println!("device:    {device:?}  max_new_tokens={max_new_tokens}\n");

    let (shape_id, quantum_count) = (3u16, 2u16);
    let prof = profile(PalwTier::Standard, &gguf, &tokenizer)?;
    let mk = || QwenLocalBackend::from_gguf(prof.clone(), &gguf, &tokenizer, shape_id, quantum_count, max_new_tokens, device.clone());

    // Two INDEPENDENT providers of the same class, over the same model.
    let provider_a = mk().context("build provider A")?;
    let provider_b = mk().context("build provider B")?;

    // Show the actual model answer (human-readable) once.
    println!("[inference] provider A answer: {:?}\n", provider_a.answer_text(prompt.as_bytes())?);

    // §7.5 k=2 dispatch on REAL inference. Same job-set / prompt / output salt for both.
    let job_set = b"palw-qwen-demo/job-set";
    let salt = [0x11u8; 32];
    println!("[k=2] dispatching the job to two independent Qwen backends…");
    let key = match dispatch_k2_backends(&provider_a, &provider_b, job_set, prompt.as_bytes(), &salt) {
        ReplicaK2Outcome::Matched(k) => {
            println!("[k=2] MATCH — both providers agreed byte-for-byte on all eight commitment fields.");
            k
        }
        ReplicaK2Outcome::Mismatch => {
            bail!("[k=2] MISMATCH — the two backends disagreed (nondeterminism?); no leaf is minted");
        }
    };

    // Optional: emit the REAL inference-derived leaf commitments (from the k=2 match key) to a JSON fixture
    // that the on-chain algo-4 emitter / consensus E2E reads. This keeps the consensus crate candle-free:
    // it builds the on-chain `PalwPublicLeafV1` from these values instead of running the model itself.
    if let Ok(path) = std::env::var("PALW_LEAF_FIXTURE") {
        let hx = |h: &Hash64| h.as_byte_slice().iter().map(|b| format!("{b:02x}")).collect::<String>();
        let json = format!(
            "{{\n  \"model_profile_id\": \"{}\",\n  \"runtime_class_id\": \"{}\",\n  \"shape_id\": {},\n  \"quantum_count\": {},\n  \"canonical_gemm_trace_root\": \"{}\",\n  \"model_gguf\": {:?},\n  \"source\": \"real k=2 Qwen inference match (palw-qwen-demo)\"\n}}\n",
            hx(&key.model_profile_id),
            hx(&key.runtime_class_id),
            key.shape_id,
            key.quantum_count,
            hx(&key.canonical_gemm_trace_root),
            gguf,
        );
        std::fs::write(&path, json).with_context(|| format!("write fixture {path}"))?;
        println!("[fixture] wrote real-inference leaf commitments -> {path}");
    }

    // Mint an on-chain leaf from the shared match key (the match-derived fields come from `key`).
    let spk = ScriptPublicKey::new(0, ScriptVec::from_slice(&[1]));
    let (batch_id, leaf_index, epoch) = (Hash64::from_bytes([0x10; 64]), 0u32, 5u64);
    let raw_nf = Hash64::from_bytes([0xC0; 64]);
    let leaf = PalwPublicLeafV1 {
        version: 1,
        batch_id,
        leaf_index,
        job_nullifier: Hash64::from_bytes([0x20; 64]),
        ticket_nullifier_commitment: ticket_nullifier_commitment(&raw_nf),
        model_profile_id: key.model_profile_id,
        runtime_class_id: key.runtime_class_id,
        shape_id: key.shape_id,
        quantum_count: key.quantum_count,
        proof_type: 1, // ReplicaExactV1
        provider_a_bond: TransactionOutpoint::new(Hash64::from_bytes([6; 64]), 0),
        provider_b_bond: TransactionOutpoint::new(Hash64::from_bytes([7; 64]), 0),
        provider_a_reward_script: spk.clone(),
        provider_b_reward_script: spk,
        ticket_authority_pk_hash: Hash64::from_bytes([8; 64]),
        private_match_commitment: key.canonical_gemm_trace_root, // binds the leaf to THIS k=2 execution
        receipt_da_root: Hash64::from_bytes([10; 64]),
        registered_epoch: 3,
        activation_epoch: 4,
        expiry_epoch: 12,
        leaf_bond_sompi: 0,
    };
    let leaf_hash = leaf.leaf_hash();
    println!("[leaf]  minted leaf {} (batch {}/{})", short(&leaf_hash), short(&batch_id), leaf_index);

    // Build the algo-4 template ticket and run the validator's full nine-clause rule.
    let (net, eligibility_beacon, chain_commit, interval) = (0x9107u32, Hash64::from_bytes([0x77; 64]), Hash64::from_bytes([0x88; 64]), 600u64);
    let lane_bits = 0x2100ffff_u32; // easy lane target (demo)
    let cand = palw_template_candidate(net, &eligibility_beacon, &chain_commit, interval, &batch_id, leaf_index, &leaf_hash, &raw_nf);
    if palw_select_template_ticket(std::slice::from_ref(&cand), lane_bits) != Some(0) {
        bail!("[ticket] the candidate did not win its eligibility draw");
    }
    let binding = PalwTicketBinding {
        ticket_nullifier_commitment: leaf.ticket_nullifier_commitment,
        proof_type: leaf.proof_type,
        leaf_activation_epoch: leaf.activation_epoch,
        leaf_expiry_epoch: leaf.expiry_epoch,
        target_daa_interval: interval,
    };
    let cert_active = leaf.activation_epoch <= epoch && epoch < leaf.expiry_epoch;
    verify_palw_ticket(
        &raw_nf, leaf.proof_type, &chain_commit, lane_bits, cand.nonce, interval, &cand.eligibility_digest, &binding, cert_active, epoch,
        &chain_commit, lane_bits, true,
    )
    .map_err(|e| anyhow::anyhow!("[ticket] validator REJECTED: {e:?}"))?;

    println!("[ticket] VALID — the algo-4 header built from a REAL-inference k=2 match passes all nine validator clauses.");
    println!("\n✅ real Qwen inference → k=2 match → leaf → valid algo-4 ticket.");
    Ok(())
}

fn short(h: &Hash64) -> String {
    let b = h.as_byte_slice();
    format!("{:02x}{:02x}{:02x}{:02x}…", b[0], b[1], b[2], b[3])
}
