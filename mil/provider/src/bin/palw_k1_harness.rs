//! ADR-0039 Canonical Compute v1 K1 harness — real Qwen single-node determinism + V_i generation +
//! peak-VRAM, on a CUDA/RTX host (`docs/design/misaka-canonical-compute-v1.md` §15 K1 / (A)-2).
//!
//! This is the RUN that needs a GPU (the harness LOGIC is unit-tested with the mock in
//! `palw_determinism.rs`; this bin drives it against the REAL Qwen backend). It reports the three things a
//! `PalwComputeSetRecordV1` commit needs measured:
//!   1. **K1 single-node determinism** — generate a golden vector set `V_i` from the reference stack, then
//!      re-run the SAME backend over `V_i` `--repeats` times and assert byte-exact reproduction every time
//!      (fresh KV cache per run). A single divergence ⇒ the stack is not K1-deterministic (fix before any
//!      set commit).
//!   2. **two-instance agreement** — a second independent backend of the same class reproduces `V_i`
//!      (the k=2 property on one machine; cross-MACHINE K2 needs a second same-SKU host and is out of scope).
//!   3. **peak VRAM** — sampled from `nvidia-smi` during the runs, the participation-floor input (§15).
//!
//! Output is a JSON report on stdout (paste it back to integrate the real set-record values). Nothing is
//! committed on-chain; this only measures.
//!
//! ## Run it (on the RTX host)
//! ```text
//! export QWEN_GGUF_PATH=/path/to/qwen2.5-7b-instruct-q4_k_m.gguf   # QW9-class; 0.5B to smoke-test
//! export QWEN_TOKENIZER_PATH=/path/to/tokenizer.json
//! export QWEN_MAX_NEW_TOKENS=16 QWEN_REPEATS=5
//! cargo run --release -p misaka-mil-provider --features qwen-cuda --bin palw-k1-harness
//! ```

use anyhow::{Context, Result, bail};
use kaspa_hashes::{Hash64, blake2b_512_keyed};
use misaka_mil_core::palw::{DeterministicInferenceOutputV1, PalwRuntimeProfileV1, PalwSamplingParams, PalwTier};
use misaka_mil_provider::palw_determinism::{
    ConformanceReport, ConformanceVector, ShapeVramMeasurement, check_conformance, generate_conformance_vectors,
    palw_class_vram_floor_bytes,
};
use misaka_mil_provider::palw_replica::VerifiableInferenceBackend;
use misaka_mil_provider::qwen_backend::QwenLocalBackend;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

fn env_path(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("set {key} (see the bin docstring)"))
}
fn file_hash(path: &str) -> Result<Hash64> {
    Ok(blake2b_512_keyed(b"palw-k1/file", &std::fs::read(path).with_context(|| format!("read {path}"))?))
}

/// A profile bound to the actual model files, so `runtime_class_id` reflects this runtime (the k=2 pair
/// build it identically). `shape_id` is the fixed shape under test (§9).
fn profile(gguf: &str, tokenizer: &str, shape_id: u16) -> Result<PalwRuntimeProfileV1> {
    Ok(PalwRuntimeProfileV1 {
        version: 1,
        tier: PalwTier::Quality,
        model_id: PalwTier::Quality.model_id(),
        tokenizer_hash: file_hash(tokenizer)?,
        quantization_manifest_hash: file_hash(gguf)?,
        runtime_image_hash: blake2b_512_keyed(b"palw-k1/runtime", b"candle-quantized-qwen2"),
        kernel_graph_hash: blake2b_512_keyed(b"palw-k1/kernels", b"candle-greedy-argmax"),
        operation_table_hash: Hash64::from_bytes([5; 64]),
        shape_table_hash: Hash64::from_bytes([shape_id as u8; 64]),
        gpu_arch_class: 100,
        tensor_parallel_degree: 1,
        pipeline_parallel_degree: 1,
        deterministic_reduction: true,
        batch_invariant: true,
        speculative_decode: false,
        sampling: PalwSamplingParams::greedy(),
    })
}

/// The committed `V_i` commitment (§13 `vector_commitment`): fold each vector's model-opaque output
/// commitments in order. Two conformant stacks on the same jobs produce the SAME value.
fn commit_v_i(v: &[ConformanceVector]) -> Hash64 {
    let mut p = Vec::new();
    for cv in v {
        let e: &DeterministicInferenceOutputV1 = &cv.expected;
        p.extend_from_slice(e.output_commitment.as_byte_slice());
        p.extend_from_slice(e.canonical_gemm_trace_root.as_byte_slice());
        p.extend_from_slice(e.operation_schedule_commitment.as_byte_slice());
    }
    blake2b_512_keyed(b"palw-k1/vector-commitment", &p)
}

/// Sample `nvidia-smi` GPU memory-used (MiB) in a background thread, tracking the peak. Portable (no CUDA
/// crate); returns a (stop_flag, peak_bytes) pair — set the flag and join to finalize. If `nvidia-smi` is
/// absent (e.g. a CPU smoke test), the peak stays 0 and is reported as unmeasured.
fn start_vram_sampler() -> (Arc<AtomicBool>, Arc<AtomicU64>, std::thread::JoinHandle<()>) {
    let stop = Arc::new(AtomicBool::new(false));
    let peak = Arc::new(AtomicU64::new(0));
    let (s, p) = (stop.clone(), peak.clone());
    let handle = std::thread::spawn(move || {
        while !s.load(Ordering::Relaxed) {
            if let Ok(out) = std::process::Command::new("nvidia-smi")
                .args(["--query-gpu=memory.used", "--format=csv,noheader,nounits"])
                .output()
            {
                if let Ok(txt) = String::from_utf8(out.stdout) {
                    if let Ok(mib) = txt.trim().lines().next().unwrap_or("0").trim().parse::<u64>() {
                        let bytes = mib * 1024 * 1024;
                        p.fetch_max(bytes, Ordering::Relaxed);
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    });
    (stop, peak, handle)
}

fn main() -> Result<()> {
    let gguf = env_path("QWEN_GGUF_PATH")?;
    let tokenizer = env_path("QWEN_TOKENIZER_PATH")?;
    let max_new_tokens: usize = std::env::var("QWEN_MAX_NEW_TOKENS").ok().and_then(|s| s.parse().ok()).unwrap_or(16);
    let repeats: usize = std::env::var("QWEN_REPEATS").ok().and_then(|s| s.parse().ok()).unwrap_or(5);
    let shape_id: u16 = 9; // the QW9 fixed shape under test
    // PARTICIPANT VERIFICATION: set QWEN_EXPECT_COMMITMENT to your class's PUBLISHED vector_commitment; the
    // harness prints conformance PASS/FAIL and exits non-zero on FAIL, so a provider can self-check that
    // their stack reproduces the class's golden vectors before registering (§14). QWEN_CLASS is a label.
    let expect = std::env::var("QWEN_EXPECT_COMMITMENT").ok().map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty());
    let class_label = std::env::var("QWEN_CLASS").unwrap_or_else(|_| "unspecified".to_string());

    // CUDA on the RTX host; fall back to Metal / CPU so the harness is runnable anywhere for a smoke test.
    let device = QwenLocalBackend::cuda_device()
        .or_else(|_| QwenLocalBackend::metal_device())
        .unwrap_or_else(|_| QwenLocalBackend::cpu_device());
    eprintln!("[k1] device={device:?} model={gguf} max_new_tokens={max_new_tokens} repeats={repeats}");

    let prof = profile(&gguf, &tokenizer, shape_id)?;
    let mk = || QwenLocalBackend::from_gguf(prof.clone(), &gguf, &tokenizer, shape_id, 2, max_new_tokens, device.clone());

    let (stop, peak, sampler) = start_vram_sampler();

    // Reference stack generates the golden vector set V_i (a handful of fixed jobs).
    let reference = mk().context("build reference backend")?;
    let jobs: Vec<(Vec<u8>, Vec<u8>, [u8; 32])> = [
        ("What is the capital of France? Answer in one word.", [0x11u8; 32]),
        ("Name the largest planet in the solar system.", [0x22u8; 32]),
        ("2+2=?", [0x33u8; 32]),
    ]
    .iter()
    .map(|(prompt, salt)| (b"palw-k1/job-set".to_vec(), prompt.as_bytes().to_vec(), *salt))
    .collect();
    let v_i = generate_conformance_vectors(&reference, &jobs);
    let commitment = commit_v_i(&v_i);
    eprintln!("[k1] generated V_i: {} vectors, commitment {}", v_i.len(), short(&commitment));

    // (1) K1 single-node determinism: the SAME backend must reproduce V_i on every repeat.
    let mut k1_deterministic = true;
    let mut k1_first_divergence = String::new();
    for r in 0..repeats {
        match check_conformance(&reference, &v_i) {
            ConformanceReport::Conforms { .. } => {}
            other => {
                k1_deterministic = false;
                k1_first_divergence = format!("repeat {r}: {other:?}");
                break;
            }
        }
    }

    // (2) two-instance agreement on one machine (k=2 property; cross-machine K2 needs a 2nd same-SKU host).
    let second = mk().context("build second backend")?;
    let two_instance_agree = matches!(check_conformance(&second, &v_i), ConformanceReport::Conforms { .. });

    // One trace for a sanity field in the report.
    let answer = reference.infer_with_trace(&jobs[0].0, &jobs[0].1, &jobs[0].2);

    stop.store(true, Ordering::Relaxed);
    let _ = sampler.join();
    let peak_vram_bytes = peak.load(Ordering::Relaxed);
    let vram = if peak_vram_bytes > 0 {
        vec![ShapeVramMeasurement { shape_id, peak_vram_bytes }]
    } else {
        vec![]
    };
    let vram_floor = palw_class_vram_floor_bytes(&vram);

    // Model file hashes so a verifier confirms they ran the SAME pinned model (a wrong model yields a
    // wrong commitment ⇒ FAIL anyway, but these make the mismatch cause obvious).
    let gguf_hash = hex(&file_hash(&gguf)?);
    let tok_hash = hex(&file_hash(&tokenizer)?);
    let commit_hex = hex(&commitment);
    let conformance = match &expect {
        Some(e) if *e == commit_hex => "PASS",
        Some(_) => "FAIL",
        None => "n/a",
    };

    // JSON report — for a provider self-check, compare `vector_commitment` to your class's published value
    // (or set QWEN_EXPECT_COMMITMENT and read `conformance`).
    println!("{{");
    println!("  \"harness\": \"palw-k1\",");
    println!("  \"class\": \"{class_label}\",");
    println!("  \"device\": \"{device:?}\",");
    println!("  \"shape_id\": {shape_id},");
    println!("  \"max_new_tokens\": {max_new_tokens},");
    println!("  \"repeats\": {repeats},");
    println!("  \"model_gguf_hash\": \"{gguf_hash}\",");
    println!("  \"model_tokenizer_hash\": \"{tok_hash}\",");
    println!("  \"v_i_vectors\": {},", v_i.len());
    println!("  \"vector_commitment\": \"{commit_hex}\",");
    println!("  \"expected_commitment\": \"{}\",", expect.as_deref().unwrap_or(""));
    println!("  \"conformance\": \"{conformance}\",");
    println!("  \"k1_single_node_deterministic\": {k1_deterministic},");
    println!("  \"k1_first_divergence\": \"{}\",", k1_first_divergence.replace('"', "'"));
    println!("  \"two_instance_agree\": {two_instance_agree},");
    println!("  \"peak_vram_bytes\": {peak_vram_bytes},");
    println!("  \"vram_floor_bytes\": {vram_floor},");
    println!("  \"first_answer_tokens\": {}", answer.output_token_ids.first().map(|t| t.len()).unwrap_or(0));
    println!("}}");

    if !k1_deterministic {
        bail!("K1 FAILED — the stack is not single-node deterministic: {k1_first_divergence}");
    }
    if conformance == "FAIL" {
        bail!("CONFORMANCE FAILED — this stack's commitment {commit_hex} != the published {} for class '{class_label}'; your stack does not reproduce the class golden vectors (not registerable)", expect.as_deref().unwrap_or(""));
    }
    eprintln!(
        "[k1] OK — single-node deterministic over {repeats} repeats; two-instance agree={two_instance_agree}; conformance={conformance}"
    );
    Ok(())
}

fn short(h: &Hash64) -> String {
    let b = h.as_byte_slice();
    format!("{:02x}{:02x}{:02x}{:02x}…", b[0], b[1], b[2], b[3])
}
fn hex(h: &Hash64) -> String {
    h.as_byte_slice().iter().map(|b| format!("{b:02x}")).collect()
}
