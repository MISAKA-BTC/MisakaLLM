//! ADR-0039 PALW — the REAL local Qwen inference backend (design §33 step 3: the activation
//! implementation of the [`VerifiableInferenceBackend`] contract the mock froze first).
//!
//! [`MockDeterministicRuntime`](crate::palw_replica::MockDeterministicRuntime) proves the k=2
//! replica rail with a deterministic *hash* standing in for the model. This backend replaces that
//! hash with a real Qwen forward pass: it loads a GGUF-quantized Qwen (the design's `MISAKA-QW*-PALW`
//! tiers ship Q4), greedy-decodes a fixed number of output tokens, and folds THOSE REAL TOKENS into
//! `output_commitment`. Everything downstream — the k=2 exact matcher, the on-chain leaf, the
//! nine-clause `verify_palw_ticket` — is unchanged, because this implements the exact same trait.
//!
//! ## What is real here, and the determinism boundary (be precise)
//! - REAL: the output tokens (an actual model forward pass) → `output_commitment`; a provider that
//!   runs a different model / different prompt / computes a wrong answer produces different tokens and
//!   the k=2 dispatch mismatches (no leaf), exactly as the design requires.
//! - LOCAL determinism holds: greedy decode (argmax, no sampling) on ONE machine is reproducible, so
//!   two `QwenLocalBackend`s over the same GGUF exact-match. The `mock_backend`-style CPU-reference
//!   proof therefore now runs on real inference.
//! - NOT yet solved (the actual PALW research crux): CROSS-machine bit-exact agreement. Floating-point
//!   matmul is not bit-identical across GPUs / BLAS / kernel versions, so two providers on *different*
//!   hardware need the design's batch-invariant deterministic kernels (§6.4) before they reliably
//!   exact-match. This backend does not claim to solve that; it makes the inference real and the local
//!   rail end-to-end, which is the step before the deterministic-kernel work.
//! - The `canonical_gemm_trace_root` / `operation_schedule_commitment` here commit to the real output
//!   tokens + the runtime class (not a low-level per-matmul GEMM trace). A true GEMM-trace Merkle root
//!   is a separate activation task (§7.4); this is faithful to "same class + same output" matching.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail, ensure};
use candle_core::quantized::gguf_file;
use candle_core::{D, DType, Device, IndexOp, Tensor};
use candle_transformers::models::quantized_qwen2::ModelWeights;
use kaspa_hashes::{Hash64, blake2b_512_keyed};
use misaka_mil_core::palw::{
    DeterministicInferenceOutputV1, PalwOperationCountersV1, PalwRuntimeProfileV1, gemm_trace_root, operation_schedule_commitment,
    output_commitment,
};
use tokenizers::Tokenizer;

use crate::palw_replica::VerifiableInferenceBackend;

/// Real-backend domain separators (mirror the mock's, distinct so a real key never collides with a
/// mock key by construction). NOT consensus domains — these feed the `misaka-mil-core::palw`
/// commitment helpers, which apply the on-chain domains.
const QWEN_TRACE_DOMAIN: &[u8] = b"palw-qwen/gemm-trace";
const QWEN_SCHED_DOMAIN: &[u8] = b"palw-qwen/op-schedule";
/// §7.4-lite — the compute-level trace domain: a commitment over the ACTUAL computed logits at every step
/// (not merely the argmax'd tokens), so two stacks that produce identical tokens but different logits get
/// DIFFERENT values. Strictly stronger than the output-token commitment.
const QWEN_LOGITS_DOMAIN: &[u8] = b"palw-qwen/logits-trace";

/// A real Qwen provider runtime: a pinned [`PalwRuntimeProfileV1`] plus a local GGUF model + tokenizer.
/// `run_verifiable` performs an actual greedy forward pass. The model is reloaded per call so each run
/// starts from a clean KV cache (determinism over speed — this is a reference/demo backend, not the
/// production hot loop).
pub struct QwenLocalBackend {
    profile: PalwRuntimeProfileV1,
    shape_id: u16,
    quantum_count: u16,
    /// Fixed number of output tokens to greedy-decode. Fixed (not EOS-terminated) so the two replicas
    /// produce the same length deterministically; the answer is the decoded prefix.
    max_new_tokens: usize,
    gguf_path: PathBuf,
    device: Device,
    tokenizer: Tokenizer,
}

impl QwenLocalBackend {
    /// CPU device (works everywhere; slow for big models). Use [`Self::metal_device`] on Apple Silicon.
    pub fn cpu_device() -> Device {
        Device::Cpu
    }

    /// Apple-Silicon Metal device (requires the `qwen-metal` feature). Falls back to an error if the
    /// crate was built without Metal.
    pub fn metal_device() -> Result<Device> {
        #[cfg(feature = "qwen-metal")]
        {
            Device::new_metal(0).map_err(|e| anyhow!("metal device: {e}"))
        }
        #[cfg(not(feature = "qwen-metal"))]
        {
            bail!("built without the `qwen-metal` feature — rebuild with --features qwen-metal, or use cpu_device()")
        }
    }

    /// NVIDIA CUDA device (requires the `qwen-cuda` feature). Used by the K1 harness on an RTX/CUDA host.
    pub fn cuda_device() -> Result<Device> {
        #[cfg(feature = "qwen-cuda")]
        {
            Device::new_cuda(0).map_err(|e| anyhow!("cuda device: {e}"))
        }
        #[cfg(not(feature = "qwen-cuda"))]
        {
            bail!("built without the `qwen-cuda` feature — rebuild with --features qwen-cuda, or use cpu_device()")
        }
    }

    /// Load a GGUF-quantized Qwen model + its `tokenizer.json`. `gguf_path` is a `*.gguf` Qwen2/2.5
    /// weight file; `tokenizer_path` the matching HF `tokenizer.json`.
    pub fn from_gguf(
        profile: PalwRuntimeProfileV1,
        gguf_path: impl AsRef<Path>,
        tokenizer_path: impl AsRef<Path>,
        shape_id: u16,
        quantum_count: u16,
        max_new_tokens: usize,
        device: Device,
    ) -> Result<Self> {
        ensure!(max_new_tokens > 0, "max_new_tokens must be > 0");
        let gguf_path = gguf_path.as_ref().to_path_buf();
        // Validate the GGUF is loadable up front (a fast fail with a clear message).
        Self::load_model(&gguf_path, &device).context("loading GGUF weights")?;
        let tokenizer =
            Tokenizer::from_file(tokenizer_path.as_ref()).map_err(|e| anyhow!("loading tokenizer.json: {e}"))?;
        Ok(Self { profile, shape_id, quantum_count, max_new_tokens, gguf_path, device, tokenizer })
    }

    fn load_model(gguf_path: &Path, device: &Device) -> Result<ModelWeights> {
        let mut file = std::fs::File::open(gguf_path).with_context(|| format!("open {}", gguf_path.display()))?;
        let content = gguf_file::Content::read(&mut file).map_err(|e| anyhow!("read gguf: {e}"))?;
        ModelWeights::from_gguf(content, &mut file, device).map_err(|e| anyhow!("from_gguf: {e}"))
    }

    /// Greedy-decode `max_new_tokens` output tokens for `prompt` from a freshly-loaded model (clean KV
    /// cache ⇒ deterministic). Pure argmax — no temperature, no sampling.
    fn greedy_decode(&self, prompt: &[u8]) -> Result<Vec<u32>> {
        let prompt_str = std::str::from_utf8(prompt).context("prompt must be valid UTF-8")?;
        let enc = self.tokenizer.encode(prompt_str, true).map_err(|e| anyhow!("tokenize: {e}"))?;
        let prompt_ids: Vec<u32> = enc.get_ids().to_vec();
        ensure!(!prompt_ids.is_empty(), "prompt tokenized to zero tokens");

        let mut model = Self::load_model(&self.gguf_path, &self.device)?;
        let mut out = Vec::with_capacity(self.max_new_tokens);

        // Prefill the prompt, then autoregress from the last-position logits.
        let input = Tensor::new(prompt_ids.as_slice(), &self.device)?.unsqueeze(0)?;
        let logits = model.forward(&input, 0).map_err(|e| anyhow!("forward(prefill): {e}"))?;
        let mut next = argmax_last(&logits)?;
        let mut pos = prompt_ids.len();
        for _ in 0..self.max_new_tokens {
            out.push(next);
            let input = Tensor::new(&[next], &self.device)?.unsqueeze(0)?;
            let logits = model.forward(&input, pos).map_err(|e| anyhow!("forward(decode): {e}"))?;
            pos += 1;
            next = argmax_last(&logits)?;
        }
        Ok(out)
    }

    /// Decode the greedy output tokens back to text (for the demo / human inspection). Best-effort.
    pub fn answer_text(&self, prompt: &[u8]) -> Result<String> {
        let toks = self.greedy_decode(prompt)?;
        self.tokenizer.decode(&toks, true).map_err(|e| anyhow!("detokenize: {e}"))
    }

    fn output_from_tokens(&self, output_salt: &[u8; 32], tokens: &[u32]) -> DeterministicInferenceOutputV1 {
        let runtime_class_id = self.profile.runtime_class_id();

        // Trace commits to the REAL output tokens + the runtime class: a wrong answer OR a different
        // class changes it (a per-matmul GEMM-trace Merkle root is a separate activation task, §7.4).
        let mut trace_in = Vec::with_capacity(64 + tokens.len() * 4);
        trace_in.extend_from_slice(runtime_class_id.as_byte_slice());
        for t in tokens {
            trace_in.extend_from_slice(&t.to_le_bytes());
        }
        let trace = blake2b_512_keyed(QWEN_TRACE_DOMAIN, &trace_in);

        // Schedule commits to the class + shape + realized output length (the structural shape of the run).
        let mut sched_in = Vec::with_capacity(64 + 6);
        sched_in.extend_from_slice(runtime_class_id.as_byte_slice());
        sched_in.extend_from_slice(&self.shape_id.to_le_bytes());
        sched_in.extend_from_slice(&(tokens.len() as u32).to_le_bytes());
        let sched = blake2b_512_keyed(QWEN_SCHED_DOMAIN, &sched_in);

        DeterministicInferenceOutputV1 {
            output_token_ids: vec![tokens.to_vec()],
            output_commitment: output_commitment(output_salt, tokens),
            canonical_gemm_trace_root: gemm_trace_root(trace.as_byte_slice()),
            operation_schedule_commitment: operation_schedule_commitment(sched.as_byte_slice()),
            operation_counters: PalwOperationCountersV1::default(),
            shape_id: self.shape_id,
            quantum_count: self.quantum_count,
        }
    }

    /// §7.4-lite — a commitment over the ACTUAL computed logits at EVERY forward step (prefill + each
    /// decode step), keyed by the runtime class. Unlike `output_from_tokens` (which commits only to the
    /// argmax'd output tokens), this witnesses the compute PATH: two stacks that greedy-decode to the same
    /// tokens but compute different logits produce DIFFERENT values here. This is the empirical probe for
    /// whether a class's cross-machine match holds at the *compute* level (logits) or only at the *output*
    /// level (tokens). Same fresh-model, clean-KV determinism as `greedy_decode`.
    pub fn logits_trace_commitment(&self, prompt: &[u8]) -> Result<Hash64> {
        let prompt_str = std::str::from_utf8(prompt).context("prompt must be valid UTF-8")?;
        let enc = self.tokenizer.encode(prompt_str, true).map_err(|e| anyhow!("tokenize: {e}"))?;
        let prompt_ids: Vec<u32> = enc.get_ids().to_vec();
        ensure!(!prompt_ids.is_empty(), "prompt tokenized to zero tokens");
        let mut model = Self::load_model(&self.gguf_path, &self.device)?;

        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(self.profile.runtime_class_id().as_byte_slice());

        let input = Tensor::new(prompt_ids.as_slice(), &self.device)?.unsqueeze(0)?;
        let logits = model.forward(&input, 0).map_err(|e| anyhow!("forward(prefill): {e}"))?;
        fold_last_logits(&logits, &mut buf)?;
        let mut next = argmax_last(&logits)?;
        let mut pos = prompt_ids.len();
        for _ in 0..self.max_new_tokens {
            let input = Tensor::new(&[next], &self.device)?.unsqueeze(0)?;
            let logits = model.forward(&input, pos).map_err(|e| anyhow!("forward(decode): {e}"))?;
            fold_last_logits(&logits, &mut buf)?;
            pos += 1;
            next = argmax_last(&logits)?;
        }
        Ok(blake2b_512_keyed(QWEN_LOGITS_DOMAIN, &buf))
    }

    /// Fallible variant of the trait method (the trait's `infer_with_trace` panics on inference error,
    /// which for a demo/reference backend is acceptable; callers that need graceful handling use this).
    pub fn try_infer_with_trace(&self, prompt: &[u8], output_salt: &[u8; 32]) -> Result<DeterministicInferenceOutputV1> {
        let tokens = self.greedy_decode(prompt)?;
        Ok(self.output_from_tokens(output_salt, &tokens))
    }
}

impl VerifiableInferenceBackend for QwenLocalBackend {
    fn profile(&self) -> &PalwRuntimeProfileV1 {
        &self.profile
    }

    fn infer_with_trace(&self, job_set_descriptor: &[u8], prompt: &[u8], output_salt: &[u8; 32]) -> DeterministicInferenceOutputV1 {
        let _ = job_set_descriptor;
        self.try_infer_with_trace(prompt, output_salt)
            .expect("QwenLocalBackend inference failed (see error); use try_infer_with_trace for graceful handling")
    }
}

/// Argmax over the vocab dim of a forward-pass logits tensor, tolerating the common shapes candle
/// quantized models return: `[1, seq, vocab]` (prefill) or `[1, vocab]` (single-step decode).
fn argmax_last(logits: &Tensor) -> Result<u32> {
    let l = logits.to_dtype(DType::F32).map_err(|e| anyhow!("logits to f32: {e}"))?;
    let row = match l.rank() {
        3 => {
            let seq = l.dim(1).map_err(|e| anyhow!("dim: {e}"))?;
            l.i((0, seq - 1, ..)).map_err(|e| anyhow!("index: {e}"))?
        }
        2 => l.i((0, ..)).map_err(|e| anyhow!("index: {e}"))?,
        1 => l,
        r => bail!("unexpected logits rank {r}"),
    };
    let idx = row.argmax(D::Minus1).map_err(|e| anyhow!("argmax: {e}"))?.to_scalar::<u32>().map_err(|e| anyhow!("to_scalar: {e}"))?;
    Ok(idx)
}

/// Append the last-position logits row (f32, little-endian) to `buf` — the compute-level fold for
/// [`QwenLocalBackend::logits_trace_commitment`]. Same last-row selection as `argmax_last`.
fn fold_last_logits(logits: &Tensor, buf: &mut Vec<u8>) -> Result<()> {
    let l = logits.to_dtype(DType::F32).map_err(|e| anyhow!("logits to f32: {e}"))?;
    let row = match l.rank() {
        3 => {
            let seq = l.dim(1).map_err(|e| anyhow!("dim: {e}"))?;
            l.i((0, seq - 1, ..)).map_err(|e| anyhow!("index: {e}"))?
        }
        2 => l.i((0, ..)).map_err(|e| anyhow!("index: {e}"))?,
        1 => l,
        r => bail!("unexpected logits rank {r}"),
    };
    let v: Vec<f32> = row.to_vec1().map_err(|e| anyhow!("logits to_vec1: {e}"))?;
    buf.reserve(v.len() * 4);
    for x in v {
        buf.extend_from_slice(&x.to_le_bytes());
    }
    Ok(())
}
