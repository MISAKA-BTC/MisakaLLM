//! Inference backend abstraction (design §7.3).
//!
//! The v0 sidecar ships a deterministic [`MockBackend`] so the data plane,
//! attestation, and receipt machinery can be exercised end-to-end with no GPU.
//! A real Tier-1 backend (vLLM in the enclave) or Tier-2 backend
//! (llama.cpp greedy) implements the same trait behind an IPC/HTTP shim; the
//! service layer above is backend-agnostic.

use async_trait::async_trait;
use misaka_mil_core::job::JobSpec;

/// One streamed response chunk. `token_count` is the model's own output-token
/// count for this chunk — it drives receipt cadence and billing (§4.1), not a
/// byte count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseChunk {
    pub text: Vec<u8>,
    pub token_count: u32,
}

/// The result of running a job: the response as a chunk stream plus the input
/// token count the backend charged.
#[derive(Debug, Clone)]
pub struct InferenceOutput {
    pub chunks: Vec<ResponseChunk>,
    pub tokens_in: u64,
}

impl InferenceOutput {
    pub fn total_tokens_out(&self) -> u64 {
        self.chunks.iter().map(|c| c.token_count as u64).sum()
    }
}

/// A serving backend. `infer` returns the full response as an ordered chunk
/// stream; the service layer handles encryption, receipt cadence, and framing.
#[async_trait]
pub trait InferenceBackend: Send + Sync {
    /// Human-readable backend name for logs.
    fn name(&self) -> &str;

    /// Run one job. `prompt` is the decrypted request body; `job` is the
    /// (tier-policy-enforced) spec.
    async fn infer(&self, prompt: &[u8], job: &JobSpec) -> Result<InferenceOutput, String>;
}

/// Deterministic development backend: echoes the prompt back as a canned
/// assistant turn, split into fixed-size word chunks so multi-chunk streaming
/// and multi-receipt cadence are exercised. Token counts are deterministic
/// (one token per whitespace-delimited word, min 1), so tests can assert exact
/// receipt boundaries.
pub struct MockBackend {
    /// Words per streamed chunk.
    chunk_words: usize,
}

impl Default for MockBackend {
    fn default() -> Self {
        Self { chunk_words: 32 }
    }
}

impl MockBackend {
    pub fn new(chunk_words: usize) -> Self {
        Self { chunk_words: chunk_words.max(1) }
    }
}

#[async_trait]
impl InferenceBackend for MockBackend {
    fn name(&self) -> &str {
        "mock-echo"
    }

    async fn infer(&self, prompt: &[u8], _job: &JobSpec) -> Result<InferenceOutput, String> {
        let prompt_str = String::from_utf8_lossy(prompt);
        let tokens_in = prompt_str.split_whitespace().count().max(1) as u64;

        // Canned deterministic reply that quotes the prompt back.
        let reply = format!("You said: {}. This is a MIL mock response.", prompt_str.trim());
        let words: Vec<&str> = reply.split_whitespace().collect();

        let mut chunks = Vec::new();
        for group in words.chunks(self.chunk_words) {
            let text = group.join(" ");
            let token_count = group.len() as u32;
            chunks.push(ResponseChunk { text: format!("{text} ").into_bytes(), token_count });
        }
        if chunks.is_empty() {
            chunks.push(ResponseChunk { text: b"(empty)".to_vec(), token_count: 1 });
        }
        Ok(InferenceOutput { chunks, tokens_in })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_hashes::Hash64;
    use misaka_mil_core::job::{SamplingParams, SlaParams, Tier};

    fn job() -> JobSpec {
        JobSpec::new(
            Hash64::from_bytes([1u8; 64]),
            Tier::Open,
            256,
            SamplingParams::greedy(),
            SlaParams { ttfb_ms: 1500, min_tps: 1 },
            1_000_000,
            Hash64::from_bytes([2u8; 64]),
        )
    }

    #[tokio::test]
    async fn mock_backend_is_deterministic_and_chunked() {
        let backend = MockBackend::new(4);
        let a = backend.infer(b"hello there decentralized world", &job()).await.unwrap();
        let b = backend.infer(b"hello there decentralized world", &job()).await.unwrap();
        assert_eq!(a.chunks, b.chunks, "mock backend must be deterministic");
        assert!(a.chunks.len() > 1, "reply must span multiple chunks with chunk_words=4");
        assert_eq!(a.tokens_in, 4);
        assert!(a.total_tokens_out() > 0);
    }
}
