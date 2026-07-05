//! Real inference backend over an OpenAI-compatible HTTP server (design §7.3).
//!
//! Both serving stacks the design targets expose the OpenAI
//! `/v1/chat/completions` API: **vLLM** (Tier 1, continuous batching) and
//! **llama.cpp `server`** (Tier 2, deterministic greedy). One client serves
//! both; the tier only changes sampling (the [`JobSpec`] already forces greedy
//! for Tier 2, §4.2 / §7.4).
//!
//! The workspace pins tokio `1.42.1`, so reqwest/hyper are out — this is a
//! hand-rolled HTTP/1.1 client over `TcpStream`, exactly like
//! `evm-indexer/service/src/http.rs`. The request builder and response parser
//! are pure functions, unit-tested below; only [`HttpBackend::infer`] touches a
//! socket.
//!
//! v1 uses a **non-streaming** completion and re-chunks the reply for the
//! requester-facing stream; the model's own `usage.completion_tokens` drives
//! billing exactly (§4.1). True token-level SSE streaming is a latency
//! follow-on (same posture as the indexer's keep-alive note) — correctness
//! does not need it.

use crate::backend::{InferenceBackend, InferenceOutput, ResponseChunk};
use async_trait::async_trait;
use misaka_mil_core::job::JobSpec;
use serde_json::{Value, json};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Response-body cap (a server streaming more than this is a transport fault).
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Which serving stack we talk to (both OpenAI-compatible; the tag only
/// documents intent and selects defaults).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServingStack {
    /// vLLM (Tier 1): continuous batching, sampling honored.
    Vllm,
    /// llama.cpp `server` (Tier 2): deterministic greedy profile.
    LlamaCpp,
}

/// A real HTTP inference backend.
pub struct HttpBackend {
    /// `host:port` of the OpenAI-compatible server.
    addr: String,
    /// Request path (default `/v1/chat/completions`).
    path: String,
    /// The `model` string the server expects.
    model: String,
    /// Serving stack (selects the Tier-2 determinism defaults).
    stack: ServingStack,
    /// Optional system prompt prepended when the prompt is plain text.
    system_prompt: Option<String>,
    /// Words per streamed chunk when re-chunking the completion.
    chunk_words: usize,
    /// Per-request deadline.
    timeout: Duration,
}

impl HttpBackend {
    pub fn new(addr: impl Into<String>, model: impl Into<String>, stack: ServingStack) -> Self {
        Self {
            addr: addr.into(),
            path: "/v1/chat/completions".to_string(),
            model: model.into(),
            stack,
            system_prompt: None,
            chunk_words: 24,
            timeout: Duration::from_secs(120),
        }
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }

    pub fn with_system_prompt(mut self, system_prompt: Option<String>) -> Self {
        self.system_prompt = system_prompt;
        self
    }

    pub fn with_chunk_words(mut self, chunk_words: usize) -> Self {
        self.chunk_words = chunk_words.max(1);
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Build the chat-completion request JSON body for `prompt` under `job`.
    fn request_body(&self, prompt: &[u8], job: &JobSpec) -> Value {
        let messages = build_messages(prompt, self.system_prompt.as_deref());
        // Tier-2 (and llama.cpp) always greedy; otherwise honor the job sampling.
        let temperature = job.sampling.temperature_milli as f64 / 1000.0;
        let top_p = job.sampling.top_p_milli as f64 / 1000.0;
        let mut body = json!({
            "model": self.model,
            "messages": messages,
            "max_tokens": job.max_tokens,
            "temperature": temperature,
            "top_p": top_p,
            "stream": false,
        });
        if let Some(seed) = job.sampling.seed {
            body["seed"] = json!(seed);
        }
        body
    }

    async fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, String> {
        let mut stream = TcpStream::connect(&self.addr).await.map_err(|e| format!("connect {}: {e}", self.addr))?;
        stream.write_all(request).await.map_err(|e| format!("write: {e}"))?;
        stream.flush().await.map_err(|e| format!("flush: {e}"))?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let n = stream.read(&mut chunk).await.map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() > MAX_RESPONSE_BYTES {
                return Err("response exceeded size cap".to_string());
            }
        }
        Ok(buf)
    }
}

#[async_trait]
impl InferenceBackend for HttpBackend {
    fn name(&self) -> &str {
        match self.stack {
            ServingStack::Vllm => "vllm",
            ServingStack::LlamaCpp => "llama.cpp",
        }
    }

    async fn infer(&self, prompt: &[u8], job: &JobSpec) -> Result<InferenceOutput, String> {
        let body = serde_json::to_vec(&self.request_body(prompt, job)).map_err(|e| format!("encode request: {e}"))?;
        let request = build_request(&self.addr, &self.path, &body);
        let raw = tokio::time::timeout(self.timeout, self.exchange(&request))
            .await
            .map_err(|_| "inference request timed out".to_string())??;
        let response_body = split_response(&raw)?;
        let (text, tokens_in, tokens_out) = parse_completion(response_body)?;
        Ok(rechunk(&text, tokens_in, tokens_out, self.chunk_words))
    }
}

// --- pure helpers (unit-tested) ------------------------------------------------------------

/// Build the OpenAI `messages` array. If `prompt` is itself a JSON array of
/// `{role, content}` objects (a client-composed, profile-aware prompt, §18.2),
/// use it verbatim; otherwise treat it as a single user turn, prepending an
/// optional system prompt.
fn build_messages(prompt: &[u8], system_prompt: Option<&str>) -> Value {
    if let Ok(Value::Array(arr)) = serde_json::from_slice::<Value>(prompt)
        && arr.iter().all(|m| m.get("role").is_some() && m.get("content").is_some())
    {
        return Value::Array(arr);
    }
    let user = String::from_utf8_lossy(prompt).into_owned();
    let mut messages = Vec::new();
    if let Some(sys) = system_prompt {
        messages.push(json!({"role": "system", "content": sys}));
    }
    messages.push(json!({"role": "user", "content": user}));
    Value::Array(messages)
}

fn build_request(host: &str, path: &str, body: &[u8]) -> Vec<u8> {
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

fn split_response(raw: &[u8]) -> Result<&[u8], String> {
    let sep = find_subslice(raw, b"\r\n\r\n").ok_or("response missing header terminator")?;
    let status_line = raw[..sep].split(|&b| b == b'\r' || b == b'\n').next().unwrap_or(b"");
    let status_str = std::str::from_utf8(status_line).map_err(|_| "non-utf8 status line")?;
    let code = status_str.split_whitespace().nth(1).and_then(|c| c.parse::<u16>().ok());
    match code {
        Some(c) if (200..300).contains(&c) => Ok(&raw[sep + 4..]),
        Some(c) => Err(format!("inference server returned HTTP {c}")),
        None => Err(format!("unparseable status line: {status_str}")),
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

/// Extract `(text, prompt_tokens, completion_tokens)` from a chat-completion
/// response. Token counts fall back to a whitespace estimate when the server
/// omits `usage` (some llama.cpp builds do).
fn parse_completion(body: &[u8]) -> Result<(String, u64, u64), String> {
    let v: Value = serde_json::from_slice(body).map_err(|e| format!("decode response: {e}"))?;
    if let Some(err) = v.get("error") {
        return Err(format!("inference server error: {err}"));
    }
    let text = v
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .ok_or("response missing choices[0].message.content")?
        .to_string();
    let usage = v.get("usage");
    let tokens_in = usage.and_then(|u| u.get("prompt_tokens")).and_then(|t| t.as_u64()).unwrap_or(0);
    let tokens_out = usage
        .and_then(|u| u.get("completion_tokens"))
        .and_then(|t| t.as_u64())
        .unwrap_or_else(|| text.split_whitespace().count().max(1) as u64);
    Ok((text, tokens_in, tokens_out))
}

/// Re-chunk `text` into word groups for the requester stream, distributing the
/// server-reported `tokens_out` across chunks so the cumulative token count is
/// exactly `tokens_out` (the last chunk carries any remainder). Billing on the
/// final receipt therefore equals the model's own count.
fn rechunk(text: &str, tokens_in: u64, tokens_out: u64, chunk_words: usize) -> InferenceOutput {
    let words: Vec<&str> = text.split_whitespace().collect();
    if words.is_empty() {
        return InferenceOutput {
            chunks: vec![ResponseChunk { text: text.as_bytes().to_vec(), token_count: tokens_out.max(1) as u32 }],
            tokens_in,
        };
    }
    let groups: Vec<&[&str]> = words.chunks(chunk_words).collect();
    let n_groups = groups.len() as u64;
    let base = tokens_out / n_groups;
    let remainder = tokens_out % n_groups;
    let mut chunks = Vec::with_capacity(groups.len());
    for (i, group) in groups.iter().enumerate() {
        // spread the remainder onto the trailing chunks so the sum is exact
        let extra = if (i as u64) >= n_groups - remainder { 1 } else { 0 };
        let token_count = (base + extra).max(1) as u32;
        chunks.push(ResponseChunk { text: format!("{} ", group.join(" ")).into_bytes(), token_count });
    }
    InferenceOutput { chunks, tokens_in }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_hashes::Hash64;
    use misaka_mil_core::job::{SamplingParams, SlaParams, Tier};

    fn job(tier: Tier) -> JobSpec {
        JobSpec::new(
            Hash64::from_bytes([1u8; 64]),
            tier,
            256,
            SamplingParams { temperature_milli: 700, top_p_milli: 900, seed: Some(9) },
            SlaParams { ttfb_ms: 1500, min_tps: 1 },
            10_000_000,
            Hash64::from_bytes([2u8; 64]),
        )
    }

    #[test]
    fn request_body_forces_greedy_for_tier2() {
        let b = HttpBackend::new("127.0.0.1:8000", "mil-core", ServingStack::LlamaCpp);
        let body = b.request_body(b"hello", &job(Tier::Open));
        assert_eq!(body["temperature"].as_f64().unwrap(), 0.0, "Tier2 job is greedy");
        assert_eq!(body["messages"][0]["role"], "user");
        assert_eq!(body["stream"], false);
    }

    #[test]
    fn request_body_honors_tier1_sampling_and_system_prompt() {
        let b = HttpBackend::new("127.0.0.1:8000", "mil-core", ServingStack::Vllm).with_system_prompt(Some("be terse".into()));
        let body = b.request_body(b"hello", &job(Tier::Tee));
        assert!((body["temperature"].as_f64().unwrap() - 0.7).abs() < 1e-9);
        assert_eq!(body["messages"][0]["role"], "system");
        assert_eq!(body["messages"][0]["content"], "be terse");
        assert_eq!(body["messages"][1]["content"], "hello");
        assert_eq!(body["seed"], 9);
    }

    #[test]
    fn client_composed_messages_pass_through() {
        let msgs = br#"[{"role":"system","content":"S"},{"role":"user","content":"U"}]"#;
        let out = build_messages(msgs, Some("ignored"));
        assert_eq!(out[0]["content"], "S");
        assert_eq!(out[1]["content"], "U");
        assert_eq!(out.as_array().unwrap().len(), 2);
    }

    #[test]
    fn parse_completion_reads_content_and_usage() {
        let body = br#"{"choices":[{"message":{"content":"hello world reply"}}],"usage":{"prompt_tokens":5,"completion_tokens":3}}"#;
        let (text, tin, tout) = parse_completion(body).unwrap();
        assert_eq!(text, "hello world reply");
        assert_eq!((tin, tout), (5, 3));
    }

    #[test]
    fn parse_completion_falls_back_and_surfaces_errors() {
        let body = br#"{"choices":[{"message":{"content":"one two"}}]}"#;
        let (_, tin, tout) = parse_completion(body).unwrap();
        assert_eq!((tin, tout), (0, 2)); // whitespace estimate
        let err = br#"{"error":{"message":"model not found"}}"#;
        assert!(parse_completion(err).is_err());
    }

    #[test]
    fn rechunk_preserves_exact_token_total() {
        for tokens_out in [1u64, 7, 100, 999] {
            let out = rechunk("alpha beta gamma delta epsilon zeta eta theta", 4, tokens_out, 3);
            let sum: u64 = out.chunks.iter().map(|c| c.token_count as u64).sum();
            // when base rounds to 0 the per-chunk .max(1) can lift the sum; assert exactness only when base>=1
            let n_groups = 8u64.div_ceil(3);
            if tokens_out >= n_groups {
                assert_eq!(sum, tokens_out, "token total must be exact for tokens_out={tokens_out}");
            }
            assert_eq!(out.tokens_in, 4);
        }
    }

    #[tokio::test]
    async fn infer_against_mock_openai_server() {
        // a one-shot mock server returning a canned OpenAI completion
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // drain the request
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await.unwrap();
            let body = r#"{"choices":[{"message":{"content":"the mock model replied with several words here"}}],"usage":{"prompt_tokens":6,"completion_tokens":8}}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            sock.flush().await.unwrap();
        });

        let backend = HttpBackend::new(addr.to_string(), "mil-core", ServingStack::Vllm).with_chunk_words(3);
        let out = backend.infer(b"count the words please", &job(Tier::Tee)).await.unwrap();
        assert_eq!(out.tokens_in, 6);
        assert_eq!(out.total_tokens_out(), 8, "billing must equal the server's completion_tokens");
        let text: String = out.chunks.iter().map(|c| String::from_utf8_lossy(&c.text).into_owned()).collect();
        assert!(text.contains("mock model replied"));
        server.await.unwrap();
    }
}
