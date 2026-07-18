//! MISAKA PALW §19.5 M1 — candle REFERENCE for the canonical Metal backend. Tokenizes a fixed prompt, runs
//! candle's (CPU) Qwen forward, and dumps the prompt token IDs + the last-position logits so the canonical
//! Swift forward can be checked FAITHFUL (its argmax must match candle's) — separate from the M1↔M4
//! bit-identity check.
//!   QWEN_GGUF_PATH=... QWEN_TOKENIZER_PATH=... PALW_DUMP_DIR=/tmp/qwen05b_fp32 \
//!     cargo run -p misaka-mil-provider --features qwen-backend --bin palw-qwen-ref
use anyhow::{Context, Result, anyhow};
use candle_core::quantized::gguf_file;
use candle_core::{D, DType, Device, IndexOp, Tensor};
use candle_transformers::models::quantized_qwen2::ModelWeights;
use std::io::Write;
use tokenizers::Tokenizer;

fn last_row(logits: &candle_core::Tensor) -> Result<candle_core::Tensor> {
    let l = logits.to_dtype(DType::F32)?;
    Ok(match l.rank() {
        3 => {
            let s = l.dim(1)?;
            l.i((0, s - 1, ..))?
        }
        2 => l.i((0, ..))?,
        _ => l,
    })
}

fn main() -> Result<()> {
    let gguf = std::env::var("QWEN_GGUF_PATH").context("QWEN_GGUF_PATH")?;
    let tok = std::env::var("QWEN_TOKENIZER_PATH").context("QWEN_TOKENIZER_PATH")?;
    let outdir = std::env::var("PALW_DUMP_DIR").context("PALW_DUMP_DIR")?;
    let prompt = std::env::var("PALW_REF_PROMPT").unwrap_or_else(|_| "What is the capital of France? Answer in one word.".to_string());
    let dev = Device::Cpu;

    let mut f = std::fs::File::open(&gguf)?;
    let content = gguf_file::Content::read(&mut f)?;
    let mut model = ModelWeights::from_gguf(content, &mut f, &dev)?;
    let tokenizer = Tokenizer::from_file(&tok).map_err(|e| anyhow!("tokenizer: {e}"))?;

    let ids: Vec<u32> = tokenizer.encode(prompt.as_str(), true).map_err(|e| anyhow!("encode: {e}"))?.get_ids().to_vec();
    println!("prompt: {prompt:?}");
    println!("prompt_ids ({}) = {ids:?}", ids.len());

    // prefill
    let input = Tensor::new(ids.as_slice(), &dev)?.unsqueeze(0)?;
    let logits = model.forward(&input, 0)?;
    let row = last_row(&logits)?;
    let v: Vec<f32> = row.to_vec1()?;
    let mut next = row.argmax(D::Minus1)?.to_scalar::<u32>()?;
    println!("vocab = {}", v.len());
    println!("prefill_argmax = {next}  decoded = {:?}", tokenizer.decode(&[next], false).unwrap_or_default());
    {
        let mut of = std::fs::File::create(format!("{outdir}/ref_logits.bin"))?;
        let mut bytes = Vec::with_capacity(v.len() * 4);
        for x in &v {
            bytes.extend_from_slice(&x.to_le_bytes());
        }
        of.write_all(&bytes)?;
    }

    // greedy generation (candle reference sequence; KV cache via `pos`)
    let gen_n: usize = std::env::var("PALW_GEN_TOKENS").ok().and_then(|s| s.parse().ok()).unwrap_or(24);
    let mut outg = vec![next];
    let mut pos = ids.len();
    for _ in 1..gen_n {
        let inp = Tensor::new(&[next], &dev)?.unsqueeze(0)?;
        let lg = model.forward(&inp, pos)?;
        next = last_row(&lg)?.argmax(D::Minus1)?.to_scalar::<u32>()?;
        outg.push(next);
        pos += 1;
    }
    println!("candle_gen ({}) = {outg:?}", outg.len());
    println!("candle_gen_text = {:?}", tokenizer.decode(&outg, false).unwrap_or_default());

    let js = |xs: &[u32]| format!("[{}]", xs.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(","));
    std::fs::write(format!("{outdir}/prompt_ids.json"), js(&ids))?;
    std::fs::write(format!("{outdir}/candle_gen.json"), js(&outg))?;
    eprintln!("dumped ref_logits + prompt_ids + candle_gen ({} tokens)", outg.len());
    Ok(())
}
