//! MISAKA PALW §19.5 M1 — dump a GGUF Qwen model to raw fp32 tensors + a config manifest, so the canonical
//! (non-candle) Metal backend can load the REAL weights without reimplementing GGUF/Q4 parsing. Candle does
//! the Q4_K_M dequant; we write each tensor as little-endian f32 and a JSON manifest of shapes + config.
//!   QWEN_GGUF_PATH=/path/qwen0.5b-q4.gguf PALW_DUMP_DIR=/tmp/qwen05b_fp32 \
//!     cargo run -p misaka-mil-provider --features qwen-backend --bin palw-qwen-dump
use anyhow::{Context, Result};
use candle_core::Device;
use candle_core::quantized::gguf_file::{self, Value};
use std::io::Write;

fn stringify(v: &Value) -> Option<String> {
    Some(match v {
        Value::U8(x) => x.to_string(),
        Value::I8(x) => x.to_string(),
        Value::U16(x) => x.to_string(),
        Value::I16(x) => x.to_string(),
        Value::U32(x) => x.to_string(),
        Value::I32(x) => x.to_string(),
        Value::U64(x) => x.to_string(),
        Value::I64(x) => x.to_string(),
        Value::F32(x) => format!("{x:?}"),
        Value::F64(x) => format!("{x:?}"),
        Value::Bool(b) => b.to_string(),
        Value::String(s) => format!("{s:?}"),
        Value::Array(_) => return None, // skip arrays (tokenizer vocab etc.)
    })
}

fn main() -> Result<()> {
    let gguf = std::env::var("QWEN_GGUF_PATH").context("set QWEN_GGUF_PATH")?;
    let outdir = std::env::var("PALW_DUMP_DIR").context("set PALW_DUMP_DIR")?;
    std::fs::create_dir_all(&outdir)?;
    let dev = Device::Cpu;
    let mut f = std::fs::File::open(&gguf).with_context(|| format!("open {gguf}"))?;
    let content = gguf_file::Content::read(&mut f).context("read gguf")?;

    let mut man = String::from("{\n  \"metadata\": {\n");
    let mut mkeys: Vec<_> = content.metadata.keys().cloned().collect();
    mkeys.sort();
    let mut first = true;
    for k in &mkeys {
        if k.contains("tokenizer") {
            continue;
        }
        if let Some(s) = stringify(&content.metadata[k]) {
            if !first {
                man.push_str(",\n");
            }
            first = false;
            man.push_str(&format!("    {k:?}: {s}"));
        }
    }
    man.push_str("\n  },\n  \"tensors\": [\n");

    let mut tkeys: Vec<_> = content.tensor_infos.keys().cloned().collect();
    tkeys.sort();
    let mut tfirst = true;
    let mut total_f32 = 0usize;
    for name in &tkeys {
        let qt = content.tensor(&mut f, name, &dev).with_context(|| format!("read tensor {name}"))?;
        let t = qt.dequantize(&dev).with_context(|| format!("dequant {name}"))?;
        let shape = t.dims().to_vec();
        let data = t.flatten_all()?.to_vec1::<f32>()?;
        total_f32 += data.len();
        let fname = name.replace(['/', '.'], "_") + ".bin";
        let mut of = std::fs::File::create(format!("{outdir}/{fname}"))?;
        let mut bytes = Vec::with_capacity(data.len() * 4);
        for x in &data {
            bytes.extend_from_slice(&x.to_le_bytes());
        }
        of.write_all(&bytes)?;
        if !tfirst {
            man.push_str(",\n");
        }
        tfirst = false;
        man.push_str(&format!("    {{ \"name\": {name:?}, \"file\": {fname:?}, \"shape\": {shape:?} }}"));
    }
    man.push_str("\n  ]\n}\n");
    std::fs::write(format!("{outdir}/manifest.json"), man)?;
    eprintln!("dumped {} tensors ({:.1}M f32) to {outdir}", tkeys.len(), total_f32 as f64 / 1e6);
    Ok(())
}
