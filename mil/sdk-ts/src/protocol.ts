// MIL wire message codecs (design §2.3/§7.4). Borsh-compatible with the Rust
// `misaka_mil_channel::wire` + `misaka_mil_core::{job, receipt}`.

import { BorshReader, BorshWriter } from "./borsh.ts";
import type { ReceiptBody, SignedReceipt } from "./receipt.ts";

export const MIL_PROTOCOL_VERSION = 1;
export const FT_CLIENT = 0x01;
export const FT_SERVER = 0x02;

export const Tier = { Tee: 0, Open: 1 } as const;
export type Tier = (typeof Tier)[keyof typeof Tier];

export interface SamplingParams {
  temperatureMilli: number;
  topPMilli: number;
  seed: bigint | null;
}

export interface SlaParams {
  ttfbMs: number;
  minTps: number;
}

export interface JobSpec {
  version: number;
  modelId: Uint8Array; // 64
  profileId: Uint8Array | null; // 64
  tier: Tier;
  maxTokens: number;
  sampling: SamplingParams;
  sla: SlaParams;
  priceCapSompi: bigint;
  cmReq: Uint8Array; // 64
}

// --- handshake ---

export function encodeClientHello(nonceReq: Uint8Array): Uint8Array {
  return new BorshWriter().u16(MIL_PROTOCOL_VERSION).fixed(nonceReq).finish();
}

export interface ServerHello {
  version: number;
  attestation: Uint8Array;
  pkKem: Uint8Array;
  pkReceipt: Uint8Array;
}

export function decodeServerHello(buf: Uint8Array): ServerHello {
  const r = new BorshReader(buf);
  return { version: r.u16(), attestation: r.bytes(), pkKem: r.bytes(), pkReceipt: r.bytes() };
}

export function encodeClientKem(kemCt: Uint8Array): Uint8Array {
  return new BorshWriter().bytes(kemCt).finish();
}

// --- encrypted frame ---

export interface EncryptedFrame {
  frameType: number;
  seq: bigint;
  ciphertext: Uint8Array;
}

export function encodeFrame(f: EncryptedFrame): Uint8Array {
  return new BorshWriter().u8(f.frameType).u64(f.seq).bytes(f.ciphertext).finish();
}

export function decodeFrame(buf: Uint8Array): EncryptedFrame {
  const r = new BorshReader(buf);
  return { frameType: r.u8(), seq: r.u64(), ciphertext: r.bytes() };
}

// --- sealed application messages ---

// ClientMsg: 0=Prompt(Vec<u8>), 1=Job(JobSpec), 2=Cancel
export function encodeClientPrompt(prompt: Uint8Array): Uint8Array {
  return new BorshWriter().u8(0).bytes(prompt).finish();
}

export function encodeJobSpec(job: JobSpec): Uint8Array {
  const w = new BorshWriter().u8(1); // ClientMsg::Job tag
  writeJobSpec(w, job);
  return w.finish();
}

function writeJobSpec(w: BorshWriter, j: JobSpec): void {
  w.u16(j.version).fixed(j.modelId);
  w.option(j.profileId, (ww, id) => ww.fixed(id));
  w.u8(j.tier);
  w.u32(j.maxTokens);
  w.u16(j.sampling.temperatureMilli).u16(j.sampling.topPMilli);
  w.option(j.sampling.seed, (ww, s) => ww.u64(s));
  w.u32(j.sla.ttfbMs).u32(j.sla.minTps);
  w.u64(j.priceCapSompi);
  w.fixed(j.cmReq);
}

export function encodeClientCancel(): Uint8Array {
  return new BorshWriter().u8(2).finish();
}

// ServerMsg: 0=Chunk{text,token_count}, 1=Receipt(SignedReceipt), 2=Done{total}, 3=Error(String)
export type ServerMsg =
  | { kind: "chunk"; text: Uint8Array; tokenCount: number }
  | { kind: "receipt"; receipt: SignedReceipt }
  | { kind: "done"; totalTokensOut: bigint }
  | { kind: "error"; message: string };

export function decodeServerMsg(buf: Uint8Array): ServerMsg {
  const r = new BorshReader(buf);
  const tag = r.u8();
  switch (tag) {
    case 0:
      return { kind: "chunk", text: r.bytes(), tokenCount: r.u32() };
    case 1:
      return { kind: "receipt", receipt: readSignedReceipt(r) };
    case 2:
      return { kind: "done", totalTokensOut: r.u64() };
    case 3:
      return { kind: "error", message: r.string() };
    default:
      throw new Error(`MIL: unknown ServerMsg tag ${tag}`);
  }
}

function readReceiptBody(r: BorshReader): ReceiptBody {
  return {
    version: r.u16(),
    sessionId: r.fixed(64),
    counter: r.u64(),
    cumTokensIn: r.u64(),
    cumTokensOut: r.u64(),
    timestampMs: r.u64(),
    cmResp: r.fixed(64),
    isFinal: r.bool(),
  };
}

export function readSignedReceipt(r: BorshReader): SignedReceipt {
  return { body: readReceiptBody(r), signature: r.bytes(), providerPk: r.bytes() };
}

export function encodeSignedReceipt(rec: SignedReceipt): Uint8Array {
  const w = new BorshWriter();
  const b = rec.body;
  w.u16(b.version).fixed(b.sessionId).u64(b.counter).u64(b.cumTokensIn).u64(b.cumTokensOut).u64(b.timestampMs).fixed(b.cmResp).bool(b.isFinal);
  w.bytes(rec.signature).bytes(rec.providerPk);
  return w.finish();
}
