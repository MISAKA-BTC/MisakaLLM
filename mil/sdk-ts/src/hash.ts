// MIL Hash64 identity derivations (design §3.2/§3.3), keyed BLAKE2b-512.
// Matches `misaka_mil_core::{ident, commit}`.

import { blake2b } from "@noble/hashes/blake2b";

const enc = new TextEncoder();

// Domain-separation strings (must equal the Rust `misaka-mil-v1/...` constants).
export const DOMAINS = {
  BIND: "misaka-mil-v1/bind",
  SESSION: "misaka-mil-v1/session",
  COMMIT: "misaka-mil-v1/commit",
  PROMPT_CT: "misaka-mil-v1/commit/prompt-ct",
  TRANSCRIPT: "misaka-mil-v1/transcript",
  PROVIDER_ID: "misaka-mil-v1/provider-id",
  QUOTE: "misaka-mil-v1/quote",
  KDF: "misaka-mil-v1/kdf",
  RECEIPT_CTX: "misaka-mil-v1/receipt/mldsa87",
} as const;

/** keyed BLAKE2b-512 (Hash64): key = domain (<=64 bytes), 64-byte output. */
export function hash64Keyed(domain: string, data: Uint8Array): Uint8Array {
  return blake2b(data, { key: enc.encode(domain), dkLen: 64 });
}

function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** report_data key binding: Hash64_k(bind, pk_kem ‖ pk_receipt). */
export function keyBinding(pkKem: Uint8Array, pkReceipt: Uint8Array): Uint8Array {
  return hash64Keyed(DOMAINS.BIND, concat(pkKem, pkReceipt));
}

/** provider id: Hash64_k(provider-id, pk_receipt). */
export function providerId(pkReceipt: Uint8Array): Uint8Array {
  return hash64Keyed(DOMAINS.PROVIDER_ID, pkReceipt);
}

/** session id: Hash64_k(session, quote_hash ‖ kem_ct ‖ nonce_req). */
export function sessionId(quoteHash: Uint8Array, kemCt: Uint8Array, nonceReq: Uint8Array): Uint8Array {
  return hash64Keyed(DOMAINS.SESSION, concat(quoteHash, kemCt, nonceReq));
}

/** inner prompt-ciphertext hash H(prompt_ct). */
export function promptCtHash(promptCt: Uint8Array): Uint8Array {
  return hash64Keyed(DOMAINS.PROMPT_CT, promptCt);
}

/** salted request commitment cm_req = Hash64_k(commit, salt ‖ H(prompt_ct)). */
export function requestCommitment(salt: Uint8Array, promptCtHashV: Uint8Array): Uint8Array {
  return hash64Keyed(DOMAINS.COMMIT, concat(salt, promptCtHashV));
}

export function requestCommitmentForCt(salt: Uint8Array, promptCt: Uint8Array): Uint8Array {
  return requestCommitment(salt, promptCtHash(promptCt));
}

/** Incremental response-transcript hasher producing cm_resp_k. The Rust hasher
 *  seeds the keyed BLAKE2b-512 state with the session id, then absorbs each
 *  response chunk; `commitment()` == blake2b(session_id ‖ chunks, key=TRANSCRIPT). */
export class TranscriptHasher {
  private absorbed: Uint8Array;
  constructor(sessionIdV: Uint8Array) {
    this.absorbed = new Uint8Array(sessionIdV); // seed prefix = session id
  }
  absorb(chunk: Uint8Array): void {
    const next = new Uint8Array(this.absorbed.length + chunk.length);
    next.set(this.absorbed);
    next.set(chunk, this.absorbed.length);
    this.absorbed = next;
  }
  commitment(): Uint8Array {
    return hash64Keyed(DOMAINS.TRANSCRIPT, this.absorbed);
  }
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function toHex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

export function fromHex(h: string): Uint8Array {
  const clean = h.startsWith("0x") ? h.slice(2) : h;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}
