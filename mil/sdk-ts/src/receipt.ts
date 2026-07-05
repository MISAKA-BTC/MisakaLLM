// MIL Proof-of-Inference receipt: signing-message reconstruction + ML-DSA-87
// verification + monotonic chain (design §4.1). Matches
// `misaka_mil_core::receipt`.

import { ml_dsa87 } from "@noble/post-quantum/ml-dsa";
import { DOMAINS, bytesEqual } from "./hash.ts";

const enc = new TextEncoder();
export const MLDSA87_PK_LEN = 2592;
export const MLDSA87_SIG_LEN = 4627;
export const MIL_PROTOCOL_VERSION = 1;

export interface ReceiptBody {
  version: number;
  sessionId: Uint8Array; // 64
  counter: bigint;
  cumTokensIn: bigint;
  cumTokensOut: bigint;
  timestampMs: bigint;
  cmResp: Uint8Array; // 64
  isFinal: boolean;
}

export interface SignedReceipt {
  body: ReceiptBody;
  signature: Uint8Array; // 4627
  providerPk: Uint8Array; // 2592
}

/** The canonical 163-byte receipt signing transcript (LE ints). */
export function signingMessage(b: ReceiptBody): Uint8Array {
  const msg = new Uint8Array(2 + 64 + 8 * 4 + 64 + 1);
  const dv = new DataView(msg.buffer);
  let off = 0;
  dv.setUint16(off, b.version, true);
  off += 2;
  msg.set(b.sessionId.subarray(0, 64), off);
  off += 64;
  for (const v of [b.counter, b.cumTokensIn, b.cumTokensOut, b.timestampMs]) {
    dv.setBigUint64(off, v, true);
    off += 8;
  }
  msg.set(b.cmResp.subarray(0, 64), off);
  off += 64;
  msg[off] = b.isFinal ? 1 : 0;
  return msg;
}

/** FIPS-204 context-wrapped message representative, matching libcrux's
 *  `sign(sk, m, ctx, r)` domain separation: 0x00 ‖ len(ctx) ‖ ctx ‖ m. */
function contextMessage(message: Uint8Array): Uint8Array {
  const ctx = enc.encode(DOMAINS.RECEIPT_CTX);
  const out = new Uint8Array(2 + ctx.length + message.length);
  out[0] = 0x00;
  out[1] = ctx.length;
  out.set(ctx, 2);
  out.set(message, 2 + ctx.length);
  return out;
}

/** Verify a receipt's ML-DSA-87 signature under the MIL receipt context. */
export function verifyReceipt(r: SignedReceipt): boolean {
  if (r.body.version !== MIL_PROTOCOL_VERSION) return false;
  if (r.providerPk.length !== MLDSA87_PK_LEN || r.signature.length !== MLDSA87_SIG_LEN) return false;
  try {
    // Prefer native context support; fall back to the manual context-wrap if the
    // installed @noble build does not accept a context argument.
    const m = signingMessage(r.body);
    try {
      return ml_dsa87.verify(r.providerPk, m, r.signature, enc.encode(DOMAINS.RECEIPT_CTX));
    } catch {
      return ml_dsa87.verify(r.providerPk, contextMessage(m), r.signature);
    }
  } catch {
    return false;
  }
}

/** Per-session receipt-chain verifier enforcing monotonicity (§4.1). */
export class ReceiptChainVerifier {
  private latest: ReceiptBody | null = null;
  private sessionIdV: Uint8Array;
  private expectedPk: Uint8Array;
  constructor(sessionIdV: Uint8Array, expectedPk: Uint8Array) {
    this.sessionIdV = sessionIdV;
    this.expectedPk = expectedPk;
  }

  ingest(r: SignedReceipt): void {
    if (!bytesEqual(r.providerPk, this.expectedPk)) throw new Error("MIL: provider key mismatch");
    if (!verifyReceipt(r)) throw new Error("MIL: receipt signature invalid");
    if (!bytesEqual(r.body.sessionId, this.sessionIdV)) throw new Error("MIL: session mismatch");
    if (r.body.counter === 0n) throw new Error("MIL: receipt counter must start at 1");
    if (this.latest) {
      if (this.latest.isFinal) throw new Error("MIL: receipt after final");
      if (r.body.counter <= this.latest.counter) throw new Error("MIL: non-monotonic counter");
      if (r.body.cumTokensIn < this.latest.cumTokensIn || r.body.cumTokensOut < this.latest.cumTokensOut) {
        throw new Error("MIL: cumulative tokens decreased");
      }
    }
    this.latest = r.body;
  }

  latestReceipt(): ReceiptBody | null {
    return this.latest;
  }
  isFinalized(): boolean {
    return this.latest?.isFinal ?? false;
  }
}
