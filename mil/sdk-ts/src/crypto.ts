// MIL data-plane crypto (design §3.2): ML-KEM-1024 encapsulation,
// HKDF-SHA3-512 key schedule, and direction-keyed AES-256-GCM framing.
// Byte-compatible with `misaka_mil_channel::{kem, session, secure}`.

import { ml_kem1024 } from "@noble/post-quantum/ml-kem";
import { hkdf } from "@noble/hashes/hkdf";
import { sha3_512 } from "@noble/hashes/sha3";
import { gcm } from "@noble/ciphers/aes";
import { DOMAINS } from "./hash.ts";

const enc = new TextEncoder();

export const KEM_CT_LEN = 1568;
export const KEM_EK_LEN = 1568;

/** Requester-side ML-KEM-1024 encapsulation to a provider's pk_kem. */
export function encapsulate(pkKem: Uint8Array): { cipherText: Uint8Array; sharedSecret: Uint8Array } {
  const { cipherText, sharedSecret } = ml_kem1024.encapsulate(pkKem);
  return { cipherText, sharedSecret };
}

export const Direction = { ClientToProvider: 0x01, ProviderToClient: 0x02 } as const;
export type Direction = (typeof Direction)[keyof typeof Direction];

/** HKDF-SHA3-512 direction keys, info = "misaka-mil-v1/kdf" ‖ session_id.
 *  Salt = None (RFC5869 → HashLen zeros; matches the Rust `Hkdf::new(None, ss)`). */
export function deriveSessionKeys(sharedSecret: Uint8Array, sessionIdV: Uint8Array): { kC2P: Uint8Array; kP2C: Uint8Array } {
  const info = new Uint8Array(DOMAINS.KDF.length + sessionIdV.length);
  info.set(enc.encode(DOMAINS.KDF));
  info.set(sessionIdV, DOMAINS.KDF.length);
  const okm = hkdf(sha3_512, sharedSecret, undefined, info, 64);
  return { kC2P: okm.slice(0, 32), kP2C: okm.slice(32, 64) };
}

function nonceFor(direction: Direction, seq: bigint): Uint8Array {
  const n = new Uint8Array(12);
  n[0] = direction;
  new DataView(n.buffer).setBigUint64(4, seq, true);
  return n;
}

function aadFor(sessionIdV: Uint8Array, direction: Direction, frameType: number, seq: bigint): Uint8Array {
  const aad = new Uint8Array(74);
  aad.set(sessionIdV.subarray(0, 64), 0);
  aad[64] = direction;
  aad[65] = frameType & 0xff;
  new DataView(aad.buffer).setBigUint64(66, seq, true);
  return aad;
}

/** Sealing half: owns a direction key and a monotonic send counter. */
export class SendCipher {
  private nextSeq = 0n;
  private key: Uint8Array;
  private sessionIdV: Uint8Array;
  private direction: Direction;
  constructor(key: Uint8Array, sessionIdV: Uint8Array, direction: Direction) {
    this.key = key;
    this.sessionIdV = sessionIdV;
    this.direction = direction;
  }

  seal(frameType: number, plaintext: Uint8Array): { seq: bigint; ciphertext: Uint8Array } {
    const seq = this.nextSeq;
    this.nextSeq += 1n;
    const aad = aadFor(this.sessionIdV, this.direction, frameType, seq);
    const ciphertext = gcm(this.key, nonceFor(this.direction, seq), aad).encrypt(plaintext);
    return { seq, ciphertext };
  }
}

/** Opening half: enforces strict in-order sequence numbers. */
export class RecvCipher {
  private expectedSeq = 0n;
  private key: Uint8Array;
  private sessionIdV: Uint8Array;
  private direction: Direction;
  constructor(key: Uint8Array, sessionIdV: Uint8Array, direction: Direction) {
    this.key = key;
    this.sessionIdV = sessionIdV;
    this.direction = direction;
  }

  open(frameType: number, seq: bigint, ciphertext: Uint8Array): Uint8Array {
    if (seq !== this.expectedSeq) {
      throw new Error(`MIL record out of order: expected ${this.expectedSeq}, got ${seq}`);
    }
    const aad = aadFor(this.sessionIdV, this.direction, frameType, seq);
    const plaintext = gcm(this.key, nonceFor(this.direction, seq), aad).decrypt(ciphertext);
    this.expectedSeq += 1n;
    return plaintext;
  }
}
