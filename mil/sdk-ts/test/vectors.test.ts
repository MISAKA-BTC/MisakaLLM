// Cross-language conformance: assert the TS SDK derivations, AEAD framing, and
// receipt verification match byte-for-byte the vectors emitted by the Rust
// implementation (misaka-mil-core / misaka-mil-channel). vectors.json is
// generated from the Rust test probes.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { keyBinding, providerId, sessionId, promptCtHash, requestCommitment, fromHex, toHex } from "../src/hash.ts";
import { Direction, SendCipher, deriveSessionKeys } from "../src/crypto.ts";
import { signingMessage, verifyReceipt } from "../src/receipt.ts";

const V = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "vectors.json"), "utf8"));

function repeat(byte: number, n: number): Uint8Array {
  return new Uint8Array(n).fill(byte);
}

test("keyBinding matches Rust", () => {
  const got = keyBinding(repeat(0x11, 1568), repeat(0x22, 2592));
  assert.equal(toHex(got), V.KEY_BINDING);
});

test("providerId matches Rust", () => {
  assert.equal(toHex(providerId(repeat(0x22, 2592))), V.PROVIDER_ID);
});

test("sessionId matches Rust", () => {
  const got = sessionId(repeat(0x07, 64), repeat(0x33, 1568), repeat(0x44, 32));
  assert.equal(toHex(got), V.SESSION_ID);
});

test("promptCtHash + requestCommitment match Rust", () => {
  const pch = promptCtHash(new TextEncoder().encode("hello ct"));
  assert.equal(toHex(pch), V.PROMPT_CT_HASH);
  const cm = requestCommitment(repeat(0x07, 32), pch);
  assert.equal(toHex(cm), V.REQUEST_COMMITMENT);
});

test("HKDF-SHA3-512 session keys match Rust", () => {
  const { kC2P, kP2C } = deriveSessionKeys(repeat(0x01, 32), repeat(0x05, 64));
  assert.equal(toHex(kC2P), V.K_C2P);
  assert.equal(toHex(kP2C), V.K_P2C);
});

test("AES-256-GCM framing matches Rust", () => {
  const sid = repeat(0x05, 64);
  const sc = new SendCipher(fromHex(V.K_C2P), sid, Direction.ClientToProvider);
  const { seq, ciphertext } = sc.seal(1, new TextEncoder().encode("hello"));
  assert.equal(Number(seq), V.AEAD_SEQ);
  assert.equal(toHex(ciphertext), V.AEAD_CT);
});

test("receipt signing message layout matches Rust", () => {
  const body = {
    version: 1,
    sessionId: repeat(0x05, 64),
    counter: 2n,
    cumTokensIn: 10n,
    cumTokensOut: 1024n,
    timestampMs: 1234n,
    cmResp: repeat(0x04, 64),
    isFinal: false,
  };
  assert.equal(toHex(signingMessage(body)), V.RCPT_MSG);
});

test("ML-DSA-87 receipt verification accepts a Rust-signed receipt", () => {
  const receipt = {
    body: {
      version: 1,
      sessionId: repeat(0x05, 64),
      counter: 2n,
      cumTokensIn: 10n,
      cumTokensOut: 1024n,
      timestampMs: 1234n,
      cmResp: repeat(0x04, 64),
      isFinal: false,
    },
    signature: fromHex(V.RCPT_SIG),
    providerPk: fromHex(V.RCPT_PK),
  };
  assert.equal(verifyReceipt(receipt), true, "a valid Rust-signed receipt must verify in TS");

  // tampering the message breaks verification
  const tampered = { ...receipt, body: { ...receipt.body, cumTokensOut: 2048n } };
  assert.equal(verifyReceipt(tampered), false);
});
