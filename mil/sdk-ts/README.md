# @misaka/mil-sdk — MISAKA Inference Lane TypeScript SDK

A local, trust-terminating client for the MISAKA Inference Lane (design §14.2).
It runs the post-quantum data-plane handshake (ML-KEM-1024 + AES-256-GCM),
verifies the provider attestation, streams the chat response, and verifies every
ML-DSA-87 Proof-of-Inference receipt — exposing an OpenAI-compatible surface so
existing apps swap the endpoint and nothing else. Plaintext exists only here and
inside the provider TEE (§15.1).

## Install / test

```
npm install
npm test        # node --test, cross-checks Rust vectors byte-for-byte
```

Crypto is from `@noble/post-quantum` (ML-KEM-1024, ML-DSA-87), `@noble/hashes`
(BLAKE2b, HKDF-SHA3-512), and `@noble/ciphers` (AES-256-GCM) — the same
`@noble` stack the wallet already uses.

## Conformance

`test/vectors.test.ts` asserts, against fixtures emitted by the Rust
implementation, that the TS SDK matches byte-for-byte:

- Hash64 derivations (`keyBinding`, `providerId`, `sessionId`, `promptCtHash`,
  `requestCommitment`),
- the HKDF-SHA3-512 session-key schedule,
- the AES-256-GCM record framing (nonce + AAD layout),
- the 163-byte receipt signing transcript,
- ML-DSA-87 verification of a Rust-signed receipt.

## Usage

```ts
import { MilOpenAI } from "@misaka/mil-sdk";

const mil = new MilOpenAI({ host: "provider.example", port: 37110, modelId: "<64-byte hex>" });
const res = await mil.chatCompletion({
  messages: [{ role: "user", content: "hello" }],
  tier: "open",
});
console.log(res.choices[0].message.content);
console.log("settled on receipt", res.mil_receipt);
```

Low-level access (`MilClient`, `SendCipher`/`RecvCipher`, borsh codecs,
`verifyReceipt`) is exported from the package root.
