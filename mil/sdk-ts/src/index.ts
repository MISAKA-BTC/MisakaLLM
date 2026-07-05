// @misaka/mil-sdk — MISAKA Inference Lane TypeScript SDK (design §14.2).
//
// A local, trust-terminating client: it runs the PQ (ML-KEM-1024 + AES-256-GCM)
// data-plane handshake, verifies the provider attestation, streams the chat
// response, and verifies every ML-DSA-87 Proof-of-Inference receipt — exposing
// an OpenAI-compatible surface so existing apps swap the endpoint and nothing
// else. Plaintext exists only here and inside the provider TEE (§15.1).

export * as borsh from "./borsh.ts";
export * from "./hash.ts";
export * from "./crypto.ts";
export * from "./receipt.ts";
export * from "./protocol.ts";
export * from "./client.ts";
export * from "./registry.ts";
export * from "./failover.ts";
export * from "./tools.ts";
export * from "./gateway.ts";
export * from "./openai.ts";
