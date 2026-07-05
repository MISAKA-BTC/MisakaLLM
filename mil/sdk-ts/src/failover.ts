// Reliability: automatic failover + hedged requests (design §14.5, §13.6).
// The SDK hides "a sometimes-broken decentralized network" by retrying across
// providers and (optionally) racing two of them.

import { MilClient, type AttestationVerifier, type PromptResult } from "./client.ts";
import type { JobSpec } from "./protocol.ts";
import type { ProviderOffer } from "./registry.ts";
import { randomBytes } from "node:crypto";

export interface RunOptions {
  makeJob: (cmReq: Uint8Array) => JobSpec;
  verify?: AttestationVerifier;
  salt?: Uint8Array;
  connectTimeoutMs?: number;
}

async function runOnce(offer: ProviderOffer, prompt: Uint8Array, opts: RunOptions): Promise<PromptResult> {
  const client = await MilClient.connect({ host: offer.host, port: offer.port, verify: opts.verify });
  try {
    const salt = opts.salt ?? new Uint8Array(randomBytes(32));
    return await client.runPrompt(prompt, opts.makeJob, salt);
  } finally {
    client.close();
  }
}

/** Try each offer in order until one produces a verified result (§14.5). The
 *  history-reprefill failover is implicit: each attempt re-sends the full prompt
 *  to a fresh provider. Throws the last error if all fail. */
export async function runWithFailover(offers: ProviderOffer[], prompt: Uint8Array, opts: RunOptions): Promise<{
  result: PromptResult;
  provider: ProviderOffer;
  attempts: number;
}> {
  if (offers.length === 0) throw new Error("MIL: no providers to fail over across");
  let lastErr: unknown;
  for (let i = 0; i < offers.length; i++) {
    try {
      const result = await runOnce(offers[i], prompt, opts);
      return { result, provider: offers[i], attempts: i + 1 };
    } catch (e) {
      lastErr = e;
    }
  }
  throw new Error(`MIL: all ${offers.length} providers failed; last error: ${lastErr}`);
}

/** Hedged mode (§13.6): send to the top-2 providers concurrently, take the
 *  first verified result, and abandon the other (its channel just closes). Tail
 *  latency is cut at the cost of double prefill on the loser. */
export async function runHedged(offers: ProviderOffer[], prompt: Uint8Array, opts: RunOptions): Promise<{
  result: PromptResult;
  provider: ProviderOffer;
}> {
  if (offers.length === 0) throw new Error("MIL: no providers to hedge across");
  const pair = offers.slice(0, 2);
  const attempts = pair.map((offer) => runOnce(offer, prompt, opts).then((result) => ({ result, provider: offer })));
  // Promise.any resolves on the first fulfilled; if both reject it throws AggregateError.
  try {
    return await Promise.any(attempts);
  } catch {
    // fall back to sequential failover across the full list on total failure
    const { result, provider } = await runWithFailover(offers, prompt, opts);
    return { result, provider };
  }
}
