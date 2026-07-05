// OpenAI-compatible surface over the MIL client (design §14.2). Lets an
// existing app talk to MIL by pointing at this SDK instead of the OpenAI API;
// matching / attestation / E2EE / receipt verification happen inside.

import { randomBytes } from "node:crypto";
import { MilClient, type AttestationVerifier } from "./client.ts";
import { Tier, type JobSpec } from "./protocol.ts";

export interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface ChatCompletionRequest {
  messages: ChatMessage[];
  model?: string; // 64-byte model_id hex; defaults to the provider's MIL-Core
  tier?: "tee" | "open";
  max_tokens?: number;
  price_cap_sompi?: bigint;
}

export interface ChatCompletionResponse {
  id: string;
  object: "chat.completion";
  model: string;
  choices: Array<{ index: number; message: ChatMessage; finish_reason: string }>;
  usage: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
  // MIL-specific: the settlement receipt so the caller can anchor/audit it.
  mil_receipt: { counter: string; cum_tokens_out: string; is_final: boolean };
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

export interface MilOpenAiOptions {
  host: string;
  port: number;
  modelId: string; // 64-byte hex
  verify?: AttestationVerifier;
}

/** A thin OpenAI-compatible client. One chat completion = one MIL session. */
export class MilOpenAI {
  private opts: MilOpenAiOptions;
  constructor(opts: MilOpenAiOptions) {
    this.opts = opts;
  }

  async chatCompletion(req: ChatCompletionRequest): Promise<ChatCompletionResponse> {
    const client = await MilClient.connect({ host: this.opts.host, port: this.opts.port, verify: this.opts.verify });
    try {
      const modelId = hexToBytes(req.model ?? this.opts.modelId);
      const tier = req.tier === "tee" ? Tier.Tee : Tier.Open;
      // the client composes the OpenAI messages into the prompt bytes (§18.2)
      const prompt = new TextEncoder().encode(JSON.stringify(req.messages));
      const salt = new Uint8Array(randomBytes(32));
      const makeJob = (cmReq: Uint8Array): JobSpec => ({
        version: 1,
        modelId,
        profileId: null,
        tier,
        maxTokens: req.max_tokens ?? 512,
        sampling: { temperatureMilli: 0, topPMilli: 1000, seed: null },
        sla: { ttfbMs: 1500, minTps: 1 },
        priceCapSompi: req.price_cap_sompi ?? 10_000_000n,
        cmReq,
      });

      const result = await client.runPrompt(prompt, makeJob, salt);
      const b = result.finalReceipt.body;
      return {
        id: "milcmpl-" + Buffer.from(result.sessionId.subarray(0, 8)).toString("hex"),
        object: "chat.completion",
        model: req.model ?? this.opts.modelId,
        choices: [{ index: 0, message: { role: "assistant", content: result.responseText }, finish_reason: "stop" }],
        usage: {
          prompt_tokens: Number(b.cumTokensIn),
          completion_tokens: Number(b.cumTokensOut),
          total_tokens: Number(b.cumTokensIn + b.cumTokensOut),
        },
        mil_receipt: { counter: b.counter.toString(), cum_tokens_out: b.cumTokensOut.toString(), is_final: b.isFinal },
      };
    } finally {
      client.close();
    }
  }
}
