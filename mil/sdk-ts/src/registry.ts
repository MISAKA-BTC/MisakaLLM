// Provider discovery + matching (design §6.2, §13.4, §13.6). The SDK reads
// provider offers (from the on-chain ProviderRegistry, a gateway, or a static
// list), filters by tier/model/SLA/hot, and picks the cheapest — the
// board-style "cheapest ask" match, simpler than a reverse auction (§6.2).

import net from "node:net";
import { toHex } from "./hash.ts";

/** A provider offer as advertised in the ProviderRegistry (§6.2). */
export interface ProviderOffer {
  providerId: string; // hex
  host: string;
  port: number;
  modelId: string; // hex Hash64
  tier: "tee" | "open";
  askInPer1k: bigint; // sompi per 1k input tokens
  askOutPer1k: bigint; // sompi per 1k output tokens
  ttfbMs: number;
  minTps: number;
  hot: boolean;
  region?: string;
}

/** Selection criteria a requester specifies. */
export interface MatchCriteria {
  modelId: Uint8Array | string; // required model
  tier?: "tee" | "open";
  maxTtfbMs?: number;
  minTps?: number;
  requireHot?: boolean; // §13.4a: avoid cold-start providers
  region?: string;
  // Estimated job shape for cost ranking.
  estTokensIn?: number;
  estTokensOut?: number;
}

function ceilDiv(a: bigint, b: bigint): bigint {
  return a === 0n ? 0n : (a - 1n) / b + 1n;
}

/** Estimated job cost under an offer for the criteria's token shape (§6.2). */
export function estimateCost(offer: ProviderOffer, tokensIn: number, tokensOut: number): bigint {
  return ceilDiv(offer.askInPer1k * BigInt(tokensIn), 1000n) + ceilDiv(offer.askOutPer1k * BigInt(tokensOut), 1000n);
}

function normHex(v: Uint8Array | string): string {
  return typeof v === "string" ? (v.startsWith("0x") ? v.slice(2) : v).toLowerCase() : toHex(v);
}

/** Filter offers to those satisfying the criteria. */
export function filterOffers(offers: ProviderOffer[], c: MatchCriteria): ProviderOffer[] {
  const model = normHex(c.modelId);
  return offers.filter((o) => {
    if (normHex(o.modelId) !== model) return false;
    if (c.tier && o.tier !== c.tier) return false;
    if (c.maxTtfbMs !== undefined && o.ttfbMs > c.maxTtfbMs) return false;
    if (c.minTps !== undefined && o.minTps < c.minTps) return false;
    if (c.requireHot && !o.hot) return false;
    if (c.region && o.region && o.region !== c.region) return false;
    return true;
  });
}

/** Rank matching offers cheapest-first (§6.2). Ties break toward hot + lower TTFT. */
export function rankByCost(offers: ProviderOffer[], c: MatchCriteria): ProviderOffer[] {
  const ti = c.estTokensIn ?? 0;
  const to = c.estTokensOut ?? 512;
  return [...offers].sort((a, b) => {
    const ca = estimateCost(a, ti, to);
    const cb = estimateCost(b, ti, to);
    if (ca !== cb) return ca < cb ? -1 : 1;
    if (a.hot !== b.hot) return a.hot ? -1 : 1;
    return a.ttfbMs - b.ttfbMs;
  });
}

/** The single cheapest matching offer, or null. */
export function selectCheapest(offers: ProviderOffer[], c: MatchCriteria): ProviderOffer | null {
  const ranked = rankByCost(filterOffers(offers, c), c);
  return ranked[0] ?? null;
}

/** Measure TCP connect RTT to an offer, ms (§13.6 geo routing). Infinity on failure. */
export function pingRtt(offer: ProviderOffer, timeoutMs = 2000): Promise<number> {
  return new Promise((resolve) => {
    const start = performance.now();
    const socket = net.connect({ host: offer.host, port: offer.port });
    const done = (rtt: number) => {
      socket.destroy();
      resolve(rtt);
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => done(performance.now() - start));
    socket.once("timeout", () => done(Infinity));
    socket.once("error", () => done(Infinity));
  });
}

/** Rank the top-k cheapest offers by measured RTT (§13.6): cheapest set first,
 *  then closest. Returns offers ordered best-first. */
export async function rankByRtt(offers: ProviderOffer[], c: MatchCriteria, k = 3): Promise<ProviderOffer[]> {
  const candidates = rankByCost(filterOffers(offers, c), c).slice(0, Math.max(1, k));
  const rtts = await Promise.all(candidates.map((o) => pingRtt(o)));
  return candidates.map((o, i) => ({ o, rtt: rtts[i] })).sort((a, b) => a.rtt - b.rtt).map((x) => x.o);
}
