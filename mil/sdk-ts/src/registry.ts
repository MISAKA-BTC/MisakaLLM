// Provider discovery + matching (design §6.2, §13.4, §13.6). The SDK reads
// provider offers (from the on-chain ProviderRegistry, a gateway, or a static
// list), filters by tier/model/SLA/hot, and picks the cheapest — the
// board-style "cheapest ask" match, simpler than a reverse auction (§6.2).

import net from "node:net";
import { toHex } from "./hash.ts";

// ---------------------------------------------------------------------------
// On-chain discovery (design §8.2): read provider offers directly from the
// ProviderRegistry EVM-lane contract over the node's Ethereum JSON-RPC adapter.
//
// v0 dialed a provider out-of-band (a hand-passed `host:port`); v1 registers
// providers ON-CHAIN and lets any client discover them. This is the read
// consumer of that registry — the piece the v0 `--provider-addr` flag stood in
// for. It is intentionally dependency-free: a minimal `eth_getLogs` +
// `eth_call` client over `fetch`, and a hand-rolled ABI decoder for the exact
// `get()` return layout (grounded by a `cast abi-encode` vector in the tests).
// ---------------------------------------------------------------------------

/** keccak256("ProviderRegistered(bytes32,address,bytes32,uint8)") — topic0 of a
 *  provider-registration log (providerId is the indexed topic1). */
export const PROVIDER_REGISTERED_TOPIC0 = "0x7e05a0090a0c618a1b410efdf58db1f25151c02909ca4174b76cf431d3b1f75e";

/** Selector of `ProviderRegistry.get(bytes32)`. */
const REGISTRY_GET_SELECTOR = "0x8eaa6ac0";

/** The subset of the on-chain `ProviderRegistry.Provider` record the SDK needs
 *  to build a dialable [`ProviderOffer`]. NOTE: on-chain `modelId` is the 32-byte
 *  registry representation (the low 32 bytes of the 64-byte Hash64 model id). */
export interface ProviderRecord {
  providerId: string; // 0x… bytes32
  operator: string; // 0x… address
  modelId: string; // 0x… bytes32 (registry 32-byte form)
  tier: "tee" | "open";
  askInPer1k: bigint;
  askOutPer1k: bigint;
  ttfbMs: number;
  minTps: number;
  active: boolean;
  hot: boolean;
  region: string;
  dataPlaneAddr: string;
}

function stripHex(h: string): string {
  return h.startsWith("0x") ? h.slice(2) : h;
}

function hexToBytes(h: string): Uint8Array {
  const s = stripHex(h);
  const out = new Uint8Array(s.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** The 32-byte ABI word (64 hex chars) at `byteOffset` of a decoded return blob. */
function wordHexAt(raw: string, byteOffset: number): string {
  return raw.slice(byteOffset * 2, byteOffset * 2 + 64);
}

function uintAt(raw: string, byteOffset: number): bigint {
  const w = wordHexAt(raw, byteOffset);
  if (w.length !== 64) throw new Error("registry decode: truncated word");
  return BigInt("0x" + w);
}

/** Decode the ABI return of `ProviderRegistry.get(bytes32)` (a single dynamic
 *  tuple) into the discovery-relevant fields. Field word indices match the
 *  Solidity `Provider` struct order; the two trailing dynamic strings (region,
 *  dataPlaneAddr) are read via their tuple-relative offsets. */
export function decodeProviderRecord(returnDataHex: string): ProviderRecord {
  const raw = stripHex(returnDataHex);
  // Outer: a single dynamic return is [offset][tuple…]; tupleBase is that offset.
  const tupleBase = Number(uintAt(raw, 0));
  const wordAt = (i: number) => wordHexAt(raw, tupleBase + i * 32);
  const uAt = (i: number) => uintAt(raw, tupleBase + i * 32);
  const addr = (i: number) => "0x" + wordAt(i).slice(24); // low 20 bytes
  const b32 = (i: number) => "0x" + wordAt(i);
  const str = (i: number) => {
    const off = Number(uAt(i)); // tuple-relative byte offset of the string
    const start = tupleBase + off;
    const lenHexEnd = (start + 32) * 2; // end of the length word / start of the data
    if (lenHexEnd > raw.length) throw new Error("registry decode: string offset out of bounds");
    const len = Number(uintAt(raw, start));
    const dataEnd = lenHexEnd + len * 2;
    // Bounds-check the declared length against the actual buffer (JS slice() would
    // otherwise clamp silently and decode a truncated string) — a malicious RPC
    // could declare len=0xFFFFFFFF.
    if (dataEnd > raw.length) throw new Error("registry decode: string length exceeds data");
    return new TextDecoder().decode(hexToBytes(raw.slice(lenHexEnd, dataEnd)));
  };
  return {
    operator: addr(0),
    providerId: b32(1),
    modelId: b32(3),
    tier: Number(uAt(6)) === 0 ? "tee" : "open",
    askInPer1k: uAt(8),
    askOutPer1k: uAt(9),
    ttfbMs: Number(uAt(10)),
    minTps: Number(uAt(11)),
    active: uAt(13) !== 0n,
    hot: uAt(14) !== 0n,
    region: str(16),
    dataPlaneAddr: str(17),
  };
}

/** Parse a `ProviderRecord` into a dialable [`ProviderOffer`], or null if its
 *  advertised `dataPlaneAddr` is not a usable `host:port`. */
export function providerRecordToOffer(r: ProviderRecord): ProviderOffer | null {
  const idx = r.dataPlaneAddr.lastIndexOf(":"); // v1 data-plane addr is host:port ([ipv6]:port allowed)
  if (idx <= 0 || idx >= r.dataPlaneAddr.length - 1) return null;
  let host = r.dataPlaneAddr.slice(0, idx);
  const port = Number(r.dataPlaneAddr.slice(idx + 1));
  if (!Number.isInteger(port) || port <= 0 || port > 65535) return null;
  // Bracketed IPv6 "[::1]:port" → strip the brackets; reject a bare host that
  // still contains a colon (a malformed "a:b:port" or unbracketed IPv6).
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  else if (host.includes(":")) return null;
  if (host.length === 0) return null;
  return {
    providerId: r.providerId,
    host,
    port,
    modelId: r.modelId,
    tier: r.tier,
    askInPer1k: r.askInPer1k,
    askOutPer1k: r.askOutPer1k,
    ttfbMs: r.ttfbMs,
    minTps: r.minTps,
    hot: r.hot,
    region: r.region,
  };
}

/** Options for [`fetchOffersFromChain`]. `fetchImpl` is injectable for tests. */
export interface DiscoverOpts {
  fromBlock?: string; // default "earliest"
  toBlock?: string; // default "latest"
  modelId?: Uint8Array | string; // filter to a served model (compared over the low 32 bytes)
  fetchImpl?: typeof fetch;
}

async function ethRpc(f: typeof fetch, url: string, method: string, params: unknown[]): Promise<unknown> {
  const res = await f(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  if (!res.ok) throw new Error(`eth-rpc ${method}: HTTP ${res.status}`);
  const j = (await res.json()) as { result?: unknown; error?: unknown };
  if (j.error) throw new Error(`eth-rpc ${method}: ${JSON.stringify(j.error)}`);
  return j.result;
}

/** The low 32 bytes (64 hex, lowercase) of a hex/bytes model id — the on-chain
 *  registry representation used for equality. */
function low32(v: Uint8Array | string): string {
  const h = normHex(v);
  return h.length > 64 ? h.slice(h.length - 64) : h.padStart(64, "0");
}

/** Discover provider offers from the on-chain ProviderRegistry: enumerate
 *  `ProviderRegistered` logs, `eth_call get()` each, keep the still-active ones
 *  with a dialable data-plane address, optionally filtered by served model.
 *  Compose with [`filterOffers`]/[`selectCheapest`] to pick a provider. */
export async function fetchOffersFromChain(
  ethRpcUrl: string,
  registryAddr: string,
  opts: DiscoverOpts = {},
): Promise<ProviderOffer[]> {
  const f = opts.fetchImpl ?? fetch;
  const logs = (await ethRpc(f, ethRpcUrl, "eth_getLogs", [
    {
      address: registryAddr,
      fromBlock: opts.fromBlock ?? "earliest",
      toBlock: opts.toBlock ?? "latest",
      topics: [PROVIDER_REGISTERED_TOPIC0],
    },
  ])) as Array<{ topics: string[] }>;
  const ids = [...new Set(logs.map((l) => l.topics[1].toLowerCase()))]; // providerId = indexed topic1 (hex, case-normalized)
  const wantModel = opts.modelId !== undefined ? low32(opts.modelId) : undefined;
  const offers: ProviderOffer[] = [];
  for (const id of ids) {
    const ret = (await ethRpc(f, ethRpcUrl, "eth_call", [
      { to: registryAddr, data: REGISTRY_GET_SELECTOR + stripHex(id) },
      "latest",
    ])) as string;
    const rec = decodeProviderRecord(ret);
    if (!rec.active) continue;
    if (wantModel !== undefined && low32(rec.modelId) !== wantModel) continue;
    const off = providerRecordToOffer(rec);
    if (off) offers.push(off);
  }
  return offers;
}

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
