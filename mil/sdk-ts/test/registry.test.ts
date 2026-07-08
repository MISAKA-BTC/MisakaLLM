// SDK matching + MIL-Code tool executor unit tests (§6.2/§13.4, §18.4).

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  decodeProviderRecord,
  estimateCost,
  fetchOffersFromChain,
  filterOffers,
  PROVIDER_REGISTERED_TOPIC0,
  providerRecordToOffer,
  rankByCost,
  selectCheapest,
  type ProviderOffer,
} from "../src/registry.ts";
import { MilCodeExecutor, parseToolCalls } from "../src/tools.ts";

const MODEL = "aa".repeat(64);

function offer(o: Partial<ProviderOffer>): ProviderOffer {
  return {
    providerId: "01",
    host: "h",
    port: 1,
    modelId: MODEL,
    tier: "open",
    askInPer1k: 1_000_000n,
    askOutPer1k: 1_000_000n,
    ttfbMs: 1500,
    minTps: 20,
    hot: true,
    ...o,
  };
}

test("estimateCost rounds up per side (§6.2)", () => {
  assert.equal(estimateCost(offer({ askInPer1k: 1000n, askOutPer1k: 2000n }), 1000, 500), 1000n + 1000n);
  assert.equal(estimateCost(offer({ askInPer1k: 1n, askOutPer1k: 0n }), 1, 0), 1n);
});

test("filter enforces model/tier/SLA/hot", () => {
  const offers = [
    offer({ providerId: "a", modelId: "bb".repeat(64) }), // wrong model
    offer({ providerId: "b", tier: "tee" }),
    offer({ providerId: "c", hot: false }),
    offer({ providerId: "d", ttfbMs: 5000 }),
    offer({ providerId: "e" }), // matches
  ];
  const got = filterOffers(offers, { modelId: MODEL, tier: "open", maxTtfbMs: 2000, requireHot: true });
  assert.deepEqual(got.map((o) => o.providerId), ["e"]);
});

test("cheapest-ask selection (§6.2)", () => {
  const offers = [
    offer({ providerId: "pricey", askOutPer1k: 5_000_000n }),
    offer({ providerId: "cheap", askOutPer1k: 100_000n }),
    offer({ providerId: "mid", askOutPer1k: 1_000_000n }),
  ];
  const ranked = rankByCost(offers, { modelId: MODEL, estTokensOut: 1000 });
  assert.deepEqual(ranked.map((o) => o.providerId), ["cheap", "mid", "pricey"]);
  assert.equal(selectCheapest(offers, { modelId: MODEL, estTokensOut: 1000 })?.providerId, "cheap");
  assert.equal(selectCheapest([], { modelId: MODEL }), null);
});

test("parseToolCalls handles tool_calls array + JSON args", () => {
  const msg = {
    tool_calls: [
      { id: "1", function: { name: "file_read", arguments: '{"path":"a.txt"}' } },
      { id: "2", function: { name: "git", arguments: { args: ["status"] } } },
    ],
  };
  const calls = parseToolCalls(msg);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].name, "file_read");
  assert.equal(calls[0].arguments.path, "a.txt");
  assert.deepEqual(calls[1].arguments.args, ["status"]);
});

test("MilCodeExecutor confines file_read to the workspace root (§18.4)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "milcode-"));
  writeFileSync(join(dir, "hello.txt"), "line one\nline two\nline three\n");
  const exec = new MilCodeExecutor({ root: dir });

  const ok = await exec.execute({ name: "file_read", arguments: { path: "hello.txt" } });
  assert.equal(ok.ok, true);
  assert.match(ok.output, /line one/);

  // path traversal is rejected
  const escape = await exec.execute({ name: "file_read", arguments: { path: "../../../etc/passwd" } });
  assert.equal(escape.ok, false);
  assert.match(escape.output, /escapes the workspace root/);

  // mutating git is rejected
  const push = await exec.execute({ name: "git", arguments: { args: ["push"] } });
  assert.equal(push.ok, false);
  assert.match(push.output, /not allowed/);

  // unknown tool rejected
  const unknown = await exec.execute({ name: "rm_rf", arguments: {} });
  assert.equal(unknown.ok, false);
});

// --- on-chain discovery (§8.2): decode + fetch from the ProviderRegistry ------
//
// Vectors are the REAL `ProviderRegistry.get()` ABI return, produced by
// `cast abi-encode "x((address,bytes32,bytes32,bytes32,bytes32,bytes32,uint8,
// uint32,uint64,uint64,uint32,uint32,uint64,bool,bool,bytes32,string,string))"`
// so the hand-rolled decoder is checked against Solidity's own encoding.

// provider #1: operator 0x..aa, id 0x11.., model 0x33.., open, ask 100/200,
// ttfb 1500, minTps 20, active, hot, region "us-east", addr "203.0.113.7:37110".
const V_ACTIVE =
  "0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000aa1111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444444444444444444444444444555555555555555555555555555555555555555555555555555555555555555500000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000007000000000000000000000000000000000000000000000000000000000000006400000000000000000000000000000000000000000000000000000000000000c800000000000000000000000000000000000000000000000000000000000005dc0000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000002a00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002400000000000000000000000000000000000000000000000000000000000000280000000000000000000000000000000000000000000000000000000000000000775732d656173740000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000113230332e302e3131332e373a3337313130000000000000000000000000000000";
// same provider but active=false.
const V_INACTIVE =
  "0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000aa1111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444444444444444444444444444555555555555555555555555555555555555555555555555555555555555555500000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000007000000000000000000000000000000000000000000000000000000000000006400000000000000000000000000000000000000000000000000000000000000c800000000000000000000000000000000000000000000000000000000000005dc0000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000002a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002400000000000000000000000000000000000000000000000000000000000000280000000000000000000000000000000000000000000000000000000000000000775732d656173740000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000113230332e302e3131332e373a3337313130000000000000000000000000000000";
// provider #2: id 0x66.., model 0x99.., tee, ask 50/60, region "eu-west",
// addr "10.0.0.9:1234", active, cold.
const V_OTHER =
  "0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000bb66666666666666666666666666666666666666666666666666666666666666662222222222222222222222222222222222222222222222222222222222222222999999999999999999999999999999999999999999999999999999999999999944444444444444444444444444444444444444444444444444444444444444445555555555555555555555555555555555555555555555555555555555555555000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000032000000000000000000000000000000000000000000000000000000000000003c0000000000000000000000000000000000000000000000000000000000000384000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000002a00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002400000000000000000000000000000000000000000000000000000000000000280000000000000000000000000000000000000000000000000000000000000000765752d7765737400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d31302e302e302e393a3132333400000000000000000000000000000000000000";

const ID1 = "0x" + "11".repeat(32);
const ID2 = "0x" + "66".repeat(32);

test("decodeProviderRecord decodes the real get() ABI return", () => {
  const r = decodeProviderRecord(V_ACTIVE);
  assert.equal(r.operator, "0x" + "00".repeat(19) + "aa");
  assert.equal(r.providerId, ID1);
  assert.equal(r.modelId, "0x" + "33".repeat(32));
  assert.equal(r.tier, "open");
  assert.equal(r.askInPer1k, 100n);
  assert.equal(r.askOutPer1k, 200n);
  assert.equal(r.ttfbMs, 1500);
  assert.equal(r.minTps, 20);
  assert.equal(r.active, true);
  assert.equal(r.hot, true);
  assert.equal(r.region, "us-east");
  assert.equal(r.dataPlaneAddr, "203.0.113.7:37110");
});

test("providerRecordToOffer parses host:port and rejects bad addrs", () => {
  const off = providerRecordToOffer(decodeProviderRecord(V_ACTIVE))!;
  assert.equal(off.host, "203.0.113.7");
  assert.equal(off.port, 37110);
  assert.equal(off.tier, "open");
  const rec = decodeProviderRecord(V_ACTIVE);
  assert.equal(providerRecordToOffer({ ...rec, dataPlaneAddr: "noport" }), null);
  assert.equal(providerRecordToOffer({ ...rec, dataPlaneAddr: "h:0" }), null);
  assert.equal(providerRecordToOffer({ ...rec, dataPlaneAddr: "h:99999" }), null);
  // a bare multi-colon host is malformed → reject (lastIndexOf would leave a ':' in host)
  assert.equal(providerRecordToOffer({ ...rec, dataPlaneAddr: "1.2.3.4:80:443" }), null);
  // bracketed IPv6 is accepted and the brackets are stripped from host
  const v6 = providerRecordToOffer({ ...rec, dataPlaneAddr: "[2001:db8::1]:37110" })!;
  assert.equal(v6.host, "2001:db8::1");
  assert.equal(v6.port, 37110);
});

test("decodeProviderRecord rejects an out-of-bounds string length (malicious RPC)", () => {
  // Corrupt V_ACTIVE's dataPlaneAddr length word (0x…11 = 17) to 0xffffffff so the
  // declared string runs past the buffer; the decoder must throw, not silently truncate.
  const raw = V_ACTIVE.slice(2);
  const lenWord = "203.0.113.7:37110".length; // 17 = 0x11
  const marker = (17).toString(16).padStart(64, "0");
  const at = raw.indexOf(marker + "3230332e302e3131332e373a3337313130"); // len word ‖ "203.0.113.7:37110"
  assert.ok(at >= 0, "found the dataPlaneAddr length word");
  const corrupted = "0x" + raw.slice(0, at) + "f".repeat(64) + raw.slice(at + 64);
  assert.throws(() => decodeProviderRecord(corrupted), /length exceeds data/);
});

// A fake eth-rpc: eth_getLogs → one ProviderRegistered log per id; eth_call → the
// canned get() return for the requested providerId.
function fakeFetch(byId: Record<string, string>, logIds: string[]): typeof fetch {
  return (async (_url: string, init: { body: string }) => {
    const req = JSON.parse(init.body);
    let result: unknown;
    if (req.method === "eth_getLogs") {
      result = logIds.map((id) => ({ topics: [PROVIDER_REGISTERED_TOPIC0, id] }));
    } else if (req.method === "eth_call") {
      const data: string = req.params[0].data;
      const id = ("0x" + data.slice(10)).toLowerCase(); // strip 0x + 4-byte selector
      result = byId[id];
      if (result === undefined) throw new Error("unexpected eth_call id " + id);
    }
    return { ok: true, status: 200, json: async () => ({ jsonrpc: "2.0", id: 1, result }) } as unknown as Response;
  }) as unknown as typeof fetch;
}

test("fetchOffersFromChain enumerates + decodes both providers", async () => {
  const byId = { [ID1.toLowerCase()]: V_ACTIVE, [ID2.toLowerCase()]: V_OTHER };
  const offers = await fetchOffersFromChain("http://node/eth", "0xReg", { fetchImpl: fakeFetch(byId, [ID1, ID2]) });
  assert.equal(offers.length, 2);
  const p1 = offers.find((o) => o.providerId === ID1)!;
  assert.equal(p1.host, "203.0.113.7");
  assert.equal(p1.port, 37110);
  const p2 = offers.find((o) => o.providerId === ID2)!;
  assert.equal(p2.host, "10.0.0.9");
  assert.equal(p2.port, 1234);
  assert.equal(p2.tier, "tee");
});

test("fetchOffersFromChain filters by served model (low-32 compare)", async () => {
  const byId = { [ID1.toLowerCase()]: V_ACTIVE, [ID2.toLowerCase()]: V_OTHER };
  const only1 = await fetchOffersFromChain("http://node/eth", "0xReg", {
    fetchImpl: fakeFetch(byId, [ID1, ID2]),
    modelId: "33".repeat(32),
  });
  assert.deepEqual(only1.map((o) => o.providerId), [ID1]);
});

test("fetchOffersFromChain drops deregistered (active=false) providers", async () => {
  const byId = { [ID1.toLowerCase()]: V_INACTIVE };
  const none = await fetchOffersFromChain("http://node/eth", "0xReg", { fetchImpl: fakeFetch(byId, [ID1]) });
  assert.equal(none.length, 0);
});

test("fetchOffersFromChain output composes with selectCheapest", async () => {
  const byId = { [ID1.toLowerCase()]: V_ACTIVE, [ID2.toLowerCase()]: V_OTHER };
  const offers = await fetchOffersFromChain("http://node/eth", "0xReg", { fetchImpl: fakeFetch(byId, [ID1, ID2]) });
  // both serve different models; pick within model 0x33.. → provider #1
  const pick = selectCheapest(offers, { modelId: "33".repeat(32), estTokensOut: 1000 });
  assert.equal(pick?.providerId, ID1);
});
