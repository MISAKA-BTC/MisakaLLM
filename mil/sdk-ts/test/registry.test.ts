// SDK matching + MIL-Code tool executor unit tests (§6.2/§13.4, §18.4).

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { estimateCost, filterOffers, rankByCost, selectCheapest, type ProviderOffer } from "../src/registry.ts";
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
