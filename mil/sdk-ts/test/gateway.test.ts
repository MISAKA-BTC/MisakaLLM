// Gateway relay tests (§14.2): the gateway splices opaque bytes and never sees
// plaintext; matching picks the cheapest provider.

import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";

import { MilGateway, encodeRouteHeader } from "../src/gateway.ts";
import type { ProviderOffer } from "../src/registry.ts";

const MODEL = "aa".repeat(64);

function offer(id: string, host: string, port: number, askOut: bigint): ProviderOffer {
  return {
    providerId: id,
    host,
    port,
    modelId: MODEL,
    tier: "open",
    askInPer1k: 1_000_000n,
    askOutPer1k: askOut,
    ttfbMs: 1500,
    minTps: 20,
    hot: true,
  };
}

test("gateway resolves the cheapest provider by criteria", () => {
  const gw = new MilGateway({
    port: 0,
    offers: [offer("pricey", "h1", 10, 9_000_000n), offer("cheap", "h2", 20, 100_000n)],
  });
  const t = gw.resolveTarget({ criteria: { modelId: MODEL, estTokensOut: 1000 } });
  assert.deepEqual(t, { host: "h2", port: 20 });
  assert.equal(gw.resolveTarget({ criteria: { modelId: "bb".repeat(64) } }), null);
});

test("gateway splices bytes verbatim to an explicit upstream (no plaintext seen)", async () => {
  // upstream: an echo server standing in for a provider's data plane
  const upstream = net.createServer((sock) => sock.pipe(sock));
  await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", () => r()));
  const upstreamPort = (upstream.address() as net.AddressInfo).port;

  const gw = new MilGateway({ port: 0, offers: [] });
  const { port } = await gw.start();

  const payload = Buffer.from("opaque ciphertext frame bytes that the gateway must not interpret");
  const got = await new Promise<Buffer>((resolve, reject) => {
    const client = net.connect(port, "127.0.0.1", () => {
      client.write(encodeRouteHeader({ target: { host: "127.0.0.1", port: upstreamPort } }));
      client.write(payload);
    });
    let buf = Buffer.alloc(0);
    client.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length >= payload.length) {
        client.destroy();
        resolve(buf.subarray(0, payload.length));
      }
    });
    client.on("error", reject);
  });

  assert.deepEqual(got, payload, "bytes round-trip through the gateway unchanged");
  gw.stop();
  upstream.close();
});
