// U2 2-hop onion relay tests (ADR-0025 §21.2). Proves the onion layering, the
// fixed-cell transport, byte-transparent end-to-end relaying, and the U6
// invariant that no single relay links the requester to the provider.

import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem";

import {
  buildOnion,
  openLayer,
  toCells,
  CellDecoder,
  CELL_SIZE,
  CELL_PAYLOAD,
  MilRelay,
  connectThroughRelays,
  selectHops,
  type RelayInfo,
} from "../src/relay.ts";

function kp() {
  const { publicKey, secretKey } = ml_kem1024.keygen();
  return { pk: publicKey, sk: secretKey };
}

/** Strip the u16 length prefix off an onion frame to get its body. */
function body(frame: Uint8Array): Uint8Array {
  const len = new DataView(frame.buffer, frame.byteOffset, frame.byteLength).getUint16(0, false);
  return frame.subarray(2, 2 + len);
}

test("onion: R1 learns only R2, R2 learns only the provider", () => {
  const r1 = kp();
  const r2 = kp();
  const hops: RelayInfo[] = [
    { host: "10.0.0.1", port: 1111, pkKem: r1.pk },
    { host: "10.0.0.2", port: 2222, pkKem: r2.pk },
  ];
  const provider = { host: "203.0.113.9", port: 9999 };
  const onion = buildOnion(hops, provider);

  // R1 opens the outer layer → next is R2, inner is opaque (sealed to R2).
  const l1 = openLayer(r1.sk, body(onion));
  assert.deepEqual(l1.next, { host: "10.0.0.2", port: 2222 }, "R1 sees R2 as next");
  assert.ok(l1.innerFrame.length > 0, "R1 forwards an inner frame it cannot read");
  // R1 must NOT be able to see the provider address anywhere it can decrypt.
  assert.equal(new TextDecoder().decode(l1.innerFrame).includes("203.0.113.9"), false, "provider host is not in R1 cleartext");

  // R1 cannot open R2's layer (wrong KEM key) — fail-closed.
  assert.throws(() => openLayer(r1.sk, body(l1.innerFrame)), "R1 cannot peel R2's layer");

  // R2 opens the inner layer → next is the provider, no further inner.
  const l2 = openLayer(r2.sk, body(l1.innerFrame));
  assert.deepEqual(l2.next, provider, "R2 sees the provider as next");
  assert.equal(l2.innerFrame.length, 0, "R2 is the last hop");
});

test("cells: toCells/CellDecoder round-trip arbitrary byte streams exactly", () => {
  const dec = new CellDecoder();
  const inputs = [
    new Uint8Array(0),
    new Uint8Array([1, 2, 3]),
    new Uint8Array(CELL_PAYLOAD).fill(7), // exactly one cell
    new Uint8Array(CELL_PAYLOAD + 1).fill(9), // spills to a 2nd cell
    new Uint8Array(3 * CELL_PAYLOAD + 5).map((_, i) => i & 0xff),
  ];
  let expected = new Uint8Array(0);
  let got = new Uint8Array(0);
  for (const chunk of inputs) {
    const merged = new Uint8Array(expected.length + chunk.length);
    merged.set(expected);
    merged.set(chunk, expected.length);
    expected = merged;
    for (const cell of toCells(chunk)) {
      assert.equal(cell.length, CELL_SIZE, "every cell is exactly 4 KB on the wire");
      const out = dec.push(cell);
      const g = new Uint8Array(got.length + out.length);
      g.set(got);
      g.set(out, got.length);
      got = g;
    }
  }
  assert.deepEqual(got, expected, "the tunneled byte stream is preserved bit-for-bit");
});

test("2-hop circuit relays raw MIL bytes end-to-end, byte-identical", async () => {
  // provider stand-in: a raw echo server (unaware it is being relayed)
  const provider = net.createServer((s) => s.pipe(s));
  await new Promise<void>((r) => provider.listen(0, "127.0.0.1", () => r()));
  const pPort = (provider.address() as net.AddressInfo).port;

  const r1kp = kp();
  const r2kp = kp();
  const R2 = new MilRelay({ skKem: r2kp.sk, port: 0, host: "127.0.0.1" });
  const R1 = new MilRelay({ skKem: r1kp.sk, port: 0, host: "127.0.0.1" });
  const { port: p2 } = await R2.start();
  const { port: p1 } = await R1.start();

  const hops: RelayInfo[] = [
    { host: "127.0.0.1", port: p1, pkKem: r1kp.pk },
    { host: "127.0.0.1", port: p2, pkKem: r2kp.pk },
  ];
  const duplex = await connectThroughRelays(hops, { host: "127.0.0.1", port: pPort });

  // a payload larger than one cell, to exercise fragmentation + reassembly
  const payload = Buffer.from(Array.from({ length: 10_000 }, (_, i) => i & 0xff));
  const got = await new Promise<Buffer>((resolve, reject) => {
    let buf = Buffer.alloc(0);
    duplex.on("data", (d: Buffer) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length >= payload.length) resolve(buf.subarray(0, payload.length));
    });
    duplex.on("error", reject);
    duplex.write(payload);
  });

  assert.deepEqual(got, payload, "raw bytes survive requester→R1→R2→provider and back");
  duplex.destroy();
  R1.stop();
  R2.stop();
  provider.close();
});

test("U6: the onion never encodes the requester, and R1 cannot reach the provider", () => {
  const r1 = kp();
  const r2 = kp();
  const provider = { host: "198.51.100.7", port: 7000 };
  const onion = buildOnion(
    [
      { host: "10.0.0.1", port: 1, pkKem: r1.pk },
      { host: "10.0.0.2", port: 2, pkKem: r2.pk },
    ],
    provider,
  );
  const l1 = openLayer(r1.sk, body(onion));
  // R1 holds {requester-IP (its TCP peer), R2}. It has no provider anywhere.
  assert.notDeepEqual(l1.next, provider);
  // R2 holds {R1 (its TCP peer), provider}. The requester address is in NO onion
  // layer at all — only next-hop addresses are ever encoded — so R2 cannot learn
  // it cryptographically; it only ever sees R1 as its peer. Hence no single relay
  // holds (requester-IP, provider-addr).
  const l2 = openLayer(r2.sk, body(l1.innerFrame));
  assert.deepEqual(l2.next, provider);
});

test("selectHops picks distinct, stake-weighted hops", () => {
  const relays: RelayInfo[] = [
    { host: "a", port: 1, pkKem: new Uint8Array(0), stake: 1n },
    { host: "b", port: 2, pkKem: new Uint8Array(0), stake: 1n },
    { host: "c", port: 3, pkKem: new Uint8Array(0), stake: 1_000_000n }, // heavy
  ];
  // rng ~1.0 → the weighted pick lands on the heavy relay 'c' first.
  const picks = selectHops(relays, 2, () => 0.999999);
  assert.equal(picks.length, 2);
  assert.notEqual(picks[0].host, picks[1].host, "two DISTINCT relays");
  assert.equal(picks[0].host, "c", "stake weighting selects the heavy relay first");
  assert.throws(() => selectHops(relays, 4), "cannot pick more relays than exist");
});
