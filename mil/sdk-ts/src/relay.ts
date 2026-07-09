// U2 — 2-hop onion relay (ADR-0025 §21.2 / U2; design §14.2 relay hardened).
//
// The single-hop `gateway.ts` splices opaque ciphertext but, seeing BOTH the
// requester IP and the provider address, itself holds the IP↔provider map U2
// forbids (U6). This module upgrades the relay to the Tier-2 *standard* path:
//
//     Requester → R1 → R2 → Provider
//
// - **R1** learns the requester IP (its TCP peer) and R2's address — but NOT the
//   provider: the provider address sits inside a layer sealed to R2's KEM key
//   that R1 cannot open.
// - **R2** learns the provider address and R1 (its TCP peer) — but NOT the
//   requester IP.
// - No single relay holds `(requester-IP, provider-addr)` (the U6 invariant).
//
// The MIL data-plane channel still terminates end-to-end requester↔provider
// (ML-KEM-1024 + AES-256-GCM, `crypto.ts`), so no relay ever sees plaintext or
// session keys — the onion only routes, it does not read. Traffic between the
// requester and R2 is padded into fixed **4 KB cells** (+ optional send-timing
// jitter) so cell counts/sizes do not correlate the two ends; R1 forwards cells
// verbatim, R2 terminates the cell transport and speaks raw MIL bytes to the
// provider (which is unchanged and unaware it is being relayed).
//
// PQ throughout: every onion layer is an independent ML-KEM-1024 encapsulation
// (the same primitive as the data plane), so a future CRQC cannot retroactively
// peel a recorded onion and de-anonymize a past session.

import net from "node:net";
import { Duplex } from "node:stream";
import { randomBytes } from "node:crypto";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem";
import { hkdf } from "@noble/hashes/hkdf";
import { sha3_512 } from "@noble/hashes/sha3";
import { gcm } from "@noble/ciphers/aes";

/** Fixed relay cell size on the wire (U2: "4 KB fixed cells"). */
export const CELL_SIZE = 4096;
/** Usable payload per cell (2-byte length header ‖ payload ‖ zero-pad). */
export const CELL_PAYLOAD = CELL_SIZE - 2;

const KEM_CT_LEN = 1568; // ML-KEM-1024 ciphertext (matches crypto.ts KEM_CT_LEN)
const GCM_TAG_LEN = 16;
const ONION_INFO = new TextEncoder().encode("misaka-mil-v1/onion");
const ZERO_NONCE = new Uint8Array(12); // one-time key per fresh KEM ss → safe
const MAX_ONION_BODY = 16 * 1024; // abuse cap on a single onion frame body

/** A relay node the SDK routes through: its dial address + KEM public key. */
export interface RelayInfo {
  host: string;
  port: number;
  /** ML-KEM-1024 public key (1568 bytes) — the onion layer is sealed to this. */
  pkKem: Uint8Array;
  /** Stake weight for selection (U2: stake-weighted random pick). */
  stake?: bigint;
}

/** A dial target (the next hop's address). */
export interface HopTarget {
  host: string;
  port: number;
}

// ------------------------------------------------------------------ onion crypto

/** One-time AEAD key from a layer's KEM shared secret (HKDF-SHA3-512, PQ). */
function onionKey(sharedSecret: Uint8Array): Uint8Array {
  return hkdf(sha3_512, sharedSecret, undefined, ONION_INFO, 32);
}

/** Encode a layer's cleartext routing payload:
 *  `u8(hostLen) ‖ host ‖ u16(port,BE) ‖ u16(innerLen,BE) ‖ innerFrame`.
 *  `innerFrame` is the *next* onion frame (empty at the last relay). */
function encodeRouting(next: HopTarget, innerFrame: Uint8Array): Uint8Array {
  const host = new TextEncoder().encode(next.host);
  if (host.length > 255) throw new Error("MIL relay: host too long");
  const out = new Uint8Array(1 + host.length + 2 + 2 + innerFrame.length);
  const dv = new DataView(out.buffer);
  let o = 0;
  out[o++] = host.length;
  out.set(host, o);
  o += host.length;
  dv.setUint16(o, next.port, false);
  o += 2;
  dv.setUint16(o, innerFrame.length, false);
  o += 2;
  out.set(innerFrame, o);
  return out;
}

function decodeRouting(pt: Uint8Array): { next: HopTarget; innerFrame: Uint8Array } {
  const dv = new DataView(pt.buffer, pt.byteOffset, pt.byteLength);
  let o = 0;
  const hostLen = pt[o++];
  const host = new TextDecoder().decode(pt.subarray(o, o + hostLen));
  o += hostLen;
  const port = dv.getUint16(o, false);
  o += 2;
  const innerLen = dv.getUint16(o, false);
  o += 2;
  const innerFrame = pt.subarray(o, o + innerLen);
  return { next: { host, port }, innerFrame };
}

/** Seal one onion layer to `pkKem`, wrapping `innerFrame`. Wire frame:
 *  `u16(bodyLen,BE) ‖ kem_ct(1568) ‖ aead_ct`. */
function sealFrame(pkKem: Uint8Array, next: HopTarget, innerFrame: Uint8Array): Uint8Array {
  const { cipherText, sharedSecret } = ml_kem1024.encapsulate(pkKem);
  const key = onionKey(sharedSecret);
  const ct = gcm(key, ZERO_NONCE).encrypt(encodeRouting(next, innerFrame));
  const bodyLen = cipherText.length + ct.length;
  if (bodyLen > MAX_ONION_BODY) throw new Error("MIL relay: onion too large");
  const frame = new Uint8Array(2 + bodyLen);
  new DataView(frame.buffer).setUint16(0, bodyLen, false);
  frame.set(cipherText, 2);
  frame.set(ct, 2 + cipherText.length);
  return frame;
}

/** Open the outermost onion layer with this relay's KEM secret key. Returns the
 *  next hop and the inner frame to forward (empty ⇒ this is the last relay). */
export function openLayer(skKem: Uint8Array, body: Uint8Array): { next: HopTarget; innerFrame: Uint8Array } {
  if (body.length < KEM_CT_LEN + GCM_TAG_LEN) throw new Error("MIL relay: onion body too short");
  const kemCt = body.subarray(0, KEM_CT_LEN);
  const aeadCt = body.subarray(KEM_CT_LEN);
  const ss = ml_kem1024.decapsulate(kemCt, skKem);
  const pt = gcm(onionKey(ss), ZERO_NONCE).decrypt(aeadCt);
  return decodeRouting(pt);
}

/** Build the onion the requester sends to the first relay. `hops[0]` is R1
 *  (dialed by the client); the last relay's `next` is `target` (the provider).
 *  Requires ≥ 1 hop; U2 mandates 2 for Tier-2. */
export function buildOnion(hops: RelayInfo[], target: HopTarget): Uint8Array {
  if (hops.length < 1) throw new Error("MIL relay: need at least one hop");
  let frame = new Uint8Array(0); // innermost inner = empty (last relay → provider)
  for (let i = hops.length - 1; i >= 0; i--) {
    const next: HopTarget = i === hops.length - 1 ? target : { host: hops[i + 1].host, port: hops[i + 1].port };
    frame = sealFrame(hops[i].pkKem, next, frame);
  }
  return frame;
}

// ------------------------------------------------------------------ cell transport

/** Split a byte stream into fixed 4 KB cells: `u16(len,BE) ‖ payload ‖ 0-pad`. A
 *  chunk larger than one cell is fragmented across cells; a short chunk is
 *  padded. Decoding concatenates payloads, so the tunneled byte stream is exact. */
export function toCells(chunk: Uint8Array): Uint8Array[] {
  const cells: Uint8Array[] = [];
  for (let off = 0; off < chunk.length || (off === 0 && chunk.length === 0); ) {
    const take = Math.min(CELL_PAYLOAD, chunk.length - off);
    const cell = new Uint8Array(CELL_SIZE); // zero-padded
    new DataView(cell.buffer).setUint16(0, take, false);
    cell.set(chunk.subarray(off, off + take), 2);
    cells.push(cell);
    off += take;
    if (take === 0) break; // empty chunk → nothing to send
  }
  return cells;
}

/** Stateful de-cell: feed wire bytes, get back the concatenated tunneled bytes
 *  from any complete 4 KB cells (partial trailing bytes are retained). */
export class CellDecoder {
  private buf = new Uint8Array(0);
  push(wire: Uint8Array): Uint8Array {
    const merged = new Uint8Array(this.buf.length + wire.length);
    merged.set(this.buf);
    merged.set(wire, this.buf.length);
    this.buf = merged;
    const out: Uint8Array[] = [];
    let o = 0;
    while (this.buf.length - o >= CELL_SIZE) {
      const cell = this.buf.subarray(o, o + CELL_SIZE);
      const len = new DataView(cell.buffer, cell.byteOffset, CELL_SIZE).getUint16(0, false);
      if (len > CELL_PAYLOAD) throw new Error("MIL relay: bad cell length");
      out.push(cell.subarray(2, 2 + len));
      o += CELL_SIZE;
    }
    this.buf = this.buf.subarray(o);
    let total = 0;
    for (const p of out) total += p.length;
    const flat = new Uint8Array(total);
    let f = 0;
    for (const p of out) {
      flat.set(p, f);
      f += p.length;
    }
    return flat;
  }
}

/** A cell-framed duplex over a raw socket: the caller writes/reads *raw* MIL
 *  bytes; the wire carries only 4 KB cells (+ optional jitter). This is what the
 *  requester talks to (as if it were a direct socket to the provider) and what
 *  R2 uses toward R1. */
export class CellDuplex extends Duplex {
  private socket: net.Socket;
  private decoder = new CellDecoder();
  private jitterMs: number;

  constructor(socket: net.Socket, opts: { jitterMs?: number } = {}) {
    super();
    this.socket = socket;
    this.jitterMs = opts.jitterMs ?? 0;
    socket.on("data", (d: Buffer) => {
      try {
        const raw = this.decoder.push(new Uint8Array(d));
        if (raw.length) this.push(Buffer.from(raw));
      } catch (e) {
        this.destroy(e as Error);
      }
    });
    socket.on("error", (e) => this.destroy(e));
    socket.on("close", () => this.push(null));
    socket.resume();
  }

  _read(): void {
    /* push-driven by socket 'data' */
  }

  _write(chunk: Buffer, _enc: BufferEncoding, cb: (e?: Error | null) => void): void {
    const cells = toCells(new Uint8Array(chunk));
    const flush = () => {
      for (const c of cells) this.socket.write(Buffer.from(c));
      cb();
    };
    if (this.jitterMs > 0) setTimeout(flush, Math.floor((this.jitterMs * randomBytes(1)[0]) / 255));
    else flush();
  }

  _final(cb: () => void): void {
    this.socket.end();
    cb();
  }
}

// ------------------------------------------------------------------ relay reader

/** Read exactly one length-prefixed onion frame from a socket, then hand back
 *  the frame body and any already-buffered stream bytes. */
function readOnionFrame(socket: net.Socket, cb: (body: Uint8Array, rest: Buffer) => void, onErr: () => void): void {
  let acc = Buffer.alloc(0);
  const onData = (chunk: Buffer) => {
    acc = Buffer.concat([acc, chunk]);
    if (acc.length < 2) return;
    const bodyLen = acc.readUInt16BE(0);
    if (bodyLen > MAX_ONION_BODY) {
      socket.off("data", onData);
      onErr();
      return;
    }
    if (acc.length < 2 + bodyLen) return;
    socket.off("data", onData);
    socket.pause(); // stop flow until the splice/pipe re-attaches a reader (no drops)
    const body = new Uint8Array(acc.subarray(2, 2 + bodyLen));
    const rest = acc.subarray(2 + bodyLen);
    cb(body, rest);
  };
  socket.on("data", onData);
}

// ------------------------------------------------------------------ relay server

export interface MilRelayOptions {
  /** This relay's ML-KEM-1024 secret key (opens its onion layer). */
  skKem: Uint8Array;
  port: number;
  host?: string;
  /** Cell jitter (ms) applied on the R2→R1 return path; 0 = deterministic. */
  jitterMs?: number;
}

/** A stake-registered relay node. The SAME binary serves as R1 or R2 — the role
 *  is decided per connection by whether its onion layer wraps an inner frame
 *  (intermediate ⇒ forward verbatim) or not (last ⇒ terminate the cell transport
 *  and dial the provider). It never holds plaintext or session keys (U6). */
export class MilRelay {
  private server: net.Server | null = null;
  private opts: MilRelayOptions;
  constructor(opts: MilRelayOptions) {
    this.opts = opts;
  }

  start(): Promise<{ port: number }> {
    return new Promise((resolve, reject) => {
      const server = net.createServer((sock) => this.onConn(sock));
      server.on("error", reject);
      server.listen(this.opts.port, this.opts.host ?? "0.0.0.0", () => {
        const addr = server.address();
        resolve({ port: typeof addr === "object" && addr ? addr.port : this.opts.port });
      });
      this.server = server;
    });
  }

  stop(): void {
    this.server?.close();
    this.server = null;
  }

  private onConn(inbound: net.Socket): void {
    readOnionFrame(
      inbound,
      (body, rest) => {
        let opened: { next: HopTarget; innerFrame: Uint8Array };
        try {
          opened = openLayer(this.opts.skKem, body);
        } catch {
          inbound.destroy();
          return;
        }
        const upstream = net.connect(opened.next, () => {
          if (opened.innerFrame.length > 0) {
            // Intermediate relay (R1): forward the inner onion frame, then splice
            // the cell stream VERBATIM in both directions — R1 reads only cells.
            upstream.write(Buffer.from(opened.innerFrame));
            if (rest.length) upstream.write(rest);
            inbound.pipe(upstream);
            upstream.pipe(inbound);
          } else {
            // Last relay (R2): the next hop is the provider, which speaks RAW MIL
            // bytes. Terminate the cell transport: de-cell inbound→provider and
            // re-cell provider→inbound so the R1 link stays uniform 4 KB cells.
            this.spliceCellToRaw(inbound, upstream, rest);
          }
        });
        upstream.on("error", () => inbound.destroy());
        inbound.on("error", () => upstream.destroy());
        inbound.on("close", () => upstream.destroy());
        upstream.on("close", () => inbound.destroy());
      },
      () => inbound.destroy(),
    );
  }

  /** R2's terminator: `cellSock` (toward R1) carries 4 KB cells; `rawSock`
   *  (toward the provider) carries raw MIL bytes. */
  private spliceCellToRaw(cellSock: net.Socket, rawSock: net.Socket, prebuffered: Buffer): void {
    const dec = new CellDecoder();
    const feed = (d: Buffer) => {
      try {
        const raw = dec.push(new Uint8Array(d));
        if (raw.length) rawSock.write(Buffer.from(raw));
      } catch {
        cellSock.destroy();
      }
    };
    if (prebuffered.length) feed(prebuffered);
    cellSock.on("data", feed);
    rawSock.on("data", (d: Buffer) => {
      for (const c of toCells(new Uint8Array(d))) cellSock.write(Buffer.from(c));
    });
  }
}

// ------------------------------------------------------------------ client helper

export interface ConnectOptions {
  jitterMs?: number;
  /** Connect timeout (ms) to R1. */
  timeoutMs?: number;
}

/** Requester-side: dial R1, send the onion routing the circuit to `target`
 *  (the provider) via `hops`, and return a duplex over which the caller runs the
 *  ordinary MIL data-plane handshake — it writes/reads *raw* MIL bytes while the
 *  wire carries only 4 KB cells. Drop-in for a direct socket to the provider. */
export function connectThroughRelays(hops: RelayInfo[], target: HopTarget, opts: ConnectOptions = {}): Promise<CellDuplex> {
  if (hops.length < 2) throw new Error("MIL relay: U2 requires 2 hops for Tier-2");
  const onion = buildOnion(hops, target);
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host: hops[0].host, port: hops[0].port }, () => {
      sock.pause(); // buffer inbound until CellDuplex attaches its reader
      sock.write(Buffer.from(onion)); // raw onion header precedes the cell stream
      resolve(new CellDuplex(sock, { jitterMs: opts.jitterMs }));
    });
    if (opts.timeoutMs) sock.setTimeout(opts.timeoutMs, () => sock.destroy(new Error("MIL relay: connect timeout")));
    sock.on("error", reject);
  });
}

/** Stake-weighted random selection of `count` DISTINCT relays (U2: "the SDK
 *  picks two stake-weighted at random"). `rng` is injectable for tests. */
export function selectHops(relays: RelayInfo[], count = 2, rng: () => number = Math.random): RelayInfo[] {
  if (relays.length < count) throw new Error(`MIL relay: need ≥ ${count} relays, have ${relays.length}`);
  const pool = relays.slice();
  const chosen: RelayInfo[] = [];
  for (let k = 0; k < count; k++) {
    const total = pool.reduce((s, r) => s + (r.stake && r.stake > 0n ? r.stake : 1n), 0n);
    // pick a target in [0,total) using rng, weighted by stake
    let target = BigInt(Math.floor(rng() * Number(total)));
    let idx = 0;
    for (; idx < pool.length; idx++) {
      const w = pool[idx].stake && pool[idx].stake! > 0n ? pool[idx].stake! : 1n;
      if (target < w) break;
      target -= w;
    }
    chosen.push(pool[Math.min(idx, pool.length - 1)]);
    pool.splice(Math.min(idx, pool.length - 1), 1);
  }
  return chosen;
}
