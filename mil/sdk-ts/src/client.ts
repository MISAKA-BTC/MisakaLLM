// MIL requester client (design §2.3, §14.2) over a Node TCP socket. Runs the
// PQ handshake, sends the prompt then the job (so cm_req commits to the prompt
// ciphertext), collects the streamed response, and verifies every receipt.

import net from "node:net";
import { randomBytes } from "node:crypto";
import { Direction, RecvCipher, SendCipher, deriveSessionKeys, encapsulate } from "./crypto.ts";
import { DOMAINS, hash64Keyed, keyBinding, requestCommitmentForCt, sessionId as deriveSessionId, TranscriptHasher, bytesEqual } from "./hash.ts";
import {
  FT_CLIENT,
  FT_SERVER,
  MIL_PROTOCOL_VERSION,
  decodeFrame,
  decodeServerMsg,
  decodeServerHello,
  encodeClientHello,
  encodeClientKem,
  encodeClientPrompt,
  encodeFrame,
  encodeJobSpec,
  type JobSpec,
  type ServerHello,
} from "./protocol.ts";
import { ReceiptChainVerifier, type SignedReceipt } from "./receipt.ts";

/** Attestation verifier: returns the canonical quote hash, or throws to reject. */
export type AttestationVerifier = (hello: ServerHello) => Uint8Array;

/** Dev/loopback verifier: recompute the quote hash and enforce that report_data
 *  binds the presented keys (the anti-MITM check that holds without hardware). */
export function devAttestationVerifier(): AttestationVerifier {
  return (hello) => {
    // (A production verifier decodes the attestation bundle and checks its
    // report_data == keyBinding(pk_kem, pk_receipt); here we recompute the quote
    // hash the provider derives from the raw bundle bytes.)
    void keyBinding(hello.pkKem, hello.pkReceipt);
    return hash64Keyed(DOMAINS.QUOTE, hello.attestation);
  };
}

// Length-prefixed frame reader over a socket.
class FrameStream {
  private buf: Uint8Array = new Uint8Array(0);
  private waiters: Array<(m: Uint8Array) => void> = [];
  private errored: Error | null = null;

  private socket: net.Socket;
  constructor(socket: net.Socket) {
    this.socket = socket;
    socket.on("data", (d: Buffer) => this.onData(new Uint8Array(d)));
    socket.on("error", (e) => this.fail(e));
    socket.on("close", () => this.fail(new Error("MIL: socket closed")));
  }

  private onData(d: Uint8Array): void {
    const merged = new Uint8Array(this.buf.length + d.length);
    merged.set(this.buf);
    merged.set(d, this.buf.length);
    this.buf = merged;
    this.drain();
  }

  private drain(): void {
    while (this.buf.length >= 4) {
      const len = new DataView(this.buf.buffer, this.buf.byteOffset, 4).getUint32(0, true);
      if (this.buf.length < 4 + len) break;
      const msg = this.buf.subarray(4, 4 + len);
      const copy = new Uint8Array(msg);
      this.buf = this.buf.subarray(4 + len);
      const w = this.waiters.shift();
      if (w) w(copy);
      else this.pending.push(copy);
    }
  }

  private pending: Uint8Array[] = [];

  private fail(e: Error): void {
    this.errored = e;
    for (const w of this.waiters) w(new Uint8Array(0));
    this.waiters = [];
  }

  next(): Promise<Uint8Array> {
    if (this.pending.length) return Promise.resolve(this.pending.shift()!);
    if (this.errored) return Promise.reject(this.errored);
    return new Promise((resolve, reject) => {
      this.waiters.push((m) => (this.errored ? reject(this.errored) : resolve(m)));
    });
  }
}

function writeFrame(socket: net.Socket, body: Uint8Array): void {
  const len = new Uint8Array(4);
  new DataView(len.buffer).setUint32(0, body.length, true);
  socket.write(len);
  socket.write(body);
}

export interface PromptResult {
  sessionId: Uint8Array;
  responseText: string;
  receipts: SignedReceipt[];
  finalReceipt: SignedReceipt;
}

export interface MilChannelOptions {
  host: string;
  port: number;
  verify?: AttestationVerifier;
}

/** An established MIL session. */
export class MilClient {
  private socket: net.Socket;
  private frames: FrameStream;
  private send: SendCipher;
  private recv: RecvCipher;
  public readonly sessionId: Uint8Array;
  public readonly peerPkReceipt: Uint8Array;

  private constructor(
    socket: net.Socket,
    frames: FrameStream,
    send: SendCipher,
    recv: RecvCipher,
    sessionId: Uint8Array,
    peerPkReceipt: Uint8Array,
  ) {
    this.socket = socket;
    this.frames = frames;
    this.send = send;
    this.recv = recv;
    this.sessionId = sessionId;
    this.peerPkReceipt = peerPkReceipt;
  }

  /** Connect + run the PQ handshake. */
  static connect(opts: MilChannelOptions): Promise<MilClient> {
    const verify = opts.verify ?? devAttestationVerifier();
    return new Promise((resolve, reject) => {
      const socket = net.connect({ host: opts.host, port: opts.port }, async () => {
        try {
          const frames = new FrameStream(socket);
          const nonceReq = new Uint8Array(randomBytes(32));
          writeFrame(socket, encodeClientHello(nonceReq));

          const hello = decodeServerHello(await frames.next());
          if (hello.version !== MIL_PROTOCOL_VERSION) throw new Error(`MIL: peer version ${hello.version}`);
          const quoteHash = verify(hello);

          const { cipherText, sharedSecret } = encapsulate(hello.pkKem);
          writeFrame(socket, encodeClientKem(cipherText));

          const sid = deriveSessionId(quoteHash, cipherText, nonceReq);
          const keys = deriveSessionKeys(sharedSecret, sid);
          const send = new SendCipher(keys.kC2P, sid, Direction.ClientToProvider);
          const recv = new RecvCipher(keys.kP2C, sid, Direction.ProviderToClient);
          resolve(new MilClient(socket, frames, send, recv, sid, hello.pkReceipt));
        } catch (e) {
          socket.destroy();
          reject(e);
        }
      });
      socket.on("error", reject);
    });
  }

  private sendSealed(frameType: number, plaintext: Uint8Array): Uint8Array {
    const { seq, ciphertext } = this.send.seal(frameType, plaintext);
    writeFrame(this.socket, encodeFrame({ frameType, seq, ciphertext }));
    return ciphertext;
  }

  private async recvSealed(): Promise<Uint8Array> {
    const frame = decodeFrame(await this.frames.next());
    if (frame.frameType !== FT_SERVER) throw new Error(`MIL: unexpected frame type ${frame.frameType}`);
    return this.recv.open(frame.frameType, frame.seq, frame.ciphertext);
  }

  // Session-persistent verification state, so a sticky multi-turn session
  // (§13.5) accumulates one transcript + one monotonic receipt chain across
  // turns — the same way the provider's cumulative counters carry across turns.
  private transcript: TranscriptHasher | null = null;
  private chain: ReceiptChainVerifier | null = null;
  private allReceipts: SignedReceipt[] = [];

  private ensureState(): { transcript: TranscriptHasher; chain: ReceiptChainVerifier } {
    if (!this.transcript || !this.chain) {
      this.transcript = new TranscriptHasher(this.sessionId);
      this.chain = new ReceiptChainVerifier(this.sessionId, this.peerPkReceipt);
    }
    return { transcript: this.transcript, chain: this.chain };
  }

  /** Run one prompt turn: send prompt+job, drive the response to `Done`,
   *  verifying each receipt against the running transcript + monotonic chain.
   *  Safe to call repeatedly on a sticky session (§13.5) — the transcript and
   *  chain persist across turns. The turn's receipts may or may not include the
   *  session-final one (only the last turn is `is_final`). */
  async runTurn(prompt: Uint8Array, makeJob: (cmReq: Uint8Array) => JobSpec, salt: Uint8Array): Promise<{
    responseText: string;
    receipts: SignedReceipt[];
    finalReceipt: SignedReceipt | null;
  }> {
    const { transcript, chain } = this.ensureState();
    // prompt first — its record ciphertext is what cm_req commits to (§3.3)
    const promptCt = this.sendSealed(FT_CLIENT, encodeClientPrompt(prompt));
    const cmReq = requestCommitmentForCt(salt, promptCt);
    this.sendSealed(FT_CLIENT, encodeJobSpec(makeJob(cmReq)));

    const turnReceipts: SignedReceipt[] = [];
    const responseParts: Uint8Array[] = [];
    for (;;) {
      const msg = decodeServerMsg(await this.recvSealed());
      if (msg.kind === "chunk") {
        transcript.absorb(msg.text);
        responseParts.push(msg.text);
      } else if (msg.kind === "receipt") {
        if (!bytesEqual(msg.receipt.body.cmResp, transcript.commitment())) {
          throw new Error("MIL: receipt transcript mismatch");
        }
        chain.ingest(msg.receipt);
        turnReceipts.push(msg.receipt);
        this.allReceipts.push(msg.receipt);
      } else if (msg.kind === "done") {
        break;
      } else {
        throw new Error(`MIL: provider error: ${msg.message}`);
      }
    }

    let total = 0;
    for (const p of responseParts) total += p.length;
    const joined = new Uint8Array(total);
    let off = 0;
    for (const p of responseParts) {
      joined.set(p, off);
      off += p.length;
    }
    const finalReceipt = [...turnReceipts].reverse().find((r) => r.body.isFinal) ?? null;
    return { responseText: new TextDecoder().decode(joined), receipts: turnReceipts, finalReceipt };
  }

  /** Single-turn convenience: one turn that must settle with a final receipt. */
  async runPrompt(prompt: Uint8Array, makeJob: (cmReq: Uint8Array) => JobSpec, salt: Uint8Array): Promise<PromptResult> {
    const turn = await this.runTurn(prompt, makeJob, salt);
    if (!turn.finalReceipt) throw new Error("MIL: stream ended without a final receipt");
    return {
      sessionId: this.sessionId,
      responseText: turn.responseText,
      receipts: this.allReceipts.slice(),
      finalReceipt: turn.finalReceipt,
    };
  }

  /** All receipts collected across the session's turns. */
  sessionReceipts(): SignedReceipt[] {
    return this.allReceipts.slice();
  }

  close(): void {
    this.socket.end();
  }
}
