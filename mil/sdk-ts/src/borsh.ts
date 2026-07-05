// Minimal Borsh reader/writer for the MIL wire types (design §2.2/§3.2).
// Matches the Rust `borsh` encoding: little-endian ints, u32-length-prefixed
// Vec<u8>/String, u8-tagged Option/enum, fixed arrays inline. Only the subset
// the MIL protocol needs is implemented.

export class BorshWriter {
  private chunks: Uint8Array[] = [];

  u8(v: number): this {
    this.chunks.push(Uint8Array.of(v & 0xff));
    return this;
  }
  u16(v: number): this {
    const b = new Uint8Array(2);
    new DataView(b.buffer).setUint16(0, v, true);
    this.chunks.push(b);
    return this;
  }
  u32(v: number): this {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, v >>> 0, true);
    this.chunks.push(b);
    return this;
  }
  u64(v: bigint): this {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, v, true);
    this.chunks.push(b);
    return this;
  }
  bool(v: boolean): this {
    return this.u8(v ? 1 : 0);
  }
  // A raw fixed-length field (e.g. Hash64 = 64 bytes) — NO length prefix.
  fixed(bytes: Uint8Array): this {
    this.chunks.push(bytes);
    return this;
  }
  // A borsh Vec<u8> — u32 length prefix then the bytes.
  bytes(bytes: Uint8Array): this {
    this.u32(bytes.length);
    this.chunks.push(bytes);
    return this;
  }
  string(s: string): this {
    return this.bytes(new TextEncoder().encode(s));
  }
  option<T>(v: T | null | undefined, write: (w: BorshWriter, val: T) => void): this {
    if (v === null || v === undefined) return this.u8(0);
    this.u8(1);
    write(this, v);
    return this;
  }

  finish(): Uint8Array {
    let len = 0;
    for (const c of this.chunks) len += c.length;
    const out = new Uint8Array(len);
    let off = 0;
    for (const c of this.chunks) {
      out.set(c, off);
      off += c.length;
    }
    return out;
  }
}

export class BorshReader {
  private off = 0;
  private view: DataView;
  private buf: Uint8Array;

  constructor(buf: Uint8Array) {
    this.buf = buf;
    this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  }

  u8(): number {
    return this.buf[this.off++];
  }
  u16(): number {
    const v = this.view.getUint16(this.off, true);
    this.off += 2;
    return v;
  }
  u32(): number {
    const v = this.view.getUint32(this.off, true);
    this.off += 4;
    return v;
  }
  u64(): bigint {
    const v = this.view.getBigUint64(this.off, true);
    this.off += 8;
    return v;
  }
  bool(): boolean {
    return this.u8() !== 0;
  }
  fixed(n: number): Uint8Array {
    const s = this.buf.subarray(this.off, this.off + n);
    this.off += n;
    return s;
  }
  bytes(): Uint8Array {
    const n = this.u32();
    return this.fixed(n);
  }
  string(): string {
    return new TextDecoder().decode(this.bytes());
  }
  option<T>(read: (r: BorshReader) => T): T | null {
    return this.u8() === 1 ? read(this) : null;
  }
  remaining(): number {
    return this.buf.length - this.off;
  }
}
