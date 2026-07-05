import Foundation

/// Minimal Borsh writer/reader for the MIL wire types (design §2.2). Matches
/// the Rust `borsh` encoding: little-endian ints, u32-length-prefixed
/// Vec<u8>/String, u8-tagged Option/enum, fixed arrays inline.
public struct BorshWriter {
    public private(set) var bytes: [UInt8] = []
    public init() {}

    public mutating func u8(_ v: UInt8) { bytes.append(v) }
    public mutating func u16(_ v: UInt16) { for i in 0..<2 { bytes.append(UInt8((v >> (8 * UInt16(i))) & 0xff)) } }
    public mutating func u32(_ v: UInt32) { for i in 0..<4 { bytes.append(UInt8((v >> (8 * UInt32(i))) & 0xff)) } }
    public mutating func u64(_ v: UInt64) { for i in 0..<8 { bytes.append(UInt8((v >> (8 * UInt64(i))) & 0xff)) } }
    public mutating func bool(_ v: Bool) { bytes.append(v ? 1 : 0) }
    public mutating func fixed(_ b: [UInt8]) { bytes.append(contentsOf: b) }
    public mutating func vecU8(_ b: [UInt8]) { u32(UInt32(b.count)); bytes.append(contentsOf: b) }
    public mutating func string(_ s: String) { vecU8(Array(s.utf8)) }
    public mutating func option(_ present: Bool, _ write: (inout BorshWriter) -> Void) {
        if present { u8(1); write(&self) } else { u8(0) }
    }
}

public struct BorshReader {
    private let buf: [UInt8]
    private var off = 0
    public init(_ buf: [UInt8]) { self.buf = buf }

    public mutating func u8() -> UInt8 { defer { off += 1 }; return buf[off] }
    public mutating func u16() -> UInt16 {
        var v: UInt16 = 0
        for i in 0..<2 { v |= UInt16(buf[off + i]) << (8 * UInt16(i)) }
        off += 2
        return v
    }
    public mutating func u32() -> UInt32 {
        var v: UInt32 = 0
        for i in 0..<4 { v |= UInt32(buf[off + i]) << (8 * UInt32(i)) }
        off += 4
        return v
    }
    public mutating func u64() -> UInt64 {
        var v: UInt64 = 0
        for i in 0..<8 { v |= UInt64(buf[off + i]) << (8 * UInt64(i)) }
        off += 8
        return v
    }
    public mutating func bool() -> Bool { u8() != 0 }
    public mutating func fixed(_ n: Int) -> [UInt8] { defer { off += n }; return Array(buf[off..<off + n]) }
    public mutating func vecU8() -> [UInt8] { let n = Int(u32()); return fixed(n) }
    public mutating func string() -> String { String(decoding: vecU8(), as: UTF8.self) }
    public mutating func option<T>(_ read: (inout BorshReader) -> T) -> T? {
        u8() == 1 ? read(&self) : nil
    }
    public var remaining: Int { buf.count - off }
}
