import Foundation

/// Pure-Swift BLAKE2b-512 (RFC 7693), with optional keying — the Hash64
/// primitive for MIL (`kaspa_hashes::blake2b_512_keyed`). Kept dependency-free
/// so the SDK's Hash64 derivations can be cross-checked against Rust vectors
/// without a crypto package.
public struct Blake2b {
    private static let iv: [UInt64] = [
        0x6a09_e667_f3bc_c908, 0xbb67_ae85_84ca_a73b,
        0x3c6e_f372_fe94_f82b, 0xa54f_f53a_5f1d_36f1,
        0x510e_527f_ade6_82d1, 0x9b05_688c_2b3e_6c1f,
        0x1f83_d9ab_fb41_bd6b, 0x5be0_cd19_137e_2179,
    ]

    private static let sigma: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    ]

    private var h: [UInt64]
    private var t0: UInt64 = 0
    private var t1: UInt64 = 0
    private var buf = [UInt8](repeating: 0, count: 128)
    private var bufLen = 0
    private let outLen: Int

    public init(outLen: Int = 64, key: [UInt8] = []) {
        precondition(outLen >= 1 && outLen <= 64)
        precondition(key.count <= 64)
        self.outLen = outLen
        h = Blake2b.iv
        h[0] ^= 0x0101_0000 ^ (UInt64(key.count) << 8) ^ UInt64(outLen)
        if !key.isEmpty {
            var block = key
            block.append(contentsOf: [UInt8](repeating: 0, count: 128 - key.count))
            update(block)
        }
    }

    private static func rotr(_ x: UInt64, _ n: UInt64) -> UInt64 {
        (x >> n) | (x << (64 - n))
    }

    private mutating func compress(_ block: ArraySlice<UInt8>, last: Bool) {
        var m = [UInt64](repeating: 0, count: 16)
        let base = block.startIndex
        for i in 0..<16 {
            var w: UInt64 = 0
            for j in 0..<8 { w |= UInt64(block[base + i * 8 + j]) << (8 * UInt64(j)) }
            m[i] = w
        }
        var v = h + Blake2b.iv
        v[12] ^= t0
        v[13] ^= t1
        if last { v[14] = ~v[14] }

        func g(_ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt64, _ y: UInt64) {
            v[a] = v[a] &+ v[b] &+ x
            v[d] = Blake2b.rotr(v[d] ^ v[a], 32)
            v[c] = v[c] &+ v[d]
            v[b] = Blake2b.rotr(v[b] ^ v[c], 24)
            v[a] = v[a] &+ v[b] &+ y
            v[d] = Blake2b.rotr(v[d] ^ v[a], 16)
            v[c] = v[c] &+ v[d]
            v[b] = Blake2b.rotr(v[b] ^ v[c], 63)
        }

        for r in 0..<12 {
            let s = Blake2b.sigma[r]
            g(0, 4, 8, 12, m[s[0]], m[s[1]])
            g(1, 5, 9, 13, m[s[2]], m[s[3]])
            g(2, 6, 10, 14, m[s[4]], m[s[5]])
            g(3, 7, 11, 15, m[s[6]], m[s[7]])
            g(0, 5, 10, 15, m[s[8]], m[s[9]])
            g(1, 6, 11, 12, m[s[10]], m[s[11]])
            g(2, 7, 8, 13, m[s[12]], m[s[13]])
            g(3, 4, 9, 14, m[s[14]], m[s[15]])
        }
        for i in 0..<8 { h[i] ^= v[i] ^ v[i + 8] }
    }

    public mutating func update(_ data: [UInt8]) {
        var offset = 0
        while offset < data.count {
            if bufLen == 128 {
                t0 = t0 &+ 128
                if t0 < 128 { t1 = t1 &+ 1 }
                compress(buf[0..<128], last: false)
                bufLen = 0
            }
            let take = min(128 - bufLen, data.count - offset)
            for i in 0..<take { buf[bufLen + i] = data[offset + i] }
            bufLen += take
            offset += take
        }
    }

    public mutating func finalize() -> [UInt8] {
        t0 = t0 &+ UInt64(bufLen)
        if t0 < UInt64(bufLen) { t1 = t1 &+ 1 }
        for i in bufLen..<128 { buf[i] = 0 }
        compress(buf[0..<128], last: true)
        var out = [UInt8](repeating: 0, count: outLen)
        for i in 0..<outLen { out[i] = UInt8((h[i / 8] >> (8 * UInt64(i % 8))) & 0xff) }
        return out
    }

    /// One-shot keyed BLAKE2b-512.
    public static func keyed512(key: [UInt8], data: [UInt8]) -> [UInt8] {
        var s = Blake2b(outLen: 64, key: key)
        s.update(data)
        return s.finalize()
    }
}
