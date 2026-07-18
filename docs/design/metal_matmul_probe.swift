// MISAKA PALW §19.5 M1 op-ratchet — step 1: canonical Q4-style matmul cross-gen golden.
// Parallel tiled matmul, K-reduction in INT32 (order-independent), fp32 scale combine. Deterministic
// int8 inputs generated in-kernel. Each of M*N threads computes one output; the host FNV-digests the fp32
// bit patterns. Run on M1 Max and M4 Pro and diff DIGEST: a match ratchets the matmul op for (a).
//   swift metal_matmul_probe.swift
import Metal
import Foundation

let src = """
#include <metal_stdlib>
using namespace metal;

// deterministic pseudo-random int8 in [-127,127] from a coordinate hash (splitmix-ish, integer only)
inline int q8(uint x) {
    x ^= x >> 16; x *= 0x7feb352du; x ^= x >> 15; x *= 0x846ca68bu; x ^= x >> 16;
    return (int)(x & 0xff) - 128; // [-128,127]
}

// C[m][n] = ( sum_k A[m][k]*B[k][n] ) * (sa*sb), A/B int8, K-accum int32 (order-independent), fp32 scale.
kernel void matmul(device float* out [[buffer(0)]],
                   constant uint& M [[buffer(1)]],
                   constant uint& N [[buffer(2)]],
                   constant uint& K [[buffer(3)]],
                   uint gid [[thread_position_in_grid]]) {
    if (gid >= M * N) return;
    uint m = gid / N, n = gid % N;
    int acc = 0;                       // int32 accumulation — parallel-order-invariant by construction
    for (uint k = 0; k < K; ++k) {
        int a = q8(m * 2654435761u + k * 40503u + 1u);
        int b = q8(k * 2246822519u + n * 3266489917u + 7u);
        acc += a * b;
    }
    float sa = 0x1.5p-4f, sb = 0x1.9p-5f; // fixed fp32 scales
    out[gid] = (float)acc * (sa * sb);
}
"""

guard let dev = MTLCreateSystemDefaultDevice() else { fatalError("no Metal device") }
print("device: \(dev.name)")
let opts = MTLCompileOptions(); opts.fastMathEnabled = false
let lib = try! dev.makeLibrary(source: src, options: opts)
let q = dev.makeCommandQueue()!
let pipe = try! dev.makeComputePipelineState(function: lib.makeFunction(name: "matmul")!)

func u32(_ v: UInt32) -> MTLBuffer { var x = v; return dev.makeBuffer(bytes: &x, length: 4, options: .storageModeShared)! }
let (M, N, K): (UInt32, UInt32, UInt32) = (96, 96, 256)   // non-power-of-2 tile to stress edges
let count = Int(M * N)
let outBuf = dev.makeBuffer(length: count * 4, options: .storageModeShared)!
let cb = q.makeCommandBuffer()!; let enc = cb.makeComputeCommandEncoder()!
enc.setComputePipelineState(pipe)
enc.setBuffer(outBuf, offset: 0, index: 0)
enc.setBuffer(u32(M), offset: 0, index: 1); enc.setBuffer(u32(N), offset: 0, index: 2); enc.setBuffer(u32(K), offset: 0, index: 3)
enc.dispatchThreads(MTLSize(width: count, height: 1, depth: 1), threadsPerThreadgroup: MTLSize(width: 64, height: 1, depth: 1))
enc.endEncoding(); cb.commit(); cb.waitUntilCompleted()

let p = outBuf.contents().bindMemory(to: UInt32.self, capacity: count)
var digest = UInt64(1469598103934665603)
for i in 0..<count { digest = (digest ^ UInt64(p[i])) &* 1099511628211 }
print("matmul \(M)x\(N)x\(K)  first=\(String(format:"0x%08x", p[0]))  last=\(String(format:"0x%08x", p[count-1]))")
print(String(format: "DIGEST 0x%016llx", digest))
