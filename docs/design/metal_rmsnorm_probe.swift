// MISAKA PALW §19.5 M1 op-ratchet — step 2: canonical RMSNorm cross-gen golden.
// The FIRST op with a parallel fp32 reduction (sum of x^2 over the hidden dim), where reduction ORDER
// first matters. Canonical order: per-thread fixed-stride partial (fma) → simd_shuffle_xor butterfly
// (fixed lane order) → threadgroup fixed-tree across simdgroups. rsqrt via integer-seed Newton (software).
// D=896 (Qwen2.5-0.5B hidden, non-power-of-2 → ragged strides). Diff DIGEST across M1 Max / M4 Pro.
//   swift metal_rmsnorm_probe.swift
import Metal
import Foundation

let src = """
#include <metal_stdlib>
using namespace metal;

inline float rsqrt_soft(float x) {
    int i = as_type<int>(x);
    i = 0x5f3759df - (i >> 1);
    float y = as_type<float>(i);
    y = y * fma(-0.5f * x, y * y, 1.5f);
    y = y * fma(-0.5f * x, y * y, 1.5f);
    return y;
}
// deterministic fp32 activation in ~[-2,2)
inline float genx(uint i) {
    uint h = i * 2654435761u + 12345u; h ^= h >> 16; h *= 0x7feb352du; h ^= h >> 15;
    float u = (float)(h & 0xffffff) * (1.0f / 16777216.0f);
    return fma(u, 4.0f, -2.0f);
}
// deterministic weight in [0.5,1.5)
inline float genw(uint i) {
    uint h = i * 40503u + 7u; h ^= h >> 13; h *= 0x846ca68bu; h ^= h >> 16;
    float u = (float)(h & 0xffffff) * (1.0f / 16777216.0f);
    return u + 0.5f;
}

kernel void rmsnorm(device float* out [[buffer(0)]],
                    constant uint& D [[buffer(1)]],
                    uint tid [[thread_position_in_threadgroup]],
                    uint tgs [[threads_per_threadgroup]],
                    uint lane [[thread_index_in_simdgroup]],
                    uint sgid [[simdgroup_index_in_threadgroup]],
                    uint nsg [[simdgroups_per_threadgroup]]) {
    threadgroup float sg_partial[32];
    threadgroup float total_s;
    // per-thread partial sum of x^2 over a fixed stride (tid, tid+tgs, ...), explicit fma
    float ps = 0.0f;
    for (uint i = tid; i < D; i += tgs) { float x = genx(i); ps = fma(x, x, ps); }
    // simd butterfly reduction (fixed lane order)
    for (uint off = 16; off > 0; off >>= 1) ps += simd_shuffle_xor(ps, off);
    if (lane == 0) sg_partial[sgid] = ps;
    threadgroup_barrier(mem_flags::mem_threadgroup);
    // fixed-order sequential sum of the simdgroup partials
    if (tid == 0) {
        float t = 0.0f;
        for (uint s = 0; s < nsg; ++s) t += sg_partial[s];
        total_s = t;
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);
    float mean = total_s / (float)D;
    float rms = rsqrt_soft(mean + 1e-6f);
    for (uint i = tid; i < D; i += tgs) { out[i] = genx(i) * rms * genw(i); }
}
"""

guard let dev = MTLCreateSystemDefaultDevice() else { fatalError("no Metal device") }
print("device: \(dev.name)")
let opts = MTLCompileOptions(); opts.fastMathEnabled = false
let lib = try! dev.makeLibrary(source: src, options: opts)
let q = dev.makeCommandQueue()!
let pipe = try! dev.makeComputePipelineState(function: lib.makeFunction(name: "rmsnorm")!)

let D: UInt32 = 896
let outBuf = dev.makeBuffer(length: Int(D) * 4, options: .storageModeShared)!
var Dv = D; let dBuf = dev.makeBuffer(bytes: &Dv, length: 4, options: .storageModeShared)!
let cb = q.makeCommandBuffer()!; let enc = cb.makeComputeCommandEncoder()!
enc.setComputePipelineState(pipe)
enc.setBuffer(outBuf, offset: 0, index: 0); enc.setBuffer(dBuf, offset: 0, index: 1)
// one threadgroup of 256 threads (= 8 simdgroups) owns the whole row
enc.dispatchThreadgroups(MTLSize(width: 1, height: 1, depth: 1), threadsPerThreadgroup: MTLSize(width: 256, height: 1, depth: 1))
enc.endEncoding(); cb.commit(); cb.waitUntilCompleted()

let p = outBuf.contents().bindMemory(to: UInt32.self, capacity: Int(D))
var digest = UInt64(1469598103934665603)
for i in 0..<Int(D) { digest = (digest ^ UInt64(p[i])) &* 1099511628211 }
print("rmsnorm D=\(D)  out[0]=\(String(format:"0x%08x", p[0]))  out[D-1]=\(String(format:"0x%08x", p[Int(D)-1]))")
print(String(format: "DIGEST 0x%016llx", digest))
