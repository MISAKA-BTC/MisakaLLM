// MISAKA PALW §19.2 canonical-Metal probe — bit-exact fp32 behavior across Apple GPU generations.
// Runs a fixed compute kernel under fast-math DISABLED and prints exact fp32 bit patterns (hex).
// Run the SAME file on M1 Max and M4 Pro and diff: identical output ⇒ the canonical op set is cross-gen
// bit-stable ⇒ the (a) logits-bit-exact path is feasible. Any differing line names the divergent op.
//   swift metal_probe.swift
import Metal
import Foundation

let src = """
#include <metal_stdlib>
using namespace metal;

// software exp: fixed 6-term series, explicit fma, no hardware exp (probe determinism, not accuracy)
inline float exp_soft(float x) {
    float p = 1.0f/720.0f;
    p = fma(p, x, 1.0f/120.0f);
    p = fma(p, x, 1.0f/24.0f);
    p = fma(p, x, 1.0f/6.0f);
    p = fma(p, x, 0.5f);
    p = fma(p, x, 1.0f);
    p = fma(p, x, 1.0f);
    return p;
}
// rsqrt: integer-bit seed + two Newton steps, explicit fma; no hardware rsqrt/approx seed
inline float rsqrt_soft(float x) {
    int i = as_type<int>(x);
    i = 0x5f3759df - (i >> 1);
    float y = as_type<float>(i);
    float t = y * y;
    y = y * fma(-0.5f * x, t, 1.5f);
    t = y * y;
    y = y * fma(-0.5f * x, t, 1.5f);
    return y;
}

kernel void probe(device uint* out [[buffer(0)]], uint gid [[thread_position_in_grid]]) {
    if (gid != 0) return;
    uint n = 0;
    // (1) safe-math contraction / fma determinism: fma(a,b,c) vs a*b+c on a contraction-bait triple.
    //     Under safe math these SHOULD differ (fma single-rounded); each must be stable cross-gen.
    float a = 1.0000001f, b = 1.0000001f, c = -1.0f;
    float f1 = fma(a, b, c);
    float f2 = a * b + c;
    out[n++] = as_type<uint>(f1);
    out[n++] = as_type<uint>(f2);
    // (2) precise divide — correctly-rounded on both generations?
    out[n++] = as_type<uint>(1.0f / 3.0f);
    out[n++] = as_type<uint>(2.0f / 3.0f);
    out[n++] = as_type<uint>(0x1.000002p+0f / 0x1.000004p+0f); // near-tie
    // (3) software transcendentals (the canonical replacements)
    out[n++] = as_type<uint>(exp_soft(0.5f));
    out[n++] = as_type<uint>(exp_soft(-0.7f));
    out[n++] = as_type<uint>(exp_soft(2.0f));
    out[n++] = as_type<uint>(rsqrt_soft(2.0f));
    out[n++] = as_type<uint>(rsqrt_soft(0.1f));
    out[n++] = as_type<uint>(rsqrt_soft(1000.0f));
    // (4) denormals — flushed or preserved, same on both?
    float d1 = as_type<float>((uint)1);       // smallest denormal
    float d3 = as_type<float>((uint)3);
    out[n++] = as_type<uint>(d1 + d1);
    out[n++] = as_type<uint>(d3 * 2.0f);
    out[n++] = as_type<uint>(1.0f + d1);
    // (5) long fma chain (accumulation-order stress in a single thread; fixed order)
    float acc = 0.0f;
    for (int k = 1; k <= 64; ++k) {
        acc = fma((float)k, 1.0f / (float)k, acc); // += ~1 each, but via fma with rounding
    }
    out[n++] = as_type<uint>(acc);
    // (6) simd butterfly reduction over 1..32 via shuffle_xor (fixed lane order) — but gid==0 only sees
    //     its own lane; done in a separate kernel below. Here: a fixed pairwise tree sum of 8 values.
    float v[8] = {1.1f, 2.2f, 3.3f, 4.4f, 5.5f, 6.6f, 7.7f, 8.8f};
    float s01 = v[0] + v[1], s23 = v[2] + v[3], s45 = v[4] + v[5], s67 = v[6] + v[7];
    float s0123 = s01 + s23, s4567 = s45 + s67;
    out[n++] = as_type<uint>(s0123 + s4567);
    out[n] = n; // count marker (overwritten last slot for sanity — see host)
}

kernel void probe_simd(device uint* out [[buffer(0)]],
                       uint lane [[thread_position_in_grid]],
                       uint sg_size [[threads_per_simdgroup]]) {
    // butterfly sum of lane values (lane+1) over the simdgroup, fixed xor order
    float x = (float)(lane + 1);
    for (uint off = sg_size / 2; off > 0; off >>= 1) {
        x += simd_shuffle_xor(x, off);
    }
    if (lane == 0) { out[0] = as_type<uint>(x); out[1] = sg_size; }
}
"""

guard let dev = MTLCreateSystemDefaultDevice() else { fatalError("no Metal device") }
print("device: \(dev.name)")

let opts = MTLCompileOptions()
opts.fastMathEnabled = false   // §19.1: safe math, explicit fma only
let lib = try! dev.makeLibrary(source: src, options: opts)
let q = dev.makeCommandQueue()!

func run(_ fn: String, threads: Int, count: Int) -> [UInt32] {
    let pipe = try! dev.makeComputePipelineState(function: lib.makeFunction(name: fn)!)
    let buf = dev.makeBuffer(length: count * 4, options: .storageModeShared)!
    let cb = q.makeCommandBuffer()!
    let enc = cb.makeComputeCommandEncoder()!
    enc.setComputePipelineState(pipe)
    enc.setBuffer(buf, offset: 0, index: 0)
    enc.dispatchThreads(MTLSize(width: threads, height: 1, depth: 1),
                        threadsPerThreadgroup: MTLSize(width: min(threads, 32), height: 1, depth: 1))
    enc.endEncoding(); cb.commit(); cb.waitUntilCompleted()
    let p = buf.contents().bindMemory(to: UInt32.self, capacity: count)
    return (0..<count).map { p[$0] }
}

let labels = ["fma(a,b,c)","a*b+c","1/3","2/3","near-tie-div","exp(0.5)","exp(-0.7)","exp(2.0)",
              "rsqrt(2)","rsqrt(0.1)","rsqrt(1000)","denorm+denorm","denorm3*2","1+denorm",
              "fma-chain-64","tree-sum-8"]
let r = run("probe", threads: 1, count: labels.count + 1)
print("=== scalar probes (fp32 bit patterns) ===")
for (i, l) in labels.enumerated() { print(String(format: "%-14s 0x%08x", (l as NSString).utf8String!, r[i])) }
let s = run("probe_simd", threads: 32, count: 2)
print(String(format: "%-14s 0x%08x  (simdgroup=%d)", ("simd-butterfly" as NSString).utf8String!, s[0], s[1]))

// one-line digest for quick cross-machine diff
var all = r.dropLast().map { $0 }; all.append(s[0])
let digest = all.reduce(UInt64(1469598103934665603)) { (h, v) in (h ^ UInt64(v)) &* 1099511628211 }
print(String(format: "DIGEST 0x%016llx", digest))
