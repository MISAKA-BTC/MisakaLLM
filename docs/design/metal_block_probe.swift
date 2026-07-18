// MISAKA PALW §19.5 M1 — canonical transformer BLOCK, end-to-end cross-gen golden.
// Composes the validated canonical ops (dispatch-per-op, like the real backend): rmsnorm → QKV matmul →
// RoPE → attention (QKᵀ + scale + causal mask + softmax[exact max + software exp + fixed-order sum] + ·V) →
// out matmul → residual → rmsnorm → gate/up matmul → SwiGLU(silu via software exp) → down matmul → residual.
// All fp32, fixed reduction order, software transcendentals, safe math. Deterministic in-kernel weights.
// Diff DIGEST across M1 Max / M4 Pro — a match validates the body's compute core end-to-end.
//   swift metal_block_probe.swift
import Metal
import Foundation

let src = """
#include <metal_stdlib>
using namespace metal;

inline float rsqrt_soft(float x){int i=as_type<int>(x);i=0x5f3759df-(i>>1);float y=as_type<float>(i);y=y*fma(-0.5f*x,y*y,1.5f);y=y*fma(-0.5f*x,y*y,1.5f);return y;}
inline float exp_soft(float x){float p=1.0f/720.0f;p=fma(p,x,1.0f/120.0f);p=fma(p,x,1.0f/24.0f);p=fma(p,x,1.0f/6.0f);p=fma(p,x,0.5f);p=fma(p,x,1.0f);p=fma(p,x,1.0f);return p;}
inline float sigmoid_soft(float x){return 1.0f/(1.0f+exp_soft(-x));}
inline float genf(uint i,uint seed,float scale){uint h=i*2654435761u+seed*2246822519u+12345u;h^=h>>16;h*=0x7feb352du;h^=h>>15;h*=0x846ca68bu;h^=h>>16;float u=(float)(h&0xffffff)*(1.0f/16777216.0f);return fma(u,2.0f*scale,-scale);}

kernel void gen(device float* out [[buffer(0)]], constant uint& seed [[buffer(1)]], constant float& scale [[buffer(2)]], uint gid [[thread_position_in_grid]]) { out[gid]=genf(gid,seed,scale); }

// C[M][N] = A[M][K] @ B[K][N], one thread per output, fixed-order fp32 fma over K.
kernel void matmul(device const float* A [[buffer(0)]], device const float* B [[buffer(1)]], device float* C [[buffer(2)]],
                   constant uint3& dims [[buffer(3)]], uint gid [[thread_position_in_grid]]) {
    uint M=dims.x,K=dims.y,N=dims.z; if(gid>=M*N) return; uint m=gid/N,n=gid%N;
    float acc=0.0f; for(uint k=0;k<K;++k) acc=fma(A[m*K+k],B[k*N+n],acc); C[gid]=acc;
}

// per-row RMSNorm (validated parallel fp32 reduction), one threadgroup per row.
kernel void rmsnorm(device const float* x [[buffer(0)]], device const float* w [[buffer(1)]], device float* out [[buffer(2)]],
                    constant uint& D [[buffer(3)]], uint row [[threadgroup_position_in_grid]],
                    uint tid [[thread_position_in_threadgroup]], uint tgs [[threads_per_threadgroup]],
                    uint lane [[thread_index_in_simdgroup]], uint sgid [[simdgroup_index_in_threadgroup]], uint nsg [[simdgroups_per_threadgroup]]) {
    threadgroup float sgp[32]; threadgroup float tot;
    device const float* xr=x+row*D; device float* outr=out+row*D;
    float ps=0.0f; for(uint i=tid;i<D;i+=tgs){float v=xr[i]; ps=fma(v,v,ps);}
    for(uint o=16;o>0;o>>=1) ps+=simd_shuffle_xor(ps,o);
    if(lane==0) sgp[sgid]=ps; threadgroup_barrier(mem_flags::mem_threadgroup);
    if(tid==0){float t=0.0f; for(uint s=0;s<nsg;++s) t+=sgp[s]; tot=t;}
    threadgroup_barrier(mem_flags::mem_threadgroup);
    float rms=rsqrt_soft(tot/(float)D+1e-6f);
    for(uint i=tid;i<D;i+=tgs) outr[i]=xr[i]*rms*w[i];
}

// RoPE in place on q[S][H][hd] (D=H*hd). Deterministic cos/sin factors per (pos, pair) — a manifest table
// stand-in (real backend commits the table). Rotation via mul/add of validated primitives.
kernel void rope(device float* q [[buffer(0)]], constant uint3& shp [[buffer(1)]], uint gid [[thread_position_in_grid]]) {
    uint S=shp.x,H=shp.y,hd=shp.z; uint P=hd/2; uint total=S*H*P; if(gid>=total) return;
    uint p=gid%P; uint h=(gid/P)%H; uint s=gid/(P*H);
    // manifest-table stand-in: deterministic rotation factors (NO hardware cos/sin — §19.1 prohibits it).
    float c=genf(s*P+p,777u,1.0f), sn=genf(s*P+p,888u,1.0f);
    uint base=(s*H+h)*hd; float a=q[base+2*p], b=q[base+2*p+1];
    q[base+2*p]=fma(a,c,-b*sn); q[base+2*p+1]=fma(a,sn,b*c);
}

// attention: out[S][H][hd]; one thread per (query s, head h). Causal, softmax = exact max + software exp +
// fixed-order sum; then fixed-order weighted V sum. All sequential ⇒ order-fixed.
kernel void attention(device const float* q [[buffer(0)]], device const float* k [[buffer(1)]], device const float* v [[buffer(2)]],
                      device float* out [[buffer(3)]], constant uint3& shp [[buffer(4)]], uint gid [[thread_position_in_grid]]) {
    uint S=shp.x,H=shp.y,hd=shp.z; if(gid>=S*H) return; uint h=gid%H; uint s=gid/H;
    uint D=H*hd; float scale=rsqrt_soft((float)hd);
    float sc[64]; // scores for j=0..s (S<=64 for the probe)
    float mx=-1e30f;
    for(uint j=0;j<=s;++j){ float d=0.0f; for(uint t=0;t<hd;++t) d=fma(q[(s*H+h)*hd+t],k[(j*H+h)*hd+t],d); d*=scale; sc[j]=d; mx=max(mx,d); }
    float sum=0.0f; for(uint j=0;j<=s;++j){ float e=exp_soft(sc[j]-mx); sc[j]=e; sum+=e; }
    float inv=1.0f/sum;
    for(uint t=0;t<hd;++t){ float o=0.0f; for(uint j=0;j<=s;++j) o=fma(sc[j]*inv, v[(j*H+h)*hd+t], o); out[(s*H+h)*hd+t]=o; }
}

kernel void swiglu(device const float* g [[buffer(0)]], device const float* u [[buffer(1)]], device float* out [[buffer(2)]], uint gid [[thread_position_in_grid]]) {
    float x=g[gid]; out[gid]=(x*sigmoid_soft(x))*u[gid]; // SiLU(g)*u
}
kernel void addv(device float* a [[buffer(0)]], device const float* b [[buffer(1)]], uint gid [[thread_position_in_grid]]) { a[gid]+=b[gid]; }
"""

guard let dev = MTLCreateSystemDefaultDevice() else { fatalError("no Metal device") }
print("device: \(dev.name)")
let opts = MTLCompileOptions(); opts.fastMathEnabled = false
let lib = try! dev.makeLibrary(source: src, options: opts)
let q = dev.makeCommandQueue()!
func pipe(_ n: String) -> MTLComputePipelineState { try! dev.makeComputePipelineState(function: lib.makeFunction(name: n)!) }
let P_gen = pipe("gen"), P_mm = pipe("matmul"), P_rms = pipe("rmsnorm"), P_rope = pipe("rope"), P_attn = pipe("attention"), P_glu = pipe("swiglu"), P_add = pipe("addv")

// dims (representative: D=256, H=8, hd=32, S=8, I=512)
let S=8, H=8, hd=32, D=256, I=512
func buf(_ n: Int) -> MTLBuffer { dev.makeBuffer(length: n*4, options: .storageModeShared)! }
func fill(_ b: MTLBuffer, _ n: Int, seed: UInt32, scale: Float) {
    let cb=q.makeCommandBuffer()!; let e=cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(P_gen); e.setBuffer(b,offset:0,index:0)
    var sd=seed; e.setBytes(&sd,length:4,index:1); var sc=scale; e.setBytes(&sc,length:4,index:2)
    e.dispatchThreads(MTLSize(width:n,height:1,depth:1),threadsPerThreadgroup:MTLSize(width:min(n,64),height:1,depth:1)); e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
}
func mm(_ A: MTLBuffer,_ B: MTLBuffer,_ M: Int,_ K: Int,_ N: Int) -> MTLBuffer {
    let C=buf(M*N); let cb=q.makeCommandBuffer()!; let e=cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(P_mm); e.setBuffer(A,offset:0,index:0); e.setBuffer(B,offset:0,index:1); e.setBuffer(C,offset:0,index:2)
    var d=SIMD3<UInt32>(UInt32(M),UInt32(K),UInt32(N)); e.setBytes(&d,length:16,index:3)
    e.dispatchThreads(MTLSize(width:M*N,height:1,depth:1),threadsPerThreadgroup:MTLSize(width:64,height:1,depth:1)); e.endEncoding(); cb.commit(); cb.waitUntilCompleted(); return C
}
func rms(_ x: MTLBuffer,_ w: MTLBuffer) -> MTLBuffer {
    let out=buf(S*D); let cb=q.makeCommandBuffer()!; let e=cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(P_rms); e.setBuffer(x,offset:0,index:0); e.setBuffer(w,offset:0,index:1); e.setBuffer(out,offset:0,index:2)
    var Dd=UInt32(D); e.setBytes(&Dd,length:4,index:3)
    e.dispatchThreadgroups(MTLSize(width:S,height:1,depth:1),threadsPerThreadgroup:MTLSize(width:256,height:1,depth:1)); e.endEncoding(); cb.commit(); cb.waitUntilCompleted(); return out
}
func rope(_ x: MTLBuffer) { let cb=q.makeCommandBuffer()!; let e=cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(P_rope); e.setBuffer(x,offset:0,index:0); var sh=SIMD3<UInt32>(UInt32(S),UInt32(H),UInt32(hd)); e.setBytes(&sh,length:16,index:1)
    e.dispatchThreads(MTLSize(width:S*H*(hd/2),height:1,depth:1),threadsPerThreadgroup:MTLSize(width:64,height:1,depth:1)); e.endEncoding(); cb.commit(); cb.waitUntilCompleted() }
func attn(_ Q: MTLBuffer,_ K: MTLBuffer,_ V: MTLBuffer) -> MTLBuffer { let out=buf(S*D); let cb=q.makeCommandBuffer()!; let e=cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(P_attn); e.setBuffer(Q,offset:0,index:0); e.setBuffer(K,offset:0,index:1); e.setBuffer(V,offset:0,index:2); e.setBuffer(out,offset:0,index:3)
    var sh=SIMD3<UInt32>(UInt32(S),UInt32(H),UInt32(hd)); e.setBytes(&sh,length:16,index:4)
    e.dispatchThreads(MTLSize(width:S*H,height:1,depth:1),threadsPerThreadgroup:MTLSize(width:min(S*H,64),height:1,depth:1)); e.endEncoding(); cb.commit(); cb.waitUntilCompleted(); return out }
func glu(_ g: MTLBuffer,_ u: MTLBuffer) -> MTLBuffer { let out=buf(S*I); let cb=q.makeCommandBuffer()!; let e=cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(P_glu); e.setBuffer(g,offset:0,index:0); e.setBuffer(u,offset:0,index:1); e.setBuffer(out,offset:0,index:2)
    e.dispatchThreads(MTLSize(width:S*I,height:1,depth:1),threadsPerThreadgroup:MTLSize(width:64,height:1,depth:1)); e.endEncoding(); cb.commit(); cb.waitUntilCompleted(); return out }
func add(_ a: MTLBuffer,_ b: MTLBuffer,_ n: Int) { let cb=q.makeCommandBuffer()!; let e=cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(P_add); e.setBuffer(a,offset:0,index:0); e.setBuffer(b,offset:0,index:1)
    e.dispatchThreads(MTLSize(width:n,height:1,depth:1),threadsPerThreadgroup:MTLSize(width:64,height:1,depth:1)); e.endEncoding(); cb.commit(); cb.waitUntilCompleted() }

// weights + input (deterministic, distinct seeds; small scales to keep activations sane)
let x=buf(S*D); fill(x,S*D,seed:1,scale:1.0)
let wq=buf(D*D); fill(wq,D*D,seed:2,scale:0.08); let wk=buf(D*D); fill(wk,D*D,seed:3,scale:0.08); let wv=buf(D*D); fill(wv,D*D,seed:4,scale:0.08)
let wo=buf(D*D); fill(wo,D*D,seed:5,scale:0.08)
let wg=buf(D*I); fill(wg,D*I,seed:6,scale:0.06); let wu=buf(D*I); fill(wu,D*I,seed:7,scale:0.06); let wd=buf(I*D); fill(wd,I*D,seed:8,scale:0.04)
let rw1=buf(D); fill(rw1,D,seed:9,scale:1.0); let rw2=buf(D); fill(rw2,D,seed:10,scale:1.0)

// --- one transformer block ---
let xn = rms(x, rw1)
let Q = mm(xn, wq, S, D, D), K = mm(xn, wk, S, D, D), V = mm(xn, wv, S, D, D)
rope(Q); rope(K)
let a = attn(Q, K, V)
let ao = mm(a, wo, S, D, D)
add(x, ao, S*D)                 // residual
let xn2 = rms(x, rw2)
let g = mm(xn2, wg, S, D, I), u = mm(xn2, wu, S, D, I)
let h = glu(g, u)
let m = mm(h, wd, S, I, D)
add(x, m, S*D)                  // residual

let p = x.contents().bindMemory(to: UInt32.self, capacity: S*D)
var digest = UInt64(1469598103934665603)
for i in 0..<(S*D) { digest = (digest ^ UInt64(p[i])) &* 1099511628211 }
print("block S=\(S) D=\(D) H=\(H) I=\(I)  out[0]=\(String(format:"0x%08x",p[0]))  out[last]=\(String(format:"0x%08x",p[S*D-1]))")
print(String(format: "DIGEST 0x%016llx", digest))
