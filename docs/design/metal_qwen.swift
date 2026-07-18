// MISAKA PALW §19.5 M1 — canonical Metal Qwen2 forward on REAL weights. Loads the fp32 tensors + config
// (from palw-qwen-dump) and prompt ids (from palw-qwen-ref), runs embedding + N canonical transformer
// layers (GQA, QKV bias, real RoPE θ, RMSNorm, SwiGLU) + LM head, all in the validated canonical kernels
// (fixed-order fp32, software transcendentals, safe math). Prints argmax (faithfulness vs candle) + a logits
// DIGEST (M1↔M4 bit-identity). Env: PALW_DUMP_DIR.
//   swift metal_qwen.swift
import Metal
import Foundation

let dir = ProcessInfo.processInfo.environment["PALW_DUMP_DIR"] ?? "\(NSHomeDirectory())/models/qwen05b_fp32"
let man = try! JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: "\(dir)/manifest.json"))) as! [String: Any]
let meta = man["metadata"] as! [String: Any]
func mi(_ k: String) -> Int { Int((meta[k] as? NSNumber)?.doubleValue ?? Double(meta[k] as! String)!) }
func mf(_ k: String) -> Float { Float((meta[k] as? NSNumber)?.doubleValue ?? Double(meta[k] as! String)!) }
let L = mi("qwen2.block_count"), D = mi("qwen2.embedding_length"), NH = mi("qwen2.attention.head_count")
let NKV = mi("qwen2.attention.head_count_kv"), FF = mi("qwen2.feed_forward_length")
let HD = D / NH, KVD = NKV * (D / NH), EPS = mf("qwen2.attention.layer_norm_rms_epsilon"), THETA = mf("qwen2.rope.freq_base")
print("config L=\(L) D=\(D) NH=\(NH) NKV=\(NKV) HD=\(HD) FF=\(FF) theta=\(THETA)")

let ids = (try! JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: "\(dir)/prompt_ids.json"))) as! [Int]).map { UInt32($0) }
let S = ids.count
let GEN = Int(ProcessInfo.processInfo.environment["PALW_GEN_TOKENS"] ?? "24")!
let MAXLEN = S + GEN
print("S=\(S) GEN=\(GEN) prompt_ids=\(ids)")

guard let dev = MTLCreateSystemDefaultDevice() else { fatalError("no Metal") }
print("device: \(dev.name)")
let opts = MTLCompileOptions(); opts.fastMathEnabled = false
let q = dev.makeCommandQueue()!

let src = """
#include <metal_stdlib>
using namespace metal;
inline float rsqrt_soft(float x){int i=as_type<int>(x);i=0x5f3759df-(i>>1);float y=as_type<float>(i);y=y*fma(-0.5f*x,y*y,1.5f);y=y*fma(-0.5f*x,y*y,1.5f);return y;}
inline float exp_soft(float x){ // range-reduced software exp: e^x = 2^k * e^r, r in [-ln2/2, ln2/2]
  float k = floor(fma(x, 1.44269504f, 0.5f));
  float r = fma(k, -0.6931471805599453f, x);
  float p = 1.0f/5040.0f; p=fma(p,r,1.0f/720.0f); p=fma(p,r,1.0f/120.0f); p=fma(p,r,1.0f/24.0f); p=fma(p,r,1.0f/6.0f); p=fma(p,r,0.5f); p=fma(p,r,1.0f); p=fma(p,r,1.0f);
  int ki=(int)k; float s=as_type<float>((ki+127)<<23); return p*s;
}
inline float sigmoid_soft(float x){return 1.0f/(1.0f+exp_soft(-x));}

kernel void embed(device const float* emb [[buffer(0)]], device const uint* ids [[buffer(1)]], device float* out [[buffer(2)]], constant uint& D [[buffer(3)]], uint gid [[thread_position_in_grid]]) {
  uint s=gid/D, d=gid%D; out[gid]=emb[ids[s]*D+d];
}
// out[M][N] = X[M][K] @ W[N][K]^T (+bias[N]).  W row-major [out,in].
kernel void linear(device const float* X [[buffer(0)]], device const float* W [[buffer(1)]], device const float* bias [[buffer(2)]], device float* out [[buffer(3)]], constant uint4& dims [[buffer(4)]], uint gid [[thread_position_in_grid]]) {
  uint M=dims.x,K=dims.y,N=dims.z,hasB=dims.w; if(gid>=M*N) return; uint m=gid/N,n=gid%N;
  float acc=0.0f; for(uint k=0;k<K;++k) acc=fma(X[m*K+k], W[n*K+k], acc); if(hasB!=0) acc+=bias[n]; out[gid]=acc;
}
kernel void rmsnorm(device const float* x [[buffer(0)]], device const float* w [[buffer(1)]], device float* out [[buffer(2)]], constant float2& cfg [[buffer(3)]], uint row [[threadgroup_position_in_grid]], uint tid [[thread_position_in_threadgroup]], uint tgs [[threads_per_threadgroup]], uint lane [[thread_index_in_simdgroup]], uint sgid [[simdgroup_index_in_threadgroup]], uint nsg [[simdgroups_per_threadgroup]]) {
  uint D=(uint)cfg.x; float eps=cfg.y; threadgroup float sgp[32]; threadgroup float tot;
  device const float* xr=x+row*D; device float* outr=out+row*D;
  float ps=0.0f; for(uint i=tid;i<D;i+=tgs){float v=xr[i]; ps=fma(v,v,ps);}
  for(uint o=16;o>0;o>>=1) ps+=simd_shuffle_xor(ps,o); if(lane==0) sgp[sgid]=ps; threadgroup_barrier(mem_flags::mem_threadgroup);
  if(tid==0){float t=0.0f; for(uint s=0;s<nsg;++s) t+=sgp[s]; tot=t;} threadgroup_barrier(mem_flags::mem_threadgroup);
  float rms=rsqrt_soft(tot/(float)D+eps); for(uint i=tid;i<D;i+=tgs) outr[i]=xr[i]*rms*w[i];
}
// RoPE (NeoX half-rotation) on buf[S][H][HD] using cos/sin table[S][HD/2].
kernel void rope(device float* buf [[buffer(0)]], device const float* cs [[buffer(1)]], constant uint3& shp [[buffer(2)]], uint gid [[thread_position_in_grid]]) {
  uint S=shp.x,H=shp.y,HD=shp.z; uint P=HD/2; if(gid>=S*H*P) return;
  uint i=gid%P; uint h=(gid/P)%H; uint s=gid/(P*H); float c=cs[(s*P+i)*2], sn=cs[(s*P+i)*2+1];
  uint base=(s*H+h)*HD; float a=buf[base+i], b=buf[base+i+P]; buf[base+i]=fma(a,c,-b*sn); buf[base+i+P]=fma(b,c,a*sn);
}
// GQA attention: out[S][NH][HD]; q[S][NH][HD], k/v[S][NKV][HD]. causal, softmax=exact max+software exp+fixed sum.
kernel void attn(device const float* Q [[buffer(0)]], device const float* K [[buffer(1)]], device const float* V [[buffer(2)]], device float* out [[buffer(3)]], constant uint4& shp [[buffer(4)]], uint gid [[thread_position_in_grid]]) {
  uint S=shp.x,NH=shp.y,NKV=shp.z,HD=shp.w; if(gid>=S*NH) return; uint h=gid%NH; uint s=gid/NH; uint kv=h/(NH/NKV);
  float scale=rsqrt_soft((float)HD); float sc[1024]; float mx=-1e30f;
  for(uint j=0;j<=s;++j){ float d=0.0f; for(uint t=0;t<HD;++t) d=fma(Q[(s*NH+h)*HD+t], K[(j*NKV+kv)*HD+t], d); d*=scale; sc[j]=d; mx=max(mx,d);}
  float sum=0.0f; for(uint j=0;j<=s;++j){ float e=exp_soft(sc[j]-mx); sc[j]=e; sum+=e; } float inv=1.0f/sum;
  for(uint t=0;t<HD;++t){ float o=0.0f; for(uint j=0;j<=s;++j) o=fma(sc[j]*inv, V[(j*NKV+kv)*HD+t], o); out[(s*NH+h)*HD+t]=o; }
}
kernel void swiglu(device const float* g [[buffer(0)]], device const float* u [[buffer(1)]], device float* out [[buffer(2)]], uint gid [[thread_position_in_grid]]) { float x=g[gid]; out[gid]=(x*sigmoid_soft(x))*u[gid]; }
kernel void addv(device float* a [[buffer(0)]], device const float* b [[buffer(1)]], uint gid [[thread_position_in_grid]]) { a[gid]+=b[gid]; }
"""
let lib = try! dev.makeLibrary(source: src, options: opts)
func P(_ n: String) -> MTLComputePipelineState { try! dev.makeComputePipelineState(function: lib.makeFunction(name: n)!) }
let pEmbed=P("embed"), pLin=P("linear"), pRms=P("rmsnorm"), pRope=P("rope"), pAttn=P("attn"), pGlu=P("swiglu"), pAdd=P("addv")

// load tensors
var W = [String: MTLBuffer]()
var shape = [String: [Int]]()
for t in man["tensors"] as! [[String: Any]] {
  let name=t["name"] as! String, file=t["file"] as! String, shp=(t["shape"] as! [Any]).map { ($0 as! NSNumber).intValue }
  let data = try! Data(contentsOf: URL(fileURLWithPath: "\(dir)/\(file)"))
  let b = dev.makeBuffer(length: data.count, options: .storageModeShared)!
  data.withUnsafeBytes { memcpy(b.contents(), $0.baseAddress!, data.count) }
  W[name]=b; shape[name]=shp
}
func buf(_ n: Int) -> MTLBuffer { dev.makeBuffer(length: n*4, options: .storageModeShared)! }
func zero() -> MTLBuffer { buf(1) }
let noBias = zero()

// RoPE cos/sin table [S][HD/2][2] (real angles; committed manifest values → identical bytes both machines)
let P2 = HD/2
let ropePath = "\(dir)/rope_table.bin"
var cs = [Float](repeating: 0, count: MAXLEN*P2*2)
if let d = try? Data(contentsOf: URL(fileURLWithPath: ropePath)), d.count == cs.count*4 {
  cs.withUnsafeMutableBytes { m in d.copyBytes(to: m) }; print("rope table: loaded committed \(ropePath)")
} else {
  for s in 0..<MAXLEN { for i in 0..<P2 { let freq = powf(THETA, -2.0*Float(i)/Float(HD)); let a = Float(s)*freq; cs[(s*P2+i)*2]=cosf(a); cs[(s*P2+i)*2+1]=sinf(a) } }
  cs.withUnsafeBytes { try? Data($0).write(to: URL(fileURLWithPath: ropePath)) }; print("rope table: computed + wrote committed (\(MAXLEN) positions)")
}
let csBuf = dev.makeBuffer(bytes: cs, length: cs.count*4, options: .storageModeShared)!

func cbuf<T>(_ v: T) -> MTLBuffer { var x=v; return dev.makeBuffer(bytes:&x, length:MemoryLayout<T>.stride, options:.storageModeShared)! }
func enc(_ p: MTLComputePipelineState, _ bufs: [(MTLBuffer,Int)], threads: Int, tpg: Int) {
  let cb=q.makeCommandBuffer()!; let e=cb.makeComputeCommandEncoder()!; e.setComputePipelineState(p)
  for (b,i) in bufs { e.setBuffer(b,offset:0,index:i) }
  e.dispatchThreads(MTLSize(width:threads,height:1,depth:1),threadsPerThreadgroup:MTLSize(width:min(threads,tpg),height:1,depth:1)); e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
}
func encTG(_ p: MTLComputePipelineState, _ bufs: [(MTLBuffer,Int)], groups: Int, tpg: Int) {
  let cb=q.makeCommandBuffer()!; let e=cb.makeComputeCommandEncoder()!; e.setComputePipelineState(p)
  for (b,i) in bufs { e.setBuffer(b,offset:0,index:i) }
  e.dispatchThreadgroups(MTLSize(width:groups,height:1,depth:1),threadsPerThreadgroup:MTLSize(width:tpg,height:1,depth:1)); e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
}
func linear(_ x: MTLBuffer,_ w: String,_ bias: String?,_ M: Int,_ K: Int,_ N: Int) -> MTLBuffer {
  let out=buf(M*N); let d=cbuf(SIMD4<UInt32>(UInt32(M),UInt32(K),UInt32(N),bias==nil ? 0:1))
  enc(pLin, [(x,0),(W[w]!,1),(bias==nil ? noBias:W[bias!]!,2),(out,3),(d,4)], threads:M*N, tpg:64); return out
}
func rms(_ x: MTLBuffer,_ w: String,_ SL: Int) -> MTLBuffer { let out=buf(SL*D); let c=cbuf(SIMD2<Float>(Float(D),EPS)); encTG(pRms, [(x,0),(W[w]!,1),(out,2),(c,3)], groups:SL, tpg:256); return out }
func rope(_ x: MTLBuffer,_ H: Int,_ SL: Int) { let sh=cbuf(SIMD3<UInt32>(UInt32(SL),UInt32(H),UInt32(HD))); enc(pRope, [(x,0),(csBuf,1),(sh,2)], threads:SL*H*(HD/2), tpg:64) }
func addr(_ a: MTLBuffer,_ b: MTLBuffer,_ n: Int) { enc(pAdd, [(a,0),(b,1)], threads:n, tpg:64) }
let VOCAB = shape["output.weight"]![0]

// recompute-full canonical forward → last-position logits [VOCAB]
func forwardLast(_ cur: [UInt32]) -> MTLBuffer {
  let SL = cur.count
  var x = buf(SL*D)
  do { let ib=dev.makeBuffer(bytes:cur,length:SL*4,options:.storageModeShared)!; let Dd=cbuf(UInt32(D))
    enc(pEmbed, [(W["token_embd.weight"]!,0),(ib,1),(x,2),(Dd,3)], threads:SL*D, tpg:64) }
  for l in 0..<L {
    let p="blk.\(l)."
    let h = rms(x, p+"attn_norm.weight", SL)
    let qb = linear(h, p+"attn_q.weight", p+"attn_q.bias", SL, D, D)
    let kb = linear(h, p+"attn_k.weight", p+"attn_k.bias", SL, D, KVD)
    let vb = linear(h, p+"attn_v.weight", p+"attn_v.bias", SL, D, KVD)
    rope(qb, NH, SL); rope(kb, NKV, SL)
    let ao = buf(SL*D); let sh=cbuf(SIMD4<UInt32>(UInt32(SL),UInt32(NH),UInt32(NKV),UInt32(HD)))
    enc(pAttn, [(qb,0),(kb,1),(vb,2),(ao,3),(sh,4)], threads:SL*NH, tpg:64)
    let proj = linear(ao, p+"attn_output.weight", nil, SL, D, D)
    addr(x, proj, SL*D)
    let h2 = rms(x, p+"ffn_norm.weight", SL)
    let g = linear(h2, p+"ffn_gate.weight", nil, SL, D, FF)
    let u = linear(h2, p+"ffn_up.weight", nil, SL, D, FF)
    let sg = buf(SL*FF); enc(pGlu, [(g,0),(u,1),(sg,2)], threads:SL*FF, tpg:64)
    let down = linear(sg, p+"ffn_down.weight", nil, SL, FF, D)
    addr(x, down, SL*D)
  }
  let xn = rms(x, "output_norm.weight", SL)
  let lastRow = buf(D); do { let cb=q.makeCommandBuffer()!; let bl=cb.makeBlitCommandEncoder()!; bl.copy(from:xn,sourceOffset:(SL-1)*D*4,to:lastRow,destinationOffset:0,size:D*4); bl.endEncoding(); cb.commit(); cb.waitUntilCompleted() }
  return linear(lastRow, "output.weight", nil, 1, D, VOCAB)
}

// greedy generation (recompute-full) + a commitment over EVERY step's last-position logits
var cur = ids
var genToks = [Int]()
var genDigest = UInt64(1469598103934665603)
let t0 = Date()
for _ in 0..<GEN {
  let lg = forwardLast(cur)
  let up = lg.contents().bindMemory(to: UInt32.self, capacity: VOCAB)
  for i in 0..<VOCAB { genDigest = (genDigest ^ UInt64(up[i])) &* 1099511628211 }
  let lp = lg.contents().bindMemory(to: Float.self, capacity: VOCAB)
  var best=0; var bv = -Float.infinity; for i in 0..<VOCAB { if lp[i]>bv { bv=lp[i]; best=i } }
  genToks.append(best); cur.append(UInt32(best))
}
let dt = Date().timeIntervalSince(t0)
print("gen_tokens (\(genToks.count)) = \(genToks)")
print(String(format: "GEN_DIGEST 0x%016llx", genDigest))
print(String(format: "throughput: %.2f tok/s (%.1f ms/tok, recompute-full)", Double(GEN)/dt, dt*1000/Double(GEN)))
