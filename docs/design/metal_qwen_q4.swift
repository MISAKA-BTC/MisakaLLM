// MISAKA PALW §19.5 M2 — canonical Metal Qwen2 with Q4_K/Q6_K dequant IN-KERNEL (weights stay quantized).
// Same canonical kernels + KV cache as metal_qwen_kv.swift, but matmul/embed dequant Q4_K/Q6_K blocks on
// the fly (from palw-qwen-dump's native dump), so 7B/14B fit in memory. Dequant is deterministic (f16->f32
// exact, integer unpack, fixed-order fp32), so M1<->M4 identity holds. Env: PALW_DUMP_DIR, PALW_GEN_TOKENS.
import Metal
import Foundation

let dir = ProcessInfo.processInfo.environment["PALW_DUMP_DIR"] ?? "\(NSHomeDirectory())/models/qwen05b_q4"
let man = try! JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: "\(dir)/manifest.json"))) as! [String: Any]
let meta = man["metadata"] as! [String: Any]
func mi(_ k: String) -> Int { Int((meta[k] as? NSNumber)?.doubleValue ?? Double(meta[k] as! String)!) }
func mf(_ k: String) -> Float { Float((meta[k] as? NSNumber)?.doubleValue ?? Double(meta[k] as! String)!) }
let L = mi("qwen2.block_count"), D = mi("qwen2.embedding_length"), NH = mi("qwen2.attention.head_count")
let NKV = mi("qwen2.attention.head_count_kv"), FF = mi("qwen2.feed_forward_length")
let HD = D / NH, KVD = NKV * (D / NH), EPS = mf("qwen2.attention.layer_norm_rms_epsilon"), THETA = mf("qwen2.rope.freq_base")
let ids = (try! JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: "\(dir)/prompt_ids.json"))) as! [Int]).map { UInt32($0) }
let S = ids.count
let GEN = Int(ProcessInfo.processInfo.environment["PALW_GEN_TOKENS"] ?? "24")!
let MAXLEN = S + GEN
print("config L=\(L) D=\(D) NH=\(NH) NKV=\(NKV) HD=\(HD) FF=\(FF) S=\(S) GEN=\(GEN)")

guard let dev = MTLCreateSystemDefaultDevice() else { fatalError("no Metal") }
print("device: \(dev.name)")
let opts = MTLCompileOptions(); opts.fastMathEnabled = false
let q = dev.makeCommandQueue()!

let src = """
#include <metal_stdlib>
using namespace metal;
inline float rsqrt_soft(float x){int i=as_type<int>(x);i=0x5f3759df-(i>>1);float y=as_type<float>(i);y=y*fma(-0.5f*x,y*y,1.5f);y=y*fma(-0.5f*x,y*y,1.5f);return y;}
inline float exp_soft(float x){float k=floor(fma(x,1.44269504f,0.5f));float r=fma(k,-0.6931471805599453f,x);float p=1.0f/5040.0f;p=fma(p,r,1.0f/720.0f);p=fma(p,r,1.0f/120.0f);p=fma(p,r,1.0f/24.0f);p=fma(p,r,1.0f/6.0f);p=fma(p,r,0.5f);p=fma(p,r,1.0f);p=fma(p,r,1.0f);int ki=(int)k;float s=as_type<float>((ki+127)<<23);return p*s;}
inline float sigmoid_soft(float x){return 1.0f/(1.0f+exp_soft(-x));}
inline float f16at(device const uchar* p){ushort u=(ushort)p[0]|((ushort)p[1]<<8);return (float)as_type<half>(u);}

// Q4_K block (144B/256w): d(f16@0) dmin(f16@2) scales[12]@4 qs[128]@16
inline float deq_q4k(device const uchar* blk, uint e){
  float d=f16at(blk), dmin=f16at(blk+2); device const uchar* sc=blk+4; device const uchar* qs=blk+16;
  uint sb=e>>5; uchar s6,m6;
  if(sb<4){ s6=sc[sb]&63; m6=sc[sb+4]&63; } else { s6=(sc[sb+4]&0xF)|((sc[sb-4]>>6)<<4); m6=(sc[sb+4]>>4)|((sc[sb]>>6)<<4); }
  uint c=e>>6; uint within=e&63; uint l=within&31; uchar b=qs[c*32+l]; uint qv=(within<32)?(b&0xF):(b>>4);
  return (float)s6*d*(float)qv - (float)m6*dmin;
}
// Q6_K block (210B/256w): ql[128]@0 qh[64]@128 scales[16](i8)@192 d(f16)@208
inline float deq_q6k(device const uchar* blk, uint e){
  device const uchar* ql=blk; device const uchar* qh=blk+128; device const char* sc=(device const char*)(blk+192); float d=f16at(blk+208);
  uint hi=e>>7; uint within=e&127; uint qlb=hi*64, qhb=hi*32, scb=hi*8; uint l=within&31; uint g=within>>5; uint is=l>>4;
  uchar qhb2=qh[qhb+l]; int qv; int si;
  if(g==0){ qv=(int)((ql[qlb+l]&0xF)|(((qhb2>>0)&3)<<4))-32; si=scb+is+0; }
  else if(g==1){ qv=(int)((ql[qlb+l+32]&0xF)|(((qhb2>>2)&3)<<4))-32; si=scb+is+2; }
  else if(g==2){ qv=(int)((ql[qlb+l]>>4)|(((qhb2>>4)&3)<<4))-32; si=scb+is+4; }
  else { qv=(int)((ql[qlb+l+32]>>4)|(((qhb2>>6)&3)<<4))-32; si=scb+is+6; }
  return d*(float)sc[si]*(float)qv;
}
inline float deqw(uint qt, device const uchar* W, uint flat){
  if(qt==0) return ((device const float*)W)[flat];
  if(qt==1) return deq_q4k(W + (flat/256)*144, flat%256);
  return deq_q6k(W + (flat/256)*210, flat%256);
}

kernel void embed(device const uchar* emb [[buffer(0)]], device const uint* ids [[buffer(1)]], device float* out [[buffer(2)]], constant uint2& cfg [[buffer(3)]], uint gid [[thread_position_in_grid]]) { uint D=cfg.x,qt=cfg.y; uint s=gid/D,d=gid%D; out[gid]=deqw(qt, emb, ids[s]*D+d); }
// f32 weight matmul.
kernel void linear_f32(device const uchar* W [[buffer(0)]], device const float* X [[buffer(1)]], device const float* bias [[buffer(2)]], device float* out [[buffer(3)]], constant uint4& dims [[buffer(4)]], uint gid [[thread_position_in_grid]]) {
  uint M=dims.x,K=dims.y,N=dims.z,hasB=dims.w; if(gid>=M*N) return; uint m=gid/N,n=gid%N;
  device const float* Wf=(device const float*)W; float acc=0.0f; for(uint k=0;k<K;++k) acc=fma(X[m*K+k], Wf[n*K+k], acc); if(hasB!=0) acc+=bias[n]; out[gid]=acc;
}
// Q4_K matmul with AMORTIZED dequant: d/dmin per 144B block, scale/min per 32-elem sub-block, then 256
// elements in k-order. Arithmetic per element identical to naive deqw (d1*q - mm, k-sequential fma) => same
// bits; only the header recompute is hoisted. Requires K % 256 == 0 (true for all quantized weights).
kernel void linear_q4k(device const uchar* W [[buffer(0)]], device const float* X [[buffer(1)]], device const float* bias [[buffer(2)]], device float* out [[buffer(3)]], constant uint4& dims [[buffer(4)]], uint gid [[thread_position_in_grid]]) {
  uint M=dims.x,K=dims.y,N=dims.z,hasB=dims.w; if(gid>=M*N) return; uint m=gid/N,n=gid%N;
  uint NB=K/256; device const uchar* wrow=W+(uint)(n*NB)*144; device const float* xr=X+m*K; float acc=0.0f;
  for(uint b=0;b<NB;++b){
    device const uchar* blk=wrow+b*144; float d=f16at(blk), dmin=f16at(blk+2); device const uchar* sc=blk+4; device const uchar* qs=blk+16; uint kb=b*256;
    for(uint c=0;c<4;++c){ for(uint hf=0;hf<2;++hf){
      uint sub=2*c+hf; uchar s6,m6;
      if(sub<4){ s6=sc[sub]&63; m6=sc[sub+4]&63; } else { s6=(sc[sub+4]&0xF)|((sc[sub-4]>>6)<<4); m6=(sc[sub+4]>>4)|((sc[sub]>>6)<<4); }
      float d1=d*(float)s6; float mm=dmin*(float)m6; uint base=kb+c*64+hf*32;
      for(uint l=0;l<32;++l){ uint qv=(hf==0)?(qs[c*32+l]&0xF):(qs[c*32+l]>>4); float w=d1*(float)qv-mm; acc=fma(xr[base+l], w, acc); }
    }}
  }
  if(hasB!=0) acc+=bias[n]; out[gid]=acc;
}
// Q6_K matmul, amortized d per 210B block (scales lookup + unpack per element); k-order, same bits as naive.
kernel void linear_q6k(device const uchar* W [[buffer(0)]], device const float* X [[buffer(1)]], device const float* bias [[buffer(2)]], device float* out [[buffer(3)]], constant uint4& dims [[buffer(4)]], uint gid [[thread_position_in_grid]]) {
  uint M=dims.x,K=dims.y,N=dims.z,hasB=dims.w; if(gid>=M*N) return; uint m=gid/N,n=gid%N;
  uint NB=K/256; device const uchar* wrow=W+(uint)(n*NB)*210; device const float* xr=X+m*K; float acc=0.0f;
  for(uint b=0;b<NB;++b){
    device const uchar* blk=wrow+b*210; device const uchar* ql=blk; device const uchar* qh=blk+128; device const char* sc=(device const char*)(blk+192); float d=f16at(blk+208); uint kb=b*256;
    for(uint hi=0;hi<2;++hi){ uint qlb=hi*64,qhb=hi*32,scb=hi*8;
      for(uint within=0; within<128; ++within){
        uint l=within&31; uint g=within>>5; uint is=l>>4; uchar qh2=qh[qhb+l]; int qv; int si;
        if(g==0){ qv=(int)((ql[qlb+l]&0xF)|(((qh2>>0)&3)<<4))-32; si=scb+is+0; }
        else if(g==1){ qv=(int)((ql[qlb+l+32]&0xF)|(((qh2>>2)&3)<<4))-32; si=scb+is+2; }
        else if(g==2){ qv=(int)((ql[qlb+l]>>4)|(((qh2>>4)&3)<<4))-32; si=scb+is+4; }
        else { qv=(int)((ql[qlb+l+32]>>4)|(((qh2>>6)&3)<<4))-32; si=scb+is+6; }
        float w=d*(float)sc[si]*(float)qv; acc=fma(xr[kb+hi*128+within], w, acc);
      }
    }
  }
  if(hasB!=0) acc+=bias[n]; out[gid]=acc;
}
kernel void rmsnorm(device const float* x [[buffer(0)]], device const float* w [[buffer(1)]], device float* out [[buffer(2)]], constant float2& cfg [[buffer(3)]], uint row [[threadgroup_position_in_grid]], uint tid [[thread_position_in_threadgroup]], uint tgs [[threads_per_threadgroup]], uint lane [[thread_index_in_simdgroup]], uint sgid [[simdgroup_index_in_threadgroup]], uint nsg [[simdgroups_per_threadgroup]]) {
  uint D=(uint)cfg.x; float eps=cfg.y; threadgroup float sgp[32]; threadgroup float tot;
  device const float* xr=x+row*D; device float* outr=out+row*D;
  float ps=0.0f; for(uint i=tid;i<D;i+=tgs){float v=xr[i]; ps=fma(v,v,ps);}
  for(uint o=16;o>0;o>>=1) ps+=simd_shuffle_xor(ps,o); if(lane==0) sgp[sgid]=ps; threadgroup_barrier(mem_flags::mem_threadgroup);
  if(tid==0){float t=0.0f; for(uint s=0;s<nsg;++s) t+=sgp[s]; tot=t;} threadgroup_barrier(mem_flags::mem_threadgroup);
  float rms=rsqrt_soft(tot/(float)D+eps); for(uint i=tid;i<D;i+=tgs) outr[i]=xr[i]*rms*w[i];
}
kernel void rope(device float* buf [[buffer(0)]], device const float* cs [[buffer(1)]], constant uint4& shp [[buffer(2)]], uint gid [[thread_position_in_grid]]) {
  uint QN=shp.x,H=shp.y,HD=shp.z,off=shp.w; uint P=HD/2; if(gid>=QN*H*P) return;
  uint i=gid%P; uint h=(gid/P)%H; uint r=gid/(P*H); uint pos=off+r; float c=cs[(pos*P+i)*2], sn=cs[(pos*P+i)*2+1];
  uint base=(r*H+h)*HD; float a=buf[base+i], b=buf[base+i+P]; buf[base+i]=fma(a,c,-b*sn); buf[base+i+P]=fma(b,c,a*sn);
}
kernel void attn_kv(device const float* Q [[buffer(0)]], device const float* KC [[buffer(1)]], device const float* VC [[buffer(2)]], device float* out [[buffer(3)]], constant uint4& shp [[buffer(4)]], constant uint& qStart [[buffer(5)]], uint gid [[thread_position_in_grid]]) {
  uint QN=shp.x,NH=shp.y,NKV=shp.z,HD=shp.w; if(gid>=QN*NH) return; uint h=gid%NH; uint r=gid/NH; uint kv=h/(NH/NKV);
  uint qpos=qStart+r; float scale=rsqrt_soft((float)HD); float sc[2048]; float mx=-1e30f;
  for(uint j=0;j<=qpos;++j){ float d=0.0f; for(uint t=0;t<HD;++t) d=fma(Q[(r*NH+h)*HD+t], KC[(j*NKV+kv)*HD+t], d); d*=scale; sc[j]=d; mx=max(mx,d); }
  float sum=0.0f; for(uint j=0;j<=qpos;++j){ float e=exp_soft(sc[j]-mx); sc[j]=e; sum+=e; } float inv=1.0f/sum;
  for(uint t=0;t<HD;++t){ float o=0.0f; for(uint j=0;j<=qpos;++j) o=fma(sc[j]*inv, VC[(j*NKV+kv)*HD+t], o); out[(r*NH+h)*HD+t]=o; }
}
kernel void swiglu(device const float* g [[buffer(0)]], device const float* u [[buffer(1)]], device float* out [[buffer(2)]], uint gid [[thread_position_in_grid]]) { float x=g[gid]; out[gid]=(x*sigmoid_soft(x))*u[gid]; }
kernel void addv(device float* a [[buffer(0)]], device const float* b [[buffer(1)]], uint gid [[thread_position_in_grid]]) { a[gid]+=b[gid]; }
"""
let lib = try! dev.makeLibrary(source: src, options: opts)
func P(_ n: String) -> MTLComputePipelineState { try! dev.makeComputePipelineState(function: lib.makeFunction(name: n)!) }
let pEmbed=P("embed"), pLinF32=P("linear_f32"), pLinQ4k=P("linear_q4k"), pLinQ6k=P("linear_q6k"), pRms=P("rmsnorm"), pRope=P("rope"), pAttn=P("attn_kv"), pGlu=P("swiglu"), pAdd=P("addv")

var W = [String: MTLBuffer](); var shape = [String: [Int]](); var qtype = [String: UInt32]()
for t in man["tensors"] as! [[String: Any]] {
  let name=t["name"] as! String, file=t["file"] as! String, shp=(t["shape"] as! [Any]).map { ($0 as! NSNumber).intValue }
  let qt = t["qtype"] as? String ?? "f32"
  let data = try! Data(contentsOf: URL(fileURLWithPath: "\(dir)/\(file)"))
  let b = dev.makeBuffer(length: max(data.count,1), options: .storageModeShared)!
  data.withUnsafeBytes { if data.count>0 { memcpy(b.contents(), $0.baseAddress!, data.count) } }
  W[name]=b; shape[name]=shp; qtype[name] = (qt=="Q4K") ? 1 : (qt=="Q6K" ? 2 : 0)
}
func buf(_ n: Int) -> MTLBuffer { dev.makeBuffer(length: n*4, options: .storageModeShared)! }
let noBias = buf(1)
let P2 = HD/2
var cs = [Float](repeating: 0, count: MAXLEN*P2*2)
if let d = try? Data(contentsOf: URL(fileURLWithPath: "\(dir)/rope_table.bin")), d.count == cs.count*4 { cs.withUnsafeMutableBytes { m in d.copyBytes(to: m) }; print("rope table: loaded") }
else { for s in 0..<MAXLEN { for i in 0..<P2 { let f=powf(THETA,-2.0*Float(i)/Float(HD)); let a=Float(s)*f; cs[(s*P2+i)*2]=cosf(a); cs[(s*P2+i)*2+1]=sinf(a) } }; cs.withUnsafeBytes { try? Data($0).write(to: URL(fileURLWithPath: "\(dir)/rope_table.bin")) }; print("rope table: computed") }
let csBuf = dev.makeBuffer(bytes: cs, length: cs.count*4, options: .storageModeShared)!

func cbuf<T>(_ v: T) -> MTLBuffer { var x=v; return dev.makeBuffer(bytes:&x, length:MemoryLayout<T>.stride, options:.storageModeShared)! }
// One command buffer per forward step: encode all ops, commit+wait once (Metal auto-tracks buffer hazards).
var CB: MTLCommandBuffer!
func enc(_ p: MTLComputePipelineState, _ bufs: [(MTLBuffer,Int)], threads: Int, tpg: Int) { let e=CB.makeComputeCommandEncoder()!; e.setComputePipelineState(p); for (b,i) in bufs { e.setBuffer(b,offset:0,index:i) }; e.dispatchThreads(MTLSize(width:threads,height:1,depth:1),threadsPerThreadgroup:MTLSize(width:min(threads,tpg),height:1,depth:1)); e.endEncoding() }
func encTG(_ p: MTLComputePipelineState, _ bufs: [(MTLBuffer,Int)], groups: Int, tpg: Int) { let e=CB.makeComputeCommandEncoder()!; e.setComputePipelineState(p); for (b,i) in bufs { e.setBuffer(b,offset:0,index:i) }; e.dispatchThreadgroups(MTLSize(width:groups,height:1,depth:1),threadsPerThreadgroup:MTLSize(width:tpg,height:1,depth:1)); e.endEncoding() }
func blitInto(_ dst: MTLBuffer,_ src: MTLBuffer,_ dstOffElems: Int,_ n: Int) { let bl=CB.makeBlitCommandEncoder()!; bl.copy(from:src,sourceOffset:0,to:dst,destinationOffset:dstOffElems*4,size:n*4); bl.endEncoding() }
func linear(_ x: MTLBuffer,_ w: String,_ bias: String?,_ M: Int,_ K: Int,_ N: Int) -> MTLBuffer { let out=buf(M*N); let d=cbuf(SIMD4<UInt32>(UInt32(M),UInt32(K),UInt32(N),bias==nil ?0:1)); let qt=qtype[w]!; let p = qt==1 ? pLinQ4k : (qt==2 ? pLinQ6k : pLinF32); enc(p, [(W[w]!,0),(x,1),(bias==nil ?noBias:W[bias!]!,2),(out,3),(d,4)], threads:M*N, tpg:64); return out }
func rms(_ x: MTLBuffer,_ w: String,_ SL: Int) -> MTLBuffer { let out=buf(SL*D); let c=cbuf(SIMD2<Float>(Float(D),EPS)); encTG(pRms, [(x,0),(W[w]!,1),(out,2),(c,3)], groups:SL, tpg:256); return out }
func rope(_ x: MTLBuffer,_ H: Int,_ SL: Int,_ off: Int) { let sh=cbuf(SIMD4<UInt32>(UInt32(SL),UInt32(H),UInt32(HD),UInt32(off))); enc(pRope, [(x,0),(csBuf,1),(sh,2)], threads:SL*H*(HD/2), tpg:64) }
func addr(_ a: MTLBuffer,_ b: MTLBuffer,_ n: Int) { enc(pAdd, [(a,0),(b,1)], threads:n, tpg:64) }
let VOCAB = shape["output.weight"]![0]
var kcache = (0..<L).map { _ in buf(MAXLEN*KVD) }; var vcache = (0..<L).map { _ in buf(MAXLEN*KVD) }

func forwardStep(_ tokens: [UInt32],_ qStart: Int) -> MTLBuffer {
  CB = q.makeCommandBuffer()!
  let QN = tokens.count; var x = buf(QN*D)
  do { let ib=dev.makeBuffer(bytes:tokens,length:QN*4,options:.storageModeShared)!; let cfg=cbuf(SIMD2<UInt32>(UInt32(D),qtype["token_embd.weight"]!)); enc(pEmbed, [(W["token_embd.weight"]!,0),(ib,1),(x,2),(cfg,3)], threads:QN*D, tpg:64) }
  for l in 0..<L {
    let p="blk.\(l)."
    let h = rms(x, p+"attn_norm.weight", QN)
    let qb = linear(h, p+"attn_q.weight", p+"attn_q.bias", QN, D, D)
    let kb = linear(h, p+"attn_k.weight", p+"attn_k.bias", QN, D, KVD)
    let vb = linear(h, p+"attn_v.weight", p+"attn_v.bias", QN, D, KVD)
    rope(qb, NH, QN, qStart); rope(kb, NKV, QN, qStart)
    blitInto(kcache[l], kb, qStart*KVD, QN*KVD); blitInto(vcache[l], vb, qStart*KVD, QN*KVD)
    let ao = buf(QN*D); let sh=cbuf(SIMD4<UInt32>(UInt32(QN),UInt32(NH),UInt32(NKV),UInt32(HD))); let qs=cbuf(UInt32(qStart))
    enc(pAttn, [(qb,0),(kcache[l],1),(vcache[l],2),(ao,3),(sh,4),(qs,5)], threads:QN*NH, tpg:64)
    let proj = linear(ao, p+"attn_output.weight", nil, QN, D, D); addr(x, proj, QN*D)
    let h2 = rms(x, p+"ffn_norm.weight", QN)
    let g = linear(h2, p+"ffn_gate.weight", nil, QN, D, FF); let u = linear(h2, p+"ffn_up.weight", nil, QN, D, FF)
    let sg = buf(QN*FF); enc(pGlu, [(g,0),(u,1),(sg,2)], threads:QN*FF, tpg:64)
    let down = linear(sg, p+"ffn_down.weight", nil, QN, FF, D); addr(x, down, QN*D)
  }
  let xn = rms(x, "output_norm.weight", QN)
  let lastRow = buf(D); do { let bl=CB.makeBlitCommandEncoder()!; bl.copy(from:xn,sourceOffset:(QN-1)*D*4,to:lastRow,destinationOffset:0,size:D*4); bl.endEncoding() }
  let logits = linear(lastRow, "output.weight", nil, 1, D, VOCAB)
  CB.commit(); CB.waitUntilCompleted()
  return logits
}
var genToks = [Int](); var genDigest = UInt64(1469598103934665603)
func foldArgmax(_ lg: MTLBuffer) -> Int { let up=lg.contents().bindMemory(to: UInt32.self, capacity: VOCAB); for i in 0..<VOCAB { genDigest=(genDigest ^ UInt64(up[i])) &* 1099511628211 }; let lp=lg.contents().bindMemory(to: Float.self, capacity: VOCAB); var best=0; var bv = -Float.infinity; for i in 0..<VOCAB { if lp[i]>bv { bv=lp[i]; best=i } }; return best }
let t0 = Date()
var lg = forwardStep(ids, 0); var tok = foldArgmax(lg); genToks.append(tok)
for k in 1..<GEN { lg = forwardStep([UInt32(tok)], S + k - 1); tok = foldArgmax(lg); genToks.append(tok) }
let dt = Date().timeIntervalSince(t0)
print("gen_tokens (\(genToks.count)) = \(genToks)")
print(String(format: "GEN_DIGEST 0x%016llx", genDigest))
print(String(format: "throughput: %.2f tok/s (Q4-in-kernel + KV)", Double(GEN)/dt))
