// MISAKA PALW §19.5 — canonical CUDA Qwen2 forward (port of metal_qwen_q4.swift). Same canonical ops:
// IEEE-754 fp32 + explicit fmaf, software exp/rsqrt (NO hardware expf/rsqrtf), fixed reduction order,
// Q4_K/Q6_K dequant in-kernel, KV cache. Compile: nvcc -O3 -fmad=false -arch=sm_89 (no fast math).
// If the GEN_DIGEST equals the Metal value, canonical unifies CROSS-VENDOR (Apple==NVIDIA), not just
// cross-generation. Env: PALW_DUMP_DIR, PALW_GEN_TOKENS.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <cuda_runtime.h>
#include <cuda_fp16.h>

#define CK(x) do{cudaError_t e=(x); if(e!=cudaSuccess){fprintf(stderr,"cuda err %s @%d: %s\n",#x,__LINE__,cudaGetErrorString(e));exit(1);} }while(0)

__device__ __forceinline__ float rsqrt_soft(float x){int i=__float_as_int(x);i=0x5f3759df-(i>>1);float y=__int_as_float(i);y=y*fmaf(-0.5f*x,y*y,1.5f);y=y*fmaf(-0.5f*x,y*y,1.5f);return y;}
__device__ __forceinline__ float exp_soft(float x){float k=floorf(fmaf(x,1.44269504f,0.5f));float r=fmaf(k,-0.6931471805599453f,x);float p=1.0f/5040.0f;p=fmaf(p,r,1.0f/720.0f);p=fmaf(p,r,1.0f/120.0f);p=fmaf(p,r,1.0f/24.0f);p=fmaf(p,r,1.0f/6.0f);p=fmaf(p,r,0.5f);p=fmaf(p,r,1.0f);p=fmaf(p,r,1.0f);int ki=(int)k;float s=__int_as_float((ki+127)<<23);return p*s;}
__device__ __forceinline__ float sigmoid_soft(float x){return 1.0f/(1.0f+exp_soft(-x));}
__device__ __forceinline__ float f16at(const unsigned char* p){unsigned short u=(unsigned short)p[0]|((unsigned short)p[1]<<8);return __half2float(__ushort_as_half(u));}

__global__ void kembed(const unsigned char* emb,const unsigned int* ids,float* out,unsigned int D,unsigned int qt,unsigned int total){
  unsigned int gid=blockIdx.x*blockDim.x+threadIdx.x; if(gid>=total) return; unsigned int s=gid/D,d=gid%D; unsigned int flat=ids[s]*D+d;
  float v; if(qt==0) v=((const float*)emb)[flat]; else if(qt==1){const unsigned char* blk=emb+(flat/256)*144; unsigned int e=flat%256; float dd=f16at(blk),dmin=f16at(blk+2);const unsigned char* sc=blk+4;const unsigned char* qs=blk+16; unsigned int sb=e>>5; unsigned char s6,m6; if(sb<4){s6=sc[sb]&63;m6=sc[sb+4]&63;}else{s6=(sc[sb+4]&0xF)|((sc[sb-4]>>6)<<4);m6=(sc[sb+4]>>4)|((sc[sb]>>6)<<4);} unsigned int c=e>>6,within=e&63,l=within&31; unsigned char b=qs[c*32+l]; unsigned int qv=(within<32)?(b&0xF):(b>>4); v=(float)s6*dd*(float)qv-(float)m6*dmin;} else {const unsigned char* blk=emb+(flat/256)*210; unsigned int e=flat%256; const unsigned char* ql=blk;const unsigned char* qh=blk+128;const char* sc=(const char*)(blk+192);float dd=f16at(blk+208); unsigned int hi=e>>7,within=e&127,qlb=hi*64,qhb=hi*32,scb=hi*8,l=within&31,g=within>>5,is=l>>4; unsigned char q2=qh[qhb+l]; int qv,si; if(g==0){qv=(int)((ql[qlb+l]&0xF)|(((q2>>0)&3)<<4))-32;si=scb+is+0;}else if(g==1){qv=(int)((ql[qlb+l+32]&0xF)|(((q2>>2)&3)<<4))-32;si=scb+is+2;}else if(g==2){qv=(int)((ql[qlb+l]>>4)|(((q2>>4)&3)<<4))-32;si=scb+is+4;}else{qv=(int)((ql[qlb+l+32]>>4)|(((q2>>6)&3)<<4))-32;si=scb+is+6;} v=dd*(float)sc[si]*(float)qv;}
  out[gid]=v;
}
__global__ void klin_f32(const unsigned char* W,const float* X,const float* bias,float* out,unsigned int M,unsigned int K,unsigned int N,unsigned int hasB){
  unsigned int gid=blockIdx.x*blockDim.x+threadIdx.x; if(gid>=M*N) return; unsigned int m=gid/N,n=gid%N; const float* Wf=(const float*)W; float acc=0.f; for(unsigned int k=0;k<K;++k) acc=fmaf(X[m*K+k],Wf[n*K+k],acc); if(hasB) acc+=bias[n]; out[gid]=acc;
}
__global__ void klin_q4k(const unsigned char* W,const float* X,const float* bias,float* out,unsigned int M,unsigned int K,unsigned int N,unsigned int hasB){
  unsigned int gid=blockIdx.x*blockDim.x+threadIdx.x; if(gid>=M*N) return; unsigned int m=gid/N,n=gid%N; unsigned int NB=K/256; const unsigned char* wrow=W+(size_t)n*NB*144; const float* xr=X+m*K; float acc=0.f;
  for(unsigned int b=0;b<NB;++b){const unsigned char* blk=wrow+b*144; float d=f16at(blk),dmin=f16at(blk+2);const unsigned char* sc=blk+4;const unsigned char* qs=blk+16; unsigned int kb=b*256;
    for(unsigned int c=0;c<4;++c) for(unsigned int hf=0;hf<2;++hf){unsigned int sub=2*c+hf; unsigned char s6,m6; if(sub<4){s6=sc[sub]&63;m6=sc[sub+4]&63;}else{s6=(sc[sub+4]&0xF)|((sc[sub-4]>>6)<<4);m6=(sc[sub+4]>>4)|((sc[sub]>>6)<<4);} float d1=d*(float)s6,mm=dmin*(float)m6; unsigned int base=kb+c*64+hf*32; for(unsigned int l=0;l<32;++l){unsigned int qv=(hf==0)?(qs[c*32+l]&0xF):(qs[c*32+l]>>4); float w=d1*(float)qv-mm; acc=fmaf(xr[base+l],w,acc);}}}
  if(hasB) acc+=bias[n]; out[gid]=acc;
}
__global__ void klin_q6k(const unsigned char* W,const float* X,const float* bias,float* out,unsigned int M,unsigned int K,unsigned int N,unsigned int hasB){
  unsigned int gid=blockIdx.x*blockDim.x+threadIdx.x; if(gid>=M*N) return; unsigned int m=gid/N,n=gid%N; unsigned int NB=K/256; const unsigned char* wrow=W+(size_t)n*NB*210; const float* xr=X+m*K; float acc=0.f;
  for(unsigned int b=0;b<NB;++b){const unsigned char* blk=wrow+b*210; const unsigned char* ql=blk;const unsigned char* qh=blk+128;const char* sc=(const char*)(blk+192);float d=f16at(blk+208); unsigned int kb=b*256;
    for(unsigned int hi=0;hi<2;++hi){unsigned int qlb=hi*64,qhb=hi*32,scb=hi*8; for(unsigned int within=0;within<128;++within){unsigned int l=within&31,g=within>>5,is=l>>4; unsigned char q2=qh[qhb+l]; int qv,si; if(g==0){qv=(int)((ql[qlb+l]&0xF)|(((q2>>0)&3)<<4))-32;si=scb+is+0;}else if(g==1){qv=(int)((ql[qlb+l+32]&0xF)|(((q2>>2)&3)<<4))-32;si=scb+is+2;}else if(g==2){qv=(int)((ql[qlb+l]>>4)|(((q2>>4)&3)<<4))-32;si=scb+is+4;}else{qv=(int)((ql[qlb+l+32]>>4)|(((q2>>6)&3)<<4))-32;si=scb+is+6;} float w=d*(float)sc[si]*(float)qv; acc=fmaf(xr[kb+hi*128+within],w,acc);}}}
  if(hasB) acc+=bias[n]; out[gid]=acc;
}
__global__ void krms(const float* x,const float* w,float* out,unsigned int D,float eps){
  unsigned int row=blockIdx.x; unsigned int tid=threadIdx.x,tgs=blockDim.x; unsigned int lane=tid&31,wid=tid>>5,nsg=tgs>>5;
  __shared__ float sgp[32]; __shared__ float tot;
  const float* xr=x+row*D; float* outr=out+(size_t)row*D;
  float ps=0.f; for(unsigned int i=tid;i<D;i+=tgs){float v=xr[i]; ps=fmaf(v,v,ps);}
  for(unsigned int o=16;o>0;o>>=1) ps+=__shfl_xor_sync(0xffffffff,ps,o);
  if(lane==0) sgp[wid]=ps; __syncthreads();
  if(tid==0){float t=0.f; for(unsigned int s=0;s<nsg;++s) t+=sgp[s]; tot=t;} __syncthreads();
  float rms=rsqrt_soft(tot/(float)D+eps); for(unsigned int i=tid;i<D;i+=tgs) outr[i]=xr[i]*rms*w[i];
}
__global__ void krope(float* buf,const float* cs,unsigned int QN,unsigned int H,unsigned int HD,unsigned int off){
  unsigned int gid=blockIdx.x*blockDim.x+threadIdx.x; unsigned int P=HD/2; if(gid>=QN*H*P) return; unsigned int i=gid%P,h=(gid/P)%H,r=gid/(P*H),pos=off+r; float c=cs[(pos*P+i)*2],sn=cs[(pos*P+i)*2+1]; unsigned int base=(r*H+h)*HD; float a=buf[base+i],b=buf[base+i+P]; buf[base+i]=fmaf(a,c,-b*sn); buf[base+i+P]=fmaf(b,c,a*sn);
}
__global__ void kattn(const float* Q,const float* KC,const float* VC,float* out,unsigned int QN,unsigned int NH,unsigned int NKV,unsigned int HD,unsigned int qStart){
  unsigned int gid=blockIdx.x*blockDim.x+threadIdx.x; if(gid>=QN*NH) return; unsigned int h=gid%NH,r=gid/NH,kv=h/(NH/NKV),qpos=qStart+r; float scale=rsqrt_soft((float)HD);
  float sc[2048]; float mx=-1e30f;
  for(unsigned int j=0;j<=qpos;++j){float d=0.f; for(unsigned int t=0;t<HD;++t) d=fmaf(Q[(r*NH+h)*HD+t],KC[(j*NKV+kv)*HD+t],d); d*=scale; sc[j]=d; mx=fmaxf(mx,d);}
  float sum=0.f; for(unsigned int j=0;j<=qpos;++j){float e=exp_soft(sc[j]-mx); sc[j]=e; sum+=e;} float inv=1.f/sum;
  for(unsigned int t=0;t<HD;++t){float o=0.f; for(unsigned int j=0;j<=qpos;++j) o=fmaf(sc[j]*inv,VC[(j*NKV+kv)*HD+t],o); out[(r*NH+h)*HD+t]=o;}
}
__global__ void kglu(const float* g,const float* u,float* out,unsigned int n){unsigned int gid=blockIdx.x*blockDim.x+threadIdx.x; if(gid>=n) return; float x=g[gid]; out[gid]=(x*sigmoid_soft(x))*u[gid];}
__global__ void kadd(float* a,const float* b,unsigned int n){unsigned int gid=blockIdx.x*blockDim.x+threadIdx.x; if(gid>=n) return; a[gid]+=b[gid];}

// ---- host ----
static std::string slurp(const std::string& p){FILE* f=fopen(p.c_str(),"rb"); if(!f){fprintf(stderr,"open %s\n",p.c_str());exit(1);} fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET); std::string s; s.resize(n); fread(&s[0],1,n,f); fclose(f); return s;}
static long ival(const std::string& m,const char* key){size_t p=m.find(std::string("\"")+key+"\""); if(p==std::string::npos){fprintf(stderr,"key %s missing\n",key);exit(1);} p=m.find(':',p)+1; return strtol(m.c_str()+p,nullptr,10);}

struct Tensor{std::string name,file,qtype; std::vector<long> shape; unsigned char* dptr=nullptr; long bytes=0;};

int main(){
  std::string dir=getenv("PALW_DUMP_DIR")?getenv("PALW_DUMP_DIR"):""; int GEN=getenv("PALW_GEN_TOKENS")?atoi(getenv("PALW_GEN_TOKENS")):24;
  std::string man=slurp(dir+"/manifest.json");
  int L=ival(man,"qwen2.block_count"),D=ival(man,"qwen2.embedding_length"),NH=ival(man,"qwen2.attention.head_count"),NKV=ival(man,"qwen2.attention.head_count_kv"),FF=ival(man,"qwen2.feed_forward_length");
  int HD=D/NH,KVD=NKV*HD; float EPS=1e-6f;
  // prompt ids
  std::string pj=slurp(dir+"/prompt_ids.json"); std::vector<unsigned int> ids; {const char* c=pj.c_str(); while(*c){ if(*c>='0'&&*c<='9'){ids.push_back(strtoul(c,(char**)&c,10));} else c++;}}
  int S=ids.size(); int MAXLEN=S+GEN;
  printf("config L=%d D=%d NH=%d NKV=%d HD=%d FF=%d S=%d GEN=%d\n",L,D,NH,NKV,HD,FF,S,GEN);
  cudaDeviceProp prop; CK(cudaGetDeviceProperties(&prop,0)); printf("device: %s\n",prop.name);
  // parse tensors
  std::map<std::string,Tensor> T;
  size_t p=man.find("\"tensors\"");
  while(true){ size_t q=man.find("\"name\":",p); if(q==std::string::npos) break; Tensor t;
    size_t a=man.find('"',q+7)+1,b=man.find('"',a); t.name=man.substr(a,b-a);
    size_t fa=man.find("\"file\":",b); fa=man.find('"',fa+7)+1; size_t fb=man.find('"',fa); t.file=man.substr(fa,fb-fa);
    size_t sa=man.find("\"shape\":",fb); sa=man.find('[',sa)+1; size_t sb=man.find(']',sa); {std::string sh=man.substr(sa,sb-sa); const char* c=sh.c_str(); while(*c){if((*c>='0'&&*c<='9')) t.shape.push_back(strtol(c,(char**)&c,10)); else c++;}}
    size_t qa=man.find("\"qtype\":",sb); qa=man.find('"',qa+8)+1; size_t qb=man.find('"',qa); t.qtype=man.substr(qa,qb-qa);
    // load file to device
    std::string data=slurp(dir+"/"+t.file); t.bytes=data.size(); CK(cudaMalloc(&t.dptr,data.size())); CK(cudaMemcpy(t.dptr,data.data(),data.size(),cudaMemcpyHostToDevice));
    T[t.name]=t; p=qb;
  }
  printf("loaded %zu tensors\n",T.size());
  int VOCAB=T["output.weight"].shape[0];
  // rope table
  std::string rt=slurp(dir+"/rope_table.bin"); float* d_cs; CK(cudaMalloc(&d_cs,rt.size())); CK(cudaMemcpy(d_cs,rt.data(),rt.size(),cudaMemcpyHostToDevice));
  auto qt=[&](const std::string& n)->unsigned int{const std::string&q=T[n].qtype; return q=="Q4K"?1:(q=="Q6K"?2:0);};
  // kv cache
  std::vector<float*> kc(L),vc(L); for(int l=0;l<L;++l){CK(cudaMalloc(&kc[l],(size_t)MAXLEN*KVD*4)); CK(cudaMalloc(&vc[l],(size_t)MAXLEN*KVD*4));}
  auto grid=[&](int n){return (n+255)/256;};
  auto buf=[&](size_t n){float* p; CK(cudaMalloc(&p,n*4)); return p;};
  auto linear=[&](float* x,const std::string& w,const std::string& bias,int M,int K,int N)->float*{
    float* out=buf((size_t)M*N); unsigned int u=qt(w); const float* bp=bias.empty()?nullptr:(const float*)T[bias].dptr; unsigned int hasB=bias.empty()?0:1;
    if(u==1) klin_q4k<<<grid(M*N),256>>>(T[w].dptr,x,bp,out,M,K,N,hasB); else if(u==2) klin_q6k<<<grid(M*N),256>>>(T[w].dptr,x,bp,out,M,K,N,hasB); else klin_f32<<<grid(M*N),256>>>(T[w].dptr,x,bp,out,M,K,N,hasB); return out;};
  auto rms=[&](float* x,const std::string& w,int SL)->float*{float* out=buf((size_t)SL*D); krms<<<SL,256>>>(x,(const float*)T[w].dptr,out,D,EPS); return out;};
  unsigned long long digest=1469598103934665603ULL; std::vector<int> gen;
  std::vector<float> hl(VOCAB);
  auto forwardStep=[&](std::vector<unsigned int>& toks,int qStart)->float*{
    int QN=toks.size(); float* x=buf((size_t)QN*D); unsigned int* d_ids; CK(cudaMalloc(&d_ids,QN*4)); CK(cudaMemcpy(d_ids,toks.data(),QN*4,cudaMemcpyHostToDevice));
    kembed<<<grid(QN*D),256>>>(T["token_embd.weight"].dptr,d_ids,x,D,qt("token_embd.weight"),QN*D);
    for(int l=0;l<L;++l){std::string pre="blk."+std::to_string(l)+".";
      float* h=rms(x,pre+"attn_norm.weight",QN);
      float* q=linear(h,pre+"attn_q.weight",pre+"attn_q.bias",QN,D,D);
      float* k=linear(h,pre+"attn_k.weight",pre+"attn_k.bias",QN,D,KVD);
      float* v=linear(h,pre+"attn_v.weight",pre+"attn_v.bias",QN,D,KVD);
      krope<<<grid(QN*NH*(HD/2)),256>>>(q,d_cs,QN,NH,HD,qStart); krope<<<grid(QN*NKV*(HD/2)),256>>>(k,d_cs,QN,NKV,HD,qStart);
      CK(cudaMemcpy(kc[l]+(size_t)qStart*KVD,k,(size_t)QN*KVD*4,cudaMemcpyDeviceToDevice)); CK(cudaMemcpy(vc[l]+(size_t)qStart*KVD,v,(size_t)QN*KVD*4,cudaMemcpyDeviceToDevice));
      float* ao=buf((size_t)QN*D); kattn<<<grid(QN*NH),256>>>(q,kc[l],vc[l],ao,QN,NH,NKV,HD,qStart);
      float* proj=linear(ao,pre+"attn_output.weight","",QN,D,D); kadd<<<grid(QN*D),256>>>(x,proj,QN*D);
      float* h2=rms(x,pre+"ffn_norm.weight",QN);
      float* g=linear(h2,pre+"ffn_gate.weight","",QN,D,FF); float* u=linear(h2,pre+"ffn_up.weight","",QN,D,FF);
      float* sg=buf((size_t)QN*FF); kglu<<<grid(QN*FF),256>>>(g,u,sg,QN*FF);
      float* down=linear(sg,pre+"ffn_down.weight","",QN,FF,D); kadd<<<grid(QN*D),256>>>(x,down,QN*D);
      cudaFree(h);cudaFree(q);cudaFree(k);cudaFree(v);cudaFree(ao);cudaFree(proj);cudaFree(h2);cudaFree(g);cudaFree(u);cudaFree(sg);cudaFree(down);
    }
    float* xn=rms(x,"output_norm.weight",QN); float* last=buf(D); CK(cudaMemcpy(last,xn+(size_t)(QN-1)*D,D*4,cudaMemcpyDeviceToDevice));
    float* logits=linear(last,"output.weight","",1,D,VOCAB); CK(cudaDeviceSynchronize());
    cudaFree(x);cudaFree(d_ids);cudaFree(xn);cudaFree(last); return logits;
  };
  auto foldArg=[&](float* lg)->int{CK(cudaMemcpy(hl.data(),lg,(size_t)VOCAB*4,cudaMemcpyDeviceToHost)); for(int i=0;i<VOCAB;++i){unsigned int u=*(unsigned int*)&hl[i]; digest=(digest^(unsigned long long)u)*1099511628211ULL;} int best=0; float bv=-1e30f; for(int i=0;i<VOCAB;++i) if(hl[i]>bv){bv=hl[i];best=i;} return best;};
  std::vector<unsigned int> cur=ids; float* lg=forwardStep(cur,0); int tok=foldArg(lg); cudaFree(lg); gen.push_back(tok);
  for(int kk=1;kk<GEN;++kk){std::vector<unsigned int> one={ (unsigned int)tok }; lg=forwardStep(one,S+kk-1); tok=foldArg(lg); cudaFree(lg); gen.push_back(tok);}
  printf("gen_tokens (%zu) = [",gen.size()); for(size_t i=0;i<gen.size();++i) printf("%d%s",gen[i],i+1<gen.size()?", ":""); printf("]\n");
  printf("GEN_DIGEST 0x%016llx\n",digest);
  return 0;
}
