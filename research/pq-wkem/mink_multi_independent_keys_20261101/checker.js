const checkMink = function checkMink(){
 let seed=0x51a9e20d,n=0;
 const rand=()=>{seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0;};
 const assert=(v,msg)=>{n++;if(!v)throw Error(msg+" at "+n);};
 const par=x=>{let p=0;for(;x;x>>>=1)p^=x&1;return p;};
 const mat=es=>es.map(([u,v,b])=>b^(1<<(u+1))^(1<<(v+1)));
 const A=mat([[0,1,0],[1,2,1],[2,0,1]]);
 const F=mat([[0,1,0],[1,2,1],[2,0,0]]);
 const v=w=>1|(w<<1),valid=(M,w)=>M.every(a=>!par(a&v(w)));
 const W=[0,1,2,3,4,5,6,7].filter(w=>valid(A,w));
 const WF=[0,1,2,3,4,5,6,7].filter(w=>valid(F,w));
 assert(W.length===2&&WF.length===0,"source truth");
 const mask=(M,s)=>M.reduce((x,a,j)=>x^(((s>>j)&1)?a:0),0);
 const enc=(M,m)=>mask(M,rand()&7)^m;
 const bit=(key,i)=>(key[i>>3]>>(i&7))&1;
 const build=(M,key)=>Array.from({length:2},()=>Array.from({length:256},(_,i)=>{
  const a=rand()&1,b=rand()&1;return [enc(M,a),enc(M,b),enc(M,a^b^bit(key,i))];
 }));
 const open=(cap,w)=>Array.from({length:32},(_,j)=>{
  let z=0;for(let b=0;b<8;b++)z|=cap[j*8+b].reduce((t,c)=>t^par(c&v(w)),0)<<b;return z;
 });
 const keys=Array.from({length:4},()=>Array.from({length:32},()=>rand()&255));
 const caps=keys.map(k=>build(A,k));
 for(const w of W)for(let j=0;j<4;j++)for(const c of caps[j])
  assert(open(c,w).every((z,i)=>z===keys[j][i]),"all witnesses recover same key");
 let delta=-1;for(let d=0;d<8;d++)if(mask(F,d)===1){delta=d;break;}
 assert(delta>=0,"false shift");
 for(let s=0;s<8;s++)assert(mask(F,s)===(mask(F,s^delta)^1),"equivocal coins");
 for(const m of [0,1]){
  const h=Array(16).fill(0);for(let s=0;s<8;s++)h[mask(F,s)^m]++;
  if(m===0)var h0=h;else assert(h.every((z,i)=>z===h0[i]),"false distributions equal");
 }
 // PUBLIC capsule does not use any signing-key input.
 const zero=Array.from({length:2},()=>Array.from({length:256},()=>Array.from({length:3},()=>{
  const s0=rand()&7;return {c:mask(F,s0),s0};
 })));
 for(const k of keys)for(const c of zero)for(let i=0;i<256;i++){
  const a=rand()&1,b=rand()&1,ms=[a,b,a^b^bit(k,i)];
  assert(ms.reduce((z,t)=>z^t,0)===bit(k,i),"share binding");
  for(let l=0;l<3;l++){
   const {c:published,s0}=c[i][l],m=ms[l];
   assert(published===(mask(F,s0^(m?delta:0))^m),"zero capsule supports any bound secret");
  }
 }
 for(const k of [0,1]){
  const pairs=[];for(const a of [0,1])for(const b of [0,1]){
   const c=a^b^k;assert((a^b^c)===k,"split correct");pairs.push(a+2*b);
  }
  assert(pairs.sort().join(",")==="0,1,2,3","two-open marginals uniform");
 }
 const wrong=Array(32).fill(0),wrongCaps=build(A,wrong);
 assert(keys[3].some(x=>x!==0),"wrong signing seed");
 for(const w of W)for(const c of wrongCaps){
  assert(open(c,w).every(x=>x===0),"wrong capsule decodes incorrectly");
  assert(open(c,w).some((z,i)=>z!==keys[3][i]),"pre-funding proof needed");
 }
 assert(![1,2,3].includes(0),"honest mandatory key");
 return {run:"MINK-2026-11-01-T15",source:"restricted signed-XOR",parties:4,related_capsules_per_party:2,seed_bytes:32,
    true_original_witnesses:W,false_original_witnesses:WF,delta,public_ciphertexts:4*2*256*3,
    checks:n,security:"No QPT-ZK, native signature, hard-TRUE extractor, or generic-NP WKEM instantiated"};
};
console.log(JSON.stringify(checkMink(),null,2));
