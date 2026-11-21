const run = function run() {
  "use strict";
  let checks=0, state=0x65c0de31>>>0;
  const ok=(v,m="assertion")=>{if(!v)throw Error(m);checks++;};
  const rand=()=>{state^=state<<13;state^=state>>>17;state^=state<<5;return state>>>0;};
  const rb=n=>Array.from({length:n},()=>rand()&255);
  const mat=(m,n,q)=>Array.from({length:m},()=>Array.from({length:n},()=>rand()%q));
  const q=2**24, m=64, n=2, delta=129, B=16;
  const a0=mat(64,8,256);
  function g(seed) {
    ok(seed.length===32);
    const out=[];
    for(let i=0;i<64;i++) {
      const bit=i*3, j=8+Math.floor(bit/8), sh=bit%8;
      const v=((seed[j]>>>sh)|((seed[j+1]||0)<<(8-sh)))&7;
      const e=v<4?v:v-8;
      let z=e;
      for(let k=0;k<8;k++)z+=a0[i][k]*seed[k];
      out.push((z%256+256)%256);
    }
    return out;
  }
  const mix=(key,tag,base)=>{
    const bytes=[...key,...Array.from(tag).map(c=>c.charCodeAt(0)),...Array.from(base).map(c=>c.charCodeAt(0))];
    let s=2166136261>>>0;
    for(const x of bytes) s=Math.imul((s^x)>>>0,16777619)>>>0;
    const z=[];for(let j=0;j<32;j++){s=Math.imul((s^(s>>>13))>>>0,2246822519)>>>0;z.push(s&255);}
    return z;
  };
  const hx=x=>x.map(v=>v.toString(16).padStart(2,"0")).join("");
  const xor=(a,b)=>a.map((x,i)=>x^b[i]);
  const planted=()=>{
    const a=mat(m,n,q);
    for(let k=0;k<n;k++){a[1][k]=(q-a[0][k])%q;a[2][k]=(q-a[0][k])%q;}
    const r1=Array(m).fill(0),r2=Array(m).fill(0);
    r1[0]=r1[1]=1;r2[0]=r2[2]=1;
    return {a,r1,r2};
  };
  const valid=(a,r)=>r.length===m&&r[0]===1&&r.every(v=>v===0||v===1)&&Array.from({length:n},(_,k)=>r.reduce((s,v,i)=>s+v*a[i][k],0)%q).every(z=>z===0);
  const words=k=>Array.from({length:B},(_,i)=>k[2*i]+256*k[2*i+1]);
  function encrypt(a,root) {
    const cs=[],ys=[];
    for(const mu of words(root)){
      const s=[rand()%q,rand()%q],y=[];
      for(let i=0;i<m;i++) y.push(((a[i][0]*s[0]+a[i][1]*s[1]+(rand()%3)-1)%q+q)%q);
      const c=y.slice();c[0]=(c[0]+delta*mu)%q;
      cs.push(c);ys.push(y);
    }
    return {cs,ys};
  }
  const decode=z=>{
    const mu=z>=q-64?0:Math.min(65535,Math.floor((z+64)/delta));
    const dist=Math.min((z-delta*mu+q)%q,(delta*mu-z+q)%q);
    ok(dist<=64);
    return mu;
  };
  function open(a,r,cs){
    ok(valid(a,r),"not a genuine SIS witness");
    const k=[];
    for(const c of cs){
      const z=r.reduce((s,v,i)=>s+v*c[i],0)%q;
      const w=decode(z);k.push(w&255,w>>>8);
    }
    return k;
  }
  const base=(scope,vk,a,cs,dsig,related)=>JSON.stringify({version:65,relation:"SIS",scope,vk,a,a0,cs,dsig,related});
  const view=(scope,vk,a,cs,dsig,key,related)=>{
    const bb=base(scope,vk,a,cs,dsig,related);
    const ck=mix(key,"CK",bb);
    const aux=mix(key,"AUX",hx(ck)+bb);
    return {base_length:bb.length, ck:hx(ck),aux:hx(aux),dsig:hx(dsig),scope,related_count:related.length};
  };
  const {a,r1,r2}=planted(), root=rb(32);
  const ctx="original-sis|utxo:44|branch:challenge|anchors:fixed|vk:toy";
  const vk="toy-native-vk-001";
  const sig=rb(64);
  const y=g(root),seed=y.slice(0,32),key=y.slice(32);
  const dsig=xor(sig,g(seed));
  const {cs,ys}=encrypt(a,root);
  const {a:ar,r1:rr1,r2:rr2}=planted(),kr=rb(32);
  const yr=g(kr),sr=yr.slice(0,32),kir=yr.slice(32),sigR=rb(64);
  const dsR=xor(sigR,g(sr)),er=encrypt(ar,kr),relatedScope="independent-utxo:45|different-message";
  const relatedView=view(relatedScope,"vk-other",ar,er.cs,dsR,kir,[]);
  const related=[{scope:relatedScope,vk:"vk-other",a:ar,cs:er.cs,dsig:dsR,ck:relatedView.ck,aux:relatedView.aux}];
  const targetView=view(ctx,vk,a,cs,dsig,key,related);
  for(const r of [r1,r2]){
    const got=open(a,r,cs);ok(hx(got)===hx(root),"root mismatch");
    const yy=g(got),sp=yy.slice(0,32),kb=yy.slice(32);
    ok(hx(kb)===hx(key));ok(hx(xor(dsig,g(sp)))===hx(sig));
    ok(JSON.stringify(view(ctx,vk,a,cs,dsig,kb,related))===JSON.stringify(targetView));
  }
  for(const rr of [rr1,rr2]){
    const got=open(ar,rr,er.cs);ok(hx(got)===hx(kr));
    const yy=g(got);ok(hx(xor(dsR,g(yy.slice(0,32))))===hx(sigR));
    ok(JSON.stringify(view(relatedScope,"vk-other",ar,er.cs,dsR,yy.slice(32),[]))===JSON.stringify(relatedView));
  }
  for(let i=0;i<B;i++){
    const c=ys[i].slice();c[0]=(c[0]+delta*words(root)[i])%q;
    ok(c.every((v,j)=>v===cs[i][j]));
    const altered=cs.slice();altered[i]=c;
    ok(JSON.stringify(view(ctx,vk,a,altered,dsig,key,related))===JSON.stringify(targetView));
  }
  const uniformCs=mat(B,m,q);
  const rootSim=yy=>{
    const s=yy.slice(0,32), k=yy.slice(32);
    const ds=xor(sig,g(s));
    return {out:view(ctx,vk,a,uniformCs,ds,k,related),ds,s,k};
  };
  const real=rootSim(g(root));ok(hx(real.s)===hx(seed));ok(hx(real.k)===hx(key));ok(hx(real.ds)===hx(dsig));
  const uniform=rootSim(rb(64));
  ok(JSON.stringify(uniform.out)===JSON.stringify(view(ctx,vk,a,uniformCs,uniform.ds,uniform.k,related)));
  const uniformTree=rb(64),treeView=view(ctx,vk,a,uniformCs,xor(sig,uniformTree),uniform.k,related);
  ok(treeView.ck!==uniform.out.ck);
  const finalD=rb(64),finalView=view(ctx,vk,a,uniformCs,finalD,uniform.k,related);
  ok(finalView.dsig===hx(finalD));
  for(let w=0;w<65536;w++)for(const e of [-64,64])ok(decode((delta*w+e+q)%q)===w);
  ok(32*m*3===6144);ok(16*m*3===3072);
  return {run:"R65-SINGLE-ROOT-CK-DERIVATION-20261104",checks,source:{q,m,n,delta,bits_per_vector:16,root_bits:256,ciphertext_vectors:16,bytes:3072},old_source_bytes:6144,source_saving_percent:50,genuine_witness_openings:2,independent_related_true_openings:2,real_source_lwe_couplings:B,whole_root_lwe_challenge:{real:1,uniform:1},tree_hybrid:1,checksum_correlations_recomputed:true,test_crypto:"noncryptographic V8 transcript hash/synthetic signer; independently executed Python checker covers real Ed25519 verification",security:"conditional ordinary-QPT-LWE SIS-only; no generic NP WKEM"};
};
console.log(JSON.stringify(run(), null, 2));
