'use strict';
// Offline finite algebra/distribution checker. Not a QPT hardness benchmark.
const crypto=require('crypto');
let state=20261029+104, checks=0;
const rnd=n=>{ state=(Math.imul(state,1664525)+1013904223)>>>0; return state%n; };
const chk=(a,m)=>{checks++;if(!a)throw Error(m);};
const mod=(x,q)=>((x%q)+q)%q;
function src(n,m,q,B,degenerate=false){
 const A=Array.from({length:n},()=>Array.from({length:m},()=>rnd(q)));
 if(degenerate)A[n-1].fill(0);
 const s=Array.from({length:n},()=>rnd(q)),e=Array.from({length:m},()=>rnd(2*B+1)-B);
 const b=Array.from({length:m},(_,j)=>mod(A.reduce((v,row,i)=>v+row[j]*s[i],e[j]),q));
 return {A,b,s,e};
}
function valid(A,b,s,q,B){return b.every((v,j)=>{let e=mod(v-A.reduce((a,row,i)=>a+row[j]*s[i],0),q);if(e>q/2)e-=q;return Math.abs(e)<=B;});}
function enc(A,b,q,bit){const r=b.map(()=>rnd(2));const u=A.map(row=>mod(row.reduce((a,v,i)=>a+v*r[i],0),q));return [u,mod(b.reduce((a,v,i)=>a+v*r[i],0)+Math.floor(q/2)*bit,q)];}
function dec(c,s,q){const v=mod(c[1]-s.reduce((a,x,i)=>a+x*c[0][i],0),q);const dist=center=>Math.min(mod(v-center,q),mod(center-v,q));return +(dist(Math.floor(q/2))<dist(0));}
function encBytes(A,b,q,K){let out=[];for(const byte of K)for(let k=0;k<8;k++)out.push(enc(A,b,q,(byte>>k)&1));return out;}
function decBytes(cs,s,q){const bits=cs.map(c=>dec(c,s,q)),K=[];for(let i=0;i<bits.length;i+=8){let v=0;for(let k=0;k<8;k++)v|=bits[i+k]<<k;K.push(v);}return Buffer.from(K);}
const q=257,n=3,m=18,B=1,{A,b,s}=src(n,m,q,B,true);
let witnesses=[];for(let j=0;j<9;j++){let w=s.slice();w[2]=mod(w[2]+23*j,q);chk(valid(A,b,w,q,B),'valid multiple SOURCE preimages');witnesses.push(w);}
let digests=[];
for(let claim=0;claim<2;claim++){
 const K=Buffer.from(Array.from({length:32},()=>rnd(256))),pk=crypto.createHash('sha256').update(K).digest('hex');
 const ct=encBytes(A,b,q,K);chk(ct.length===256,'all native seed bits encrypted');
 for(const w of witnesses){const rec=decBytes(ct,w,q);chk(rec.equals(K),'every witness SAME key');chk(crypto.createHash('sha256').update(rec).digest('hex')===pk,'checking key correlated');}
 digests.push(pk);
}
chk(digests[0]!==digests[1],'independent claims');
for(let t=0;t<12;t++){const r=src(3,18,257,1);chk(valid(r.A,r.b,r.s,257,1),'true source sampling');for(let bit=0;bit<2;bit++)chk(dec(enc(r.A,r.b,257,bit),r.s,257)===bit,'complete ciphertext decoding');}
// Exhaust exact 2^m encryption randomness for fixed public H in tiny uniform-source cases.
const qf=17,mf=16,exact=[];let falseCount=0;
for(let trial=0;trial<12;trial++){
 const h=Array.from({length:mf},()=>rnd(qf)),bb=Array.from({length:mf},()=>rnd(qf));
 if(!Array.from({length:qf},(_,x)=>x).some(x=>h.every((a,j)=>mod(a*x,qf)===bb[j])))falseCount++;
 const cnt=new Uint32Array(qf*qf);
 for(let r=0;r<(1<<mf);r++){
   let u=0,v=0;for(let j=0;j<mf;j++)if(r&(1<<j)){u+=h[j];v+=bb[j];}
   cnt[mod(u,qf)*qf+mod(v,qf)]++;
 }
 chk(cnt.reduce((a,v)=>a+v,0)===(1<<mf),'exhaustive source output distribution');
 const unif=1/(qf*qf);let tv=0;
 for(let i=0;i<cnt.length;i++)tv+=Math.abs(cnt[i]/(1<<mf)-unif)/2;
 exact.push(tv);
}
const avg=exact.reduce((a,v)=>a+v,0)/exact.length,bound=0.5*Math.sqrt((qf*qf-1)/(2**mf));
chk(avg<=bound,'empirical average below average LHL bound');chk(falseCount>=10,'mostly FALSE uniform-source cases');
// Source false-instance exhaustive search: 257^2 secrets, q=257, n=2, m=18, B=1.
const rf=src(2,18,257,1);let bs=Array.from({length:18},()=>rnd(257)),num=0;
for(let s0=0;s0<257;s0++)for(let s1=0;s1<257;s1++)if(valid(rf.A,bs,[s0,s1],257,1))num++;
chk(num===0,'exhaustive sampled fixed FALSE SOURCE');
const large={q:2**24,n:256,m:6600,B:256,L:256};
chk(large.q>4*large.m*large.B+2,'large illustrative correctness');
const logDelta=-1+0.5*((large.n+1)*24-large.m),log2Tdelta=Math.log2(2*large.L)+logDelta;
chk(log2Tdelta<-128,'only statistical bound, NOT QPT LWE certification');
const out={status:'PASS (restricted SOURCE only)',checks,validWitnesses:9,independentNativeSeeds:2,
 source:{q,n,m,B},uniformTiny:{q:qf,m:mf,cases:exact.length,falseCount,avgTV:avg,lhlUpper:bound,maxTV:Math.max(...exact)},
 sampledFixedFalseSourceWitnesses:num,illustrative:{...large,log2Delta:logDelta,log2_2LDelta:log2Tdelta,
 rawDenseABytes:large.n*large.m*3,rawCipherBytes:large.L*(large.n+1)*3},
 disclaimer:'Genuine Lamport OTS checking-key correlation and second independent checker are in local-only check.py; NOT native SLH, QPT hardness, generic NP or every-fixed-FALSE security.'};
console.log(JSON.stringify(out,null,2));
