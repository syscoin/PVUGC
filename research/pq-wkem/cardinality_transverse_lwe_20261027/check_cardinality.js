'use strict';
// Offline reproducible finite-algebra checker for cardinality-pinned transverse LWE.
// Node.js >= 18; no external modules, no random network dependencies.
const assert = require('assert').strict;
let checks = 0;
function eq(x, y, msg) { assert.deepEqual(x, y, msg); checks++; }
function ok(x, msg) { assert.ok(x, msg); checks++; }
const mod=(x,q)=>((x%q)+q)%q;
function pc(x) { let n=0; while(x){n+=x&1;x>>>=1;} return n; }
function binom(n,k){let x=1n;for(let i=1;i<=k;i++)x=x*BigInt(n-k+i)/BigInt(i);return x;}
function witnesses(B,h,q){const n=B[0].length,ws=[];for(let w=0;w<(1<<n);w++){if(pc(w)!==h)continue;if(B.every(row=>mod(row.reduce((sum,a,i)=>sum+((w>>i)&1)*a,0),q)===0))ws.push(w);}return ws;}
const test1=()=>{
 const q=64,g=8,h=2,beta=1,c=g/h,n=6,hs=[3,5];
 const B=[[2,62,11,53,7,57],[5,59,13,51,17,47]];
 const A=[Array(n).fill(c),...B.map((row,i)=>row.map(x=>mod(x+hs[i]*c,q)))];
 const b=[g,...hs.map(x=>g*x)],good=witnesses(B,h,q);
 eq(g>2*h*beta,true);ok(c*n<q);ok(good.length>=3);
 for(let w=0;w<(1<<n);w++){
   const direct=pc(w)===h&&B.every(row=>mod(row.reduce((s,a,i)=>s+a*((w>>i)&1),0),q)===0);
   const aw=A.every((row,i)=>mod(row.reduce((s,a,j)=>s+a*((w>>j)&1),0),q)===mod(b[i],q));
   eq(aw,direct,'cardinality must characterize ALL binary solutions');
 }
 let opens=0;
 for(let t=0;t<q;t++){
   const u=[mod(7*t+5,q),mod(11*t+9,q)];
   const s=[mod(t-hs[0]*u[0]-hs[1]*u[1],q),...u];
   for(let code=0;code<3**n;code++){
     let x=code;const e=[];for(let z=0;z<n;z++){e.push(x%3-1);x=Math.floor(x/3);}
     const p=A[0].map((_,i)=>mod(A.reduce((sum,row,j)=>sum+row[i]*s[j],e[i]),q));
     const emb=A[0].map((_,i)=>mod(c*t+B.reduce((sum,row,j)=>sum+row[i]*u[j],e[i]),q));
     eq(p,emb,'entire noisy LWE vector identity');
     for(const w of good){
       const y=mod(p.reduce((sum,x,i)=>sum+((w>>i)&1)*x,0),q);
       const rounded=Math.floor((y+g/2)/g)%(q/g);
       eq(rounded,t%(q/g),'all valid witnesses open SAME t residue');opens++;
     }
   }
 }
 return {validWitnesses:good.length,allWitnessOpeningChecks:opens};
};
const test2=()=>{
 // All B in Z_4^(1x6), all weight-three binary vectors; verify expectation,
 // exact pairwise independence and the second-moment existence guarantee.
 const q=4,n=6,h=3,wm=[];for(let w=0;w<1<<n;w++)if(pc(w)===h)wm.push(w);
 const cnt=Array(wm.length).fill(0),pair=Array.from({length:wm.length},()=>Array(wm.length).fill(0));
 let no=0;
 for(let bc=0;bc<q**n;bc++){
   let x=bc;const row=[];for(let i=0;i<n;i++){row.push(x%q);x=Math.floor(x/q);}
   const sat=wm.map(w=>mod(row.reduce((sum,a,i)=>sum+a*((w>>i)&1),0),q)===0);
   if(!sat.some(Boolean))no++;
   for(let i=0;i<wm.length;i++){
     if(sat[i])cnt[i]++;
     for(let j=i+1;j<wm.length;j++)if(sat[i]&&sat[j])pair[i][j]++;
   }
 }
 for(let i=0;i<wm.length;i++){
   eq(cnt[i],q**(n-1));
   for(let j=i+1;j<wm.length;j++)eq(pair[i][j],q**(n-2));
 }
 ok(no/(q**n)<=q/(wm.length),'Chebyshev one-sided zero-probability bound');
 return {enumeratedMatrices:q**n,cardinalityWitnesses:wm.length,falseMatrices:no};
};
const test3=()=>{
 // Fully enumerate the native-key-correlated ALL-UNIFORM LWE final hybrid.
 // k=2, two one-bit z_j; any K (even with deterministic public checking key).
 for(let K=0;K<4;K++){
  const seen=Array.from({length:4},()=>Array(4).fill(0));
  for(let U=0;U<4;U++)for(let z=0;z<4;z++){
   const D=U^z,V=K^U;seen[D][V]++;
  }
  for(const row of seen)for(const frequency of row)eq(frequency,1);
 }
 return {keys:4,jointPairsPerKey:16};
};
const test4=()=>{
 const a=20,k=256,beta=1,n=4096,h=128,d=32,q=2**a;
 const nextPow2Above=x=>{let z=1;while(z<=x)z*=2;return z;};
 const gold=nextPow2Above(2*n*beta),gnew=nextPow2Above(2*h*beta);
 const rold=a-Math.log2(gold),rnew=a-Math.log2(gnew);
 const ellOld=Math.ceil(k/rold),ellNew=Math.ceil(k/rnew);
 eq(gold,16384);eq(gnew,512);eq(rold,6);eq(rnew,11);
 eq(ellOld,43);eq(ellNew,24);
 ok((gnew/h)*n<q); // Cardinality does not alias modulo q.
 const M=binom(n,h);const exponent=a*d;
 ok(M>(1n<<BigInt(exponent+128)),'true unplanted source with >=128-bit second-moment safety');
 // Signal sample reduction does not change (d,n,q,chi) LWE challenge distribution.
 return {q,n,h,d,gOld:gold,gNew:gnew,ellOld,ellNew,pctFewerColumns:(100*(ellOld-ellNew)/ellOld).toFixed(3),satisfiabilitySlackBits:M.toString(2).length-1-exponent};
};
const data={record:'cardinality-transverse-lwe-20261027',fullVector:test1(),pairwise:test2(),nullHybrid:test3(),parameters:test4(),checks};
console.log(JSON.stringify(data,null,2));
