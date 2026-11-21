(() => {
"use strict";
const q=65537, Delta=(q-1)/2, n=6, N=1<<n;
let assertions=0;
function ok(c,m){assertions++;if(!c)throw Error("assertion "+assertions+": "+m);}
const mod=x=>((x%q)+q)%q;
const clauseSpecs=[
[[1,3,4],[0,0,0]],[[0,1,4],[0,0,0]],[[0,1,4],[1,0,1]],
[[1,3,5],[1,0,1]],[[1,3,4],[1,0,0]],[[0,1,2],[0,0,0]],
[[0,3,4],[0,1,1]],[[2,3,5],[1,0,0]],[[0,4,5],[1,1,0]],
[[1,2,5],[1,1,1]],[[1,2,4],[1,0,0]],[[0,3,4],[1,0,0]],
[[0,4,5],[0,0,1]],[[2,4,5],[1,0,0]],[[2,3,4],[0,1,1]],
[[0,3,5],[0,0,1]],[[0,4,5],[0,1,0]],[[1,3,4],[0,1,0]],
[[1,2,4],[1,1,0]]];
const fail=(spec,z)=>+spec[0].every((v,i)=>((z>>v)&1)===spec[1][i]);
const F=clauseSpecs.map(c=>Array.from({length:N},(_,z)=>fail(c,z)));
const generators=[],meta=[];
for(let j=0;j<F.length;j++)for(let k=j;k<F.length;k++){
  generators.push(Array.from({length:N},(_,z)=>F[j][z]*F[k][z]));
  meta.push([j,k,-1]);
}
const originalLength=generators.length;
const repaired=Array.from({length:N},(_,z)=>F[8][z]*F[14][z]*((z>>1)&1));
generators.push(repaired);meta.push([8,14,1]);
const cert=[
[1,0,0,-1],[-1,0,7,-1],[-1,0,12,-1],
[1,2,2,-1],[-1,2,8,-1],[-1,2,14,-1],
[1,3,3,-1],[-1,3,9,-1],[-1,3,10,-1],[-1,3,15,-1],
[1,6,6,-1],[-1,6,9,-1],[-1,6,14,-1],[-1,6,16,-1],
[1,8,8,-1],[1,9,9,-1],[1,10,10,-1],
[1,13,13,-1],[-1,13,17,-1],[1,14,14,-1],
[1,15,15,-1],[1,16,16,-1],[1,17,17,-1],
[-1,8,14,1]];
const coeff=Array(generators.length).fill(0);
for(const [a,j,k,i] of cert){const t=meta.findIndex(g=>g[0]===j&&g[1]===k&&g[2]===i);ok(t>=0,"missing certificate generator");coeff[t]+=a;}
for(let z=0;z<N;z++){
 ok(F.some(f=>f[z]===1),"F must be unsatisfiable");
 let eq=0;
 for(let j=0;j<generators.length;j++)eq+=coeff[j]*generators[j][z];
 ok(eq===1,"exact INTEGER Boolean quotient unit certificate");
}
const inv=a=>{let b=q,u=1,v=0;a=mod(a);while(b){let k=Math.floor(a/b);[a,b]=[b,a-k*b];[u,v]=[v,u-k*v]}return mod(u)};
function spanRank(arr){
 const b=new Map();
 for(const row of arr){let v=row.map(mod);
  for(let i=0;i<N;i++){
   if(!v[i])continue;
   if(b.has(i)){
     let x=v[i],w=b.get(i);
     for(let k=i;k<N;k++)v[k]=mod(v[k]-x*w[k]);
   }else{
     let x=inv(v[i]);for(let k=i;k<N;k++)v[k]=mod(v[k]*x);
     b.set(i,v);break;
   }
  }
 }
 return b.size;
}
const ones=Array(N).fill(1);
const rankOld=spanRank(generators.slice(0,-1));
const rankNew=spanRank(generators);
ok(rankOld===50,"rank W2");ok(rankNew===51,"rank W2+single lift");
ok(spanRank(generators.slice(0,-1).concat([ones]))===51,"unit absent before repair");
ok(spanRank(generators.concat([ones]))===51,"unit present after repair");
const hs=[[17,-1],[19,1],[25,1],[27,-1],[49,1],[57,-1],[59,1]];
let h=Array(N).fill(0);for(const [z,v] of hs)h[z]=v;
ok(h.reduce((a,b)=>a+b,0)===1,"false linear functional normalizes constant");
for(let j=0;j<originalLength;j++)ok(h.reduce((a,v,z)=>a+v*generators[j][z],0)===0,"old mask annihilator");
const liftMoment=h.reduce((a,v,z)=>a+v*repaired[z],0);
ok(liftMoment!==0,"new mask defeats old pseudo functional");
let hc=Array.from({length:N},(_,T)=>h.reduce((a,v,z)=>a+v*+((z&T)===T),0));
const noiseNorm=hc.reduce((a,b)=>a+Math.abs(b),0);
ok(noiseNorm===20,"deterministic coefficient-noise bound 20");
let state=0x6238042;
function rand(){state^=state<<13;state^=state>>>17;state^=state<<5;return state>>>0;}
function rndQ(){return rand()%q;}
function noise(){
 const e=Array.from({length:N},()=> (rand()&1)?1:-1);
 return Array.from({length:N},(_,z)=>e.reduce((s,v,T)=>s+((z&T)===T?v:0),0));
}
function dist(x,t){let a=mod(x-t);return Math.min(a,q-a)}
function decode(x){return dist(x,Delta)<dist(x,0)?1:0}
let oldAttacks=0,coupled=0;
for(let trial=0;trial<128;trial++){
 let bit=rand()&1,e=noise();
 const a=Array.from({length:generators.length},rndQ);
 let old=0;
 for(const [z,w] of hs){
  let v=Delta*bit+e[z];
  for(let j=0;j<originalLength;j++)v+=a[j]*generators[j][z];
  old+=w*mod(v);
 }
 ok(decode(mod(old))===bit,"old FALSE capsule discloses capability bit");
 oldAttacks++;
 const shifted=a.map((v,j)=>mod(v+Delta*bit*coeff[j]));
 for(let z=0;z<N;z++){
  let real=Delta*bit+e[z],sim=e[z];
  for(let j=0;j<generators.length;j++){
   real+=a[j]*generators[j][z];sim+=shifted[j]*generators[j][z];
  }
  ok(mod(real)===mod(sim),"exact whole-capsule shifted coupling");
  coupled++;
 }
}
const G=[
[[0,1,2],[1,1,1]],
[[3,4,5],[1,1,0]],
[[0,3,5],[0,1,0]]
].map(spec=>Array.from({length:N},(_,z)=>fail(spec,z)));
const valid=Array.from({length:N},(_,z)=>z).filter(z=>G.every(f=>!f[z]));
ok(valid.length>=2,"noncanonical ORIGINAL witnesses exist");
let recovers=0;
for(let scope=0;scope<3;scope++)for(let bitNo=0;bitNo<16;bitNo++){
 const bit=rand()&1,e=noise(),a=Array.from({length:6},rndQ);
 for(const z of valid){
  let v=Delta*bit+e[z],j=0;
  for(let x=0;x<3;x++)for(let y=x;y<3;y++)v+=a[j++]*G[x][z]*G[y][z];
  ok(decode(mod(v))===bit,"all genuine witnesses SAME key bit");
  recovers++;
 }
}
const result={run:"R36-SPARSE-ONE-LIFT",q,vars:n,clauses:F.length,productGenerators:originalLength,repairedGenerators:generators.length,
 rankOld,rankNew,unitBefore:false,unitAfter:true,unitCertificateTerms:cert.length,unitCertificateInteger:true,
 oldPseudoFunctionalSupport:hs.length,oldPseudoFunctionalCoefficientL1:noiseNorm,
 oldPseudoFunctionalNewLiftMoment:liftMoment,oldFalseBitRecoveries:oldAttacks,
 exactWholeCapsuleCouplings:coupled,validOriginalWitnesses:valid.length,
 sameCapabilityRecoveries:recovers,assertions};
if(typeof console!=="undefined")console.log(JSON.stringify(result));
return result;
})()