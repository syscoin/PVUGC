/* R100 deterministic bounded algebra checker (Node 22). Toy parameters only. */
'use strict';
const crypto=require('crypto');
let assertions=0;
function ok(v,m){assertions++;if(!v)throw Error('R100 '+assertions+': '+m)}
function h(x){return crypto.createHash('sha256').update(JSON.stringify(x)).digest('hex')}
function mul(a,b){let z=0;for(let i=0;i<8;i++){if(b&1)z^=a;let hi=a&128;a=(a*2)&255;if(hi)a^=27;b>>=1}return z}
function pw(a,e){let z=1;for(;e;e>>=1,a=mul(a,a))if(e&1)z=mul(z,a);return z}
function decode(M){const U=Object.keys(M).map(Number).sort((a,b)=>a-b).slice(0,3);if(U.length<3)return null;let z=0;for(const i of U){let num=1,den=1;for(const j of U)if(j!==i){num=mul(num,j+1);den=mul(den,(i+1)^(j+1))}z^=mul(M[i],mul(num,pw(den,254)))}return z}
let state=1000526;function rnd(m){state=(Math.imul(state,1664525)+1013904223)>>>0;return state%m}
const q=257,m=10,d=3,n=5,k=3,cycles=24,delta=128;
const mod=x=>((x%q)+q)%q;
const counts={shared_A_keys:0,authorized_shares:0,insufficient_sets:0,lwe_bits:0,joint_rebindings:0,universal_collision_pairs:0};
for(let r=-3;r<=3;r++)for(let s=r+1;s<=3;s++){
 let collisions=0;for(let a=0;a<7;a++)for(let b=0;b<7;b++)if(a*(r-s)%7===0&&b*(r-s)%7===0)collisions++;
 ok(collisions===1,'uniform (A,B) linear map is two-universal for distinct r');counts.universal_collision_pairs++;
}
for(let t=0;t<cycles;t++){
 const A=Array.from({length:m},()=>Array.from({length:d},()=>rnd(q)));
 const keys=Array.from({length:n},()=>{
  const S=Array.from({length:d},()=>rnd(q));
  const E=Array.from({length:m},()=>rnd(3)-1);
  const B=A.map((row,i)=>mod(row.reduce((z,x,j)=>z+x*S[j],0)+E[i]));
  return {S,E,B};
 });
 for(const key of keys){ok(key.B.every((v,i)=>mod(v-A[i].reduce((z,x,j)=>z+x*key.S[j],0)-key.E[i])===0),'honest shared-A LWE witness');counts.shared_A_keys++}
 const T=rnd(256),co=[T,rnd(256),rnd(256)];
 const shares=Array.from({length:n},(_,i)=>co.reduceRight((z,v)=>mul(z,i+1)^v,0));
 for(let mask=0;mask<(1<<n);mask++){
  const W={};for(let i=0;i<n;i++)if(mask>>i&1)W[i]=shares[i];
  const got=decode(W);
  if(Object.keys(W).length>=k){ok(got===T,'different authorized sets recover identical root');counts.authorized_shares++}
  else{ok(got===null,'short local source witness set fails to reconstruct');counts.insufficient_sets++}
 }
 for(let i=0;i<n;i++)for(let bit=0;bit<2;bit++){
  const r=Array.from({length:m},()=>rnd(7)-3);
  const u=Array.from({length:d},(_,j)=>mod(A.reduce((z,row,x)=>z+row[j]*r[x],0)));
  const v=mod(keys[i].B.reduce((z,b,x)=>z+b*r[x],0)+delta*bit);
  const z=mod(v-keys[i].S.reduce((s,x,j)=>s+x*u[j],0));
  const d0=Math.min(z,q-z),d1=Math.min((z-delta+q)%q,(delta-z+q)%q);
  ok(Number(d1<d0)===bit,'real matching S decrypts ciphertext under shared A');counts.lwe_bits++;
 }
 const base={A,keys:keys.map(x=>x.B),capsules:[{claim:'UTXO:0',ct:[shares[0],shares[1]]},{claim:'UTXO:1',ct:[shares[2],shares[3]]}]};
 const manifest=h(base),ck=base.capsules.map((c,i)=>h([manifest,c.claim,i]));
 const changed=JSON.parse(JSON.stringify(base));changed.capsules[0].ct[0]^=1;
 const m2=h(changed),ck2=changed.capsules.map((c,i)=>h([m2,c.claim,i]));
 ok(m2!==manifest&&ck.every((v,i)=>v!==ck2[i]),'all related public checking fields recomputed from challenge ciphertext');
 counts.joint_rebindings++;
}
const mrows=1649,dim=256,packed=16,leaves=16;
const independent=leaves*mrows*(dim+packed)*2;
const shared=mrows*(dim+leaves*packed)*2;
ok(independent===14352896&&shared===1688576&&independent-shared===12664320,'exact public-key saving');
console.log(JSON.stringify({run:'R100-SHARED-UNIFORM-A-20261105',status:'RESTRICTED_EFFICIENCY_ADVANCE_NOT_GENERIC_NP',assertions,counts,bytes:{old:independent,new:shared,saved:independent-shared},fixture:'insecure q257/short GF256 Shamir, deterministic toy; NOT QPT security'},null,2));
