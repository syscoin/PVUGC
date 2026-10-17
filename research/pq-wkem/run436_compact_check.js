'use strict';
// Run 436: independent static noisy output frames, classical gauge alignment.
// Noncryptographic deterministic fixture, no ORIGINAL witness and no PQ security claim.
let z=0x4362026,checks=0;
function rng(){z^=z<<13;z^=z>>>17;z^=z<<5;return z>>>0}
function ok(c,m){checks++;if(!c)throw Error(m)}
const M=4096,r=160,bits=Array.from({length:256},()=>((rng()>>>16)&1));
const F=[];
for(let t=0;t<8;t++)for(let i=0;i<256;i++)F.push(bits[i],1-bits[i]);
ok(F.length===M&&F.filter(x=>x===0).length===M/2,'balanced');
const frames=Array.from({length:r},()=>((rng()>>>16)&1)),G=[];
for(let j=0;j<r;j++){
  const row=[];
  for(let x=0;x<M;x++)row.push(F[x]^frames[j]^(((rng()>>>16)&3)===0?1:0));
  G.push(row);
}
const maps=[];
for(let j=0;j<r;j++){
  let same=0,flip=0;
  for(let x=0;x<M;x++)G[0][x]===G[j][x]?same++:flip++;
  const relative=flip>same?1:0;
  maps.push(relative);
  ok(relative===(frames[j]^frames[0]),'relative frame');
}
const recovered=[];
for(let x=0;x<M;x++){
  let one=0;
  for(let j=0;j<r;j++)one+=(G[j][x]^maps[j]);
  ok(one!==r/2,'no plurality tie');
  const b=one>r/2?1:0;
  recovered.push(b);
  ok(b===(F[x]^frames[0]),'recovered F modulo one global gauge');
}
for(let j=0;j<r;j++){
  let match=0;
  for(let i=0;i<256;i++)match+=(G[j][2*i]===bits[i]);
  ok(match!==0&&match!==256,'single noisy view lacks exact 256-bit key');
}
const key0=Array.from({length:256},(_,i)=>recovered[2*i]);
const exact=key0.every((b,i)=>b===bits[i]);
const inverted=key0.every((b,i)=>b===1-bits[i]);
ok(exact!==inverted,'only one global binary orientation remains');
const delta=1/8,fail=(r-1)*2*Math.exp(-M*delta*delta/2)+M*Math.exp(-2*r*(1/2-1/4)**2);
ok(fail<1e-5,'analytic union bound');
console.log(JSON.stringify({run:436,model:'finite balanced binary source / independently noisy hidden output permutations',
  assertions:checks,domain:M,views:r,relativeFramesRecovered:r,sourceRecoveredUpToOneGlobalSwap:true,
  seedBitsRecoverableGivenPublicOrientationCheck:256,formulaGap:delta,
  analyticJointFailureUpperBound:fail,actualQuantumComputation:false,postQuantumRelease:false},null,2));
