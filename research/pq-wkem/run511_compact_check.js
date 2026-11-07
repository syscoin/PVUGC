'use strict';
// Run 511: exact ideal-frame cross-capsule terminal transplantation (toy S8).
const pack=(k,w,t)=>4*k+2*w+t;
const permute=(a,p)=>p.map((_,i)=>a[p.indexOf(i)]); // unused, retained for clarity? no
const conjugate=(p,g)=>{
  const inv=Array(8); for(let i=0;i<8;i++)inv[p[i]]=i;
  return Array.from({length:8},(_,y)=>p[g[inv[y]]]);
};
const R=Array.from({length:8},(_,s)=>s);
const X=Array.from({length:8},(_,s)=>s^2); // n=1 witness bit
const Bref=Array.from({length:8},(_,s)=>s ^ (((s>>2)&1)&&((s>>1)&1)?1:0));
const Bfalse=Array.from({length:8},(_,s)=>s);
let frames=0,attacks=0,loader=0,couplings=0,independent=0;
function test(p){
  const A=conjugate(p,Bref), Ax=conjugate(p,X);
  for(let K=0;K<2;K++){
    const a=p[pack(K,0,0)], y=Ax[a];
    if(y!==p[pack(K,1,0)])throw Error('loader'); loader++;
    if(Number(A[y]!==y)!==K)throw Error('false-instance seed disclosed incorrectly'); attacks++;
    if(conjugate(p,Bfalse).some((v,i)=>v!==i))throw Error('false-target terminal nonidentity');
  }
  const swapK=Array.from({length:8},(_,s)=>s^4);
  const p2=swapK.map(s=>p[s]);
  if(p2[pack(1,0,0)]!==p[pack(0,0,0)] ||
     conjugate(p2,X).some((v,i)=>v!==Ax[i]) ||
     conjugate(p2,Bref).every((v,i)=>v===A[i]))throw Error('coupling');
  couplings++;
  if(A.reduce((sum,y,i)=>sum+(y!==i),0)!==2)throw Error('independent-frame probability');
  independent++; frames++;
}
function enumerate(a,i){if(i===a.length){test(a);return;} for(let j=i;j<a.length;j++){
  [a[i],a[j]]=[a[j],a[i]];enumerate(a,i+1);[a[i],a[j]]=[a[j],a[i]];
}}
enumerate([0,1,2,3,4,5,6,7],0);
if(frames!==40320||attacks!==80640||loader!==80640||couplings!==40320||independent!==40320)throw Error('count mismatch');
console.log(JSON.stringify({run:511,frames,attacks,loader,couplings,independent,
 model:'toy shared ideal frame; false target; known true reference',
 sharedFrameBitRecovery:'perfect',independentFrameBitBias:'zero',
 independentFrameNonfixProbability:'1/4',practicalSecurity:'UNPROVED'},null,2));
