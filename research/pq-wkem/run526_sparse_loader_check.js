'use strict';
// Run 526 research checker: sparse-Toffoli conjugated public loader.
// Uses deterministic toy experiments, not cryptographic parameters.
let state=0x526c0de1;
function rnd(){state^=state<<13;state^=state>>>17;state^=state<<5;return state>>>0;}
function randInt(n){return rnd()%n;}
function bit(x,i){return (x>>>i)&1;}
function affineGate(n){const t=randInt(n);let a=randInt(n-1);if(a>=t)a++;const kind=randInt(3);return kind===0?['not',t,0,0]:kind===1?['cx',t,a,0]:['swap',t,a,0];}
function toffoliGate(n){const t=randInt(n);let a=randInt(n-1);if(a>=t)a++;let b=randInt(n-2);const remaining=[];for(let i=0;i<n;i++)if(i!==t&&i!==a)remaining.push(i);b=remaining[b];return ['ccx',t,a,b];}
function apply(g,x){const [kind,t,a,b]=g;if(kind==='not')return x^(1<<t);if(kind==='cx')return x^(bit(x,a)<<t);if(kind==='swap'){return bit(x,t)===bit(x,a)?x:x^((1<<t)|(1<<a));}return x^((bit(x,a)&bit(x,b))<<t);}
function invertibleFrame(n,r){const gates=[];for(let j=0;j<22;j++)gates.push(affineGate(n));for(let j=0;j<r;j++){gates.push(toffoliGate(n));for(let k=0;k<17;k++)gates.push(affineGate(n));}return gates;}
function action(gates,v,y){let x=y;for(let j=gates.length-1;j>=0;j--)x=apply(gates[j],x);x^=v;for(const g of gates)x=apply(g,x);return x;}
function rank(xs,n){let basis=Array(n).fill(0),s=0;for(let v of xs){for(let b=n-1;b>=0;b--){if(!(v&(1<<b)))continue;if(basis[b])v^=basis[b];else{basis[b]=v;s++;break;}}}return s;}
function derivativeRank(F,n,q){const out=[],used=new Set();for(let j=0;j<q;j++){let z;do{z=4*randInt((1<<n)/4);}while(used.has(z));used.add(z);out.push(F(z)^F(z+1)^F(z+2)^F(z+3));}return rank(out,n);}
function randomPermutation(n){const N=1<<n,p=new Uint32Array(N);for(let i=0;i<N;i++)p[i]=i;for(let i=N-1;i>0;i--){const j=randInt(i+1),v=p[i];p[i]=p[j];p[j]=v;}return p;}
function uniformConjugateLoader(p,v){const inv=new Uint32Array(p.length);for(let i=0;i<p.length;i++)inv[p[i]]=i;return x=>p[inv[x]^v];}
const scenarios=[],trials=40;let sparseChecks=0,idealFullRank=0,idealTrials=0,seenUnexpected=[];
for(const n of [12,16])for(const r of (n===12?[1,2,3]:[1,2,3,4,5])){
 const q=2*r+1;let good=0,high=0,highestSparse=0,minimumIdeal=q;
 for(let t=0;t<trials;t++){
  const gates=invertibleFrame(n,r),v=1<<randInt(n),a=derivativeRank(y=>action(gates,v,y),n,q);
  if(a<=2*r)good++;else seenUnexpected.push({n,r,t,a});
  highestSparse=Math.max(highestSparse,a);sparseChecks++;
  const p=randomPermutation(n),b=derivativeRank(uniformConjugateLoader(p,v),n,q);
  if(b===q)high++;
  minimumIdeal=Math.min(minimumIdeal,b);idealTrials++;
 }
 idealFullRank+=high;scenarios.push({n,r,q,queries:4*q,sparse_bound:2*r,sparse_success:good,maximum_sparse_rank:highestSparse,ideal_full_rank:high,minimum_ideal_rank:minimumIdeal,trials});
}
if(seenUnexpected.length)throw Error(JSON.stringify(seenUnexpected));
const output={run:526,description:'Sparse-Toffoli hidden frame; only public conjugated loader is queried',trials_per_scenario:trials,scenarios,sparse_rank_checks:sparseChecks,ideal_full_rank:idealFullRank,ideal_trials:idealTrials,pass:true};
console.log(JSON.stringify(output,null,2));
