'use strict';
// Exact finite check of a proposed noisy-projective local release; not a security proof.
const C=require('crypto');
const q=65537,n=4,m=8,B=3,E=2,h=128;
class RNG {constructor(label){this.label=label;this.i=0;}
  u(k){const lim=Math.floor(4294967296/k)*k;for(;;){const v=C.createHash('sha256').update(this.label+":"+(this.i++)).digest().readUInt32BE(0);if(v<lim)return v%k;}}}
const mod=x=>(x%q+q)%q;
const dot=(a,b)=>mod(a.reduce((s,x,i)=>s+x*b[i],0));
const bit=v=>Number(mod(v)>=(q+1)/2);
const distance=(v,b)=>Math.min(mod(v-b),mod(b-v));
const margin=v=>Math.min(distance(v,0),distance(v,Math.floor(q/2)),distance(v,Math.ceil(q/2)));
const vec=(r)=>Array.from({length:n},()=>r.u(q));
const matrix=(r,dup=false)=>{const A=Array.from({length:m},()=>vec(r));if(dup)A[2]=A[1].slice();return A;};
const add=(a,b)=>a.map((v,i)=>mod(v+b[i]));
const scale=(a,k)=>a.map(v=>mod(v*k));
function valid(A,y,w){if(w.some(v=>v!==0&&v!==1)||w.reduce((a,b)=>a+b,0)>B)return false;
  return y.every((v,j)=>v===mod(A.reduce((s,a,i)=>s+w[i]*a[j],0)));}
function allValid(A,y){const a=[];for(let mask=0;mask<(1<<m);mask++){const w=Array.from({length:m},(_,i)=>(mask>>i)&1);if(valid(A,y,w))a.push(w);}return a;}
function compile(A,y,r){const p=Array.from({length:m},()=>[]),K=[];let draws=0;
  for(let j=0;j<h;j++){let alpha,t;do{alpha=vec(r);t=dot(alpha,y);draws++;}while(margin(t)<=B*E+1);
    K.push(bit(t));for(let i=0;i<m;i++)p[i].push(mod(dot(alpha,A[i])+r.u(2*E+1)-E));}
  const check=C.createHash('sha256').update(Buffer.from(K)).digest('hex');return {p,K,check,draws};}
function recover(p,w){return Array.from({length:h},(_,j)=>bit(mod(p.reduce((s,row,i)=>s+row[j]*w[i],0))));}
const same=(a,b)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
let trueCases=0,falseCases=0,validEvaluations=0,distinctStates=0,falseChecked=0;
for(let k=0;k<12;k++){const r=new RNG('true'+k),A=matrix(r,true),y=add(A[0],A[1]),w=allValid(A,y),c=compile(A,y,r);
  if(w.length<2)throw Error('missing alternate witness');for(const x of w){if(!same(c.K,recover(c.p,x)))throw Error('honest correctness');validEvaluations++;}
  if(!c.p[1].some((v,i)=>v!==c.p[2][i]))throw Error('states did not differ');distinctStates++;trueCases++;}
for(let k=0;k<24;k++){const r=new RNG('false'+k),A=matrix(r),y=scale(A[0],2);
  if(allValid(A,y).length)throw Error('false chosen statement unexpectedly true');falseChecked++;
  const c=compile(A,y,r),guess=c.p[0].map(v=>bit(mod(2*v)));
  if(!same(guess,c.K))throw Error('invalid short representation did not recover key');
  if(C.createHash('sha256').update(Buffer.from(guess)).digest('hex')!==c.check)throw Error('checking key mismatch');falseCases++;}
console.log(JSON.stringify({status:'PASS: finite algebraic falsifier; not cryptographic security',q,n,m,B,eta:E,capability_bits:h,true_cases:trueCases,valid_witness_evaluations:validEvaluations,distinct_witness_states:distinctStates,false_cases:falseCases,false_exhaustively_certified:falseChecked,false_full_key_recoveries:falseCases,union_bound_false_becomes_true:'93/'+(BigInt(q)**BigInt(n))},null,2));
