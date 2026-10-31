// Run 525: exact public candidate predicate and Grover-amplitude toy checks.
// Deterministic stdlib-only; not a real SLH-DSA or quantum implementation.
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
let state = 0x52520261;
function rand(){state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return state >>> 0;}
function permutation(n){const a=Array.from({length:1<<n},(_,i)=>i); for(let i=a.length-1;i>0;i--){const j=rand()%(i+1);[a[i],a[j]]=[a[j],a[i]];}const inv=a.map(()=>0);a.forEach((y,i)=>{inv[y]=i;});return [a,inv];}
function forward(L,R,a,b,c,f,g,h){let T=L^f[R^a],U=R^g[T^b],V=T^h[U^c];return [U,V];}
function backward(U,V,a,b,c,f,g,h){let T=V^h[U^c],R=U^g[T^b],L=T^f[R^a];return [L,R];}
function vk(K,n){return crypto.createHash('sha256').update('run525:native-branch:').update(Buffer.from([n,K])).digest('hex');}
function candidate(a,p1,anchor,claim,vkey,n,f,g,h,gi,hi){
  const [L1,R1,U1,V1]=p1;
  const T1=L1^f[R1^a],b=T1^gi[U1^R1],c=U1^hi[V1^T1];
  const [K,R]=backward(...anchor,a,b,c,f,g,h);
  return R===claim&&vk(K,n)===vkey?K:null;
}
function grover(marks,n){const N=1<<n,M=marks.length,theta=Math.asin(Math.sqrt(M/N));const turns=Math.max(0,Math.round(Math.PI/(4*theta)-0.5));
  let amp=Array(N).fill(1/Math.sqrt(N));
  for(let j=0;j<turns;j++){for(const k of marks)amp[k]=-amp[k];const av=amp.reduce((a,b)=>a+b,0)/N;amp=amp.map(v=>2*av-v);}
  const actual=marks.reduce((s,k)=>s+amp[k]*amp[k],0), expected=Math.sin((2*turns+1)*theta)**2;
  assert.ok(Math.abs(actual-expected)<2e-10);return turns;
}
let trials=0, predicates=0, maxMarked=0, nonbijective=0;
for(const n of [3,4,6,8]){const N=1<<n;
  for(let j=0;j<24;j++){
    let [f]=permutation(n);const [g,gi]=permutation(n),[h,hi]=permutation(n);
    if(j%6===0){f=f.map(x=>x&((1<<Math.max(1,n-2))-1));nonbijective++;}
    const a=rand()%N,b=rand()%N,c=rand()%N,L1=rand()%N,R1=rand()%N;
    const p1=[L1,R1,...forward(L1,R1,a,b,c,f,g,h)];
    const K=rand()%N,claim=rand()%N,anchor=forward(K,claim,a,b,c,f,g,h),vkey=vk(K,n);
    const marks=[];for(let guess=0;guess<N;guess++){const out=candidate(guess,p1,anchor,claim,vkey,n,f,g,h,gi,hi);if(out!==null){assert.equal(out,K);marks.push(guess);}}
    assert.ok(marks.includes(a));grover(marks,n);maxMarked=Math.max(maxMarked,marks.length);trials++;predicates+=N;
  }
}
console.log(JSON.stringify({run:525,pass:true,model:'one full reference opening, arbitrary public first round, invertible middle/final rounds, bound public key checker',trials,true_first_round_keys_accepted:trials,grover_amplitude_checks:trials,nonbijective_first_round_trials:nonbijective,classical_predicate_evaluations:predicates,maximum_marked: maxMarked,quantum_hardware:false,native_slh_dsa:false},null,2));
