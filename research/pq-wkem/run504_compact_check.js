'use strict';
// Run 504: deterministic classical simulation of Grover search over public
// native-key-checkable release states. Mathematical check, NOT QPT security.
let assertions=0, cases=0, maxError=0;
function ok(x){if(!x)throw Error('assert '+assertions); assertions++}
for(let n=2;n<=9;n++){
 const N=2**n;
 for(const t of [...new Set([1,2,3,Math.floor(N/4),Math.floor(N/2),N-1,N])].sort((a,b)=>a-b)){
  const theta=Math.asin(Math.sqrt(t/N));
  const ideal=Math.max(0,Math.round(Math.PI/(4*theta)-0.5));
  for(const steps of [...new Set([0,1,2,ideal,Math.max(0,ideal-1),ideal+1])]){
   let a=Array(N).fill(1/Math.sqrt(N));
   for(let j=0;j<steps;j++){
    for(let i=0;i<t;i++)a[i]=-a[i];
    let avg=a.reduce((s,v)=>s+v,0)/N;
    a=a.map(v=>2*avg-v);
   }
   const observed=a.slice(0,t).reduce((s,v)=>s+v*v,0);
   const predicted=Math.sin((2*steps+1)*theta)**2;
   let norm=a.reduce((s,v)=>s+v*v,0);
   maxError=Math.max(maxError,Math.abs(observed-predicted));
   ok(Math.abs(observed-predicted)<5e-11);
   ok(Math.abs(norm-1)<5e-11);
   cases++;
  }
 }
}
ok(assertions===402);
console.log(JSON.stringify({run:504,scope:'public short-state release and native verifying oracle',grover_cases:cases,assertions,max_absolute_error:maxError,claim:'mathematical amplitude check only; not an actual quantum device or PQ WKEM'},null,2));
