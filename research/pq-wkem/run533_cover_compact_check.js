'use strict';
// Exact finite falsification of nominal-bitlength padding at a public release
// seam. Toy acceptance predicates, not a cryptographic WKEM or quantum code.
const assert = require('node:assert/strict');
const close=(a,b)=>assert.ok(Math.abs(a-b)<1e-11,'numerical mismatch');
let padded=0, randomized=0, dominated=0, correlated=0, repetitions=0, quantum=0;
for(let ell=1;ell<=6;ell++) for(const bits of [0,2,5]) {
  const n=2**ell, m=2**bits;
  for(const a of [0,n-1]) for(const alpha of [1,0.5,0.75]) {
    let honest=0, sampled=0;
    for(let tag=0;tag<n;tag++) for(let salt=0;salt<m;salt++) {
      const p=tag===a?alpha:0;
      if(tag===a) honest+=p/m;
      sampled+=p/(n*m);
    }
    close(honest,alpha); close(sampled,alpha/n);
    padded++; if(alpha<1) randomized++;
  }
}
for(let n=3;n<=12;n++) for(let j=0;j<20;j++) {
  const weights=Array.from({length:n},(_,i)=>(1+((7*i+11*j)%13)));
  const total=weights.reduce((a,b)=>a+b,0);
  const q=weights.map(x=>x/total);
  const d=q.map(x=>x/8+7/(8*n));
  const p=weights.map((x,i)=>((x+3*i)%8)/7);
  close(q.reduce((a,b)=>a+b,0),1);
  close(d.reduce((a,b)=>a+b,0),1);
  const C=q.reduce((v,x,i)=>v+x*p[i],0);
  const A=d.reduce((v,x,i)=>v+x*p[i],0);
  assert.ok(q.every((x,i)=>x<=8*d[i]+1e-13));
  assert.ok(A>=C/8-1e-13); dominated++;
}
for(let ell=2;ell<=8;ell++) {
  const n=2**ell, mask=Math.floor((n-1)/3);
  for(const a of [0,Math.floor(n/2),n-1]) {
    let sampled=0;
    for(let t=0;t<n;t++) if(t===a && (t^mask)===(a^mask)) sampled+=1/n;
    close(sampled,1/n); correlated++;
  }
}
for(let d=1;d<=11;d++) {
  const C=0.75, A=C/(2**d), m=2**d;
  const success=1-(1-A)**m;
  assert.ok(success>=1-Math.exp(-C)-1e-13);
  repetitions++;
  const frac=1/(2**d), theta=Math.asin(Math.sqrt(frac));
  const t=Math.max(0,Math.round(Math.PI/(4*theta)-0.5));
  const grover=Math.sin((2*t+1)*theta)**2;
  assert.ok(grover>=0.5-1e-13); quantum++;
}
// Negative control: authenticated token absent from public sampler support.
assert.equal(([['public',1]]).reduce((v,[s,d])=>v+d*(s==='secret'?1:0),0),0);
console.log(JSON.stringify({run:533,status:'PASS',padded_cases:padded,randomized_cases:randomized,nonuniform_domination_cases:dominated,correlated_sampler_cases:correlated,repeat_probability_cases:repetitions,simulated_grover_identities:quantum,negative_controls:1,scope:'interface attack; no signature or QPT security implementation'},null,2));
