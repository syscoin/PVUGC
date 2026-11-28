'use strict';
// Exact finite arithmetic and algebraic asymptotic bound for XNAR.
// No cryptographic-security experiment or native signature simulation.
const assert = require('node:assert/strict');
const N=6, E=2, q=65537, b=11, g=Math.floor(q/(2**b));
const z=[0,1,1,-1,0,1];
const p=z.flatMap(v=>[1-v,v]);
let checks=0;
function check(ok,msg){assert.ok(ok,msg);checks++;}
check(p.reduce((s,v)=>s+Math.abs(v),0)===N+2,'L1');
check(p.reduce((s,v)=>s+v*v,0)===N+4,'L2');
check(g===32 && g>2*E*(N+1),'honest gap');
let dist=new Map([[0,1n]]);
for(const a of [1,...p.map(x=>-x)]){
  const next=new Map();
  for(const [sum,count] of dist) for(let e=-E;e<=E;e++){
    const key=sum+a*e;next.set(key,(next.get(key)||0n)+count);
  }
  dist=next;
}
const total=5n**13n;
check([...dist.values()].reduce((s,v)=>s+v,0n)===total,'distribution mass');
let exact={};
for(const gap of [29,31,32,33,35,37,256]){
  let good=0n;for(const [noise,count] of dist)if(2*Math.abs(noise)<gap)good+=count;
  check(good<=total,'bounded probability');
  exact[String(gap)]={success_numerator:String(good),denominator:String(total),success: Number(good)/Number(total)};
}
const per=exact['32'].success;
check(Math.abs(per-0.99981056)<1e-14,'exact channel');
const trials={};
for(const c of [2,8]){const count=c*Math.ceil(512/b);trials[String(c)]={ciphertexts:count,all_correct_lower_bound:per**count};}
const bounds=[];
for(const n of [6,64,128,256,512,1024]){
  const T=n**3*Math.ceil(512/b);
  const log2=(Math.log(2*T)-(n+1)**2/(2*(n+5)))/Math.LN2;
  bounds.push({N:n,ciphertexts:T,log2_union_failure_upper_bound:log2});
  check(T>0,'positive budget');
}
check(bounds[bounds.length-1].log2_union_failure_upper_bound < -600,'asymptotic failure negligible');
console.log(JSON.stringify({run:'XNAR-2026-11-01-T05',status:'FAILED_REPAIR',
 fixture:{q,b,g,E,N,p,false_l1:N+2,false_l2_squared:N+4},
 exact_false_noise_channel:exact,capsule_xor_correct_recovery_lower_bounds:trials,
 asymptotic_polynomial_repetition:bounds,assertions:checks,
 limits:'Finite error algebra and a Hoeffding union bound only; never claim QPT or native Bitcoin security.'},null,2));
