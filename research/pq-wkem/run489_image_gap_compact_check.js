"use strict";
// Run 489 compact executed finite checker. This is not native SLH-DSA or QPT code.
function main(){
let checks=0;const ck=(v)=>{if(!v)throw Error("failed");checks++};
const exact=[];
for(const N of [2,4]){
 let count=0,sum=0;
 for(let code=0;code<N**N;code++){
  let t=code;const a=Array(N).fill(0);
  for(let z=0;z<N;z++){a[t%N]++;t=Math.floor(t/N)}
  const absent=a.filter(v=>v===0).length;
  ck(a.reduce((q,v)=>q+Math.abs(v-1),0)===2*absent);
  sum+=absent;count++;
 }
 ck(sum*N**N===(N-1)**N*N*count);
 exact.push({N,maps:count,missing_sum:sum,
    expected_absent_numerator:(N-1)**N,expected_absent_denominator:N**N});
}
const f=[0,0,2,2];
ck(!f.includes(1));
ck(f[3]===2&&f.includes(f[3]));
const p=(1-1/65536)**65536;
ck(Math.abs(p-Math.exp(-1))<0.00001);
return {run:489,assertions_passed:checks,exact,explicit_unreachable_root:1,
retained_builder_seed:3,retained_seed_root:2,ideal_absent_probability_16bit:p,
limits:"toy finite and ideal-model only, not SLH-DSA, quantum attack or WKEM"};
}
const output=JSON.stringify(main(),null,2)+"\n";
if(typeof process!=="undefined"&&process.stdout)process.stdout.write(output);
