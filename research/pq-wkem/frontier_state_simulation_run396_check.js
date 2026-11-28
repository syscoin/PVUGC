'use strict';
// Run 396: finite conditional-interface falsifier, NOT a PQ WKEM or RIO test.
const N=8, K=17, W=[1,3,5], GOOD=new Set([0,1,2,3,5,6,7]);
let checks=0, perms=0, states=0;
function assert(x,why){checks++; if(!x)throw Error(`${checks}: ${why}`);}
function next(a){let i=a.length-2;while(i>=0&&a[i]>=a[i+1])i--;
  if(i<0)return false;let j=a.length-1;while(a[j]<=a[i])j--;
  [a[i],a[j]]=[a[j],a[i]];let l=i+1,r=a.length-1;
  while(l<r){[a[l],a[r]]=[a[r],a[l]];l++;r--;}return true;}
let p=Array.from({length:N},(_,i)=>i);
do {perms++;for(const w of W){const histogram=Array(N).fill(0);let good=0;
  for(let r=0;r<N;r++){const s=p[r]^w;histogram[s]++;good+=Number(GOOD.has(s));states++;}
  assert(histogram.every(v=>v===1),'bijective scrambling uniform');
  assert(good===GOOD.size,'honest witness release correctness rate');
}} while(next(p));
assert(perms===40320,'all 8! permutations');
assert([...Array(N).keys()].filter(s=>GOOD.has(s)).length===GOOD.size,'witness-free sampler');
let marginalChecks=0;
for(let k=0;k<N;k++){
 let tv=0, realGood=0, simGood=0;
 for(let a=0;a<N;a++)for(let b=0;b<N;b++){
   const real=Number(b===(a^k))/N, sim=1/(N*N);
   tv+=Math.abs(real-sim)/2;
   if((a^b)===k){realGood+=real;simGood+=sim;}
 }
 assert(Math.abs(tv-(1-1/N))<1e-12,'joint TV');
 assert(realGood===1,'valid correlated shares');
 assert(Math.abs(simGood-1/N)<1e-12,'independent shares fail');
 for(let bit=0;bit<2;bit++)for(let v=0;v<N;v++){
   const rm=Array.from({length:N},(_,u)=>bit===0?u===v:(u^k)===v)
     .filter(Boolean).length/N;
   assert(rm===1/N,'marginal uniform');marginalChecks++;
 }
}
console.log(JSON.stringify({run:396,status:'PASS',assertions:checks,
 reversible_three_bit_permutations:perms,valid_witness_labels:W,
 exact_honest_frontier_states_tested:states,
 honest_release_success:GOOD.size/N,witness_free_release_success:GOOD.size/N,
 two_share_joint_tv:1-1/N,two_share_real_authorization:1,
 two_share_independent_authorization:1/N,individual_marginal_checks:marginalChecks,
 proves_wkem:false,proves_rio_break:false,proves_qpt_security:false},null,2));
