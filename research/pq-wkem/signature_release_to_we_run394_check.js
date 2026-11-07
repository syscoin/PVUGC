'use strict';
// Run 394. Small exact classical finite distributions for the QROM reduction.
// Does NOT simulate arbitrary quantum queries or prove quantum security.
let checks=0;
function check(x,m){checks++;if(!x)throw Error(`assertion ${checks}: ${m}`)}
const N=8, j=0;
let winsReal=0,winsIdeal=0,sourceHits=0,total=0;
for(let sigma=0;sigma<N;sigma++){
  const freq=new Uint16Array(1<<N);
  for(let h=0;h<(1<<N);h++)for(let u=0;u<2;u++){
    const h1=(h&~(1<<sigma))|(u<<sigma);
    freq[h1]++;
    for(let bit=0;bit<2;bit++){
      const c=bit^u;
      const realGuess=c^((h1>>j)&1);
      const idealGuess=c^((h>>j)&1);
      winsReal+=(realGuess===bit);
      winsIdeal+=(idealGuess===bit);
      sourceHits+=(sigma===j);
      total++;
    }
  }
  check(freq.every(f=>f===2),'H1 uniform after reprogramming at unknown fixed point');
}
check(total===N*(1<<N)*2*2,'distribution exhaustive');
const pReal=winsReal/total,pIdeal=winsIdeal/total,pExtract=sourceHits/total;
check(pReal===0.5625,'one-query real success');
check(pIdeal===0.5,'one-query ideal success');
check(pExtract===1/N,'ideal-world query gives signing token with prob 1/N');
const advantage=pReal-pIdeal;
check(pExtract>=advantage*advantage/4,'q=1 O2H extraction inequality');
// Shared signature-index/RO input is not an IND-CPA-safe joint capsule.
let reused=0;
for(let pad=0;pad<2;pad++)for(let a=0;a<2;a++)for(let b=0;b<2;b++){
  const c0=a^pad,c1=b^pad;
  check((c0^c1)===(a^b),'reused pad exposes message xor');
  reused++;
}
// Independent domain tags give independent ideal pads for two capsules.
let counts=[0,0];
for(let u0=0;u0<2;u0++)for(let u1=0;u1<2;u1++){
  counts[u0^u1]++;
}
check(counts[0]===counts[1]&&counts[0]===2,'distinct tags remove this xor leak');
console.log(JSON.stringify({run:394,status:'PASS',checks,oracle_inputs:N,
  fully_enumerated_cases:total,real_success:pReal,ideal_success:pIdeal,
  advantage,pMeasuredSignature:pExtract,
  predicted_lower_bound:advantage*advantage/4,
  repeated_pad_cases:reused,
  domain_separated_xor_counts:counts,
  quantum_oracle_simulated:false,
  classical_exact_distributions:true,
  generic_WKEM_constructed:false,
  finding:'The QROM O2H reduction is consistent with exact toy coupling; shared pad reuse exposes a two-capsule xor.'
},null,2));
