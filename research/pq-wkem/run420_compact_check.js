'use strict';
// Run 420. Pure finite FE-key description separation, NOT an FE implementation.
const assert=require('assert').strict;
let checks=0, pairs=0, sameKey=0, transcripts=0;
function ok(v){assert(v);checks++;}
function R(enabled,w){return Boolean(enabled)&&(w===0||w===3);}
function F(desc,w){return R(desc.enabled,w)?desc.K:null;}
function wrap(sk,desc){return {opaque:sk,description:desc};}
for(let i=0;i<16;i++){
  const a={relation:'two-witness',enabled:false,K:'keyA-'+i};
  const b={relation:'two-witness',enabled:false,K:'keyB-'+i};
  ok(a.K!==b.K);
  for(let w=0;w<256;w++)ok(F(a,w)===null&&F(b,w)===null);
  pairs++;
  const published=wrap('opaque-'+i,a);
  ok(published.description.K===a.K); // false-instance leak without a witness
  const yes={...a,enabled:true};
  ok(F(yes,0)===F(yes,3)&&F(yes,3)===a.K);
  for(let w=0;w<256;w++)ok((F(yes,w)===a.K)===R(true,w));
  sameKey++;
  for(let bit=0;bit<2;bit++)for(let count=1;count<=3;count++){
    const descriptions=Array.from({length:count},(_,j)=>({c:j,K:'k'+i+'-'+j}));
    const original=Array.from({length:count},(_,j)=>'opaque-base-'+i+'-'+bit+'-'+j);
    const direct=original.map((sk,j)=>wrap(sk,descriptions[j]));
    const simulated=original.map((sk,j)=>({opaque:sk,description:descriptions[j]}));
    ok(JSON.stringify(direct)===JSON.stringify(simulated));
    transcripts++;
  }
}
console.log(JSON.stringify({run:420,assertions:checks,equivalent_false_pairs:pairs,all_witness_fixtures:sameKey,exact_transcript_simulations:transcripts,real_FE:false,practical_WKEM:false}));
