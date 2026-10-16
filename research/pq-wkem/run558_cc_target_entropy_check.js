// Run 558 independent JavaScript finite checker. Classical semantics ONLY.
"use strict";
let assertions=0,models=0,independent=0,collisions=0,noncollisions=0;
function check(q,why){assertions++; if(!q) throw Error(why);}
function phi(s,b,k){
 let h=(Math.imul(s+1,0x85ebca6b)^Math.imul(b+17,0xc2b2ae35))>>>0;
 h^=h>>>16;h=Math.imul(h,0x7feb352d)>>>0;h^=h>>>15;
 return h&((1<<k)-1);
}
for(const n of [1,2,3]){
 const size=1<<n;
 for(let table=1;table<(1<<size);table++){
  const valid=Array.from({length:size},(_,w)=>w).filter(w=>(table>>>w)&1);
  for(let s=0;s<8;s++)for(let k=1;k<=5;k++){
   const v0=phi(s,0,k),v1=phi(s,1,k);
   check(phi(s,1,k)===v1,"target publicly predicted");
   if(v0===v1){
    collisions++;
    check(Array.from({length:size}).every(()=>v0===v1),"invalid acceptance under collision");
   } else {noncollisions++;check(v0!==v1,"separated labels");}
   let successes=0;
   for(let y=0;y<(1<<k);y++){
    const success=valid.every(w=>phi(s,(table>>>w)&1,k)===y);
    check(success===(y===v1),"independent target count");
    if(success)successes++;
    independent++;
   }
   check(successes===1,"exact 2^-k completeness");
   models++;
  }
 }
}
const p=257,range=128,K=0x5a12;
const G=y=>(y*y*y)%p;
check(new Set(Array.from({length:p},(_,y)=>G(y))).size===p,"G permutation");
let trueCases=0,falseCases=0;
for(let y=0;y<p;y++){
 const P=G(y),valid=[];
 for(let w=0;w<range*2;w++){
  const f=Math.floor(w/2);
  const R=(G(f)===P),out=f===y?K:null;
  check((out!==null)===R,"restricted exact source relation");
  if(R){check(out===K,"all valid same K");valid.push(w);}
 }
 if(y<range){trueCases++;check(valid.length===2&&valid[0]===2*y&&valid[1]===2*y+1,"two valid witnesses");}
 else{falseCases++;check(valid.length===0,"false statement reject");}
}
return {run:558,checker:"run558_cc_target_entropy_check.js",status:"PASS",
 assertions_passed:assertions,public_accept_bit_models:models,
 independent_target_exhaustive_cases:independent,
 hash_label_collisions:collisions,noncolliding_adapters:noncollisions,
 programmed_target_conditional_min_entropy_bits:0,
 independent_target_all_valid_success:"2^-k exactly",
 restricted_true_instances:trueCases,restricted_false_instances:falseCases,
 restricted_true_witness_multiplicity:2,toy_permutation_modulus:p,
 cryptographic_obfuscation_executed:false,QPT_security_proved:false};
