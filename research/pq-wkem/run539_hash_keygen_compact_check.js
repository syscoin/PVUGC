'use strict';
// Run 539: toy hash-to-keygen query experiments, not native signature security.
let seed=5392026;
function rand(){seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed;}
function assert(x){if(!x)throw Error('assertion failed');}
let known=0, guesses=0, collision=0;
for(let i=0;i<256;i++){
  let sk=rand()>>>16, pk=rand()>>>16;
  let builderQueries=new Map([[sk,pk]]);
  assert(builderQueries.get(sk)===pk);known++;
}
for(let t=0;t<50000;t++){
  let pk=rand()>>>22, hit=false;
  for(let j=0;j<4;j++)if((rand()>>>22)===pk)hit=true;
  if(hit)guesses++;
}
for(let t=0;t<192;t++){
  let table=[];for(let j=0;j<64;j++)table.push(rand()>>>20);
  let idx=rand()>>>26;
  for(let j=0;j<64;j++)if(j!==idx&&table[j]===table[idx]){collision++;break;}
}
const result={run:539,model:'toy classical random oracle key mapping',retained_builder_queries:known,fresh_query_trials:50000,fresh_queries_per_trial:4,fresh_query_hits:guesses,per_trial_theorem_upper_bound:5/1024,preimage_relation_trials:192,nonunique_preimage_images:collision,all_assertions_passed:true,native_signatures:false,qpt_security:false};
console.log(JSON.stringify(result,null,2));
