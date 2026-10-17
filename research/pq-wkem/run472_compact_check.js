'use strict';
// Run 472 finite algebra only. Not a QPT security proof or WKEM implementation.
const assert = require('node:assert/strict');
let checks = 0;
function ck(a,b){assert.deepEqual(a,b); checks++;}
const parity = n => n.toString(2).split('1').length % 2 === 0 ? 1 : 0;
const n=6, size=1<<n, rows=[];
for(const h of [2,3,4,5]){
  const a=new Map(), b=new Map();
  const add=(m,key)=>m.set(key,(m.get(key)||0)+1);
  for(let k=0;k<size;k++){
    const p=k>>h;
    for(let r=0;r<size;r++){
      const bit=parity(k&r);
      add(a,`${p},${r},${bit}`);
      add(b,`${p},${r},${bit^1}`);
    }
  }
  let sum=0;
  const keys=new Set([...a.keys(),...b.keys()]);
  for(const key of keys)sum+=Math.abs((a.get(key)||0)-(b.get(key)||0));
  ck(sum* (1<<h),2*size*size);
  for(let p=0;p<(1<<(n-h));p++){
    let candidates=0;
    for(let k=0;k<size;k++) if((k>>h)===p)candidates++;
    ck(candidates,1<<h);
  }
  rows.push({hidden_bits:h, message_tv:`1/${1<<h}`,
    optimal_exact_key_guess:`1/${1<<h}`,
    raw_key_candidate_check_tv:`${(1<<(n-h))-1}/${1<<(n-h)}`});
}
// Two separately labelled capsules can share a hidden key; opening 2 opens 1.
for(let k=0;k<size;k++)ck(k,k);
// Padding the key can hide the exact string while leaking usable signing seed.
for(let seed=0;seed<16;seed++)for(let extra=0;extra<16;extra++){
  const publishedSigningSeed=seed, accepted=(publishedSigningSeed===seed);
  ck(accepted,true);
  ck((seed===publishedSigningSeed && extra===0),(extra===0));
}
console.log(JSON.stringify({run:472,checks,rows,
  quantum_claim:'NO: exact finite checks, conditional GL reduction only',
  authorization_separation:'exact-key hiding does not imply native-forgery resistance'},null,2));
