'use strict';
// Restricted public-unary-control negative control; no cryptographic security claim.
const assert = require('node:assert/strict');
let checks = 0;
const ck = (v,msg) => { assert.ok(v,msg); checks++; };
const mask=(1n<<64n)-1n;
const step = z => (z*6364136223846793005n+1442695040888963407n)&mask;
const fixtures=[];
for (const T of [31,255,4095]) for(const x of [0,3,5,7]) {
  const init=1n+BigInt(73*x+T), K=`SAME-CAPABILITY-${T}-${x}`;
  const valid=t=>t>=T-24&&t<=T&&t%8===x%8;
  const allowed=new Set(); let z=init;
  for(let t=0;t<=T;t++){if(valid(t)) allowed.add(z.toString());z=step(z);}
  const release=z=>allowed.has(z.toString())?K:null;
  const witnesses=Array.from({length:T+1},(_,i)=>i).filter(valid);
  ck(witnesses.length>=3,'insufficient valid witnesses');
  const states=[];
  for (const w of [witnesses[0],witnesses[1],witnesses.at(-1)]){
    let s=init;for(let t=0;t<w;t++)s=step(s);
    states.push(s.toString());ck(release(s)===K,'honest common release failed');
  }
  ck(new Set(states).size===3,'distinct witness-dependent states collapsed');
  let accepted=null,calls=0;z=init;
  for(let t=0;t<=T;t++){const candidate=release(z);calls++;
    if(candidate===K){accepted=t;break;}z=step(z);
  }
  ck(accepted===witnesses[0],'witness-free enumeration failed');
  ck(calls<=T+1,'excessive public actions');
  fixtures.push({T,x,valid_witness_count:witnesses.length,first_accepted_schedule:accepted,public_actions_used:calls});
}
process.stdout.write(JSON.stringify({run:444,scope:'finite public-unary control cover; not WKEM',assertions:checks,fixtures})+'\n');
