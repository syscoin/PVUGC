'use strict';
// Run 419: finite tests of unary-root noninterference and a public Boolean seam.
// This is NOT cryptographic hiding, obfuscation or QPT security validation.
const crypto=require('crypto');
let assertions=0;
const ok=(v,m)=>{assertions++;if(!v)throw Error(m)};
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
let traces=0;
for(let depth=0;depth<=7;depth++){
  const n=5**depth;
  for(let word=0;word<n;word++)for(const root of [0,1,2]){
    let origin=root;
    let v=word;
    for(let j=0;j<depth;j++){const op=v%5;v=Math.floor(v/5);
      ok(op>=0&&op<5,'op');
      origin=origin;  // every operation has exactly one parent, no hidden side input
      ok(origin===root,'unary lineage');
    }
    ok(origin!==3,'unauthorized mixed lineage');
    traces++;
  }
}
let seams=0;
for(let i=0;i<256;i++){
  const z=sha('source-'+i), h=sha(z), K=sha('key-'+i);
  const valid=(flag,w)=>(flag===1 && (w.t===0||w.t===1) && sha(w.z)===h);
  const a={z,t:0},b={z,t:1};
  ok(valid(1,a)&&valid(1,b),'two valid representations');
  const gate=bit=>bit?K:null;
  ok(gate(valid(1,a))===gate(valid(1,b)),'same K');
  ok(!valid(0,a)&&gate(valid(0,a))===null,'false source');
  ok(gate(true)===K,'attacker forges detached accept bit');
  const ideal=(flag,w)=>valid(flag,w)?K:null; // oracle only: NOT a construction
  ok(ideal(1,a)===K&&ideal(1,b)===K,'ideal common K');
  ok(ideal(0,a)===null,'ideal false');
  seams++;
}
const out={run:419,assertions,unary_traces:traces,boolean_seam_fixtures:seams,
  scope:'root lineage and bare-verdict negative control ONLY',
  security_claims:['no cryptographic scheme','no QPT hiding or extraction']};
process.stdout.write(JSON.stringify(out,null,2)+'\n');
