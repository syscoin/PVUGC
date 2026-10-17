"use strict";
// Run494: symbolic public-homomorphic late witness admission and flag override.
// Not encryption, obfuscation, FHE, witness encryption, or post-quantum security.
const assert = require("assert");
let checks = 0;
function eq(actual, expected) { checks++; assert.deepStrictEqual(actual,expected); }
function R(x,w) {
  const [a,b,c]=w;
  return !x.contradictory && (a^b)===x.target && c===1;
}
function Oracle() {
  const map=new Map(); let next=0;
  this.enc=(v)=>{const id=next++;map.set(id,v);return id;};
  this.eval=(f,...cs)=>this.enc(f(...cs.map(c=>map.get(c))));
  // Represents an *ideal protected* release oracle with the FHE sk.
  this.release=(cipher)=>{const [accept,k]=map.get(cipher);return accept?k:null;};
}
const cases=[];
for(let i=0;i<32;i++)for(const contradictory of [false,true]) {
  const x={utxo:"tx_"+i+":0",branch:"disprove",target:i%2,contradictory};
  const K=(19*i + (contradictory?7:2) + 13)%256;
  const fhe=new Oracle();const ck=fhe.enc(K);
  let witnessReleases=0;
  for(let a=0;a<2;a++)for(let b=0;b<2;b++)for(let c=0;c<2;c++) {
    const w=[a,b,c], cw=fhe.enc(w);
    const good=R(x,w);
    const result=fhe.eval((key,ww)=>[R(x,ww),R(x,ww)?key:0],ck,cw);
    eq(fhe.release(result),good?K:null);
    if(good)witnessReleases++;
  }
  eq(witnessReleases,contradictory?0:2);
  // One unauthorized chosen public Eval, independent of witness.
  const forged=fhe.eval(key=>[true,key],ck);
  eq(fhe.release(forged),K);
  cases.push({false_instance:contradictory,valid_witness_releases:witnessReleases,
    unauthorized_key_release:true});
}
eq(cases.length,64);
eq(cases.filter(c=>c.false_instance).length,32);
eq(cases.reduce((s,c)=>s+c.valid_witness_releases,0),64);
console.log(JSON.stringify({run:494,assertions:checks,contexts:cases.length,
  false_original_contexts:32,valid_witness_releases:64,
  public_eval_override_key_recoveries:64,
  scope:"Exact symbolic semantics only; no actual ciphertext security or PQ claim."},null,2));
