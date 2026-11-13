'use strict';
// Run 564. Ideal-handle symbolic FHE model. Not real encryption or a cryptographic proof.
const assert = require('assert');
let assertions=0, falseBypasses=0, trueWitnesses=0, replayBypasses=0;
class IdealHomomorphicWorld {
  constructor(){this.vault=new Map();this.next=0;}
  hide(state){const id=++this.next;this.vault.set(id,structuredClone(state));return id;}
  // Represents prescribed controlled evaluation with public ORIGINAL input.
  join(c,w){const a=this.vault.get(c);const valid=a.x.kind===1 && w.u===a.x.target;
    return this.hide({...a,ok:Number(valid),tag:w.tag});}
  // Represents UNRESTRICTED public Eval: setting a plaintext register to one.
  overwrite(c){const a=this.vault.get(c);return this.hide({...a,ok:1});}
  // Represents unrestricted cross-ciphertext ciphertext operations.
  splice(c,other){const a=this.vault.get(c),b=this.vault.get(other);
    return this.hide({...a,ok:b.ok});}
  // Ideal protected release: the only plaintext decryption available.
  release(c,scope){const a=this.vault.get(c);return a.ok===1 && a.x.id===scope ? a.K:null;}
}
for(let kind=0;kind<=1;kind++)for(let target=0;target<9;target++)
for(let key=0;key<64;key++){
  const world=new IdealHomomorphicWorld();
  const x={id:`U${kind}:${target}`,kind,target};
  const c=world.hide({K:key,x,ok:0,tag:null});
  assert.strictEqual(world.release(c,x.id),null);assertions++;
  for(let u=0;u<9;u++)for(let tag=0;tag<2;tag++){
    const joined=world.join(c,{u,tag});
    const expected=kind===1 && u===target ? key:null;
    assert.strictEqual(world.release(joined,x.id),expected);assertions++;
    if(expected!==null){trueWitnesses++;assert.strictEqual(world.vault.get(joined).tag,tag);assertions++;}
  }
  if(kind===0){
    const forged=world.overwrite(c);
    assert.strictEqual(world.release(forged,x.id),key);assertions++;falseBypasses++;
    const y={id:`V:${target}`,kind:1,target};
    const c2=world.hide({K:key^7,x:y,ok:0,tag:null});
    const permitted=world.join(c2,{u:target,tag:1});
    assert.strictEqual(world.release(permitted,y.id),key^7);assertions++;
    const spliced=world.splice(c,permitted);
    assert.strictEqual(world.release(spliced,x.id),key);assertions++;replayBypasses++;
    assert.strictEqual(world.release(spliced,y.id),null);assertions++;
  }
}
assert.strictEqual(falseBypasses,576);assert.strictEqual(trueWitnesses,1152);
assert.strictEqual(replayBypasses,576);assertions+=3;
console.log(JSON.stringify({run:564,status:'PASS',assertions_passed:assertions,
  false_statement_overwrite_bypasses:falseBypasses,
  cross_capsule_splice_bypasses:replayBypasses,
  all_valid_two_witness_recoveries:trueWitnesses,
  symbolic_handle_model_not_real_FHE:true,QPT_security_proved:false},null,2));
