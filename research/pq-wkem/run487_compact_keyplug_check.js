'use strict';
const check = function check(){
  function f(x){return (((x^0x5a)*73)+19)&255}
  const inv=Array(256).fill(-1);
  for(let i=0;i<256;i++){if(inv[f(i)]!==-1)throw Error("not permutation");inv[f(i)]=i}
  let state=0x48701234, assertions=256, accepted=0;
  function rnd(){state^=state<<13;state^=state>>>17;state^=state<<5;return state>>>0}
  for(let j=0;j<128;j++){
    const secret=Array.from({length:8},()=>rnd()&255);
    const vk=secret.map(f), capsule={context:"relation|utxo-"+j+"|disprove",vk:[...vk]};
    if("secret" in capsule)throw Error("builder retained key");assertions++;
    const open=w=>w.valid?capsule.vk.map(t=>inv[t]):null;
    const k0=open({valid:true,tag:0}), k1=open({valid:true,tag:1});
    if(k0.some((v,i)=>v!==secret[i])||k1.some((v,i)=>v!==secret[i]))throw Error("key mismatch");
    assertions+=2;
    if(open({valid:false})!==null)throw Error("false source admitted");
    assertions++;
    for(let m=0;m<16;m++){
      const signature=Array.from({length:4},(_,i)=>k0[2*i+((m>>>i)&1)]);
      const verify=(p)=>signature.every((v,i)=>f(v)===p[2*i+((m>>>i)&1)]);
      if(!verify(vk))throw Error("native signature rejected"); assertions++;
      const wrong=[...vk];wrong[m&1]^=1;
      if(verify(wrong))throw Error("tampered checking key accepted"); assertions++;
      accepted++;
    }
  }
  return {run:487,assertions,contexts:128,valid_source_witnesses_per_context:2,accepted_toy_native_signatures:accepted,scope:"insecure finite permutation only; does not establish QPT or concrete security"};
};
console.log(JSON.stringify(check(),null,2));
