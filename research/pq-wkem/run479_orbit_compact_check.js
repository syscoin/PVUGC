"use strict";
// Run 479: deterministic finite orbit semantics, NOT encryption or native PQ signing.
function run() {
  let checks=0, releases=0, cross=0, different=0, refreshing=0;
  const check=(ok,msg)=>{checks++; if(!ok) throw Error(msg);};
  const H=(a)=>{let x=(a>>>0)^0x9e3779b9;x=Math.imul(x^(x>>>16),0x85ebca6b);x=Math.imul(x^(x>>>13),0xc2b2ae35);return (x^(x>>>16))>>>0;};
  for(let i=0;i<64;i++) {
    const secret=H(i+541), x=H(secret), cap=H(i+93173), vk=H(cap);
    const ctx=H(i+1234), j0=2+x%5, j1=j0+1, limit=12;
    const source=(s,b)=>H(s)===x&&(b===0||b===1);
    const initial=()=>({tick:0,nonce:H(ctx),cap});
    const step=(s)=>({tick:s.tick+1,nonce:H(s.nonce+11),cap:s.cap});
    const refresh=(s,r)=>({tick:s.tick,nonce:H(s.nonce^r),cap:s.cap});
    const open=(s)=>(s.tick===j0||s.tick===j1)?s.cap:null;
    function honest(s,b) {
      check(source(s,b),"valid ORIGINAL witness");
      let c=initial();for(let t=0;t<(b?j1:j0);t++)c=refresh(step(c),H(s+t));
      return [c,open(c)];
    }
    const [a,k0]=honest(secret,0),[b,k1]=honest(secret,1);
    check(k0===cap&&k1===cap,"all witness same K");
    check(a.tick!==b.tick,"different witness-dependent state");different++;
    check(!source(secret,2),"invalid bit rejected");
    let c=initial(),got=null,found=-1;
    for(let j=0;j<=limit;j++){const cand=open(c);if(cand!==null&&H(cand)===vk){got=cand;found=j;break;}if(j<limit)c=step(c);}
    check(got===cap&&found===j0,"witnessless exhaustive public orbit");releases++;
    let d=initial();for(let j=0;j<found;j++)d=refresh(step(d),H(i+j+716));
    check(open(d)===got,"ciphertext refreshing leaves semantics");refreshing++;
    check(d.nonce!==a.nonce,"different refresh coins");
    const boundMessage=(c)=>H(c^0x34ee9d09);
    check(boundMessage(ctx)!==boundMessage(H(ctx+56)),"different context");cross++;
  }
  return {run:479,status:"PASS",assertions:checks,fixtures:64,valid_original_witnesses_per_fixture:2,different_plaintext_states:different,witnessless_capability_recoveries:releases,refresh_checks:refreshing,context_separation_checks:cross,public_step_budget:12,limitations:"finite transparent semantics only; no encrypted implementation or native signing; extended local Python independently checks Ed25519"};
}
if(typeof module!=="undefined" && require.main===module) process.stdout.write(JSON.stringify(run(),null,2)+"\n");
