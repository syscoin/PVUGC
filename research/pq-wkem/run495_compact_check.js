"use strict";
// Run 495: finite chosen-coin image + exact-Eval certificate falsifier.
// Symbolic model, not an FHE implementation or a QPT security experiment.
let assertions=0;
function chk(b){assertions++;if(!b)throw Error("Run495 assertion "+assertions);}
const rates=[];
for(let bits=2;bits<=10;bits++){
  const total=2**bits, bad=Array.from({length:total},(_,r)=>r===0).filter(Boolean).length;
  chk(bad===1);chk(bad/total===2**(-bits));
  rates.push({bits,total,bad,honest_probability:bad/total,chosen_probability:1});
}
const counts={contexts:0,false_contexts:0,valid_witness_releases:0,
             honest_false_rejections:0,chosen_coin_false_releases:0,
             exact_encryption_certificates:0,exact_evaluation_certificates:0};
for(let j=0;j<64;j++){
 const x={enabled:Boolean(j%2),target:j%4,context:"claim"+j},K="hidden-key-"+j;
 const R=w=>x.enabled && w%4===x.target;
 const Enc=(w,b,t)=>b===0?{tag:1,w}:{tag:0,w,t};
 const Eval=cw=>cw.tag===1?{accept:1,key:K,op:"force"}:
                    {accept:Number(R(cw.w)),key:R(cw.w)?K:null,op:"source"};
 const VerifyEnc=(w,b,t,cw)=>JSON.stringify(Enc(w,b,t))===JSON.stringify(cw);
 const VerifyEval=(cw,out)=>JSON.stringify(Eval(cw))===JSON.stringify(out);
 const Release=(w,b,t,cw,out)=>VerifyEnc(w,b,t,cw)&&VerifyEval(cw,out)&&out.accept===1?out.key:null;
 counts.contexts++;
 if(x.enabled){
  const W=Array.from({length:8},(_,w)=>w).filter(R);chk(W.length===2);
  for(const w of W){const cw=Enc(w,5,17),out=Eval(cw);
   chk(Release(w,5,17,cw,out)===K);counts.valid_witness_releases++;}
 }else{
  counts.false_contexts++;chk(!Array.from({length:8},(_,w)=>w).some(R));
  const cw=Enc(0,5,17),out=Eval(cw);
  chk(Release(0,5,17,cw,out)===null);counts.honest_false_rejections++;
 }
 const w=7,cw=Enc(w,0,17),out=Eval(cw);
 chk(VerifyEnc(w,0,17,cw));counts.exact_encryption_certificates++;
 chk(VerifyEval(cw,out));counts.exact_evaluation_certificates++;
 chk(Release(w,0,17,cw,out)===K);
 chk(Release(w,0,17,cw,{accept:1,key:K,op:"tampered"})===null);
 if(!x.enabled)counts.chosen_coin_false_releases++;
}
chk(counts.false_contexts===32);chk(counts.valid_witness_releases===64);
chk(counts.chosen_coin_false_releases===32);
console.log(JSON.stringify({run:495,assertions,rates,counts,
 limitations:"Symbolic, plaintext-visible finite model; no FHE, native PQ signature, WE, or QPT hardness proof."},null,2));
