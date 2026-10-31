"use strict";
function parity(x){let z=0;while(x){z^=x&1;x>>>=1;}return z;}
function run(){
 let assertions=0,cases=[],identities=0;
 for(let n=2;n<=8;n++){
  let predOK=0,msgOK=0,total=0;
  for(let k=0;k<(1<<n);k++){
   for(let r=0;r<(1<<n);r++){
    const truth=parity(k&r),guess=parity(((k>>1)<<1)&r);
    predOK+=(guess===truth);
    for(let b=0;b<2;b++){
     const c=b^truth;
     msgOK+=((c^guess)===b);
     if((c^truth)!==b)throw Error("correctness");
     assertions++;total++;
    }
   }
  }
  if(4*predOK!==3*(total/2)||4*msgOK!==3*total)throw Error("rate");
  assertions+=2;cases.push({n,bit_predictions:predOK+"/"+(total/2),message_success:msgOK+"/"+total});
 }
 for(const n of [2,3,4]){
  const N=1<<n,V=N>>1;let state=0x574+31*n;
  for(let j=0;j<256;j++){
   const t=new Uint8Array(V*N*2);
   for(let a=0;a<t.length;a++){state=(Math.imul(state,1664525)+1013904223)>>>0;t[a]=(state>>>27)&1;}
   const D=(v,r,c)=>t[(v*N+r)*2+c];
   let dOK=0,pOK=0;
   for(let k=0;k<N;k++)for(let r=0;r<N;r++){
    let z=parity(k&r),v=k>>1;
    for(let b=0;b<2;b++)dOK+=(D(v,r,b^z)===b);
    for(let u=0;u<2;u++)pOK+=((u^D(v,r,u))===z);
   }
   if(dOK!==pOK)throw Error("predictor identity");
   identities++;assertions++;
  }
 }
 return {run:574,assertions_passed:assertions,independent_fixed_distinguisher_identities:identities,enumerated_n:cases,scope:"finite algebra only; no WE, WKEM, quantum implementation",qpt_security_established:false};
}
