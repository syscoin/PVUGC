"use strict";
/* Run490: deterministic toy seed-adaptive matching and numerical Grover phase oracle.
   No FIPS 205 implementation, protected release, quantum circuit, or QPT security claim. */
function run490(){
  let checks=0;const ck=x=>{if(!x)throw Error("check failed "+checks);++checks;};
  function m32(x){x=(x^x>>>16)>>>0;x=Math.imul(x,0x7feb352d)>>>0;
    x=(x^x>>>15)>>>0;x=Math.imul(x,0x846ca68b)>>>0;
    return (x^x>>>16)>>>0;}
  const cases=[];
  for(const h of [4,5,6,7])for(const ctx of [0,1]){
    const N=1<<h,D=N*N,mask=N-1;
    const S=r=>m32((ctx+13)*0x1fa123 ^ Math.imul(r+41,0x9e3779b9))&mask;
    const B=r=>m32((ctx+47)*0x6549b1 ^ Math.imul(r+17,0x85ebca6b))&mask;
    const G=(s,z)=>m32((s+5)*0x123ab7 ^ Math.imul(z+61,0xc2b2ae35))&mask;
    const flags=new Uint8Array(D),perR=new Uint16Array(N);
    let marked=0,selected=null,seedVariation=false;
    for(let r=0;r<N;r++){
      if(S(r)!==S(0))seedVariation=true;
      for(let z=0;z<N;z++)if(B(r)===G(S(r),z)){
        flags[r*N+z]=1;marked++;perR[r]++;
        if(!selected)selected={r,z,seed:S(r),root:B(r)};
      }
    }
    ck(marked>0&&marked<D);ck(seedVariation);
    const missing=Array.from(perR).filter(v=>v===0).length;
    ck(missing>0);
    ck(selected.seed===S(selected.r)&&selected.root===G(selected.seed,selected.z));
    const theta=Math.asin(Math.sqrt(marked/D));
    const iterations=Math.max(0,Math.round(Math.PI/(4*theta)-0.5));
    const a=new Float64Array(D);a.fill(1/Math.sqrt(D));
    for(let k=0;k<iterations;k++){
      for(let j=0;j<D;j++)if(flags[j])a[j]=-a[j];
      let sum=0;for(let j=0;j<D;j++)sum+=a[j];
      const twiceMean=2*sum/D;
      for(let j=0;j<D;j++)a[j]=twiceMean-a[j];
    }
    let success=0,norm=0;for(let j=0;j<D;j++){
      norm+=a[j]*a[j];if(flags[j])success+=a[j]*a[j];
    }
    const formula=Math.sin((2*iterations+1)*theta)**2;
    ck(Math.abs(success-formula)<1e-9);ck(Math.abs(norm-1)<1e-9);
    ck(success>0.90);
    cases.push({root_bits:h,context:ctx,pairs:D,marked,unreachable_builder_coins:missing,
      matched_coin:selected.r,matched_signer_seed:selected.z,seed:selected.seed,root:selected.root,
      grover_iterations:iterations,simulated_success:Number(success.toFixed(12))});
  }
  return {run:490,fixtures:cases.length,assertions_passed:checks,cases,
    correction:"adaptive PK.seed copying gives h-bit root predicate; ideal Grover O(2^(h/2)), NOT generic independent full-key 2^(2h/3)",
    limitations:"toy arithmetic maps and ideal phase reflections; no FIPS 205, quantum circuit, WKEM, or 128-bit security proof"};
}
if(typeof process!=="undefined"&&process.stdout)process.stdout.write(JSON.stringify(run490(),null,2)+"\n");
