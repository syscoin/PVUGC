// Run 556 compact independent checker; exact source intended for GitHub.
"use strict";
function run556() {
  let assertions = 0, cases = 0, recovered = 0, maxSamples = 0;
  const assert = (ok, why) => { assertions++; if (!ok) throw Error(why); };
  const parity = x => { let b=0; while(x){b ^= x&1; x >>>= 1;} return b; };
  const rank = (v, width) => {
    const basis=Array(width).fill(0); let r=0;
    for(let z of v) while(z) {
      const i=31-Math.clz32(z);
      if(basis[i]) z ^= basis[i];
      else { basis[i]=z; r++; break; }
    }
    return r;
  };
  let rng=0x5567567;
  function rand() {rng=(Math.imul(rng,1664525)+1013904223)>>>0; return rng;}
  for(let n=2;n<=6;n++){
    const size=1<<n, N=2*size;
    const P=Array.from({length:size}, (_,i)=>i);
    for(let i=size-1;i>0;i--){const j=rand()%(i+1);[P[i],P[j]]=[P[j],P[i]];}
    const deltas=n<=4?Array.from({length:size-1},(_,i)=>i+1):[1,3,size-1];
    for(const delta of deltas) {
      cases++;
      const sigma=size|delta;
      const F=q=>P[(q&(size-1)) ^ ((q&size)?delta:0)];
      const outputs=new Map();
      for(let q=0;q<N;q++){const v=F(q);if(!outputs.has(v))outputs.set(v,[]);outputs.get(v).push(q);}
      assert(outputs.size===size,"range");
      for(const pre of outputs.values()){
        assert(pre.length===2 && (pre[0]^pre[1])===sigma,"two-to-one period");
      }
      const span=[];
      let squareSum=0;
      for(let y=0;y<N;y++){
        const a=1+(parity(sigma&y)?-1:1);
        const squared=a*a;
        squareSum+=squared;
        assert(squared === (parity(sigma&y)?0:4), "Fourier numerator");
        if(squared)span.push(y);
      }
      assert(squareSum===2*N && span.length===size,"Fourier normalization");
      assert(rank(span,n+1)===n,"orthogonal hyperplane rank");
      for(let trial=0;trial<5;trial++){
        const eq=[];let draws=0;
        while(rank(eq,n+1)<n && draws<20*(n+1)){
          eq.push(span[rand()%span.length]);draws++;
        }
        maxSamples=Math.max(maxSamples,draws);
        const kernel=[];
        for(let z=1;z<N;z++)if(eq.every(y=>!parity(y&z)))kernel.push(z);
        assert(kernel.length===1 && kernel[0]===sigma,"Simon's recovered period");
        assert((kernel[0]& (size-1))===delta,"recovered shift");
        recovered++;
      }
      if(n<=4){
        for(let u=0;u<N;u++)for(let v=0;v<N;v++)
          assert((F(u)===F(v)) === (u===v || (u^v)===sigma),"full promise iff");
      }
    }
  }
  return {run:556, checker:"run556_forward_shift_check.js", assertions_passed:assertions,
    parameter_shift_configurations:cases, simulated_simon_recovery_trials:recovered,
    max_fourier_samples_in_toy_trials:maxSamples,
    claim:"Finite Simon Fourier/gauge identity, not quantum hardware or QPT security proof"};
}
if(typeof console !== "undefined") console.log(JSON.stringify(run556(),null,2));
