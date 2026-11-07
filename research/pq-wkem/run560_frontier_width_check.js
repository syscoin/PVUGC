'use strict';
// Run 560 exact executed finite checker; no external packages.
// Algebra and state-vector identities only, NOT cryptographic security.
const checkRun560 = function checkRun560() {
  let assertions=0,fixtures=0,examined=0,groverComparisons=0;
  const ok=(v,label)=>{if(!v) throw Error("Run560 checker failure: "+label);assertions++;};
  const near=(a,b)=>Math.abs(a-b)<3e-10;
  for(const ell of [3,4,5,6,7,8]){
    for(const rho of [0,1,2]){
      const n=2**ell, coins=2**rho;
      for(const D of [1,2,4]){
        if(D>=n)continue;
        for(const goodCoins of [...new Set([coins,Math.max(1,coins-1)])]){
          const N=n*coins,M=D*goodCoins;
          let actual=0; const selected=[];
          const K=271828+ell*1000+rho*100+D*10+goodCoins;
          const vk=(((K^0xa5a5a5)>>>0)*17)>>>0;
          function accepts(s,r){
            const credential=(s<D&&r<goodCoins)?K:null;
            return credential!==null && (((credential^0xa5a5a5)>>>0)*17>>>0)===vk;
          }
          for(let i=0;i<N;i++){
            const s=Math.floor(i/coins),r=i%coins;
            const yes=accepts(s,r);
            ok(yes===(s<D&&r<goodCoins),"exact public check");
            if(yes){actual++;selected.push(i);}
            examined++;
          }
          ok(actual===M,"marked-pair count");
          ok(near(M/N,(D/n)*(goodCoins/coins)),"explicit random-coin cancellation");
          const q=5;
          ok(near(1-(1-M/N)**q,1-(1-(D/n)*(goodCoins/coins))**q),"classical trial formula");
          if(ell<=6&&rho<=1){
            const theta=Math.asin(Math.sqrt(M/N));
            const marked=new Set(selected);
            const a=new Float64Array(N).fill(1/Math.sqrt(N));
            for(let j=0;j<5;j++){
              let measured=0;
              for(const i of selected)measured+=a[i]*a[i];
              ok(near(measured,Math.sin((2*j+1)*theta)**2),"Grover formula vs coherent amplitudes");
              groverComparisons++;
              for(const i of marked)a[i]=-a[i];
              let mean=0; for(const v of a)mean+=v;mean/=N;
              let norm=0;
              for(let i=0;i<N;i++){a[i]=2*mean-a[i];norm+=a[i]*a[i];}
              ok(near(norm,1),"Grover unitarity");
            }
          }
          fixtures++;
        }
      }
    }
  }
  const examples=[{ell:128,dBits:0},{ell:256,dBits:0},{ell:256,dBits:64},{ell:320,dBits:64}].map(
    e=>({...e,idealQuantumQueryExponent:(e.ell-e.dBits)/2}));
  for(const e of examples)ok(e.idealQuantumQueryExponent*2===e.ell-e.dBits,"exponent");
  return {run:560,status:"PASS",assertions_passed:assertions,finite_fixtures:fixtures,
    state_coin_pairs_checked:examined,direct_grover_amplitude_matches:groverComparisons,
    ideal_quantum_query_formula:"O(sqrt(2^ell/(D*p)))",
    public_coin_bits_cancel:true,practical_QPT_security_proved:false,
    actual_quantum_hardware:false,native_SLH_DSA_tested:false,examples};
};
console.log(JSON.stringify(checkRun560(),null,2));
