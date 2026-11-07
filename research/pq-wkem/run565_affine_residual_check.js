'use strict';
// Run 565, deterministic finite demonstration. NOT a real encryption/KEM/PQ test.
function mod(a,q){return ((a%q)+q)%q;}
function inv(a,q){a=mod(a,q);for(let z=1;z<q;z++)if(mod(a*z,q)===1)return z;throw new Error('not invertible');}
function check(){
  let assertions=0, trueCases=0, falseCases=0, honestCases=0;
  const specs=[[3,17],[4,37],[5,67],[6,131],[7,257],[8,521]];
  for(const [n,q] of specs){const N=2**n;
    for(const a of [1,3,5])for(const b of [0,1,N/2]){
      const f=w=>mod(a*w+b,N);
      for(let y=0;y<N;y++){
        const ws=[];for(let w=0;w<N&&ws.length<2;w++)if(f(w)!==y)ws.push(w);
        if(ws.length!==2)throw Error('not enough invalid witnesses');
        const [w1,w2]=ws,r1=mod(f(w1)-y,q),r2=mod(f(w2)-y,q);
        if(!(r1!==0 && r2!==0 && r1!==r2))throw Error('incorrect residuals');assertions++;
        const alpha=mod(r2*inv(mod(r2-r1,q),q),q),beta=mod(1-alpha,q);
        if(mod(alpha+beta,q)!==1)throw Error('nonaffine');assertions++;
        if(mod(alpha*r1+beta*r2,q)!==0)throw Error('interpolation failed');assertions++;
        const u=Array.from({length:N},(_,w)=>w).find(w=>f(w)===y);
        if(u===undefined || mod(f(u)-y,q)!==0)throw Error('source correctness');assertions++;honestCases++;
        for(const K of [0,1,7,q-1])for(const ctx of [2,5]){
          // The ciphertexts are symbolic field triples (K,residual,context).
          const c1=[K,r1,ctx],c2=[K,r2,ctx];
          const mixed=c1.map((v,i)=>mod(alpha*v+beta*c2[i],q));
          if(mixed[0]!==K || mixed[1]!==0 || mixed[2]!==ctx)throw Error('early release');assertions++;
          if(f(w1)===y||f(w2)===y)throw Error('attacker had witness');assertions++;
          trueCases++;
          // Deliberately false b=0 relation uses residual 1 for all witnesses.
          const falseMix=mod(alpha*1+beta*1,q);
          if(falseMix!==1)throw Error('unexpected false branch release');assertions++;falseCases++;
        }
      }
    }
  }
  return {run:565,status:'PASS',assertions_passed:assertions,
    true_instance_early_release_fixtures:trueCases,
    false_instance_nonrelease_fixtures:falseCases,
    genuine_source_correctness_fixtures:honestCases,
    checked:'affine ciphertext-state closure yields zero residual from two public invalid-witness evaluations',
    implementation:'symbolic field triples, not encrypted ciphertexts',
    original_witness_extracted:false, qpt_security_proved:false,
    source_one_way_permutation_instantiated:false};
}
console.log(JSON.stringify(check(),null,2));
