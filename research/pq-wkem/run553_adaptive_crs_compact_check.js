// Run 553: exact finite semantics, not FE/SNARG/quantum cryptography.
function runCheck() {
  let assertions=0; const results=[];
  for(let n=1;n<=7;n++) {
    const N=2**n, fixed=Array(N).fill(0);
    const original=(b,z,w)=>b===0 && ((5*w+3)%N)===z;
    const verify=(sigma,b,z,pi)=>original(b,z,pi) || (b===1 && z===sigma && pi===0);
    let adaptive=0;
    for(let z=0;z<N;z++) {
      let count=0, witness=-1;
      for(let w=0;w<N;w++) if(original(0,z,w)) {count++;witness=w;}
      if(count!==1) throw Error("ORIGINAL completeness"); assertions++;
      for(let sigma=0;sigma<N;sigma++) {if(!verify(sigma,0,z,witness)) throw Error("honest proof");assertions++;}
    }
    for(let sigma=0;sigma<N;sigma++) {
      if(original(1,sigma,0)||!verify(sigma,1,sigma,0)) throw Error("adaptive attack");
      assertions+=2; adaptive++;
      for(let z=0;z<N;z++) {
        let accepting=0;
        for(let pi=0;pi<N;pi++) {
          const got=verify(sigma,1,z,pi);
          if(got !== (z===sigma && pi===0)) throw Error("false-proof pattern");
          assertions++; if(got) accepting++;
        }
        if(accepting!==Number(z===sigma)) throw Error("false soundness");
        assertions++; if(accepting) fixed[z]++;
      }
    }
    for(const v of fixed) {if(v!==1) throw Error("fixed-instance count");assertions++;}
    let shared=[];
    for(let q=1;q<=Math.min(N,5);q++) {
      let hits=0;
      for(let sigma=0;sigma<N;sigma++)
        if(Array.from({length:q},(_,z)=>z).some(z=>verify(sigma,1,z,0))) hits++;
      if(hits!==q) throw Error("precommitted multi-claim"); assertions++;
      shared.push([q,hits,N]);
    }
    if(adaptive!==N) throw Error("adaptive count");assertions++;
    results.push({n,parameters:N,fixed_false_error:"1/"+N,adaptive_false_success:N+"/"+N,precommitted_shared_crs:shared});
  }
  return {run:553,claims:"finite exact semantics only; no protected release or QPT implementation",assertions,results};
}
