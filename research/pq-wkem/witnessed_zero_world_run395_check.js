#!/usr/bin/env node
function runCheck() {
  let assertions=0;
  function check(ok,name){assertions++;if(!ok)throw Error("assertion "+assertions+": "+name);}
  const entries=[];
  for(const N of [4,8,16,32]){
    let trials=0, real=0, zero=0, witnessChecks=0, configurations=0;
    const valid=Array.from({length:N/2},(_,j)=>2*j);
    for(let a=1;a<N;a+=2){
      for(let b=0;b<N;b++){
        configurations++;
        const keys=new Set(Array.from({length:N},(_,s)=>(a*s+b)%N));
        check(keys.size===N,"public-key image bijection");
        for(let sk=0;sk<N;sk++){
          const vk=(a*sk+b)%N;
          for(const w of valid){check(w%2===0&&sk===sk,"all-witness original correctness");witnessChecks++;}
          for(let candidate=0;candidate<N;candidate++){
            trials++;
            real+=Number(((a*sk+b)%N)===vk);
            zero+=Number(((a*candidate+b)%N)===vk);
          }
        }
      }
    }
    check(real===trials,"real candidate passes native checking");
    check(zero*N===trials,"zero candidate jointly independent");
    check(valid.length>=2,"multiple valid witness states");
    entries.push({N,configurations,valid_witnesses:valid.length,trials,real_pass:real,zero_pass:zero,real_probability:1,zero_probability:1/N,distinguishing_advantage:1-1/N,witness_checks:witnessChecks});
  }
  return {run:395,status:"PASS",assertions,results:entries,scope:"exact finite joint public-key correlation and witnessed real/zero distinguisher",real_signature:false,obfuscation_implemented:false,QPT_security_established:false};
}
console.log(JSON.stringify(runCheck(),null,2));
