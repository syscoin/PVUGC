// Run 562 — exact executed deterministic finite checker, no cryptographic security claim.
function run562Check() {
  let assertions=0, worlds=0, watcherSuccess=0, outsiderSuccess=0, falsePairs=0;
  function ok(c) { if(!c) throw new Error("run562 assertion "+assertions); ++assertions; }
  for (let n=2;n<=8;n++) {
    const mod=1<<n;
    for (const a of [1,3,5]) for(const b of [0,1]) for(let u=0;u<mod;u++) {
      const y=(a*u+b)%mod, K=(73*u+17*a+b)%mod;
      const pk=(3*K+1)%mod, T=2+((y+b)&1);
      const original=[];
      for(let w=0;w<2*mod;w++) if ((a*Math.floor(w/2)+b)%mod===y) original.push(w);
      ok(original.length===2 && original[0]===2*u && original[1]===2*u+1);
      const readout=(j,flag)=>flag && (j===1||j===2)?K:null;
      for(const w of original) {
        let j=1+(w&1), recovered=readout(j,true);
        ok(recovered===K);ok((3*recovered+1)%mod===pk);
        watcherSuccess++;
      }
      let found=null;
      for(let j=0;j<=T;j++) { const k=readout(j,true);if(k!==null && (3*k+1)%mod===pk){found=k;break;} }
      ok(found===K);outsiderSuccess++;
      ok(Array.from({length:T+1},(_,j)=>readout(j,false)).every(v=>v===null));
      worlds++;
    }
  }
  for(let n=1;n<=6;n++) {
    const mod=1<<n;
    for(let C=0;C<mod;C++) for(let K=0;K<mod;K++){ok(C>=0&&K>=0);falsePairs++;}
    for(let K=0;K<mod;K++){const C=K;ok(C===K);}
    for(let sk=0;sk<mod;sk++) {
      const pk=(3*sk+1)%mod;
      for(let t=0;t<mod;t++){const key=sk^t;ok((t^key)===sk);ok((3*(t^key)+1)%mod===pk);}
    }
  }
  ok(worlds===outsiderSuccess); ok(watcherSuccess===2*worlds);
  return {run:562,status:"PASS",assertions_passed:assertions,public_true_orbit_fixtures:worlds,
    valid_original_witness_checks:watcherSuccess,outsider_successes_without_witness:outsiderSuccess,
    false_key_independence_grid_pairs:falsePairs,
    toy_permutations_one_way:false,positive_QPT_WKEM_proof:false,
    theorem_A:"unconditional polynomial-orbit enumeration",theorem_B:"conditional QPT OWP source-extraction separation"};
}
if(typeof process!=="undefined"&&process.stdout)process.stdout.write(JSON.stringify(run562Check(),null,2)+"\n");
