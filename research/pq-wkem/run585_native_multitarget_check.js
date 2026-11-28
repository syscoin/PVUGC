// Run 585: exactly executed self-contained finite oracle cardinality checker (Node/V8).
// This DOES NOT run a quantum algorithm or implement SLH-DSA.
function checkRun585() {
  let checks=0, state=5852026>>>0;
  const assert=(v,s)=>{if(!v)throw new Error(s);checks++};
  const rnd=()=>{state=(Math.imul(state,1664525)+1013904223)>>>0;return state};
  const perm=(m)=>{const a=Array.from({length:m},(_,i)=>i);for(let j=m-1;j>0;j--){let t=rnd()%(j+1);[a[t],a[j]]=[a[j],a[t]]}return a};
  let shared=0,salted=0,derivations=0;
  for(let bits=3;bits<=9;bits++){const m=2**bits;
    for(const n of [1,2,4,8,16]){if(n>m)continue;
      const f=perm(m), seeds=[];let index=0;
      while(seeds.length<n){const x=(index*13+7)%m;if(!seeds.includes(x))seeds.push(x);index++}
      const targets=new Set(seeds.map(s=>f[s]));
      const marked=Array.from({length:m},(_,s)=>s).filter(s=>targets.has(f[s]));
      assert(marked.length===n,'shared marked count');assert(marked.every(s=>seeds.includes(s)),'shared exact preimages');
      assert(marked.length/m===n/m,'shared density');shared++;
      const fs=Array.from({length:n},()=>perm(m));
      const xs=Array.from({length:n},(_,i)=>(7+i*13)%m);
      const ys=xs.map((x,i)=>fs[i][x]);
      let pairMarks=0;
      for(let i=0;i<n;i++)for(let s=0;s<m;s++)if(fs[i][s]===ys[i])pairMarks++;
      assert(pairMarks===n,'per-public-seed marked count');
      assert(pairMarks/(n*m)===1/m,'per-public-seed marked fraction');
      salted++;
    }
    // A different upstream context maps to independent final seeds but does not change shared native F.
    const F=perm(m), seed1=5%m,seed2=17%m;
    assert(seed1!==seed2,'distinct final seeds fixture');
    const roots=new Set([F[seed1],F[seed2]]);
    const successes=Array.from({length:m},(_,s)=>s).filter(s=>roots.has(F[s]));
    assert(successes.length===2,'upstream context has no effect on shared final map');
    derivations++;
  }
  const ledger=[];
  for(const k of [128,192,256,276,288])for(const logN of [0,10,20,32]){
    const sharedExponent=(k-logN)/2,saltedExponent=k/2;
    assert(sharedExponent<=saltedExponent,'shared bound');
    assert((sharedExponent>=128)===(k>=256+logN),'parameter threshold');
    ledger.push({native_secret_bits:k,log2_target_count:logN,shared_log2_root_queries:sharedExponent,per_claim_seeded_log2_root_queries:saltedExponent});
  }
  return JSON.stringify({run:585,assertions_passed:checks,fixtures:{shared,salted,upstream_context:derivations},parameter_ledger:ledger,
    limitation:'Toy permutations/cardinality and query arithmetic only; no SLH-DSA implementation, no quantum circuit, no QPT WKEM security claim.'},null,2)+'\n';
}
if(typeof module!=='undefined'&&module.exports)module.exports=checkRun585;
if(typeof process!=='undefined'&&process.stdout)process.stdout.write(checkRun585());
