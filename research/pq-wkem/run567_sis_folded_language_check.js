"use strict";
function check() {
  let assertions=0,total=0,totalSolutions=0,falseFoldedTrue=0;
  const grids=[[3,1,2],[3,1,3],[3,1,5],[3,1,6],[3,2,2],[3,2,3],[3,2,4],[3,2,5],[5,1,2],[5,1,4],[5,1,5],[5,2,2],[5,2,3]];
  function ok(c,m) {if(!c)throw Error(m||"check failed");assertions++;}
  function popcount(v) {let c=0;while(v){v&=v-1n;c++;}return c;}
  const rows=[];
  for (const [q,n,L] of grids) {
    const all=q**L, N=1<<L, M=N-1, qn=q**n, rowMasks=[];
    for(let j=0;j<all;j++) {
      let v=j;const coeff=[];
      for(let k=0;k<L;k++){coeff.push(v%q);v=Math.floor(v/q);}
      let bits=0n;
      for(let e=0;e<N;e++){
        let z=0;
        for(let k=0;k<L;k++) z+=((e>>k)&1)*coeff[k];
        if(z%q===0)bits|=1n<<BigInt(e);
      }
      rowMasks.push(bits);
    }
    const histogram=Array(N).fill(0);
    if(n===1){for(let i=0;i<all;i++){const x=popcount(rowMasks[i])-1;histogram[x]++;totalSolutions+=x;total++;ok(x>=0);}}
    else {for(let i=0;i<all;i++)for(let j=0;j<all;j++){const x=popcount(rowMasks[i]&rowMasks[j])-1;histogram[x]++;totalSolutions+=x;total++;ok(x>=0);}}
    const trials=all**n, S1=histogram.reduce((s,c,i)=>s+c*i,0), S2=histogram.reduce((s,c,i)=>s+c*i*i,0);
    ok(histogram.reduce((a,b)=>a+b,0)===trials,"total");
    ok(S1*qn===trials*M,"mean");
    ok(S2*qn*qn===trials*(M*(qn-1)+M*M),"variance");
    ok(histogram[0]*M<=trials*qn,"Chebyshev");
    if(L>n*(q-1))ok(histogram[0]===0,"Chevalley-Warning");
    falseFoldedTrue+=trials-histogram[0];
    rows.push({q,n,L,matrices:trials,zero_kernel_matrices:histogram[0],false_original_folded_true:trials-histogram[0],deterministic_threshold:L>n*(q-1)});
  }
  for (const [q,L] of [[3,5],[5,4]])for(let e=1;e<(1<<L);e++)for(let f=1;f<(1<<L);f++){
    let dep=false;
    for(let a=1;a<q;a++){
      let match=true;for(let k=0;k<L;k++)if((a*((e>>k)&1)-((f>>k)&1))%q!==0){match=false;break;}
      if(match){dep=true;break;}
    }
    ok(dep===(e===f),"pairwise independence");
  }
  return {run:567,status:"PASS",assertions_passed:assertions,total_matrices_exhausted:total,sum_binary_kernel_solutions:totalSolutions,false_original_folded_true_matrices:falseFoldedTrue,grids:rows,security:"finite algebra only; no QPT SIS hardness or WKEM"};
}
if (typeof require !== 'undefined' && require.main === module) process.stdout.write(JSON.stringify(check(), null, 2)+'\n');
