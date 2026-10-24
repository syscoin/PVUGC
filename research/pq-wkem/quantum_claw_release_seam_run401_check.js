// Run 401, exact executed compact checker. Quantum statevector Grover simulation; not a cryptographic implementation.
function main() {
  let checks=0;
  function ck(x,why){checks++;if(!x)throw Error("check "+checks+": "+why);}
  let state=0x20261009;
  function random(){state^=state<<13;state^=state>>>17;state^=state<<5;return state>>>0;}
  const results=[];
  for(const width of [6,9,12]){
    const N=2**width,t=Math.ceil(N**(1/3));
    let coherentBetter=0,minP=1,trials=0,markedTotal=0;
    for(let fixture=0;fixture<12;fixture++){
      const F=Array.from({length:N},()=>random()%N);
      const G=Array.from({length:N},()=>random()%N);
      const table=new Map();
      for(let i=0;i<t;i++)if(!table.has(F[i]))table.set(F[i],i);
      const marked=G.map(y=>Number(table.has(y)));
      const M=marked.reduce((a,v)=>a+v,0);
      ck(table.size>=1,"nonempty table");
      if(!M)continue;
      let first=-1;
      for(let y=0;y<N;y++)if(marked[y]){first=y;break;}
      ck(first>=0,"a claw exists");
      const a=table.get(G[first]);
      ck(F[a]===G[first],"claw equality exact");
      const secret=0x3a7b9321;
      const release=(i,j)=>F[i]===G[j]?secret:null;
      ck(release(a,first)===secret,"ideal weak seam releases without SOURCE");
      const theta=Math.asin(Math.sqrt(M/N));
      const rounds=Math.max(0,Math.round(Math.PI/(4*theta)-0.5));
      let amplitudes=Array(N).fill(1/Math.sqrt(N));
      for(let k=0;k<rounds;k++){
        for(let z=0;z<N;z++)if(marked[z])amplitudes[z]*=-1;
        const mean=amplitudes.reduce((s,v)=>s+v,0)/N;
        for(let z=0;z<N;z++)amplitudes[z]=2*mean-amplitudes[z];
      }
      const norm=amplitudes.reduce((s,v)=>s+v*v,0);
      const pCoherent=amplitudes.reduce((s,v,z)=>s+marked[z]*v*v,0);
      const formula=Math.sin((2*rounds+1)*theta)**2;
      ck(Math.abs(norm-1)<1e-9,"unitarity of Grover iterate");
      ck(Math.abs(pCoherent-formula)<1e-9,"coherent amplitude equals exact formula");
      const classical=1-(1-M/N)**Math.max(1,rounds);
      if(pCoherent>classical)coherentBetter++;
      minP=Math.min(minP,pCoherent);markedTotal+=M;trials++;
    }
    ck(trials>=10,"adequate nonempty marked fixtures");
    ck(coherentBetter>=10,"coherent search succeeds more often than same number of classical samples");
    results.push({width,N,table_target:t,nonempty_trials:trials,mean_marked_count:markedTotal/trials,coherent_better_trials:coherentBetter,min_coherent_success:Math.round(minP*1000000)/1000000});
  }
  const estimates=[96,128,192,256,384,512].map(width=>({label_bits:width,classical_birthday_exponent:width/2,quantum_claw_query_exponent:Math.round(width/3*1e6)/1e6,classical_table_memory_exponent:Math.round(width/3*1e6)/1e6}));
  for(const r of estimates){ck(Math.abs(r.quantum_claw_query_exponent-r.label_bits/3)<1e-5,"query exponent");ck(r.classical_birthday_exponent===r.label_bits/2,"classical exponent");}
  const N=2**36,L=16;
  const optimal_t=Math.ceil((L*L*N/4)**(1/3));
  const shared=optimal_t+L*Math.sqrt(N/optimal_t);
  const independent=L*(N**(1/3)+(N/(N**(1/3)))**0.5);
  ck(shared<independent,"shared-frame multi-capsule tradeoff");
  return {run:401,status:"PASS",checks,seed:"0x20261009",coherent_small_statevector_fixtures:results,bit_security_raw_query_estimates:estimates,
    shared_frame_amortization:{N_exponent:36,capsules:L,sample_count:optimal_t,shared_query_model:Math.ceil(shared),independent_query_model:Math.ceil(independent)},
    note:"Ideal public two-frame hash-claw seam ONLY. No full source-bound mixer, concrete quantum hardware security or native signing is proved."};
}
console.log(JSON.stringify(main(),null,2));
