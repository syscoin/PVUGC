'use strict';
function run448Check(){
  let assertions=0;const check=(cond,msg)=>{if(!cond)throw Error(msg);assertions++;};
  let finite=[];
  for(const n of [1,2]){
    const N=1<<n,total=N**N;
    let fixed=0,any=0;let qcounts=Array(N).fill(0);
    for(let code=0;code<total;code++){
      let z=code;const f=[];
      for(let j=0;j<N;j++){f.push(z%N);z=Math.floor(z/N);}
      if(f[0]===0)fixed++;
      if(f.some((x,j)=>x===j))any++;
      for(let q=1;q<=N;q++)if(f.slice(0,q).some((x,j)=>x===j))qcounts[q-1]++;
    }
    check(fixed===N**(N-1),"fixed statement exact count");
    check(total-any===(N-1)**N,"global-existence count");
    for(let q=1;q<=N;q++){
      let expected=total*((1-(1-1/N)**q));
      check(Math.abs(qcounts[q-1]-expected)<1e-10,"adaptive q-query exact");
      check(qcounts[q-1]/total<=q/N+1e-10,"classical union bound");
    }
    finite.push({n,functions:total,fixed_bad_probability:fixed/total,
      global_bad_probability:any/total,adaptive_counts:qcounts});
  }
  let large=[];
  for(const n of [3,4,6,8,10,12,16]){
    let N=2**n,delta=1/N,p=1-(1-delta)**N;
    check(p>0.632&&p<0.66,"global quantifier range");
    large.push({n,per_statement_delta:delta,global_bad_probability:p});
  }
  let grover=[];
  for(const bits of [5,8,10,12,16]){
    const a=2**(-bits),th=Math.asin(Math.sqrt(a));
    const j=Math.max(0,Math.round(Math.PI/(4*th)-0.5));
    const pq=Math.sin((2*j+1)*th)**2;
    const pc=1-(1-a)**j;
    check(pq>pc,"coherent Grover lower-control");
    check(j<=2**(bits/2),"Grover query scale");
    grover.push({mark_bits:bits,marked_density:a,iterations:j,quantum_probability:pq,classical_equal_queries:pc});
  }
  return {run:448,assertions,kind:"finite probability proof checker and ideal Grover amplitude diagnostic",
   finite,large,grover,findings:[
   "pointwise false-instance delta does not imply universal global good CRS",
   "independent per-context oracle classical Q+1 query success <=(Q+1)delta",
   "coherent mark-oracle grinding cost Theta(1/sqrt(delta)); general QPT hiding unproved"
   ],not_established:["local-mixing compiler","QPT-secure witness-KEM","native PQ signing","full QROM upper bound"]};
}
console.log(JSON.stringify(run448Check(),null,2));
