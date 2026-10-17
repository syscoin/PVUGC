const result=(function checker(){
 let assertions=0, fixtures=0, cells=0;
 const ck=(b)=>{assertions++;if(!b)throw Error('assertion '+assertions)};
 const par=x=>{let q=0;while(x){q^=1;x&=x-1;}return q;};
 for(let n=3;n<=7;n++){
  const N=2**n;
  for(let d of [...new Set([1,3,(2**(n-1))|1])]){
   for(let xs of [[],[0],[0,d],[0,1],[1,2,3]]){
    const bad=new Set(xs),f=Array.from({length:N},(_,x)=>Math.min(x,x^d));
    for(const x of bad)f[x]=N+x;
    const classes=new Map();for(let x=0;x<N;x++){const k=f[x];if(!classes.has(k))classes.set(k,[]);classes.get(k).push(x);}
    let j=0;for(let x=0;x<N;x++)if(x<(x^d)&&(bad.has(x)||bad.has(x^d)))j++;
    let total=0,wrong=0,tv=0;
    for(let y=0;y<N;y++){
     let mass=0;for(const group of classes.values()){
      let amp=0;for(const x of group)amp+=par(x&y)?-1:1;
      mass+=amp*amp;
     }
     const odd=par(y&d)===1;
     ck(mass===(odd?2*j:2*N-2*j));
     total+=mass;if(odd)wrong+=mass;
     tv+=Math.abs(mass-(odd?0:2*N));cells++;
    }
    ck(total===N*N);ck(wrong===j*N);ck(tv===2*j*N);
    ck(j/N<=bad.size/N);
    ck(j/N<=Math.sqrt(2*bad.size/N-(bad.size/N)**2)+1e-12);
    if(bad.size)ck(f.some((v,x)=>v!==f[x^d]));
    fixtures++;
   }
  }
 }
 return {run:501,claim:'sparse fresh-label exceptions preserve quantum Simon recovery',
  assertions,fixtures,fourier_cells:cells,exact_mass_formula:true,
  exact_total_variation:true,conditioned_good_samples_uniform:true,
  theorem_scope:'conditional approximate-period public evaluator, NOT full WKEM or RIO security',
  implementation_scope:'finite classical computation of quantum Fourier measurement probabilities; no quantum circuit or PQ primitives'};
})();
console.log(JSON.stringify(result,null,2));
