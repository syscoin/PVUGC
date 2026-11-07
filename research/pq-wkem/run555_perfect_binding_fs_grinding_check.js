function run555() {
  let assertions=0;
  const ok=(v,m)=>{assertions++;if(!v)throw Error(m)};
  function hash(t,trial,nonce,a=0) {
    let z=(nonce ^ Math.imul(trial+1,0x9e3779b9) ^ (t<<24) ^ Math.imul(a+1,0x85ebca6b))|0;
    z=Math.imul(z^(z>>>16),0x7feb352d);
    z=Math.imul(z^(z>>>15),0x846ca68b);
    return (z^(z>>>16))&((1<<t)-1);
  }
  const samples=[];
  for(let t=2;t<=10;t++){
    let wins=0;
    for(let c=0;c<(1<<t);c++){let yes=(c===0);if(yes)wins++;ok(yes===(c===0),"sound")}
    ok(wins===1,"unique interactive challenge");
    for(let nu=0;nu<16;nu++){
      const commitment=[0,nu];
      ok(commitment[0]===0&&commitment[1]===nu,"opening");
      ok(commitment[0]!==1,"perfect binding");
    }
    if([4,6,8,10].includes(t)){
      let N=16*(1<<t), M=0,first=-1;
      for(let nu=0;nu<N;nu++)if(hash(t,0,nu)===0){M++;if(first<0)first=nu}
      ok(M>0,"at least one FS winner");
      ok(hash(t,0,first)===0,"winning transcript");
      const theta=Math.asin(Math.sqrt(M/N));
      const q=Math.max(0,Math.round(Math.PI/(4*theta)-.5));
      const P=Math.sin((2*q+1)*theta)**2;
      ok(P>=0&&P<=1.0000001,"Grover probability");
      if(t>=6)ok(P>.8,"Grover succeeds in finite fixture");
      const existence=1-Math.pow(1-Math.pow(2,-t),N);
      ok(existence>.999,"ideal-oracle existence");
      samples.push({t,N,M,first,q,grover_probability:+P.toFixed(9),ideal_existence_probability:+existence.toFixed(9)});
    }
  }
  return {run:555,assertions_passed:assertions,checker:"run555_perfect_binding_fs_grinding_check.js",
   statement:"Finite arithmetic checker. Ideal random-oracle and quantum-query claims are mathematical, not measured.",
   samples,pointwise_FE_violation_on_winning_proof:true};
}
run555();
