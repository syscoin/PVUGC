function run447Check(){
  let assertions=0;
  function check(ok){assertions++;if(!ok)throw Error("assertion "+assertions)}
  const order=[];
  for(let n=1;n<=10;n++){
    const N=2**n,x=Math.floor(N/3);
    let fixed=0,adaptive=0;
    for(let r=0;r<N;r++){
      // All (0,x) claims are ORIGINAL-false. The forged proof is pi=0.
      if(x===r) fixed++;
      const chosen=r;
      if(chosen===r) adaptive++;
    }
    check(fixed===1);
    check(adaptive===N);
    check(fixed/N===1/N);
    order.push({lambda:n,crs_count:N,fixed_bad:fixed,adaptive_bad:adaptive});
  }
  const folds=[];
  for(const q of [2,3,5]){
    for(const t of [1,2,3]){
      const total=q**(2*t);
      let bad=0,acceptedPairs=0;
      for(let matrix=0;matrix<total;matrix++){
        let enc=matrix;const v=[];
        for(let k=0;k<2*t;k++){v.push(enc%q);enc=Math.floor(enc/q)}
        let saw=false;
        for(let z=0;z<q;z++){
          let accepts=true;
          for(let row=0;row<t;row++)if((v[2*row]+v[2*row+1]*z)%q!==0){accepts=false;break}
          if(accepts){saw=true;acceptedPairs++}
        }
        if(saw)bad++;
      }
      check(acceptedPairs===q**(t+1));
      check(bad<=acceptedPairs);
      check(bad/total<=q/(q**t)+1e-12);
      folds.push({q,t,crs_count:total,bad_setups:bad,accepted_invalid_pairs:acceptedPairs,
                  union_bound:`${q}/${q**t}`});
    }
  }
  return {run:447,assertions,order,folds,
   theorem:"Fixed-before-CRS existential statistical soundness can justify a conditional iO false-claim zero hybrid; adaptive-after-CRS choice cannot.",
   limits:"Finite algebra only; no QPT security, native signature, iO, SNARG, or actual bridge construction."};
}
console.log(JSON.stringify(run447Check(),null,2));
