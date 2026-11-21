function run499Checker() {
  let assertions=0; const check=(x)=>{assertions++;if(!x)throw Error("Run499 assertion "+assertions)};
  const parity=(a,b)=>{let v=a&b,t=0;while(v){t^=v&1;v>>>=1;}return t};
  function walsh(a) {a=a.slice();for(let h=1;h<a.length;h*=2)for(let i=0;i<a.length;i+=2*h)for(let j=i;j<i+h;j++){const x=a[j],y=a[j+h];a[j]=x+y;a[j+h]=x-y;}return a;}
  const cases=[];
  for(let n=5;n<=10;n++)for(let ctx=0;ctx<3;ctx++){
    const N=1<<n,K=((n*53+ctx*29)^0x5a3b)&(N-1),mask=(1<<(n>>1))-1;
    const noisy=r=>r!==0&&r%7===0 ? 1:0;
    const pred=r=>parity(K,r)^noisy(r);
    const wrong=Array.from({length:N},(_,r)=>noisy(r)).reduce((a,b)=>a+b,0);
    const coeff=walsh(Array.from({length:N},(_,r)=>pred(r)?-1:1));
    check(coeff[K]===N-2*wrong);
    check(coeff[K]>Math.max(...coeff.filter((v,i)=>i!==K).map(Math.abs)));
    let max=-1,decoded=-1;for(let i=0;i<N;i++)if(Math.abs(coeff[i])>max){max=Math.abs(coeff[i]);decoded=i;}
    check(decoded===K);check((decoded&mask)===(K&mask));
    let d1b0=0,d1b1=0,oracleCorrect=0;
    for(let r=0;r<N;r++){
      let h=parity(K,r),g=pred(r);
      if((h^g)===1)d1b0++;
      if((1^h^g)===1)d1b1++;
      if(g===h)oracleCorrect++;
    }
    check(oracleCorrect===N-wrong);
    check(Math.abs(Math.abs(d1b1-d1b0)/N-coeff[K]/N)<1e-12);
    let witnessCount=0;
    for(let w=0;w<16;w++)if(w%4===ctx%4){
      witnessCount++;
      for(let r of [0,1,3,N-1]){
        const m=(w^r)&1,c=m^parity(K,r);
        check((c^parity(K,r))===m);
      }
    }
    check(witnessCount===4);
    cases.push({key_bits:n,context:ctx,public_vk_suffix_bits:n>>1,oracle_correct_fraction:oracleCorrect/N,walsh_correlation:coeff[K]/N,ind_adv:Math.abs(d1b1-d1b0)/N,exact_recovery:true,distinct_valid_states:4});
  }
  check(cases.length===18);
  return {run:499,title:"Key-correlated hardcore bit lemma finite diagnostic",assertions,cases,limitations:"This is an intentionally biased hypothetical parity predictor with oracle access to K. It demonstrates Fourier reconstruction and an IND-to-parity identity, not key recovery from a real capsule, WE, SLH-DSA, or QPT security."};
}
console.log(JSON.stringify(run499Checker(),null,2));
