function runCheck(){
  let checks=0;
  function ok(v,msg){checks++;if(!v)throw Error(msg)}
  const q=67,m=16,w=4,g=24,B=1,n=2;
  let seed=20261030;
  function randint(k){seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%k}
  function dot(a,b){let s=0;for(let i=0;i<a.length;i++)s+=a[i]*b[i];return ((s%q)+q)%q}
  function syn(A,z){return A.map(a=>dot(a,z))}
  function eq(a,b){return a.every((v,i)=>v===b[i])}
  function open(A,U){
    for(let a=0;a<m-3;a++)for(let b=a+1;b<m-2;b++)for(let c=b+1;c<m-1;c++)for(let d=c+1;d<m;d++)
    for(let mask=0;mask<16;mask++){
      const z=Array(m).fill(0),idx=[a,b,c,d];
      for(let i=0;i<4;i++)z[idx[i]]=(mask&(1<<i))?1:-1;
      if(eq(syn(A,z),U))return z
    }
    return null
  }
  function packet(A,U,k){
    const r=Array.from({length:n},()=>randint(q));
    const ec=Array.from({length:m},()=>randint(3)-1);
    const ed=randint(3)-1;
    const c=Array.from({length:m},(_,j)=>{
      let s=ec[j];for(let i=0;i<n;i++)s+=A[i][j]*r[i];return ((s%q)+q)%q;
    });
    const d=(dot(U,r)+ed+g*k)%q;
    return [c,d]
  }
  function decode(z,C){
    const v=((C[1]-dot(z,C[0]))%q+q)%q;
    const d0=Math.min(v,q-v), v1=((v-g)%q+q)%q,d1=Math.min(v1,q-v1);
    return d1<d0?1:0
  }
  const trials=20;let falseRecover=0;
  for(let trial=0;trial<trials;trial++){
    const A=Array.from({length:n},()=>Array.from({length:m},()=>randint(q)));
    const z0=Array(m).fill(0);
    let support=new Set;while(support.size<w)support.add(randint(m));
    for(const j of support)z0[j]=randint(2)?1:-1;
    const U=syn(A,z0),kf=randint(2),kt=randint(2);
    const falseC=packet(A,U,kf),dummyC=packet(A,U,kt);
    const z=open(A,U);
    ok(!!z,"planted opening");
    ok(eq(syn(A,z),U),"valid syndrome");
    ok(z.reduce((s,x)=>s+Math.abs(x),0)===w,"weight");
    ok(decode(z,dummyC)===kt,"true dummy correctness");
    ok(decode(z,falseC)===kf,"transfer false ciphertext recovery");
    falseRecover++;
  }
  function comb(N,K){let r=1n;for(let i=1;i<=K;i++)r=(r*BigInt(N-i+1))/BigInt(i);return r}
  const Q=16777213n, N=256n, M=4469,W=2006,L=103;
  const T=(1n<<BigInt(W))*comb(M,W), J=BigInt(3*L);
  const big=(Q**N-1n);
  ok(J*J*big*(1n<<256n)<4n*T,"full-scope target TV exact threshold");
  const E=128*(W+1),ratio=(2*E+1)/Number(Q),factor=(2/3)*(1-ratio);
  ok(factor>0.64&&factor<0.65,"constant QPT-LWE contradiction factor");
  ok(2*E+1<Number(Q),"cyclic residual acceptance not trivial");
  return {candidate:"SOURCE-independent planted target with hypothetical public ORIGINAL Lift",status:"NO POSITIVE WKEM ADVANCE",toyTrials:trials,toyFalseRecovered:falseRecover,toyQ:q,toyOpeningWeight:w,toyShortVectorCandidates:16*1820,realLargeParams:{q:Number(Q),n:256,m:M,w:W,L,noiseB:128},singleScopeStatisticalDistanceBelow2Pow128:true,largeNullAcceptanceExact:`${2*E+1}/${Q}`,lweContradictionAdvantageFactor:factor,checks,disclaimer:"Toy finite scope-transfer only; no QPT security or native signature test"};
}
console.log(JSON.stringify(runCheck(),null,2));
