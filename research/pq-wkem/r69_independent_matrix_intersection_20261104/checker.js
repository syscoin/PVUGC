console.log(JSON.stringify((function runR69(){
  let assertions=0;
  const check=(b,s)=>{assertions++;if(!b)throw Error("assertion "+assertions+": "+s)};
  const q=65536,p=4096,scale=16,m=8,n=2,N=4,B=16,L=12,D=scale*L;
  let state=0x691104;
  const rand=()=>{state^=state<<13;state^=state>>>17;state^=state<<5;return state>>>0};
  const mod=(v,k)=>(v%k+k)%k;
  const matrix=()=>Array.from({length:m},()=>Array.from({length:n},()=>rand()%q));
  const vector=()=>Array.from({length:n},()=>rand()%q);
  const fromLwe=(A,z)=>A.map(row=>mod(row.reduce((v,a,j)=>v+a*z[j],0)+(rand()%3-1),q));
  const round=(v)=>mod(Math.floor((mod(v,q)+scale/2)/scale),p);
  const honest=(Y,w)=>Y.map((v,i)=>round(v+(i===0?D*w:0)));
  const challenge=(Y,w)=>Y.map((v,i)=>mod(Math.floor((mod(v+(i===0?D*w:0),q)+8)/16),p));
  const hash=(v)=>{let s=JSON.stringify(v),z=2166136261;for(let i=0;i<s.length;i++){z=Math.imul((z^s.charCodeAt(i)),16777619)>>>0}return z.toString(16)};
  check(L>2*m*(1/scale+0.5),"minimum separation");
  check(p-15*L>2*m*(1/scale+0.5),"no wrap ambiguity");
  const r1=[1,1,0,0,0,0,0,0],r2=[1,0,1,0,0,0,0,0];
  let openings=0;
  for(let j=0;j<N;j++){
    const A=matrix();A[1]=A[0].map(v=>mod(-v,q));A[2]=A[0].map(v=>mod(-v,q));
    const root=Array.from({length:B},()=>rand()%16);
    const Cs=root.map(w=>honest(fromLwe(A,vector()),w));
    for(const r of [r1,r2]){
      for(let col=0;col<n;col++)check(mod(r.reduce((s,z,i)=>s+z*A[i][col],0),q)===0,"joint planted SIS kernel");
      const recovered=Cs.map(C=>{
        const y=mod(C.reduce((s,z,i)=>s+z*r[i],0),p);
        let ds=Array.from({length:16},(_,w)=>Math.min(mod(y-L*w,p),mod(L*w-y,p)));
        let best=Math.min(...ds);
        check(best<L/2,"bounded rounding error");
        return ds.indexOf(best);
      });
      check(JSON.stringify(recovered)===JSON.stringify(root),"every valid r opens same precommitted root");
      openings++;
    }
  }
  let sourceCouplings=0,postCouplings=0,aborts=0;
  const adversarialMatrices=(A)=>{
    const h=hash(A),c=Number.parseInt(h[0],16);
    return Array.from({length:N-1},(_,j)=>A.map((row,i)=>row.map((v,k)=>mod(v+17*j+13*i+7*k+c,q))));
  };
  for(let mode of ["lwe","uniform"]){
    for(let trial=0;trial<64;trial++){
      const Ah=matrix(),bad=adversarialMatrices(Ah);
      // All matrices are frozen BEFORE the target ciphertext is published.
      const V={relation:"intersection-SIS",scope:"UTXO:branch:window:challenge",
        A:[Ah,...bad],vks:["vk_h","vk1","vk2","vk3"],branch:"native N-of-N"};
      const words=Array.from({length:B},()=>rand()%16);
      const Ys=words.map(()=>mode==="lwe"?fromLwe(Ah,vector()):Array.from({length:m},()=>rand()%q));
      const C1=Ys.map((Y,t)=>honest(Y,words[t]));
      const C2=Ys.map((Y,t)=>challenge(Y,words[t]));
      check(JSON.stringify(C1)===JSON.stringify(C2),"actual q-LWE challenge embed");
      const build=(C)=>{
        const K=hash(words),msg=hash(["native scoped message",V]);
        const base={V,C,Dsig:hash(["concealed signature",msg,K])};
        const CK=hash(["CK",K,base]),Aux=hash(["Aux",K,CK,base]);
        const hostile={A:bad,CK:hash(["hostile CK",base,CK]),
          Aux:hash(["hostile AUX",base,Aux]),related:hash(["related independent capsules",base])};
        return {base,CK,Aux,hostile};
      };
      const H1=build(C1),H2=build(C2);
      check(JSON.stringify(H1)===JSON.stringify(H2),"full checking-key and auxiliary coupling");
      const abort=T=>Number.parseInt(hash(T).slice(0,2),16)%4===0;
      check(abort(H1)===abort(H2),"selective abort postprocessing coupling");
      if(abort(H1))aborts++;
      sourceCouplings++;postCouplings++;
    }
  }
  let pairs=0;
  const rs=[[1,0,0],[1,0,1],[1,1,0],[1,1,1]];
  for(let i=0;i<rs.length;i++)for(let j=i+1;j<rs.length;j++){
    let both=0;
    for(let a=0;a<4;a++)for(let b=0;b<4;b++)for(let c=0;c<4;c++){
      const A=[a,b,c];
      if(mod(A.reduce((z,v,t)=>z+v*rs[i][t],0),4)===0&&
         mod(A.reduce((z,v,t)=>z+v*rs[j][t],0),4)===0)both++;
    }
    check(both===4,"pairwise indicator independence over Z4");
    pairs++;
  }
  // A malicious non-honest participant can make the intersection empty.
  const poison=Array.from({length:m},(_,i)=>[i===0?1:0,0]);
  check([r1,r2].every(r=>mod(r.reduce((s,v,i)=>s+v*poison[i][0],0),q)===1),
    "malicious capsule/matrix can destroy completeness");
  return {run:"R69-INDEPENDENT-MATRIX-INTERSECTION-20261104",
    status:"RESTRICTED_ONE_HONEST_SETUP_AND_QPT_HYBRID_NOT_GENERIC_WKEM",
    assertions,planted_all_original_openings:openings,
    genuine_qLWE_or_uniform_jointview_couplings:sourceCouplings,
    adaptive_corrupt_public_output_couplings:postCouplings,
    abort_decisions:aborts,pairwise_independent_pairs:pairs,
    toy:"q=65536,p=4096,m=8,n=2,N=4,4-bit words,noncryptographic hashes",
    limitations:"planted correctness separate from uniform real setup; no QPT hardness, generic-NP compiler, malicious completeness or PQ native signer"};
})(), null, 2));
