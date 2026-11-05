function runR86() {
  const q=257,n=2,ell=3,m=8,Delta=128,beta=1,k=24; let assertions=0,decodes=0,openings=0,views=0,negatives=0;
  const check=(v,why)=>{assertions++; if(!v)throw Error(`R86 ${assertions}: ${why}`)};
  const mod=x=>(x%q+q)%q;
  const derive=(caseId)=>{
    const A=Array.from({length:m},(_,i)=>[(37*i+13*caseId+19)%q,(i+caseId)%2]);
    const S=[[23+caseId,37+caseId,51+caseId],[17+caseId,21+caseId,25+caseId]];
    const B=A.map(row=>Array.from({length:ell},(_,j)=>mod(row[0]*S[0][j]+row[1]*S[1][j])));
    return {A,S,B};
  };
  const enc=(A,B,seed,caseId)=>{
    const out=[];
    for(let g=0;g<Math.ceil(k/ell);g++){
      const r=Array.from({length:m},(_,i)=>((i*17+g*23+caseId*7+(i+g)*3)>>>((i+g)%3))&1);
      const u=Array.from({length:n},(_,t)=>mod(A.reduce((s,row,i)=>s+row[t]*r[i],0)));
      const v=Array.from({length:ell},(_,j)=>{
        const bit=(seed>>(k-1-(g*ell+j)))&1;
        return mod(B.reduce((s,row,i)=>s+row[j]*r[i],0)+Delta*bit);
      });
      out.push({u,v});
    }
    return out;
  };
  const open=(C,S)=>{
    let result=0;
    for(const block of C)for(let j=0;j<block.v.length;j++){
      const residue=mod(block.v[j]-block.u.reduce((a,u,t)=>a+u*S[t][j],0));
      const d0=Math.min(residue,q-residue),d1=Math.min(mod(residue-Delta),mod(Delta-residue));
      check(d0!==d1,"no decoding tie");decodes++;
      result=(result<<1)|Number(d1<d0);
    }
    return result;
  };
  const toyView=(C,seed,caseId)=>{
    const P=(seed*73+19)&255,B=(seed*151+53)&255,sig=(caseId*29+7)&255;
    const Dsig=sig^P;
    const checksum=C.flatMap(x=>x.u.concat(x.v)).reduce((a,b)=>a+b,0)%257;
    return {C,Dsig,CK:(B+31*Dsig+checksum+caseId)%257,
       Aux:(B+13*checksum+17*Dsig+caseId)%257,context:caseId};
  };
  for(let c=0;c<64;c++){
    const {A,S,B}=derive(c), seed=(c*1723+89211)&((1<<k)-1);
    const S1=S.map(row=>row.slice());for(let j=0;j<ell;j++)S1[1][j]++;
    const E1=A.map(row=>Array(ell).fill(-row[1]));
    const S2=S.map(row=>row.slice());for(const j of [0,2])S2[1][j]++;
    const E2=A.map(row=>Array.from({length:ell},(_,j)=>[0,2].includes(j)?-row[1]:0));
    const W=[[S,A.map(()=>[0,0,0])],[S1,E1],[S2,E2]];
    for(const [Sw,Ew] of W)for(let i=0;i<m;i++)for(let j=0;j<ell;j++){
      check(mod(A[i].reduce((sum,a,t)=>sum+a*Sw[t][j],0)+Ew[i][j])===B[i][j],"ORIGINAL equality");
      check(Math.abs(Ew[i][j])<=beta,"ORIGINAL bound");
    }
    const C=enc(A,B,seed,c),v=toyView(C,seed,c);
    check(JSON.stringify(v)===JSON.stringify(toyView(C,seed,c)),"full deterministic public-view coupling");views++;
    for(const [Sw] of W){const found=open(C,Sw);
      check(found===seed,"every valid ORIGINAL witness recovers identical seed");
      check(toyView(C,found,c).Dsig===v.Dsig && toyView(C,found,c).CK===v.CK &&
      toyView(C,found,c).Aux===v.Aux,"same native masked capability and CK/Aux");openings++;
    }
    for(const a of [0,1])for(const b of [0,1]){
      const sharedNoise=87, va=mod(sharedNoise+Delta*a),vb=mod(sharedNoise+Delta*b);
      check(mod(va-vb)===mod(Delta*(a-b)),"naive same-column reuse reveals relation");negatives++;
    }
  }
  let meanTV=0;const count=8**4;
  for(let idx=0;idx<count;idx++){
    const rows=Array.from({length:4},(_,i)=>(idx>>(3*i))&7), hist=Array(8).fill(0);
    for(let r=0;r<16;r++){let v=0;for(let i=0;i<4;i++)if((r>>i)&1)v^=rows[i];hist[v]++}
    meanTV+=hist.reduce((s,c)=>s+Math.abs(c/16-1/8),0)/2;
  }
  meanTV/=count;
  check(Math.abs(meanTV-0.198883056640625)<1e-12 && meanTV<=0.5*Math.sqrt(8/16),"leftover-hash exact toy census");
  const K=11008,N=256,L=16;
  const unpacked=K*(N+1), packed=Math.ceil(K/L)*N+K;
  check(unpacked===2829056 && packed===187136,"illustrative source bandwidth");
  return {run:"R86-VECTOR-REGEV-PACKED-SOURCE-20261105",status:"RESTRICTED_CONDITIONAL_NOT_GENERIC_WKEM",
    assertions,source_decodes:decodes,all_original_witness_openings:openings,
    full_view_toy_couplings:views,negative_same_column_controls:negatives,
    leftover_hash_census:{public_matrices:4096,r_per_matrix:16,mean_tv:meanTV,bound:0.5*Math.sqrt(8/16)},
    source_q_symbols:{before:unpacked,after:packed,ratio:unpacked/packed},
    limitations:"insecure toy A,PRG,signature; no QPT test, no generic NP or malicious setup"};
}

console.log(JSON.stringify(runR86(), null, 2));
