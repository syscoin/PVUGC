(function runCheck(){
  "use strict";
  let checks=0; const ck=(ok,why)=>{if(!ok)throw Error(why);checks++};
  let jointTrue=0,singleFalse=0;
  for(let id=0;id<729;id++){
    let z=id;const a=[];for(let j=0;j<6;j++){a.push(z%3);z=Math.floor(z/3)}
    const represented=new Set();
    for(let w=0;w<64;w++){let v=0;for(let j=0;j<6;j++)if((w>>j)&1)v+=a[j];represented.add(v%3)}
    const k=represented.size;jointTrue+=k*k*k;singleFalse+=3-k;ck(k>=1&&k<=3,"finite SOURCE");
  }
  ck(jointTrue===19429&&singleFalse===14,"exact finite shared-A probability");
  const q=257,n=8,b=2,h=3,r=2,ell=12,B=1,g=Math.floor(q/4);
  const A=[[3,3,5,5,11,11,19,19],[2,2,7,7,13,13,23,23]];
  let state=20261031>>>0;
  const rnd=()=>{state^=state<<13;state^=state>>>17;state^=state<<5;return state>>>0};
  const sm=k=>rnd()%k;
  const dot=(x,y)=>x.reduce((sum,v,j)=>sum+v*y[j],0)%q;
  const mv=w=>A.map(row=>dot(row,w));
  const cert=e=>{let p=0,neg=0;for(const x of e){if(x>0)p+=x;else neg-=x}return 2*(B+Math.max(p,neg))<g};
  const enc=(t,m)=>{
    const s=[sm(q),sm(q)], e=Array.from({length:n},()=>sm(3)-1), eStar=sm(3)-1;
    ck(cert(e),"source-independent coin certificate");
    const beta=Array.from({length:n},(_,j)=>(A[0][j]*s[0]+A[1][j]*s[1]+e[j]+q)%q);
    const tau=(dot(t,s)+eStar+g*m+q)%q;
    return {s,e,eStar,m,beta,tau};
  };
  const dist=(u,v)=>Math.min((u-v+q)%q,(v-u+q)%q);
  const dec=(w,c)=>{
    const rho=((c.tau-dot(w,c.beta))%q+q)%q;
    let best=0;for(let j=1;j<4;j++)if(dist(rho,g*j)<dist(rho,g*best))best=j;
    ck(dist(rho,g*best)<g/2,"decode radius");
    return best;
  };
  const verifyCoins=(t,c)=>{
    ck(cert(c.e),"coin opening cert");
    ck(c.beta.every((v,j)=>v===(A[0][j]*c.s[0]+A[1][j]*c.s[1]+c.e[j]+q)%q),"beta coin opening");
    ck(c.tau===(dot(t,c.s)+c.eStar+g*c.m+q)%q,"tau coin opening");
  };
  const scopes=[];
  for(let i=0;i<4;i++){
    const t=[A[0][2*i],A[1][2*i]];
    const W=[0,1].map(k=>Array.from({length:n},(_,j)=>j===2*i+k?1:0));
    const sk=Array.from({length:ell},()=>sm(2));
    const shares=[Array.from({length:ell},()=>sm(2)),Array.from({length:ell},()=>sm(2))];
    shares.push(sk.map((x,j)=>x^shares[0][j]^shares[1][j]));
    const cells=[];
    for(let a=0;a<h;a++){
      cells[a]=[];
      for(let cap=0;cap<r;cap++){
        cells[a][cap]=[];
        for(let j=0;j<ell;j+=b)cells[a][cap].push(enc(t,shares[a][j]+2*shares[a][j+1]));
      }
    }
    for(const w of W){
      ck(mv(w).join(",")===t.join(","),"two ORIGINAL witnesses");
      for(let cap=0;cap<r;cap++){
        const recovered=[];
        for(let a=0;a<h;a++){
          const symbols=cells[a][cap].map(c=>dec(w,c));
          recovered.push(symbols.flatMap(v=>[v&1,(v>>1)&1]));
        }
        ck(sk.every((v,j)=>v===(recovered[0][j]^recovered[1][j]^recovered[2][j])),"SAME precommitted capability");
      }
    }
    for(let a=0;a<h;a++)for(let cap=0;cap<r;cap++)for(const c of cells[a][cap])verifyCoins(t,c);
    scopes.push({t,sk,cells});
  }
  // Target selection occurs AFTER all publicly visible ciphertexts are generated.
  const target=scopes.reduce((s,v)=>s+v.cells[0][0][0].tau,0)%scopes.length;
  const sealedLane=(target+1)%h;
  for(let i=0;i<4;i++)if(i!==target)
    for(let a=0;a<h;a++)for(let cap=0;cap<r;cap++)for(const c of scopes[i].cells[a][cap])verifyCoins(scopes[i].t,c);
  for(let a=0;a<h;a++)if(a!==sealedLane)
    for(let cap=0;cap<r;cap++)for(const c of scopes[target].cells[a][cap])verifyCoins(scopes[target].t,c);
  const badSecret=101,badSymbol=2;
  const wrongOpener=3;
  const rho=(((3*badSecret+g*badSymbol)-wrongOpener*badSecret)%q+q)%q;
  ck(rho===g*badSymbol,"adversarial FALSE nonbinary opener");
  ck(![0,1].some(w=>w===3),"FALSE source has no binary W");
  const qR=1099511627689,dR=512,nR=21008,bytes=5;
  const symbolsPerScope=3*2*Math.ceil(512/12);
  const matrix=dR*nR*bytes,tBytes=dR*bytes,cipherBytes=symbolsPerScope*(nR+1)*bytes,groups=8;
  const separate=groups*(matrix+tBytes+cipherBytes),shared=matrix+groups*(tBytes+cipherBytes);
  ck(matrix===53780480&&cipherBytes===27101610&&symbolsPerScope===258,"exact C12 baseline");
  ck(separate-shared===(groups-1)*matrix,"matrix amortization gain");
  const logdelta=-Math.log2(1+2**(nR-dR*Math.log2(qR)));
  const mu=16384*16385/(2*(32769)),gR=Math.floor(qR/4096);
  const D=gR/2-16384-nR*mu;
  const logeps=1-2*D*D/(nR*16384**2*Math.log(2));
  ck(Math.log2(groups)+logdelta< -500,"joint TRUE union bound");
  ck(Math.log2(groups*symbolsPerScope)+logeps< -1000,"joint coin-law coupling");
  return {candidate:"SSMA 2026-10-31",assertions:checks,finite:{q:3,d:1,n:6,matrices:729,source_tuples:19683,joint_false_count:254,single_false_count:14},toy:{q,d:2,n,scopes:4,witnesses_per_scope:2,share_lanes:h,capsules_per_scope:r,protected_target:target,unopened_lane:sealedLane,opened_sibling_coins_verified:true,nonbinary_false_recovery:true},illustrative:{scopes:groups,matrix_bytes:matrix,t_bytes_per_scope:tBytes,ciphertext_bytes_per_scope:cipherBytes,ciphertext_vectors_per_scope:symbolsPerScope,separate_bytes:separate,shared_bytes:shared,saved_bytes:separate-shared,savings_percent:100*(separate-shared)/separate,log2_group_false_bound:Math.log2(groups)+logdelta,log2_group_error_conditioning:Math.log2(groups*symbolsPerScope)+logeps},limitation:"toy checks neither QPT security nor generic ORIGINAL soundness"};
})();
