function run() {
  let checks=0,seed=20261029;
  const assert=(b,m)=>{checks++;if(!b)throw Error(m||"check failed")};
  const rand=n=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%n};
  const mod=(x,q)=>((x%q)+q)%q;
  const pc=x=>{let z=0;while(x){z+=x&1;x>>>=1}return z};
  const mons=Array.from({length:64},(_,x)=>x).filter(x=>pc(x)<=3).sort((a,b)=>pc(a)-pc(b)||a-b);
  const viol=(triple,bits)=> {
    let terms=new Map([[0,1]]);
    for(let j=0;j<3;j++){
      const bit=bits[j],i=triple[j],fac=bit?[[1<<i,1]]:[[0,1],[1<<i,-1]],next=new Map();
      for(const [mask,x] of terms)for(const [fm,y] of fac)next.set(mask|fm,(next.get(mask|fm)||0)+x*y);
      terms=next;
    }
    return mons.map(mask=>terms.get(mask)||0);
  };
  const trips=[[0,1,2],[0,3,4],[1,3,5],[2,4,5]],parity=[0,0,0,1],A=[];
  for(let g=0;g<4;g++)for(let bits=0;bits<8;bits++){
    const bs=[bits&1,(bits>>1)&1,(bits>>2)&1];
    if((bs[0]^bs[1]^bs[2])!==parity[g])A.push(viol(trips[g],bs));
  }
  const norm=mons.map(x=>Number(x===0));A.push(norm);
  const U=A.map((_,i)=>Number(i===A.length-1)),z=A.map(()=>1),m=mons.length,n=A.length;
  assert(m===42&&n===17,"Pasch shape");
  for(let j=0;j<m;j++)assert((A.reduce((sum,row)=>sum+row[j],0)&1)===0,"mod2 certificate");
  assert(z.reduce((s,zi,i)=>s+zi*U[i],0)%2===1);
  for(let w=0;w<64;w++) {
    const X=trips.map((tr,i)=>((w>>tr[0])^(w>>tr[1])^(w>>tr[2]))&1);
    assert(X.some((x,i)=>x!==parity[i]),"Pasch FALSE");
  }
  const q=256,g=128;
  const enc=(AA,UU,a,coin)=>{
    const [s,e,eps]=coin;
    return {c:AA[0].map((_,j)=>mod(AA.reduce((v,row,i)=>v+row[j]*s[i],e[j]),q)),
      d:mod(UU.reduce((v,x,i)=>v+x*s[i],eps)+g*a,q)};
  };
  const coins=AA=>[AA.map(()=>rand(q)),AA[0].map(()=>rand(3)-1),rand(3)-1];
  const ident=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
  for(let bit=0;bit<256;bit++){
    const a=rand(2),coin=coins(A),old=enc(A,U,a,coin),b=a^1;
    const shifted=[coin[0].map((v,i)=>mod(v+g*(a-b)*z[i],q)),coin[1].slice(),coin[2]];
    assert(ident(old,enc(A,U,b,shifted)),"Pasch ciphertext equivocation");
  }
  const falseCapsules=[];
  let target=Array.from({length:256},()=>rand(2));
  for(let cap=0;cap<2;cap++){
    const shares=Array.from({length:3},()=>Array.from({length:256},()=>rand(2)));
    const mask=Array.from({length:256},()=>rand(2));
    const full=shares.map(share=>share.map(a=>({a,coin:coins(A)})));
    const before=full.map(sh=>sh.map(d=>enc(A,U,d.a,d.coin)));
    const hidden=Array.from({length:256},(_,i)=>target[i]^mask[i]^shares[0][i]^shares[2][i]);
    const transformed=full[1].map((d,i)=>{
      const b=hidden[i];
      return {a:b,coin:[d.coin[0].map((x,j)=>mod(x+g*(d.a-b)*z[j],q)),d.coin[1],d.coin[2]]};
    });
    for(let i=0;i<256;i++)assert(ident(before[1][i],enc(A,U,transformed[i].a,transformed[i].coin)),"same-key hidden share");
    for(let i=0;i<256;i++)assert((target[i]^mask[i]^shares[0][i]^hidden[i]^shares[2][i])===0,"mask consistency");
    falseCapsules.push({hiddenReconciled:256,independentCoins:true,openingShares:[0,2]});
  }
  const trueClause=viol([0,1,2],[0,0,0]),At=[trueClause,norm],Ut=[0,1], tShares=Array.from({length:3},()=>Array.from({length:256},()=>rand(2)));
  const tMask=target.map((v,i)=>v^tShares[0][i]^tShares[1][i]^tShares[2][i]);
  const ct=tShares.map(sh=>sh.map(a=>enc(At,Ut,a,coins(At))));
  let witnessCount=0;
  for(let w=0;w<64;w++){
    if(!(w&7))continue;witnessCount++;
    const phi=mons.map(m=>Number((w&m)===m));
    for(let r=0;r<At.length;r++)assert(mod(At[r].reduce((v,x,j)=>v+x*phi[j],0),q)===Ut[r],"original witness source equality");
    const rec=[[],[],[]];
    for(let j=0;j<3;j++)for(let i=0;i<256;i++){
      const r=mod(ct[j][i].d-ct[j][i].c.reduce((sum,c,k)=>sum+c*phi[k],0),q);
      const d0=Math.min(r,q-r),d1=Math.abs(r-g),b=Number(d1<d0);
      assert(d0!==d1&&Math.min(d0,d1)<=m+1,"bounded native bit decoding");
      rec[j].push(b);
    }
    for(let i=0;i<256;i++)assert((tMask[i]^rec[0][i]^rec[1][i]^rec[2][i])===target[i],"SAME K for distinct original witnesses");
  }
  assert(witnessCount===56);assert(g>2*(m+1));
  return {status:"PASS",assertions:checks,q,g,degree:3,shape:[n,m],pasch_false_assignments_checked:64,mod2_certificate_weight:17,distinct_true_witnesses:56,mock_capability_bits:256,shares:3,related_false_capsules:falseCapsules,full_false_ciphertext_equalities:768,raw_ciphertext_field_elements:3*256*(m+1),scope:"finite algebra only, not QPT or native SLH security"};
}
console.log(JSON.stringify(run(), null, 2));
