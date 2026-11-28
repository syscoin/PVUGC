const check = function check(){
  let seed=20261030>>>0, checks=0;
  const ck=(c,s)=>{if(!c)throw Error(s);checks++};
  const rand=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed};
  const rb=n=>Array.from({length:n},()=>rand()&255);
  const mul=(a,b)=>{let out=0;while(b){if(b&1)out^=a;a<<=1;if(a&256)a^=0x11b;b>>>=1}return out};
  const pow=(a,k)=>{let v=1;while(k){if(k&1)v=mul(v,a);a=mul(a,a);k>>>=1}return v};
  const div=(a,b)=>{ck(b!==0,"zero denominator");return mul(a,pow(b,254))};
  const qm=65537,n=3,m=8,L=52,w=2,g=2000,B=2;
  const digits=ks=>{let carry=0,bits=0,i=0;const out=[];while(out.length<L){while(bits<5){carry|=(i<ks.length?ks[i]:0)<<bits;bits+=8;i++}out.push(carry&31);carry>>>=5;bits-=5}return out};
  const decodeBytes=ds=>{let carry=0,bits=0,bs=[];for(const d of ds){ck(d>=0&&d<=31,"digit range");carry|=d<<bits;bits+=5;while(bits>=8){bs.push(carry&255);carry>>>=8;bits-=8}}ck(bs.length===32&&carry===0,"canonical 256 bits");return bs};
  const source=()=>{
    let A=Array.from({length:n},()=>Array.from({length:m},()=>rand()%qm));
    for(const a of A)for(const p of [0,1,4,5])a[p+2]=a[p];
    let U=[],Za=[],Zb=[];
    for(let l=0;l<L;l++){
      let ps=[0,1,4,5],p=ps[rand()%4],t=ps[rand()%4];
      if(t===p)t=ps[(ps.indexOf(p)+1)%4];
      let zp=Array(m).fill(0),zq=Array(m).fill(0);
      let sp=(rand()&1)?1:-1,st=(rand()&1)?1:-1;
      zp[p]=sp;zp[t]=st;zq[p+2]=sp;zq[t+2]=st;
      U.push(A.map(row=>row.reduce((sum,x,j)=>sum+x*zp[j],0)%qm+qm).map(x=>x%qm));
      Za.push(zp);Zb.push(zq);
    }
    return {A,U,Za,Zb};
  };
  const make=(A,U,share)=>{
    let r=Array.from({length:n},()=>rand()%qm);
    let ec=Array.from({length:m},()=>rand()%5-2);
    let ed=Array.from({length:L},()=>rand()%5-2);
    let dg=digits(share);
    let c=Array.from({length:m},(_,j)=>((A.reduce((s,row,i)=>s+row[j]*r[i],0)+ec[j])%qm+qm)%qm);
    let d=Array.from({length:L},(_,l)=>((U[l].reduce((s,x,i)=>s+x*r[i],0)+ed[l]+g*dg[l])%qm+qm)%qm);
    return {c,d,r,ec,ed};
  };
  const decrypt=(A,U,p,zs)=>{
    let ds=[];
    for(let l=0;l<L;l++){
      let z=zs[l],count=z.reduce((s,x)=>s+Math.abs(x),0);
      ck(count===w&&z.every(x=>[-1,0,1].includes(x)),"SOURCE weight");
      for(let i=0;i<n;i++)ck(((A[i].reduce((s,x,j)=>s+x*z[j],0)-U[l][i])%qm+qm)%qm===0,"SOURCE relation");
      let t=((p.d[l]-p.c.reduce((s,x,j)=>s+x*z[j],0))%qm+qm)%qm;
      let errs=Array.from({length:32},(_,v)=>Math.min((t-g*v+qm*4)%qm,(g*v-t+qm*4)%qm));
      let min=Math.min(...errs),idx=errs.indexOf(min);
      ck(min<=B*(w+1)&&errs.filter(x=>x===min).length===1,"rounding");
      ds.push(idx);
    }
    return decodeBytes(ds);
  };
  const reconstruct=(i,j,si,sj)=>{ck(i!==j,"distinct indexes");return si.map((v,k)=>v^mul(i,div(v^sj[k],i^j)))};
  const same=(a,b)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
  const fakeRoot=(secretSeed,publicSeed)=>Array.from({length:16},(_,i)=>(secretSeed[i]^publicSeed[(i+3)%16]^((i*73+9)&255))&255);
  for(let a=1;a<256;a++)ck(mul(a,pow(a,254))===1,"GF inverse");
  for(let i=1;i<=3;i++)for(const keybyte of [0,17,127,255]){
    let obs=Array.from({length:256},(_,v)=>keybyte^mul(i,v)).sort((a,b)=>a-b);
    ck(obs.every((v,j)=>v===j),"single-share perfect hiding");
  }
  for(let trial=0;trial<24;trial++){
    let secretSeed=rb(16),secretPrf=rb(16),publicSeed=rb(16),K=secretSeed.concat(secretPrf),V=rb(32);
    let pk=publicSeed.concat(fakeRoot(secretSeed,publicSeed));
    ck(same(pk.slice(0,16),publicSeed),"PK.seed public and independent");
    let shares={};for(let i=1;i<=3;i++)shares[i]=K.map((x,j)=>x^mul(i,V[j]));
    let {A,U,Za,Zb}=source(), packets={};
    for(let i=1;i<=3;i++)packets[i]=make(A,U,shares[i]);
    for(const [i,j] of [[1,2],[1,3],[2,3]])for(const z1 of [Za,Zb])for(const z2 of [Za,Zb]){
      let si=decrypt(A,U,packets[i],z1),sj=decrypt(A,U,packets[j],z2);
      let got=reconstruct(i,j,si,sj);
      ck(same(got,K),"same native seed capability for distinct SOURCE openings");
      ck(same(pk,publicSeed.concat(fakeRoot(got.slice(0,16),publicSeed))),"mock PK.root binding");
    }
    for(let disclosed=1;disclosed<=3;disclosed++){
      let p=packets[disclosed],dg=[];
      for(let l=0;l<L;l++){
        let t=((p.d[l]-p.ed[l]-U[l].reduce((s,x,i)=>s+x*p.r[i],0))%qm+qm)%qm;
        ck(t%g===0&&t/g>=0&&t/g<32,"full coins reveal one share");
        dg.push(t/g);
      }
      ck(same(decodeBytes(dg),shares[disclosed]),"single disclosed share");
      let un=[1,2,3].filter(i=>i!==disclosed);
      let got=reconstruct(un[0],un[1],decrypt(A,U,packets[un[0]],Za),decrypt(A,U,packets[un[1]],Zb));
      ck(same(got,K),"remaining pair still releases");
    }
    let broken=shares[1].slice();broken[0]^=1;
    ck(!same(reconstruct(1,2,broken,shares[2]),K),"inconsistent Shamir share rejected");
  }
  ck(524287>2*128*(2000+1),"illustrative decoding margin");
  ck(16777213-31*524287>2*128*(2000+1),"illustrative cyclic margin");
  let size=4*256*4469*3+4*100*(256*52*3+3*(4469+52)*3);
  ck(size===45978768,"unchanged full SOURCE storage");
  return {candidate:"Direct native secret seeds; 2-of-3 Shamir SOURCE",source_only:true,prg_assumption_removed:true,native_keygen:"mock root, not real SLH",toy_uniform_lwe:false,trials:24,assertions:checks,illustrative_bytes:size};
};
console.log(JSON.stringify(check()));
