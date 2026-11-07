const runChecker = function() {
  "use strict";
  const q=(1n<<255n)-19n,g=(q-1n)/2n,B=1n<<148n,T=3072;
  let seed=20261101, checks=0, graphs=0, falseCases=0, trueDec=0, opens=0, projections=0;
  const ok=(a,s)=>{checks++;if(!a)throw Error("CHECK FAIL: "+s);};
  const rnd=()=>{seed=(Math.imul(1664525,seed)+1013904223)>>>0;return seed;};
  const mod=x=>((x%q)+q)%q;
  const cent=x=>{const a=mod(x);return a<=q/2n?a:a-q;};
  const make=(n,E,dense=false)=>{
    const feat=[[-1,-1],...Array.from({length:n},(_,i)=>[i,-1])];
    if(dense){for(let u=0;u<n;u++)for(let v=u+1;v<n;v++)feat.push([u,v]);}
    else for(const [u,v] of E)feat.push([u,v]);
    const pos=new Map(feat.map(([u,v],i)=>[u+","+v,i]));
    const A=E.map(([u,v,b])=>{const r=Array(feat.length).fill(0);r[0]=-b;r[pos.get(u+",-1")]+=1;r[pos.get(v+",-1")]+=1;r[pos.get(u+","+v)]-=2;return r;});
    return {feat,A,pos};
  };
  const ev=(feat,w)=>feat.map(([u,v])=>u<0?1n:v<0?BigInt(w[u]):BigInt(w[u]*w[v]));
  const enc=(A,s,e,m)=>e.map((z,j)=>mod(A.reduce((v,row,i)=>v+BigInt(row[j])*s[i],z)+(j===0?g*BigInt(m):0n)));
  const dec=(c,v)=>{const p=mod(c.reduce((sum,z,j)=>sum+z*v[j],0n));const a=p<q-p?p:q-p;const h=mod(p-g),r=mod(g-p);return Number((h<r?h:r)<a);};
  for(const n of [3,7,13,31]){
    const rings=[];for(let i=0;i<n-1;i++)rings.push([i,i+1]);rings.push([0,n-1]);
    const all=new Map(rings.map(([u,v])=>[u+","+v,[u,v]]));
    for(let i=0;i<3*n;i++){let u=rnd()%n,v=rnd()%n;if(u===v)continue;if(u>v)[u,v]=[v,u];all.set(u+","+v,[u,v]);}
    const pairs=[...all.values()].sort((a,b)=>a[0]-b[0]||a[1]-b[1]);
    const isRing=new Set(rings.map(([u,v])=>u+","+v));
    const planted=Array.from({length:n},()=>rnd()%2);
    const Etrue=pairs.map(([u,v])=>[u,v,planted[u]^planted[v]]);
    const {feat:fts,A:At,pos:pt}=make(n,Etrue);
    const {feat:ftd,A:Ad,pos:pd}=make(n,Etrue,true);
    ok(fts.length===1+n+Etrue.length,"sparse support dimension");
    for(let i=0;i<Etrue.length;i++)for(let j=0;j<ftd.length;j++) {
      const [u,v]=ftd[j],key=u+","+v,idx=pt.get(key);
      if(idx===undefined)ok(Ad[i][j]===0,"all removed columns vanish");
      else ok(Ad[i][j]===At[i][idx],"rows project exactly");
    }
    const w2=planted.map(x=>1-x);
    const v0=ev(fts,planted),v1=ev(fts,w2);
    for(const row of At)ok(row.reduce((a,z,j)=>a+BigInt(z)*v0[j],0n)===0n&&row.reduce((a,z,j)=>a+BigInt(z)*v1[j],0n)===0n,"two distinct ORIGINAL witnesses");
    for(let t=0;t<5;t++){
      const m=rnd()%2,s=At.map(()=>BigInt(rnd())),e=fts.map(()=>BigInt(rnd()%101)-50n),c=enc(At,s,e,m);
      ok(dec(c,v0)===m&&dec(c,v1)===m,"same capability from different traces");trueDec+=2;
      const ed=ftd.map(()=>BigInt(rnd()%101)-50n);
      for(let j=0;j<fts.length;j++)ed[pd.get(fts[j].join(","))]=e[j];
      const cd=enc(Ad,s,ed,m);
      for(let j=0;j<fts.length;j++)ok(c[j]===cd[pd.get(fts[j].join(","))],"ciphertext coordinate projection");
      for(let j=0;j<ftd.length;j++)if(!pt.has(ftd[j].join(",")))ok(cd[j]===mod(ed[j]),"removed coordinate is independent error");
      projections++;
    }
    // Mix all constraint labels, with one forced parity contradiction on the entire base cycle.
    let parity=0;
    const labels=new Map();
    for(const [u,v] of rings.slice(0,-1)){const b=rnd()%2;labels.set(u+","+v,b);parity^=b;}
    const last=rings[rings.length-1];labels.set(last.join(","),parity^1);
    const Ef=pairs.map(([u,v])=>[u,v,isRing.has(u+","+v)?labels.get(u+","+v):rnd()%2]);
    const {feat,A}=make(n,Ef),d=Ef.map(([u,v])=>isRing.has(u+","+v)?(q+1n)/2n:0n);
    const h=feat.map((_,j)=>cent((j===0?g:0n)+A.reduce((acc,row,i)=>acc+BigInt(row[j])*d[i],0n)));
    const bs=rings.reduce((a,p)=>a+labels.get(p.join(",")),0);
    const expected=feat.map(([u,v],j)=>j===0?-BigInt((bs+1)/2):v<0?1n:isRing.has(u+","+v)?-1n:0n);
    ok(h.every((v,j)=>v===expected[j]),"exact false graph shift, including chords and labels");
    const H=h.reduce((a,z)=>a+(z<0n?-z:z),0n);
    ok(H===BigInt((bs+1)/2+2*n),"graph shift norm formula");
    ok(Math.log2(Number(BigInt(T)*H))-Math.log2(Number(2n*B+1n))<-128,"bounded full-view statistical error");
    for(let t=0;t<15;t++){
      const s=A.map(()=>BigInt(rnd())),e=feat.map(()=>BigInt(rnd()%201)-100n),m=rnd()%2;
      const zero=enc(A,s,e,0),sm=s.map((v,j)=>mod(v+BigInt(m)*d[j])),em=e.map((v,j)=>v-BigInt(m)*h[j]);
      ok(zero.every((v,j)=>v===enc(A,sm,em,m)[j]),"exact adaptive opening identity");
      opens++;
    }
    ok(q>4n*B*BigInt(feat.length)+2n,"all-error completeness gap");
    falseCases++;graphs++;
  }
  const storage=n=>({n,dense:1+n+n*(n-1)/2,sparse:1+2*n,dense_bytes:3072*(1+n+n*(n-1)/2)*32,sparse_bytes:3072*(1+2*n)*32});
  return {run:"SPNIDR-2026-11-01-T09",status:"restricted support projection and all signed XOR graphs; generic NP unsolved",checks,true_original_bit_decryptions:trueDec,false_cases:falseCases,graphs,coin_equations:opens,dense_sparse_projection_cases:projections,seed_initial:20261101,storage:[storage(31),storage(101),storage(1001)],q_bits:255,B_bits:149};
};
console.log(JSON.stringify(runChecker(), null, 2));
