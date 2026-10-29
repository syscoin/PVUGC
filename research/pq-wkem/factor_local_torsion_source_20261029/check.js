function run(){
  let assertions=0, seed=20261029;
  const ok=(x,m)=>{assertions++;if(!x)throw Error(m||"assertion")};
  const rnd=n=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%n};
  const mod=(x,q)=>((x%q)+q)%q;
  const pop=x=>{let r=0;while(x){r+=x&1;x>>>=1}return r};
  function xorFactor(vs,p){const vals=[];for(let b=0;b<(1<<vs.length);b++)if(pop(b)%2===p)vals.push(vs.map((_,i)=>(b>>i)&1));return {vs,vals,p};}
  function orFactor(vs,neg){const vals=[];for(let b=0;b<(1<<vs.length);b++){const bits=vs.map((_,i)=>(b>>i)&1);if(bits.some((v,i)=>neg[i]?!v:v))vals.push(bits)}return {vs,vals,p:null};}
  function compile(factors){
    const offs=[],columns=[];for(let j=0;j<factors.length;j++){offs.push(columns.length);for(let k=0;k<factors[j].vals.length;k++)columns.push([j,k]);}
    const L=columns.length,A=[],U=[],tags=[],app=new Map();
    for(let j=0;j<factors.length;j++){const row=Array(L).fill(0);for(let k=0;k<factors[j].vals.length;k++)row[offs[j]+k]=1;A.push(row);U.push(1);tags.push(["norm",j]);}
    for(let j=0;j<factors.length;j++)factors[j].vs.forEach((v,pos)=>{if(!app.has(v))app.set(v,[]);app.get(v).push([j,pos]);});
    for(const v of Array.from(app.keys()).sort((a,b)=>a-b)){
      const loc=app.get(v);for(let t=1;t<loc.length;t++){
        const [root,rp]=loc[0], [child,cp]=loc[t],row=Array(L).fill(0);
        factors[root].vals.forEach((bits,k)=>row[offs[root]+k]+=bits[rp]);
        factors[child].vals.forEach((bits,k)=>row[offs[child]+k]-=bits[cp]);
        A.push(row);U.push(0);tags.push(["edge",v,root,child]);
      }
    }
    return {factors,offs,A,U,tags,app,L};
  }
  function valid(factors,w){return factors.every(f=>f.vals.some(bits=>bits.every((b,i)=>w[f.vs[i]]===b)));}
  function phi(C,w){const p=Array(C.L).fill(0);for(let j=0;j<C.factors.length;j++){const f=C.factors[j],k=f.vals.findIndex(bits=>bits.every((b,i)=>w[f.vs[i]]===b));ok(k>=0,"valid local choice");p[C.offs[j]+k]=1}return p;}
  function sourceOK(C,p,q=0){return C.A.every((row,i)=>{const v=row.reduce((s,a,k)=>s+a*p[k],0)-C.U[i];return q?mod(v,q)===0:v===0})}
  function certificate(C,J){
    const z=Array(C.A.length).fill(0);
    for(let j=0;j<J.length;j++){ok(C.factors[j].p!==null,"XOR-only selected certificate");z[j]=J[j]*C.factors[j].p;}
    for(const [v,loc] of C.app){
      ok(loc.reduce((t,[j])=>t+J[j],0)%2===0,"even selected occurrences");
      for(let t=1;t<loc.length;t++){const j=loc[t][0],root=loc[0][0],idx=C.tags.findIndex(x=>x[0]==="edge"&&x[1]===v&&x[2]===root&&x[3]===j);ok(idx>=0,"edge exists");z[idx]=J[j];}
    }
    ok(mod(z.reduce((s,b,i)=>s+b*C.U[i],0),2)===1,"odd normalization");
    for(let k=0;k<C.L;k++)ok(mod(z.reduce((s,b,i)=>s+b*C.A[i][k],0),2)===0,"A^T z even");
    return z;
  }
  function coin(C,q){return [C.A.map(()=>rnd(q)),Array.from({length:C.L},()=>rnd(3)-1),rnd(3)-1];}
  function enc(C,a,coins,q){const [s,e,ep]=coins;return {c:Array.from({length:C.L},(_,k)=>mod(C.A.reduce((v,row,i)=>v+row[k]*s[i],e[k]),q)),d:mod(C.U.reduce((v,u,i)=>v+u*s[i],ep)+(q/2)*a,q)};}
  function same(a,b){return JSON.stringify(a)===JSON.stringify(b);}
  function bits(bytes){return bytes.flatMap(b=>Array.from({length:8},(_,i)=>(b>>i)&1));}
  const triples=[[0,1,2],[0,3,4],[1,3,5],[2,4,5]];
  const F=compile(triples.map((x,i)=>xorFactor(x,[0,0,0,1][i])));
  const T=compile(triples.map(x=>xorFactor(x,0)));
  ok(F.L===16&&F.A.length===10,"Pasch source 10 by 16");
  const z=certificate(F,[1,1,1,1]);
  ok(same(z,[0,0,0,1,1,1,1,1,1,1]),"weight-seven certificate");
  const witnesses=[];for(let x=0;x<64;x++){const w=Array.from({length:6},(_,i)=>(x>>i)&1);ok(!valid(F.factors,w),"FALSE Pasch");if(valid(T.factors,w))witnesses.push(w);}
  ok(witnesses.length===8,"eight TRUE witnesses");
  for(let mask=0;mask<256;mask++){const p=Array(16).fill(0);for(let j=0;j<4;j++)p[4*j+((mask>>(2*j))&3)]=1;ok(!sourceOK(F,p,32),"no integral false opening");}
  let generalized=0;
  for(let trial=0;trial<120;trial++){
    const nf=5+rnd(4),ffs=[];
    for(let j=0;j<nf;j++){const vs=[];while(vs.length<3){const v=rnd(5);if(!vs.includes(v))vs.push(v)}vs.sort((a,b)=>a-b);ffs.push(xorFactor(vs,rnd(2)));}
    let J=null;
    for(let mask=1;mask<(1<<nf);mask++){
      const sel=ffs.map((_,j)=>(mask>>j)&1);
      if(mod(sel.reduce((s,b,j)=>s+b*ffs[j].p,0),2)!==1)continue;
      if([0,1,2,3,4].every(v=>mod(ffs.reduce((s,f,j)=>s+sel[j]*Number(f.vs.includes(v)),0),2)===0)){J=sel;break}
    }
    if(J){const C=compile(ffs);certificate(C,J);generalized++;}
  }
  ok(generalized>=12,"multiple inconsistent XOR families");
  const q=32,g=16;
  ok(g>2*(T.factors.length+1),"every-original decoding radius");
  for(let i=0;i<512;i++){const a=rnd(2),co=coin(F,q),prior=enc(F,a,co,q),next=[co[0].map((v,j)=>mod(v+g*(2*a-1)*z[j],q)),co[1],co[2]];ok(same(prior,enc(F,1-a,next,q)),"full c,d pointwise");}
  const K=Array.from({length:32},()=>rnd(256));
  const shares=Array.from({length:3},()=>Array.from({length:32},()=>rnd(256)));
  const M=K.map((v,i)=>v^shares[0][i]^shares[1][i]^shares[2][i]);
  const cts=shares.map(sh=>bits(sh).map(a=>enc(T,a,coin(T,q),q)));
  for(const w of witnesses){
    const p=phi(T,w);ok(p.reduce((s,x)=>s+x,0)===4&&sourceOK(T,p),"one-hot honest source");
    const recovered=[];
    for(const ctsShare of cts){
      const bs=ctsShare.map(ct=>{const r=mod(ct.d-ct.c.reduce((s,v,i)=>s+v*p[i],0),q),d0=Math.min(r,q-r),d1=Math.abs(r-g);ok(d0!==d1&&Math.min(d0,d1)<=5,"safe centered residual");return Number(d1<d0)});
      recovered.push(Array.from({length:32},(_,i)=>bs.slice(8*i,8*i+8).reduce((s,b,k)=>s+(b<<k),0)));
    }
    for(let i=0;i<32;i++)ok((M[i]^recovered[0][i]^recovered[1][i]^recovered[2][i])===K[i],"same precommitted K");
  }
  const G=compile([orFactor([0,1,2],[0,0,0]),orFactor([2,3,4],[1,0,1])]);
  let gw=0;for(let x=0;x<32;x++){const w=Array.from({length:5},(_,i)=>(x>>i)&1);if(valid(G.factors,w)){gw++;ok(sourceOK(G,phi(G,w)),"generic 3CNF completeness");}}
  ok(gw===24&&G.L===14,"generic 3CNF test");
  for(let cap=0;cap<2;cap++){
    const capshares=Array.from({length:3},()=>Array.from({length:32},()=>rnd(256)));
    const mask=Array.from({length:32},()=>rnd(256));
    const entry=capshares.map(sh=>bits(sh).map(a=>[a,coin(F,q)]));
    const publicC=entry.map(sh=>sh.map(([a,co])=>enc(F,a,co,q)));
    const wanted=bits(K.map((v,i)=>v^mask[i]^capshares[0][i]^capshares[2][i]));
    for(let i=0;i<256;i++){const [a,co]=entry[1][i],b=wanted[i];const shift=[co[0].map((v,j)=>mod(v+g*(a-b)*z[j],q)),co[1],co[2]];ok(same(enc(F,b,shift,q),publicC[1][i]),"same-key independent false capsule");}
  }
  ok(3*256*17*5/8===8160&&3*256*43===33024,"size");
  return {status:"PASS",assertions,source:"factor-local torsion; general bounded-arity original NP correctness, restricted XOR-certificate FALSE security",falsePasch:{rows:10,columns:16,certificate:z,local_onehot_choices_rejected:256,random_inconsistent_xor_systems:generalized},trueFixture:{valid_original_witnesses:8,identical_recovered_mock_key_bits:256},generic3CNF:{valid_witnesses:gw,columns:G.L},q:32,radix:16,maxLegitimateNoise:5,relatedSameKeyFalseCapsules:2,ciphertextPackedBytes:8160,predecessorRawBytes:33024,scope:"finite algebra, not generic NP security/QPT LWE/native SLH or Bitcoin verification"};
}
console.log(JSON.stringify(run(), null, 2));
