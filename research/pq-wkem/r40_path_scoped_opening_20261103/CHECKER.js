const checker = function checker() {
  let checks=0,st=0x40c0ffee;
  const ok=(v,why)=>{checks++;if(!v)throw Error(why);};
  const rnd=()=>{st^=st<<13;st^=st>>>17;st^=st<<5;return st>>>0;};
  const ri=n=>rnd()%n, mod=(v,q)=>((v%q)+q)%q;
  const hash=s=>{let h=2166136261>>>0;for(let j=0;j<s.length;j++)h=Math.imul(h^s.charCodeAt(j),16777619)>>>0;return h;};
  const q=257,n=2,m=16,B=1,Delta=128,paths=3,target=1,scopes=2,keyBits=128;
  const sources=Array.from({length:paths},()=>{
    const A=Array.from({length:m},()=>[ri(q),0]); // degeneracy ONLY in the correctness fixture
    const s=[ri(q),ri(q)],e=Array.from({length:m},()=>ri(3)-1);
    const b=A.map((row,j)=>mod(row[0]*s[0]+e[j],q));
    return{pk:{q,n,m,B,A,b},secret:{s,e}};
  });
  const sourceValid=(pk,w)=>pk.b.every((bj,j)=>mod(w.s[0]*pk.A[j][0]+w.s[1]*pk.A[j][1]+w.e[j],q)===bj&&Math.abs(w.e[j])<=B);
  const distinctWitnesses=src=>[0,19,233].map(second=>({s:[src.secret.s[0],second],e:src.secret.e}));
  for(const src of sources)for(const w of distinctWitnesses(src))ok(sourceValid(src.pk,w),"correctness fixture witness invalid");
  const H=v=>mod(37*v+71,65521); // INSECURE toy signature
  const skNative=Array.from({length:16},()=>[ri(65521),ri(65521)]);
  const vk=skNative.map(pair=>pair.map(H));
  const ctx={relation:"ORIGINAL-NOT-INSTANTIATED",claim:"claim-42",utxo:"funding-7",branch_set:[0,1,2],anchors:["SYS-2020000","BTC-window-5"]};
  const msgs=sources.map((src,i)=>JSON.stringify({ctx,branch:i,pkHash:hash(JSON.stringify(src.pk)),vkHash:hash(JSON.stringify(vk))}));
  ok(new Set(msgs).size===paths,"native signature messages must differ");
  const sign=msg=>{const h=hash(msg);return skNative.map((pair,j)=>pair[(h>>>j)&1]);};
  const verify=(msg,sig)=>!!sig&&sig.length===16&&sig.every((v,j)=>H(v)===vk[j][(hash(msg)>>>j)&1]);
  const toBytes=s=>s.flatMap(v=>[v&255,(v>>>8)&255]);
  const fromBytes=b=>Array.from({length:16},(_,j)=>b[2*j]+(b[2*j+1]<<8));
  const xor=(x,y)=>x.map((v,j)=>v^y[j]);
  const randBytes=n=>Array.from({length:n},()=>ri(256));
  const pad=(K,path,n)=>{
    let x=hash(K.join(",")+"|PATH:"+path)||1;
    return Array.from({length:n},()=>{x^=x<<13;x^=x>>>17;x^=x<<5;return(x>>>0)&255;});
  };
  const bit=(K,j)=>(K[j>>>3]>>>(j&7))&1;
  const enc=(pk,bv)=>{
    let u=[0,0],v=Delta*bv;
    for(let j=0;j<m;j++){const r=ri(2);u[0]+=r*pk.A[j][0];u[1]+=r*pk.A[j][1];v+=r*pk.b[j];}
    return{u:u.map(a=>mod(a,q)),v:mod(v,q)};
  };
  const dist=(z,a)=>{let d=mod(z-a,q);return Math.min(d,q-d);};
  const dec=(ct,w)=>{
    const v=mod(ct.v-w.s[0]*ct.u[0]-w.s[1]*ct.u[1],q);
    return dist(v,Delta)<dist(v,0)?1:0;
  };
  function build(mode,{sharedKey=false,sharedPK=false}={}){
    let keys=[],sigs=[],calls=[],records=[];
    const keyShared=sharedKey?randBytes(keyBits/8):null;
    const localPks=sharedPK?Array.from({length:paths},()=>sources[0].pk):sources.map(src=>src.pk);
    const localSec=sharedPK?Array.from({length:paths},()=>sources[0].secret):sources.map(src=>src.secret);
    for(let i=0;i<paths;i++){
      const K=keyShared?keyShared.slice():randBytes(keyBits/8);
      const msg=JSON.stringify({ctx,branch:i,pkHash:hash(JSON.stringify(localPks[i])),vkHash:hash(JSON.stringify(vk))});
      let signature=null;
      if(mode!=="sim"||i!==target){calls.push(i);signature=sign(msg);ok(verify(msg,signature),"invalid test signature");}
      const sigmaBytes=signature?toBytes(signature):null;
      const D=sigmaBytes?xor(sigmaBytes,pad(K,i,32)):randBytes(32);
      const C=Array.from({length:scopes},()=>Array.from({length:keyBits},(_,j)=>enc(localPks[i],mode==="sim"&&i===target?0:bit(K,j))));
      keys.push(K);sigs.push(signature);records.push({i,msg,D,C});
    }
    const aux={publicOnly:true,vkHash:hash(JSON.stringify(vk)),ctxHash:hash(JSON.stringify(ctx))};
    const pre={version:"R40-path-separated-toy",pks:localPks,ctx,vk,aux,records};
    const publicView={...pre,CK:hash(JSON.stringify(pre))};
    const sourceSecrets=localSec.map((w,i)=>mode==="sim"&&i===target?null:w);
    const open=i=>i===target?null:{K:keys[i].slice(),sigma:sigs[i].slice(),sourceWitness:{s:localSec[i].s.slice(),e:localSec[i].e.slice()}};
    return{publicView,keys,sigs,calls,sourceSecrets,open};
  }
  const real=build("real"),sim=build("sim"),badKey=build("real",{sharedKey:true}),badPK=build("real",{sharedPK:true});
  for(const v of [real,sim]){
    const {CK,...pre}=v.publicView;ok(CK===hash(JSON.stringify(pre)),"nonpublic checking key");
  }
  ok(sim.sourceSecrets[target]===null&&sim.calls.every(i=>i!==target),"simulator used target signing/source witness");
  let recoveredBits=0,opens=0;
  for(let i=0;i<paths;i++){
    const rec=real.publicView.records[i],pk=real.publicView.pks[i];
    for(const witness of distinctWitnesses(sources[i])){
      const observed=[];
      for(const scope of rec.C)for(let j=0;j<keyBits;j++){
        const v=dec(scope[j],witness);
        ok(v===bit(real.keys[i],j),"valid witness decodes incorrect key");
        recoveredBits++;if(observed.length<keyBits)observed.push(v);
      }
      const K=Array.from({length:keyBits/8},(_,j)=>observed.slice(8*j,8*j+8).reduce((v,z,k)=>v+(z<<k),0));
      ok(K.every((v,j)=>v===real.keys[i][j]),"witness-specific keys diverged");
      const recoveredSig=fromBytes(xor(rec.D,pad(K,i,32)));
      ok(verify(rec.msg,recoveredSig),"witness did not recover the prescribed signature");
      ok(recoveredSig.every((v,j)=>v===real.sigs[i][j]),"witness recovered alternate signature");
      ok(sourceValid(pk,witness),"witness not actually accepted by surrogate relation");
    }
  }
  for(const v of [real,sim]){
    ok(v.open(target)===null,"forbidden target opening");
    for(const i of [2,0,2,0]){
      const opening=v.open(i),rec=v.publicView.records[i];
      ok(sourceValid(v.publicView.pks[i],opening.sourceWitness),"other source witness invalid");
      ok(verify(rec.msg,opening.sigma),"opened signature invalid");
      ok(opening.K.every((z,j)=>z===v.keys[i][j]),"revealed key inconsistent");
      ok(fromBytes(xor(rec.D,pad(opening.K,i,32))).every((z,j)=>z===opening.sigma[j]),"opened DEM inconsistent");
      opens++;
    }
  }
  ok(real.publicView.pks.every((p,i)=>i===target||JSON.stringify(p)!==JSON.stringify(real.publicView.pks[target])),"source pk shared");
  const keyLeaked=badKey.open(0).K,recK=badKey.publicView.records[target];
  ok(keyLeaked.every((v,j)=>v===badKey.keys[target][j]),"shared-key negative control invalid");
  ok(verify(recK.msg,fromBytes(xor(recK.D,pad(keyLeaked,target,32)))),"opening same key did not compromise target signature");
  const foreignWitness=badPK.open(0).sourceWitness,pkTarget=badPK.publicView.pks[target],recP=badPK.publicView.records[target];
  ok(sourceValid(pkTarget,foreignWitness),"shared-pk negative control invalid");
  for(let j=0;j<keyBits;j++)ok(dec(recP.C[0][j],foreignWitness)===bit(badPK.keys[target],j),"opening shared source pk did not compromise target encryption");
  // Exact finite-field Markov extension with a separately fixed, opened source.
  const q2=3,m2=4,seeds=3**(2*m2),R=2**m2;
  const otherA=[1,2,0,1],otherE=[0,1,0,1],otherS=1,otherB=otherA.map((v,j)=>mod(v*otherS+otherE[j],q2));
  ok(otherB.every((v,j)=>mod(otherA[j]*otherS+otherE[j],q2)===v),"opened other source not consistent");
  const other=Array(9).fill(0);
  for(let r=0;r<R;r++){let u=0,v=1;for(let j=0;j<m2;j++)if((r>>>j)&1){u+=otherA[j];v+=otherB[j];}other[(u%3)*3+v%3]++;}
  let totalAbs=0,maxCondTV=0;
  for(let seed=0;seed<seeds;seed++){
    let z=seed,aa=[],bb=[];
    for(let j=0;j<m2;j++){aa.push(z%3);z=Math.floor(z/3);}
    for(let j=0;j<m2;j++){bb.push(z%3);z=Math.floor(z/3);}
    const c0=Array(9).fill(0),c1=Array(9).fill(0);
    for(let r=0;r<R;r++){
      let u=0,v=0;for(let j=0;j<m2;j++)if((r>>>j)&1){u+=aa[j];v+=bb[j];}
      u%=3;v%=3;c0[u*3+v]++;c1[u*3+(v+1)%3]++;
    }
    const abs=c0.reduce((a,c,j)=>a+Math.abs(c-c1[j]),0);
    let joint=0;for(let i=0;i<9;i++)for(let j=0;j<9;j++)joint+=Math.abs((c0[i]-c1[i])*other[j]);
    ok(joint===R*abs,"opened independent source changed target statistical distance");
    totalAbs+=abs;maxCondTV=Math.max(maxCondTV,abs/(2*R));
  }
  const averageTV=totalAbs/(2*R*seeds);
  ok(averageTV<0.75,"average extractor toy bound fails");
  return{run:"R40-PATH-SEPARATED-SOURCE-OPENINGS-20261103",checks,toy:{q,n,m,B,paths,scopes,keyBits,distinct_witnesses_per_path:3,recovered_bits:recoveredBits,non_target_source_and_capability_openings:opens,target_sign_queries:sim.calls.filter(i=>i===target).length,sim_target_source_secret:sim.sourceSecrets[target],negative_shared_key_compromises_target:true,negative_shared_source_key_compromises_target:true},finite:{q:3,n:1,m:4,seeds,binary_inputs:R,average_target_TV:averageTV,average_joint_with_open_other_source_TV:averageTV,max_per_key_TV:maxCondTV},caution:"Toy 2nd zero A row, native signature/hash/PRG/PRNG insecure. No original NP compiler, practical QPT security or Bitcoin deployment claim."};
};
const a=checker(),b=checker();
if(JSON.stringify(a)!==JSON.stringify(b))throw Error('nonreproducible');
console.log(JSON.stringify(a,null,2));
